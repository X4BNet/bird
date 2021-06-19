/*
 *	BIRD Coroutines
 *
 *	(c) 2017 Martin Mares <mj@ucw.cz>
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#undef LOCAL_DEBUG

#undef DEBUG_LOCKING

#include "lib/birdlib.h"
#include "lib/locking.h"
#include "lib/coro.h"
#include "lib/resource.h"
#include "lib/timer.h"

/* Using a rather big stack for coroutines to allow for stack-local allocations.
 * In real world, the kernel doesn't alloc this memory until it is used.
 * */
#define CORO_STACK_SIZE	1048576

/*
 *	Implementation of coroutines based on POSIX threads
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 *	Locking subsystem
 */

_Thread_local struct lock_order locking_stack = {};
_Thread_local struct domain_generic **last_locked = NULL;

#define ASSERT_NO_LOCK	ASSERT_DIE(last_locked == NULL)

struct domain_generic {
  pthread_mutex_t mutex;
  uint order;
  struct domain_generic **prev;
  struct lock_order *locked_by;
  const char *name;
};

#define DOMAIN_INIT(_name, _order) { .mutex = PTHREAD_MUTEX_INITIALIZER, .name = _name, .order = _order }

static struct domain_generic the_bird_domain_gen = DOMAIN_INIT("The BIRD", OFFSETOF(struct lock_order, the_bird));

DOMAIN(the_bird) the_bird_domain = { .the_bird = &the_bird_domain_gen };

struct domain_generic *
domain_new(const char *name, uint order)
{
  ASSERT_DIE(order < sizeof(struct lock_order));
  struct domain_generic *dg = xmalloc(sizeof(struct domain_generic));
  *dg = (struct domain_generic) DOMAIN_INIT(name, order);
  return dg;
}

void
domain_free(struct domain_generic *dg)
{
  pthread_mutex_destroy(&dg->mutex);
  xfree(dg);
}

uint dg_order(struct domain_generic *dg)
{
  return dg->order;
}

void do_lock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if ((char *) lsp - (char *) &locking_stack != dg->order)
    bug("Trying to lock on bad position: order=%u, lsp=%p, base=%p", dg->order, lsp, &locking_stack);

  if (lsp <= last_locked)
    bug("Trying to lock in a bad order");
  if (*lsp)
    bug("Inconsistent locking stack state on lock");

  pthread_mutex_lock(&dg->mutex);

  if (dg->prev || dg->locked_by)
    bug("Previous unlock not finished correctly");
  dg->prev = last_locked;
  *lsp = dg;
  last_locked = lsp;
  dg->locked_by = &locking_stack;
}

void do_unlock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if ((char *) lsp - (char *) &locking_stack != dg->order)
    bug("Trying to unlock on bad position: order=%u, lsp=%p, base=%p", dg->order, lsp, &locking_stack);

  if (dg->locked_by != &locking_stack)
    bug("Inconsistent domain state on unlock");
  if ((last_locked != lsp) || (*lsp != dg))
    bug("Inconsistent locking stack state on unlock");
  dg->locked_by = NULL;
  last_locked = dg->prev;
  *lsp = NULL;
  dg->prev = NULL;
  pthread_mutex_unlock(&dg->mutex);
}

/* Coroutines */
struct coroutine {
  resource r;
  pthread_t id;
  pthread_attr_t attr;
  void (*entry)(void *);
  void *data;
};

static _Thread_local _Bool coro_cleaned_up = 0;

static void coro_free(resource *r)
{
  struct coroutine *c = (void *) r;
  ASSERT_DIE(pthread_equal(pthread_self(), c->id));
  pthread_attr_destroy(&c->attr);
  coro_cleaned_up = 1;
}

static struct resclass coro_class = {
  .name = "Coroutine",
  .size = sizeof(struct coroutine),
  .free = coro_free,
};

_Thread_local struct coroutine *this_coro = NULL;

static void *coro_entry(void *p)
{
  struct coroutine *c = p;
  struct timeloop tloc = {};

  times_init(&tloc);
  local_timeloop = &tloc;

  ASSERT_DIE(c->entry);

  this_coro = c;

  c->entry(c->data);
  ASSERT_DIE(coro_cleaned_up);

  return NULL;
}

struct coroutine *coro_run(pool *p, void (*entry)(void *), void *data)
{
  ASSERT_DIE(entry);
  ASSERT_DIE(p);

  struct coroutine *c = ralloc(p, &coro_class);

  c->entry = entry;
  c->data = data;

  int e = 0;

  if (e = pthread_attr_init(&c->attr))
    die("pthread_attr_init() failed: %M", e);

  if (e = pthread_attr_setstacksize(&c->attr, CORO_STACK_SIZE))
    die("pthread_attr_setstacksize(%u) failed: %M", CORO_STACK_SIZE, e);

  if (e = pthread_attr_setdetachstate(&c->attr, PTHREAD_CREATE_DETACHED))
    die("pthread_attr_setdetachstate(PTHREAD_CREATE_DETACHED) failed: %M", e);

  if (e = pthread_create(&c->id, &c->attr, coro_entry, c))
    die("pthread_create() failed: %M", e);

  return c;
}

/* Semaphores */
struct bsem {
  resource r;
  sem_t sem;
};

static void bsem_free(resource *r)
{
  struct bsem *b = (void *) r;
  if (sem_destroy(&b->sem) < 0)
    bug("sem_destroy() failed: %m");
}

static struct resclass bsem_class = {
  .name = "Semaphore",
  .size = sizeof(struct bsem),
  .free = bsem_free,
};

struct bsem *bsem_new(pool *p) {
  struct bsem *b = ralloc(p, &bsem_class);
  if (sem_init(&b->sem, 0, 0) < 0)
    bug("sem_init() failed: %m");

  return b;
}

void bsem_post(struct bsem *b) {
  if (sem_post(&b->sem) < 0)
    bug("sem_post() failed: %m");
}

void bsem_wait(struct bsem *b) {
  if (sem_wait(&b->sem) < 0)
    if (errno == EINTR)
      return bsem_wait(b);
    else
      bug("sem_wait() failed: %m");
}

void bsem_wait_all(struct bsem *b) {
  bsem_wait(b);
  while (sem_trywait(&b->sem) == 0)
    ;
}

static int bsem_alarm_pipe[2];
static struct timeloop bsem_alarm_timeloop;

static int bsem_alarm_cmp(const void *_a, const void *_b)
{
  struct bsem_alarm *a = (void *) _a, *b = (void *) _b;
  btime wa = atomic_load_explicit(&a->when, memory_order_acquire);
  btime wb = atomic_load_explicit(&b->when, memory_order_acquire);

  return wb - wa;
}

static void bsem_alarm_coro(void * data UNUSED)
{
  uint max = 64;
  uint count = 0;
  struct bsem_alarm **ba = xmalloc(sizeof(struct bsem_alarm *) * max);

  local_timeloop = &bsem_alarm_timeloop;

  while (1)
  {
    /* Ring the alarms */
    int timeout = -1;
    uint count_before = count;

    times_update(&bsem_alarm_timeloop);

    DBG("Alarms max=%u count=%u\n", max, count);

    while (count)
    {
      btime when = atomic_load_explicit(&ba[count-1]->when, memory_order_acquire);
      btime now = current_time();
      if (when - now < 1 MS)
      {
	count--;
	DBG("when=%t now=%t posting bsem %p\n", when, now, ba[count]->bsem);
	atomic_store_explicit(&ba[count]->when, 0, memory_order_release);
	atomic_store_explicit(&ba[count]->set, 1, memory_order_release);
	bsem_post(ba[count]->bsem);
      }
      else
      {
	timeout = (when - now) TO_MS;
	DBG("when=%t now=%t timeout=%d\n", when, now, timeout);
	break;
      }
    }

    DBG("Processed %u fast alarms, timeout %d now", count_before - count, timeout);

    struct pollfd pfd = {
      .fd = bsem_alarm_pipe[0],
      .events = POLLIN,
    };

    int e = poll(&pfd, 1, timeout);

    if ((!e) || (e < 0) && ((errno == EAGAIN) || (errno == EINTR)))
      continue;

    if (e < 0)
    {
      log(L_ERR "Error polling the internal alarm pipe: %m");
      continue;
    }

    count_before = count;

    while (1)
    {
      if (count >= max)
	xrealloc(ba, sizeof(struct bsem_alarm *) * (max *= 2));

      e = read(bsem_alarm_pipe[0], &ba[count], sizeof(struct bsem_alarm *));
      if ((e < 0) && ((errno == EAGAIN) || (errno == EINTR)))
	break;

      if (e < 0)
      {
	log(L_ERR "Error reading from internal alarm pipe: %m");
	break;
      }

      ASSERT_DIE(e == sizeof(struct bsem_alarm *));
      count++;
    }

    DBG("Received %u fast alarms", count - count_before);

    qsort(ba, count, sizeof(struct bsem_alarm *), bsem_alarm_cmp);
  }
}

void bsem_alarm_init(void)
{
  times_init(&bsem_alarm_timeloop);

  if (pipe(bsem_alarm_pipe) < 0)
    die("pipe(&bsem_alarm_pipe) failed: %m");

  if (fcntl(bsem_alarm_pipe[0], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK) on bsem_alarm_pipe[0] failed: %m");

  /* Purposedly not setting the write end nonblocking */

  coro_run(&root_pool, bsem_alarm_coro, NULL);
}

void bsem_alarm(struct bsem_alarm *a, btime interval)
{
  if (atomic_load_explicit(&a->when, memory_order_acquire))
    return;

  btime when = current_time() + interval;

  atomic_store_explicit(&a->set, 0, memory_order_release);
  atomic_store_explicit(&a->when, when, memory_order_release);

  while (1)
  {
    int e = write(bsem_alarm_pipe[1], &a, sizeof(struct bsem_alarm *));
    if ((e < 0) && ((errno == EINTR) || (errno == EAGAIN)))
      continue;

    if (e < 0)
    {
      log(L_ERR "Error writing to internal alarm pipe: %m");
      continue;
    }

    ASSERT_DIE(e == sizeof(struct bsem_alarm *));
    DBG("Sent a fast alarm with interval %t (when=%t)", interval, when);
    return;
  }
}
