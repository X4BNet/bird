/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#include "nest/bird.h"

#include "lib/buffer.h"
#include "lib/coro.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include "lib/io-loop.h"
#include "sysdep/unix/io-loop.h"

/*
 *	Current thread context
 */

static _Thread_local struct birdloop *birdloop_current;

/*
 *	Wakeup code for birdloop
 */

static void
pipe_new(int *pfds)
{
  int rv = pipe(pfds);
  if (rv < 0)
    die("pipe: %m");

  if (fcntl(pfds[0], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");

  if (fcntl(pfds[1], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");
}

void
pipe_drain(int fd)
{
  char buf[64];
  int rv;
  
 try:
  rv = read(fd, buf, 64);
  if (rv < 0)
  {
    if (errno == EINTR)
      goto try;
    if (errno == EAGAIN)
      return;
    die("wakeup read: %m");
  }
  if (rv == 64)
    goto try;
}

void
pipe_kick(int fd)
{
  u64 v = 1;
  int rv;

 try:
  rv = write(fd, &v, sizeof(u64));
  if (rv < 0)
  {
    if (errno == EINTR)
      goto try;
    if (errno == EAGAIN)
      return;
    die("wakeup write: %m");
  }
}

static inline void
wakeup_init(struct birdloop *loop)
{
  pipe_new(loop->wakeup_fds);
}

static inline void
wakeup_drain(struct birdloop *loop)
{
  pipe_drain(loop->wakeup_fds[0]);
}

static inline void
wakeup_do_kick(struct birdloop *loop)
{
  pipe_kick(loop->wakeup_fds[1]);
}

void
birdloop_ping(struct birdloop *loop)
{
  ASSERT_DIE(DG_IS_LOCKED(loop->time.domain));

  if (loop->ping_sent)
    return;

  loop->ping_sent = 1;

  if (!loop->wakeup_masked)
    wakeup_do_kick(loop);
  else
    loop->wakeup_masked = 2;
}


/*
 *	Events
 */

static inline uint
events_waiting(struct birdloop *loop)
{
  return !EMPTY_LIST(loop->event_list);
}

static inline void
events_init(struct birdloop *loop)
{
  init_list(&loop->event_list);
}

static void
events_fire(struct birdloop *loop)
{
  times_update(&loop->time);
  ev_run_list(&loop->event_list);
}

void
ev2_schedule(event *e)
{
  if (EMPTY_LIST(birdloop_current->event_list))
    birdloop_ping(birdloop_current);

  if (e->n.next)
    rem_node(&e->n);

  add_tail(&birdloop_current->event_list, &e->n);
}


/*
 *	Sockets
 */

static void
sockets_init(struct birdloop *loop)
{
  init_list(&loop->sock_list);
  loop->sock_num = 0;

  BUFFER_INIT(loop->poll_sk, loop->pool, 4);
  BUFFER_INIT(loop->poll_fd, loop->pool, 4);
  loop->poll_changed = 1;	/* add wakeup fd */
}

static void
sockets_add(struct birdloop *loop, sock *s)
{
  add_tail(&loop->sock_list, &s->n);
  loop->sock_num++;

  s->index = -1;
  loop->poll_changed = 1;

  birdloop_ping(loop);
}

void
sk_start(sock *s)
{
  sockets_add(birdloop_current, s);
}

static void
sockets_remove(struct birdloop *loop, sock *s)
{
  rem_node(&s->n);
  loop->sock_num--;

  if (s->index >= 0)
  {
    loop->poll_sk.data[s->index] = NULL;
    s->index = -1;
    loop->poll_changed = 1;
    loop->close_scheduled = 1;
    birdloop_ping(loop);
  }
  else
    close(s->fd);
}

void
sk_stop(sock *s)
{
  sockets_remove(birdloop_current, s);
}

static inline uint sk_want_events(sock *s)
{ return (s->rx_hook ? POLLIN : 0) | ((s->ttx != s->tpos) ? POLLOUT : 0); }

/*
FIXME: this should be called from sock code

static void
sockets_update(struct birdloop *loop, sock *s)
{
  if (s->index >= 0)
    loop->poll_fd.data[s->index].events = sk_want_events(s);
}
*/

static void
sockets_prepare(struct birdloop *loop)
{
  BUFFER_SET(loop->poll_sk, loop->sock_num + 1);
  BUFFER_SET(loop->poll_fd, loop->sock_num + 1);

  struct pollfd *pfd = loop->poll_fd.data;
  sock **psk = loop->poll_sk.data;
  uint i = 0;
  node *n;

  WALK_LIST(n, loop->sock_list)
  {
    sock *s = SKIP_BACK(sock, n, n);

    ASSERT(i < loop->sock_num);

    s->index = i;
    *psk = s;
    pfd->fd = s->fd;
    pfd->events = sk_want_events(s);
    pfd->revents = 0;

    pfd++;
    psk++;
    i++;
  }

  ASSERT(i == loop->sock_num);

  /* Add internal wakeup fd */
  *psk = NULL;
  pfd->fd = loop->wakeup_fds[0];
  pfd->events = POLLIN;
  pfd->revents = 0;

  loop->poll_changed = 0;
}

static void
sockets_close_fds(struct birdloop *loop)
{
  struct pollfd *pfd = loop->poll_fd.data;
  sock **psk = loop->poll_sk.data;
  int poll_num = loop->poll_fd.used - 1;

  int i;
  for (i = 0; i < poll_num; i++)
    if (psk[i] == NULL)
      close(pfd[i].fd);

  loop->close_scheduled = 0;
}

int sk_read(sock *s, int revents);
int sk_write(sock *s);

static void
sockets_fire(struct birdloop *loop)
{
  struct pollfd *pfd = loop->poll_fd.data;
  sock **psk = loop->poll_sk.data;
  int poll_num = loop->poll_fd.used - 1;

  times_update(&loop->time);

  /* Last fd is internal wakeup fd */
  if (pfd[poll_num].revents & POLLIN)
    wakeup_drain(loop);

  int i;
  for (i = 0; i < poll_num; pfd++, psk++, i++)
  {
    int e = 1;

    if (! pfd->revents)
      continue;

    if (pfd->revents & POLLNVAL)
      die("poll: invalid fd %d", pfd->fd);

    if (pfd->revents & POLLIN)
      while (e && *psk && (*psk)->rx_hook)
	e = sk_read(*psk, 0);

    e = 1;
    if (pfd->revents & POLLOUT)
      while (e && *psk)
	e = sk_write(*psk);
  }
}


/*
 *	Birdloop
 */

struct birdloop main_birdloop;

void
birdloop_init(void)
{
  wakeup_init(&main_birdloop);

  main_birdloop.time.domain = the_bird_domain.the_bird;
  main_birdloop.time.loop = &main_birdloop;

  timers_init(&main_birdloop.time, &root_pool);

  local_timeloop = &main_birdloop.time;
}

static void birdloop_main(void *arg);

struct birdloop *
birdloop_new(pool *pp, struct domain_generic *dg)
{
  ASSERT_DIE(DG_IS_LOCKED(dg));

  pool *p = rp_new(pp, "Loop pool");
  struct birdloop *loop = mb_allocz(p, sizeof(struct birdloop));
  loop->pool = p;

  loop->time.domain = dg;
  loop->time.loop = loop;

  wakeup_init(loop);

  events_init(loop);
  timers_init(&loop->time, p);
  sockets_init(loop);

  loop->time.coro = coro_run(p, birdloop_main, loop);

  return loop;
}

void
birdloop_stop(struct birdloop *loop, void (*stopped)(void *data), void *data)
{
  DG_LOCK(loop->time.domain);
  loop->stopped = stopped;
  loop->stop_data = data;
  wakeup_do_kick(loop);
  DG_UNLOCK(loop->time.domain);
}

void
birdloop_free(struct birdloop *loop)
{
  rfree(loop->pool);
}

void
birdloop_enter_locked(struct birdloop *loop)
{
  ASSERT_DIE(DG_IS_LOCKED(loop->time.domain));

  /* Store the old context */
  loop->prev_loop = birdloop_current;
  loop->prev_time = local_timeloop;

  /* Put the new context */
  birdloop_current = loop;
  local_timeloop = &loop->time;
}

void
birdloop_enter(struct birdloop *loop)
{
  DG_LOCK(loop->time.domain);
  return birdloop_enter_locked(loop);
}

void
birdloop_leave_locked(struct birdloop *loop)
{
  /* Reset the ping limiter */
  loop->ping_sent = 0;

  /* Check the current context */
  ASSERT_DIE(birdloop_current == loop);
  ASSERT_DIE(local_timeloop == &loop->time);

  /* Restore the old context */
  birdloop_current = loop->prev_loop;
  local_timeloop = loop->prev_time;
}

void
birdloop_leave(struct birdloop *loop)
{
  birdloop_leave_locked(loop);
  DG_UNLOCK(loop->time.domain);
}

void
birdloop_mask_wakeups(struct birdloop *loop)
{
  DG_LOCK(loop->time.domain);
  loop->wakeup_masked = 1;
  DG_UNLOCK(loop->time.domain);
}

void
birdloop_unmask_wakeups(struct birdloop *loop)
{
  DG_LOCK(loop->time.domain);
  if (loop->wakeup_masked == 2)
    wakeup_do_kick(loop);
  loop->wakeup_masked = 0;
  DG_UNLOCK(loop->time.domain);
}

static void
birdloop_main(void *arg)
{
  struct birdloop *loop = arg;
  timer *t;
  int rv, timeout;

  birdloop_current = loop;
  local_timeloop = &loop->time;

  DG_LOCK(loop->time.domain);
  while (1)
  {
    events_fire(loop);
    timers_fire(&loop->time);

    times_update(&loop->time);
    if (events_waiting(loop))
      timeout = 0;
    else if (t = timers_first(&loop->time))
      timeout = (tm_remains(t) TO_MS) + 1;
    else
      timeout = -1;

    if (loop->poll_changed)
      sockets_prepare(loop);

    DG_UNLOCK(loop->time.domain);

  try:
    rv = poll(loop->poll_fd.data, loop->poll_fd.used, timeout);
    if (rv < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	goto try;
      die("poll: %m");
    }

    DG_LOCK(loop->time.domain);

    if (loop->close_scheduled)
      sockets_close_fds(loop);

    if (loop->stopped)
      break;

    if (rv)
      sockets_fire(loop);

    timers_fire(&loop->time);
  }

  DG_UNLOCK(loop->time.domain);
  loop->stopped(loop->stop_data);
}


