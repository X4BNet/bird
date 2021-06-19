/*
 *	BIRD Coroutines
 *
 *	(c) 2017 Martin Mares <mj@ucw.cz>
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CORO_H_
#define _BIRD_CORO_H_

#include "lib/resource.h"

/* A completely opaque coroutine handle. */
struct coroutine;

/* Coroutines are independent threads bound to pools.
 * You request a coroutine by calling coro_run().
 * It is forbidden to free a running coroutine from outside.
 * The running coroutine must free itself by rfree() before returning.
 */
struct coroutine *coro_run(pool *, void (*entry)(void *), void *data);

/* Get self. */
extern _Thread_local struct coroutine *this_coro;

/* Semaphores are handy to sleep and wake worker threads. */
struct bsem;

/* Create a semaphore. Be sure to choose such a pool that happens to be freed
 * only when the semaphore can't be waited for or posted. */
struct bsem *bsem_new(pool *);

/* Post a semaphore (wake the worker). */
void bsem_post(struct bsem *);

/* Wait for a semaphore. Never do this within a locked context. */
void bsem_wait(struct bsem *);

/* Wait for a semaphore and consume all the wakeups at once. */
void bsem_wait_all(struct bsem *);

/* There are no portable ways to make semaphores wait for a limited time.
 * Instead, if you want to wakeup a semaphore after some short time, you should
 * register a bsem_alarm. Attempts to register an already running alarm are
 * ignored.
 * */
struct bsem_alarm {
  struct bsem *bsem;	/* The semaphore to be woken up. */
  _Atomic btime when;	/* When it should run. Set internally. */
  _Atomic _Bool set;	/* Set to 1 by the alarm. */
};

void bsem_alarm(struct bsem_alarm *, btime interval);
void bsem_alarm_init(void);

#endif
