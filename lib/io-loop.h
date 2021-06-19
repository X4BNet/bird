/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IO_LOOP_H_
#define _BIRD_IO_LOOP_H_

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/locking.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"


void ev2_schedule(event *e);

void sk_start(sock *s);
void sk_stop(sock *s);

extern struct birdloop main_birdloop;

/* Start a new birdloop owned by given pool and domain */
struct birdloop *birdloop_new(pool *p, struct domain_generic *dg);

/* Stop the loop. At the end, the @stopped callback is called unlocked in tail
 * position to finish cleanup. Run birdloop_free() from that callback to free
 * the loop itself. */
void birdloop_stop(struct birdloop *loop, void (*stopped)(void *data), void *data);
void birdloop_free(struct birdloop *loop);

/* Enter and exit the birdloop */
void birdloop_enter(struct birdloop *loop);
void birdloop_enter_locked(struct birdloop *loop);
void birdloop_leave(struct birdloop *loop);
void birdloop_leave_locked(struct birdloop *loop);

void birdloop_mask_wakeups(struct birdloop *loop);
void birdloop_unmask_wakeups(struct birdloop *loop);

void birdloop_ping(struct birdloop *loop);

void birdloop_init(void);

#endif /* _BIRD_IO_LOOP_H_ */
