/*
 *	BIRD Test -- Utils for testing parsing configuration file
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/bird.h"
#include "nest/rtable.h"
#include "nest/protocol.h"

#include "sysdep/unix/unix.h"
#include "sysdep/unix/krt.h"

#include "nest/iface.h"
#include "nest/locks.h"

#include "filter/filter.h"

#include "conf/parser.h"

#define BETWEEN(a, b, c)  (((a) >= (b)) && ((a) <= (c)))

/* Defined in sysdep/unix/conf.c */
int unix_read_config(const char *name, struct config *conf, cf_error_type arg_cf_error, volatile _Atomic _Bool *cancelled);

struct cf_context *
bt_bird_init(void)
{
  if(bt_verbose)
    log_init_debug("");
  log_switch(bt_verbose != 0, NULL, NULL);

  the_bird_lock();

  net_init();
  resource_init();
  olock_init();
  birdloop_init();
  io_init();
  rt_init();
  if_init();
  config_init();

  protos_build();
  proto_build(&proto_unix_kernel);
  proto_build(&proto_unix_iface);

  bsem_alarm_init();

  pool *p = rp_new(&root_pool, "helper_pool");
  linpool *l = lp_new_default(p);

  struct config *c = lp_alloc(l, sizeof(struct config));
  *c = (struct config) { .pool = p, .mem = l, };

  struct conf_state *cs = lp_alloc(l, sizeof(struct conf_state));
  *cs = (struct conf_state) {};

  struct conf_order *co = lp_alloc(l, sizeof(struct conf_order));
  *co = (struct conf_order) { .pool = p, .lp = l, .new_config = c, .state = cs };

  return cf_new_context(co);
}

void bt_bird_cleanup(struct cf_context *ctx)
{
  for (int i = 0; i < PROTOCOL__MAX; i++)
    class_to_protocol[i] = NULL;

  cf_free_context(ctx);
}

static void
bt_cf_error(struct conf_order *order, const char *msg, va_list args)
{
  bt_abort_msg("%s, line %u: %V", order->state->name, order->state->lino, msg, &args);
}

struct config *
bt_config_file_parse(const char *filepath)
{
  struct config *new = config_alloc(NULL, NULL);
  unix_read_config(filepath, new, bt_cf_error, NULL);
  config_commit(new, RECONFIG_HARD, 0);
  return new;
}

/*
 * Returns @base raised to the power of @power.
 */
uint
bt_naive_pow(uint base, uint power)
{
  uint result = 1;
  uint i;
  for (i = 0; i < power; i++)
    result *= base;
  return result;
}

/**
 * bytes_to_hex - transform data into hexadecimal representation
 * @buf: preallocated string buffer
 * @in_data: data for transformation
 * @size: the length of @in_data
 *
 * This function transforms @in_data of length @size into hexadecimal
 * representation and writes it into @buf.
 */
void
bt_bytes_to_hex(char *buf, const byte *in_data, size_t size)
{
  size_t i;
  for(i = 0; i < size; i++)
    sprintf(buf + i*2, "%02x", in_data[i]);
}

