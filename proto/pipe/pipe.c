/*
 *	BIRD -- Table-to-Table Routing Protocol a.k.a Pipe
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Pipe
 *
 * The Pipe protocol is very simple. It just connects to two routing tables
 * using proto_add_announce_hook() and whenever it receives a rt_notify()
 * about a change in one of the tables, it converts it to a rte_update()
 * in the other one.
 *
 * To avoid pipe loops, Pipe keeps a `being updated' flag in each routing
 * table.
 *
 * A pipe has two announce hooks, the first connected to the main
 * table, the second connected to the peer table. When a new route is
 * announced on the main table, it gets checked by an export filter in
 * ahook 1, and, after that, it is announced to the peer table via
 * rte_update(), an import filter in ahook 2 is called. When a new
 * route is announced in the peer table, an export filter in ahook2
 * and an import filter in ahook 1 are used. Oviously, there is no
 * need in filtering the same route twice, so both import filters are
 * set to accept, while user configured 'import' and 'export' filters
 * are used as export filters in ahooks 2 and 1. Route limits are
 * handled similarly, but on the import side of ahooks.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/rtable.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"

#ifdef CONFIG_BGP
#include "proto/bgp/bgp.h"
#endif

#include "pipe.h"

static void
pipe_rt_notify(struct proto *P, struct channel *src_ch, linpool *lp, const net_addr *n, rte *new, rte *old)
{
  struct pipe_proto *p = (void *) P;
  struct channel *dst = (src_ch == p->pri) ? p->sec : p->pri;

  if (!new && !old)
    return;

  if (new)
    {
      rta *a = alloca(rta_size(new->attrs));
      memcpy(a, new->attrs, rta_size(new->attrs));

      a->cached = 0;
      atomic_store_explicit(&a->uc_atomic, 0, memory_order_relaxed);
      a->hostentry = NULL;

      rte e0 = {
	.attrs = a,
	.src = new->src,
	.net = n,
	.generation = new->generation + 1,
      };

      rte_update(dst, &e0, lp);
    }
  else
    rte_withdraw(dst, n, old->src);
}

static int
pipe_preexport(struct rt_export_request *src_req, struct rte *e)
{
  struct channel *src_ch = SKIP_BACK(struct channel, out, src_req);
  struct pipe_proto *p = (void *) src_ch->proto;

  /* Avoid direct loopbacks */
  if (src_ch->in.hook == e->sender)
    return -1;

  /* Indirection check */
  uint max_generation = ((struct pipe_config *) p->p.cf)->max_generation;
  if (e->generation >= max_generation)
  {
    log_rl(&rl_pipe, L_ERR "Route overpiped (%u hops of %u configured in %s) in table %s: %N %s/%u:%u",
	e->generation, max_generation, src_ch->proto->name,
	src_ch->table->name, e->net, e->src->proto->name, e->src->private_id, e->src->global_id);

#if 0
    if (config->pipe_debug)
      e->sender->proto->rte_track(e->sender, e->net, e->src);
#endif
    return -1;
  }

  return 0;
}

static void
pipe_reload_routes(struct channel *C)
{
  struct pipe_proto *p = (void *) C->proto;

  /* Route reload on one channel is just refeed on the other */
  channel_request_feeding((C == p->pri) ? p->sec : p->pri);
}

static void
pipe_rte_track(struct channel *C, const net_addr *n, struct rte_src *src)
{
  struct pipe_proto *p = (void *) C->proto;
  struct channel *src_ch = (C == p->pri) ? p->sec : p->pri;

  /*
   * TODO: make this asynchronous
  RT_LOCK(src_ch->table);
  net *nn = net_find(RT_PRIV(src_ch->table), n);
  struct rte_storage *e = nn ? rte_find(nn, src) : NULL;
  RT_UNLOCK(src_ch->table);
  */

  log_rl(&rl_pipe, L_TRACE "[route trace] Piped by protocol %s from table %s to table %s: %N %s/%u:%u",
      p->p.name, src_ch->table->name, C->table->name, n, src->proto->name, src->private_id, src->global_id);

  /*
  if (!e)
  {
    log_rl(&rl_pipe, L_ERR "[route trace] Couldn't find parent route in table %s: %N %s/%u:%u", src_ch->table->name,
	n, src->proto->name, src->private_id, src->global_id);
    return;
  }
  else if (!e->generation)
    log_rl(&rl_pipe, L_TRACE "[route trace] Authored by channel %s.%s in table %s: %N %s/%u:%u",
	e->sender->proto->name, e->sender->name, src_ch->table->name,
	n, src->proto->name, src->private_id, src->global_id);
  else
    return e->sender->proto->rte_track(e->sender, n, src);
    */
}

static void
pipe_postconfig(struct cf_context *ctx, struct proto_config *CF)
{
  struct pipe_config *cf = (void *) CF;
  struct channel_config *cc = proto_cf_main_channel(CF);

  if (!cc->table)
    cf_error("Primary routing table not specified");

  if (!cf->peer)
    cf_error("Secondary routing table not specified");

  if (cc->table == cf->peer)
    cf_error("Primary table and peer table must be different");

  if (cc->table->addr_type != cf->peer->addr_type)
    cf_error("Primary table and peer table must have the same type");

  if (cc->rx_limit.action)
    cf_error("Pipe protocol does not support receive limits");

  if (cc->in_keep_filtered)
    cf_error("Pipe protocol prohibits keeping filtered routes");

  cc->debug = cf->c.debug;
}

static int
pipe_configure_channels(struct pipe_proto *p, struct pipe_config *cf)
{
  struct channel_config *cc = proto_cf_main_channel(&cf->c);

  struct channel_config pri_cf = {
    .name = "pri",
    .channel = cc->channel,
    .table = cc->table,
    .out_filter = cc->out_filter,
    .in_limit = cc->in_limit,
    .ra_mode = RA_ANY,
    .debug = cc->debug,
    .rpki_reload = cc->rpki_reload,
  };

  struct channel_config sec_cf = {
    .name = "sec",
    .channel = cc->channel,
    .table = cf->peer,
    .out_filter = cc->in_filter,
    .in_limit = cc->out_limit,
    .ra_mode = RA_ANY,
    .debug = cc->debug,
    .rpki_reload = cc->rpki_reload,
  };

  return
    proto_configure_channel(&p->p, &p->pri, &pri_cf) &&
    proto_configure_channel(&p->p, &p->sec, &sec_cf);
}

static struct proto *
pipe_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct pipe_proto *p = (void *) P;
  struct pipe_config *cf = (void *) CF;

  P->rt_notify = pipe_rt_notify;
  P->reload_routes = pipe_reload_routes;
  P->rte_track = pipe_rte_track;

  pipe_configure_channels(p, cf);

  p->pri->out.preexport = pipe_preexport;
  p->sec->out.preexport = pipe_preexport;

  return P;
}

static int
pipe_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct pipe_proto *p = (void *) P;
  struct pipe_config *cf = (void *) CF;

  return pipe_configure_channels(p, cf);
}

static void
pipe_copy_config(struct config *new UNUSED, struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy, not many items here */
}

static void
pipe_get_status(struct proto *P, byte *buf)
{
  struct pipe_proto *p = (void *) P;

  bsprintf(buf, "%s <=> %s", p->pri->table->name, p->sec->table->name);
}

static void
pipe_show_stats(struct pipe_proto *p)
{
  struct import_stats *s1i = &p->pri->in.hook->stats;
  struct export_stats *s1e = &p->pri->out.hook->stats;
  struct import_stats *s2i = &p->sec->in.hook->stats;
  struct export_stats *s2e = &p->sec->out.hook->stats;

  /*
   * Pipe stats (as anything related to pipes) are a bit tricky. There
   * are two sets of stats - s1 for ahook to the primary routing and
   * s2 for the ahook to the secondary routing table. The user point
   * of view is that routes going from the primary routing table to
   * the secondary routing table are 'exported', while routes going in
   * the other direction are 'imported'.
   *
   * Each route going through a pipe is, technically, first exported
   * to the pipe and then imported from that pipe and such operations
   * are counted in one set of stats according to the direction of the
   * route propagation. Filtering is done just in the first part
   * (export). Therefore, we compose stats for one directon for one
   * user direction from both import and export stats, skipping
   * immediate and irrelevant steps (exp_updates_accepted,
   * imp_updates_received, imp_updates_filtered, ...).
   *
   * Rule of thumb is that stats s1 have the correct 'polarity'
   * (imp/exp), while stats s2 have switched 'polarity'.
   */

  cli_msg(-1006, "  Routes:         %u imported, %u exported",
	  s1i->routes, s2i->routes);
  cli_msg(-1006, "  Route change stats:     received   rejected   filtered    ignored   accepted");
  cli_msg(-1006, "    Import updates:     %10u %10u %10u %10u %10u",
	  s2e->updates_received, s2e->updates_rejected + s1i->updates_invalid,
	  s2e->updates_filtered, s1i->updates_ignored, s1i->updates_accepted);
  cli_msg(-1006, "    Import withdraws:   %10u %10u        --- %10u %10u",
	  s2e->withdraws_received, s1i->withdraws_invalid,
	  s1i->withdraws_ignored, s1i->withdraws_accepted);
  cli_msg(-1006, "    Export updates:     %10u %10u %10u %10u %10u",
	  s1e->updates_received, s1e->updates_rejected + s2i->updates_invalid,
	  s1e->updates_filtered, s2i->updates_ignored, s2i->updates_accepted);
  cli_msg(-1006, "    Export withdraws:   %10u %10u        --- %10u %10u",
	  s1e->withdraws_received, s2i->withdraws_invalid,
	  s2i->withdraws_ignored, s2i->withdraws_accepted);
}

static const char *pipe_feed_state[] = {
  [TES_DOWN] = "down",
  [TES_HUNGRY] = "feed pending",
  [TES_FEEDING] = "feed running",
  [TES_READY] = "up",
  [TES_STOP] = "stopping",
};

static void
pipe_show_proto_info(struct proto *P)
{
  struct pipe_proto *p = (void *) P;

  cli_msg(-1006, "  Channel %s", "main");
  cli_msg(-1006, "    Table:          %s", p->pri->table->name);
  cli_msg(-1006, "    Peer table:     %s", p->sec->table->name);
  cli_msg(-1006, "    Import state:   %s", pipe_feed_state[p->sec->out.hook ? rt_export_get_state(p->sec->out.hook) : TES_DOWN]);
  cli_msg(-1006, "    Export state:   %s", pipe_feed_state[p->pri->out.hook ? rt_export_get_state(p->pri->out.hook) : TES_DOWN]);
  cli_msg(-1006, "    Import filter:  %s", filter_name(p->sec->out.filter));
  cli_msg(-1006, "    Export filter:  %s", filter_name(p->pri->out.filter));

  channel_show_limit(&p->pri->in.in_limit, "Import limit:");
  channel_show_limit(&p->sec->in.in_limit, "Export limit:");

  if (P->proto_state != PS_DOWN)
    pipe_show_stats(p);
}

void
pipe_update_debug(struct proto *P)
{
  struct pipe_proto *p = (void *) P;

  p->pri->debug = p->sec->debug = p->p.debug;
}


struct protocol proto_pipe = {
  .name =		"Pipe",
  .template =		"pipe%d",
  .class =		PROTOCOL_PIPE,
  .proto_size =		sizeof(struct pipe_proto),
  .config_size =	sizeof(struct pipe_config),
  .postconfig =		pipe_postconfig,
  .init =		pipe_init,
  .reconfigure =	pipe_reconfigure,
  .copy_config = 	pipe_copy_config,
  .get_status = 	pipe_get_status,
  .show_proto_info = 	pipe_show_proto_info
};
