/*
 *	BIRD -- Routing Tables
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Routing tables
 *
 * Routing tables are probably the most important structures BIRD uses. They
 * hold all the information about known networks, the associated routes and
 * their attributes.
 *
 * There are multiple routing tables (a primary one together with any
 * number of secondary ones if requested by the configuration). Each table
 * is basically a FIB containing entries describing the individual
 * destination networks. For each network (represented by structure &net),
 * there is a one-way linked list of route entries (&rte), the first entry
 * on the list being the best one (i.e., the one we currently use
 * for routing), the order of the other ones is undetermined.
 *
 * The &rte contains information specific to the route (preference, protocol
 * metrics, time of last modification etc.) and a pointer to a &rta structure
 * (see the route attribute module for a precise explanation) holding the
 * remaining route attributes which are expected to be shared by multiple
 * routes in order to conserve memory.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/rtable.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/resource.h"
#include "lib/coro.h"
#include "lib/locking.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/hash.h"
#include "lib/string.h"
#include "lib/alloca.h"
#include "sysdep/unix/unix.h"

#ifdef CONFIG_RIP
#include "proto/rip/rip.h"
#endif

#ifdef CONFIG_OSPF
#include "proto/ospf/ospf.h"
#endif

#ifdef CONFIG_BGP
#include "proto/bgp/bgp.h"
#endif

#ifdef CONFIG_BABEL
#include "proto/babel/babel.h"
#endif

#include <stdatomic.h>

pool *rt_table_pool;

list routing_tables;

/* Data structures for export journal */
struct rt_pending_export {
  struct rt_pending_export * _Atomic next;	/* Next export for the same destination */
  struct rte_storage *new;			/* New route */
  struct rte_storage *new_best;			/* New best route */
  struct rte_storage *old;			/* Old route */
  struct rte_storage *old_best;			/* Old best route */
  u64 seq;				/* Sequential ID (table-local) of the pending export */
};

#define RT_PENDING_EXPORT_ITEMS		(get_page_size() - sizeof(struct rt_export_block)) / sizeof(struct rt_pending_export)

struct rt_export_block {
  node n;
  _Atomic u16 end;
  _Atomic _Bool not_last;
  struct rt_pending_export export[];
};

struct rt_pending_export_fib_node {
  struct rt_pending_export *last, *first;
  struct fib_node n;
};

static void rt_free_hostcache(rtable_private *tab);
static void rt_notify_hostcache(rtable_private *tab, net *net);
static void rt_update_hostcache(rtable_private *tab);
static void rt_next_hop_update(rtable_private *tab);
static _Bool rt_prune_table(rtable_private *tab);
static void rt_finish_prune(rtable *tab);
static inline void rt_schedule_notify(rtable_private *tab);
static inline void rt_export_used(rtable *tab);
static _Bool rt_export_cleanup(rtable_private *tab);

struct tbf rl_pipe = TBF_DEFAULT_LOG_LIMITS;

/* Like fib_route(), but skips empty net entries */
static inline void *
net_route_ip4(rtable_private *t, net_addr_ip4 *n)
{
  net *r;

  while (r = net_find_valid(t, (net_addr *) n), (!r) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip4_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

static inline void *
net_route_ip6(rtable_private *t, net_addr_ip6 *n)
{
  net *r;

  while (r = net_find_valid(t, (net_addr *) n), (!r) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip6_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

static inline void *
net_route_ip6_sadr(rtable_private *t, net_addr_ip6_sadr *n)
{
  struct fib_node *fn;

  while (1)
  {
    net *best = NULL;
    int best_pxlen = 0;

    /* We need to do dst first matching. Since sadr addresses are hashed on dst
       prefix only, find the hash table chain and go through it to find the
       match with the smallest matching src prefix. */
    for (fn = fib_get_chain(&t->fib, (net_addr *) n); fn; fn = fn->next)
    {
      net_addr_ip6_sadr *a = (void *) fn->addr;

      if (net_equal_dst_ip6_sadr(n, a) &&
	  net_in_net_src_ip6_sadr(n, a) &&
	  (a->src_pxlen >= best_pxlen))
      {
	best = fib_node_to_user(&t->fib, fn);
	best_pxlen = a->src_pxlen;
      }
    }

    if (best)
      return best;

    if (!n->dst_pxlen)
      break;

    n->dst_pxlen--;
    ip6_clrbit(&n->dst_prefix, n->dst_pxlen);
  }

  return NULL;
}

void *
net_route(rtable_private *tab, const net_addr *n)
{
  ASSERT(tab->addr_type == n->type);

  net_addr *n0 = alloca(n->length);
  net_copy(n0, n);

  switch (n->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return net_route_ip4(tab, (net_addr_ip4 *) n0);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
    return net_route_ip6(tab, (net_addr_ip6 *) n0);

  case NET_IP6_SADR:
    return net_route_ip6_sadr(tab, (net_addr_ip6_sadr *) n0);

  default:
    return NULL;
  }
}


static int
net_roa_check_ip4(rtable_private *tab, const net_addr_ip4 *px, u32 asn)
{
  struct net_addr_roa4 n = NET_ADDR_ROA4(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa4 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa4(roa, &n) && rte_is_valid(r->routes))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip4_clrbit(&n.prefix, n.pxlen);
  }

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

static int
net_roa_check_ip6(rtable_private *tab, const net_addr_ip6 *px, u32 asn)
{
  struct net_addr_roa6 n = NET_ADDR_ROA6(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa6 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa6(roa, &n) && rte_is_valid(r->routes))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip6_clrbit(&n.prefix, n.pxlen);
  }

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

/**
 * roa_check - check validity of route origination in a ROA table
 * @tab: ROA table
 * @n: network prefix to check
 * @asn: AS number of network prefix
 *
 * Implements RFC 6483 route validation for the given network prefix. The
 * procedure is to find all candidate ROAs - ROAs whose prefixes cover the given
 * network prefix. If there is no candidate ROA, return ROA_UNKNOWN. If there is
 * a candidate ROA with matching ASN and maxlen field greater than or equal to
 * the given prefix length, return ROA_VALID. Otherwise, return ROA_INVALID. If
 * caller cannot determine origin AS, 0 could be used (in that case ROA_VALID
 * cannot happen). Table @tab must have type NET_ROA4 or NET_ROA6, network @n
 * must have type NET_IP4 or NET_IP6, respectively.
 */
int
net_roa_check(rtable_private *tab, const net_addr *n, u32 asn)
{
  if ((tab->addr_type == NET_ROA4) && (n->type == NET_IP4))
    return net_roa_check_ip4(tab, (const net_addr_ip4 *) n, asn);
  else if ((tab->addr_type == NET_ROA6) && (n->type == NET_IP6))
    return net_roa_check_ip6(tab, (const net_addr_ip6 *) n, asn);
  else
    return ROA_UNKNOWN;	/* Should not happen */
}

/**
 * rte_find - find a route
 * @net: network node
 * @src: route source
 *
 * The rte_find() function returns a route for destination @net
 * which is from route source @src.
 */
struct rte_storage *
rte_find(net *net, struct rte_src *src)
{
  struct rte_storage *e = net->routes;

  while (e && e->src != src)
    e = e->next;
  return e;
}

struct rte_storage *
rte_store(rtable_private *tab, const rte *r, net *n)
{
  DBG("rte_store(%s, %N)\n", tab->name, n->n.addr);

  struct rte_storage *e = sl_alloc(tab->rte_slab);
  *e = (struct rte_storage) {
    .attrs = r->attrs,
    .net = n,
    .src = r->src,
    .generation = r->generation,
  };

  rt_lock_source(e->src);

  if (e->attrs->cached)
    e->attrs = rta_clone(r->attrs);
  else
    e->attrs = rta_lookup(r->attrs);

  return e;
}

void
rte_copy_metadata(struct rte_storage *dest, struct rte_storage *src)
{
  dest->sender = src->sender;
  dest->flags = src->flags & REF_FILTERED;
  dest->pflags = src->pflags;
  dest->lastmod = src->lastmod;
}

/**
 * rte_cow_rta - get a private writable copy of &rte with writable &rta
 * @r: a route entry to be copied
 * @lp: a linpool from which to allocate &rta
 *
 * rte_cow_rta() returns directly a &rte struct; the route attributes are
 * a shallow copy made on the given linpool, src is not locked.
 *
 * To work properly, the caller must own the original rte_storage whole the
 * time this route is being used.
 *
 * Result: a new &rte with writable &rta.
 */
rte
rte_cow_rta(const struct rte_storage *r, linpool *lp)
{
  return (rte) {
    .attrs = rta_do_cow(r->attrs, lp),
    .net = r->net->n.addr,
    .src = r->src,
  };
}

/**
 * rte_free - delete a &rte
 * @e: &rte to be deleted
 *
 * rte_free() deletes the given &rte from the routing table it's linked to.
 */
void
rte_free(rtable_private *tab, struct rte_storage *e)
{
  DBG("rte_free(%s, %N)\n", tab->name, e->net->n.addr);

  rt_unlock_source(e->src);
  rta_free(e->attrs);
  sl_free(tab->rte_slab, e);
}

static int				/* Actually better or at least as good as */
rte_better(struct rte_storage *new, struct rte_storage *old)
{
  int (*better)(struct rte_storage *, struct rte_storage *);

  if (!rte_is_valid(old))
    return 1;
  if (!rte_is_valid(new))
    return 0;

  if (new->attrs->pref > old->attrs->pref)
    return 1;
  if (new->attrs->pref < old->attrs->pref)
    return 0;
  if (new->src->proto->proto != old->src->proto->proto)
    {
      /*
       *  If the user has configured protocol preferences, so that two different protocols
       *  have the same preference, try to break the tie by comparing addresses. Not too
       *  useful, but keeps the ordering of routes unambiguous.
       */
      return new->src->proto->proto > old->src->proto->proto;
    }
  if (better = new->src->proto->rte_better)
    return better(new, old);
  return 0;
}

static int
rte_mergable(struct rte_storage *pri, struct rte_storage *sec)
{
  int (*mergable)(struct rte_storage *, struct rte_storage *);

  if (!rte_is_valid(pri) || !rte_is_valid(sec))
    return 0;

  if (pri->attrs->pref != sec->attrs->pref)
    return 0;

  if (pri->src->proto->proto != sec->src->proto->proto)
    return 0;

  if (mergable = pri->src->proto->rte_mergable)
    return mergable(pri, sec);

  return 0;
}

static void
rte_trace(struct channel *c, rte *e, int dir, const char *msg)
{
  log(L_TRACE "%s.%s %c %s %N %s",
      c->proto->name, c->name ?: "?", dir, msg, e->net,
      e->attrs ? rta_dest_name(e->attrs->dest) : "-");
}

static inline void
rte_trace_in(uint flag, struct channel *c, rte *e, const char *msg)
{
  if ((c->debug & flag) || (c->proto->debug & flag))
    rte_trace(c, e, '>', msg);
}

static inline void
rte_trace_out(uint flag, struct channel *c, rte *e, const char *msg)
{
  if ((c->debug & flag) || (c->proto->debug & flag))
    rte_trace(c, e, '<', msg);
}

static void
export_filter(struct channel *c, struct rte *rt, linpool *pool, int silent)
{
  struct proto *p = c->proto;
  const struct filter *filter = c->out_filter;
  struct export_stats *stats = &c->export_stats;

  /* Do nothing if we have already rejected the route */
  if (silent && bmap_test(&c->export_reject_map, rt->id))
    goto reject_noset;

  int v = p->preexport ? p->preexport(c, rt) : 0;
  if (v < 0)
    {
      if (silent)
	goto reject_noset;

      stats->updates_rejected++;
      if (v == RIC_REJECT)
	rte_trace_out(D_FILTERS, c, rt, "rejected by protocol");
      goto reject_noset;

    }
  if (v > 0)
    {
      if (!silent)
	rte_trace_out(D_FILTERS, c, rt, "forced accept by protocol");
      goto accept;
    }

  v = filter && ((filter == FILTER_REJECT) ||
		 (f_run(filter, rt, pool,
			(silent ? FF_SILENT : 0)) > F_ACCEPT));
  if (v)
    {
      if (silent)
	goto reject;

      stats->updates_filtered++;
      rte_trace_out(D_FILTERS, c, rt, "filtered out");
      goto reject;
    }

 accept:
  /* We have accepted the route */
  bmap_clear(&c->export_reject_map, rt->id);
  return;

 reject:
  /* We have rejected the route by filter */
  the_bird_lock();
  bmap_set(&c->export_reject_map, rt->id);
  the_bird_unlock();

reject_noset:
  /* Invalidate the route */
  rt->attrs = NULL;
  return;
}

static void
do_rt_notify(struct channel *c, linpool *lp, const net_addr *n, rte *new, struct rte_storage *old, int refeed)
{
  struct proto *p = c->proto;
  struct export_stats *stats = &c->export_stats;

  birdloop_enter(&main_birdloop);

  if (c->export_state > ES_READY)
  {
    /* Situation has suddenly changed. No more exporting! */
    birdloop_leave(&main_birdloop);
    return;
  }

  if (refeed && new)
    c->refeed_count++;

  /* Apply export limit */
  struct channel_limit *l = &c->out_limit;
  if (l->action && !old && new)
  {
    if (stats->routes >= l->limit)
      channel_notify_limit(c, l, PLD_OUT, stats->routes);

    if (l->state == PLS_BLOCKED)
    {
      stats->updates_rejected++;
      rte_trace_out(D_FILTERS, c, new, "rejected [limit]");
      the_bird_unlock();
      return;
    }
  }

  /* Apply export table */
  struct rte_storage *old_exported = NULL;
  if (c->out_table)
  {
    if (!rte_update_out(c, lp, new, old, &old_exported))
    {
      rte_trace_out(D_ROUTES, c, new, "idempotent");
      the_bird_unlock();
      return;
    }
  }

  if (new)
    stats->updates_accepted++;
  else
    stats->withdraws_accepted++;

  if (old)
  {
    bmap_clear(&c->export_map, old->id);
    stats->routes--;
  }

  if (new)
  {
    bmap_set(&c->export_map, new->id);
    stats->routes++;
  }

  if (p->debug & D_ROUTES)
  {
    if (new && old)
      rte_trace_out(D_ROUTES, c, new, "replaced");
    else if (new)
      rte_trace_out(D_ROUTES, c, new, "added");
    else if (old)
    {
      rte old_copy = rte_copy(old);
      rte_trace_out(D_ROUTES, c, &old_copy, "removed");
    }
  }

  p->rt_notify(p, c, lp, n, new, c->out_table ? old_exported : old);

  if (c->out_table && old_exported)
  {
    RT_LOCK(c->out_table);
    net *net = old_exported->net;
    rte_free(RT_PRIV(c->out_table), old_exported);

    if (!net->routes)
      fib_delete(&RT_PRIV(c->out_table)->fib, net);

    RT_UNLOCK(c->out_table);
  }

  birdloop_leave(&main_birdloop);
}

static void
rt_notify_basic(struct channel *c, linpool *lp, const net_addr *n, struct rte_storage *new, struct rte_storage *old, int refeed)
{
  // struct proto *p = c->proto;

  if (new)
    c->export_stats.updates_received++;
  else
    c->export_stats.withdraws_received++;

  struct rte new0 = {};
  if (new)
  {
    new0 = rte_copy(new);
    export_filter(c, &new0, lp, 0);
    if (!new0.attrs)
      new = NULL;
  }

  if (old && !bmap_test(&c->export_map, old->id))
    old = NULL;

  if (!new && !old)
    return;

  do_rt_notify(c, lp, n, new ? &new0 : NULL, old, refeed);
}

static void
rt_notify_accepted(struct channel *c, linpool *lp, const net_addr *n,
    struct rt_pending_export *rpe, struct rt_pending_export *rpe_last,
    struct rte_storage **feed, uint count, int refeed)
{
  DBG("rt_notify_accepted(%s.%s, %p, %N, %lu, %lu, %p, %u, %d)\n",
      c->proto->name, c->name, lp, n,
      rpe ? rpe->seq : 0, rpe_last ? rpe_last->seq : 0,
      feed, count, refeed);

  // struct proto *p = c->proto;
  rte new_best = {};
  struct rte_storage *old_best = NULL;

  for (uint i = 0; i < count; i++)
  {
    if (!rte_is_valid(feed[i]))
      continue;

    /* Has been already rejected, won't bother with it */
    if (!refeed && bmap_test(&c->export_reject_map, feed[i]->id))
      continue;

    /* Previously exported */
    if (!old_best && bmap_test(&c->export_map, feed[i]->id))
    {
      /* is still best */
      if (!new_best.attrs)
      {
	DBG("rt_notify_accepted: idempotent\n");
	return;
      }

      /* is superseded */
      old_best = feed[i];
      break;
    }

    /* Have no new best route yet */
    if (!new_best.attrs)
    {
      /* Try this route not seen before */
      new_best = rte_copy(feed[i]);
      export_filter(c, &new_best, lp, 0);
      DBG("rt_notify_accepted: checking route id %u: %s\n", feed[i]->id, new_best.attrs ? "ok" : "no");
    }
  }

  /* Check obsolete routes for previously exported */
  if (!old_best)
    for (; rpe; rpe = atomic_load_explicit(&rpe->next, memory_order_relaxed))
    {
      if (rpe->old && bmap_test(&c->export_map, rpe->old->id))
      {
	old_best = rpe->old;
	break;
      }

      if (rpe == rpe_last)
	break;
    }

  /* Nothing to export */
  if (!new_best.attrs && !old_best)
  {
    DBG("rt_notify_accepted: nothing to export\n");
    return;
  }

  do_rt_notify(c, lp, n, new_best.attrs ? &new_best : NULL, old_best, refeed);
}


static struct nexthop *
nexthop_merge_rta(struct nexthop *nhs, rta *a, linpool *pool, int max)
{
  return nexthop_merge(nhs, &(a->nh), 1, 0, max, pool);
}

static rte *
rt_export_merged(struct channel *c, struct rte_storage **feed, uint count, rte *best, linpool *pool, int silent, int refeed)
{
  // struct proto *p = c->proto;
  struct nexthop *nhs = NULL;
  struct rte_storage *best0 = feed[0];

  if (!rte_is_valid(best0))
    return NULL;

  /* Already rejected, no need to re-run the filter */
  if (!refeed && bmap_test(&c->export_reject_map, best0->id))
    return NULL;

  *best = rte_copy(best0);
  export_filter(c, best, pool, silent);
  if (!best->attrs)
    /* Best route doesn't pass the filter */
    return NULL;

  if (!rte_is_reachable(best))
    /* Unreachable routes can't be merged */
    return best;

  for (uint i = 1; i < count; i++)
  {
    if (!rte_mergable(best0, feed[i]))
      continue;

    rte tmp = rte_copy(feed[i]);
    export_filter(c, &tmp, pool, 1);
    if (!tmp.attrs)
      continue;

    if (!rte_is_reachable(&tmp))
      continue;

    nhs = nexthop_merge_rta(nhs, tmp.attrs, pool, c->merge_limit);
  }

  if (nhs)
  {
    nhs = nexthop_merge_rta(nhs, best->attrs, pool, c->merge_limit);

    if (nhs->next)
    {
      best->attrs = rta_cow(best->attrs, pool);
      nexthop_link(best->attrs, nhs);
    }
  }

  return best;
}


static void
rt_notify_merged(struct channel *c, linpool *lp, const net_addr *n,
    struct rt_pending_export *rpe, struct rt_pending_export *rpe_last,
    struct rte_storage **feed, uint count, int refeed)
{
  // struct proto *p = c->proto;

#if 0 /* TODO: Find whether this check is possible when processing multiple changes at once. */
  /* Check whether the change is relevant to the merged route */
  if ((new_best == old_best) &&
      (new_changed != old_changed) &&
      !rte_mergable(new_best, new_changed) &&
      !rte_mergable(old_best, old_changed))
    return;
#endif

  struct rte_storage *old_best = NULL;
  /* Find old best route */
  for (uint i = 0; i < count; i++)
    if (bmap_test(&c->export_map, feed[i]->id))
    {
      old_best = feed[i];
      break;
    }

  /* Check obsolete routes for previously exported */
  if (!old_best)
    for (; rpe; rpe = atomic_load_explicit(&rpe->next, memory_order_relaxed))
    {
      if (rpe->old && bmap_test(&c->export_map, rpe->old->id))
      {
	old_best = rpe->old;
	break;
      }

      if (rpe == rpe_last)
	break;
    }

  /* Prepare new merged route */
  rte new_merged0 = {}, *new_merged = NULL;
  if (count)
    new_merged = rt_export_merged(c, feed, count, &new_merged0, lp, 0, refeed);

  if (!new_merged && !old_best)
    return;

  do_rt_notify(c, lp, n, new_merged, old_best, refeed);
}

static void
rte_export_mark_seen(struct channel *c, struct rt_pending_export *first, struct rt_pending_export *last)
{
  if (!first || !last)
    return;

  the_bird_lock();
  for (struct rt_pending_export *rpen = first;
      rpen;
      rpen = atomic_load_explicit(&rpen->next, memory_order_relaxed))
  {
    ASSERT_DIE(rpen->seq <= last->seq);
    bmap_set(&c->export_seen_map, rpen->seq);
    if (rpen->seq == last->seq)
    {
      ASSERT_DIE(rpen == last);
      the_bird_unlock();
      return;
    }
  }

  bug("Sequential export order messed up");
}

static uint
rte_feed_count(net *n)
{
  uint count = 0;
  for (struct rte_storage *e = n->routes; e; e = e->next)
    if (rte_is_valid(e))
      count++;
  return count;
}

static void
rte_feed_obtain(net *n, struct rte_storage **feed, uint count)
{
  uint i = 0;
  for (struct rte_storage *e = n->routes; e; e = e->next)
    if (rte_is_valid(e))
    {
      ASSERT_DIE(i < count);
      feed[i++] = e;
    }
  ASSERT_DIE(i == count);
}

#define FEED_MAX_COUNT 256

struct rte_feed_info {
  uint feed_pos;
  uint count;
  const net_addr *n;
  struct rt_pending_export *first;
  struct rt_pending_export *last;
};

static _Bool
rte_feed(struct channel *c, linpool *lp)
{
  /* First we need some routes to feed */
  RT_LOCK(c->table);
  rtable_private *tab = RT_PRIV(c->table);

  uint feed_count = 0;
  uint info_count = 0;
  struct rte_storage **feed = NULL;
  struct rte_feed_info *info = NULL;

  _Bool put = 0;

  FIB_ITERATE_START(&tab->fib, &c->feed_fit, net, n)
    {
      uint count = (c->ra_mode == RA_OPTIMAL) ? !!rte_is_valid(n->routes) : rte_feed_count(n);

      /* No valid routes, just continue */
      if (!count)
	goto next;

      /* First run */
      if (!feed)
      {
	/* Also the last one */
	if (count > FEED_MAX_COUNT)
	{
	  feed = alloca(count * sizeof(struct rte_storage *));
	  info = alloca(sizeof(struct rte_feed_info));

	  put = 1;
	}
	else
	{
	  feed = alloca(FEED_MAX_COUNT * sizeof(struct rte_storage *));
	  info = alloca(FEED_MAX_COUNT * sizeof(struct rte_feed_info));
	}
      }

      /* Too many routes to add, leave for next time */
      else if (count + feed_count > FEED_MAX_COUNT)
      {
	put = 1;
	FIB_ITERATE_PUT(&c->feed_fit);
	break;
      }

      struct rt_pending_export_fib_node *rpefn = fib_get(&tab->export_fib, n->n.addr);

      info[info_count++] = (struct rte_feed_info) {
	.feed_pos = feed_count,
	.count = count,
	.n = n->n.addr,
	.first = rpefn ? rpefn->first : NULL,
	.last = rpefn ? rpefn->last : NULL,
      };
	  
      /* Dump the routes */
      if (c->ra_mode == RA_OPTIMAL)
	feed[feed_count] = n->routes;
      else
	rte_feed_obtain(n, &feed[feed_count], count);

      feed_count += count;

      /* Single net put */
      if (put)
      {
	FIB_ITERATE_PUT_NEXT(&c->feed_fit, &tab->fib);
	break;
      }
next:;
    }
  FIB_ITERATE_END;
	
  RT_UNLOCK(c->table);

  /* Now we have to process the dumps one after another */
  switch (c->ra_mode)
  {
    case RA_OPTIMAL:
    case RA_ANY:
      for (uint i = 0; i < info_count; i++)
      {
	for (uint f = 0; f < info[i].count; f++)
	  rt_notify_basic(c, lp, info[i].n, feed[info[i].feed_pos + f], NULL, c->refeeding);

	rte_export_mark_seen(c, info[i].first, info[i].last);
      }
      break;
    case RA_ACCEPTED:
      for (uint i = 0; i < info_count; i++)
      {
	rt_notify_accepted(c, lp, info[i].n, NULL, NULL, &feed[info[i].feed_pos], info[i].count, c->refeeding);
	rte_export_mark_seen(c, info[i].first, info[i].last);
      }
      break;
    case RA_MERGED:
      for (uint i = 0; i < info_count; i++)
      {
	rt_notify_merged(c, lp, info[i].n, NULL, NULL, &feed[info[i].feed_pos], info[i].count, c->refeeding);
	rte_export_mark_seen(c, info[i].first, info[i].last);
      }
      break;
    default:
      bug("Feeding a channel with a strange route announcement mode: %u", c->ra_mode);
  }

  return put;
}

static void
rte_export(struct channel *c, linpool *lp, struct rt_pending_export *rpe)
{
  if (bmap_test(&c->export_seen_map, rpe->seq))
    return;

  net *net = rpe->new_best ? rpe->new_best->net : rpe->old_best->net;
  const net_addr *n = net->n.addr;

  switch (c->ra_mode)
  {
    case RA_OPTIMAL:
      {
	struct rte_storage *old = rpe->old_best, *new = rpe->new_best;
	struct rt_pending_export *rpe_last = rpe;
	for (struct rt_pending_export *rpen;
	    rpen = atomic_load_explicit(&rpe_last->next, memory_order_relaxed);
	    rpe_last = rpen)
	{
	  ASSERT_DIE(new == rpen->old_best);
	  new = rpen->new_best;
	}

	if (new != old)
	  rt_notify_basic(c, lp, n, new, old, 0);

	rte_export_mark_seen(c, rpe, rpe_last);
	return;
      }
    case RA_ANY:
      {
	struct rt_pending_export *rpe_last;
	for (struct rt_pending_export *rpen = rpe;
	    rpen;
	    rpen = atomic_load_explicit(&rpen->next, memory_order_relaxed))
	{
	  rt_notify_basic(c, lp, n, rpen->new, rpen->old, 0);
	  rpe_last = rpen;
	}

	rte_export_mark_seen(c, rpe, rpe_last);
	return;
      }
    case RA_ACCEPTED:
    {
      struct rt_pending_export *rpe_last = rpe;
      for (struct rt_pending_export *rpen;
	  rpen = atomic_load_explicit(&rpe_last->next, memory_order_relaxed);
	  rpe_last = rpen)
	;

      RT_LOCK(c->table);
      uint count = rte_feed_count(net);
      struct rte_storage **feed = alloca(count * sizeof(struct rte_storage *));
      rte_feed_obtain(net, feed, count);
      RT_UNLOCK(c->table);

      rt_notify_accepted(c, lp, n, rpe, rpe_last, feed, count, 0);
      rte_export_mark_seen(c, rpe, rpe_last);

      return;
    }
    case RA_MERGED:
    {
      struct rt_pending_export *rpe_last = rpe;
      for (struct rt_pending_export *rpen;
	  rpen = atomic_load_explicit(&rpe_last->next, memory_order_relaxed);
	  rpe_last = rpen)
	;

      RT_LOCK(c->table);
      uint count = rte_feed_count(net);
      struct rte_storage **feed = alloca(count * sizeof(struct rte_storage *));
      rte_feed_obtain(net, feed, count);
      RT_UNLOCK(c->table);

      rt_notify_merged(c, lp, n, rpe, rpe_last, feed, count, 0);
      rte_export_mark_seen(c, rpe, rpe_last);

      return;
    }
  }
}


/**
 * rte_announce - announce a routing table change
 * @tab: table the route has been added to
 * @net: network in question
 * @new: the new or changed route
 * @old: the previous route replaced by the new one
 * @new_best: the new best route for the same network
 * @old_best: the previous best route for the same network
 *
 * This function gets a routing table update and announces it to all protocols
 * that are connected to the same table by their channels.
 *
 * There are two ways of how routing table changes are announced. First, there
 * is a change of just one route in @net (which may caused a change of the best
 * route of the network). In this case @new and @old describes the changed route
 * and @new_best and @old_best describes best routes. Other routes are not
 * affected, but in sorted table the order of other routes might change.
 *
 * The function announces the change to all associated channels. For each
 * channel, an appropriate preprocessing is done according to channel &ra_mode.
 * For example, %RA_OPTIMAL channels receive just changes of best routes.
 *
 * In general, we first call preexport() hook of a protocol, which performs
 * basic checks on the route (each protocol has a right to veto or force accept
 * of the route before any filter is asked). Then we consult an export filter
 * of the channel and verify the old route in an export map of the channel.
 * Finally, the rt_notify() hook of the protocol gets called.
 *
 * Note that there are also calls of rt_notify() hooks due to feed, but that is
 * done outside of scope of rte_announce().
 */
static void
rte_announce(rtable_private *tab, net *net, struct rte_storage *new, struct rte_storage *old,
	     struct rte_storage *new_best, struct rte_storage *old_best)
{
  if (!rte_is_valid(new))
    new = NULL;

  if (!rte_is_valid(old))
    old = NULL;

  if (!rte_is_valid(new_best))
    new_best = NULL;

  if (!rte_is_valid(old_best))
    old_best = NULL;

  if (!new && !old && !new_best && !old_best)
  {
    DBG("rte_announce table=%s net=%N: nothing to do\n", tab->name, net->n.addr);
    return;
  }

  if (new_best != old_best)
  {
    if (new_best)
      new_best->sender->import_stats.pref++;
    if (old_best)
      old_best->sender->import_stats.pref--;

    if (tab->hostcache)
      rt_notify_hostcache(tab, net);
  }

  rt_schedule_notify(tab);

  /* Get the same-network squasher pointer */
  struct rt_pending_export_fib_node *rpefn = fib_get(&tab->export_fib, net->n.addr);

  /* Get the pending export structure */
  struct rt_export_block *rpeb = NULL, *rpebsnl = NULL;
  u16 end = 0;

  if (!EMPTY_LIST(tab->pending_exports))
  {
    rpeb = TAIL(tab->pending_exports);
    end = atomic_load_explicit(&rpeb->end, memory_order_relaxed);
    if (end >= RT_PENDING_EXPORT_ITEMS)
    {
      ASSERT_DIE(end == RT_PENDING_EXPORT_ITEMS);
      rpebsnl = rpeb;

      rpeb = NULL;
      end = 0;
    }
  }

  if (!rpeb)
  {
    rpeb = alloc_page();
    *rpeb = (struct rt_export_block) {};
    add_tail(&tab->pending_exports, &rpeb->n);
  }

  /* Fill the pending export */
  struct rt_pending_export *rpe = &rpeb->export[rpeb->end];
  *rpe = (struct rt_pending_export) {
    .new = new,
    .new_best = new_best,
    .old = old,
    .old_best = old_best,
    .seq = tab->next_export_seq++,
  };

  DBG("rte_announce: table=%s net=%N new=%p old=%p new_best=%p old_best=%p seq=%lu\n", tab->name, net->n.addr, new, old, new_best, old_best, rpe->seq);

  ASSERT_DIE(atomic_fetch_add_explicit(&rpeb->end, 1, memory_order_release) == end);

  if (rpebsnl)
  {
    _Bool f = 0;
    ASSERT_DIE(atomic_compare_exchange_strong_explicit(&rpebsnl->not_last, &f, 1,
	  memory_order_release, memory_order_relaxed));
  }

  /* Append to the same-network squasher list */
  if (rpefn->last)
  {
    struct rt_pending_export *rpenull = NULL;
    ASSERT_DIE(atomic_compare_exchange_strong_explicit(
	  &rpefn->last->next, &rpenull, rpe,
	  memory_order_relaxed,
	  memory_order_relaxed));
    
  }

  rpefn->last = rpe;

  if (!rpefn->first)
    rpefn->first = rpe;

  if (tab->first_export == NULL)
    tab->first_export = rpe;

  bsem_alarm(&tab->export_alarm, tab->config->export_settle_time);
}

/*
 * There are two threads running in parallel. The table is a producer, the
 * channel is a consumer. The buffer (pending export list) is owned by the
 * table and shared between multiple channels. OTOH, every channel sees exactly
 * one pending export list.
 */

static struct rt_pending_export *
channel_next_export_fast(struct rt_pending_export *last)
{
  /* Get the whole export block and find our position in there. */
  struct rt_export_block *rpeb = PAGE_HEAD(last);
  int pos = (last - &rpeb->export[0]);
  u16 end = atomic_load_explicit(&rpeb->end, memory_order_acquire);
  ASSERT_DIE(pos < end);
  ASSERT_DIE(pos >= 0);

  /* Next is in the same block. */
  if (++pos < end)
    return &rpeb->export[pos];

  /* There is another block. */
  if (atomic_load_explicit(&rpeb->not_last, memory_order_acquire))
  {
    /* This is OK to do non-atomically because of the not_last flag. */
    rpeb = NODE_NEXT(rpeb);
    return &rpeb->export[0];
  }

  /* There is nothing more. */
  return NULL;
}

static struct rt_pending_export *
channel_next_export(struct channel *c, rtable_private *tab)
{
  /* As the table is locked, it is safe to reload the last export pointer */
  struct rt_pending_export *last = atomic_load_explicit(&c->last_export, memory_order_acquire);

  /* It is still valid, let's reuse it */
  if (last)
    return channel_next_export_fast(last);

  /* No, therefore we must process the table's first pending export */
  else
    return tab->first_export;
}

static void
rt_announce_exports(rtable_private *tab)
{
  struct channel *c; node *n;
  WALK_LIST2(c, n, tab->channels, table_node)
  {
    if (c->export_state != ES_READY)
      continue;

    bsem_post(c->export_sem);
  }
}

static struct rt_pending_export *
rt_last_export(rtable_private *tab)
{
  struct rt_pending_export *rpe = NULL;

  if (!EMPTY_LIST(tab->pending_exports))
  {
    /* We'll continue processing exports from this export on */
    struct rt_export_block *reb = TAIL(tab->pending_exports);
    ASSERT_DIE(reb->end);
    rpe = &reb->export[reb->end - 1];
  }

  return rpe;
}

void
channel_export_coro(void *_c)
{
  /* This is a coroutine. This is run unlocked. */
  struct channel *c = _c;

  _Bool feeding = 0;

  linpool *lp = NULL;
  struct rt_pending_export *rpe = NULL;

  while (1)
  {
    if (lp)
      lp_flush(lp);

    uint es = atomic_load_explicit(&c->export_state, memory_order_acquire);
    switch (es)
    {
      /* Feed initialization */
      case ES_HUNGRY:
	birdloop_enter(&main_birdloop);
	if (atomic_load_explicit(&c->export_state, memory_order_acquire) != ES_HUNGRY)
	{
	  birdloop_leave(&main_birdloop);
	  continue;
	}

	DBG("Export coro %s.%s: ES_HUNGRY\n", c->proto->name, c->name);
	feeding = 1;

	if (c->proto->feed_begin)
	  c->proto->feed_begin(c, !c->refeeding);

	if (!lp)
	  lp = lp_new_default(c->proto->pool);

	bmap_init(&c->export_seen_map, c->proto->pool, 1024);

init_channel_feed:
	RT_LOCK(c->table);

	c->refeed_count = 0;
	atomic_store_explicit(&c->export_state, ES_FEEDING, memory_order_release);

	atomic_store_explicit(&c->last_export, rt_last_export(RT_PRIV(c->table)), memory_order_relaxed);
	FIB_ITERATE_INIT(&c->feed_fit, &RT_PRIV(c->table)->fib);

	RT_UNLOCK(c->table);

	birdloop_ping(&main_birdloop);
	birdloop_leave(&main_birdloop);
	/* fall through */

      /* Regular feeding */
      case ES_FEEDING:
	{
	  if (rte_feed(c, lp))
	    continue;

	  DBG("Export coro %s.%s: feeding done\n", c->proto->name, c->name);

	  birdloop_enter(&main_birdloop);
	  if (atomic_load_explicit(&c->export_state, memory_order_acquire) != ES_FEEDING)
	  {
	    birdloop_leave(&main_birdloop);
	    continue;
	  }

	  /* Reset export limit if the feed ended with acceptable number of exported routes */
	  struct channel_limit *l = &c->out_limit;
	  if (c->refeeding &&
	      (l->state == PLS_BLOCKED) &&
	      (c->refeed_count <= l->limit) &&
	      (c->export_stats.routes <= l->limit))
	  {
	    log(L_INFO "Protocol %s resets route export limit (%u)", c->proto->name, l->limit);
	    channel_reset_limit(&c->out_limit);

	    /* Continue in feed internally - it will process routing table again from beginning */
	    bmap_reset(&c->export_seen_map, 1024);

	    /* This jump is done inside the_bird locked context */
	    goto init_channel_feed;
	  }

	  if (c->proto->feed_end)
	    c->proto->feed_end(c);

	  RT_LOCK(c->table);
	  feeding = 0;

	  /* We must acquire the channel's next export before we actually set ES_READY
	   * to mitigate possible table export cleanup inbetween. */
	  rpe = channel_next_export(c, RT_PRIV(c->table));

	  /* Now we're done with feeds. */
	  atomic_store_explicit(&c->export_state, ES_READY, memory_order_release);
	  DBG("Export coro %s.%s: switched to normal export mode\n", c->proto->name, c->name);
	  RT_UNLOCK(c->table);

	  channel_log_state_change(c);

	  if (c->refeed_pending)
	  {
	    channel_request_feeding(c);
	    birdloop_leave(&main_birdloop);
	    break;
	  }

	  birdloop_leave(&main_birdloop);
	}
	/* fall through */

      /* Regular export */
      case ES_READY:
	{
	  /* There is no export known from previous stages, try to load */
	  if (!rpe)
	  {
	    /* Next export loading may clash with table cleanup */
	    RT_LOCK(c->table);
	    rpe = channel_next_export(c, RT_PRIV(c->table));
	    RT_UNLOCK(c->table);
	  }

	  /* There is no export at all */
	  if (!rpe)
	    break;

	  /* Process the export */
	  rte_export(c, lp, rpe);

	  /* Cleaning up the old route rejection bit */
	  if (rpe->old)
	    bmap_clear(&c->export_reject_map, rpe->old->id);

	  /* Get the next export if exists */
	  struct rt_pending_export *rpe_next = channel_next_export_fast(rpe);

	  /* The last block may be available to free */
	  if (PAGE_HEAD(rpe_next) != PAGE_HEAD(rpe))
	    rt_export_used(c->table);

	  /* Releasing this export for cleanup routine */
	  atomic_store_explicit(&c->last_export, rpe, memory_order_release);
	  rpe = rpe_next;
	  continue;
	}

      /* Stop requested */
      case ES_STOP:
      case ES_RESTART:
	DBG("Export coro %s.%s: %s requested\n", c->proto->name, c->name,
	    (es == ES_STOP) ? "stop" : "restart");

	birdloop_enter(&main_birdloop);
	if (atomic_load_explicit(&c->export_state, memory_order_acquire) != es)
	{
	  birdloop_leave(&main_birdloop);
	  continue;
	}

	if (feeding)
	{
	  RT_LOCK(c->table);
	  fit_get(&RT_PRIV(c->table)->fib, &c->feed_fit);
	  RT_UNLOCK(c->table);
	}

	/* Stop may be requested before the export actually gets initialized */
	if (c->export_seen_map.data)
	  bmap_free(&c->export_seen_map);

	if (lp)
	  rfree(lp);

	/* The coroutine must be freed from itself. */
	rfree(c->export_coro);
	c->export_coro = NULL;

	/* Reporting the channel as stopped. */
	channel_export_stopped(c);

	DBG("Export coroutine of %s.%s finished", c->proto->name, c->name);

	/* Finishing */
	birdloop_ping(&main_birdloop);
	birdloop_leave(&main_birdloop);

	return;

      case ES_DOWN:
	bug("Export coroutine of %s.%s running while ES_DOWN", c->proto->name, c->name);

      default:
	bug("Broken export state of %s.%s: %u", c->proto->name, c->name, es);
    }

    bsem_wait_all(c->export_sem);
  }
}

static int
rte_same(struct rte_storage *x, rte *y, _Bool fy)
{
  /* rte.flags are not checked, as they are mostly internal to rtable */
  return
    x->attrs == y->attrs &&
    x->src == y->src &&
    rte_is_filtered(x) == fy;
}

static void NONNULL(1,2,3)
rte_recalculate(struct channel *c, net *net, rte *new, _Bool filtered)
{
  struct proto *p = c->proto;
  rtable_private *table = RT_PRIV(c->table);
  struct import_stats *stats = &c->import_stats;
  struct rte_storage *old_best = net->routes;
  struct rte_storage *old = NULL, **before_old = NULL;

  /* Find and remove original route from the same protocol */
  for (before_old = &net->routes; old = *before_old; before_old = &(old->next))
    {
      /* Another route */
      if (old->src != new->src)
	continue;

      /* If there is the same route in the routing table but from
       * a different sender, then there are two paths from the
       * source protocol to this routing table through transparent
       * pipes, which is not allowed.
       * We log that and ignore the route. */
      if (old->sender->proto != p)
	{
	  if (!old->generation && !new->generation)
	    bug("Two protocols claim to author a route with the same rte_src in table %s: %N %s/%u:%u",
		c->table->name, net->n.addr, old->src->proto->name, old->src->private_id, old->src->global_id);

	  log_rl(&rl_pipe, L_ERR "Route source collision in table %s: %N %s/%u:%u",
		c->table->name, net->n.addr, old->src->proto->name, old->src->private_id, old->src->global_id);

	  if (config->pipe_debug)
	  {
	    if (old->generation)
	      old->sender->proto->rte_track(old->sender, net->n.addr, old->src);

	    if (new->generation)
	      c->proto->rte_track(c, net->n.addr, new->src);
	  }

	  return;
	}

      if (new->attrs && rte_same(old, new, filtered))
	{
	  /* No changes, ignore the new route and refresh the old one */

	  old->flags &= ~(REF_STALE | REF_DISCARD | REF_MODIFY);

	  if (!filtered)
	    {
	      stats->updates_ignored++;
	      rte_trace_in(D_ROUTES, c, new, "ignored");
	    }

	  return;
	}
      *before_old = old->next;
      table->rt_count--;
      break;
    }

  if (!old && !new->attrs)
    {
      stats->withdraws_ignored++;
      return;
    }

  _Bool new_ok = new->attrs && !filtered;
  _Bool old_ok = old && !rte_is_filtered(old);

  struct channel_limit *l = &c->rx_limit;
  if (l->action && !old && new->attrs && !c->in_table)
    {
      u32 all_routes = stats->routes + stats->filtered;

      if (all_routes >= l->limit)
	channel_notify_limit(c, l, PLD_RX, all_routes);

      if (l->state == PLS_BLOCKED)
	{
	  /* In receive limit the situation is simple, old is NULL so
	     we just free new and exit like nothing happened */

	  stats->updates_ignored++;
	  rte_trace_in(D_FILTERS, c, new, "ignored [limit]");
	  return;
	}
    }

  l = &c->in_limit;
  if (l->action && !old_ok && new_ok)
    {
      if (stats->routes >= l->limit)
	channel_notify_limit(c, l, PLD_IN, stats->routes);

      if (l->state == PLS_BLOCKED)
	{
	  /* In import limit the situation is more complicated. We
	     shouldn't just drop the route, we should handle it like
	     it was filtered. We also have to continue the route
	     processing if old or new is non-NULL, but we should exit
	     if both are NULL as this case is probably assumed to be
	     already handled. */

	  stats->updates_ignored++;
	  rte_trace_in(D_FILTERS, c, new, "ignored [limit]");

	  if (c->in_keep_filtered)
	    filtered = 1;
	  else
	    new->attrs = NULL;

	  /* Note that old && !new could be possible when
	     c->in_keep_filtered changed in the recent past. */

	  if (!old && !new->attrs)
	    return;

	  new_ok = 0;
	  goto skip_stats1;
	}
    }

  if (new_ok)
    stats->updates_accepted++;
  else if (old_ok)
    stats->withdraws_accepted++;
  else
    stats->withdraws_ignored++;

  if (old_ok || new_ok)
    table->last_rt_change = current_time();

 skip_stats1:

  if (new->attrs)
    filtered ? stats->filtered++ : stats->routes++;
  if (old)
    rte_is_filtered(old) ? stats->filtered-- : stats->routes--;

  /* Store the new route now, it is going to be inserted. */
  struct rte_storage *new_stored = NULL;

  if (new->attrs) {
    new_stored = rte_store(table, new, net);
    new_stored->sender = c;

    if (filtered)
      new_stored->flags |= REF_FILTERED;
  }

  if (table->config->sorted)
    {
      /* If routes are sorted, just insert new route to appropriate position */
      if (new_stored)
	{
	  if (!*before_old || rte_better(new_stored, *before_old))
	    before_old = &net->routes;

	  for (; *before_old; before_old = &(*before_old)->next)
	    if (rte_better(new_stored, *before_old))
	      break;

	  new_stored->next = *before_old;
	  *before_old = new_stored;

	  table->rt_count++;
	}
    }
  else
    {
      /* If routes are not sorted, find the best route and move it on
	 the first position. There are several optimized cases. */

      if (new->src->proto->rte_recalculate && new->src->proto->rte_recalculate(table, net, new_stored, old, old_best))
	goto do_recalculate;

      if (new_stored && rte_better(new_stored, old_best))
	{
	  /* The first case - the new route is cleary optimal,
	     we link it at the first position */

	  new_stored->next = net->routes;
	  net->routes = new_stored;

	  table->rt_count++;
	}
      else if (old == old_best)
	{
	  /* The second case - the old best route disappeared, we add the
	     new route (if we have any) to the list (we don't care about
	     position) and then we elect the new optimal route and relink
	     that route at the first position and announce it. New optimal
	     route might be NULL if there is no more routes */

	do_recalculate:
	  /* Add the new route to the list */
	  if (new_stored)
	    {
	      new_stored->next = *before_old;
	      *before_old = new_stored;
	      table->rt_count++;
	    }

	  /* Find a new optimal route (if there is any) */
	  if (net->routes)
	    {
	      struct rte_storage **bp = &net->routes;
	      for (struct rte_storage **k=&(*bp)->next; *k; k=&(*k)->next)
		if (rte_better(*k, *bp))
		  bp = k;

	      /* And relink it */
	      struct rte_storage *best = *bp;
	      *bp = best->next;
	      best->next = net->routes;
	      net->routes = best;
	    }
	}
      else if (new_stored)
	{
	  /* The third case - the new route is not better than the old
	     best route (therefore old_best != NULL) and the old best
	     route was not removed (therefore old_best == net->routes).
	     We just link the new route to the old/last position. */

	  new_stored->next = *before_old;
	  *before_old = new_stored;

	  table->rt_count++;
	}
      /* The fourth (empty) case - suboptimal route was removed, nothing to do */
    }

  if (new_stored)
    {
      new_stored->lastmod = current_time();

      new_stored->id = hmap_first_zero(&table->id_map);
      hmap_set(&table->id_map, new_stored->id);
    }

  /* Log the route change */
  if ((c->debug & D_ROUTES) || (p->debug & D_ROUTES))
    {
      if (new_ok)
	rte_trace(c, new, '>', new_stored == net->routes ? "added [best]" : "added");
      else if (old_ok)
	{
	  rte old_copy = rte_copy(old);
	  if (old != old_best)
	    rte_trace(c, &old_copy, '>', "removed");
	  else if (net->routes && !rte_is_filtered(net->routes))
	    rte_trace(c, &old_copy, '>', "removed [replaced]");
	  else
	    rte_trace(c, &old_copy, '>', "removed [sole]");
	}
    }

  /* Propagate the route change */
  rte_announce(table, net, new_stored, old, net->routes, old_best);

  if (!net->routes &&
      (table->gc_counter++ >= table->config->gc_max_ops) &&
      (table->gc_time + table->config->gc_min_time <= current_time()))
    rt_schedule_prune(table);

  if (old_ok && p->rte_remove)
    p->rte_remove(net, old);
  if (new_ok && p->rte_insert)
    p->rte_insert(net, new_stored);
}

static int NONNULL(1,2) rte_update_in(struct channel *c, rte *new);
static void NONNULL(1,2) rte_update2(struct channel *c, rte *new, linpool *lp);

void NONNULL(1,2)
rte_update(struct channel *c, rte *new, linpool *lp)
{
  ASSERT(c->channel_state == CS_UP);
  ASSERT(new->net);
  ASSERT(new->src);

  if (new->attrs && !new->attrs->pref)
  {
    ASSERT(!new->attrs->cached);
    new->attrs->pref = c->preference;
  }

  if (c->in_table && !rte_update_in(c, new))
    return;

  rte_update2(c, new, lp);
}

static void NONNULL(1,2)
rte_update2(struct channel *c, rte *new, linpool *lp)
{
  struct proto *p = c->proto;
  struct import_stats *stats = &c->import_stats;
  const struct filter *filter = c->in_filter;

  _Bool filtered = 0;

  if (new->generation && !p->rte_track)
    bug("Announced a non-authored route without rte_track() implemented");

  if (new->attrs)
    stats->updates_received++;
  else
    stats->withdraws_received++;

  if (!net_validate(new->net))
  {
    log(L_WARN "Ignoring bogus prefix %N received via %s.%s",
	new->net, c->proto->name, c->name);
    goto invalid;
  }

  /* FIXME: better handling different nettypes */
  int cl = !net_is_flow(new->net) ?
    net_classify(new->net): (IADDR_HOST | SCOPE_UNIVERSE);
  if ((cl < 0) || !(cl & IADDR_HOST) || ((cl & IADDR_SCOPE_MASK) <= SCOPE_LINK))
  {
    log(L_WARN "Ignoring bogus route %N received via %s.%s",
	new->net, c->proto->name, c->name);
    goto invalid;
  }

  if (new->attrs)
    {
      ASSERT_DIE(lp);

      if (net_type_match(new->net, NB_DEST) == !new->attrs->dest)
      {
	log(L_WARN "Ignoring route %N with invalid dest %d received via %s.%s",
	    new->net, new->attrs->dest, c->proto->name, c->name);
	goto invalid;
      }

      if ((new->attrs->dest == RTD_UNICAST) && !nexthop_is_sorted(&(new->attrs->nh)))
      {
	log(L_WARN "Ignoring unsorted multipath route %N received via %s.%s",
	    new->net, c->proto->name, c->name);
	goto invalid;
      }

      if ((filter == FILTER_REJECT) || (filter && (f_run(filter, new, lp, 0) > F_ACCEPT)))
	{
	  stats->updates_filtered++;
	  rte_trace_in(D_FILTERS, c, new, "filtered out");
	  filtered = 1;
	}
    }

  RT_LOCK(c->table);
  rtable_private *table = RT_PRIV(c->table);

  /* Find a table record */
  net *nn;

  if (new->attrs && (!filtered || c->in_keep_filtered))
    /* This is an update and it shall pass to the table */
    nn = net_get(table, new->net);
  else
  {
    /* This is a withdraw and it need not be in the table */
    nn = net_find(table, new->net);

    if (!nn) /* No previous table record found */
    {
      if (!new->attrs) /* Regular withdraw */
	stats->withdraws_ignored++;

      RT_UNLOCK(c->table);
      return;
    }

    /* Drop the attributes as they aren't for anything now. */
    new->attrs = NULL;
  }

  /* And recalculate the best route */
  rte_recalculate(c, nn, new, filtered);
  RT_UNLOCK(c->table);
  return;

 invalid:
  if (new->attrs)
  {
    stats->updates_invalid++;
    rte_trace_in(D_FILTERS, c, new, "invalid");
  }
  else
    stats->withdraws_invalid++;

  return;
}

/* Modify existing route by protocol hook, used for long-lived graceful restart */
static inline void
rte_modify(rtable_private *tab, struct rte_storage *old)
{
  rte new = {
    .net = old->net->n.addr,
    .src = old->src,
    .attrs = old->sender->proto->rte_modify(old, tab->maint_lp),
    .generation = old->generation,
  };

  if (new.attrs != old->attrs)
    rte_recalculate(old->sender, old->net, &new, old->src);
}

/**
 * rt_refresh_begin - start a refresh cycle
 * @t: related routing table
 * @c related channel
 *
 * This function starts a refresh cycle for given routing table and announce
 * hook. The refresh cycle is a sequence where the protocol sends all its valid
 * routes to the routing table (by rte_update()). After that, all protocol
 * routes (more precisely routes with @c as @sender) not sent during the
 * refresh cycle but still in the table from the past are pruned. This is
 * implemented by marking all related routes as stale by REF_STALE flag in
 * rt_refresh_begin(), then marking all related stale routes with REF_DISCARD
 * flag in rt_refresh_end() and then removing such routes in the prune loop.
 */
void
rt_refresh_begin(rtable *t, struct channel *c)
{
  RT_LOCK(t);
  FIB_WALK(&RT_PRIV(t)->fib, net, n)
    {
      for (struct rte_storage *e = n->routes; e; e = e->next)
	if (e->sender == c)
	  e->flags |= REF_STALE;
    }
  FIB_WALK_END;
  RT_UNLOCK(t);
}

/**
 * rt_refresh_end - end a refresh cycle
 * @t: related routing table
 * @c: related channel
 *
 * This function ends a refresh cycle for given routing table and announce
 * hook. See rt_refresh_begin() for description of refresh cycles.
 */
void
rt_refresh_end(rtable *t, struct channel *c)
{
  int prune = 0;

  RT_LOCK(t);
  FIB_WALK(&RT_PRIV(t)->fib, net, n)
    {
      for (struct rte_storage *e = n->routes; e; e = e->next)
	if ((e->sender == c) && (e->flags & REF_STALE))
	  {
	    e->flags |= REF_DISCARD;
	    prune = 1;
	  }
    }
  FIB_WALK_END;

  if (prune)
    rt_schedule_prune(RT_PRIV(t));

  RT_UNLOCK(t);
}

void
rt_modify_stale(rtable *t, struct channel *c)
{
  int prune = 0;

  RT_LOCK(t);
  FIB_WALK(&RT_PRIV(t)->fib, net, n)
    {
      for (struct rte_storage *e = n->routes; e; e = e->next)
	if ((e->sender == c) && (e->flags & REF_STALE) && !(e->flags & REF_FILTERED))
	  {
	    e->flags |= REF_MODIFY;
	    prune = 1;
	  }
    }
  FIB_WALK_END;

  if (prune)
    rt_schedule_prune(RT_PRIV(t));

  RT_UNLOCK(t);
}

/**
 * rte_dump - dump a route
 * @e: &rte to be dumped
 *
 * This functions dumps contents of a &rte to debug output.
 */
void
rte_dump(struct rte_storage *e)
{
  net *n = e->net;
  debug("%-1N ", n->n.addr);
  debug("p=%s src=(%u/%u) ", e->src->proto->name, e->src->private_id, e->src->global_id);
  debug("PF=%02x ", e->pflags);
  rta_dump(e->attrs);
  debug("\n");
}

/**
 * rt_dump - dump a routing table
 * @t: routing table to be dumped
 *
 * This function dumps contents of a given routing table to debug output.
 */
void
rt_dump(rtable *t)
{
  debug("Dump of routing table <%s>\n", t->name);
  RT_LOCK(t);
#ifdef DEBUGGING
  fib_check(&RT_PRIV(t)->fib);
#endif
  FIB_WALK(&RT_PRIV(t)->fib, net, n)
    {
      for(struct rte_storage *e=n->routes; e; e=e->next)
	rte_dump(e);
    }
  FIB_WALK_END;
  debug("\n");
  RT_UNLOCK(t);
}

/**
 * rt_dump_all - dump all routing tables
 *
 * This function dumps contents of all routing tables to debug output.
 */
void
rt_dump_all(void)
{
  rtable *t;
  node *n;

  WALK_LIST2(t, n, routing_tables, n)
    rt_dump(t);
}

static inline void
rt_schedule_hcu(rtable_private *tab)
{
  if (tab->hcu_scheduled)
    return;

  tab->hcu_scheduled = 1;
  bsem_post(tab->maint_sem);
}

static inline void
rt_schedule_nhu(rtable *tab)
{
  /* state change:
   *   NHU_CLEAN   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_DIRTY
   */
  if (atomic_fetch_or_explicit(
	&tab->nhu_state,
	NHU_SCHEDULED,
	memory_order_release) == NHU_CLEAN)
    bsem_post(tab->maint_sem);
}

void
rt_schedule_prune(rtable_private *tab)
{
  /* state change 0->1, 2->3 */
  tab->prune_state |= 1;

  if (tab->prune_state == 1)
    bsem_post(tab->maint_sem);
}

void
rt_export_used(rtable *tab)
{
  if (atomic_fetch_or_explicit(
	&tab->export_used,
	1,
	memory_order_release) == 0)
    bsem_post(tab->maint_sem);
}

static void
rt_maint(void *ptr)
{
  /* Running standalone in independent context. Be aware. */
  rtable_private *tab = RT_PRIV((rtable *) ptr);

  while (1)
  {
    _Bool finish_prune = 0;

    bsem_wait(tab->maint_sem);

    RT_LOCK(tab);

    DBG("rt_maint for %s woken up at %p\n", tab->name, tab->maint_sem);

    if (tab->maint_lp)
      lp_flush(tab->maint_lp);
    else
      tab->maint_lp = lp_new_default(tab->rp);

    if (atomic_load_explicit(&tab->export_alarm.set, memory_order_acquire))
    {
      atomic_store_explicit(&tab->export_alarm.set, 0, memory_order_release);
      rt_announce_exports(tab);
    }

    if (atomic_load_explicit(&tab->export_used, memory_order_acquire))
      if (rt_export_cleanup(tab))
	finish_prune = 1;

    if (tab->hcu_scheduled)
      rt_update_hostcache(tab);

    if (atomic_load_explicit(&tab->nhu_state, memory_order_acquire))
      rt_next_hop_update(tab);

    if (tab->prune_state)
      if (rt_prune_table(tab))
	finish_prune = 1;

    if (!finish_prune && !tab->use_count && tab->deleted)
    {
      RT_UNLOCK(tab);
      /* For here, we may simply unlock as nobody knows about the table anyway. */
      the_bird_lock();
      rfree(tab);
      the_bird_unlock();
      return;
    }

    RT_UNLOCK(tab);

    if (finish_prune)
      rt_finish_prune((rtable *) ptr);
  }
}


static inline btime
rt_settled_time(rtable_private *tab)
{
  ASSUME(tab->base_settle_time != 0);

  return MIN(tab->last_rt_change + tab->config->min_settle_time,
	     tab->base_settle_time + tab->config->max_settle_time);
}

static void
rt_settle_timer(timer *t)
{
  rtable_private *tab = RT_PRIV((rtable *) t->data);
  RT_LOCK(tab);

  if (!tab->base_settle_time)
    goto done;

  btime settled_time = rt_settled_time(tab);
  if (current_time() < settled_time)
  {
    tm_set(tab->settle_timer, settled_time);
    goto done;
  }

  /* Settled */
  tab->base_settle_time = 0;

  struct rt_subscription *s;
  WALK_LIST(s, tab->subscribers)
    s->hook(s);

done:
  RT_UNLOCK(tab);
}

static void
rt_kick_settle_timer(rtable_private *tab)
{
  tab->base_settle_time = current_time();

  if (!tab->settle_timer)
    tab->settle_timer = tm_new_init(tab->rp, rt_settle_timer, tab, 0, 0);

  if (!tm_active(tab->settle_timer))
    tm_set(tab->settle_timer, rt_settled_time(tab));
}

static inline void
rt_schedule_notify(rtable_private *tab)
{
  if (EMPTY_LIST(tab->subscribers))
    return;

  if (tab->base_settle_time)
    return;

  rt_kick_settle_timer(tab);
}

void
rt_subscribe(rtable *tab_, struct rt_subscription *s)
{
  s->tab = tab_;

  RT_LOCK(tab_);
  rtable_private *tab = RT_PRIV(tab_);

  rt_lock_table(tab);
  add_tail(&tab->subscribers, &s->n);

  RT_UNLOCK(tab_);
}

void
rt_unsubscribe(struct rt_subscription *s)
{
  ASSERT_DIE(s->tab);
  RT_LOCK(s->tab);

  rem_node(&s->n);
  rt_unlock_table(RT_PRIV(s->tab));

  RT_UNLOCK(s->tab);
  s->tab = NULL;
}

static void
rt_free(resource *_r)
{
  /* Should be called always from rt_maint() */
  rtable_private *r = (rtable_private *) _r;
  struct config *conf = r->deleted;

  DBG("Deleting routing table %s\n", r->name);
  ASSERT_DIE(r->use_count == 0);

  if (r->internal)
    DOMAIN_FREE(rtable_internal, r->idom);
  else
  {
    if (r->hostcache)
      rt_free_hostcache(r);

    r->config->table = NULL;
    DOMAIN_FREE(rtable, r->dom);

    /* Internal tables are freed by flushing their resource pools */
    rfree(r->rp);
  }

  if (conf)
    config_del_obstacle(conf);
}

static void
rt_res_dump(resource *_r)
{
  rtable *rr = (rtable *) _r;
  RT_LOCK(rr);
  rtable_private *r = RT_PRIV(rr);

  debug("name \"%s\", addr_type=%s, rt_count=%u, use_count=%d\n",
      r->name, net_label[r->addr_type], r->rt_count, r->use_count);

  RT_UNLOCK(rr);
}

static struct resclass rt_class = {
  .name = "Routing table",
  .size = sizeof(rtable),
  .free = rt_free,
  .dump = rt_res_dump,
  .lookup = NULL,
  .memsize = NULL,
};

rtable *
rt_setup(pool *pp, struct rtable_config *cf)
{
  int ns = strlen("Routing table ") + strlen(cf->name) + 1;
  void *nb = mb_alloc(pp, ns);
  ASSERT_DIE(ns - 1 == bsnprintf(nb, ns, "Routing table %s", cf->name));

  pool *p = rp_new(pp, nb);
  mb_move(nb, p);

  rtable *tu = ralloc(p, &rt_class);
  rtable_private *t = RT_PRIV(tu);
  t->rp = p;

  t->name = cf->name;
  t->config = cf;
  t->addr_type = cf->addr_type;

  fib_init(&t->fib, p, t->addr_type, sizeof(net), OFFSETOF(net, n), 0, NULL);
  t->rte_slab = sl_new(p, sizeof(struct rte_storage));

  t->next_export_seq = 1;
  init_list(&t->pending_exports);
  fib_init(&t->export_fib, p, t->addr_type, sizeof(struct rt_pending_export_fib_node), OFFSETOF(struct rt_pending_export_fib_node, n), 0, NULL);

  if (t->internal = cf->internal)
    t->idom = DOMAIN_NEW(rtable_internal, t->name);
  else
  {
    t->dom = DOMAIN_NEW(rtable, t->name);

    init_list(&t->channels);
    hmap_init(&t->id_map, p, 1024);
    hmap_set(&t->id_map, 0);

    t->last_rt_change = t->gc_time = current_time();

    init_list(&t->subscribers);

    t->maint_sem = bsem_new(p);
    DBG("maint_sem for %s = %p\n", t->name, t->maint_sem);
    t->export_alarm = (struct bsem_alarm) { .bsem = t->maint_sem };
    t->maint_coro = coro_run(p, rt_maint, t);
  }

  return tu;
}

/**
 * rt_init - initialize routing tables
 *
 * This function is called during BIRD startup. It initializes the
 * routing table module.
 */
void
rt_init(void)
{
  rta_init();
  rt_table_pool = rp_new(&root_pool, "Routing tables");
  init_list(&routing_tables);
}


/**
 * rt_prune_table - prune a routing table
 *
 * The prune loop scans routing tables and removes routes belonging to flushing
 * protocols, discarded routes and also stale network entries. It is called from
 * rt_maint(). This loop is rescheduled if the current iteration do not finish
 * the table. The pruning is directed by the prune state (@prune_state),
 * specifying whether the prune cycle is scheduled or running, and there
 * is also a persistent pruning iterator (@prune_fit).
 *
 * The prune loop is used also for channel flushing. For this purpose, the
 * channels to flush are marked before the iteration and notified after the
 * iteration.
 */
static _Bool
rt_prune_table(rtable_private *tab)
{
  struct fib_iterator *fit = &tab->prune_fit;
  int limit = 512;

  struct channel *c;
  node *n;

  DBG("Pruning route table %s\n", tab->name);
#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  if (tab->prune_state == 0)
    return 0;

  if (tab->prune_state == 1)
  {
    /* Mark channels to flush */
    WALK_LIST2(c, n, tab->channels, table_node)
      if ((c->channel_state == CS_FLUSHING) && !c->flush_active)
      {
	DBG("Setting channel %s.%s flush_active=1\n", c->proto->name, c->name);
	c->flush_active = 1;
	c->flush_seq = tab->next_export_seq;
      }

    FIB_ITERATE_INIT(fit, &tab->fib);
    tab->prune_state = 2;
  }

again:
  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
    rescan:
      for (struct rte_storage *e=n->routes; e; e=e->next)
      {
	if (e->sender->flush_active || (e->flags & REF_DISCARD))
	  {
	    ASSERT_DIE(e->sender->flush_active <= 1);
	    if (limit <= 0)
	      {
		FIB_ITERATE_PUT(fit);
		bsem_post(tab->maint_sem);
		return 0;
	      }

	    /* Discard the route */
	    rte ew = { .net = e->net->n.addr, .src = e->src, .generation = e->generation, };
	    rte_recalculate(e->sender, e->net, &ew, 0);

	    limit--;

	    goto rescan;
	  }

	if (e->flags & REF_MODIFY)
	  {
	    if (limit <= 0)
	      {
		FIB_ITERATE_PUT(fit);
		bsem_post(tab->maint_sem);
		return 0;
	      }

	    rte_modify(tab, e);
	    limit--;

	    goto rescan;
	  }
      }

      if (!n->routes && !fib_find(&tab->export_fib, n->n.addr))		/* Orphaned FIB entry */
	{
	  FIB_ITERATE_PUT(fit);
	  fib_delete(&tab->fib, n);
	  goto again;
	}
    }
  FIB_ITERATE_END;

#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  tab->gc_counter = 0;
  tab->gc_time = current_time();

  _Bool check_exports = 0;

  /* Mark the channels as flushed from the table */
  WALK_LIST2(c, n, tab->channels, table_node)
    if ((c->channel_state == CS_FLUSHING) && (c->flush_active == 1))
    {
      DBG("Setting channel %s.%s flush_active=2\n", c->proto->name, c->name);
      c->flush_active = 2;
      check_exports = 1;
    }

  if (check_exports)
    rt_export_used((rtable *) tab);

  /* state change 2->0, 3->1 */
  tab->prune_state &= 1;

  if (tab->prune_state == 1)
    bsem_post(tab->maint_sem);

  return 1;
}

static void
rt_finish_prune(rtable *tab)
{
  DBG("rt_finish_prune(%s)\n", tab->name);

  birdloop_enter(&main_birdloop);

  /* Get channels flushed also from exports */
  RT_LOCK(tab);
  uint cnt = 0;
  node *n;
  struct channel *c;
  WALK_LIST2(c, n, RT_PRIV(tab)->channels, table_node)
    if (c->flush_active == 3)
      cnt++;

  uint ci = 0;
  struct channel **clist = alloca(cnt * sizeof(struct channel *));
  WALK_LIST2(c, n, RT_PRIV(tab)->channels, table_node)
    if (c->flush_active == 3)
    {
      clist[ci++] = c;
      c->flush_active = 0;
    }

  ASSERT_DIE(ci == cnt);
  RT_UNLOCK(tab);

  /* Close flushed channels */
  for (uint i = 0; i < cnt; i++)
    channel_set_state(clist[i], CS_DOWN);

  /* FIXME: This should be handled in a better way */
  rt_prune_sources();

  birdloop_leave(&main_birdloop);

  return;
}

static _Bool
rt_export_cleanup(rtable_private *tab)
{
  _Bool finish_prune = 0;

  atomic_exchange_explicit(&tab->export_used, 2, memory_order_acq_rel);

  u64 min_seq = ~((u64) 0);
  struct rt_pending_export *last_export_to_free = NULL;

  struct channel *c;
  node *n;
  WALK_LIST2(c, n, tab->channels, table_node)
  {
    byte state = atomic_load_explicit(&c->export_state, memory_order_acquire);

    if (state == ES_DOWN)
      continue;

    if (state == ES_READY)
    {
      struct rt_pending_export *last = atomic_load_explicit(&c->last_export, memory_order_acquire);
      if (!last)
	/* No last export means that the channel has exported nothing since last cleanup */
	goto done;

      else if (min_seq > last->seq)
      {
	min_seq = last->seq;
	last_export_to_free = last;
      }
      continue;
    }

    /* It's only safe to cleanup when the export state is ES_READY or ES_DOWN. */
    goto done;
  }

  struct rt_pending_export *first_export = tab->first_export;
  tab->first_export = last_export_to_free ? channel_next_export_fast(last_export_to_free) : NULL;

  DBG("Export cleanup of %s: old first_export seq %lu, new %lu, min_seq %lu\n",
      tab->name,
      first_export ? first_export->seq : 0,
      tab->first_export ? tab->first_export->seq : 0,
      min_seq);

  WALK_LIST2(c, n, tab->channels, table_node)
  {
    struct rt_pending_export *last = atomic_load_explicit(&c->last_export, memory_order_acquire);
    if (last == last_export_to_free)
      /* This may fail when the channel managed to export more inbetween. This is OK. */
      atomic_compare_exchange_strong_explicit(
	  &c->last_export, &last, NULL,
	  memory_order_release,
	  memory_order_relaxed);
  }

  while (first_export && (first_export->seq <= min_seq))
  {
    ASSERT_DIE(first_export->new || first_export->old);

    net *net = first_export->new ?
      first_export->new->net :
      first_export->old->net;

    const net_addr *n = net->n.addr;

    struct rt_pending_export_fib_node *rpefn = fib_find(&tab->export_fib, n);
    ASSERT_DIE(rpefn);
    ASSERT_DIE(rpefn->first == first_export);
    
    if (first_export == rpefn->last)
      /* The only export here */
      fib_delete(&tab->export_fib, rpefn);
    else
      /* First is now the next one */
      rpefn->first = atomic_load_explicit(&first_export->next, memory_order_relaxed);

    /* For now, the old route may be finally freed */
    if (first_export->old)
    {
      hmap_clear(&tab->id_map, first_export->old->id);
      rte_free(tab, first_export->old);
    }

#ifdef LOCAL_DEBUG
    memset(first_export, 0xbd, sizeof(struct rt_pending_export));
#endif

    struct rt_export_block *reb = HEAD(tab->pending_exports);
    ASSERT_DIE(reb == PAGE_HEAD(first_export));

    int pos = (first_export - &reb->export[0]);
    u16 end = atomic_load_explicit(&reb->end, memory_order_relaxed);
    ASSERT_DIE(pos < end);
    ASSERT_DIE(pos >= 0);

    struct rt_pending_export *next = NULL;
    
    if (++pos < end)
      next = &reb->export[pos];
    else
    {
      rem_node(&reb->n);

#ifdef LOCAL_DEBUG
      memset(reb, 0xbe, get_page_size());
#endif

      free_page(reb);

      if (!EMPTY_LIST(tab->pending_exports))
      {
	reb = HEAD(tab->pending_exports);
	next = &reb->export[0];
      }
    }

    first_export = next;
  }

  WALK_LIST2(c, n, tab->channels, table_node)
    if (c->flush_active == 2)
      if (!first_export || (first_export->seq >= c->flush_seq))
      {
	DBG("Setting channel %s.%s flush_active=3\n", c->proto->name, c->name);
	c->flush_active = 3;
	finish_prune = 1;
      }
      else
      {
	DBG("Channel %s.%s flush not finished yet: first_export->seq = %lu, c->flush_seq = %lu\n",
	    c->proto->name, c->name, first_export->seq, c->flush_seq);
      }

done:
  if (atomic_fetch_and_explicit(&tab->export_used, 1, memory_order_acq_rel) & 1)
    bsem_post(tab->maint_sem);

  return finish_prune;
}

void
rt_preconfig(struct config *c)
{
  init_list(&c->tables);

  c->def_table_attrs = cfg_allocz(sizeof(struct rtable_config));
  c->def_table_attrs->min_settle_time = 1 S;
  c->def_table_attrs->max_settle_time = 20 S;
  c->def_table_attrs->export_settle_time = 10 MS;

  rt_new_table(cf_get_symbol("master4"), NET_IP4);
  rt_new_table(cf_get_symbol("master6"), NET_IP6);
}


/*
 * Some functions for handing internal next hop updates
 * triggered by rt_schedule_nhu().
 */

static inline int
rta_next_hop_outdated(rta *a)
{
  struct hostentry *he = a->hostentry;

  if (!he)
    return 0;

  if (!he->src)
    return a->dest != RTD_UNREACHABLE;

  return (a->dest != he->dest) || (a->igp_metric != he->igp_metric) ||
    (!he->nexthop_linkable) || !nexthop_same(&(a->nh), &(he->src->nh));
}

void
rta_apply_hostentry(linpool *lp, rta *a, struct hostentry *he, mpls_label_stack *mls)
{
  a->hostentry = he;
  a->dest = he->dest;
  a->igp_metric = he->igp_metric;

  if (a->dest != RTD_UNICAST)
  {
    /* No nexthop */
no_nexthop:
    a->nh = (struct nexthop) {};
    if (mls)
    { /* Store the label stack for later changes */
      a->nh.labels_orig = a->nh.labels = mls->len;
      memcpy(a->nh.label, mls->stack, mls->len * sizeof(u32));
    }
    return;
  }

  if (((!mls) || (!mls->len)) && he->nexthop_linkable)
  { /* Just link the nexthop chain, no label append happens. */
    memcpy(&(a->nh), &(he->src->nh), nexthop_size(&(he->src->nh)));
    return;
  }

  struct nexthop *nhp = NULL, *nhr = NULL;
  int skip_nexthop = 0;

  for (struct nexthop *nh = &(he->src->nh); nh; nh = nh->next)
  {
    if (skip_nexthop)
      skip_nexthop--;
    else
    {
      nhr = nhp;
      nhp = (nhp ? (nhp->next = lp_alloc(lp, NEXTHOP_MAX_SIZE)) : &(a->nh));
    }

    memset(nhp, 0, NEXTHOP_MAX_SIZE);
    nhp->iface = nh->iface;
    nhp->weight = nh->weight;

    if (mls)
    {
      nhp->labels = nh->labels + mls->len;
      nhp->labels_orig = mls->len;
      if (nhp->labels <= MPLS_MAX_LABEL_STACK)
      {
	memcpy(nhp->label, nh->label, nh->labels * sizeof(u32)); /* First the hostentry labels */
	memcpy(&(nhp->label[nh->labels]), mls->stack, mls->len * sizeof(u32)); /* Then the bottom labels */
      }
      else
      {
	log(L_WARN "Sum of label stack sizes %d + %d = %d exceedes allowed maximum (%d)",
	    nh->labels, mls->len, nhp->labels, MPLS_MAX_LABEL_STACK);
	skip_nexthop++;
	continue;
      }
    }
    else if (nh->labels)
    {
      nhp->labels = nh->labels;
      nhp->labels_orig = 0;
      memcpy(nhp->label, nh->label, nh->labels * sizeof(u32));
    }

    if (ipa_nonzero(nh->gw))
    {
      nhp->gw = nh->gw;			/* Router nexthop */
      nhp->flags |= (nh->flags & RNF_ONLINK);
    }
    else if (!(nh->iface->flags & IF_MULTIACCESS) || (nh->iface->flags & IF_LOOPBACK))
      nhp->gw = IPA_NONE;		/* PtP link - no need for nexthop */
    else if (ipa_nonzero(he->link))
      nhp->gw = he->link;		/* Device nexthop with link-local address known */
    else
      nhp->gw = he->addr;		/* Device nexthop with link-local address unknown */
  }

  if (skip_nexthop)
    if (nhr)
      nhr->next = NULL;
    else
    {
      a->dest = RTD_UNREACHABLE;
      log(L_WARN "No valid nexthop remaining, setting route unreachable");
      goto no_nexthop;
    }
}

static inline struct rte_storage *
rt_next_hop_update_rte(rtable_private *tab, struct rte_storage *old)
{
  rta *a = alloca(RTA_MAX_SIZE);
  memcpy(a, old->attrs, rta_size(old->attrs));

  mpls_label_stack mls = { .len = a->nh.labels_orig };
  memcpy(mls.stack, &a->nh.label[a->nh.labels - mls.len], mls.len * sizeof(u32));

  rta_apply_hostentry(tab->maint_lp, a, old->attrs->hostentry, &mls);
  a->cached = 0;

  rte e = {
    .attrs = a,
    .net = old->net->n.addr,
    .src = old->src,
    .generation = old->generation,
  };

  rte_trace_in(D_ROUTES, old->sender, &e, "updated");

  struct rte_storage *new = rte_store(tab, &e, old->net);
  rte_copy_metadata(new, old);
  return new;
}

static inline int
rt_next_hop_update_net(rtable_private *tab, net *n)
{
  struct rte_storage *new;
  int count = 0;

  struct rte_storage *old_best = n->routes;
  if (!old_best)
    return 0;

  DBG("next_hop_update_net(%s, %N) begin, old_best=%p\n", tab->name, n->n.addr, old_best);

  for (struct rte_storage **k = &n->routes, *e; e = *k; k = &e->next)
    if (rta_next_hop_outdated(e->attrs))
      count++;

  if (!count)
    return 0;

  DBG("next_hop_update_net(%s, %N) found %d routes to change\n", tab->name, n->n.addr, count);

  struct rte_multiupdate {
    struct rte_storage *old, *new;
  } *updates = alloca(sizeof(struct rte_multiupdate) * count);

  int pos = 0;
  for (struct rte_storage **k = &n->routes, *e; e = *k; k = &e->next)
    if (rta_next_hop_outdated(e->attrs))
      {
	struct rte_storage *new = rt_next_hop_update_rte(tab, e);
	DBG("next_hop_update_net(%s, %N) %p -> %p\n", tab->name, n->n.addr, e, new);

	/* Call a pre-comparison hook */
	/* Not really an efficient way to compute this */
	if (e->src->proto->rte_recalculate)
	  e->src->proto->rte_recalculate(tab, n, new, e, old_best);

	updates[pos++] = (struct rte_multiupdate) {
	  .old = e,
	  .new = new,
	};

	/* Replace the route in the list */
	new->next = e->next;
	*k = e = new;
      }

  DBG("next_hop_update_net(%s, %N) found %d routes to change and changed %d\n", tab->name, n->n.addr, count, pos);

  ASSERT_DIE(pos == count);

  /* Find the new best route */
  struct rte_storage **new_best = NULL;
  for (struct rte_storage **k = &n->routes, *e; e = *k; k = &e->next)
    {
      if (!new_best || rte_better(e, *new_best))
	new_best = k;
    }

  /* Relink the new best route to the first position */
  new = *new_best;
  if (new != n->routes)
    {
      *new_best = new->next;
      new->next = n->routes;
      n->routes = new;
    }

  int bp = 0;
  while ((bp < count) && (new != updates[bp].new))
    bp++;

  /* Announce first the best route change */
  if (bp && (bp < count))
  {
    struct rte_multiupdate tmp = updates[0];
    updates[0] = updates[bp];
    updates[bp] = tmp;
  }

  ASSERT_DIE((new == old_best) || (bp < count));

  /* Announce the changes */
  for (int i=0; i<count; i++)
  {
    _Bool nb = (new == updates[i].new), ob = (old_best == updates[i].old);
    const char *best_indicator[2][2] = { { "updated", "updated [-best]" }, { "updated [+best]", "updated [best]" } };
    rte nloc = rte_copy(updates[i].new);
    rte_trace_in(D_ROUTES, new->sender, &nloc, best_indicator[nb][ob]);

    if (i)
      rte_announce(tab, n, updates[i].new, updates[i].old, new, new);
    else
      rte_announce(tab, n, updates[i].new, updates[i].old, new, old_best);
  }

  DBG("next_hop_update_net(%s, %N) finished\n", tab->name, n->n.addr);

  return count;
}

static void
rt_next_hop_update(rtable_private *tab)
{
  struct fib_iterator *fit = &tab->nhu_fit;
  int max_feed = 32;

  byte nhu_state = atomic_load_explicit(&tab->nhu_state, memory_order_acquire);

  if (nhu_state == NHU_CLEAN)
    return;

  if (nhu_state == NHU_SCHEDULED)
    {
      FIB_ITERATE_INIT(fit, &tab->fib);
      atomic_store_explicit(&tab->nhu_state, NHU_RUNNING, memory_order_release);
    }

  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  bsem_post(tab->maint_sem);
	  return;
	}
      max_feed -= rt_next_hop_update_net(tab, n);
    }
  FIB_ITERATE_END;

  /* State change:
   *   NHU_DIRTY   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_CLEAN
   */
  if ((atomic_fetch_and_explicit(&tab->nhu_state, 1, memory_order_acq_rel) & 1) != NHU_CLEAN)
    bsem_post(tab->maint_sem);
}


struct rtable_config *
rt_new_table(struct symbol *s, uint addr_type)
{
  /* Hack that allows to 'redefine' the master table */
  if ((s->class == SYM_TABLE) &&
      (s->table == new_config->def_tables[addr_type]) &&
      ((addr_type == NET_IP4) || (addr_type == NET_IP6)))
    return s->table;

  struct rtable_config *c = cfg_allocz(sizeof(struct rtable_config));

  cf_define_symbol(s, SYM_TABLE, table, c);
  c->name = s->name;
  c->addr_type = addr_type;
  c->gc_max_ops = 1000;
  c->gc_min_time = 5;
  c->min_settle_time = new_config->def_table_attrs->min_settle_time;
  c->max_settle_time = new_config->def_table_attrs->max_settle_time;
  c->export_settle_time = new_config->def_table_attrs->export_settle_time;

  add_tail(&new_config->tables, &c->n);

  /* First table of each type is kept as default */
  if (! new_config->def_tables[addr_type])
    new_config->def_tables[addr_type] = c;

  return c;
}

/**
 * rt_lock_table - lock a routing table
 * @r: routing table to be locked
 *
 * Lock a routing table, because it's in use by a protocol,
 * preventing it from being freed when it gets undefined in a new
 * configuration.
 */
void
rt_lock_table(rtable_private *r)
{
  r->use_count++;
}

/**
 * rt_unlock_table - unlock a routing table
 * @r: routing table to be unlocked
 *
 * Unlock a routing table formerly locked by rt_lock_table().
 * If scheduled for deletion, ping the maintenance coroutine to delete
 * the table and finish.
 */
void
rt_unlock_table(rtable_private *r)
{
  r->use_count--;

  if (!r->use_count && r->deleted)
    bsem_post(r->maint_sem);
}

static struct rtable_config *
rt_find_table_config(struct config *cf, char *name)
{
  struct symbol *sym = cf_find_symbol(cf, name);
  return (sym && (sym->class == SYM_TABLE)) ? sym->table : NULL;
}

/**
 * rt_commit - commit new routing table configuration
 * @new: new configuration
 * @old: original configuration or %NULL if it's boot time config
 *
 * Scan differences between @old and @new configuration and modify
 * the routing tables according to these changes. If @new defines a
 * previously unknown table, create it, if it omits a table existing
 * in @old, schedule it for deletion (it gets deleted when all protocols
 * disconnect from it by calling rt_unlock_table()), if it exists
 * in both configurations, leave it unchanged.
 */
void
rt_commit(struct config *new, struct config *old)
{
  struct rtable_config *o, *r;

  DBG("rt_commit:\n");
  if (old)
    {
      WALK_LIST(o, old->tables)
	{
	  rtable *otu = o->table;
	  RT_LOCK(otu);
	  rtable_private *ot = RT_PRIV(otu);
	  if (!ot->deleted)
	    {
	      r = rt_find_table_config(new, o->name);
	      if (r && (r->addr_type == o->addr_type) && !new->shutdown)
		{
		  DBG("\t%s: same\n", o->name);
		  r->table = otu;
		  ot->name = r->name;
		  ot->config = r;
		  if (o->sorted != r->sorted)
		    log(L_WARN "Reconfiguration of rtable sorted flag not implemented");
		  if (o->max_settle_time < r->max_settle_time)
		  {
		    tm_stop(ot->settle_timer);
		    rt_kick_settle_timer(ot);
		  }
		}
	      else
		{
		  DBG("\t%s: deleted\n", o->name);
		  ot->deleted = old;
		  config_add_obstacle(old);
		  rem_node(&ot->n);
		  bsem_post(ot->maint_sem); /* Allow the maint_coro to finish. */
		}
	    }
	  RT_UNLOCK(otu);
	}
    }

  WALK_LIST(r, new->tables)
    if (!r->table)
      {
	r->table = rt_setup(rt_table_pool, r);
	DBG("\t%s: created\n", r->name);
	add_tail(&routing_tables, &r->table->n);
      }
  DBG("\tdone\n");
}


/*
 *	Import table
 */

static int
rte_update_in(struct channel *c, rte *new)
{
  RT_LOCK(c->in_table);
  rtable_private *tab = RT_PRIV(c->in_table);
  struct rte_storage *old, **pos;
  net *net;

  if (new->attrs)
  {
    net = net_get(tab, new->net);

    if (!rta_is_cached(new->attrs))
      new->attrs = rta_lookup(new->attrs);
  }
  else
  {
    net = net_find(tab, new->net);

    if (!net)
      goto drop_withdraw;
  }

  /* Find the old rte */
  for (pos = &net->routes; old = *pos; pos = &old->next)
    if (old->src == new->src)
    {
      if (new->attrs && rte_same(old, new, 0))
      {
	/* Refresh the old rte, continue with update to main rtable */
	if (old->flags & (REF_STALE | REF_DISCARD | REF_MODIFY))
	{
	  old->flags &= ~(REF_STALE | REF_DISCARD | REF_MODIFY);
	  RT_UNLOCK(c->in_table);
	  return 1;
	}

	goto drop_update;
      }

      /* Move iterator if needed */
      if (old == c->reload_next_rte)
	c->reload_next_rte = old->next;

      /* Remove the old rte */
      *pos = old->next;
      rte_free(tab, old);
      tab->rt_count--;

      break;
    }

  if (!new->attrs)
  {
    if (!old)
      goto drop_withdraw;

    if (!net->routes)
      fib_delete(&tab->fib, net);

    RT_UNLOCK(c->in_table);
    return 1;
  }

  struct channel_limit *l = &c->rx_limit;
  if (l->action && !old)
  {
    if (tab->rt_count >= l->limit)
      channel_notify_limit(c, l, PLD_RX, tab->rt_count);

    if (l->state == PLS_BLOCKED)
    {
      rte_trace_in(D_FILTERS, c, new, "ignored [limit]");
      goto drop_update;
    }
  }

  /* Insert the new rte */
  struct rte_storage *e = rte_store(tab, new, net);
  e->sender = c;
  e->lastmod = current_time();
  e->next = *pos;
  *pos = e;
  tab->rt_count++;
  RT_UNLOCK(c->in_table);
  return 1;

drop_update:
  c->import_stats.updates_received++;
  c->import_stats.updates_ignored++;

  if (!net->routes)
    fib_delete(&tab->fib, net);

  RT_UNLOCK(c->in_table);
  return 0;

drop_withdraw:
  c->import_stats.withdraws_received++;
  c->import_stats.withdraws_ignored++;

  RT_UNLOCK(c->in_table);
  return 0;
}

int
rt_reload_channel(struct channel *c, linpool *lp)
{
  RT_LOCK(c->in_table);
  rtable_private *tab = RT_PRIV(c->in_table);
  struct fib_iterator *fit = &c->reload_fit;
  int max_feed = 64;

  ASSERT(c->channel_state == CS_UP);

  if (!c->reload_active)
  {
    FIB_ITERATE_INIT(fit, &tab->fib);
    c->reload_active = 1;
  }

  do {
    for (struct rte_storage *e = c->reload_next_rte; e; e = e->next)
    {
      if (max_feed-- <= 0)
      {
	c->reload_next_rte = e;
	debug("%s channel reload burst split (max_feed=%d)", c->proto->name, max_feed);
	RT_UNLOCK(c->in_table);
	return 0;
      }

      rte eloc = rte_copy(e);
      rte_update2(c, &eloc, lp);
    }

    c->reload_next_rte = NULL;

    FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (c->reload_next_rte = n->routes)
      {
	FIB_ITERATE_PUT_NEXT(fit, &tab->fib);
	break;
      }
    }
    FIB_ITERATE_END;
  }
  while (c->reload_next_rte);

  c->reload_active = 0;
  RT_UNLOCK(c->in_table);
  return 1;
}

void
rt_reload_channel_abort(struct channel *c)
{
  RT_LOCK(c->in_table);

  if (c->reload_active)
  {
    /* Unlink the iterator */
    fit_get(&RT_PRIV(c->in_table)->fib, &c->reload_fit);
    c->reload_next_rte = NULL;
    c->reload_active = 0;
  }

  RT_UNLOCK(c->in_table);
}

void
rt_prune_sync(rtable *_t, int all)
{
  struct fib_iterator fit;
  RT_LOCK(_t);
  rtable_private *t = RT_PRIV(_t);

  ASSERT_DIE(t->internal);

  FIB_ITERATE_INIT(&fit, &t->fib);

again:
  FIB_ITERATE_START(&t->fib, &fit, net, n)
  {
    struct rte_storage *e, **ee = &n->routes;

    while (e = *ee)
    {
      if (all || (e->flags & (REF_STALE | REF_DISCARD)))
      {
	*ee = e->next;
	rte_free(t, e);
	t->rt_count--;
      }
      else
	ee = &e->next;
    }

    if (all || !n->routes)
    {
      FIB_ITERATE_PUT(&fit);
      fib_delete(&t->fib, n);
      goto again;
    }
  }
  FIB_ITERATE_END;

  RT_UNLOCK(t);
}


/*
 *	Export table
 */

int
rte_update_out(struct channel *c, linpool *lp, rte *new, struct rte_storage *old, struct rte_storage **old_stored)
{
  RT_LOCK(c->out_table);
  rtable_private *tab = RT_PRIV(c->out_table);
  struct rte_storage **pos;
  net *net;

  if (new)
  {
    net = net_get(tab, new->net);

    /* Copy the recursive nexthop as we don't want to inherit it */
    if (new->attrs->hostentry)
    {
      new->attrs = rta_cow(new->attrs, lp);
      new->attrs->hostentry = NULL;
    }

    if (!rta_is_cached(new->attrs))
      new->attrs = rta_lookup(new->attrs);
  }
  else
  {
    net = net_find(tab, old->net->n.addr);

    if (!net)
      goto drop;
  }

  /* Find the old rte */
  for (pos = &net->routes; *pos; pos = &(*pos)->next)
    if ((c->ra_mode != RA_ANY) || ((*pos)->src == old->src))
    {
      if (new && rte_same(*pos, new, 0))
      {
	/* REF_STALE / REF_DISCARD not used in export table */
	/*
	if (old->flags & (REF_STALE | REF_DISCARD | REF_MODIFY))
	{
	  old->flags &= ~(REF_STALE | REF_DISCARD | REF_MODIFY);
	  return 1;
	}
	*/

	goto drop;
      }

      /* Keep the old rte */
      *old_stored = *pos;

      /* Remove the old rte from the list */
      *pos = (*pos)->next;
      tab->rt_count--;

      break;
    }

  if (!new)
  {
    if (!*old_stored)
      goto drop;

    RT_UNLOCK(c->out_table);
    return 1;
  }

  /* Insert the new rte */
  struct rte_storage *e = rte_store(tab, new, net);
  e->sender = new->sender;
  e->lastmod = current_time();
  e->id = new->id;
  e->next = *pos;
  *pos = e;
  tab->rt_count++;
  RT_UNLOCK(c->out_table);
  return 1;

drop:
  RT_UNLOCK(c->out_table);
  return 0;
}

void
rt_refeed_channel(struct channel *c, struct bmap *seen, linpool *lp)
{
  if (!c->out_table)
  {
    channel_request_feeding(c);
    return;
  }

  RT_LOCK(c->out_table);
  rtable_private *tab = RT_PRIV(c->out_table);

  if (c->proto->feed_begin)
    c->proto->feed_begin(c, 0);

  FIB_WALK(&tab->fib, net, n)
  {
    for (struct rte_storage *r = n->routes; r; r = r->next)
    {
      if (seen && bmap_test(seen, r->id))
	continue;
      rte e = rte_copy(r);
      c->proto->rt_notify(c->proto, c, lp, n->n.addr, &e, NULL);
    }
  }
  FIB_WALK_END;
  
  if (c->proto->feed_end)
    c->proto->feed_end(c);

  RT_UNLOCK(c->out_table);
}

void
rt_refeed_channel_net(struct channel *c, linpool *lp, const net_addr *n)
{
  if (c->out_table)
  {
    RT_LOCK(c->out_table);
    net *nn = net_find(RT_PRIV(c->out_table), n);
    if (nn)
      for (struct rte_storage *r = nn->routes; r; r = r->next)
      {
	rte e = rte_copy(r);
	c->proto->rt_notify(c->proto, c, lp, n, &e, NULL);
      }
    RT_UNLOCK(c->out_table);
  }
  else
  {
    RT_LOCK(c->table);
    net *nn = net_find(RT_PRIV(c->table), n);
    if (!nn)
      return;

    switch (c->ra_mode)
    {
      case RA_OPTIMAL:
	rt_notify_basic(c, lp, n, nn->routes, NULL, 1);
	return;

      default:
	bug("Calling refeed_channel_net with unimplemented ra_mode");
    }
    RT_UNLOCK(c->table);
  }
}

void
rt_flush_channel(struct channel *c, linpool *lp)
{
  ASSERT_DIE(c->out_table);
  ASSERT_DIE(c->ra_mode != RA_ANY);

  RT_LOCK(c->out_table);

  FIB_WALK(&RT_PRIV(c->out_table)->fib, net, n)
  {
    if (!n->routes)
      continue;

    c->proto->rt_notify(c->proto, c, lp, n->n.addr, NULL, n->routes);
  }
  FIB_WALK_END;

  RT_UNLOCK(c->out_table);
}


/*
 *	Hostcache
 */

static inline u32
hc_hash(ip_addr a, rtable *dep)
{
  return ipa_hash(a) ^ ptr_hash(dep);
}

static inline void
hc_insert(struct hostcache *hc, struct hostentry *he)
{
  uint k = he->hash_key >> hc->hash_shift;
  he->next = hc->hash_table[k];
  hc->hash_table[k] = he;
}

static inline void
hc_remove(struct hostcache *hc, struct hostentry *he)
{
  struct hostentry **hep;
  uint k = he->hash_key >> hc->hash_shift;

  for (hep = &hc->hash_table[k]; *hep != he; hep = &(*hep)->next);
  *hep = he->next;
}

#define HC_DEF_ORDER 10
#define HC_HI_MARK *4
#define HC_HI_STEP 2
#define HC_HI_ORDER 16			/* Must be at most 16 */
#define HC_LO_MARK /5
#define HC_LO_STEP 2
#define HC_LO_ORDER 10

static void
hc_alloc_table(struct hostcache *hc, pool *p, unsigned order)
{
  uint hsize = 1 << order;
  hc->hash_order = order;
  hc->hash_shift = 32 - order;
  hc->hash_max = (order >= HC_HI_ORDER) ? ~0U : (hsize HC_HI_MARK);
  hc->hash_min = (order <= HC_LO_ORDER) ?  0U : (hsize HC_LO_MARK);

  hc->hash_table = mb_allocz(p, hsize * sizeof(struct hostentry *));
}

static void
hc_resize(struct hostcache *hc, pool *p, unsigned new_order)
{
  struct hostentry **old_table = hc->hash_table;
  struct hostentry *he, *hen;
  uint old_size = 1 << hc->hash_order;
  uint i;

  hc_alloc_table(hc, p, new_order);
  for (i = 0; i < old_size; i++)
    for (he = old_table[i]; he != NULL; he=hen)
      {
	hen = he->next;
	hc_insert(hc, he);
      }
  mb_free(old_table);
}

static struct hostentry *
hc_new_hostentry(struct hostcache *hc, pool *p, ip_addr a, ip_addr ll, rtable *dep, unsigned k)
{
  struct hostentry *he = sl_alloc(hc->slab);

  *he = (struct hostentry) {
    .addr = a,
    .link = ll,
    .tab = dep,
    .hash_key = k,
  };

  add_tail(&hc->hostentries, &he->ln);
  hc_insert(hc, he);

  hc->hash_items++;
  if (hc->hash_items > hc->hash_max)
    hc_resize(hc, p, hc->hash_order + HC_HI_STEP);

  return he;
}

static void
hc_delete_hostentry(struct hostcache *hc, pool *p, struct hostentry *he)
{
  rta_free(he->src);

  rem_node(&he->ln);
  hc_remove(hc, he);
  sl_free(hc->slab, he);

  hc->hash_items--;
  if (hc->hash_items < hc->hash_min)
    hc_resize(hc, p, hc->hash_order - HC_LO_STEP);
}

static void
rt_init_hostcache(rtable_private *tab)
{
  struct hostcache *hc = mb_allocz(tab->rp, sizeof(struct hostcache));
  init_list(&hc->hostentries);

  hc->hash_items = 0;
  hc_alloc_table(hc, tab->rp, HC_DEF_ORDER);
  hc->slab = sl_new(tab->rp, sizeof(struct hostentry));

  hc->lp = lp_new(tab->rp, LP_GOOD_SIZE(1024));
  hc->trie = f_new_trie(hc->lp, 0);

  tab->hostcache = hc;
}

static void
rt_free_hostcache(rtable_private *tab)
{
  struct hostcache *hc = tab->hostcache;

  node *n;
  WALK_LIST(n, hc->hostentries)
    {
      struct hostentry *he = SKIP_BACK(struct hostentry, ln, n);
      rta_free(he->src);

      unsigned uc = atomic_load_explicit(&he->uc_atomic, memory_order_acquire);
      if (uc)
      {
	rt_dump_all();
	rta_dump_all();
	bug("Hostcache is not empty in table %s: "
	    "addr=%I link=%I dep=%s uc=%u",
	    tab->name, he->addr, he->link, he->tab->name, uc);
      }
    }

  /* Freed automagically by the resource pool
  rfree(hc->slab);
  rfree(hc->lp);
  mb_free(hc->hash_table);
  mb_free(hc);
  */
}

static void
rt_notify_hostcache(rtable_private *tab, net *net)
{
  if (tab->hcu_scheduled)
    return;

  if (trie_match_net(tab->hostcache->trie, net->n.addr))
    rt_schedule_hcu(tab);
}

static int
if_local_addr(ip_addr a, struct iface *i)
{
  struct ifa *b;

  WALK_LIST(b, i->addrs)
    if (ipa_equal(a, b->ip))
      return 1;

  return 0;
}

u32
rt_get_igp_metric(rta *a)
{
  eattr *ea;

  if (ea = ea_find(a->eattrs, EA_GEN_IGP_METRIC))
    return ea->u.data;

  switch (a->source)
  {
#ifdef CONFIG_OSPF
    case RTS_OSPF:
    case RTS_OSPF_IA:
    case RTS_OSPF_EXT1:
      if (ea = ea_find(a->eattrs, EA_OSPF_METRIC1))
	return ea->u.data;
      break;
#endif

#ifdef CONFIG_RIP
    case RTS_RIP:
      if (ea = ea_find(a->eattrs, EA_RIP_METRIC))
	return ea->u.data;
      break;
#endif

#ifdef CONFIG_BGP
    case RTS_BGP:
      {
	u64 metric = bgp_total_aigp_metric(a);
	return (u32) MIN(metric, (u64) IGP_METRIC_UNKNOWN);
      }
#endif

#ifdef CONFIG_BABEL
    case RTS_BABEL:
      if (ea = ea_find(a->eattrs, EA_BABEL_METRIC))
	return ea->u.data;
      break;
#endif

    case RTS_DEVICE:
      return 0;
  }

  return IGP_METRIC_UNKNOWN;
}

static int
rt_update_hostentry(rtable_private *tab, struct hostentry *he)
{
  rta *old_src = he->src;
  int direct = 0;
  int pxlen = 0;

  /* Reset the hostentry */
  he->src = NULL;
  he->dest = RTD_UNREACHABLE;
  he->nexthop_linkable = 0;
  he->igp_metric = 0;

  net_addr he_addr;
  net_fill_ip_host(&he_addr, he->addr);
  net *n = net_route(tab, &he_addr); /* This always returns a valid route or NULL */
  if (n)
    {
      rta *a = n->routes->attrs;
      pxlen = n->n.addr->pxlen;

      if (a->hostentry)
	{
	  /* Recursive route should not depend on another recursive route */
	  log(L_WARN "Next hop address %I resolvable through recursive route for %N",
	      he->addr, n->n.addr);
	  goto done;
	}

      if (a->dest == RTD_UNICAST)
	{
	  for (struct nexthop *nh = &(a->nh); nh; nh = nh->next)
	    if (ipa_zero(nh->gw))
	      {
		if (if_local_addr(he->addr, nh->iface))
		  {
		    /* The host address is a local address, this is not valid */
		    log(L_WARN "Next hop address %I is a local address of iface %s",
			he->addr, nh->iface->name);
		    goto done;
		  }

		direct++;
	      }
	}

      he->src = rta_clone(a);
      he->dest = a->dest;
      he->nexthop_linkable = !direct;
      he->igp_metric = rt_get_igp_metric(a);
    }

done:
  /* Add a prefix range to the trie */
  trie_add_prefix(tab->hostcache->trie, &he_addr, pxlen, he_addr.pxlen);

  rta_free(old_src);
  return old_src != he->src;
}

static void
rt_update_hostcache(rtable_private *tab)
{
  struct hostcache *hc = tab->hostcache;
  struct hostentry *he;
  node *n, *x;

  /* Reset the trie */
  lp_flush(hc->lp);
  hc->trie = f_new_trie(hc->lp, 0);

  WALK_LIST_DELSAFE(n, x, hc->hostentries)
    {
      he = SKIP_BACK(struct hostentry, ln, n);
      if (!atomic_load_explicit(&he->uc_atomic, memory_order_acquire))
	{
	  hc_delete_hostentry(hc, tab->rp, he);
	  continue;
	}

      if (rt_update_hostentry(tab, he))
	rt_schedule_nhu(he->tab);
    }

  tab->hcu_scheduled = 0;
}

struct hostentry *
rt_get_hostentry(rtable_private *tab, ip_addr a, ip_addr ll, rtable *dep)
{
  struct hostentry *he;

  if (!tab->hostcache)
    rt_init_hostcache(tab);

  u32 k = hc_hash(a, dep);
  struct hostcache *hc = tab->hostcache;
  for (he = hc->hash_table[k >> hc->hash_shift]; he != NULL; he = he->next)
    if (ipa_equal(he->addr, a) && (he->tab == dep))
      return he;

  he = hc_new_hostentry(hc, tab->rp, a, ipa_zero(ll) ? a : ll, dep, k);
  rt_update_hostentry(tab, he);
  return he;
}


/*
 *  Documentation for functions declared inline in rtable.h
 */
#if 0

/**
 * net_find - find a network entry
 * @tab: a routing table
 * @addr: address of the network
 *
 * net_find() looks up the given network in routing table @tab and
 * returns a pointer to its &net entry or %NULL if no such network
 * exists.
 */
static inline net *net_find(rtable *tab, net_addr *addr)
{ DUMMY; }

/**
 * net_get - obtain a network entry
 * @tab: a routing table
 * @addr: address of the network
 *
 * net_get() looks up the given network in routing table @tab and
 * returns a pointer to its &net entry. If no such entry exists, it's
 * created.
 */
static inline net *net_get(rtable *tab, net_addr *addr)
{ DUMMY; }

/**
 * rte_cow - copy a route for writing
 * @r: a route entry to be copied
 *
 * rte_cow() takes a &rte and prepares it for modification. The exact action
 * taken depends on the flags of the &rte -- if it's a temporary entry, it's
 * just returned unchanged, else a new temporary entry with the same contents
 * is created.
 *
 * The primary use of this function is inside the filter machinery -- when
 * a filter wants to modify &rte contents (to change the preference or to
 * attach another set of attributes), it must ensure that the &rte is not
 * shared with anyone else (and especially that it isn't stored in any routing
 * table).
 *
 * Result: a pointer to the new writable &rte.
 */
static inline rte * rte_cow(rte *r)
{ DUMMY; }

#endif
