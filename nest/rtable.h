/*
 *	BIRD Internet Routing Daemon -- Routing Table
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2019--2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RTABLE_H_
#define _BIRD_RTABLE_H_

#include "lib/lists.h"
#include "lib/bitmap.h"
#include "lib/resource.h"
#include "lib/net.h"
#include "lib/locking.h"
#include "lib/coro.h"

#include "nest/route.h"

#include <stdatomic.h>

struct ea_list;
struct protocol;
struct proto;
struct rte_src;
struct rte_storage;
struct symbol;
struct timer;
struct filter;
struct cli;
struct cf_context;

/*
 *	Generic data structure for storing network prefixes. Also used
 *	for the master routing table. Currently implemented as a hash
 *	table.
 *
 *	Available operations:
 *		- insertion of new entry
 *		- deletion of entry
 *		- searching for entry by network prefix
 *		- asynchronous retrieval of fib contents
 */

struct fib_node {
  struct fib_node *next;		/* Next in hash chain */
  struct fib_iterator *readers;		/* List of readers of this node */
  net_addr addr[0];
};

struct fib_iterator {			/* See lib/slists.h for an explanation */
  struct fib_iterator *prev, *next;	/* Must be synced with struct fib_node! */
  byte efef;				/* 0xff to distinguish between iterator and node */
  byte pad[3];
  struct fib_node *node;		/* Or NULL if freshly merged */
  uint hash;
};

typedef void (*fib_init_fn)(void *);

struct fib {
  pool *fib_pool;			/* Pool holding all our data */
  slab *fib_slab;			/* Slab holding all fib nodes */
  struct fib_node **hash_table;		/* Node hash table */
  uint hash_size;			/* Number of hash table entries (a power of two) */
  uint hash_order;			/* Binary logarithm of hash_size */
  uint hash_shift;			/* 32 - hash_order */
  uint addr_type;			/* Type of address data stored in fib (NET_*) */
  uint node_size;			/* FIB node size, 0 for nonuniform */
  uint node_offset;			/* Offset of fib_node struct inside of user data */
  uint entries;				/* Number of entries */
  uint entries_min, entries_max;	/* Entry count limits (else start rehashing) */
  fib_init_fn init;			/* Constructor */
};

static inline void * fib_node_to_user(struct fib *f, struct fib_node *e)
{ return e ? (void *) ((char *) e - f->node_offset) : NULL; }

static inline struct fib_node * fib_user_to_node(struct fib *f, void *e)
{ return e ? (void *) ((char *) e + f->node_offset) : NULL; }

void fib_init(struct fib *f, pool *p, uint addr_type, uint node_size, uint node_offset, uint hash_order, fib_init_fn init);
void *fib_find(struct fib *, const net_addr *);	/* Find or return NULL if doesn't exist */
void *fib_get_chain(struct fib *f, const net_addr *a); /* Find first node in linked list from hash table */
void *fib_get(struct fib *, const net_addr *);	/* Find or create new if nonexistent */
void *fib_route(struct fib *, const net_addr *); /* Longest-match routing lookup */
void fib_delete(struct fib *, void *);	/* Remove fib entry */
void fib_free(struct fib *);		/* Destroy the fib */
void fib_check(struct fib *);		/* Consistency check for debugging */

void fit_init(struct fib_iterator *, struct fib *); /* Internal functions, don't call */
struct fib_node *fit_get(struct fib *, struct fib_iterator *);
void fit_put(struct fib_iterator *, struct fib_node *);
void fit_put_next(struct fib *f, struct fib_iterator *i, struct fib_node *n, uint hpos);
void fit_put_end(struct fib_iterator *i);
void fit_copy(struct fib *f, struct fib_iterator *dst, struct fib_iterator *src);


#define FIB_WALK(fib, type, z) do {				\
	struct fib_node *fn_, **ff_ = (fib)->hash_table;	\
	uint count_ = (fib)->hash_size;				\
	type *z;						\
	while (count_--)					\
	  for (fn_ = *ff_++; z = fib_node_to_user(fib, fn_); fn_=fn_->next)

#define FIB_WALK_END } while (0)

#define FIB_ITERATE_INIT(it, fib) fit_init(it, fib)

#define FIB_ITERATE_START(fib, it, type, z) do {		\
	struct fib_node *fn_ = fit_get(fib, it);		\
	uint count_ = (fib)->hash_size;				\
	uint hpos_ = (it)->hash;				\
	type *z;						\
	for(;;) {						\
	  if (!fn_)						\
	    {							\
	       if (++hpos_ >= count_)				\
		 break;						\
	       fn_ = (fib)->hash_table[hpos_];			\
	       continue;					\
	    }							\
	  z = fib_node_to_user(fib, fn_);

#define FIB_ITERATE_END fn_ = fn_->next; } } while(0)

#define FIB_ITERATE_PUT(it) fit_put(it, fn_)

#define FIB_ITERATE_PUT_NEXT(it, fib) fit_put_next(fib, it, fn_, hpos_)

#define FIB_ITERATE_PUT_END(it) fit_put_end(it)

#define FIB_ITERATE_UNLINK(it, fib) fit_get(fib, it)

#define FIB_ITERATE_COPY(dst, src, fib) fit_copy(fib, dst, src)


/*
 *	Master Routing Tables. Generally speaking, each of them contains a FIB
 *	with each entry pointing to a list of route entries representing routes
 *	to given network (with the selected one at the head).
 *
 *	Each of the RTE's contains variable data (the preference and protocol-dependent
 *	metrics) and a pointer to a route attribute block common for many routes).
 *
 *	It's guaranteed that there is at most one RTE for every (prefix,src) pair.
 */

DEFINE_DOMAIN(rtable);
DEFINE_DOMAIN(rtable_internal);

typedef struct rtable_private {
  /* This part is public */
#define RTABLE_PUBLIC \
  resource r; \
  node n;				/* Node in list of all tables */ \
  uint addr_type;			/* Type of address data stored in table (NET_*) */ \
  char *name;				/* Name of this table */ \
  struct bsem *maint_sem;		/* Maintenance semaphore */ \
  _Atomic byte nhu_state;		/* Next Hop Update state */ \
  _Atomic byte export_used;		/* Export journal cleanup scheduled */ \
  u8 internal;				/* 0 for main table, 1 for a protocol's private table */ \
  union {				/* The table is a separate locking domain */ \
    DOMAIN(rtable) dom;			/* Domain for main table */ \
    DOMAIN(rtable_internal) idom;	/* Domain for internal table */ \
  };

  /* Put the public part here */
  RTABLE_PUBLIC

  /* The rest is private */
  pool *rp;				/* Resource pool to allocate everything from, including itself */
  struct fib fib;
  slab *rte_slab;			/* Slab for allocating routes */
  int use_count;			/* Number of channels and others using this table */
  u32 rt_count;				/* Number of routes in the table */

  list imports;				/* Registered route importers */
  list exports;				/* Registered route exporters */

  struct hmap id_map;
  struct hostcache *hostcache;
  struct rtable_config *config;		/* Configuration of this table */
  struct config *deleted;		/* Table doesn't exist in current configuration,
					 * delete as soon as use_count becomes 0 and remove
					 * obstacle from this routing table.
					 */
  btime last_rt_change;			/* Last time when route changed */
  btime base_settle_time;		/* Start time of rtable settling interval */
  btime gc_time;			/* Time of last GC */
  int gc_counter;			/* Number of operations since last GC */

  struct coroutine *maint_coro;		/* Maintenance coroutine */
  linpool *maint_lp;			/* Maintenance linpool */
  byte prune_state;			/* Table prune state, 1 -> scheduled, 2-> running */
  byte hcu_scheduled;			/* Hostcache update is scheduled */
  byte prune_sources;			/* Call to rt_prune_sources() requested */

  struct bsem_alarm export_alarm;	/* Export notifier */

  struct fib_iterator prune_fit;	/* Rtable prune FIB iterator */
  struct fib_iterator nhu_fit;		/* Next Hop Update FIB iterator */

  list subscribers;			/* Subscribers for notifications */
  struct timer *settle_timer;		/* Settle time for notifications */

  list pending_exports;			/* List of packed struct rt_pending_export */

  struct rt_pending_export *first_export;	/* First export to announce */
  struct fib export_fib;		/* Auxiliary fib for storing pending exports */
  u64 next_export_seq;			/* The next export will have this ID */
} rtable_private;

typedef union {
  struct { RTABLE_PUBLIC };
  rtable_private priv;
} rtable;

#define RT_PRIV(tab)	(&((tab)->priv))

#define RT_INT(tab) ((tab)->internal)
#define RT_LOCK(tab) (RT_INT(tab) ? LOCK_DOMAIN(rtable_internal, (tab)->idom) : LOCK_DOMAIN(rtable, (tab)->dom))
#define RT_UNLOCK(tab) (RT_INT(tab) ? UNLOCK_DOMAIN(rtable_internal, (tab)->idom) : UNLOCK_DOMAIN(rtable, (tab)->dom))

/*
 * Channel limits
 */

#define PLD_RX		0	/* Receive limit */
#define PLD_IN		1	/* Import limit */
#define PLD_OUT		2	/* Export limit */
#define PLD_MAX		3

#define PLA_NONE	0	/* No limit */
#define PLA_WARN	1	/* Issue log warning */
#define PLA_BLOCK	2	/* Block new routes */
#define PLA_RESTART	4	/* Force protocol restart */
#define PLA_DISABLE	5	/* Shutdown and disable protocol */

#define PLS_INITIAL	0	/* Initial limit state after protocol start */
#define PLS_ACTIVE	1	/* Limit was hit */
#define PLS_BLOCKED	2	/* Limit is active and blocking new routes */

struct channel_limit {
  u32 limit;			/* Maximum number of prefixes */
  u8 action;			/* Action to take (PLA_*) */
  u8 state;			/* State of limit (PLS_*) */
};

struct channel;
void channel_notify_limit(struct channel *c, struct channel_limit *l, int dir, u32 rt_count);

static inline void
channel_reset_limit(struct channel_limit *l)
{
  if (l->action)
    l->state = PLS_INITIAL;
}

/* Table-channel connections */

struct rt_import_request {
  struct rt_import_hook *hook;		/* The table part of importer */

  const struct filter *filter;

  u8 keep_filtered;			/* Routes rejected in import filter are kept */
  u8 reloadable;			/* Hook reload_routes() is allowed on the channel */
  u8 apply_rx_limit;			/* Apply rx limit */

  struct channel_limit rx_limit;	/* Receive limit (for in_keep_filtered) */
  struct channel_limit in_limit;	/* Input limit */

  void (*notify_limit)(struct rt_import_request *req, struct channel_limit *l, int dir, u32 rt_count);
  void (*rte_trace)(uint flag, struct rt_import_request *req, rte *e, const char *msg);
  void (*dump_req)(struct rt_import_request *req);
  void (*log_state_change)(struct rt_import_request *req, u8 state);
  void (*rte_invalid)(struct rt_import_request *req, const char *msg, ...);
  struct rta *(*rte_modify)(struct rte_storage *, struct linpool *);
};

struct rt_import_hook {
  node n;
  rtable *table;			/* The connected table */
  struct rt_import_request *req;	/* The requestor */

  struct import_stats {
    /* Import - from protocol to core */
    u32 routes;				/* Number of routes successfully imported to the (adjacent) routing table */
    u32 filtered;			/* Number of routes rejected in import filter but kept in the routing table */
    u32 pref;				/* Number of routes selected as best in the (adjacent) routing table */
    u32 updates_received;		/* Number of route updates received */
    u32 updates_limited_rx;		/* Number of route updates exceeding the rx_limit */
    u32 updates_invalid;		/* Number of route updates rejected as invalid */
    u32 updates_filtered;		/* Number of route updates rejected by filters */
    u32 updates_ignored;		/* Number of route updates rejected as already in route table */
    u32 updates_accepted;		/* Number of route updates accepted and imported */
    u32 updates_limited_in;		/* Number of route updates exceeding the in_limit */
    u32 withdraws_received;		/* Number of route withdraws received */
    u32 withdraws_invalid;		/* Number of route withdraws rejected as invalid */
    u32 withdraws_ignored;		/* Number of route withdraws rejected as already not in route table */
    u32 withdraws_accepted;		/* Number of route withdraws accepted and processed */
  } stats;

  u64 flush_seq;			/* Table export seq when the channel announced flushing */
  btime last_state_change;		/* Time of last state transition */

  u8 import_state;			/* IS_* */

  void (*stopped)(struct rt_import_request *);	/* Stored callback when import is stopped */
};

struct rt_export_request {
  struct rt_export_hook *hook;		/* Table part of the export */

  const struct filter *filter;

  struct channel_limit out_limit;	/* Output limit */

  u8 ra_mode;				/* Mode of received route advertisements (RA_*) */
  u8 merge_limit;			/* Maximal number of nexthops for RA_MERGED */
  u8 refeeding;				/* We are refeeding */
  u8 explicit_flush;			/* Feed by withdrawals on export reset */

  int (*preexport)(struct rt_export_request *req, struct rte *e);
  void (*export)(struct rt_export_request *req, linpool *, const net_addr *net, rte *new, rte *old, int refeed);

  void (*feed_begin)(struct rt_export_request *req);
  void (*feed_end)(struct rt_export_request *req);

  void (*rte_trace)(uint flag, struct rt_export_request *req, rte *e, const char *msg);
  void (*log_state_change)(struct rt_export_request *req, u8);
  void (*dump_req)(struct rt_export_request *req);
};

struct rt_export_hook {
  node n;
  rtable *table;			/* The connected table */

  pool *pool;

  struct rt_export_request *req;	/* The requestor */

  struct export_stats {
    /* Export - from core to protocol */
    u32 routes;				/* Number of routes successfully exported to the protocol */
    u32 updates_received;		/* Number of route updates received */
    u32 updates_rejected;		/* Number of route updates rejected by protocol */
    u32 updates_filtered;		/* Number of route updates rejected by filters */
    u32 updates_limited;		/* Number of route updates rejected by limits */
    u32 updates_accepted;		/* Number of route updates accepted and exported */
    u32 withdraws_received;		/* Number of route withdraws received */
    u32 withdraws_accepted;		/* Number of route withdraws accepted and processed */
  } stats;

  struct bmap accept_map;		/* Keeps track which routes were really exported */
  struct bmap reject_map;		/* Keeps track which routes were rejected by export filter */

  struct fib_iterator feed_fit;		/* Routing table iterator used during feeding */

  struct coroutine *coro;		/* Exporter and feeder coroutine */
  struct bsem *sem;			/* Exporter and feeder semaphore */
  struct bmap seen_map;			/* Keep track which exports were already procesed */
  struct rt_pending_export * _Atomic last_export;/* Last export processed */

  btime last_state_change;		/* Time of last state transition */

  u8 refeed_pending;			/* Refeeding and another refeed is scheduled */
  u8 export_state;			/* Route export state (TES_*, see below) */

  void (*stopped)(struct rt_export_request *);	/* Stored callback when export is stopped */
};

void rt_request_import(rtable *tab, struct rt_import_request *req);
void rt_request_export(rtable *tab, struct rt_export_request *req);

void rt_stop_import(struct rt_import_request *, void (*stopped)(struct rt_import_request *));
void rt_stop_export(struct rt_export_request *, void (*stopped)(struct rt_export_request *));

const char *rt_import_state_name(u8 state);
const char *rt_export_state_name(u8 state);

u8 rt_import_get_state(struct rt_import_hook *);
u8 rt_export_get_state(struct rt_export_hook *);

void rte_import(struct rt_import_request *req, rte *new, linpool *lp);

#define TIS_DOWN	0
#define TIS_UP		1
#define TIS_STOP	2
#define TIS_FLUSHING	3
#define TIS_WAITING	4
#define TIS_CLEARED	5
#define TIS_MAX		6

#define TES_DOWN	0
#define TES_HUNGRY	1
#define TES_FEEDING	2
#define TES_READY	3
#define TES_STOP	4
#define TES_MAX		5

struct rtable_config {
  node n;
  char *name;
  rtable *table;
  struct proto_config *krt_attached;	/* Kernel syncer attached to this table */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  int gc_max_ops;			/* Maximum number of operations before GC is run */
  int gc_min_time;			/* Minimum time between two consecutive GC runs */
  byte sorted;				/* Routes of network are sorted according to rte_better() */
  byte internal;			/* Internal table of a protocol */
  btime min_settle_time;		/* Minimum settle time for notifications */
  btime max_settle_time;		/* Maximum settle time for notifications */
  btime export_settle_time;		/* Delay before exports are announced */
};

struct rt_subscription {
  node n;
  rtable *tab;
  void (*hook)(struct rt_subscription *b);
  void *data;
};

#define NHU_CLEAN	0
#define NHU_SCHEDULED	1
#define NHU_RUNNING	2
#define NHU_DIRTY	3

#define RTFP_CLEAN	0
#define RTFP_SCHEDULED	1
#define RTFP_RUNNING	2

typedef struct network {
  struct rte_storage *routes;			/* Available routes for this network */
  struct fib_node n;			/* FIB flags reserved for kernel syncer */
} net;

struct hostcache {
  slab *slab;				/* Slab holding all hostentries */
  struct hostentry **hash_table;	/* Hash table for hostentries */
  unsigned hash_order, hash_shift;
  unsigned hash_max, hash_min;
  unsigned hash_items;
  linpool *lp;				/* Linpool for trie */
  struct f_trie *trie;			/* Trie of prefixes that might affect hostentries */
  list hostentries;			/* List of all hostentries */
  byte update_hostcache;
};

struct hostentry {
  node ln;
  ip_addr addr;				/* IP address of host, part of key */
  ip_addr link;				/* (link-local) IP address of host, used as gw
					   if host is directly attached */
  rtable *tab;				/* Dependent table, part of key */
  struct hostentry *next;		/* Next in hash chain */
  unsigned hash_key;			/* Hash key */
  _Atomic unsigned uc_atomic;			/* Use count */
  struct rta *src;			/* Source rta entry */
  byte dest;				/* Chosen route destination type (RTD_...) */
  byte nexthop_linkable;		/* Nexthop list is completely non-device */
  u32 igp_metric;			/* Chosen route IGP metric */
};

struct rte_storage {
  struct rte_storage *next;		/* Next in chain */
  net *net;				/* Network this RTE belongs to */
  struct rte_src *src;			/* Route source that created the route */
  struct rt_import_hook *sender;	/* Channel used to send the route to the routing table */
  struct rta *attrs;			/* Attributes of this route */
  u32 id;				/* Table specific route id */
  byte flags;				/* Flags (REF_...) */
  byte pflags;				/* Protocol-specific flags */
  u8 generation;			/* See struct rte */
  btime lastmod;			/* Last modified */
};

#define REF_FILTERED	2		/* Route is rejected by import filter */
#define REF_STALE	4		/* Route is stale in a refresh cycle */
#define REF_DISCARD	8		/* Route is scheduled for discard */
#define REF_MODIFY	16		/* Route is scheduled for modify */

/* Route is valid for propagation (may depend on other flags in the future), accepts NULL */
static inline int rte_is_valid(const struct rte_storage *r) { return r && !(r->flags & REF_FILTERED); }

/* Route just has REF_FILTERED flag */
static inline int rte_is_filtered(const struct rte_storage *r) { return !!(r->flags & REF_FILTERED); }


/* Types of route announcement, also used as flags */
#define RA_UNDEF	0		/* Undefined RA type */
#define RA_OPTIMAL	1		/* Announcement of optimal route change */
#define RA_ACCEPTED	2		/* Announcement of first accepted route */
#define RA_ANY		3		/* Announcement of any route change */
#define RA_MERGED	4		/* Announcement of optimal route merged with next ones */

/* Return value of preexport() callback */
#define RIC_ACCEPT	1		/* Accepted by protocol */
#define RIC_PROCESS	0		/* Process it through import filter */
#define RIC_REJECT	-1		/* Rejected by protocol */
#define RIC_DROP	-2		/* Silently dropped by protocol */

#define rte_update  channel_rte_import

/**
 * rte_update - enter a new update to a routing table
 * @c: channel doing the update
 * @rte: a &rte representing the new route
 * @lp: a linpool for temporary allocations
 *
 * This function imports a new route to the appropriate table (via the channel).
 * Table keys are @rte->net and @rte->src, both obligatory.
 * The @rte pointer can be local as well as @rte->net. The @rte->src must be
 * either the protocol's main_source, or looked-up by rt_get_source().
 * The @rte pointer must be writable.
 *
 * For an update, the route attributes (@rte->attrs) are obligatory.
 * They can be also allocated locally. If you use an already-cached
 * attribute object, this function returns keeping your reference
 * for yourself. No attributes means withdraw.
 *
 * When rte_update() gets a route, it automatically validates it. This includes
 * checking for validity of the given network and next hop addresses and also
 * checking for host-scope or link-scope routes. Then the import filters are
 * processed and if accepted, the route is passed to route table recalculation.
 *
 * The accepted routes are then inserted into the table, replacing the old route
 * (key is the @net together with @rte->attrs->src). Then the route is announced
 * to all the channels connected to the table using the standard export mechanism.
 */
void rte_update(struct channel *c, struct rte *rte, linpool *lp) NONNULL(1,2);

/**
 * rte_withdraw - withdraw a route from a routing table
 * @c: channel doing the withdraw
 * @net: network address
 * @src: the route source identifier
 *
 * This function withdraws a previously announced route from the table.
 * No import filter is called. This function is idempotent. If no route
 * is found under the given key, it does nothing.
 */
static inline void rte_withdraw(struct channel *c, const net_addr *net, struct rte_src *src)
{
  rte e = { .net = net, .src = src}; rte_update(c, &e, NULL);
}

extern list routing_tables;
struct config;

void rt_init(void);
void rt_preconfig(struct cf_context *);
void rt_commit(struct config *new, struct config *old);
void rt_lock_table(rtable_private *);
void rt_unlock_table(rtable_private *);
void rt_subscribe(rtable *tab, struct rt_subscription *s);
void rt_unsubscribe(struct rt_subscription *s);
rtable *rt_setup(pool *, struct rtable_config *);

static inline net *net_find(rtable_private *tab, const net_addr *addr) { return (net *) fib_find(&tab->fib, addr); }
static inline net *net_find_valid(rtable_private *tab, const net_addr *addr)
{ net *n = net_find(tab, addr); return (n && rte_is_valid(n->routes)) ? n : NULL; }
static inline net *net_get(rtable_private *tab, const net_addr *addr) { return (net *) fib_get(&tab->fib, addr); }
void *net_route(rtable_private *tab, const net_addr *n);
int net_roa_check(rtable_private *tab, const net_addr *n, u32 asn);
struct rte_storage *rte_find(net *net, struct rte_src *src);
void rt_refresh_begin(rtable *t, struct rt_import_request *);
void rt_refresh_end(rtable *t, struct rt_import_request *);
void rt_modify_stale(rtable *t, struct rt_import_request *);
void rt_schedule_prune(rtable_private *t);
void channel_export_coro(void *);
void rte_dump(struct rte_storage *);
void rte_free(rtable_private *, struct rte_storage *);
struct rte_storage *rte_store(rtable_private *, const rte *, net *n);
void rte_copy_metadata(struct rte_storage *dest, struct rte_storage *src);
static inline rte rte_copy(const struct rte_storage *r)
{ return (rte) { .attrs = r->attrs, .net = r->net->n.addr, .src = r->src, .id = r->id, .sender = r->sender, .generation = r->generation, }; }
void rt_dump(rtable *);
void rt_dump_all(void);
void rt_dump_hooks(rtable *);
void rt_dump_hooks_all(void);
int rt_feed_channel(struct channel *c);
void rt_feed_channel_abort(struct channel *c);
int rt_reload_channel(struct channel *c, linpool *lp);
void rt_reload_channel_abort(struct channel *c);
void rt_refeed_channel(struct channel *c, struct bmap *seen, linpool *lp);
void rt_refeed_channel_net(struct channel *c, linpool *lp, const net_addr *n);
void rt_flush_channel(struct channel *c, linpool *lp);
void rt_prune_sync(rtable *t, int all);
int rte_update_out(struct channel *c, linpool *lp, rte *new, rte *old, struct rte_storage **old_stored);
int rte_update_in(struct channel *c, rte *new);
struct rtable_config *rt_new_table(struct cf_context *ctx, struct symbol *s, uint addr_type);

/* Default limit for ECMP next hops, defined in sysdep code */
extern const int rt_default_ecmp;

struct rt_show_data_rtable {
  node n;
  rtable *table;
  struct channel *export_channel;
};

struct rt_show_data {
  net_addr *addr;
  list tables;
  struct cf_context *ctx;              /* Parent parser context */
  struct rt_show_data_rtable *tab;	/* Iterator over table list */
  rtable_private *tab_priv;		/* Private (if locked) */
  struct rt_show_data_rtable *last_table; /* Last table in output */
  struct fib_iterator fit;		/* Iterator over networks in table */
  int verbose, tables_defined_by;
  const struct filter *filter;
  struct proto *show_protocol;
  struct proto *export_protocol;
  struct channel *export_channel;
  struct config *running_on_config;
  struct krt_proto *kernel;
  struct rt_export_hook *kernel_export_hook;
  int export_mode, primary_only, filtered, stats, show_for;

  int table_open;			/* Iteration (fit) is open */
  int net_counter, rt_counter, show_counter, table_counter;
  int net_counter_last, rt_counter_last, show_counter_last;
};

void rt_show(struct rt_show_data *);
struct rt_show_data_rtable * rt_show_add_table(struct rt_show_data *d, rtable *t);

/* Value of table definition mode in struct rt_show_data */
#define RSD_TDB_DEFAULT	  0		/* no table specified */
#define RSD_TDB_INDIRECT  0		/* show route ... protocol P ... */
#define RSD_TDB_ALL	  RSD_TDB_SET			/* show route ... table all ... */
#define RSD_TDB_DIRECT	  RSD_TDB_SET | RSD_TDB_NMN	/* show route ... table X table Y ... */

#define RSD_TDB_SET	  0x1		/* internal: show empty tables */
#define RSD_TDB_NMN	  0x2		/* internal: need matching net */

/* Value of export_mode in struct rt_show_data */
#define RSEM_NONE	0		/* Export mode not used */
#define RSEM_PREEXPORT	1		/* Routes ready for export, before filtering */
#define RSEM_EXPORT	2		/* Routes accepted by export filter */
#define RSEM_NOEXPORT	3		/* Routes rejected by export filter */
#define RSEM_EXPORTED	4		/* Routes marked in export map */

struct hostentry * rt_get_hostentry(rtable_private *tab, ip_addr a, ip_addr ll, rtable *dep);
void rta_apply_hostentry(linpool *lp, rta *a, struct hostentry *he, mpls_label_stack *mls);

/*
 * rta_set_recursive_next_hop() acquires hostentry from hostcache and fills
 * rta->hostentry field.  New hostentry has zero use count. Cached rta locks its
 * hostentry (increases its use count), uncached rta does not lock it. Hostentry
 * with zero use count is removed asynchronously during host cache update,
 * therefore it is safe to hold such hostentry temorarily. Hostentry holds a
 * lock for a 'source' rta, mainly to share multipath nexthops.
 *
 * There is no need to hold a lock for hostentry->dep table, because that table
 * contains routes responsible for that hostentry, and therefore is non-empty if
 * given hostentry has non-zero use count. If the hostentry has zero use count,
 * the entry is removed before dep is referenced.
 *
 * The protocol responsible for routes with recursive next hops should hold a
 * lock for a 'source' table governing that routes (argument tab to
 * rta_set_recursive_next_hop()), because its routes reference hostentries
 * (through rta) related to the governing table. When all such routes are
 * removed, rtas are immediately removed achieving zero uc. Then the 'source'
 * table lock could be immediately released, although hostentries may still
 * exist - they will be freed together with the 'source' table.
 */

static inline void rt_lock_hostentry(struct hostentry *he)
{
  if (he)
  {
    UNUSED uint uc = atomic_fetch_add_explicit(&he->uc_atomic, 1, memory_order_acq_rel);
    DBG("rt_lock_hostentry(addr=%I link=%I dep=%s uc=%u)\n",
	    he->addr, he->link, he->tab->name, uc+1);
  }
}

static inline void rt_unlock_hostentry(struct hostentry *he)
{
  if (he)
  {
    UNUSED uint uc = atomic_fetch_sub_explicit(&he->uc_atomic, 1, memory_order_acq_rel);
    DBG("rt_unlock_hostentry(addr=%I link=%I dep=%s uc=%u)\n",
	he->addr, he->link, he->tab->name, uc-1);
  }
}

#endif
