/*
 *	BIRD Internet Routing Daemon -- Route and its Attributes
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2019--2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	In future, this file may get moved to lib/.
 */

#ifndef _BIRD_ROUTE_H_
#define _BIRD_ROUTE_H_

#include "lib/resource.h"
#include "lib/net.h"

#include <stdatomic.h>

struct ea_list;
struct protocol;
struct proto;
struct rte_src;
struct symbol;
struct timer;
struct filter;
struct cli;

/* Route */

typedef struct rte {
  struct rta *attrs;			/* Attributes of this route */
  const net_addr *net;			/* Network this RTE belongs to */
  struct rte_src *src;			/* Route source that created the route */
  struct channel *sender;		/* Channel used to send the route to the routing table */
  u32 id;				/* Table specific route id */
  u8 generation;			/* If this route import is based on other previously exported route,
					   this value should be 1 + MAX(generation of the parent routes).
					   Otherwise the route is independent and this value is zero. */
} rte;

/*
 *	Route Attributes
 *
 *	Beware: All standard BGP attributes must be represented here instead
 *	of making them local to the route. This is needed to ensure proper
 *	construction of BGP route attribute lists.
 */

/* Nexthop structure */
struct nexthop {
  ip_addr gw;				/* Next hop */
  struct iface *iface;			/* Outgoing interface */
  struct nexthop *next;
  byte flags;
  byte weight;
  byte labels_orig;			/* Number of labels before hostentry was applied */
  byte labels;				/* Number of all labels */
  u32 label[0];
};

#define RNF_ONLINK		0x1	/* Gateway is onlink regardless of IP ranges */


struct rte_src {
  struct rte_src *next;			/* Hash chain */
  struct proto *proto;			/* Protocol the source is based on */
  u32 private_id;			/* Private ID, assigned by the protocol */
  u32 global_id;			/* Globally unique ID of the source */
  _Atomic unsigned uc;			/* Use count */
};


typedef struct rta {
  struct rta *next, **pprev;		/* Hash chain */
  _Atomic u32 uc_atomic;		/* Use count */
  u32 hash_key;				/* Hash over important fields */
  struct ea_list *eattrs;		/* Extended Attribute chain */
  struct hostentry *hostentry;		/* Hostentry for recursive next-hops */
  ip_addr from;				/* Advertising router */
  u32 igp_metric;			/* IGP metric to next hop (for iBGP routes) */
  u16 cached:1;				/* Are attributes cached? */
  u16 source:7;				/* Route source (RTS_...) */
  u16 scope:4;				/* Route scope (SCOPE_... -- see ip.h) */
  u16 dest:4;				/* Route destination type (RTD_...) */
  word pref;
  struct nexthop nh;			/* Next hop */
} rta;

#define RTS_STATIC 1			/* Normal static route */
#define RTS_INHERIT 2			/* Route inherited from kernel */
#define RTS_DEVICE 3			/* Device route */
#define RTS_STATIC_DEVICE 4		/* Static device route */
#define RTS_REDIRECT 5			/* Learned via redirect */
#define RTS_RIP 6			/* RIP route */
#define RTS_OSPF 7			/* OSPF route */
#define RTS_OSPF_IA 8			/* OSPF inter-area route */
#define RTS_OSPF_EXT1 9			/* OSPF external route type 1 */
#define RTS_OSPF_EXT2 10		/* OSPF external route type 2 */
#define RTS_BGP 11			/* BGP route */
#define RTS_PIPE 12			/* Inter-table wormhole */
#define RTS_BABEL 13			/* Babel route */
#define RTS_RPKI 14			/* Route Origin Authorization */
#define RTS_PERF 15			/* Perf checker */
#define RTS_MAX 16

#define RTD_NONE 0			/* Undefined next hop */
#define RTD_UNICAST 1			/* Next hop is neighbor router */
#define RTD_BLACKHOLE 2			/* Silently drop packets */
#define RTD_UNREACHABLE 3		/* Reject as unreachable */
#define RTD_PROHIBIT 4			/* Administratively prohibited */
#define RTD_MAX 5

#define IGP_METRIC_UNKNOWN 0x80000000	/* Default igp_metric used when no other
					   protocol-specific metric is availabe */


extern const char * rta_dest_names[RTD_MAX];

static inline const char *rta_dest_name(uint n)
{ return (n < RTD_MAX) ? rta_dest_names[n] : "???"; }

/* Route has regular, reachable nexthop (i.e. not RTD_UNREACHABLE and like) */
static inline int rte_is_reachable(rte *r)
{ return r->attrs->dest == RTD_UNICAST; }

/* Rate limiting token buffer for route trace */
extern struct tbf rl_pipe;


/*
 *	Extended Route Attributes
 */

typedef struct eattr {
  word id;				/* EA_CODE(PROTOCOL_..., protocol-dependent ID) */
  byte flags;				/* Protocol-dependent flags */
  byte type;				/* Attribute type and several flags (EAF_...) */
  union {
    uintptr_t data;
    const struct adata *ptr;		/* Attribute data elsewhere */
  } u;
} eattr;


#define EA_CODE(proto,id) (((proto) << 8) | (id))
#define EA_ID(ea) ((ea) & 0xff)
#define EA_PROTO(ea) ((ea) >> 8)
#define EA_CUSTOM(id) ((id) | EA_CUSTOM_BIT)
#define EA_IS_CUSTOM(ea) ((ea) & EA_CUSTOM_BIT)
#define EA_CUSTOM_ID(ea) ((ea) & ~EA_CUSTOM_BIT)

const char *ea_custom_name(uint ea);

#define EA_GEN_IGP_METRIC EA_CODE(PROTOCOL_NONE, 0)

#define EA_CODE_MASK 0xffff
#define EA_CUSTOM_BIT 0x8000
#define EA_ALLOW_UNDEF 0x10000		/* ea_find: allow EAF_TYPE_UNDEF */
#define EA_BIT(n) ((n) << 24)		/* Used in bitfield accessors */
#define EA_BIT_GET(ea) ((ea) >> 24)

#define EAF_TYPE_MASK 0x1f		/* Mask with this to get type */
#define EAF_TYPE_INT 0x01		/* 32-bit unsigned integer number */
#define EAF_TYPE_OPAQUE 0x02		/* Opaque byte string (not filterable) */
#define EAF_TYPE_IP_ADDRESS 0x04	/* IP address */
#define EAF_TYPE_ROUTER_ID 0x05		/* Router ID (IPv4 address) */
#define EAF_TYPE_AS_PATH 0x06		/* BGP AS path (encoding per RFC 1771:4.3) */
#define EAF_TYPE_BITFIELD 0x09		/* 32-bit embedded bitfield */
#define EAF_TYPE_INT_SET 0x0a		/* Set of u32's (e.g., a community list) */
#define EAF_TYPE_PTR 0x0d		/* Pointer to an object */
#define EAF_TYPE_EC_SET 0x0e		/* Set of pairs of u32's - ext. community list */
#define EAF_TYPE_LC_SET 0x12		/* Set of triplets of u32's - large community list */
#define EAF_TYPE_UNDEF 0x1f		/* `force undefined' entry */
#define EAF_EMBEDDED 0x01		/* Data stored in eattr.u.data (part of type spec) */
#define EAF_VAR_LENGTH 0x02		/* Attribute length is variable (part of type spec) */
#define EAF_ORIGINATED 0x20		/* The attribute has originated locally */
#define EAF_FRESH 0x40			/* An uncached attribute (e.g. modified in export filter) */

typedef struct adata {
  uint length;				/* Length of data */
  byte data[0];
} adata;

extern const adata null_adata;		/* adata of length 0 */

static inline struct adata *
lp_alloc_adata(struct linpool *pool, uint len)
{
  struct adata *ad = lp_alloc(pool, sizeof(struct adata) + len);
  ad->length = len;
  return ad;
}

static inline int adata_same(const struct adata *a, const struct adata *b)
{ return (a->length == b->length && !memcmp(a->data, b->data, a->length)); }


typedef struct ea_list {
  struct ea_list *next;			/* In case we have an override list */
  byte flags;				/* Flags: EALF_... */
  byte rfu;
  word count;				/* Number of attributes */
  eattr attrs[0];			/* Attribute definitions themselves */
} ea_list;

#define EALF_SORTED 1			/* Attributes are sorted by code */
#define EALF_BISECT 2			/* Use interval bisection for searching */
#define EALF_CACHED 4			/* Attributes belonging to cached rta */

/* These two calls must be always guarded by the_bird_lock.
 *
 * If you release the_bird_lock between obtaining a brand new rte_src
 * and locking it by rt_lock_source() (e.g. inside rte_update()),
 * you are at risk of having your rte_src pruned inbetween without further notice.
 * It is recommended to lock the source or announce the route immediately after
 * obtaining the rte_src.
 *
 * This should be fixed in near future.
 * */
struct rte_src *rt_get_source(struct proto *p, u32 id);
void rt_prune_sources(void);

/* Locking and unlocking itself may anyway run unguarded themselves */
static inline void rt_lock_source(struct rte_src *src)
{ atomic_fetch_add_explicit(&src->uc, 1, memory_order_acq_rel); }
static inline void rt_unlock_source(struct rte_src *src)
{ atomic_fetch_sub_explicit(&src->uc, 1, memory_order_acq_rel); }

struct ea_walk_state {
  ea_list *eattrs;			/* Ccurrent ea_list, initially set by caller */
  eattr *ea;				/* Current eattr, initially NULL */
  u32 visited[4];			/* Bitfield, limiting max to 128 */
};

eattr *ea_find(ea_list *, unsigned ea);
eattr *ea_walk(struct ea_walk_state *s, uint id, uint max);
uintptr_t ea_get_int(ea_list *, unsigned ea, uintptr_t def);
void ea_dump(ea_list *);
void ea_sort(ea_list *);		/* Sort entries in all sub-lists */
unsigned ea_scan(ea_list *);		/* How many bytes do we need for merged ea_list */
void ea_merge(ea_list *from, ea_list *to); /* Merge sub-lists to allocated buffer */
int ea_same(ea_list *x, ea_list *y);	/* Test whether two ea_lists are identical */
uint ea_hash(ea_list *e);	/* Calculate 16-bit hash value */
ea_list *ea_append(ea_list *to, ea_list *what);
void ea_format_bitfield(const struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max);

#define ea_normalize(ea) do { \
  if (ea->next) { \
    ea_list *t = alloca(ea_scan(ea)); \
    ea_merge(ea, t); \
    ea = t; \
  } \
  ea_sort(ea); \
  if (ea->count == 0) \
    ea = NULL; \
} while(0) \

static inline eattr *
ea_set_attr(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, uintptr_t val)
{
  ea_list *a = lp_alloc(pool, sizeof(ea_list) + sizeof(eattr));
  eattr *e = &a->attrs[0];

  a->flags = EALF_SORTED;
  a->count = 1;
  a->next = *to;
  *to = a;

  e->id = id;
  e->type = type;
  e->flags = flags;

  if (type & EAF_EMBEDDED)
    e->u.data = (u32) val;
  else
    e->u.ptr = (struct adata *) val;

  return e;
}

static inline void
ea_set_attr_u32(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, u32 val)
{ ea_set_attr(to, pool, id, flags, type, (uintptr_t) val); }

static inline void
ea_set_attr_ptr(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, struct adata *val)
{ ea_set_attr(to, pool, id, flags, type, (uintptr_t) val); }

static inline void
ea_set_attr_data(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, void *data, uint len)
{
  struct adata *a = lp_alloc_adata(pool, len);
  memcpy(a->data, data, len);
  ea_set_attr(to, pool, id, flags, type, (uintptr_t) a);
}


#define NEXTHOP_MAX_SIZE (sizeof(struct nexthop) + sizeof(u32)*MPLS_MAX_LABEL_STACK)

static inline size_t nexthop_size(const struct nexthop *nh)
{ return sizeof(struct nexthop) + sizeof(u32)*nh->labels; }
int nexthop__same(struct nexthop *x, struct nexthop *y); /* Compare multipath nexthops */
static inline int nexthop_same(struct nexthop *x, struct nexthop *y)
{ return (x == y) || nexthop__same(x, y); }
struct nexthop *nexthop_merge(struct nexthop *x, struct nexthop *y, int rx, int ry, int max, linpool *lp);
struct nexthop *nexthop_sort(struct nexthop *x);
static inline void nexthop_link(struct rta *a, struct nexthop *from)
{ memcpy(&a->nh, from, nexthop_size(from)); }
void nexthop_insert(struct nexthop **n, struct nexthop *y);
int nexthop_is_sorted(struct nexthop *x);

void rta_init(void);
static inline size_t rta_size(const rta *a) { return sizeof(rta) + sizeof(u32)*a->nh.labels; }
#define RTA_MAX_SIZE (sizeof(rta) + sizeof(u32)*MPLS_MAX_LABEL_STACK)
rta *rta_lookup(rta *);			/* Get rta equivalent to this one, uc++ */
static inline int rta_is_cached(rta *r) { return r->cached; }
static inline rta *rta_clone(rta *r)
{
  DBG("rta_clone(%p)\n", r);
  atomic_fetch_add_explicit(&r->uc_atomic, 1, memory_order_acq_rel);
  return r;
}
void rta__free(rta *r);
static inline void rta_free(rta *r)
{
  DBG("rta_free(%p)\n", r);
  if (r && (atomic_fetch_sub_explicit(&r->uc_atomic, 1, memory_order_acq_rel) == 1))
    rta__free(r);
}
rta *rta_do_cow(rta *o, linpool *lp);
static inline rta * rta_cow(rta *r, linpool *lp) { return rta_is_cached(r) ? rta_do_cow(r, lp) : r; }
void rta_dump(rta *);
void rta_dump_all(void);
void rta_show(struct cli *, rta *);

u32 rt_get_igp_metric(struct rta *);

/*
 *	Default protocol preferences
 */

#define DEF_PREF_DIRECT		240	/* Directly connected */
#define DEF_PREF_STATIC		200	/* Static route */
#define DEF_PREF_OSPF		150	/* OSPF intra-area, inter-area and type 1 external routes */
#define DEF_PREF_BABEL		130	/* Babel */
#define DEF_PREF_RIP		120	/* RIP */
#define DEF_PREF_BGP		100	/* BGP */
#define DEF_PREF_RPKI		100	/* RPKI */
#define DEF_PREF_INHERITED	10	/* Routes inherited from other routing daemons */

/*
 *	Route Origin Authorization
 */

#define ROA_UNKNOWN	0
#define ROA_VALID	1
#define ROA_INVALID	2

#endif
