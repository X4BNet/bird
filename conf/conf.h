/*
 *	BIRD Internet Routing Daemon -- Configuration File Handling
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CONF_H_
#define _BIRD_CONF_H_

#include "sysdep/config.h"
#include "nest/cli.h"
#include "lib/ip.h"
#include "lib/hash.h"
#include "lib/resource.h"
#include "lib/timer.h"

/* Configuration structure */

typedef HASH(struct symbol) symbol_hash;

struct config {
  pool *pool;				/* Pool the configuration is stored in */
  linpool *mem;				/* Linear pool containing configuration data */
  list protos;				/* Configured protocol instances (struct proto_config) */
  list tables;				/* Configured routing tables (struct rtable_config) */
  list logfiles;			/* Configured log files (sysdep) */
  list tests;				/* Configured unit tests (f_bt_test_suite) */
  list symbols;				/* Configured symbols in config order */

  int mrtdump_file;			/* Configured MRTDump file (sysdep, fd in unix) */
  const char *syslog_name;		/* Name used for syslog (NULL -> no syslog) */
  struct rtable_config *def_tables[NET_MAX]; /* Default routing tables for each network */
  struct iface_patt *router_id_from;	/* Configured list of router ID iface patterns */
  struct rtable_config *def_table_attrs;/* Default table attributes */

  u32 router_id;			/* Our Router ID */
  u32 proto_default_debug;		/* Default protocol debug mask */
  u32 proto_default_mrtdump;		/* Default protocol mrtdump mask */
  u32 channel_default_debug;		/* Default channel debug mask */
  struct timeformat tf_route;		/* Time format for 'show route' */
  struct timeformat tf_proto;		/* Time format for 'show protocol' */
  struct timeformat tf_log;		/* Time format for the logfile */
  struct timeformat tf_base;		/* Time format for other purposes */
  u32 gr_wait;				/* Graceful restart wait timeout (sec) */
  const char *hostname;			/* Hostname */

  int cli_debug;			/* Tracing of CLI connections and commands */
  int latency_debug;			/* I/O loop tracks duration of each event */
  int pipe_debug;			/* Track route propagation through pipes */
  int table_debug;			/* Track table maintenance operations */
  u32 latency_limit;			/* Events with longer duration are logged (us) */
  u32 watchdog_warning;			/* I/O loop watchdog limit for warning (us) */
  u32 watchdog_timeout;			/* Watchdog timeout (in seconds, 0 = disabled) */
  symbol_hash sym_hash;		/* Lexer: symbol hash table */
  symbol_hash *cli_sym;		/* Fallback symbol hash table for CLI parsing */
  struct sym_scope *root_scope;		/* Scope for root symbols */
  int obstacle_count;			/* Number of items blocking freeing of this config */
  int shutdown;				/* This is a pseudo-config for daemon shutdown */
  int gr_down;				/* This is a pseudo-config for graceful restart */
  btime load_time;			/* When we've got this configuration */
};

struct conf_state {
  void *buffer;				/* Internal lexer state */
  const char *name;			/* Current file name */
  const char *lastpos;			/* Last seen position in lexer */
  uint lino;				/* Current line */
  uint chno;				/* Current column */
  uint toklen;				/* Current token length */
};

struct conf_order {
  struct config *new_config;		/* Store the allocated config here */
  struct cf_context *ctx;		/* Internal config context, do not set */
  struct conf_state *state;
  struct pool *pool;			/* If set, use this resource pool */
  struct linpool *lp;			/* If set, use this linpool */
  int (*cf_read_hook)(struct conf_order *order, byte *buf, uint max);
  void (*cf_include)(struct conf_order *order, char *name, uint len);
  int (*cf_outclude)(struct conf_order *order);
  void (*cf_error_hook)(struct conf_order *order, const char *msg, va_list args);
  int lexer_hack;			/* Begin with CLI_MARKER token */
};

typedef void (*cf_error_type)(struct conf_order *order, const char *msg, va_list args);

/* Please don't use these variables in protocols. Use proto_config->global instead. */
extern struct config *config;		/* Currently active configuration */

/**
 * Parse configuration
 *
 * Arguments:
 * @order provides callbacks to read config files
 *
 * Return value:
 * 1 on success; order->new_config is then set to the parsed config
 * 0 on fail; order->new_config is undefined
 **/
int config_parse(struct conf_order *order);

/**
 * Parse CLI command
 *
 * Arguments:
 * @order provides callbacks to read command line
 *
 * Return value:
 * 1 on success
 * 0 on fail
 *
 * Parsed config is never kept, order->new_config should be zero after return.
 **/
int cli_parse(struct conf_order *order);

/** Callback for returning error from parser hooks */
#define cf_error(...) cf_error_(ctx, __VA_ARGS__)
void cf_error_(struct cf_context *, const char *msg, ...) NORET;

void config_free(struct config *);
int config_commit(struct config *, int type, uint timeout);
int config_confirm(void);
int config_undo(void);
int config_status(void);
btime config_timer_status(void);
void config_init(void);
void config_add_obstacle(struct config *);
void config_del_obstacle(struct config *);
void order_shutdown(int gr);

#define RECONFIG_NONE	0
#define RECONFIG_HARD	1
#define RECONFIG_SOFT	2
#define RECONFIG_UNDO	3

#define CONF_DONE	0
#define CONF_PROGRESS	1
#define CONF_QUEUED	2
#define CONF_UNQUEUED	3
#define CONF_CONFIRM	4
#define CONF_SHUTDOWN	-1
#define CONF_NOTHING	-2

/* Pools */

static inline void *cf_alloc(struct config *cf, unsigned size) { return lp_alloc(cf->mem, size); }
static inline void *cf_allocu(struct config *cf, unsigned size) { return lp_allocu(cf->mem, size); }
static inline void *cf_allocz(struct config *cf, unsigned size) { return lp_allocz(cf->mem, size); }
static inline char *cf_strdup(struct config *cf, const char *c) { return lp_strdup(cf->mem, c); }

void cf_copy_list(struct config *cf, list *dest, list *src, unsigned node_size);

/* Lexer */

struct symbol {
  node n;				/* In list of symbols in config */
  struct symbol *next;
  struct sym_scope *scope;
  int class;				/* SYM_* */
  uint flags;				/* SYM_FLAG_* */

  union {
    struct proto_config *proto;		/* For SYM_PROTO and SYM_TEMPLATE */
    const struct f_line *function;	/* For SYM_FUNCTION */
    const struct filter *filter;	/* For SYM_FILTER */
    struct rtable_config *table;	/* For SYM_TABLE */
    struct f_dynamic_attr *attribute;	/* For SYM_ATTRIBUTE */
    struct f_val *val;			/* For SYM_CONSTANT */
    uint offset;			/* For SYM_VARIABLE */
  };

  char name[0];
};

struct sym_scope {
  struct sym_scope *next;		/* Next on scope stack */
  struct symbol *name;			/* Name of this scope */
  uint slots;				/* Variable slots */
  int active;				/* Currently entered */
};

#define SYM_MAX_LEN 64

/* Remember to update cf_symbol_class_name() */
#define SYM_VOID 0
#define SYM_PROTO 1
#define SYM_TEMPLATE 2
#define SYM_FUNCTION 3
#define SYM_FILTER 4
#define SYM_TABLE 5
#define SYM_ATTRIBUTE 6

#define SYM_VARIABLE 0x100	/* 0x100-0x1ff are variable types */
#define SYM_VARIABLE_RANGE SYM_VARIABLE ... (SYM_VARIABLE | 0xff)
#define SYM_CONSTANT 0x200	/* 0x200-0x2ff are variable types */
#define SYM_CONSTANT_RANGE SYM_CONSTANT ... (SYM_CONSTANT | 0xff)

#define SYM_TYPE(s) ((s)->val->type)
#define SYM_VAL(s) ((s)->val->val)

/* Symbol flags */
#define SYM_FLAG_SAME 0x1	/* For SYM_FUNCTION and SYM_FILTER */

char *cf_symbol_class_name(struct symbol *sym);

static inline int cf_symbol_is_constant(struct symbol *sym)
{ return (sym->class & 0xff00) == SYM_CONSTANT; }

/* Find a symbol in existing config. */
struct symbol *cf_find_symbol(const struct config *cfg, const byte *c);

/* Allocate a new symbol in existing config. To be done better. */
struct symbol *cf_alloc_symbol(struct config *cfg, struct sym_scope *scope, const byte *c, uint len);

/* Allocate a new dynamic name by a template in existing config. To be done better. */
struct symbol *cf_dynamic_name(struct config *cfg, const char *template, int *counter);


/* Sysdep hooks */

void sysdep_preconfig(struct cf_context *ctx);
int sysdep_commit(struct config *, struct config *);
void sysdep_shutdown_done(void);

#endif
