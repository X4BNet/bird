/*
 *	BIRD Internet Routing Daemon -- Symbol Handling
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "conf/conf.h"
#include "conf/parser.h"
#include "lib/hash.h"

/**
 * cf_push_scope - enter new scope
 * @sym: symbol representing scope name
 *
 * If we want to enter a new scope to process declarations inside
 * a nested block, we can just call cf_push_scope() to push a new
 * scope onto the scope stack which will cause all new symbols to be
 * defined in this scope and all existing symbols to be sought for
 * in all scopes stored on the stack.
 */
void
cf_push_scope(struct cf_context *ctx, struct symbol *sym)
{
  struct sym_scope *s = cfg_alloc(sizeof(struct sym_scope));
  *s = (struct sym_scope) {
    .next = ctx->sym_scope,
    .active = 1,
    .name = sym,
  };

  ctx->sym_scope = s;
}

/**
 * cf_pop_scope - leave a scope
 *
 * cf_pop_scope() pops the topmost scope from the scope stack,
 * leaving all its symbols in the symbol table, but making them
 * invisible to the rest of the config.
 */
void
cf_pop_scope(struct cf_context *ctx)
{
  ctx->sym_scope->active = 0;
  ctx->sym_scope = ctx->sym_scope->next;
  ASSERT(ctx->sym_scope);
}

/**
 * cf_symbol_class_name - get name of a symbol class
 * @sym: symbol
 *
 * This function returns a string representing the class
 * of the given symbol.
 */
char *
cf_symbol_class_name(struct symbol *sym)
{
  if (cf_symbol_is_constant(sym))
    return "constant";

  switch (sym->class)
    {
    case SYM_VOID:
      return "undefined";
    case SYM_PROTO:
      return "protocol";
    case SYM_TEMPLATE:
      return "protocol template";
    case SYM_FUNCTION:
      return "function";
    case SYM_FILTER:
      return "filter";
    case SYM_TABLE:
      return "routing table";
    default:
      return "unknown type";
    }
}

#define SYM_KEY(n)		n->name, n->scope->active
#define SYM_NEXT(n)		n->next
#define SYM_EQ(a,s1,b,s2)	!strcmp(a,b) && s1 == s2
#define SYM_FN(k,s)		cf_hash(k)
#define SYM_ORDER		6 /* Initial */

#define SYM_REHASH		sym_rehash
#define SYM_PARAMS		/8, *1, 2, 2, 6, 20

HASH_DEFINE_REHASH_FN(SYM, struct symbol)

struct symbol *
cf_alloc_symbol(struct config *cfg, struct sym_scope *scope, const byte *c, uint len)
{
  struct symbol *s = lp_alloc(cfg->mem, sizeof(struct symbol) + len + 1);
  *s = (struct symbol) { .scope = scope, .class = SYM_VOID, };
  memcpy(s->name, c, len+1);

  if (!cfg->sym_hash.data)
    HASH_INIT(cfg->sym_hash, cfg->pool, SYM_ORDER);

  HASH_INSERT2(cfg->sym_hash, SYM, cfg->pool, s);

  add_tail(&(cfg->symbols), &(s->n));

  return s;
}

static struct symbol *
cf_new_symbol(struct cf_context *ctx, const byte *c)
{
  uint l = strlen(c);
  if (l > SYM_MAX_LEN)
    cf_error("Symbol too long");

  return cf_alloc_symbol(ctx->new_config, ctx->sym_scope, c, l);
}

/**
 * cf_find_symbol - find a symbol by name
 * @cfg: specificed config
 * @c: symbol name
 *
 * This functions searches the symbol table in the config @cfg for a symbol of
 * given name. First it examines the current scope, then the second recent one
 * and so on until it either finds the symbol and returns a pointer to its
 * &symbol structure or reaches the end of the scope chain and returns %NULL to
 * signify no match.
 */
struct symbol *
cf_find_symbol(const struct config *cfg, const byte *c)
{
  struct symbol *s;

  if (cfg->sym_hash.data &&
      (s = HASH_FIND(cfg->sym_hash, SYM, c, 1)))
    return s;

  /* In CLI command parsing, cli_sym points to the current config symbol hash, otherwise it is NULL. */
  if (cfg->cli_sym &&
      (s = HASH_FIND(*(cfg->cli_sym), SYM, c, 1)))
    return s;

  return NULL;
}

/**
 * cf_get_symbol - get a symbol by name
 * @c: symbol name
 *
 * This functions searches the symbol table of the currently parsed config
 * (@new_config) for a symbol of given name. It returns either the already
 * existing symbol or a newly allocated undefined (%SYM_VOID) symbol if no
 * existing symbol is found.
 */
struct symbol *
cf_get_symbol(struct cf_context *ctx, const byte *c)
{
  return cf_find_symbol(ctx->new_config, c) ?: cf_new_symbol(ctx, c);
}

/**
 * cf_localize_symbol - get the local instance of given symbol
 * @sym: the symbol to localize
 *
 * This functions finds the symbol that is local to current scope
 * for purposes of cf_define_symbol().
 */
struct symbol *
cf_localize_symbol(struct cf_context *ctx, struct symbol *sym)
{
  /* If the symbol type is void, it has been recently allocated just in this scope. */
  if (!sym->class)
    return sym;

  /* If the scope is the current, it is already defined in this scope. */
  if (sym->scope == ctx->sym_scope)
    cf_error("Symbol already defined");

  /* Not allocated here yet, doing it now. */
  return cf_new_symbol(ctx, sym->name);
}

struct symbol *
cf_dynamic_name(struct config *cfg, const char *template, int *counter)
{
  char buf[SYM_MAX_LEN] = {};
  struct symbol *s;
  char *perc = strchr(template, '%');

  ASSERT(strlen(template) <= SYM_MAX_LEN - 11);

  if (!perc || perc[1] != 'd' || strchr(perc+1, '%'))
    bug("Invalid dynamic name pattern");

  do ASSERT(bsprintf(buf, template, ++(*counter)) >= 0);
  while (s = cf_find_symbol(cfg, buf));

  ASSERT(*counter < 1000000000);
  ASSERT(buf[SYM_MAX_LEN-1] == 0);

  uint len = strlen(buf);
  ASSERT(len < SYM_MAX_LEN);

  if (!(s = cf_alloc_symbol(cfg, cfg->root_scope, buf, len)))
    bug("Unable to allocate symbol for dynamic name");

  return s;
}

struct symbol *
cf_default_name(struct cf_context *ctx, const char *template, int *counter)
{
  return cf_dynamic_name(ctx->new_config, template, counter);
}

