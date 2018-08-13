/*
 *	BIRD Internet Routing Daemon -- Configuration Parser Headers
 *
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CONF_PARSER_H_
#define _BIRD_CONF_PARSER_H_

#include "conf/context.h"

/* Pools */

#define cfg_alloc(size) lp_alloc(ctx->cfg_mem, size)
#define cfg_allocu(size) lp_allocu(ctx->cfg_mem, size)
#define cfg_allocz(size) lp_allocz(ctx->cfg_mem, size)
#define cfg_strdup(str) lp_strdup(ctx->cfg_mem, str)
#define cfg_copy_list(dest, src, node_size) cf_copy_list(ctx, dest, src, node_size)

/* Lexer */

/* Generated lexer entry point */
typedef void * yyscan_t;
union YYSTYPE;
int cfx_lex(union YYSTYPE *, yyscan_t);

/* Config context alloc and free */
struct cf_context *cf_new_context(struct conf_order *);
void cf_free_context(struct cf_context *);

/* Lexer state alloc and free */
struct conf_state *cf_new_state(struct cf_context *ctx, const char *name);
void cf_free_state(struct cf_context *ctx, struct conf_state *cs);

/* Init keyword hash is called once from global init */
void cf_init_kh(void);

/* Hash function is common for keywords and symbols */
uint cf_hash(const byte *c);


/* Parser */

int cfx_parse(struct cf_context *ctx, void *yyscanner);

/* Generated error callback */
#define cfx_error(ctx, yyscanner, ...) cf_error(__VA_ARGS__)

/* Symbols */

void cf_push_scope(struct cf_context *, struct symbol *);
void cf_pop_scope(struct cf_context *);

struct symbol *cf_get_symbol(struct cf_context *ctx, const byte *c);
struct symbol *cf_default_name(struct cf_context *ctx, const char *template, int *counter);
struct symbol *cf_localize_symbol(struct cf_context *ctx, struct symbol *sym);

/**
 * cf_define_symbol - define meaning of a symbol
 * @sym: symbol to be defined
 * @type: symbol class to assign
 * @def: class dependent data
 *
 * Defines new meaning of a symbol. If the symbol is an undefined
 * one (%SYM_VOID), it's just re-defined to the new type. If it's defined
 * in different scope, a new symbol in current scope is created and the
 * meaning is assigned to it. If it's already defined in the current scope,
 * an error is reported via cf_error().
 *
 * Result: Pointer to the newly defined symbol. If we are in the top-level
 * scope, it's the same @sym as passed to the function.
 */
#define cf_define_symbol(ctx_, sym_, type_, var_, def_) ({ \
    struct symbol *sym__ = cf_localize_symbol(ctx_, sym_); \
    sym__->class = type_; \
    sym__->var_ = def_; \
    sym__; })

#endif
