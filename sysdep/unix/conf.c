/*
 *	BIRD Internet Routing Daemon -- Unix Config Reader
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nest/bird.h"
#include "lib/coro.h"
#include "lib/locking.h"
#include "conf/conf.h"
#include "conf/parser.h"
#include "sysdep/unix/unix.h"

#ifdef PATH_IPROUTE_DIR

static inline void
add_num_const(struct cf_context *ctx, char *name, int val, const char *file, const uint line)
{
  struct f_val *v = cfg_alloc(sizeof(struct f_val));
  *v = (struct f_val) { .type = T_INT, .val.i = val };
  struct symbol *sym = cf_get_symbol(ctx, name);
  if (sym->class && (sym->scope == ctx->sym_scope))
    cf_error("Error reading value for %s from %s:%d: already defined", name, file, line);

  cf_define_symbol(ctx, sym, SYM_CONSTANT | T_INT, val, v);
}


/* the code of read_iproute_table() is based on
   rtnl_tab_initialize() from iproute2 package */
static void
read_iproute_table(struct cf_context *ctx, char *file, char *prefix, int max)
{
  char buf[512], namebuf[512];
  char *name;
  int val;
  FILE *fp;

  strcpy(namebuf, prefix);
  name = namebuf + strlen(prefix);

  fp = fopen(file, "r");
  if (!fp)
    return;

  for (uint line = 1; fgets(buf, sizeof(buf), fp); line++)
  {
    char *p = buf;

    while (*p == ' ' || *p == '\t')
      p++;

    if (*p == '#' || *p == '\n' || *p == 0)
      continue;

    if (sscanf(p, "0x%x %s\n", &val, name) != 2 &&
	sscanf(p, "0x%x %s #", &val, name) != 2 &&
	sscanf(p, "%d %s\n", &val, name) != 2 &&
	sscanf(p, "%d %s #", &val, name) != 2)
      continue;

    if (val < 0 || val > max)
      continue;

    for(p = name; *p; p++)
      if ((*p < 'a' || *p > 'z') && (*p < 'A' || *p > 'Z') && (*p < '0' || *p > '9') && (*p != '_'))
	*p = '_';

    add_num_const(ctx, namebuf, val, file, line);
  }

  fclose(fp);
}

#endif // PATH_IPROUTE_DIR


char *config_name = PATH_CONFIG_FILE;

void
sysdep_preconfig(struct cf_context *ctx)
{
  init_list(&ctx->new_config->logfiles);

  ctx->new_config->latency_limit = UNIX_DEFAULT_LATENCY_LIMIT;
  ctx->new_config->watchdog_warning = UNIX_DEFAULT_WATCHDOG_WARNING;

#ifdef PATH_IPROUTE_DIR
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_protos", "ipp_", 256);
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_realms", "ipr_", 256);
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_scopes", "ips_", 256);
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_tables", "ipt_", 256);
#endif
}

int
sysdep_commit(struct config *new, struct config *old UNUSED)
{
  log_switch(0, &new->logfiles, new->syslog_name);
  return 0;
}

struct unix_conf_order {
  struct conf_order co;
  struct unix_ifs *ifs;
};

struct unix_ifs {
  struct unix_ifs *up;			/* Who included this file */
  struct unix_ifs *next;		/* Next file to include */

  struct conf_state *state;		/* Appropriate conf_state */
  int fd;				/* File descriptor */
  byte depth;				/* Include depth remaining, 0 = cannot include */
};

static int
unix_cf_read(struct conf_order *co, byte *dest, uint len)
{
  struct unix_conf_order *uco = (struct unix_conf_order *) co;
  struct cf_context *ctx = co->ctx;

  ASSERT(uco->ifs->state == co->state);

  if (uco->ifs->fd == -1)
    uco->ifs->fd = open(co->state->name, O_RDONLY);

  if (uco->ifs->fd < 0)
    if (uco->ifs->up)
      {
	const char *fn = co->state->name;
	co->state = uco->ifs->up->state; /* We want to raise this error in the parent file */
	cf_error("Unable to open included file %s: %m", fn);
      }
    else
      cf_error("Unable to open configuration file %s: %m", co->state->name);

  int l = read(uco->ifs->fd, dest, len);
  if (l < 0)
    cf_error("Read error: %m");
  return l;
}

static void
unix_cf_include(struct conf_order *co, char *name, uint len)
{
  struct unix_conf_order *uco = (struct unix_conf_order *) co;
  struct cf_context *ctx = co->ctx;

  if (!uco->ifs)
    cf_error("Max include depth reached");

  byte new_depth = uco->ifs->depth - 1;

  /* Includes are relative to the current file unless the path is absolute.
   * Joining the current file dirname with the include relative path. */
  char *patt;
  if (*name != '/')
    {
      /* dlen is upper bound of current file dirname length */
      int dlen = strlen(co->state->name);
      char *dir = alloca(dlen + 1);
      patt = alloca(dlen + len + 2);

      /* dirname() may overwrite its argument */
      memcpy(dir, co->state->name, dlen + 1);
      sprintf(patt, "%s/%s", dirname(dir), name);
    }
  else
    patt = name;

  /* Skip globbing if there are no wildcards, mainly to get proper
     response when the included config file is missing */
  if (!strpbrk(name, "?*["))
    {
      struct unix_ifs *uifs = lp_alloc(co->ctx->cfg_mem, sizeof(struct unix_ifs));

      *uifs = (struct unix_ifs) {
	.next = uco->ifs,
	.up = uco->ifs,
	.state = cf_new_state(co->ctx, patt),
	.fd = -1,
	.depth = new_depth,
      };

      co->state = uifs->state;
      uco->ifs = uifs;

      return;
    }

  /* Expand the pattern */
  /* FIXME: glob() is not completely thread-safe, see the manpage */
  glob_t g = {};
  int rv = glob(patt, GLOB_ERR | GLOB_NOESCAPE, NULL, &g);
  if (rv == GLOB_ABORTED)
    cf_error("Unable to match pattern %s: %m", patt);
  if ((rv != 0) || (g.gl_pathc <= 0))
    return;

  /*
   * Now we put all found files to ifs stack in reverse order, they
   * will be activated and processed in order as ifs stack is popped
   * by pop_ifs() and enter_ifs() in check_eof().
   */
  struct unix_ifs *last_uifs = uco->ifs;
  for (int i = g.gl_pathc - 1; i >= 0; i--)
    {
      char *fname = g.gl_pathv[i];
      struct stat fs;

      if (stat(fname, &fs) < 0)
	{
	  globfree(&g);
	  cf_error("Unable to stat included file %s: %m", fname);
	}

      if (fs.st_mode & S_IFDIR)
        continue;

      /* Prepare new stack item */
      struct unix_ifs *uifs = lp_alloc(co->ctx->cfg_mem, sizeof(struct unix_ifs));

      *uifs = (struct unix_ifs) {
	.next = last_uifs,
	.up = uco->ifs,
	.state = cf_new_state(co->ctx, fname),
	.fd = -1,
	.depth = new_depth,
      };

      last_uifs = uifs;
    }

  globfree(&g);

  co->state = last_uifs->state;
  uco->ifs = last_uifs;

  return;
}

static int
unix_cf_outclude(struct conf_order *co)
{
  struct unix_conf_order *uco = (struct unix_conf_order *) co;

  close(uco->ifs->fd);
  cf_free_state(co->ctx, uco->ifs->state);

  /* No more files to read */
  if (!uco->ifs->next)
    return 1;

  uco->ifs = uco->ifs->next;
  co->state = uco->ifs->state;
  return 0;
}

#define MAX_INCLUDE_DEPTH 8
  
int
unix_read_config(const char *name, struct config *new_config, cf_error_type arg_cf_error, volatile _Atomic _Bool *cancelled)
{
  struct conf_state state = { .name = name };

  struct unix_ifs uifs = {
    .state = &state,
    .depth = MAX_INCLUDE_DEPTH,
    .fd = -1,
  };

  struct unix_conf_order uco = {
    .co = {
      .cf_read_hook = unix_cf_read,
      .cf_include = unix_cf_include,
      .cf_outclude = unix_cf_outclude,
      .cf_error_hook = arg_cf_error,
      .state = &state,
      .cancelled = cancelled,
      .new_config = new_config,
    },
    .ifs = &uifs,
  };

  return config_parse(&uco.co);
}

static void
unix_cf_error_die(struct conf_order *order, const char *msg, va_list args)
{
  die("%s, line %u: %V", order->state->name, order->state->lino, msg, &args);
}

struct config *
read_config(void)
{
  struct config *conf = config_alloc(NULL, NULL);

  if (unix_read_config(config_name, conf, unix_cf_error_die, NULL))
    return conf;

  config_free(conf);
  return NULL;
}

static struct reconfig_coro {
  const char *name;
  int type;
  uint timeout;
  struct coroutine *coro;
  cli *cli;
  cf_error_type err;
  struct conf_order *order;
  volatile _Atomic _Bool cancelled;
} *current_reconfig_coro;

static _Thread_local struct reconfig_coro *local_reconfig_coro;

static void
unix_cf_error_log(struct conf_order *order, const char *msg, va_list args)
{
  log(L_ERR "%s, line %u: %V", order->state->name, order->state->lino, msg, &args);
}

static void
unix_cf_error_cli(struct conf_order *order, const char *msg, va_list args)
{
  birdloop_enter(&main_birdloop);

  cli *c = local_reconfig_coro->cli;
  if (c)
  {
    cli_printf(c, 8002, "%s, line %d: %s", order->state->name, order->state->lino, msg, &args);
    cli_write_trigger(c);
    birdloop_ping(&main_birdloop);
  }

  birdloop_leave(&main_birdloop);
}

static void
cmd_reconfig_msg(int r)
{
  switch (r)
    {
    case CONF_DONE:	cli_msg( 3, "Reconfigured"); break;
    case CONF_PROGRESS: cli_msg( 4, "Reconfiguration in progress"); break;
    case CONF_QUEUED:	cli_msg( 5, "Reconfiguration already in progress, queueing new config"); break;
    case CONF_UNQUEUED:	cli_msg(17, "Reconfiguration already in progress, removing queued config"); break;
    case CONF_CONFIRM:	cli_msg(18, "Reconfiguration confirmed"); break;
    case CONF_SHUTDOWN:	cli_msg( 6, "Reconfiguration ignored, shutting down"); break;
    case CONF_NOTHING:	cli_msg(19, "Nothing to do"); break;
    default:		break;
    }
}

/* Hack for scheduled undo notification */
cli *cmd_reconfig_stored_cli;

void
cmd_reconfig_undo_notify(void)
{
  if (cmd_reconfig_stored_cli)
    {
      cli *c = cmd_reconfig_stored_cli;
      cli_printf(c, CLI_ASYNC_CODE, "Config timeout expired, starting undo");
      cli_write_trigger(c);
    }
}

void
reconfig_coro(void *data)
{
  struct reconfig_coro *rc = local_reconfig_coro = data;

  birdloop_enter(&main_birdloop);
  struct config *conf = config_alloc(NULL, NULL);
  birdloop_leave(&main_birdloop);
  
  int success = unix_read_config(rc->name, conf, rc->err, &rc->cancelled);

  birdloop_enter(&main_birdloop);

  if (!success)
  {
    config_free(conf);
    goto cleanup;
  }

  this_cli = rc->cli;

  switch (rc->type)
  {
    case RECONFIG_IGNORE:
      ASSERT_DIE(this_cli == NULL);
      config_free(conf);
      break;

    case RECONFIG_NONE:
      config_free(conf);
      if (this_cli)
      {
	cli_msg(20, "Configuration OK");
	cli_write_trigger(this_cli);
	this_cli->cont = NULL;
      }
      break;

    default:
      {
	if (this_cli)
	{
	  cli_msg(-20, "Configuration parsed OK, applying.");
	  cli_write_trigger(this_cli);
	}

	int r = config_commit(conf, rc->type, rc->timeout);

	if ((r >= 0) && (rc->timeout > 0) && this_cli)
	{
	  cmd_reconfig_stored_cli = this_cli;
	  cli_msg(-22, "Undo scheduled in %d s", rc->timeout);
	}

	if (this_cli)
	{
	  cmd_reconfig_msg(r);
	  cli_write_trigger(this_cli);
	  this_cli->cont = NULL;
	}
      }
  }

cleanup:
  if (rc == current_reconfig_coro)
    current_reconfig_coro = NULL;

  rfree(rc->coro);
  mb_free(rc);

  birdloop_ping(&main_birdloop);
  birdloop_leave(&main_birdloop);
}

static void
cmd_reconfig_cont(cli *c UNUSED)
{}

static _Bool
cancel_reconfig(void)
{
  /* Nothing to cancel? */
  if (!current_reconfig_coro)
    return 0;

  /* Set the reconfig type to ignore to drop it at least before commiting reconfig */
  current_reconfig_coro->type = RECONFIG_IGNORE;

  /* If the CLI is still connected to that reconfig coro, finish the command right now. */
  if (current_reconfig_coro->cli)
  {
    current_reconfig_coro->cli->cont = NULL;
    cli_printf(current_reconfig_coro->cli, 26, "Reconfiguration cancelled");
    cli_write_trigger(current_reconfig_coro->cli);
    /* This is always called from the main thread, no need to io_loop_reload(). */
    current_reconfig_coro->cli = NULL;
  }

  /* Inform the lexer that it should stop right now. */
  atomic_store_explicit(&current_reconfig_coro->cancelled, 1, memory_order_release);

  /* Nobody is now reconfiguring. */
  current_reconfig_coro = NULL;

  /* Yes, something has been cancelled. */
  return 1;
}

void
cmd_reconfig_cancel(void)
{
  if (cancel_reconfig())
    cli_msg(26, "Reconfiguration succesfully cancelled");
  else
    cli_msg(19, "Nothing to cancel");
}

void
run_reconfig(cli *c, const char *name, int type, uint timeout)
{
  if (cancel_reconfig())
    if (c)
      cli_printf(c, -26, "Previous reconfiguration cancelled");

  ASSERT_DIE(current_reconfig_coro == NULL);

  if (c)
  {
    c->cont = cmd_reconfig_cont;
    cli_printf(c, -2, "Reading configuration from %s", name);
  }

  current_reconfig_coro = mb_alloc(&root_pool, sizeof(struct reconfig_coro));
  *current_reconfig_coro = (struct reconfig_coro) {
    .name = name,
    .type = type,
    .timeout = timeout,
    .cli = c,
    .err = c ? unix_cf_error_cli : unix_cf_error_log,
  };

  current_reconfig_coro->coro = coro_run(&root_pool, reconfig_coro, current_reconfig_coro);
}

void
async_config(void)
{
  log(L_INFO "Reconfiguration requested by SIGHUP");
  run_reconfig(NULL, config_name, RECONFIG_HARD, 0);
}

void
cmd_reconfig(const char *name, int type, uint timeout)
{
  if (cli_access_restricted())
    return;

  run_reconfig(this_cli, name ? name : config_name, type, timeout);
}

void
cmd_reconfig_confirm(void)
{
  if (cli_access_restricted())
    return;

  int r = config_confirm();
  cmd_reconfig_msg(r);
}

void
cmd_reconfig_undo(void)
{
  if (cli_access_restricted())
    return;

  cli_msg(-21, "Undo requested");

  int r = config_undo();
  cmd_reconfig_msg(r);
}

void
cmd_reconfig_status(void)
{
  int s = config_status();
  btime t = config_timer_status();

  switch (s)
  {
    case CONF_DONE:      cli_msg(-3, "Daemon is up and running"); break;
    case CONF_PROGRESS:  cli_msg(-4, "Reconfiguration in progress"); break;
    case CONF_QUEUED:    cli_msg(-5, "Reconfiguration in progress, next one enqueued"); break;
    case CONF_SHUTDOWN:  cli_msg(-6, "Shutdown in progress"); break;
    default:             break;
  }

  if (t >= 0)
    cli_msg(-22, "Configuration unconfirmed, undo in %t s", t);

  cli_msg(0, "");
}