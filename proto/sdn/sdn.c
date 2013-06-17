/*
 *	BIRD -- Binding for SDN controllers
 *
 *	(c) 2013 Sam Russell <sam.h.russell@gmail.com>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: SDN
 *
 * The SDN protocol 
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"

#include "sdn.h"

static void
sdn_rt_notify(struct proto *P, rtable *src_table, net *n, rte *new, rte *old, ea_list *attrs)
{
  struct sdn_proto *p = (struct sdn_proto *) P;
  struct announce_hook *ah = (src_table == P->table) ? p->peer_ahook : P->main_ahook;
  rtable *dst_table = ah->table;
  struct proto *src;

  net *nn;
  rte *e;
  rta a;

  if (!new && !old)
    return;

  if (dst_table->sdn_busy)
    {
      log(L_ERR "Pipe loop detected when sending %I/%d to table %s",
	  n->n.prefix, n->n.pxlen, dst_table->name);
      return;
    }

  nn = net_get(dst_table, n->n.prefix, n->n.pxlen);
  if (new)
    {
      memcpy(&a, new->attrs, sizeof(rta));

      if (p->mode == SDN_OPAQUE)
	{
	  a.proto = &p->p;
	  a.source = RTS_SDN;
	}

      a.aflags = 0;
      a.eattrs = attrs;
      a.hostentry = NULL;
      e = rte_get_temp(&a);
      e->net = nn;
      e->pflags = 0;

      if (p->mode == SDN_TRANSPARENT)
	{
	  /* Copy protocol specific embedded attributes. */
	  memcpy(&(e->u), &(new->u), sizeof(e->u));
	  e->pref = new->pref;
	  e->pflags = new->pflags;
	}

      src = new->attrs->proto;
    }
  else
    {
      e = NULL;
      src = old->attrs->proto;
    }

  src_table->sdn_busy = 1;
  rte_update2(ah, nn, e, (p->mode == SDN_OPAQUE) ? &p->p : src);
  src_table->sdn_busy = 0;
}

static int
sdn_import_control(struct proto *P, rte **ee, ea_list **ea UNUSED, struct linpool *p UNUSED)
{
  struct proto *pp = (*ee)->sender->proto;

  if (pp == P)
    return -1;	/* Avoid local loops automatically */
  return 0;
}

static int
sdn_reload_routes(struct proto *P)
{
  struct sdn_proto *p = (struct sdn_proto *) P;

  /*
   * Because the sdn protocol feeds routes from both routing tables
   * together, both directions are reloaded during refeed and 'reload
   * out' command works like 'reload' command. For symmetry, we also
   * request refeed when 'reload in' command is used.
   */
  proto_request_feeding(P);

  proto_reset_limit(P->main_ahook->in_limit);
  proto_reset_limit(p->peer_ahook->in_limit);

  return 1;
}

static struct proto *
sdn_init(struct proto_config *C)
{
  struct sdn_config *c = (struct sdn_config *) C;
  struct proto *P = proto_new(C, sizeof(struct sdn_proto));
  struct sdn_proto *p = (struct sdn_proto *) P;

  p->mode = c->mode;
  p->peer_table = c->peer->table;
  P->accept_ra_types = (p->mode == SDN_OPAQUE) ? RA_OPTIMAL : RA_ANY;
  P->rt_notify = sdn_rt_notify;
  P->import_control = sdn_import_control;
  P->reload_routes = sdn_reload_routes;

  return P;
}

static int
sdn_start(struct proto *P)
{
  struct sdn_config *cf = (struct sdn_config *) P->cf;
  struct sdn_proto *p = (struct sdn_proto *) P;

  /* Lock both tables, unlock is handled in sdn_cleanup() */
  rt_lock_table(P->table);
  rt_lock_table(p->peer_table);

  /* Going directly to PS_UP - prepare for feeding,
     connect the protocol to both routing tables */

  P->main_ahook = proto_add_announce_hook(P, P->table, &P->stats);
  P->main_ahook->out_filter = cf->c.out_filter;
  P->main_ahook->in_limit = cf->c.in_limit;
  proto_reset_limit(P->main_ahook->in_limit);

  p->peer_ahook = proto_add_announce_hook(P, p->peer_table, &p->peer_stats);
  p->peer_ahook->out_filter = cf->c.in_filter;
  p->peer_ahook->in_limit = cf->c.out_limit;
  proto_reset_limit(p->peer_ahook->in_limit);

  return PS_UP;
}

static void
sdn_cleanup(struct proto *P)
{
  struct sdn_proto *p = (struct sdn_proto *) P;

  bzero(&P->stats, sizeof(struct proto_stats));
  bzero(&p->peer_stats, sizeof(struct proto_stats));

  P->main_ahook = NULL;
  p->peer_ahook = NULL;

  rt_unlock_table(P->table);
  rt_unlock_table(p->peer_table);
}

static void
sdn_postconfig(struct proto_config *C)
{
  struct sdn_config *c = (struct sdn_config *) C;

  if (!c->peer)
    cf_error("Name of peer routing table not specified");
  if (c->peer == C->table)
    cf_error("Primary table and peer table must be different");

  if (C->in_keep_filtered)
    cf_error("Pipe protocol prohibits keeping filtered routes");
  if (C->rx_limit)
    cf_error("Pipe protocol does not support receive limits");
}

extern int proto_reconfig_type;

static int
sdn_reconfigure(struct proto *P, struct proto_config *new)
{
  struct sdn_proto *p = (struct sdn_proto *)P;
  struct proto_config *old = P->cf;
  struct sdn_config *oc = (struct sdn_config *) old;
  struct sdn_config *nc = (struct sdn_config *) new;

  if ((oc->peer->table != nc->peer->table) || (oc->mode != nc->mode))
    return 0;

  /* Update output filters in ahooks */
  if (P->main_ahook)
    {
      P->main_ahook->out_filter = new->out_filter;
      P->main_ahook->in_limit = new->in_limit;
    }

  if (p->peer_ahook)
    {
      p->peer_ahook->out_filter = new->in_filter;
      p->peer_ahook->in_limit = new->out_limit;
    }

  if ((P->proto_state != PS_UP) || (proto_reconfig_type == RECONFIG_SOFT))
    return 1;
  
  if ((new->preference != old->preference)
      || ! filter_same(new->in_filter, old->in_filter)
      || ! filter_same(new->out_filter, old->out_filter))
    proto_request_feeding(P);

  return 1;
}

static void
sdn_copy_config(struct proto_config *dest, struct proto_config *src)
{
  /* Just a shallow copy, not many items here */
  proto_copy_rest(dest, src, sizeof(struct sdn_config));
}

static void
sdn_get_status(struct proto *P, byte *buf)
{
  struct sdn_proto *p = (struct sdn_proto *) P;

  bsprintf(buf, "%c> %s", (p->mode == SDN_OPAQUE) ? '-' : '=', p->peer_table->name);
}

static void
sdn_show_stats(struct sdn_proto *p)
{
  struct proto_stats *s1 = &p->p.stats;
  struct proto_stats *s2 = &p->peer_stats;

  /*
   * Pipe stats (as anything related to sdns) are a bit tricky. There
   * are two sets of stats - s1 for ahook to the primary routing and
   * s2 for the ahook to the secondary routing table. The user point
   * of view is that routes going from the primary routing table to
   * the secondary routing table are 'exported', while routes going in
   * the other direction are 'imported'.
   *
   * Each route going through a sdn is, technically, first exported
   * to the sdn and then imported from that sdn and such operations
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
	  s1->imp_routes, s2->imp_routes);
  cli_msg(-1006, "  Route change stats:     received   rejected   filtered    ignored   accepted");
  cli_msg(-1006, "    Import updates:     %10u %10u %10u %10u %10u",
	  s2->exp_updates_received, s2->exp_updates_rejected + s1->imp_updates_invalid,
	  s2->exp_updates_filtered, s1->imp_updates_ignored, s1->imp_updates_accepted);
  cli_msg(-1006, "    Import withdraws:   %10u %10u        --- %10u %10u",
	  s2->exp_withdraws_received, s1->imp_withdraws_invalid,
	  s1->imp_withdraws_ignored, s1->imp_withdraws_accepted);
  cli_msg(-1006, "    Export updates:     %10u %10u %10u %10u %10u",
	  s1->exp_updates_received, s1->exp_updates_rejected + s2->imp_updates_invalid,
	  s1->exp_updates_filtered, s2->imp_updates_ignored, s2->imp_updates_accepted);
  cli_msg(-1006, "    Export withdraws:   %10u %10u        --- %10u %10u",
	  s1->exp_withdraws_received, s2->imp_withdraws_invalid,
	  s2->imp_withdraws_ignored, s2->imp_withdraws_accepted);
}

static void
sdn_show_proto_info(struct proto *P)
{
  struct sdn_proto *p = (struct sdn_proto *) P;
  struct sdn_config *cf = (struct sdn_config *) P->cf;

  // cli_msg(-1006, "  Table:          %s", P->table->name);
  // cli_msg(-1006, "  Peer table:     %s", p->peer_table->name);
  cli_msg(-1006, "  Preference:     %d", P->preference);
  cli_msg(-1006, "  Input filter:   %s", filter_name(cf->c.in_filter));
  cli_msg(-1006, "  Output filter:  %s", filter_name(cf->c.out_filter));

  proto_show_limit(cf->c.in_limit, "Import limit:");
  proto_show_limit(cf->c.out_limit, "Export limit:");

  if (P->proto_state != PS_DOWN)
    sdn_show_stats(p);
}


struct protocol proto_sdn = {
  name:			"Pipe",
  template:		"sdn%d",
  multitable:		1,
  preference:		DEF_PREF_SDN,
  postconfig:		sdn_postconfig,
  init:			sdn_init,
  start:		sdn_start,
  cleanup:		sdn_cleanup,
  reconfigure:		sdn_reconfigure,
  copy_config:  	sdn_copy_config,
  get_status:		sdn_get_status,
  show_proto_info:	sdn_show_proto_info
};
