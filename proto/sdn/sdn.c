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
#define LOCAL_DEBUG 1

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/socket.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/timer.h"
#include "lib/string.h"

#include "sdn.h"

#define P ((struct sdn_proto *) p)
#define P_CF ((struct sdn_proto_config *)p->cf)

#define TRACE(level, msg, args...) do { if (p->debug & level) { log(L_TRACE "%s: " msg, p->name , ## args); } } while(0)

static struct sdn_interface *new_iface(struct proto *p, struct iface *new, unsigned long flags, struct iface_patt *patt);

/*
 * Input processing
 *
 * This part is responsible for any updates that come from network
 */

/*
 * Output processing
 *
 * This part is responsible for getting packets out to the network.
 */

static void
sdn_tx_err( sock *s, int err )
{
  struct rip_connection *c = ((struct rip_interface *)(s->data))->busy;
  struct proto *p = c->proto;
  log( L_ERR "%s: Unexpected error at rip transmit: %M", p->name, err );
}


/*
 * sdn_tx - send one rip packet to the network
 */
static void
sdn_tx( sock *s )
{
  DBG ( "not actually txing but sdn_tx called");
  return;
}


/*
 * sdn_rx - Receive hook: get packet and be awesome
 */
static int
sdn_rx(sock *s, int size)
{
  return 1;
}


/*
 * Interface to BIRD core
 */

static void
sdn_dump_entry( struct sdn_entry *e )
{
  debug( "%I told me %d/%d ago: to %I/%d go via %I, metric %d ",
  e->whotoldme, e->updated-now, e->changed-now, e->n.prefix, e->n.pxlen, e->nexthop, e->metric );
  debug( "\n" );
}

/*
 * sdn_start - initialize instance of sdn
 */
static int
sdn_start(struct proto *p)
{
  struct sdn_interface *rif;
  DBG( "sdn: starting instance...\n" );

#ifdef LOCAL_DEBUG
  P->magic = SDN_MAGIC;
#endif

  fib_init( &P->rtable, p->pool, sizeof( struct sdn_entry ), 0, NULL );
  init_list( &P->connections );
  init_list( &P->garbage );
  init_list( &P->interfaces );
  //DBG( "sdn: initialised lists\n" );
  //rif = new_iface(p, NULL, 0, NULL);	/* Initialize dummy interface */
  //add_head( &P->interfaces, NODE rif );
  CHK_MAGIC;

  sdn_init_instance(p);

  DBG( "sdn: ...done\n" );
  return PS_UP;
}

static struct proto *
sdn_init(struct proto_config *cfg)
{
  struct proto *p = proto_new(cfg, sizeof(struct sdn_proto));

  return p;
}

static void
sdn_dump(struct proto *p)
{
  int i;
  node *w;
  struct sdn_interface *rif;

  CHK_MAGIC;
  WALK_LIST( w, P->connections ) {
    struct sdn_connection *n = (void *) w;
    debug( "sdn: connection #%d: %I\n", n->num, n->addr );
  }
  i = 0;
  FIB_WALK( &P->rtable, e ) {
    debug( "sdn: entry #%d: ", i++ );
    sdn_dump_entry( (struct sdn_entry *)e );
  } FIB_WALK_END;
  i = 0;
  WALK_LIST( rif, P->interfaces ) {
    debug( "sdn: interface #%d: %s, %I, busy = %x\n", i++, rif->iface?rif->iface->name:"(dummy)", rif->sock->daddr, rif->busy );
  }
}

static void
sdn_get_route_info(rte *rte, byte *buf, ea_list *attrs)
{
  eattr *metric = ea_find(attrs, EA_SDN_METRIC);
  eattr *tag = ea_find(attrs, EA_SDN_TAG);

  buf += bsprintf(buf, " (%d/%d)", rte->pref, metric ? metric->u.data : 0);
  if (tag && tag->u.data)
    bsprintf(buf, " t%04x", tag->u.data);
}

static void
kill_iface(struct sdn_interface *i)
{
  DBG( "sdn: Interface %s disappeared\n", i->iface->name);
  rfree(i->sock);
  mb_free(i);
}

/**
 * new_iface
 * @p: myself
 * @new: interface to be created or %NULL if we are creating a magic
 * socket. The magic socket is used for listening and also for
 * sending requested responses.
 * @flags: interface flags
 * @patt: pattern this interface matched, used for access to config options
 *
 * Create an interface structure and start listening on the interface.
 */
static struct sdn_interface *
new_iface(struct proto *p, struct iface *new, unsigned long flags, struct iface_patt *patt )
{
  struct sdn_interface *rif;
  struct sdn_patt *PATT = (struct sdn_patt *) patt;

  rif = mb_allocz(p->pool, sizeof( struct sdn_interface ));
  rif->iface = new;
  rif->proto = p;
  rif->busy = NULL;
  if (PATT) {
    rif->mode = PATT->mode;
    rif->metric = PATT->metric;
    rif->multicast = (!(PATT->mode & IM_BROADCAST)) && (flags & IF_MULTICAST);
  }

  if (rif->multicast)
    DBG( "Doing multicasts!\n" );

  rif->sock = sk_new( p->pool );
  rif->sock->type = SK_UDP;
  rif->sock->sport = P_CF->port;
  rif->sock->rx_hook = sdn_rx;
  rif->sock->data = rif;
  rif->sock->rbsize = 10240;
  rif->sock->iface = new;		/* Automagically works for dummy interface */
  rif->sock->tbuf = mb_alloc( p->pool, sizeof( struct sdn_packet ));
  rif->sock->tx_hook = sdn_tx;
  rif->sock->err_hook = sdn_tx_err;
  rif->sock->daddr = IPA_NONE;
  rif->sock->dport = P_CF->port;
  if (new)
    {
      rif->sock->ttl = 1;
      rif->sock->tos = IP_PREC_INTERNET_CONTROL;
      rif->sock->flags = SKF_LADDR_RX;
    }

  if (new) {
    if (new->addr->flags & IA_PEER)
      log( L_WARN "%s: sdn is not defined over unnumbered links", p->name );
    rif->sock->saddr = IPA_NONE;
    if (rif->multicast) {
#ifndef IPV6
      rif->sock->daddr = ipa_from_u32(0xe0000009);
#else
      rif->sock->daddr = ipa_build(0xff020000, 0, 0, 9);
#endif
    } else {
      rif->sock->daddr = new->addr->brd;
    }
  }
}

static void
sdn_if_notify(struct proto *p, unsigned c, struct iface *iface)
{
  DBG( "sdn: if notify\n" );
}

static struct ea_list *
sdn_gen_attrs(struct linpool *pool, int metric, u16 tag)
{
  struct ea_list *l = lp_alloc(pool, sizeof(struct ea_list) + 2*sizeof(eattr));

  l->next = NULL;
  l->flags = EALF_SORTED;
  l->count = 2;
  l->attrs[0].id = EA_SDN_TAG;
  l->attrs[0].flags = 0;
  l->attrs[0].type = EAF_TYPE_INT | EAF_TEMP;
  l->attrs[0].u.data = tag;
  l->attrs[1].id = EA_SDN_METRIC;
  l->attrs[1].flags = 0;
  l->attrs[1].type = EAF_TYPE_INT | EAF_TEMP;
  l->attrs[1].u.data = metric;
  return l;
}

static int
sdn_import_control(struct proto *p, struct rte **rt, struct ea_list **attrs, struct linpool *pool)
{
  if ((*rt)->attrs->proto == p)	/* My own must not be touched */
    return 1;

  if ((*rt)->attrs->source != RTS_SDN) {
    struct ea_list *new = sdn_gen_attrs(pool, 1, 0);
    new->next = *attrs;
    *attrs = new;
	// say yes for giggles
	return 1;
  }
  return 0;
}

static struct ea_list *
sdn_make_tmp_attrs(struct rte *rt, struct linpool *pool)
{
  return sdn_gen_attrs(pool, rt->u.sdn.metric, rt->u.sdn.tag);
}

static void
sdn_store_tmp_attrs(struct rte *rt, struct ea_list *attrs)
{
  rt->u.sdn.tag = ea_get_int(attrs, EA_SDN_TAG, 0);
  rt->u.sdn.metric = ea_get_int(attrs, EA_SDN_METRIC, 1);
}

/*
 * sdn_rt_notify - core tells us about new route (possibly our
 * own), so store it into our data structures.
 */
static void
sdn_rt_notify(struct proto *p, struct rtable *table UNUSED, struct network *net,
	      struct rte *new, struct rte *old, struct ea_list *attrs)
{
  CHK_MAGIC;
  struct sdn_entry *e;

  log_msg(L_DEBUG "Calling sdn_rt_notify");
  if(new){
    //log_msg(L_DEBUG "New route: %I", net->n.prefix);
    log_msg(L_DEBUG "New route: %-1I/%2d ", net->n.prefix, net->n.pxlen);
    log_msg(L_DEBUG "KF=%02x PF=%02x pref=%d ", net->n.flags, new->pflags, new->pref);
    if (new->attrs->dest == RTD_ROUTER)
      log_msg(" ->%I", new->attrs->gw);
  }
  else{
    log_msg(L_DEBUG "Removing route: %-1I/%2d ", net->n.prefix, net->n.pxlen);
    if(old){
      log_msg(L_DEBUG "KF=%02x PF=%02x pref=%d ", net->n.flags, old->pflags, old->pref);
      if (old->attrs->dest == RTD_ROUTER)
        log_msg(" ->%I", old->attrs->gw);
    }
  }

  e = fib_find( &P->rtable, &net->n.prefix, net->n.pxlen );
  if (e)
    fib_delete( &P->rtable, e );

  if (new) {
    e = fib_get( &P->rtable, &net->n.prefix, net->n.pxlen );

    e->nexthop = new->attrs->gw;
    e->metric = 0;
    e->whotoldme = IPA_NONE;
    new->u.sdn.entry = e;

    e->tag = ea_get_int(attrs, EA_SDN_TAG, 0);
    e->metric = ea_get_int(attrs, EA_SDN_METRIC, 1);
    if (e->metric > P_CF->infinity)
      e->metric = P_CF->infinity;

    if (new->attrs->proto == p)
      e->whotoldme = new->attrs->from;

    if (!e->metric)	/* That's okay: this way user can set his own value for external
			   routes in sdn. */
      e->metric = 5;
    e->updated = e->changed = now;
    e->flags = 0;
  }
}

static int
sdn_rte_same(struct rte *new, struct rte *old)
{
  /* new->attrs == old->attrs always */
  return new->u.sdn.metric == old->u.sdn.metric;
}


static int
sdn_rte_better(struct rte *new, struct rte *old)
{
  struct proto *p = new->attrs->proto;

  if (ipa_equal(old->attrs->from, new->attrs->from))
    return 1;

  if (old->u.sdn.metric < new->u.sdn.metric)
    return 0;

  if (old->u.sdn.metric > new->u.sdn.metric)
    return 1;

  if (old->attrs->proto == new->attrs->proto)		/* This does not make much sense for different protocols */
    if ((old->u.sdn.metric == new->u.sdn.metric) &&
	((now - old->lastmod) > (P_CF->timeout_time / 2)))
      return 1;

  return 0;
}

/*
 * sdn_rte_insert - we maintain linked list of "our" entries in main
 * routing table, so that we can timeout them correctly. sdn_timer()
 * walks the list.
 */
static void
sdn_rte_insert(net *net UNUSED, rte *rte)
{
  struct proto *p = rte->attrs->proto;
  CHK_MAGIC;
  DBG( "sdn_rte_insert: %p\n", rte );
  add_head( &P->garbage, &rte->u.sdn.garbage );
}

/*
 * sdn_rte_remove - link list maintenance
 */
static void
sdn_rte_remove(net *net UNUSED, rte *rte)
{
#ifdef LOCAL_DEBUG
  struct proto *p = rte->attrs->proto;
  CHK_MAGIC;
  DBG( "sdn_rte_remove: %p\n", rte );
#endif
  rem_node( &rte->u.sdn.garbage );
}

void
sdn_init_instance(struct proto *p)
{
  p->accept_ra_types = RA_ANY;
  p->if_notify = sdn_if_notify;
  p->rt_notify = sdn_rt_notify;
  p->import_control = sdn_import_control;
  p->make_tmp_attrs = sdn_make_tmp_attrs;
  p->store_tmp_attrs = sdn_store_tmp_attrs;
  p->rte_better = sdn_rte_better;
  p->rte_same = sdn_rte_same;
  p->rte_insert = sdn_rte_insert;
  p->rte_remove = sdn_rte_remove;
}

void
sdn_init_config(struct sdn_proto_config *c)
{
  init_list(&c->iface_list);
  c->infinity	= 16;
  c->port	= SDN_PORT;
  c->period	= 30;
  c->garbage_time = 120+180;
  c->timeout_time = 120;
  c->passwords	= NULL;
  c->authtype	= AT_NONE;
}

static int
sdn_get_attr(eattr *a, byte *buf, int buflen UNUSED)
{
  switch (a->id) {
  case EA_SDN_METRIC: bsprintf( buf, "metric: %d", a->u.data ); return GA_FULL;
  case EA_SDN_TAG:    bsprintf( buf, "tag: %d", a->u.data );    return GA_FULL;
  default: return GA_UNKNOWN;
  }
}

static int
sdn_pat_compare(struct sdn_patt *a, struct sdn_patt *b)
{
  return ((a->metric == b->metric) &&
	  (a->mode == b->mode));
}

static int
sdn_reconfigure(struct proto *p, struct proto_config *c)
{
  struct sdn_proto_config *new = (struct sdn_proto_config *) c;
  int generic = sizeof(struct proto_config) + sizeof(list) /* + sizeof(struct password_item *) */;

  if (!iface_patts_equal(&P_CF->iface_list, &new->iface_list, (void *) sdn_pat_compare))
    return 0;
  return !memcmp(((byte *) P_CF) + generic,
                 ((byte *) new) + generic,
                 sizeof(struct sdn_proto_config) - generic);
}

static void
sdn_copy_config(struct proto_config *dest, struct proto_config *src)
{
  /* Shallow copy of everything */
  proto_copy_rest(dest, src, sizeof(struct sdn_proto_config));

  /* We clean up iface_list, ifaces are non-sharable */
  init_list(&((struct sdn_proto_config *) dest)->iface_list);

  /* Copy of passwords is OK, it just will be replaced in dest when used */
}


struct protocol proto_sdn = {
  name: "sdn",
  template: "sdn%d",
  attr_class: EAP_SDN,
  preference: DEF_PREF_SDN,
  get_route_info: sdn_get_route_info,
  get_attr: sdn_get_attr,

  init: sdn_init,
  dump: sdn_dump,
  start: sdn_start,
  reconfigure: sdn_reconfigure,
  copy_config: sdn_copy_config
};
