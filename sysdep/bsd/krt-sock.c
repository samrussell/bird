/*
 *	BIRD -- Unix Routing Table Syncing
 *
 *	(c) 2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/timer.h"
#include "lib/unix.h"
#include "lib/krt.h"
#include "lib/string.h"
#include "lib/socket.h"


#ifndef RTAX_MAX
#define RTAX_MAX        8
#endif

struct ks_msg
{
  struct rt_msghdr rtm;
  struct sockaddr_storage buf[RTAX_MAX];
};


static int rt_sock = 0;

int
krt_capable(rte *e)
{
  rta *a = e->attrs;

  return
    a->cast == RTC_UNICAST &&
    (a->dest == RTD_ROUTER
     || a->dest == RTD_DEVICE
#ifdef RTF_REJECT
     || a->dest == RTD_UNREACHABLE
#endif
#ifdef RTF_BLACKHOLE
     || a->dest == RTD_BLACKHOLE
#endif
     );
}

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#define NEXTADDR(w, u) \
        if (msg.rtm.rtm_addrs & (w)) {\
          l = ROUNDUP(((struct sockaddr *)&(u))->sa_len);\
          memmove(body, &(u), l); body += l;}

#define GETADDR(p, F) \
  bzero(p, sizeof(*p));\
  if ((addrs & (F)) && ((struct sockaddr *)body)->sa_len) {\
    unsigned int l = ROUNDUP(((struct sockaddr *)body)->sa_len);\
    memcpy(p, body, (l > sizeof(*p) ? sizeof(*p) : l));\
    body += l;}

static int
krt_sock_send(int cmd, rte *e)
{
  net *net = e->net;
  rta *a = e->attrs;
  static int msg_seq;
  struct iface *j, *i = a->iface;
  int l;
  struct ks_msg msg;
  char *body = (char *)msg.buf;
  sockaddr gate, mask, dst;
  ip_addr gw;

  DBG("krt-sock: send %I/%d via %I\n", net->n.prefix, net->n.pxlen, a->gw);

  bzero(&msg,sizeof (struct rt_msghdr));
  msg.rtm.rtm_version = RTM_VERSION;
  msg.rtm.rtm_type = cmd;
  msg.rtm.rtm_seq = msg_seq++;
  msg.rtm.rtm_addrs = RTA_DST;
  msg.rtm.rtm_flags = RTF_UP | RTF_PROTO1;

  if (net->n.pxlen == MAX_PREFIX_LENGTH)
  {
    msg.rtm.rtm_flags |= RTF_HOST;
  }
  else
  {
    msg.rtm.rtm_addrs |= RTA_NETMASK;
  }

#ifdef RTF_REJECT
  if(a->dest == RTD_UNREACHABLE)
    msg.rtm.rtm_flags |= RTF_REJECT;
#endif
#ifdef RTF_BLACKHOLE
  if(a->dest == RTD_BLACKHOLE)
    msg.rtm.rtm_flags |= RTF_BLACKHOLE;
#endif

  /* This is really very nasty, but I'm not able
   * to add "(reject|blackhole)" route without
   * gateway set
   */
  if(!i)
  {
    i = HEAD(iface_list);

    WALK_LIST(j, iface_list)
    {
      if (j->flags & IF_LOOPBACK)
      {
        i = j;
        break;
      }
    }
  }

  gw = a->gw;

#ifdef IPV6
  /* Embed interface ID to link-local address */
  if (ipa_has_link_scope(gw))
    _I0(gw) = 0xfe800000 | (i->index & 0x0000ffff);
#endif

  fill_in_sockaddr(&dst, net->n.prefix, NULL, 0);
  fill_in_sockaddr(&mask, ipa_mkmask(net->n.pxlen), NULL, 0);
  fill_in_sockaddr(&gate, gw, NULL, 0);

  switch (a->dest)
  {
    case RTD_ROUTER:
      msg.rtm.rtm_flags |= RTF_GATEWAY;
      msg.rtm.rtm_addrs |= RTA_GATEWAY;
      break;
#ifdef RTF_REJECT
    case RTD_UNREACHABLE:
#endif
#ifdef RTF_BLACKHOLE
    case RTD_BLACKHOLE:
#endif
    case RTD_DEVICE:
      if(i)
      {
#ifdef RTF_CLONING
        if (cmd == RTM_ADD && (i->flags & IF_MULTIACCESS) != IF_MULTIACCESS)	/* PTP */
          msg.rtm.rtm_flags |= RTF_CLONING;
#endif

        if(!i->addr) {
          log(L_ERR "KRT: interface %s has no IP addess", i->name);
          return -1;
        }

        fill_in_sockaddr(&gate, i->addr->ip, NULL, 0);
        msg.rtm.rtm_addrs |= RTA_GATEWAY;
      }
      break;
    default:
      bug("krt-sock: unknown flags, but not filtered");
  }

  msg.rtm.rtm_index = i->index;

  NEXTADDR(RTA_DST, dst);
  NEXTADDR(RTA_GATEWAY, gate);
  NEXTADDR(RTA_NETMASK, mask);

  l = body - (char *)&msg;
  msg.rtm.rtm_msglen = l;

  if ((l = write(rt_sock, (char *)&msg, l)) < 0) {
    log(L_ERR "KRT: Error sending route %I/%d to kernel: %m", net->n.prefix, net->n.pxlen);
    return -1;
  }

  return 0;
}

void
krt_replace_rte(struct krt_proto *p UNUSED, net *n, rte *new, rte *old,
		struct ea_list *eattrs UNUSED)
{
  int err = 0;

  if (old)
    krt_sock_send(RTM_DELETE, old);

  if (new)
    err = krt_sock_send(RTM_ADD, new);

  if (err < 0)
    n->n.flags |= KRF_SYNC_ERROR;
  else
    n->n.flags &= ~KRF_SYNC_ERROR;
}

#define SKIP(ARG...) do { DBG("KRT: Ignoring route - " ARG); return; } while(0)

static void
krt_read_rt(struct ks_msg *msg, struct krt_proto *p, int scan)
{
  rte *e;
  net *net;
  sockaddr dst, gate, mask;
  ip_addr idst, igate, imask;
  void *body = (char *)msg->buf;
  int new = (msg->rtm.rtm_type == RTM_ADD);
  char *errmsg = "KRT: Invalid route received";
  int flags = msg->rtm.rtm_flags;
  int addrs = msg->rtm.rtm_addrs;
  int src;
  byte src2;

  if (!(flags & RTF_UP) && scan)
    SKIP("not up in scan\n");

  if (!(flags & RTF_DONE) && !scan)
    SKIP("not done in async\n");

  if (flags & RTF_LLINFO)
    SKIP("link-local\n");

  GETADDR(&dst, RTA_DST);
  GETADDR(&gate, RTA_GATEWAY);
  GETADDR(&mask, RTA_NETMASK);

  if (sa_family_check(&dst))
    get_sockaddr(&dst, &idst, NULL, NULL, 0);
  else
    SKIP("invalid DST");

  /* We will check later whether we have valid gateway addr */
  if (sa_family_check(&gate))
    get_sockaddr(&gate, &igate, NULL, NULL, 0);
  else
    igate = IPA_NONE;

  /* We do not test family for RTA_NETMASK, because BSD sends us
     some strange values, but interpreting them as IPv4/IPv6 works */
  get_sockaddr(&mask, &imask, NULL, NULL, 0);

  int c = ipa_classify_net(idst);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
    SKIP("strange class/scope\n");

  int pxlen = (flags & RTF_HOST) ? MAX_PREFIX_LENGTH : ipa_mklen(imask);
  if (pxlen < 0)
    { log(L_ERR "%s (%I) - netmask %I", errmsg, idst, imask); return; }

  if ((flags & RTF_GATEWAY) && ipa_zero(igate))
    { log(L_ERR "%s (%I/%d) - missing gateway", errmsg, idst, pxlen); return; }

  u32 self_mask = RTF_PROTO1;
  u32 alien_mask = RTF_STATIC | RTF_PROTO1 | RTF_GATEWAY;

  src2 = (flags & RTF_STATIC) ? 1 : 0;
  src2 |= (flags & RTF_PROTO1) ? 2 : 0;

#ifdef RTF_PROTO2
  alien_mask |= RTF_PROTO2;
  src2 |= (flags & RTF_PROTO2) ? 4 : 0;
#endif

#ifdef RTF_PROTO3
  alien_mask |= RTF_PROTO3;
  src2 |= (flags & RTF_PROTO3) ? 8 : 0;
#endif

#ifdef RTF_REJECT
  alien_mask |= RTF_REJECT;
#endif

#ifdef RTF_BLACKHOLE
  alien_mask |= RTF_BLACKHOLE;
#endif

  if (flags & (RTF_DYNAMIC | RTF_MODIFIED))
    src = KRT_SRC_REDIRECT;
  else if (flags & self_mask)
    {
      if (!scan)
	SKIP("echo\n");
      src = KRT_SRC_BIRD;
    }
  else if (flags & alien_mask)
    src = KRT_SRC_ALIEN;
  else
    src = KRT_SRC_KERNEL;

  net = net_get(p->p.table, idst, pxlen);

  rta a = {
    .proto = &p->p,
    .source = RTS_INHERIT,
    .scope = SCOPE_UNIVERSE,
    .cast = RTC_UNICAST
  };

  /* reject/blackhole routes have also set RTF_GATEWAY,
     we wil check them first. */

#ifdef RTF_REJECT
  if(flags & RTF_REJECT) {
    a.dest = RTD_UNREACHABLE;
    goto done;
  }
#endif

#ifdef RTF_BLACKHOLE
  if(flags & RTF_BLACKHOLE) {
    a.dest = RTD_BLACKHOLE;
    goto done;
  }
#endif

  a.iface = if_find_by_index(msg->rtm.rtm_index);
  if (!a.iface)
    {
      log(L_ERR "KRT: Received route %I/%d with unknown ifindex %u",
	  net->n.prefix, net->n.pxlen, msg->rtm.rtm_index);
      return;
    }

  if (flags & RTF_GATEWAY)
  {
    neighbor *ng;
    a.dest = RTD_ROUTER;
    a.gw = igate;

#ifdef IPV6
    /* Clean up embedded interface ID returned in link-local address */
    if (ipa_has_link_scope(a.gw))
      _I0(a.gw) = 0xfe800000;
#endif

    ng = neigh_find2(&p->p, &a.gw, a.iface, 0);
    if (!ng || (ng->scope == SCOPE_HOST))
      {
	/* Ignore routes with next-hop 127.0.0.1, host routes with such
	   next-hop appear on OpenBSD for address aliases. */
        if (ipa_classify(a.gw) == (IADDR_HOST | SCOPE_HOST))
          return;

	log(L_ERR "KRT: Received route %I/%d with strange next-hop %I",
	    net->n.prefix, net->n.pxlen, a.gw);
	return;
      }
  }
  else
    a.dest = RTD_DEVICE;

 done:
  e = rte_get_temp(&a);
  e->net = net;
  e->u.krt.src = src;
  e->u.krt.proto = src2;

  /* These are probably too Linux-specific */
  e->u.krt.type = 0;
  e->u.krt.metric = 0;

  if (scan)
    krt_got_route(p, e);
  else
    krt_got_route_async(p, e, new);
}

static void
krt_read_ifannounce(struct ks_msg *msg)
{
  struct if_announcemsghdr *ifam = (struct if_announcemsghdr *)&msg->rtm;

  if (ifam->ifan_what == IFAN_ARRIVAL)
  {
    /* Not enough info to create the iface, so we just trigger iface scan */
    kif_request_scan();
  }
  else if (ifam->ifan_what == IFAN_DEPARTURE)
  {
    struct iface *iface = if_find_by_index(ifam->ifan_index);

    /* Interface is destroyed */
    if (!iface)
    {
      DBG("KRT: unknown interface (%s, #%d) going down. Ignoring\n", ifam->ifan_name, ifam->ifan_index);
      return;
    }

    if_delete(iface);
  }

  DBG("KRT: IFANNOUNCE what: %d index %d name %s\n", ifam->ifan_what, ifam->ifan_index, ifam->ifan_name);
}

static void
krt_read_ifinfo(struct ks_msg *msg)
{
  struct if_msghdr *ifm = (struct if_msghdr *)&msg->rtm;
  void *body = (void *)(ifm + 1);
  struct sockaddr_dl *dl = NULL;
  unsigned int i;
  struct iface *iface = NULL, f = {};
  int fl = ifm->ifm_flags;
  int nlen = 0;

  for (i = 1; i<=RTA_IFP; i <<= 1)
  {
    if (i & ifm->ifm_addrs)
    {
      if (i == RTA_IFP)
      {
        dl = (struct sockaddr_dl *)body;
        break;
      }
      body += ROUNDUP(((struct sockaddr *)&(body))->sa_len);
    }
  }

  if (dl && (dl->sdl_family != AF_LINK))
  {
    log(L_WARN "Ignoring strange IFINFO");
    return;
  }

  if (dl)
    nlen = MIN(sizeof(f.name)-1, dl->sdl_nlen);

  /* Note that asynchronous IFINFO messages do not contain iface
     name, so we have to found an existing iface by iface index */

  iface = if_find_by_index(ifm->ifm_index);
  if (!iface)
  {
    /* New interface */
    if (!dl)
      return;	/* No interface name, ignoring */

    memcpy(f.name, dl->sdl_data, nlen);
    DBG("New interface '%s' found\n", f.name);
  }
  else if (dl && memcmp(iface->name, dl->sdl_data, nlen))
  {
    /* Interface renamed */
    if_delete(iface);
    memcpy(f.name, dl->sdl_data, nlen);
  }
  else
  {
    /* Old interface */
    memcpy(f.name, iface->name, sizeof(f.name));
  }

  f.index = ifm->ifm_index;
  f.mtu = ifm->ifm_data.ifi_mtu;

  if (fl & IFF_UP)
    f.flags |= IF_ADMIN_UP;
  if (ifm->ifm_data.ifi_link_state != LINK_STATE_DOWN)
    f.flags |= IF_LINK_UP;          /* up or unknown */
  if (fl & IFF_LOOPBACK)            /* Loopback */
    f.flags |= IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE;
  else if (fl & IFF_POINTOPOINT)    /* PtP */
    f.flags |= IF_MULTICAST;
  else if (fl & IFF_BROADCAST)      /* Broadcast */
    f.flags |= IF_MULTIACCESS | IF_BROADCAST | IF_MULTICAST;
  else
    f.flags |= IF_MULTIACCESS;      /* NBMA */

  if_update(&f);
}

static void
krt_read_addr(struct ks_msg *msg)
{
  struct ifa_msghdr *ifam = (struct ifa_msghdr *)&msg->rtm;
  void *body = (void *)(ifam + 1);
  sockaddr addr, mask, brd;
  struct iface *iface = NULL;
  struct ifa ifa;
  struct sockaddr null;
  ip_addr iaddr, imask, ibrd;
  int addrs = ifam->ifam_addrs;
  int scope, masklen = -1;
  int new = (ifam->ifam_type == RTM_NEWADDR);

  /* Strange messages with zero (invalid) ifindex appear on OpenBSD */
  if (ifam->ifam_index == 0)
    return;

  if(!(iface = if_find_by_index(ifam->ifam_index)))
  {
    log(L_ERR "KIF: Received address message for unknown interface %d", ifam->ifam_index);
    return;
  }

  GETADDR (&null, RTA_DST);
  GETADDR (&null, RTA_GATEWAY);
  GETADDR (&mask, RTA_NETMASK);
  GETADDR (&null, RTA_GENMASK);
  GETADDR (&null, RTA_IFP);
  GETADDR (&addr, RTA_IFA);
  GETADDR (&null, RTA_AUTHOR);
  GETADDR (&brd, RTA_BRD);

  /* Some other family address */
  if (!sa_family_check(&addr))
    return;

  get_sockaddr(&addr, &iaddr, NULL, NULL, 0);
  get_sockaddr(&mask, &imask, NULL, NULL, 0);
  get_sockaddr(&brd, &ibrd, NULL, NULL, 0);

  if ((masklen = ipa_mklen(imask)) < 0)
  {
    log("Invalid masklen");
    return;
  }

  bzero(&ifa, sizeof(ifa));

  ifa.iface = iface;

  memcpy(&ifa.ip, &iaddr, sizeof(ip_addr));
  ifa.pxlen = masklen;
  memcpy(&ifa.brd, &ibrd, sizeof(ip_addr));

  scope = ipa_classify(ifa.ip);
  if (scope < 0)
  {
    log(L_ERR "KIF: Invalid interface address %I for %s", ifa.ip, iface->name);
    return;
  }
  ifa.scope = scope & IADDR_SCOPE_MASK;

#ifdef IPV6
  /* Clean up embedded interface ID returned in link-local address */
  if (ipa_has_link_scope(ifa.ip))
    _I0(ifa.ip) = 0xfe800000;
#endif

#ifdef IPV6
  /* Why not the same check also for IPv4? */
  if ((iface->flags & IF_MULTIACCESS) || (masklen != BITS_PER_IP_ADDRESS))
#else
  if (iface->flags & IF_MULTIACCESS)
#endif
  {
    ifa.prefix = ipa_and(ifa.ip, ipa_mkmask(masklen));

    if (masklen == BITS_PER_IP_ADDRESS)
      ifa.flags |= IA_HOST;

    if (masklen == (BITS_PER_IP_ADDRESS - 1))
      ifa.opposite = ipa_opposite_m1(ifa.ip);

#ifndef IPV6
    if (masklen == (BITS_PER_IP_ADDRESS - 2))
      ifa.opposite = ipa_opposite_m2(ifa.ip);
#endif
  }
  else         /* PtP iface */
  {
    ifa.flags |= IA_PEER;
    ifa.prefix = ifa.opposite = ifa.brd;
  }

  if (new)
    ifa_update(&ifa);
  else
    ifa_delete(&ifa);
}


void
krt_read_msg(struct proto *p, struct ks_msg *msg, int scan)
{
  switch (msg->rtm.rtm_type)
  {
    case RTM_GET:
      if(!scan) return;
    case RTM_ADD:
    case RTM_DELETE:
      krt_read_rt(msg, (struct krt_proto *)p, scan);
      break;
    case RTM_IFANNOUNCE:
      krt_read_ifannounce(msg);
      break;
    case RTM_IFINFO:
      krt_read_ifinfo(msg);
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      krt_read_addr(msg);
      break;
    default:
      break;
  }
}

static void
krt_sysctl_scan(struct proto *p, pool *pool, byte **buf, size_t *bl, int cmd)
{
  byte *next;
  int mib[6];
  size_t obl, needed;
  struct ks_msg *m;
  int retries = 3;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = BIRD_PF;
  mib[4] = cmd;
  mib[5] = 0;

 try:
  if (sysctl(mib, 6 , NULL , &needed, NULL, 0) < 0)
    die("krt_sysctl_scan 1: %m");

  obl = *bl;

  while (needed > *bl) *bl *= 2;
  while (needed < (*bl/2)) *bl /= 2;

  if ((obl!=*bl) || !*buf)
  {
    if (*buf) mb_free(*buf);
    if ((*buf = mb_alloc(pool, *bl)) == NULL) die("RT scan buf alloc");
  }

  if (sysctl(mib, 6 , *buf, &needed, NULL, 0) < 0)
  {
    if (errno == ENOMEM)
    {
      /* The buffer size changed since last sysctl ('needed' is not changed) */
      if (retries--)
	goto try;

      log(L_ERR "KRT: Route scan failed");
      return;
    }
    die("krt_sysctl_scan 2: %m");
  }

  for (next = *buf; next < (*buf + needed); next += m->rtm.rtm_msglen)
  {
    m = (struct ks_msg *)next;
    krt_read_msg(p, m, 1);
  }
}

static byte *krt_buffer = NULL;
static byte *kif_buffer = NULL;
static size_t krt_buflen = 32768;
static size_t kif_buflen = 4096;

void
krt_do_scan(struct krt_proto *p)
{
  krt_sysctl_scan((struct proto *)p, p->krt_pool, &krt_buffer, &krt_buflen, NET_RT_DUMP);
}

void
kif_do_scan(struct kif_proto *p)
{
  struct proto *P = (struct proto *)p;
  if_start_update();
  krt_sysctl_scan(P, P->pool, &kif_buffer, &kif_buflen, NET_RT_IFLIST);
  if_end_update();
}

static int
krt_sock_hook(sock *sk, int size UNUSED)
{
  struct ks_msg msg;
  int l = read(sk->fd, (char *)&msg, sizeof(msg));

  if(l <= 0)
    log(L_ERR "krt-sock: read failed");
  else
  krt_read_msg((struct proto *)sk->data, &msg, 0);

  return 0;
}

void
krt_sys_start(struct krt_proto *x, int first UNUSED)
{
  sock *sk_rt;
  static int ks_open_tried = 0;

  if (ks_open_tried)
    return;

  ks_open_tried = 1;

  DBG("KRT: Opening kernel socket\n");

  if( (rt_sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)) < 0)
    die("Cannot open kernel socket for routes");

  sk_rt = sk_new(krt_pool);
  sk_rt->type = SK_MAGIC;
  sk_rt->rx_hook = krt_sock_hook;
  sk_rt->fd = rt_sock;
  sk_rt->data = x;
  if (sk_open(sk_rt))
    bug("krt-sock: sk_open failed");
}

void
krt_sys_shutdown(struct krt_proto *x UNUSED, int last UNUSED)
{
  if (!krt_buffer)
    return;

  mb_free(krt_buffer);
  krt_buffer = NULL;
}


void
kif_sys_start(struct kif_proto *p UNUSED)
{
}

void
kif_sys_shutdown(struct kif_proto *p UNUSED)
{
  if (!kif_buffer)
    return;

  mb_free(kif_buffer);
  kif_buffer = NULL;
}

