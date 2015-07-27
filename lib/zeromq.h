/*
 *	BIRD ZeroMQ Interface
 *
 *	(c) 1998--2004 Martin Mares <mj@ucw.cz>
 *	(c) 2015 Sam Russell <sam.h.russell@gmail.com>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ZEROMQ_H_
#define _BIRD_ZEROMQ_H_

#include "lib/resource.h"

typedef struct birdzmq {
  resource r;
  pool *pool;				/* Pool where incoming connections should be allocated (for SK_xxx_PASSIVE) */
  int type;				/* Socket type */
  void *data;				/* User data */
  char* url;                            /* URL to zeromq dest */
  unsigned sport, dport;		/* 0 = unspecified (for IP: protocol type) */
  int tos;				/* TOS / traffic class, -1 = default */
  int priority;				/* Local socket priority, -1 = default */
  int ttl;				/* Time To Live, -1 = default */
  u32 flags;

  byte *rbuf, *rpos;			/* NULL=allocate automatically */
  unsigned rbsize;
  int (*rx_hook)(struct birdzmq *, int size); /* NULL=receiving turned off, returns 1 to clear rx buffer */

  byte *tbuf, *tpos;			/* NULL=allocate automatically */
  byte *ttx;				/* Internal */
  unsigned tbsize;
  void (*tx_hook)(struct birdzmq *);

  void (*err_hook)(struct birdzmq *, int); /* errno or zero if EOF */

  /* Information about received datagrams (UDP, RAW), valid in rx_hook */
  ip_addr faddr, laddr;			/* src (From) and dst (Local) address of the datagram */
  unsigned fport;			/* src port of the datagram */
  unsigned lifindex;			/* local interface that received the datagram */
  /* laddr and lifindex are valid only if SKF_LADDR_RX flag is set to request it */

  int af;				/* Address family (AF_INET, AF_INET6 or 0 for non-IP) of fd */
  void* fd;				/* System-dependent data */
  int index;				/* Index in poll buffer */
  int rcv_ttl;				/* TTL of last received datagram */
  node n;
  void *rbuf_alloc, *tbuf_alloc;
  char *err;				/* Error message */
} zeromq;

zeromq *zq_new(pool *);			/* Allocate new socket */

int zq_open(zeromq *);			/* Open socket */
int zq_rx_ready(zeromq *s);
int zq_send(zeromq *, unsigned len);	/* Send data, <0=err, >0=ok, 0=sleep */
int zq_send_to(zeromq *, unsigned len, ip_addr to, unsigned port); /* sk_send to given destination */
void zq_reallocate(zeromq *);		/* Free and allocate tbuf & rbuf */
void zq_set_rbsize(zeromq *z, uint val);	/* Resize RX buffer */
void zq_set_tbsize(zeromq *z, uint val);	/* Resize TX buffer, keeping content */
void zq_set_tbuf(zeromq *z, void *tbuf);	/* Switch TX buffer, NULL-> return to internal */
void zq_dump_all(void);

static inline int zq_send_buffer_empty(zeromq *zq)
{ return zq->tbuf == zq->tpos; }


#ifdef IPV6
#define zq_is_ipv4(X) 0
#define zq_is_ipv6(X) 1
#else
#define zq_is_ipv4(X) 1
#define zq_is_ipv6(X) 0
#endif


void zq_log_error(zeromq *s, const char *p);

extern int zq_priority_control;		/* Suggested priority for control traffic, should be sysdep define */


/* Socket flags */

#define ZQF_V4ONLY	0x01	/* Use IPv4 for IP sockets */
#define ZQF_V6ONLY	0x02	/* Use IPV6_V6ONLY socket option */
#define ZQF_LADDR_RX	0x04	/* Report local address for RX packets */
#define ZQF_TTL_RX	0x08	/* Report TTL / Hop Limit for RX packets */
#define ZQF_BIND	0x10	/* Bind datagram socket to given source address */

#define ZQF_THREAD	0x100	/* Socked used in thread, Do not add to main loop */
#define ZQF_TRUNCATED	0x200	/* Received packet was truncated, set by IO layer */
#define ZQF_HDRINCL	0x400	/* Used internally */
#define ZQF_PKTINFO	0x800	/* Used internally */

/*
 *	Socket types		     SA SP DA DP IF  TTL SendTo	(?=may, -=must not, *=must)
 */

#define ZQ_TCP_PASSIVE	0	   /* ?  *  -  -  -  ?   -	*/
#define ZQ_TCP_ACTIVE	1          /* ?  ?  *  *  -  ?   -	*/
#define ZQ_TCP		2
#define ZQ_UDP		3          /* ?  ?  ?  ?  ?  ?   ?	*/
#define ZQ_IP		5          /* ?  -  ?  *  ?  ?   ?	*/
#define ZQ_MAGIC	7	   /* Internal use by sysdep code */
#define ZQ_UNIX_PASSIVE	8
#define ZQ_UNIX		9

/*
 *  For SK_UDP or SK_IP sockets setting DA/DP allows to use sk_send(),
 *  otherwise sk_send_to() must be used.
 *
 *  For SK_IP sockets setting DP specifies protocol number, which is used
 *  for both receiving and sending.
 *
 *  For multicast on SK_UDP or SK_IP sockets set IF and TTL,
 *  call sk_setup_multicast() to enable multicast on that socket,
 *  and then use sk_join_group() and sk_leave_group() to manage
 *  a set of received multicast groups.
 *
 *  For datagram (SK_UDP, SK_IP) sockets, there are two ways to handle
 *  source address. The socket could be bound to it using bind()
 *  syscall, but that also forbids the reception of multicast packets,
 *  or the address could be set on per-packet basis using platform
 *  dependent options (but these are not available in some corner
 *  cases). The first way is used when SKF_BIND is specified, the
 *  second way is used otherwise.
 */

#endif
