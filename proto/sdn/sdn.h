/*
 *	BIRD -- Binding for SDN controllers
 *
 *	(c) 2013 Sam Russell <sam.h.russell@gmail.com>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SDN_H_
#define _BIRD_SDN_H_

#define SDN_OPAQUE 0
#define SDN_TRANSPARENT 1

struct sdn_config {
  struct proto_config c;
  //struct rtable_config *peer;		/* Table we're connected to */
  int mode;				/* SDN_OPAQUE or SDN_TRANSPARENT */
};

struct sdn_proto {
  struct proto p;
  //struct rtable *peer_table;
  //struct announce_hook *peer_ahook;	/* Announce hook for direction peer->primary */
  //struct proto_stats peer_stats;	/* Statistics for the direction peer->primary */
  int mode;				/* SDN_OPAQUE or SDN_TRANSPARENT */
};


extern struct protocol proto_sdn;

static inline int proto_is_sdn(struct proto *p)
{ return p->proto == &proto_sdn; }

#endif
