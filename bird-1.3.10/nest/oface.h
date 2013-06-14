/*
 *	BIRD Internet Routing Daemon -- Network Interfaces
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	Modified by Sam Russell 2013 sam.h.russell@gmail.com to try to add SDN support
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_OFACE_H_
#define _BIRD_OFACE_H_

#include "lib/lists.h"

extern list oface_list;


void of_init(void);
void of_dump(struct iface *);
void of_dump_all(void);
void ofa_dump(struct ifa *);
void of_show(void);
void of_show_summary(void);
struct iface *of_update(struct iface *);
void of_delete(struct iface *old);
struct ifa *ofa_update(struct ifa *);
void ofa_delete(struct ifa *);
void of_start_update(void);
void of_end_partial_update(struct iface *);
void of_end_update(void);
void of_flush_ifaces(struct proto *p);
void of_feed_baby(struct proto *);
struct iface *of_find_by_index(unsigned);
struct iface *of_find_by_name(char *);
struct iface *of_get_by_name(char *);
void ofa_recalc_all_primary_addresses(void);


int oface_patt_match(struct iface_patt *ifp, struct iface *i, struct ifa *a);
struct iface_patt *oface_patt_find(list *l, struct iface *i, struct ifa *a);
int oface_patts_equal(list *, list *, int (*)(struct iface_patt *, struct iface_patt *));


u32 of_choose_router_id(struct iface_patt *mask, u32 old_id);

#endif
