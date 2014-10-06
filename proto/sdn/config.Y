/*
 *	BIRD -- SDN Configuration
 *
 *	(c) 2013 Sam Russell <sam.h.russell@gmail.com>
 * 
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/sdn/sdn.h"
#include "nest/iface.h"

CF_DEFINES

#define SDN_CFG ((struct sdn_proto_config *) this_proto)
#define SDN_IPATT ((struct sdn_patt *) this_ipatt)
#define SDN_DEFAULT_TTL_SECURITY 0

CF_DECLS

CF_KEYWORDS(SDN, METRIC)

%type <i> sdn_mode

CF_GRAMMAR

CF_ADDTO(proto, sdn_cfg '}')

sdn_cfg_start: proto_start SDN {
     this_proto = proto_config_new(&proto_sdn, sizeof(struct sdn_proto_config), $1);
     sdn_init_config(SDN_CFG);
   }
 ;

sdn_cfg:
   sdn_cfg_start proto_name '{'
 | sdn_cfg proto_item ';'
 | sdn_cfg INTERFACE sdn_iface ';'
 ;

sdn_mode: 
    BROADCAST { $$=IM_BROADCAST; }
  | MULTICAST { $$=0; }
  | QUIET     { $$=IM_QUIET; }
  | NOLISTEN  { $$=IM_NOLISTEN; }
  | VERSION1  { $$=IM_VERSION1 | IM_BROADCAST; }
 ;

sdn_iface_item:
 | METRIC expr { SDN_IPATT->metric = $2; }
 | MODE sdn_mode { SDN_IPATT->mode |= $2; }
 | TX tos { SDN_IPATT->tx_tos = $2; }
 | TX PRIORITY expr { SDN_IPATT->tx_priority = $3; }
 | TTL SECURITY bool { SDN_IPATT->ttl_security = $3; }
 | TTL SECURITY TX ONLY { SDN_IPATT->ttl_security = 2; }
 ;

sdn_iface_opts: 
   /* empty */
 | sdn_iface_opts sdn_iface_item ';'
 ;

sdn_iface_opt_list:
   /* empty */
 | '{' sdn_iface_opts '}'
 ;

sdn_iface_init:
   /* EMPTY */ {
     this_ipatt = cfg_allocz(sizeof(struct sdn_patt));
     add_tail(&SDN_CFG->iface_list, NODE this_ipatt);
     init_list(&this_ipatt->ipn_list);
     SDN_IPATT->metric = 1;
     SDN_IPATT->tx_tos = IP_PREC_INTERNET_CONTROL;
     SDN_IPATT->tx_priority = sk_priority_control;
     SDN_IPATT->ttl_security = SDN_DEFAULT_TTL_SECURITY;
   }
 ;

sdn_iface:	/* TODO: switch to iface_patt_list_nopx */
   sdn_iface_init iface_patt_list sdn_iface_opt_list
 ;

CF_CODE

CF_END
