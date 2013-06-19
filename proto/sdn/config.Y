/*
 *	BIRD -- SDN Configuration
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
To add:

version1 switch

*/


CF_HDR

#include "proto/sdn/sdn.h"
#include "nest/iface.h"

CF_DEFINES

#define SDN_CFG ((struct sdn_proto_config *) this_proto)
#define SDN_IPATT ((struct sdn_patt *) this_ipatt)

CF_DECLS

CF_KEYWORDS(SDN, INFINITY, METRIC, PORT, PERIOD, GARBAGE, TIMEOUT,
	    MODE, BROADCAST, MULTICAST, QUIET, NOLISTEN, VERSION1, 
	    AUTHENTICATION, NONE, PLAINTEXT, MD5,
	    HONOR, NEVER, NEIGHBOR, ALWAYS,
	    SDN_METRIC, SDN_TAG)

%type <i> sdn_mode sdn_auth

CF_GRAMMAR

CF_ADDTO(proto, sdn_cfg '}' { SDN_CFG->passwords = get_passwords(); } )

sdn_cfg_start: proto_start SDN {
     this_proto = proto_config_new(&proto_sdn, sizeof(struct sdn_proto_config), $1);
     sdn_init_config(SDN_CFG);
   }
 ;

sdn_cfg:
   sdn_cfg_start proto_name '{'
 | sdn_cfg proto_item ';'
 | sdn_cfg INFINITY expr ';'	{ SDN_CFG->infinity = $3; }
 | sdn_cfg PORT expr ';'	{ SDN_CFG->port = $3; }
 | sdn_cfg PERIOD expr ';'	{ SDN_CFG->period = $3; }
 | sdn_cfg GARBAGE TIME expr ';' { SDN_CFG->garbage_time = $4; }
 | sdn_cfg TIMEOUT TIME expr ';' { SDN_CFG->timeout_time = $4; }
 | sdn_cfg AUTHENTICATION sdn_auth ';' {SDN_CFG->authtype = $3; }
 | sdn_cfg password_list ';'
 | sdn_cfg HONOR ALWAYS ';'    { SDN_CFG->honor = HO_ALWAYS; }
 | sdn_cfg HONOR NEIGHBOR ';'    { SDN_CFG->honor = HO_NEIGHBOR; }
 | sdn_cfg HONOR NEVER ';'    { SDN_CFG->honor = HO_NEVER; }
 | sdn_cfg INTERFACE sdn_iface ';'
 ;

sdn_auth:
   PLAINTEXT { $$=AT_PLAINTEXT; }
 | MD5 { $$=AT_MD5; }
 | NONE { $$=AT_NONE; }
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
   }
 ;

sdn_iface:
   sdn_iface_init iface_patt_list sdn_iface_opt_list
 ;

CF_ADDTO(dynamic_attr, SDN_METRIC { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_SDN_METRIC); })
CF_ADDTO(dynamic_attr, SDN_TAG { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_SDN_TAG); })

CF_CODE

CF_END
