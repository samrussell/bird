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

CF_KEYWORDS(SDN)

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
 ;

CF_CODE

CF_END
