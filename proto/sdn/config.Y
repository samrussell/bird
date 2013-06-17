/*
 *	BIRD -- Binding for SDN controllers
 *
 *	(c) 2013 Sam Russell <sam.h.russell@gmail.com>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/sdn/sdn.h"

CF_DEFINES

#define SDN_CFG ((struct sdn_config *) this_proto)

CF_DECLS

CF_KEYWORDS(SDN) /* , PEER, TABLE, MODE, OPAQUE, TRANSPARENT */

CF_GRAMMAR

CF_ADDTO(proto, sdn_proto '}')

sdn_proto_start: proto_start SDN {
     this_proto = proto_config_new(&proto_sdn, sizeof(struct sdn_config), $1);
     SDN_CFG->mode = SDN_TRANSPARENT;
  }
 ;

sdn_proto:
   sdn_proto_start proto_name '{'
 | sdn_proto proto_item ';'
 | sdn_proto PEER TABLE SYM ';' {
     if ($4->class != SYM_TABLE)
       cf_error("Routing table name expected");
     SDN_CFG->peer = $4->def;
   }
 | sdn_proto MODE OPAQUE ';' { SDN_CFG->mode = SDN_OPAQUE; }
 | sdn_proto MODE TRANSPARENT ';' { SDN_CFG->mode = SDN_TRANSPARENT; }
 ;

CF_CODE

CF_END
