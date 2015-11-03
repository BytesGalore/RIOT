/*
 * Copyright (C) 2015 Martin Landsmann <martin.landsmann@haw-hamburg.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup net_gnrc_dsr
 * @{
 *
 * @file
 * @brief       DSR tables
 *
 * Table types used by DSR
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef GNRC_DSR_TABLES_H_
#define GNRC_DSR_TABLES_H_

#ifdef __cplusplus
extern "C" {
#endif

//#include "xtimer.h"
#include "net/gnrc.h"
#include "net/ipv6/addr.h"

/**
 * @brief the route request table data container
 */
typedef struct{
    /** target node address for rreq */
    ipv6_addr_t dst;
    /** Hop limit from the last route discovery  */
    uint8_t TTL;
    /** Timepoint of the last route request for this target */
    uint64_t last_rreq;
    /** number of cosecutive discoveries since last succesfull rrep */
    uint8_t initiated_route_discoveries;
    /** Timepoint of the next route request for this target */
    uint64_t next_rreq;    
}dsr_rreq_table_t;

/** the mximum number of entries of cached recent rreqs*/
#define DSR_RECENT_RREQS (3)
/** the route request table */
dsr_rreq_table_t dsr_recent_rreqs[DSR_RECENT_RREQS];

/**
 * @brief FIFO for most recent rreq from this initiator
 */
typedef struct{
    /** initiator node */
    ipv6_addr_t initiator_addr;
    /** identification value */
    uint16_t target_identification;
    /** target address */
    ipv6_addr_t target_addr;
}dsr_recent_id_target_t;

/** size of the FIFO cache for the recent rreq from each initiator */
#define DSR_REQUEST_TABLE_IDS (3) // RequestTableIds
/** FIFO cache for the recent rreq from each initiator */
dsr_recent_id_target_t dsr_rreq_fifo_cache[DSR_REQUEST_TABLE_IDS];

/**
 * @brief gratious rrep table data container 
 */
typedef struct{
    /** originator node (the node I forward the gratious rrep first) */
    ipv6_addr_t originator_addr;
    /** the overheared node address */
    ipv6_addr_t overheared_addr;
    /** Lifetime of this entry SHOULD be (now + GratReplyHoldoff) */
    uint64_t timeout; 
}dsr_gratious_rrep_table_t;

/** size of the gratious rrep table size */
#define DSR_GRATIOUS_RREPS (3)
/** the gratious rrep table */
dsr_gratious_rrep_table_t dsr_gratious_rrep_table[DSR_GRATIOUS_RREPS];

/**
 * @brief Maintenence Buffer data structure
 */
 typedef struct{
     /** maximum nuber of retransmits before drop */
     size_t MaxMaintRexmt;
     /** buffered packet */
     gnrc_pktsnip_t* pkt;
 }dsr_maintenece_buffer_t;
 
/** size of the Maintenence Buffer size */
#define DSR_MANTENENCE_BUFFER (3)
/** the gMaintenence Buffer */
dsr_maintenece_buffer_t dsr_maintenece_buffer[DSR_MANTENENCE_BUFFER];

/**
 * @brief a blacklist entry state
 */
typedef enum{
    /** unreachability is NOT positively determined (may be tested) */
    questionable,
    /** unreachability is positively determined */
    probable,
}dsr_blacklist_entry_state_e;

/**
 * @brief Blacklist data structure
 */
 typedef struct{
    /** this entry state */
    dsr_blacklist_entry_state_e state;
    /** this entry address */
    ipv6_addr_t addr;
    /** timeout of node considered unreachable switch state to questionable */
    uint64_t timeout; 
 }dsr_blacklist_entry_t;
 
/** size of the blacklist */
#define DSR_BLACKLIST (3)
/** node blacklist for only unidirectional cosidered nodes */
dsr_blacklist_entry_t dsr_blacklist[DSR_BLACKLIST];


/** identifier tripple for a flow */
typedef struct{
    /** source address */
    ipv6_addr_t src_addr;
    /** destiantion address */
    ipv6_addr_t dst_addr;
    /** flow ID */
    uint16_t flow_id;
}dsr_flow_identifier_t;

/**
 * @brief Flow Table data structure
 */
typedef struct{
    /** identifier tripple for this flow table entry */
    dsr_flow_identifier_t ident; 
    
    /** MAC address of the next-hop node */
    uint64_t next_mac_addr;
    /** interface ID for sendig/forwarding */
    kernel_pid_t send_iface_id;
    
    /** MAC address of the previous-hop node */
    uint64_t prev_mac_addr;
    /** interface ID of received packet from previous-hop node */
    kernel_pid_t prev_iface_id;
    
    /** Lifetime of this flow */
    uint64_t lifetime;
    
    /** expected hop count*/
    uint8_t expected_hop_count;
    /** can this flow be a default flow */
    bool flow_can_be_default;
    
    /** number of entries in source route */
    size_t source_route_entries;
    /** this entry address */
    ipv6_addr_t* source_route;
    
    /** Timepoint when the entry was last used */
    uint64_t last_used; 
}dsr_flow_table_t;

/** size of the Flow Table */
#define DSR_FLOW_TABLE (3)
/** the Flow Table */
dsr_flow_table_t dsr_flow_table[DSR_FLOW_TABLE];


/** the shortening list entry data structure */
typedef struct{
    /** unique identifier for the packet */
    uint64_t packet_identifier;
    /** hop count from flow sate header of this packet */
    uint8_t hop_count;
}dsr_shortening_packet_t;

/** number of saved packets in one shortening list entry */
#define DSR_SHORTENING_TABLE_PACKETS (3)

/**
 * @brief Automatic Route Shortening Table structure
 */
typedef struct{
    /** identifier tripple for this shortening table entry */
    dsr_flow_identifier_t ident;
    /** saved packet information for shortening */
    dsr_shortening_packet_t packets[DSR_SHORTENING_TABLE_PACKETS];
}dsr_flow_shortening_table_t;

/** size of the Automatic Route Shortening Table */
#define DSR_AUTO_ROUTE_SHORTENING_TABLE (3)
/** the Automatic Route Shortening Table */
dsr_flow_shortening_table_t dsr_flow_shortening_table[DSR_AUTO_ROUTE_SHORTENING_TABLE];

/**
 * @brief Default Flow ID Table data structure
 */
typedef struct{
    /** identifier for this entry 
     *  @note the flow_id MUST be set to the largest odd Flow ID value seen
     *        when forwarding a matching packet for src_addr && dst_addr
     */
    dsr_flow_identifier_t ident;
    
    /** Timepoint at which all the corresponding flows that are forwarded
     * by this node expire 
     */
    uint64_t lifetime;
    
    /** current flow ID */
    uint16_t flow_id;
    
    /** indicates whether or not the current default Flow ID is valid. */
    bool is_valid;
    
}dsr_flow_id_table_t;

/** size of the Default Flow ID Table */
#define DSR_DEFAULT_FLOW_ID_TABLE (3)
/** the Default Flow ID Table */
dsr_flow_id_table_t dsr_default_flow_id_table[DSR_DEFAULT_FLOW_ID_TABLE];


#ifdef __cplusplus
}
#endif

#endif /* GNRC_DSR_TABLES_H_ */
/**
 * @}
 */
