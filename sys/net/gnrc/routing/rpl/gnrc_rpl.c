/*
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 *
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#include "net/icmpv6.h"
#include "net/ipv6.h"
#include "net/gnrc/ipv6/netif.h"
#include "net/gnrc.h"
#include "mutex.h"

#include "net/gnrc/rpl.h"
#ifdef MODULE_GNRC_RPL_P2P
#include "net/gnrc/rpl/p2p.h"
#include "net/gnrc/rpl/p2p_dodag.h"
#endif

#include "net/gnrc/rpl/hop.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/nettype.h"
#define ENABLE_DEBUG    (0)
#include "debug.h"

static char _stack[GNRC_RPL_STACK_SIZE];
kernel_pid_t gnrc_rpl_pid = KERNEL_PID_UNDEF;
const ipv6_addr_t ipv6_addr_all_rpl_nodes = GNRC_RPL_ALL_NODES_ADDR;
static uint32_t _lt_time = GNRC_RPL_LIFETIME_UPDATE_STEP * US_PER_SEC;
static xtimer_t _lt_timer;
static msg_t _lt_msg = { .type = GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE };
static msg_t _msg_q[GNRC_RPL_MSG_QUEUE_SIZE];
static gnrc_netreg_entry_t _me_reg;
static gnrc_netreg_entry_t _me_reg_dataplane_ext;
static mutex_t _inst_id_mutex = MUTEX_INIT;
static uint8_t _instance_id;

gnrc_rpl_instance_t gnrc_rpl_instances[GNRC_RPL_INSTANCES_NUMOF];
gnrc_rpl_parent_t gnrc_rpl_parents[GNRC_RPL_PARENTS_NUMOF];

#ifdef MODULE_NETSTATS_RPL
netstats_rpl_t gnrc_rpl_netstats;
#endif

static void _update_lifetime(void);
static void _dao_handle_send(gnrc_rpl_dodag_t *dodag);
static void _receive(gnrc_pktsnip_t *pkt);
static void *_event_loop(void *args);

kernel_pid_t gnrc_rpl_init(kernel_pid_t if_pid)
{
    /* check if RPL was initialized before */
    if (gnrc_rpl_pid == KERNEL_PID_UNDEF) {
        _instance_id = 0;
        /* start the event loop */
        gnrc_rpl_pid = thread_create(_stack, sizeof(_stack), GNRC_RPL_PRIO,
                                     THREAD_CREATE_STACKTEST,
                                     _event_loop, NULL, "RPL");

        if (gnrc_rpl_pid == KERNEL_PID_UNDEF) {
            DEBUG("RPL: could not start the event loop\n");
            return KERNEL_PID_UNDEF;
        }

        _me_reg.demux_ctx = ICMPV6_RPL_CTRL;
        _me_reg.target.pid = gnrc_rpl_pid;
        /* register interest in all ICMPv6 packets */
        gnrc_netreg_register(GNRC_NETTYPE_ICMPV6, &_me_reg);

        _me_reg_dataplane_ext.demux_ctx = PROTNUM_IPV6_EXT_HOPOPT;
        _me_reg_dataplane_ext.target.pid = gnrc_rpl_pid;
        /* register interest for IPv6 Hop-by-Hop extension headers */
        gnrc_netreg_register(GNRC_NETTYPE_IPV6, &_me_reg_dataplane_ext);

        gnrc_rpl_of_manager_init();
        xtimer_set_msg(&_lt_timer, _lt_time, &_lt_msg, gnrc_rpl_pid);

#ifdef MODULE_NETSTATS_RPL
        memset(&gnrc_rpl_netstats, 0, sizeof(gnrc_rpl_netstats));
#endif
    }

    /* register all_RPL_nodes multicast address */
    gnrc_ipv6_netif_add_addr(if_pid, &ipv6_addr_all_rpl_nodes, IPV6_ADDR_BIT_LEN, 0);

    gnrc_rpl_send_DIS(NULL, (ipv6_addr_t *) &ipv6_addr_all_rpl_nodes);
    return gnrc_rpl_pid;
}

gnrc_rpl_instance_t *gnrc_rpl_root_init(uint8_t instance_id, ipv6_addr_t *dodag_id,
                                        bool gen_inst_id, bool local_inst_id)
{
    if (gen_inst_id) {
        instance_id = gnrc_rpl_gen_instance_id(local_inst_id);
    }

    gnrc_rpl_dodag_t *dodag = NULL;
    gnrc_rpl_instance_t *inst = gnrc_rpl_root_instance_init(instance_id, dodag_id,
                                                            GNRC_RPL_DEFAULT_MOP);

    if (!inst) {
        return NULL;
    }

    dodag = &inst->dodag;

    dodag->dtsn = 1;
    dodag->prf = 0;
    dodag->dio_interval_doubl = GNRC_RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS;
    dodag->dio_min = GNRC_RPL_DEFAULT_DIO_INTERVAL_MIN;
    dodag->dio_redun = GNRC_RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT;
    dodag->default_lifetime = GNRC_RPL_DEFAULT_LIFETIME;
    dodag->lifetime_unit = GNRC_RPL_LIFETIME_UNIT;
    dodag->version = GNRC_RPL_COUNTER_INIT;
    dodag->grounded = GNRC_RPL_GROUNDED;
    dodag->node_status = GNRC_RPL_ROOT_NODE;
    dodag->my_rank = GNRC_RPL_ROOT_RANK;
    dodag->dio_opts |= GNRC_RPL_REQ_DIO_OPT_DODAG_CONF;
#ifndef GNRC_RPL_WITHOUT_PIO
    dodag->dio_opts |= GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO;
#endif

    trickle_start(gnrc_rpl_pid, &dodag->trickle, GNRC_RPL_MSG_TYPE_TRICKLE_MSG,
                  (1 << dodag->dio_min), dodag->dio_interval_doubl,
                  dodag->dio_redun);

    return inst;
}

static void _handle_ext_hdr_insert(gnrc_pktsnip_t *pkt)
{
    ipv6_hdr_t* hdr = gnrc_ipv6_get_header(pkt);
    /* get the ipv6 header to append the extensions */
    if (hdr == NULL) {
        return;
    }

    for (uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
        /* check if the destination is in one of our DODAGs */
        gnrc_ipv6_netif_addr_t* prefix = gnrc_rpl_instances[i].dodag.netif_addr;

        if (ipv6_addr_match_prefix(&(prefix->addr), &(hdr->dst)) == prefix->prefix_len) {
            /* determine the forwarding direction towards the destination */
            kernel_pid_t fib_iface;
            ipv6_addr_t next_hop;
            size_t next_hop_size = sizeof(ipv6_addr_t);
            uint32_t next_hop_flags;

            int ret = fib_get_next_hop(&gnrc_ipv6_fib_table, &fib_iface,
                                       next_hop.u8, &next_hop_size,
                                       &next_hop_flags, hdr->dst.u8, next_hop_size,
                                       0);
            if ( (ret == 0) && (next_hop_flags & FIB_FLAG_RPL_ROUTE) ) {
                /* we know a next hop and it has been set by RPL */
                gnrc_rpl_hop_opt_t ext_hdr;

                ext_hdr.nh = 0x63;
                ext_hdr.len = (sizeof(gnrc_rpl_hop_opt_t) - 2);
                /* set default propagation direction to upward */
                ext_hdr.ORF_flags = GNRC_RPL_HOP_OPT_FLAG_O;

                ext_hdr.instance_id = gnrc_rpl_instances[i].id;
                ext_hdr.sender_rank = gnrc_rpl_instances[i].dodag.my_rank;

                if ( !ipv6_addr_is_unspecified(&next_hop) ) {
                    /* its a downward route entry so we clear the bit */
                    ext_hdr.ORF_flags &= ~GNRC_RPL_HOP_OPT_FLAG_O;
                }
                /* append the extension below the IPv6 Header */
                gnrc_pktsnip_t* ext = gnrc_pktbuf_add(pkt->next, &ext_hdr,
                                                      sizeof(gnrc_ipv6_ext_hdr_handle_t),
                                                      GNRC_NETTYPE_UNDEF);
                if (ext) {
                    /* bend the pointers */
                    pkt->next = ext;
                }
            }
        }
    }
}

static void _handle_ext_hdr_process(gnrc_pktsnip_t *ext, msg_t *msg)
{
        ipv6_ext_t *ext_header = ext->data;
        gnrc_ipv6_ext_hdr_handle_t* content = (gnrc_ipv6_ext_hdr_handle_t*)msg->content.ptr;
        content->next_hdr = NULL;
        content->nh_type = PROTNUM_RESERVED;

        gnrc_pktsnip_t *netif = gnrc_pktsnip_search_type(content->current, GNRC_NETTYPE_NETIF);
        content->iface = ((gnrc_netif_hdr_t *)netif->data)->if_pid;

        if (ext_header->nh == GNRC_RPL_HOP_OPT_TYPE) {
            gnrc_rpl_hop_opt_t *hop = (gnrc_rpl_hop_opt_t *)ext_header;
            int ret = gnrc_rpl_hop_opt_process(hop);
            switch (ret) {
                case HOP_OPT_ERR_NOT_FOR_ME:
                /* we found the header is just not for us */
                /* fallthrough intentionally */
                case HOP_OPT_ERR_HEADER_LENGTH:
                /* something is broken with the extension -> ignore header, probably just not for us */
                /* fallthrough intentionally */
                case HOP_OPT_ERR_FLAG_R_SET:
                /* we determined the first forwarding error and have set the R Flag */
                /* fallthrough intentionally */
                case HOP_OPT_SUCCESS: {
                    /* we check for more headers and let IPv6 demux them */
                    if ((ext->next) && ext->next->type == GNRC_NETTYPE_IPV6_EXT) {
                        content->next_hdr = ext->next;
                        content->nh_type = ((ipv6_ext_t*)ext->next->data)->nh;
                    }

                    msg_send(msg, msg->sender_pid);
                    break;
                }
                case HOP_OPT_ERR_INCONSISTENCY:
                    // we received a F Flag, process dependant on MOP
                    // drop on non-storing
                    // TODO: keep track of original sender and count F errors
                    break;
                case HOP_OPT_ERR_FLAG_F_SET:
                    // we determined the second forwarding error and set the F Flag
                    // drop on non-storing
                    // TODO: keep track of original sender and count F errors
                    break;

                default:
                    break;
            }
        }
}

static void _receive(gnrc_pktsnip_t *icmpv6)
{
    gnrc_pktsnip_t *ipv6, *netif;
    ipv6_hdr_t *ipv6_hdr;
    icmpv6_hdr_t *icmpv6_hdr;
    kernel_pid_t iface = KERNEL_PID_UNDEF;

    assert(icmpv6 != NULL);

    ipv6 = gnrc_pktsnip_search_type(icmpv6, GNRC_NETTYPE_IPV6);
    netif = gnrc_pktsnip_search_type(icmpv6, GNRC_NETTYPE_NETIF);

    assert(ipv6 != NULL);

    if (netif) {
        iface = ((gnrc_netif_hdr_t *)netif->data)->if_pid;
    }

    ipv6_hdr = (ipv6_hdr_t *)ipv6->data;

    icmpv6_hdr = (icmpv6_hdr_t *)icmpv6->data;
    switch (icmpv6_hdr->code) {
        case GNRC_RPL_ICMPV6_CODE_DIS:
            DEBUG("RPL: DIS received\n");
            gnrc_rpl_recv_DIS((gnrc_rpl_dis_t *)(icmpv6_hdr + 1), iface, &ipv6_hdr->src,
                              &ipv6_hdr->dst, byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DIO:
            DEBUG("RPL: DIO received\n");
            gnrc_rpl_recv_DIO((gnrc_rpl_dio_t *)(icmpv6_hdr + 1), iface, &ipv6_hdr->src,
                              &ipv6_hdr->dst, byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO:
            DEBUG("RPL: DAO received\n");
            gnrc_rpl_recv_DAO((gnrc_rpl_dao_t *)(icmpv6_hdr + 1), iface, &ipv6_hdr->src,
                              &ipv6_hdr->dst, byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO_ACK:
            DEBUG("RPL: DAO-ACK received\n");
            gnrc_rpl_recv_DAO_ACK((gnrc_rpl_dao_ack_t *)(icmpv6_hdr + 1), iface, &ipv6_hdr->src,
                                  &ipv6_hdr->dst, byteorder_ntohs(ipv6_hdr->len));
            break;
#ifdef MODULE_GNRC_RPL_P2P
        case GNRC_RPL_P2P_ICMPV6_CODE_DRO:
            DEBUG("RPL: P2P DRO received\n");
            gnrc_pktsnip_t *icmpv6_snip = gnrc_pktbuf_add(NULL, NULL, icmpv6->size,
                                                          GNRC_NETTYPE_ICMPV6);
            if (icmpv6_snip == NULL) {
                DEBUG("RPL-P2P: cannot copy ICMPv6 packet\n");
                break;
            }

            memcpy(icmpv6_snip->data, icmpv6->data, icmpv6->size);

            gnrc_rpl_p2p_recv_DRO(icmpv6_snip, &ipv6_hdr->src);
            break;
        case GNRC_RPL_P2P_ICMPV6_CODE_DRO_ACK:
            DEBUG("RPL: P2P DRO-ACK received\n");
            break;
#endif
        default:
            DEBUG("RPL: Unknown ICMPV6 code received\n");
            break;
    }

    gnrc_pktbuf_release(icmpv6);
}

static void *_event_loop(void *args)
{
    msg_t msg, reply, ext_handle;
    gnrc_ipv6_ext_hdr_handle_t ext_msg_content;

    (void)args;
    msg_init_queue(_msg_q, GNRC_RPL_MSG_QUEUE_SIZE);

    /* preinitialize next header call */
    ext_handle.type = GNRC_IPV6_EXT_HANDLE_NEXT_HDR;
    ext_handle.content.ptr = (void*)&ext_msg_content;

    /* preinitialize ACK */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    trickle_t *trickle;
    /* start event loop */
    while (1) {
        DEBUG("RPL: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
            case GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE:
                DEBUG("RPL: GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE received\n");
                _update_lifetime();
                break;
            case GNRC_RPL_MSG_TYPE_TRICKLE_MSG:
                DEBUG("RPL: GNRC_RPL_MSG_TYPE_TRICKLE_MSG received\n");
                trickle = msg.content.ptr;
                if (trickle && (trickle->callback.func != NULL)) {
                    trickle_callback(trickle);
                }
                break;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("RPL: GNRC_NETAPI_MSG_TYPE_RCV received\n");
                /* check for header extensions */
                gnrc_pktsnip_t *ext = gnrc_pktsnip_search_type(msg.content.ptr,
                                                               GNRC_NETTYPE_IPV6_EXT);
                if (ext) {
                    ext_msg_content.current = msg.content.ptr;
                    _handle_ext_hdr_process(ext, &ext_handle);
                }
                else {
                /* handle control msg */
                    _receive(msg.content.ptr);
                }
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                break;
            case GNRC_NETAPI_MSG_TYPE_SET:
                DEBUG("RPL: reply to unsupported set\n");
                reply.content.value = -ENOTSUP;
                msg_reply(&msg, &reply);
                break;
            case GNRC_NETAPI_MSG_TYPE_GET: {
                gnrc_netapi_opt_t *o = (gnrc_netapi_opt_t*)msg.content.ptr;
                if (o->opt == NETOPT_IPV6_EXT_HDR) {
                    DEBUG("RPL: call to add extension header received\n");
                    switch (o->context) {
                        case PROTNUM_IPV6_EXT_HOPOPT:
                            /* preinit that no extension has been inserted */
                            reply.content.value = 0;
                            if (gnrc_pktsnip_search_type(o->data,
                                                         GNRC_NETTYPE_ICMPV6) == NULL) {
                                /* but only if we send a dataplane packet */
                                _handle_ext_hdr_insert(o->data);
                                /* reply that we added an extension */
                                reply.content.value = 1;
                            }
                            msg_reply(&msg, &reply);
                            break;
                        case PROTNUM_IPV6_EXT_RH:
                            break;
                        default:
                            DEBUG("RPL: reply to unsupported context\n");
                            reply.content.value = -ENOTSUP;
                            msg_reply(&msg, &reply);
                            break;
                    }
                }
                break;
            }
            default:
                break;
        }
    }

    return NULL;
}

void _update_lifetime(void)
{
    gnrc_rpl_parent_t *parent;
    gnrc_rpl_instance_t *inst;

    for (uint8_t i = 0; i < GNRC_RPL_PARENTS_NUMOF; ++i) {
        parent = &gnrc_rpl_parents[i];
        if (parent->state != 0) {
            if (parent->lifetime > GNRC_RPL_LIFETIME_UPDATE_STEP) {
                if (parent->lifetime <= (2 * GNRC_RPL_LIFETIME_UPDATE_STEP)) {
                    gnrc_rpl_send_DIS(parent->dodag->instance, &parent->addr);
                }
                parent->lifetime -= GNRC_RPL_LIFETIME_UPDATE_STEP;
            }
            else {
                gnrc_rpl_dodag_t *dodag = parent->dodag;
                gnrc_rpl_parent_remove(parent);
                gnrc_rpl_parent_update(dodag, NULL);
            }
        }
    }

    for (int i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
        inst = &gnrc_rpl_instances[i];
        if (inst->state != 0) {
            if ((inst->cleanup > 0) && (inst->dodag.parents == NULL) &&
                (inst->dodag.my_rank == GNRC_RPL_INFINITE_RANK)) {
                inst->cleanup -= GNRC_RPL_LIFETIME_UPDATE_STEP;
                if (inst->cleanup <= 0) {
                    /* no parents - delete this instance and DODAG */
                    gnrc_rpl_instance_remove(inst);
                    continue;
                }
            }

            if (inst->dodag.dao_time > GNRC_RPL_LIFETIME_UPDATE_STEP) {
                inst->dodag.dao_time -= GNRC_RPL_LIFETIME_UPDATE_STEP;
            }
            else {
                _dao_handle_send(&inst->dodag);
            }
        }
    }

#ifdef MODULE_GNRC_RPL_P2P
    gnrc_rpl_p2p_update();
#endif

    xtimer_set_msg(&_lt_timer, _lt_time, &_lt_msg, gnrc_rpl_pid);
}

void gnrc_rpl_delay_dao(gnrc_rpl_dodag_t *dodag)
{
    dodag->dao_time = GNRC_RPL_DEFAULT_DAO_DELAY;
    dodag->dao_counter = 0;
    dodag->dao_ack_received = false;
}

void gnrc_rpl_long_delay_dao(gnrc_rpl_dodag_t *dodag)
{
    dodag->dao_time = GNRC_RPL_REGULAR_DAO_INTERVAL;
    dodag->dao_counter = 0;
    dodag->dao_ack_received = false;
}

void _dao_handle_send(gnrc_rpl_dodag_t *dodag)
{
#ifdef MODULE_GNRC_RPL_P2P
    if (dodag->instance->mop == GNRC_RPL_P2P_MOP) {
        return;
    }
#endif
    if ((dodag->dao_ack_received == false) && (dodag->dao_counter < GNRC_RPL_DAO_SEND_RETRIES)) {
        dodag->dao_counter++;
        gnrc_rpl_send_DAO(dodag->instance, NULL, dodag->default_lifetime);
        dodag->dao_time = GNRC_RPL_DEFAULT_WAIT_FOR_DAO_ACK;
    }
    else if (dodag->dao_ack_received == false) {
        gnrc_rpl_long_delay_dao(dodag);
    }
}

uint8_t gnrc_rpl_gen_instance_id(bool local)
{
    mutex_lock(&_inst_id_mutex);
    uint8_t instance_id = GNRC_RPL_DEFAULT_INSTANCE;

    if (local) {
        instance_id = ((_instance_id++) | GNRC_RPL_INSTANCE_ID_MSB);
        mutex_unlock(&_inst_id_mutex);
        return instance_id;
    }

    instance_id = ((_instance_id++) & GNRC_RPL_GLOBAL_INSTANCE_MASK);
    mutex_unlock(&_inst_id_mutex);
    return instance_id;
}

/**
 * @}
 */
