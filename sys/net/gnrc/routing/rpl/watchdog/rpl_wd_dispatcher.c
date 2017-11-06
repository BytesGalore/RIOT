/*
 * Copyright (C) 2017
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
 * @author  martin.landsmann@haw-hamburg.de
 */

#include "net/gnrc/rpl/watchdog/rpl_wd_dispatcher.h"
#include "net/gnrc/rpl/watchdog/rpl_wd_parser_base.h"
#include "net/gnrc/rpl/watchdog/rpl_wd_rule_base.h"
#include "net/icmpv6.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

kernel_pid_t rpl_watchdog_pid = KERNEL_PID_UNDEF;
kernel_pid_t rpl_pid = KERNEL_PID_UNDEF;
static char _stack[GNRC_RPL_WATCHDOG_STACK_SIZE];
static msg_t _msg_q[GNRC_RPL_WATCHDOG_MSG_QUEUE_SIZE];

static void *_event_loop(void *args);


ipv6_addr_t *current_pkt_sender;
kernel_pid_t current_incoming_iface;
ipv6_addr_t *current_pkt_dst;

rpl_watchdog_result_t rpl_wd_result_field;

#define GET_VARIABLE_NAME(Variable) (#Variable)

static void _prepare(void)
{
    current_pkt_sender = NULL;
    current_incoming_iface = KERNEL_PID_UNDEF;
    current_pkt_dst = NULL;

    rpl_wd_result_field = 0;

    init_rules();
    register_rules();
}

kernel_pid_t rpl_watchdog_init(kernel_pid_t gnrc_rpl_pid)
{
    /* start the event loop */
    rpl_watchdog_pid = thread_create(_stack, sizeof(_stack), GNRC_RPL_WATCHDOG_PRIO,
                                     THREAD_CREATE_STACKTEST,
                                     _event_loop, NULL, "RPL watchdog");
    rpl_pid = gnrc_rpl_pid;

    _prepare();
    
    return rpl_watchdog_pid;
}

static void _dispatch_timer_event(gnrc_pktsnip_t *pkt, uint16_t type)
{
    (void)pkt;
    (void)type;
}

static void _print_result(void)
{
    printf("rpl_wd_result_field: %x\n", rpl_wd_result_field);
    for (size_t i = 0; i < (eENTRYCOUNT); ++i)
    {
        printf("[%2d]", i );
    }
    puts("");
    for (size_t i = 0; i < (eENTRYCOUNT); ++i)
    {
        printf(" %2d ", (rpl_wd_result_field >> i)&1 );
    }
    puts("");
}

static void _dispatch_incoming_packet(gnrc_pktsnip_t *pkt)
{
    DEBUG("RPL WD: dispatch\n");
    gnrc_pktsnip_t *ipv6, *netif;
    ipv6_hdr_t *ipv6_hdr;
    icmpv6_hdr_t *icmpv6_hdr;
    kernel_pid_t iface = KERNEL_PID_UNDEF;

    assert(pkt != NULL);

    ipv6 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6);
    netif = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_NETIF);

    assert(ipv6 != NULL);

    if (netif) {
        iface = ((gnrc_netif_hdr_t *)netif->data)->if_pid;
    }

    ipv6_hdr = (ipv6_hdr_t *)ipv6->data;

    current_pkt_sender = &ipv6_hdr->src;
    current_incoming_iface = iface;
    current_pkt_dst = &ipv6_hdr->dst;

    icmpv6_hdr = (icmpv6_hdr_t *)pkt->data;
    switch (icmpv6_hdr->code) {
        case GNRC_RPL_ICMPV6_CODE_DIS:
            DEBUG("RPL WD: dispatch DIS\n");
            rpl_wd_process_DIS((gnrc_rpl_dis_t *)(icmpv6_hdr + 1),
                               byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DIO:
            DEBUG("RPL WD: dispatch DIO\n");
            rpl_wd_process_DIO((gnrc_rpl_dio_t *)(icmpv6_hdr + 1),
                               byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO:
            DEBUG("RPL WD: dispatch DAO\n");
            rpl_wd_process_DAO((gnrc_rpl_dao_t *)(icmpv6_hdr + 1),
                               byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO_ACK:
            DEBUG("RPL WD: dispatch DAO-ACK\n");
            rpl_wd_process_DAO_ACK((gnrc_rpl_dao_ack_t *)(icmpv6_hdr + 1),
                                   byteorder_ntohs(ipv6_hdr->len));
            break;
#ifdef MODULE_GNRC_RPL_P2P
        case GNRC_RPL_P2P_ICMPV6_CODE_DRO:
            DEBUG("RPL WD: dispatch P2P DRO\n");
            rpl_wd_process_DRO(pkt);
            break;
        case GNRC_RPL_P2P_ICMPV6_CODE_DRO_ACK:
            DEBUG("RPL WD: dispatch P2P DRO-ACK\n");

            break;
#endif
        default:
            DEBUG("RPL WD: dispatch Unknown ICMPV6 code.\n");
            break;
    }
_print_result();
    current_pkt_sender = NULL;
    current_incoming_iface = KERNEL_PID_UNDEF;
    current_pkt_dst = NULL;
    rpl_wd_result_field = 0;

//    gnrc_pktbuf_release(pkt);
}

static void *_event_loop(void *args)
{
    msg_t msg, reply;

    (void)args;
    msg_init_queue(_msg_q, GNRC_RPL_WATCHDOG_MSG_QUEUE_SIZE);

    /* preinitialize ACK */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    /* start event loop */
    while (1) {
        DEBUG("RPL WD: waiting for incoming message.\n");
        msg_receive(&msg);
        switch (msg.type) {
            case GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE:
                DEBUG("RPL WD: GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE received\n");
                _dispatch_timer_event(msg.content.ptr, msg.type);
                msg_send(&msg, rpl_pid);
                break;
            case GNRC_RPL_MSG_TYPE_TRICKLE_MSG:
                DEBUG("RPL WD: GNRC_RPL_MSG_TYPE_TRICKLE_MSG received\n");
                _dispatch_timer_event(msg.content.ptr, msg.type);
                msg_send(&msg, rpl_pid);
                break;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("RPL WD: GNRC_NETAPI_MSG_TYPE_RCV received\n");
                _dispatch_incoming_packet(msg.content.ptr);
                msg_send(&msg, rpl_pid);
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                break;
            case GNRC_NETAPI_MSG_TYPE_GET:
            case GNRC_NETAPI_MSG_TYPE_SET:
                DEBUG("RPL WD: reply to unsupported get/set\n");
                reply.content.value = -ENOTSUP;
                msg_reply(&msg, &reply);
                break;
            default:
                break;
        }
    }

    return NULL;
}
