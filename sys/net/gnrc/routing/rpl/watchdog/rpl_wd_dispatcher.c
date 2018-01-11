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
#include "net/gnrc/rpl/watchdog/rpl_wd_protector_base.h"
#include "trickle.h"
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

const uint8_t rpl_wd_field_size = (eENTRYCOUNT/8) + 1;
uint8_t* rpl_wd_idientification_field;

uint8_t* rpl_wd_result_field;

uint8_t* rpl_wd_handled_field;

static void _prepare(void)
{
    current_pkt_sender = NULL;
    current_incoming_iface = KERNEL_PID_UNDEF;
    current_pkt_dst = NULL;

    memset(rpl_wd_idientification_field, 0, rpl_wd_field_size);

    init_rules();
    register_rules();
    init_protectors();
    register_protectors();
}

kernel_pid_t rpl_watchdog_init(kernel_pid_t gnrc_rpl_pid)
{
    //printf("rpl_wd_field_size: %d\n", rpl_wd_field_size);
    /* start the event loop */
    rpl_watchdog_pid = thread_create(_stack, sizeof(_stack), GNRC_RPL_WATCHDOG_PRIO,
                                     THREAD_CREATE_STACKTEST,
                                     _event_loop, NULL, "RPL watchdog");
    rpl_pid = gnrc_rpl_pid;

    _prepare();
    return rpl_watchdog_pid;
}

static void _dispatch_timer_event(void *data, uint16_t type)
{
    switch (type) {
        case GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE:
            DEBUG("RPL: GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE received\n");
            setIdentificationBit(eTrickleUpdateLifetimes);
            break;
        case GNRC_RPL_MSG_TYPE_TRICKLE_MSG:
            DEBUG("RPL: GNRC_RPL_MSG_TYPE_TRICKLE_MSG received\n");
            trickle_t *trickle = data;
            if (trickle && (trickle->callback.func != NULL)) {
                if ((trickle->c < trickle->k) || (trickle->k == 0)) {
                    setIdentificationBit(eTrickleCallback);
                }
            }
            break;
        default:
            break;
    }
}

static void _print_result(void)
{
    /*
    for (size_t i = 0; i < (eENTRYCOUNT); ++i)
    {
        printf("[%2d]", i );
    }
    puts("");
    */
    /*
    printf("IDT: ");
    for (size_t i = 0; i < (eENTRYCOUNT); ++i)
    {
        printf("%d", (rpl_wd_idientification_field[(i/8)] & 1<<(i % 8)) != 0);
    }
    puts("");

    printf("HDL: ");
    for (size_t i = 0; i < (eENTRYCOUNT); ++i)
    {
        printf("%d", (rpl_wd_handled_field[(i/8)] & 1<<(i % 8)) != 0);
    }
    puts("");

    printf("RES: ");
    for (size_t i = 0; i < (eENTRYCOUNT); ++i)
    {
        printf("%d", (rpl_wd_result_field[(i/8)] & 1<<(i % 8)) != 0);
    }
    puts("\n");
    */
}

static void _apply_protectors(void)
{
    
    memcpy(rpl_wd_result_field, rpl_wd_idientification_field, rpl_wd_field_size);

    stProtector_t* protector = get_next_protector(NULL);
    while (protector)
    {
        protector->gethandled(rpl_wd_handled_field);

        if(protector->is_matching())
        {
            protector->apply(rpl_wd_result_field);
        }
        protector = get_next_protector(protector);
    }

    uint8_t tmp[rpl_wd_field_size];
    for (size_t i = 0; i < rpl_wd_field_size; ++i)
    {
        tmp[i] = (rpl_wd_idientification_field[i] & rpl_wd_handled_field[i]) ^ (rpl_wd_idientification_field[i]);
        rpl_wd_result_field[i] = ~tmp[i] & rpl_wd_result_field[i];
    }
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
            _apply_protectors();
            break;
        case GNRC_RPL_ICMPV6_CODE_DIO:
            DEBUG("RPL WD: dispatch DIO\n");
            rpl_wd_process_DIO((gnrc_rpl_dio_t *)(icmpv6_hdr + 1),
                               byteorder_ntohs(ipv6_hdr->len));
            _apply_protectors();
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO:
            DEBUG("RPL WD: dispatch DAO\n");
            rpl_wd_process_DAO((gnrc_rpl_dao_t *)(icmpv6_hdr + 1),
                               byteorder_ntohs(ipv6_hdr->len));
            _apply_protectors();
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO_ACK:
            DEBUG("RPL WD: dispatch DAO-ACK\n");
            rpl_wd_process_DAO_ACK((gnrc_rpl_dao_ack_t *)(icmpv6_hdr + 1),
                                   byteorder_ntohs(ipv6_hdr->len));
            _apply_protectors();
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

    memset(rpl_wd_idientification_field, 0, rpl_wd_field_size);
    memset(rpl_wd_result_field, 0, rpl_wd_field_size);
    memset(rpl_wd_handled_field, 0, rpl_wd_field_size);
//    gnrc_pktbuf_release(pkt);
}

static void *_event_loop(void *args)
{
    (void)args;
    msg_t msg, reply;

    uint8_t identification_field[rpl_wd_field_size];
    rpl_wd_idientification_field = identification_field;

    uint8_t result_field[rpl_wd_field_size];
    rpl_wd_result_field = result_field;

    uint8_t handled_field[rpl_wd_field_size];
    rpl_wd_handled_field = handled_field;


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
