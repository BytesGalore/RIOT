/*
 * Copyright (C) 2015 Martin Landsmann <martin.landsmann@haw-hamburg.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @{
 *
 * @file
 *
 * @author  Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#include "kernel.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"
#include "net/gnrc/dsr/data_types.h"
#include "net/gnrc/dsr/tables.h"
#include "net/gnrc/dsr/basic_functions.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

/*
#if ENABLE_DEBUG
static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif
*/

static kernel_pid_t _pid = KERNEL_PID_UNDEF;
/**
 * @brief   Stack for the DSR UDP thread
 */
static char _stack[THREAD_STACKSIZE_MAIN];

static int _receive(gnrc_pktsnip_t* pkt)
{
    //gnrc_pktsnip_t *snip = pkt;
    gnrc_pktsnip_t *snip = pkt;
    if( snip != NULL && snip->type == GNRC_NETTYPE_UDP) {
        puts("udp snip\n");
    }
    
    udp_hdr_t* hdr = (udp_hdr_t*)snip->data;
    printf("udp size: %d\n", byteorder_ntohl(hdr->length));
    
    
    if( snip != NULL && snip->type == GNRC_NETTYPE_UDP) {
        printf("payload snip: %d Bytes\n", snip->size);
        for( size_t i = 0; i < snip->size; ++i) {
            
            if((i > 0) && (i%8 == 0) ){
                puts("");
            }
            printf("%02x ", ((uint8_t*)(snip->data))[i]);
        }
    }
    
    gnrc_pktbuf_release(pkt);
    return 0;
}

static void *_event_loop(void *arg)
{
    (void)arg;
    msg_t msg, reply;
    msg_t msg_queue[GNRC_UDP_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t netreg;

    /* preset reply message */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
    reply.content.value = (uint32_t)-ENOTSUP;
    /* initialize message queue */
    msg_init_queue(msg_queue, GNRC_UDP_MSG_QUEUE_SIZE);
    /* register UPD at netreg */
    netreg.demux_ctx = GNRC_NETREG_DEMUX_CTX_ALL;
    netreg.pid = thread_getpid();
    gnrc_netreg_register(GNRC_NETTYPE_UDP, &netreg);

    /* dispatch NETAPI messages */
    while (1) {
        msg_receive(&msg);
        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("udp: GNRC_NETAPI_MSG_TYPE_RCV\n");
                _receive((gnrc_pktsnip_t *)msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUG("udp: GNRC_NETAPI_MSG_TYPE_SND\n");
                //_send((gnrc_pktsnip_t *)msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SET:
            case GNRC_NETAPI_MSG_TYPE_GET:
                msg_reply(&msg, &reply);
                break;
            default:
                DEBUG("udp: received unidentified message\n");
                break;
        }
    }

    /* never reached */
    return NULL;
}

void dsr_start_listener(void)
{
   _pid = thread_create(_stack, sizeof(_stack), (THREAD_PRIORITY_MAIN - 4), 
                        CREATE_STACKTEST, _event_loop, NULL, "DSR");
}

static void print_dsr_head(dsr_opt_hdr_t* hdr)
{
    printf("size: %d\n", sizeof(*hdr));
    printf("Next Header %x\n", hdr->next_header);
    printf("flags %x\n", hdr->flags.flow_state);
    printf("payload length %d\n", hdr->payload_length);
}

static void print_dsr_opt_rreq(dsr_route_request_option_t* rreq)
{
    printf("size: %d\n", sizeof(*rreq));
    printf("type %d\n", rreq->opt_type);
    printf("opt_data_length %d\n", rreq->opt_data_length);
    printf("identification %d\n", rreq->identification);
}

void dsr_construct_opt_rreq( void ) {
    
    puts("dsr_construct_opt_rreq called.");
    dsr_opt_hdr_t dsr_hdr;
    
    /* no header following */
    dsr_hdr.next_header = DSR_NO_NEXT_HEADER;
    /* no flow state */
    dsr_hdr.flags.all_bits = 0;
    //dsr_hdr.flags.reserved_bits = 0;
    /* we start with an empty header, i.e. no options */
    dsr_hdr.payload_length = 0;
    
    dsr_route_request_option_t opt_rreq;
    opt_rreq.opt_type = 255;
    opt_rreq.opt_data_length = 2 + 16 + (16);
    
    opt_rreq.target_address.u32[0] = byteorder_htonl(0x20010000);
    opt_rreq.target_address.u32[1] = byteorder_htonl(0x00000000);
    opt_rreq.target_address.u32[2] = byteorder_htonl(0x00000000);
    opt_rreq.target_address.u32[3] = byteorder_htonl(0x00001234);
    
    /* some unique ID */
    opt_rreq.identification = 12345;
    
    /* total size is all plus 2 additional addresses */
    dsr_hdr.payload_length = sizeof(opt_rreq) + (16);
    
    print_dsr_head(&dsr_hdr);
    print_dsr_opt_rreq(&opt_rreq);
    
    uint32_t* as_number; 
    as_number = (uint32_t*)(&dsr_hdr);
    printf("%x\n", *as_number);

    ipv6_addr_t hop1;// = IPV6_ADDR_UNSPECIFIED; // 0
    hop1.u32[0] = byteorder_htonl(0x20020000);
    hop1.u32[1] = byteorder_htonl(0x0);
    hop1.u32[2] = byteorder_htonl(0x0);
    hop1.u32[3] = byteorder_htonl(0x2222);
    ipv6_addr_t hop2;// = IPV6_ADDR_LOOPBACK; // 1
    hop2.u32[0] = byteorder_htonl(0x20030000);
    hop2.u32[1] = byteorder_htonl(0x0);
    hop2.u32[2] = byteorder_htonl(0x0);
    hop2.u32[3] = byteorder_htonl(0x3333);

    gnrc_pktsnip_t *tmp_data;
    tmp_data = gnrc_pktbuf_add(NULL, &hop2.u8[0], sizeof(ipv6_addr_t), GNRC_NETTYPE_UNDEF);
    tmp_data = gnrc_pktbuf_add(tmp_data, &hop1.u8[0], sizeof(ipv6_addr_t), GNRC_NETTYPE_UNDEF);
    tmp_data = gnrc_pktbuf_add(tmp_data, (uint8_t*)&opt_rreq, sizeof(opt_rreq), GNRC_NETTYPE_UNDEF);
    tmp_data = gnrc_pktbuf_add(tmp_data, (uint8_t*)&dsr_hdr, sizeof(dsr_hdr), GNRC_NETTYPE_UNDEF);
    
    //_receive(tmp_data);
    /* set the IP fields 
     * Source Address: The originator.
     *                 on initial its me, when forwarding its someone else
     * Destination Address: Limited broadcast (in IPv4 255.255.255.255)
     *                      so we use ff02::1 (IPV6_ADDR_ALL_NODES_LINK_LOCAL)
     */
    ipv6_addr_t all_nodes = IPV6_ADDR_ALL_NODES_LINK_LOCAL, ll_addr;
    kernel_pid_t iface = gnrc_ipv6_netif_find_by_addr(NULL, &all_nodes);
    ipv6_addr_set_link_local_prefix(&ll_addr);
    ipv6_addr_t* src = gnrc_ipv6_netif_match_prefix(iface, &ll_addr);

    if (src == NULL) {
        DEBUG("DSR: no suitable src address found\n");
        return;
    }
    
    uint8_t port[2];
    uint16_t tmp_port = 4711;
    port[0] = (uint8_t)tmp_port;
    port[1] = tmp_port >> 8;
    
    gnrc_pktsnip_t *udp, *ip;
    /*
    gnrc_pktsnip_t *payload
    // allocate payload 
    payload = gnrc_pktbuf_add(tmp_data, data, strlen(data), GNRC_NETTYPE_UNDEF);
    if (payload == NULL) {
        DEBUG("Error: unable to copy data to packet buffer");
        return;
    }
    * */
    /* allocate UDP header, set source port := destination port */
    udp = gnrc_udp_hdr_build(tmp_data, port, 2, port, 2);
    //_receive(udp);
    if (udp == NULL) {
        DEBUG("Error: unable to allocate UDP header");
        gnrc_pktbuf_release(tmp_data);
        return;
    }
    /* allocate IPv6 header */
    ip = gnrc_ipv6_hdr_build(udp, (uint8_t *)src, sizeof(ipv6_addr_t), 
                             (uint8_t *)&all_nodes, sizeof(ipv6_addr_t));
    if (ip == NULL) {
        DEBUG("Error: unable to allocate IPv6 header");
        gnrc_pktbuf_release(udp);
        return;
    }
    /* send packet */
    if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP, GNRC_NETREG_DEMUX_CTX_ALL, ip)) {
        DEBUG("Error: unable to locate UDP thread");
        gnrc_pktbuf_release(ip);
        return;
    }
    puts("dsr_construct_opt_rreq end.");
}

/**
 * @}
 */
