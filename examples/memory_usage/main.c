/*
 * Copyright (C) 2015
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Memory usage application
 *
 * @author
 *
 * @}
 */

#include <stdio.h>
#include "udp.h"
#include "ps.h"
#include "hwtimer.h"

#define CHANNEL         (26)     /**< The used channel */
#define PAN             (0x03e9) /**< The used PAN ID */
#define IFACE           (0)      /**< The used Trasmssion device */
#define UDP_PORT        (12345)  /**< The UDP port to listen */
#define UDP_BUFFER_SIZE (1024)   /**< The buffer size for receiving UDPs */

#define WITH_UDP_SERVER (0) /**< Switch UDP server */

/** The node IPv6 address */
ipv6_addr_t myaddr;

mutex_t mtx_send = MUTEX_INIT;

#if (WITH_UDP_SERVER)
/** The UDP server thread stack */
char udp_server_stack_buffer[KERNEL_CONF_STACKSIZE_MAIN];
/**
* @brief the sample UDP server that expects receiving strings
* @param[in] arg unused parameter pointer
*/
static void *udp_server(void *arg)
{
    (void) arg;

    sockaddr6_t sa;
    char buffer_main[UDP_BUFFER_SIZE];
    uint32_t fromlen;
    int sock = socket_base_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    memset(&sa, 0, sizeof(sa));

    sa.sin6_family = AF_INET;
    sa.sin6_port = HTONS(UDP_PORT);

    fromlen = sizeof(sa);

    if (-1 == socket_base_bind(sock, &sa, sizeof(sa))) {
        puts("[udp_server] Error bind failed!");
        socket_base_close(sock);
        return NULL;
    }

    while (1) {
        int32_t recsize = socket_base_recvfrom(sock, (void *)buffer_main,
                                               UDP_BUFFER_SIZE, 0,
                                               &sa, &fromlen);

        if (recsize < 0) {
            puts("[udp_server] ERROR: recsize < 0!");
        } else {
            /* if we received a string print it */
            if (buffer_main[recsize-1] == '\0' ) {
                printf("UDP packet received, payload:\n%s\n", buffer_main);
            } else {
                /* print the buffer bytes in hex */
                printf("UDP packet received, payload (%d bytes):\n", (int)recsize);
                for(int i = 0; i < recsize; ++i) {

                    if ( (i%8) == 0 ) {
                        /* newline after 8 bytes */
                        puts("");
                    }

                    printf("%02x ", buffer_main[i]);
                }
                puts("");
            }
        }

    }

    socket_base_close(sock);

    return NULL;
}

/**
* @brief create a thread to receive UDP messages
*/
static void start_udp_server(void)
{
    thread_create(udp_server_stack_buffer,sizeof(udp_server_stack_buffer),
                  PRIORITY_MAIN, CREATE_STACKTEST, udp_server, NULL,
                  "udp_server");
}
#endif

/**
* @brief sends a packet to a destination address
* @param[in] dst the destination IPv6 address
* @param[in] payload pointer to the payload to be sent
* @param[in] size number of bytes of the payload
*/
static void udp_send(ipv6_addr_t* dst, char* payload, size_t payload_size)
{
    int sock;
    sockaddr6_t sa;
    int bytes_sent;
    sock = socket_base_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    //char addr_str[IPV6_MAX_ADDR_STR_LEN];

    if (-1 == sock) {
        puts("[udp_send] Error Creating Socket!");
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET;
    memcpy(&sa.sin6_addr, dst, 16);
    sa.sin6_port = HTONS(UDP_PORT);

    bytes_sent = socket_base_sendto(sock,
                                    payload,
                                    payload_size,
                                    0, &sa, sizeof(sa));

    if (bytes_sent < 0) {
        puts("[udp_send] Error sending packet!");
    } else {
        /*
            printf("[udp_send] Successful deliverd %i bytes over UDP to %s to 6LoWPAN\n",
                   bytes_sent, ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN,
                        &(sa.sin6_addr)));*/
            }

    socket_base_close(sock);
}

/**
* @brief setup the readio interface
* @retrun radio_address_t of the set interface
*/
static radio_address_t set_if(void)
{
    net_if_set_src_address_mode(IFACE, NET_IF_TRANS_ADDR_M_SHORT);
    radio_address_t iface_id = net_if_get_hardware_address(IFACE);
    return iface_id;
}

/**
* @brief set the channel for this node
* @param[in] chan the channel to use
* @return 0 on success
*/
static int set_channel(int32_t chan)
{
    transceiver_command_t tcmd;
    msg_t m;

    tcmd.transceivers = TRANSCEIVER_DEFAULT;
    tcmd.data = &chan;
    m.type = SET_CHANNEL;
    m.content.ptr = (void *) &tcmd;

    msg_send_receive(&m, &m, transceiver_pid);
    return 0;
}

/**
* @brief set the PAN ID for this node
* @param[in] pan the PAN ID to use
* @return 0 on success
*/
static int set_pan(int32_t pan)
{
    transceiver_command_t tcmd;
    msg_t m;

    tcmd.transceivers = TRANSCEIVER_DEFAULT;
    tcmd.data = &pan;
    m.type = SET_PAN;
    m.content.ptr = (void *) &tcmd;

    msg_send_receive(&m, &m, transceiver_pid);
    return 0;
}

/**
* @brief set a desire address for this node
* @return 0 on success
*/
static int set_address(ipv6_addr_t* node_addr)
{
    ipv6_net_if_add_addr(IFACE, node_addr, NDP_ADDR_STATE_PREFERRED, 0, 0, 0);
    return 0;
}

/**
* @brief prepares this node
* @return 0 on success
*/
static int setup_node(void)
{
    radio_address_t iface_id = 0xffff;

    set_channel(CHANNEL);
    set_pan(PAN);
    iface_id = set_if();

#if (WITH_UDP_SERVER)
    /* set a fixed  address for this node */
    ipv6_addr_init(&myaddr, 0x2015, 0x3, 0x18, 0x1111, 0x0, 0x0, 0x0, 0x99);
#else
    /* choose address */
    ipv6_addr_init(&myaddr, 0x2015, 0x3, 0x18, 0x1111, 0x0, 0x0, 0x0, iface_id);
#endif
    /* and set it */
    set_address(&myaddr);

    return 0;
}

/**
* @brief a dummy "Routing-Protocol" to provide a function pointer for get next-hop calls
*        in net/network_layer/sixlowpan/ip.c::~106
* @param[in] dest pointer to the requested destination address
* @return dest
*/
ipv6_addr_t *get_next_hop(ipv6_addr_t *dest) {
    return dest;
}

int main(void)
{puts("main:");
    ps();
    char addr_str[IPV6_MAX_ADDR_STR_LEN];
    puts("Hello!");

    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s MCU.\n", RIOT_MCU);


    setup_node();
    ipv6_iface_set_routing_provider(get_next_hop);

    printf("[main] My address is: %s\n",
            ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, &myaddr));

#if (WITH_UDP_SERVER)
    start_udp_server();
    (void) udp_send;
    /* nothing left to do */
    while(1){
        sleep(30);
    }
#else
    char payload[80];
    int msgnum = 0;

    /* choose a receiver address */
    ipv6_addr_t dst;
    ipv6_addr_init(&dst, 0x2015, 0x3, 0x18, 0x1111, 0x0, 0x0, 0x0, 0x99);

    //puts("main:");

    while(msgnum<10){
        msgnum++;
        printf("num: %d\n", msgnum);
        //sleep(30);
        //snprintf(payload, 80, "node(%x) msg: %d", HTONS(myaddr.uint16[7]), msgnum++);
        udp_send(&dst, payload, 40);
        //if(msgnum%100 == 0){printf("sent: %d\n", msgnum);}
        //hwtimer_wait(20000);
    }
#endif
    return 0;
}
