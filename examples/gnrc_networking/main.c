/*
 * Copyright (C) 2015 Freie Universität Berlin
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
 * @brief       Example application for demonstrating the RIOT network stack
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>

#include "shell.h"
#include "msg.h"

#ifdef MODULE_ROUTING_SEC_INTERFACES
#include "rpl_sec_interfaces.h"
#endif

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int udp_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "udp", "send data over UDP and listen on UDP ports", udp_cmd },
    { NULL, NULL, NULL }
};

#ifdef MODULE_ROUTING_SEC_INTERFACES
static int rpl_sec_dio(gnrc_rpl_dio_t *dio, ipv6_addr_t *src, uint16_t len, uint16_t own_rank)
{
    (void)dio;
    (void)src;
    (void)len;
    (void)own_rank;
    puts("rpl_sec_dio called.");

    return RPL_SEC_IF_VERIFICATION_FAILED;
}
#endif

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("RIOT network stack example application");

#ifdef MODULE_ROUTING_SEC_INTERFACES
    rpl_sec_if_init();
    ipv6_addr_t prefix = IPV6_ADDR_UNSPECIFIED;
    ipv6_addr_from_str(&prefix, "2001::abcd");

    /* add a 2001::abcd/32 prefix, i.e. 2001:0000::/32 */
    rpl_sec_if_register_dio_cb(rpl_sec_dio, prefix, 32);
#endif

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
