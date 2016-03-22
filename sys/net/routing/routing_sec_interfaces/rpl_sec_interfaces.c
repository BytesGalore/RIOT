/*
 * Copyright (C) 2016 Martin Landsmann <Martin.Landsmann@HAW-Hamburg.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup rpl_sec_interfaces
 * @{
 * @file
 * @brief   Functions to hook rpl security interfaces
 *
 * @author  Martin Landsmann <Martin.Landsmann@HAW-Hamburg.de>
 * @}
 *
 */

#include <stdio.h>
#include <string.h>
#include "rpl_sec_interfaces.h"

/**
 * @brief internal data type to store callbacks with their associated prefixes
 */
typedef struct {
    /** prefix the callback belongs to, e.g. 2001::abcd */
    ipv6_addr_t prefix;
    /** prefix length in bits, e.g. 32: 2001::abcd/32 i.e. 2001:0000::/32 */
    size_t prefix_len;
    /** the callback function associated with the prefix */
    rpl_sec_if_dio_cb cb;
} sec_parent_check_t;

/** the list of registered DIO callbacks */
static sec_parent_check_t rpl_sec_if_dio_callbacks[RPL_SEC_IF_NUMBER_OF_DIO_CB];

void rpl_sec_if_init(void)
{
    for (size_t i = 0; i < RPL_SEC_IF_NUMBER_OF_DIO_CB; ++i) {
        memset((void*)&rpl_sec_if_dio_callbacks[i].prefix, 0x00, sizeof(ipv6_addr_t));
        rpl_sec_if_dio_callbacks[i].prefix_len = 0;
        rpl_sec_if_dio_callbacks[i].cb = NULL;
    }
    puts("rpl_sec_if: module loaded.");
}

int rpl_sec_if_register_dio_cb(rpl_sec_if_dio_cb cb, ipv6_addr_t prefix, size_t prefix_len)
{
    puts("rpl_sec_if_register_dio_cb called.");
    for (size_t i = 0; i < RPL_SEC_IF_NUMBER_OF_DIO_CB; ++i) {
        if (rpl_sec_if_dio_callbacks[i].cb == NULL) {
            rpl_sec_if_dio_callbacks[i].prefix = prefix;
            rpl_sec_if_dio_callbacks[i].prefix_len = prefix_len;
            rpl_sec_if_dio_callbacks[i].cb = cb;
            return RPL_SEC_IF_SUCCESS;
        }
    }
    return RPL_SEC_IF_ERROR_REGISTER_CB_FAILED;
}

int rpl_sec_if_unregister_dio_cb(rpl_sec_if_dio_cb cb)
{
    puts("rpl_sec_if_unregister_dio_cb called.");
    for (size_t i = 0; i < RPL_SEC_IF_NUMBER_OF_DIO_CB; ++i) {
        if (rpl_sec_if_dio_callbacks[i].cb == cb) {
            memset((void*)&rpl_sec_if_dio_callbacks[i].prefix, 0x00, sizeof(ipv6_addr_t));
            rpl_sec_if_dio_callbacks[i].prefix_len = 0;
            rpl_sec_if_dio_callbacks[i].cb = NULL;
            return RPL_SEC_IF_SUCCESS;
        }
    }
    return RPL_SEC_IF_ERROR_UNREGISTER_CB_FAILED;
}

bool rpl_sec_if_verify_dio_parent(gnrc_rpl_dio_t *dio, ipv6_addr_t *src, uint16_t len, uint16_t own_rank)
{
    puts("rpl_sec_if_verify_dio_parent called.");

    size_t prefix_match = 0;
    int pos = -1;
    for (size_t i = 0; i < RPL_SEC_IF_NUMBER_OF_DIO_CB; ++i) {
        if(rpl_sec_if_dio_callbacks[i].cb != NULL) {
            size_t match_len = ipv6_addr_match_prefix(&rpl_sec_if_dio_callbacks[i].prefix, &dio->dodag_id);
            /* if the dio->dodag_id matches the associated prefix, we have a candidate */
            if((match_len >= rpl_sec_if_dio_callbacks[i].prefix_len) && (match_len > prefix_match)) {
                prefix_match = match_len;
                pos = i;
            }
        }
    }
    /* we call our best matching candidate */
    if (pos >= 0) {
        /* return if the security module decided if the parameters are verified
         * Note: the granularity of decision can be extended
         *       using additional return values and dispatching them, e.g. here.
         */
        return (rpl_sec_if_dio_callbacks[pos].cb(dio, src, len, own_rank) == RPL_SEC_IF_SUCCESS);
    }

    /* since no callback-prefix matched the dio->dodag_id,
     * the DODAG is unmanaged/unprotected and handled with the set default behaviour.
     */
    return (RPL_SEC_IF_VERIFIED_BY_DEFAULT != 0);
}

