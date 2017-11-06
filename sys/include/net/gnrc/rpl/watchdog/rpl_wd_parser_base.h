/*
 * Copyright (C) 2017 
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    rpl_watchdog_parser_base
 * @ingroup     rpl_watchdog_identification
 * @brief       The RPL watchdog filter base
 * @{
 *
 * @file
 * @brief       Definition of the RPL watchdog filter base
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef NET_RPL_WATCHDOG_PARSER_BASE_H
#define NET_RPL_WATCHDOG_PARSER_BASE_H

#include "rpl_wd_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RPL_WD_MAX_RULES_COUNT
#define RPL_WD_MAX_RULES_COUNT (5)
#endif



typedef struct stFilter_t {
    uint16_t code;
    union {
        int (*apply_dis)(gnrc_rpl_dis_t *pkt);
        int (*apply_dio)(gnrc_rpl_dio_t *pkt);
        int (*apply_dao)(gnrc_rpl_dao_t *pkt);
        int (*apply_dao_ack)(gnrc_rpl_dao_ack_t *pkt);
    } func;
}stRule;



int add_rule(stRule* rule);
int del_rule(stRule* rule);

stRule* get_next_typed_rule(uint16_t type, stRule* rule);
stRule* get_next_rule(stRule* rule);

void init_rules(void);


#ifdef __cplusplus
}
#endif

#endif /* NET_RPL_WATCHDOG_PARSER_BASE_H */
/** @} */
