/*
 * Copyright (C) 2017 
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    rpl_watchdog_rule_base
 * @ingroup     rpl_watchdog_parser_base
 * @brief       The RPL watchdog rule base
 * @{
 *
 * @file
 * @brief       Interface definition of the RPL watchdog identification rules
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef NET_RPL_WATCHDOG_RULE_BASE_H
#define NET_RPL_WATCHDOG_RULE_BASE_H

#include "rpl_wd_result.h"

#ifdef __cplusplus
extern "C" {
#endif

int register_rules(void);

#ifdef __cplusplus
}
#endif

#endif /* NET_RPL_WATCHDOG_RULE_BASE_H */
/** @} */
