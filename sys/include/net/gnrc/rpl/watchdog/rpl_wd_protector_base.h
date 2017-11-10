/*
 * Copyright (C) 2017 
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    rpl_watchdog_protector_base
 * @ingroup     rpl_watchdog_protectors
 * @brief       The RPL watchdog protector base
 * @{
 *
 * @file
 * @brief       Definition of the RPL watchdog protector base
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef NET_RPL_WATCHDOG_PROTECTOR_BASE_H
#define NET_RPL_WATCHDOG_PROTECTOR_BASE_H

#include "rpl_wd_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RPL_WD_MAX_PROTECTORS_COUNT
#define RPL_WD_MAX_PROTECTORS_COUNT (5)
#endif

typedef struct {
    int (*init)(void);
    void (*gethandled)(uint8_t* handled)
    bool (*is_matching)(void);
    int (*apply)(uint8_t* result);
}stProtector_t;

int add_protector(stProtector_t* rule);
int del_protector(stProtector_t* rule);

stProtector_t* get_next_protector(stProtector_t* protector);

void init_protectors(void);

#ifdef __cplusplus
}
#endif

#endif /* NET_RPL_WATCHDOG_PROTECTOR_BASE_H */
/** @} */
