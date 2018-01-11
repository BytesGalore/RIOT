/*
 * Copyright (C) 2017 
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    rpl_watchdog
 * @ingroup     rpl_watchdog
 * @brief       The RPL watchdog
 * @{
 *
 * @file
 * @brief       Definition of the RPL watchdog component
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef NET_RPL_WATCHDOG_H
#define NET_RPL_WATCHDOG_H

#include "rpl_wd_identification.h"
#include "rpl_wd_protectors.h"
#include "rpl_wd_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Default stack size to use for the RPL watchdog thread
 */
#define GNRC_RPL_WATCHDOG_STACK_SIZE     (THREAD_STACKSIZE_DEFAULT>>1)

/**
 * @brief   Default priority for the RPL watchdog thread
 */
#ifndef GNRC_RPL_WATCHDOG_PRIO
#define GNRC_RPL_WATCHDOG_PRIO           (GNRC_IPV6_PRIO + 1)
#endif

/**
 * @brief   Default message queue size to use for the RPL watchdog thread.
 */
#ifndef GNRC_RPL_WATCHDOG_MSG_QUEUE_SIZE
#define GNRC_RPL_WATCHDOG_MSG_QUEUE_SIZE (GNRC_RPL_MSG_QUEUE_SIZE)
#endif

/**
 * @brief Initialization of the RPL watchdog thread.
 *
 * @param[in] rpl_pid            PID of the RPL thread
 *
 * @return  The PID of the RPL watchdog thread.
 */
kernel_pid_t rpl_watchdog_init(kernel_pid_t rpl_pid);

#ifdef __cplusplus
}
#endif

#endif /* NET_RPL_WATCHDOG_H */
/** @} */
