/*
 * Copyright (C) 2017 
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    rpl_watchdog_result
 * @ingroup     rpl_watchdog
 * @brief       The RPL watchdog result component
 * @{
 *
 * @file
 * @brief       Definition of the RPL watchdog result component
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef NET_RPL_WATCHDOG_RESULT_H
#define NET_RPL_WATCHDOG_RESULT_H

#include "net/gnrc/rpl.h"

#ifdef __cplusplus
extern "C" {
#endif

extern ipv6_addr_t *current_pkt_sender;
extern kernel_pid_t current_incoming_iface;
extern ipv6_addr_t *current_pkt_dst;

typedef enum EBitCodes_t{
    eInvert = 0,
    eDIOpkt,
    eDISpkt,
    eDAOpkt,
    eDAOACKpkt,
    eHBHOption,

    eTrickleReset,
    eParentSetPrune,
    eParentAdd,
    eParentDel,
    ePreferedParentExchange,

    eNodeErrorCountCreate,
    eNodeErrorCountUp,

    eRankRise,
    eRankLower,

    eDODAGVersionRaise,
    eRPLInstanceAdd,
    eRPLMyInstance,

    eDAOParentAdd,
    eDAOParentDel,
    eDAOParentsDrop,
    eDTSNRaise,


    eDISUnicast,
    eDISIsMyDODAG,

    eDAORouteAdd,

    eSendDAO,
    eSendDIO,
    eSendDIS,
    eSendDAOACK,

    eENTRYCOUNT
}EBitCodes;

#if (((eENTRYCOUNT+1)>>64) > 0)
typedef uint64_t rpl_watchdog_result_t;
#elif (((eENTRYCOUNT+1)>>32) > 0)
typedef uint32_t rpl_watchdog_result_t;
#elif (((eENTRYCOUNT+1)>>16) > 0)
typedef uint16_t rpl_watchdog_result_t;
#else
typedef uint8_t rpl_watchdog_result_t;
#endif

extern rpl_watchdog_result_t rpl_wd_result_field;

#ifdef __cplusplus
}
#endif

#endif /* NET_RPL_WATCHDOG_RESULT_H */
/** @} */
