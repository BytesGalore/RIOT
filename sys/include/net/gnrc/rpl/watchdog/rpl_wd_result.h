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

typedef enum {
    eInvert = 0,
    eDIOpkt,
    eDISpkt,
    eDAOpkt,
    eDAOACKpkt,
    eHBHOption,

    eTrickleReset,
    eTrickleUpdateLifetimes,
    eTrickleCallback,
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

extern const uint8_t rpl_wd_field_size;
extern uint8_t* rpl_wd_idientification_field;

static inline void setbit(EBitCodes code, uint8_t* filed)
{
    filed[(code/8)] |= 1<<(code % 8);
}

static inline void clearbit(EBitCodes code, uint8_t* filed)
{
    filed[(code/8)] &= ~(1<<(code % 8));
}

static inline bool getbit(EBitCodes code, uint8_t* filed)
{
    return ((filed[(code/8)] & 1<<(code % 8)) != 0);
}

static inline void setIdentificationBit(EBitCodes code)
{
    setbit(code, rpl_wd_idientification_field);
}

static inline bool getIdentificationBit(EBitCodes code)
{
    return getbit(code, rpl_wd_idientification_field);
}

#ifdef __cplusplus
}
#endif

#endif /* NET_RPL_WATCHDOG_RESULT_H */
/** @} */
