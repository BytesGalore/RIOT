/*
 * Copyright (C) 2017 
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    rpl_watchdog_identification
 * @ingroup     rpl_watchdog
 * @brief       The RPL watchdog identification component
 * @{
 *
 * @file
 * @brief       Definition of the RPL watchdog identification component
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef NET_RPL_WATCHDOG_IDNETIFICATION_H
#define NET_RPL_WATCHDOG_IDNETIFICATION_H

#include "rpl_wd_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Apply filters on a DIS.
 *
 * @param[in] dis       Pointer to the DIS message.
 * @param[in] len       Length of the IPv6 packet.
 */
void rpl_wd_process_DIS(gnrc_rpl_dis_t *dis, uint16_t len);

/**
 * @brief   Apply filters on a DIO.
 *
 * @param[in] dio       Pointer to the DIO message.
 * @param[in] len       Length of the IPv6 packet.
 */
void rpl_wd_process_DIO(gnrc_rpl_dio_t *dio, uint16_t len);

/**
 * @brief   Apply filters on a DAO.
 *
 * @param[in] dao       Pointer to the DAO message.
 * @param[in] len       Length of the IPv6 packet.
 */
void rpl_wd_process_DAO(gnrc_rpl_dao_t *dao, uint16_t len);

/**
 * @brief   Apply filters on a DAO-ACK.
 *
 * @param[in] dao_ack   Pointer to the DAO-ACK message.
 * @param[in] len       Length of the IPv6 packet.
 */
void rpl_wd_process_DAO_ACK(gnrc_rpl_dao_ack_t *dao_ack, uint16_t len);

#ifdef MODULE_GNRC_RPL_P2P
/**
 * @brief   Apply filters on a DRO control message
 *
 * @param[in] pkt       The DRO pktsnip to parse.
 * @param[in] src       The source address of the IPv6 packet.
 */
void rpl_wd_process_DRO(gnrc_pktsnip_t *pkt, ipv6_addr_t *src);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NET_RPL_WATCHDOG_IDNETIFICATION_H */
/** @} */
