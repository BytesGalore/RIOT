/*
 * Copyright (C) 2017
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 *
 * @author  martin.landsmann@haw-hamburg.de
 */

#include "net/gnrc/rpl/watchdog/rpl_wd_identification.h"
#include "net/gnrc/rpl/watchdog/rpl_wd_parser_base.h"
#include "../gnrc_rpl_internal/validation.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"


void rpl_wd_process_DIS(gnrc_rpl_dis_t *dis, uint16_t len)
{
    if (!gnrc_rpl_validation_DIS(dis, len)) {
        return;
    }

    stRule* rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DIS, NULL);
    while (rule)
    {
        rule->func.apply_dis(dis);
        rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DIS, rule);
    }
}

void rpl_wd_process_DIO(gnrc_rpl_dio_t *dio, uint16_t len)
{
    if (!gnrc_rpl_validation_DIO(dio, len)) {
        return;
    }

    stRule* rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DIO, NULL);
    while (rule)
    {
        rule->func.apply_dio(dio);
        rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DIO, rule);
    }
}

void rpl_wd_process_DAO(gnrc_rpl_dao_t *dao, uint16_t len)
{
    if (!gnrc_rpl_validation_DAO(dao, len)) {
        return;
    }

    stRule* rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DAO, NULL);
    while (rule)
    {
        rule->func.apply_dao(dao);
        rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DAO, rule);
    }
}

void rpl_wd_process_DAO_ACK(gnrc_rpl_dao_ack_t *dao_ack, uint16_t len)
{
    if (!gnrc_rpl_validation_DAO_ACK(dao_ack, len, current_pkt_dst)) {
        return;
    }

    stRule* rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DAO_ACK, NULL);
    while (rule)
    {
        rule->func.apply_dao_ack(dao_ack);
        rule = get_next_typed_rule(GNRC_RPL_ICMPV6_CODE_DAO_ACK, rule);
    }
}

#ifdef MODULE_GNRC_RPL_P2P
void rpl_wd_process_DRO(gnrc_pktsnip_t *pkt)
{
}
#endif
