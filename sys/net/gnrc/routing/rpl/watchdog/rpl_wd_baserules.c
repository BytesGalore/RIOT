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

#include "net/gnrc/rpl/watchdog/rpl_wd_parser_base.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static stRule dio_rule = { GNRC_RPL_ICMPV6_CODE_DIO, {NULL} };
static stRule dis_rule = { GNRC_RPL_ICMPV6_CODE_DIS, {NULL} };
static stRule dao_rule = { GNRC_RPL_ICMPV6_CODE_DAO, {NULL} };
static stRule daoACK_rule = { GNRC_RPL_ICMPV6_CODE_DAO_ACK, {NULL} };

int parse_dio(gnrc_rpl_dio_t* dio)
{
    rpl_wd_result_field |= (1 << eDIOpkt);
    
    for (uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
         if (gnrc_rpl_instances[i].state != 0) {
            if (gnrc_rpl_instances[i].id == dio->instance_id)
            {
                rpl_wd_result_field |= (1 << eRPLMyInstance);
                if (ipv6_addr_equal(&(dio->dodag_id), &(gnrc_rpl_instances[i].dodag.dodag_id)))
                {
                    // DODAG Version Number
                    if (GNRC_RPL_COUNTER_GREATER_THAN(dio->version_number, gnrc_rpl_instances[i].dodag.version)) {
                        rpl_wd_result_field |= (1 << eDODAGVersionRaise); 
                    }

                    // Rank in DODAG
                    if (gnrc_rpl_instances[i].dodag.parents[0].rank > byteorder_ntohs(dio->rank)) {
                        rpl_wd_result_field |= (1 << eRankRise);
                        rpl_wd_result_field |= (1 << ePreferedParentExchange);
                    }

                    // dtsn
                    gnrc_rpl_parent_t *elt, *tmp;
                    LL_FOREACH_SAFE(gnrc_rpl_instances[i].dodag.parents, elt, tmp) {
                        if (elt->dtsn > dio->dtsn) {
                            rpl_wd_result_field |= (1 << eDTSNRaise);
                        } else if (elt->dtsn < dio->dtsn) {
                            // provided DTSN is lower, i.e. inconsistent neighbour state
                            rpl_wd_result_field |= (1 << eTrickleReset);
                        }
                        
                        if (DAGRANK(gnrc_rpl_instances[i].dodag.my_rank, gnrc_rpl_instances[i].min_hop_rank_inc)
                        <= DAGRANK(elt->rank, gnrc_rpl_instances[i].min_hop_rank_inc)) {
                            rpl_wd_result_field |= (1 << eParentDel);
                        }
                    }
                }
            }
            else {
                rpl_wd_result_field |= (1 << eRPLInstanceAdd);
            }
        }
    }
    return 0;
}

int parse_dis(gnrc_rpl_dis_t* dis)
{
    (void)dis;
    rpl_wd_result_field |= (1 << eDISpkt);

    if (ipv6_addr_is_multicast(current_pkt_dst)) {
        
        //dis->dodag_id
    }
    else {
        rpl_wd_result_field |= (1 << eDISUnicast);
    }
    /*
    
// 
    
    rpl_wd_result_field;
    
    dio->instance_id;
    dio->

    for (uint8_t i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
            if ((gnrc_rpl_instances[i].state != 0)
                // a leaf node should only react to unicast DIS 
                 && (gnrc_rpl_instances[i].dodag.node_status != GNRC_RPL_LEAF_NODE)) {
#ifdef MODULE_GNRC_RPL_P2P
            if (gnrc_rpl_instances[i].mop == GNRC_RPL_P2P_MOP) {
                DEBUG("RPL: Not responding to DIS for P2P-RPL DODAG\n");
                continue;
            }
#endif
            trickle_reset_timer(&(gnrc_rpl_instances[i].dodag.trickle));
        }
    }
    */
    return 0;
}

int parse_dao(gnrc_rpl_dao_t* dao)
{
    (void)dao;
    rpl_wd_result_field |= (1 << eDAOpkt);
    return 0;
}

int parse_dao_ack(gnrc_rpl_dao_ack_t* dao_ack)
{
    (void)dao_ack;
    rpl_wd_result_field |= (1 << eDAOACKpkt);
    return 0;
}

int register_rules(void)
{
    dio_rule.code = GNRC_RPL_ICMPV6_CODE_DIO;
    dio_rule.func.apply_dio = parse_dio;
    add_rule(&dio_rule);

    dis_rule.code = GNRC_RPL_ICMPV6_CODE_DIS;
    dis_rule.func.apply_dis = parse_dis;
    add_rule(&dis_rule);

    dao_rule.code = GNRC_RPL_ICMPV6_CODE_DAO;
    dao_rule.func.apply_dao = parse_dao;
    add_rule(&dao_rule);
       
    daoACK_rule.code = GNRC_RPL_ICMPV6_CODE_DAO_ACK;
    daoACK_rule.func.apply_dao_ack = parse_dao_ack;
    add_rule(&daoACK_rule);

    return 0;
}
