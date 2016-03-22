/*
 * Copyright (C) 2016 Martin Landsmann <Martin.Landsmann@HAW-Hamburg.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    rpl_sec_interfaces rpl security interfaces
 * @ingroup     sys
 * @brief       security interface definitions for RPL
 * @{
 *
 * @brief
 * @author      Martin Landsmann <Martin.Landsmann@HAW-Hamburg.de>
 */

#ifndef RPL_SECURITY_INTERFACES_H
#define RPL_SECURITY_INTERFACES_H

#include <stdint.h>
#include "net/gnrc/rpl.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief maximum number of dio protecting functions allowed to register
 */
#ifndef RPL_SEC_IF_NUMBER_OF_DIO_CB
/** the default number of callbacks is set to 1 */
#define RPL_SEC_IF_NUMBER_OF_DIO_CB (1)
#endif

/**
 * @brief set the verification behaviour on unmanaged DODAG IDs
 */
#ifndef RPL_SEC_IF_VERIFIED_BY_DEFAULT
/** the default behaviour is to NOT trust unmanaged DODAG IDs */
#define RPL_SEC_IF_VERIFIED_BY_DEFAULT (0)
#endif

/**
 * @brief return value of successful operation 
 */
#define RPL_SEC_IF_SUCCESS (0)

/**
 * @brief return value of failed callback registration
 */
#define RPL_SEC_IF_ERROR_REGISTER_CB_FAILED (-1)

/**
 * @brief return value of failed callback de-registration
 */
#define RPL_SEC_IF_ERROR_UNREGISTER_CB_FAILED (-2)

/**
 * @brief return value indicating the verification process was not successful
 */
#define RPL_SEC_IF_VERIFICATION_FAILED (-3)

/**
 * @brief callback prototype definition for DIO protection.
 *        The implementation is specific to the actual security module that
 *        provides this callback function.
 *
 * @param[in] dio pointer to the DIO structure received by RPL
 * @param[in] src the ipv6 address of the node that sent the DIO
 * @param[in] len the fulll size in bytes of the DIO
 * @param[in] own_rank the current set rank of this node
 *
 * @return RPL_SEC_IF_SUCCESS if the actual called security module decided
 *                            the given parameters are verified and the DIO
 *                            procesing in RPL may be safely continued.
 *
 * @return RPL_SEC_IF_VERIFICATION_FAILED if the actual security module decided
 *                                        the given parameters are not valid
 *                                        and the DIO should not be processed further.
 */
typedef int (*rpl_sec_if_dio_cb)(gnrc_rpl_dio_t *dio, ipv6_addr_t *src, uint16_t len, uint16_t own_rank);

/**
 * @brief initializes all members, i.e. sets all arrays to NULL
 */
void rpl_sec_if_init(void);

/**
 * @brief register a callback function being called on arriving DIOs
 *
 * @param[in] cb the function to be called as callback
 * @param[in] prefix the prefix this function belongs to,
 *            i.e. define which dio->dodag_id should be protected with this call
 * @param[in] prefix_len the number of significant bits used in the given prefix
 *
 * @return RPL_SEC_IF_SUCCESS if the callback has been succesfully registered
 * @return RPL_SEC_IF_ERROR_REGISTER_CB_FAILED if the callback could not be stored
 */
int rpl_sec_if_register_dio_cb(rpl_sec_if_dio_cb cb, ipv6_addr_t prefix, size_t prefix_len);

/**
 * @brief unregister a DIO callback function
 *
 * @param[in] cb the function to be removed from the list
 *
 * @return RPL_SEC_IF_SUCCESS if the callback has been removed
 * @return RPL_SEC_IF_ERROR_UNREGISTER_CB_FAILED if the callback was not present
 *                                               in the list of callbacks
 */
int rpl_sec_if_unregister_dio_cb(rpl_sec_if_dio_cb cb);

/**
 * @brief calls interfaced functions of the specific security module to perform verifications
 *        on arriving DIOs.
 *        The registered callback prefix with 'longest common prefix match' (LPM) is called
 *        with the given parameters.
 *
 * @param[in] dio pointer to the DIO structure received by RPL
 * @param[in] src the ipv6 address of the node that sent the DIO
 * @param[in] len the fulll size in bytes of the DIO
 * @param[in] own_rank the current set rank of this node
 *
 * @return true if the given parameters are succesfully verified.
 * @return false if the given parameters could not be succesfully verified.
 */
bool rpl_sec_if_verify_dio_parent(gnrc_rpl_dio_t *dio, ipv6_addr_t *src, uint16_t len, uint16_t own_rank);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* RPL_SECURITY_INTERFACES_H */
