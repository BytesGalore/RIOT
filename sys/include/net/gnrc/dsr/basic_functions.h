/*
 * Copyright (C) 2015 Martin Landsmann <martin.landsmann@haw-hamburg.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup net_gnrc_dsr
 * @{
 *
 * @file
 * @brief       DSR basic functions
 *
 * Header file defining basic functions of DSR
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef GNRC_DSR_BASIC_FUNCTIONS_H_
#define GNRC_DSR_BASIC_FUNCTIONS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "kernel.h"

//#include "net/gnrc/dsr.h" // not present yet

void dsr_construct_opt_rreq( void );

void dsr_start_listener(void);
/*
void dsr_construct_opt();

void dsr_send_rreq();

void dsr_send_rrep();
*/
#ifdef __cplusplus
}
#endif

#endif /* GNRC_DSR_DATA_TYPES_H_ */
/**
 * @}
 */
