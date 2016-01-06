/*
 * Copyright (C) 2016
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @addtogroup  unittests
 * @{
 *
 * @file
 * @brief       Test native xtimer
 *
 * @author
 */
#ifndef TESTS_XTIMER_H_
#define TESTS_XTIMER_H_

#include "embUnit.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   The entry point of this test suite.
 */
void tests_xtimer(void);

/**
 * @brief   Generates tests for timex
 *
 * @return  embUnit tests if successful, NULL if not.
 */
Test *tests_xtimer_tests(void);

#ifdef __cplusplus
}
#endif

#endif /* TESTS_XTIMER_H_ */
/** @} */
