/*
 * Copyright (C) 2016
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>
#include "tests-xtimer.h"

#include "xtimer.h"

#define TEST_XTIMER_ENTRIES (20)
static uint64_t _entries[TEST_XTIMER_ENTRIES];

static void test_xtimer_native(void)
{
    /* reset all to 0 */
    for (size_t i = 0; i < TEST_XTIMER_ENTRIES; ++i) {
        _entries[i] = 0;
    }

    for (size_t j = 0; j < TEST_XTIMER_ENTRIES; ++j) {
        
        uint64_t now = xtimer_now64();
        _entries[j] = now;

        /* just burn some time pass */
        for (size_t i = 0; i < TEST_XTIMER_ENTRIES; ++i) {
            uint64_t a_bit_later = xtimer_now64();
            
            /* arbitrary value set to 3 times */
            if ( (3*_entries[i]) < a_bit_later ) 
            {
                printf("_entries[%d]: %"PRIu64", a_bit_later: %"PRIu64"\n", 
                i, _entries[i], a_bit_later);
            }
        }
    }
    /* always fail, since this is only a helper */
    TEST_ASSERT(false);
}

Test *tests_xtimer_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_xtimer_native),
    };

    EMB_UNIT_TESTCALLER(tests_xtimer_tests, NULL, NULL, fixtures);

    return (Test *)&tests_xtimer_tests;
}

void tests_xtimer(void)
{
    TESTS_RUN(tests_xtimer_tests());
}
