/*
 * Copyright (C) 2016 Oliver Hahm <oliver.hahm@inria.fr>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     unittests
 * @{
 *
 * @file
 * @brief       Test cases for the SHA-1 hash implementation
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>

#include "embUnit/embUnit.h"

#include "hashes/sha1.h"

#define TEST_CASES_NUM      (4)
/*
 *  *  Define patterns for testing
 *   */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b

static char *_testarray[TEST_CASES_NUM] =
{
    TEST1,
    TEST2,
    TEST3,
    TEST4
};

static long int _repeatcount[TEST_CASES_NUM] = { 1, 1, 1000000, 10 };

static char *_resultarray[TEST_CASES_NUM] =
{
    "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
    "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
    "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
    "DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"
};


static int calc_and_compare_hash(const char *str, const char *expected,
                                 long int repeatcount)
{
    sha1_context ctx;

    uint8_t *hash;
    char tmp[(3 * SHA1_DIGEST_LENGTH) + 1];

    /* calculate hash */
    sha1_init(&ctx);
    for (long int i = 0; i < repeatcount; ++i) {
        sha1_update(&ctx, (unsigned char*) str, strlen(str));
    }
    hash = sha1_final(&ctx);
    /* copy hash to string */
    for (size_t i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        sprintf(&(tmp[i * 3]), "%02X ", (unsigned) hash[i]);
    }
    tmp[SHA1_DIGEST_LENGTH* 2] = '\0';
    /* compare with result string */
    return strncmp(tmp, expected, strlen((char*) tmp));
}

/* test cases copied from section 7.3 of RFC 3174
 * https://tools.ietf.org/html/rfc3174#section-7.3
 */
static void test_hashes_sha1(void)
{
    TEST_ASSERT(calc_and_compare_hash(_testarray[0], _resultarray[0], _repeatcount[0]) == 0);
    TEST_ASSERT(calc_and_compare_hash(_testarray[1], _resultarray[1], _repeatcount[1]) == 0);
    TEST_ASSERT(calc_and_compare_hash(_testarray[2], _resultarray[2], _repeatcount[2]) == 0);
    TEST_ASSERT(calc_and_compare_hash(_testarray[3], _resultarray[3], _repeatcount[3]) == 0);
}

Test *tests_hashes_sha1_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_hashes_sha1),
    };

    EMB_UNIT_TESTCALLER(test_hashes_sha1, NULL, NULL, fixtures);

    return (Test *)&test_hashes_sha1;
}
