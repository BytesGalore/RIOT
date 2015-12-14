/*
 * Copyright (C) 2015 Martin Landsmann <Martin.Landsmann@HAW-Hamburg.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "embUnit/embUnit.h"

#include "crypto/sha512.h"

#include "tests-crypto.h"

static int calc_and_compare_hash(const char *str, const char *expected)
{
    static unsigned char hash[SHA512_DIGEST_LENGTH];
    sha512_context_t sha512;
    sha512_init(&sha512);
    sha512_update(&sha512, str, strlen(str));
    sha512_final(hash, &sha512);

    return strncmp((const char *) hash, expected, SHA512_DIGEST_LENGTH);
}

static void test_crypto_sha512_hash_sequence(void)
{
    /*
    TEST_ASSERT(calc_and_compare_hash("1234567890_1",
                 "3eda9ffe5537a588f54d0b2a453e5fa932986d0bc0f9556924f5c2379b2c91b0"));
    TEST_ASSERT(calc_and_compare_hash("1234567890_2",
                 "a144d0b4d285260ebbbab6840baceaa09eab3e157443c9458de764b7262c8ace"));
    TEST_ASSERT(calc_and_compare_hash("1234567890_3",
                 "9f839169d293276d1b799707d2171ac1fd5b78d0f3bc7693dbed831524dd2d77"));
    TEST_ASSERT(calc_and_compare_hash("1234567890_4",
                 "6c5fe2a8e3de58a5e5ac061031a8e802ae1fb9e7197862ec1aedf236f0e23475"));
    TEST_ASSERT(calc_and_compare_hash(
                 "0123456789abcde-0123456789abcde-0123456789abcde-0123456789abcde-",
                 "945ab9d52b069923680c2c067fa6092cbbd9234cf7a38628f3033b2d54d3d3bf"));
                 */
    TEST_ASSERT(calc_and_compare_hash(
                 "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern",
                 "af9ed2de700433b803240a552b41b5a472a6ef3fe1431a722b2063c75e9f07451f67a28e37d09cde769424c96aea6f8971389db9e1993d6c565c3c71b855723c"));
    TEST_ASSERT(calc_and_compare_hash(
                 "Frank jagt im komplett verwahrlosten Taxi quer durch Bayern",
                 "90b30ef9902ae4c4c691d2d78c2f8fa0aa785afbc5545286b310f68e91dd2299c84a2484f0419fc5eaa7de598940799e1091c4948926ae1c9488dddae180bb80"));
    TEST_ASSERT(calc_and_compare_hash("",
                 "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
}

Test *tests_crypto_sha512_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
    new_TestFixture(test_crypto_sha512_hash_sequence),
};

EMB_UNIT_TESTCALLER(crypto_sha512_tests, NULL, NULL,
        fixtures);

return (Test *)&crypto_sha512_tests;
}
