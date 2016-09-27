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
    TEST_ASSERT(calc_and_compare_hash("1234567890_1",
                 "0f3e840daba378160173034567d6fa7373056634834c7127399871f6175ff9f5c09cb0d1af35679de6b5893ab7c800a46f121821414f4cf11c27e67630e10e99"));
    TEST_ASSERT(calc_and_compare_hash("1234567890_2",
                 "448e45902091177d01a402e1d31d0852899c48eaa2b331868b91afbec39a2a3413145f565336004055bbc05cfdc862732bf002bf90bc3f941ed7f6bcbc19bdc9"));
    TEST_ASSERT(calc_and_compare_hash("1234567890_3",
                 "bc92bfae4d2b2e40371e543e0b70033ca1d308e01452fcc5678ac7b20b254b09159290166e5c1f4012d5295e2057dc202a4c42bf7d4cb7229f28c5bcf18e655f"));
    TEST_ASSERT(calc_and_compare_hash("1234567890_4",
                 "e9a43cf81972a22e85f1dca0b3be0b71f07ef30778ddf0eb5ae40e6d9ff1927db1d53c717f0cf43f1d99cfe360170a0a5885d2a85ac498be4f12405da4a8c79d"));
    TEST_ASSERT(calc_and_compare_hash(
                 "0123456789abcde-0123456789abcde-0123456789abcde-0123456789abcde-",
                 "f380afeb63f7d64018d89836c766a18f3cde99047a7fe183326d101ca9d9d4f9a5f03d77b6d542c66bcc9f46c766fe59a6a7dab300237b031a38600f463bb329"));
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
