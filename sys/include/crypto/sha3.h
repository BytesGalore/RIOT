/*-
 * Copyright 2015 
 * 
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
 */


/**
 * @ingroup     sys_crypto
 * @{
 *
 * @file
 * @brief       Header definitions for the SHA3 hash function
 *
 * @author
 */

#ifndef _SHA3_H_
#define _SHA3_H_

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief compute sha3 from the given input to specified size digest
 * @param[in] digest_length the digest length in bits
 *            224, 256, 384 and 512 
 * @param[in] input the data to compute the hash from
 * @param[in] input_size the number of bytes of input
 * @param[out] output the given out buffer, MUST be >= (digest_length/8)
 */
void sha3(size_t digest_length, const uint8_t *input, size_t input_size, uint8_t *output);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* _SHA3_H_ */
