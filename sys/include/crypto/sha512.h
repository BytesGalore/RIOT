/*
 * Copyright (C) 2015 Martin Landsmann <Martin.Landsmann@HAW-Hamburg.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
 
/**
 * @ingroup     sys_crypto
 * @{
 *
 * @file
 * @brief       Header definitions for the SHA512 hash function
 *
 * @author
 */

#ifndef _SHA512_H_
#define _SHA512_H_

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_DIGEST_LENGTH 64

/**
 * @brief Context for ciper operatins based on sha512
 */
typedef struct {
    /** global state */
    uint64_t state[8];
    /** processed bytes counter */
    uint32_t count[2];
    /** buffer */
    unsigned char buf[128];
} sha512_context_t;

/**
 * @brief SHA-512 initialization.  Begins a SHA-512 operation.
 *
 * @param ctx  sha512_context_t handle to init
 */
void sha512_init(sha512_context_t *ctx);

/**
 * @brief Add bytes into the hash
 *
 * @param ctx  sha512_context_t handle to use
 * @param in   pointer to the input buffer
 * @param len  length of the buffer
 */
void sha512_update(sha512_context_t *ctx, const void *in, size_t len);

/**
 * @brief SHA-512 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 *
 * @param digest resulting digest, this is the hash of all the bytes
 * @param ctx    sha512_context_t handle to use
 */
void sha512_final(unsigned char digest[SHA512_DIGEST_LENGTH], sha512_context_t *ctx);

/**
 * @brief A wrapper function to simplify the generation of a hash, this is
 * usefull for generating sha512 for one buffer
 *
 * @param d pointer to the buffer to generate hash from
 * @param n length of the buffer
 * @param md optional pointer to an array for the result, length must be
 *           SHA256_DIGEST_LENGTH
 *           if md == NULL, one static buffer is used
 */
unsigned char *sha512(const unsigned char *d, size_t n, unsigned char *md);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* _SHA512_H_ */
