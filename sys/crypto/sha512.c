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
 * @brief       SHA512 hash function implementation
 *              aligning to the sha256 implmentation by:
 *              Colin Percival (2005)
 *              Christian Mehlis & René Kijewski (2013)
 *              to keep things uniform 
 *              cf. http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 *
 * @author
 *
 * @}
 */

#include <string.h>

#include "crypto/sha512.h"
#include "board.h"

#ifdef __BIG_ENDIAN__
/* Copy a vector of big-endian uint32_t into a vector of bytes */
#define be32enc_vect memcpy

/* Copy a vector of bytes into a vector of big-endian uint32_t */
#define be32dec_vect memcpy

#else /* !__BIG_ENDIAN__ */

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void be32enc_vect(void *dst_, const void *src_, size_t len)
{
    uint32_t *dst = dst_;
    const uint32_t *src = src_;
    for (size_t i = 0; i < len / 4; i++) {
        dst[i] = __builtin_bswap32(src[i]);
    }
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
#define be32dec_vect be32enc_vect

#endif /* __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__ */

/* Elementary functions used by SHA512 */
#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define SHR(x, n)   (x >> n)
#define ROTR(x, n)  ((x >> n) | (x << (64 - n)))

/* SHA-512 Sum */
#define S0(x)       (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x)       (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

/* SHA-512 Sigma*/
#define s0(x)       (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define s1(x)       (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

/*
 * SHA-512 round constants
 * These are the first 64 bits of the fractional parts of the cube roots
 * of the first 80 primes
 * (same for sha256 but just 32 bits and sixty-four primes)
 */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

/*
 * SHA512 block compression function.  The 512-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void sha512_transform(uint64_t *state, const unsigned char block[80])
{
    uint64_t W[80];
    uint64_t S[8];

    /* 1. Prepare message schedule W. */
    be32dec_vect(W, block, 80);
    for (int i = 16; i < 80; i++) {
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
    }

    /* 2. Initialize working variables. */
    memcpy(S, state, 8);

    /* 3. Mix. */
    for (int i = 0; i < 80; ++i) {
        uint64_t e = S[(84 - i) % 8], f = S[(85 - i) % 8];
        uint64_t g = S[(86 - i) % 8], h = S[(87 - i) % 8];
        
        uint64_t t0 = h + S1(e) + Ch(e, f, g) + W[i] + K[i];

        uint64_t a = S[(80 - i) % 8], b = S[(81 - i) % 8];
        uint64_t c = S[(82 - i) % 8], d = S[(83 - i) % 8];
        
        uint64_t t1 = S0(a) + Maj(a, b, c);

        S[(83 - i) % 8] = d + t0;
        S[(87 - i) % 8] = t0 + t1;
    }

    /* 4. Mix local working variables into global state */
    for (int i = 0; i < 8; i++) {
        state[i] += S[i];
    }
}

static unsigned char PAD[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* Add padding and terminating bit-count. */
static void sha512_pad(sha512_context_t *ctx)
{
    /*
     * Convert length to a vector of bytes -- we do this now rather
     * than later because the length will change after we pad.
     */
    unsigned char len[8];
    be32enc_vect(len, ctx->count, 8);

    /* Add 1--64 bytes so that the resulting length is 56 mod 64 */
    uint32_t r = (uint32_t)((ctx->count[1] >> 3) & 0x3f);
    uint32_t plen = (r < 72) ? (72 - r) : (120 - r);
    sha512_update(ctx, PAD, (size_t) plen);

    /* Add the terminating bit-count */
    sha512_update(ctx, len, 8);
}

/* SHA-512 initialization.  Begins a SHA-512 operation. */
void sha512_init(sha512_context_t *ctx)
{
    /* Zero bits processed so far */
    ctx->count[0] = ctx->count[1] = 0;

    /*
     * SHA-512 initial hash values
     * Initialization each with 64 Bits of the fractional part 
     * computed from the squareroot of the first 8 primes (2 to 19)
     * (same for sha256 but only 32 Bits of the fractional part)
     */
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
}

/* Add bytes into the hash */
void sha512_update(sha512_context_t *ctx, const void *in, size_t len)
{
    /* Number of bytes left in the buffer from previous updates */
    uint32_t r = (ctx->count[1] >> 3) & 0x3f;

    /* Convert the length into a number of bits */
    uint32_t bitlen1 = ((uint32_t) len) << 3;
    uint32_t bitlen0 = ((uint32_t) len) >> 29;

    /* Update number of bits */
    if ((ctx->count[1] += bitlen1) < bitlen1) {
        ctx->count[0]++;
    }

    ctx->count[0] += bitlen0;

    /* Handle the case where we don't need to perform any transforms */
    if (len < 128 - r) {
        memcpy(&ctx->buf[r], in, len);
        return;
    }

    /* Finish the current block */
    const unsigned char *src = in;

    memcpy(&ctx->buf[r], src, 128 - r);
    sha512_transform(ctx->state, ctx->buf);
    src += 128 - r;
    len -= 128 - r;

    /* Perform complete blocks */
    while (len >= 128) {
        sha512_transform(ctx->state, src);
        src += 128;
        len -= 128;
    }

    /* Copy left over data into buffer */
    memcpy(ctx->buf, src, len);
}

/*
 * SHA-512 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
void sha512_final(unsigned char digest[SHA512_DIGEST_LENGTH], sha512_context_t *ctx)
{
    /* Add padding */
    sha512_pad(ctx);

    /* Write the hash */
    be32enc_vect(digest, ctx->state, SHA512_DIGEST_LENGTH);

    /* Clear the context state */
    memset((void *) ctx, 0, sizeof(*ctx));
}

unsigned char *sha512(const unsigned char *d, size_t n, unsigned char *md)
{
    sha512_context_t c;
    static unsigned char m[SHA512_DIGEST_LENGTH];

    if (md == NULL) {
        md = m;
    }

    sha512_init(&c);
    sha512_update(&c, d, n);
    sha512_final(md, &c);

    return md;
}
