#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "md5_utils.h"

#define LEFTROTATE(x, c) ((x << c) | (x >> (32 - c)))
#define CHUNK_SIZE 4096  // Process 4KB at a time
#define MD5_BLOCK_SIZE 64  // MD5 processes data in 64-byte blocks

// MD5 context structure
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[MD5_BLOCK_SIZE];
} MD5_CTX;

void md5_transform(uint32_t state[4], const uint8_t block[MD5_BLOCK_SIZE]);

// Initialize MD5 context
void md5_init(MD5_CTX *ctx) {
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

// MD5 processing (for each block)
void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t len) {
    size_t index = (ctx->count[0] >> 3) & 0x3F;
    ctx->count[0] += len << 3;
    if (ctx->count[0] < (len << 3)) {
        ctx->count[1]++;
    }
    ctx->count[1] += len >> 29;

    size_t partLen = 64 - index;
    size_t i = 0;

    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        md5_transform(ctx->state, ctx->buffer);

        for (i = partLen; i + 63 < len; i += 64) {
            md5_transform(ctx->state, &data[i]);
        }
        index = 0;
    }
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

// Final MD5 digest
void md5_final(uint8_t digest[16], MD5_CTX *ctx) {
    uint8_t padding[64] = { 0x80 };
    uint8_t bits[8];
    size_t index = (ctx->count[0] >> 3) & 0x3F;
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);

    // Encode bit count
    for (int i = 0; i < 8; i++) {
        bits[i] = (uint8_t)((ctx->count[i >> 2] >> ((i % 4) * 8)) & 0xFF);
    }

    md5_update(ctx, padding, padLen);
    md5_update(ctx, bits, 8);

    for (int i = 0; i < 4; i++) {
        digest[i]      = (uint8_t)(ctx->state[i] & 0xFF);
        digest[i + 4]  = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        digest[i + 8]  = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i + 12] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
    }
}

// Process one MD5 block
void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    memcpy(x, block, 64);

    #define STEP(f, a, b, c, d, x, t, s) \
        a += f(b, c, d) + x + t; \
        a = LEFTROTATE(a, s); \
        a += b;

    // Define functions
    #define F(x, y, z) ((x & y) | (~x & z))
    #define G(x, y, z) ((x & z) | (y & ~z))
    #define H(x, y, z) (x ^ y ^ z)
    #define I(x, y, z) (y ^ (x | ~z))

    // Round 1
    STEP(F, a, b, c, d, x[0], 0xd76aa478, 7)
    STEP(F, d, a, b, c, x[1], 0xe8c7b756, 12)
    STEP(F, c, d, a, b, x[2], 0x242070db, 17)
    STEP(F, b, c, d, a, x[3], 0xc1bdceee, 22)
    
    // Round 2
    STEP(G, a, b, c, d, x[1], 0xf61e2562, 5)
    STEP(G, d, a, b, c, x[6], 0xc040b340, 9)

    // Round 3
    STEP(H, a, b, c, d, x[5], 0xfffa3942, 4)
    STEP(H, d, a, b, c, x[8], 0x8771f681, 11)

    // Round 4
    STEP(I, a, b, c, d, x[0], 0xf4292244, 6)
    STEP(I, d, a, b, c, x[7], 0x432aff97, 10)

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// Compute MD5 hash of a file
int compute_md5(const char *filename, char hash_str[33]) {
    FILE *file = fopen(filename, "rb");
    if (!file) return 0;

    MD5_CTX ctx;
    md5_init(&ctx);

    uint8_t buffer[CHUNK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        md5_update(&ctx, buffer, bytes_read);
    }

    fclose(file);

    uint8_t digest[16];
    md5_final(digest, &ctx);

    // Convert to hex string
    for (int i = 0; i < 16; i++) {
        sprintf(hash_str + i * 2, "%02x", digest[i]);
    }
    hash_str[32] = '\0';

    return 1;
}
