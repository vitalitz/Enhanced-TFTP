#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "md5_utils.h"

#define LEFTROTATE(x, c) ((x << c) | (x >> (32 - c)))

void compute_md5(const char *filename, uint8_t hash[16]) {
    static const uint32_t s[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    static const uint32_t k[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453,  0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05,  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    uint8_t buffer[64];
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    uint64_t bitlen = 0;
    FILE *file = fopen(filename, "rb");

    if (!file) {
        perror("File open error");
        return;
    }

    while (1) {
        size_t read = fread(buffer, 1, 64, file);
        bitlen += read * 8;
        if (read < 64) {
            buffer[read] = 0x80;
            memset(buffer + read + 1, 0, 63 - read);

            if (read <= 55) {
                *(uint64_t *)(buffer + 56) = bitlen;
                read = 64;
            }
        }

        uint32_t m[16];
        for (int i = 0; i < 16; i++)
            m[i] = ((uint32_t)buffer[i * 4]) | (((uint32_t)buffer[i * 4 + 1]) << 8) |
                   (((uint32_t)buffer[i * 4 + 2]) << 16) | (((uint32_t)buffer[i * 4 + 3]) << 24);

        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; i++) {
            uint32_t F, g;
            if (i < 16) {
                F = (B & C) | ((~B) & D);
                g = i;
            } else if (i < 32) {
                F = (D & B) | ((~D) & C);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                F = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            } else {
                F = C ^ (B | (~D));
                g = (7 * i) % 16;
            }

            F += A + k[i] + m[g];
            A = D;
            D = C;
            C = B;
            B += LEFTROTATE(F, s[i]);
        }

        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;

        if (read < 64) break;
    }

    fclose(file);
    memcpy(hash, &a0, 4);
    memcpy(hash + 4, &b0, 4);
    memcpy(hash + 8, &c0, 4);
    memcpy(hash + 12, &d0, 4);
}