#ifndef MD5_UTILS_H
#define MD5_UTILS_H

#include <stdint.h>
#include <stddef.h>

/**
 * Computes the MD5 hash of a file.
 * @param filename Path to the file.
 * @param hash_str Output buffer (must be at least 33 bytes: 32 for hash + 1 for '\0').
 * @return 1 if successful, 0 if file not found.
 */
int compute_md5(const char *filename, char hash_str[33]);

/**
 * Computes the MD5 hash of a given data buffer.
 * @param data Pointer to data buffer.
 * @param length Length of the data.
 * @param hash Output buffer (16-byte raw MD5 hash).
 */
void md5_compute(const uint8_t *data, size_t length, uint8_t hash[16]);

#endif /* MD5_UTILS_H */
