#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>

#define AES_KEY_SIZE    16  // AES-128 key size (128-bit)
#define AES_BLOCK_SIZE  16  // AES block size (always 16 bytes for AES)

// Declare AES key globally so client & server can use it
extern const uint8_t AES_SECRET_KEY[AES_KEY_SIZE];

// Function to load the AES key from a file
int load_aes_key(const char *key_file);
void aes_encrypt(uint8_t *data, size_t length, uint8_t *iv);
void aes_decrypt(uint8_t *data, size_t length, uint8_t *iv);

#endif /* CRYPTO_UTILS_H */

