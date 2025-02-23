#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>   // OpenSSL EVP API
#include <openssl/aes.h>

#define AES_KEY_SIZE 16  // AES-128 key size (16 bytes)
#define AES_BLOCK_SIZE 16 // AES block size (always 16 bytes)

static uint8_t AES_SECRET_KEY[AES_KEY_SIZE];  // Buffer for AES key

/**
 * Reads the AES key from a file.
 * @param key_file The file containing the AES key.
 * @return 0 on success, -1 on failure.
 */
int load_aes_key(const char *key_file) {
    FILE *file = fopen(key_file, "rb");
    if (!file) {
        perror("❌ Error opening AES key file");
        return -1;
    }

    size_t bytes_read = fread(AES_SECRET_KEY, 1, AES_KEY_SIZE, file);
    fclose(file);

    if (bytes_read != AES_KEY_SIZE) {
        fprintf(stderr, "❌ Error: AES key file must be exactly %d bytes\n", AES_KEY_SIZE);
        return -1;
    }

    printf("🔑 AES key loaded successfully from %s\n", key_file);
    return 0;
}

/**
 * Encrypts data using AES-128 in CTR mode.
 */
void aes_encrypt(uint8_t *data, size_t length, uint8_t *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("❌ OpenSSL EVP_CIPHER_CTX_new failed");
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, AES_SECRET_KEY, iv) != 1) {
        perror("❌ OpenSSL EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int outlen;
    if (EVP_EncryptUpdate(ctx, data, &outlen, data, length) != 1) {
        perror("❌ OpenSSL EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_free(ctx);
}

/**
 * Decrypts data using AES-128 in CTR mode.
 */
void aes_decrypt(uint8_t *data, size_t length, uint8_t *iv) {
    aes_encrypt(data, length, iv);  // AES-CTR decryption is the same as encryption
}
