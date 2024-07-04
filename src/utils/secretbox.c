//
// Created by Conan Exiles on 7/3/2024.
//

#include "secretbox.h"
#include "vertices_log.h"
#include <string.h>

 ret_code_t derive_key(const char *password, unsigned char *salt, unsigned char *key) {
    ret_code_t err_code = VTC_SUCCESS;
    if (crypto_pwhash(key, KEY_SIZE,
                      password, strlen(password),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        LOG_ERROR("Failed to derive key.");
        err_code = VTC_ERROR_INTERNAL;
    }
     return err_code;
}

ret_code_t encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext, int *ciphertext_len) {
    memcpy(ciphertext, nonce, NONCE_SIZE); // Store nonce at the beginning of the ciphertext
    if (crypto_secretbox_easy(ciphertext + NONCE_SIZE, plaintext, plaintext_len, nonce, key) != 0) {
        LOG_ERROR("Encryption failed.");
        return VTC_ERROR_INTERNAL;
    }
    *ciphertext_len = plaintext_len + MAC_SIZE + NONCE_SIZE;

    return VTC_SUCCESS;
}

ret_code_t decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, int *plaintext_len) {
    unsigned char nonce[NONCE_SIZE];

    memcpy(nonce, ciphertext, NONCE_SIZE); // Extract nonce from the beginning of the ciphertext
    if (crypto_secretbox_open_easy(plaintext, ciphertext + NONCE_SIZE, ciphertext_len - NONCE_SIZE, nonce, key) != 0) {
        LOG_ERROR("Decryption failed.");
        return VTC_ERROR_INTERNAL;
    }
    *plaintext_len = ciphertext_len - MAC_SIZE - NONCE_SIZE;

    return VTC_SUCCESS;
}