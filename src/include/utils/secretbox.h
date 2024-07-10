//
// Created by Bruno on 7/3/2024.
//

#ifndef VERTICES_SDK_SECRETBOX_H
#define VERTICES_SDK_SECRETBOX_H

#include <sodium.h>
#include "vertices_errors.h"

#define KEY_SIZE crypto_secretbox_KEYBYTES
#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define SALT_SIZE crypto_pwhash_SALTBYTES
#define MAC_SIZE crypto_secretbox_MACBYTES

ret_code_t derive_key(const char *password, unsigned char *salt, unsigned char *key);
ret_code_t encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext, int *ciphertext_len);
ret_code_t decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, int* plaintext_len);

#endif //VERTICES_SDK_SECRETBOX_H
