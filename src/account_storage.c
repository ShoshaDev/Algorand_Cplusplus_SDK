//
// Created by Conan Exiles on 7/3/2024.
//

#include "account_storage.h"
#include <vertices_log.h>
#include <string.h>

ret_code_t save_account_data(const char *filename, const char *password, s_account_t *accounts, int account_count) {
    ret_code_t err_code = VTC_SUCCESS;
    unsigned char key[KEY_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char salt[SALT_SIZE];
    int plaintext_len_1 = sizeof(s_account_t) * account_count;
    int plaintext_len_2 = sizeof(account_info_t) * account_count;
    unsigned char *plaintext = malloc(plaintext_len_1 + plaintext_len_2);
    int ciphertext_malloc_len = plaintext_len_1 + plaintext_len_2 + MAC_SIZE + NONCE_SIZE;
    unsigned char *ciphertext = malloc(ciphertext_malloc_len);

    // Generate a random salt and nonce
    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(nonce, sizeof(nonce));

    // Derive the key from the password and salt
    err_code = derive_key(password, salt, key);
    RET_CODE_SUCCESS(err_code);

    memcpy(plaintext, accounts, plaintext_len_1);

    uint32_t i = 0;
    for(i = 0; i < account_count; i++) {
        memcpy(plaintext + plaintext_len_1 + i * sizeof(account_info_t), accounts[i].vtc_account, sizeof(account_info_t));
    }

    int ciphertext_len = 0;
    err_code = encrypt(plaintext, plaintext_len_1 + plaintext_len_2, key, nonce, ciphertext, &ciphertext_len);
    RET_CODE_SUCCESS(err_code);

    // Store the salt and ciphertext to the file
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(salt, sizeof(unsigned char), SALT_SIZE, file);
        fwrite(ciphertext, sizeof(unsigned char), ciphertext_len, file);
        fclose(file);
    } else {
        LOG_ERROR("Failed to open file for writing");
        err_code = VTC_ERROR_INTERNAL;
    }

    return err_code;
}

ret_code_t load_account_data(const char *filename, const char *password, s_account_t *accounts, int max_account_count) {
    ret_code_t err_code = VTC_SUCCESS;
    unsigned char key[KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    int plaintext_malloc_len_1 = sizeof(s_account_t) * max_account_count;
    int plaintext_malloc_len_2 = sizeof(account_info_t) * max_account_count;
    unsigned char *plaintext = malloc(plaintext_malloc_len_1 + plaintext_malloc_len_2);
    int ciphertext_malloc_len = plaintext_malloc_len_1 + plaintext_malloc_len_2 + MAC_SIZE + NONCE_SIZE;
    unsigned char *ciphertext = malloc(ciphertext_malloc_len);

    // Read the salt and ciphertext from the file
    FILE *file = fopen(filename, "rb");
    if (file) {
        fread(salt, sizeof(unsigned char), SALT_SIZE, file);
        int ciphertext_len = fread(ciphertext, sizeof(unsigned char), ciphertext_malloc_len, file);
        fclose(file);

        // Derive the key from the password and salt
        err_code = derive_key(password, salt, key);
        RET_CODE_SUCCESS(err_code);

        int plaintext_len = 0;
        err_code = decrypt(ciphertext, ciphertext_len, key, plaintext, &plaintext_len);
        RET_CODE_SUCCESS(err_code);

        memcpy(accounts, plaintext, plaintext_malloc_len_1);

        uint32_t i = 0;
        for(i = 0; i < max_account_count; i++) {
            accounts[i].vtc_account = (account_info_t *) malloc(sizeof (account_info_t));
            memset(accounts[i].vtc_account, 0 , sizeof (account_info_t));
            memcpy(accounts[i].vtc_account, plaintext + plaintext_malloc_len_1 + i * sizeof(account_info_t), sizeof(account_info_t));
        }
    } else {
        LOG_ERROR("Failed to open file for loading wallet");
        err_code = VTC_ERROR_INTERNAL;
    }

    return err_code;
}
