//
// Created by Conan Exiles on 7/3/2024.
//

#ifndef VERTICES_SDK_ACCOUNT_STORAGE_H
#define VERTICES_SDK_ACCOUNT_STORAGE_H

#include "secretbox.h"
#include <vertices_types.h>

#ifndef WALLET_STORAGE_FILENAME
#define WALLET_STORAGE_FILENAME "save_acc.dat"
#endif

ret_code_t save_account_data(const char *filename, const char *password, s_account_t *accounts, int account_count);
ret_code_t load_account_data(const char *filename, const char *password, s_account_t *accounts, int max_account_count);

#endif //VERTICES_SDK_ACCOUNT_STORAGE_H
