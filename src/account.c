/*
 * Copyright (c) 2021 Vertices Network <cyril@vertices.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <vertices_log.h>
#include "include/provider.h"
#include "utils/base32.h"
#include "account.h"

#define ACCOUNTS_MAXIMUM_COUNT  10
#define SECRET_ACCOUNTS_MAXIMUM_COUNT   5

static local_accounts_t m_accounts[ACCOUNTS_MAXIMUM_COUNT] = {0};
static s_account_t s_accounts[SECRET_ACCOUNTS_MAXIMUM_COUNT] = {0};

static ret_code_t
from_b32_init(size_t index, char *public_b32, account_info_t *info)
{
    char result[36] = {0};
    size_t result_size = sizeof result;
    b32_decode(public_b32, result, &result_size);

    // todo verify checksum

    // copy address part
    memcpy(info->public_key,
           result,
           sizeof(info->public_key));

    return VTC_SUCCESS;
}

static bool
account_exists(account_info_t *account)
{
    uint32_t i = 0;
    for (; i < ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (account == (account_info_t *) &m_accounts[i].account)
        {
            return true;
        }
    }

    return false;
}

ret_code_t
account_new(char *public_b32, account_info_t **account)
{
    VTC_ASSERT_BOOL(public_b32 != NULL);
    ret_code_t err_code;

    // look for free spot to store the new account
    size_t i = 0;
    for (i = 0; i < ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (m_accounts[i].status == ACCOUNT_NONE)
        {
            m_accounts[i].status = ACCOUNT_ADDED;

            LOG_INFO("👛 Added account to memory: #%lu", (long unsigned int) i);
            break;
        }
    }

    // cannot store another account
    if (i == ACCOUNTS_MAXIMUM_COUNT)
    {
        return VTC_ERROR_NO_MEM;
    }

    err_code = from_b32_init(i, public_b32, &m_accounts[i].account.info);
    VTC_ASSERT(err_code);

    // copy public key
    memcpy(m_accounts[i].account.info.public_b32,
           public_b32,
           sizeof(m_accounts[i].account.info.public_b32));

    // update account info
    err_code = provider_account_info_get(&m_accounts[i].account);

    *account = (account_info_t *) &m_accounts[i].account;

    return err_code;
}

bool
account_has_app(account_info_t *account, uint64_t app_id)
{
    if (account_exists(account))
    {
        account_details_t *details = (account_details_t *) account;

        for (uint32_t j = 0; j < details->app_idx; ++j)
        {
            if (details->apps_local[j].app_id == app_id)
            {
                return true;
            }
        }
    }

    return false;
}

ret_code_t
account_balance(account_info_t *account, int32_t *balance)
{
    if (account_exists(account))
    {
        *balance = account->amount;
    }
    else
    {
        return VTC_ERROR_INVALID_PARAM;
    }

    return VTC_SUCCESS;
}

ret_code_t
account_free(account_info_t *account)
{
    uint32_t i = 0;
    for (; i < ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (account == (account_info_t *) &m_accounts[i].account)
        {
            m_accounts[i].status = ACCOUNT_NONE;
            memset(&m_accounts[i].account, 0, sizeof(account_details_t));
            break;
        }
    }

    if (i == ACCOUNTS_MAXIMUM_COUNT)
    {
        return VTC_ERROR_NOT_FOUND;
    }

    LOG_INFO("👛 Deleted account from memory: #%u", i);

    return VTC_SUCCESS;
}

ret_code_t
account_update(account_info_t *account)
{
    if (account_exists(account))
    {
        account_details_t *details = (account_details_t *) account;

        // update account info
        return provider_account_info_get(details);
    }
    else
    {
        return VTC_ERROR_INVALID_PARAM;
    }
}

ret_code_t
account_init()
{
    memset(m_accounts, 0, sizeof m_accounts);

    return VTC_SUCCESS;
}

ret_code_t
s_account_new(char *public_b32, char *private_key,  s_account_t *account, const char *account_name) {
    VTC_ASSERT_BOOL(public_b32 != NULL);
    ret_code_t err_code;

    // look for free spot to store the new account
    size_t i = 0;
    for (i = 0; i < SECRET_ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (s_accounts[i].status == ACCOUNT_NONE)
        {
            s_accounts[i].status = ACCOUNT_ADDED;

            LOG_INFO("👛 Added secret account to wallet: #%lu", (long unsigned int) i);
            break;
        }
    }

    // cannot store another account
    if (i == SECRET_ACCOUNTS_MAXIMUM_COUNT)
    {
        return VTC_ERROR_NO_MEM;
    }

    err_code = from_b32_init(i, public_b32, s_accounts[i].vtc_account);
    VTC_ASSERT(err_code);

    // copy account keys
    memcpy(s_accounts[i].vtc_account->public_b32,
           public_b32,
           sizeof(s_accounts[i].vtc_account->public_b32));

    memcpy(s_accounts[i].private_key,
           private_key,
           sizeof(s_accounts[i].private_key));

    account_details_t accountDetails;
    memcpy(&accountDetails.info,
           s_accounts[i].vtc_account,
           sizeof(account_info_t));

    // update account info
    err_code = provider_account_info_get(&accountDetails);

    memcpy(s_accounts[i].vtc_account,
           &accountDetails.info,
           sizeof(account_info_t));

    memcpy(s_accounts[i].name,
           account_name,
           strlen(account_name));

    memcpy(account,
        &s_accounts[i],
           sizeof(s_account_t));

    return err_code;
}

ret_code_t
s_account_init(void) {
    memset(s_accounts, 0, sizeof s_accounts);

    uint32_t i = 0;
    for (; i < SECRET_ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        s_accounts[i].vtc_account = (account_info_t *) malloc(sizeof (account_info_t));
        memset(s_accounts[i].vtc_account, 0 , sizeof (account_info_t));
    }

    return VTC_SUCCESS;
}

bool
s_wallet_exists(void) {
    FILE *file = fopen(WALLET_STORAGE_FILENAME, "r");
    if (file) {
        fclose(file);
        return true;
    }
    return false;
}

static bool
s_account_exists_by_addr(s_account_t **account)
{
    uint32_t i = 0;
    for (; i < SECRET_ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (*account == (s_account_t *) &s_accounts[i])
        {
            return true;
        }
    }

    return false;
}

bool
s_account_exists(const char *account_name) {
    size_t i = 0;
    for (i = 0; i < SECRET_ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (strcmp(s_accounts[i].name, account_name) == 0 && s_accounts[i].status == ACCOUNT_ADDED)
        {
            LOG_INFO("👛 Discovered secret account with the same name on wallet: #%s", s_accounts[i].vtc_account->public_b32);
            break;
        }
    }

    if(i == SECRET_ACCOUNTS_MAXIMUM_COUNT) {
        return 0;
    } else {
        return 1;
    }
}

ret_code_t
s_account_get_by_name(s_account_t *account, const char *account_name) {
    size_t i = 0;
    for (i = 0; i < SECRET_ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (strcmp(s_accounts[i].name, account_name) == 0 && s_accounts[i].status == ACCOUNT_ADDED)
        {
            LOG_INFO("👛 Discovered secret account with the same name on wallet: #%s", s_accounts[i].vtc_account->public_b32);
            break;
        }
    }

    if(i == SECRET_ACCOUNTS_MAXIMUM_COUNT) {
        return VTC_ERROR_NOT_FOUND;
    }

    memcpy(account,
           &s_accounts[i],
           sizeof(s_account_t));

    return VTC_SUCCESS;
}

ret_code_t
s_accounts_all_get(s_account_t **accounts) {
    *accounts = s_accounts;

    return VTC_SUCCESS;
}

ret_code_t
s_account_update(s_account_t **account) {
    if (s_account_exists_by_addr(*account))
    {
        account_details_t accountDetails;
        memcpy(&accountDetails.info,
               (*account)->vtc_account,
               sizeof(account_info_t));

        // update account info
        ret_code_t err_code = provider_account_info_get(&accountDetails);

        memcpy((*account)->vtc_account,
               &accountDetails.info,
               sizeof(account_info_t));
        return VTC_SUCCESS;
    }
    else
    {
        return VTC_ERROR_INVALID_PARAM;
    }
}

ret_code_t
s_account_load(const char *password) {
    if (sodium_init() == -1) {
        return VTC_ERROR_INTERNAL;
    }

    LOG_INFO("👛 Loading accounts from a wallet");
    return load_account_data(WALLET_STORAGE_FILENAME, password, s_accounts, SECRET_ACCOUNTS_MAXIMUM_COUNT);

}

ret_code_t
s_account_save(const char *password) {
    if (sodium_init() == -1) {
        return VTC_ERROR_INTERNAL;
    }

    LOG_INFO("👛 Saving accounts to a wallet");
    return save_account_data(WALLET_STORAGE_FILENAME, password, s_accounts, SECRET_ACCOUNTS_MAXIMUM_COUNT);
}

ret_code_t
s_account_free(s_account_t **account) {
    uint32_t i = 0;
    for (; i < SECRET_ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if (*account == (s_account_t *) &s_accounts[i])
        {
            s_accounts[i].status = ACCOUNT_NONE;
            memset(&s_accounts[i], 0, sizeof(s_account_t));
            break;
        }
    }

    if (i == SECRET_ACCOUNTS_MAXIMUM_COUNT)
    {
        return VTC_ERROR_NOT_FOUND;
    }

    LOG_INFO("👛 Deleted secret account from wallet: #%u", i);

    return VTC_SUCCESS;
}

ret_code_t
s_wallet_free(void) {
    uint32_t account_count = 0;
    uint32_t i = 0;
    for (; i < SECRET_ACCOUNTS_MAXIMUM_COUNT; ++i)
    {
        if(m_accounts[i].status == ACCOUNT_ADDED) {
            account_count++;
        }
        m_accounts[i].status = ACCOUNT_NONE;
        memset(&m_accounts[i].account, 0, sizeof(account_details_t));
    }

    LOG_INFO("👛 Deleted #%u accounts from wallet", account_count);

    return VTC_SUCCESS;
}