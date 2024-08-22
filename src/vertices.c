/*
 * Copyright (c) 2021 Vertices Network <cyril@vertices.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "include/provider.h"
#include <account.h>
#include <transaction.h>
#include "mnemonic.h"
#include <vertices_log.h>
#include <string.h>
#include "utils/sha512_256.h"
#include "utils/base32.h"
#include "vertices.h"
#include <sodium.h>

#if defined APP_TYPE
#define VERTICES_EXPORT
#elif defined _WIN32 || defined _WIN64
#define VERTICES_EXPORT __declspec(dllexport)
#endif

static ret_code_t
(*m_vertices_evt_handler)(vtc_evt_t *evt) = NULL;

typedef struct
{
    size_t wr_index;
    size_t rd_index;
    vtc_evt_t evt[VTC_EVENTS_COUNT];
} vtc_events_buf_t;

#define increment_event_index(i) \
    i = ((i) + 1) & (VTC_EVENTS_COUNT - 1)

static vtc_events_buf_t m_events_queue = {0};

/// Get node version
/// \param version Pointer to \c provider_version_t
/// \return
/// * \c VTC_SUCCESS when \c version has been filled with node info
/// * \c VTC_ERROR_OFFLINE when node cannot be reached to get info. Version could still be filled with information from a previous call.
VERTICES_EXPORT ret_code_t
vertices_version(provider_version_t *version)
{
    return provider_version_get(version);
}

/// Check if node is alive
/// \return
/// * \c VTC_SUCCESS when API can be reached
/// * \c VTC_ERROR_HTTP_BASE when an error occurs
VERTICES_EXPORT ret_code_t
vertices_ping()
{
    return provider_ping();
}

VERTICES_EXPORT ret_code_t
vertices_provider_buf_get(char **buf)
{
    return provider_buffer_get(buf);
}

VERTICES_EXPORT ret_code_t
vertices_account_new_from_b32(char *public_b32, account_info_t **account)
{
    return account_new(public_b32, account);
}

VERTICES_EXPORT ret_code_t
vertices_account_init() {
    return account_init();
}

VERTICES_EXPORT ret_code_t
vertices_account_new_from_bin(char *public_key, account_info_t **account)
{
    VTC_ASSERT_BOOL(public_key != 0);
    VTC_ASSERT_BOOL(account != 0);

    ret_code_t err_code;

    unsigned char checksum[32] = {0};
    char public_key_checksum[36] = {0};
    char public_b32[PUBLIC_B32_STR_MAX_LENGTH] = {0};

    memcpy(public_key_checksum, public_key, ADDRESS_LENGTH);

    err_code = sha512_256((const unsigned char *) public_key,
                          ADDRESS_LENGTH,
                          checksum,
                          sizeof(checksum));
    VTC_ASSERT(err_code);

    memcpy(&public_key_checksum[32], &checksum[32 - 4], 4);

    size_t size = 58;
    err_code = b32_encode((const char *) public_key_checksum,
                          sizeof(public_key_checksum),
                          public_b32,
                          &size);
    VTC_ASSERT(err_code);

    return account_new(public_b32, account);
}

VERTICES_EXPORT ret_code_t
vertices_s_account_new_from_keys(char *public_key, char *private_key, s_account_t *account, const char *account_name)
{
    VTC_ASSERT_BOOL(public_key != 0);
    VTC_ASSERT_BOOL(account != 0);

    ret_code_t err_code;

    unsigned char checksum[32] = {0};
    char public_key_checksum[36] = {0};
    char public_b32[PUBLIC_B32_STR_MAX_LENGTH] = {0};

    memcpy(public_key_checksum, public_key, sizeof(account->vtc_account->public_key));

    err_code = sha512_256((const unsigned char *) public_key,
                          ADDRESS_LENGTH,
                          checksum,
                          sizeof(checksum));
    VTC_ASSERT(err_code);

    memcpy(&public_key_checksum[32], &checksum[32 - 4], 4);

    size_t size = 58;
    err_code = b32_encode((const char *) public_key_checksum,
                          sizeof(public_key_checksum),
                          public_b32,
                          &size);
    VTC_ASSERT(err_code);

    if(strcmp(account_name, "RANDOM$NAME") != 0) {
        return s_account_new(public_b32, private_key, account, account_name);
    } else {
        // copy account keys
        if(account == NULL) {
            return VTC_ERROR_INVALID_PARAM;
        }
        account->vtc_account = (account_info_t*) malloc(sizeof (account_info_t));

        memcpy(account->vtc_account->public_b32,
               public_b32,
               sizeof(account->vtc_account->public_b32));

        memcpy(account->private_key,
               private_key,
               sizeof(account->private_key));

        return VTC_SUCCESS;
    }
}

VERTICES_EXPORT ret_code_t
vertices_s_account_new_from_mnemonic(char *mnemonic_str, s_account_t *account, const char *account_name) {
    ret_code_t err_code;

    if(strlen(account_name) > ACCOUNT_NAME_LENGTH) {
        return VTC_ERROR_INVALID_PARAM;
    }

    if(s_account_exists(account_name)) {
        return VTC_SAME_MEM_EXIST;
    }

    initialize_mnemonic();
    bytes recovered_seed;
    err_code = seed_from_mnemonic(mnemonic_str, &recovered_seed);

    RET_CODE_SUCCESS(err_code);

    if(sodium_init() < 0) {
        LOG_ERROR("Sodium Library cannot be inited");
        return VTC_ERROR_INTERNAL;
    }

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];

    crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk, recovered_seed.data);

    return vertices_s_account_new_from_keys(ed25519_pk,  ed25519_sk, account, account_name);
}

VERTICES_EXPORT ret_code_t
vertices_s_account_new_random(s_account_t *account) {
    ret_code_t err_code;

    if(sodium_init() < 0) {
        LOG_ERROR("Sodium Library cannot be inited");
        return VTC_ERROR_INTERNAL;
    }

    unsigned char seed[crypto_sign_ed25519_SEEDBYTES] = {0};
    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
    randombytes_buf(seed, sizeof(seed));

    crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk, seed);

    return vertices_s_account_new_from_keys(ed25519_pk,  ed25519_sk, account, "RANDOM$NAME");
}

VERTICES_EXPORT ret_code_t
vertices_mnemonic_from_account(const char *account_name, char **mnemonic_str) {
    ret_code_t err_code;
    s_account_t account;

    if(strlen(account_name) > ACCOUNT_NAME_LENGTH) {
        return VTC_ERROR_INVALID_PARAM;
    }

    if(!s_account_exists(account_name)) {
        return VTC_ERROR_NOT_FOUND;
    }

    account.vtc_account = (account_info_t *) malloc(sizeof(account_info_t));
    memset(account.vtc_account, 0, sizeof(account_info_t));

    err_code = s_account_get_by_name(&account, account_name);

    RET_CODE_SUCCESS(err_code);

    return vertices_mnemonic_from_sk(account.private_key, mnemonic_str);
}

VERTICES_EXPORT ret_code_t
vertices_mnemonic_from_sk(unsigned char *sk, char **mnemonic_str) {
    ret_code_t err_code;
    bytes recovered_seed;

    if(sodium_init() < 0) {
        LOG_ERROR("Sodium Library cannot be inited");
        return VTC_ERROR_INTERNAL;
    }

    recovered_seed.data = (unsigned char*)malloc(32 * sizeof(unsigned char));

    initialize_mnemonic();
    crypto_sign_ed25519_sk_to_seed(recovered_seed.data, sk);
    recovered_seed.size = 32;

    err_code = mnemonic_from_seed(recovered_seed, mnemonic_str);

    return err_code;
}



VERTICES_EXPORT ret_code_t
vertices_account_update(account_info_t *account)
{
    return account_update(account);
}

VERTICES_EXPORT ret_code_t
vertices_account_free(account_info_t *account)
{
    return account_free(account);
}

VERTICES_EXPORT ret_code_t
vertices_transaction_pay_new(account_info_t *account, char *receiver, uint64_t amount, void *params)
{
    return transaction_pay(account, receiver, amount, params);
}

VERTICES_EXPORT ret_code_t
vertices_transaction_asset_cfg(account_info_t *account, char *manager , char *reserve, char *freeze, char *clawback, uint64_t asset_id, uint64_t total, uint64_t decimals, bool isFrozen, void *unit_name, void *asset_name, void *url, void *params)
{
    return transaction_acfg(account, manager, reserve, freeze, clawback, asset_id, total, decimals, isFrozen, unit_name, asset_name, url, params);
}

VERTICES_EXPORT ret_code_t
vertices_transaction_asset_xfer(account_info_t *account, char *sender , char *receiver, uint64_t asset_id, double amount, void *params)
{
    return transaction_axfer(account, sender, receiver, asset_id, amount, params);
}

VERTICES_EXPORT ret_code_t
vertices_transaction_app_call(account_info_t *account, uint64_t app_id, void *params)
{
    return transaction_appl(account, app_id, params);
}

VERTICES_EXPORT ret_code_t
vertices_application_get(uint64_t app_id, app_values_t * global_states)
{
    return provider_application_info_get(app_id, global_states);
}

VERTICES_EXPORT ret_code_t
vertices_event_tx_get(size_t bufid, signed_transaction_t **tx)
{
    return transaction_get(bufid, tx);
}

static size_t
event_queue_size(void)
{
    return (m_events_queue.wr_index - m_events_queue.rd_index) & (VTC_EVENTS_COUNT - 1);
}

VERTICES_EXPORT ret_code_t
vertices_event_schedule(vtc_evt_t *evt)
{
    size_t next = (m_events_queue.wr_index + 1) % VTC_EVENTS_COUNT;
    if (next == m_events_queue.rd_index)
    {
        return VTC_ERROR_NO_MEM;
    }

    m_events_queue.evt[m_events_queue.wr_index].type = evt->type;
    m_events_queue.evt[m_events_queue.wr_index].bufid = evt->bufid;

    increment_event_index(m_events_queue.wr_index);

    return VTC_SUCCESS;
}

VERTICES_EXPORT ret_code_t
vertices_event_process(size_t * queue_size, unsigned char * txID)
{
    ret_code_t err_code = VTC_SUCCESS;

    if (event_queue_size() == 0)
    {
        if (queue_size != NULL)
        {
            *queue_size = event_queue_size();
        }
        return VTC_SUCCESS;
    }

    if (m_events_queue.rd_index != m_events_queue.wr_index)
    {
        // internal handling for action to be taken before the user
        switch (m_events_queue.evt[m_events_queue.rd_index].type)
        {
            case VTC_EVT_TX_READY_TO_SIGN:break;
            case VTC_EVT_TX_SENDING:
            {
                err_code =
                    transaction_pending_send(m_events_queue.evt[m_events_queue.rd_index].bufid);
                if(err_code > VTC_ERROR_HTTP_BASE) {
                    int response_code = err_code - VTC_ERROR_HTTP_BASE;
                    err_code = VTC_ERROR_HTTP_BASE;
                }
            }
                break;
            default:break;
        }

        if (err_code != VTC_SUCCESS)
        {
            LOG_ERROR("Pre-processing failed. Type: %u, Error: %x",
                      m_events_queue.evt[m_events_queue.rd_index].type,
                      err_code);
            return err_code;
        }

        // now let's have the user handle the event
        if (m_vertices_evt_handler != NULL)
        {
            err_code = m_vertices_evt_handler(&m_events_queue.evt[m_events_queue.rd_index]);

            if (err_code != VTC_SUCCESS)
            {
                LOG_ERROR("User-processing failed. Type: %u, Error: %x",
                          m_events_queue.evt[m_events_queue.rd_index].type,
                          err_code);
                return err_code;
            }
        }

        // internal handling for action to be taken after the user
        switch (m_events_queue.evt[m_events_queue.rd_index].type)
        {
            case VTC_EVT_TX_SUCCESS:
            {
                // txID handling after success
                signed_transaction_t *tx = NULL;
                transaction_get(m_events_queue.evt[m_events_queue.rd_index].bufid, &tx);
                memcpy(txID, tx->id, TRANSACTION_HASH_STR_MAX_LENGTH);

                err_code = transaction_free(m_events_queue.evt[m_events_queue.rd_index].bufid);
            }
                break;

            default:
                break;
        }

        if (err_code != VTC_SUCCESS)
        {
            LOG_ERROR("Post-processing failed. Type: %u, Error: %u",
                      m_events_queue.evt[m_events_queue.rd_index].type,
                      err_code);
            return err_code;
        }

        // successful processing, we can increment the read index
        increment_event_index(m_events_queue.rd_index);
    }

    if (queue_size != NULL)
    {
        *queue_size = event_queue_size();
    }

    return err_code;
}

VERTICES_EXPORT ret_code_t
vertices_new(vertex_t *config, bool withNewWallet)
{
    ret_code_t err_code;

    vertices_cache_clear();

    err_code = provider_init(config->provider);
    if (err_code != VTC_SUCCESS)
    {
        return err_code;
    }

    err_code = account_init();
    RET_CODE_SUCCESS(err_code);

    if(withNewWallet) {
        err_code = s_account_init();
        RET_CODE_SUCCESS(err_code);
    }

    m_vertices_evt_handler = config->vertices_evt_handler;

    return err_code;
}

VERTICES_EXPORT ret_code_t
vertices_cache_clear() {
    memset(&m_events_queue, 0, sizeof m_events_queue);
    provider_cache_clear();
    transaction_cache_clear();

    return VTC_SUCCESS;
}

VERTICES_EXPORT ret_code_t
vertices_wallet_init()
{
    return s_account_init();
}

VERTICES_EXPORT ret_code_t
vertices_s_account_init(const char *account_name)
{
    return s_account_init_by_name(account_name);
}

VERTICES_EXPORT bool
vertices_wallet_exists()
{
    return s_wallet_exists();
}

VERTICES_EXPORT ret_code_t
vertices_s_account_get_by_name(s_account_t *account, const char *account_name)
{
    return s_account_get_by_name(account, account_name);
}

VERTICES_EXPORT ret_code_t
vertices_s_accounts_all_get(s_account_t **accounts)
{
    return s_accounts_all_get(accounts);
}

VERTICES_EXPORT ret_code_t
vertices_s_account_update(s_account_t **account)
{
    return s_account_update(account);
}

VERTICES_EXPORT ret_code_t
vertices_wallet_load(const char *pw)
{
    ret_code_t err_code;

    err_code = s_account_init();
    RET_CODE_SUCCESS(err_code);

    return s_account_load(pw);
}

VERTICES_EXPORT ret_code_t
vertices_wallet_save(const char *pw)
{
    return s_account_save(pw);
}

VERTICES_EXPORT ret_code_t
vertices_wallet_free()
{
    return s_wallet_free();
}