/*
 * Copyright (c) 2021 Vertices Network <cyril@vertices.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "vertices.h"
#include <vertices_log.h>
#include <unix_config.h>
#include <cstring>
#include <sodium.h>
#include "utils/base64.h"
#include "http_weak.h"
#include "../vertices_ports/http_curl.cpp"

typedef enum {
    PAY_TX = 0,
    ACFG_TX,
    AXFER_TX,
    APP_CALL_TX
} tx_type_t;

typedef enum {
    CREATE_RANDOM_ACC = 0,
    CREATE_MNEMONIC_ACC,
    GET_MNEMONIC,
} acc_type_t;

typedef union {
    acc_type_t acc_type;
    tx_type_t tx_type;
} action_type_t;

typedef enum {
    ACC_TYPE = 0,
    TX_TYPE
} action_kind_t;

typedef struct {
    action_kind_t kind;
    action_type_t action;
} action_t;

static ret_code_t
vertices_evt_handler(vtc_evt_t *evt);

static provider_info_t providers;

// Alice's account is used to send data, keys will be retrived from config/key_files.txt
static s_account_t alice_account;
// Bob is receiving the money 😎
static s_account_t bob_account;

// accounts for aseet config tx
static s_account_t manager_account;
static s_account_t reserve_account;
static s_account_t freeze_account;
static s_account_t clawback_account;


static vertex_t m_vertex;

static ret_code_t
vertices_evt_handler(vtc_evt_t *evt) {
    ret_code_t err_code = VTC_SUCCESS;

    switch (evt->type) {
        case VTC_EVT_TX_READY_TO_SIGN: {
            signed_transaction_t *tx = nullptr;
            err_code = vertices_event_tx_get(evt->bufid, &tx);
            if (err_code == VTC_SUCCESS) {
                LOG_DEBUG("About to sign tx: data length %zu", tx->payload_body_length);

                // libsodium wants to have private and public keys concatenated
                unsigned char keys[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
                memcpy(keys, bob_account.private_key, sizeof(bob_account.private_key));
                memcpy(&keys[32],
                       bob_account.vtc_account->public_key,
                       ADDRESS_LENGTH);

                // prepend "TX" to the payload before signing
                unsigned char *to_be_signed;
                to_be_signed = (unsigned char*) malloc(tx->payload_body_length + 2);
                memset(to_be_signed, 0, tx->payload_body_length + 2);
                to_be_signed[0] = 'T';
                to_be_signed[1] = 'X';

                // copy body
                memcpy(&to_be_signed[2],
                       &tx->payload[tx->payload_header_length],
                       tx->payload_body_length);

                // sign the payload
                crypto_sign_ed25519_detached(tx->signature,
                                             nullptr, to_be_signed, tx->payload_body_length + 2, keys);

                char b64_signature[128] = {0};
                size_t b64_signature_len = sizeof(b64_signature);
                b64_encode((const char *) tx->signature,
                           sizeof(tx->signature),
                           b64_signature,
                           &b64_signature_len);
                LOG_DEBUG("Signature %s (%zu bytes)", b64_signature, b64_signature_len);

                // send event to send the signed TX
                vtc_evt_t sched_evt;
                sched_evt.type = VTC_EVT_TX_SENDING;
                sched_evt.bufid = evt->bufid;
                err_code = vertices_event_schedule(&sched_evt);
            }
        }
            break;

        case VTC_EVT_TX_SENDING: {
            // let's create transaction files which can then be used with `goal clerk ...`
            signed_transaction_t *tx = nullptr;
            err_code = vertices_event_tx_get(evt->bufid, &tx);

            FILE *fstx = fopen(CONFIG_PATH "../signed_tx.bin", "wb");

            if (fstx == nullptr) {
                return VTC_ERROR_NOT_FOUND;
            }

            fwrite(tx->payload, tx->payload_header_length + tx->payload_body_length, 1, fstx);
            fclose(fstx);

            FILE *ftx = fopen(CONFIG_PATH "../tx.bin", "wb");

            if (ftx == nullptr) {
                return VTC_ERROR_NOT_FOUND;
            }

            // goal-generated transaction files are packed into a map of one element: `txn`.
            // the one-element map takes 4 bytes into our message packed payload <=> `txn`
            // we also add the `map` type before
            // which results in 5-bytes to be added before the payload at `payload_offset`
            char *payload;
            payload = (char *) malloc(tx->payload_body_length + 5);
            memset(payload, 0, tx->payload_body_length + 5);
            payload[0] = (char) 0x81; // starting flag for map of one element
            memcpy(&payload[1],
                   &tx->payload[tx->payload_header_length - 4],
                   tx->payload_body_length + 4);

            fwrite(payload, sizeof payload, 1, ftx);
            fclose(ftx);
        }
            break;

        default:
            break;
    }

    return err_code;
}

/// Create new random account
/// Account keys will be stored in files
static ret_code_t
create_new_account() {
    ret_code_t err_code;

    unsigned char seed[crypto_sign_ed25519_SEEDBYTES] = {0};
    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];

    LOG_WARNING("🧾 Creating new random account and storing it (path " CONFIG_PATH ")");

    unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
    randombytes_buf(seed, sizeof(seed));

    crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk, seed);

    memcpy(alice_account.private_key, ed25519_sk, sizeof(alice_account.private_key));

    FILE *fw_priv = fopen(CONFIG_PATH "private_key.bin", "wb");
    if (fw_priv == nullptr) {
        LOG_ERROR("Cannot create " CONFIG_PATH "private_key.bin");
        return VTC_ERROR_NOT_FOUND;
    } else {
        fwrite(ed25519_sk, 1, ADDRESS_LENGTH, fw_priv);
        fclose(fw_priv);
    }

    // adding account, account address will be computed from binary public key
    err_code = vertices_account_new_from_bin((char *) ed25519_pk, &alice_account.vtc_account);
    VTC_ASSERT(err_code);

    // we can now store the b32 address in a file
    FILE *fw_pub = fopen(CONFIG_PATH "public_b32.txt", "w");
    if (fw_pub != nullptr) {
        size_t len = strlen(alice_account.vtc_account->public_b32);

        fwrite(alice_account.vtc_account->public_b32, 1, len, fw_pub);
        fwrite("\n", 1, 1, fw_pub);
        fclose(fw_pub);
    }

    return err_code;
}

/// Source the account using private/public keys from files.
/// \return \c VTC_ERROR_NOT_FOUND account not found
static ret_code_t
load_existing_account() {
    ret_code_t err_code;

    char public_b32[PUBLIC_B32_STR_MAX_LENGTH] = {0};

    size_t bytes_read = 0;

    // we either create a new random account or load it from private and public key files.
    // key files can also be generated using [`algokey`](https://developer.algorand.org/docs/reference/cli/algokey/generate/)
    FILE *f_priv = fopen(CONFIG_PATH "private_key.bin", "rb");
    if (f_priv != nullptr) {
        LOG_INFO("🔑 Loading private key from: %s", CONFIG_PATH "private_key.bin");

        bytes_read = fread(alice_account.private_key, 1, ADDRESS_LENGTH, f_priv);
        fclose(f_priv);
    }

    if (f_priv == nullptr || bytes_read != ADDRESS_LENGTH) {
        LOG_WARNING(
                "🤔 private_key.bin does not exist or keys not found. You can pass the -n flag to create a new account");

        return VTC_ERROR_NOT_FOUND;
    }

    FILE *f_pub = fopen(CONFIG_PATH "public_b32.txt", "r");
    if (f_pub != nullptr) {
        LOG_INFO("🔑 Loading public key from: %s", CONFIG_PATH "public_b32.txt");

        bytes_read = fread(public_b32, 1, PUBLIC_B32_STR_MAX_LENGTH, f_pub);
        fclose(f_pub);

        size_t len = strlen(public_b32);
        while (public_b32[len - 1] == '\n' || public_b32[len - 1] == '\r') {
            public_b32[len - 1] = '\0';
            len--;
        }
    }

    if (f_pub == nullptr || bytes_read < ADDRESS_LENGTH) {
        LOG_WARNING(
                "🤔 public_b32.txt does not exist or keys not found. You can pass the -n flag to create a new account");

        return VTC_ERROR_NOT_FOUND;
    }

    err_code = vertices_account_new_from_b32(public_b32, &alice_account.vtc_account);
    VTC_ASSERT(err_code);

    LOG_INFO("💳 Created Alice's account: %s", alice_account.vtc_account->public_b32);

    return VTC_SUCCESS;
}

static ret_code_t
init_provider() {
    // Init providers
    providers.algod_url = (char *) SERVER_NODE_URL;
    providers.indexer_url = (char *) SERVER_INDEXER_URL;
    providers.port = SERVER_PORT;
    providers.header = (char *) SERVER_TOKEN_HEADER;

    m_vertex.provider = &providers;
    m_vertex.vertices_evt_handler = vertices_evt_handler;
    return VTC_SUCCESS;
}

static ret_code_t
init_account(s_account_t *account) {
    memset(account->private_key, 0, ADDRESS_LENGTH);
    account->vtc_account = nullptr;
    return VTC_SUCCESS;
}

static ret_code_t
init_accounts(action_t run_action) {
    // Init Accounts Alice & Bob
    init_account(&alice_account);
    init_account(&bob_account);

    if(run_action.kind == TX_TYPE && ( run_action.action.tx_type == ACFG_TX || run_action.action.tx_type == AXFER_TX )) {
        init_account(&manager_account);
        init_account(&reserve_account);
        init_account(&freeze_account);
        init_account(&clawback_account);
    }
    return VTC_SUCCESS;
}

static ret_code_t
load_wallet(action_t run_action) {
    ret_code_t err_code = vertices_wallet_load((const char *) WALLET_PASSWORD);
    if(err_code != VTC_SUCCESS) {
        LOG_WARNING("😎 Vertices SDK Wallet can't be loaded");
    }

    if(run_action.kind == ACC_TYPE && run_action.action.acc_type != GET_MNEMONIC) {
        err_code = vertices_s_account_init((const char*) ALICE_NAME);
    }

    const int ACCOUNT_COUNT = 5;
    s_account_t *all_accounts;
    all_accounts = (s_account_t *) malloc(sizeof (s_account_t) * ACCOUNT_COUNT);
    err_code = vertices_s_accounts_all_get(&all_accounts);
    VTC_ASSERT(err_code);

    size_t i = 0;
    for (i = 0; i < ACCOUNT_COUNT; ++i)
    {
        if (all_accounts[i].status == ACCOUNT_ADDED)
        {
            LOG_INFO("👛 Discovered secret account : %s --- %s", all_accounts[i].vtc_account->public_b32, all_accounts[i].name);
        }
    }

    return err_code;
}

static ret_code_t
vertex_health() {
    // making sure the provider is accessible
    ret_code_t err_code = vertices_ping();
    VTC_ASSERT(err_code);

    // ask for provider version
    provider_version_t version = {0};
    err_code = vertices_version(&version);
    if (err_code == VTC_ERROR_OFFLINE) {
        LOG_WARNING("Version might not be accurate: old value is being used");
    } else {
        VTC_ASSERT(err_code);
    }

    LOG_INFO("🏎 Running on %s v.%u.%u.%u",
             version.network,
             version.major,
             version.minor,
             version.patch);

    return err_code;
}

static ret_code_t
check_atomic_balance(s_account_t *account) {
    LOG_INFO("🤑 %f Algos on this account (%s)",
             account->vtc_account->amount / 1.e6,
             account->vtc_account->public_b32);

    if (account->vtc_account->amount < 1001000) {
        LOG_ERROR(
                "🙄 Amount available on account is too low to pass a transaction, consider adding Algos");
        LOG_INFO("👉 Go to https://bank.testnet.algorand.network/, dispense Algos to: %s",
                 account->vtc_account->public_b32);
        LOG_INFO("😎 Then wait for a few seconds for transaction to pass...");
        return VTC_ERROR_INVALID_STATE;
    }

    return VTC_SUCCESS;
}

static ret_code_t
load_account_by_addr(char *acc_name, s_account_t *account) {
    ret_code_t err_code = vertices_account_new_from_b32(acc_name, &account->vtc_account);
    return err_code;
}

static ret_code_t
load_config_accounts(action_t run_action) {
    ret_code_t err_code = vertices_account_init();
    VTC_ASSERT(err_code);
//
//    load_account_by_addr((char *) ACCOUNT_RECEIVER, &bob_account);

    if(run_action.kind == TX_TYPE && ( run_action.action.tx_type == ACFG_TX) || run_action.action.tx_type == AXFER_TX) {
        load_account_by_addr((char *) ACCOUNT_MANAGER, &manager_account);
        load_account_by_addr((char *) ACCOUNT_RESERVE, &reserve_account);
        load_account_by_addr((char *) ACCOUNT_FREEZE, &freeze_account);
        load_account_by_addr((char *) ACCOUNT_CLAWBACK, &clawback_account);
    }

    return VTC_SUCCESS;
}

static ret_code_t
account_free(s_account_t *account) {
    ret_code_t err_code = vertices_account_free(bob_account.vtc_account);
    VTC_ASSERT(err_code);
    return err_code;
}

int
main(int argc, char *argv[]) {
    ret_code_t err_code;

    action_t run_tx;
    run_tx.kind = TX_TYPE;
    run_tx.action.tx_type = AXFER_TX;

    // init provider
    init_provider();

    // init accounts for processing transaction
    init_accounts(run_tx);

    int ret = sodium_init();
    VTC_ASSERT_BOOL(ret == 0);

    // create new vertex
    err_code = vertices_new(&m_vertex);
    VTC_ASSERT(err_code);

    // load vertices wallet
    err_code = load_wallet(run_tx);
    VTC_ASSERT(err_code);

    // check health of vertex net
    err_code = vertex_health();
    VTC_ASSERT(err_code);

    LOG_INFO("😎 Vertices SDK running on Unix-based OS");

    if(run_tx.kind == TX_TYPE) {
        // get alice_account from wallet
        err_code = vertices_s_account_get_by_name(&alice_account, (const char*) ALICE_NAME);
        if(err_code == VTC_ERROR_NOT_FOUND) {
            printf("account doesn't exist: %s\n", (const char*) ALICE_NAME);
            VTC_ASSERT(err_code);
        }

        err_code = vertices_s_account_get_by_name(&bob_account, (const char*) BOB_NAME);
        if(err_code == VTC_ERROR_NOT_FOUND) {
            printf("account doesn't exist: %s\n", (const char*) BOB_NAME);
            VTC_ASSERT(err_code);
        }

        load_config_accounts(run_tx);
    }

    if(run_tx.kind == ACC_TYPE) {
        switch (run_tx.action.acc_type) {
            case CREATE_RANDOM_ACC: {
                err_code = vertices_s_account_new_random(&alice_account);
                VTC_ASSERT(err_code);
                err_code = vertices_s_account_new_random(&bob_account);
                VTC_ASSERT(err_code);
                // Test mnemonic from account
                char *mnemonic;
                err_code = vertices_mnemonic_from_sk(alice_account.private_key, &mnemonic);
                VTC_ASSERT(err_code);
                printf("mnemonics of a random account: %s\n", mnemonic);
                err_code = vertices_mnemonic_from_sk(bob_account.private_key, &mnemonic);
                VTC_ASSERT(err_code);
                printf("mnemonics of a random account: %s\n", mnemonic);
                break;
            }

            case CREATE_MNEMONIC_ACC: {
                char *mnemonic_str = "rally relief lucky maple primary chair syrup economy tired hurdle slot upset clever chest curve bitter weekend prepare movie letter lamp alert then able taste";  // base giraffe believe make tone transfer wrap attend typical dirt grocery distance outside horn also abstract slim ecology island alter daring equal boil absent carpet
                err_code = vertices_s_account_new_from_mnemonic(mnemonic_str, &alice_account, (const char*) ALICE_NAME);
                VTC_ASSERT(err_code);
                mnemonic_str = "base giraffe believe make tone transfer wrap attend typical dirt grocery distance outside horn also abstract slim ecology island alter daring equal boil absent carpet";
                err_code = vertices_s_account_new_from_mnemonic(mnemonic_str, &bob_account, (const char*) BOB_NAME);
                VTC_ASSERT(err_code);
                // Test mnemonic from account
                char *mnemonic;
                err_code = vertices_mnemonic_from_account((const char *) ALICE_NAME, &mnemonic);
                VTC_ASSERT(err_code);
                printf("mnemonic of %s account : ->%s\n", (const char *) ALICE_NAME, mnemonic);
                err_code = vertices_mnemonic_from_account((const char *) BOB_NAME, &mnemonic);
                VTC_ASSERT(err_code);
                printf("mnemonic of %s account : ->%s\n", (const char *) BOB_NAME, mnemonic);
                break;
            }

            case GET_MNEMONIC: {
                VTC_ASSERT(err_code);
                break;
            }
        }
    } else {
        switch (run_tx.action.tx_type) {
            case PAY_TX: {
                // send assets from account 0 to account 1
                char *notes = (char *) "Alice sent 1 Algo to Bob";
                err_code =
                        vertices_transaction_pay_new(alice_account.vtc_account,
                                                     (char *) bob_account.vtc_account->public_key /* or ACCOUNT_RECEIVER Public Key */,
                                                     AMOUNT_SENT,
                                                     notes);
                VTC_ASSERT(err_code);
            }
                break;

            case ACFG_TX: {
                char *notes = (char *) "Create a new asset";
                err_code =
                        vertices_transaction_asset_cfg(alice_account.vtc_account,
                                                       (char *) alice_account.vtc_account->public_key, // (char *) manager_account.vtc_account->public_key,
                                                       (char *) reserve_account.vtc_account->public_key,
                                                       (char *) freeze_account.vtc_account->public_key,
                                                       (char *) alice_account.vtc_account->public_key,
                                                       0,
                                                       10000,
                                                       8,
                                                       true,
                                                       (void *) "USD",
                                                       (void *) "SHOSHA",
                                                       (void *) "http://this.test.com",
                                                       notes
                                                       );
                VTC_ASSERT(err_code);
                break;
            }

            case AXFER_TX: {
                // For transferring asset, enable below function work
//                char *notes = (char *) "Transfer an algorand asset";
//                err_code =
//                        vertices_transaction_asset_xfer(alice_account.vtc_account,
//                                                        (char *) alice_account.vtc_account->public_key,
//                                                        (char *) bob_account.vtc_account->public_key,
//                                                        715553268,      // 715550315, 715530013
//                                                        200,
//                                                        notes
//                                                        );

                // For opt-in tx, enable below function work
                // change alice_account to bob_account when tx is signed
                char *notes = (char *) "Create an Opt-In transaction";
                err_code =
                        vertices_transaction_asset_xfer(bob_account.vtc_account,
                                                        (char *) bob_account.vtc_account->public_key,
                                                        (char *) bob_account.vtc_account->public_key,
                                                        715553268,      // 715550315, 715530013
                                                        0,
                                                        notes
                        );
                VTC_ASSERT(err_code);
                break;
            }

            case APP_CALL_TX: {
                // get application information
                LOG_INFO("Application %u, global states", APP_ID);

                app_values_t app_kv = {0};
                err_code = vertices_application_get(APP_ID, &app_kv);
                VTC_ASSERT(err_code);
                for (uint32_t i = 0; i < app_kv.count; ++i) {
                    if (app_kv.values[i].type == VALUE_TYPE_INTEGER) {
                        LOG_INFO("%s: %llu", app_kv.values[i].name, (long long unsigned) app_kv.values[i].value_uint);
                    } else if (app_kv.values[i].type == VALUE_TYPE_BYTESLICE) {
                        LOG_INFO("%s: %s", app_kv.values[i].name, app_kv.values[i].value_slice);
                    }
                }

                // send application call
                app_values_t kv = {0};
                kv.count = 1;
                kv.values[0].type = VALUE_TYPE_INTEGER;
                kv.values[0].value_uint = 32;

                err_code = vertices_transaction_app_call(alice_account.vtc_account, APP_ID, &kv);
                VTC_ASSERT(err_code);
            }
                break;

            default:
                LOG_ERROR("Unknown action to run");
        }

        unsigned char *txID = nullptr;
        txID = new unsigned char[TRANSACTION_HASH_STR_MAX_LENGTH];

        // processing
        size_t queue_size = 1;
        while (queue_size && err_code == VTC_SUCCESS) {
            err_code = vertices_event_process(&queue_size, txID);
            VTC_ASSERT(err_code);
        }

        if(err_code == VTC_SUCCESS)
        {
            LOG_INFO("👉 Haha This is transaction ID: %s",txID);
        }

        free(txID);
    }

    vertices_wallet_save((const char*) WALLET_PASSWORD);

    // delete the created secret accounts from the Vertices wallet
    err_code = vertices_wallet_free();
    VTC_ASSERT(err_code);
}
