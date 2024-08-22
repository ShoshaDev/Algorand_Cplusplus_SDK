/*
 * Copyright (c) 2021 Vertices Network <cyril@vertices.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vertices_errors.h>
#include <stdio.h>
#include <transaction.h>
#include <account.h>
#include <string.h>
#include "../include/provider.h"
#include <mpack.h>
#include <vertices_log.h>
#include <vertices.h>
#include <compilers.h>
#include <stdlib.h>

#define	htobe64(x)	((uint64_t)(x))

const char *algorand_tx_types[] = {"pay", "keyreg", "acfg", "axfer", "afrz", "appl"};

#define PENDING_TX_COUNT    4
static signed_transaction_t m_pending_tx_buffer[PENDING_TX_COUNT];
static size_t m_tx_buffer_idx = 0;

static ret_code_t
encode_tx_replace_signature(size_t bufid)
{
    ret_code_t err_code = VTC_ERROR_NOT_FOUND;

    // check that a payload is ready
    if (m_pending_tx_buffer[bufid].payload_body_length == 0)
    {
        return VTC_ERROR_INVALID_PARAM;
    }

    // let's find the location of the signature in the current payload
    // first we need to find a map
    // 'sig', 'msig' or 'lsig' followed by 64-byte signature
    // then the transaction, but we don't care about that part in that function
    mpack_reader_t reader;
    mpack_reader_init_data(&reader,
                           (const char *) m_pending_tx_buffer[bufid].payload,
                           m_pending_tx_buffer[bufid].payload_body_length);

    mpack_tag_t map_tag = mpack_read_tag(&reader);
    if (mpack_reader_error(&reader) == mpack_ok && mpack_tag_type(&map_tag) == mpack_type_map)
    {
        mpack_tag_t tag = mpack_read_tag(&reader);
        if (mpack_tag_type(&tag) == mpack_type_str)
        {
            // get the pointer to the beginning of the string tag
            uint32_t length = mpack_tag_str_length(&tag);
            const char *data = mpack_read_bytes_inplace(&reader, length);

            if (strncmp(data, "sig", length) == 0)
            {
                // get the pointer to the beginning of the signature
                mpack_tag_t signature_tag = mpack_read_tag(&reader);
                size_t len = mpack_tag_bin_length(&signature_tag);
                if (len == SIGNATURE_LENGTH)
                {
                    char *signature_ptr = (char *) mpack_read_bytes_inplace(&reader, len);
                    // replace the signature with the current one
                    memcpy(signature_ptr, (const void *) m_pending_tx_buffer[bufid].signature, len);
                    err_code = VTC_SUCCESS;
                }
            }
        }
    }

    return err_code;
}

static ret_code_t
encode_tx(transaction_t *tx)
{
    ret_code_t err_code = VTC_SUCCESS;
    const int8_t empty_sig[SIGNATURE_LENGTH] = {0};

    char *data = (char *) m_pending_tx_buffer[m_tx_buffer_idx].payload;
    size_t size = sizeof(m_pending_tx_buffer[m_tx_buffer_idx].payload);

    // encode to memory buffer
    mpack_writer_t writer;
    mpack_writer_init(&writer, (char *) data, size);

    mpack_start_map(&writer, 2);
    mpack_write_cstr(&writer, "sig");
    mpack_write_bin(&writer, (const char *) empty_sig, sizeof empty_sig);

    mpack_write_cstr(&writer, "txn");

    // from there, the payload is part of the signature body, we store the offset location
    m_pending_tx_buffer[m_tx_buffer_idx].payload_header_length = (size_t) (writer.current - writer.buffer);

    // minimum is 7 fields in header map
    // add some depending on `tx`
    uint32_t txn_map_element_count = 7;
    if (tx->details->tx_type == ALGORAND_PAYMENT_TRANSACTION)
    {
        txn_map_element_count += 2; // + receiver & amount
    }
    else if (tx->details->tx_type == ALGORAND_ASSET_CONFIGURATION_TRANSACTION)
    {
        txn_map_element_count ++; // + apar
        if(tx->details->tx.acfg.asset_id != 0) {
            txn_map_element_count ++; //  + caid
        }
    }
    else if (tx->details->tx_type == ALGORAND_ASSET_TRANSFER_TRANSACTION) {
        txn_map_element_count += 2; // xfer_asset, asset_amount, asset_sender, asset_receiver, asset_close_to
        if(tx->details->tx.axfer.amount != 0) {
            txn_map_element_count += 2;
        }
    }
    else if (tx->details->tx_type == ALGORAND_APPLICATION_CALL_TRANSACTION)
    {
        txn_map_element_count += 1; // + app ID

        if (tx->details->tx.appl.on_complete != 0)
        {
            txn_map_element_count += 1;
        }

        if (tx->details->tx.appl.key_values->count != 0)
        {
            txn_map_element_count += 1;
        }
    }

    if (tx->details->note != NULL)
    {
        txn_map_element_count += 1;
    }

    mpack_start_map(&writer, txn_map_element_count);

    if (tx->details->tx_type == ALGORAND_PAYMENT_TRANSACTION)
    {
        mpack_write_cstr(&writer, "amt");
        mpack_write_uint(&writer, tx->details->tx.pay.amount);
    }

    if(tx->details->tx_type == ALGORAND_ASSET_CONFIGURATION_TRANSACTION) {
        uint32_t asset_param_map_element_count = 9;
        if(tx->details->tx.acfg.isFrozen) {
            asset_param_map_element_count ++;
        }
        // optional asset params
        mpack_write_cstr(&writer, "apar");
        mpack_start_map(&writer, asset_param_map_element_count);
        /// an, au, c, dc, df, f, m,r, t, un
            mpack_write_cstr(&writer, "an");
            mpack_write_cstr(&writer, tx->details->tx.acfg.asset_name);

            mpack_write_cstr(&writer, "au");
            mpack_write_cstr(&writer, tx->details->tx.acfg.url);

            mpack_write_cstr(&writer, "c");
            mpack_write_bin(&writer, (const char*) tx->details->tx.acfg.clawback, ADDRESS_LENGTH);

            mpack_write_cstr(&writer, "dc");
            mpack_write_uint(&writer, tx->details->tx.acfg.decimals);

            if(tx->details->tx.acfg.isFrozen) {
                mpack_write_cstr(&writer, "df");
                mpack_write_true(&writer);
            }

            mpack_write_cstr(&writer, "f");
            mpack_write_bin(&writer, (const char*) tx->details->tx.acfg.freeze, ADDRESS_LENGTH);

            mpack_write_cstr(&writer, "m");
            mpack_write_bin(&writer, (const char*) tx->details->tx.acfg.manager, ADDRESS_LENGTH);

            mpack_write_cstr(&writer, "r");
            mpack_write_bin(&writer, (const char*) tx->details->tx.acfg.reserve, ADDRESS_LENGTH);

            mpack_write_cstr(&writer, "t");
            mpack_write_uint(&writer, tx->details->tx.acfg.total);

            mpack_write_cstr(&writer, "un");
            mpack_write_cstr(&writer, tx->details->tx.acfg.unit_name);

        mpack_finish_map(&writer);

        // config asset - caid - order depends on c++ context, not alphabetical order of algorand transaction
        if(tx->details->tx.acfg.asset_id != 0) {
            mpack_write_cstr(&writer, "caid");
            mpack_write_uint(&writer, tx->details->tx.acfg.asset_id);
        }
    }

    if(tx->details->tx_type == ALGORAND_ASSET_TRANSFER_TRANSACTION) {
        if(tx->details->tx.axfer.amount != 0) {
            mpack_write_cstr(&writer, "aamt");
            mpack_write_uint(&writer, tx->details->tx.axfer.amount);

//            mpack_write_cstr(&writer, "aclose");
//            mpack_write_bin(&writer, (const char*) tx->details->tx.axfer.closeTo, ADDRESS_LENGTH);
        }

        mpack_write_cstr(&writer, "arcv");
        mpack_write_bin(&writer, (const char*) tx->details->tx.axfer.receiver, ADDRESS_LENGTH);

        if(tx->details->tx.axfer.amount != 0) {
            mpack_write_cstr(&writer, "asnd");
            mpack_write_bin(&writer, (const char*) tx->details->tx.axfer.sender, ADDRESS_LENGTH);
        }
    }

    if (tx->details->tx_type == ALGORAND_APPLICATION_CALL_TRANSACTION)
    {
        // optional app arguments
        if (tx->details->tx.appl.key_values != NULL && tx->details->tx.appl.key_values->count != 0)
        {
            mpack_write_cstr(&writer, "apaa");

            mpack_start_array(&writer, tx->details->tx.appl.key_values->count);

            for (uint32_t i = 0; i < tx->details->tx.appl.key_values->count; ++i)
            {
                if (tx->details->tx.appl.key_values->values[i].type == VALUE_TYPE_INTEGER)
                {
                    uint64_t value = tx->details->tx.appl.key_values->values[i].value_uint;

                    // convert to big endian
#ifdef _WIN64 || _WIN32

                    value = _byteswap_uint64(value);
#else
                    value = htobe64(value);

#endif

                    mpack_write_bin(&writer,
                                    (const char *) &value,
                                    APPS_KV_SLICE_MAX_SIZE);
                }
                else if (tx->details->tx.appl.key_values->values[i].type == VALUE_TYPE_BYTESLICE)
                {
                    mpack_write_bin(&writer,
                                    (const char *) tx->details->tx.appl.key_values->values->value_slice,
                                    APPS_KV_SLICE_MAX_SIZE);
                }
                else
                {
                    LOG_ERROR("Unknown type to write: %u",
                              tx->details->tx.appl.key_values->values[i].type);
                }
            }

            mpack_finish_array(&writer);
        }

        if (tx->details->tx.appl.on_complete != 0)
        {
            mpack_write_str(&writer, "apan", 4);
            mpack_write_uint(&writer, (uint64_t) tx->details->tx.appl.on_complete);
        }

        mpack_write_cstr(&writer, "apid");
        mpack_write_uint(&writer, (uint64_t) tx->details->tx.appl.app_id);
    }

//    todo add support to close an account using the "pay" transaction, using field "close"
//    When set, it indicates that the transaction is requesting that the Sender account should be
//    closed, and all remaining funds, after the fee and amount are paid, be transferred to this
//    address.
//    if (tx->details->tx_type == ALGORAND_PAYMENT_TRANSACTION)
//    {
//    mpack_write_cstr(&writer, "close");
//    mpack_write_str(&writer, (const char *) tx->receiver_pub, sizeof tx->receiver_pub);
//    }

    mpack_write_cstr(&writer, "fee");
    mpack_write_uint(&writer, tx->fee);

    mpack_write_cstr(&writer, "fv");
    mpack_write_uint(&writer, tx->details->first_valid);

    mpack_write_cstr(&writer, "gen");
    mpack_write_str(&writer, (const char *) "testnet-v1.0", sizeof "testnet-v1.0" - 1);

    mpack_write_cstr(&writer, "gh");
    mpack_write_bin(&writer, (const char *) tx->genesis_hash, sizeof tx->genesis_hash);

    mpack_write_cstr(&writer, "lv");
    mpack_write_uint(&writer, tx->details->last_valid);

    if (tx->details->note != NULL)
    {
        mpack_write_cstr(&writer, "note");
        mpack_write_bin(&writer, tx->details->note, (uint32_t) strlen(tx->details->note));
    }

    if (tx->details->tx_type == ALGORAND_PAYMENT_TRANSACTION)
    {
        mpack_write_cstr(&writer, "rcv");
        mpack_write_bin(&writer,
                        (const char *) tx->details->tx.pay.receiver,
                        sizeof tx->details->tx.pay.receiver);
    }

    mpack_write_cstr(&writer, "snd");
    mpack_write_bin(&writer, (const char *) tx->sender_pub, sizeof tx->sender_pub);

    mpack_write_cstr(&writer, "type");
    mpack_write_cstr(&writer, algorand_tx_types[tx->details->tx_type]);

    if(tx->details->tx_type == ALGORAND_ASSET_TRANSFER_TRANSACTION) {
        mpack_write_cstr(&writer, "xaid");
        mpack_write_uint(&writer, tx->details->tx.axfer.asset_id);
    }

    mpack_finish_map(&writer); // finished "txn" map
    mpack_finish_map(&writer); // finished root map

    size = mpack_writer_buffer_used(&writer);
    m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length =
        size - m_pending_tx_buffer[m_tx_buffer_idx].payload_header_length;

    LOG_DEBUG("mpack used %u bytes to encode tx", (unsigned int)size);  // bug fixing
//    LOG_DEBUG("mpack used %u bytes to encode tx", size);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok)
    {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return VTC_ERROR_INTERNAL;
    }

    return err_code;
}

ret_code_t
transaction_pay(account_info_t *sender, char *receiver, uint64_t amount, void *params)
{
    ret_code_t err_code;

    if (m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length != 0)
    {
        return VTC_ERROR_NO_MEM;
    }

    // check params are correct
    if (params != NULL)
    {
        if (strlen((const char *) params) > OPTIONAL_TX_FIELDS_MAX_SIZE_BYTES)
        {
            // consider using more bytes for each transaction by setting a larger value to
            // OPTIONAL_TX_FIELDS_MAX_SIZE
            LOG_ERROR("Unable to store params");
            return VTC_ERROR_INVALID_PARAM;
        }
    }

    m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length =
        sizeof m_pending_tx_buffer[m_tx_buffer_idx].payload;

    // instantiate transaction
    transaction_details_t details = {0};
    transaction_t tx_full = {0};
    tx_full.details = &details;

    // fill generic transaction_t
    memcpy(tx_full.sender_pub, sender->public_key, sizeof(tx_full.sender_pub));

    tx_full.fee = TX_DEFAULT_FEE;
    tx_full.details->tx_type = ALGORAND_PAYMENT_TRANSACTION;
    tx_full.details->note = (char *) params;

    tx_full.details->tx.pay.amount = amount;

    memcpy(tx_full.details->tx.pay.receiver,
           receiver,
           sizeof(tx_full.details->tx.pay.receiver));

    // get provider details
    err_code = provider_tx_params_load(&tx_full);
    if (err_code != VTC_SUCCESS && err_code != VTC_ERROR_OFFLINE)
    {
        LOG_ERROR("Cannot fetch tx params");
        return err_code;
    }

    // tx is now ready to be encoded
    err_code = encode_tx(&tx_full);
    VTC_ASSERT(err_code);

    vtc_evt_t evt = {.type = VTC_EVT_TX_READY_TO_SIGN, .bufid = m_tx_buffer_idx};

    // m_tx_buffer_idx spot is now taken, push index
    m_tx_buffer_idx = (m_tx_buffer_idx + 1) % PENDING_TX_COUNT;

    // push event for asynchronous operation
    err_code = vertices_event_schedule(&evt);

    return err_code;
}

ret_code_t
transaction_acfg(account_info_t *account, char *manager , char *reserve, char *freeze, char *clawback, uint64_t asset_id, uint64_t total, uint64_t decimals, bool isFrozen, void *unit_name, void *asset_name, void *url, void *params) {
    ret_code_t err_code;

    if (m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length != 0)
    {
        return VTC_ERROR_NO_MEM;
    }

    // check params are correct
    if (params != NULL)
    {
        if (strlen((const char *) params) > OPTIONAL_TX_FIELDS_MAX_SIZE_BYTES)
        {
            // consider using more bytes for each transaction by setting a larger value to
            // OPTIONAL_TX_FIELDS_MAX_SIZE
            LOG_ERROR("Unable to store params");
            return VTC_ERROR_INVALID_PARAM;
        }
    }

    // check asset url are correct
    if (url != NULL)
    {
        if (strlen((const char *) url) > OPTIONAL_TX_FIELDS_MAX_SIZE_BYTES)
        {
            // consider using more bytes for each transaction by setting a larger value to
            // OPTIONAL_TX_FIELDS_MAX_SIZE
            LOG_ERROR("Unable to store url");
            return VTC_ERROR_INVALID_PARAM;
        }
    }

    if (unit_name == NULL || asset_name == NULL)
    {
        LOG_ERROR("Unable to store unit and asset name because their value hasn't been given");
        return VTC_ERROR_INVALID_PARAM;
    }

    // check unit and asset name are correct
    if (strlen((const char *) unit_name) == 0 || strlen((const char *) asset_name) == 0)
    {
        LOG_ERROR("Unable to store unit or asset name because invalid value been given");
        return VTC_ERROR_INVALID_PARAM;
    }

    // check when decimals is bigger than 19
    if (decimals > 19)
    {
        LOG_ERROR("Unable to store decimals because its value is bigger than 19");
        return VTC_ERROR_INVALID_PARAM;
    }

    m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length =
            sizeof m_pending_tx_buffer[m_tx_buffer_idx].payload;

    // instantiate transaction
    transaction_details_t details = {0};
    transaction_t tx_full = {0};
    tx_full.details = &details;

    // fill generic transaction_t
    memcpy(tx_full.sender_pub, account->public_key, sizeof(tx_full.sender_pub));

    tx_full.fee = TX_DEFAULT_FEE;
    tx_full.details->tx_type = ALGORAND_ASSET_CONFIGURATION_TRANSACTION;
    tx_full.details->note = (char *) params;

    tx_full.details->tx.acfg.asset_id = asset_id;
    tx_full.details->tx.acfg.total = total;
    tx_full.details->tx.acfg.isFrozen = isFrozen;
    tx_full.details->tx.acfg.decimals = decimals;
    tx_full.details->tx.acfg.url = (char *) url;
    tx_full.details->tx.acfg.asset_name = (char *) asset_name;
    tx_full.details->tx.acfg.unit_name = (char *) unit_name;

    memcpy(tx_full.details->tx.acfg.manager,
           manager,
           sizeof(tx_full.details->tx.acfg.manager));

    memcpy(tx_full.details->tx.acfg.reserve,
           reserve,
           sizeof(tx_full.details->tx.acfg.reserve));

    memcpy(tx_full.details->tx.acfg.freeze,
           freeze,
           sizeof(tx_full.details->tx.acfg.freeze));

    memcpy(tx_full.details->tx.acfg.clawback,
           clawback,
           sizeof(tx_full.details->tx.acfg.clawback));

    // get provider details
    err_code = provider_tx_params_load(&tx_full);
    if (err_code != VTC_SUCCESS && err_code != VTC_ERROR_OFFLINE)
    {
        LOG_ERROR("Cannot fetch tx params");
        return err_code;
    }

    // tx is now ready to be encoded
    err_code = encode_tx(&tx_full);
    VTC_ASSERT(err_code);

    vtc_evt_t evt = {.type = VTC_EVT_TX_READY_TO_SIGN, .bufid = m_tx_buffer_idx};

    // m_tx_buffer_idx spot is now taken, push index
    m_tx_buffer_idx = (m_tx_buffer_idx + 1) % PENDING_TX_COUNT;

    // push event for asynchronous operation
    err_code = vertices_event_schedule(&evt);

    return err_code;
}

ret_code_t
transaction_axfer(account_info_t *account, char *sender , char *receiver, uint64_t asset_id, double amount, void *params) {
    ret_code_t err_code;

    if (m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length != 0)
    {
        return VTC_ERROR_NO_MEM;
    }

    // check params are correct
    if (params != NULL)
    {
        if (strlen((const char *) params) > OPTIONAL_TX_FIELDS_MAX_SIZE_BYTES)
        {
            // consider using more bytes for each transaction by setting a larger value to
            // OPTIONAL_TX_FIELDS_MAX_SIZE
            LOG_ERROR("Unable to store params");
            return VTC_ERROR_INVALID_PARAM;
        }
    }

    m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length =
            sizeof m_pending_tx_buffer[m_tx_buffer_idx].payload;

    // instantiate transaction
    transaction_details_t details = {0};
    transaction_t tx_full = {0};
    tx_full.details = &details;

    // fill generic transaction_t
    memcpy(tx_full.sender_pub, account->public_key, sizeof(tx_full.sender_pub));

    tx_full.fee = TX_DEFAULT_FEE;
    tx_full.details->tx_type = ALGORAND_ASSET_TRANSFER_TRANSACTION;
    tx_full.details->note = (char *) params;

    tx_full.details->tx.axfer.asset_id = asset_id;
    tx_full.details->tx.axfer.amount = amount;

    if(sender != NULL) {
        memcpy(tx_full.details->tx.axfer.sender,
               sender,
               sizeof(tx_full.details->tx.axfer.sender));
    }

    memcpy(tx_full.details->tx.axfer.receiver,
           receiver,
           sizeof(tx_full.details->tx.axfer.receiver));

    // get provider details
    err_code = provider_tx_params_load(&tx_full);
    if (err_code != VTC_SUCCESS && err_code != VTC_ERROR_OFFLINE)
    {
        LOG_ERROR("Cannot fetch tx params");
        return err_code;
    }

    // tx is now ready to be encoded
    err_code = encode_tx(&tx_full);
    VTC_ASSERT(err_code);

    vtc_evt_t evt = {.type = VTC_EVT_TX_READY_TO_SIGN, .bufid = m_tx_buffer_idx};

    // m_tx_buffer_idx spot is now taken, push index
    m_tx_buffer_idx = (m_tx_buffer_idx + 1) % PENDING_TX_COUNT;

    // push event for asynchronous operation
    err_code = vertices_event_schedule(&evt);

    return err_code;
}

ret_code_t
transaction_appl(account_info_t *sender,
                 uint64_t app_id,
                 void *params)
{
    ret_code_t err_code;

    if (m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length != 0)
    {
        return VTC_ERROR_NO_MEM;
    }

    m_pending_tx_buffer[m_tx_buffer_idx].payload_body_length =
        sizeof m_pending_tx_buffer[m_tx_buffer_idx].payload;

    // instantiate transaction
    transaction_details_t details = {0};
    transaction_t tx_full = {0};
    tx_full.details = &details;

    // fill generic transaction_t
    memcpy(tx_full.sender_pub, sender->public_key, sizeof(tx_full.sender_pub));

    tx_full.fee = TX_DEFAULT_FEE;
    tx_full.details->tx_type = ALGORAND_APPLICATION_CALL_TRANSACTION;

    // TODO handle notes in app calls
    // tx_full.details->note = (char *);

    tx_full.details->tx.appl.app_id = app_id;
    tx_full.details->tx.appl.key_values = (app_values_t *) params;

    if (!account_has_app(sender, app_id))
    {
        LOG_INFO("Sender account opting-in application %llu", (long long unsigned int)app_id);

        tx_full.details->tx.appl.on_complete = ALGORAND_ON_COMPLETE_OPT_IN;
    }

    // get provider details
    err_code = provider_tx_params_load(&tx_full);
    if (err_code != VTC_SUCCESS && err_code != VTC_ERROR_OFFLINE)
    {
        LOG_ERROR("Cannot fetch tx params");
        return err_code;
    }

    // tx is now ready to be encoded
    err_code = encode_tx(&tx_full);
    if (err_code != VTC_SUCCESS)
    {
        LOG_ERROR("Cannot encode tx");
        return err_code;
    }

    vtc_evt_t evt = {.type = VTC_EVT_TX_READY_TO_SIGN, .bufid = m_tx_buffer_idx};

    // m_tx_buffer_idx spot is now taken, push index
    m_tx_buffer_idx = (m_tx_buffer_idx + 1) % PENDING_TX_COUNT;

    // push event for asynchronous operation
    err_code = vertices_event_schedule(&evt);
    if (err_code != VTC_SUCCESS)
    {
        LOG_ERROR("Cannot schedule event");
        return err_code;
    }

    return err_code;
}

ret_code_t
transaction_get(size_t bufid, signed_transaction_t **tx)
{
    if (m_pending_tx_buffer[bufid].payload_body_length == 0)
    {
        return VTC_ERROR_INVALID_PARAM;
    }

    *tx = &m_pending_tx_buffer[bufid];

    return VTC_SUCCESS;
}

ret_code_t
transaction_free(size_t bufid)
{
    if (m_pending_tx_buffer[bufid].payload_body_length == 0)
    {
        return VTC_ERROR_INVALID_PARAM;
    }

    memset(&m_pending_tx_buffer[bufid], 0, sizeof(signed_transaction_t));

    return VTC_SUCCESS;
}

ret_code_t
transaction_cache_clear() {
    m_tx_buffer_idx = 0;

    for(int i = 0; i < PENDING_TX_COUNT; i++) {
        transaction_free(i);
    }
    return VTC_SUCCESS;
}

ret_code_t
transaction_pending_send(size_t bufid)
{
    if (m_pending_tx_buffer[bufid].payload_body_length == 0)
    {
        return VTC_ERROR_INVALID_PARAM;
    }

    ret_code_t err_code;

    err_code = encode_tx_replace_signature(bufid);
    VTC_ASSERT(err_code);

    size_t payload_len = m_pending_tx_buffer[bufid].payload_body_length
        + m_pending_tx_buffer[bufid].payload_header_length;
    err_code = provider_tx_post(m_pending_tx_buffer[bufid].payload,
                                payload_len, m_pending_tx_buffer[bufid].id);

    // transaction has been executed, free up spot
    if (err_code == VTC_SUCCESS)
    {
        vtc_evt_t evt = {.type = VTC_EVT_TX_SUCCESS, .bufid = bufid};

        LOG_INFO("🧾 Transaction executed, ID: %s", m_pending_tx_buffer[bufid].id);

        // push event for asynchronous operation
        vertices_event_schedule(&evt);
    }

    return err_code;
}
