/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#include "els_psa_selftest.h"

#include <psa/crypto.h>
#include <zephyr/logging/log.h>

#include <string.h>

LOG_MODULE_REGISTER(els_psa_selftest, LOG_LEVEL_INF);

static int test_aes_gcm(void)
{
    static const uint8_t key[16] = {0};
    static const uint8_t nonce[12] = {0};
    static const uint8_t plaintext[16] = {0};
    static const uint8_t expected[32] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t encrypted[sizeof(expected)];
    uint8_t decrypted[sizeof(plaintext)];
    size_t encrypted_length = 0;
    size_t decrypted_length = 0;
    psa_status_t status;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

    status = psa_import_key(&attributes, key, sizeof(key), &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA AES key import failed: %d", status);
        return -1;
    }

    status = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                              nonce, sizeof(nonce),
                              NULL, 0,
                              plaintext, sizeof(plaintext),
                              encrypted, sizeof(encrypted),
                              &encrypted_length);
    if (status != PSA_SUCCESS || encrypted_length != sizeof(expected) ||
        memcmp(encrypted, expected, sizeof(expected)) != 0) {
        LOG_ERR("ELS PSA AES-GCM encryption self-test failed: %d", status);
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                              nonce, sizeof(nonce),
                              NULL, 0,
                              encrypted, encrypted_length,
                              decrypted, sizeof(decrypted),
                              &decrypted_length);
    if (status != PSA_SUCCESS || decrypted_length != sizeof(plaintext) ||
        memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
        LOG_ERR("ELS PSA AES-GCM decryption self-test failed: %d", status);
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA AES key cleanup failed: %d", status);
        return -1;
    }

    LOG_INF("ELS PSA AES-128-GCM hardware self-test PASS");
    return 0;
}

static int test_sha256(void)
{
    static const uint8_t message[] = {'a', 'b', 'c'};
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t hash[sizeof(expected)];
    size_t hash_length = 0;
    psa_status_t status;

    status = psa_hash_compute(PSA_ALG_SHA_256,
                              message, sizeof(message),
                              hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS || hash_length != sizeof(expected) ||
        memcmp(hash, expected, sizeof(expected)) != 0) {
        LOG_ERR("ELS/PKC PSA SHA-256 self-test failed: %d", status);
        return -1;
    }

    LOG_INF("ELS/PKC PSA SHA-256 self-test PASS");
    return 0;
}

static int test_aes_cmac(void)
{
    static const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    static const uint8_t message[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    static const uint8_t expected[16] = {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
    };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t mac[sizeof(expected)];
    size_t mac_length = 0;
    psa_status_t status;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);

    status = psa_import_key(&attributes, key, sizeof(key), &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA CMAC key import failed: %d", status);
        return -1;
    }

    status = psa_mac_compute(key_id, PSA_ALG_CMAC,
                             message, sizeof(message),
                             mac, sizeof(mac), &mac_length);
    if (status != PSA_SUCCESS || mac_length != sizeof(expected) ||
        memcmp(mac, expected, sizeof(expected)) != 0) {
        LOG_ERR("ELS/PKC PSA AES-CMAC self-test failed: %d", status);
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA CMAC key cleanup failed: %d", status);
        return -1;
    }

    LOG_INF("ELS/PKC PSA AES-CMAC self-test PASS");
    return 0;
}

static int test_ecdh_p256(void)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_a = PSA_KEY_ID_NULL;
    psa_key_id_t key_b = PSA_KEY_ID_NULL;
    uint8_t public_a[65];
    uint8_t public_b[65];
    uint8_t shared_a[32];
    uint8_t shared_b[32];
    size_t public_a_length = 0;
    size_t public_b_length = 0;
    size_t shared_a_length = 0;
    size_t shared_b_length = 0;
    psa_status_t status;
    int result = -1;

    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

    status = psa_generate_key(&attributes, &key_a);
    if (status != PSA_SUCCESS) {
        LOG_ERR("ELS/PKC PSA ECDH key A generation failed: %d", status);
        goto cleanup;
    }

    status = psa_generate_key(&attributes, &key_b);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        LOG_ERR("ELS/PKC PSA ECDH key B generation failed: %d", status);
        goto cleanup;
    }

    status = psa_export_public_key(key_a, public_a, sizeof(public_a),
                                   &public_a_length);
    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA ECDH public key A export failed: %d", status);
        goto cleanup;
    }

    status = psa_export_public_key(key_b, public_b, sizeof(public_b),
                                   &public_b_length);
    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA ECDH public key B export failed: %d", status);
        goto cleanup;
    }

    status = psa_raw_key_agreement(PSA_ALG_ECDH, key_a,
                                   public_b, public_b_length,
                                   shared_a, sizeof(shared_a),
                                   &shared_a_length);
    if (status != PSA_SUCCESS) {
        LOG_ERR("ELS/PKC PSA ECDH agreement A failed: %d", status);
        goto cleanup;
    }

    status = psa_raw_key_agreement(PSA_ALG_ECDH, key_b,
                                   public_a, public_a_length,
                                   shared_b, sizeof(shared_b),
                                   &shared_b_length);
    if (status != PSA_SUCCESS || shared_a_length != sizeof(shared_a) ||
        shared_b_length != shared_a_length ||
        memcmp(shared_a, shared_b, shared_a_length) != 0) {
        LOG_ERR("ELS/PKC PSA ECDH shared-secret self-test failed: %d", status);
        goto cleanup;
    }

    LOG_INF("ELS/PKC PSA P-256 ECDH self-test PASS");
    result = 0;

cleanup:
    psa_reset_key_attributes(&attributes);
    if (key_a != PSA_KEY_ID_NULL) {
        psa_destroy_key(key_a);
    }
    if (key_b != PSA_KEY_ID_NULL) {
        psa_destroy_key(key_b);
    }
    return result;
}

static int test_ecdsa_p256(void)
{
    static const uint8_t hash[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    const psa_algorithm_t algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    uint8_t signature[64];
    size_t signature_length = 0;
    psa_status_t status;

    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, algorithm);

    status = psa_generate_key(&attributes, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        LOG_ERR("ELS/PKC PSA ECDSA key generation failed: %d", status);
        return -1;
    }

    status = psa_sign_hash(key_id, algorithm,
                           hash, sizeof(hash),
                           signature, sizeof(signature), &signature_length);
    if (status != PSA_SUCCESS) {
        LOG_ERR("ELS/PKC PSA ECDSA signing failed: %d", status);
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_verify_hash(key_id, algorithm,
                             hash, sizeof(hash),
                             signature, signature_length);
    if (status != PSA_SUCCESS) {
        LOG_ERR("ELS/PKC PSA ECDSA verification failed: %d", status);
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA ECDSA key cleanup failed: %d", status);
        return -1;
    }

    LOG_INF("ELS/PKC PSA P-256 ECDSA sign/verify self-test PASS");
    return 0;
}

int els_psa_selftest(void)
{
    psa_status_t status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        LOG_ERR("PSA initialization failed: %d", status);
        return -1;
    }

    if (test_aes_gcm() != 0 ||
        test_sha256() != 0 ||
        test_aes_cmac() != 0 ||
        test_ecdh_p256() != 0 ||
        test_ecdsa_p256() != 0) {
        LOG_ERR("ELS/PKC PSA full-profile self-test FAILED");
        return -1;
    }

    LOG_INF("ELS/PKC PSA full-profile self-test: ALL PASS");
    return 0;
}
