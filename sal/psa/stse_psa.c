/*!
 ******************************************************************************
 * \file    stse_psa.c
 * \brief   STSE PSA Crypto adaptation layer (source)
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2024 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include "sal/psa/stse_psa.h"

/* -------------------------------------------------------------------------- */
/* Module-level context (single instance)                                      */
/* -------------------------------------------------------------------------- */

static stse_psa_ctx_t _stse_psa_ctx;

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

/**
 * \brief  Map a PSA algorithm identifier to an STSE hash algorithm.
 * \return \ref STSE_OK on success; \ref STSE_API_INVALID_PARAMETER otherwise.
 */
static stse_ReturnCode_t _stse_psa_alg_to_hash(stse_psa_algorithm_t   alg,
                                                stse_hash_algorithm_t *pAlgo)
{
    stse_psa_algorithm_t hash_id;

    /* If this is an ECDSA compound algorithm (0x066006xx), extract embedded hash */
    if ((alg & 0xFFFFFF00U) == 0x06000600U) {
        /* Reconstruct standalone hash identifier from embedded byte */
        hash_id = 0x02000000U | (alg & 0xFFU);
    } else {
        hash_id = alg;
    }

    switch (hash_id) {
#ifdef STSE_CONF_HASH_SHA_256
        case 0x02000009U: /* STSE_PSA_ALG_SHA_256 */
            *pAlgo = STSE_SHA_256;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_384
        case 0x0200000AU: /* STSE_PSA_ALG_SHA_384 */
            *pAlgo = STSE_SHA_384;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_512
        case 0x0200000BU: /* STSE_PSA_ALG_SHA_512 */
            *pAlgo = STSE_SHA_512;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_256
        case 0x02000011U: /* STSE_PSA_ALG_SHA3_256 (PSA H=0x11) */
            *pAlgo = STSE_SHA3_256;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_384
        case 0x02000012U: /* STSE_PSA_ALG_SHA3_384 (PSA H=0x12) */
            *pAlgo = STSE_SHA3_384;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_512
        case 0x02000013U: /* STSE_PSA_ALG_SHA3_512 (PSA H=0x13) */
            *pAlgo = STSE_SHA3_512;
            break;
#endif
        default:
            return STSE_API_INVALID_PARAMETER;
    }

    return STSE_OK;
}

/**
 * \brief  Look up an entry in the key table by \p key_id.
 * \return Pointer to the key context, or NULL if not found.
 */
static stse_psa_key_context_t *_stse_psa_find_key(stse_psa_key_id_t key_id)
{
    PLAT_UI8 i;

    for (i = 0U; i < STSE_PSA_MAX_KEYS; i++) {
        if (_stse_psa_ctx.keys[i].in_use && (_stse_psa_ctx.keys[i].id == key_id)) {
            return &_stse_psa_ctx.keys[i];
        }
    }

    return NULL;
}

/**
 * \brief  Allocate a free entry in the key table.
 * \return Pointer to the free entry, or NULL if the table is full.
 */
static stse_psa_key_context_t *_stse_psa_alloc_key(void)
{
    PLAT_UI8 i;

    for (i = 0U; i < STSE_PSA_MAX_KEYS; i++) {
        if (!_stse_psa_ctx.keys[i].in_use) {
            return &_stse_psa_ctx.keys[i];
        }
    }

    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

stse_psa_status_t stse_psa_crypto_init(stse_Handler_t *pSTSE)
{
    PLAT_UI8 i;

    if (pSTSE == NULL) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    _stse_psa_ctx.pSTSE       = pSTSE;
    _stse_psa_ctx.initialized = 1U;

    for (i = 0U; i < STSE_PSA_MAX_KEYS; i++) {
        _stse_psa_ctx.keys[i].in_use = 0U;
    }

    return STSE_PSA_SUCCESS;
}

stse_psa_status_t stse_psa_generate_key(const stse_psa_key_attributes_t *pAttributes,
                                         stse_ecc_key_type_t               ecc_type,
                                         PLAT_UI16                         usage_limit,
                                         PLAT_UI8                         *pPublicKey)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;
    PLAT_UI8                 stse_slot;
    PLAT_UI8                 pub_key_buf[STSE_PSA_MAX_PUBLIC_KEY_SIZE];
    PLAT_UI8                *pub_key_dst;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if (pAttributes == NULL) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (_stse_psa_find_key(pAttributes->id) != NULL) {
        /* Key ID already registered */
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_alloc_key();
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    stse_slot   = STSE_PSA_KEY_ID_GET_SLOT(pAttributes->id);
    pub_key_dst = (pPublicKey != NULL) ? pPublicKey : pub_key_buf;

    ret = stse_generate_ecc_key_pair(_stse_psa_ctx.pSTSE,
                                     stse_slot,
                                     ecc_type,
                                     usage_limit,
                                     pub_key_dst);

    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_HARDWARE_FAILURE;
    }

    pKeyCtx->in_use      = 1U;
    pKeyCtx->id          = pAttributes->id;
    pKeyCtx->type        = pAttributes->type;
    pKeyCtx->alg         = pAttributes->alg;
    pKeyCtx->usage       = pAttributes->usage;
    pKeyCtx->stse_slot   = stse_slot;
    pKeyCtx->ecc_type    = ecc_type;

#if (STSE_PSA_SPEC_VERSION >= 12)
    pKeyCtx->lifetime = pAttributes->lifetime;
#endif

    /* Cache the public key using the correct STSE key size from the info table */
    pKeyCtx->pub_key_len = (PLAT_UI8)stse_ecc_info_table[ecc_type].public_key_size;
    if (pKeyCtx->pub_key_len > STSE_PSA_MAX_PUBLIC_KEY_SIZE) {
        pKeyCtx->pub_key_len = STSE_PSA_MAX_PUBLIC_KEY_SIZE;
    }

    PLAT_UI8 i;
    for (i = 0U; i < pKeyCtx->pub_key_len; i++) {
        pKeyCtx->pub_key[i] = pub_key_dst[i];
    }

    return STSE_PSA_SUCCESS;
}

stse_psa_status_t stse_psa_destroy_key(stse_psa_key_id_t key_id)
{
    stse_psa_key_context_t *pKeyCtx;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
#if (STSE_PSA_SPEC_VERSION >= 12)
        return STSE_PSA_ERROR_DOES_NOT_EXIST;
#else
        return STSE_PSA_ERROR_INVALID_HANDLE;
#endif
    }

    pKeyCtx->in_use = 0U;

    return STSE_PSA_SUCCESS;
}

stse_psa_status_t stse_psa_export_public_key(stse_psa_key_id_t  key_id,
                                              PLAT_UI8          *pData,
                                              PLAT_UI32          data_size,
                                              PLAT_UI32         *pData_len)
{
    stse_psa_key_context_t *pKeyCtx;
    PLAT_UI8                i;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pData == NULL) || (pData_len == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    if (pKeyCtx->pub_key_len == 0U) {
        /* Public key was not cached at generation time */
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    if (data_size < (PLAT_UI32)pKeyCtx->pub_key_len) {
        return STSE_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    for (i = 0U; i < pKeyCtx->pub_key_len; i++) {
        pData[i] = pKeyCtx->pub_key[i];
    }

    *pData_len = (PLAT_UI32)pKeyCtx->pub_key_len;

    return STSE_PSA_SUCCESS;
}

stse_psa_status_t stse_psa_sign_hash(stse_psa_key_id_t   key_id,
                                      stse_psa_algorithm_t alg,
                                      const PLAT_UI8      *pHash,
                                      PLAT_UI32            hash_length,
                                      PLAT_UI8            *pSignature,
                                      PLAT_UI32            sig_size,
                                      PLAT_UI32           *pSig_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;

    (void)alg;      /* algorithm is derived from key context */
    (void)sig_size; /* size assumed sufficient by caller */

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pHash == NULL) || (pSignature == NULL) || (pSig_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    ret = stse_ecc_generate_signature(_stse_psa_ctx.pSTSE,
                                      pKeyCtx->stse_slot,
                                      pKeyCtx->ecc_type,
                                      (PLAT_UI8 *)pHash,
                                      (PLAT_UI16)hash_length,
                                      pSignature);

    if (ret == STSE_OK) {
        *pSig_length = (PLAT_UI32)stse_ecc_info_table[pKeyCtx->ecc_type].signature_size;
        return STSE_PSA_SUCCESS;
    }

    return STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_sign_message(stse_psa_key_id_t   key_id,
                                         stse_psa_algorithm_t alg,
                                         const PLAT_UI8      *pMessage,
                                         PLAT_UI32            msg_length,
                                         PLAT_UI8            *pSignature,
                                         PLAT_UI32            sig_size,
                                         PLAT_UI32           *pSig_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;
    stse_hash_algorithm_t    hash_algo;
    PLAT_UI8                 digest[64];  /* max digest size (SHA-512) */
    PLAT_UI16                digest_len = (PLAT_UI16)sizeof(digest);

    (void)sig_size;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pMessage == NULL) || (pSignature == NULL) || (pSig_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    /* Extract hash algorithm from the compound PSA algorithm identifier */
    ret = _stse_psa_alg_to_hash(alg, &hash_algo);
    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    /* Step 1: hash the message on the STSE */
    ret = stse_compute_hash(_stse_psa_ctx.pSTSE,
                            hash_algo,
                            (PLAT_UI8 *)pMessage,
                            (PLAT_UI16)msg_length,
                            digest,
                            &digest_len);
    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Step 2: sign the digest */
    ret = stse_ecc_generate_signature(_stse_psa_ctx.pSTSE,
                                      pKeyCtx->stse_slot,
                                      pKeyCtx->ecc_type,
                                      digest,
                                      digest_len,
                                      pSignature);
    if (ret == STSE_OK) {
        *pSig_length = (PLAT_UI32)stse_ecc_info_table[pKeyCtx->ecc_type].signature_size;
        return STSE_PSA_SUCCESS;
    }

    return STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_verify_hash(stse_psa_key_id_t   key_id,
                                        stse_psa_algorithm_t alg,
                                        const PLAT_UI8      *pPublicKey,
                                        PLAT_UI32            pub_key_length,
                                        const PLAT_UI8      *pHash,
                                        PLAT_UI32            hash_length,
                                        const PLAT_UI8      *pSignature,
                                        PLAT_UI32            sig_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;
    PLAT_UI8                 validity = 0U;

    (void)alg;
    (void)pub_key_length;
    (void)sig_length;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pPublicKey == NULL) || (pHash == NULL) || (pSignature == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    ret = stse_ecc_verify_signature(_stse_psa_ctx.pSTSE,
                                    pKeyCtx->ecc_type,
                                    (PLAT_UI8 *)pPublicKey,
                                    (PLAT_UI8 *)pSignature,
                                    (PLAT_UI8 *)pHash,
                                    (PLAT_UI16)hash_length,
                                    0U,
                                    &validity);

    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_HARDWARE_FAILURE;
    }

    return (validity != 0U) ? STSE_PSA_SUCCESS : STSE_PSA_ERROR_INVALID_SIGNATURE;
}

stse_psa_status_t stse_psa_verify_message(stse_psa_key_id_t   key_id,
                                           stse_psa_algorithm_t alg,
                                           const PLAT_UI8      *pPublicKey,
                                           PLAT_UI32            pub_key_length,
                                           const PLAT_UI8      *pMessage,
                                           PLAT_UI32            msg_length,
                                           const PLAT_UI8      *pSignature,
                                           PLAT_UI32            sig_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;
    stse_hash_algorithm_t    hash_algo;
    PLAT_UI8                 digest[64];
    PLAT_UI16                digest_len = (PLAT_UI16)sizeof(digest);
    PLAT_UI8                 validity   = 0U;

    (void)pub_key_length;
    (void)sig_length;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pPublicKey == NULL) || (pMessage == NULL) || (pSignature == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    ret = _stse_psa_alg_to_hash(alg, &hash_algo);
    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    /* Step 1: hash the message */
    ret = stse_compute_hash(_stse_psa_ctx.pSTSE,
                            hash_algo,
                            (PLAT_UI8 *)pMessage,
                            (PLAT_UI16)msg_length,
                            digest,
                            &digest_len);
    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Step 2: verify the signature over the digest */
    ret = stse_ecc_verify_signature(_stse_psa_ctx.pSTSE,
                                    pKeyCtx->ecc_type,
                                    (PLAT_UI8 *)pPublicKey,
                                    (PLAT_UI8 *)pSignature,
                                    digest,
                                    digest_len,
                                    0U,
                                    &validity);

    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_HARDWARE_FAILURE;
    }

    return (validity != 0U) ? STSE_PSA_SUCCESS : STSE_PSA_ERROR_INVALID_SIGNATURE;
}

stse_psa_status_t stse_psa_hash_compute(stse_psa_algorithm_t  alg,
                                         const PLAT_UI8       *pInput,
                                         PLAT_UI32             input_length,
                                         PLAT_UI8             *pHash,
                                         PLAT_UI32             hash_size,
                                         PLAT_UI32            *pHash_length)
{
    stse_ReturnCode_t     ret;
    stse_hash_algorithm_t hash_algo;
    PLAT_UI16             digest_len;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pInput == NULL) || (pHash == NULL) || (pHash_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = _stse_psa_alg_to_hash(alg, &hash_algo);
    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    digest_len = (PLAT_UI16)hash_size;

    ret = stse_compute_hash(_stse_psa_ctx.pSTSE,
                            hash_algo,
                            (PLAT_UI8 *)pInput,
                            (PLAT_UI16)input_length,
                            pHash,
                            &digest_len);

    if (ret == STSE_OK) {
        *pHash_length = (PLAT_UI32)digest_len;
        return STSE_PSA_SUCCESS;
    }

    return STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_hash_setup(stse_psa_hash_operation_t *pOperation,
                                       stse_psa_algorithm_t       alg)
{
    stse_ReturnCode_t     ret;
    stse_hash_algorithm_t hash_algo;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if (pOperation == NULL) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = _stse_psa_alg_to_hash(alg, &hash_algo);
    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    pOperation->alg          = alg;
    pOperation->stse_algo    = hash_algo;
    pOperation->active       = 1U;
    pOperation->hash_started = 0U;

    return STSE_PSA_SUCCESS;
}

stse_psa_status_t stse_psa_hash_update(stse_psa_hash_operation_t *pOperation,
                                        const PLAT_UI8            *pInput,
                                        PLAT_UI32                  input_length)
{
    stse_ReturnCode_t ret;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pOperation == NULL) || (pInput == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!pOperation->active) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if (!pOperation->hash_started) {
        ret = stse_start_hash(_stse_psa_ctx.pSTSE,
                              pOperation->stse_algo,
                              (PLAT_UI8 *)pInput,
                              (PLAT_UI16)input_length);
        if (ret == STSE_OK) {
            pOperation->hash_started = 1U;
        }
    } else {
        ret = stse_process_hash(_stse_psa_ctx.pSTSE,
                                (PLAT_UI8 *)pInput,
                                (PLAT_UI16)input_length);
    }

    return (ret == STSE_OK) ? STSE_PSA_SUCCESS : STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_hash_finish(stse_psa_hash_operation_t *pOperation,
                                        PLAT_UI8                  *pHash,
                                        PLAT_UI32                  hash_size,
                                        PLAT_UI32                 *pHash_length)
{
    stse_ReturnCode_t ret;
    PLAT_UI16         digest_len;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pOperation == NULL) || (pHash == NULL) || (pHash_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!pOperation->active || !pOperation->hash_started) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    digest_len = (PLAT_UI16)hash_size;

    ret = stse_finish_hash(_stse_psa_ctx.pSTSE,
                           pOperation->stse_algo,
                           NULL,
                           0U,
                           pHash,
                           &digest_len);

    if (ret == STSE_OK) {
        *pHash_length         = (PLAT_UI32)digest_len;
        pOperation->active    = 0U;
        pOperation->hash_started = 0U;
        return STSE_PSA_SUCCESS;
    }

    return STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_mac_compute(stse_psa_key_id_t    key_id,
                                        stse_psa_algorithm_t alg,
                                        const PLAT_UI8      *pInput,
                                        PLAT_UI32            input_length,
                                        PLAT_UI8            *pMac,
                                        PLAT_UI32            mac_size,
                                        PLAT_UI32           *pMac_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pInput == NULL) || (pMac == NULL) || (pMac_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    if (alg != STSE_PSA_ALG_CMAC) {
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    ret = stse_cmac_hmac_compute(_stse_psa_ctx.pSTSE,
                                 pKeyCtx->stse_slot,
                                 (PLAT_UI8 *)pInput,
                                 (PLAT_UI8)input_length,
                                 pMac,
                                 (PLAT_UI8)mac_size);

    if (ret == STSE_OK) {
        *pMac_length = mac_size;
        return STSE_PSA_SUCCESS;
    }

    return STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_mac_verify(stse_psa_key_id_t    key_id,
                                       stse_psa_algorithm_t alg,
                                       const PLAT_UI8      *pInput,
                                       PLAT_UI32            input_length,
                                       const PLAT_UI8      *pMac,
                                       PLAT_UI32            mac_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;
    PLAT_UI8                 verify_result = 0U;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pInput == NULL) || (pMac == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    if (alg != STSE_PSA_ALG_CMAC) {
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    ret = stse_cmac_hmac_verify(_stse_psa_ctx.pSTSE,
                                pKeyCtx->stse_slot,
                                (PLAT_UI8 *)pMac,
                                (PLAT_UI8)mac_length,
                                (PLAT_UI8 *)pInput,
                                (PLAT_UI8)input_length,
                                &verify_result);

    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_HARDWARE_FAILURE;
    }

    return (verify_result != 0U) ? STSE_PSA_SUCCESS : STSE_PSA_ERROR_INVALID_SIGNATURE;
}

stse_psa_status_t stse_psa_aead_encrypt(stse_psa_key_id_t   key_id,
                                         stse_psa_algorithm_t alg,
                                         const PLAT_UI8      *pNonce,
                                         PLAT_UI32            nonce_length,
                                         const PLAT_UI8      *pAdditionalData,
                                         PLAT_UI32            aad_length,
                                         const PLAT_UI8      *pPlaintext,
                                         PLAT_UI32            plaintext_length,
                                         PLAT_UI8            *pCiphertext,
                                         PLAT_UI32            ciphertext_size,
                                         PLAT_UI32           *pCiphertext_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;
    PLAT_UI8                 tag_len     = 16U; /* default tag size */
    PLAT_UI8                 dummy_ctr_p = 0U;
    PLAT_UI32                dummy_ctr   = 0U;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pNonce == NULL) || (pPlaintext == NULL) ||
        (pCiphertext == NULL) || (pCiphertext_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    (void)ciphertext_size;

    switch (alg) {
        case STSE_PSA_ALG_CCM:
            ret = stse_aes_ccm_encrypt(_stse_psa_ctx.pSTSE,
                                       pKeyCtx->stse_slot,
                                       tag_len,
                                       (PLAT_UI8 *)pNonce,
                                       (PLAT_UI16)aad_length,
                                       (PLAT_UI8 *)pAdditionalData,
                                       (PLAT_UI16)plaintext_length,
                                       (PLAT_UI8 *)pPlaintext,
                                       pCiphertext,
                                       pCiphertext + plaintext_length,
                                       dummy_ctr_p,
                                       &dummy_ctr);
            if (ret == STSE_OK) {
                *pCiphertext_length = plaintext_length + (PLAT_UI32)tag_len;
            }
            break;

        case STSE_PSA_ALG_GCM:
            ret = stse_aes_gcm_encrypt(_stse_psa_ctx.pSTSE,
                                       pKeyCtx->stse_slot,
                                       tag_len,
                                       (PLAT_UI16)nonce_length,
                                       (PLAT_UI8 *)pNonce,
                                       (PLAT_UI16)aad_length,
                                       (PLAT_UI8 *)pAdditionalData,
                                       (PLAT_UI16)plaintext_length,
                                       (PLAT_UI8 *)pPlaintext,
                                       pCiphertext,
                                       pCiphertext + plaintext_length);
            if (ret == STSE_OK) {
                *pCiphertext_length = plaintext_length + (PLAT_UI32)tag_len;
            }
            break;

        default:
            return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    return (ret == STSE_OK) ? STSE_PSA_SUCCESS : STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_aead_decrypt(stse_psa_key_id_t   key_id,
                                         stse_psa_algorithm_t alg,
                                         const PLAT_UI8      *pNonce,
                                         PLAT_UI32            nonce_length,
                                         const PLAT_UI8      *pAdditionalData,
                                         PLAT_UI32            aad_length,
                                         const PLAT_UI8      *pCiphertext,
                                         PLAT_UI32            ciphertext_length,
                                         PLAT_UI8            *pPlaintext,
                                         PLAT_UI32            plaintext_size,
                                         PLAT_UI32           *pPlaintext_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;
    PLAT_UI8                 tag_len      = 16U;
    PLAT_UI32                ct_len;
    PLAT_UI8                 verify_result = 0U;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pNonce == NULL) || (pCiphertext == NULL) ||
        (pPlaintext == NULL) || (pPlaintext_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    ct_len = ciphertext_length - (PLAT_UI32)tag_len;

    (void)plaintext_size;

    switch (alg) {
        case STSE_PSA_ALG_CCM:
            ret = stse_aes_ccm_decrypt(_stse_psa_ctx.pSTSE,
                                       pKeyCtx->stse_slot,
                                       tag_len,
                                       (PLAT_UI8 *)pNonce,
                                       (PLAT_UI16)aad_length,
                                       (PLAT_UI8 *)pAdditionalData,
                                       (PLAT_UI16)ct_len,
                                       (PLAT_UI8 *)pCiphertext,
                                       (PLAT_UI8 *)pCiphertext + ct_len,
                                       &verify_result,
                                       pPlaintext);
            break;

        case STSE_PSA_ALG_GCM:
            ret = stse_aes_gcm_decrypt(_stse_psa_ctx.pSTSE,
                                       pKeyCtx->stse_slot,
                                       tag_len,
                                       (PLAT_UI16)nonce_length,
                                       (PLAT_UI8 *)pNonce,
                                       (PLAT_UI16)aad_length,
                                       (PLAT_UI8 *)pAdditionalData,
                                       (PLAT_UI16)ct_len,
                                       (PLAT_UI8 *)pCiphertext,
                                       (PLAT_UI8 *)pCiphertext + ct_len,
                                       &verify_result,
                                       pPlaintext);
            break;

        default:
            return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    if (ret != STSE_OK) {
        return STSE_PSA_ERROR_HARDWARE_FAILURE;
    }

    if (verify_result == 0U) {
        return STSE_PSA_ERROR_INVALID_SIGNATURE;
    }

    *pPlaintext_length = ct_len;

    return STSE_PSA_SUCCESS;
}

stse_psa_status_t stse_psa_raw_key_agreement(stse_psa_key_id_t   key_id,
                                              stse_psa_algorithm_t alg,
                                              const PLAT_UI8      *pPeerKey,
                                              PLAT_UI32            peer_key_length,
                                              PLAT_UI8            *pOutput,
                                              PLAT_UI32            output_size,
                                              PLAT_UI32           *pOutput_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;

    (void)peer_key_length;
    (void)output_size;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if ((pPeerKey == NULL) || (pOutput == NULL) || (pOutput_length == NULL)) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (alg != STSE_PSA_ALG_ECDH) {
        return STSE_PSA_ERROR_NOT_SUPPORTED;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    ret = stse_ecc_establish_shared_secret(_stse_psa_ctx.pSTSE,
                                           pKeyCtx->stse_slot,
                                           pKeyCtx->ecc_type,
                                           (PLAT_UI8 *)pPeerKey,
                                           pOutput);

    if (ret == STSE_OK) {
        *pOutput_length = (PLAT_UI32)stse_ecc_info_table[pKeyCtx->ecc_type].shared_secret_size;
        return STSE_PSA_SUCCESS;
    }

    return STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_generate_random(PLAT_UI8 *pOutput, PLAT_UI32 output_size)
{
    stse_ReturnCode_t ret;

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if (pOutput == NULL) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = stse_generate_random(_stse_psa_ctx.pSTSE, pOutput, (PLAT_UI16)output_size);

    return (ret == STSE_OK) ? STSE_PSA_SUCCESS : STSE_PSA_ERROR_HARDWARE_FAILURE;
}

stse_psa_status_t stse_psa_key_derivation_output_bytes(stse_psa_key_id_t   key_id,
                                                        stse_psa_algorithm_t alg,
                                                        const PLAT_UI8      *pSalt,
                                                        PLAT_UI32            salt_length,
                                                        const PLAT_UI8      *pInfo,
                                                        PLAT_UI32            info_length,
                                                        PLAT_UI8            *pOutput,
                                                        PLAT_UI32            output_length)
{
    stse_psa_key_context_t *pKeyCtx;
    stse_ReturnCode_t        ret;

    (void)alg; /* HKDF algorithm; the STSE derive_key handles internally */

    if (!_stse_psa_ctx.initialized) {
        return STSE_PSA_ERROR_BAD_STATE;
    }

    if (pOutput == NULL) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pKeyCtx = _stse_psa_find_key(key_id);
    if (pKeyCtx == NULL) {
        return STSE_PSA_ERROR_INVALID_HANDLE;
    }

    ret = stse_derive_key(_stse_psa_ctx.pSTSE,
                          pKeyCtx->stse_slot,
                          (PLAT_UI8 *)pSalt,
                          (PLAT_UI16)salt_length,
                          (PLAT_UI8 *)pInfo,
                          (PLAT_UI16)info_length,
                          pOutput,
                          (PLAT_UI16)output_length);

    return (ret == STSE_OK) ? STSE_PSA_SUCCESS : STSE_PSA_ERROR_HARDWARE_FAILURE;
}

/* -------------------------------------------------------------------------- */
/* PSA 1.3+ PAKE operation stubs                                              */
/* -------------------------------------------------------------------------- */

#if (STSE_PSA_SPEC_VERSION >= 13)

stse_psa_status_t stse_psa_pake_setup(stse_psa_pake_operation_t *pOperation,
                                       stse_psa_key_id_t          key_id,
                                       stse_psa_algorithm_t       alg)
{
    (void)key_id;

    if (pOperation == NULL) {
        return STSE_PSA_ERROR_INVALID_ARGUMENT;
    }

    pOperation->active = 0U;
    pOperation->alg    = alg;

    /* PAKE is not supported by the STSE device */
    return STSE_PSA_ERROR_NOT_SUPPORTED;
}

stse_psa_status_t stse_psa_pake_abort(stse_psa_pake_operation_t *pOperation)
{
    if (pOperation != NULL) {
        pOperation->active = 0U;
    }

    return STSE_PSA_SUCCESS;
}

#endif /* STSE_PSA_SPEC_VERSION >= 13 */

/* -------------------------------------------------------------------------- */
/* PSA 1.4+ post-quantum operation stubs                                      */
/* -------------------------------------------------------------------------- */

#if (STSE_PSA_SPEC_VERSION >= 14)

stse_psa_status_t stse_psa_kem_encapsulate(stse_psa_key_id_t   key_id,
                                            stse_psa_algorithm_t alg,
                                            PLAT_UI8            *pCiphertext,
                                            PLAT_UI32            ciphertext_size,
                                            PLAT_UI32           *pCiphertext_length,
                                            PLAT_UI8            *pSharedSecret,
                                            PLAT_UI32            shared_secret_size,
                                            PLAT_UI32           *pSharedSecret_length)
{
    (void)key_id;
    (void)alg;
    (void)pCiphertext;
    (void)ciphertext_size;
    (void)pCiphertext_length;
    (void)pSharedSecret;
    (void)shared_secret_size;
    (void)pSharedSecret_length;

    /* Post-quantum KEM is not supported by the STSE device */
    return STSE_PSA_ERROR_NOT_SUPPORTED;
}

stse_psa_status_t stse_psa_kem_decapsulate(stse_psa_key_id_t   key_id,
                                            stse_psa_algorithm_t alg,
                                            const PLAT_UI8      *pCiphertext,
                                            PLAT_UI32            ciphertext_length,
                                            PLAT_UI8            *pSharedSecret,
                                            PLAT_UI32            shared_secret_size,
                                            PLAT_UI32           *pSharedSecret_length)
{
    (void)key_id;
    (void)alg;
    (void)pCiphertext;
    (void)ciphertext_length;
    (void)pSharedSecret;
    (void)shared_secret_size;
    (void)pSharedSecret_length;

    /* Post-quantum KEM is not supported by the STSE device */
    return STSE_PSA_ERROR_NOT_SUPPORTED;
}

#endif /* STSE_PSA_SPEC_VERSION >= 14 */
