/*!
 ******************************************************************************
 * \file    stse_pkcs11.c
 * \brief   STSE PKCS \#11 adaptation layer (source)
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

#include "sal/pkcs11/stse_pkcs11.h"

/* -------------------------------------------------------------------------- */
/* Module-level context (single instance)                                      */
/* -------------------------------------------------------------------------- */

static stse_pkcs11_ctx_t _stse_pkcs11_ctx;

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

/**
 * \brief  Retrieve the session pointer for \p hSession, or NULL if invalid.
 */
static stse_pkcs11_session_t *_stse_pkcs11_get_session(STSE_CK_SESSION_HANDLE hSession)
{
    stse_pkcs11_session_t *pSession;

    if (hSession == STSE_CK_INVALID_HANDLE || hSession > STSE_PKCS11_MAX_SESSIONS) {
        return NULL;
    }

    pSession = &_stse_pkcs11_ctx.sessions[hSession - 1U];
    if (!pSession->in_use) {
        return NULL;
    }

    return pSession;
}

/**
 * \brief  Map a PKCS \#11 digest/ECDSA mechanism to an STSE hash algorithm.
 * \return \ref STSE_OK on success; \ref STSE_API_INVALID_PARAMETER otherwise.
 */
static stse_ReturnCode_t _stse_pkcs11_mech_to_hash_algo(STSE_CK_MECHANISM_TYPE mech,
                                                         stse_hash_algorithm_t *pAlgo)
{
    switch (mech) {
#ifdef STSE_CONF_HASH_SHA_256
        case STSE_CKM_SHA256:
        case STSE_CKM_ECDSA_SHA256:
            *pAlgo = STSE_SHA_256;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_384
        case STSE_CKM_SHA384:
        case STSE_CKM_ECDSA_SHA384:
            *pAlgo = STSE_SHA_384;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_512
        case STSE_CKM_SHA512:
        case STSE_CKM_ECDSA_SHA512:
            *pAlgo = STSE_SHA_512;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_256
        case STSE_CKM_SHA3_256:
            *pAlgo = STSE_SHA3_256;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_384
        case STSE_CKM_SHA3_384:
            *pAlgo = STSE_SHA3_384;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_512
        case STSE_CKM_SHA3_512:
            *pAlgo = STSE_SHA3_512;
            break;
#endif
        default:
            return STSE_API_INVALID_PARAMETER;
    }

    return STSE_OK;
}

/**
 * \brief  Return non-zero when \p mech is a recognised AES symmetric mechanism.
 */
static PLAT_UI8 _stse_pkcs11_is_aes_mech(STSE_CK_MECHANISM_TYPE mech)
{
    return ((mech == STSE_CKM_AES_ECB) ||
            (mech == STSE_CKM_AES_CCM) ||
            (mech == STSE_CKM_AES_GCM) ||
            (mech == STSE_CKM_AES_CMAC)) ? 1U : 0U;
}

/**
 * \brief  Return non-zero when \p mech is a recognised ECDSA mechanism.
 */
static PLAT_UI8 _stse_pkcs11_is_ecdsa_mech(STSE_CK_MECHANISM_TYPE mech)
{
    return ((mech == STSE_CKM_ECDSA)         ||
            (mech == STSE_CKM_ECDSA_SHA256)  ||
            (mech == STSE_CKM_ECDSA_SHA384)  ||
            (mech == STSE_CKM_ECDSA_SHA512)) ? 1U : 0U;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

STSE_CK_RV stse_pkcs11_initialize(void)
{
    PLAT_UI8 i;

    for (i = 0U; i < STSE_PKCS11_MAX_SESSIONS; i++) {
        _stse_pkcs11_ctx.sessions[i].in_use           = 0U;
        _stse_pkcs11_ctx.sessions[i].pSTSE            = NULL;
        _stse_pkcs11_ctx.sessions[i].active_operation = STSE_PKCS11_OP_NONE;
        _stse_pkcs11_ctx.sessions[i].hash_started     = 0U;
        _stse_pkcs11_ctx.sessions[i].pPublic_key      = NULL;
    }

    _stse_pkcs11_ctx.initialized = 1U;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_finalize(void)
{
    PLAT_UI8 i;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_SESSIONS; i++) {
        _stse_pkcs11_ctx.sessions[i].in_use           = 0U;
        _stse_pkcs11_ctx.sessions[i].pSTSE            = NULL;
        _stse_pkcs11_ctx.sessions[i].active_operation = STSE_PKCS11_OP_NONE;
    }

    _stse_pkcs11_ctx.initialized = 0U;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_open_session(stse_Handler_t           *pSTSE,
                                     STSE_CK_FLAGS             flags,
                                     STSE_CK_SESSION_HANDLE   *phSession)
{
    PLAT_UI8 i;

    (void)flags; /* reserved for future use */

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if ((pSTSE == NULL) || (phSession == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_SESSIONS; i++) {
        if (!_stse_pkcs11_ctx.sessions[i].in_use) {
            _stse_pkcs11_ctx.sessions[i].in_use           = 1U;
            _stse_pkcs11_ctx.sessions[i].pSTSE            = pSTSE;
            _stse_pkcs11_ctx.sessions[i].active_operation = STSE_PKCS11_OP_NONE;
            _stse_pkcs11_ctx.sessions[i].hash_started     = 0U;
            _stse_pkcs11_ctx.sessions[i].pPublic_key      = NULL;
            *phSession = (STSE_CK_SESSION_HANDLE)(i + 1U);
            return STSE_CKR_OK;
        }
    }

    return STSE_CKR_GENERAL_ERROR;
}

STSE_CK_RV stse_pkcs11_close_session(STSE_CK_SESSION_HANDLE hSession)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    pSession->in_use           = 0U;
    pSession->pSTSE            = NULL;
    pSession->active_operation = STSE_PKCS11_OP_NONE;
    pSession->hash_started     = 0U;
    pSession->pPublic_key      = NULL;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_generate_random(STSE_CK_SESSION_HANDLE hSession,
                                        STSE_CK_BYTE_PTR       pRandomData,
                                        STSE_CK_ULONG          ulRandomLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if ((pRandomData == NULL) || (ulRandomLen == 0U)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    ret = stse_generate_random(pSession->pSTSE,
                               (PLAT_UI8 *)pRandomData,
                               (PLAT_UI16)ulRandomLen);

    return (ret == STSE_OK) ? STSE_CKR_OK : STSE_CKR_DEVICE_ERROR;
}

STSE_CK_RV stse_pkcs11_digest_init(STSE_CK_SESSION_HANDLE    hSession,
                                    stse_pkcs11_mechanism_t  *pMechanism)
{
    stse_pkcs11_session_t *pSession;
    stse_hash_algorithm_t  algo;
    stse_ReturnCode_t      ret;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    ret = _stse_pkcs11_mech_to_hash_algo(pMechanism->mechanism, &algo);
    if (ret != STSE_OK) {
        return STSE_CKR_MECHANISM_INVALID;
    }

    pSession->hash_algorithm   = algo;
    pSession->hash_started     = 0U;
    pSession->active_operation = STSE_PKCS11_OP_DIGEST;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_digest_update(STSE_CK_SESSION_HANDLE hSession,
                                      STSE_CK_BYTE_PTR       pPart,
                                      STSE_CK_ULONG          ulPartLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_DIGEST) {
        return STSE_CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pPart == NULL) || (ulPartLen == 0U)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    if (!pSession->hash_started) {
        /* First update: start the hash on the STSE device */
        ret = stse_start_hash(pSession->pSTSE,
                              pSession->hash_algorithm,
                              (PLAT_UI8 *)pPart,
                              (PLAT_UI16)ulPartLen);
        if (ret == STSE_OK) {
            pSession->hash_started = 1U;
        }
    } else {
        /* Subsequent updates: continue the in-progress hash */
        ret = stse_process_hash(pSession->pSTSE,
                                (PLAT_UI8 *)pPart,
                                (PLAT_UI16)ulPartLen);
    }

    return (ret == STSE_OK) ? STSE_CKR_OK : STSE_CKR_DEVICE_ERROR;
}

STSE_CK_RV stse_pkcs11_digest_final(STSE_CK_SESSION_HANDLE hSession,
                                     STSE_CK_BYTE_PTR       pDigest,
                                     STSE_CK_ULONG         *pulDigestLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;
    PLAT_UI16              digest_size;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_DIGEST) {
        return STSE_CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pDigest == NULL) || (pulDigestLen == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    if (!pSession->hash_started) {
        /* No data was provided via digest_update - operation cannot complete */
        return STSE_CKR_OPERATION_NOT_INITIALIZED;
    }

    digest_size = (PLAT_UI16)*pulDigestLen;

    /* Finalise with an empty last chunk */
    ret = stse_finish_hash(pSession->pSTSE,
                           pSession->hash_algorithm,
                           NULL,
                           0U,
                           (PLAT_UI8 *)pDigest,
                           &digest_size);

    if (ret == STSE_OK) {
        *pulDigestLen              = (STSE_CK_ULONG)digest_size;
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        pSession->hash_started     = 0U;
        return STSE_CKR_OK;
    }

    return STSE_CKR_DEVICE_ERROR;
}

STSE_CK_RV stse_pkcs11_sign_init(STSE_CK_SESSION_HANDLE    hSession,
                                  stse_pkcs11_mechanism_t  *pMechanism,
                                  STSE_CK_OBJECT_HANDLE     hKey,
                                  stse_ecc_key_type_t       key_type)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_ecdsa_mech(pMechanism->mechanism)) {
        return STSE_CKR_MECHANISM_INVALID;
    }

    pSession->key_slot         = (PLAT_UI8)hKey;
    pSession->ecc_key_type     = key_type;
    pSession->active_operation = STSE_PKCS11_OP_SIGN;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_sign(STSE_CK_SESSION_HANDLE hSession,
                             STSE_CK_BYTE_PTR       pData,
                             STSE_CK_ULONG          ulDataLen,
                             STSE_CK_BYTE_PTR       pSignature,
                             STSE_CK_ULONG         *pulSignatureLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;

    (void)pulSignatureLen; /* size checked by caller per PKCS#11 convention */

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_SIGN) {
        return STSE_CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pData == NULL) || (pSignature == NULL) || (pulSignatureLen == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    ret = stse_ecc_generate_signature(pSession->pSTSE,
                                      pSession->key_slot,
                                      pSession->ecc_key_type,
                                      (PLAT_UI8 *)pData,
                                      (PLAT_UI16)ulDataLen,
                                      (PLAT_UI8 *)pSignature);

    if (ret == STSE_OK) {
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        return STSE_CKR_OK;
    }

    return STSE_CKR_DEVICE_ERROR;
}

STSE_CK_RV stse_pkcs11_verify_init(STSE_CK_SESSION_HANDLE    hSession,
                                    stse_pkcs11_mechanism_t  *pMechanism,
                                    STSE_CK_OBJECT_HANDLE     hKey,
                                    PLAT_UI8                 *pPublic_key)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if ((pMechanism == NULL) || (pPublic_key == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_ecdsa_mech(pMechanism->mechanism)) {
        return STSE_CKR_MECHANISM_INVALID;
    }

    pSession->ecc_key_type     = (stse_ecc_key_type_t)hKey;
    pSession->pPublic_key      = pPublic_key;
    pSession->active_operation = STSE_PKCS11_OP_VERIFY;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_verify(STSE_CK_SESSION_HANDLE hSession,
                               STSE_CK_BYTE_PTR       pData,
                               STSE_CK_ULONG          ulDataLen,
                               STSE_CK_BYTE_PTR       pSignature,
                               STSE_CK_ULONG          ulSignatureLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;
    PLAT_UI8               validity = 0U;

    (void)ulSignatureLen; /* length implicit in the key type */

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_VERIFY) {
        return STSE_CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pData == NULL) || (pSignature == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    ret = stse_ecc_verify_signature(pSession->pSTSE,
                                    pSession->ecc_key_type,
                                    pSession->pPublic_key,
                                    (PLAT_UI8 *)pSignature,
                                    (PLAT_UI8 *)pData,
                                    (PLAT_UI16)ulDataLen,
                                    0U,
                                    &validity);

    pSession->active_operation = STSE_PKCS11_OP_NONE;

    if (ret != STSE_OK) {
        return STSE_CKR_DEVICE_ERROR;
    }

    return (validity != 0U) ? STSE_CKR_OK : STSE_CKR_SIGNATURE_INVALID;
}

STSE_CK_RV stse_pkcs11_encrypt_init(STSE_CK_SESSION_HANDLE    hSession,
                                     stse_pkcs11_mechanism_t  *pMechanism,
                                     STSE_CK_OBJECT_HANDLE     hKey)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_aes_mech(pMechanism->mechanism)) {
        return STSE_CKR_MECHANISM_INVALID;
    }

    pSession->sym_key_slot     = (PLAT_UI8)hKey;
    pSession->active_mechanism = pMechanism->mechanism;
    pSession->mechanism        = *pMechanism;
    pSession->active_operation = STSE_PKCS11_OP_ENCRYPT;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_encrypt(STSE_CK_SESSION_HANDLE hSession,
                                STSE_CK_BYTE_PTR       pData,
                                STSE_CK_ULONG          ulDataLen,
                                STSE_CK_BYTE_PTR       pEncryptedData,
                                STSE_CK_ULONG         *pulEncryptedDataLen)
{
    stse_pkcs11_session_t    *pSession;
    stse_ReturnCode_t         ret;
    stse_pkcs11_ccm_params_t *pCcmParams;
    stse_pkcs11_gcm_params_t *pGcmParams;
    PLAT_UI8                  ctr_presence = 0U;
    PLAT_UI32                 ctr_value    = 0U;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_ENCRYPT) {
        return STSE_CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pData == NULL) || (pEncryptedData == NULL) || (pulEncryptedDataLen == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    switch (pSession->active_mechanism) {
        case STSE_CKM_AES_ECB:
            ret = stse_aes_ecb_encrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI16)ulDataLen,
                                       (PLAT_UI8 *)pData,
                                       (PLAT_UI8 *)pEncryptedData);
            if (ret == STSE_OK) {
                *pulEncryptedDataLen = ulDataLen;
            }
            break;

        case STSE_CKM_AES_CCM:
            if (pSession->mechanism.pParameter == NULL) {
                return STSE_CKR_ARGUMENTS_BAD;
            }
            pCcmParams = (stse_pkcs11_ccm_params_t *)pSession->mechanism.pParameter;
            ret = stse_aes_ccm_encrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI8)pCcmParams->ulMACLen,
                                       (PLAT_UI8 *)pCcmParams->pNonce,
                                       (PLAT_UI16)pCcmParams->ulAADLen,
                                       (PLAT_UI8 *)pCcmParams->pAAD,
                                       (PLAT_UI16)ulDataLen,
                                       (PLAT_UI8 *)pData,
                                       (PLAT_UI8 *)pEncryptedData,
                                       (PLAT_UI8 *)pEncryptedData + ulDataLen,
                                       ctr_presence,
                                       &ctr_value);
            if (ret == STSE_OK) {
                *pulEncryptedDataLen = ulDataLen + pCcmParams->ulMACLen;
            }
            break;

        case STSE_CKM_AES_GCM:
            if (pSession->mechanism.pParameter == NULL) {
                return STSE_CKR_ARGUMENTS_BAD;
            }
            pGcmParams = (stse_pkcs11_gcm_params_t *)pSession->mechanism.pParameter;
            ret = stse_aes_gcm_encrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI8)(pGcmParams->ulTagBits / 8U),
                                       (PLAT_UI16)pGcmParams->ulIvLen,
                                       (PLAT_UI8 *)pGcmParams->pIv,
                                       (PLAT_UI16)pGcmParams->ulAADLen,
                                       (PLAT_UI8 *)pGcmParams->pAAD,
                                       (PLAT_UI16)ulDataLen,
                                       (PLAT_UI8 *)pData,
                                       (PLAT_UI8 *)pEncryptedData,
                                       (PLAT_UI8 *)pEncryptedData + ulDataLen);
            if (ret == STSE_OK) {
                *pulEncryptedDataLen = ulDataLen + (pGcmParams->ulTagBits / 8U);
            }
            break;

        default:
            return STSE_CKR_MECHANISM_INVALID;
    }

    if (ret == STSE_OK) {
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        return STSE_CKR_OK;
    }

    return STSE_CKR_DEVICE_ERROR;
}

STSE_CK_RV stse_pkcs11_decrypt_init(STSE_CK_SESSION_HANDLE    hSession,
                                     stse_pkcs11_mechanism_t  *pMechanism,
                                     STSE_CK_OBJECT_HANDLE     hKey)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_aes_mech(pMechanism->mechanism)) {
        return STSE_CKR_MECHANISM_INVALID;
    }

    pSession->sym_key_slot     = (PLAT_UI8)hKey;
    pSession->active_mechanism = pMechanism->mechanism;
    pSession->mechanism        = *pMechanism;
    pSession->active_operation = STSE_PKCS11_OP_DECRYPT;

    return STSE_CKR_OK;
}

STSE_CK_RV stse_pkcs11_decrypt(STSE_CK_SESSION_HANDLE hSession,
                                STSE_CK_BYTE_PTR       pEncryptedData,
                                STSE_CK_ULONG          ulEncryptedDataLen,
                                STSE_CK_BYTE_PTR       pData,
                                STSE_CK_ULONG         *pulDataLen)
{
    stse_pkcs11_session_t    *pSession;
    stse_ReturnCode_t         ret;
    stse_pkcs11_ccm_params_t *pCcmParams;
    stse_pkcs11_gcm_params_t *pGcmParams;
    PLAT_UI8                  verify_result = 0U;
    STSE_CK_ULONG             ciphertext_len;
    STSE_CK_ULONG             tag_len;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_DECRYPT) {
        return STSE_CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pEncryptedData == NULL) || (pData == NULL) || (pulDataLen == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    switch (pSession->active_mechanism) {
        case STSE_CKM_AES_ECB:
            ret = stse_aes_ecb_decrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI16)ulEncryptedDataLen,
                                       (PLAT_UI8 *)pEncryptedData,
                                       (PLAT_UI8 *)pData);
            if (ret == STSE_OK) {
                *pulDataLen = ulEncryptedDataLen;
            }
            break;

        case STSE_CKM_AES_CCM:
            if (pSession->mechanism.pParameter == NULL) {
                return STSE_CKR_ARGUMENTS_BAD;
            }
            pCcmParams     = (stse_pkcs11_ccm_params_t *)pSession->mechanism.pParameter;
            tag_len        = pCcmParams->ulMACLen;
            ciphertext_len = ulEncryptedDataLen - tag_len;
            ret = stse_aes_ccm_decrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI8)tag_len,
                                       (PLAT_UI8 *)pCcmParams->pNonce,
                                       (PLAT_UI16)pCcmParams->ulAADLen,
                                       (PLAT_UI8 *)pCcmParams->pAAD,
                                       (PLAT_UI16)ciphertext_len,
                                       (PLAT_UI8 *)pEncryptedData,
                                       (PLAT_UI8 *)pEncryptedData + ciphertext_len,
                                       &verify_result,
                                       (PLAT_UI8 *)pData);
            if (ret == STSE_OK) {
                *pulDataLen = ciphertext_len;
            }
            break;

        case STSE_CKM_AES_GCM:
            if (pSession->mechanism.pParameter == NULL) {
                return STSE_CKR_ARGUMENTS_BAD;
            }
            pGcmParams     = (stse_pkcs11_gcm_params_t *)pSession->mechanism.pParameter;
            tag_len        = pGcmParams->ulTagBits / 8U;
            ciphertext_len = ulEncryptedDataLen - tag_len;
            ret = stse_aes_gcm_decrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI8)tag_len,
                                       (PLAT_UI16)pGcmParams->ulIvLen,
                                       (PLAT_UI8 *)pGcmParams->pIv,
                                       (PLAT_UI16)pGcmParams->ulAADLen,
                                       (PLAT_UI8 *)pGcmParams->pAAD,
                                       (PLAT_UI16)ciphertext_len,
                                       (PLAT_UI8 *)pEncryptedData,
                                       (PLAT_UI8 *)pEncryptedData + ciphertext_len,
                                       &verify_result,
                                       (PLAT_UI8 *)pData);
            if (ret == STSE_OK) {
                *pulDataLen = ciphertext_len;
            }
            break;

        default:
            return STSE_CKR_MECHANISM_INVALID;
    }

    if (ret == STSE_OK) {
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        return STSE_CKR_OK;
    }

    return STSE_CKR_DEVICE_ERROR;
}

STSE_CK_RV stse_pkcs11_generate_key_pair(STSE_CK_SESSION_HANDLE    hSession,
                                          stse_pkcs11_mechanism_t  *pMechanism,
                                          PLAT_UI8                  key_slot,
                                          stse_ecc_key_type_t       key_type,
                                          PLAT_UI16                 usage_limit,
                                          PLAT_UI8                 *pPublicKey,
                                          STSE_CK_OBJECT_HANDLE    *phPrivateKey,
                                          STSE_CK_OBJECT_HANDLE    *phPublicKey)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;

    if (!_stse_pkcs11_ctx.initialized) {
        return STSE_CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return STSE_CKR_SESSION_HANDLE_INVALID;
    }

    if ((pMechanism == NULL) || (pPublicKey == NULL) ||
        (phPrivateKey == NULL) || (phPublicKey == NULL)) {
        return STSE_CKR_ARGUMENTS_BAD;
    }

    if (pMechanism->mechanism != STSE_CKM_EC_KEY_PAIR_GEN) {
        return STSE_CKR_MECHANISM_INVALID;
    }

    ret = stse_generate_ecc_key_pair(pSession->pSTSE,
                                     key_slot,
                                     key_type,
                                     usage_limit,
                                     pPublicKey);

    if (ret == STSE_OK) {
        *phPrivateKey = (STSE_CK_OBJECT_HANDLE)key_slot;
        *phPublicKey  = (STSE_CK_OBJECT_HANDLE)key_slot;
        return STSE_CKR_OK;
    }

    return STSE_CKR_DEVICE_ERROR;
}
