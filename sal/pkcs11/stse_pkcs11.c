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

stse_pkcs11_ctx_t _stse_pkcs11_ctx;

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

/**
 * \brief  Retrieve the session pointer for \p hSession, or NULL if invalid.
 */
static stse_pkcs11_session_t *_stse_pkcs11_get_session(CK_SESSION_HANDLE hSession)
{
    stse_pkcs11_session_t *pSession;

    if (hSession == CK_INVALID_HANDLE || hSession > STSE_PKCS11_MAX_SESSIONS) {
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
static stse_ReturnCode_t _stse_pkcs11_mech_to_hash_algo(CK_MECHANISM_TYPE mech,
                                                         stse_hash_algorithm_t *pAlgo)
{
    switch (mech) {
#ifdef STSE_CONF_HASH_SHA_256
        case CKM_SHA256:
        case CKM_ECDSA_SHA256:
            *pAlgo = STSE_SHA_256;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_384
        case CKM_SHA384:
        case CKM_ECDSA_SHA384:
            *pAlgo = STSE_SHA_384;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_512
        case CKM_SHA512:
        case CKM_ECDSA_SHA512:
            *pAlgo = STSE_SHA_512;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_256
        case CKM_SHA3_256:
            *pAlgo = STSE_SHA3_256;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_384
        case CKM_SHA3_384:
            *pAlgo = STSE_SHA3_384;
            break;
#endif
#ifdef STSE_CONF_HASH_SHA_3_512
        case CKM_SHA3_512:
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
static PLAT_UI8 _stse_pkcs11_is_aes_mech(CK_MECHANISM_TYPE mech)
{
    return ((mech == CKM_AES_ECB) ||
            (mech == CKM_AES_CCM) ||
            (mech == CKM_AES_GCM) ||
            (mech == CKM_AES_CMAC)) ? 1U : 0U;
}

/**
 * \brief  Return non-zero when \p mech is a recognised ECDSA mechanism.
 */
static PLAT_UI8 _stse_pkcs11_is_ecdsa_mech(CK_MECHANISM_TYPE mech)
{
    return ((mech == CKM_ECDSA)         ||
            (mech == CKM_ECDSA_SHA256)  ||
            (mech == CKM_ECDSA_SHA384)  ||
            (mech == CKM_ECDSA_SHA512)) ? 1U : 0U;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

CK_RV stse_pkcs11_initialize(void)
{
    PLAT_UI8 i;

    for (i = 0U; i < STSE_PKCS11_MAX_SLOTS; i++) {
        _stse_pkcs11_ctx.slots[i].in_use = 0U;
        _stse_pkcs11_ctx.slots[i].pSTSE  = NULL;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_SESSIONS; i++) {
        _stse_pkcs11_ctx.sessions[i].in_use           = 0U;
        _stse_pkcs11_ctx.sessions[i].pSTSE            = NULL;
        _stse_pkcs11_ctx.sessions[i].slotID           = 0U;
        _stse_pkcs11_ctx.sessions[i].active_operation = STSE_PKCS11_OP_NONE;
        _stse_pkcs11_ctx.sessions[i].hash_started     = 0U;
        _stse_pkcs11_ctx.sessions[i].pPublic_key      = NULL;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_KEY_OBJECTS; i++) {
        _stse_pkcs11_ctx.key_objects[i].in_use = 0U;
    }

    _stse_pkcs11_ctx.initialized = 1U;

    return CKR_OK;
}

CK_RV stse_pkcs11_finalize(void)
{
    PLAT_UI8 i;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_SLOTS; i++) {
        _stse_pkcs11_ctx.slots[i].in_use = 0U;
        _stse_pkcs11_ctx.slots[i].pSTSE  = NULL;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_SESSIONS; i++) {
        _stse_pkcs11_ctx.sessions[i].in_use           = 0U;
        _stse_pkcs11_ctx.sessions[i].pSTSE            = NULL;
        _stse_pkcs11_ctx.sessions[i].active_operation = STSE_PKCS11_OP_NONE;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_KEY_OBJECTS; i++) {
        _stse_pkcs11_ctx.key_objects[i].in_use = 0U;
    }

    _stse_pkcs11_ctx.initialized = 0U;

    return CKR_OK;
}

CK_RV stse_pkcs11_register_slot(CK_SLOT_ID slotID, stse_Handler_t *pSTSE)
{
    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (pSTSE == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (slotID >= STSE_PKCS11_MAX_SLOTS) {
        return CKR_SLOT_ID_INVALID;
    }

    _stse_pkcs11_ctx.slots[slotID].pSTSE  = pSTSE;
    _stse_pkcs11_ctx.slots[slotID].in_use = 1U;

    return CKR_OK;
}

CK_RV stse_pkcs11_open_session(CK_SLOT_ID         slotID,
                                CK_FLAGS           flags,
                                CK_SESSION_HANDLE *phSession)
{
    PLAT_UI8 i;

    (void)flags; /* reserved for future use */

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (phSession == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (slotID >= STSE_PKCS11_MAX_SLOTS || !_stse_pkcs11_ctx.slots[slotID].in_use) {
        return CKR_SLOT_ID_INVALID;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_SESSIONS; i++) {
        if (!_stse_pkcs11_ctx.sessions[i].in_use) {
            _stse_pkcs11_ctx.sessions[i].in_use           = 1U;
            _stse_pkcs11_ctx.sessions[i].pSTSE            = _stse_pkcs11_ctx.slots[slotID].pSTSE;
            _stse_pkcs11_ctx.sessions[i].slotID           = slotID;
            _stse_pkcs11_ctx.sessions[i].active_operation = STSE_PKCS11_OP_NONE;
            _stse_pkcs11_ctx.sessions[i].hash_started     = 0U;
            _stse_pkcs11_ctx.sessions[i].pPublic_key      = NULL;
            *phSession = (CK_SESSION_HANDLE)(i + 1U);
            return CKR_OK;
        }
    }

    return CKR_SESSION_COUNT;
}

CK_RV stse_pkcs11_close_session(CK_SESSION_HANDLE hSession)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    pSession->in_use           = 0U;
    pSession->pSTSE            = NULL;
    pSession->active_operation = STSE_PKCS11_OP_NONE;
    pSession->hash_started     = 0U;
    pSession->pPublic_key      = NULL;

    return CKR_OK;
}

CK_RV stse_pkcs11_generate_random(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR       pRandomData,
                                        CK_ULONG          ulRandomLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if ((pRandomData == NULL) || (ulRandomLen == 0U)) {
        return CKR_ARGUMENTS_BAD;
    }

    ret = stse_generate_random(pSession->pSTSE,
                               (PLAT_UI8 *)pRandomData,
                               (PLAT_UI16)ulRandomLen);

    return (ret == STSE_OK) ? CKR_OK : CKR_DEVICE_ERROR;
}

CK_RV stse_pkcs11_digest_init(CK_SESSION_HANDLE    hSession,
                                    CK_MECHANISM  *pMechanism)
{
    stse_pkcs11_session_t *pSession;
    stse_hash_algorithm_t  algo;
    stse_ReturnCode_t      ret;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    ret = _stse_pkcs11_mech_to_hash_algo(pMechanism->mechanism, &algo);
    if (ret != STSE_OK) {
        return CKR_MECHANISM_INVALID;
    }

    pSession->hash_algorithm   = algo;
    pSession->hash_started     = 0U;
    pSession->active_operation = STSE_PKCS11_OP_DIGEST;

    return CKR_OK;
}

CK_RV stse_pkcs11_digest_update(CK_SESSION_HANDLE hSession,
                                      CK_BYTE_PTR       pPart,
                                      CK_ULONG          ulPartLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_DIGEST) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pPart == NULL) || (ulPartLen == 0U)) {
        return CKR_ARGUMENTS_BAD;
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

    return (ret == STSE_OK) ? CKR_OK : CKR_DEVICE_ERROR;
}

CK_RV stse_pkcs11_digest_final(CK_SESSION_HANDLE hSession,
                                     CK_BYTE_PTR       pDigest,
                                     CK_ULONG         *pulDigestLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;
    PLAT_UI16              digest_size;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_DIGEST) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pDigest == NULL) || (pulDigestLen == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!pSession->hash_started) {
        /* No data was provided via digest_update - operation cannot complete */
        return CKR_OPERATION_NOT_INITIALIZED;
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
        *pulDigestLen              = (CK_ULONG)digest_size;
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        pSession->hash_started     = 0U;
        return CKR_OK;
    }

    return CKR_DEVICE_ERROR;
}

CK_RV stse_pkcs11_sign_init(CK_SESSION_HANDLE    hSession,
                                  CK_MECHANISM  *pMechanism,
                                  CK_OBJECT_HANDLE     hKey,
                                  stse_ecc_key_type_t       key_type)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_ecdsa_mech(pMechanism->mechanism)) {
        return CKR_MECHANISM_INVALID;
    }

    pSession->key_slot         = (PLAT_UI8)hKey;
    pSession->ecc_key_type     = key_type;
    pSession->active_operation = STSE_PKCS11_OP_SIGN;

    return CKR_OK;
}

CK_RV stse_pkcs11_sign(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR       pData,
                             CK_ULONG          ulDataLen,
                             CK_BYTE_PTR       pSignature,
                             CK_ULONG         *pulSignatureLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;

    (void)pulSignatureLen; /* size checked by caller per PKCS#11 convention */

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_SIGN) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pData == NULL) || (pSignature == NULL) || (pulSignatureLen == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    ret = stse_ecc_generate_signature(pSession->pSTSE,
                                      pSession->key_slot,
                                      pSession->ecc_key_type,
                                      (PLAT_UI8 *)pData,
                                      (PLAT_UI16)ulDataLen,
                                      (PLAT_UI8 *)pSignature);

    if (ret == STSE_OK) {
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        return CKR_OK;
    }

    return CKR_DEVICE_ERROR;
}

CK_RV stse_pkcs11_verify_init(CK_SESSION_HANDLE    hSession,
                                    CK_MECHANISM  *pMechanism,
                                    CK_OBJECT_HANDLE     hKey,
                                    PLAT_UI8                 *pPublic_key)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if ((pMechanism == NULL) || (pPublic_key == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_ecdsa_mech(pMechanism->mechanism)) {
        return CKR_MECHANISM_INVALID;
    }

    pSession->ecc_key_type     = (stse_ecc_key_type_t)hKey;
    pSession->pPublic_key      = pPublic_key;
    pSession->active_operation = STSE_PKCS11_OP_VERIFY;

    return CKR_OK;
}

CK_RV stse_pkcs11_verify(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR       pData,
                               CK_ULONG          ulDataLen,
                               CK_BYTE_PTR       pSignature,
                               CK_ULONG          ulSignatureLen)
{
    stse_pkcs11_session_t *pSession;
    stse_ReturnCode_t      ret;
    PLAT_UI8               validity = 0U;

    (void)ulSignatureLen; /* length implicit in the key type */

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_VERIFY) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pData == NULL) || (pSignature == NULL)) {
        return CKR_ARGUMENTS_BAD;
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
        return CKR_DEVICE_ERROR;
    }

    return (validity != 0U) ? CKR_OK : CKR_SIGNATURE_INVALID;
}

CK_RV stse_pkcs11_encrypt_init(CK_SESSION_HANDLE    hSession,
                                     CK_MECHANISM  *pMechanism,
                                     CK_OBJECT_HANDLE     hKey)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_aes_mech(pMechanism->mechanism)) {
        return CKR_MECHANISM_INVALID;
    }

    pSession->sym_key_slot     = (PLAT_UI8)hKey;
    pSession->active_mechanism = pMechanism->mechanism;
    pSession->mechanism        = *pMechanism;
    pSession->active_operation = STSE_PKCS11_OP_ENCRYPT;

    return CKR_OK;
}

CK_RV stse_pkcs11_encrypt(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR       pData,
                                CK_ULONG          ulDataLen,
                                CK_BYTE_PTR       pEncryptedData,
                                CK_ULONG         *pulEncryptedDataLen)
{
    stse_pkcs11_session_t    *pSession;
    stse_ReturnCode_t         ret;
    CK_CCM_PARAMS *pCcmParams;
    CK_GCM_PARAMS *pGcmParams;
    PLAT_UI8                  ctr_presence = 0U;
    PLAT_UI32                 ctr_value    = 0U;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_ENCRYPT) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pData == NULL) || (pulEncryptedDataLen == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pSession->active_mechanism) {
        case CKM_AES_ECB:
            /* Size query: return required length without encrypting */
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulDataLen;
                return CKR_OK;
            }
            if (*pulEncryptedDataLen < ulDataLen) {
                return CKR_BUFFER_TOO_SMALL;
            }
            ret = stse_aes_ecb_encrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI16)ulDataLen,
                                       (PLAT_UI8 *)pData,
                                       (PLAT_UI8 *)pEncryptedData);
            if (ret == STSE_OK) {
                *pulEncryptedDataLen = ulDataLen;
            }
            break;

        case CKM_AES_CCM:
            if (pSession->mechanism.pParameter == NULL) {
                return CKR_ARGUMENTS_BAD;
            }
            pCcmParams = (CK_CCM_PARAMS *)pSession->mechanism.pParameter;
            /* Size query: return required length without encrypting */
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulDataLen + pCcmParams->ulMACLen;
                return CKR_OK;
            }
            if (*pulEncryptedDataLen < (ulDataLen + pCcmParams->ulMACLen)) {
                return CKR_BUFFER_TOO_SMALL;
            }
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

        case CKM_AES_GCM:
            if (pSession->mechanism.pParameter == NULL) {
                return CKR_ARGUMENTS_BAD;
            }
            pGcmParams = (CK_GCM_PARAMS *)pSession->mechanism.pParameter;
            /* Size query: return required length without encrypting */
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulDataLen + (pGcmParams->ulTagBits / 8U);
                return CKR_OK;
            }
            if (*pulEncryptedDataLen < (ulDataLen + (pGcmParams->ulTagBits / 8U))) {
                return CKR_BUFFER_TOO_SMALL;
            }
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
            return CKR_MECHANISM_INVALID;
    }

    if (ret == STSE_OK) {
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        return CKR_OK;
    }

    return CKR_DEVICE_ERROR;
}

CK_RV stse_pkcs11_decrypt_init(CK_SESSION_HANDLE    hSession,
                                     CK_MECHANISM  *pMechanism,
                                     CK_OBJECT_HANDLE     hKey)
{
    stse_pkcs11_session_t *pSession;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pMechanism == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!_stse_pkcs11_is_aes_mech(pMechanism->mechanism)) {
        return CKR_MECHANISM_INVALID;
    }

    pSession->sym_key_slot     = (PLAT_UI8)hKey;
    pSession->active_mechanism = pMechanism->mechanism;
    pSession->mechanism        = *pMechanism;
    pSession->active_operation = STSE_PKCS11_OP_DECRYPT;

    return CKR_OK;
}

CK_RV stse_pkcs11_decrypt(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR       pEncryptedData,
                                CK_ULONG          ulEncryptedDataLen,
                                CK_BYTE_PTR       pData,
                                CK_ULONG         *pulDataLen)
{
    stse_pkcs11_session_t    *pSession;
    stse_ReturnCode_t         ret;
    CK_CCM_PARAMS *pCcmParams;
    CK_GCM_PARAMS *pGcmParams;
    PLAT_UI8                  verify_result = 0U;
    CK_ULONG             ciphertext_len;
    CK_ULONG             tag_len;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->active_operation != STSE_PKCS11_OP_DECRYPT) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ((pEncryptedData == NULL) || (pulDataLen == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pSession->active_mechanism) {
        case CKM_AES_ECB:
            /* Size query: return required length without decrypting */
            if (pData == NULL) {
                *pulDataLen = ulEncryptedDataLen;
                return CKR_OK;
            }
            if (*pulDataLen < ulEncryptedDataLen) {
                return CKR_BUFFER_TOO_SMALL;
            }
            ret = stse_aes_ecb_decrypt(pSession->pSTSE,
                                       pSession->sym_key_slot,
                                       (PLAT_UI16)ulEncryptedDataLen,
                                       (PLAT_UI8 *)pEncryptedData,
                                       (PLAT_UI8 *)pData);
            if (ret == STSE_OK) {
                *pulDataLen = ulEncryptedDataLen;
            }
            break;

        case CKM_AES_CCM:
            if (pSession->mechanism.pParameter == NULL) {
                return CKR_ARGUMENTS_BAD;
            }
            pCcmParams = (CK_CCM_PARAMS *)pSession->mechanism.pParameter;
            tag_len    = pCcmParams->ulMACLen;
            if (ulEncryptedDataLen < tag_len) {
                return CKR_DATA_LEN_RANGE;
            }
            ciphertext_len = ulEncryptedDataLen - tag_len;
            /* Size query: return required length without decrypting */
            if (pData == NULL) {
                *pulDataLen = ciphertext_len;
                return CKR_OK;
            }
            if (*pulDataLen < ciphertext_len) {
                return CKR_BUFFER_TOO_SMALL;
            }
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

        case CKM_AES_GCM:
            if (pSession->mechanism.pParameter == NULL) {
                return CKR_ARGUMENTS_BAD;
            }
            pGcmParams = (CK_GCM_PARAMS *)pSession->mechanism.pParameter;
            tag_len    = pGcmParams->ulTagBits / 8U;
            if (ulEncryptedDataLen < tag_len) {
                return CKR_DATA_LEN_RANGE;
            }
            ciphertext_len = ulEncryptedDataLen - tag_len;
            /* Size query: return required length without decrypting */
            if (pData == NULL) {
                *pulDataLen = ciphertext_len;
                return CKR_OK;
            }
            if (*pulDataLen < ciphertext_len) {
                return CKR_BUFFER_TOO_SMALL;
            }
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
            return CKR_MECHANISM_INVALID;
    }

    if (ret == STSE_OK) {
        pSession->active_operation = STSE_PKCS11_OP_NONE;
        return CKR_OK;
    }

    return CKR_DEVICE_ERROR;
}

CK_RV stse_pkcs11_generate_key_pair(CK_SESSION_HANDLE    hSession,
                                          CK_MECHANISM  *pMechanism,
                                          PLAT_UI8                  key_slot,
                                          stse_ecc_key_type_t       key_type,
                                          PLAT_UI16                 usage_limit,
                                          PLAT_UI8                 *pPublicKey,
                                          CK_OBJECT_HANDLE    *phPrivateKey,
                                          CK_OBJECT_HANDLE    *phPublicKey)
{
    stse_pkcs11_session_t    *pSession;
    stse_pkcs11_key_object_t *pPubObj  = NULL;
    stse_pkcs11_key_object_t *pPrivObj = NULL;
    stse_ReturnCode_t         ret;
    PLAT_UI8                  i;
    PLAT_UI16                 pub_key_size;

    if (!_stse_pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pSession = _stse_pkcs11_get_session(hSession);
    if (pSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if ((pMechanism == NULL) || (pPublicKey == NULL) ||
        (phPrivateKey == NULL) || (phPublicKey == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) {
        return CKR_MECHANISM_INVALID;
    }

    /* Allocate two key-object slots: one for private, one for public */
    for (i = 0U; i < STSE_PKCS11_MAX_KEY_OBJECTS; i++) {
        if (!_stse_pkcs11_ctx.key_objects[i].in_use) {
            if (pPrivObj == NULL) {
                pPrivObj = &_stse_pkcs11_ctx.key_objects[i];
            } else if (pPubObj == NULL) {
                pPubObj = &_stse_pkcs11_ctx.key_objects[i];
                break;
            }
        }
    }

    if ((pPrivObj == NULL) || (pPubObj == NULL)) {
        return CKR_HOST_MEMORY; /* no room in key store */
    }

    ret = stse_generate_ecc_key_pair(pSession->pSTSE,
                                     key_slot,
                                     key_type,
                                     usage_limit,
                                     pPublicKey);

    if (ret != STSE_OK) {
        return CKR_DEVICE_ERROR;
    }

    /* Populate the private-key object */
    pub_key_size = stse_ecc_info_table[key_type].public_key_size;
    pPrivObj->in_use      = 1U;
    pPrivObj->obj_class   = CKO_PRIVATE_KEY;
    pPrivObj->ecc_type    = key_type;
    pPrivObj->slot        = key_slot;
    pPrivObj->pub_key_size = 0U;
    pPrivObj->handle      = STSE_PKCS11_MAKE_PRIV_HANDLE(key_slot, key_type);

    /* Populate the public-key object (cache the public key bytes) */
    pPubObj->in_use      = 1U;
    pPubObj->obj_class   = CKO_PUBLIC_KEY;
    pPubObj->ecc_type    = key_type;
    pPubObj->slot        = key_slot;
    pPubObj->handle      = STSE_PKCS11_MAKE_PUB_HANDLE(key_slot, key_type);
    pPubObj->pub_key_size = pub_key_size;
    if (pub_key_size > 0U && pub_key_size <= STSE_PKCS11_MAX_PUB_KEY_SIZE) {
        (void)memcpy(pPubObj->pub_key, pPublicKey, (PLAT_UI32)pub_key_size);
    }

    *phPrivateKey = pPrivObj->handle;
    *phPublicKey  = pPubObj->handle;

    return CKR_OK;
}
