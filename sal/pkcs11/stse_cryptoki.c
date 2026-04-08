/*!
 ******************************************************************************
 * \file    stse_cryptoki.c
 * \brief   STSE standard PKCS \#11 Cryptoki entry points
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
 *
 * \details
 * This file implements the full standard PKCS \#11 \c C_* function table
 * following the same pattern as cryptoauthlib (pkcs11_main.c):
 *
 *  - Internal implementation functions live in stse_pkcs11.c.
 *  - This file provides the public \c C_* wrappers and exports the
 *    \c CK_FUNCTION_LIST via \c C_GetFunctionList.
 *  - Slot/token management is provided through the slot registry in
 *    stse_pkcs11.c (see \ref stse_pkcs11_register_slot).
 *  - Functions not supported by STSE hardware return
 *    \c CKR_FUNCTION_NOT_SUPPORTED.
 *
 * Typical initialization sequence:
 * \code
 *   CK_FUNCTION_LIST_PTR pFunc;
 *   C_GetFunctionList(&pFunc);
 *   pFunc->C_Initialize(NULL_PTR);
 *   stse_pkcs11_register_slot(0, &stse_handler);
 *   pFunc->C_OpenSession(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
 * \endcode
 ******************************************************************************
 */

#include "sal/pkcs11/stse_pkcs11.h"
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Forward declarations for the function table                                 */
/* -------------------------------------------------------------------------- */

static CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
static CK_RV C_Finalize(CK_VOID_PTR pReserved);
static CK_RV C_GetInfo(CK_INFO_PTR pInfo);
static CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
static CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID CK_PTR pSlotList, CK_ULONG_PTR pulCount);
static CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
static CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
static CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
static CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
static CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
static CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
static CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
static CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE CK_PTR phSession);
static CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
static CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
static CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
static CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
static CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
static CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
static CK_RV C_Logout(CK_SESSION_HANDLE hSession);
static CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
static CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
static CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
static CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
static CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
static CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
static CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
static CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
static CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
static CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
static CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
static CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
static CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
static CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
static CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
static CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
static CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
static CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
static CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
static CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
static CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
static CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
static CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
static CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
static CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
static CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
static CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
static CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
static CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
static CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
static CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
static CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
static CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
static CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
static CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
static CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
static CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
static CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
static CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
static CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
static CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
static CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
static CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
static CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);
static CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID CK_PTR pSlot, CK_VOID_PTR pReserved);

/* -------------------------------------------------------------------------- */
/* Supported mechanism list                                                    */
/* -------------------------------------------------------------------------- */

static const CK_MECHANISM_TYPE _stse_mech_list[] = {
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_ECDH1_DERIVE,
    CKM_AES_ECB,
    CKM_AES_CCM,
    CKM_AES_GCM,
    CKM_AES_CMAC,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
};

#define STSE_MECH_COUNT  ((CK_ULONG)(sizeof(_stse_mech_list) / sizeof(_stse_mech_list[0])))

/* -------------------------------------------------------------------------- */
/* Standard PKCS #11 function list                                             */
/* -------------------------------------------------------------------------- */

static CK_FUNCTION_LIST stse_function_list = {
    /* version */
    { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
    /* function pointers */
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

/* -------------------------------------------------------------------------- */
/* Helper: look up a key object in the global key store by handle              */
/* -------------------------------------------------------------------------- */

static stse_pkcs11_key_object_t *_find_key_object(CK_OBJECT_HANDLE hKey)
{
    PLAT_UI8 i;

    for (i = 0U; i < STSE_PKCS11_MAX_KEY_OBJECTS; i++) {
        if (_stse_pkcs11_ctx.key_objects[i].in_use &&
            _stse_pkcs11_ctx.key_objects[i].handle == hKey) {
            return &_stse_pkcs11_ctx.key_objects[i];
        }
    }
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* C_GetFunctionList — standard PKCS #11 library entry point                  */
/* -------------------------------------------------------------------------- */

/**
 * \brief Returns a pointer to the STSE PKCS \#11 function list.
 *        This is the standard Cryptoki entry point called by PKCS \#11-aware
 *        middleware to obtain all function pointers.
 */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &stse_function_list;

    return CKR_OK;
}

/* -------------------------------------------------------------------------- */
/* Library initialisation / finalisation                                       */
/* -------------------------------------------------------------------------- */

static CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    (void)pInitArgs; /* mutex/threading not required on embedded target */
    return stse_pkcs11_initialize();
}

static CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    if (pReserved != NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    return stse_pkcs11_finalize();
}

static CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    static const CK_BYTE mfr[32] = "STMicroelectronics              ";
    static const CK_BYTE lib[32] = "STSELib PKCS#11 Adapter         ";

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
    (void)memcpy(pInfo->manufacturerID, mfr, 32U);
    pInfo->flags = 0U;
    (void)memcpy(pInfo->libraryDescription, lib, 32U);
    pInfo->libraryVersion.major = 1U;
    pInfo->libraryVersion.minor = 0U;

    return CKR_OK;
}

/* -------------------------------------------------------------------------- */
/* Slot / token management                                                     */
/* -------------------------------------------------------------------------- */

static CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID CK_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    CK_ULONG count = 0U;
    PLAT_UI8 i;

    (void)tokenPresent;

    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 0U; i < STSE_PKCS11_MAX_SLOTS; i++) {
        if (_stse_pkcs11_ctx.slots[i].in_use) {
            if (pSlotList != NULL) {
                if (count >= *pulCount) {
                    return CKR_BUFFER_TOO_SMALL;
                }
                pSlotList[count] = (CK_SLOT_ID)i;
            }
            count++;
        }
    }

    *pulCount = count;
    return CKR_OK;
}

static CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    static const CK_BYTE slot_desc[64] =
        "STSAFE-Axx Secure Element Slot                                  ";

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (slotID >= STSE_PKCS11_MAX_SLOTS || !_stse_pkcs11_ctx.slots[slotID].in_use) {
        return CKR_SLOT_ID_INVALID;
    }

    (void)memcpy(pInfo->slotDescription, slot_desc, 64U);
    (void)memset(pInfo->manufacturerID, (int)' ', 32U);
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 1U;
    pInfo->hardwareVersion.minor = 0U;
    pInfo->firmwareVersion.major = 0U;
    pInfo->firmwareVersion.minor = 0U;

    return CKR_OK;
}

static CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    static const CK_BYTE token_label[32] =
        "STSAFE-A Token                  ";

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (slotID >= STSE_PKCS11_MAX_SLOTS || !_stse_pkcs11_ctx.slots[slotID].in_use) {
        return CKR_SLOT_ID_INVALID;
    }

    (void)memcpy(pInfo->label, token_label, 32U);
    (void)memset(pInfo->manufacturerID, (int)' ', 32U);
    (void)memset(pInfo->model, (int)' ', 16U);
    (void)memset(pInfo->serialNumber, (int)' ', 16U);
    pInfo->flags               = CKF_TOKEN_INITIALIZED | CKF_TOKEN_PRESENT;
    pInfo->ulMaxSessionCount   = STSE_PKCS11_MAX_SESSIONS;
    pInfo->ulSessionCount      = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = STSE_PKCS11_MAX_SESSIONS;
    pInfo->ulRwSessionCount    = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen         = 0U;
    pInfo->ulMinPinLen         = 0U;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory  = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory  = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1U;
    pInfo->hardwareVersion.minor = 0U;
    pInfo->firmwareVersion.major = 0U;
    pInfo->firmwareVersion.minor = 0U;
    (void)memset(pInfo->utcTime, (int)' ', 16U);

    return CKR_OK;
}

static CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (slotID >= STSE_PKCS11_MAX_SLOTS || !_stse_pkcs11_ctx.slots[slotID].in_use) {
        return CKR_SLOT_ID_INVALID;
    }

    if (pMechanismList != NULL) {
        if (*pulCount < STSE_MECH_COUNT) {
            *pulCount = STSE_MECH_COUNT;
            return CKR_BUFFER_TOO_SMALL;
        }
        (void)memcpy(pMechanismList, _stse_mech_list, STSE_MECH_COUNT * sizeof(CK_MECHANISM_TYPE));
    }

    *pulCount = STSE_MECH_COUNT;
    return CKR_OK;
}

static CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    CK_ULONG i;

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (slotID >= STSE_PKCS11_MAX_SLOTS || !_stse_pkcs11_ctx.slots[slotID].in_use) {
        return CKR_SLOT_ID_INVALID;
    }

    for (i = 0U; i < STSE_MECH_COUNT; i++) {
        if (_stse_mech_list[i] == type) {
            pInfo->ulMinKeySize = 128U;
            pInfo->ulMaxKeySize = 521U;
            pInfo->flags        = CKF_HW;
            if (type == CKM_ECDSA || type == CKM_ECDSA_SHA256 ||
                type == CKM_ECDSA_SHA384 || type == CKM_ECDSA_SHA512) {
                pInfo->flags |= CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
                                CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;
            } else if (type == CKM_EC_KEY_PAIR_GEN) {
                pInfo->flags |= CKF_GENERATE_KEY_PAIR | CKF_EC_F_P |
                                CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;
            } else if (type == CKM_ECDH1_DERIVE) {
                pInfo->flags |= CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE;
            } else if (type == CKM_AES_ECB || type == CKM_AES_CCM || type == CKM_AES_GCM) {
                pInfo->flags       |= CKF_ENCRYPT | CKF_DECRYPT;
                pInfo->ulMinKeySize = 128U;
                pInfo->ulMaxKeySize = 256U;
            } else if (type == CKM_AES_CMAC) {
                pInfo->flags       |= CKF_SIGN | CKF_VERIFY;
                pInfo->ulMinKeySize = 128U;
                pInfo->ulMaxKeySize = 256U;
            } else {
                /* digest mechanisms */
                pInfo->flags       |= CKF_DIGEST;
                pInfo->ulMinKeySize = 0U;
                pInfo->ulMaxKeySize = 0U;
            }
            return CKR_OK;
        }
    }

    return CKR_MECHANISM_INVALID;
}

static CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    (void)slotID; (void)pPin; (void)ulPinLen; (void)pLabel;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    (void)hSession; (void)pPin; (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    (void)hSession; (void)pOldPin; (void)ulOldLen; (void)pNewPin; (void)ulNewLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Session management                                                          */
/* -------------------------------------------------------------------------- */

static CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE CK_PTR phSession)
{
    (void)pApplication;
    (void)Notify;
    return stse_pkcs11_open_session(slotID, flags, phSession);
}

static CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    return stse_pkcs11_close_session(hSession);
}

static CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    PLAT_UI8 i;

    (void)slotID;

    for (i = 0U; i < STSE_PKCS11_MAX_SESSIONS; i++) {
        if (_stse_pkcs11_ctx.sessions[i].in_use &&
            _stse_pkcs11_ctx.sessions[i].slotID == slotID) {
            _stse_pkcs11_ctx.sessions[i].in_use = 0U;
            _stse_pkcs11_ctx.sessions[i].pSTSE  = NULL;
            _stse_pkcs11_ctx.sessions[i].active_operation = STSE_PKCS11_OP_NONE;
        }
    }

    return CKR_OK;
}

static CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    PLAT_UI8 idx;

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (hSession == CK_INVALID_HANDLE || hSession > STSE_PKCS11_MAX_SESSIONS) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    idx = (PLAT_UI8)(hSession - 1U);

    if (!_stse_pkcs11_ctx.sessions[idx].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    pInfo->slotID      = _stse_pkcs11_ctx.sessions[idx].slotID;
    pInfo->state       = CKS_RW_PUBLIC_SESSION;
    pInfo->flags       = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    pInfo->ulDeviceError = 0U;

    return CKR_OK;
}

static CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    (void)hSession; (void)pOperationState; (void)pulOperationStateLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)hSession; (void)pOperationState; (void)ulOperationStateLen;
    (void)hEncryptionKey; (void)hAuthenticationKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    (void)hSession; (void)userType; (void)pPin; (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Object management — CreateObject imports a public key into the key store    */
/* -------------------------------------------------------------------------- */

static CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    stse_pkcs11_key_object_t *pObj = NULL;
    CK_OBJECT_CLASS  obj_class    = CKO_VENDOR_DEFINED;
    stse_ecc_key_type_t ecc_type  = STSE_ECC_KT_INVALID;
    CK_BYTE_PTR  pub_key_val      = NULL;
    CK_ULONG     pub_key_len      = 0U;
    PLAT_UI8     key_slot         = 0U;
    CK_ULONG     i;
    PLAT_UI8     j;

    (void)hSession;

    if ((pTemplate == NULL) || (phObject == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    /* Parse template attributes */
    for (i = 0U; i < ulCount; i++) {
        if (pTemplate[i].pValue == NULL) {
            continue;
        }
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                obj_class = *(CK_OBJECT_CLASS *)pTemplate[i].pValue;
                break;
            case CKA_ID:
                if (pTemplate[i].ulValueLen >= 1U) {
                    key_slot = *(CK_BYTE_PTR)pTemplate[i].pValue;
                }
                break;
            case CKA_EC_POINT:
                pub_key_val = (CK_BYTE_PTR)pTemplate[i].pValue;
                pub_key_len = pTemplate[i].ulValueLen;
                break;
            /* CKA_KEY_TYPE / CKA_EC_PARAMS: derive ECC type from key size */
            default:
                break;
        }
    }

    if (obj_class != CKO_PUBLIC_KEY || pub_key_val == NULL || pub_key_len == 0U) {
        return CKR_TEMPLATE_INCONSISTENT;
    }

    /* Infer ECC type from public key size */
    for (j = 0U; j < (PLAT_UI8)STSE_ECC_KT_INVALID; j++) {
        if ((PLAT_UI16)pub_key_len == stse_ecc_info_table[j].public_key_size) {
            ecc_type = (stse_ecc_key_type_t)j;
            break;
        }
    }

    if (ecc_type == STSE_ECC_KT_INVALID) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    /* Allocate a key object slot */
    for (j = 0U; j < STSE_PKCS11_MAX_KEY_OBJECTS; j++) {
        if (!_stse_pkcs11_ctx.key_objects[j].in_use) {
            pObj = &_stse_pkcs11_ctx.key_objects[j];
            break;
        }
    }

    if (pObj == NULL) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    pObj->in_use        = 1U;
    pObj->obj_class     = obj_class;
    pObj->ecc_type      = ecc_type;
    pObj->slot          = key_slot;
    pObj->pub_key_size  = (PLAT_UI16)pub_key_len;
    pObj->handle        = STSE_PKCS11_MAKE_PUB_HANDLE(key_slot, ecc_type);
    if (pub_key_len <= STSE_PKCS11_MAX_PUB_KEY_SIZE) {
        (void)memcpy(pObj->pub_key, pub_key_val, pub_key_len);
    }

    *phObject = pObj->handle;

    return CKR_OK;
}

static CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount; (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    stse_pkcs11_key_object_t *pObj;

    (void)hSession;

    pObj = _find_key_object(hObject);
    if (pObj == NULL) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    pObj->in_use = 0U;

    return CKR_OK;
}

static CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    (void)hSession; (void)hObject; (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    stse_pkcs11_key_object_t *pObj;
    CK_ULONG i;

    (void)hSession;

    if (pTemplate == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    pObj = _find_key_object(hObject);
    if (pObj == NULL) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    for (i = 0U; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                if (pTemplate[i].pValue != NULL && pTemplate[i].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
                    *(CK_OBJECT_CLASS *)pTemplate[i].pValue = pObj->obj_class;
                }
                pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
                break;
            case CKA_EC_POINT:
                if (pObj->obj_class == CKO_PUBLIC_KEY) {
                    if (pTemplate[i].pValue != NULL && pTemplate[i].ulValueLen >= pObj->pub_key_size) {
                        (void)memcpy(pTemplate[i].pValue, pObj->pub_key, pObj->pub_key_size);
                    }
                    pTemplate[i].ulValueLen = pObj->pub_key_size;
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                }
                break;
            default:
                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                break;
        }
    }

    return CKR_OK;
}

static CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    (void)hSession; (void)pTemplate; (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    (void)hSession; (void)phObject; (void)ulMaxObjectCount; (void)pulObjectCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Encryption / decryption                                                     */
/* -------------------------------------------------------------------------- */

static CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return stse_pkcs11_encrypt_init(hSession, pMechanism, hKey);
}

static CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    return stse_pkcs11_encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

static CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    (void)hSession; (void)pLastEncryptedPart; (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return stse_pkcs11_decrypt_init(hSession, pMechanism, hKey);
}

static CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return stse_pkcs11_decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}

static CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    (void)hSession; (void)pLastPart; (void)pulLastPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Digest                                                                      */
/* -------------------------------------------------------------------------- */

static CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    return stse_pkcs11_digest_init(hSession, pMechanism);
}

static CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_RV rv;

    rv = stse_pkcs11_digest_update(hSession, pData, ulDataLen);
    if (rv != CKR_OK) {
        return rv;
    }

    return stse_pkcs11_digest_final(hSession, pDigest, pulDigestLen);
}

static CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return stse_pkcs11_digest_update(hSession, pPart, ulPartLen);
}

static CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    (void)hSession; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    return stse_pkcs11_digest_final(hSession, pDigest, pulDigestLen);
}

/* -------------------------------------------------------------------------- */
/* Signing                                                                     */
/* -------------------------------------------------------------------------- */

static CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    stse_pkcs11_key_object_t *pObj;

    pObj = _find_key_object(hKey);
    if (pObj == NULL) {
        /* Fall back: treat hKey as an encoded handle */
        return stse_pkcs11_sign_init(hSession, pMechanism,
                                     STSE_PKCS11_HANDLE_SLOT(hKey),
                                     STSE_PKCS11_HANDLE_KEY_TYPE(hKey));
    }

    return stse_pkcs11_sign_init(hSession, pMechanism, pObj->slot, pObj->ecc_type);
}

static CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return stse_pkcs11_sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

static CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

static CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    stse_pkcs11_key_object_t *pObj;

    pObj = _find_key_object(hKey);
    if (pObj == NULL) {
        return CKR_KEY_HANDLE_INVALID;
    }

    if (pObj->obj_class != CKO_PUBLIC_KEY || pObj->pub_key_size == 0U) {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    return stse_pkcs11_verify_init(hSession, pMechanism,
                                   (CK_OBJECT_HANDLE)pObj->ecc_type,
                                   pObj->pub_key);
}

static CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return stse_pkcs11_verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}

static CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession; (void)pSignature; (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    (void)hSession; (void)pSignature; (void)ulSignatureLen; (void)pData; (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Dual-function operations (not supported)                                    */
/* -------------------------------------------------------------------------- */

static CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Key generation                                                              */
/* -------------------------------------------------------------------------- */

static CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession; (void)pMechanism; (void)pTemplate; (void)ulCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * \brief Standard PKCS \#11 \c C_GenerateKeyPair wrapping
 *        \ref stse_pkcs11_generate_key_pair.
 *
 * The private-key template must contain:
 *   - \c CKA_ID (1 byte): STSE key slot number.
 *
 * The public-key template must contain:
 *   - \c CKA_ID (1 byte): STSE key slot number (same as private-key template).
 *
 * The \c key_type (ECC curve) is taken from the \c CKA_EC_PARAMS attribute
 * in the public-key template; if not present, it defaults to
 * \ref STSE_ECC_KT_NIST_P_256.  A temporary buffer is allocated on the stack
 * to receive the generated public key from the STSE device.
 */
static CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    PLAT_UI8            key_slot         = 0U;
    stse_ecc_key_type_t ecc_type         = STSE_ECC_KT_NIST_P_256;
    PLAT_UI16           usage_limit      = 0U;
    PLAT_UI8            pub_key_buf[STSE_PKCS11_MAX_PUB_KEY_SIZE];
    CK_ULONG            i;

    /* Extract key_slot from private-key template (CKA_ID) */
    if (pPrivateKeyTemplate != NULL) {
        for (i = 0U; i < ulPrivateKeyAttributeCount; i++) {
            if (pPrivateKeyTemplate[i].type == CKA_ID &&
                pPrivateKeyTemplate[i].pValue != NULL &&
                pPrivateKeyTemplate[i].ulValueLen >= 1U) {
                key_slot = *(CK_BYTE_PTR)pPrivateKeyTemplate[i].pValue;
            }
        }
    }

    /* Extract ecc_type from public-key template (CKA_EC_PARAMS = OID bytes)
     * For simplicity we use the modulus bits if available; callers can pass
     * the slot-encoded ecc_type via a vendor CKA attribute, or accept the
     * default of NIST P-256. */
    if (pPublicKeyTemplate != NULL) {
        for (i = 0U; i < ulPublicKeyAttributeCount; i++) {
            if (pPublicKeyTemplate[i].type == CKA_VENDOR_DEFINED &&
                pPublicKeyTemplate[i].pValue != NULL &&
                pPublicKeyTemplate[i].ulValueLen == sizeof(stse_ecc_key_type_t)) {
                ecc_type = *(stse_ecc_key_type_t *)pPublicKeyTemplate[i].pValue;
            }
        }
    }

    return stse_pkcs11_generate_key_pair(hSession, pMechanism,
                                         key_slot, ecc_type, usage_limit,
                                         pub_key_buf,
                                         phPrivateKey, phPublicKey);
}

static CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    (void)hSession; (void)pMechanism; (void)hWrappingKey; (void)hKey; (void)pWrappedKey; (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession; (void)pMechanism; (void)hUnwrappingKey; (void)pWrappedKey; (void)ulWrappedKeyLen; (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession; (void)pMechanism; (void)hBaseKey; (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
/* Random number generation                                                    */
/* -------------------------------------------------------------------------- */

static CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    (void)hSession; (void)pSeed; (void)ulSeedLen;
    return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

static CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    return stse_pkcs11_generate_random(hSession, RandomData, ulRandomLen);
}

/* -------------------------------------------------------------------------- */
/* Legacy parallel-function stubs                                              */
/* -------------------------------------------------------------------------- */

static CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}

static CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}

static CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID CK_PTR pSlot, CK_VOID_PTR pReserved)
{
    (void)flags; (void)pSlot; (void)pRserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
