/*!
 ******************************************************************************
 * \file    pkcs11.h
 * \brief   Bundled OASIS PKCS \#11 type definitions for the STSE adaptation layer
 *
 ******************************************************************************
 * \attention
 *
 * Derived from the OASIS PKCS \#11 Cryptographic Token Interface specification
 * (https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/).
 *
 * Copyright (c) OASIS Open 2016, 2019, 2024. All Rights Reserved.
 * Distributed under the terms of the OASIS IPR Policy
 * (http://www.oasis-open.org/policies-guidelines/ipr), AS-IS, WITHOUT ANY
 * IMPLIED OR EXPRESS WARRANTY.
 *
 * This self-contained header provides all PKCS \#11 type definitions and
 * constants needed by the STSE adaptation layer, including the
 * \c CK_FUNCTION_LIST type required by the standard \c C_GetFunctionList
 * entry point.  Type definitions follow OASIS PKCS \#11 v3.0 (where
 * \c CK_GCM_PARAMS.ulIvBits was introduced).
 *
 ******************************************************************************
 */

#ifndef PKCS11_H
#define PKCS11_H

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Platform pointer helper                                                     */
/* -------------------------------------------------------------------------- */

#ifndef CK_PTR
/** \brief Indirection string used for PKCS \#11 pointer typedefs */
#define CK_PTR *
#endif

#ifndef NULL_PTR
/** \brief Null pointer constant */
#define NULL_PTR 0
#endif

/* -------------------------------------------------------------------------- */
/* Fundamental types                                                           */
/* -------------------------------------------------------------------------- */

/** \brief Unsigned 8-bit value */
typedef unsigned char     CK_BYTE;
/** \brief Unsigned 8-bit character */
typedef CK_BYTE           CK_CHAR;
/** \brief 8-bit UTF-8 character */
typedef CK_BYTE           CK_UTF8CHAR;
/** \brief Byte-sized Boolean flag */
typedef CK_BYTE           CK_BBOOL;

/** \brief Unsigned value (at least 32 bits) */
typedef unsigned long int CK_ULONG;
/** \brief Signed value (same size as CK_ULONG) */
typedef long int          CK_LONG;
/** \brief Bit-field flags */
typedef CK_ULONG          CK_FLAGS;

/** \brief Special sentinel: unavailable information */
#define CK_UNAVAILABLE_INFORMATION (~0UL)
/** \brief Special sentinel: effectively infinite */
#define CK_EFFECTIVELY_INFINITE    0UL

/* -------------------------------------------------------------------------- */
/* Pointer types                                                               */
/* -------------------------------------------------------------------------- */

typedef CK_BYTE     CK_PTR   CK_BYTE_PTR;
typedef CK_CHAR     CK_PTR   CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR   CK_UTF8CHAR_PTR;
typedef CK_ULONG    CK_PTR   CK_ULONG_PTR;
typedef void        CK_PTR   CK_VOID_PTR;

/* -------------------------------------------------------------------------- */
/* Handle types                                                                */
/* -------------------------------------------------------------------------- */

/** \brief Invalid handle sentinel */
#define CK_INVALID_HANDLE  0UL

/** \brief Session handle */
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;

/** \brief Object (key/certificate) handle */
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;

/** \brief Slot identifier */
typedef CK_ULONG CK_SLOT_ID;

/* -------------------------------------------------------------------------- */
/* Mechanism types (CK_MECHANISM_TYPE)                                        */
/* -------------------------------------------------------------------------- */

typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;

/* Return value type */
typedef CK_ULONG CK_RV;

/* -------------------------------------------------------------------------- */
/* CKB / CKF values for Boolean and flags                                     */
/* -------------------------------------------------------------------------- */

#define CK_TRUE   1
#define CK_FALSE  0

/* Session flags */
#define CKF_RW_SESSION              0x00000002UL /*!< Session is read/write */
#define CKF_SERIAL_SESSION          0x00000004UL /*!< Serial (non-parallel) session */

/* Token flags (subset) */
#define CKF_TOKEN_PRESENT           0x00000001UL
#define CKF_WRITE_PROTECTED         0x00000002UL
#define CKF_LOGIN_REQUIRED          0x00000004UL
#define CKF_TOKEN_INITIALIZED       0x00000400UL

/* -------------------------------------------------------------------------- */
/* Return codes (CKR_*)                                                       */
/* -------------------------------------------------------------------------- */

#define CKR_OK                             0x00000000UL /*!< Success */
#define CKR_CANCEL                         0x00000001UL
#define CKR_HOST_MEMORY                    0x00000002UL /*!< Insufficient host memory */
#define CKR_SLOT_ID_INVALID                0x00000003UL
#define CKR_GENERAL_ERROR                  0x00000005UL /*!< Generic error */
#define CKR_FUNCTION_FAILED                0x00000006UL
#define CKR_ARGUMENTS_BAD                  0x00000007UL /*!< Invalid arguments */
#define CKR_NO_EVENT                       0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS         0x00000009UL
#define CKR_CANT_LOCK                      0x0000000AUL
#define CKR_ATTRIBUTE_READ_ONLY            0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE            0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID         0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID        0x00000013UL
#define CKR_ACTION_PROHIBITED              0x0000001BUL
#define CKR_DATA_INVALID                   0x00000020UL /*!< Invalid data */
#define CKR_DATA_LEN_RANGE                 0x00000021UL /*!< Data length out of range */
#define CKR_DEVICE_ERROR                   0x00000030UL /*!< Device error */
#define CKR_DEVICE_MEMORY                  0x00000031UL
#define CKR_DEVICE_REMOVED                 0x00000032UL
#define CKR_ENCRYPTED_DATA_INVALID         0x00000040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE       0x00000041UL
#define CKR_FUNCTION_CANCELED              0x00000050UL
#define CKR_FUNCTION_NOT_PARALLEL          0x00000051UL
#define CKR_FUNCTION_NOT_SUPPORTED         0x00000054UL /*!< Function not supported */
#define CKR_KEY_HANDLE_INVALID             0x00000060UL /*!< Invalid key handle */
#define CKR_KEY_SIZE_RANGE                 0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT          0x00000063UL
#define CKR_KEY_NOT_NEEDED                 0x00000064UL
#define CKR_KEY_CHANGED                    0x00000065UL
#define CKR_KEY_NEEDED                     0x00000066UL
#define CKR_KEY_INDIGESTIBLE               0x00000067UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED     0x00000068UL
#define CKR_KEY_NOT_WRAPPABLE              0x00000069UL
#define CKR_KEY_UNEXTRACTABLE              0x0000006AUL
#define CKR_MECHANISM_INVALID              0x00000070UL /*!< Invalid mechanism */
#define CKR_MECHANISM_PARAM_INVALID        0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID          0x00000082UL
#define CKR_OPERATION_ACTIVE               0x00000090UL /*!< An operation is already active */
#define CKR_OPERATION_NOT_INITIALIZED      0x00000091UL /*!< No active operation */
#define CKR_PIN_INCORRECT                  0x000000A0UL
#define CKR_PIN_INVALID                    0x000000A1UL
#define CKR_PIN_LEN_RANGE                  0x000000A2UL
#define CKR_PIN_EXPIRED                    0x000000A3UL
#define CKR_PIN_LOCKED                     0x000000A4UL
#define CKR_SESSION_CLOSED                 0x000000B0UL
#define CKR_SESSION_COUNT                  0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID         0x000000B3UL /*!< Invalid session handle */
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4UL
#define CKR_SESSION_READ_ONLY              0x000000B5UL
#define CKR_SESSION_EXISTS                 0x000000B6UL
#define CKR_SESSION_READ_ONLY_EXISTS       0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS   0x000000B8UL
#define CKR_SIGNATURE_INVALID              0x000000C0UL /*!< Signature verification failed */
#define CKR_SIGNATURE_LEN_RANGE           0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE            0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT          0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT              0x000000E0UL /*!< Token not present */
#define CKR_TOKEN_NOT_RECOGNIZED           0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED          0x000000E2UL
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID  0x000000F0UL
#define CKR_UNWRAPPING_KEY_SIZE_RANGE      0x000000F1UL
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT 0x000000F2UL
#define CKR_USER_ALREADY_LOGGED_IN         0x00000100UL
#define CKR_USER_NOT_LOGGED_IN             0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED       0x00000102UL
#define CKR_USER_TYPE_INVALID              0x00000103UL
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN 0x00000104UL
#define CKR_USER_TOO_MANY_TYPES            0x00000105UL
#define CKR_WRAPPED_KEY_INVALID            0x00000110UL
#define CKR_WRAPPED_KEY_LEN_RANGE          0x00000112UL
#define CKR_WRAPPING_KEY_HANDLE_INVALID    0x00000113UL
#define CKR_WRAPPING_KEY_SIZE_RANGE        0x00000114UL
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT 0x00000115UL
#define CKR_RANDOM_SEED_NOT_SUPPORTED      0x00000120UL
#define CKR_RANDOM_NO_RNG                  0x00000121UL
#define CKR_DOMAIN_PARAMS_INVALID          0x00000130UL
#define CKR_CURVE_NOT_SUPPORTED            0x00000140UL
#define CKR_BUFFER_TOO_SMALL               0x00000150UL /*!< Output buffer too small */
#define CKR_SAVED_STATE_INVALID            0x00000160UL
#define CKR_INFORMATION_SENSITIVE          0x00000170UL
#define CKR_STATE_UNSAVEABLE               0x00000180UL
#define CKR_CRYPTOKI_NOT_INITIALIZED       0x00000190UL /*!< Cryptoki library not initialized */
#define CKR_CRYPTOKI_ALREADY_INITIALIZED   0x00000191UL
#define CKR_MUTEX_BAD                      0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED               0x000001A1UL
#define CKR_NEW_PIN_MODE                   0x000001B0UL
#define CKR_NEXT_OTP                       0x000001B1UL
#define CKR_EXCEEDED_MAX_ITERATIONS        0x000001B5UL
#define CKR_FIPS_SELF_TEST_FAILED          0x000001B6UL
#define CKR_LIBRARY_LOAD_FAILED            0x000001B7UL
#define CKR_PIN_TOO_WEAK                   0x000001B8UL
#define CKR_PUBLIC_KEY_INVALID             0x000001B9UL
#define CKR_FUNCTION_REJECTED              0x00000200UL
#define CKR_TOKEN_RESOURCE_EXCEEDED        0x00000201UL
#define CKR_OPERATION_CANCEL_FAILED        0x00000202UL
#define CKR_KEY_EXHAUSTED                  0x00000203UL
#define CKR_VENDOR_DEFINED                 0x80000000UL

/* -------------------------------------------------------------------------- */
/* Mechanism type constants (CKM_*)                                           */
/* -------------------------------------------------------------------------- */

/* Hash algorithms */
#define CKM_SHA_1                      0x00000220UL /*!< SHA-1 */
#define CKM_SHA224                     0x00000255UL /*!< SHA-224 */
#define CKM_SHA256                     0x00000250UL /*!< SHA-256 */
#define CKM_SHA384                     0x00000260UL /*!< SHA-384 */
#define CKM_SHA512                     0x00000270UL /*!< SHA-512 */
#define CKM_SHA3_224                   0x000002B5UL /*!< SHA3-224 */
#define CKM_SHA3_256                   0x000002B0UL /*!< SHA3-256 */
#define CKM_SHA3_384                   0x000002C0UL /*!< SHA3-384 */
#define CKM_SHA3_512                   0x000002D0UL /*!< SHA3-512 */

/* HMAC algorithms */
#define CKM_SHA_1_HMAC                 0x00000221UL
#define CKM_SHA256_HMAC                0x00000251UL
#define CKM_SHA384_HMAC                0x00000261UL
#define CKM_SHA512_HMAC                0x00000271UL
#define CKM_SHA3_256_HMAC              0x000002B1UL
#define CKM_SHA3_384_HMAC              0x000002C1UL
#define CKM_SHA3_512_HMAC              0x000002D1UL

/* ECC mechanisms */
#define CKM_EC_KEY_PAIR_GEN            0x00001040UL /*!< ECC key-pair generation */
#define CKM_ECDSA                      0x00001041UL /*!< ECDSA (hash supplied by caller) */
#define CKM_ECDSA_SHA1                 0x00001042UL /*!< ECDSA with SHA-1 */
#define CKM_ECDSA_SHA224               0x00001043UL /*!< ECDSA with SHA-224 */
#define CKM_ECDSA_SHA256               0x00001044UL /*!< ECDSA with SHA-256 */
#define CKM_ECDSA_SHA384               0x00001045UL /*!< ECDSA with SHA-384 */
#define CKM_ECDSA_SHA512               0x00001046UL /*!< ECDSA with SHA-512 */
#define CKM_ECDH1_DERIVE               0x00001050UL /*!< ECDH key derivation */

/* AES mechanisms */
#define CKM_AES_KEY_GEN                0x00001080UL
#define CKM_AES_ECB                    0x00001081UL /*!< AES-ECB */
#define CKM_AES_CBC                    0x00001082UL /*!< AES-CBC */
#define CKM_AES_CBC_PAD                0x00001085UL /*!< AES-CBC with padding */
#define CKM_AES_CTR                    0x00001086UL /*!< AES-CTR */
#define CKM_AES_GCM                    0x00001087UL /*!< AES-GCM */
#define CKM_AES_CCM                    0x00001088UL /*!< AES-CCM */
#define CKM_AES_CMAC                   0x0000108AUL /*!< AES-CMAC */
#define CKM_AES_CMAC_GENERAL           0x0000108BUL

/* -------------------------------------------------------------------------- */
/* Object classes (CK_OBJECT_CLASS / CKO_*)                                   */
/* -------------------------------------------------------------------------- */

typedef CK_ULONG CK_OBJECT_CLASS;
#define CKO_DATA            0x00000000UL
#define CKO_CERTIFICATE     0x00000001UL
#define CKO_PUBLIC_KEY      0x00000002UL
#define CKO_PRIVATE_KEY     0x00000003UL
#define CKO_SECRET_KEY      0x00000004UL
#define CKO_HW_FEATURE      0x00000005UL
#define CKO_DOMAIN_PARAMETERS 0x00000006UL
#define CKO_MECHANISM       0x00000007UL
#define CKO_VENDOR_DEFINED  0x80000000UL

/* -------------------------------------------------------------------------- */
/* Key types (CK_KEY_TYPE / CKK_*)                                            */
/* -------------------------------------------------------------------------- */

typedef CK_ULONG CK_KEY_TYPE;
#define CKK_RSA             0x00000000UL
#define CKK_DSA             0x00000001UL
#define CKK_DH              0x00000002UL
#define CKK_EC              0x00000003UL
#define CKK_GENERIC_SECRET  0x00000010UL
#define CKK_AES             0x0000001FUL
#define CKK_EC_EDWARDS      0x00000040UL /*!< EdDSA (Ed25519/Ed448) */
#define CKK_EC_MONTGOMERY   0x00000041UL /*!< Curve25519/Curve448 */
#define CKK_HKDF            0x00000042UL
#define CKK_ML_KEM          0x00000049UL /*!< ML-KEM (FIPS 203) */
#define CKK_ML_DSA          0x0000004AUL /*!< ML-DSA (FIPS 204) */
#define CKK_SLH_DSA         0x0000004BUL /*!< SLH-DSA (FIPS 205) */
#define CKK_VENDOR_DEFINED  0x80000000UL

/* -------------------------------------------------------------------------- */
/* Attribute types (CK_ATTRIBUTE_TYPE / CKA_*)                                */
/* -------------------------------------------------------------------------- */

typedef CK_ULONG CK_ATTRIBUTE_TYPE;
#define CKA_CLASS           0x00000000UL
#define CKA_TOKEN           0x00000001UL
#define CKA_PRIVATE         0x00000002UL
#define CKA_LABEL           0x00000003UL
#define CKA_KEY_TYPE        0x00000100UL
#define CKA_ID              0x00000102UL
#define CKA_SENSITIVE       0x00000103UL
#define CKA_ENCRYPT         0x00000104UL
#define CKA_DECRYPT         0x00000105UL
#define CKA_WRAP            0x00000106UL
#define CKA_UNWRAP          0x00000107UL
#define CKA_SIGN            0x00000108UL
#define CKA_VERIFY          0x0000010AUL
#define CKA_DERIVE          0x0000010CUL
#define CKA_MODULUS_BITS    0x00000121UL
#define CKA_EC_PARAMS       0x00000180UL
#define CKA_EC_POINT        0x00000181UL
#define CKA_VALUE           0x00000011UL
#define CKA_VALUE_LEN       0x00000161UL
#define CKA_EXTRACTABLE     0x00000162UL
#define CKA_VENDOR_DEFINED  0x80000000UL

/* CK_ATTRIBUTE structure */
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen; /*!< in bytes */
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

/* -------------------------------------------------------------------------- */
/* Mechanism parameter structures                                             */
/* -------------------------------------------------------------------------- */

/** \brief CK_GCM_PARAMS: AES-GCM mechanism parameters */
typedef struct CK_GCM_PARAMS {
    CK_BYTE_PTR pIv;       /*!< Initialisation vector buffer */
    CK_ULONG    ulIvLen;   /*!< IV length in bytes */
    CK_ULONG    ulIvBits;  /*!< IV length in bits */
    CK_BYTE_PTR pAAD;      /*!< Additional authenticated data buffer */
    CK_ULONG    ulAADLen;  /*!< AAD length in bytes */
    CK_ULONG    ulTagBits; /*!< Authentication tag length in bits */
} CK_GCM_PARAMS;
typedef CK_GCM_PARAMS CK_PTR CK_GCM_PARAMS_PTR;

/** \brief CK_CCM_PARAMS: AES-CCM mechanism parameters */
typedef struct CK_CCM_PARAMS {
    CK_ULONG    ulDataLen;  /*!< Plaintext/ciphertext data length */
    CK_BYTE_PTR pNonce;     /*!< Nonce buffer */
    CK_ULONG    ulNonceLen; /*!< Nonce length in bytes */
    CK_BYTE_PTR pAAD;       /*!< Additional authenticated data buffer */
    CK_ULONG    ulAADLen;   /*!< AAD length in bytes */
    CK_ULONG    ulMACLen;   /*!< MAC/tag length in bytes */
} CK_CCM_PARAMS;
typedef CK_CCM_PARAMS CK_PTR CK_CCM_PARAMS_PTR;

/** \brief CK_MECHANISM: mechanism descriptor */
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;    /*!< Mechanism type identifier (CKM_*) */
    CK_VOID_PTR       pParameter;   /*!< Pointer to mechanism-specific parameters */
    CK_ULONG          ulParameterLen; /*!< Parameter buffer length in bytes */
} CK_MECHANISM;
typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;

/* -------------------------------------------------------------------------- */
/* User type                                                                   */
/* -------------------------------------------------------------------------- */

typedef CK_ULONG CK_USER_TYPE;
#define CKU_SO              0UL /*!< Security Officer */
#define CKU_USER            1UL /*!< Normal user */
#define CKU_CONTEXT_SPECIFIC 2UL

/* -------------------------------------------------------------------------- */
/* Version structure                                                           */
/* -------------------------------------------------------------------------- */

typedef struct CK_VERSION {
    CK_BYTE major;  /*!< Integer portion of version number */
    CK_BYTE minor;  /*!< 1/100ths portion of version number */
} CK_VERSION;

/* -------------------------------------------------------------------------- */
/* Notification callback                                                       */
/* -------------------------------------------------------------------------- */

typedef CK_ULONG CK_NOTIFICATION;
#define CKN_SURRENDER    0UL
#define CKN_OTP_CHANGED  1UL

typedef CK_RV (* CK_NOTIFY)(CK_SESSION_HANDLE hSession,
                             CK_NOTIFICATION   event,
                             CK_VOID_PTR       pApplication);

/* -------------------------------------------------------------------------- */
/* CK_INFO – library information                                              */
/* -------------------------------------------------------------------------- */

typedef struct CK_INFO {
    CK_VERSION    cryptokiVersion;         /*!< Cryptoki interface version */
    CK_UTF8CHAR   manufacturerID[32];      /*!< Blank padded */
    CK_FLAGS      flags;                   /*!< Must be zero */
    CK_UTF8CHAR   libraryDescription[32];  /*!< Blank padded */
    CK_VERSION    libraryVersion;          /*!< Library version */
} CK_INFO;
typedef CK_INFO CK_PTR CK_INFO_PTR;

/* -------------------------------------------------------------------------- */
/* CK_SLOT_INFO – slot information                                            */
/* -------------------------------------------------------------------------- */

/** Slot flags — CKF_TOKEN_PRESENT (0x00000001) is already defined above */
#define CKF_REMOVABLE_DEVICE  0x00000002UL
#define CKF_HW_SLOT           0x00000004UL

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR  slotDescription[64]; /*!< Blank padded */
    CK_UTF8CHAR  manufacturerID[32];  /*!< Blank padded */
    CK_FLAGS     flags;
    CK_VERSION   hardwareVersion;
    CK_VERSION   firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;

/* -------------------------------------------------------------------------- */
/* CK_TOKEN_INFO – token information                                          */
/* -------------------------------------------------------------------------- */

/** Token flags (subset) */
#define CKF_USER_PIN_INITIALIZED    0x00000008UL
#define CKF_CLOCK_ON_TOKEN          0x00000040UL
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200UL
/* CKF_TOKEN_INITIALIZED (0x00000400) is defined in the token flags section above */
#define CKF_USER_CARDHOLDER         0x01000000UL

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR  label[32];            /*!< Blank padded */
    CK_UTF8CHAR  manufacturerID[32];   /*!< Blank padded */
    CK_UTF8CHAR  model[16];            /*!< Blank padded */
    CK_CHAR      serialNumber[16];     /*!< Blank padded */
    CK_FLAGS     flags;
    CK_ULONG     ulMaxSessionCount;
    CK_ULONG     ulSessionCount;
    CK_ULONG     ulMaxRwSessionCount;
    CK_ULONG     ulRwSessionCount;
    CK_ULONG     ulMaxPinLen;
    CK_ULONG     ulMinPinLen;
    CK_ULONG     ulTotalPublicMemory;
    CK_ULONG     ulFreePublicMemory;
    CK_ULONG     ulTotalPrivateMemory;
    CK_ULONG     ulFreePrivateMemory;
    CK_VERSION   hardwareVersion;
    CK_VERSION   firmwareVersion;
    CK_CHAR      utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;

/* -------------------------------------------------------------------------- */
/* CK_MECHANISM_INFO – mechanism capabilities                                 */
/* -------------------------------------------------------------------------- */

/** Mechanism flags */
#define CKF_HW              0x00000001UL /*!< Performed in hardware */
#define CKF_ENCRYPT         0x00000100UL
#define CKF_DECRYPT         0x00000200UL
#define CKF_DIGEST          0x00000400UL
#define CKF_SIGN            0x00000800UL
#define CKF_SIGN_RECOVER    0x00001000UL
#define CKF_VERIFY          0x00002000UL
#define CKF_VERIFY_RECOVER  0x00004000UL
#define CKF_GENERATE        0x00008000UL
#define CKF_GENERATE_KEY_PAIR 0x00010000UL
#define CKF_WRAP            0x00020000UL
#define CKF_UNWRAP          0x00040000UL
#define CKF_DERIVE          0x00080000UL
#define CKF_EC_F_P          0x00100000UL
#define CKF_EC_NAMEDCURVE   0x00400000UL
#define CKF_EC_UNCOMPRESS   0x01000000UL
#define CKF_EC_COMPRESS     0x02000000UL

typedef struct CK_MECHANISM_INFO {
    CK_ULONG  ulMinKeySize; /*!< Minimum key size in bits */
    CK_ULONG  ulMaxKeySize; /*!< Maximum key size in bits */
    CK_FLAGS  flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;

/* -------------------------------------------------------------------------- */
/* CK_SESSION_INFO                                                            */
/* -------------------------------------------------------------------------- */

typedef CK_ULONG CK_STATE;
#define CKS_RO_PUBLIC_SESSION   0UL
#define CKS_RO_USER_FUNCTIONS   1UL
#define CKS_RW_PUBLIC_SESSION   2UL
#define CKS_RW_USER_FUNCTIONS   3UL
#define CKS_RW_SO_FUNCTIONS     4UL

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID  slotID;
    CK_STATE    state;
    CK_FLAGS    flags;
    CK_ULONG    ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;

/* -------------------------------------------------------------------------- */
/* CK_C_INITIALIZE_ARGS – C_Initialize arguments                              */
/* -------------------------------------------------------------------------- */

/** C_Initialize flags */
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS  0x00000001UL
#define CKF_OS_LOCKING_OK                   0x00000002UL

typedef CK_RV (* CK_CREATEMUTEX)(CK_VOID_PTR CK_PTR ppMutex);
typedef CK_RV (* CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (* CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (* CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX  CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX    LockMutex;
    CK_UNLOCKMUTEX  UnlockMutex;
    CK_FLAGS        flags;
    CK_VOID_PTR     pReserved;
} CK_C_INITIALIZE_ARGS;
typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;

/* -------------------------------------------------------------------------- */
/* CK_FUNCTION_LIST – standard PKCS \#11 function pointer table               */
/* -------------------------------------------------------------------------- */

/* Forward-declare to allow self-referential pointer in function list */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

struct CK_FUNCTION_LIST {
    CK_VERSION version;

    CK_RV (* C_Initialize)(CK_VOID_PTR pInitArgs);
    CK_RV (* C_Finalize)(CK_VOID_PTR pReserved);
    CK_RV (* C_GetInfo)(CK_INFO_PTR pInfo);
    CK_RV (* C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV (* C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID CK_PTR pSlotList, CK_ULONG_PTR pulCount);
    CK_RV (* C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
    CK_RV (* C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
    CK_RV (* C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
    CK_RV (* C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
    CK_RV (* C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
    CK_RV (* C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV (* C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
    CK_RV (* C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE CK_PTR phSession);
    CK_RV (* C_CloseSession)(CK_SESSION_HANDLE hSession);
    CK_RV (* C_CloseAllSessions)(CK_SLOT_ID slotID);
    CK_RV (* C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    CK_RV (* C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
    CK_RV (* C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
    CK_RV (* C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV (* C_Logout)(CK_SESSION_HANDLE hSession);
    CK_RV (* C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_RV (* C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
    CK_RV (* C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_RV (* C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
    CK_RV (* C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (* C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (* C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (* C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
    CK_RV (* C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
    CK_RV (* C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (* C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    CK_RV (* C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_RV (* C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
    CK_RV (* C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (* C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (* C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_RV (* C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
    CK_RV (* C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
    CK_RV (* C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_RV (* C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (* C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
    CK_RV (* C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_RV (* C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (* C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (* C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (* C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (* C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (* C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (* C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (* C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_RV (* C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (* C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_RV (* C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (* C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (* C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_RV (* C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_RV (* C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_RV (* C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_RV (* C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_RV (* C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
    CK_RV (* C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
    CK_RV (* C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_RV (* C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_RV (* C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
    CK_RV (* C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
    CK_RV (* C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
    CK_RV (* C_CancelFunction)(CK_SESSION_HANDLE hSession);
    CK_RV (* C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID CK_PTR pSlot, CK_VOID_PTR pReserved);
};

/* PKCS #11 Cryptoki version supported */
#define CRYPTOKI_VERSION_MAJOR  3
#define CRYPTOKI_VERSION_MINOR  0

#ifdef __cplusplus
}
#endif

#endif /* PKCS11_H */
