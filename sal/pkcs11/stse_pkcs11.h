/*!
 ******************************************************************************
 * \file    stse_pkcs11.h
 * \brief   STSE PKCS \#11 adaptation layer (header)
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

#ifndef STSE_PKCS11_H
#define STSE_PKCS11_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "api/stse_aes.h"
#include "api/stse_asymmetric_keys_management.h"
#include "api/stse_ecc.h"
#include "api/stse_hash.h"
#include "api/stse_mac.h"
#include "api/stse_random.h"
#include "core/stse_device.h"
#include "core/stse_return_codes.h"

/** \defgroup stse_sal_pkcs11 STSE PKCS \#11 Adaptation Layer
 *  \ingroup  stse_sal
 *  \brief    PKCS \#11 adaptation layer for STSELib
 *  \details  The PKCS \#11 adaptation layer maps standard PKCS \#11
 *            (Cryptographic Token Interface Standard, OASIS) operations to
 *            STSELib API calls, enabling integration of STSAFE secure elements
 *            into systems that use PKCS \#11 as their cryptographic interface.
 *
 *            \b Key mapping conventions:
 *            - For sign/encrypt/decrypt operations: \c hKey encodes the STSE
 *              private or symmetric key slot number.
 *            - For verify operations: \c hKey encodes the \ref stse_ecc_key_type_t
 *              value, and the public key bytes are supplied via \c pPublic_key in
 *              \ref stse_pkcs11_verify_init (STSE-specific extension).
 *            - For key-pair generation: the slot number and key type are given
 *              explicitly (STSE-specific extension).
 *  @{
 */

/* -------------------------------------------------------------------------- */
/* Configuration                                                               */
/* -------------------------------------------------------------------------- */

#ifndef STSE_PKCS11_MAX_SESSIONS
/** \brief Maximum number of concurrent PKCS \#11 sessions */
#define STSE_PKCS11_MAX_SESSIONS 4U
#endif

/* -------------------------------------------------------------------------- */
/* PKCS #11 compatible type definitions                                        */
/* -------------------------------------------------------------------------- */

typedef unsigned long      STSE_CK_ULONG;      /*!< PKCS\#11 unsigned long type */
typedef unsigned char      STSE_CK_BYTE;       /*!< PKCS\#11 byte type */
typedef STSE_CK_BYTE      *STSE_CK_BYTE_PTR;   /*!< Pointer to PKCS\#11 byte */
typedef void              *STSE_CK_VOID_PTR;   /*!< Pointer to void */
typedef STSE_CK_ULONG      STSE_CK_RV;         /*!< PKCS\#11 return value */
typedef STSE_CK_ULONG      STSE_CK_SESSION_HANDLE;  /*!< Session handle */
typedef STSE_CK_ULONG      STSE_CK_OBJECT_HANDLE;   /*!< Key/object handle */
typedef STSE_CK_ULONG      STSE_CK_MECHANISM_TYPE;  /*!< Mechanism type identifier */
typedef STSE_CK_ULONG      STSE_CK_FLAGS;      /*!< Session/token flags */

/** \brief Sentinel value for an invalid handle */
#define STSE_CK_INVALID_HANDLE  0UL

/* -------------------------------------------------------------------------- */
/* PKCS #11 Return codes (CKR_* equivalents)                                  */
/* -------------------------------------------------------------------------- */

#define STSE_CKR_OK                         0x00000000UL /*!< Operation successful */
#define STSE_CKR_GENERAL_ERROR              0x00000005UL /*!< General error */
#define STSE_CKR_ARGUMENTS_BAD              0x00000007UL /*!< Invalid arguments */
#define STSE_CKR_DATA_LEN_RANGE             0x00000021UL /*!< Data length out of range */
#define STSE_CKR_DEVICE_ERROR               0x00000030UL /*!< Device / secure-element error */
#define STSE_CKR_FUNCTION_NOT_SUPPORTED     0x00000054UL /*!< Function not supported */
#define STSE_CKR_KEY_HANDLE_INVALID         0x00000060UL /*!< Invalid key handle */
#define STSE_CKR_MECHANISM_INVALID          0x00000070UL /*!< Unsupported mechanism */
#define STSE_CKR_OPERATION_NOT_INITIALIZED  0x00000090UL /*!< No active operation */
#define STSE_CKR_BUFFER_TOO_SMALL           0x00000150UL /*!< Output buffer too small */
#define STSE_CKR_SESSION_HANDLE_INVALID     0x000000B3UL /*!< Invalid session handle */
#define STSE_CKR_TOKEN_NOT_PRESENT          0x000000E0UL /*!< Token (STSE device) not present */
#define STSE_CKR_CRYPTOKI_NOT_INITIALIZED   0x00000190UL /*!< Library not initialised */
#define STSE_CKR_SIGNATURE_INVALID          0x000000C0UL /*!< Signature verification failed */

/* -------------------------------------------------------------------------- */
/* PKCS #11 Mechanism type identifiers (CKM_* equivalents)                    */
/* -------------------------------------------------------------------------- */

#define STSE_CKM_EC_KEY_PAIR_GEN    0x00001040UL /*!< ECC key-pair generation */
#define STSE_CKM_ECDSA              0x00001041UL /*!< ECDSA raw (hash supplied externally) */
#define STSE_CKM_ECDSA_SHA256       0x00001044UL /*!< ECDSA with SHA-256 */
#define STSE_CKM_ECDSA_SHA384       0x00001045UL /*!< ECDSA with SHA-384 */
#define STSE_CKM_ECDSA_SHA512       0x00001046UL /*!< ECDSA with SHA-512 */
#define STSE_CKM_ECDH1_DERIVE       0x00001050UL /*!< ECDH key-derivation */
#define STSE_CKM_AES_ECB            0x00001081UL /*!< AES-ECB cipher */
#define STSE_CKM_AES_CCM            0x00001088UL /*!< AES-CCM authenticated cipher */
#define STSE_CKM_AES_GCM            0x00001087UL /*!< AES-GCM authenticated cipher */
#define STSE_CKM_AES_CMAC           0x0000108AUL /*!< AES-CMAC message authentication */
#define STSE_CKM_SHA256             0x00000250UL /*!< SHA-256 digest */
#define STSE_CKM_SHA384             0x00000260UL /*!< SHA-384 digest */
#define STSE_CKM_SHA512             0x00000270UL /*!< SHA-512 digest */
#define STSE_CKM_SHA3_256           0x000002B0UL /*!< SHA3-256 digest */
#define STSE_CKM_SHA3_384           0x000002C0UL /*!< SHA3-384 digest */
#define STSE_CKM_SHA3_512           0x000002D0UL /*!< SHA3-512 digest */

/* -------------------------------------------------------------------------- */
/* PKCS #11 Session flag (CKF_* equivalents)                                  */
/* -------------------------------------------------------------------------- */

#define STSE_CKF_RW_SESSION         0x00000002UL /*!< Read-write session */
#define STSE_CKF_SERIAL_SESSION     0x00000004UL /*!< Serial-access session (mandatory per PKCS\#11) */

/* -------------------------------------------------------------------------- */
/* Mechanism parameter structures                                              */
/* -------------------------------------------------------------------------- */

/*!
 * \struct stse_pkcs11_gcm_params_t
 * \brief  AES-GCM mechanism parameters (CK_GCM_PARAMS equivalent)
 */
typedef struct stse_pkcs11_gcm_params_t {
    STSE_CK_BYTE_PTR pIv;       /*!< Initialisation vector buffer */
    STSE_CK_ULONG    ulIvLen;   /*!< IV length in bytes */
    STSE_CK_BYTE_PTR pAAD;      /*!< Additional authenticated data buffer */
    STSE_CK_ULONG    ulAADLen;  /*!< AAD length in bytes */
    STSE_CK_ULONG    ulTagBits; /*!< Authentication tag length in bits */
} stse_pkcs11_gcm_params_t;

/*!
 * \struct stse_pkcs11_ccm_params_t
 * \brief  AES-CCM mechanism parameters (CK_CCM_PARAMS equivalent)
 */
typedef struct stse_pkcs11_ccm_params_t {
    STSE_CK_ULONG    ulDataLen;   /*!< Plaintext/ciphertext data length */
    STSE_CK_BYTE_PTR pNonce;      /*!< Nonce buffer */
    STSE_CK_ULONG    ulNonceLen;  /*!< Nonce length in bytes */
    STSE_CK_BYTE_PTR pAAD;        /*!< Additional authenticated data buffer */
    STSE_CK_ULONG    ulAADLen;    /*!< AAD length in bytes */
    STSE_CK_ULONG    ulMACLen;    /*!< MAC/tag length in bytes */
} stse_pkcs11_ccm_params_t;

/*!
 * \struct stse_pkcs11_mechanism_t
 * \brief  PKCS \#11 mechanism descriptor (CK_MECHANISM equivalent)
 */
typedef struct stse_pkcs11_mechanism_t {
    STSE_CK_MECHANISM_TYPE mechanism;    /*!< Mechanism type identifier (STSE_CKM_*) */
    STSE_CK_VOID_PTR       pParameter;  /*!< Pointer to mechanism-specific parameters */
    STSE_CK_ULONG          ulParameterLen; /*!< Parameter buffer length in bytes */
} stse_pkcs11_mechanism_t;

/* -------------------------------------------------------------------------- */
/* Adaptation-layer internal types                                             */
/* -------------------------------------------------------------------------- */

/*!
 * \enum  stse_pkcs11_operation_t
 * \brief Active cryptographic operation tracked per PKCS \#11 session
 */
typedef enum stse_pkcs11_operation_t {
    STSE_PKCS11_OP_NONE    = 0x00, /*!< No active operation */
    STSE_PKCS11_OP_DIGEST  = 0x01, /*!< Hash / digest in progress */
    STSE_PKCS11_OP_SIGN    = 0x02, /*!< Sign operation in progress */
    STSE_PKCS11_OP_VERIFY  = 0x03, /*!< Verify operation in progress */
    STSE_PKCS11_OP_ENCRYPT = 0x04, /*!< Encrypt operation in progress */
    STSE_PKCS11_OP_DECRYPT = 0x05, /*!< Decrypt operation in progress */
} stse_pkcs11_operation_t;

/*!
 * \struct stse_pkcs11_session_t
 * \brief  Per-session context maintained by the PKCS \#11 adaptation layer
 */
typedef struct stse_pkcs11_session_t {
    PLAT_UI8                  in_use;             /*!< Non-zero when slot is occupied */
    stse_Handler_t           *pSTSE;              /*!< Bound STSE device handler */
    stse_pkcs11_operation_t   active_operation;   /*!< Currently active operation */
    /* Digest state */
    stse_hash_algorithm_t     hash_algorithm;     /*!< Hash algorithm for digest/sign */
    PLAT_UI8                  hash_started;       /*!< Non-zero after first DigestUpdate */
    /* Asymmetric-key state (sign / verify) */
    PLAT_UI8                  key_slot;           /*!< Private-key slot for sign operations */
    stse_ecc_key_type_t       ecc_key_type;       /*!< ECC key type for sign/verify */
    PLAT_UI8                 *pPublic_key;        /*!< Public key buffer for verify (caller-owned) */
    /* Symmetric-key state (encrypt / decrypt) */
    PLAT_UI8                  sym_key_slot;       /*!< Symmetric-key slot */
    STSE_CK_MECHANISM_TYPE    active_mechanism;   /*!< Mechanism set at EncryptInit/DecryptInit */
    stse_pkcs11_mechanism_t   mechanism;          /*!< Full mechanism descriptor (including params) */
} stse_pkcs11_session_t;

/*!
 * \struct stse_pkcs11_ctx_t
 * \brief  Global PKCS \#11 adaptation-layer context
 */
typedef struct stse_pkcs11_ctx_t {
    PLAT_UI8                  initialized;                          /*!< Non-zero after initialise */
    stse_pkcs11_session_t     sessions[STSE_PKCS11_MAX_SESSIONS];  /*!< Session pool */
} stse_pkcs11_ctx_t;

/* -------------------------------------------------------------------------- */
/* Function declarations                                                       */
/* -------------------------------------------------------------------------- */

/**
 * \brief       Initialise the PKCS \#11 adaptation layer
 * \details     Clears and initialises the internal context. Must be called
 *              once before any other \c stse_pkcs11_* function.
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_initialize(void);

/**
 * \brief       Finalise the PKCS \#11 adaptation layer
 * \details     Closes all open sessions and resets the internal context.
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_finalize(void);

/**
 * \brief       Open a PKCS \#11 session backed by an STSE device
 * \details     Allocates a session slot and binds it to the given STSE handler.
 *              Equivalent to \c C_OpenSession.
 * \param[in]   pSTSE       Pointer to an initialised STSE handler
 * \param[in]   flags       Session flags (\ref STSE_CKF_RW_SESSION |
 *                          \ref STSE_CKF_SERIAL_SESSION)
 * \param[out]  phSession   Receives the new session handle on success
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_open_session(
    stse_Handler_t           *pSTSE,
    STSE_CK_FLAGS             flags,
    STSE_CK_SESSION_HANDLE   *phSession);

/**
 * \brief       Close a PKCS \#11 session
 * \details     Releases the session slot. Equivalent to \c C_CloseSession.
 * \param[in]   hSession    Handle of the session to close
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_close_session(
    STSE_CK_SESSION_HANDLE hSession);

/**
 * \brief       Generate random bytes using the STSE TRNG
 * \details     Equivalent to \c C_GenerateRandom.
 * \param[in]   hSession        Session handle
 * \param[out]  pRandomData     Buffer to receive random bytes
 * \param[in]   ulRandomLen     Number of random bytes requested
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_generate_random(
    STSE_CK_SESSION_HANDLE hSession,
    STSE_CK_BYTE_PTR       pRandomData,
    STSE_CK_ULONG          ulRandomLen);

/**
 * \brief       Initialise a hash (digest) operation
 * \details     Stores the algorithm and prepares session state.
 *              Equivalent to \c C_DigestInit. Supported mechanisms:
 *              \ref STSE_CKM_SHA256, \ref STSE_CKM_SHA384, \ref STSE_CKM_SHA512,
 *              \ref STSE_CKM_SHA3_256, \ref STSE_CKM_SHA3_384, \ref STSE_CKM_SHA3_512.
 * \param[in]   hSession    Session handle
 * \param[in]   pMechanism  Mechanism descriptor
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_digest_init(
    STSE_CK_SESSION_HANDLE    hSession,
    stse_pkcs11_mechanism_t  *pMechanism);

/**
 * \brief       Feed data into an in-progress hash operation
 * \details     The first call after \ref stse_pkcs11_digest_init starts the
 *              hash on the STSE device. Subsequent calls append more data.
 *              Equivalent to \c C_DigestUpdate.
 *              \n\b Note: at least one call to this function is required before
 *              \ref stse_pkcs11_digest_final.
 * \param[in]   hSession    Session handle
 * \param[in]   pPart       Data buffer
 * \param[in]   ulPartLen   Data length in bytes
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_digest_update(
    STSE_CK_SESSION_HANDLE hSession,
    STSE_CK_BYTE_PTR       pPart,
    STSE_CK_ULONG          ulPartLen);

/**
 * \brief       Finalise a hash operation and retrieve the digest
 * \details     Equivalent to \c C_DigestFinal.
 *              \n\b Note: \ref stse_pkcs11_digest_update must be called at
 *              least once before this function.
 * \param[in]     hSession      Session handle
 * \param[out]    pDigest       Buffer to receive the digest
 * \param[in,out] pulDigestLen  On input: buffer capacity in bytes;
 *                              on output: actual digest length in bytes
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_digest_final(
    STSE_CK_SESSION_HANDLE hSession,
    STSE_CK_BYTE_PTR       pDigest,
    STSE_CK_ULONG         *pulDigestLen);

/**
 * \brief       Initialise an ECDSA sign operation
 * \details     Stores the signing key slot and optional hash mechanism.
 *              Equivalent to \c C_SignInit.
 *              \n Supported mechanisms: \ref STSE_CKM_ECDSA,
 *              \ref STSE_CKM_ECDSA_SHA256, \ref STSE_CKM_ECDSA_SHA384,
 *              \ref STSE_CKM_ECDSA_SHA512.
 *              \n\b STSE extension: \c key_type must be supplied because PKCS\#11
 *              key objects do not carry curve information in this adaptation layer.
 * \param[in]   hSession    Session handle
 * \param[in]   pMechanism  Mechanism descriptor
 * \param[in]   hKey        Private-key slot number (0-based STSE slot index)
 * \param[in]   key_type    ECC key type (\ref stse_ecc_key_type_t)
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_sign_init(
    STSE_CK_SESSION_HANDLE    hSession,
    stse_pkcs11_mechanism_t  *pMechanism,
    STSE_CK_OBJECT_HANDLE     hKey,
    stse_ecc_key_type_t       key_type);

/**
 * \brief       Perform an ECDSA sign operation
 * \details     Signs \p pData using the key slot set in \ref stse_pkcs11_sign_init.
 *              The output signature is the raw R||S concatenation.
 *              Equivalent to \c C_Sign.
 * \param[in]     hSession          Session handle
 * \param[in]     pData             Data (or hash) to sign
 * \param[in]     ulDataLen         Data length in bytes
 * \param[out]    pSignature        Buffer to receive the R||S signature
 * \param[in,out] pulSignatureLen   On input: buffer capacity; on output: actual length
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_sign(
    STSE_CK_SESSION_HANDLE hSession,
    STSE_CK_BYTE_PTR       pData,
    STSE_CK_ULONG          ulDataLen,
    STSE_CK_BYTE_PTR       pSignature,
    STSE_CK_ULONG         *pulSignatureLen);

/**
 * \brief       Initialise an ECDSA verify operation
 * \details     Stores the ECC key type and public key for the subsequent
 *              \ref stse_pkcs11_verify call.
 *              Equivalent to \c C_VerifyInit.
 *              \n Supported mechanisms: \ref STSE_CKM_ECDSA,
 *              \ref STSE_CKM_ECDSA_SHA256, \ref STSE_CKM_ECDSA_SHA384,
 *              \ref STSE_CKM_ECDSA_SHA512.
 *              \n\b STSE extension: \c hKey encodes the \ref stse_ecc_key_type_t
 *              value, and \c pPublic_key must point to the raw public key bytes
 *              (X||Y for uncompressed NIST/Brainpool, or the appropriate encoding
 *              for other curve families). The caller must keep \c pPublic_key
 *              valid until \ref stse_pkcs11_verify returns.
 * \param[in]   hSession    Session handle
 * \param[in]   pMechanism  Mechanism descriptor
 * \param[in]   hKey        ECC key type (cast from \ref stse_ecc_key_type_t)
 * \param[in]   pPublic_key Pointer to the public key byte buffer (caller-owned)
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_verify_init(
    STSE_CK_SESSION_HANDLE    hSession,
    stse_pkcs11_mechanism_t  *pMechanism,
    STSE_CK_OBJECT_HANDLE     hKey,
    PLAT_UI8                 *pPublic_key);

/**
 * \brief       Verify an ECDSA signature
 * \details     Verifies \p pSignature over \p pData using the key configured
 *              in \ref stse_pkcs11_verify_init. Equivalent to \c C_Verify.
 * \param[in]   hSession       Session handle
 * \param[in]   pData          Data (or hash) that was signed
 * \param[in]   ulDataLen      Data length in bytes
 * \param[in]   pSignature     R||S signature buffer
 * \param[in]   ulSignatureLen Signature length in bytes
 * \return      \ref STSE_CKR_OK if the signature is valid;
 *              \ref STSE_CKR_SIGNATURE_INVALID if verification fails;
 *              other PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_verify(
    STSE_CK_SESSION_HANDLE hSession,
    STSE_CK_BYTE_PTR       pData,
    STSE_CK_ULONG          ulDataLen,
    STSE_CK_BYTE_PTR       pSignature,
    STSE_CK_ULONG          ulSignatureLen);

/**
 * \brief       Initialise an AES encrypt operation
 * \details     Stores the symmetric-key slot and mechanism for the encrypt.
 *              Equivalent to \c C_EncryptInit. Supported mechanisms:
 *              \ref STSE_CKM_AES_ECB, \ref STSE_CKM_AES_CCM, \ref STSE_CKM_AES_GCM.
 *              For \ref STSE_CKM_AES_CCM set \c pParameter to a
 *              \ref stse_pkcs11_ccm_params_t; for \ref STSE_CKM_AES_GCM set it
 *              to a \ref stse_pkcs11_gcm_params_t.
 * \param[in]   hSession    Session handle
 * \param[in]   pMechanism  Mechanism descriptor (with optional parameters)
 * \param[in]   hKey        Symmetric-key slot number
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_encrypt_init(
    STSE_CK_SESSION_HANDLE    hSession,
    stse_pkcs11_mechanism_t  *pMechanism,
    STSE_CK_OBJECT_HANDLE     hKey);

/**
 * \brief       Perform an AES encrypt operation
 * \details     Encrypts \p pData using the key and mechanism set in
 *              \ref stse_pkcs11_encrypt_init. For CCM/GCM modes the
 *              authentication tag is appended to the ciphertext in
 *              \p pEncryptedData. Equivalent to \c C_Encrypt.
 * \param[in]     hSession              Session handle
 * \param[in]     pData                 Plaintext buffer
 * \param[in]     ulDataLen             Plaintext length in bytes
 * \param[out]    pEncryptedData        Ciphertext (+ optional tag) buffer
 * \param[in,out] pulEncryptedDataLen   On input: buffer capacity; on output: ciphertext length
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_encrypt(
    STSE_CK_SESSION_HANDLE hSession,
    STSE_CK_BYTE_PTR       pData,
    STSE_CK_ULONG          ulDataLen,
    STSE_CK_BYTE_PTR       pEncryptedData,
    STSE_CK_ULONG         *pulEncryptedDataLen);

/**
 * \brief       Initialise an AES decrypt operation
 * \details     Equivalent to \c C_DecryptInit. See \ref stse_pkcs11_encrypt_init
 *              for supported mechanisms and parameter details.
 * \param[in]   hSession    Session handle
 * \param[in]   pMechanism  Mechanism descriptor
 * \param[in]   hKey        Symmetric-key slot number
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_decrypt_init(
    STSE_CK_SESSION_HANDLE    hSession,
    stse_pkcs11_mechanism_t  *pMechanism,
    STSE_CK_OBJECT_HANDLE     hKey);

/**
 * \brief       Perform an AES decrypt operation
 * \details     Decrypts \p pEncryptedData using the key and mechanism set in
 *              \ref stse_pkcs11_decrypt_init. For CCM/GCM modes the input must
 *              contain the authentication tag appended after the ciphertext.
 *              Equivalent to \c C_Decrypt.
 * \param[in]     hSession            Session handle
 * \param[in]     pEncryptedData      Ciphertext (+ optional tag) buffer
 * \param[in]     ulEncryptedDataLen  Ciphertext length in bytes
 * \param[out]    pData               Plaintext buffer
 * \param[in,out] pulDataLen          On input: buffer capacity; on output: plaintext length
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_decrypt(
    STSE_CK_SESSION_HANDLE hSession,
    STSE_CK_BYTE_PTR       pEncryptedData,
    STSE_CK_ULONG          ulEncryptedDataLen,
    STSE_CK_BYTE_PTR       pData,
    STSE_CK_ULONG         *pulDataLen);

/**
 * \brief       Generate an ECC key pair in the STSE
 * \details     Requests the STSE to generate an ECC key pair and stores the
 *              private key in \p key_slot. The generated public key is returned
 *              in \p pPublicKey. Equivalent to \c C_GenerateKeyPair.
 * \param[in]   hSession        Session handle
 * \param[in]   pMechanism      Key-generation mechanism (\ref STSE_CKM_EC_KEY_PAIR_GEN)
 * \param[in]   key_slot        STSE private-key slot to generate the key pair into
 * \param[in]   key_type        ECC key type (\ref stse_ecc_key_type_t)
 * \param[in]   usage_limit     Key usage limit (0 = unlimited)
 * \param[out]  pPublicKey      Buffer to receive the generated public key bytes
 * \param[out]  phPrivateKey    Receives the private-key object handle (= \p key_slot)
 * \param[out]  phPublicKey     Receives the public-key object handle  (= \p key_slot)
 * \return      \ref STSE_CKR_OK on success; PKCS \#11 error code otherwise
 */
STSE_CK_RV stse_pkcs11_generate_key_pair(
    STSE_CK_SESSION_HANDLE    hSession,
    stse_pkcs11_mechanism_t  *pMechanism,
    PLAT_UI8                  key_slot,
    stse_ecc_key_type_t       key_type,
    PLAT_UI16                 usage_limit,
    PLAT_UI8                 *pPublicKey,
    STSE_CK_OBJECT_HANDLE    *phPrivateKey,
    STSE_CK_OBJECT_HANDLE    *phPublicKey);

/** @}*/

#ifdef __cplusplus
}
#endif

#endif /* STSE_PKCS11_H */
