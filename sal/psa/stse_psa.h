/*!
 ******************************************************************************
 * \file    stse_psa.h
 * \brief   STSE PSA Crypto adaptation layer (header)
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

#ifndef STSE_PSA_H
#define STSE_PSA_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "api/stse_aes.h"
#include "api/stse_asymmetric_keys_management.h"
#include "api/stse_derive_keys.h"
#include "api/stse_ecc.h"
#include "api/stse_hash.h"
#include "api/stse_mac.h"
#include "api/stse_random.h"
#include "core/stse_device.h"
#include "core/stse_return_codes.h"

/** \defgroup stse_sal_psa STSE PSA Crypto Adaptation Layer
 *  \ingroup  stse_sal
 *  \brief    PSA Crypto adaptation layer for STSELib
 *  \details  The PSA Crypto adaptation layer maps ARM Platform Security
 *            Architecture (PSA) Crypto API operations to STSELib API calls,
 *            enabling integration of STSAFE secure elements into systems built
 *            on the PSA Crypto standard (e.g. Mbed TLS / TF-M).
 *
 *            \b Key-ID encoding convention:
 *            - Bits [7:0]  : STSE key slot number
 *            - Bits [15:8] : Key category (0 = symmetric AES, 1 = asymmetric ECC)
 *            - Bits [31:16]: Reserved, must be 0
 *
 *            Helper macros \ref STSE_PSA_KEY_ID_SYM and
 *            \ref STSE_PSA_KEY_ID_ASYM build compliant key IDs.
 *  @{
 */

/* -------------------------------------------------------------------------- */
/* Configuration                                                               */
/* -------------------------------------------------------------------------- */

#ifndef STSE_PSA_MAX_KEYS
/** \brief Maximum number of key slots tracked in the PSA adaptation layer */
#define STSE_PSA_MAX_KEYS 16U
#endif

/** \brief Maximum size of a cached ECC public key in bytes
 *         (covers P-521 STSE format: 1 prefix + 2 len + 66 X + 2 len + 66 Y = 137) */
#define STSE_PSA_MAX_PUBLIC_KEY_SIZE 137U

/* -------------------------------------------------------------------------- */
/* PSA Crypto compatible type definitions                                      */
/* -------------------------------------------------------------------------- */

typedef int            stse_psa_status_t;   /*!< PSA status code (signed, 0 = success) */
typedef unsigned int   stse_psa_key_id_t;   /*!< PSA key identifier */
typedef unsigned short stse_psa_key_type_t; /*!< PSA key type */
typedef unsigned int   stse_psa_algorithm_t;/*!< PSA algorithm identifier */
typedef unsigned int   stse_psa_key_usage_t;/*!< PSA key usage flags */
typedef unsigned short stse_psa_key_bits_t; /*!< PSA key size in bits */

/* -------------------------------------------------------------------------- */
/* PSA status codes (psa_status_t equivalents)                                */
/* -------------------------------------------------------------------------- */

#define STSE_PSA_SUCCESS                   ((stse_psa_status_t) 0)    /*!< Operation successful */
#define STSE_PSA_ERROR_GENERIC_ERROR       ((stse_psa_status_t)-132)  /*!< Generic error */
#define STSE_PSA_ERROR_NOT_SUPPORTED       ((stse_psa_status_t)-134)  /*!< Operation not supported */
#define STSE_PSA_ERROR_INVALID_ARGUMENT    ((stse_psa_status_t)-135)  /*!< Invalid argument */
#define STSE_PSA_ERROR_INVALID_HANDLE      ((stse_psa_status_t)-136)  /*!< Invalid key handle */
#define STSE_PSA_ERROR_BAD_STATE           ((stse_psa_status_t)-137)  /*!< Bad state */
#define STSE_PSA_ERROR_BUFFER_TOO_SMALL    ((stse_psa_status_t)-138)  /*!< Output buffer too small */
#define STSE_PSA_ERROR_INSUFFICIENT_MEMORY ((stse_psa_status_t)-141)  /*!< Insufficient memory */
#define STSE_PSA_ERROR_COMMUNICATION_FAILURE ((stse_psa_status_t)-145)/*!< Communication error */
#define STSE_PSA_ERROR_HARDWARE_FAILURE    ((stse_psa_status_t)-147)  /*!< Hardware failure */
#define STSE_PSA_ERROR_INVALID_SIGNATURE   ((stse_psa_status_t)-149)  /*!< Signature verification failed */

/* -------------------------------------------------------------------------- */
/* PSA key type identifiers (psa_key_type_t equivalents)                      */
/* -------------------------------------------------------------------------- */

/* Symmetric key types */
#define STSE_PSA_KEY_TYPE_AES              ((stse_psa_key_type_t)0x2400U) /*!< AES key */
#define STSE_PSA_KEY_TYPE_HMAC             ((stse_psa_key_type_t)0x1100U) /*!< HMAC key */

/* ECC curve family identifiers */
#define STSE_PSA_ECC_FAMILY_SECP_R1        ((PLAT_UI8)0x12U) /*!< NIST P-curves (P-256, P-384, P-521) */
#define STSE_PSA_ECC_FAMILY_BRAINPOOL_P_R1 ((PLAT_UI8)0x30U) /*!< Brainpool P-curves */
#define STSE_PSA_ECC_FAMILY_MONTGOMERY     ((PLAT_UI8)0x41U) /*!< Montgomery curves (Curve25519) */
#define STSE_PSA_ECC_FAMILY_TWISTED_EDWARDS ((PLAT_UI8)0x42U)/*!< Twisted Edwards curves (Ed25519) */

/** \brief Build a PSA ECC key-pair type for a given curve family */
#define STSE_PSA_KEY_TYPE_ECC_KEY_PAIR(curve) \
    ((stse_psa_key_type_t)(0x7100U | (PLAT_UI8)(curve)))

/** \brief Build a PSA ECC public-key type for a given curve family */
#define STSE_PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve) \
    ((stse_psa_key_type_t)(0x4100U | (PLAT_UI8)(curve)))

/* -------------------------------------------------------------------------- */
/* PSA algorithm identifiers (psa_algorithm_t equivalents)                    */
/* -------------------------------------------------------------------------- */

/* Hash algorithms */
#define STSE_PSA_ALG_SHA_256    ((stse_psa_algorithm_t)0x02000009U) /*!< SHA-256 */
#define STSE_PSA_ALG_SHA_384    ((stse_psa_algorithm_t)0x0200000AU) /*!< SHA-384 */
#define STSE_PSA_ALG_SHA_512    ((stse_psa_algorithm_t)0x0200000BU) /*!< SHA-512 */
#define STSE_PSA_ALG_SHA3_256   ((stse_psa_algorithm_t)0x02000010U) /*!< SHA3-256 */
#define STSE_PSA_ALG_SHA3_384   ((stse_psa_algorithm_t)0x02000011U) /*!< SHA3-384 */
#define STSE_PSA_ALG_SHA3_512   ((stse_psa_algorithm_t)0x02000012U) /*!< SHA3-512 */

/** \brief Build a PSA ECDSA algorithm identifier for a given hash algorithm */
#define STSE_PSA_ALG_ECDSA(hash_alg) \
    ((stse_psa_algorithm_t)(0x06000600U | ((hash_alg) & 0xFFU)))

/** \brief ECDSA with pre-hashed input (hash algorithm not embedded in sign) */
#define STSE_PSA_ALG_ECDSA_ANY          ((stse_psa_algorithm_t)0x06000600U)

/* ECDH */
#define STSE_PSA_ALG_ECDH               ((stse_psa_algorithm_t)0x09020000U) /*!< ECDH */

/* MAC algorithms */
#define STSE_PSA_ALG_CMAC               ((stse_psa_algorithm_t)0x03C00200U) /*!< AES-CMAC */

/** \brief Build a PSA HMAC algorithm identifier for a given hash */
#define STSE_PSA_ALG_HMAC(hash_alg) \
    ((stse_psa_algorithm_t)(0x03800000U | ((hash_alg) & 0xFFU)))

/* AEAD algorithms */
#define STSE_PSA_ALG_CCM                ((stse_psa_algorithm_t)0x05500300U) /*!< AES-CCM */
#define STSE_PSA_ALG_GCM                ((stse_psa_algorithm_t)0x05500200U) /*!< AES-GCM */

/* Key derivation */
/** \brief Build a PSA HKDF algorithm identifier for a given hash */
#define STSE_PSA_ALG_HKDF(hash_alg) \
    ((stse_psa_algorithm_t)(0x08000100U | ((hash_alg) & 0xFFU)))

/* -------------------------------------------------------------------------- */
/* PSA key usage flags (psa_key_usage_t equivalents)                          */
/* -------------------------------------------------------------------------- */

#define STSE_PSA_KEY_USAGE_EXPORT          0x00000001U /*!< Key may be exported */
#define STSE_PSA_KEY_USAGE_ENCRYPT         0x00000100U /*!< Key may be used for encryption */
#define STSE_PSA_KEY_USAGE_DECRYPT         0x00000200U /*!< Key may be used for decryption */
#define STSE_PSA_KEY_USAGE_SIGN_HASH       0x00001000U /*!< Key may be used to sign hashes */
#define STSE_PSA_KEY_USAGE_VERIFY_HASH     0x00002000U /*!< Key may be used to verify signatures */
#define STSE_PSA_KEY_USAGE_SIGN_MESSAGE    0x00000400U /*!< Key may be used to sign messages */
#define STSE_PSA_KEY_USAGE_VERIFY_MESSAGE  0x00000800U /*!< Key may be used to verify messages */
#define STSE_PSA_KEY_USAGE_DERIVE          0x00004000U /*!< Key may be used for key derivation */

/* -------------------------------------------------------------------------- */
/* Key-ID encoding helpers                                                     */
/* -------------------------------------------------------------------------- */

/** \brief Build a PSA key ID for a symmetric (AES) key in STSE slot \p slot */
#define STSE_PSA_KEY_ID_SYM(slot)  ((stse_psa_key_id_t)(((PLAT_UI8)(slot)) | (0x00U << 8U)))

/** \brief Build a PSA key ID for an asymmetric (ECC) key in STSE slot \p slot */
#define STSE_PSA_KEY_ID_ASYM(slot) ((stse_psa_key_id_t)(((PLAT_UI8)(slot)) | (0x01U << 8U)))

/** \brief Extract STSE slot number from a PSA key ID */
#define STSE_PSA_KEY_ID_GET_SLOT(key_id)  ((PLAT_UI8)((key_id) & 0xFFU))

/** \brief Extract key category from a PSA key ID (0 = symmetric, 1 = asymmetric) */
#define STSE_PSA_KEY_ID_GET_CATEGORY(key_id) ((PLAT_UI8)(((key_id) >> 8U) & 0xFFU))

/* -------------------------------------------------------------------------- */
/* PSA Crypto key attribute structure                                          */
/* -------------------------------------------------------------------------- */

/*!
 * \struct stse_psa_key_attributes_t
 * \brief  PSA key attributes (psa_key_attributes_t equivalent)
 */
typedef struct stse_psa_key_attributes_t {
    stse_psa_key_id_t    id;      /*!< Application-assigned key identifier */
    stse_psa_key_type_t  type;    /*!< Key type (symmetric / ECC key-pair / ECC public key) */
    stse_psa_algorithm_t alg;     /*!< Permitted algorithm for this key */
    stse_psa_key_usage_t usage;   /*!< Key usage flags */
    stse_psa_key_bits_t  bits;    /*!< Key size in bits (e.g. 256 for AES-256, 256 for P-256) */
} stse_psa_key_attributes_t;

/* -------------------------------------------------------------------------- */
/* PSA hash operation context                                                  */
/* -------------------------------------------------------------------------- */

/*!
 * \struct stse_psa_hash_operation_t
 * \brief  Context for a multi-part PSA hash operation
 *         (psa_hash_operation_t equivalent)
 */
typedef struct stse_psa_hash_operation_t {
    PLAT_UI8              active;          /*!< Non-zero when an operation is in progress */
    stse_psa_algorithm_t  alg;            /*!< Hash algorithm */
    stse_hash_algorithm_t stse_algo;      /*!< Mapped STSE hash algorithm */
    PLAT_UI8              hash_started;   /*!< Non-zero after first stse_start_hash call */
} stse_psa_hash_operation_t;

/* -------------------------------------------------------------------------- */
/* Internal key context table entry                                            */
/* -------------------------------------------------------------------------- */

/*!
 * \struct stse_psa_key_context_t
 * \brief  Internal key tracking entry in the PSA adaptation-layer key table
 */
typedef struct stse_psa_key_context_t {
    PLAT_UI8                  in_use;      /*!< Non-zero when slot is occupied */
    stse_psa_key_id_t         id;          /*!< Application key identifier */
    stse_psa_key_type_t       type;        /*!< PSA key type */
    stse_psa_algorithm_t      alg;         /*!< Permitted algorithm */
    stse_psa_key_usage_t      usage;       /*!< Usage flags */
    PLAT_UI8                  stse_slot;   /*!< STSE key slot number */
    stse_ecc_key_type_t       ecc_type;    /*!< ECC key type (asymmetric keys only) */
    stse_aes_key_type_t       aes_type;    /*!< AES key type (symmetric keys only) */
    PLAT_UI8                  pub_key[STSE_PSA_MAX_PUBLIC_KEY_SIZE]; /*!< Cached public key */
    PLAT_UI8                  pub_key_len; /*!< Cached public key length in bytes */
} stse_psa_key_context_t;

/* -------------------------------------------------------------------------- */
/* Global PSA context                                                          */
/* -------------------------------------------------------------------------- */

/*!
 * \struct stse_psa_ctx_t
 * \brief  Global PSA Crypto adaptation-layer context
 */
typedef struct stse_psa_ctx_t {
    PLAT_UI8                 initialized; /*!< Non-zero after stse_psa_crypto_init */
    stse_Handler_t          *pSTSE;       /*!< Bound STSE device handler */
    stse_psa_key_context_t   keys[STSE_PSA_MAX_KEYS]; /*!< Key context table */
} stse_psa_ctx_t;

/* -------------------------------------------------------------------------- */
/* Function declarations                                                       */
/* -------------------------------------------------------------------------- */

/**
 * \brief       Initialise the PSA Crypto adaptation layer
 * \details     Binds the given STSE handler to the PSA adaptation layer.
 *              Must be called once before any other \c stse_psa_* function.
 * \param[in]   pSTSE   Pointer to an initialised STSE handler
 * \return      \ref STSE_PSA_SUCCESS on success;
 *              \ref STSE_PSA_ERROR_INVALID_ARGUMENT if \p pSTSE is NULL
 */
stse_psa_status_t stse_psa_crypto_init(stse_Handler_t *pSTSE);

/**
 * \brief       Generate an ECC key pair in the STSE and register it
 * \details     Generates an ECC key pair in the STSE private-key table and
 *              records the mapping in the PSA key table.
 *              The generated public key is optionally returned in \p pPublicKey.
 * \param[in]   pAttributes     Key attributes including \c id, \c type, \c alg,
 *                              \c usage, \c bits
 * \param[in]   ecc_type        STSE ECC key type (\ref stse_ecc_key_type_t)
 * \param[in]   usage_limit     Key usage limit (0 = unlimited)
 * \param[out]  pPublicKey      Buffer to receive the generated public key
 *                              (may be NULL if public key is not needed)
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_generate_key(const stse_psa_key_attributes_t *pAttributes,
                                         stse_ecc_key_type_t               ecc_type,
                                         PLAT_UI16                         usage_limit,
                                         PLAT_UI8                         *pPublicKey);

/**
 * \brief       Remove a registered PSA key
 * \details     Removes the key ID from the PSA adaptation-layer key table.
 *              The underlying STSE key slot is not erased by this call.
 * \param[in]   key_id  Key identifier to remove
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_destroy_key(stse_psa_key_id_t key_id);

/**
 * \brief       Export the public key of a registered ECC key pair
 * \details     Reads the public key associated with \p key_id from the STSE
 *              and copies it into \p pData.
 * \param[in]   key_id      Key identifier (must be an asymmetric key)
 * \param[out]  pData       Buffer to receive the public key bytes
 * \param[in]   data_size   Capacity of \p pData in bytes
 * \param[out]  pData_len   Actual public key length written to \p pData
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_export_public_key(stse_psa_key_id_t  key_id,
                                              PLAT_UI8          *pData,
                                              PLAT_UI32          data_size,
                                              PLAT_UI32         *pData_len);

/**
 * \brief       Sign a pre-computed hash using ECDSA
 * \details     Uses the private key identified by \p key_id to sign \p pHash.
 *              Equivalent to \c psa_sign_hash.
 * \param[in]     key_id        Key identifier (asymmetric private key)
 * \param[in]     alg           Signing algorithm (\ref STSE_PSA_ALG_ECDSA_ANY or
 *                              \c STSE_PSA_ALG_ECDSA(hash))
 * \param[in]     pHash         Hash buffer
 * \param[in]     hash_length   Hash length in bytes
 * \param[out]    pSignature    Buffer to receive the R||S signature
 * \param[in]     sig_size      Capacity of \p pSignature in bytes
 * \param[out]    pSig_length   Actual signature length written
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_sign_hash(stse_psa_key_id_t   key_id,
                                      stse_psa_algorithm_t alg,
                                      const PLAT_UI8      *pHash,
                                      PLAT_UI32            hash_length,
                                      PLAT_UI8            *pSignature,
                                      PLAT_UI32            sig_size,
                                      PLAT_UI32           *pSig_length);

/**
 * \brief       Sign a message using ECDSA (hash computed on-device)
 * \details     Hashes \p pMessage on the STSE and signs the resulting digest.
 *              The hash algorithm is derived from \p alg.
 *              Equivalent to \c psa_sign_message.
 * \param[in]     key_id       Key identifier (asymmetric private key)
 * \param[in]     alg          Signing algorithm including hash
 *                             (e.g. \c STSE_PSA_ALG_ECDSA(STSE_PSA_ALG_SHA_256))
 * \param[in]     pMessage     Message buffer
 * \param[in]     msg_length   Message length in bytes
 * \param[out]    pSignature   Buffer to receive the R||S signature
 * \param[in]     sig_size     Capacity of \p pSignature in bytes
 * \param[out]    pSig_length  Actual signature length written
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_sign_message(stse_psa_key_id_t   key_id,
                                         stse_psa_algorithm_t alg,
                                         const PLAT_UI8      *pMessage,
                                         PLAT_UI32            msg_length,
                                         PLAT_UI8            *pSignature,
                                         PLAT_UI32            sig_size,
                                         PLAT_UI32           *pSig_length);

/**
 * \brief       Verify an ECDSA signature over a pre-computed hash
 * \details     Verifies \p pSignature over \p pHash using the ECC key type
 *              associated with \p key_id and the supplied \p pPublicKey.
 *              Equivalent to \c psa_verify_hash.
 * \param[in]   key_id         Key identifier (used to retrieve the ECC key type)
 * \param[in]   alg            Verification algorithm
 * \param[in]   pPublicKey     Public key bytes (X||Y for uncompressed NIST/Brainpool)
 * \param[in]   pub_key_length Public key length in bytes
 * \param[in]   pHash          Hash buffer
 * \param[in]   hash_length    Hash length in bytes
 * \param[in]   pSignature     R||S signature buffer
 * \param[in]   sig_length     Signature length in bytes
 * \return      \ref STSE_PSA_SUCCESS if the signature is valid;
 *              \ref STSE_PSA_ERROR_INVALID_SIGNATURE otherwise;
 *              other PSA error code on failure
 */
stse_psa_status_t stse_psa_verify_hash(stse_psa_key_id_t   key_id,
                                        stse_psa_algorithm_t alg,
                                        const PLAT_UI8      *pPublicKey,
                                        PLAT_UI32            pub_key_length,
                                        const PLAT_UI8      *pHash,
                                        PLAT_UI32            hash_length,
                                        const PLAT_UI8      *pSignature,
                                        PLAT_UI32            sig_length);

/**
 * \brief       Verify an ECDSA signature over a message (hash computed on-device)
 * \details     Hashes \p pMessage on the STSE and verifies the signature.
 *              Equivalent to \c psa_verify_message.
 * \param[in]   key_id         Key identifier (used to retrieve the ECC key type)
 * \param[in]   alg            Verification algorithm including hash
 * \param[in]   pPublicKey     Public key bytes
 * \param[in]   pub_key_length Public key length in bytes
 * \param[in]   pMessage       Message buffer
 * \param[in]   msg_length     Message length in bytes
 * \param[in]   pSignature     R||S signature buffer
 * \param[in]   sig_length     Signature length in bytes
 * \return      \ref STSE_PSA_SUCCESS if the signature is valid;
 *              \ref STSE_PSA_ERROR_INVALID_SIGNATURE otherwise;
 *              other PSA error code on failure
 */
stse_psa_status_t stse_psa_verify_message(stse_psa_key_id_t   key_id,
                                           stse_psa_algorithm_t alg,
                                           const PLAT_UI8      *pPublicKey,
                                           PLAT_UI32            pub_key_length,
                                           const PLAT_UI8      *pMessage,
                                           PLAT_UI32            msg_length,
                                           const PLAT_UI8      *pSignature,
                                           PLAT_UI32            sig_length);

/**
 * \brief       Compute a hash (single-shot)
 * \details     Computes the hash of \p pInput in a single STSE command.
 *              Equivalent to \c psa_hash_compute.
 * \param[in]   alg          Hash algorithm (\ref STSE_PSA_ALG_SHA_256, etc.)
 * \param[in]   pInput       Input data buffer
 * \param[in]   input_length Input data length in bytes
 * \param[out]  pHash        Buffer to receive the digest
 * \param[in]   hash_size    Capacity of \p pHash in bytes
 * \param[out]  pHash_length Actual digest length written
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_hash_compute(stse_psa_algorithm_t  alg,
                                         const PLAT_UI8       *pInput,
                                         PLAT_UI32             input_length,
                                         PLAT_UI8             *pHash,
                                         PLAT_UI32             hash_size,
                                         PLAT_UI32            *pHash_length);

/**
 * \brief       Start a multi-part hash operation
 * \details     Initialises \p pOperation for a subsequent sequence of
 *              \ref stse_psa_hash_update / \ref stse_psa_hash_finish calls.
 *              Equivalent to \c psa_hash_setup.
 * \param[out]  pOperation  Hash operation context to initialise
 * \param[in]   alg         Hash algorithm
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_hash_setup(stse_psa_hash_operation_t *pOperation,
                                       stse_psa_algorithm_t       alg);

/**
 * \brief       Feed data into an ongoing hash operation
 * \details     Equivalent to \c psa_hash_update.
 *              \n\b Note: at least one call is required before
 *              \ref stse_psa_hash_finish.
 * \param[in]   pOperation   Hash operation context
 * \param[in]   pInput       Data buffer
 * \param[in]   input_length Data length in bytes
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_hash_update(stse_psa_hash_operation_t *pOperation,
                                        const PLAT_UI8            *pInput,
                                        PLAT_UI32                  input_length);

/**
 * \brief       Finalise a multi-part hash operation
 * \details     Equivalent to \c psa_hash_finish.
 * \param[in]     pOperation   Hash operation context
 * \param[out]    pHash        Buffer to receive the digest
 * \param[in]     hash_size    Capacity of \p pHash in bytes
 * \param[out]    pHash_length Actual digest length written
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_hash_finish(stse_psa_hash_operation_t *pOperation,
                                        PLAT_UI8                  *pHash,
                                        PLAT_UI32                  hash_size,
                                        PLAT_UI32                 *pHash_length);

/**
 * \brief       Compute a MAC (single-shot)
 * \details     Computes AES-CMAC or AES-GMAC over \p pInput using the
 *              symmetric key identified by \p key_id.
 *              Equivalent to \c psa_mac_compute.
 * \param[in]   key_id       Symmetric key identifier
 * \param[in]   alg          MAC algorithm (\ref STSE_PSA_ALG_CMAC)
 * \param[in]   pInput       Input data buffer
 * \param[in]   input_length Input data length in bytes
 * \param[out]  pMac         Buffer to receive the MAC
 * \param[in]   mac_size     Capacity of \p pMac in bytes
 * \param[out]  pMac_length  Actual MAC length written
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_mac_compute(stse_psa_key_id_t    key_id,
                                        stse_psa_algorithm_t alg,
                                        const PLAT_UI8      *pInput,
                                        PLAT_UI32            input_length,
                                        PLAT_UI8            *pMac,
                                        PLAT_UI32            mac_size,
                                        PLAT_UI32           *pMac_length);

/**
 * \brief       Verify a MAC (single-shot)
 * \details     Equivalent to \c psa_mac_verify.
 * \param[in]   key_id       Symmetric key identifier
 * \param[in]   alg          MAC algorithm
 * \param[in]   pInput       Input data buffer
 * \param[in]   input_length Input data length in bytes
 * \param[in]   pMac         Expected MAC buffer
 * \param[in]   mac_length   MAC length in bytes
 * \return      \ref STSE_PSA_SUCCESS if the MAC matches;
 *              \ref STSE_PSA_ERROR_INVALID_SIGNATURE otherwise;
 *              other PSA error code on failure
 */
stse_psa_status_t stse_psa_mac_verify(stse_psa_key_id_t    key_id,
                                       stse_psa_algorithm_t alg,
                                       const PLAT_UI8      *pInput,
                                       PLAT_UI32            input_length,
                                       const PLAT_UI8      *pMac,
                                       PLAT_UI32            mac_length);

/**
 * \brief       Authenticated encryption (AEAD, single-shot)
 * \details     Encrypts \p pPlaintext with authentication using the symmetric
 *              key identified by \p key_id. Supported algorithms:
 *              \ref STSE_PSA_ALG_CCM, \ref STSE_PSA_ALG_GCM.
 *              The authentication tag is appended to the ciphertext in
 *              \p pCiphertext. Equivalent to \c psa_aead_encrypt.
 * \param[in]     key_id           Symmetric key identifier
 * \param[in]     alg              AEAD algorithm
 * \param[in]     pNonce           Nonce / IV buffer
 * \param[in]     nonce_length     Nonce length in bytes
 * \param[in]     pAdditionalData  Additional authenticated data buffer
 * \param[in]     aad_length       AAD length in bytes
 * \param[in]     pPlaintext       Plaintext buffer
 * \param[in]     plaintext_length Plaintext length in bytes
 * \param[out]    pCiphertext      Ciphertext + tag output buffer
 * \param[in]     ciphertext_size  Capacity of \p pCiphertext in bytes
 * \param[out]    pCiphertext_length Actual output length (ciphertext + tag)
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
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
                                         PLAT_UI32           *pCiphertext_length);

/**
 * \brief       Authenticated decryption (AEAD, single-shot)
 * \details     Decrypts and authenticates \p pCiphertext (which includes the
 *              authentication tag at the end). Supported algorithms:
 *              \ref STSE_PSA_ALG_CCM, \ref STSE_PSA_ALG_GCM.
 *              Equivalent to \c psa_aead_decrypt.
 * \param[in]     key_id            Symmetric key identifier
 * \param[in]     alg               AEAD algorithm
 * \param[in]     pNonce            Nonce / IV buffer
 * \param[in]     nonce_length      Nonce length in bytes
 * \param[in]     pAdditionalData   Additional authenticated data buffer
 * \param[in]     aad_length        AAD length in bytes
 * \param[in]     pCiphertext       Ciphertext + tag input buffer
 * \param[in]     ciphertext_length Total ciphertext + tag length in bytes
 * \param[out]    pPlaintext        Decrypted plaintext output buffer
 * \param[in]     plaintext_size    Capacity of \p pPlaintext in bytes
 * \param[out]    pPlaintext_length Actual plaintext length written
 * \return      \ref STSE_PSA_SUCCESS on success;
 *              \ref STSE_PSA_ERROR_INVALID_SIGNATURE if authentication fails;
 *              other PSA error code otherwise
 */
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
                                         PLAT_UI32           *pPlaintext_length);

/**
 * \brief       Perform raw ECDH key agreement
 * \details     Computes the shared secret from the private key identified by
 *              \p key_id and the remote peer's public key \p pPeerKey.
 *              Equivalent to \c psa_raw_key_agreement.
 * \param[in]     key_id          Private-key identifier
 * \param[in]     alg             Key-agreement algorithm (\ref STSE_PSA_ALG_ECDH)
 * \param[in]     pPeerKey        Peer public key buffer
 * \param[in]     peer_key_length Peer public key length in bytes
 * \param[out]    pOutput         Buffer to receive the shared secret
 * \param[in]     output_size     Capacity of \p pOutput in bytes
 * \param[out]    pOutput_length  Actual shared secret length written
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_raw_key_agreement(stse_psa_key_id_t   key_id,
                                              stse_psa_algorithm_t alg,
                                              const PLAT_UI8      *pPeerKey,
                                              PLAT_UI32            peer_key_length,
                                              PLAT_UI8            *pOutput,
                                              PLAT_UI32            output_size,
                                              PLAT_UI32           *pOutput_length);

/**
 * \brief       Generate random bytes using the STSE TRNG
 * \details     Equivalent to \c psa_generate_random.
 * \param[out]  pOutput       Buffer to receive random bytes
 * \param[in]   output_size   Number of random bytes to generate
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_generate_random(PLAT_UI8 *pOutput, PLAT_UI32 output_size);

/**
 * \brief       Derive key material using HKDF
 * \details     Derives \p output_length bytes using HKDF from the master key
 *              identified by \p key_id, optional salt and info/context label.
 *              Equivalent to running \c psa_key_derivation_* with HKDF.
 * \param[in]   key_id        Master key identifier (symmetric HKDF key)
 * \param[in]   alg           HKDF algorithm
 *                            (e.g. \c STSE_PSA_ALG_HKDF(STSE_PSA_ALG_SHA_256))
 * \param[in]   pSalt         Salt buffer (optional, may be NULL)
 * \param[in]   salt_length   Salt length in bytes
 * \param[in]   pInfo         Info / context label buffer (optional, may be NULL)
 * \param[in]   info_length   Info length in bytes
 * \param[out]  pOutput       Buffer to receive the derived key material
 * \param[in]   output_length Desired derived key length in bytes
 * \return      \ref STSE_PSA_SUCCESS on success; PSA error code otherwise
 */
stse_psa_status_t stse_psa_key_derivation_output_bytes(stse_psa_key_id_t   key_id,
                                                        stse_psa_algorithm_t alg,
                                                        const PLAT_UI8      *pSalt,
                                                        PLAT_UI32            salt_length,
                                                        const PLAT_UI8      *pInfo,
                                                        PLAT_UI32            info_length,
                                                        PLAT_UI8            *pOutput,
                                                        PLAT_UI32            output_length);

/** @}*/

#ifdef __cplusplus
}
#endif

#endif /* STSE_PSA_H */
