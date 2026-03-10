/*!
 ******************************************************************************
 * \file	stse_aes.c
 * \brief   STSE AES API set (sources)
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2022 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 *****************************************************************************/

#include "api/stse_aes.h"

stse_return_code_t stse_aes_ecb_encrypt(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 message_length,
    PLAT_UI8 *pPlaintext_message,
    PLAT_UI8 *pEncrypted_message) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ecb_encrypt(
        p_stse,
        slot_number,
        message_length,
        pPlaintext_message,
        pEncrypted_message);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ecb_decrypt(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 message_length,
    PLAT_UI8 *pEncrypted_message,
    PLAT_UI8 *pPlaintext_message) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ecb_decrypt(
        p_stse,
        slot_number,
        message_length,
        pEncrypted_message,
        pPlaintext_message);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_encrypt(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 associated_data_length, PLAT_UI8 *pAssociated_data,
    PLAT_UI16 message_length, PLAT_UI8 *pPlaintext_message,
    PLAT_UI8 *pEncrypted_message,
    PLAT_UI8 *pEncrypted_authentication_tag,
    PLAT_UI8 counter_presence, PLAT_UI32 *pCounter) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_encrypt(
        p_stse,
        slot_number,
        authentication_tag_length,
        p_nonce,
        associated_data_length, pAssociated_data,
        message_length,
        pPlaintext_message,
        pEncrypted_message,
        pEncrypted_authentication_tag,
        counter_presence, pCounter);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_encrypt_start(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 nonce_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 total_associated_data_length,
    PLAT_UI32 total_message_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pPlaintext_message_chunk,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pCounter_presence,
    PLAT_UI32 *pCounter) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_encrypt_start(
        p_stse,
        slot_number,
        nonce_length,
        p_nonce,
        total_associated_data_length,
        total_message_length,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pPlaintext_message_chunk,
        pEncrypted_message_chunk,
        pCounter_presence,
        pCounter);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_encrypt_process(
    stse_handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pPlaintext_message_chunk,
    PLAT_UI8 *pEncrypted_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_encrypt_process(
        p_stse,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pPlaintext_message_chunk,
        pEncrypted_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_encrypt_finish(
    stse_handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pPlaintext_message_chunk,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pEncrypted_authentication_tag) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_encrypt_finish(
        p_stse,
        authentication_tag_length,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pPlaintext_message_chunk,
        pEncrypted_message_chunk,
        pEncrypted_authentication_tag);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_decrypt(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *pAssociated_data,
    PLAT_UI16 message_length,
    PLAT_UI8 *pEncrypted_message,
    PLAT_UI8 *pEncrypted_authentication_tag,
    PLAT_UI8 *pVerification_result,
    PLAT_UI8 *pPlaintext_message) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_decrypt(
        p_stse,
        slot_number,
        authentication_tag_length,
        p_nonce,
        associated_data_length,
        pAssociated_data,
        message_length,
        pEncrypted_message,
        pEncrypted_authentication_tag,
        pVerification_result,
        pPlaintext_message);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_encrypt(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *pAssociated_data,
    PLAT_UI16 message_length,
    PLAT_UI8 *pPlaintext_message,
    PLAT_UI8 *pEncrypted_message,
    PLAT_UI8 *pAuthentication_tag) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_encrypt(
        p_stse,
        slot_number,
        authentication_tag_length,
        iv_length,
        p_iv,
        associated_data_length,
        pAssociated_data,
        message_length,
        pPlaintext_message,
        pEncrypted_message,
        pAuthentication_tag);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_decrypt_start(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 nonce_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 total_associated_data_length,
    PLAT_UI16 total_ciphertext_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pPlaintext_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_decrypt_start(
        p_stse,
        slot_number,
        nonce_length,
        p_nonce,
        total_associated_data_length,
        total_ciphertext_length,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pEncrypted_message_chunk,
        pPlaintext_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_decrypt_process(
    stse_handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pPlaintext_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_decrypt_process(
        p_stse,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pEncrypted_message_chunk,
        pPlaintext_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_ccm_decrypt_finish(
    stse_handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pAuthentication_tag,
    PLAT_UI8 *pVerification_result,
    PLAT_UI8 *pPlaintext_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_ccm_decrypt_finish(
        p_stse,
        authentication_tag_length,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pEncrypted_message_chunk,
        pAuthentication_tag,
        pVerification_result,
        pPlaintext_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_encrypt_start(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pPlaintext_message_chunk,
    PLAT_UI8 *pEncrypted_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_encrypt_start(
        p_stse,
        slot_number,
        iv_length,
        p_iv,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pPlaintext_message_chunk,
        pEncrypted_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_encrypt_process(
    stse_handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pPlaintext_message_chunk,
    PLAT_UI8 *pEncrypted_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_encrypt_process(
        p_stse,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pPlaintext_message_chunk,
        pEncrypted_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_encrypt_finish(
    stse_handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pPlaintext_message_chunk,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pAuthentication_tag) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_encrypt_finish(
        p_stse,
        authentication_tag_length,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pPlaintext_message_chunk,
        pEncrypted_message_chunk,
        pAuthentication_tag);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_decrypt(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *pAssociated_data,
    PLAT_UI16 message_length,
    PLAT_UI8 *pEncrypted_message,
    PLAT_UI8 *pAuthentication_tag,
    PLAT_UI8 *pVerification_result,
    PLAT_UI8 *pPlaintext_message) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_decrypt(
        p_stse,
        slot_number,
        authentication_tag_length,
        iv_length,
        p_iv,
        associated_data_length,
        pAssociated_data,
        message_length,
        pEncrypted_message,
        pAuthentication_tag,
        pVerification_result,
        pPlaintext_message);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_decrypt_start(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pPlaintext_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_decrypt_start(
        p_stse,
        slot_number,
        iv_length,
        p_iv,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pEncrypted_message_chunk,
        pPlaintext_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_decrypt_process(
    stse_handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pPlaintext_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_decrypt_process(
        p_stse,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pEncrypted_message_chunk,
        pPlaintext_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gcm_decrypt_finish(
    stse_handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *pAssociated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *pEncrypted_message_chunk,
    PLAT_UI8 *pAuthentication_tag,
    PLAT_UI8 *pVerification_result,
    PLAT_UI8 *pPlaintext_message_chunk) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gcm_decrypt_finish(
        p_stse,
        authentication_tag_length,
        associated_data_chunk_length,
        pAssociated_data_chunk,
        message_chunk_length,
        pEncrypted_message_chunk,
        pAuthentication_tag,
        pVerification_result,
        pPlaintext_message_chunk);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}
