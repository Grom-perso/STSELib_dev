/*!
 ******************************************************************************
 * \file	stsafea_aes.c
 * \brief   STSAFE Middleware services for symmetric key cryptography (source)
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

#include "services/stsafea/stsafea_aes.h"
#include "services/stsafea/stsafea_frame_transfer.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_ReturnCode_t stsafea_aes_ecb_encrypt(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 message_length,
    PLAT_UI8 *p_plaintext_message,
    PLAT_UI8 *p_encrypted_message) {
    stse_ReturnCode_t ret;
    PLAT_UI8 cmd_header = STSAFEA_CMD_ENCRYPT;
    PLAT_UI8 sub_command_distinguisher = 0x02;
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */

    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    /* - Check stsafe-a handler initialization */

    if ((p_plaintext_message == NULL) || (p_encrypted_message == NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame : [HEADER] [CMD DISTINGUISHER] [SLOT] [MESSAGE]  */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSub_command_distinguisher, 1, &sub_command_distinguisher);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, ePlaintext_message, message_length, p_plaintext_message);

    /* - Prepare RSP Frame : [HEADER] [ENCRYPTED MESSAGE]  */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eEncrypted_message, message_length, p_encrypted_message);

    /* - Perform Transfer*/
    ret = stsafea_frame_transfer(p_stse,
                                 &CmdFrame,
                                 &Rsp_frame);

#ifdef STSE_CONF_USE_HOST_SESSION
    if (ret != STSE_OK) {
        memset(p_encrypted_message, 0, message_length);
    }
#endif
    return ret;
}

stse_ReturnCode_t stsafea_aes_ecb_decrypt(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 message_length,
    PLAT_UI8 *p_encrypted_message,
    PLAT_UI8 *p_plaintext_message) {
    stse_ReturnCode_t ret;
    PLAT_UI8 cmd_header = STSAFEA_CMD_DECRYPT;
    PLAT_UI8 sub_command_distinguisher = 0x02;
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_plaintext_message == NULL) || (p_encrypted_message == NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame : [HEADER] [CMD DISTINGUISHER] [SLOT] [ENCRYPTED MESSAGE]  */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSub_command_distinguisher, 1, &sub_command_distinguisher);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eEncrypted_message, message_length, p_encrypted_message);

    /* - Prepare RSP Frame : [HEADER] [PLAIN TEXT MESSAGE]  */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, ePlaintext_message, message_length, p_plaintext_message);

    /* - Perform Transfer*/
    ret = stsafea_frame_transfer(p_stse,
                                 &CmdFrame,
                                 &Rsp_frame);

#ifdef STSE_CONF_USE_HOST_SESSION
    if (ret != STSE_OK) {
        memset(p_plaintext_message, 0, message_length);
    }
#endif
    return ret;
}

stse_ReturnCode_t stsafea_aes_ccm_encrypt(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *p_associated_data,
    PLAT_UI16 message_length,
    PLAT_UI8 *p_plaintext_message,
    PLAT_UI8 *p_encrypted_message,
    PLAT_UI8 *p_encrypted_authentication_tag,
    PLAT_UI8 counter_presence,
    PLAT_UI32 *p_counter) {
    stse_ReturnCode_t ret;
    PLAT_UI8 cmd_header = STSAFEA_CMD_ENCRYPT;
    PLAT_UI8 sub_command_distinguisher = 0x02;
    PLAT_UI8 rsp_header;
    PLAT_UI8 received_counter_presence = 0;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_nonce == NULL) ||
        (p_associated_data == NULL && associated_data_length != 0) ||
        (p_associated_data != NULL && associated_data_length == 0) ||
        (p_plaintext_message == NULL && message_length != 0) ||
        (p_plaintext_message != NULL && message_length == 0) ||
        (p_encrypted_message == NULL && message_length != 0) ||
        (p_encrypted_message != NULL && message_length == 0) ||
        (p_encrypted_authentication_tag == NULL && authentication_tag_length != 0) ||
        (p_encrypted_authentication_tag != NULL && authentication_tag_length == 0)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    if ((counter_presence == 1) && (p_counter == NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame : [HEADER] [CMD DISTINGUISHER] [SLOT] [ASSOCIATED DATA LENGHT] ...
	 *                       ... [ASSOCIATED DATA MESSAGE] [MESSAGE LENGHT] [MESSAGE] */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSub_command_distinguisher, 1, &sub_command_distinguisher);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eNonce, STSAFEA_NONCE_SIZE, p_nonce);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_length);
    stse_frame_element_allocate(eAssociated_data, associated_data_length, p_associated_data);
    if (associated_data_length != 0) {
        stse_frame_push_element(&CmdFrame, &eAssociated_data);
    }
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_length);
    stse_frame_element_allocate(ePlaintext_message, message_length, p_plaintext_message);
    if (associated_data_length != 0) {
        stse_frame_push_element(&CmdFrame, &ePlaintext_message);
    }

    /* - Prepare RSP Frame : [HEADER] [ENCRYPTED MESSAGE] [TAG LENGTH] [COUNTER PRES.] [COUNTER VAL] */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eEncrypted_message, message_length, p_encrypted_message);
    stse_frame_element_allocate_push(&Rsp_frame, eAuthentication_tag, authentication_tag_length, p_encrypted_authentication_tag);
    stse_frame_element_allocate_push(&Rsp_frame, eCounter_presence, 1, &received_counter_presence);
    stse_frame_element_allocate(eCounter, STSAFEA_COUNTER_VALUE_SIZE, (PLAT_UI8 *)p_counter);
    if (counter_presence != 0) {
        stse_frame_push_element(&Rsp_frame, &eCounter);
    }

    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    ret = stsafea_frame_transfer(p_stse,
                                 &CmdFrame,
                                 &Rsp_frame);

    if (counter_presence != 0) {
        stse_frame_element_swap_byte_order(&eCounter);
    }

    return ret;
}

stse_ReturnCode_t stsafea_aes_ccm_encrypt_start(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 Nonce_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 total_associated_data_length,
    PLAT_UI32 total_message_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_plaintext_message_chunk,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_counter_presence,
    PLAT_UI32 *p_counter) {
    stse_ReturnCode_t ret;
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_START_ENCRYPT};

    PLAT_UI8 rsp_header;
    PLAT_UI8 alt_counter_presence;
    PLAT_UI8 alt_counter[STSAFEA_COUNTER_VALUE_SIZE];

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_nonce == NULL) || (p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0) || (p_encrypted_message_chunk == NULL && message_chunk_length != 0) || (p_encrypted_message_chunk != NULL && message_chunk_length == 0)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eNonce_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&Nonce_length);
    stse_frame_element_allocate_push(&CmdFrame, eNonce, Nonce_length, p_nonce);
    stse_frame_element_allocate_push(&CmdFrame, eTotal_associated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&total_associated_data_length);
    stse_frame_element_allocate_push(&CmdFrame, eTotal_message_length, 4, (PLAT_UI8 *)&total_message_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);
    stse_frame_element_allocate_push(&Rsp_frame, eCounter_presence, 1, p_counter_presence);
    stse_frame_element_allocate_push(&Rsp_frame, eCounter, STSAFEA_COUNTER_VALUE_SIZE, (PLAT_UI8 *)p_counter);

    if (p_counter_presence == NULL) {
        eCounter_presence.p_data = &alt_counter_presence;
    }

    if (p_counter == NULL) {
        eCounter.p_data = alt_counter;
    }

    /* - Swap byte order */
    stse_frame_element_swap_byte_order(&eNonce_length);
    stse_frame_element_swap_byte_order(&eTotal_associated_data_length);
    stse_frame_element_swap_byte_order(&eTotal_message_length);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    ret = stsafea_frame_transfer(p_stse,
                                 &CmdFrame,
                                 &Rsp_frame);

    if (*p_counter_presence != 0) {
        stse_frame_element_swap_byte_order(&eCounter);
    }

    return ret;
}

stse_ReturnCode_t stsafea_aes_ccm_encrypt_process(
    stse_Handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_plaintext_message_chunk,
    PLAT_UI8 *p_encrypted_message_chunk) {
    return stsafea_aes_gcm_encrypt_process(p_stse,
                                           associated_data_chunk_length,
                                           p_associated_data_chunk,
                                           message_chunk_length,
                                           p_plaintext_message_chunk,
                                           p_encrypted_message_chunk);
}

stse_ReturnCode_t stsafea_aes_ccm_encrypt_finish(
    stse_Handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_plaintext_message_chunk,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_encrypted_authentication_tag) {
    return stsafea_aes_gcm_encrypt_finish(p_stse,
                                          authentication_tag_length,
                                          associated_data_chunk_length,
                                          p_associated_data_chunk,
                                          message_chunk_length,
                                          p_plaintext_message_chunk,
                                          p_encrypted_message_chunk,
                                          p_encrypted_authentication_tag);
}

stse_ReturnCode_t stsafea_aes_ccm_decrypt(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *p_associated_data,
    PLAT_UI16 message_length,
    PLAT_UI8 *p_encrypted_message,
    PLAT_UI8 *p_encrypted_authentication_tag,
    PLAT_UI8 *p_verification_result,
    PLAT_UI8 *p_plaintext_message) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_DECRYPT;
    PLAT_UI8 sub_command_distinguisher = 0x02;
    PLAT_UI16 encrypted_message_length = message_length + authentication_tag_length;
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_nonce == NULL) || (p_associated_data == NULL && associated_data_length != 0) || (p_associated_data != NULL && associated_data_length == 0) || (p_encrypted_message == NULL && message_length != 0) || (p_encrypted_message != NULL && message_length == 0) || (p_plaintext_message == NULL && message_length != 0) || (p_plaintext_message != NULL && message_length == 0) || (p_encrypted_authentication_tag == NULL && authentication_tag_length != 0) || (p_encrypted_authentication_tag != NULL && authentication_tag_length == 0) || (p_verification_result == NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame : [HEADER] [CMD DISTINGUISHER] [SLOT] [NONCE] [ASSOCIATED DATA LENGHT] ...
	 *                       ... [ASSOCIATED DATA] [MESSAGE LENGHT] [ENCRYPTED MESSAGE] [TAG] */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSub_command_distinguisher, 1, &sub_command_distinguisher);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eNonce, STSAFEA_NONCE_SIZE, p_nonce);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_length, p_associated_data);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&encrypted_message_length);
    stse_frame_element_allocate_push(&CmdFrame, eEncrypted_message, message_length, p_encrypted_message);
    stse_frame_element_allocate_push(&CmdFrame, eAuthentication_tag, authentication_tag_length, p_encrypted_authentication_tag);

    /* - Prepare RSP Frame : [HEADER] [VERIFICATION RESULT] [PLAIN TEXT MESSAGE] */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eVerification_result, 1, p_verification_result);
    stse_frame_element_allocate_push(&Rsp_frame, ePlaintext_message, message_length, p_plaintext_message);

    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_ccm_decrypt_start(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 Nonce_length,
    PLAT_UI8 *p_nonce,
    PLAT_UI16 total_associated_data_length,
    PLAT_UI16 total_ciphertext_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_plaintext_message_chunk) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_START_DECRYPT};
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_nonce == NULL) || (p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_encrypted_message_chunk == NULL && message_chunk_length != 0) || (p_encrypted_message_chunk != NULL && message_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eNonce_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&Nonce_length);
    stse_frame_element_allocate_push(&CmdFrame, eIV, Nonce_length, p_nonce);
    stse_frame_element_allocate_push(&CmdFrame, eTotal_associated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&total_associated_data_length);
    stse_frame_element_allocate_push(&CmdFrame, eTotal_ciphertext_length, 4, (PLAT_UI8 *)&total_ciphertext_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);

    /* - Swap byte order */
    stse_frame_element_swap_byte_order(&eNonce_length);
    stse_frame_element_swap_byte_order(&eTotal_associated_data_length);
    stse_frame_element_swap_byte_order(&eTotal_ciphertext_length);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_ccm_decrypt_process(
    stse_Handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_plaintext_message_chunk) {
    return stsafea_aes_gcm_decrypt_process(p_stse,
                                           associated_data_chunk_length,
                                           p_associated_data_chunk,
                                           message_chunk_length,
                                           p_encrypted_message_chunk,
                                           p_plaintext_message_chunk);
}

stse_ReturnCode_t stsafea_aes_ccm_decrypt_finish(
    stse_Handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_authentication_tag,
    PLAT_UI8 *p_verification_result,
    PLAT_UI8 *p_plaintext_message_chunk) {
    return stsafea_aes_gcm_decrypt_finish(p_stse,
                                          authentication_tag_length,
                                          associated_data_chunk_length,
                                          p_associated_data_chunk,
                                          message_chunk_length,
                                          p_encrypted_message_chunk,
                                          p_authentication_tag,
                                          p_verification_result,
                                          p_plaintext_message_chunk);
}

stse_ReturnCode_t stsafea_aes_gcm_encrypt(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 IV_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *p_associated_data,
    PLAT_UI16 message_length,
    PLAT_UI8 *p_plaintext_message,
    PLAT_UI8 *p_encrypted_message,
    PLAT_UI8 *p_authentication_tag) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_ENCRYPT;
    PLAT_UI8 sub_command_distinguisher = 0x02;
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_iv == NULL || IV_length == 0) || (p_associated_data == NULL && p_plaintext_message == NULL) || (p_associated_data == NULL && associated_data_length != 0) || (p_associated_data != NULL && associated_data_length == 0) || (p_plaintext_message == NULL && message_length != 0) || (p_plaintext_message != NULL && message_length == 0) || (p_encrypted_message == NULL && p_plaintext_message != NULL) || (p_authentication_tag == NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame : [HEADER] [CMD DISTINGUISHER] [SLOT] [ASSOCIATED DATA LENGHT] ...
	 *                       ... [ASSOCIATED DATA MESSAGE] [MESSAGE LENGHT] [MESSAGE] */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSub_command_distinguisher, 1, &sub_command_distinguisher);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eIV_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&IV_length);
    stse_frame_element_allocate_push(&CmdFrame, eIV, IV_length, p_iv);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_length, p_associated_data);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_length);
    stse_frame_element_allocate_push(&CmdFrame, ePlaintext_message, message_length, p_plaintext_message);

    /* - Prepare RSP Frame : [HEADER] [ENCRYPTED MESSAGE] [TAG LENGTH] */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eEncrypted_message, message_length, p_encrypted_message);
    stse_frame_element_allocate_push(&Rsp_frame, eAuthentication_tag, authentication_tag_length, p_authentication_tag);

    stse_frame_element_swap_byte_order(&eIV_length);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_gcm_encrypt_start(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 IV_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_plaintext_message_chunk,
    PLAT_UI8 *p_encrypted_message_chunk) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_START_ENCRYPT};
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_iv == NULL || IV_length == 0) || (p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0) || (p_plaintext_message_chunk == NULL && p_plaintext_message_chunk != NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eIV_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&IV_length);
    stse_frame_element_allocate_push(&CmdFrame, eIV, IV_length, p_iv);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);

    stse_frame_element_swap_byte_order(&eIV_length);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_gcm_encrypt_process(
    stse_Handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_plaintext_message_chunk,
    PLAT_UI8 *p_encrypted_message_chunk) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_PROCESS_ENCRYPT};
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0) || (p_encrypted_message_chunk == NULL && p_plaintext_message_chunk != NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_gcm_encrypt_finish(
    stse_Handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_plaintext_message_chunk,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_authentication_tag) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_FINISH_ENCRYPT};
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0) || (p_encrypted_message_chunk == NULL && p_plaintext_message_chunk != NULL) || (p_authentication_tag == NULL && authentication_tag_length == 0)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);
    stse_frame_element_allocate_push(&Rsp_frame, eAuthentication_tag, authentication_tag_length, p_authentication_tag);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_gcm_decrypt(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 IV_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *p_associated_data,
    PLAT_UI16 message_length,
    PLAT_UI8 *p_encrypted_message,
    PLAT_UI8 *p_authentication_tag,
    PLAT_UI8 *p_verification_result,
    PLAT_UI8 *p_plaintext_message) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_DECRYPT;
    PLAT_UI8 sub_command_distinguisher = 0x02;
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */

    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_iv == NULL || IV_length == 0) || (p_associated_data == NULL && p_encrypted_message == NULL) || (p_associated_data == NULL && associated_data_length != 0) || (p_associated_data != NULL && associated_data_length == 0) || (p_encrypted_message == NULL && message_length != 0) || (p_encrypted_message != NULL && message_length == 0) || (p_plaintext_message == NULL && p_encrypted_message != NULL) || (p_authentication_tag == NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame : [HEADER] [CMD DISTINGUISHER] [SLOT] [IV] [ASSOCIATED DATA LENGHT] ...
	 *                       ... [ASSOCIATED DATA] [MESSAGE LENGHT] [ENCRYPTED MESSAGE] [TAG] */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSub_command_distinguisher, 1, &sub_command_distinguisher);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eIV_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&IV_length);
    stse_frame_element_allocate_push(&CmdFrame, eIV, IV_length, p_iv);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_length, p_associated_data);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_length);
    stse_frame_element_allocate_push(&CmdFrame, eEncrypted_message, message_length, p_encrypted_message);
    stse_frame_element_allocate_push(&CmdFrame, eAuthentication_tag, authentication_tag_length, p_authentication_tag);

    /* - Prepare RSP Frame : [HEADER] [VERIFICATION RESULT] [PLAIN TEXT MESSAGE] */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eVerification_result, 1, p_verification_result);
    stse_frame_element_allocate_push(&Rsp_frame, ePlaintext_message, message_length, p_plaintext_message);

    stse_frame_element_swap_byte_order(&eIV_length);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_gcm_decrypt_start(
    stse_Handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 IV_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_plaintext_message_chunk) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_START_DECRYPT};
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_iv == NULL || IV_length == 0) || (p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0) || (p_encrypted_message_chunk == NULL && p_plaintext_message_chunk != NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &slot_number);
    stse_frame_element_allocate_push(&CmdFrame, eIV_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&IV_length);
    stse_frame_element_allocate_push(&CmdFrame, eIV, IV_length, p_iv);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);
    stse_frame_element_swap_byte_order(&eIV_length);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_gcm_decrypt_process(
    stse_Handler_t *p_stse,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_plaintext_message_chunk) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_PROCESS_DECRYPT};
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0) || (p_encrypted_message_chunk == NULL && p_plaintext_message_chunk != NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafea_aes_gcm_decrypt_finish(
    stse_Handler_t *p_stse,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI16 associated_data_chunk_length,
    PLAT_UI8 *p_associated_data_chunk,
    PLAT_UI16 message_chunk_length,
    PLAT_UI8 *p_encrypted_message_chunk,
    PLAT_UI8 *p_authentication_tag,
    PLAT_UI8 *p_verification_result,
    PLAT_UI8 *p_plaintext_message_chunk) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_FINISH_DECRYPT};
    PLAT_UI8 rsp_header;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((p_associated_data_chunk == NULL && associated_data_chunk_length != 0) || (p_associated_data_chunk != NULL && associated_data_chunk_length == 0) || (p_plaintext_message_chunk == NULL && message_chunk_length != 0) || (p_plaintext_message_chunk != NULL && message_chunk_length == 0) || (p_encrypted_message_chunk == NULL && p_plaintext_message_chunk != NULL) || (p_authentication_tag == NULL && authentication_tag_length == 0) || (p_verification_result == NULL)) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    /* - Prepare CMD Frame */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&associated_data_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eAssociated_data, associated_data_chunk_length, p_associated_data_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eMessage_length, STSAFEA_GENERIC_LENGTH_SIZE, (PLAT_UI8 *)&message_chunk_length);
    stse_frame_element_allocate_push(&CmdFrame, eEncrypted_message, message_chunk_length, p_encrypted_message_chunk);
    stse_frame_element_allocate_push(&CmdFrame, eAuthentication_tag, authentication_tag_length, p_authentication_tag);

    /* - Prepare RSP Frame */
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eVerification_result, 1, p_verification_result);
    stse_frame_element_allocate_push(&Rsp_frame, ePlaintext_message, message_chunk_length, p_plaintext_message_chunk);
    stse_frame_element_swap_byte_order(&eAssociated_data_length);
    stse_frame_element_swap_byte_order(&eMessage_length);

    /* - Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
