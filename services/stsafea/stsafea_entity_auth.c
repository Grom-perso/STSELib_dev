/*!
 ******************************************************************************
 * \file	stsafea_entity_auth.c
 * \brief   Entity authentication services for STSAFE-A (source)
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
 ******************************************************************************
 */

#include "services/stsafea/stsafea_entity_auth.h"
#include "services/stsafea/stsafea_frame_transfer.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_return_code_t stsafea_generate_challenge(
    stse_handler_t *p_stse,
    PLAT_UI8 challenge_size,
    PLAT_UI8 *p_challenge) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_GENERATE_CHALLENGE};
    PLAT_UI8 rsp_header;

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if ((p_challenge == NULL) || (challenge_size < STSE_EDDSA_CHALLENGE_SIZE)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(cmd_frame);
    stse_frame_element_allocate_push(&cmd_frame, ecmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(rsp_frame);
    stse_frame_element_allocate_push(&rsp_frame, ersp_header, 1, &rsp_header);
    stse_frame_element_allocate_push(&rsp_frame, eChallenge, STSE_EDDSA_CHALLENGE_SIZE, p_challenge);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(p_stse,
                                  &cmd_frame,
                                  &rsp_frame);
}

stse_return_code_t stsafea_verify_entity_signature(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *p_signature,
    PLAT_UI8 *p_signature_validity) {
    stse_return_code_t ret;
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_VERIFY_ENTITY_SIGNATURE};

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if (p_signature == NULL || p_signature_validity == NULL || key_type >= STSE_ECC_KT_INVALID) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    PLAT_UI8 filler = 0x00;
    stse_frame_element_allocate(eFiller, 1, &filler);

    stse_frame_allocate(cmd_frame);
    stse_frame_element_allocate_push(&cmd_frame, ecmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_push_element(&cmd_frame, &eFiller);
    stse_frame_element_allocate_push(&cmd_frame, eslot_number, STSAFEA_SLOT_NUMBER_ID_SIZE, &slot_number);

    /* Signature elements */
    PLAT_UI8 p_signature_length_element[STSE_ECC_GENERIC_LENGTH_SIZE] = {
        UI16_B1(stse_ecc_info_table[key_type].signature_size >> 1),
        UI16_B0(stse_ecc_info_table[key_type].signature_size >> 1),
    };

    stse_frame_element_allocate_push(&cmd_frame, eSignature_r_length, STSE_ECC_GENERIC_LENGTH_SIZE, p_signature_length_element);
    stse_frame_element_allocate_push(&cmd_frame, eSignature_R, (stse_ecc_info_table[key_type].signature_size >> 1), p_signature);
    stse_frame_element_allocate_push(&cmd_frame, eSignature_s_length, STSE_ECC_GENERIC_LENGTH_SIZE, p_signature_length_element);
    stse_frame_element_allocate_push(&cmd_frame, eSignature_S, (stse_ecc_info_table[key_type].signature_size >> 1), p_signature + (stse_ecc_info_table[key_type].signature_size >> 1));

    PLAT_UI8 rsp_header;
    stse_frame_allocate(rsp_frame);
    stse_frame_element_allocate_push(&rsp_frame, ersp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&rsp_frame, esignature_validity, 1, p_signature_validity);

    /*- Perform Transfer*/
    ret = stsafea_frame_transfer(p_stse,
                                 &cmd_frame,
                                 &rsp_frame);

    if (ret != STSE_OK) {
        *p_signature_validity = STSAFEA_FALSE;
    }

    return (ret);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
