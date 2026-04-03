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
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

static PLAT_UI8 s_gen_challenge_cmd_header[STSAFEA_EXT_HEADER_SIZE];
static PLAT_UI8 s_gen_challenge_rsp_header;
static stse_frame_t s_gen_challenge_CmdFrame;
static stse_frame_t s_gen_challenge_RspFrame;
static stse_frame_element_t s_gen_challenge_eCmd_header;
static stse_frame_element_t s_gen_challenge_eRsp_header;
static stse_frame_element_t s_gen_challenge_eChallenge;

static PLAT_UI8 s_verify_entity_sig_cmd_header[STSAFEA_EXT_HEADER_SIZE];
static PLAT_UI8 s_verify_entity_sig_filler;
static PLAT_UI8 s_verify_entity_sig_slot_number;
static PLAT_UI8 s_verify_entity_sig_signature_length[STSE_ECC_GENERIC_LENGTH_SIZE];
static PLAT_UI8 s_verify_entity_sig_rsp_header;
static stse_frame_t s_verify_entity_sig_CmdFrame;
static stse_frame_t s_verify_entity_sig_RspFrame;
static stse_frame_element_t s_verify_entity_sig_eCmd_header;
static stse_frame_element_t s_verify_entity_sig_eFiller;
static stse_frame_element_t s_verify_entity_sig_eSlot_number;
static stse_frame_element_t s_verify_entity_sig_eSignature_R_length;
static stse_frame_element_t s_verify_entity_sig_eSignature_R;
static stse_frame_element_t s_verify_entity_sig_eSignature_S_length;
static stse_frame_element_t s_verify_entity_sig_eSignature_S;
static stse_frame_element_t s_verify_entity_sig_eRsp_header;
static stse_frame_element_t s_verify_entity_sig_eSignature_validity;
static PLAT_UI8 *s_verify_entity_sig_pSignature_validity;

stse_ReturnCode_t stsafea_generate_challenge(
    stse_Handler_t *pSTSE,
    PLAT_UI8 challenge_size,
    PLAT_UI8 *pChallenge) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_GENERATE_CHALLENGE};
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if ((pChallenge == NULL) || (challenge_size < STSE_EDDSA_CHALLENGE_SIZE)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eChallenge, STSE_EDDSA_CHALLENGE_SIZE, pChallenge);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(pSTSE,
                                  &CmdFrame,
                                  &RspFrame);
}

stse_ReturnCode_t stsafea_verify_entity_signature(
    stse_Handler_t *pSTSE,
    PLAT_UI8 slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *pSignature,
    PLAT_UI8 *pSignature_validity) {
    stse_ReturnCode_t ret;
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_VERIFY_ENTITY_SIGNATURE};

    /* - Check stsafe handler initialization */
    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if (pSignature == NULL || pSignature_validity == NULL || key_type >= STSE_ECC_KT_INVALID) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    PLAT_UI8 filler = 0x00;
    stse_frame_element_allocate(eFiller, 1, &filler);

    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_push_element(&CmdFrame, &eFiller);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, STSAFEA_SLOT_NUMBER_ID_SIZE, &slot_number);

    /* Signature elements */
    PLAT_UI8 pSignature_length_element[STSE_ECC_GENERIC_LENGTH_SIZE] = {
        UI16_B1(stse_ecc_info_table[key_type].signature_size >> 1),
        UI16_B0(stse_ecc_info_table[key_type].signature_size >> 1),
    };

    stse_frame_element_allocate_push(&CmdFrame, eSignature_R_length, STSE_ECC_GENERIC_LENGTH_SIZE, pSignature_length_element);
    stse_frame_element_allocate_push(&CmdFrame, eSignature_R, (stse_ecc_info_table[key_type].signature_size >> 1), pSignature);
    stse_frame_element_allocate_push(&CmdFrame, eSignature_S_length, STSE_ECC_GENERIC_LENGTH_SIZE, pSignature_length_element);
    stse_frame_element_allocate_push(&CmdFrame, eSignature_S, (stse_ecc_info_table[key_type].signature_size >> 1), pSignature + (stse_ecc_info_table[key_type].signature_size >> 1));

    PLAT_UI8 rsp_header;
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eSignature_validity, 1, pSignature_validity);

    /*- Perform Transfer*/
    ret = stsafea_frame_transfer(pSTSE,
                                 &CmdFrame,
                                 &RspFrame);

    if (ret != STSE_OK) {
        *pSignature_validity = STSAFEA_FALSE;
    }

    return (ret);
}

stse_ReturnCode_t stsafea_generate_challenge_start(
    stse_Handler_t *pSTSE,
    PLAT_UI8 challenge_size,
    PLAT_UI8 *pChallenge) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pChallenge == NULL) || (challenge_size < STSE_EDDSA_CHALLENGE_SIZE)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_gen_challenge_cmd_header[0] = STSAFEA_EXTENDED_COMMAND_PREFIX;
    s_gen_challenge_cmd_header[1] = STSAFEA_EXTENDED_CMD_GENERATE_CHALLENGE;

    s_gen_challenge_CmdFrame = (stse_frame_t){0};
    s_gen_challenge_eCmd_header = (stse_frame_element_t){STSAFEA_EXT_HEADER_SIZE, s_gen_challenge_cmd_header, NULL};
    stse_frame_push_element(&s_gen_challenge_CmdFrame, &s_gen_challenge_eCmd_header);

    s_gen_challenge_RspFrame = (stse_frame_t){0};
    s_gen_challenge_eRsp_header = (stse_frame_element_t){1, &s_gen_challenge_rsp_header, NULL};
    stse_frame_push_element(&s_gen_challenge_RspFrame, &s_gen_challenge_eRsp_header);
    s_gen_challenge_eChallenge = (stse_frame_element_t){STSE_EDDSA_CHALLENGE_SIZE, pChallenge, NULL};
    stse_frame_push_element(&s_gen_challenge_RspFrame, &s_gen_challenge_eChallenge);

    return stsafea_frame_transfer_start(pSTSE, &s_gen_challenge_CmdFrame, &s_gen_challenge_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_generate_challenge_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_generate_challenge_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_gen_challenge_CmdFrame, &s_gen_challenge_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_verify_entity_signature_start(
    stse_Handler_t *pSTSE,
    PLAT_UI8 slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *pSignature,
    PLAT_UI8 *pSignature_validity) {
    PLAT_UI16 half_sig_size;

    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (pSignature == NULL || pSignature_validity == NULL || key_type >= STSE_ECC_KT_INVALID) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_verify_entity_sig_pSignature_validity = pSignature_validity;
    s_verify_entity_sig_cmd_header[0] = STSAFEA_EXTENDED_COMMAND_PREFIX;
    s_verify_entity_sig_cmd_header[1] = STSAFEA_EXTENDED_CMD_VERIFY_ENTITY_SIGNATURE;
    s_verify_entity_sig_filler = 0x00;
    s_verify_entity_sig_slot_number = slot_number;

    half_sig_size = stse_ecc_info_table[key_type].signature_size >> 1;
    s_verify_entity_sig_signature_length[0] = UI16_B1(half_sig_size);
    s_verify_entity_sig_signature_length[1] = UI16_B0(half_sig_size);

    s_verify_entity_sig_CmdFrame = (stse_frame_t){0};
    s_verify_entity_sig_eCmd_header = (stse_frame_element_t){STSAFEA_EXT_HEADER_SIZE, s_verify_entity_sig_cmd_header, NULL};
    stse_frame_push_element(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_eCmd_header);
    s_verify_entity_sig_eFiller = (stse_frame_element_t){1, &s_verify_entity_sig_filler, NULL};
    stse_frame_push_element(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_eFiller);
    s_verify_entity_sig_eSlot_number = (stse_frame_element_t){STSAFEA_SLOT_NUMBER_ID_SIZE, &s_verify_entity_sig_slot_number, NULL};
    stse_frame_push_element(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_eSlot_number);
    s_verify_entity_sig_eSignature_R_length = (stse_frame_element_t){STSE_ECC_GENERIC_LENGTH_SIZE, s_verify_entity_sig_signature_length, NULL};
    stse_frame_push_element(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_eSignature_R_length);
    s_verify_entity_sig_eSignature_R = (stse_frame_element_t){half_sig_size, pSignature, NULL};
    stse_frame_push_element(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_eSignature_R);
    s_verify_entity_sig_eSignature_S_length = (stse_frame_element_t){STSE_ECC_GENERIC_LENGTH_SIZE, s_verify_entity_sig_signature_length, NULL};
    stse_frame_push_element(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_eSignature_S_length);
    s_verify_entity_sig_eSignature_S = (stse_frame_element_t){half_sig_size, pSignature + half_sig_size, NULL};
    stse_frame_push_element(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_eSignature_S);

    s_verify_entity_sig_RspFrame = (stse_frame_t){0};
    s_verify_entity_sig_eRsp_header = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &s_verify_entity_sig_rsp_header, NULL};
    stse_frame_push_element(&s_verify_entity_sig_RspFrame, &s_verify_entity_sig_eRsp_header);
    s_verify_entity_sig_eSignature_validity = (stse_frame_element_t){1, pSignature_validity, NULL};
    stse_frame_push_element(&s_verify_entity_sig_RspFrame, &s_verify_entity_sig_eSignature_validity);

    return stsafea_frame_transfer_start(pSTSE, &s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_verify_entity_signature_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_verify_entity_signature_finalize(void) {
    stse_ReturnCode_t ret;
    ret = stsafea_frame_transfer_finalize(&s_verify_entity_sig_CmdFrame, &s_verify_entity_sig_RspFrame, &stsafea_nb_ctx);
    if (ret != STSE_OK) {
        *s_verify_entity_sig_pSignature_validity = STSAFEA_FALSE;
    }
    return ret;
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
