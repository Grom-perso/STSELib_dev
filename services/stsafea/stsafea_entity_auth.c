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
    stsafea_generate_challenge_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 challenge_size,
    PLAT_UI8 *pChallenge) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pChallenge == NULL) || (challenge_size < STSE_EDDSA_CHALLENGE_SIZE)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header[0] = STSAFEA_EXTENDED_COMMAND_PREFIX;
    pCtx->cmd_header[1] = STSAFEA_EXTENDED_CMD_GENERATE_CHALLENGE;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){STSAFEA_EXT_HEADER_SIZE, pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eChallenge_elem = (stse_frame_element_t){STSE_EDDSA_CHALLENGE_SIZE, pChallenge, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eChallenge_elem);

    return stsafea_frame_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_generate_challenge_transfer(stsafea_generate_challenge_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_generate_challenge_finalize(stsafea_generate_challenge_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_finalize(&pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_verify_entity_signature_start(
    stsafea_verify_entity_signature_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *pSignature,
    PLAT_UI8 *pSignature_validity) {
    PLAT_UI16 half_sig_size;

    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (pSignature == NULL || pSignature_validity == NULL || key_type >= STSE_ECC_KT_INVALID) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header[0] = STSAFEA_EXTENDED_COMMAND_PREFIX;
    pCtx->cmd_header[1] = STSAFEA_EXTENDED_CMD_VERIFY_ENTITY_SIGNATURE;
    pCtx->filler = 0x00;
    pCtx->slot_number = slot_number;

    half_sig_size = stse_ecc_info_table[key_type].signature_size >> 1;
    pCtx->signature_length[0] = UI16_B1(half_sig_size);
    pCtx->signature_length[1] = UI16_B0(half_sig_size);

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){STSAFEA_EXT_HEADER_SIZE, pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eFiller_elem = (stse_frame_element_t){1, &pCtx->filler, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eFiller_elem);
    pCtx->eSlot_number_elem = (stse_frame_element_t){STSAFEA_SLOT_NUMBER_ID_SIZE, &pCtx->slot_number, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSlot_number_elem);
    pCtx->eSignature_R_length_elem = (stse_frame_element_t){STSE_ECC_GENERIC_LENGTH_SIZE, pCtx->signature_length, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSignature_R_length_elem);
    pCtx->eSignature_R_elem = (stse_frame_element_t){half_sig_size, pSignature, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSignature_R_elem);
    pCtx->eSignature_S_length_elem = (stse_frame_element_t){STSE_ECC_GENERIC_LENGTH_SIZE, pCtx->signature_length, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSignature_S_length_elem);
    pCtx->eSignature_S_elem = (stse_frame_element_t){half_sig_size, pSignature + half_sig_size, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSignature_S_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eSignature_validity_elem = (stse_frame_element_t){1, pSignature_validity, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eSignature_validity_elem);

    return stsafea_frame_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_verify_entity_signature_transfer(stsafea_verify_entity_signature_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_verify_entity_signature_finalize(stsafea_verify_entity_signature_ctx_t *pCtx) {
    stse_ReturnCode_t ret;

    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    ret = stsafea_frame_transfer_finalize(&pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
    if (ret != STSE_OK) {
        *(pCtx->eSignature_validity_elem.pData) = STSAFEA_FALSE;
    }
    return ret;
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
