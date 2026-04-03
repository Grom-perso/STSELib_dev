/*!
 ******************************************************************************
 * \file	stsafea_password.c
 * \brief   password services for STSAFE-A
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

#include "services/stsafea/stsafea_password.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_ReturnCode_t stsafea_verify_password(
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pPassword_buffer,
    PLAT_UI8 password_length,
    PLAT_UI8 *pVerification_status,
    PLAT_UI8 *pRemaining_tries) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_VERIFY_PASSWORD;
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((password_length != STSAFEA_PASSWORD_LENGTH)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, ePassword, password_length, pPassword_buffer);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eVerStat, 1, pVerification_status);
    stse_frame_element_allocate_push(&RspFrame, eRemTri, 1, pRemaining_tries);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(pSTSE,
                                  &CmdFrame,
                                  &RspFrame);
}

stse_ReturnCode_t stsafea_delete_password(stse_Handler_t *pSTSE) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_DELETE;
    PLAT_UI8 tag = STSAFEA_DELETE_TAG_PASSWORD;
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eTag, 1, &tag);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);

    /*- Perform Transfer*/
    return stsafea_frame_raw_transfer(pSTSE,
                                      &CmdFrame,
                                      &RspFrame,
                                      stsafea_cmd_timings[pSTSE->device_type][cmd_header]);
}

stse_ReturnCode_t stsafea_verify_password_start(
    stsafea_verify_password_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pPassword_buffer,
    PLAT_UI8 password_length,
    PLAT_UI8 *pVerification_status,
    PLAT_UI8 *pRemaining_tries) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (password_length != STSAFEA_PASSWORD_LENGTH) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_VERIFY_PASSWORD;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->ePassword_elem = (stse_frame_element_t){password_length, pPassword_buffer, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->ePassword_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eVerStat_elem = (stse_frame_element_t){1, pVerification_status, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eVerStat_elem);
    pCtx->eRemTri_elem = (stse_frame_element_t){1, pRemaining_tries, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRemTri_elem);

    return stsafea_frame_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_verify_password_transfer(stsafea_verify_password_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_verify_password_finalize(stsafea_verify_password_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_finalize(&pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_delete_password_start(
    stsafea_delete_password_ctx_t *pCtx,
    stse_Handler_t *pSTSE) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_DELETE;
    pCtx->tag = STSAFEA_DELETE_TAG_PASSWORD;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eTag_elem = (stse_frame_element_t){1, &pCtx->tag, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eTag_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);

    return stsafea_frame_raw_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_delete_password_transfer(stsafea_delete_password_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_delete_password_finalize(stsafea_delete_password_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_raw_transfer_finalize(&pCtx->nb_ctx, &pCtx->RspFrame);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
