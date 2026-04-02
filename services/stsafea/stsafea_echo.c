/*!
 ******************************************************************************
 * \file	stsafea_echo.c
 * \brief   Echo services for STSAFE-A
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

#include "services/stsafea/stsafea_echo.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_ReturnCode_t stsafea_echo(stse_Handler_t *pSTSE,
                               PLAT_UI8 *pMessage,
                               PLAT_UI8 *pEchoed_message,
                               PLAT_UI16 message_length) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_ECHO;
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if (pMessage == NULL || pEchoed_message == NULL || message_length == 0) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eMessage, message_length, pMessage);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eEchoed_message, message_length, pEchoed_message);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(pSTSE,
                                  &CmdFrame,
                                  &RspFrame);
}

stse_ReturnCode_t stsafea_echo_start(
    stsafea_echo_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pMessage,
    PLAT_UI8 *pEchoed_message,
    PLAT_UI16 message_length) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (pMessage == NULL || pEchoed_message == NULL || message_length == 0) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_ECHO;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eMessage_elem = (stse_frame_element_t){message_length, pMessage, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eMessage_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eEchoed_message_elem = (stse_frame_element_t){message_length, pEchoed_message, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eEchoed_message_elem);

    return stsafea_frame_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_echo_transfer(stsafea_echo_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_echo_finalize(stsafea_echo_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_finalize(pCtx->pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
