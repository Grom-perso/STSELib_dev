/*!
 ******************************************************************************
 * \file	stsafea_wrap_unwrap.c
 * \brief   Wrap & unwrap services for STSAFE-A
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

#include "services/stsafea/stsafea_wrap_unwrap.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_ReturnCode_t stsafea_wrap_payload(stse_Handler_t *pSTSE,
                                       PLAT_UI8 wrap_key_slot,
                                       PLAT_UI8 *pPayload,
                                       PLAT_UI16 payload_size,
                                       PLAT_UI8 *pWrapped_Payload,
                                       PLAT_UI16 wrapped_payload_size) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_WRAP_LOCAL_ENVELOPE;

    /* - Check stsafe handler initialization */
    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((pPayload == NULL) || (pWrapped_Payload == NULL) || (payload_size > 480) || (payload_size == 0) || (wrapped_payload_size != (payload_size + 8))) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    PLAT_UI8 rsp_header;

    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &wrap_key_slot);
    stse_frame_element_allocate_push(&CmdFrame, ePayload, payload_size, pPayload);

    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eWrapped, wrapped_payload_size, pWrapped_Payload);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(pSTSE,
                                  &CmdFrame,
                                  &RspFrame);
}

stse_ReturnCode_t stsafea_unwrap_payload(stse_Handler_t *pSTSE,
                                         PLAT_UI8 wrap_key_slot,
                                         PLAT_UI8 *pWrapped_Payload,
                                         PLAT_UI16 wrapped_payload_size,
                                         PLAT_UI8 *pPayload,
                                         PLAT_UI16 payload_size) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_UNWRAP_LOCAL_ENVELOPE;

    /* - Check stsafe handler initialization */
    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((pPayload == NULL) || (pWrapped_Payload == NULL) || (wrapped_payload_size > 488) || (wrapped_payload_size < 8) || (wrapped_payload_size != (payload_size + 8))) {
        return (STSE_SERVICE_INVALID_PARAMETER);
    }

    PLAT_UI8 rsp_header;

    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSlot_number, 1, &wrap_key_slot);
    stse_frame_element_allocate_push(&CmdFrame, ePayload, wrapped_payload_size, pWrapped_Payload);

    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eWrapped, payload_size, pPayload);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(pSTSE,
                                  &CmdFrame,
                                  &RspFrame);
}

stse_ReturnCode_t stsafea_wrap_payload_start(
    stsafea_wrap_payload_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pPayload == NULL) || (pWrapped_Payload == NULL) || (payload_size > 480) || (payload_size == 0) || (wrapped_payload_size != (payload_size + 8))) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_WRAP_LOCAL_ENVELOPE;
    pCtx->wrap_key_slot = wrap_key_slot;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eSlot_number_elem = (stse_frame_element_t){1, &pCtx->wrap_key_slot, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSlot_number_elem);
    pCtx->ePayload_elem = (stse_frame_element_t){payload_size, pPayload, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->ePayload_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eWrapped_elem = (stse_frame_element_t){wrapped_payload_size, pWrapped_Payload, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eWrapped_elem);

    return stsafea_frame_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_wrap_payload_transfer(stsafea_wrap_payload_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_wrap_payload_finalize(stsafea_wrap_payload_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_finalize(&pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_unwrap_payload_start(
    stsafea_unwrap_payload_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pPayload == NULL) || (pWrapped_Payload == NULL) || (wrapped_payload_size > 488) || (wrapped_payload_size < 8) || (wrapped_payload_size != (payload_size + 8))) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_UNWRAP_LOCAL_ENVELOPE;
    pCtx->wrap_key_slot = wrap_key_slot;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eSlot_number_elem = (stse_frame_element_t){1, &pCtx->wrap_key_slot, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSlot_number_elem);
    pCtx->ePayload_elem = (stse_frame_element_t){wrapped_payload_size, pWrapped_Payload, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->ePayload_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eWrapped_elem = (stse_frame_element_t){payload_size, pPayload, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eWrapped_elem);

    return stsafea_frame_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_unwrap_payload_transfer(stsafea_unwrap_payload_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_unwrap_payload_finalize(stsafea_unwrap_payload_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_finalize(&pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
