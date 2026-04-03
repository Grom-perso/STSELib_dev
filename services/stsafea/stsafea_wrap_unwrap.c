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

static PLAT_UI8 s_wrap_payload_cmd_header;
static PLAT_UI8 s_wrap_payload_wrap_key_slot;
static PLAT_UI8 s_wrap_payload_rsp_header;
static stse_frame_t s_wrap_payload_CmdFrame;
static stse_frame_t s_wrap_payload_RspFrame;
static stse_frame_element_t s_wrap_payload_eCmd_header;
static stse_frame_element_t s_wrap_payload_eSlot_number;
static stse_frame_element_t s_wrap_payload_ePayload;
static stse_frame_element_t s_wrap_payload_eRsp_header;
static stse_frame_element_t s_wrap_payload_eWrapped;

static PLAT_UI8 s_unwrap_payload_cmd_header;
static PLAT_UI8 s_unwrap_payload_wrap_key_slot;
static PLAT_UI8 s_unwrap_payload_rsp_header;
static stse_frame_t s_unwrap_payload_CmdFrame;
static stse_frame_t s_unwrap_payload_RspFrame;
static stse_frame_element_t s_unwrap_payload_eCmd_header;
static stse_frame_element_t s_unwrap_payload_eSlot_number;
static stse_frame_element_t s_unwrap_payload_ePayload;
static stse_frame_element_t s_unwrap_payload_eRsp_header;
static stse_frame_element_t s_unwrap_payload_eWrapped;

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
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pPayload == NULL) || (pWrapped_Payload == NULL) || (payload_size > 480) || (payload_size == 0) || (wrapped_payload_size != (payload_size + 8))) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_wrap_payload_cmd_header = STSAFEA_CMD_WRAP_LOCAL_ENVELOPE;
    s_wrap_payload_wrap_key_slot = wrap_key_slot;

    s_wrap_payload_CmdFrame = (stse_frame_t){0};
    s_wrap_payload_eCmd_header = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &s_wrap_payload_cmd_header, NULL};
    stse_frame_push_element(&s_wrap_payload_CmdFrame, &s_wrap_payload_eCmd_header);
    s_wrap_payload_eSlot_number = (stse_frame_element_t){1, &s_wrap_payload_wrap_key_slot, NULL};
    stse_frame_push_element(&s_wrap_payload_CmdFrame, &s_wrap_payload_eSlot_number);
    s_wrap_payload_ePayload = (stse_frame_element_t){payload_size, pPayload, NULL};
    stse_frame_push_element(&s_wrap_payload_CmdFrame, &s_wrap_payload_ePayload);

    s_wrap_payload_RspFrame = (stse_frame_t){0};
    s_wrap_payload_eRsp_header = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &s_wrap_payload_rsp_header, NULL};
    stse_frame_push_element(&s_wrap_payload_RspFrame, &s_wrap_payload_eRsp_header);
    s_wrap_payload_eWrapped = (stse_frame_element_t){wrapped_payload_size, pWrapped_Payload, NULL};
    stse_frame_push_element(&s_wrap_payload_RspFrame, &s_wrap_payload_eWrapped);

    return stsafea_frame_transfer_start(pSTSE, &s_wrap_payload_CmdFrame, &s_wrap_payload_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_wrap_payload_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_wrap_payload_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_wrap_payload_CmdFrame, &s_wrap_payload_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_unwrap_payload_start(
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pPayload == NULL) || (pWrapped_Payload == NULL) || (wrapped_payload_size > 488) || (wrapped_payload_size < 8) || (wrapped_payload_size != (payload_size + 8))) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_unwrap_payload_cmd_header = STSAFEA_CMD_UNWRAP_LOCAL_ENVELOPE;
    s_unwrap_payload_wrap_key_slot = wrap_key_slot;

    s_unwrap_payload_CmdFrame = (stse_frame_t){0};
    s_unwrap_payload_eCmd_header = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &s_unwrap_payload_cmd_header, NULL};
    stse_frame_push_element(&s_unwrap_payload_CmdFrame, &s_unwrap_payload_eCmd_header);
    s_unwrap_payload_eSlot_number = (stse_frame_element_t){1, &s_unwrap_payload_wrap_key_slot, NULL};
    stse_frame_push_element(&s_unwrap_payload_CmdFrame, &s_unwrap_payload_eSlot_number);
    s_unwrap_payload_ePayload = (stse_frame_element_t){wrapped_payload_size, pWrapped_Payload, NULL};
    stse_frame_push_element(&s_unwrap_payload_CmdFrame, &s_unwrap_payload_ePayload);

    s_unwrap_payload_RspFrame = (stse_frame_t){0};
    s_unwrap_payload_eRsp_header = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &s_unwrap_payload_rsp_header, NULL};
    stse_frame_push_element(&s_unwrap_payload_RspFrame, &s_unwrap_payload_eRsp_header);
    s_unwrap_payload_eWrapped = (stse_frame_element_t){payload_size, pPayload, NULL};
    stse_frame_push_element(&s_unwrap_payload_RspFrame, &s_unwrap_payload_eWrapped);

    return stsafea_frame_transfer_start(pSTSE, &s_unwrap_payload_CmdFrame, &s_unwrap_payload_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_unwrap_payload_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_unwrap_payload_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_unwrap_payload_CmdFrame, &s_unwrap_payload_RspFrame, &stsafea_nb_ctx);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
