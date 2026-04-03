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

static PLAT_UI8 s_echo_cmd_header;
static PLAT_UI8 s_echo_rsp_header;
static stse_frame_t s_echo_CmdFrame;
static stse_frame_t s_echo_RspFrame;
static stse_frame_element_t s_echo_eCmd_header;
static stse_frame_element_t s_echo_eMessage;
static stse_frame_element_t s_echo_eRsp_header;
static stse_frame_element_t s_echo_eEchoed_message;

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
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pMessage,
    PLAT_UI8 *pEchoed_message,
    PLAT_UI16 message_length) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (pMessage == NULL || pEchoed_message == NULL || message_length == 0) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_echo_cmd_header = STSAFEA_CMD_ECHO;

    s_echo_CmdFrame = (stse_frame_t){0};
    s_echo_eCmd_header = (stse_frame_element_t){1, &s_echo_cmd_header, NULL};
    stse_frame_push_element(&s_echo_CmdFrame, &s_echo_eCmd_header);
    s_echo_eMessage = (stse_frame_element_t){message_length, pMessage, NULL};
    stse_frame_push_element(&s_echo_CmdFrame, &s_echo_eMessage);

    s_echo_RspFrame = (stse_frame_t){0};
    s_echo_eRsp_header = (stse_frame_element_t){1, &s_echo_rsp_header, NULL};
    stse_frame_push_element(&s_echo_RspFrame, &s_echo_eRsp_header);
    s_echo_eEchoed_message = (stse_frame_element_t){message_length, pEchoed_message, NULL};
    stse_frame_push_element(&s_echo_RspFrame, &s_echo_eEchoed_message);

    return stsafea_frame_transfer_start(pSTSE, &s_echo_CmdFrame, &s_echo_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_echo_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_echo_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_echo_CmdFrame, &s_echo_RspFrame, &stsafea_nb_ctx);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
