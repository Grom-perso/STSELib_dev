/*!
 ******************************************************************************
 * \file	stsafea_reset.c
 * \brief   Reset services for STSAFE
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

#include "services/stsafea/stsafea_reset.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

static PLAT_UI8 s_reset_cmd_header;
static PLAT_UI8 s_reset_rsp_header;
static stse_frame_t s_reset_CmdFrame;
static stse_frame_t s_reset_RspFrame;
static stse_frame_element_t s_reset_eCmd_header;
static stse_frame_element_t s_reset_eRsp_header;

stse_ReturnCode_t stsafea_reset(stse_Handler_t *pSTSE) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_RESET;
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, &cmd_header);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);

    /*- Perform Transfer*/
    return stsafea_frame_raw_transfer(pSTSE,
                                      &CmdFrame,
                                      &RspFrame,
                                      stsafea_cmd_timings[pSTSE->device_type][cmd_header]);
}

stse_ReturnCode_t stsafea_reset_start(stse_Handler_t *pSTSE) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    s_reset_cmd_header = STSAFEA_CMD_RESET;

    s_reset_CmdFrame = (stse_frame_t){0};
    s_reset_eCmd_header = (stse_frame_element_t){1, &s_reset_cmd_header, NULL};
    stse_frame_push_element(&s_reset_CmdFrame, &s_reset_eCmd_header);

    s_reset_RspFrame = (stse_frame_t){0};
    s_reset_eRsp_header = (stse_frame_element_t){1, &s_reset_rsp_header, NULL};
    stse_frame_push_element(&s_reset_RspFrame, &s_reset_eRsp_header);

    return stsafea_frame_raw_transfer_start(pSTSE, &s_reset_CmdFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_reset_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_reset_finalize(void) {
    return stsafea_frame_raw_transfer_finalize(&stsafea_nb_ctx, &s_reset_RspFrame);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
