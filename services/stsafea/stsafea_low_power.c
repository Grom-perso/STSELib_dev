/*!
 ******************************************************************************
 * \file	stsafea_low_power.c
 * \brief   low-power modes services for STSAFE-A
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

#include "services/stsafea/stsafea_low_power.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_ReturnCode_t stsafea_hibernate(stse_Handler_t *pSTSE,
                                    stse_hibernate_wake_up_mode_t wake_up_mode)

{
    (void)wake_up_mode;
    PLAT_UI8 cmd_header = STSAFEA_CMD_HIBERNATE;
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

stse_ReturnCode_t stsafea_hibernate_start(
    stsafea_hibernate_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    stse_hibernate_wake_up_mode_t wake_up_mode) {
    (void)wake_up_mode;

    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_HIBERNATE;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);

    return stsafea_frame_raw_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_hibernate_transfer(stsafea_hibernate_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_hibernate_finalize(stsafea_hibernate_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_raw_transfer_finalize(&pCtx->nb_ctx, &pCtx->RspFrame);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
