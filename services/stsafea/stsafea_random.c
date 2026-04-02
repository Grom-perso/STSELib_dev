/*!
 ******************************************************************************
 * \file	stsafea_random.c
 * \brief   Random services for STSAFE
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

#include "services/stsafea/stsafea_random.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_ReturnCode_t stsafea_generate_random(
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pRandom,
    PLAT_UI8 random_size) {
    stse_ReturnCode_t ret;
    PLAT_UI8 cmd_header = STSAFEA_CMD_GENERATE_RANDOM;
    PLAT_UI8 subject = 0x00;
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if ((pRandom == NULL) || (random_size == 0)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eSubject, 1, &subject);
    stse_frame_element_allocate_push(&CmdFrame, eSize, 1, &random_size);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eRandom, random_size, pRandom);

    /*- Perform Transfer*/
    ret = stsafea_frame_transfer(pSTSE,
                                 &CmdFrame,
                                 &RspFrame);

    return (ret);
}

stse_ReturnCode_t stsafea_generate_random_start(
    stsafea_generate_random_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pRandom,
    PLAT_UI8 random_size) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (pRandom == NULL || random_size == 0) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_GENERATE_RANDOM;
    pCtx->subject = 0x00;
    pCtx->random_size = random_size;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eSubject_elem = (stse_frame_element_t){1, &pCtx->subject, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSubject_elem);
    pCtx->eSize_elem = (stse_frame_element_t){1, &pCtx->random_size, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eSize_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eRandom_elem = (stse_frame_element_t){random_size, pRandom, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRandom_elem);

    return stsafea_frame_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_generate_random_transfer(stsafea_generate_random_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_generate_random_finalize(stsafea_generate_random_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_finalize(pCtx->pSTSE, &pCtx->CmdFrame, &pCtx->RspFrame, &pCtx->nb_ctx);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
