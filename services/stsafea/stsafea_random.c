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

static PLAT_UI8 s_random_cmd_header;
static PLAT_UI8 s_random_subject;
static PLAT_UI8 s_random_size;
static PLAT_UI8 s_random_rsp_header;
static stse_frame_t s_random_CmdFrame;
static stse_frame_t s_random_RspFrame;
static stse_frame_element_t s_random_eCmd_header;
static stse_frame_element_t s_random_eSubject;
static stse_frame_element_t s_random_eSize;
static stse_frame_element_t s_random_eRsp_header;
static stse_frame_element_t s_random_eRandom;

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
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pRandom,
    PLAT_UI8 random_size) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (pRandom == NULL || random_size == 0) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_random_cmd_header = STSAFEA_CMD_GENERATE_RANDOM;
    s_random_subject = 0x00;
    s_random_size = random_size;

    s_random_CmdFrame = (stse_frame_t){0};
    s_random_eCmd_header = (stse_frame_element_t){1, &s_random_cmd_header, NULL};
    stse_frame_push_element(&s_random_CmdFrame, &s_random_eCmd_header);
    s_random_eSubject = (stse_frame_element_t){1, &s_random_subject, NULL};
    stse_frame_push_element(&s_random_CmdFrame, &s_random_eSubject);
    s_random_eSize = (stse_frame_element_t){1, &s_random_size, NULL};
    stse_frame_push_element(&s_random_CmdFrame, &s_random_eSize);

    s_random_RspFrame = (stse_frame_t){0};
    s_random_eRsp_header = (stse_frame_element_t){1, &s_random_rsp_header, NULL};
    stse_frame_push_element(&s_random_RspFrame, &s_random_eRsp_header);
    s_random_eRandom = (stse_frame_element_t){random_size, pRandom, NULL};
    stse_frame_push_element(&s_random_RspFrame, &s_random_eRandom);

    return stsafea_frame_transfer_start(pSTSE, &s_random_CmdFrame, &s_random_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_generate_random_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_generate_random_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_random_CmdFrame, &s_random_RspFrame, &stsafea_nb_ctx);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
