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

static PLAT_UI8 s_verify_password_cmd_header;
static PLAT_UI8 s_verify_password_rsp_header;
static stse_frame_t s_verify_password_CmdFrame;
static stse_frame_t s_verify_password_RspFrame;
static stse_frame_element_t s_verify_password_eCmd_header;
static stse_frame_element_t s_verify_password_ePassword;
static stse_frame_element_t s_verify_password_eRsp_header;
static stse_frame_element_t s_verify_password_eVerStat;
static stse_frame_element_t s_verify_password_eRemTri;

static PLAT_UI8 s_delete_password_cmd_header;
static PLAT_UI8 s_delete_password_tag;
static PLAT_UI8 s_delete_password_rsp_header;
static stse_frame_t s_delete_password_CmdFrame;
static stse_frame_t s_delete_password_RspFrame;
static stse_frame_element_t s_delete_password_eCmd_header;
static stse_frame_element_t s_delete_password_eTag;
static stse_frame_element_t s_delete_password_eRsp_header;

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
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pPassword_buffer,
    PLAT_UI8 password_length,
    PLAT_UI8 *pVerification_status,
    PLAT_UI8 *pRemaining_tries) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (password_length != STSAFEA_PASSWORD_LENGTH) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_verify_password_cmd_header = STSAFEA_CMD_VERIFY_PASSWORD;

    s_verify_password_CmdFrame = (stse_frame_t){0};
    s_verify_password_eCmd_header = (stse_frame_element_t){1, &s_verify_password_cmd_header, NULL};
    stse_frame_push_element(&s_verify_password_CmdFrame, &s_verify_password_eCmd_header);
    s_verify_password_ePassword = (stse_frame_element_t){password_length, pPassword_buffer, NULL};
    stse_frame_push_element(&s_verify_password_CmdFrame, &s_verify_password_ePassword);

    s_verify_password_RspFrame = (stse_frame_t){0};
    s_verify_password_eRsp_header = (stse_frame_element_t){1, &s_verify_password_rsp_header, NULL};
    stse_frame_push_element(&s_verify_password_RspFrame, &s_verify_password_eRsp_header);
    s_verify_password_eVerStat = (stse_frame_element_t){1, pVerification_status, NULL};
    stse_frame_push_element(&s_verify_password_RspFrame, &s_verify_password_eVerStat);
    s_verify_password_eRemTri = (stse_frame_element_t){1, pRemaining_tries, NULL};
    stse_frame_push_element(&s_verify_password_RspFrame, &s_verify_password_eRemTri);

    return stsafea_frame_transfer_start(pSTSE, &s_verify_password_CmdFrame, &s_verify_password_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_verify_password_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_verify_password_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_verify_password_CmdFrame, &s_verify_password_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_delete_password_start(stse_Handler_t *pSTSE) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    s_delete_password_cmd_header = STSAFEA_CMD_DELETE;
    s_delete_password_tag = STSAFEA_DELETE_TAG_PASSWORD;

    s_delete_password_CmdFrame = (stse_frame_t){0};
    s_delete_password_eCmd_header = (stse_frame_element_t){1, &s_delete_password_cmd_header, NULL};
    stse_frame_push_element(&s_delete_password_CmdFrame, &s_delete_password_eCmd_header);
    s_delete_password_eTag = (stse_frame_element_t){1, &s_delete_password_tag, NULL};
    stse_frame_push_element(&s_delete_password_CmdFrame, &s_delete_password_eTag);

    s_delete_password_RspFrame = (stse_frame_t){0};
    s_delete_password_eRsp_header = (stse_frame_element_t){1, &s_delete_password_rsp_header, NULL};
    stse_frame_push_element(&s_delete_password_RspFrame, &s_delete_password_eRsp_header);

    return stsafea_frame_raw_transfer_start(pSTSE, &s_delete_password_CmdFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_delete_password_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_delete_password_finalize(void) {
    return stsafea_frame_raw_transfer_finalize(&stsafea_nb_ctx, &s_delete_password_RspFrame);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
