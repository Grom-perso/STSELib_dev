/*!
 ******************************************************************************
 * \file	stsafea_put_query.c
 * \brief   Put and query services for STSAFE-A
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

#include "services/stsafea/stsafea_put_query.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

static PLAT_UI8 s_put_lcs_cmd_header;
static PLAT_UI8 s_put_lcs_tag;
static stsafea_life_cycle_state_t s_put_lcs_life_cycle_state;
static PLAT_UI8 s_put_lcs_rsp_header;
static stse_frame_t s_put_lcs_CmdFrame;
static stse_frame_t s_put_lcs_RspFrame;
static stse_frame_element_t s_put_lcs_eCmd_header;
static stse_frame_element_t s_put_lcs_eTag;
static stse_frame_element_t s_put_lcs_eLifeCycleState;
static stse_frame_element_t s_put_lcs_eRsp_header;

static PLAT_UI8 s_query_lcs_cmd_header;
static PLAT_UI8 s_query_lcs_tag;
static PLAT_UI8 s_query_lcs_rsp_header;
static stse_frame_t s_query_lcs_CmdFrame;
static stse_frame_t s_query_lcs_RspFrame;
static stse_frame_element_t s_query_lcs_eCmd_header;
static stse_frame_element_t s_query_lcs_eTag;
static stse_frame_element_t s_query_lcs_eRsp_header;
static stse_frame_element_t s_query_lcs_eLife_cycle_state;

static PLAT_UI8 s_put_i2c_cmd_header;
static PLAT_UI8 s_put_i2c_tag;
static PLAT_UI8 s_put_i2c_rsp_header;
static stse_frame_t s_put_i2c_CmdFrame;
static stse_frame_t s_put_i2c_RspFrame;
static stse_frame_element_t s_put_i2c_eCmd_header;
static stse_frame_element_t s_put_i2c_eTag;
static stse_frame_element_t s_put_i2c_eI2cParameters;
static stse_frame_element_t s_put_i2c_eRsp_header;

static PLAT_UI8 s_query_i2c_cmd_header;
static PLAT_UI8 s_query_i2c_tag;
static PLAT_UI8 s_query_i2c_rsp_header;
static stse_frame_t s_query_i2c_CmdFrame;
static stse_frame_t s_query_i2c_RspFrame;
static stse_frame_element_t s_query_i2c_eCmd_header;
static stse_frame_element_t s_query_i2c_eTag;
static stse_frame_element_t s_query_i2c_eRsp_header;
static stse_frame_element_t s_query_i2c_eI2cParameters;

stse_ReturnCode_t stsafea_put_life_cyle_state(
    stse_Handler_t *pSTSE,
    stsafea_life_cycle_state_t life_cycle_state) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_PUT_ATTRIBUTE;
    PLAT_UI8 tag = STSAFEA_SUBJECT_TAG_LIFE_CYCLE_STATE;
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eTag, 1, &tag);
    stse_frame_element_allocate_push(&CmdFrame, eLifeCycleState, 1, (PLAT_UI8 *)&life_cycle_state);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);

    /*- Perform Transfer*/
    return stsafea_frame_raw_transfer(pSTSE,
                                      &CmdFrame,
                                      &RspFrame,
                                      stsafea_cmd_timings[pSTSE->device_type][cmd_header]);
}

stse_ReturnCode_t stsafea_query_life_cycle_state(
    stse_Handler_t *pSTSE,
    stsafea_life_cycle_state_t *pLife_cycle_state) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_QUERY;
    PLAT_UI8 tag = STSAFEA_SUBJECT_TAG_LIFE_CYCLE_STATE;
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
    stse_frame_element_allocate_push(&RspFrame, eLife_cycle_state, 1, (PLAT_UI8 *)pLife_cycle_state);

    /*- Perform Transfer*/
    return stsafea_frame_raw_transfer(pSTSE,
                                      &CmdFrame,
                                      &RspFrame,
                                      stsafea_cmd_timings[pSTSE->device_type][cmd_header]);
}

stse_ReturnCode_t stsafea_put_i2c_parameters(
    stse_Handler_t *pSTSE,
    stsafea_i2c_parameters_t *pI2c_parameters) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_PUT_ATTRIBUTE;
    PLAT_UI8 tag = STSAFEA_SUBJECT_TAG_I2C_PARAMETERS;
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (pSTSE->device_type == STSAFE_L010) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }
#endif

    if (pSTSE->device_type == STSAFE_A100 ||
        pSTSE->device_type == STSAFE_A110 ||
        pSTSE->device_type == STSAFE_A200) {
        pI2c_parameters->idle_bus_time_to_standby = 0;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, 1, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eTag, 1, &tag);
    stse_frame_element_allocate_push(&CmdFrame, eI2cParameters, sizeof(stsafea_i2c_parameters_t), (PLAT_UI8 *)pI2c_parameters);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);

    /*- Perform Transfer*/
    return stsafea_frame_raw_transfer(pSTSE,
                                      &CmdFrame,
                                      &RspFrame,
                                      stsafea_cmd_timings[pSTSE->device_type][cmd_header]);
}

stse_ReturnCode_t stsafea_query_i2c_parameters(
    stse_Handler_t *pSTSE,
    stsafea_i2c_parameters_t *pI2c_parameters) {
    PLAT_UI8 cmd_header = STSAFEA_CMD_QUERY;
    PLAT_UI8 tag = STSAFEA_SUBJECT_TAG_I2C_PARAMETERS;
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
    stse_frame_element_allocate_push(&RspFrame, eLife_cycle_state, sizeof(stsafea_i2c_parameters_t), (PLAT_UI8 *)pI2c_parameters);

    /*- Perform Transfer*/
    return stsafea_frame_raw_transfer(pSTSE,
                                      &CmdFrame,
                                      &RspFrame,
                                      stsafea_cmd_timings[pSTSE->device_type][cmd_header]);
}

stse_ReturnCode_t stsafea_put_life_cyle_state_start(
    stse_Handler_t *pSTSE,
    stsafea_life_cycle_state_t life_cycle_state) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    s_put_lcs_cmd_header = STSAFEA_CMD_PUT_ATTRIBUTE;
    s_put_lcs_tag = STSAFEA_SUBJECT_TAG_LIFE_CYCLE_STATE;
    s_put_lcs_life_cycle_state = life_cycle_state;

    s_put_lcs_CmdFrame = (stse_frame_t){0};
    s_put_lcs_eCmd_header = (stse_frame_element_t){1, &s_put_lcs_cmd_header, NULL};
    stse_frame_push_element(&s_put_lcs_CmdFrame, &s_put_lcs_eCmd_header);
    s_put_lcs_eTag = (stse_frame_element_t){1, &s_put_lcs_tag, NULL};
    stse_frame_push_element(&s_put_lcs_CmdFrame, &s_put_lcs_eTag);
    s_put_lcs_eLifeCycleState = (stse_frame_element_t){1, (PLAT_UI8 *)&s_put_lcs_life_cycle_state, NULL};
    stse_frame_push_element(&s_put_lcs_CmdFrame, &s_put_lcs_eLifeCycleState);

    s_put_lcs_RspFrame = (stse_frame_t){0};
    s_put_lcs_eRsp_header = (stse_frame_element_t){1, &s_put_lcs_rsp_header, NULL};
    stse_frame_push_element(&s_put_lcs_RspFrame, &s_put_lcs_eRsp_header);

    return stsafea_frame_raw_transfer_start(pSTSE, &s_put_lcs_CmdFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_put_life_cyle_state_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_put_life_cyle_state_finalize(void) {
    return stsafea_frame_raw_transfer_finalize(&stsafea_nb_ctx, &s_put_lcs_RspFrame);
}

stse_ReturnCode_t stsafea_query_life_cycle_state_start(
    stse_Handler_t *pSTSE,
    stsafea_life_cycle_state_t *pLife_cycle_state) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    s_query_lcs_cmd_header = STSAFEA_CMD_QUERY;
    s_query_lcs_tag = STSAFEA_SUBJECT_TAG_LIFE_CYCLE_STATE;

    s_query_lcs_CmdFrame = (stse_frame_t){0};
    s_query_lcs_eCmd_header = (stse_frame_element_t){1, &s_query_lcs_cmd_header, NULL};
    stse_frame_push_element(&s_query_lcs_CmdFrame, &s_query_lcs_eCmd_header);
    s_query_lcs_eTag = (stse_frame_element_t){1, &s_query_lcs_tag, NULL};
    stse_frame_push_element(&s_query_lcs_CmdFrame, &s_query_lcs_eTag);

    s_query_lcs_RspFrame = (stse_frame_t){0};
    s_query_lcs_eRsp_header = (stse_frame_element_t){1, &s_query_lcs_rsp_header, NULL};
    stse_frame_push_element(&s_query_lcs_RspFrame, &s_query_lcs_eRsp_header);
    s_query_lcs_eLife_cycle_state = (stse_frame_element_t){1, (PLAT_UI8 *)pLife_cycle_state, NULL};
    stse_frame_push_element(&s_query_lcs_RspFrame, &s_query_lcs_eLife_cycle_state);

    return stsafea_frame_raw_transfer_start(pSTSE, &s_query_lcs_CmdFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_query_life_cycle_state_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_query_life_cycle_state_finalize(void) {
    return stsafea_frame_raw_transfer_finalize(&stsafea_nb_ctx, &s_query_lcs_RspFrame);
}

stse_ReturnCode_t stsafea_put_i2c_parameters_start(
    stse_Handler_t *pSTSE,
    stsafea_i2c_parameters_t *pI2c_parameters) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (pSTSE->device_type == STSAFE_L010) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }
#endif

    if (pSTSE->device_type == STSAFE_A100 ||
        pSTSE->device_type == STSAFE_A110 ||
        pSTSE->device_type == STSAFE_A200) {
        pI2c_parameters->idle_bus_time_to_standby = 0;
    }

    s_put_i2c_cmd_header = STSAFEA_CMD_PUT_ATTRIBUTE;
    s_put_i2c_tag = STSAFEA_SUBJECT_TAG_I2C_PARAMETERS;

    s_put_i2c_CmdFrame = (stse_frame_t){0};
    s_put_i2c_eCmd_header = (stse_frame_element_t){1, &s_put_i2c_cmd_header, NULL};
    stse_frame_push_element(&s_put_i2c_CmdFrame, &s_put_i2c_eCmd_header);
    s_put_i2c_eTag = (stse_frame_element_t){1, &s_put_i2c_tag, NULL};
    stse_frame_push_element(&s_put_i2c_CmdFrame, &s_put_i2c_eTag);
    s_put_i2c_eI2cParameters = (stse_frame_element_t){sizeof(stsafea_i2c_parameters_t), (PLAT_UI8 *)pI2c_parameters, NULL};
    stse_frame_push_element(&s_put_i2c_CmdFrame, &s_put_i2c_eI2cParameters);

    s_put_i2c_RspFrame = (stse_frame_t){0};
    s_put_i2c_eRsp_header = (stse_frame_element_t){1, &s_put_i2c_rsp_header, NULL};
    stse_frame_push_element(&s_put_i2c_RspFrame, &s_put_i2c_eRsp_header);

    return stsafea_frame_raw_transfer_start(pSTSE, &s_put_i2c_CmdFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_put_i2c_parameters_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_put_i2c_parameters_finalize(void) {
    return stsafea_frame_raw_transfer_finalize(&stsafea_nb_ctx, &s_put_i2c_RspFrame);
}

stse_ReturnCode_t stsafea_query_i2c_parameters_start(
    stse_Handler_t *pSTSE,
    stsafea_i2c_parameters_t *pI2c_parameters) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    s_query_i2c_cmd_header = STSAFEA_CMD_QUERY;
    s_query_i2c_tag = STSAFEA_SUBJECT_TAG_I2C_PARAMETERS;

    s_query_i2c_CmdFrame = (stse_frame_t){0};
    s_query_i2c_eCmd_header = (stse_frame_element_t){1, &s_query_i2c_cmd_header, NULL};
    stse_frame_push_element(&s_query_i2c_CmdFrame, &s_query_i2c_eCmd_header);
    s_query_i2c_eTag = (stse_frame_element_t){1, &s_query_i2c_tag, NULL};
    stse_frame_push_element(&s_query_i2c_CmdFrame, &s_query_i2c_eTag);

    s_query_i2c_RspFrame = (stse_frame_t){0};
    s_query_i2c_eRsp_header = (stse_frame_element_t){1, &s_query_i2c_rsp_header, NULL};
    stse_frame_push_element(&s_query_i2c_RspFrame, &s_query_i2c_eRsp_header);
    s_query_i2c_eI2cParameters = (stse_frame_element_t){sizeof(stsafea_i2c_parameters_t), (PLAT_UI8 *)pI2c_parameters, NULL};
    stse_frame_push_element(&s_query_i2c_RspFrame, &s_query_i2c_eI2cParameters);

    return stsafea_frame_raw_transfer_start(pSTSE, &s_query_i2c_CmdFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_query_i2c_parameters_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_query_i2c_parameters_finalize(void) {
    return stsafea_frame_raw_transfer_finalize(&stsafea_nb_ctx, &s_query_i2c_RspFrame);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
