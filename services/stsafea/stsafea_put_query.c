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
    stsafea_put_life_cyle_state_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    stsafea_life_cycle_state_t life_cycle_state) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_PUT_ATTRIBUTE;
    pCtx->tag = STSAFEA_SUBJECT_TAG_LIFE_CYCLE_STATE;
    pCtx->life_cycle_state = life_cycle_state;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eTag_elem = (stse_frame_element_t){1, &pCtx->tag, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eTag_elem);
    pCtx->eLifeCycleState_elem = (stse_frame_element_t){1, (PLAT_UI8 *)&pCtx->life_cycle_state, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eLifeCycleState_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);

    return stsafea_frame_raw_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_put_life_cyle_state_transfer(stsafea_put_life_cyle_state_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_put_life_cyle_state_finalize(stsafea_put_life_cyle_state_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_raw_transfer_finalize(&pCtx->nb_ctx, &pCtx->RspFrame);
}

stse_ReturnCode_t stsafea_query_life_cycle_state_start(
    stsafea_query_life_cycle_state_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    stsafea_life_cycle_state_t *pLife_cycle_state) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_QUERY;
    pCtx->tag = STSAFEA_SUBJECT_TAG_LIFE_CYCLE_STATE;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eTag_elem = (stse_frame_element_t){1, &pCtx->tag, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eTag_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eLife_cycle_state_elem = (stse_frame_element_t){1, (PLAT_UI8 *)pLife_cycle_state, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eLife_cycle_state_elem);

    return stsafea_frame_raw_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_query_life_cycle_state_transfer(stsafea_query_life_cycle_state_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_query_life_cycle_state_finalize(stsafea_query_life_cycle_state_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_raw_transfer_finalize(&pCtx->nb_ctx, &pCtx->RspFrame);
}

stse_ReturnCode_t stsafea_put_i2c_parameters_start(
    stsafea_put_i2c_parameters_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    stsafea_i2c_parameters_t *pI2c_parameters) {
    if (pCtx == NULL || pSTSE == NULL) {
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

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_PUT_ATTRIBUTE;
    pCtx->tag = STSAFEA_SUBJECT_TAG_I2C_PARAMETERS;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eTag_elem = (stse_frame_element_t){1, &pCtx->tag, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eTag_elem);
    pCtx->eI2cParameters_elem = (stse_frame_element_t){sizeof(stsafea_i2c_parameters_t), (PLAT_UI8 *)pI2c_parameters, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eI2cParameters_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);

    return stsafea_frame_raw_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_put_i2c_parameters_transfer(stsafea_put_i2c_parameters_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_put_i2c_parameters_finalize(stsafea_put_i2c_parameters_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_raw_transfer_finalize(&pCtx->nb_ctx, &pCtx->RspFrame);
}

stse_ReturnCode_t stsafea_query_i2c_parameters_start(
    stsafea_query_i2c_parameters_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    stsafea_i2c_parameters_t *pI2c_parameters) {
    if (pCtx == NULL || pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    pCtx->pSTSE = pSTSE;
    pCtx->cmd_header = STSAFEA_CMD_QUERY;
    pCtx->tag = STSAFEA_SUBJECT_TAG_I2C_PARAMETERS;

    pCtx->CmdFrame = (stse_frame_t){0};
    pCtx->eCmd_header_elem = (stse_frame_element_t){1, &pCtx->cmd_header, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eCmd_header_elem);
    pCtx->eTag_elem = (stse_frame_element_t){1, &pCtx->tag, NULL};
    stse_frame_push_element(&pCtx->CmdFrame, &pCtx->eTag_elem);

    pCtx->RspFrame = (stse_frame_t){0};
    pCtx->eRsp_header_elem = (stse_frame_element_t){1, &pCtx->rsp_header, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eRsp_header_elem);
    pCtx->eI2cParameters_elem = (stse_frame_element_t){sizeof(stsafea_i2c_parameters_t), (PLAT_UI8 *)pI2c_parameters, NULL};
    stse_frame_push_element(&pCtx->RspFrame, &pCtx->eI2cParameters_elem);

    return stsafea_frame_raw_transfer_start(pSTSE, &pCtx->CmdFrame, &pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_query_i2c_parameters_transfer(stsafea_query_i2c_parameters_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_transfer_check(&pCtx->nb_ctx);
}

stse_ReturnCode_t stsafea_query_i2c_parameters_finalize(stsafea_query_i2c_parameters_ctx_t *pCtx) {
    if (pCtx == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    return stsafea_frame_raw_transfer_finalize(&pCtx->nb_ctx, &pCtx->RspFrame);
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
