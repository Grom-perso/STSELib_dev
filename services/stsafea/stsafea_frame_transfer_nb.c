/*!
 ******************************************************************************
 * \file    stsafea_frame_transfer_nb.c
 * \brief   STSAFE-A non-blocking frame transfer layer (source)
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

#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

/* -------------------------------------------------------------------------
 * Raw transfer (no session) – non-blocking split
 * -------------------------------------------------------------------------*/

stse_ReturnCode_t stsafea_frame_raw_transfer_start(stse_Handler_t *pSTSE,
                                                   stse_frame_t *pCmdFrame,
                                                   PLAT_UI16 inter_frame_delay,
                                                   stsafea_nb_transfer_ctx_t *pNbCtx)
{
    stse_ReturnCode_t ret;

    if (pSTSE == NULL || pCmdFrame == NULL || pNbCtx == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /* Transmit the command frame (retry handled inside transmit, no sleep) */
    ret = stsafea_frame_transmit(pSTSE, pCmdFrame);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Record send timestamp and required inter-frame delay */
    pNbCtx->cmd_sent_timestamp_ms = stse_platform_get_timestamp_ms();
    pNbCtx->inter_frame_delay_ms  = inter_frame_delay;

    return STSE_OK;
}

stse_ReturnCode_t stsafea_frame_transfer_check(stsafea_nb_transfer_ctx_t *pNbCtx)
{
    PLAT_UI32 now;
    PLAT_UI32 elapsed;

    if (pNbCtx == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    now     = stse_platform_get_timestamp_ms();
    elapsed = now - pNbCtx->cmd_sent_timestamp_ms;

    if (elapsed < (PLAT_UI32)pNbCtx->inter_frame_delay_ms) {
        return STSE_PLATFORM_PENDING;
    }

    return STSE_OK;
}

stse_ReturnCode_t stsafea_frame_raw_transfer_finalize(stse_Handler_t *pSTSE,
                                                      stse_frame_t *pRspFrame)
{
    if (pSTSE == NULL || pRspFrame == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    return stsafea_frame_receive(pSTSE, pRspFrame);
}

/* -------------------------------------------------------------------------
 * Session-capable transfer – non-blocking split
 * -------------------------------------------------------------------------*/

stse_ReturnCode_t stsafea_frame_transfer_start(stse_Handler_t *pSTSE,
                                               stse_frame_t *pCmdFrame,
                                               stse_frame_t *pRspFrame,
                                               stsafea_nb_transfer_ctx_t *pNbCtx)
{
    stse_ReturnCode_t ret = STSE_SERVICE_INVALID_PARAMETER;
    PLAT_UI16 inter_frame_delay = STSAFEA_EXEC_TIME_DEFAULT;

    if (pSTSE == NULL || pCmdFrame == NULL || pRspFrame == NULL || pNbCtx == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /* Determine inter-frame delay and (optionally) session flags from frame header */
#ifdef STSE_CONF_USE_HOST_SESSION
    pNbCtx->cmd_encryption_flag = 0;
    pNbCtx->rsp_encryption_flag = 0;
    pNbCtx->cmd_ac_info         = STSE_CMD_AC_FREE;
#endif

    if (pCmdFrame->first_element != NULL && pCmdFrame->first_element->pData != NULL) {
        if (pCmdFrame->first_element->length == STSAFEA_EXT_HEADER_SIZE &&
            pCmdFrame->first_element->pData[0] == STSAFEA_EXTENDED_COMMAND_PREFIX) {
            inter_frame_delay = stsafea_extended_cmd_timings[pSTSE->device_type][pCmdFrame->first_element->pData[1]];
#ifdef STSE_CONF_USE_HOST_SESSION
            stsafea_perso_info_get_ext_cmd_AC(&pSTSE->perso_info, pCmdFrame->first_element->pData[1], &pNbCtx->cmd_ac_info);
            stsafea_perso_info_get_ext_cmd_encrypt_flag(&pSTSE->perso_info, pCmdFrame->first_element->pData[1], &pNbCtx->cmd_encryption_flag);
            stsafea_perso_info_get_ext_rsp_encrypt_flag(&pSTSE->perso_info, pCmdFrame->first_element->pData[1], &pNbCtx->rsp_encryption_flag);
#endif
            ret = STSE_OK;
        } else if (pCmdFrame->first_element->length == STSAFEA_HEADER_SIZE &&
                   pCmdFrame->first_element->pData[0] != STSAFEA_EXTENDED_COMMAND_PREFIX) {
            inter_frame_delay = stsafea_cmd_timings[pSTSE->device_type][pCmdFrame->first_element->pData[0]];
#ifdef STSE_CONF_USE_HOST_SESSION
            stsafea_perso_info_get_cmd_AC(&pSTSE->perso_info, pCmdFrame->first_element->pData[0], &pNbCtx->cmd_ac_info);
            stsafea_perso_info_get_cmd_encrypt_flag(&pSTSE->perso_info, pCmdFrame->first_element->pData[0], &pNbCtx->cmd_encryption_flag);
            stsafea_perso_info_get_rsp_encrypt_flag(&pSTSE->perso_info, pCmdFrame->first_element->pData[0], &pNbCtx->rsp_encryption_flag);
#endif
            ret = STSE_OK;
        }
    }

    if (ret != STSE_OK) {
        return ret;
    }

#ifdef STSE_CONF_USE_HOST_SESSION
    if (pNbCtx->cmd_encryption_flag || pNbCtx->rsp_encryption_flag) {
        /* ---- Encrypted session pre-processing ---- */
        stse_session_t *pSession = pSTSE->pActive_host_session;
        if (pSession == NULL) {
            return STSE_SERVICE_SESSION_ERROR;
        }

        /* --- Encrypt command payload (local VLA is acceptable in _start) --- */
        if (pNbCtx->cmd_encryption_flag) {
            PLAT_UI8 padding = 16U;
            PLAT_UI16 plaintext_payload_size = pCmdFrame->length - pCmdFrame->first_element->length;
            if ((plaintext_payload_size % 16U) != 0U) {
                padding = (PLAT_UI8)(16U - (plaintext_payload_size % 16U));
            }
            PLAT_UI16 encrypted_cmd_payload_size = plaintext_payload_size + padding;
            PLAT_UI8 encrypted_cmd_payload[encrypted_cmd_payload_size];
            stse_frame_element_t eEncCmd = {encrypted_cmd_payload_size, encrypted_cmd_payload, NULL};
            stse_frame_strap_allocate(S1_cmd);

            ret = stsafea_session_frame_encrypt(pSession, pCmdFrame, &eEncCmd);
            if (ret != STSE_OK) {
                return ret;
            }
            stse_frame_insert_strap(&S1_cmd, pCmdFrame->first_element, &eEncCmd);
            stse_frame_update(pCmdFrame);
        }

        /* --- Set up encrypted response payload strap (persistent in context) --- */
        if (pNbCtx->rsp_encryption_flag && pRspFrame->first_element->next != NULL) {
            PLAT_UI8 padding = 16U;
            PLAT_UI16 plaintext_rsp_payload_size = pRspFrame->length - pRspFrame->first_element->length;
            if ((plaintext_rsp_payload_size % 16U) != 0U) {
                padding = (PLAT_UI8)(16U - (plaintext_rsp_payload_size % 16U));
            }
            pNbCtx->encrypted_rsp_payload_size = plaintext_rsp_payload_size + padding;
            if (pNbCtx->encrypted_rsp_payload_size > STSAFEA_NB_MAX_ENCRYPTED_PAYLOAD_SIZE) {
                return STSE_SERVICE_FRAME_SIZE_ERROR;
            }
            pNbCtx->eEncrypted_rsp_payload.length = pNbCtx->encrypted_rsp_payload_size;
            pNbCtx->eEncrypted_rsp_payload.pData  = pNbCtx->encrypted_rsp_payload;
            pNbCtx->eEncrypted_rsp_payload.next    = NULL;
            stse_frame_insert_strap(&pNbCtx->S2, pRspFrame->first_element, &pNbCtx->eEncrypted_rsp_payload);
            stse_frame_update(pRspFrame);
        } else {
            pNbCtx->encrypted_rsp_payload_size = 0U;
        }

        /* --- Authenticated transfer pre-processing (C-MAC) --- */
        if (pSession->type == STSE_HOST_SESSION) {
            *(pCmdFrame->first_element->pData) |= (1U << 5);
        }
        *(pCmdFrame->first_element->pData) |= ((1U << 7) | (1U << 6));

        /* Push R-MAC element onto RspFrame (persistent in context) */
        pNbCtx->eRspMAC.length = STSAFEA_MAC_SIZE;
        pNbCtx->eRspMAC.pData  = pNbCtx->Rsp_MAC;
        pNbCtx->eRspMAC.next   = NULL;
        stse_frame_push_element(pRspFrame, &pNbCtx->eRspMAC);

        /* Compute C-MAC and push onto CmdFrame (persistent in context) */
        ret = stsafea_session_frame_c_mac_compute(pSession, pCmdFrame, pNbCtx->Cmd_MAC);
        if (ret != STSE_OK) {
            return ret;
        }
        pNbCtx->eCmdMAC.length = STSAFEA_MAC_SIZE;
        pNbCtx->eCmdMAC.pData  = pNbCtx->Cmd_MAC;
        pNbCtx->eCmdMAC.next   = NULL;
        stse_frame_push_element(pCmdFrame, &pNbCtx->eCmdMAC);

        /* Transmit */
        ret = stsafea_frame_transmit(pSTSE, pCmdFrame);
        if (ret != STSE_OK) {
            return ret;
        }
    } else if (pNbCtx->cmd_ac_info != STSE_CMD_AC_FREE) {
        /* ---- Authenticated session pre-processing (MAC only) ---- */
        stse_session_t *pSession = pSTSE->pActive_host_session;
        if (pSession == NULL) {
            return STSE_SERVICE_SESSION_ERROR;
        }

        if (pSession->type == STSE_HOST_SESSION) {
            *(pCmdFrame->first_element->pData) |= (1U << 5);
        }
        *(pCmdFrame->first_element->pData) |= ((1U << 7) | (1U << 6));

        pNbCtx->eRspMAC.length = STSAFEA_MAC_SIZE;
        pNbCtx->eRspMAC.pData  = pNbCtx->Rsp_MAC;
        pNbCtx->eRspMAC.next   = NULL;
        stse_frame_push_element(pRspFrame, &pNbCtx->eRspMAC);

        ret = stsafea_session_frame_c_mac_compute(pSession, pCmdFrame, pNbCtx->Cmd_MAC);
        if (ret != STSE_OK) {
            return ret;
        }
        pNbCtx->eCmdMAC.length = STSAFEA_MAC_SIZE;
        pNbCtx->eCmdMAC.pData  = pNbCtx->Cmd_MAC;
        pNbCtx->eCmdMAC.next   = NULL;
        stse_frame_push_element(pCmdFrame, &pNbCtx->eCmdMAC);

        ret = stsafea_frame_transmit(pSTSE, pCmdFrame);
        if (ret != STSE_OK) {
            return ret;
        }
    } else
#endif /* STSE_CONF_USE_HOST_SESSION */
    {
        /* ---- Plain (no session) path ---- */
        ret = stsafea_frame_transmit(pSTSE, pCmdFrame);
        if (ret != STSE_OK) {
            return ret;
        }
    }

    pNbCtx->cmd_sent_timestamp_ms = stse_platform_get_timestamp_ms();
    pNbCtx->inter_frame_delay_ms  = inter_frame_delay;

    return STSE_OK;
}

stse_ReturnCode_t stsafea_frame_transfer_finalize(stse_Handler_t *pSTSE,
                                                  stse_frame_t *pCmdFrame,
                                                  stse_frame_t *pRspFrame,
                                                  stsafea_nb_transfer_ctx_t *pNbCtx)
{
    stse_ReturnCode_t ret;

    if (pSTSE == NULL || pCmdFrame == NULL || pRspFrame == NULL || pNbCtx == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /* Receive the response frame */
    ret = stsafea_frame_receive(pSTSE, pRspFrame);

#ifdef STSE_CONF_USE_HOST_SESSION
    if (pNbCtx->cmd_encryption_flag || pNbCtx->rsp_encryption_flag ||
        pNbCtx->cmd_ac_info != STSE_CMD_AC_FREE) {
        stse_session_t *pSession = pSTSE->pActive_host_session;

        /* Update MAC counter */
        if (pSession != NULL && pSession->type == STSE_HOST_SESSION &&
            ret <= 0xFF && ret != STSE_INVALID_C_MAC && ret != STSE_COMMUNICATION_ERROR) {
            pSession->context.host.MAC_counter++;
        }

        /* Pop C-MAC from CmdFrame */
        stse_frame_pop_element(pCmdFrame);

        if (ret == STSE_OK && pSession != NULL) {
            ret = stsafea_session_frame_r_mac_verify(pSession, pCmdFrame, pRspFrame, pNbCtx->Rsp_MAC);

            /* Decrypt response if needed */
            if (ret == STSE_OK && pNbCtx->rsp_encryption_flag) {
                ret = stsafea_session_frame_decrypt(pSession, pRspFrame);
            }
        }
    }
#endif /* STSE_CONF_USE_HOST_SESSION */

    return ret;
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
