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

stsafea_nb_transfer_ctx_t stsafea_nb_ctx;

/* -------------------------------------------------------------------------
 * Private helper — second-pass receive using header+length already read
 * during stsafea_frame_transfer_check().
 *
 * This implements the data-receive portion of stsafea_frame_receive()
 * (from the length calculation onwards), using the pre-read header byte
 * and raw length stored in the non-blocking context.
 * -------------------------------------------------------------------------*/
static stse_ReturnCode_t stsafea_frame_receive_data(stsafea_nb_transfer_ctx_t *pNbCtx,
                                                    stse_frame_t *pFrame)
{
    stse_ReturnCode_t ret;
    stse_Handler_t *pSTSE = pNbCtx->pSTSE;
    stse_frame_element_t *pCurrent_element;
    PLAT_UI8  received_crc[STSE_FRAME_CRC_SIZE];
    PLAT_UI16 computed_crc;
    PLAT_UI16 filler_size = 0;

    /* Calculate total response payload length from the pre-read raw length */
    PLAT_UI16 received_length =
        (PLAT_UI16)(((PLAT_UI16)pNbCtx->received_length_raw[0] << 8) |
                     (PLAT_UI16)pNbCtx->received_length_raw[1]);
    received_length = received_length - STSE_FRAME_CRC_SIZE + STSE_RSP_FRAME_HEADER_SIZE;

    /* Verify frame overflow */
    if (received_length > stsafea_maximum_frame_length[pSTSE->device_type - STSAFE_A100]) {
        return STSE_SERVICE_FRAME_SIZE_ERROR;
    }

    /* When the device signals an error, strip all payload elements */
    if ((pNbCtx->received_header & STSE_STSAFEA_RSP_STATUS_MASK) != STSE_OK) {
        while (pFrame->element_count > 1) {
            stse_frame_pop_element(pFrame);
        }
    }

    /* Reconcile frame length with received length */
    if (received_length > pFrame->length) {
        filler_size = received_length - pFrame->length;
    }
    if (received_length < pFrame->length) {
        pFrame->length = received_length;
    }

    /* Append optional filler element */
    PLAT_UI8 filler[filler_size];
    stse_frame_element_allocate(eFiller, filler_size, filler);
    if (filler_size > 0) {
        stse_frame_push_element(pFrame, &eFiller);
    }

    /* Second-pass BusRecvStart — device already confirmed ready by _transfer */
    ret = pSTSE->io.BusRecvStart(pSTSE->io.busID,
                                  pSTSE->io.Devaddr,
                                  pSTSE->io.BusSpeed,
                                  STSE_FRAME_LENGTH_SIZE + received_length + STSE_FRAME_CRC_SIZE);
    if (ret != STSE_OK) {
        if (filler_size > 0) {
            stse_frame_pop_element(pFrame);
        }
        return ret;
    }

    /* Receive response header (first element = status byte) */
    ret = pSTSE->io.BusRecvContinue(pSTSE->io.busID,
                                     pSTSE->io.Devaddr,
                                     pSTSE->io.BusSpeed,
                                     pFrame->first_element->pData,
                                     STSE_RSP_FRAME_HEADER_SIZE);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Deduct already-read header byte from remaining payload */
    received_length -= STSE_RSP_FRAME_HEADER_SIZE;

    /* Discard the 2-byte length field embedded in the data stream */
    ret = pSTSE->io.BusRecvContinue(pSTSE->io.busID,
                                     pSTSE->io.Devaddr,
                                     pSTSE->io.BusSpeed,
                                     NULL,
                                     STSE_FRAME_LENGTH_SIZE);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Append CRC placeholder element */
    stse_frame_element_allocate_push(pFrame, eCRC, STSE_FRAME_CRC_SIZE, received_crc);

    /* Continue reading remaining bytes of the first element (if longer than header) */
    if (pFrame->first_element->length > STSE_RSP_FRAME_HEADER_SIZE) {
        ret = pSTSE->io.BusRecvContinue(pSTSE->io.busID,
                                         pSTSE->io.Devaddr,
                                         pSTSE->io.BusSpeed,
                                         pFrame->first_element->pData + STSE_RSP_FRAME_HEADER_SIZE,
                                         pFrame->first_element->length - STSE_RSP_FRAME_HEADER_SIZE);
        if (ret != STSE_OK) {
            return ret;
        }
    }

    /* Receive all payload elements */
    pCurrent_element = pFrame->first_element->next;
    while (pCurrent_element != pFrame->last_element) {
        if (received_length < pCurrent_element->length) {
            pCurrent_element->length = received_length;
        }
        ret = pSTSE->io.BusRecvContinue(pSTSE->io.busID,
                                         pSTSE->io.Devaddr,
                                         pSTSE->io.BusSpeed,
                                         pCurrent_element->pData,
                                         pCurrent_element->length);
        if (ret != STSE_OK) {
            return ret;
        }
        received_length -= pCurrent_element->length;
        pCurrent_element = pCurrent_element->next;
    }

    /* Receive final element (last element is the CRC placeholder) */
    ret = pSTSE->io.BusRecvStop(pSTSE->io.busID,
                                 pSTSE->io.Devaddr,
                                 pSTSE->io.BusSpeed,
                                 pCurrent_element->pData,
                                 pCurrent_element->length);
    if (ret != STSE_OK) {
        return ret;
    }

#ifdef STSE_FRAME_DEBUG_LOG
    printf("\n\r STSAFE Frame < ");
    stse_frame_debug_print(pFrame);
    printf("\n\r");
#endif /* STSE_FRAME_DEBUG_LOG */

    /* Swap received CRC bytes for comparison */
    stse_frame_element_swap_byte_order(&eCRC);

    /* Pop CRC element */
    stse_frame_pop_element(pFrame);

    /* Compute expected CRC */
    ret = stse_frame_crc16_compute(pFrame, &computed_crc);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Pop filler element if any */
    if (filler_size > 0) {
        stse_frame_pop_element(pFrame);
    }

    /* Verify CRC */
    if (computed_crc != *(PLAT_UI16 *)received_crc) {
        return STSE_SERVICE_FRAME_CRC_ERROR;
    }

    return (stse_ReturnCode_t)(pFrame->first_element->pData[0] & STSE_STSAFEA_RSP_STATUS_MASK);
}

/* -------------------------------------------------------------------------
 * Raw transfer (no session) — non-blocking split
 * -------------------------------------------------------------------------*/

stse_ReturnCode_t stsafea_frame_raw_transfer_start(stse_Handler_t *pSTSE,
                                                   stse_frame_t *pCmdFrame,
                                                   stsafea_nb_transfer_ctx_t *pNbCtx)
{
    stse_ReturnCode_t ret;

    if (pSTSE == NULL || pCmdFrame == NULL || pNbCtx == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /* Transmit the command frame */
    ret = stsafea_frame_transmit(pSTSE, pCmdFrame);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Store handler so _transfer can poll the device */
    pNbCtx->pSTSE = pSTSE;

    return STSE_OK;
}

stse_ReturnCode_t stsafea_frame_transfer_check(stsafea_nb_transfer_ctx_t *pNbCtx)
{
    stse_ReturnCode_t ret;
    stse_Handler_t *pSTSE;

    if (pNbCtx == NULL || pNbCtx->pSTSE == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    pSTSE = pNbCtx->pSTSE;

    /*
     * Single-attempt I²C probe: try to start reading the response header and
     * frame-length bytes from the device.
     * - NACK  → device still processing → return STSE_PLATFORM_PENDING
     * - ACK   → device ready → read header + length, store in context
     *           then return STSE_OK so the caller proceeds to _finalize
     */
    ret = pSTSE->io.BusRecvStart(pSTSE->io.busID,
                                  pSTSE->io.Devaddr,
                                  pSTSE->io.BusSpeed,
                                  STSE_FRAME_LENGTH_SIZE + STSE_RSP_FRAME_HEADER_SIZE);
    if (ret == STSE_PLATFORM_BUS_ACK_ERROR) {
        return STSE_PLATFORM_PENDING;
    }
    if (ret != STSE_OK) {
        return ret;
    }

    /* Device ACKed — read the header byte */
    ret = pSTSE->io.BusRecvContinue(pSTSE->io.busID,
                                     pSTSE->io.Devaddr,
                                     pSTSE->io.BusSpeed,
                                     &pNbCtx->received_header,
                                     STSE_RSP_FRAME_HEADER_SIZE);
    if (ret != STSE_OK) {
        return ret;
    }

    /* Read the 2-byte frame length */
    ret = pSTSE->io.BusRecvStop(pSTSE->io.busID,
                                 pSTSE->io.Devaddr,
                                 pSTSE->io.BusSpeed,
                                 pNbCtx->received_length_raw,
                                 STSE_FRAME_LENGTH_SIZE);
    return ret;  /* STSE_OK: caller may proceed to _finalize */
}

stse_ReturnCode_t stsafea_frame_raw_transfer_finalize(stsafea_nb_transfer_ctx_t *pNbCtx,
                                                      stse_frame_t *pRspFrame)
{
    if (pNbCtx == NULL || pNbCtx->pSTSE == NULL || pRspFrame == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    return stsafea_frame_receive_data(pNbCtx, pRspFrame);
}

/* -------------------------------------------------------------------------
 * Session-capable transfer — non-blocking split
 * -------------------------------------------------------------------------*/

stse_ReturnCode_t stsafea_frame_transfer_start(stse_Handler_t *pSTSE,
                                               stse_frame_t *pCmdFrame,
                                               stse_frame_t *pRspFrame,
                                               stsafea_nb_transfer_ctx_t *pNbCtx)
{
    stse_ReturnCode_t ret = STSE_SERVICE_INVALID_PARAMETER;

    if (pSTSE == NULL || pCmdFrame == NULL || pRspFrame == NULL || pNbCtx == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /* Store handler so _transfer can poll the device */
    pNbCtx->pSTSE = pSTSE;

    /* Determine session flags from the frame command header */
#ifdef STSE_CONF_USE_HOST_SESSION
    pNbCtx->cmd_encryption_flag = 0;
    pNbCtx->rsp_encryption_flag = 0;
    pNbCtx->cmd_ac_info         = STSE_CMD_AC_FREE;
#endif

    if (pCmdFrame->first_element != NULL && pCmdFrame->first_element->pData != NULL) {
        if (pCmdFrame->first_element->length == STSAFEA_EXT_HEADER_SIZE &&
            pCmdFrame->first_element->pData[0] == STSAFEA_EXTENDED_COMMAND_PREFIX) {
#ifdef STSE_CONF_USE_HOST_SESSION
            stsafea_perso_info_get_ext_cmd_AC(&pSTSE->perso_info, pCmdFrame->first_element->pData[1], &pNbCtx->cmd_ac_info);
            stsafea_perso_info_get_ext_cmd_encrypt_flag(&pSTSE->perso_info, pCmdFrame->first_element->pData[1], &pNbCtx->cmd_encryption_flag);
            stsafea_perso_info_get_ext_rsp_encrypt_flag(&pSTSE->perso_info, pCmdFrame->first_element->pData[1], &pNbCtx->rsp_encryption_flag);
#endif
            ret = STSE_OK;
        } else if (pCmdFrame->first_element->length == STSAFEA_HEADER_SIZE &&
                   pCmdFrame->first_element->pData[0] != STSAFEA_EXTENDED_COMMAND_PREFIX) {
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

    } else
#endif /* STSE_CONF_USE_HOST_SESSION */
    {
        /* ---- Plain (no session) path ---- */
        ret = stsafea_frame_transmit(pSTSE, pCmdFrame);
    }

    return ret;
}

stse_ReturnCode_t stsafea_frame_transfer_finalize(stse_frame_t *pCmdFrame,
                                                  stse_frame_t *pRspFrame,
                                                  stsafea_nb_transfer_ctx_t *pNbCtx)
{
    stse_ReturnCode_t ret;

    if (pCmdFrame == NULL || pRspFrame == NULL || pNbCtx == NULL || pNbCtx->pSTSE == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /* Second-pass data receive using header+length captured during _transfer */
    ret = stsafea_frame_receive_data(pNbCtx, pRspFrame);

#ifdef STSE_CONF_USE_HOST_SESSION
    if (pNbCtx->cmd_encryption_flag || pNbCtx->rsp_encryption_flag ||
        pNbCtx->cmd_ac_info != STSE_CMD_AC_FREE) {
        stse_session_t *pSession = pNbCtx->pSTSE->pActive_host_session;

        /* Update MAC counter */
        if (pSession != NULL && pSession->type == STSE_HOST_SESSION &&
            ret <= 0xFF && ret != STSE_INVALID_C_MAC && ret != STSE_COMMUNICATION_ERROR) {
            pSession->context.host.MAC_counter++;
        }

        /* Pop C-MAC from CmdFrame */
        stse_frame_pop_element(pCmdFrame);

        if (ret == STSE_OK && pSession != NULL) {
            ret = stsafea_session_frame_r_mac_verify(pSession, pCmdFrame, pRspFrame, pNbCtx->Rsp_MAC);

            if (ret == STSE_OK && pNbCtx->rsp_encryption_flag) {
                ret = stsafea_session_frame_decrypt(pSession, pRspFrame);
            }
        }
    }
#endif /* STSE_CONF_USE_HOST_SESSION */

    return ret;
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
