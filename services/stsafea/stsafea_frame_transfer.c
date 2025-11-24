/*!
 * ******************************************************************************
 * \file    stsafea_frame_transfer.c
 * \brief   STSAFE-A Frame transfer service (sources)
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

#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_commands.h"
#include "services/stsafea/stsafea_sessions.h"
#include "services/stsafea/stsafea_timings.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

stse_ReturnCode_t stsafea_frame_transmit(stse_Handler_t *pSTSE, stse_frame_t *pFrame) {
    stse_ReturnCode_t ret = STSE_PLATFORM_BUS_ACK_ERROR;
    PLAT_UI16 retry_count = STSE_MAX_POLLING_RETRY;
    PLAT_UI8 element_index;
    stse_frame_element_t *pFirst_element;
    stse_frame_element_t *pLast_element;
    PLAT_UI16 crc_ret;
    PLAT_UI8 crc[STSE_FRAME_CRC_SIZE] = {0};

    /*- Verify Parameters */
    if ((pSTSE == NULL) || (pFrame == NULL)) {
        return STSE_CORE_INVALID_PARAMETER;
    }
    /*- Verify Frame length */
    if (pFrame->element_count == 0) {
        return STSE_CORE_INVALID_PARAMETER;
    }
    /*- Compute frame crc */
    ret = stse_frame_crc16_compute(pFrame, &crc_ret);
    if (ret != STSE_OK) {
        return ret;
    }
    crc[0] = (crc_ret >> 8) & 0xFF;
    crc[1] = crc_ret & 0xFF;

    /* - Append CRC element to the RSP Frame (valid only on Receive Scope) */
    stse_frame_element_allocate(crc_element, STSE_FRAME_CRC_SIZE, crc);
    stse_frame_push_element(pFrame, &crc_element);

#ifdef STSE_FRAME_DEBUG_LOG
    printf("\n\r STSAFE Frame > ");
    stse_frame_debug_print(pFrame);
    printf("\n\r");
#endif /* STSE_FRAME_DEBUG_LOG */
    ret = STSE_PLATFORM_BUS_ACK_ERROR;
    while ((retry_count != 0) && (ret == STSE_PLATFORM_BUS_ACK_ERROR)) {
        /* - Receive frame length from target STSAFE */
        ret = pSTSE->io.BusSendStart(
            pSTSE->io.busID,
            pSTSE->io.Devaddr,
            pSTSE->io.BusSpeed,
            pFrame->length);

        if (ret == STSE_OK) {
            pFirst_element = stse_frame_get_first_element(pFrame);
            pLast_element = stse_frame_get_last_element(pFrame);

            /* Send all elements except the last one */
            for (element_index = 0; element_index < pFrame->element_count - 1; element_index++) {
                ret = pSTSE->io.BusSendContinue(
                    pSTSE->io.busID,
                    pSTSE->io.Devaddr,
                    pSTSE->io.BusSpeed,
                    pFrame->pElements[element_index].pData,
                    pFrame->pElements[element_index].length);
                if (ret != STSE_OK) {
                    break;
                }
            }
            if (ret == STSE_OK && pLast_element != NULL) {
                ret = pSTSE->io.BusSendStop(
                    pSTSE->io.busID,
                    pSTSE->io.Devaddr,
                    pSTSE->io.BusSpeed,
                    pLast_element->pData,
                    pLast_element->length);
            }
        }

        if (ret != STSE_OK) {
            retry_count--;
            stse_platform_Delay_ms(STSE_POLLING_RETRY_INTERVAL);
        }
    }

    /* - Pop CRC element from Frame*/
    stse_frame_pop_element(pFrame);
    return ret;
}

stse_ReturnCode_t stsafea_frame_receive(stse_Handler_t *pSTSE, stse_frame_t *pFrame) {
    stse_ReturnCode_t ret = STSE_PLATFORM_BUS_ACK_ERROR;
    PLAT_UI8 element_index;
    stse_frame_element_t *pFirst_element;
    stse_frame_element_t *pLast_element;
    PLAT_UI8 received_header;
    PLAT_UI16 received_length;
    PLAT_UI8 received_crc[STSE_FRAME_CRC_SIZE];
    PLAT_UI16 computed_crc;
    PLAT_UI16 filler_size = 0;
    PLAT_UI16 retry_count = STSE_MAX_POLLING_RETRY;
    PLAT_UI8 length_value[STSE_FRAME_LENGTH_SIZE];

    /*- Verify Parameters */
    if ((pSTSE == NULL) || (pFrame == NULL)) {
        return STSE_CORE_INVALID_PARAMETER;
    }
    /* - Verify Frame length */
    if (pFrame->element_count == 0) {
        return (STSE_CORE_INVALID_PARAMETER);
    }

    /* ======================================================= */
    /* ============== Get the total frame length ============= */
    while ((retry_count != 0) && (ret == STSE_PLATFORM_BUS_ACK_ERROR)) {
        /* - Receive frame length from target STSAFE */
        ret = pSTSE->io.BusRecvStart(
            pSTSE->io.busID,
            pSTSE->io.Devaddr,
            pSTSE->io.BusSpeed,
            STSE_FRAME_LENGTH_SIZE + STSE_RSP_FRAME_HEADER_SIZE);

        if (ret != STSE_OK) {
            retry_count--;
            stse_platform_Delay_ms(STSE_POLLING_RETRY_INTERVAL);
        }
    }

    /* - Verify correct reception*/
    if (ret != STSE_OK) {
        return ret;
    }

    /* Discard response header */
    pSTSE->io.BusRecvContinue(
        pSTSE->io.busID,
        pSTSE->io.Devaddr,
        pSTSE->io.BusSpeed,
        &received_header,
        STSE_RSP_FRAME_HEADER_SIZE);

    /* - Get STSAFE Response Length */
    ret = pSTSE->io.BusRecvStop(
        pSTSE->io.busID,
        pSTSE->io.Devaddr,
        pSTSE->io.BusSpeed,
        length_value,
        STSE_FRAME_LENGTH_SIZE);
    if (ret != STSE_OK) {
        return ret;
    }

    /* - Store response Length */
    received_length = ((length_value[0] << 8) + length_value[1]) - STSE_FRAME_CRC_SIZE + STSE_RSP_FRAME_HEADER_SIZE;

    if ((received_header & STSE_STSAFEA_RSP_STATUS_MASK) != STSE_OK) {
        while (pFrame->element_count > 1) {
            stse_frame_pop_element(pFrame);
        }
    }

    /* ======================================================= */
    /* ====== Format the frame to handle CRC and filler ====== */

    /* - Compare STSAFE Received frame length with local RSP Frame length */
    if (received_length > pFrame->length) {
        /* Calculate needed filler to match both length */
        filler_size = received_length - pFrame->length;
    }
    if (received_length < pFrame->length) {
        pFrame->length = received_length;
    }

    /* Append filler frame element even if its length equal 0 */
    PLAT_UI8 filler[filler_size];
    stse_frame_element_allocate(eFiller,
                                filler_size,
                                filler);
    if (filler_size > 0) {
        stse_frame_push_element(pFrame,
                                &eFiller);
    }

    /* ======================================================= */
    /* ========= Receive the frame in frame elements ========= */

    ret = STSE_PLATFORM_BUS_ACK_ERROR;
    while ((retry_count != 0) && (ret == STSE_PLATFORM_BUS_ACK_ERROR)) {
        /* - Receive frame length from target STSAFE */
        ret = pSTSE->io.BusRecvStart(
            pSTSE->io.busID,
            pSTSE->io.Devaddr,
            pSTSE->io.BusSpeed,
            STSE_FRAME_LENGTH_SIZE + received_length + STSE_FRAME_CRC_SIZE);

        if (ret != STSE_OK) {
            retry_count--;
            stse_platform_Delay_ms(STSE_POLLING_RETRY_INTERVAL);
        }
    }

    /* - Verify correct reception*/
    if (ret != STSE_OK) {
        return ret;
    }

    pFirst_element = stse_frame_get_first_element(pFrame);

    /* Receive response header */
    ret = pSTSE->io.BusRecvContinue(
        pSTSE->io.busID,
        pSTSE->io.Devaddr,
        pSTSE->io.BusSpeed,
        pFirst_element->pData,
        STSE_RSP_FRAME_HEADER_SIZE);

    if (ret != STSE_OK) {
        return ret;
    }

    /* Substract response header already read in STSAFE-A */
    received_length -= STSE_RSP_FRAME_HEADER_SIZE;

    /* Receive and discard length (already stored) */
    ret = pSTSE->io.BusRecvContinue(
        pSTSE->io.busID,
        pSTSE->io.Devaddr,
        pSTSE->io.BusSpeed,
        NULL,
        STSE_FRAME_LENGTH_SIZE);
    if (ret != STSE_OK) {
        return ret;
    }

    /* - Append CRC element to the RSP Frame (valid only in Receive Scope) */
    stse_frame_element_allocate_push(pFrame, eCRC, STSE_FRAME_CRC_SIZE, received_crc);

    /* If first element is longer than just the header */
    if (pFirst_element->length > STSE_RSP_FRAME_HEADER_SIZE) {
        /* Receive missing bytes after discarding the 2 bytes length */
        ret = pSTSE->io.BusRecvContinue(
            pSTSE->io.busID,
            pSTSE->io.Devaddr,
            pSTSE->io.BusSpeed,
            pFirst_element->pData + STSE_RSP_FRAME_HEADER_SIZE,
            pFirst_element->length - STSE_RSP_FRAME_HEADER_SIZE);
        if (ret != STSE_OK) {
            return ret;
        }
    }

    /* - Perform frame element reception and populate local RSP Frame */
    pLast_element = stse_frame_get_last_element(pFrame);
    for (element_index = 1; element_index < pFrame->element_count - 1; element_index++) {
        if (received_length < pFrame->pElements[element_index].length) {
            pFrame->pElements[element_index].length = received_length;
        }
        ret = pSTSE->io.BusRecvContinue(
            pSTSE->io.busID,
            pSTSE->io.Devaddr,
            pSTSE->io.BusSpeed,
            pFrame->pElements[element_index].pData,
            pFrame->pElements[element_index].length);
        if (ret != STSE_OK) {
            return ret;
        }

        received_length -= pFrame->pElements[element_index].length;
    }
    if (pLast_element != NULL) {
        ret = pSTSE->io.BusRecvStop(
            pSTSE->io.busID,
            pSTSE->io.Devaddr,
            pSTSE->io.BusSpeed,
            pLast_element->pData,
            pLast_element->length);
        if (ret != STSE_OK) {
            return ret;
        }
    }

#ifdef STSE_FRAME_DEBUG_LOG
    printf("\n\r STSAFE Frame < ");
    stse_frame_debug_print(pFrame);
    printf("\n\r");
#endif /* STSE_FRAME_DEBUG_LOG */

    /* - Swap CRC */
    stse_frame_element_swap_byte_order(&eCRC);

    /* - Pop CRC element from Frame*/
    stse_frame_pop_element(pFrame);

    /* - Compute CRC */
    ret = stse_frame_crc16_compute(pFrame, &computed_crc);
    if (ret != STSE_OK) {
        return ret;
    }

    /* - Pop Filler element from Frame*/
    if (filler_size > 0) {
        stse_frame_pop_element(pFrame);
    }

    /* - Verify CRC */
    if (computed_crc != *(PLAT_UI16 *)received_crc) {
        return (STSE_CORE_FRAME_CRC_ERROR);
    }

    pFirst_element = stse_frame_get_first_element(pFrame);
    ret = (stse_ReturnCode_t)(pFirst_element->pData[0] & STSE_STSAFEA_RSP_STATUS_MASK);

    return ret;
}

stse_ReturnCode_t stsafea_frame_raw_transfer(stse_Handler_t *pSTSE,
                                             stse_frame_t *pCmdFrame,
                                             stse_frame_t *pRspFrame,
                                             PLAT_UI16 inter_frame_delay) {
    stse_ReturnCode_t ret = STSE_CORE_INVALID_PARAMETER;

#ifdef STSE_USE_RSP_POLLING
    (void)inter_frame_delay;
#endif /* STSE_USE_RSP_POLLING */

    /* - Send Non-protected Frame */
    ret = stsafea_frame_transmit(pSTSE, pCmdFrame);
    if (ret == STSE_OK) {
#ifdef STSE_USE_RSP_POLLING
        /* - Wait for command to be executed by target STSAFE  */
        stse_platform_Delay_ms(STSE_FIRST_POLLING_INTERVAL);
#else
        /* - Wait for command to be executed by target STSAFE  */
        stse_platform_Delay_ms(inter_frame_delay);
#endif /* STSE_USE_RSP_POLLING */
        /* - Receive non protected Frame */
        ret = stsafea_frame_receive(pSTSE, pRspFrame);
    }

    return ret;
}

stse_ReturnCode_t stsafea_frame_transfer(stse_Handler_t *pSTSE, stse_frame_t *pCmdFrame,
                                         stse_frame_t *pRspFrame) {
    stse_ReturnCode_t ret = STSE_CORE_INVALID_PARAMETER;
    PLAT_UI16 inter_frame_delay = STSAFEA_EXEC_TIME_DEFAULT;
    stse_frame_element_t *pFirst_element;

#ifdef STSE_CONF_USE_HOST_SESSION
    stse_cmd_access_conditions_t cmd_ac_info;
    PLAT_UI8 cmd_encryption_flag = 0;
    PLAT_UI8 rsp_encryption_flag = 0;
#endif /* STSE_CONF_USE_HOST_SESSION */

    pFirst_element = stse_frame_get_first_element(pCmdFrame);
    if (pFirst_element != NULL && pFirst_element->pData != NULL) {
        if (pFirst_element->length == STSAFEA_EXT_HEADER_SIZE && pFirst_element->pData[0] == STSAFEA_EXTENDED_COMMAND_PREFIX) {
            inter_frame_delay = stsafea_extended_cmd_timings[pSTSE->device_type][pFirst_element->pData[1]];
#ifdef STSE_CONF_USE_HOST_SESSION
            stsafea_perso_info_get_ext_cmd_AC(&pSTSE->perso_info, pFirst_element->pData[1], &cmd_ac_info);
            stsafea_perso_info_get_ext_cmd_encrypt_flag(&pSTSE->perso_info, pFirst_element->pData[1], &cmd_encryption_flag);
            stsafea_perso_info_get_ext_rsp_encrypt_flag(&pSTSE->perso_info, pFirst_element->pData[1], &rsp_encryption_flag);
#endif /* STSE_CONF_USE_HOST_SESSION */
            ret = STSE_OK;
        } else if (pFirst_element->length == STSAFEA_HEADER_SIZE && pFirst_element->pData[0] != STSAFEA_EXTENDED_COMMAND_PREFIX) {
            inter_frame_delay = stsafea_cmd_timings[pSTSE->device_type][pFirst_element->pData[0]];
#ifdef STSE_CONF_USE_HOST_SESSION
            stsafea_perso_info_get_cmd_AC(&pSTSE->perso_info, pFirst_element->pData[0], &cmd_ac_info);
            stsafea_perso_info_get_cmd_encrypt_flag(&pSTSE->perso_info, pFirst_element->pData[0], &cmd_encryption_flag);
            stsafea_perso_info_get_rsp_encrypt_flag(&pSTSE->perso_info, pFirst_element->pData[0], &rsp_encryption_flag);
#endif /* STSE_CONF_USE_HOST_SESSION */
            ret = STSE_OK;
        }
    }

    if (ret != STSE_OK) {
        return ret;
    }

    /*- Perform Transfer*/
#ifdef STSE_CONF_USE_HOST_SESSION
    if (cmd_encryption_flag || rsp_encryption_flag) {
        ret = stsafea_session_encrypted_transfer(pSTSE->pActive_host_session,
                                                 pCmdFrame,
                                                 pRspFrame,
                                                 cmd_encryption_flag,
                                                 rsp_encryption_flag,
                                                 cmd_ac_info,
                                                 inter_frame_delay);
    } else if (cmd_ac_info != STSE_CMD_AC_FREE) {
        ret = stsafea_session_authenticated_transfer(pSTSE->pActive_host_session,
                                                     pCmdFrame,
                                                     pRspFrame,
                                                     cmd_ac_info,
                                                     inter_frame_delay);
    } else
#endif /* STSE_CONF_USE_HOST_SESSION */
    {
        ret = stsafea_frame_raw_transfer(pSTSE,
                                         pCmdFrame,
                                         pRspFrame,
                                         inter_frame_delay);
    }

    return ret;
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT **/
