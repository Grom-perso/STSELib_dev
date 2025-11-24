/*!
 * ******************************************************************************
 * \file	stsafel_frame_transfer.c
 * \brief   STSAFE-L Frame transfer service (sources)
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

#include "services/stsafel/stsafel_frame_transfer.h"
#include "services/stsafel/stsafel_timings.h"

#ifdef STSE_CONF_STSAFE_L_SUPPORT

stse_ReturnCode_t stsafel_frame_transmit(stse_Handler_t *pSTSE, stse_frame_t *pFrame) {
    stse_ReturnCode_t ret = STSE_PLATFORM_BUS_ACK_ERROR;
    PLAT_UI16 retry_count = STSE_MAX_POLLING_RETRY;
    PLAT_UI8 element_index;
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

#ifdef STSE_CONF_USE_I2C
stse_ReturnCode_t stsafel_i2c_frame_receive(stse_Handler_t *pSTSE, stse_frame_t *pFrame) {
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
            STSE_FRAME_LENGTH_SIZE);

        if (ret != STSE_OK) {
            retry_count--;
            stse_platform_Delay_ms(STSE_POLLING_RETRY_INTERVAL);
        }
    }

    /* - Verify correct reception*/
    if ((ret & STSE_STSAFEL_RSP_STATUS_MASK) != STSE_OK) {
        return ret;
    }

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
    received_length = ((length_value[0] << 8) + length_value[1]) - STSE_FRAME_CRC_SIZE;

    /* ======================================================= */
    /* ====== Format the frame to handle CRC and filler ====== */

    /* - Compare STSAFE Received frame length with local RSP Frame length */
    if (received_length > pFrame->length) {
        /* Calculate needed filler to match both length */
        filler_size = received_length - pFrame->length;
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
            received_length + STSE_FRAME_CRC_SIZE);

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

    received_header = (stse_ReturnCode_t)(pFirst_element->pData[0] & STSE_STSAFEL_RSP_STATUS_MASK);
    if (received_header != STSE_OK) {
        while (pFrame->element_count > 1) {
            stse_frame_pop_element(pFrame);
        }
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
    ret = (stse_ReturnCode_t)(pFirst_element->pData[0] & STSE_STSAFEL_RSP_STATUS_MASK);

    return ret;
}
#endif /* STSE_CONF_USE_I2C */

#ifdef STSE_CONF_USE_ST1WIRE
stse_ReturnCode_t stsafel_st1wire_frame_receive(stse_Handler_t *pSTSE, stse_frame_t *pFrame) {
    stse_ReturnCode_t ret = STSE_PLATFORM_BUS_ACK_ERROR;
    PLAT_UI8 element_index;
    stse_frame_element_t *pFirst_element;
    stse_frame_element_t *pLast_element;
    PLAT_UI16 received_length;
    PLAT_UI8 received_crc[STSE_FRAME_CRC_SIZE];
    PLAT_UI16 computed_crc = 0;
    PLAT_UI16 retry_count = STSE_MAX_POLLING_RETRY;

    /*- Verify Parameters */
    if ((pSTSE == NULL) || (pFrame == NULL)) {
        return STSE_CORE_INVALID_PARAMETER;
    }
    /* - Verify Frame length */
    if (pFrame->element_count == 0) {
        return (STSE_CORE_INVALID_PARAMETER);
    }

    /* - Append CRC element to the RSP Frame (valid only in Receive Scope) */
    stse_frame_element_allocate_push(pFrame, eCRC, STSE_FRAME_CRC_SIZE, received_crc);

    /* - Store response Length */
    received_length = pFrame->length;

    while ((retry_count != 0) && (ret == STSE_PLATFORM_BUS_ACK_ERROR)) {
        ret = pSTSE->io.BusRecvStart(
            pSTSE->io.busID,
            pSTSE->io.Devaddr,
            pSTSE->io.BusSpeed,
            pFrame->length);

        if (ret != STSE_OK) {
            retry_count--;
            stse_platform_Delay_ms(STSE_POLLING_RETRY_INTERVAL);
        }
    }

    pFirst_element = stse_frame_get_first_element(pFrame);

    /* - Receive response header */
    ret = pSTSE->io.BusRecvContinue(
        pSTSE->io.busID,
        pSTSE->io.Devaddr,
        pSTSE->io.BusSpeed,
        pFirst_element->pData,
        STSE_RSP_FRAME_HEADER_SIZE);

    ret = (stse_ReturnCode_t)(pFirst_element->pData[0] & STSE_STSAFEL_RSP_STATUS_MASK);

    if (ret != STSE_OK) {
        return ret;
    }

    ret = pSTSE->io.BusRecvContinue(
        pSTSE->io.busID,
        pSTSE->io.Devaddr,
        pSTSE->io.BusSpeed,
        pFirst_element->pData + STSE_RSP_FRAME_HEADER_SIZE,
        pFirst_element->length - STSE_RSP_FRAME_HEADER_SIZE);
    if (ret != STSE_OK) {
        return ret;
    }

    received_length--;

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
    printf("\n\r STSE Frame < ");
    stse_frame_debug_print(pFrame);
    printf("\n\r");
#endif

    /* - Swap CRC */
    stse_frame_element_swap_byte_order(&eCRC);

    /* - Pop CRC element from Frame*/
    stse_frame_pop_element(pFrame);

    /* - Compute CRC */
    ret = stse_frame_crc16_compute(pFrame, &computed_crc);
    if (ret != STSE_OK) {
        return ret;
    }

    /* - Verify CRC */
    if (computed_crc != *(PLAT_UI16 *)received_crc) {
        return (STSE_CORE_FRAME_CRC_ERROR);
    }

    pFirst_element = stse_frame_get_first_element(pFrame);
    ret = (stse_ReturnCode_t)(pFirst_element->pData[0] & STSE_STSAFEL_RSP_STATUS_MASK);

    return ret;
}
#endif /* STSE_CONF_USE_ST1WIRE */

stse_ReturnCode_t stsafel_frame_raw_transfer(stse_Handler_t *pSTSE,
                                             stse_frame_t *pCmdFrame,
                                             stse_frame_t *pRspFrame,
                                             PLAT_UI16 inter_frame_delay) {
    stse_ReturnCode_t ret = STSE_CORE_INVALID_PARAMETER;

#ifdef STSE_USE_RSP_POLLING
    (void)inter_frame_delay;
#endif /* STSE_USE_RSP_POLLING */

    /* - Send Non-protected Frame */
    ret = stsafel_frame_transmit(pSTSE, pCmdFrame);
    if (ret == STSE_OK) {
#ifdef STSE_USE_RSP_POLLING
        /* - Wait for command to be executed by target STSAFE  */
        stse_platform_Delay_ms(STSE_FIRST_POLLING_INTERVAL);
#else
        /* - Wait for command to be executed by target STSAFE  */
        stse_platform_Delay_ms(inter_frame_delay);
#endif /* STSE_USE_RSP_POLLING */

        /* - Receive non protected Frame */
        switch (pSTSE->io.BusType) {
#ifdef STSE_CONF_USE_I2C
        case STSE_BUS_TYPE_I2C:
            ret = stsafel_i2c_frame_receive(pSTSE, pRspFrame);
            break;
#endif /* STSE_CONF_USE_I2C */
#ifdef STSE_CONF_USE_ST1WIRE
        case STSE_BUS_TYPE_ST1WIRE:
            ret = stsafel_st1wire_frame_receive(pSTSE, pRspFrame);
            break;
#endif /* STSE_CONF_USE_ST1WIRE */
        default:
            break;
        }
    }

    return ret;
}

stse_ReturnCode_t stsafel_frame_transfer(stse_Handler_t *pSTSE,
                                         stse_frame_t *pCmdFrame,
                                         stse_frame_t *pRspFrame) {
    stse_ReturnCode_t ret = STSE_CORE_INVALID_PARAMETER;
    PLAT_UI8 cmd_header;
    stse_frame_element_t *pFirst_element;

    PLAT_UI16 inter_frame_delay = STSAFEL_EXEC_TIME_DEFAULT;

    pFirst_element = stse_frame_get_first_element(pCmdFrame);
    if (pFirst_element != NULL && pFirst_element->pData != NULL) {
        if (pFirst_element->length == 1) // STSAFEA_HEADER_SIZE)
        {
            cmd_header = pFirst_element->pData[0];
            inter_frame_delay = stsafel_cmd_exec_duration(pSTSE, (stsafel_cmd_code_t)cmd_header);
            ret = STSE_OK;
        }
    }

    if (ret != STSE_OK) {
        return ret;
    }

    /*- Perform Transfer*/
    ret = stsafel_frame_raw_transfer(pSTSE,
                                     pCmdFrame,
                                     pRspFrame,
                                     inter_frame_delay);

    return ret;
}

#endif /* STSE_CONF_STSAFE_L_SUPPORT */
