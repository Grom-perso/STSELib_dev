/*!
 * ******************************************************************************
 * \filestse_frame.c
 * \brief   STSAFE Frame layer (sources)
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

#include <stdio.h>
#include "core/stse_frame.h"

/**
 * \brief Global RAM arrays for command and response frame elements.
 *        Array depth is configured via STSE_CONF_CMD_FRAME_MAX_ELEMENTS and
 *        STSE_CONF_RSP_FRAME_MAX_ELEMENTS (default 16 each).
 */
stse_frame_element_t stse_cmd_frame_elements[STSE_CONF_CMD_FRAME_MAX_ELEMENTS];
stse_frame_element_t stse_rsp_frame_elements[STSE_CONF_RSP_FRAME_MAX_ELEMENTS];

/**
 * \brief Global RAM counters for current element count in each frame array.
 *        Updated by stse_frame_push_element() and stse_frame_pop_element().
 */
PLAT_UI8 stse_cmd_frame_element_count = 0;
PLAT_UI8 stse_rsp_frame_element_count = 0;

stse_ReturnCode_t stse_frame_crc16_compute(stse_frame_t *pFrame, PLAT_UI16 *pCrc) {
    PLAT_UI8 i;

    if (pFrame == NULL || pCrc == NULL) {
        return STSE_CORE_INCONSISTENT_FRAME;
    }

    if (pFrame->element_count == 0 || pFrame->pElements == NULL) {
        return STSE_CORE_INCONSISTENT_FRAME;
    }

    /* Calculate CRC from first element */
    *pCrc = stse_platform_Crc16_Calculate(pFrame->pElements[0].pData, pFrame->pElements[0].length);

    /* Accumulate CRC from remaining elements */
    for (i = 1; i < pFrame->element_count; i++) {
        if (pFrame->pElements[i].length != 0) {
            if (pFrame->pElements[i].pData == NULL) {
                return STSE_CORE_INCONSISTENT_FRAME;
            }
            *pCrc = stse_platform_Crc16_Accumulate(pFrame->pElements[i].pData, pFrame->pElements[i].length);
        }
    }

    return STSE_OK;
}

void stse_frame_element_swap_byte_order(stse_frame_element_t *pElement) {
    PLAT_UI8 tmp;
    PLAT_UI16 i;

    if (pElement == NULL) {
        return;
    }
    for (i = 0; i < pElement->length / 2; ++i) {
        tmp = *(pElement->pData + i);
        *(pElement->pData + i) = *(pElement->pData + (pElement->length - 1 - i));
        *(pElement->pData + (pElement->length - 1 - i)) = tmp;
    }
}

void stse_append_frame(stse_frame_t *pFrame1, stse_frame_t *pFrame2) {
    PLAT_UI8 i;

    if (pFrame1 == NULL || pFrame2 == NULL) {
        return;
    }

    /* Copy elements from pFrame2 to pFrame1 */
    for (i = 0; i < pFrame2->element_count; i++) {
        if (pFrame1->element_count < pFrame1->max_elements) {
            pFrame1->pElements[pFrame1->element_count] = pFrame2->pElements[i];
            pFrame1->element_count++;
            pFrame1->length += pFrame2->pElements[i].length;
        }
    }
}

void stse_frame_insert_strap(stse_frame_t *pFrame, stse_frame_element_t *pStrap,
                             stse_frame_element_t *pElement_1, stse_frame_element_t *pElement_2) {
    PLAT_UI8 i;
    PLAT_UI8 element1_index = 0xFF;

    if (pFrame == NULL || pStrap == NULL || pElement_1 == NULL || pElement_2 == NULL) {
        return;
    }

    /* Find index of Element_1 in the frame */
    for (i = 0; i < pFrame->element_count; i++) {
        if (&pFrame->pElements[i] == pElement_1) {
            element1_index = i;
            break;
        }
    }

    /* If Element_1 found and there's space for the strap and Element_2 */
    if (element1_index != 0xFF && pFrame->element_count < pFrame->max_elements) {
        /* Shift elements from element1_index+1 onwards to make room for strap+element2 */
        for (i = pFrame->element_count; i > element1_index + 1; i--) {
            pFrame->pElements[i] = pFrame->pElements[i - 1];
        }
        /* Insert the strap (zero-length marker) after Element_1 */
        pFrame->pElements[element1_index + 1] = *pStrap;
        pFrame->element_count++;
        /* Insert Element_2 at next position if there is space */
        if (pFrame->element_count < pFrame->max_elements) {
            for (i = pFrame->element_count; i > element1_index + 2; i--) {
                pFrame->pElements[i] = pFrame->pElements[i - 1];
            }
            pFrame->pElements[element1_index + 2] = *pElement_2;
            pFrame->element_count++;
            pFrame->length += pElement_2->length;
        }
    }
}

void stse_frame_unstrap(stse_frame_t *pFrame) {
    PLAT_UI8 i, j;

    if (pFrame == NULL || pFrame->pElements == NULL) {
        return;
    }

    /* Remove strap elements (zero-length elements with NULL pData acting as placeholders) */
    pFrame->length = 0;
    j = 0;
    for (i = 0; i < pFrame->element_count; i++) {
        /* Skip strap elements: length == 0 and pData == NULL */
        if (pFrame->pElements[i].length == 0 && pFrame->pElements[i].pData == NULL) {
            continue;
        }
        if (i != j) {
            pFrame->pElements[j] = pFrame->pElements[i];
        }
        pFrame->length += pFrame->pElements[j].length;
        j++;
    }
    pFrame->element_count = j;
}

void stse_frame_update(stse_frame_t *pFrame) {
    PLAT_UI8 i;

    if (pFrame == NULL || pFrame->pElements == NULL) {
        return;
    }

    /* Recalculate total length from all elements */
    pFrame->length = 0;
    for (i = 0; i < pFrame->element_count; i++) {
        pFrame->length += pFrame->pElements[i].length;
    }
}

void stse_frame_push_element(stse_frame_t *pFrame, stse_frame_element_t *pElement) {
    if (pFrame == NULL || pElement == NULL || pFrame->pElements == NULL) {
        return;
    }

    /* Check if there's space for a new element */
    if (pFrame->element_count >= pFrame->max_elements) {
        return;
    }

    /* Copy element into the next slot in the array */
    pFrame->pElements[pFrame->element_count] = *pElement;

    /* Increment element count and total length */
    pFrame->element_count++;
    pFrame->length += pElement->length;

    /* Maintain global element count for the two standard global arrays */
    if (pFrame->pElements == stse_cmd_frame_elements) {
        stse_cmd_frame_element_count = pFrame->element_count;
    } else if (pFrame->pElements == stse_rsp_frame_elements) {
        stse_rsp_frame_element_count = pFrame->element_count;
    }
}

void stse_frame_pop_element(stse_frame_t *pFrame) {
    if (pFrame == NULL || pFrame->pElements == NULL || pFrame->element_count == 0) {
        return;
    }

    /* Subtract the length of the last element */
    pFrame->length -= pFrame->pElements[pFrame->element_count - 1].length;
    /* Decrement element count */
    pFrame->element_count--;

    /* Maintain global element count for the two standard global arrays */
    if (pFrame->pElements == stse_cmd_frame_elements) {
        stse_cmd_frame_element_count = pFrame->element_count;
    } else if (pFrame->pElements == stse_rsp_frame_elements) {
        stse_rsp_frame_element_count = pFrame->element_count;
    }
}

void stse_frame_debug_print(stse_frame_t *pFrame) {
    PLAT_UI8 i;
    PLAT_UI16 data_index;

    if (pFrame == NULL || pFrame->element_count == 0) {
        printf("\n\r (EMPTY)");
        return;
    }

    printf(" (%d-byte) :", pFrame->length);
    for (i = 0; i < pFrame->element_count; i++) {
        printf(" { ");
        if (pFrame->pElements[i].length == 0) {
            printf("S ");
        } else {
            for (data_index = 0; data_index < pFrame->pElements[i].length; data_index++) {
                if (pFrame->pElements[i].pData != NULL) {
                    printf("0x%02X ", pFrame->pElements[i].pData[data_index]);
                } else {
                    printf("0x00 ");
                }
            }
        }
        printf("}");
    }
}

stse_frame_element_t *stse_frame_get_element(stse_frame_t *pFrame, PLAT_UI8 index) {
    if (pFrame == NULL || pFrame->pElements == NULL || index >= pFrame->element_count) {
        return NULL;
    }
    return &pFrame->pElements[index];
}

stse_frame_element_t *stse_frame_get_first_element(stse_frame_t *pFrame) {
    if (pFrame == NULL || pFrame->pElements == NULL || pFrame->element_count == 0) {
        return NULL;
    }
    return &pFrame->pElements[0];
}

stse_frame_element_t *stse_frame_get_last_element(stse_frame_t *pFrame) {
    if (pFrame == NULL || pFrame->pElements == NULL || pFrame->element_count == 0) {
        return NULL;
    }
    return &pFrame->pElements[pFrame->element_count - 1];
}

stse_frame_element_t *stse_frame_get_next_element(stse_frame_t *pFrame, stse_frame_element_t *pElement) {
    PLAT_UI8 i;

    if (pFrame == NULL || pFrame->pElements == NULL || pElement == NULL) {
        return NULL;
    }

    /* Find the current element's index and return the next one */
    for (i = 0; i < pFrame->element_count; i++) {
        if (&pFrame->pElements[i] == pElement) {
            if (i + 1 < pFrame->element_count) {
                return &pFrame->pElements[i + 1];
            }
            break;
        }
    }

    return NULL;
}
