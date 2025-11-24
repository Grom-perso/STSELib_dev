/*!
 * ******************************************************************************
 * \file	stse_frame.c
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

#include "core/stse_frame.h"

/* Global RAM arrays for command and response frame elements */
stse_frame_element_t stse_cmd_frame_elements[STSE_CONF_CMD_FRAME_MAX_ELEMENTS];
stse_frame_element_t stse_rsp_frame_elements[STSE_CONF_RSP_FRAME_MAX_ELEMENTS];

/* Global RAM variables for tracking element counts */
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

    for (PLAT_UI16 i = 0; i < pElement->length / 2; ++i) {
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

void stse_frame_insert_strap(stse_frame_t *pFrame, stse_frame_element_t *pStrap, stse_frame_element_t *pElement_1,
                             stse_frame_element_t *pElement_2) {
    PLAT_UI8 i;
    PLAT_UI8 element1_index = 0xFF;
    PLAT_UI8 element2_index = 0xFF;

    if (pFrame == NULL || pStrap == NULL || pElement_1 == NULL || pElement_2 == NULL) {
        return;
    }

    /* Find indices of Element_1 and Element_2 in the frame */
    for (i = 0; i < pFrame->element_count; i++) {
        if (&pFrame->pElements[i] == pElement_1) {
            element1_index = i;
        }
        if (&pFrame->pElements[i] == pElement_2) {
            element2_index = i;
        }
    }

    /* If both elements found and there's space for strap */
    if (element1_index != 0xFF && element2_index != 0xFF && pFrame->element_count < pFrame->max_elements) {
        /* Insert strap element after Element_1 by shifting elements */
        for (i = pFrame->element_count; i > element1_index + 1; i--) {
            pFrame->pElements[i] = pFrame->pElements[i - 1];
        }
        /* Insert the strap */
        pFrame->pElements[element1_index + 1] = *pStrap;
        pFrame->element_count++;
    }
}

void stse_frame_unstrap(stse_frame_t *pFrame) {
    PLAT_UI8 i, j;

    if (pFrame == NULL || pFrame->pElements == NULL) {
        return;
    }

    /* Remove strap elements (elements with length 0 and non-NULL pData used as strap marker) */
    pFrame->length = 0;
    j = 0;
    for (i = 0; i < pFrame->element_count; i++) {
        /* Skip strap elements (length == 0 and pData != NULL indicates a strap) */
        if (pFrame->pElements[i].length == 0 && pFrame->pElements[i].pData != NULL) {
            continue;
        }
        /* Keep non-strap elements */
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

    /* Recalculate total length */
    pFrame->length = 0;
    for (i = 0; i < pFrame->element_count; i++) {
        pFrame->length += pFrame->pElements[i].length;
    }
}

void stse_frame_push_element(stse_frame_t *pFrame,
                             stse_frame_element_t *pElement)
{
    if (pFrame == NULL || pElement == NULL || pFrame->pElements == NULL) {
        return;
    }

    /* Check if there's space for a new element */
    if (pFrame->element_count >= pFrame->max_elements) {
        return;
    }

    /* Copy element to the next position in the array */
    pFrame->pElements[pFrame->element_count] = *pElement;

    /* Increment Frame length and frame element count */
    pFrame->element_count += 1;
    pFrame->length += pElement->length;

    /* Update the global element count based on which array is being used */
    if (pFrame->pElements == stse_cmd_frame_elements) {
        stse_cmd_frame_element_count = pFrame->element_count;
    } else if (pFrame->pElements == stse_rsp_frame_elements) {
        stse_rsp_frame_element_count = pFrame->element_count;
    }
}

void stse_frame_pop_element(stse_frame_t *pFrame) {
    if (pFrame == NULL || pFrame->pElements == NULL) {
        return;
    }

    if (pFrame->element_count > 0) {
        /* Subtract the length of the last element */
        pFrame->length -= pFrame->pElements[pFrame->element_count - 1].length;
        /* Decrement element count */
        pFrame->element_count--;

        /* Update the global element count based on which array is being used */
        if (pFrame->pElements == stse_cmd_frame_elements) {
            stse_cmd_frame_element_count = pFrame->element_count;
        } else if (pFrame->pElements == stse_rsp_frame_elements) {
            stse_rsp_frame_element_count = pFrame->element_count;
        }
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
    if (pFrame == NULL || pFrame->pElements == NULL) {
        return NULL;
    }

    if (index >= pFrame->element_count) {
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

    /* Find the current element's index */
    for (i = 0; i < pFrame->element_count; i++) {
        if (&pFrame->pElements[i] == pElement) {
            /* Return the next element if it exists */
            if (i + 1 < pFrame->element_count) {
                return &pFrame->pElements[i + 1];
            }
            break;
        }
    }

    return NULL;
}
