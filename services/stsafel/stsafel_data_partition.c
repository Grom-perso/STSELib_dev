/*!
 ******************************************************************************
 * \file	stsafel_data_partition.c
 * \brief   Data partition services for STSAFE-L
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2024 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include "services/stsafel/stsafel_data_partition.h"
#include "services/stsafel/stsafel_commands.h"
#include "services/stsafel/stsafel_frame_transfer.h"

#ifdef STSE_CONF_STSAFE_L_SUPPORT

stse_return_code_t stsafel_read_data_zone(stse_handler_t *p_stse,
                                         PLAT_UI8 zone_index,
                                         stsafel_read_option_t option,
                                         PLAT_UI16 offset,
                                         PLAT_UI8 *p_data,
                                         PLAT_UI16 data_length,
                                         stse_cmd_protection_t protection) {
    PLAT_UI8 cmd_header = STSAFEL_CMD_READ;
    PLAT_UI8 rsp_header;

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if (p_data == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(cmd_frame);
    stse_frame_element_allocate_push(&cmd_frame, ecmd_header, STSAFEL_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&cmd_frame, eRead_option, sizeof(stsafel_read_option_t), (PLAT_UI8 *)&option);
    stse_frame_element_allocate_push(&cmd_frame, ezone_index, 1, &zone_index);
    stse_frame_element_allocate_push(&cmd_frame, eOffset, 2, (PLAT_UI8 *)&offset);
    stse_frame_element_allocate_push(&cmd_frame, edata_length, 2, (PLAT_UI8 *)&data_length);

    /*- Create Rsp frame and populate elements */
    stse_frame_allocate(rsp_frame);
    stse_frame_element_allocate_push(&rsp_frame, ersp_header, STSAFEL_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&rsp_frame, eData, data_length, p_data);

    stse_frame_element_swap_byte_order(&eOffset);
    stse_frame_element_swap_byte_order(&edata_length);

    /*- Perform Transfer*/
    return stsafel_frame_transfer(p_stse,
                                  &cmd_frame,
                                  &rsp_frame);
}

stse_return_code_t stsafel_update_data_zone(stse_handler_t *p_stse,
                                           PLAT_UI8 zone_index,
                                           stsafel_update_option_t option,
                                           PLAT_UI16 offset,
                                           PLAT_UI8 *p_data,
                                           PLAT_UI16 data_length,
                                           stse_cmd_protection_t protection) {
    PLAT_UI8 cmd_header = STSAFEL_CMD_UPDATE;
    PLAT_UI8 rsp_header;

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if (p_data == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(cmd_frame);
    stse_frame_element_allocate_push(&cmd_frame, ecmd_header, STSAFEL_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&cmd_frame, eUpdate_option, sizeof(stsafel_update_option_t), (PLAT_UI8 *)&option);
    stse_frame_element_allocate_push(&cmd_frame, ezone_index, 1, &zone_index);
    stse_frame_element_allocate_push(&cmd_frame, eOffset, 2, (PLAT_UI8 *)&offset);
    stse_frame_element_allocate_push(&cmd_frame, eData, data_length, p_data);

    /*- Create Rsp frame and populate elements */
    stse_frame_allocate(rsp_frame);
    stse_frame_element_allocate_push(&rsp_frame, ersp_header, STSAFEL_HEADER_SIZE, &rsp_header);

    stse_frame_element_swap_byte_order(&eOffset);

    /*- Perform Transfer*/
    /*- Perform Transfer*/
    return stsafel_frame_transfer(p_stse,
                                  &cmd_frame,
                                  &rsp_frame);
}

stse_return_code_t stsafel_read_counter_zone(stse_handler_t *p_stse,
                                            PLAT_UI8 zone_index,
                                            stsafel_read_option_t option,
                                            PLAT_UI16 offset,
                                            PLAT_UI8 *p_data,
                                            PLAT_UI16 data_length,
                                            PLAT_UI32 *p_counter_value,
                                            stse_cmd_protection_t protection) {
    stse_return_code_t ret;
    PLAT_UI8 cmd_header = STSAFEL_CMD_READ;
    PLAT_UI8 rsp_header;
    PLAT_UI8 temp_counter[STSAFEL_COUNTER_VALUE_SIZE];

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if (p_data == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(cmd_frame);
    stse_frame_element_allocate_push(&cmd_frame, ecmd_header, STSAFEL_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&cmd_frame, eRead_option, sizeof(stsafel_read_option_t), (PLAT_UI8 *)&option);
    stse_frame_element_allocate_push(&cmd_frame, ezone_index, 1, &zone_index);
    stse_frame_element_allocate_push(&cmd_frame, eOffset, 2, (PLAT_UI8 *)&offset);
    stse_frame_element_allocate_push(&cmd_frame, edata_length, 2, (PLAT_UI8 *)&data_length);

    /*- Create Rsp frame and populate elements */
    stse_frame_allocate(rsp_frame);
    stse_frame_element_allocate_push(&rsp_frame, ersp_header, STSAFEL_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&rsp_frame, eCounter, STSAFEL_COUNTER_VALUE_SIZE, temp_counter);
    stse_frame_element_allocate_push(&rsp_frame, eData, data_length, p_data);

    stse_frame_element_swap_byte_order(&eOffset);
    stse_frame_element_swap_byte_order(&edata_length);

    /*- Perform Transfer*/
    ret = stsafel_frame_transfer(p_stse,
                                 &cmd_frame,
                                 &rsp_frame);

    if (ret == STSE_OK) {
        *p_counter_value = ((temp_counter[2]) | (temp_counter[1] << 8) | (temp_counter[0] << 16));
    }

    return (ret);
}

stse_return_code_t stsafel_decrement_counter_zone(stse_handler_t *p_stse,
                                                 PLAT_UI8 zone_index,
                                                 stsafel_decrement_option_t option,
                                                 PLAT_UI32 amount,
                                                 PLAT_UI16 offset,
                                                 PLAT_UI8 *p_data,
                                                 PLAT_UI16 data_length,
                                                 PLAT_UI32 *p_new_counter_value,
                                                 stse_cmd_protection_t protection) {
    stse_return_code_t ret;
    PLAT_UI8 cmd_header = STSAFEL_CMD_DECREMENT;
    PLAT_UI8 rsp_header;
    PLAT_UI8 decrement_amount[STSAFEL_COUNTER_VALUE_SIZE] = {
        ((amount & 0xFF0000) >> 16),
        ((amount & 0xFF00) >> 8),
        (amount & 0xFF)};
    PLAT_UI8 temp_counter[STSAFEL_COUNTER_VALUE_SIZE];

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if (p_data == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(cmd_frame);
    stse_frame_element_allocate_push(&cmd_frame, ecmd_header, STSAFEL_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&cmd_frame, eDecrement_option, sizeof(stsafel_decrement_option_t), (PLAT_UI8 *)&option);
    stse_frame_element_allocate_push(&cmd_frame, ezone_index, 1, &zone_index);
    stse_frame_element_allocate_push(&cmd_frame, eOffset, 2, (PLAT_UI8 *)&offset);
    stse_frame_element_allocate_push(&cmd_frame, eAmount, STSAFEL_COUNTER_VALUE_SIZE, decrement_amount);
    stse_frame_element_allocate_push(&cmd_frame, eData, data_length, p_data);

    /*- Create Rsp frame and populate elements */
    stse_frame_allocate(rsp_frame);
    stse_frame_element_allocate_push(&rsp_frame, ersp_header, STSAFEL_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&rsp_frame, eCounter, STSAFEL_COUNTER_VALUE_SIZE, temp_counter);

    stse_frame_element_swap_byte_order(&eOffset);

    /*- Perform Transfer*/
    ret = stsafel_frame_transfer(p_stse,
                                 &cmd_frame,
                                 &rsp_frame);

    if (ret == STSE_OK) {
        *p_new_counter_value = ((temp_counter[2]) | (temp_counter[1] << 8) | (temp_counter[0] << 16));
    }

    return (ret);
}

#endif /* STSE_CONF_STSAFE_L_SUPPORT */
