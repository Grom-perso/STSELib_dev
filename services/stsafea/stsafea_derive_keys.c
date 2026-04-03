/*!
 ******************************************************************************
 * \file	stsafea_derive_keys.c
 * \brief   STSAFE-A services for derive keys command (source)
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2025 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 *****************************************************************************/

/* Includes ------------------------------------------------------------------*/
#include <stddef.h>

#include "services/stsafea/stsafea_derive_keys.h"
#include "services/stsafea/stsafea_frame_transfer.h"

stse_return_code_t stsafea_derive_keys(
    stse_handler_t *p_stse,
    stsafea_hkdf_input_key_t *p_input_key,
    PLAT_UI8 extract_flag,
    PLAT_UI8 expand_flag,
    stsafea_hkdf_salt_t *p_salt,
    stsafea_hkdf_info_t *p_info,
    stsafea_hkdf_okm_description_t *p_okm_map,
    PLAT_UI8 okm_count,
    stsafea_hkdf_output_t *p_output) {
    stse_return_code_t ret;
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_DERIVE_KEYS};
    PLAT_UI8 rsp_header;
    PLAT_UI8 hkdf_flags = 0;
    stsafea_hash_algorithm_identifier_t hash_algo = {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA_256};

    /* -- Frame Element Declarations -- */
    stse_frame_element_t eCmdHeader;

    /* Input Key Elements */
    stse_frame_element_t eInputSource;
    stse_frame_element_t eInputMode, eInputLength, eInputValue; /* For Command source */
    stse_frame_element_t eInputSlot;                            /* For Slot source */

    /* HKDF Param Elements */
    stse_frame_element_t eHkdfFlags, eHashAlgo;

    /* Salt Elements */
    stse_frame_element_t eSaltSource;
    stse_frame_element_t eSaltLength, eSaltValue; /* For Command source */
    stse_frame_element_t eSaltSlot;               /* For Slot source */

    /* Info Elements */
    stse_frame_element_t eInfoLength, eInfoValue;

    /* Response Elements */
    stse_frame_element_t eRspHeader, eRspPrkSlot;

    /* -- Auxiliary Buffers -- */
    PLAT_UI8 input_len_buf[2];
    PLAT_UI8 salt_len_buf[2];
    PLAT_UI8 info_len_buf[2];

    /* 1. Parameter Validation */
    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (p_input_key == NULL || p_output == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }
    if (expand_flag && (p_okm_map == NULL || p_output->derived_keys == NULL)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /* 2. Loop Arrays & Buffer Allocation */
    stse_frame_element_t eOkmDescLength[okm_count], eOkmDestination[okm_count];
    stse_frame_element_t eOkmData1[okm_count], eOkmData2[okm_count];
    stse_frame_element_t eRspOkmData[okm_count];

    PLAT_UI8 okm_desc_len_buf[okm_count][2];
    PLAT_UI8 okm_key_len_buf[okm_count][2];

    /* Initialize Frames */
    stse_frame_allocate(cmd_frame);
    stse_frame_allocate(rsp_frame);

    /* 3. Build Command Frame */
    /* Header */
    eCmdHeader.length = STSAFEA_EXT_HEADER_SIZE;
    eCmdHeader.p_data = cmd_header;
    stse_frame_push_element(&cmd_frame, &eCmdHeader);

    /* -- Input Key -- */
    eInputSource.length = 1;
    eInputSource.p_data = &p_input_key->source;
    stse_frame_push_element(&cmd_frame, &eInputSource);

    if (p_input_key->source == STSAFEA_KEY_SOURCE_COMMAND) {
        input_len_buf[0] = (PLAT_UI8)(p_input_key->command.length >> 8);
        input_len_buf[1] = (PLAT_UI8)(p_input_key->command.length);

        eInputMode.length = 1;
        eInputMode.p_data = (PLAT_UI8 *)&p_input_key->command.mode_of_operation;

        eInputLength.length = 2;
        eInputLength.p_data = input_len_buf;

        eInputValue.length = p_input_key->command.length;
        eInputValue.p_data = p_input_key->command.data;

        stse_frame_push_element(&cmd_frame, &eInputMode);
        stse_frame_push_element(&cmd_frame, &eInputLength);
        stse_frame_push_element(&cmd_frame, &eInputValue);
    } else {
        eInputSlot.length = 1;
        eInputSlot.p_data = &p_input_key->symmkey.slot_number;
        stse_frame_push_element(&cmd_frame, &eInputSlot);
    }

    /* -- HKDF Parameters -- */
    if (extract_flag)
        hkdf_flags |= (1 << STSAFEA_HKDF_FLAG_EXTRACT_POS);
    if (expand_flag)
        hkdf_flags |= (1 << STSAFEA_HKDF_FLAG_EXPAND_POS);

    eHkdfFlags.length = 1;
    eHkdfFlags.p_data = &hkdf_flags;

    eHashAlgo.length = STSAFEA_HASH_ALGO_ID_SIZE;
    eHashAlgo.p_data = (PLAT_UI8 *)&hash_algo;

    stse_frame_push_element(&cmd_frame, &eHkdfFlags);
    stse_frame_push_element(&cmd_frame, &eHashAlgo);

    /* -- Salt (Conditional) -- */
    if (extract_flag) {
        if (p_salt == NULL)
            return STSE_SERVICE_INVALID_PARAMETER;

        eSaltSource.length = 1;
        eSaltSource.p_data = &p_salt->source;
        stse_frame_push_element(&cmd_frame, &eSaltSource);

        if (p_salt->source == STSAFEA_KEY_SOURCE_COMMAND) {
            salt_len_buf[0] = (PLAT_UI8)(p_salt->command.length >> 8);
            salt_len_buf[1] = (PLAT_UI8)(p_salt->command.length);

            eSaltLength.length = 2;
            eSaltLength.p_data = salt_len_buf;
            stse_frame_push_element(&cmd_frame, &eSaltLength);

            if (p_salt->command.length > 0 && p_salt->command.data != NULL) {
                eSaltValue.length = p_salt->command.length;
                eSaltValue.p_data = p_salt->command.data;
                stse_frame_push_element(&cmd_frame, &eSaltValue);
            }
        } else {
            eSaltSlot.length = 1;
            eSaltSlot.p_data = &p_salt->symmkey.slot_number;
            stse_frame_push_element(&cmd_frame, &eSaltSlot);
        }
    }

    /* -- Info (Conditional) -- */
    if (expand_flag) {
        PLAT_UI16 info_len = (p_info != NULL) ? p_info->length : 0;
        info_len_buf[0] = (PLAT_UI8)(info_len >> 8);
        info_len_buf[1] = (PLAT_UI8)(info_len);

        eInfoLength.length = 2;
        eInfoLength.p_data = info_len_buf;
        stse_frame_push_element(&cmd_frame, &eInfoLength);

        if (info_len > 0 && p_info != NULL && p_info->data != NULL) {
            eInfoValue.length = info_len;
            eInfoValue.p_data = p_info->data;
            stse_frame_push_element(&cmd_frame, &eInfoValue);
        }
    }

    /* -- OKM Map (Conditional) -- */
    if (expand_flag) {
        for (int i = 0; i < okm_count; i++) {
            stsafea_hkdf_okm_description_t *p_desc = &p_okm_map[i];
            PLAT_UI16 desc_len;

            /* Calculate Lengths and Pointers */
            if (p_desc->destination == STSAFEA_KEY_SOURCE_RESPONSE) {
                desc_len = 3; /* Dest(1) + KeyLen(2) */
                okm_desc_len_buf[i][0] = (PLAT_UI8)(desc_len >> 8);
                okm_desc_len_buf[i][1] = (PLAT_UI8)(desc_len);

                okm_key_len_buf[i][0] = (PLAT_UI8)(p_desc->response.key_length >> 8);
                okm_key_len_buf[i][1] = (PLAT_UI8)(p_desc->response.key_length);

                eOkmDescLength[i].length = 2;
                eOkmDescLength[i].p_data = okm_desc_len_buf[i];

                eOkmDestination[i].length = 1;
                eOkmDestination[i].p_data = (PLAT_UI8 *)&p_desc->destination;

                eOkmData1[i].length = 2;
                eOkmData1[i].p_data = okm_key_len_buf[i];

                eOkmData2[i].length = 0;
                eOkmData2[i].p_data = NULL;
            } else {
                if (p_desc->symmkey.key_info == NULL)
                    return STSE_SERVICE_INVALID_PARAMETER;

                desc_len = 1 + p_desc->symmkey.key_info->info_length;
                okm_desc_len_buf[i][0] = (PLAT_UI8)(desc_len >> 8);
                okm_desc_len_buf[i][1] = (PLAT_UI8)(desc_len);

                eOkmDescLength[i].length = 2;
                eOkmDescLength[i].p_data = okm_desc_len_buf[i];

                eOkmDestination[i].length = 1;
                eOkmDestination[i].p_data = (PLAT_UI8 *)&p_desc->destination;

                eOkmData1[i].length = 1;
                eOkmData1[i].p_data = (PLAT_UI8 *)&p_desc->symmkey.key_info->lock_indicator;

                eOkmData2[i].length = (p_desc->symmkey.key_info->info_length > 1) ? (p_desc->symmkey.key_info->info_length - 1) : 0;
                eOkmData2[i].p_data = (eOkmData2[i].length > 0) ? (PLAT_UI8 *)(&p_desc->symmkey.key_info->lock_indicator) + 1 : NULL;
            }
        }

        /* Push Elements */
        for (int i = 0; i < okm_count; i++) {
            stse_frame_push_element(&cmd_frame, &eOkmDescLength[i]);
            stse_frame_push_element(&cmd_frame, &eOkmDestination[i]);
            stse_frame_push_element(&cmd_frame, &eOkmData1[i]);
            if (eOkmData2[i].length > 0) {
                stse_frame_push_element(&cmd_frame, &eOkmData2[i]);
            }
        }
    }

    /* 4. Build Response Frame */
    eRspHeader.length = STSAFEA_HEADER_SIZE;
    eRspHeader.p_data = &rsp_header;
    stse_frame_push_element(&rsp_frame, &eRspHeader);

    if (extract_flag && !expand_flag) {
        eRspPrkSlot.length = 1;
        eRspPrkSlot.p_data = &p_output->prk_slot;
        stse_frame_push_element(&rsp_frame, &eRspPrkSlot);
    }

    if (expand_flag) {
        for (int i = 0; i < okm_count; i++) {
            if (p_okm_map[i].destination == STSAFEA_KEY_SOURCE_RESPONSE) {
                p_output->derived_keys[i].response.length = p_okm_map[i].response.key_length;
                eRspOkmData[i].length = p_output->derived_keys[i].response.length;
                eRspOkmData[i].p_data = p_output->derived_keys[i].response.data;
            } else {
                eRspOkmData[i].length = 1;
                eRspOkmData[i].p_data = &p_output->derived_keys[i].symmkey.slot_number;
            }
            stse_frame_push_element(&rsp_frame, &eRspOkmData[i]);
        }
    }

    /* 5. Transfer */
    ret = stsafea_frame_transfer(p_stse, &cmd_frame, &rsp_frame);

    return ret;
}
