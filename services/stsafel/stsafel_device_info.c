/*!
 ******************************************************************************
 * \file	stsafel_device_info.c
 * \brief   Device info services for STSAFE-L
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

#include "services/stsafel/stsafel_device_info.h"
#include "services/stsafel/stsafel_commands.h"
#include "services/stsafel/stsafel_frame_transfer.h"

#ifdef STSE_CONF_STSAFE_L_SUPPORT

stse_ReturnCode_t stsafel_get_device_UID(
    stse_Handler_t *p_stse,
    PLAT_UI8 *p_device_uid) {
    return stsafel_get_data(
        p_stse,
        STSAFEL_INFO_UNIQUE_IDENTIFIER,
        0,
        NULL,
        STSAFEL_UID_LENGTH,
        p_device_uid);
}

stse_ReturnCode_t stsafel_get_device_traceability(
    stse_Handler_t *p_stse,
    stsafel_device_traceability_t *p_device_traceability) {
    return stsafel_get_data(
        p_stse,
        STSAFEL_INFO_TRACEABILITY_DATA,
        0,
        NULL,
        sizeof(stsafel_device_traceability_t),
        (PLAT_UI8 *)p_device_traceability);
}

stse_ReturnCode_t stsafel_get_data(
    stse_Handler_t *p_stse,
    stsafel_device_info_tag_t tag,
    PLAT_UI16 additional_data_length,
    PLAT_UI8 *p_additional_data,
    PLAT_UI16 device_info_expected_length,
    PLAT_UI8 *p_device_info) {
    PLAT_UI8 cmd_header = STSAFEL_CMD_GET_DATA;
    PLAT_UI8 rsp_header;

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if ((p_additional_data == NULL && additional_data_length != 0) ||
        (p_device_info == NULL)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEL_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eTag, 1, (PLAT_UI8 *)&tag);
    stse_frame_element_allocate_push(&CmdFrame, eAdditional_data, additional_data_length, p_additional_data);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEL_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&Rsp_frame, eDevice_info, device_info_expected_length, p_device_info);

    /*- Perform Transfer*/
    return stsafel_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

stse_ReturnCode_t stsafel_put_data(
    stse_Handler_t *p_stse,
    stsafel_device_info_tag_t tag,
    PLAT_UI16 device_info_length,
    PLAT_UI8 *p_device_info) {
    PLAT_UI8 cmd_header = STSAFEL_CMD_PUT_DATA;
    PLAT_UI8 rsp_header;

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if (p_device_info == NULL) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEL_HEADER_SIZE, &cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eTag, 1, (PLAT_UI8 *)&tag);
    stse_frame_element_allocate_push(&CmdFrame, eDevice_info, device_info_length, p_device_info);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(Rsp_frame);
    stse_frame_element_allocate_push(&Rsp_frame, eRsp_header, STSAFEL_HEADER_SIZE, &rsp_header);

    /*- Perform Transfer*/
    return stsafel_frame_transfer(p_stse,
                                  &CmdFrame,
                                  &Rsp_frame);
}

#endif /* STSE_CONF_STSAFE_L_SUPPORT */
