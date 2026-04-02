/*!
 ******************************************************************************
 * \file	stsafea_hash.h
 * \brief   Hash services for STSAFE-A
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

#ifndef STSAFEA_WRAP_UNWRAP_H
#define STSAFEA_WRAP_UNWRAP_H

#include "core/stse_device.h"
#include "core/stse_frame.h"
#include "core/stse_platform.h"
#include "core/stse_return_codes.h"
#include "core/stse_util.h"
#include "services/stsafea/stsafea_commands.h"
#include "services/stsafea/stsafea_sessions.h"
#include "services/stsafea/stsafea_timings.h"

/*! \defgroup stsafea_wrap STSAFE-A Wrap/Un-wrap
 *  \ingroup stsafea_services
 *  \{
 */

/**
 * \brief 		STSAFEA wrap service
 * \details 	This service format and send STSAFEA wrap command/response to target STSE
 * \param[in]	pSTSE					Pointer to target SE handler
 * \param[in]	wrap_key_slot			Wrap key slot
 * \param[in] 	pPayload				Pointer to the payload buffer to be wrapped
 * \param[in]	payload_size			size of the payload buffer
 * \param[out] 	pWrapped_Payload		Pointer to the wrapped payload buffer
 * \param[in]	wrapped_payload_size	size of the wrapped payload buffer
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stsafea_wrap_payload(
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size);

/**
 * \brief 		STSAFEA un-wrap service
 * \details 	This service format and send STSAFEA un-wrap command/response to target STSE
 * \param[in]	pSTSE					Pointer to target SE handler
 * \param[in]	wrap_key_slot			wrap key slot
 * \param[in]	pWrapped_Payload		Pointer to the wrapped payload buffer to be un-wrapped
 * \param[in]	wrapped_payload_size	Size of the wrapped payload buffer
 * \param[out]	pPayload				Pointer to the plain text payload buffer
 * \param[in]	payload_size			Size of the payload buffer
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stsafea_unwrap_payload(
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size);

#ifdef STSE_CONF_STSAFE_A_SUPPORT
#include "services/stsafea/stsafea_frame_transfer_nb.h"

typedef struct {
    stse_Handler_t *pSTSE;
    stsafea_nb_transfer_ctx_t nb_ctx;
    PLAT_UI8 cmd_header;
    PLAT_UI8 wrap_key_slot;
    stse_frame_t CmdFrame;
    stse_frame_element_t eCmd_header_elem;
    stse_frame_element_t eSlot_number_elem;
    stse_frame_element_t ePayload_elem;
    PLAT_UI8 rsp_header;
    stse_frame_t RspFrame;
    stse_frame_element_t eRsp_header_elem;
    stse_frame_element_t eWrapped_elem;
} stsafea_wrap_payload_ctx_t;

stse_ReturnCode_t stsafea_wrap_payload_start(
    stsafea_wrap_payload_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size);

stse_ReturnCode_t stsafea_wrap_payload_transfer(stsafea_wrap_payload_ctx_t *pCtx);

stse_ReturnCode_t stsafea_wrap_payload_finalize(stsafea_wrap_payload_ctx_t *pCtx);

typedef struct {
    stse_Handler_t *pSTSE;
    stsafea_nb_transfer_ctx_t nb_ctx;
    PLAT_UI8 cmd_header;
    PLAT_UI8 wrap_key_slot;
    stse_frame_t CmdFrame;
    stse_frame_element_t eCmd_header_elem;
    stse_frame_element_t eSlot_number_elem;
    stse_frame_element_t ePayload_elem;
    PLAT_UI8 rsp_header;
    stse_frame_t RspFrame;
    stse_frame_element_t eRsp_header_elem;
    stse_frame_element_t eWrapped_elem;
} stsafea_unwrap_payload_ctx_t;

stse_ReturnCode_t stsafea_unwrap_payload_start(
    stsafea_unwrap_payload_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 wrap_key_slot,
    PLAT_UI8 *pWrapped_Payload,
    PLAT_UI16 wrapped_payload_size,
    PLAT_UI8 *pPayload,
    PLAT_UI16 payload_size);

stse_ReturnCode_t stsafea_unwrap_payload_transfer(stsafea_unwrap_payload_ctx_t *pCtx);

stse_ReturnCode_t stsafea_unwrap_payload_finalize(stsafea_unwrap_payload_ctx_t *pCtx);

#endif /* STSE_CONF_STSAFE_A_SUPPORT */

/** \}*/

#endif /*STSAFEA_WRAP_UNWRAP_H*/
