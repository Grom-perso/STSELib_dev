/*!
 ******************************************************************************
 * \file	stsafea_entity_auth.c
 * \brief   Entity authentication services for STSAFE-A (header)
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

#ifndef STSAFE_ENTITY_AUTH_H
#define STSAFE_ENTITY_AUTH_H

#include "core/stse_device.h"
#include "core/stse_frame.h"
#include "core/stse_platform.h"
#include "core/stse_return_codes.h"
#include "core/stse_util.h"
#include "services/stsafea/stsafea_commands.h"
#include "services/stsafea/stsafea_timings.h"

/*! \defgroup stsafea_entity_auth STSAFE-A Entity authentication
 *  \ingroup stsafea_services
 *  @{
 */

/**
 * \brief 			STSAFEA generate challenge service
 * \details 		This service format and send/receive the generate challenge command/response
 * \param[in]		pSTSE 			Pointer to target STSecureElement device
 * \param[in]		challenge_size 	Challenge buffer size (expected STSE_EDDSA_CHALLENGE_SIZE)
 * \param[out]		pChallenge 		Pointer to challenge buffer
 * \return 			\ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stsafea_generate_challenge(
    stse_Handler_t *pSTSE,
    PLAT_UI8 challenge_size,
    PLAT_UI8 *pChallenge);

/**
 * \brief 			STSAFEA verify entity's signature service
 * \details 		This service format and send/receive the verify entity's signature command/response
 * \param[in]		pSTSE 				Pointer to target STSecureElement device
 * \param[in] 		slot_number 		Public key slot value
 * \param[in] 		key_type 			Targeted public key's type stored through STSAFE-A generic public slot
 * \param[out]		pSignature 			Pointer to signature buffer
 * \param[out]		pSignature_validity Pointer to signature validity byte
 * \return 			\ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stsafea_verify_entity_signature(
    stse_Handler_t *pSTSE,
    PLAT_UI8 slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *pSignature,
    PLAT_UI8 *pSignature_validity);

#ifdef STSE_CONF_STSAFE_A_SUPPORT
#include "services/stsafea/stsafea_frame_transfer_nb.h"

typedef struct {
    stse_Handler_t *pSTSE;
    stsafea_nb_transfer_ctx_t nb_ctx;
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE];
    stse_frame_t CmdFrame;
    stse_frame_element_t eCmd_header_elem;
    PLAT_UI8 rsp_header;
    stse_frame_t RspFrame;
    stse_frame_element_t eRsp_header_elem;
    stse_frame_element_t eChallenge_elem;
} stsafea_generate_challenge_ctx_t;

stse_ReturnCode_t stsafea_generate_challenge_start(
    stsafea_generate_challenge_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 challenge_size,
    PLAT_UI8 *pChallenge);

stse_ReturnCode_t stsafea_generate_challenge_transfer(stsafea_generate_challenge_ctx_t *pCtx);

stse_ReturnCode_t stsafea_generate_challenge_finalize(stsafea_generate_challenge_ctx_t *pCtx);

typedef struct {
    stse_Handler_t *pSTSE;
    stsafea_nb_transfer_ctx_t nb_ctx;
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE];
    PLAT_UI8 filler;
    PLAT_UI8 slot_number;
    PLAT_UI8 signature_length[STSE_ECC_GENERIC_LENGTH_SIZE];
    stse_frame_t CmdFrame;
    stse_frame_element_t eCmd_header_elem;
    stse_frame_element_t eFiller_elem;
    stse_frame_element_t eSlot_number_elem;
    stse_frame_element_t eSignature_R_length_elem;
    stse_frame_element_t eSignature_R_elem;
    stse_frame_element_t eSignature_S_length_elem;
    stse_frame_element_t eSignature_S_elem;
    PLAT_UI8 rsp_header;
    stse_frame_t RspFrame;
    stse_frame_element_t eRsp_header_elem;
    stse_frame_element_t eSignature_validity_elem;
} stsafea_verify_entity_signature_ctx_t;

stse_ReturnCode_t stsafea_verify_entity_signature_start(
    stsafea_verify_entity_signature_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *pSignature,
    PLAT_UI8 *pSignature_validity);

stse_ReturnCode_t stsafea_verify_entity_signature_transfer(stsafea_verify_entity_signature_ctx_t *pCtx);

stse_ReturnCode_t stsafea_verify_entity_signature_finalize(stsafea_verify_entity_signature_ctx_t *pCtx);

#endif /* STSE_CONF_STSAFE_A_SUPPORT */

/** \}*/

#endif /* STSAFE_ENTITY_AUTH_H */
