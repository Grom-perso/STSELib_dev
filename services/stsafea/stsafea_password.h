/*!
 ******************************************************************************
 * \file	stsafea_password.h
 * \brief   password services for STSAFE-A
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

#ifndef STSAFEA_PASSWORD_H
#define STSAFEA_PASSWORD_H

#include "core/stse_device.h"
#include "core/stse_frame.h"
#include "core/stse_platform.h"
#include "core/stse_return_codes.h"
#include "core/stse_util.h"
#include "services/stsafea/stsafea_commands.h"
#include "services/stsafea/stsafea_timings.h"

#define STSAFEA_PASSWORD_LENGTH 16U
#define STSAFEA_DELETE_TAG_PASSWORD 0x09

/*! \defgroup stsafea_password STSAFE-A Password management
 *  \ingroup stsafea_services
 *  @{
 */

/**
 * \brief 			STSAFEA verify password service
 * \details 		This service format and send/receive the generate random command/response
 * \param[in]		pSTSE					Pointer to target SE handler
 * \param[in]	 	pPassword_buffer 		Pointer to password buffer
 * \param[in]	 	password_length 		Password length in bytes
 * \param[out]	 	pVerification_status 	Pointer to verification status
 * \param[out]	 	pRemaining_tries 		Pointer to remaining tries
 * \return 			\ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stsafea_verify_password(stse_Handler_t *pSTSE,
                                          PLAT_UI8 *pPassword_buffer,
                                          PLAT_UI8 password_length,
                                          PLAT_UI8 *pVerification_status,
                                          PLAT_UI8 *pRemaining_tries);

/**
 * \brief 			STSAFEA delete password service
 * \details 		This service format and send/receive the generate random command/response
 * \param[in]		pSTSE					Pointer to target SE handler
 * \return 			\ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stsafea_delete_password(stse_Handler_t *pSTSE);

#ifdef STSE_CONF_STSAFE_A_SUPPORT
#include "services/stsafea/stsafea_frame_transfer_nb.h"

typedef struct {
    stse_Handler_t *pSTSE;
    stsafea_nb_transfer_ctx_t nb_ctx;
    PLAT_UI8 cmd_header;
    stse_frame_t CmdFrame;
    stse_frame_element_t eCmd_header_elem;
    stse_frame_element_t ePassword_elem;
    PLAT_UI8 rsp_header;
    stse_frame_t RspFrame;
    stse_frame_element_t eRsp_header_elem;
    stse_frame_element_t eVerStat_elem;
    stse_frame_element_t eRemTri_elem;
} stsafea_verify_password_ctx_t;

stse_ReturnCode_t stsafea_verify_password_start(
    stsafea_verify_password_ctx_t *pCtx,
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pPassword_buffer,
    PLAT_UI8 password_length,
    PLAT_UI8 *pVerification_status,
    PLAT_UI8 *pRemaining_tries);

stse_ReturnCode_t stsafea_verify_password_transfer(stsafea_verify_password_ctx_t *pCtx);

stse_ReturnCode_t stsafea_verify_password_finalize(stsafea_verify_password_ctx_t *pCtx);

typedef struct {
    stse_Handler_t *pSTSE;
    stsafea_nb_transfer_ctx_t nb_ctx;
    PLAT_UI8 cmd_header;
    PLAT_UI8 tag;
    stse_frame_t CmdFrame;
    stse_frame_element_t eCmd_header_elem;
    stse_frame_element_t eTag_elem;
    PLAT_UI8 rsp_header;
    stse_frame_t RspFrame;
    stse_frame_element_t eRsp_header_elem;
} stsafea_delete_password_ctx_t;

stse_ReturnCode_t stsafea_delete_password_start(
    stsafea_delete_password_ctx_t *pCtx,
    stse_Handler_t *pSTSE);

stse_ReturnCode_t stsafea_delete_password_transfer(stsafea_delete_password_ctx_t *pCtx);

stse_ReturnCode_t stsafea_delete_password_finalize(stsafea_delete_password_ctx_t *pCtx);

#endif /* STSE_CONF_STSAFE_A_SUPPORT */

/** \}*/

#endif /*STSAFEA_PASSWORD_H*/
