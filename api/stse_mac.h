/*!
 ******************************************************************************
 * \file	stse_mac.h
 * \brief   STSE MAC API set (header)
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2023 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#ifndef STSE_MAC_H
#define STSE_MAC_H

/* Includes ------------------------------------------------------------------*/
#include "services/stsafea/stsafea_aes.h"
#include "services/stsafea/stsafea_mac.h"

/** \defgroup 	stse_mac 	STSE MAC cryptography
 *  \ingroup 	stse_api
 *  \brief		STSE Message Authentication Code (MAC) API set
 *  \details  	The Message Authentication Code (MAC) API set provides high level functions to MAC generation/verification.
 *  \{
 */

/**
 * \brief 		Generate a CMAC
 * \details 	This service format and send Generate CMAC command
 * \param[in] 	p_stse 		Pointer to STSE Handler
 * \param[in] 	slot_number 	Key slot in symmetric key table to be used
 * \param[in]	p_message		Plaintext message
 * \param[in]	message_length	Plaintext message length
 * \param[out] 	p_mac 			Buffer to store the MAC
 * \param[out]	mac_length		MAC length (CMAC:2,4,8,16 / HMAC:16-32)
 * \return \ref STSE_OK on success ; \ref stse_return_code_t error code otherwise
 */
stse_return_code_t stse_cmac_hmac_compute(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 *p_message,
    PLAT_UI8 message_length,
    PLAT_UI8 *p_mac,
    PLAT_UI8 mac_length);

/**
 * \brief 		Verify a CMAC
 * \details 	This service format and send Verify CMAC command
 * \param[in] 	p_stse 				Pointer to STSE Handler
 * \param[in] 	slot_number 			Key slot in symmetric key table to be used
 * \param[in] 	p_mac 					Buffer containing the MAC
 * \param[in]	mac_length				MAC length (CMAC:2,4,8,16 / HMAC:16-32)
 * \param[in]	p_message				Plaintext message
 * \param[in]	message_length			Plaintext message length
 * \param[out]	verification_result		Verification result flag
 * \return \ref STSE_OK on success ; \ref stse_return_code_t error code otherwise
 */
stse_return_code_t stse_cmac_hmac_verify(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 *p_mac,
    PLAT_UI8 mac_length,
    PLAT_UI8 *p_message,
    PLAT_UI8 message_length,
    PLAT_UI8 *verification_result);

/**
 * \brief 		Generate a GMAC
 * \details 	This service format and send Generate GMAC command
 * \param[in] 	p_stse 						Pointer to STSE Handler
 * \param[in] 	slot_number 				Key slot in symmetric key table to be used
 * \param[in]	iv_length					IV buffer length in bytes
 * \param[in]	p_iv							IV buffer
 * \param[in]	associated_data_length		Length of the associated data
 * \param[in]	p_associated_data			Buffer containing associated data
 * \param[in] 	authentication_tag_length 	Expected length for the authentication tag
 * \param[out]	p_authentication_tag			Buffer to store the authentication tag
 * \return \ref STSE_OK on success ; \ref stse_return_code_t error code otherwise
 */
stse_return_code_t stse_aes_gmac_compute(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *p_associated_data,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *p_authentication_tag);

/**
 * \brief 		Verify a GMAC
 * \details 	This service format and send Verify GMAC command
 * \param[in] 	p_stse 						Pointer to STSE Handler
 * \param[in] 	slot_number 				Key slot in symmetric key table to be used
 * \param[in]	iv_length					IV buffer length in bytes
 * \param[in]	p_iv							IV buffer
 * \param[in]	associated_data_length		Length of the associated data
 * \param[in]	p_associated_data			Buffer containing associated data
 * \param[in] 	authentication_tag_length 	Expected length for the authentication tag
 * \param[in]	p_authentication_tag			Buffer containing the authentication tag
 * \param[out]	p_verification_result		Verification result flag
 * \return \ref STSE_OK on success ; \ref stse_return_code_t error code otherwise
 */
stse_return_code_t stse_aes_gmac_verify(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *p_associated_data,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *p_authentication_tag,
    PLAT_UI8 *p_verification_result);

/** @}*/

#endif /*STSE_MAC_H*/
