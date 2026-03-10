/*!
 ******************************************************************************
 * \file	stse_mac.c
 * \brief   STSE MAC API set (sources)
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
 *****************************************************************************/

#include "api/stse_mac.h"

stse_return_code_t stse_cmac_hmac_compute(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 *p_message,
    PLAT_UI8 message_length,
    PLAT_UI8 *p_mac,
    PLAT_UI8 mac_length) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_cmac_hmac_compute(p_stse, slot_number, p_message, message_length, p_mac, mac_length);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_cmac_hmac_verify(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI8 *p_mac,
    PLAT_UI8 mac_length,
    PLAT_UI8 *p_message,
    PLAT_UI8 message_length,
    PLAT_UI8 *verification_result) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_cmac_hmac_verify(p_stse, slot_number, p_mac, mac_length, p_message, message_length, verification_result);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gmac_compute(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *pAssociated_data,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *pAuthentication_tag) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gmac_compute(p_stse, slot_number, iv_length, p_iv, associated_data_length, pAssociated_data, authentication_tag_length, pAuthentication_tag);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_aes_gmac_verify(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    PLAT_UI16 iv_length,
    PLAT_UI8 *p_iv,
    PLAT_UI16 associated_data_length,
    PLAT_UI8 *pAssociated_data,
    PLAT_UI8 authentication_tag_length,
    PLAT_UI8 *pAuthentication_tag,
    PLAT_UI8 *pVerification_result) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    return stsafea_aes_gmac_verify(p_stse, slot_number, iv_length, p_iv, associated_data_length, pAssociated_data, authentication_tag_length, pAuthentication_tag, pVerification_result);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}
