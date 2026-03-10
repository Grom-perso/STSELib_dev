/*!
 ******************************************************************************
 * \file    stse_ecc.c
 * \brief   STSE ECC API set (sources)
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

#include "api/stse_ecc.h"

stse_return_code_t stse_ecc_verify_signature(
    stse_handler_t *p_stse,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *p_public_key,
    PLAT_UI8 *p_signature,
    PLAT_UI8 *p_message,
    PLAT_UI16 message_length,
    PLAT_UI8 eddsa_variant,
    PLAT_UI8 *pSignature_validity) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    stse_return_code_t ret;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    /* - Check device type */
    if (p_stse->device_type == STSAFE_L010) {
        return (STSE_API_INCOMPATIBLE_DEVICE_TYPE);
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    if (p_public_key == NULL || p_signature == NULL || p_message == NULL || pSignature_validity == NULL) {
        return (STSE_API_INVALID_PARAMETER);
    }

    ret = stsafea_ecc_verify_signature(p_stse, key_type, p_public_key, p_signature, p_message, message_length, eddsa_variant, pSignature_validity);

    return ret;
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_ecc_generate_signature(
    stse_handler_t *p_stse,
    PLAT_UI8 slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *p_message,
    PLAT_UI16 message_length,
    PLAT_UI8 *p_signature) {
    stse_return_code_t ret;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    if (p_message == NULL || p_signature == NULL) {
        return (STSE_API_INVALID_PARAMETER);
    }

    switch (p_stse->device_type) {
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    case STSAFE_L010:
        ret = stsafel_ecc_generate_signature(p_stse, key_type, p_message, message_length, p_signature);
        break;
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    case STSAFE_A100:
    case STSAFE_A110:
    case STSAFE_A120:
    case STSAFE_A200:
        ret = stsafea_ecc_generate_signature(p_stse, slot_number, key_type, p_message, message_length, p_signature);
        break;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
    default:
        return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    }

    return ret;
}

stse_return_code_t stse_ecc_establish_shared_secret(
    stse_handler_t *p_stse,
    PLAT_UI8 private_key_slot_number,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *p_public_key,
    PLAT_UI8 *pShared_secret) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    stse_return_code_t ret;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    /* - Check device type */
    if (p_stse->device_type == STSAFE_L010) {
        return (STSE_API_INCOMPATIBLE_DEVICE_TYPE);
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    if (p_public_key == NULL || pShared_secret == NULL) {
        return (STSE_API_INVALID_PARAMETER);
    }

    ret = stsafea_ecc_establish_shared_secret(p_stse, private_key_slot_number, key_type, p_public_key, pShared_secret);

    return ret;
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}

stse_return_code_t stse_ecc_decompress_public_key(
    stse_handler_t *p_stse,
    stse_ecc_key_type_t key_type,
    PLAT_UI8 point_representation_id,
    PLAT_UI8 *pPublic_key_X,
    PLAT_UI8 *pPublic_key_Y) {
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    stse_return_code_t ret;

    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    /* - Check device type */
    if (p_stse->device_type == STSAFE_L010) {
        return (STSE_API_INCOMPATIBLE_DEVICE_TYPE);
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    if (pPublic_key_X == NULL || pPublic_key_Y == NULL) {
        return (STSE_API_INVALID_PARAMETER);
    }

    ret = stsafea_ecc_decompress_public_key(p_stse, key_type, point_representation_id, pPublic_key_X, pPublic_key_Y);

    return ret;
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}
