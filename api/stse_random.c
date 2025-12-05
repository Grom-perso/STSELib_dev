/*!
 ******************************************************************************
 * \file	stse_random.c
 * \brief   STSE Random API set (sources)
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

#include "api/stse_random.h"

stse_return_code_t stse_generate_random(
    stse_handler_t *p_stse,
    PLAT_UI8 *p_random,
    PLAT_UI16 random_size) {
    stse_return_code_t ret = STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    /* - Check stsafe handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    if (p_random == NULL) {
        return (STSE_API_INVALID_PARAMETER);
    }

#ifdef STSE_CONF_STSAFE_A_SUPPORT
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (p_stse->device_type != STSAFE_L010) {
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
        for (PLAT_UI16 index = 0; index < random_size;) {
            ret = stsafea_generate_random(
                p_stse,
                &p_random[index],
                ((random_size - index) < STSAFEA_MAXIMUM_RNG_SIZE) ? (random_size - index) : STSAFEA_MAXIMUM_RNG_SIZE);

            if (ret != STSE_OK) {
                break;
            }

            index += STSAFEA_MAXIMUM_RNG_SIZE;
        }
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
#endif /* STSE_CONF_STSAFE_A_SUPPORT */

    return ret;
}
