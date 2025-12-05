/*!
 ******************************************************************************
 * \file    stse_device_management.c
 * \brief   STSE device management API set (sources)
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

/* Includes ------------------------------------------------------------------*/
#include "api/stse_device_management.h"

/* Exported variables --------------------------------------------------------*/
#define I2C_ADDR_MAX 0x7F
#define IDLE_BUS_DELAY_MAX 0x1F

/* Exported functions --------------------------------------------------------*/
stse_return_code_t stse_init(stse_handler_t *p_stse) {
    stse_return_code_t ret = STSE_API_INVALID_PARAMETER;

    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    switch (p_stse->io.bus_type) {
#if defined(STSE_CONF_STSAFE_A_SUPPORT) || \
    (defined(STSE_CONF_STSAFE_L_SUPPORT) && defined(STSE_CONF_USE_I2C))
    case STSE_BUS_TYPE_I2C:
        ret = stse_platform_i2c_init(p_stse->io.bus_id);
        if (ret != STSE_OK) {
            return ret;
        }
        break;
#endif /* STSE_CONF_STSAFE_A_SUPPORT || (STSE_CONF_STSAFE_L_SUPPORT && defined(STSE_CONF_USE_I2C) */
#ifdef STSE_CONF_USE_ST1WIRE
    case STSE_BUS_TYPE_ST1WIRE:
        ret = stse_platform_st1wire_init(p_stse->io.bus_id);
        if (ret != STSE_OK) {
            return ret;
        }

        p_stse->io.bus_send_start = stse_platform_st1wire_send_start;
        p_stse->io.bus_send_continue = stse_platform_st1wire_send_continue;
        p_stse->io.bus_send_stop = stse_platform_st1wire_send_stop;
        p_stse->io.bus_recv_start = stse_platform_st1wire_receive_start;
        p_stse->io.bus_recv_continue = stse_platform_st1wire_receive_continue;
        p_stse->io.bus_recv_stop = stse_platform_st1wire_receive_stop;
        break;
#endif /* STSE_CONF_USE_ST1WIRE */

    default:
        return (STSE_CORE_INVALID_PARAMETER);
    }

    if (ret != STSE_OK) {
        return ret;
    }

    /* - Initialize Host platform */
    ret = stse_platform_generate_random_init();
    if (ret != STSE_OK) {
        return ret;
    }
    ret = stse_platform_delay_init();
    if (ret != STSE_OK) {
        return ret;
    }
    ret = stse_platform_power_init();
    if (ret != STSE_OK) {
        return ret;
    }
    ret = stse_platform_crc16_init();
    if (ret != STSE_OK) {
        return ret;
    }
    ret = stse_platform_crypto_init();
    if (ret != STSE_OK) {
        return ret;
    }

#ifdef STSE_CONF_STSAFE_A_SUPPORT
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (p_stse->device_type != STSAFE_L010) {
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
        stse_platform_delay_ms(stsafea_boot_time[p_stse->device_type]);

#ifndef STSE_CONF_USE_STATIC_PERSONALIZATION_INFORMATIONS
        ret = stsafea_perso_info_update(p_stse);
#endif /* STSE_CONF_USE_STATIC_PERSONALIZATION_INFORMATIONS */
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
#endif /* STSE_CONF_STSAFE_A_SUPPORT */

    return ret;
}

stse_return_code_t stse_device_enter_hibernate(stse_handler_t *p_stse,
                                              stse_hibernate_wake_up_mode_t wake_up_mode) {
    stse_return_code_t ret = STSE_API_INCOMPATIBLE_DEVICE_TYPE;

    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    switch (p_stse->device_type) {
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    case STSAFE_L010:
        ret = stsafel_hibernate(p_stse);
        break;
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    case STSAFE_A100:
    case STSAFE_A110:
    case STSAFE_A200:
        ret = stsafea_hibernate(p_stse, wake_up_mode);
        break;
    case STSAFE_A120:
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
    default:
        break;
    }

    return ret;
}

stse_return_code_t stse_device_power_on(stse_handler_t *p_stse) {
    /* - Check STSE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    /* - Check STSE power_line_on callback initialization */
    if (p_stse->io.power_line_on == NULL) {
        return (STSE_API_INVALID_PARAMETER);
    }

    /* - Power-on the device */
    p_stse->io.power_line_on(p_stse->io.bus_id, p_stse->io.devaddr);

    /* - Wait for device to boot (tboot) */
    stse_platform_delay_ms(stsafea_boot_time[p_stse->device_type]);
    return (STSE_OK);
}

stse_return_code_t stse_device_power_off(stse_handler_t *p_stse) {
    /* - Check STSE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    /* - Check STSE power_line_off callback initialization */
    if (p_stse->io.power_line_off == NULL) {
        return (STSE_API_INVALID_PARAMETER);
    }

    /* - Power-Off the device */
    p_stse->io.power_line_off(p_stse->io.bus_id, p_stse->io.devaddr);
    return (STSE_OK);
}

stse_return_code_t stse_device_echo(stse_handler_t *p_stse, PLAT_UI8 *p_in, PLAT_UI8 *p_out, PLAT_UI16 size) {
    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    switch (p_stse->device_type) {
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    case STSAFE_L010:
        return stsafel_echo(p_stse, p_in, p_out, size);
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    case STSAFE_A100:
    case STSAFE_A110:
    case STSAFE_A120:
    case STSAFE_A200:
        return stsafea_echo(p_stse, p_in, p_out, size);
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
    default:
        return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    }
}

stse_return_code_t stse_device_lock(stse_handler_t *p_stse, PLAT_UI8 *p_password, PLAT_UI8 password_length) {
    stse_return_code_t ret;
    PLAT_UI8 password_verification_status = 0;

    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (p_stse->device_type == STSAFE_L010) {
        return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    if (p_password == NULL || password_length != STSAFEA_PASSWORD_LENGTH) {
        return STSE_API_INVALID_PARAMETER;
    }

    /*- Password submission */
    ret = stsafea_verify_password(p_stse,
                                  p_password,
                                  password_length,
                                  &password_verification_status,
                                  NULL);

    if (ret != STSE_OK) {
        return ret;
    }

    if (password_verification_status == 0) {
        return STSE_API_INVALID_PARAMETER;
    }

    /* - Switch device Life-cycle to Lock */
    ret = stsafea_put_life_cyle_state(p_stse, STSAFEA_LCS_OPERATIONAL_AND_LOCKED);

    return ret;
}

stse_return_code_t stse_device_unlock(stse_handler_t *p_stse, PLAT_UI8 *p_password, PLAT_UI8 password_length) {
    stse_return_code_t ret;
    PLAT_UI8 password_verification_status = 0;
    PLAT_UI8 remaining_tries;

    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (p_stse->device_type == STSAFE_L010) {
        return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    if (p_password == NULL || password_length != STSAFEA_PASSWORD_LENGTH) {
        return STSE_API_INVALID_PARAMETER;
    }

    /*- Password submission */
    ret = stsafea_verify_password(p_stse,
                                  p_password,
                                  password_length,
                                  &password_verification_status,
                                  &remaining_tries);

    if (ret != STSE_OK) {
        return ret;
    }

    if (password_verification_status == 0) {
        return STSE_API_INVALID_PARAMETER;
    }

    /* - Switch device Life-cycle to operational */
    ret = stsafea_put_life_cyle_state(p_stse, STSAFEA_LCS_OPERATIONAL);

    return ret;
}

stse_return_code_t stse_device_reset(stse_handler_t *p_stse) {
    stse_return_code_t ret = STSE_API_INCOMPATIBLE_DEVICE_TYPE;

    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

    switch (p_stse->device_type) {
#ifdef STSE_CONF_STSAFE_L_SUPPORT
    case STSAFE_L010:
        ret = stsafel_reset(p_stse);
        break;
#endif /* STSE_CONF_STSAFE_L_SUPPORT */
#ifdef STSE_CONF_STSAFE_A_SUPPORT
    case STSAFE_A100:
    case STSAFE_A110:
    case STSAFE_A120:
    case STSAFE_A200:
        ret = stsafea_reset(p_stse);
        break;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
    default:
        break;
    }

    return ret;
}

stse_return_code_t stse_device_get_command_count(stse_handler_t *p_stse, PLAT_UI8 *p_record_count) {
    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (p_stse->device_type == STSAFE_L010) {
        return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    return stsafea_get_command_count(p_stse, p_record_count);
}

stse_return_code_t stse_device_get_command_AC_records(stse_handler_t *p_stse,
                                                     PLAT_UI8 record_count,
                                                     stse_cmd_authorization_CR_t *p_change_rights,
                                                     stse_cmd_authorization_record_t *p_record_table) {
    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (p_stse->device_type == STSAFE_L010) {
        return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    return stsafea_get_command_ac_table(p_stse, record_count, p_change_rights, p_record_table);
}

stse_return_code_t stse_device_get_life_cycle_state(stse_handler_t *p_stse,
                                                   stsafea_life_cycle_state_t *p_life_cycle_state) {
    /* - Check STSAFE handler initialization */
    if (p_stse == NULL) {
        return (STSE_API_HANDLER_NOT_INITIALISED);
    }

#ifdef STSE_CONF_STSAFE_L_SUPPORT
    if (p_stse->device_type == STSAFE_L010) {
        return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
    }
#endif /* STSE_CONF_STSAFE_L_SUPPORT */

    return stsafea_query_life_cycle_state(p_stse, p_life_cycle_state);
}

stse_return_code_t stse_put_i2c_parameters(
    stse_handler_t *p_stse,
    PLAT_UI8 i2c_address,
    stse_low_power_mode_t low_power_mode,
    PLAT_UI8 idle_bus_time_to_standby,
    PLAT_UI8 i2c_lock_parameters) {

#ifdef STSE_CONF_STSAFE_A_SUPPORT

    if (p_stse == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }

    if (i2c_address > I2C_ADDR_MAX || idle_bus_time_to_standby > IDLE_BUS_DELAY_MAX) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*Create new I2C parameters structure */
    stsafea_i2c_parameters_t i2c_param = {0};
    i2c_param.i2c_address = i2c_address;
    i2c_param.idle_bus_time_to_standby = idle_bus_time_to_standby;
    i2c_param.low_power_mode = low_power_mode;
    i2c_param.i2c_paramers_lock = i2c_lock_parameters;

    /*- Update I2C parameters*/
    return stsafea_put_i2c_parameters(p_stse, &i2c_param);
#else
    return STSE_API_INCOMPATIBLE_DEVICE_TYPE;
#endif /* STSE_CONF_STSAFE_A_SUPPORT */
}
