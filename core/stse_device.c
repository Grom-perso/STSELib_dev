/*!
 * ******************************************************************************
 * \file	stse_device.c
 * \brief   STSAFE Frame layer (sources)
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

#include "core/stse_device.h"
#include "core/stse_platform.h"
#include <string.h>

stse_ReturnCode_t stse_set_default_handler_value(stse_Handler_t *pStseHandler) {
    if (pStseHandler == NULL) {
        return STSE_CORE_HANDLER_NOT_INITIALISED;
    }

    pStseHandler->device_type = (stse_device_t)0;
    memset(&pStseHandler->perso_info, 0, sizeof(pStseHandler->perso_info));
    pStseHandler->pActive_host_session = NULL;
    pStseHandler->pActive_other_session = NULL;
    pStseHandler->io.bus_recv_start = stse_platform_i2c_receive_start;
    pStseHandler->io.bus_recv_continue = stse_platform_i2c_receive_continue;
    pStseHandler->io.bus_recv_stop = stse_platform_i2c_receive_stop;
    pStseHandler->io.bus_send_start = stse_platform_i2c_send_start;
    pStseHandler->io.bus_send_continue = stse_platform_i2c_send_continue;
    pStseHandler->io.bus_send_stop = stse_platform_i2c_send_stop;
    pStseHandler->io.io_line_get = NULL;
    pStseHandler->io.bus_wake = stse_platform_i2c_wake;
    pStseHandler->io.bus_recovery = NULL;
    pStseHandler->io.power_line_off = stse_platform_power_off;
    pStseHandler->io.power_line_on = stse_platform_power_on;
    pStseHandler->io.busID = 0;
    pStseHandler->io.devaddr = 0x20;
    pStseHandler->io.bus_speed = 100;
#if defined(STSE_CONF_STSAFE_A_SUPPORT) || \
    (defined(STSE_CONF_STSAFE_L_SUPPORT) && defined(STSE_CONF_USE_I2C))
    pStseHandler->io.bus_type = STSE_BUS_TYPE_I2C;
#endif /* STSE_CONF_STSAFE_A_SUPPORT || (STSE_CONF_STSAFE_L_SUPPORT && defined(STSE_CONF_USE_I2C) */
    return STSE_OK;
}
