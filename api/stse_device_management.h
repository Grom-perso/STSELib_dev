
/*!
 *******************************************************************************
 * \file	stse_device_management.h
 * \brief   STSE SE Management API (header)
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
#ifndef STSAFE_SE_MANAGEMENT_H
#define STSAFE_SE_MANAGEMENT_H

/* Includes ------------------------------------------------------------------*/

#include "core/stse_device.h"
#include "core/stse_return_codes.h"

#include "services/stsafea/stsafea_commands.h"
#include "services/stsafea/stsafea_echo.h"
#include "services/stsafea/stsafea_low_power.h"
#include "services/stsafea/stsafea_password.h"
#include "services/stsafea/stsafea_put_query.h"
#include "services/stsafea/stsafea_reset.h"

#include "services/stsafel/stsafel_echo.h"
#include "services/stsafel/stsafel_low_power.h"
#include "services/stsafel/stsafel_reset.h"

/** \defgroup 	stse_device_management 	STSE Device Management
 *  \ingroup 	stse_api
 *  \brief		STSecureElement middleware device Management API
 *  \details  	The Application Programming Interface (API) layer is the entry point for the upper system application layer. \n
 *  			It provides high level functions to the application layer for secure element management.
 *  @{
 */

/*!
 * \enum stse_low_power_mode_t
 * STSAFEA Low power mode type
 */
typedef enum stse_low_power_mode_t {
    STSE_LPM_NONE = 0,    /*!< No low power mode */
    STSE_LPM_STANDBY = 2, /*!< Standby power mode */
} stse_low_power_mode_t;

/* Exported Functions  ------------------------------------------------------------*/

/**
 * \brief 		Initialize target device
 * \details 	This function call the handler initialization function from core layer
 *          	to initialize STSE handler in argument
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 * \details 	\include{doc} stse_init.dox
 */
stse_ReturnCode_t stse_init(stse_Handler_t *p_stse);

/**
 * \brief 		Reset target device
 * \details 	This function call reset service to reset the device
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_device_reset(stse_Handler_t *p_stse);

/**
 * \brief 		Put target device in hibernate mode
 * \details 	This function call hibernate service to put the device in hibernate
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \param[in]	wake_up_mode 		Event to wake up from,
 * 									listed in enum \ref stse_hibernate_wake_up_mode_t
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_device_enter_hibernate(stse_Handler_t *p_stse, stse_hibernate_wake_up_mode_t wake_up_mode);

/**
 * \brief 		Power-on target device
 * \details 	This function power-on the target device
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_device_power_on(stse_Handler_t *p_stse);

/**
 * \brief 		Power-off target device
 * \details 	This function power-off the target device
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 * \details 	Please refer to stse_device_power_on()
 */
stse_ReturnCode_t stse_device_power_off(stse_Handler_t *p_stse);

/**
 * \brief 		Send echo command
 * \details 	This function call send service to send an echo command
 * \param[in]  	p_stse 			Pointer to STSE Handler
 * \param[in]  	p_in 				Pointer to data buffer to be sent
 * \param[out] 	p_out 				Pointer to received data buffer
 * \param[in]  	size 				Size in bytes of p_in buffer
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 * \details 	\include{doc} stse_device_echo.dox
 */
stse_ReturnCode_t stse_device_echo(stse_Handler_t *p_stse, PLAT_UI8 *p_in, PLAT_UI8 *p_out, PLAT_UI16 size);

/**
 * \brief 		Lock target device
 * \details 	This function lock the target device using the password in argument
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \param[in] 	p_password 			Pointer to the password buffer
 * \param[in]	password_length 	Length of the password buffer in bytes
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 * \details 	\include{doc} stse_device_lock.dox
 */
stse_ReturnCode_t stse_device_lock(stse_Handler_t *p_stse, PLAT_UI8 *p_password, PLAT_UI8 password_length);

/**
 * \brief 		Unlock target device
 * \details 	This function unlock the target device using the password in argument
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \param[in] 	p_password 			Pointer to the password buffer
 * \param[in]	password_length 	Length of the password buffer in bytes
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 * \details 	\include{doc} stse_device_unlock.dox
 */
stse_ReturnCode_t stse_device_unlock(stse_Handler_t *p_stse, PLAT_UI8 *p_password, PLAT_UI8 password_length);

/**
 * \brief 		Return the record count of command access conditions
 * \details 	This function query the access conditions
 * 				of the target device command set and return the number of records
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \param[out] 	record_count 		Command authorization records count
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 * \details 	Please refer to stse_device_get_command_AC()
 */
stse_ReturnCode_t stse_device_get_command_count(stse_Handler_t *p_stse, PLAT_UI8 *record_count);

/**
 * \brief 		Return the command access conditions and change right
 * \details 	This function query the access conditions
 * 				of the target device command set
 * \param[in] 	p_stse 			Pointer to STSE Handler
 * \param[in] 	record_count 		Command authorization records count
 * \param[out] 	p_change_rights 		Pointer to change rights structure of the commands AC and host encrytpion flag
 * \param[out] 	p_record_table 		Command authorization records table
 * \return \ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 * \details 	\include{doc} stse_device_get_command_AC.dox
 */
stse_ReturnCode_t stse_device_get_command_AC_records(stse_Handler_t *p_stse,
                                                     PLAT_UI8 record_count,
                                                     stse_cmd_authorization_CR_t *p_change_rights,
                                                     stse_cmd_authorization_record_t *p_record_table);

/**
 * \brief 		Return the command access conditions and change right
 * \details 	This function query the access conditions of the target device command set
 * \param[in] 	p_stse 					Pointer to STSE Handler
 * \param[out] 	p_life_cycle_state 		Pointer to \ref stsafea_life_cycle_state_t variable to be updated
 * \return 		\ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_device_get_life_cycle_state(stse_Handler_t *p_stse,
                                                   stsafea_life_cycle_state_t *p_life_cycle_state);

/**
 * \brief 		STSE put I2C parameters API
 * \details 	This API format and send/receive the put I2C parameters command/response
 * \param[in] 	p_stse 						Pointer to STSE Handler
 * \param[in] 	i2c_address 				I2C address (Max 0x7F)
 * \param[in] 	low_power_mode 				Low power mode (0: none, otherwise standby)
 * \param[in] 	idle_bus_time_to_standby 	For standby, period of time without any command processing and with I2C bus idle until the chip enters standby mode. Coded in 50ms steps, starting from 50ms as floor value (0: 50ms, 1: 100ms, ..., 31: 1600ms)
 * \param[in] 	i2c_lock_parameters 		Lock I2C configuration defined by other parameters (0: none, otherwise lock)
 * \return 		\ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_put_i2c_parameters(
    stse_Handler_t *p_stse,
    PLAT_UI8 i2c_address,
    stse_low_power_mode_t low_power_mode,
    PLAT_UI8 idle_bus_time_to_standby,
    PLAT_UI8 i2c_lock_parameters);

/** \}*/

#endif /* STSE_SE_MANAGEMENT_H */
