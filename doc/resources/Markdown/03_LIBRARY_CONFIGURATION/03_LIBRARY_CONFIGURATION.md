# Library Configuration

To operate, the STSELib relies on specific configuration parameters to be defined in each application project embedding the library. The configuration file (`stse_conf.h`) should be added to each project along with a path to this file in the compiler preprocessor include path.

This configuration file allows you to:
- Adjust API/Services/Core performance
- Adapt platform callbacks
- Optimize the library size

It is recommended to adjust each application configuration file according to:
- End-application requirements
- ST SecureElement type and personalization profile

The configuration of these parameters simplifies the STSELib porting requirements by helping identify the low-level callbacks to be implemented at the application level to integrate the library on a specific host MCU/MPU platform.

## Configuration File Template

Here is a typical `stse_conf.h` definition, followed by an explanation of each parameter:

```c

 /******************************************************************************
 * \file	stse_conf.h
 * \brief   STSecureElement library configuration file
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


/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef STSE_CONF_H
#define STSE_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stse_platform_generic.h"

/************************************************************
 *                STSELIB DEVICE SUPPORT
 ************************************************************/
#define STSE_CONF_STSAFE_A_SUPPORT
#define STSE_CONF_STSAFE_L_SUPPORT

/************************************************************
 *                STSAFE-A API/SERVICE SETTINGS
 ************************************************************/
#ifdef STSE_CONF_STSAFE_A_SUPPORT

/* STSAFE-A ECC services configuration */
#define STSE_CONF_ECC_NIST_P_256
#define STSE_CONF_ECC_NIST_P_384
#define STSE_CONF_ECC_NIST_P_521
#define STSE_CONF_ECC_BRAINPOOL_P_256
#define STSE_CONF_ECC_BRAINPOOL_P_384
#define STSE_CONF_ECC_BRAINPOOL_P_512
#define STSE_CONF_ECC_CURVE_25519
#define STSE_CONF_ECC_EDWARD_25519

/* STSAFE-A HASH services configuration */
#define STSE_CONF_HASH_SHA_1
#define STSE_CONF_HASH_SHA_224
#define STSE_CONF_HASH_SHA_256
#define STSE_CONF_HASH_SHA_384
#define STSE_CONF_HASH_SHA_512
#define STSE_CONF_HASH_SHA_3_256
#define STSE_CONF_HASH_SHA_3_384
#define STSE_CONF_HASH_SHA_3_512

/* STSAFE-A HOST KEY MANAGEMENT (DEVICE PAIRING) */
#define STSE_CONF_USE_HOST_SESSION
#define STSE_CONF_USE_HOST_KEY_ESTABLISHMENT
#define STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED
#define STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED

/* STSAFE-A SYMMETRIC KEY MANAGEMENT (DEVICE PAIRING) */
#define STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT
#define STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED
#define STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED
#define STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED

#endif /* STSE_CONF_STSAFE_A_SUPPORT */

/************************************************************
 *                STSAFE-L API/SERVICE SETTINGS
 ************************************************************/
#ifdef STSE_CONF_STSAFE_L_SUPPORT
#define STSE_CONF_USE_ST1WIRE

#ifndef STSE_CONF_HASH_SHA_256
#define STSE_CONF_HASH_SHA_256
#endif /*STSE_CONF_HASH_SHA_256*/

#ifndef STSE_CONF_ECC_CURVE_25519
#define STSE_CONF_ECC_CURVE_25519
#endif /*STSE_CONF_ECC_CURVE_25519*/

#ifndef STSE_CONF_ECC_EDWARD_25519
#define STSE_CONF_ECC_EDWARD_25519
#endif /*STSE_CONF_ECC_EDWARD_25519*/

#endif /* STSE_CONF_STSAFE_L_SUPPORT */


/*********************************************************
 *                COMMUNICATION SETTINGS
 *********************************************************/

#define STSE_USE_RSP_POLLING
#define STSE_MAX_POLLING_RETRY 			100
#define STSE_FIRST_POLLING_INTERVAL		10
#define STSE_POLLING_RETRY_INTERVAL		10
//#define STSE_FRAME_DEBUG_LOG

#ifdef __cplusplus
}
#endif

#endif /* STSE_CONF_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/

```


## Configuration Parameters

The following table lists all configuration parameters:


| <b>Definition</b> | <b>Description</b> | <b>Associated STSE Product Family</b>
| :----    |    :----   | :---- |
| STSE_CONF_STSAFE_A_SUPPORT | Enable STSAFE-A APIs/services support | STSAFE-A
| STSE_CONF_STSAFE_L_SUPPORT | Enable STSAFE-L APIs/services support | STSAFE-L
| STSE_CONF_ECC_NIST_P_256 | Enable ECC NIST-P256 support in API/services/platform | STSAFE-A / STSAFE-L
| STSE_CONF_ECC_NIST_P_384 | Enable ECC NIST-P384 support in API/services/platform | STSAFE-A
| STSE_CONF_ECC_NIST_P_521 | Enable ECC NIST-P521 support in API/services/platform | STSAFE-A
| STSE_CONF_ECC_BRAINPOOL_P_256 | Enable ECC NIST-P256 support in API/services/platform | STSAFE-A
| STSE_CONF_ECC_BRAINPOOL_P_384 | Enable ECC NIST-P384 support in API/services/platform | STSAFE-A
| STSE_CONF_ECC_BRAINPOOL_P_512 | Enable ECC NIST-P512 support in API/services/platform | STSAFE-A
| STSE_CONF_ECC_CURVE_25519 | Enable CURVE25519 support in API/services/platform | STSAFE-A / STSAFE-L
| STSE_CONF_ECC_EDWARD_25519 | Enable ED25519 support in API/services/platform | STSAFE-A / STSAFE-L
| STSE_CONF_HASH_SHA_1 | Enable SHA-1 support in API/services/platform | STSAFE-A
| STSE_CONF_HASH_SHA_224 | Enable SHA224 support in API/services/platform | STSAFE-A
| STSE_CONF_HASH_SHA_256 | Enable SHA256 support in API/services/platform | STSAFE-A
| STSE_CONF_HASH_SHA_384 | Enable SHA384 support in API/services/platform | STSAFE-A
| STSE_CONF_HASH_SHA_512 | Enable SHA512 support in API/services/platform | STSAFE-A
| STSE_CONF_HASH_SHA_3_256 | Enable SHA3-256 support in API/services/platform | STSAFE-A
| STSE_CONF_HASH_SHA_3_384 | Enable SHA3-384 support in API/services/platform | STSAFE-A
| STSE_CONF_HASH_SHA_3_512 | Enable SHA3-512 support in API/services/platform | STSAFE-A
| STSE_CONF_USE_HOST_SESSION | Enable Host session support in services/platform | STSAFE-A
| STSE_CONF_USE_HOST_KEY_ESTABLISHMENT | Enable Host key establishment support via ECDH and key derivation | STSAFE-A
| STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED | Enable Host key secure provisioning using KEK wrapped exchange | STSAFE-A
| STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED  | Enable Host key secure provisioning using KEK wrapped exchange and authentication | STSAFE-A
| STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT | Enable symmetric key establishment support via key exchange , ECDH and key derivation | STSAFE-A
| STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED | Enable symmetric key establishment support via authenticated key exchange , ECDH and key derivation | STSAFE-A
| STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED | Enable symmetric key secure provisioning using KEK wrapped exchange | STSAFE-A
| STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED | Enable symmetric key secure provisioning using authenticated KEK wrapped exchange | STSAFE-A
| STSE_CONF_USE_ST1WIRE | Enable ST1Wire communication protocol support | STSAFE-L
| STSE_USE_RSP_POLLING | Enable STSE response polling (see section below) | STSAFE-A / STSAFE-L
| STSE_MAX_POLLING_RETRY | Max polling retry definition (see section below) | STSAFE-A / STSAFE-L
| STSE_FIRST_POLLING_INTERVAL | First polling delay definition in ms (see section below) | STSAFE-A / STSAFE-L
| STSE_POLLING_RETRY_INTERVAL | Polling retry interval definition in ms (see section below) | STSAFE-A / STSAFE-L
| STSE_FRAME_DEBUG_LOG | Enable HOST<->STSE communication logs | STSAFE-A / STSAFE-L
