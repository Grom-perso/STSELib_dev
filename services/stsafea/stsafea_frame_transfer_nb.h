/*!
 ******************************************************************************
 * \file    stsafea_frame_transfer_nb.h
 * \brief   STSAFE-A non-blocking frame transfer layer (header)
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
 *
 * \defgroup stsafea_frame_nb Non-Blocking Frame Transfer
 * \ingroup  stsafea_services
 * \brief    Three-phase non-blocking frame transfer for STSAFE-A services.
 *
 * Every service command is split into three steps so that the host MCU is
 * never blocked waiting for the STSAFE-A to finish its internal processing:
 *
 *  1. **_start**  – validate parameters, build frames, transmit the command
 *                   and record the send timestamp.
 *  2. **_transfer** – return \ref STSE_PLATFORM_PENDING while the
 *                   inter-frame delay has not yet elapsed; return \ref STSE_OK
 *                   as soon as the device is ready to be read.  This step
 *                   performs no I²C activity and completes in < 1 µs.
 *  3. **_finalize** – read the response frame and verify its CRC / status.
 *
 * Typical applicative state-machine usage:
 * \code
 *   stsafea_echo_start(pSTSE, msg, rsp, len);
 *   while (stsafea_echo_transfer() == STSE_PLATFORM_PENDING);
 *   ret = stsafea_echo_finalize();
 * \endcode
 *
 * @{
 */

#ifndef STSAFEA_FRAME_TRANSFER_NB_H
#define STSAFEA_FRAME_TRANSFER_NB_H

#include "core/stse_device.h"
#include "core/stse_frame.h"
#include "core/stse_platform.h"
#include "core/stse_return_codes.h"
#include "core/stse_util.h"
#include "services/stsafea/stsafea_aes.h"
#include "services/stsafea/stsafea_commands.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_timings.h"

#ifdef STSE_CONF_USE_HOST_SESSION
#include "services/stsafea/stsafea_sessions.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Non-blocking encrypted response payload limit.
 * When STSE_CONF_USE_HOST_SESSION is enabled and a session uses encryption,
 * the response ciphertext must be buffered between _start and _finalize.
 * The buffer is sized for the largest possible STSAFE-A frame (A120 = 752 B)
 * plus one AES block of padding (16 B).
 * -------------------------------------------------------------------------*/
#define STSAFEA_NB_MAX_ENCRYPTED_PAYLOAD_SIZE (STSAFEA_MAX_FRAME_LENGTH_A120 + 16U)

/**
 * \brief   Non-blocking transfer context.
 *
 * Embed this struct inside every per-service non-blocking context.  It carries
 * all state required between _start, _transfer and _finalize.
 *
 * The _transfer step actively polls the device by attempting a single I²C read.
 * If the device NACKs it returns \ref STSE_PLATFORM_PENDING; when the device
 * ACKs the first read (header + length bytes) the data is stored here so that
 * _finalize can perform the second-pass data read immediately without delay.
 * Pacing between _transfer calls is entirely controlled by the application.
 */
typedef struct {
    stse_Handler_t *pSTSE;           /*!< Device handler used by _transfer for bus polling  */
    PLAT_UI8  received_header;        /*!< RSP status/header byte read during _transfer       */
    PLAT_UI8  received_length_raw[STSE_FRAME_LENGTH_SIZE]; /*!< Raw 2-byte length from _transfer */
#ifdef STSE_CONF_USE_HOST_SESSION
    PLAT_UI8                    cmd_encryption_flag;  /*!< 1 = command payload was encrypted   */
    PLAT_UI8                    rsp_encryption_flag;  /*!< 1 = response payload is encrypted    */
    stse_cmd_access_conditions_t cmd_ac_info;          /*!< Access-condition for session MAC     */
    PLAT_UI8  Cmd_MAC[STSAFEA_MAC_SIZE];              /*!< C-MAC buffer                         */
    PLAT_UI8  Rsp_MAC[STSAFEA_MAC_SIZE];              /*!< R-MAC buffer                         */
    stse_frame_element_t eCmdMAC;                     /*!< Frame element wrapping Cmd_MAC       */
    stse_frame_element_t eRspMAC;                     /*!< Frame element wrapping Rsp_MAC       */
    /* Encrypted RSP payload (needed from _start strap-setup to _finalize decrypt) */
    PLAT_UI8             encrypted_rsp_payload[STSAFEA_NB_MAX_ENCRYPTED_PAYLOAD_SIZE];
    PLAT_UI16            encrypted_rsp_payload_size;
    stse_frame_element_t eEncrypted_rsp_payload;      /*!< Frame element for enc. rsp payload   */
    stse_frame_element_t S2;                          /*!< Strap element inserted on RspFrame   */
#endif /* STSE_CONF_USE_HOST_SESSION */
} stsafea_nb_transfer_ctx_t;
#define STSAFEA_NB_CTX_T_DEFINED

/* -------------------------------------------------------------------------
 * Low-level non-blocking frame-transfer API (raw – no session handling)
 * -------------------------------------------------------------------------*/

/**
 * \brief   Start a raw non-blocking frame transfer (no session).
 * \details Transmits \p pCmdFrame and stores the device handler in \p pNbCtx
 *          so that \ref stsafea_frame_transfer_check can poll the device.
 *          Use this when calling the session-free path (equivalent of
 *          \ref stsafea_frame_raw_transfer).
 * \param[in]  pSTSE     Pointer to STSE handler
 * \param[in]  pCmdFrame Pointer to the pre-built command frame
 * \param[out] pNbCtx    Pointer to the non-blocking context to fill
 * \return \ref STSE_OK on success; error code otherwise
 */
stse_ReturnCode_t stsafea_frame_raw_transfer_start(stse_Handler_t *pSTSE,
                                                   stse_frame_t *pCmdFrame,
                                                   stsafea_nb_transfer_ctx_t *pNbCtx);

/**
 * \brief   Poll device readiness (raw or session path).
 * \details Attempts a single I²C read of the response header and length bytes.
 *          Returns \ref STSE_PLATFORM_PENDING while the device NACKs (still
 *          processing); returns \ref STSE_OK once the device ACKs and the
 *          header + length bytes have been stored in \p pNbCtx for use by the
 *          subsequent _finalize call.  No delay is applied — the application
 *          state machine is responsible for pacing repeated calls.
 * \param[in,out] pNbCtx  Pointer to the non-blocking context
 * \return \ref STSE_OK when ready; \ref STSE_PLATFORM_PENDING if not yet ready;
 *         other \ref stse_ReturnCode_t on bus error
 */
stse_ReturnCode_t stsafea_frame_transfer_check(stsafea_nb_transfer_ctx_t *pNbCtx);

/**
 * \brief   Finalize a raw non-blocking frame transfer (no session).
 * \details Uses the response header and length already captured by
 *          \ref stsafea_frame_transfer_check to perform the second-pass
 *          I²C data read and validate the CRC.  Must be called only after
 *          \ref stsafea_frame_transfer_check has returned \ref STSE_OK.
 * \param[in,out] pNbCtx   Non-blocking context containing the pre-read header/length
 * \param[in,out] pRspFrame Pointer to the pre-built response frame
 * \return \ref STSE_OK on success; error code otherwise
 */
stse_ReturnCode_t stsafea_frame_raw_transfer_finalize(stsafea_nb_transfer_ctx_t *pNbCtx,
                                                      stse_frame_t *pRspFrame);

/* -------------------------------------------------------------------------
 * Session-capable non-blocking frame-transfer API
 * -------------------------------------------------------------------------*/

/**
 * \brief   Start a session-capable non-blocking frame transfer.
 * \details Mirrors \ref stsafea_frame_transfer for the transmit phase:
 *          looks up the inter-frame timing, performs any required session
 *          pre-processing (C-MAC computation, command encryption), transmits
 *          the frame and stores \p pSTSE in \p pNbCtx so that
 *          \ref stsafea_frame_transfer_check can poll the device.
 * \param[in]  pSTSE     Pointer to STSE handler
 * \param[in]  pCmdFrame Pointer to the pre-built command frame
 * \param[in,out] pRspFrame Pointer to the pre-built response frame (needed
 *                for session strap setup)
 * \param[out] pNbCtx   Pointer to the non-blocking context to fill
 * \return \ref STSE_OK on success; error code otherwise
 */
stse_ReturnCode_t stsafea_frame_transfer_start(stse_Handler_t *pSTSE,
                                               stse_frame_t *pCmdFrame,
                                               stse_frame_t *pRspFrame,
                                               stsafea_nb_transfer_ctx_t *pNbCtx);

/**
 * \brief   Finalize a session-capable non-blocking frame transfer.
 * \details Uses the response header and length captured by
 *          \ref stsafea_frame_transfer_check to perform the second-pass
 *          data read, then applies session post-processing (R-MAC
 *          verification, response decryption).  Must be called only after
 *          \ref stsafea_frame_transfer_check has returned \ref STSE_OK.
 * \param[in,out] pCmdFrame Pointer to the command frame (needed to pop C-MAC
 *                          in authenticated-session mode)
 * \param[in,out] pRspFrame Pointer to the response frame
 * \param[in]     pNbCtx    Pointer to the non-blocking context
 * \return \ref STSE_OK on success; error code otherwise
 */
stse_ReturnCode_t stsafea_frame_transfer_finalize(stse_frame_t *pCmdFrame,
                                                  stse_frame_t *pRspFrame,
                                                  stsafea_nb_transfer_ctx_t *pNbCtx);

extern stsafea_nb_transfer_ctx_t stsafea_nb_ctx;

/*! @} */

#ifdef __cplusplus
}
#endif

#endif /* STSAFEA_FRAME_TRANSFER_NB_H */
