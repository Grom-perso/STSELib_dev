/*!
 ******************************************************************************
 * \file	stsafea_hash.c
 * \brief   Hash services for STSAFE-A
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

#include "services/stsafea/stsafea_hash.h"
#include "services/stsafea/stsafea_frame_transfer.h"
#include "services/stsafea/stsafea_frame_transfer_nb.h"

#ifdef STSE_CONF_STSAFE_A_SUPPORT

static PLAT_UI8 s_start_hash_cmd_header[STSAFEA_EXT_HEADER_SIZE];
static PLAT_UI8 s_start_hash_rsp_header;
static stse_frame_t s_start_hash_CmdFrame;
static stse_frame_t s_start_hash_RspFrame;
static stse_frame_element_t s_start_hash_eCmd_header;
static stse_frame_element_t s_start_hash_eHashAlgo;
static stse_frame_element_t s_start_hash_eMessage;
static stse_frame_element_t s_start_hash_eRsp_header;

static PLAT_UI8 s_process_hash_cmd_header[STSAFEA_EXT_HEADER_SIZE];
static PLAT_UI8 s_process_hash_rsp_header;
static stse_frame_t s_process_hash_CmdFrame;
static stse_frame_t s_process_hash_RspFrame;
static stse_frame_element_t s_process_hash_eCmd_header;
static stse_frame_element_t s_process_hash_eMessage;
static stse_frame_element_t s_process_hash_eRsp_header;

static PLAT_UI8 s_finish_hash_cmd_header[STSAFEA_EXT_HEADER_SIZE];
static PLAT_UI8 s_finish_hash_rsp_header;
static PLAT_UI8 s_finish_hash_digest_size_array[STSAFEA_GENERIC_LENGTH_SIZE];
static stse_hash_algorithm_t s_finish_hash_sha_algorithm;
static PLAT_UI16 *s_finish_hash_pDigest_size;
static stse_frame_t s_finish_hash_CmdFrame;
static stse_frame_t s_finish_hash_RspFrame;
static stse_frame_element_t s_finish_hash_eCmd_header;
static stse_frame_element_t s_finish_hash_eMessage;
static stse_frame_element_t s_finish_hash_eRsp_header;
static stse_frame_element_t s_finish_hash_eDigestSize;
static stse_frame_element_t s_finish_hash_eDigest;

const stsafea_hash_info_t stsafea_hash_info_table[] =
#if !defined(STSE_CONF_HASH_SHA_1) && !defined(STSE_CONF_HASH_SHA_224) &&                                       \
    !defined(STSE_CONF_HASH_SHA_256) && !defined(STSE_CONF_HASH_SHA_384) && !defined(STSE_CONF_HASH_SHA_512) && \
    !defined(STSE_CONF_HASH_SHA_3_256) && !defined(STSE_CONF_HASH_SHA_3_384) && !defined(STSE_CONF_HASH_SHA_3_512)
    {0};
#else
    {
#ifdef STSE_CONF_HASH_SHA_1
        {
            STSAFEA_SHA_1_HASH_SIZE,
            {STSAFEA_SHA1_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA_1},
        },
#endif
#ifdef STSE_CONF_HASH_SHA_224
        {
            STSAFEA_SHA_224_HASH_SIZE,
            {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA_224},
        },
#endif
#ifdef STSE_CONF_HASH_SHA_256
        {
            STSAFEA_SHA_256_HASH_SIZE,
            {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA_256},
        },
#endif
#ifdef STSE_CONF_HASH_SHA_384
        {
            STSAFEA_SHA_384_HASH_SIZE,
            {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA_384},
        },
#endif
#ifdef STSE_CONF_HASH_SHA_512
        {
            STSAFEA_SHA_512_HASH_SIZE,
            {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA_512},
        },
#endif
#ifdef STSE_CONF_HASH_SHA_3_256
        {
            STSAFEA_SHA_256_HASH_SIZE,
            {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA3_256},
        },
#endif
#ifdef STSE_CONF_HASH_SHA_3_384
        {
            STSAFEA_SHA_384_HASH_SIZE,
            {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA3_384},
        },
#endif
#ifdef STSE_CONF_HASH_SHA_3_512
        {STSAFEA_SHA_512_HASH_SIZE,
         {STSAFEA_HASH_ALGO_ID_LENGTH, STSAFEA_HASH_ALGO_ID_SHA3_512}}
#endif
};
#endif

#if defined(STSE_CONF_HASH_SHA_1) || defined(STSE_CONF_HASH_SHA_224) ||                                      \
    defined(STSE_CONF_HASH_SHA_256) || defined(STSE_CONF_HASH_SHA_384) || defined(STSE_CONF_HASH_SHA_512) || \
    defined(STSE_CONF_HASH_SHA_3_256) || defined(STSE_CONF_HASH_SHA_3_384) || defined(STSE_CONF_HASH_SHA_3_512)

stse_ReturnCode_t stsafea_start_hash(
    stse_Handler_t *pSTSE,
    stse_hash_algorithm_t sha_algorithm,
    PLAT_UI8 *pMessage,
    PLAT_UI16 message_size) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_START_HASH};
    PLAT_UI8 rsp_header;
    PLAT_UI16 hash_algo_id_length = STSAFEA_HASH_ALGO_ID_SIZE;

    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((pMessage == NULL) || (message_size == 0)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eHashAlgo, hash_algo_id_length, (PLAT_UI8 *)&stsafea_hash_info_table[sha_algorithm].id);
    stse_frame_element_allocate_push(&CmdFrame, eMessage, message_size, pMessage);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(pSTSE,
                                  &CmdFrame,
                                  &RspFrame);
}

stse_ReturnCode_t stsafea_process_hash(
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pMessage,
    PLAT_UI16 message_size) {
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_PROCESS_HASH};
    PLAT_UI8 rsp_header;

    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if ((pMessage == NULL) || (message_size == 0)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eMessage, message_size, pMessage);

    /*- Create Rsp frame and populate elements*/
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, 1, &rsp_header);

    /*- Perform Transfer*/
    return stsafea_frame_transfer(pSTSE,
                                  &CmdFrame,
                                  &RspFrame);
}

stse_ReturnCode_t stsafea_finish_hash(
    stse_Handler_t *pSTSE,
    stse_hash_algorithm_t sha_algorithm,
    PLAT_UI8 *pMessage,
    PLAT_UI16 message_size,
    PLAT_UI8 *pDigest,
    PLAT_UI16 *pDigest_size) {
    stse_ReturnCode_t ret;
    PLAT_UI8 cmd_header[STSAFEA_EXT_HEADER_SIZE] = {STSAFEA_EXTENDED_COMMAND_PREFIX, STSAFEA_EXTENDED_CMD_FINISH_HASH};
    PLAT_UI8 rsp_header;
    PLAT_UI8 digest_size_array[STSAFEA_GENERIC_LENGTH_SIZE];
    PLAT_UI16 expected_digest_size = stsafea_hash_info_table[sha_algorithm].length;

    /*- Verify Parameters */
    if (pSTSE == NULL) {
        return (STSE_SERVICE_HANDLER_NOT_INITIALISED);
    }

    if (pDigest == NULL || pDigest_size == NULL || (pMessage != NULL && message_size == 0) || (pMessage == NULL && message_size != 0)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    /*- Create CMD frame and populate elements */
    stse_frame_allocate(CmdFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header, STSAFEA_EXT_HEADER_SIZE, cmd_header);
    stse_frame_element_allocate_push(&CmdFrame, eMessage, message_size, pMessage);

    /*- Create Rsp frame and populate elements */
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header, STSAFEA_HEADER_SIZE, &rsp_header);
    stse_frame_element_allocate_push(&RspFrame, eDigestSize, STSAFEA_GENERIC_LENGTH_SIZE, digest_size_array);
    stse_frame_element_allocate_push(&RspFrame, eDigest, expected_digest_size, pDigest);

    /*- Perform Transfer*/
    ret = stsafea_frame_transfer(pSTSE,
                                 &CmdFrame,
                                 &RspFrame);

    if (ret == STSE_OK) {
        *pDigest_size = ARRAY_2B_SWAP_TO_UI16(digest_size_array);
        *pDigest_size = expected_digest_size;
    } else {
        *pDigest_size = 0;
    }

    return (ret);
}

#endif

stse_ReturnCode_t stsafea_start_hash_start(
    stse_Handler_t *pSTSE,
    stse_hash_algorithm_t sha_algorithm,
    PLAT_UI8 *pMessage,
    PLAT_UI16 message_size) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pMessage == NULL) || (message_size == 0)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_start_hash_cmd_header[0] = STSAFEA_EXTENDED_COMMAND_PREFIX;
    s_start_hash_cmd_header[1] = STSAFEA_EXTENDED_CMD_START_HASH;

    s_start_hash_CmdFrame = (stse_frame_t){0};
    s_start_hash_eCmd_header = (stse_frame_element_t){STSAFEA_EXT_HEADER_SIZE, s_start_hash_cmd_header, NULL};
    stse_frame_push_element(&s_start_hash_CmdFrame, &s_start_hash_eCmd_header);
    s_start_hash_eHashAlgo = (stse_frame_element_t){STSAFEA_HASH_ALGO_ID_SIZE, (PLAT_UI8 *)&stsafea_hash_info_table[sha_algorithm].id, NULL};
    stse_frame_push_element(&s_start_hash_CmdFrame, &s_start_hash_eHashAlgo);
    s_start_hash_eMessage = (stse_frame_element_t){message_size, pMessage, NULL};
    stse_frame_push_element(&s_start_hash_CmdFrame, &s_start_hash_eMessage);

    s_start_hash_RspFrame = (stse_frame_t){0};
    s_start_hash_eRsp_header = (stse_frame_element_t){1, &s_start_hash_rsp_header, NULL};
    stse_frame_push_element(&s_start_hash_RspFrame, &s_start_hash_eRsp_header);

    return stsafea_frame_transfer_start(pSTSE, &s_start_hash_CmdFrame, &s_start_hash_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_start_hash_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_start_hash_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_start_hash_CmdFrame, &s_start_hash_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_process_hash_start(
    stse_Handler_t *pSTSE,
    PLAT_UI8 *pMessage,
    PLAT_UI16 message_size) {
    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if ((pMessage == NULL) || (message_size == 0)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_process_hash_cmd_header[0] = STSAFEA_EXTENDED_COMMAND_PREFIX;
    s_process_hash_cmd_header[1] = STSAFEA_EXTENDED_CMD_PROCESS_HASH;

    s_process_hash_CmdFrame = (stse_frame_t){0};
    s_process_hash_eCmd_header = (stse_frame_element_t){STSAFEA_EXT_HEADER_SIZE, s_process_hash_cmd_header, NULL};
    stse_frame_push_element(&s_process_hash_CmdFrame, &s_process_hash_eCmd_header);
    s_process_hash_eMessage = (stse_frame_element_t){message_size, pMessage, NULL};
    stse_frame_push_element(&s_process_hash_CmdFrame, &s_process_hash_eMessage);

    s_process_hash_RspFrame = (stse_frame_t){0};
    s_process_hash_eRsp_header = (stse_frame_element_t){1, &s_process_hash_rsp_header, NULL};
    stse_frame_push_element(&s_process_hash_RspFrame, &s_process_hash_eRsp_header);

    return stsafea_frame_transfer_start(pSTSE, &s_process_hash_CmdFrame, &s_process_hash_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_process_hash_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_process_hash_finalize(void) {
    return stsafea_frame_transfer_finalize(&s_process_hash_CmdFrame, &s_process_hash_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_finish_hash_start(
    stse_Handler_t *pSTSE,
    stse_hash_algorithm_t sha_algorithm,
    PLAT_UI8 *pMessage,
    PLAT_UI16 message_size,
    PLAT_UI8 *pDigest,
    PLAT_UI16 *pDigest_size) {
    PLAT_UI16 expected_digest_size;

    if (pSTSE == NULL) {
        return STSE_SERVICE_HANDLER_NOT_INITIALISED;
    }
    if (pDigest == NULL || pDigest_size == NULL || (pMessage != NULL && message_size == 0) || (pMessage == NULL && message_size != 0)) {
        return STSE_SERVICE_INVALID_PARAMETER;
    }

    s_finish_hash_sha_algorithm = sha_algorithm;
    s_finish_hash_pDigest_size = pDigest_size;
    s_finish_hash_cmd_header[0] = STSAFEA_EXTENDED_COMMAND_PREFIX;
    s_finish_hash_cmd_header[1] = STSAFEA_EXTENDED_CMD_FINISH_HASH;
    expected_digest_size = stsafea_hash_info_table[sha_algorithm].length;

    s_finish_hash_CmdFrame = (stse_frame_t){0};
    s_finish_hash_eCmd_header = (stse_frame_element_t){STSAFEA_EXT_HEADER_SIZE, s_finish_hash_cmd_header, NULL};
    stse_frame_push_element(&s_finish_hash_CmdFrame, &s_finish_hash_eCmd_header);
    s_finish_hash_eMessage = (stse_frame_element_t){message_size, pMessage, NULL};
    stse_frame_push_element(&s_finish_hash_CmdFrame, &s_finish_hash_eMessage);

    s_finish_hash_RspFrame = (stse_frame_t){0};
    s_finish_hash_eRsp_header = (stse_frame_element_t){STSAFEA_HEADER_SIZE, &s_finish_hash_rsp_header, NULL};
    stse_frame_push_element(&s_finish_hash_RspFrame, &s_finish_hash_eRsp_header);
    s_finish_hash_eDigestSize = (stse_frame_element_t){STSAFEA_GENERIC_LENGTH_SIZE, s_finish_hash_digest_size_array, NULL};
    stse_frame_push_element(&s_finish_hash_RspFrame, &s_finish_hash_eDigestSize);
    s_finish_hash_eDigest = (stse_frame_element_t){expected_digest_size, pDigest, NULL};
    stse_frame_push_element(&s_finish_hash_RspFrame, &s_finish_hash_eDigest);

    return stsafea_frame_transfer_start(pSTSE, &s_finish_hash_CmdFrame, &s_finish_hash_RspFrame, &stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_finish_hash_transfer(void) {
    return stsafea_frame_transfer_check(&stsafea_nb_ctx);
}

stse_ReturnCode_t stsafea_finish_hash_finalize(void) {
    stse_ReturnCode_t ret;
    ret = stsafea_frame_transfer_finalize(&s_finish_hash_CmdFrame, &s_finish_hash_RspFrame, &stsafea_nb_ctx);
    if (ret == STSE_OK) {
        *s_finish_hash_pDigest_size = stsafea_hash_info_table[s_finish_hash_sha_algorithm].length;
    } else {
        *s_finish_hash_pDigest_size = 0;
    }
    return ret;
}

#endif /* STSE_CONF_STSAFE_A_SUPPORT */
