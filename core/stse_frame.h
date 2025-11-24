/*!
 * ******************************************************************************
 * \file	stse_frame.h
 * \brief   STSAFE Frame layer (header)
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

/*! \defgroup stse_frame Frame Management
 *  \ingroup stse_core
 *  @{
 */

#ifndef STSAFE_FRAME_H
#define STSAFE_FRAME_H

#include "core/stse_device.h"
#include "core/stse_platform.h"
#include "core/stse_return_codes.h"
#include "core/stse_util.h"

#define STSE_FRAME_CRC_SIZE 2U
#define STSE_FRAME_LENGTH_SIZE 2U
#define STSE_RSP_FRAME_HEADER_SIZE 1U
#define STSE_STSAFEA_RSP_STATUS_MASK 0x1F
#define STSE_STSAFEL_RSP_STATUS_MASK 0x0F

/**
 * \brief Default maximum number of elements in command frame array
 * \details Can be overridden by defining STSE_CONF_CMD_FRAME_MAX_ELEMENTS in stse_conf.h
 */
#ifndef STSE_CONF_CMD_FRAME_MAX_ELEMENTS
#define STSE_CONF_CMD_FRAME_MAX_ELEMENTS 16U
#endif

/**
 * \brief Default maximum number of elements in response frame array
 * \details Can be overridden by defining STSE_CONF_RSP_FRAME_MAX_ELEMENTS in stse_conf.h
 */
#ifndef STSE_CONF_RSP_FRAME_MAX_ELEMENTS
#define STSE_CONF_RSP_FRAME_MAX_ELEMENTS 16U
#endif

typedef struct stse_frame_t stse_frame_t;
typedef struct stse_frame_element_t stse_frame_element_t;

/**
 * \brief Frame element structure
 * \details Represents a single element in a frame with its data pointer and length
 */
struct stse_frame_element_t {
    PLAT_UI16 length;    /*!< Length of the element data */
    PLAT_UI8 *pData;     /*!< Pointer to the element data */
};

/**
 * \brief Frame structure using array-based element storage
 * \details Contains an array of frame elements and metadata for frame management
 */
struct stse_frame_t {
    PLAT_UI8 element_count;  /*!< Current number of elements in the frame */
    PLAT_UI16 length;        /*!< Total length of all element data in the frame */
    PLAT_UI8 max_elements;   /*!< Maximum number of elements allowed in this frame */
    stse_frame_element_t *pElements;  /*!< Pointer to the array of frame elements */
};

typedef enum {
    STSAFE_FRAME_PLAINTEXT = 0,
    STSAFE_FRAME_ENCRYPT
} stse_frame_encrypt_flag_t;

/**
 * \brief RAM arrays for command and response frame elements
 */
extern stse_frame_element_t stse_cmd_frame_elements[STSE_CONF_CMD_FRAME_MAX_ELEMENTS];
extern stse_frame_element_t stse_rsp_frame_elements[STSE_CONF_RSP_FRAME_MAX_ELEMENTS];

/**
 * \brief RAM variables for tracking element counts
 */
extern PLAT_UI8 stse_cmd_frame_element_count;
extern PLAT_UI8 stse_rsp_frame_element_count;

/**
 * \brief Allocate a command frame using the global command frame element array
 */
#define stse_frame_allocate(frame) \
    stse_cmd_frame_element_count = 0; \
    stse_frame_t frame = {0, 0, STSE_CONF_CMD_FRAME_MAX_ELEMENTS, stse_cmd_frame_elements};

/**
 * \brief Allocate a response frame using the global response frame element array
 */
#define stse_rsp_frame_allocate(frame) \
    stse_rsp_frame_element_count = 0; \
    stse_frame_t frame = {0, 0, STSE_CONF_RSP_FRAME_MAX_ELEMENTS, stse_rsp_frame_elements};

/**
 * \brief Allocate a frame element (for temporary/local use)
 */
#define stse_frame_element_allocate(element, len, data) \
    stse_frame_element_t element = {len, data};

/**
 * \brief Allocate a frame element and push it to the frame
 */
#define stse_frame_element_allocate_push(pFrame, element, len, data) \
    stse_frame_element_t element = {len, data}; \
    stse_frame_push_element(pFrame, &element);

/**
 * \brief Allocate a strap element (for temporary/local use)
 */
#define stse_frame_strap_allocate(strap) \
    stse_frame_element_t strap = {0, NULL};

/**
 * \brief Create and insert a strap between two elements
 */
#define stse_frame_strap(pFrame, strap, pBaseElement, pStrappedElement) \
    stse_frame_strap_allocate(strap);                                   \
    stse_frame_insert_strap(pFrame, &strap, pBaseElement, pStrappedElement);    \
    stse_frame_update(pFrame);

/**
 * \brief 			Attach a strap element that reroute a frame element (Element1) to another (Element2)
 * \details 		This core function attach a strap element that link Element1 to Element2 until un-strap command is executed
 * \param[in] 		pFrame 			Pointer to the frame
 * \param[in] 		pStrap 			Pointer to strap element
 * \param[in] 		pElement_1 		Pointer to frame element 1
 * \param[in] 		pElement_2 		Pointer to frame element 2
 */
void stse_frame_insert_strap(stse_frame_t *pFrame, stse_frame_element_t *pStrap, stse_frame_element_t *pElement_1,
                             stse_frame_element_t *pElement_2);

/**
 * \brief 			Frame un-strap
 * \details 		This core function remove strap element from a frame
 * \param[in] 		pFrame 			Pointer to a frame
 */
void stse_frame_unstrap(stse_frame_t *pFrame);

/**
 * \brief 			Update frame meta data
 * \details 		This core function update frame structure
 * \param[in,out] 	pFrame 	Pointer to the frame to be updated
 */
void stse_frame_update(stse_frame_t *pFrame);

/**
 * \brief 			Compute Frame CRC
 * \details 		This core function compute and return the CRC of a Frame
 * \param[in] 		pFrame 			Pointer to frame
 * \param[in] 		pCrc 			Pointer to crc (2-byte CRC value)
 * \return 			\ref STSE_OK on success ; \ref stse_ReturnCode_t error code otherwise
 */
stse_ReturnCode_t stse_frame_crc16_compute(stse_frame_t *pFrame, PLAT_UI16 *pCrc);

/**
 * \brief 			swap the Data byte order pointed by pData frame element
 * \details 		This core function swap the Data byte order pointed/defined by pData and length value from frame
 * \param[in] 		pElement 			Pointer to frame element
 */
void stse_frame_element_swap_byte_order(stse_frame_element_t *pElement);

/**
 * \brief 			Push frame element into frame
 * \details 		This core function set selected element as the frame last one
 * \param[in] 		pFrame 				Pointer to frame
 * \param[in] 		pElement 			Pointer to frame element
 */
void stse_frame_push_element(stse_frame_t *pFrame,
                             stse_frame_element_t *pElement);

/**
 * \brief 			Pop last element from frame
 * \details 		This core function remove the last element from frame
 * \param[in,out] 	pFrame 				Pointer to frame
 */
void stse_frame_pop_element(stse_frame_t *pFrame);

/**
 * \brief 			Frame debug print
 * \details 		This core function print the content of a frame
 * \param[in,out] 	pFrame 				Pointer to the frame to be printed
 */
void stse_frame_debug_print(stse_frame_t *pFrame);

/**
 * \brief 			Get frame element at specified index
 * \details 		This core function returns the pointer to a frame element at the given index
 * \param[in] 		pFrame 				Pointer to frame
 * \param[in] 		index 				Index of the element to get
 * \return 			Pointer to the frame element, or NULL if index is out of bounds
 */
stse_frame_element_t *stse_frame_get_element(stse_frame_t *pFrame, PLAT_UI8 index);

/**
 * \brief 			Get first element of the frame
 * \details 		This core function returns the pointer to the first element in the frame
 * \param[in] 		pFrame 				Pointer to frame
 * \return 			Pointer to the first frame element, or NULL if frame is empty
 */
stse_frame_element_t *stse_frame_get_first_element(stse_frame_t *pFrame);

/**
 * \brief 			Get last element of the frame
 * \details 		This core function returns the pointer to the last element in the frame
 * \param[in] 		pFrame 				Pointer to frame
 * \return 			Pointer to the last frame element, or NULL if frame is empty
 */
stse_frame_element_t *stse_frame_get_last_element(stse_frame_t *pFrame);

/**
 * \brief 			Get next element after the given element
 * \details 		This core function returns the pointer to the next element in the frame
 * \param[in] 		pFrame 				Pointer to frame
 * \param[in] 		pElement 			Pointer to current element
 * \return 			Pointer to the next frame element, or NULL if there is no next element
 */
stse_frame_element_t *stse_frame_get_next_element(stse_frame_t *pFrame, stse_frame_element_t *pElement);

/*! @}*/

#endif /* STSAFE_FRAME_H */
