/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_adv.h
 * \brief Switching logic for multiple advertisements
 */

#ifndef __SKG_ADV_H__
#define __SKG_ADV_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \struct bt_skg_data
 * \brief Generic advertisement instance data structure
 */
struct bt_skg_data {
	int8_t txp;		//!< Transmit power for this instance
	uint8_t *data;		//!< Pointer to payload data
	uint8_t len;		//!< Length of the payload
};

/**

 * \brief Sets up advertising helper API
 */
int initAdvertiseLogic(void);

/**

 * \brief Advertise SKG prompt with some power and metadata
 * 
 * \note DO NOT USE THE BUILT IN ADVERTISING METHOD
 * 
 * \param prompt Advertising data
 */
int advertiseSkgPrompt(struct bt_skg_data *prompt);

/**

 * \brief Quickly dispatch interleaved advertisements
 * 
 * \note The probe array must stay valid throughout the advertising
 *       session, otherwise errors will ocurr.
 *       DO NOT USE THE BUILT IN ADVERTISING METHOD
 * 
 * \param probe Advertising data array
 * \param len Size of the advertising set
 */
int advertiseProbes(struct bt_skg_data *probe, const uint8_t len);

/**

 * \brief Gracefully stop advertising
 * 
 * \note DO NOT USE THE BUILT IN STOP ADVERTISING METHOD
 */
int stopAdvertising(void);

/**

 * \note Not implemented in API
 */
uint8_t *getPrivateIdentity(void);

/**

 * \note Not implemented in API
 */
void setPrivateIdentity(uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif /* __SKG_ADV_H__ */
