/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_char.h
 * \brief Helper API for BLE DAP characteristic R/W
 */

#ifndef __SKG_DAP_H__
#define __SKG_DAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <bluetooth/gatt.h>

/**
 * \typedef dap_char_handles_t
 * \brief Holds DAP-relevant ATT handles for quick access
 */
typedef struct dap_char_handles {
	u16_t device;
	u16_t probe;
	u16_t probe_ccc;
	u16_t syndrome;
	u16_t syndrome_ccc;
	u16_t data_relay;
	u16_t data_relay_ccc;
} dap_char_handles_t;

/**

 * \brief Sets up characteristic helper API
 */
int initCharacteristicAPI(void);

/**

 * \brief Blocking call to quickly map DAP-relevant ATTs
 * 
 * \param conn Connection object
 * \param handles Output structure for the recovered handles
 */
int bt_dap_discover(struct bt_conn *conn, dap_char_handles_t *handles);

/**

 * \brief Blocking call to write to a characteristic/descriptor
 * 
 * \param conn Connection object
 * \param params Writing parameters
 */
int bt_dap_write(struct bt_conn *conn, struct bt_gatt_write_params *params);

/**

 * \brief Blocking call to read from a characteristic/descriptor
 * 
 * \note This function performs no array safety checks
 * 
 * \param conn Connection object
 * \param params Read parameters
 * \param data Output array for read data
 * \param len Length of the read data
 */
int bt_dap_read(struct bt_conn *conn, struct bt_gatt_read_params *params,
		uint8_t *data, u16_t *len);

/**

 * \brief Blocking call to subscribe to all DAP-relevant notifiers
 * 
 * \note The params struct must stay valid through the lifetime of the
 *       subscription, otherwise errors will ocurr
 * 
 * \param conn Connection object
 * \param params Subscribe parameters
 * \param handles Full handle structure with ATT table to subscribe to
 */
int bt_dap_subscribe(struct bt_conn *conn,
		     struct bt_gatt_subscribe_params *params,
		     dap_char_handles_t *handles);

#ifdef __cplusplus
}
#endif

#endif /* __SKG_DAP_H__ */
