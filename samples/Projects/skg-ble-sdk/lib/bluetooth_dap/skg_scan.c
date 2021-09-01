/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_scan.c
 * \brief LE Scanning and filtering logic implementation
 */

#include <kernel.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>

#include <zephyr.h>

#include <settings/settings.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/services/bas.h>
#include <bluetooth/services/hrs.h>

#include "skg_scan.h"
#include "wio_uuid.h"

#include "callbacks.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(skg_scan, CONFIG_SKG_LOG_LEVEL);

#define UUID_128_BYTES              16

/**
 * Internal state
 */
static bool scanning;
static bool foundManId;
static bool foundUUID;
static s8_t lastRssi;
// static struct bt_conn *default_conn = NULL;

/**
 * Filtering definitions
 */
static struct bt_le_scan_param probeParam = {
	.type       = BT_HCI_LE_SCAN_PASSIVE,   // All data is contained in the
						// advertisement itself
	.filter_dup = BT_HCI_LE_SCAN_FILTER_DUP_DISABLE,  // Probe UUID repeats,
							  // but payload changes
	.interval   = BT_GAP_SCAN_FAST_INTERVAL,   // These should somehow match
	.window     = BT_GAP_SCAN_FAST_WINDOW,     //  the android latency
};

static u8_t wioManId[WIO_MAN_ID_LEN] = {WIO_MAN_ID};

static bool __findProbes(struct bt_data *data, void *user_data)
{
	// bt_addr_le_t *addr = user_data;

	switch (data->type) {
	case BT_DATA_UUID128_SOME:
	case BT_DATA_UUID128_ALL:
		if (data->data_len % UUID_128_BYTES != 0U) {
			LOG_DBG("AD malformed.");
			return true;
		}

		if (memcmp(data->data, wio_uuid_probe.data, UUID_128_BYTES)
			    == 0) {
			// LOG_DBG("Found UUID!.");
			foundUUID = true;
		}

		break;

	case BT_DATA_MANUFACTURER_DATA:
		if (data->data_len <= WIO_MAN_ID_LEN) {
			LOG_DBG("AD malformed.");
			return false;
		}

		if (memcmp(data->data, wioManId, WIO_MAN_ID_LEN) == 0) {
			// LOG_DBG("Found Manufacturer ID!.");
			foundManId = true;
		}

		u8_t *id = (u8_t *)data->data + WIO_MAN_ID_LEN;
		// This index corresponds to the probe id, save it and pass it
		callback_matchedProbe(lastRssi, *((uint32_t *)id));
		break;

	default:
		break;
	}

	// Check if matched
	if (foundManId && foundUUID)
		return false;

	return true;
}

static void __device_found(const bt_addr_le_t *addr, s8_t rssi, u8_t type,
			 struct net_buf_simple *ad)
{
	char dev[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(addr, dev, sizeof(dev));

	/* We're only interested in nonconnectable events */
	if (type == BT_LE_ADV_NONCONN_IND) {
		lastRssi = rssi;
		foundManId = false;
		foundUUID = false;
		bt_data_parse(ad, __findProbes, (void *)addr);
	}
}

/**
 * Public API
 */
int initScanLogic(void)
{
	scanning = false;
	foundManId = false;
	foundUUID = false;

	return 0;
}

int scanForProbes(void)
{
	int err = 0;

	if (!scanning)
		err = bt_le_scan_start(&probeParam, &__device_found);

	if (err) {
		LOG_ERR("Scan start error %d", err);
		return err;
	}

	scanning = true;

	LOG_DBG("Started Scanning");

	return 0;
}

int stopScanning(void)
{
	int err = 0;

	if (scanning)
		err = bt_le_scan_stop();

	if (err) {
		LOG_ERR("Scan stop error %d", err);
		return err;
	}

	scanning = false;

	LOG_DBG("Stopped Scanning");

	return 0;
}
