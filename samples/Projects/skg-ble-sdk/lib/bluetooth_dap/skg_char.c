/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_char.c
 * \brief Helper API for BLE DAP characteristic R/W
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <errno.h>
#include <zephyr.h>

#include <sys/printk.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/gap.h>

#include "skg_char.h"
#include "wio_uuid.h"

#include "callbacks.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(skg_char, CONFIG_SKG_LOG_LEVEL);

#define DISCOVER_TIMEOUT_MS		K_MSEC(1200)
#define RW_TIMEOUT_MS			K_MSEC(200)

/**
 * Scheduling
 */
static struct k_sem attr_sem;

static int err_cb;
static u8_t *data_cb;
static u16_t *len_cb;

static u8_t probe_val[1];
static u8_t synd[MAX_CHAR_LEN];
static u8_t relay_data[MAX_CHAR_LEN];

static struct bt_gatt_discover_params discover_params;

static struct bt_uuid_128 uuid_gatt_ccc;

static dap_char_handles_t *local_handles;

static uint8_t count;

/**
 * Attribute discovery helpers
 */
static u8_t __discover_skg(struct bt_conn *conn,
			   const struct bt_gatt_attr *attr,
			   struct bt_gatt_discover_params *params)
{
	int err;

	if (!attr) {
		LOG_ERR("Failed to find attribute!\n");
		k_sem_give(&attr_sem);
		return BT_GATT_ITER_STOP;
	}

	switch (count) {
	case 0:
		// LOG_DBG("Found skg %d!", attr->handle);

		discover_params.uuid = &wio_uuid_skg_device.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			LOG_ERR("Discover failed (err %d)", err);

		break;

	case 1:
		// LOG_DBG("Found device characteristic %d!", attr->handle);

		discover_params.uuid = &wio_uuid_skg_probe.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

		local_handles->device = bt_gatt_attr_value_handle(attr);

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			LOG_ERR("Discover failed (err %d)", err);

		break;

	case 2:
		// LOG_DBG("Found probe characteristic %d!", attr->handle);

		discover_params.uuid = &uuid_gatt_ccc.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;

		local_handles->probe = bt_gatt_attr_value_handle(attr);

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			LOG_ERR("Discover failed (err %d)", err);

		break;

	case 3:
		// LOG_DBG("Found probe descriptor %d!", attr->handle);

		discover_params.uuid = &wio_uuid_skg_syndrome.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

		local_handles->probe_ccc = attr->handle;

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			LOG_ERR("Discover failed (err %d)", err);

		break;

	case 4:
		// LOG_DBG("Found syndrome characteristic %d!", attr->handle);

		discover_params.uuid = &uuid_gatt_ccc.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;

		local_handles->syndrome = bt_gatt_attr_value_handle(attr);

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			LOG_ERR("Discover failed (err %d)", err);

		break;

	case 5:
		// LOG_DBG("Found syndrome descriptor %d!", attr->handle);

		local_handles->syndrome_ccc = attr->handle;

		k_sem_give(&attr_sem);

		return BT_GATT_ITER_STOP;

	default:
		break;
	}

	count++;

	return BT_GATT_ITER_STOP;
}

static u8_t __discover_relay(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	int err;

	if (!attr) {
		LOG_ERR("Failed to find attribute!\n");
		k_sem_give(&attr_sem);
		return BT_GATT_ITER_STOP;
	}

	switch (count) {
	case 0:
		// LOG_DBG("Found relay %d!", attr->handle);

		discover_params.uuid = &wio_uuid_relay_data.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			LOG_ERR("Discover failed (err %d)", err);

		break;

	case 1:
		// LOG_DBG("Found relay data %d!", attr->handle);

		discover_params.uuid = &uuid_gatt_ccc.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;

		local_handles->data_relay = bt_gatt_attr_value_handle(attr);

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			LOG_ERR("Discover failed (err %d)", err);

		break;

	case 2:
		// LOG_DBG("Found relay data descriptor %d!", attr->handle);

		local_handles->data_relay_ccc = attr->handle;

		k_sem_give(&attr_sem);

		return BT_GATT_ITER_STOP;

	default:
		break;
	}

	count++;

	return BT_GATT_ITER_STOP;
}

/**
 * R/W Characteristic helpers
 */
static void __write_callback(struct bt_conn *conn, u8_t err,
			     struct bt_gatt_write_params *params)
{
	err_cb = err;

	LOG_DBG("Wrote %d bytes to %d", params->length, params->handle);

	/* Allow next call */
	k_sem_give(&attr_sem);
}

static u8_t __read_callback(struct bt_conn *conn, u8_t err,
			    struct bt_gatt_read_params *params,
			    const void *data, u16_t length)
{
	err_cb = err;

	if (data) {
		*len_cb = length;
		memcpy(data_cb, data, length);
	} else {
		LOG_DBG("Read %d bytes from %d", *len_cb,
			params->single.handle);

		/* Allow next call */
		k_sem_give(&attr_sem);
	}

	return length;
}

/**
 * Notification helpers
 */
static u8_t __notify_probe(struct bt_conn *conn,
			   struct bt_gatt_subscribe_params *params,
			   const void *data, u16_t length)
{
	if (!data) {
		LOG_DBG("Probe Notifications disabled");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}

	if (length != 1) {
		LOG_WRN("Malformed Probe notification! len: %d", length);
		return BT_GATT_ITER_CONTINUE;
	}

	memcpy(probe_val, data, length);
	callback_wroteProbe(probe_val[0]);

	return BT_GATT_ITER_CONTINUE;
}

static u8_t __notify_syndrome(struct bt_conn *conn,
			   struct bt_gatt_subscribe_params *params,
			   const void *data, u16_t length)
{
	if (!data) {
		LOG_DBG("Syndrome Notifications disabled");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}

	memcpy(synd, data, length);
	callback_wroteSyndrome(synd, length);

	return BT_GATT_ITER_CONTINUE;
}

static u8_t __notify_data_relay(struct bt_conn *conn,
			   struct bt_gatt_subscribe_params *params,
			   const void *data, u16_t length)
{
	if (!data) {
		LOG_DBG("Relay Data Notifications disabled");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}

	memcpy(relay_data, data, length);
	callback_wroteRelayData(relay_data, length);

	return BT_GATT_ITER_CONTINUE;
}

/**
 * Public API
 */
int initCharacteristicAPI(void)
{
	struct bt_uuid *ccc_bt_uuid = BT_UUID_GATT_CCC;

	k_sem_init(&attr_sem, 1, 1);
	memcpy(&uuid_gatt_ccc, ccc_bt_uuid, sizeof(uuid_gatt_ccc));

	LOG_DBG("Initialized Characteristic API Logic.");
	return 0;
}

int bt_dap_discover(struct bt_conn *conn, dap_char_handles_t *handles)
{
	int err;

	if (handles == NULL || conn == NULL)
		return -EINVAL;

	/* Only one gatt operation permitted at a time */
	err = k_sem_take(&attr_sem, DISCOVER_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	memset(handles, 0, sizeof(dap_char_handles_t));

	/* Discover skg service */
	discover_params.uuid = &wio_uuid_skg.uuid;
	discover_params.func = __discover_skg;
	discover_params.start_handle = 0x0001;
	discover_params.end_handle = 0xffff;
	discover_params.type = BT_GATT_DISCOVER_PRIMARY;

	local_handles = handles;
	count = 0;

	LOG_DBG("Starting discovery!");

	err = bt_gatt_discover(conn, &discover_params);
	if (err) {
		k_sem_give(&attr_sem);
		LOG_ERR("Discover failed (err %d)", err);
		return err;
	}

	/* Wait for discover to finish */
	err = k_sem_take(&attr_sem, DISCOVER_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	if (!(handles->device && handles->probe && handles->probe_ccc &&
	      handles->syndrome && handles->syndrome_ccc)) {
		/* We missed a handle, abort */
		k_sem_give(&attr_sem);
		LOG_ERR("Discover missed skg attributes");
		return -ENXIO;
	}

	/* Discover relay service */
	discover_params.uuid = &wio_uuid_relay.uuid;
	discover_params.func = __discover_relay;
	discover_params.start_handle = 0x0001;
	discover_params.type = BT_GATT_DISCOVER_PRIMARY;

	count = 0;

	err = bt_gatt_discover(conn, &discover_params);
	if (err) {
		k_sem_give(&attr_sem);
		LOG_ERR("Discover failed (err %d)", err);
		return err;
	}

	/* Wait for discover to finish */
	err = k_sem_take(&attr_sem, DISCOVER_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	if (!(handles->data_relay && handles->data_relay_ccc)) {
		/* We missed a handle, abort */
		k_sem_give(&attr_sem);
		LOG_ERR("Discover missed relay attributes");
		return -ENXIO;
	}

	local_handles = NULL;

	/* Allow next call */
	k_sem_give(&attr_sem);

	LOG_DBG("Finished discovery!");

	return 0;
}

int bt_dap_write(struct bt_conn *conn, struct bt_gatt_write_params *params)
{
	int err;

	if (conn == NULL || params == NULL)
		return -EINVAL;

	params->func = __write_callback;
	params->offset = 0;

	err_cb = 0;

	/* Only one gatt operation permitted at a time */
	err = k_sem_take(&attr_sem, RW_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	err = bt_gatt_write(conn, params);
	if (err) {
		k_sem_give(&attr_sem);
		LOG_ERR("Failed to write to %d (err %d)", params->handle, err);
		return err;
	}

	/* Wait for op to finish */
	err = k_sem_take(&attr_sem, RW_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	if (err_cb) {
		LOG_ERR("Failed to write to %d (err %d)",
			params->handle, err_cb);
	}

	/* Allow next call */
	k_sem_give(&attr_sem);

	return err_cb;
}

int bt_dap_read(struct bt_conn *conn, struct bt_gatt_read_params *params,
		uint8_t *data, u16_t *len)
{
	int err;

	if (conn == NULL || params == NULL)
		return -EINVAL;

	params->func = __read_callback;
	params->single.offset = 0;
	params->handle_count = 1;

	err_cb = 0;
	data_cb = data;
	len_cb = len;

	/* Only one gatt operation permitted at a time */
	err = k_sem_take(&attr_sem, RW_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	err = bt_gatt_read(conn, params);
	if (err) {
		k_sem_give(&attr_sem);
		LOG_ERR("Failed to read from %d (err %d)",
			params->single.handle, err);
		return err;
	}

	/* Wait for op to finish */
	err = k_sem_take(&attr_sem, RW_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	if (err_cb) {
		LOG_ERR("Failed to read from %d (err %d)",
			params->single.handle, err_cb);
	}

	/* Allow next call */
	k_sem_give(&attr_sem);

	return err_cb;
}

int bt_dap_subscribe(struct bt_conn *conn,
		     struct bt_gatt_subscribe_params *params,
		     dap_char_handles_t *handles)
{
	int err;

	if (conn == NULL || params == NULL || handles == NULL)
		return -EINVAL;

	/* Only one gatt operation permitted at a time */
	err = k_sem_take(&attr_sem, RW_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Failed to acquire sem (err %d)", err);
		return err;
	}

	/* Subscribe Probe */
	params[0].notify = __notify_probe;
	params[0].value_handle = handles->probe;
	params[0].ccc_handle = handles->probe_ccc;
	params[0].value = BT_GATT_CCC_NOTIFY;

	err = bt_gatt_subscribe(conn, &params[0]);
	if (err && err != -EALREADY) {
		LOG_ERR("Probe Subscribe failed (err %d)", err);
		return err;
	}

	LOG_DBG("Probe Notifications Enabled");

	/* Subscribe Syndrome */
	params[1].notify = __notify_syndrome;
	params[1].value_handle = handles->syndrome;
	params[1].ccc_handle = handles->syndrome_ccc;
	params[1].value = BT_GATT_CCC_NOTIFY;

	err = bt_gatt_subscribe(conn, &params[1]);
	if (err && err != -EALREADY) {
		LOG_ERR("Syndrome Subscribe failed (err %d)", err);
		return err;
	}

	LOG_DBG("Syndrome Notifications Enabled");

	/* Subscribe Relay Data */
	params[2].notify = __notify_data_relay;
	params[2].value_handle = handles->data_relay;
	params[2].ccc_handle = handles->data_relay_ccc;
	params[2].value = BT_GATT_CCC_NOTIFY;

	err = bt_gatt_subscribe(conn, &params[2]);
	if (err && err != -EALREADY) {
		LOG_ERR("Relay Data Subscribe failed (err %d)", err);
		return err;
	}

	LOG_DBG("Relay Data Notifications Enabled");

	/* Allow next call */
	k_sem_give(&attr_sem);

	return 0;
}
