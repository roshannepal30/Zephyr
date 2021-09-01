/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */
/**
 * \file relay_service.c
 * \brief Zephyr Relay Detection Service implementation.
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/printk.h>
#include <sys/byteorder.h>
#include <zephyr.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include "../wio_uuid.h"
#include "../callbacks.h"

#include "services.h"
#include "challenge_settings.h"

#include <logging/log.h>
LOG_MODULE_DECLARE(bt_dap, CONFIG_SKG_LOG_LEVEL);

static u8_t data[20];

static ssize_t write_data(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			  const void *buf, u16_t len, u16_t offset, u8_t flags)
{
	u8_t *value = attr->user_data;

	if (offset + len > sizeof(data))
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);

	memcpy(value + offset, buf, len);
	callback_wroteRelayData(data, len);

	return len;
}

static void ccc_cfg_changed_data(const struct bt_gatt_attr *attr,
				  u16_t value)
{
	ARG_UNUSED(attr);

	bool notif_enabled = (value == BT_GATT_CCC_NOTIFY);

	LOG_DBG("Relay Data Notifications %s",
		notif_enabled ? "enabled" : "disabled");

	if (notif_enabled)
		callback_clientSubscribed();
}

/* Current Time Service Declaration */
BT_GATT_SERVICE_DEFINE(relay_svc,
	BT_GATT_PRIMARY_SERVICE(&wio_uuid_relay),
	BT_GATT_CHARACTERISTIC(
		&wio_uuid_relay_data.uuid,
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
		BT_GATT_PERM_WRITE_AUTHEN,
		NULL, write_data, data),
	BT_GATT_CCC(
		ccc_cfg_changed_data,
		BT_GATT_PERM_WRITE),
);

int notify_relayData(struct bt_conn *conn, const u8_t *rData, const u8_t len)
{
	int err = 0;

	if (len > sizeof(data))
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);

	memcpy(data, rData, len);

	err = bt_gatt_notify(NULL, &relay_svc.attrs[1], &data, len);

	return err;
}

inline void __rlsvc_stub_init(void)
{
	/* Nothing to do here */
}
