/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */
/**
 * \file skg_service.c
 * \brief Zephyr SKG Service implementation.
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <init.h>
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

#include "recon_settings.h"

#include "services.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(wio_services, CONFIG_SKG_LOG_LEVEL);

static u8_t probe_val[1];
static u8_t pid[WIO_DEVICE_PID_BYTE_LEN + 2];
static u8_t synd[MAX_CHAR_LEN];

static ssize_t read_device(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     void *buf, u16_t len, u16_t offset)
{
	const char *value = attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, 0,
				 value + WIO_DEVICE_PID_BYTE_LEN + 1, 1);
}

static ssize_t write_device(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr, const void *buf,
			    u16_t len, u16_t offset, u8_t flags)
{
	u8_t *value = attr->user_data;

	if (offset + len > sizeof(pid))
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);

	if (len != WIO_DEVICE_PID_BYTE_LEN + 1)
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_REQ_REJECTED);

	memcpy(value + offset, buf, len);

	callback_wrotePID(value);

	return len;
}

static void ccc_cfg_changed_probe(const struct bt_gatt_attr *attr,
				     u16_t value)
{
	ARG_UNUSED(attr);

	bool notif_enabled = (value == BT_GATT_CCC_NOTIFY);

	LOG_DBG("Probe Notifications %s",
		notif_enabled ? "enabled" : "disabled");
}

static ssize_t write_probe(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf, u16_t len, u16_t offset,
			      u8_t flags)
{
	u8_t *value = attr->user_data;

	if (offset + len > sizeof(probe_val))
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);

	memcpy(value + offset, buf, len);
	callback_wroteProbe(probe_val[0]);

	return len;
}

static void ccc_cfg_changed_syndrome(const struct bt_gatt_attr *attr,
				     u16_t value)
{
	ARG_UNUSED(attr);

	bool notif_enabled = (value == BT_GATT_CCC_NOTIFY);

	LOG_DBG("Syndrome Notifications %s",
		notif_enabled ? "enabled" : "disabled");
}

static ssize_t write_syndrome(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf, u16_t len, u16_t offset,
			      u8_t flags)
{
	u8_t *value = attr->user_data;

	if (offset + len > sizeof(synd))
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);

	memcpy(value + offset, buf, len);
	callback_wroteSyndrome(synd, len);

	return len;
}

/* SKG Service Declaration */
BT_GATT_SERVICE_DEFINE(skg_svc,
	BT_GATT_PRIMARY_SERVICE(&wio_uuid_skg),

	BT_GATT_CHARACTERISTIC(
		&wio_uuid_skg_device.uuid,
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_READ,
		BT_GATT_PERM_WRITE | BT_GATT_PERM_READ,
		read_device, write_device, pid),

	BT_GATT_CHARACTERISTIC(
		&wio_uuid_skg_probe.uuid,
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
		BT_GATT_PERM_WRITE,
		NULL, write_probe, probe_val),
	BT_GATT_CCC(
		ccc_cfg_changed_probe,
		BT_GATT_PERM_WRITE),

	BT_GATT_CHARACTERISTIC(
		&wio_uuid_skg_syndrome.uuid,
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
		BT_GATT_PERM_WRITE,
		NULL, write_syndrome, synd),
	BT_GATT_CCC(
		ccc_cfg_changed_syndrome,
		BT_GATT_PERM_WRITE)
);

void set_capaPID(uint8_t capa)
{
	pid[WIO_DEVICE_PID_BYTE_LEN + 1] = capa;
}

int notify_probe(struct bt_conn *conn, u8_t val)
{
	int err = 0;

	probe_val[0] = val;

	err = bt_gatt_notify(conn, &skg_svc.attrs[3], &probe_val, 1);

	return err;
}

int notify_syndrome(struct bt_conn *conn, const u8_t *syndrome, const u8_t len,
	const u8_t repeats)
{
	int err = 0;

	for (uint8_t i = 0 ; i < repeats ; ++i)
		memcpy(synd + (len * i), syndrome + (MAX_CODEWORDS * i), len);

	err = bt_gatt_notify(conn, &skg_svc.attrs[6], &synd, len * repeats);

	return err;
}

inline void __skgsvc_stub_init(void)
{
	/* Nothing to do here */
}
