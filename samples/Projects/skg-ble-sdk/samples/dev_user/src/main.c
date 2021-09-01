/* main.c - Application main entry point */

/*
 * Copyright (c) 2018-2020, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

#include <zephyr.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/printk.h>

#include <drivers/gpio.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include "bluetooth_dap.h"
#include "bluetooth_dap_err.h"

static struct bt_uuid_128 display_uuid = BT_UUID_INIT_128(
					0xdf, 0x2e, 0xbd, 0xda,
					0x84, 0x5a, 0xf0, 0xb2,
					0x12, 0x4b, 0x03, 0xaa,
					0x49, 0x44, 0x58, 0x10);

static struct bt_uuid_128 display_text_uuid = BT_UUID_INIT_128(
					0xdf, 0x2e, 0xbd, 0xda,
					0x84, 0x5a, 0xf0, 0xb2,
					0x12, 0x4b, 0x03, 0xaa,
					0x54, 0x54, 0x58, 0x10);

static struct bt_uuid_16 uuid_gatt_ccc = BT_UUID_INIT_16(0x2902);

static struct bt_conn *local;
static bool scanning;
static bool success;

static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;
static int count = 0;

static struct bt_le_conn_param conn_param = {
	.interval_min = BT_GAP_INIT_CONN_INT_MIN,
	.interval_max = BT_GAP_INIT_CONN_INT_MIN,
	.latency = 0,
	.timeout = 400
};

static u8_t notify_text(struct bt_conn *conn,
			   struct bt_gatt_subscribe_params *params,
			   const void *data, u16_t length)
{
	if (!data) {
		printk("[UNSUBSCRIBED]\n");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}

	printk("[NOTIFICATION]: %d\n", *((unsigned int *)data));

	return BT_GATT_ITER_CONTINUE;
}

static u8_t discover_func(struct bt_conn *conn,
		     const struct bt_gatt_attr *attr,
		     struct bt_gatt_discover_params *params)
{
	int err;

	if (!attr) {
		printk("Failed to find attribute!\n");
		return BT_GATT_ITER_STOP;
	}

	switch (count) {
	case 0:

		discover_params.uuid = &display_text_uuid.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			printk("Discover failed (err %d)\n", err);

		break;

	case 1:
		discover_params.uuid = &uuid_gatt_ccc.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;

		subscribe_params.value_handle = bt_gatt_attr_value_handle(attr);

		err = bt_gatt_discover(conn, &discover_params);
		if (err)
			printk("Discover failed (err %d)\n", err);

		break;
	
	case 2:
		subscribe_params.notify = notify_text;
		subscribe_params.ccc_handle = attr->handle;
		subscribe_params.value = BT_GATT_CCC_NOTIFY;

		err = bt_gatt_subscribe(conn, &subscribe_params);
		if (err && err != -EALREADY)
			printk("Init Subscribe failed (err %d)\n", err);
		else
			printk("[SUBSCRIBED]\n");
		
		break;

	default:
		printk("Unexpected value: %d!\n", count);
	}

	count++;

	return BT_GATT_ITER_STOP;
}

void subscribe_text(void)
{
	int err;

	/* Discover display service */
	discover_params.uuid = &display_uuid.uuid;
	discover_params.func = discover_func;
	discover_params.start_handle = 0x0001;
	discover_params.end_handle = 0xffff;
	discover_params.type = BT_GATT_DISCOVER_PRIMARY;

	count = 0;

	err = bt_gatt_discover(local, &discover_params);
	if (err) {
		printk("Discover failed (err %d)", err);
	}

}

static void device_found(const bt_addr_le_t *addr, s8_t rssi)
{
	static bt_addr_le_t persistent_addr;
	int err;

	memcpy(&persistent_addr, addr, sizeof(bt_addr_le_t));

	err = bt_le_dap_scan_stop();
	if (err) {
		printk("Failed to stop scanning (err %d)\n", err);
		return;
	}

	err = bt_conn_create_le_dap(&persistent_addr, &conn_param);
	if (err)
		printk("Failed to init LE DAP conn (err %d)\n", err);
}

static int scan_start(void)
{
	struct bt_le_scan_param scan_param = {
		.type       = BT_HCI_LE_SCAN_ACTIVE,
		.filter_dup = BT_HCI_LE_SCAN_FILTER_DUP_ENABLE,
		.interval   = BT_GAP_SCAN_FAST_INTERVAL,
		.window     = BT_GAP_SCAN_FAST_WINDOW,
	};

	scanning = true;

	return bt_le_dap_scan_start(&scan_param, device_found);
}

static void dap_started(struct bt_conn *conn)
{
	if (conn) {
		local = conn;
		printk("Started BLE DAP!\n");
	} else {
		printk("Failed to start BLE DAP, null conn object!\n");
	}
}

static void dap_finished(struct bt_conn *conn, int result, uint32_t gtime_ms)
{
	int err;

	switch (result) {
	case BT_DAP_ERR_SUCCESS:
		scanning = false;
		success = true;
		local = conn;
		printk("==========\nSuccessfully established secure connection!\
			\nGeneration time: \x1B[1;32m%dms\x1B[0m\n==========\n",
			gtime_ms);

		subscribe_text();

		return;// Escape

	case BT_DAP_ERR_TIMEOUT:
		printk("Client timed out!\n");
		break;

	case BT_DAP_ERR_PAIRING_DISCONNECT:
		printk("Client disconnected!\n");
		break;

	default:
		printk("Failed to stablish secure connection!\n");
		break;
	}

	k_sleep(K_MSEC(100));

	scanning = false;
	success = false;
	local = NULL;

	err = scan_start();
	if (err)
		printk("Failed to start scan (err %d)!\n", err);

}
static struct bt_le_dap_cb dap_callbacks = {
	.started = dap_started,
	.finished = dap_finished,
};

static void button_pressed(struct device *dev,
			   struct gpio_callback *cb, u32_t pins)
{
	int err;

	if (!scanning && !success) {
		err = scan_start();
		if (err)
			printk("Failed to start scanning (err %d)!\n", err);
	} else if (!scanning && success) {
		err = bt_conn_disconnect(local, BT_HCI_ERR_LOCALHOST_TERM_CONN);
		if (err)
			printk("Failed to disconnect (err %d)!\n", err);
	} else {
		err = bt_le_dap_abort();
		if (err)
			printk("Failed to force abort (err %d)!\n", err);
	}
}

static void app_gpio_init(void)
{
	static struct device *button;
	static struct gpio_callback button_cb;

	button = device_get_binding(DT_ALIAS_SW0_GPIOS_CONTROLLER);

	gpio_pin_configure(button, DT_ALIAS_SW0_GPIOS_PIN,
				(GPIO_DIR_IN | GPIO_INT | GPIO_INT_EDGE |
				GPIO_PUD_PULL_UP |
				GPIO_INT_DEBOUNCE | GPIO_INT_ACTIVE_LOW));
	gpio_init_callback(&button_cb,
				button_pressed,
				BIT(DT_ALIAS_SW0_GPIOS_PIN));
	gpio_add_callback(button, &button_cb);
	gpio_pin_enable_callback(button, DT_ALIAS_SW0_GPIOS_PIN);
}

void main(void)
{
	int err;

	app_gpio_init();

	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return;
	}

	printk("Bluetooth initialized\n");

	err = bt_le_dap_enable(DAP_MODE_PROVER);
	if (err) {
		printk("Failed to initialize BLE DAP module (err %d)\n", err);
		return;
	}

	bt_le_dap_cb_register(&dap_callbacks);

	success = false;
	scanning = false;

	err = scan_start();
	if (err) {
		printk("Failed to start scanning (err %d)!\n", err);
		return;
	}
}
