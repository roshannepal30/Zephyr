/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file bluetooth_dap.c
 * \brief Main public API for SKG and relay detection
 */

#include <kernel.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <zephyr.h>
#include <errno.h>

#include <settings/settings.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#include <bluetooth/bluetooth_dap.h>
#include <bluetooth/bluetooth_dap_err.h>

#include "callbacks.h"
#include "skg_fsm.h"
#include "skg_adv.h"
#include "wio_uuid.h"
#include "version.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(bt_dap, CONFIG_SKG_LOG_LEVEL);

/**
 * State machine
 */
static stateMachine_t machine;
static struct bt_le_dap_cb *callbackList;

static eventData_attempConn_t attemptConn;
static eventData_probe_t probe[ADV_SET_SIZE];
static eventData_t syndromeData;
static eventData_t relayData;
static eventData_crypto_t cryptoTrans;

static bool enabled;
static bool dapCompatible;
static bool gotId;
static u8_t id_local[16];
static bt_le_dap_scan_cb_t *scan_cb;

/**
 * Private helper functions
 */
static void __stateCallback(stateMachine_t *machine, stateEvent_t event,
			    int err, void *args)
{
	struct bt_le_dap_cb *cb;

	if (machine->prevState == STATE_INIT && event == EVENT_CONNECTED &&
	    err == 0) {
		for (cb = callbackList ; cb ; cb = cb->_next) {
			if (cb->started)
				cb->started(machine->conn);
		}
		return;
	}

	if (machine->prevState == STATE_DETECT &&
	    event == EVENT_GOT_RELAY_DATA) {
		for (cb = callbackList ; cb ; cb = cb->_next) {
			if (cb->finished)
				cb->finished(machine->conn, err,
					     (uint32_t)args);
		}
		return;
	}

	if (machine->prevState == STATE_AUTHENTICATED &&
	    err == BT_DAP_ERR_PAIRING_DISCONNECT) {
		for (cb = callbackList ; cb ; cb = cb->_next) {
			if (cb->finished)
				cb->finished(machine->conn,
					     BT_DAP_ERR_DISCONNECT, -1);
		}
		return;
	}

	if (err == BT_DAP_ERR_PAIRING_DISCONNECT) {
		for (cb = callbackList ; cb ; cb = cb->_next) {
			if (cb->finished)
				cb->finished(machine->conn, err, -1);
		}
		return;
	}

	if (event == EVENT_ABORT) {
		for (cb = callbackList ; cb ; cb = cb->_next) {
			if (cb->finished)
				cb->finished(machine->conn, err, -1);
		}
		return;
	}
}

static void __connected(struct bt_conn *conn, u8_t err)
{
	if (err) {
		LOG_ERR("Connection failed (err 0x%02x).", err);
		return;
	}

	LOG_DBG("Connected");

	err = runStateMachine(&machine, EVENT_CONNECTED, bt_conn_ref(conn));
	if (err) {
		LOG_ERR("Error in %s + EVENT_CONNECTED : %d",
			stateStrings[machine.currState], err);
	}
}

static void __disconnected(struct bt_conn *conn, u8_t reason)
{
	LOG_DBG("Disconnected (reason 0x%02x).", reason);

	reason = runStateMachine(&machine, EVENT_DISCONNECTED, NULL);
	if (reason) {
		LOG_ERR("Error in %s + EVENT_DISCONNECTED : %d",
			stateStrings[machine.currState], reason);
	}
}

static void __security_changed(struct bt_conn *conn, bt_security_t level,
			     enum bt_security_err err)
{
	if (!err) {
		LOG_DBG("Security changed level %d",  level);
	} else {
		LOG_ERR("Security failed: level %u err %d", level, err);
	}
}

static struct bt_conn_cb connCallbacks = {
	.connected = __connected,
	.disconnected = __disconnected,
	.security_changed = __security_changed,
};

static void __auth_oob_request(struct bt_conn *conn,
				struct bt_conn_oob_info *info)
{
	int err;
	uint8_t *tk;

	err = runStateMachine(&machine, EVENT_PAIRING_REQUEST, &tk);
	if (err) {
		LOG_ERR("Error in %s + EVENT_PAIRING_REQUEST : %d",
			stateStrings[machine.currState], err);
	}

	err = bt_le_oob_set_legacy_tk(conn, tk);
	if (err)
		LOG_ERR("Failed to set OOB TK: %d", err);
}

static void __auth_cancel(struct bt_conn *conn)
{
	LOG_INF("Pairing cancelled. Aborting DAP");
}

static void __pairing_complete(struct bt_conn *conn, bool bonded)
{
	LOG_INF("Pairing Complete");

	int err;

	err  = runStateMachine(&machine, EVENT_PAIRING_SUCCESS, NULL);
	if (err) {
		LOG_ERR("Error in %s + EVENT_PAIRING_SUCCESS : %d",
			stateStrings[machine.currState], err);
	}
}

static void __pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	LOG_ERR("Pairing Failed (%d). Aborting DAP", reason);

	int err;

	err  = runStateMachine(&machine, EVENT_ABORT, NULL);
	if (err)
		LOG_ERR("Could not abort after pairing fail: %d", err);
}

static struct bt_conn_auth_cb authCallbacks = {
	.oob_data_request = __auth_oob_request,
	.cancel = __auth_cancel,
	.pairing_complete = __pairing_complete,
	.pairing_failed = __pairing_failed,
};

/**
 * Prover specific helper functions
 */
static bool __adv_found(struct bt_data *data, void *user_data)
{
	struct bt_data ref = WIO_UUIDS_SKG_PROMPT;

	if  (data->type == ref.type) {
		if (data->data_len != ref.data_len)
			return false;

		if (!memcmp(ref.data, data->data, ref.data_len)) {
			dapCompatible = true;
		} else {
			/* do not waste time with this ADV - not what we want */
			return false;
		}
	}

	return true;
}

static bool __scan_found(struct bt_data *data, void *user_data)
{

	if  (data->type == BT_DATA_UUID128_SOME) {
		if (!dapCompatible || data->data_len != 16)
			return false;

		memcpy(id_local, data->data, data->data_len);
		gotId = true;
	}

	return true;
}

static void __device_found(const bt_addr_le_t *addr, s8_t rssi, u8_t type,
			 struct net_buf_simple *ad)
{

	if (type == BT_LE_ADV_IND) {
		dapCompatible = false;
		bt_data_parse(ad, __adv_found, (void *)addr);

	} else if (type == BT_LE_ADV_SCAN_RSP) {

		gotId = false;
		bt_data_parse(ad, __scan_found, (void *)addr);
		dapCompatible = false;
	}

	if (gotId) {
		gotId = false;
		scan_cb(addr, rssi);
	}
}

/**
 * Callback implementations
 */
void callback_wrotePID(u8_t *pid)
{
	int err;

	err = runStateMachine(&machine, EVENT_GOT_PID, (void *)pid);
	if (err)
		LOG_ERR("Error in STATE_INIT + EVENT_GOT_PID : %d", err);
}

void callback_matchedProbe(s8_t rssi, u32_t id)
{
	static uint8_t probeIdx;
	int err;

	for (uint8_t i = 0 ; i < ADV_SET_SIZE ; ++i) {
		if (id == probe[i].id)
			return;
	}

	probe[probeIdx].rssi = rssi;
	probe[probeIdx].id = id;

	err = runStateMachine(&machine, EVENT_GOT_PROBE, &probe[probeIdx]);
	if (err)
		LOG_ERR("Error in STATE_PROBE + EVENT_GOT_PROBE : %d", err);

	probeIdx = (probeIdx + 1) % ADV_SET_SIZE;
}

void callback_clientSubscribed(void)
{
	int err;

	err = runStateMachine(&machine, EVENT_CLIENT_SUB, NULL);
	if (err)
		LOG_ERR("Error in STATE_INIT + EVENT_CLIENT_SUB : %d", err);

}

void callback_wroteProbe(u8_t val)
{
	int err;

	err = runStateMachine(&machine, EVENT_PROBE_UPDATE, (void *)(u32_t)val);
	if (err)
		LOG_ERR("Error in STATE_PROBE + EVENT_PROBE_UPDATE : %d", err);
}

void callback_wroteSyndrome(u8_t *data, u8_t len)
{
	int err;

	syndromeData.data = data;
	syndromeData.len = len;

	err = runStateMachine(&machine, EVENT_GOT_SYNDROME, &syndromeData);
	if (err)
		LOG_ERR("Error in STATE_RECON + EVENT_GOT_SYNDROME : %d", err);

}

void callback_wroteRelayData(u8_t *data, u8_t len)
{
	int err;

	relayData.data = data;
	relayData.len = len;

	err = runStateMachine(&machine, EVENT_GOT_RELAY_DATA, &relayData);
	if (err) {
		LOG_ERR("Error in STATE_DETECT + EVENT_GOT_RELAY_DATA : %d",
			err);
	}

}

/**
 * Public API
 */
int bt_le_dap_enable(bt_le_dap_mode_t mode)
{
	int err;

	if (enabled)
		return -EALREADY;

	err = initStateMachine(&machine, mode, 32, __stateCallback);
	if (err) {
		LOG_ERR("Could not initialize State Machine!");
		return err;
	}

	dapCompatible = false;

	bt_conn_cb_register(&connCallbacks);
	bt_conn_auth_cb_register(&authCallbacks);

	LOG_INF("Initialized BLE DAP protocol - SDK %s", SDK_VERSION_STRING);

	enabled = true;

	return 0;
}

int bt_le_dap_set_identity(u8_t *identity)
{
	if (enabled)
		return -EAGAIN;

	if (!identity)
		return -EINVAL;

	setPrivateIdentity(identity);

	return 0;
}

int bt_le_dap_adv_start(void)
{
	if (!enabled)
		return -EAGAIN;

	return runStateMachine(&machine, EVENT_SEND_SKG_PROMPT, NULL);
}

int bt_le_dap_adv_stop(void)
{
	if (!enabled)
		return -EAGAIN;

	return runStateMachine(&machine, EVENT_STOP_ADVERTISING, NULL);
}

int bt_le_dap_scan_start(const struct bt_le_scan_param *param,
			 bt_le_dap_scan_cb_t cb)
{
	if (!enabled)
		return -EAGAIN;

	if (!cb || !param)
		return -EINVAL;

	if (!scan_cb) {
		scan_cb = cb;
		return bt_le_scan_start(param, __device_found);
	}

	return -EALREADY;
}

int bt_le_dap_scan_stop(void)
{
	if (!enabled)
		return -EAGAIN;

	if (scan_cb) {
		scan_cb = NULL;
		return bt_le_scan_stop();
	}

	return 0;
}

int bt_conn_create_le_dap(const bt_addr_le_t *addr,
			  const struct bt_le_conn_param *param)
{
	if (!enabled)
		return -EAGAIN;

	attemptConn = (eventData_attempConn_t) {
		.addr = addr,
		.param = param
	};

	return runStateMachine(&machine, EVENT_ATTEMPT_CONN, &attemptConn);
}

int bt_le_dap_abort(void)
{
	if (!enabled)
		return -EAGAIN;

	return runStateMachine(&machine, EVENT_ABORT, NULL);
}

void bt_le_dap_cb_register(struct bt_le_dap_cb *cb)
{
	cb->_next = callbackList;
	callbackList = cb;
}

int bt_conn_dap_encrypt(uint8_t *dout, uint16_t olen, const uint8_t *din,
			const uint16_t ilen, const struct bt_conn *conn)
{
	if (!enabled)
		return -EAGAIN;

	cryptoTrans = (eventData_crypto_t) {
		.conn = conn,
		.din = din,
		.ilen = ilen,
		.dout = dout,
		.olen = olen
	};

	return runStateMachine(&machine, EVENT_ENCRYPT, &cryptoTrans);
}

int bt_conn_dap_decrypt(uint8_t *dout, uint16_t olen, const uint8_t *din,
			const uint16_t ilen, const struct bt_conn *conn)
{
	if (!enabled)
		return -EAGAIN;

	cryptoTrans = (eventData_crypto_t) {
		.conn = conn,
		.din = din,
		.ilen = ilen,
		.dout = dout,
		.olen = olen
	};

	return runStateMachine(&machine, EVENT_DECRYPT, &cryptoTrans);
}

void bt_dap_version(uint8_t *major, uint8_t *minor, uint8_t *patch)
{
	*major = (uint8_t)SDK_VERSION_MAJOR;
	*minor = (uint8_t)SDK_VERSION_MINOR;
	*patch = (uint8_t)SDK_PATCHLEVEL;
}
