/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_fsm.h
 * \brief Implementation for event driven FSM
 */

#ifndef __SKG_FSM_H__
#define __SKG_FSM_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <zephyr/types.h>
#include <bluetooth/conn.h>

#include <bluetooth/bluetooth_dap.h>

#include "wiolink_settings.h"

#define ADV_SET_SIZE         WIOLINK_SKG_ECHOS_NUM

typedef enum state {
	STATE_IDLE = 0,
	STATE_INIT,
	STATE_PROBE,
	STATE_RECON,
	STATE_PAIRING,
	STATE_DETECT,
	STATE_AUTHENTICATED,

	STATE_NUM
} state_t;

typedef enum stateEvent {
	EVENT_SEND_SKG_PROMPT = 0,
	EVENT_GOT_PID,
	EVENT_ATTEMPT_CONN,
	EVENT_CONNECTED,
	EVENT_GOT_PROBE,
	EVENT_PROBE_TIMEOUT,
	EVENT_PROBE_UPDATE,
	EVENT_CLIENT_SUB,
	EVENT_GOT_SYNDROME,
	EVENT_PAIRING_REQUEST,
	EVENT_PAIRING_SUCCESS,
	EVENT_GOT_RELAY_DATA,
	EVENT_DISCONNECTED,
	EVENT_STOP_ADVERTISING,
	EVENT_ENCRYPT,
	EVENT_DECRYPT,
	EVENT_TIMEOUT,
	EVENT_ABORT,

	EVENT_NUM
} stateEvent_t;

/**
 * \var stateStrings
 * \brief Debug array containing state names as strings
 */
extern const char *stateStrings[];

/**
 * \var eventStrings
 * \brief Debug array containing event names as strings
 */
extern const char *eventStrings[];

typedef struct stateMachine {
	state_t currState;
	state_t prevState;
	bt_le_dap_mode_t mode;
	struct bt_conn *conn;		//!< Device performing SKG with
	void *data;
} stateMachine_t;

typedef struct eventData {
	u8_t *data;
	u8_t len;
} eventData_t;

typedef struct eventData_probe {
	s8_t rssi;
	u32_t id;
} eventData_probe_t;

typedef struct eventData_attempConn {
	const bt_addr_le_t *addr;
	const struct bt_le_conn_param *param;
} eventData_attempConn_t;

typedef struct eventData_crypto {
	const struct bt_conn *conn;
	const uint8_t *din;
	uint16_t ilen;
	uint8_t *dout;
	uint16_t olen;
	bool encrypt;
} eventData_crypto_t;

typedef void (stateFunction_t) (stateMachine_t *machine,
			     stateEvent_t event, void *args);

typedef void (*stateCb_t) (stateMachine_t *machine, stateEvent_t event,
			   int err, void *args);

int initStateMachine(stateMachine_t *machine,
		     bt_le_dap_mode_t mode, uint16_t keyLengthBits,
		     stateCb_t cb);
int runStateMachine(stateMachine_t *machine,
		    stateEvent_t event, void *args);

#ifdef __cplusplus
}
#endif

#endif /* __SKG_FSM_H__ */
