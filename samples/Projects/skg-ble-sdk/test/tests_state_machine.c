/*
 * Copyright (c) 2019 WIOsense GmbH & Co. KG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>

#include <zephyr/types.h>
#include <bluetooth/bluetooth.h>

#include <stdlib.h>

#include "skg_adv.h"
#include "skg_fsm.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(sdk_test, CONFIG_SKG_LOG_LEVEL);

#define NUM_TRANSITIONS         23
#define NUM_PROBES              16
#define IDX_PID_OFFSET          1
#define IDX_PROBES_OFFSET       3

#define SEM_TIMEOUT_MS          K_MSEC(500)

char *stateStrings[] = {"STATE_IDLE", "STATE_INIT", "STATE_PROBE",
			"STATE_RECON", "STATE_CONNECTED", "STATE_STATE_NUM"};

char *eventStrings[] = {"EVENT_SEND_SKG_PROMPT", "EVENT_GOT_PID",
			"EVENT_GOT_INIT", "EVENT_GOT_PROBE",
			"EVENT_CLIENT_SUB", "EVENT_GOT_SYNDROME",
			"EVENT_DISCONNECTED", "EVENT_ABORT", "EVENT_NUM"};

static const state_t states[] = {STATE_INIT, STATE_INIT,
				 STATE_PROBE, STATE_PROBE, STATE_PROBE,
				 STATE_PROBE, STATE_PROBE, STATE_PROBE,
				 STATE_PROBE, STATE_PROBE, STATE_PROBE,
				 STATE_PROBE, STATE_PROBE, STATE_PROBE,
				 STATE_PROBE, STATE_PROBE, STATE_PROBE,
				 STATE_PROBE, STATE_RECON, STATE_RECON,
				 STATE_CONNECTED, STATE_CONNECTED, STATE_IDLE};

static const stateEvent_t events[] = {EVENT_SEND_SKG_PROMPT, EVENT_GOT_PID,
				      EVENT_GOT_INIT, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_GOT_PROBE,
				      EVENT_GOT_PROBE, EVENT_CLIENT_SUB,
				      EVENT_GOT_SYNDROME, EVENT_GOT_INIT,
				      EVENT_DISCONNECTED};

static const int8_t rssiV[NUM_PROBES] = {-33, -31, -34, -27, -27, -28, -27, -31,
				 -33, -35, -26, -31, -29, -34, -32, -33};

// Might use later
// static const int8_t txPowV[NUM_PROBES] = { 6, 10, 13,  8, 12, 10, 12,  6,
//					  13,  8,  8,  6, 12, 10, 13, 10};

static eventData_probe_t probes[NUM_PROBES];

static const u32_t probeIdxV[ADV_SET_SIZE] = {0x5927e523, 0xa0e72e33,
					      0xc3f0d2f5, 0x0c107f22};

static void *mockArgs[NUM_TRANSITIONS] = {NULL};

static const uint32_t pid = 0xDEAFFADE;

eventData_syndrome_t syndromeData;
static uint8_t syndrome[5] = {0x4, 0x19, 0x10, 0x05, 0x0A};

static stateMachine_t machine;
static int gError;

static struct k_sem stateSem;

static void __stateCallback(state_t nextState, int error)
{
	gError = error;
	k_sem_give(&stateSem);
}

static void __sendSyndromeMock(const uint8_t *syndrome, const uint8_t len,
			   const uint8_t repeats)
{
	LOG_INF("Sending syndrome!");
}

void setup_fsm(void)
{
	int err;
	if (machine.data == NULL) {
		k_sem_init(&stateSem, 0, 1);

		err = bt_enable(NULL);
		if (err) {
			LOG_ERR("Could not initialize BLE: %d!", err);
			return;
		}

		err = initStateMachine(&machine, DAP_MODE_VERIFIER, 64,
				       __stateCallback);
		if (err) {
			LOG_ERR("Could not initialize State Machine: %d!", err);
			return;
		}

		err = initAdvertiseLogic();
		if (err) {
			LOG_ERR("Could not initialize Advertising Logic: %d!"
				, err);
			return;
		}

		eventData_probe_t *probe;
		int i;

		mockArgs[IDX_PID_OFFSET] = (void *)pid;

		for (i = 0 ; i < NUM_PROBES ; ++i) {
			probes[i].rssi = rssiV[i];
			probes[i].id = probeIdxV[i % ADV_SET_SIZE];

			mockArgs[i + IDX_PROBES_OFFSET] = probes + i;
		}
		i += IDX_PROBES_OFFSET;

		mockArgs[i] = (void *)__sendSyndromeMock;
		i++;

		mockArgs[i] = (void *)&syndromeData;
		syndromeData.syndrome = syndrome;
		syndromeData.syndromeLen = ARRAY_SIZE(syndrome);

	}

}

void teardown_fsm(void)
{

}

void test_fsm(void)
{
	state_t prevState;
	int err;
	uint32_t time;

	machine.currState = STATE_INIT;

	for (int i = 0 ; i < NUM_TRANSITIONS ; ++i) {
		prevState = machine.currState;

		time = k_uptime_get_32();
		err = runStateMachine(&machine, events[i], mockArgs[i]);
		zassert_true(err == 0, "Got setup error: %02X", err);

		err = k_sem_take(&stateSem, SEM_TIMEOUT_MS);
		zassert_true(err == 0, "Semaphore error: %d", err);

		zassert_true(gError == 0, "Got runtime error: %02X", err);

		zassert_true(machine.currState == states[i],
			     "%s + %s = %s | Got %s | %ums",
			     stateStrings[prevState],
			     eventStrings[events[i]],
			     stateStrings[states[i]],
			     stateStrings[machine.currState]);

		LOG_INF("%s + %s = %s\n", stateStrings[prevState],
					 eventStrings[events[i]],
					 stateStrings[states[i]]);
	}
}
