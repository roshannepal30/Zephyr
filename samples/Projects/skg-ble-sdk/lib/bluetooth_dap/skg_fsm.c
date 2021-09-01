/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_fsm.c
 * \brief Implementation for event driven FSM
 */

#include <zephyr.h>
#include <sys/atomic.h>

#include "skg_fsm.h"

#include <bluetooth/bluetooth_dap_err.h>

#include "wio_uuid.h"
#include "skg_scan.h"
#include "skg_adv.h"
#include "skg_char.h"

#include "callbacks.h"
#include "services/services.h"

#include "wiolink_settings.h"
#include "permute.h"
#include "samples_api.h"

#include "quantizer_settings.h"
#include "quantization.h"

#include "recon.h"
#include "recon_util.h"
#include "recon_settings.h"

#include "challenge_api.h"
#include "challenge_settings.h"

#include <errno.h>

#include <drivers/entropy.h>

#include <tinycrypt/aes.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/cbc_mode.h>

#include <bluetooth/conn.h>
#include <bluetooth/gatt.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(state_machine, CONFIG_SKG_LOG_LEVEL);

#define MAX_SIZE_INV_PERM    (MAX_SHUFFLES * MAX_CODEWORDS * EC_7_2_CODE_LENGTH)
#define RECON_SYND_CAPACITY  (MAX_SHUFFLES * MAX_CODEWORDS)
#define NUM_RSSI_CTRL        4
#define UNKNOWN_ADV_ID       0xFF

#define FSM_STACK_SIZE		1284
#define FSM_PRIORITY		5

#define FSM_QUEUE_CAP		4

#define TIMEOUT_INIT_CHAR_MS	K_MSEC(1100)
#define TIMEOUT_SKG_MS		K_MSEC(3999)
#define TIMEOUT_PROBE_MS	K_MSEC(500)
#define TIMEOUT_PAIR_MS		K_MSEC(5000)
#define TIMEOUT_DETECT_MS	K_MSEC(1000)
#define TIME_PROVER_WAIT_MS	K_MSEC(30)

#define BT_DAP_CONST_PROBE_ADVANCE	0xF0
#define BT_DAP_CONST_PROBE_REPEAT	0xFF

#define BT_DAP_FLAG_ZEPHYR	0
#define BT_DAP_FLAG_OOB		1

#define CHAN_WARN_MSG	"Vulnerable BLE data channels detected - "\
			"reciprocity lower than %.2f"

K_THREAD_STACK_DEFINE(fsm_stack_area, FSM_STACK_SIZE);

const char *stateStrings[] = {"STATE_IDLE", "STATE_INIT", "STATE_PROBE",
			      "STATE_RECON", "STATE_PAIRING", "STATE_DETECT",
			      "STATE_AUTHENTICATED"};

const char *eventStrings[] = {"EVENT_SEND_SKG_PROMPT", "EVENT_GOT_PID",
			      "EVENT_ATTEMPT_CONN", "EVENT_CONNECTED",
			      "EVENT_GOT_PROBE", "EVENT_PROBE_TIMEOUT",
			      "EVENT_PROBE_UPDATE", "EVENT_CLIENT_SUB",
			      "EVENT_GOT_SYNDROME", "EVENT_PAIRING_REQUEST",
			      "EVENT_PAIRING_SUCCESS", "EVENT_GOT_RELAY_DATA",
			      "EVENT_DISCONNECTED", "EVENT_STOP_ADVERTISING",
			      "EVENT_ENCRYPT", "EVENT_DECRYPT", "EVENT_TIMEOUT",
			      "EVENT_ABORT"};

/**
 * \typedef fsmWork_t
 * \brief Work structure containing an event to be processed
 */
typedef struct fsmWork {
	struct k_delayed_work work;
	stateMachine_t *machine;	//!< State machine to do the processing
	stateEvent_t event;		//!< Event to be processed
	void *args;			//!< Passed arguments
	bool free;			//!< False if instance is pending or
					//   being processed, true otherwise
} fsmWork_t;

/**
 * \typedef skgMonitor_t
 * \brief Data structure containing data for a DAP session
 */
typedef struct skgMonitor {
	stateCb_t stateCallback;	//!< Function call when state is done

	uint16_t nBitsKey;		//!< Desired number of bits for the key
	uint8_t echoCounter;		//!< Probe counter

	WioLink_ChannelProbe_t probe;	//!< Channel probe sensing unit
	WioLink_QuantizedSample_t quant;//!< Quantizer structure
	WioLink_ReconStruct_t recon;	//!< Reconciliation structure
	WioLink_CandidateKey_t local;	//!< Local candidate key material

	WioPRNG_t reconPrng;		//!< Used in Recon for shuffle/deshuffle
	WioPRNG_t pidPrng;		//!< Generates device and txPow IDs
	WioPRNG_t powPrng;		//!< Shuffles txPower indices

	uint8_t *txPowIndices;		//!< Shuffled txPower indices
	uint32_t *txPowIdentifiers;	//!< Block PIDs used in RX parsing
	uint8_t *txPowIdentifiersArr;	//!< Block PIDs used in Tx payload

	challenge_t varChall;		//!< Variance challenge state
	challenge_t chanChall;		//!< Channel challenge state
	challenge_chan_init_t chanInit;	//!< Channel challenge init state
	challenge_chan_data_t chanData;	//!< Channel challenge input data

	uint32_t pid;			//!< Session device PID

	uint8_t *cryptoStore;		//!< Hashed key storage
	uint8_t *temp;			//!< Generic array for characteristic
					//   write / notification / OTT crypto

	uint32_t genTime;		//!< Time from probing to key hashing
	uint32_t authTime;		//!< Time from DAP start to auth. state

	int dapConnCapa;		//!< DAP capabilities of current conn
	bool *gotId;			//!< Keeps track of received probe IDs
	bool gotAdvance;		//!< Remote filled a block of probes
	bool disconnect;		//!< Disconnect remote device on abort

	// Prover only data
	dap_char_handles_t handles;	//!< Characteristic handles
	struct bt_gatt_subscribe_params subParam[3];
					//!< Storage for notification CBs
} skgMonitor_t;

/**
 * Work queue
 */
static struct k_work_q machineQueue;
static fsmWork_t fsmWork[FSM_QUEUE_CAP];

/**
 * Scheduling
 */
static struct k_timer timeoutTimer;
static struct k_timer probeTimer;

/**
 * Internal State
 */
static skgMonitor_t skgMon;

/* Power buffers */
static uint32_t txPowersIds[ADV_SET_SIZE];
static uint8_t txPowersIdsArr[sizeof(txPowersIds)];
static bool gotIdBuffer[ADV_SET_SIZE];

static struct bt_skg_data probeSet[ADV_SET_SIZE];

/* Channel samples buffer */
static WioLink_ChannelSample_t samplesBuffer[ADV_SET_SIZE];

/* Quantizes samples buffer */
static uint8_t quanBuffer[QUAN_BITS_LENGTH/8 + 1];

/* Recon structure storage */
static uint16_t invPermBuff[MAX_SIZE_INV_PERM] = {0};
static uint8_t syndLocalBuff[RECON_SYND_CAPACITY] = {0};
static uint8_t syndExtBuff[RECON_SYND_CAPACITY] = {0};
static uint8_t discardsBuff[RECON_SYND_CAPACITY] = {0};

/* Channel candidate key buffer */
static uint8_t localKeyBuff[WIOLINK_SKG_KEY_LENGTH_CAPACITY] = {0};

/* Channel challenge buffers and necessary data structures */
static int8_t chalRssiBuff[CHAL_TOKEN_CAPACITY];
static int8_t chalTxPowBuff[CHAL_TOKEN_CAPACITY];
static int8_t chalCtrlRssiBuff[NUM_RSSI_CTRL];
static uint8_t chalIdxBuff[CHAL_IDX_BUFF_CAPACITY];
static uint8_t chalSerialBuff[CHAL_CHANNEL_SER_BUFF_CAPACITY];

/* Entropy source */
struct device *entropy;

/* Crypto storage */
#define MAX_ENCRYPT_PAYLOAD_LEN    15
static uint8_t keyDigestBuff[TC_SHA256_DIGEST_SIZE];
static uint8_t tempBuff[MAX_ENCRYPT_PAYLOAD_LEN];
static uint8_t iv[TC_AES_BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0};

/* TXP internal arrays */
int8_t __txPowers[ADV_SET_SIZE] = {
	0,
	-8,
	-16,
	-20,
};

uint8_t __txPowersIdxs[ADV_SET_SIZE] = {
	0,
	1,
	2,
	3,
};

#define RSSI_OFFSET		6

/**
 * State-wise event handler declarations
 */
static fsmWork_t *__getFreeWork();
static void __submitEvent(struct k_work *item);
static void __timeOutExpiry(struct k_timer *timer_id);
static void __probeExpiry(struct k_timer *timer_id);
static void __skg_reset(stateMachine_t *machine);
static int __skg_abort(stateMachine_t *machine, stateEvent_t event, void *args,
		       int err);
static int __encryptEvent(stateMachine_t *machine, eventData_crypto_t *trans);
static int __decryptEvent(stateMachine_t *machine, eventData_crypto_t *trans);

/**
 * Private helper declarations
 */
static void __getRand32(uint32_t *random);
static void __resetReconciledKey(WioLink_CandidateKey_t *key,
				 uint8_t *keyBuffer,
				 const uint16_t keyLength);
static void __resetSkgMonitor(skgMonitor_t *monitor, bt_le_dap_mode_t mode,
			      const uint16_t keyLengthBits, const stateCb_t cb);
static int __get_dap_capa(void);
static int __conf_dap_capa(int extCap);
static void __generatePowerIds(skgMonitor_t *monitor);
static void __setPowerIds(skgMonitor_t *monitor);
static void __shuffleTxPowers(skgMonitor_t *monitor);
static uint8_t __id2index(skgMonitor_t *monitor, uint32_t id);
static void __processProbe(skgMonitor_t *monitor, eventData_probe_t *probe,
			   uint8_t id);
// static void __truncateKey(WioLink_CandidateKey_t *key);
static int __prover_quantize(stateMachine_t *machine);
static int __addKeyToCryptoStore(skgMonitor_t *monitor);
static int __encryptBuff(uint8_t *key, uint8_t *data, uint8_t *len);
static int __decryptBuff(uint8_t *key, uint8_t *data, uint8_t *len);

#define IF_ERR_ABORT(err, event, machine) \
	if (err) {__skg_abort(machine, event, NULL, BT_DAP_ERR_ABORT); return;}

#define IF_NULL_ABORT(in, event, machine) \
	if (!in) {__skg_abort(machine, event, NULL, BT_DAP_ERR_ABORT); return;}

/**
 * Private State handlers
 */
static inline void __unHandledEvent(state_t state, stateEvent_t event)
{
	LOG_DBG("State %s does not handle event %s", stateStrings[state],
		eventStrings[event]);
}

static inline void __verifierState_idle(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	int err;

	if (event == EVENT_SEND_SKG_PROMPT) {
		LOG_DBG("\x1B[1;32m=== Send Prompt ===\x1B[0m");

		static uint8_t ffByte = 0xFF;
		static struct bt_skg_data prompt = {
			.txp = 0,
			.data = &ffByte,
			.len = 1
		};

		err = advertiseSkgPrompt(&prompt);
		IF_ERR_ABORT(err, event, machine);

		machine->currState = STATE_INIT;
	} else {
		__unHandledEvent(STATE_IDLE, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static void __verifierState_init(stateMachine_t *machine,
				stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	int err;

	switch (event) {
	case (EVENT_CONNECTED):
		IF_NULL_ABORT(args, event, machine);

		/* Store connection obj, ref number was already increased */
		machine->conn = (struct bt_conn *)args;

		/* Stop broadcasting skgPrompt */
		err = stopAdvertising();
		IF_ERR_ABORT(err, event, machine);

		/* Start Init timeout */
		k_timer_start(&timeoutTimer, TIMEOUT_INIT_CHAR_MS, 0);
		monitor->authTime = (uint32_t)k_uptime_get_32();

		break;

	case (EVENT_GOT_PID):
		IF_NULL_ABORT(args, event, machine);

		monitor->pid = *((uint32_t *)args);

		if (monitor->pid == 0) {
			LOG_INF("Got 0 PID");
			return;
		}

		if ((monitor->pid & 0x0000FFFF) == WIO_MAN_ID_U32) {
			monitor->pid = 0;
			LOG_INF("PID too similar to static seed");
			return;
		}

		monitor->dapConnCapa = (int)
				       (((uint8_t *)args)[sizeof(uint32_t)]);
		monitor->dapConnCapa = __conf_dap_capa(monitor->dapConnCapa);

		LOG_DBG("=== Got PID: %08X ===", monitor->pid);

		WioPRNG_srand(&monitor->reconPrng, monitor->pid);
		WioPRNG_srand(&monitor->pidPrng, monitor->pid ^ WIO_MAN_ID_U32);

		__generatePowerIds(monitor);
		__setPowerIds(monitor);
		__shuffleTxPowers(monitor);
		break;

	case (EVENT_CLIENT_SUB):
		LOG_DBG("=== Client Subscribed ===");

		/* Cancel init timeOut */
		k_timer_stop(&timeoutTimer);

		err = scanForProbes();
		IF_ERR_ABORT(err, event, machine);

		/* Start SKG timeout */
		k_timer_start(&timeoutTimer, TIMEOUT_SKG_MS, 0);

		machine->currState = STATE_PROBE;
		break;

	default:
		__unHandledEvent(STATE_INIT, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static void __verifierState_probe(stateMachine_t *machine,
				 stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	eventData_probe_t *probe = (eventData_probe_t *)args;
	static eventData_probe_t *probeArr;
	uint8_t id;
	int err;

	switch (event) {
	case (EVENT_GOT_PROBE):
		IF_NULL_ABORT(args, event, machine);

		id = __id2index(monitor, probe->id);
		probe->id = 0;
		if (id == UNKNOWN_ADV_ID || monitor->gotId[id])
			return;    //Ignore wrong IDs and repeated ones

		LOG_DBG("=== Got Probe %d ===", id);

		if (monitor->echoCounter == 0) {
			probeArr = probe;
			monitor->genTime = (uint32_t)k_uptime_get_32();

			err = advertiseProbes(probeSet, ADV_SET_SIZE);
			IF_ERR_ABORT(err, event, machine);

			k_timer_start(&probeTimer, TIMEOUT_PROBE_MS, 0);
		} else if (monitor->echoCounter % ADV_SET_SIZE == 0) {
			// Prover moved ad sets, update power ids
			__shuffleTxPowers(monitor);
			__setPowerIds(monitor);

			k_timer_start(&probeTimer, TIMEOUT_PROBE_MS, 0);
		}

		__processProbe(monitor, probe, id);

		if (monitor->probe.size == ADV_SET_SIZE) {
			k_timer_stop(&probeTimer);

			err = (int)runChallenge(&monitor->varChall,
						&monitor->probe);

			if (err != (int)WioLink_ChallengePassed) {
				LOG_ERR("Failed variance test %d", err);

				__skg_abort(machine, event, NULL,
					    BT_DAP_ERR_ABORT);
				return;
			}

			err = notify_probe(machine->conn,
					   BT_DAP_CONST_PROBE_ADVANCE);
			IF_ERR_ABORT(err, event, machine);

			memset(monitor->gotId, false,
			       ADV_SET_SIZE * sizeof(bool));

			runQuantization(&monitor->local,
					&monitor->probe,
					monitor->probe.size,
					&monitor->quant);
			monitor->probe.size = 0;

			/* Wait until first probe of the next set comes to
			 * update local tx probeSet
			 **/
			__generatePowerIds(monitor);
		}

		if (monitor->local.bitLen >= monitor->nBitsKey) {
			err = stopScanning();
			IF_ERR_ABORT(err, event, machine);

			k_timer_stop(&probeTimer);

			// __truncateKey(&monitor->local);

			printk("Extracted Key %d:", monitor->local.bitLen);
			for (uint8_t i = 0 ; i < monitor->local.byteLen ; ++i)
				printk(" %d", monitor->local.key[i]);
			printk("\n");

			machine->currState = STATE_RECON;
		}
		break;

	case (EVENT_PROBE_TIMEOUT):
		LOG_DBG("\x1B[1;33m=== Block timed out ===\x1B[0m");

		err = notify_probe(machine->conn, BT_DAP_CONST_PROBE_REPEAT);
		IF_ERR_ABORT(err, event, machine);

		flushChannelProbe(&monitor->probe);
		__shuffleTxPowers(monitor);
		__generatePowerIds(monitor);
		__setPowerIds(monitor);

		memset(probeArr, 0, ADV_SET_SIZE * sizeof(eventData_probe_t));
		memset(monitor->gotId, false, ADV_SET_SIZE*sizeof(bool));

		monitor->echoCounter = monitor->echoCounter % ADV_SET_SIZE ?
				       monitor->echoCounter / ADV_SET_SIZE + 1 :
				       monitor->echoCounter / ADV_SET_SIZE;
		monitor->echoCounter = (monitor->echoCounter - 1)*ADV_SET_SIZE;

		err = advertiseProbes(probeSet, ADV_SET_SIZE);
		IF_ERR_ABORT(err, event, machine);
		break;

	default:
		__unHandledEvent(STATE_PROBE, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static void __verifierState_recon(stateMachine_t *machine,
				 stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	eventData_t *synd = (eventData_t *)args;
	int err;
	uint8_t len;

	switch (event) {
	case (EVENT_PROBE_UPDATE):
		IF_NULL_ABORT(args, event, machine);

		err = stopAdvertising();
		IF_ERR_ABORT(err, event, machine);

		WioLink_ShuffleSyndrome(&monitor->recon,
					&monitor->local,
					&monitor->reconPrng);

		err = notify_syndrome(machine->conn,
				      monitor->recon.syndromeLocal,
				      monitor->recon.codeNum,
				      monitor->recon.shuffleNum);
		IF_ERR_ABORT(err, event, machine);

		/* Allow OOB pairing requests */
		bt_set_oob_data_flag(true);
		break;

	case (EVENT_GOT_SYNDROME):
		IF_NULL_ABORT(args, event, machine);

		/* Stop SKG timeout */
		k_timer_stop(&timeoutTimer);

		LOG_DBG("=== Got Syndrome ===");

		memcpy(monitor->recon.syndromeExtern, synd->data,
		       synd->len);

		WioLink_Syndrome(&monitor->recon, &monitor->local,
				 &monitor->reconPrng);

		WioLink_Correct(&monitor->recon, &monitor->local, DISCARD_ON);

		monitor->genTime = (uint32_t)k_uptime_get_32()
				   - monitor->genTime;

		printk("Corrected Key:");
		for (uint8_t i = 0 ; i < monitor->local.byteLen ; ++i)
			printk(" %d", monitor->local.key[i]);
		printk("\n");

		LOG_INF("=== Generated key in %ums ===", monitor->genTime);

		err = __addKeyToCryptoStore(monitor);
		IF_ERR_ABORT(err, event, machine);

		printk("Hashed Key:");
		for (uint8_t i = 0 ; i < TC_SHA256_DIGEST_SIZE ; ++i)
			printk(" %02X", monitor->cryptoStore[i]);
		printk("\n");

		if (atomic_test_bit(&monitor->dapConnCapa, BT_DAP_FLAG_OOB)) {
			/* If both devices are OOB compatible create a bond */
			/* Start pairing timeout */
			k_timer_start(&timeoutTimer, TIMEOUT_PAIR_MS, 0);

			machine->currState = STATE_PAIRING;
		} else {
			/* Else, use OTT encryption for relay detection phase */
			len = monitor->chanInit.idLen;
			memcpy(monitor->temp, monitor->chanInit.idBuff, len);

			err = __encryptBuff(monitor->cryptoStore, monitor->temp,
					    &len);
			IF_ERR_ABORT(err, event, machine);

			err = notify_relayData(machine->conn, monitor->temp,
					       len);
			IF_ERR_ABORT(err, event, machine);

			/* Start relay detection timeout */
			k_timer_start(&timeoutTimer, TIMEOUT_DETECT_MS, 0);

			machine->currState = STATE_DETECT;
		}

		break;

	default:
		__unHandledEvent(STATE_RECON, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static void __verifierState_pairing(stateMachine_t *machine,
				     stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	int err;

	switch (event) {
	case (EVENT_PAIRING_REQUEST):
		IF_NULL_ABORT(args, event, machine);

		LOG_INF("=== Got Pair Req ===");

		uint8_t **tk = (uint8_t **)args;
		*tk = monitor->cryptoStore;

		break;

	case (EVENT_PAIRING_SUCCESS):
		/* Stop pairing timeout */
		k_timer_stop(&timeoutTimer);

		LOG_INF("=== Secure connection stablished ===");

		/* Reject upcoming OOB pairing requests */
		bt_set_oob_data_flag(false);

		/* Start relay detection timeout */
		k_timer_start(&timeoutTimer, TIMEOUT_DETECT_MS, 0);

		err = notify_relayData(machine->conn, monitor->chanInit.idBuff,
				       monitor->chanInit.idLen);
		IF_ERR_ABORT(err, event, machine);

		machine->currState = STATE_DETECT;
		break;

	default:
		__unHandledEvent(STATE_PAIRING, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static void __verifierState_detect(stateMachine_t *machine,
				 stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	eventData_t *data = (eventData_t *)args;
	int err;

	if (event == EVENT_GOT_RELAY_DATA) {
		IF_NULL_ABORT(args, event, machine);

		LOG_DBG("=== Got Relay Data ===");

		/* Stop relay dectection timeout */
		k_timer_stop(&timeoutTimer);

		if (!atomic_test_bit(&monitor->dapConnCapa, BT_DAP_FLAG_OOB)) {
			err = __decryptBuff(monitor->cryptoStore, data->data,
					&data->len);
			IF_ERR_ABORT(err, event, machine);
		}

		monitor->chanData.serialBuff = data->data;
		monitor->chanData.serialLen = data->len;

		err = (int)runChallenge(&monitor->chanChall,
					&monitor->chanData);

		if (err != (int)WioLink_ChallengePassed) {
			LOG_WRN(CHAN_WARN_MSG, CHAL_RECIP_THRESHOLD);
			// __skg_abort(machine, event, machine->conn,
			//             BT_DAP_ERR_ABORT);
			// return;
		}

		monitor->authTime = (uint32_t)k_uptime_get_32()
				    - monitor->authTime;

		LOG_INF("=== Authenticated link \x1B[1;32m%ums\x1B[0m ===",
			monitor->authTime);

		machine->currState = STATE_AUTHENTICATED;

	} else {
		__unHandledEvent(STATE_DETECT, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, (void *)monitor->genTime);
}

static void __verifierState_authenticated(stateMachine_t *machine,
				     stateEvent_t event, void *args)
{
	// skgMonitor_t *monitor = (skgMonitor_t *)machine->data;

	__unHandledEvent(STATE_AUTHENTICATED, event);

	// monitor->stateCallback(machine, event, 0, NULL);
}

static inline void __proverState_idle(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	eventData_attempConn_t *attemptConn = (eventData_attempConn_t *)args;
	int err;

	if (event == EVENT_ATTEMPT_CONN) {
		IF_NULL_ABORT(args, event, machine);

		LOG_DBG("\x1B[1;32m=== Attempt DAP ===\x1B[0m");

		machine->conn = bt_conn_create_le(attemptConn->addr,
						  attemptConn->param);

		err = machine->conn ? 0 : -ENOTCONN;
		IF_ERR_ABORT(err, event, machine);

		/* Start Init timeout */
		k_timer_start(&timeoutTimer, TIMEOUT_INIT_CHAR_MS, 0);
		machine->currState = STATE_INIT;

	} else {
		__unHandledEvent(STATE_IDLE, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static inline void __proverState_init(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	int err;

	if (event == EVENT_CONNECTED) {
		IF_NULL_ABORT(args, event, machine);

		machine->conn = (struct bt_conn *)args;
		monitor->authTime = (uint32_t)k_uptime_get_32();

		/* Cancel init timeOut */
		k_timer_stop(&timeoutTimer);

		monitor->stateCallback(machine, event, 0, NULL);

		LOG_DBG("=== Connected to device ===");

		err = bt_dap_discover(machine->conn, &monitor->handles);
		IF_ERR_ABORT(err, event, machine);

		do {
			__getRand32(&monitor->pid);
		} while ((monitor->pid & 0x0000FFFF) == WIO_MAN_ID_U32);

		LOG_DBG("=== Generated PID: %08X ===", monitor->pid);

		WioPRNG_srand(&monitor->reconPrng, monitor->pid);
		WioPRNG_srand(&monitor->pidPrng, monitor->pid ^ WIO_MAN_ID_U32);

		__generatePowerIds(monitor);
		__setPowerIds(monitor);
		__shuffleTxPowers(monitor);

		/* Read DAP Parameters */
		struct bt_gatt_read_params read_params;
		uint16_t len;

		read_params.single.handle = monitor->handles.device;

		err = bt_dap_read(machine->conn, &read_params, monitor->temp,
				  &len);
		IF_ERR_ABORT(err, event, machine);

		err = (len != 1) ? -EINVAL : 0;
		IF_ERR_ABORT(err, event, machine);

		/* Negotiate DAP Parameters */
		monitor->dapConnCapa = (int)monitor->temp[0];
		monitor->dapConnCapa = __conf_dap_capa(monitor->dapConnCapa);

		memcpy(monitor->temp, &monitor->pid, sizeof(uint32_t));
		monitor->temp[sizeof(uint32_t)] = (uint8_t)__get_dap_capa();

		/* Write own DAP Parameters */
		struct bt_gatt_write_params write_params;
		write_params.handle = monitor->handles.device;
		write_params.data = monitor->temp;
		write_params.length = sizeof(uint32_t) + sizeof(uint8_t);

		err = bt_dap_write(machine->conn, &write_params);
		IF_ERR_ABORT(err, event, machine);

		memset(monitor->temp, 0, sizeof(uint32_t) + sizeof(uint8_t));

		/* Subscribe to DAP Notifiers */
		err = bt_dap_subscribe(machine->conn, monitor->subParam,
					       &monitor->handles);
		IF_ERR_ABORT(err, event, machine);

		err = scanForProbes();
		IF_ERR_ABORT(err, event, machine);

		monitor->genTime = (uint32_t)k_uptime_get_32();

		err = advertiseProbes(probeSet, ADV_SET_SIZE);
		IF_ERR_ABORT(err, event, machine);

		/* Start SKG timeout */
		k_timer_start(&timeoutTimer, TIMEOUT_SKG_MS, 0);

		machine->currState = STATE_PROBE;
	} else {
		__unHandledEvent(STATE_INIT, event);
		return;
	}
}

static inline void __proverState_probe(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	eventData_probe_t *probe = (eventData_probe_t *)args;
	static eventData_probe_t *probeArr;
	uint8_t id;
	int err;

	switch (event) {
	case (EVENT_GOT_PROBE):
		IF_NULL_ABORT(args, event, machine);

		id = __id2index(monitor, probe->id);
		probe->id = 0;
		if (id == UNKNOWN_ADV_ID || monitor->gotId[id])
			return;    //Ignore wrong IDs and repeated ones

		LOG_DBG("=== Got Probe %d ===", id);

		/**
		 * \note probeArr is the base of the bluetooth_dap.c probe array
		 *       used to limit repeated submissions to the FSM. It is
		 *       saved in the state machine to clear it when the
		 *       BT_DAP_CONST_PROBE_REPEAT value was raised.
		 */
		if (monitor->echoCounter == 0) {
			probeArr = probe;
		}

		__processProbe(monitor, probe, id);

		if (monitor->gotAdvance &&
		    monitor->probe.size == ADV_SET_SIZE) {
			monitor->gotAdvance = false;

			err = __prover_quantize(machine);
			IF_ERR_ABORT(err, event, machine);

			if (monitor->local.bitLen >= monitor->nBitsKey)
				machine->currState = STATE_RECON;
		}

		break;

	case (EVENT_PROBE_UPDATE):
		IF_NULL_ABORT(args, event, machine);
		u8_t update = (u8_t)(u32_t)args;// Single cast raises warning

		if (update == BT_DAP_CONST_PROBE_ADVANCE) {
			if (monitor->probe.size == ADV_SET_SIZE) {
				err = __prover_quantize(machine);
				IF_ERR_ABORT(err, event, machine);

			} else {
				monitor->gotAdvance = true;
			}

			if (monitor->local.bitLen >= monitor->nBitsKey) {
				machine->currState = STATE_RECON;
			}

		} else if (update == BT_DAP_CONST_PROBE_REPEAT) {
			LOG_DBG("=== Block timed out ===");

			flushChannelProbe(&monitor->probe);

			__shuffleTxPowers(monitor);
			__generatePowerIds(monitor);
			__setPowerIds(monitor);

			memset(probeArr, 0,
			       ADV_SET_SIZE * sizeof(eventData_probe_t));
			memset(monitor->gotId, false,
			       ADV_SET_SIZE * sizeof(bool));
		}

		break;

	default:
		__unHandledEvent(STATE_PROBE, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static inline void __proverState_recon(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	eventData_t *synd = (eventData_t *)args;
	int err;

	if (event == EVENT_GOT_SYNDROME) {
		IF_NULL_ABORT(args, event, machine);

		err = stopAdvertising();
		IF_ERR_ABORT(err, event, machine);

		LOG_DBG("=== Got Syndrome ===");

		/* Stop SKG timeout */
		k_timer_stop(&timeoutTimer);

		/* Correct to the Verifier's Key */
		WioLink_ShuffleSyndrome(&monitor->recon,
					&monitor->local,
					&monitor->reconPrng);

		if (synd->len !=
		    (monitor->recon.shuffleNum * monitor->recon.codeNum)) {
			err = -EINVAL;
			__skg_abort(machine, event, NULL, err);
		}

		for (uint8_t i = 0 ; i < monitor->recon.shuffleNum ; ++i) {
			memcpy(monitor->recon.syndromeExtern + i*MAX_CODEWORDS,
			       synd->data + i*monitor->recon.codeNum,
			       monitor->recon.codeNum);
		}

		WioLink_ShuffleCorrect(&monitor->recon, &monitor->local);

		monitor->genTime = (uint32_t)k_uptime_get_32()
				   - monitor->genTime;

		/* Provide SS to Verifier */
		WioLink_Syndrome(&monitor->recon,
				&monitor->local,
				&monitor->reconPrng);

		printk("Corrected Key:");
		for (uint8_t i = 0 ; i < monitor->local.byteLen ; ++i)
			printk(" %d", monitor->local.key[i]);
		printk("\n");

		struct bt_gatt_write_params write_params;

		write_params.handle = monitor->handles.syndrome;
		write_params.data = monitor->recon.syndromeLocal;
		write_params.length = monitor->recon.codeNum;

		err = bt_dap_write(machine->conn, &write_params);
		IF_ERR_ABORT(err, event, machine);

		LOG_INF("=== Generated key in %ums ===", monitor->genTime);

		/* Hash and store final key */
		err = __addKeyToCryptoStore(monitor);
		IF_ERR_ABORT(err, event, machine);

		printk("Hashed Key:");
		for (uint8_t i = 0 ; i < TC_SHA256_DIGEST_SIZE ; ++i)
			printk(" %02X", monitor->cryptoStore[i]);
		printk("\n");

		if (atomic_test_bit(&monitor->dapConnCapa, BT_DAP_FLAG_OOB)) {
			/* If both devices are OOB compatible create a bond */
			/* Start pairing timeout */
			k_timer_start(&timeoutTimer, TIMEOUT_PAIR_MS, 0);

			bt_set_oob_data_flag(true);
			err = bt_conn_set_security(machine->conn,
						   BT_SECURITY_L3);
			IF_ERR_ABORT(err, event, machine);

			machine->currState = STATE_PAIRING;
		} else {
			/* Else, use OTT encryption for relay detection phase */
			/* Start relay detection timeout */
			k_timer_start(&timeoutTimer, TIMEOUT_DETECT_MS, 0);

			machine->currState = STATE_DETECT;
		}

	} else {
		__unHandledEvent(STATE_RECON, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static inline void __proverState_pairing(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;

	switch (event) {
	case (EVENT_PAIRING_REQUEST):
		IF_NULL_ABORT(args, event, machine);

		LOG_INF("=== Got Pair Req ===");

		uint8_t **tk = (uint8_t **)args;
		*tk = monitor->cryptoStore;

		return;

	case (EVENT_PAIRING_SUCCESS):
		/* Stop pairing timeout */
		k_timer_stop(&timeoutTimer);

		bt_set_oob_data_flag(false);

		LOG_INF("=== Secure connection stablished ===");

		/* Start relay detection timeout */
		k_timer_start(&timeoutTimer, TIMEOUT_DETECT_MS, 0);

		machine->currState = STATE_DETECT;

		break;

	default:
		__unHandledEvent(STATE_PAIRING, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, NULL);
}

static inline void __proverState_detect(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	eventData_t *data = (eventData_t *)args;
	struct bt_gatt_write_params write_params;
	int err;
	uint8_t len;

	if (event == EVENT_GOT_RELAY_DATA) {
		IF_NULL_ABORT(args, event, machine);

		LOG_DBG("=== Got Relay Block ID %d ===", data->len);

		/* Stop relay dectection timeout */
		k_timer_stop(&timeoutTimer);

		if (!atomic_test_bit(&monitor->dapConnCapa, BT_DAP_FLAG_OOB)) {
			err = __decryptBuff(monitor->cryptoStore, data->data,
					&data->len);
			IF_ERR_ABORT(err, event, machine);
		}

		/* Select requested blocks by Verifier */
		monitor->chanInit.idBuff = data->data;
		monitor->chanInit.idLen = data->len;

		err = (int)resetChallenge(&monitor->chanChall,
					  &monitor->chanInit);

		if (err != (int)WioLink_ChallengePassed) {
			LOG_ERR("Failed to initialize channel test %d", err);
			__skg_abort(machine, event, NULL, BT_DAP_ERR_ABORT);
		}

		/* Format required information */
		err = (int)serializeChallenge(&monitor->chanChall,
					      &monitor->chanData);

		if (err != (int)WioLink_ChallengePassed) {
			LOG_ERR("Failed to serialize channel test %d", err);
			__skg_abort(machine, event, NULL, BT_DAP_ERR_ABORT);
		}

		/* Write values accordingly LL/OTT encryption */
		write_params.handle = monitor->handles.data_relay;

		if (atomic_test_bit(&monitor->dapConnCapa, BT_DAP_FLAG_OOB)) {
			write_params.data = monitor->chanData.serialBuff;
			write_params.length = monitor->chanData.serialLen;

		} else {
			len = monitor->chanData.serialLen;
			memcpy(monitor->temp, monitor->chanData.serialBuff,
			       len);

			err = __encryptBuff(monitor->cryptoStore, monitor->temp,
					&len);
			IF_ERR_ABORT(err, event, machine);

			write_params.data = monitor->temp;
			write_params.length = len;
		}

		err = bt_dap_write(machine->conn, &write_params);
		IF_ERR_ABORT(err, event, machine);

		monitor->authTime = (uint32_t)k_uptime_get_32()
				    - monitor->authTime;

		LOG_INF("=== Authenticated link \x1B[1;32m%ums\x1B[0m ===",
			monitor->authTime);

		machine->currState = STATE_AUTHENTICATED;

		//Give some time for the verifier to receive and process the msg
		k_sleep(TIME_PROVER_WAIT_MS);

	} else {
		__unHandledEvent(STATE_DETECT, event);
		return;
	}

	monitor->stateCallback(machine, event, 0, (void *)monitor->genTime);
}

static inline void __proverState_authenticated(stateMachine_t *machine,
				       stateEvent_t event, void *args)
{
	// skgMonitor_t *monitor = (skgMonitor_t *)machine->data;

	__unHandledEvent(STATE_AUTHENTICATED, event);

	// monitor->stateCallback(machine, event, 0, NULL);
}

static void __conn_iter(struct bt_conn *conn, void *data)
{
	stateMachine_t *machine = (stateMachine_t *)data;
	int err;

	if (conn == machine->conn) {
		if (((skgMonitor_t *)machine->data)->disconnect) {
			err = bt_conn_disconnect(conn,
					BT_HCI_ERR_LOCALHOST_TERM_CONN);
			if (err)
				LOG_ERR("Error while disconnecting %d!", err);
		}

		err = bt_unpair(BT_ID_DEFAULT, bt_conn_get_dst(conn));
		if (err)
			LOG_ERR("Error while removing pair data %d!", err);

		bt_conn_unref(conn);
		if (machine->mode == DAP_MODE_PROVER)
			bt_conn_unref(conn);
			//The prover has an extra reference, so unref twice
	}
}

static void __skg_reset(stateMachine_t *machine)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;

	k_timer_stop(&timeoutTimer);

	LOG_DBG("Resetting SKG!");

	bt_set_oob_data_flag(false);

	stopAdvertising();
	stopScanning();

	bt_conn_foreach(BT_CONN_TYPE_LE, __conn_iter, machine);

	machine->conn = NULL;

	__resetSkgMonitor(monitor, machine->mode, monitor->nBitsKey,
			  monitor->stateCallback);

	machine->currState = STATE_IDLE;
}

static int __skg_abort(stateMachine_t *machine, stateEvent_t event, void *args,
		       int err)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	struct bt_conn *conn;

	if (event == EVENT_DISCONNECTED) {
		err = BT_DAP_ERR_PAIRING_DISCONNECT;

		if (!machine->conn)
			return 0;
	} else {
		monitor->disconnect = true;
	}

	LOG_INF("Aborting in %s: %d", stateStrings[machine->currState], err);

	conn = machine->conn;// Improve on this ?
	__skg_reset(machine);
	machine->conn = conn;

	monitor->stateCallback(machine, EVENT_ABORT, err, args);

	machine->conn = NULL;

	return 0;
}

static stateFunction_t *const __functionTable[DAP_MODE_INVALID][STATE_NUM] = {
	{__verifierState_idle,
	__verifierState_init,
	__verifierState_probe,
	__verifierState_recon,
	__verifierState_pairing,
	__verifierState_detect,
	__verifierState_authenticated},
	{__proverState_idle,
	__proverState_init,
	__proverState_probe,
	__proverState_recon,
	__proverState_pairing,
	__proverState_detect,
	__proverState_authenticated}
};

/**
 * Public API
 */
int initStateMachine(stateMachine_t *machine,
		     bt_le_dap_mode_t mode, uint16_t keyLength, stateCb_t cb)
{
	int err;

	if (mode >= DAP_MODE_INVALID || cb == NULL)
		return -EINVAL;

	entropy = device_get_binding(CONFIG_ENTROPY_NAME);
	if (!entropy) {
		LOG_ERR("No entropy device found!");
		return -ENXIO;
	}

	err = initAdvertiseLogic();
	if (err) {
		LOG_ERR("Could not initialize Advertising Logic!");
		return err;
	}

	err = initScanLogic();
	if (err) {
		LOG_ERR("Could not initialize Scan Logic!");
		return err;
	}

	if (mode == DAP_MODE_VERIFIER) {
		set_capaPID((uint8_t)__get_dap_capa());

		/* Static service declaration linkage stubs */
		__skgsvc_stub_init();
		__rlsvc_stub_init();

	} else if (mode == DAP_MODE_PROVER) {
		err = initCharacteristicAPI();
		if (err)
			LOG_ERR("Could not initialize Characteristic API");
	}

	k_timer_init(&timeoutTimer, __timeOutExpiry, NULL);
	k_timer_init(&probeTimer, __probeExpiry, NULL);
	k_work_q_start(&machineQueue, fsm_stack_area,
		       K_THREAD_STACK_SIZEOF(fsm_stack_area), FSM_PRIORITY);
	for (uint8_t i = 0 ; i < FSM_QUEUE_CAP ; ++i) {
		k_delayed_work_init(&(fsmWork[i].work), __submitEvent);
		fsmWork[i].free = true;
	}

	machine->currState = STATE_IDLE;
	machine->data = &skgMon;
	machine->mode = mode;

	__resetSkgMonitor(machine->data, machine->mode, keyLength, cb);

	for (uint8_t i = 0 ; i < ADV_SET_SIZE ; ++i) {
		probeSet[i].data = (skgMon.txPowIdentifiersArr +
				    i*sizeof(uint32_t));
		probeSet[i].len = sizeof(uint32_t);
	}

	LOG_DBG("Initialized State Machine");
	return 0;
}

int runStateMachine(stateMachine_t *machine,
		    stateEvent_t event, void *args)
{
	fsmWork_t *localWork;

	if (machine->currState >= STATE_NUM)
		return -EINVAL;

	if (event >= EVENT_NUM)
		return -EINVAL;

	switch (event) {
	case (EVENT_STOP_ADVERTISING):
		if (machine->currState != STATE_INIT)
			return -EINVAL;

		return stopAdvertising();
	case (EVENT_PAIRING_REQUEST):
		if (machine->currState != STATE_PAIRING)
			return -EINVAL;

		__functionTable[machine->mode][STATE_PAIRING]
			(machine, EVENT_PAIRING_REQUEST, args);
		return 0;
	case (EVENT_ENCRYPT):
		return __encryptEvent(machine, args);
	case (EVENT_DECRYPT):
		return __decryptEvent(machine, args);
	default:
		break;
	}

	machine->prevState = machine->currState;

	localWork = __getFreeWork();
	if (!localWork) {
		LOG_ERR("There is no work available to queue!!");
		return -ENOBUFS;
	}
	localWork->free = false;

	localWork->machine = machine;
	localWork->event = event;
	localWork->args = args;

	return k_delayed_work_submit_to_queue(&machineQueue,
					      &(localWork->work), 0);
}

/**
 * State-wise event handler definitions
 */
/**

 * \brief Finds a free work object and passes it to be enqueued
 */
static fsmWork_t *__getFreeWork()
{
	for (uint8_t i = 0 ; i < FSM_QUEUE_CAP ; ++i) {
		if (fsmWork[i].free)
			return &fsmWork[i];
	}

	return NULL;
}

/**

 * \brief Dispatches events to be serially processed outside the system WorkQ
 */
static void __submitEvent(struct k_work *item)
{
	fsmWork_t *ptr = CONTAINER_OF(item, fsmWork_t, work);

	switch (ptr->event) {
	case (EVENT_ABORT):
		__skg_abort(ptr->machine, ptr->event, ptr->args,
			    BT_DAP_ERR_ABORT);
		ptr->free = true;
		return;
	case (EVENT_TIMEOUT):
		LOG_ERR("Timing out!");
		__skg_abort(ptr->machine, ptr->event, ptr->args,
			    BT_DAP_ERR_TIMEOUT);
		ptr->free = true;
		return;
	case (EVENT_DISCONNECTED):
		__skg_abort(ptr->machine, ptr->event, ptr->args,
			    BT_DAP_ERR_PAIRING_DISCONNECT);
		ptr->free = true;
		return;
	default:
		break;
	}

	__functionTable[ptr->machine->mode][ptr->machine->currState]
			(ptr->machine, ptr->event, ptr->args);

	ptr->free = true;
}


static void __timeOutExpiry(struct k_timer *timer_id)
{
	runStateMachine(fsmWork[0].machine, EVENT_TIMEOUT, NULL);
}

static void __probeExpiry(struct k_timer *timer_id)
{
	runStateMachine(fsmWork[0].machine, EVENT_PROBE_TIMEOUT, NULL);
}

/**

 * \brief OTT in place encryption executed directly on the caller thread
 */
static int __encryptEvent(stateMachine_t *machine, eventData_crypto_t *trans)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	struct tc_aes_key_sched_struct sched;

	if (trans->conn != machine->conn) {
		LOG_ERR("No key has been generated for this connection!");
		return -EINVAL;
	}

	if (!tc_aes128_set_encrypt_key(&sched, monitor->cryptoStore)) {
		LOG_ERR("Failed to set encryption key!");
		return -EINVAL;
	}

	if (!tc_cbc_mode_encrypt(trans->dout, trans->olen, trans->din,
				 trans->ilen, iv, &sched)) {
		LOG_ERR("Failed to encrypt!");
		return -EINVAL;
	}

	return 0;
}

/**

 * \brief OTT in place decryption executed directly on the caller thread
 */
static int __decryptEvent(stateMachine_t *machine, eventData_crypto_t *trans)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	struct tc_aes_key_sched_struct sched;

	if (trans->conn != machine->conn) {
		LOG_ERR("No key has been generated for this connection!");
		return -EINVAL;
	}

	if (!tc_aes128_set_decrypt_key(&sched, monitor->cryptoStore)) {
		LOG_ERR("Failed to set encryption key!");
		return -EINVAL;
	}

	int err = tc_cbc_mode_decrypt(trans->dout, trans->olen, trans->din,
				 trans->ilen, iv, &sched);
	if (err == 1) {
		LOG_ERR("Failed to decrypt! (Invalid)");
		return -EINVAL;
	} else if (err == 2) {
		LOG_ERR("Failed to decrypt! (Key mismatch)");
		return BT_DAP_ERR_ABORT;
	}

	return 0;
}

/**
 * Private helper definitions
 */
static void __getRand32(uint32_t *random)
{
	u8_t buffer[5];
	int err;

	buffer[4] = 0;

	err = entropy_get_entropy(entropy, buffer, 4);
	if (err) {
		LOG_ERR("Failed to extract entropy (err %d)", err);
		*random = 0;
		return;
	}

	if (buffer[4] != 0)
		LOG_WRN("entropy_get_entropy buffer overflow");

	memcpy(random, buffer, sizeof(uint32_t));
}

static void __resetReconciledKey(WioLink_CandidateKey_t *key,
		uint8_t *keyBuffer,
		const uint16_t keyLength)
{
	key->key = keyBuffer;
	key->bitLen = 0;
	key->byteLen = 0;
	key->totalBits = keyLength;

	memset(key->key, 0, WIOLINK_SKG_KEY_LENGTH_CAPACITY);
}

/**

 * \brief Gracefully resets all monitor values to their initial state
 */
static void __resetSkgMonitor(skgMonitor_t *monitor, bt_le_dap_mode_t mode,
			      const uint16_t keyLengthBits, const stateCb_t cb)
{
	// memset(monitor, 0, sizeof(skgMonitor_t));
	monitor->stateCallback = cb;

	k_timer_stop(&timeoutTimer);
	k_timer_stop(&probeTimer);

	// Set advertising structures
	monitor->txPowIndices = __txPowersIdxs;
	monitor->txPowIdentifiers = txPowersIds;
	monitor->txPowIdentifiersArr = txPowersIdsArr;
	memset(monitor->txPowIdentifiers, 0, ADV_SET_SIZE*sizeof(uint32_t));

	monitor->gotId = gotIdBuffer;
	memset(monitor->gotId, 0, ADV_SET_SIZE*sizeof(bool));

	monitor->pid = 0;

	monitor->gotAdvance = false;
	monitor->disconnect = false;

	// Initialize skg structures
	monitor->probe.samples = samplesBuffer;
	monitor->probe.size = 0;
	memset(monitor->probe.samples, 0,
	       ADV_SET_SIZE*sizeof(WioLink_ChannelSample_t));

	monitor->echoCounter = 0;
	monitor->genTime = 0;
	monitor->authTime = 0;
	monitor->nBitsKey = keyLengthBits;

	monitor->quant.nbytes = getQuantizationByteLength(ADV_SET_SIZE);
	monitor->quant.token = quanBuffer;
	memset(monitor->quant.token, 0, monitor->quant.nbytes);

	monitor->recon.discards = discardsBuff;
	memset(monitor->recon.discards, 0, RECON_SYND_CAPACITY);
	monitor->recon.invPerm = invPermBuff;
	memset(monitor->recon.invPerm, 0, sizeof(uint16_t)*RECON_SYND_CAPACITY);
	monitor->recon.syndromeExtern = syndExtBuff;
	memset(monitor->recon.syndromeExtern, 0, RECON_SYND_CAPACITY);
	monitor->recon.syndromeLocal = syndLocalBuff;
	memset(monitor->recon.syndromeLocal, 0, RECON_SYND_CAPACITY);
	monitor->recon.shuffleNum = MAX_SHUFFLES;
	monitor->recon.discardNum = 0;

	/* Reinitialize any legacy key content to start with a clean slate */
	__resetReconciledKey(&monitor->local, localKeyBuff, monitor->nBitsKey);

	// Initialize PRNGs
	monitor->powPrng.mat1 = 45278;
	monitor->powPrng.mat2 = 7524;
	monitor->powPrng.tmat = 4124;

	monitor->pidPrng.mat1 = 101234;
	monitor->pidPrng.mat2 = 18;
	monitor->pidPrng.tmat = 42352351;

	monitor->reconPrng.mat1 = 101234;
	monitor->reconPrng.mat2 = 18;
	monitor->reconPrng.tmat = 42352351;

	// Initialize challenges
	monitor->varChall.c_type = challenge_var;
	if (monitor->varChall.handle == NULL)
		initChallenge(&(monitor->varChall), NULL);

	monitor->chanChall.c_type = challenge_chan;
	monitor->chanInit.idBuff = chalIdxBuff;
	monitor->chanInit.idLen = 0;
	monitor->chanInit.keyLengthBits = keyLengthBits;

	if (mode == DAP_MODE_VERIFIER)
		monitor->chanInit.getRand = __getRand32;
	else
		monitor->chanInit.getRand = NULL;

	if (monitor->chanChall.handle == NULL)
		initChallenge(&(monitor->chanChall), &(monitor->chanInit));
	else
		resetChallenge(&(monitor->chanChall), &(monitor->chanInit));

	monitor->chanData.rssiValues = chalRssiBuff;
	monitor->chanData.txPowValues = chalTxPowBuff;
	monitor->chanData.ctrlRssi = chalCtrlRssiBuff;
	monitor->chanData.serialBuff = chalSerialBuff;

	memset(monitor->chanData.rssiValues, 0,
	       CHAL_TOKEN_CAPACITY*sizeof(int8_t));
	memset(monitor->chanData.txPowValues, 0,
	       CHAL_TOKEN_CAPACITY*sizeof(int8_t));
	monitor->chanData.pairNum = 0;

	memset(monitor->chanData.ctrlRssi, -50, NUM_RSSI_CTRL*sizeof(int8_t));
	monitor->chanData.ctrlNum = NUM_RSSI_CTRL;

	memset(monitor->chanData.serialBuff, 0,
	       CHAL_CHANNEL_SER_BUFF_CAPACITY*sizeof(uint8_t));
	monitor->chanData.serialLen = 0;

	// Set crypto storage
	monitor->cryptoStore = keyDigestBuff;
	memset(monitor->cryptoStore, 0, TC_SHA256_DIGEST_SIZE);

	monitor->temp = tempBuff;
	memset(monitor->temp, 0, MAX_ENCRYPT_PAYLOAD_LEN);
}

/**

 * \brief Returns local DAP capabilities
 *
 * \return Local DAP capabilities
 */
static int __get_dap_capa(void)
{
	int cap = 0;

	if (IS_ENABLED(DAP_ZEPHYR_IMPLEMENTATION))
		atomic_set_bit(&cap, BT_DAP_FLAG_ZEPHYR);

	if (IS_ENABLED(DAP_OOB_COMPATIBLE))
		atomic_set_bit(&cap, BT_DAP_FLAG_OOB);

	return cap;
}

/**

 * \brief Performs local/remote DAP capability negotiation
 *
 * \return Negotiated DAP capabilities
 */
static int __conf_dap_capa(int extCap)
{
	// Can be done with AND, but this way it can be more "future proof"
	int cap = __get_dap_capa();

	if (!atomic_test_bit(&extCap, BT_DAP_FLAG_ZEPHYR))
		atomic_clear_bit(&cap, BT_DAP_FLAG_ZEPHYR);

	if (!atomic_test_bit(&extCap, BT_DAP_FLAG_OOB))
		atomic_clear_bit(&cap, BT_DAP_FLAG_OOB);

	return cap;
}

/**

 * \brief Extract \see ADV_SET_SIZE random PIDs from PRNG
 *
 * \note This function does not update the power IDs used for transmission, it
 *       only affects the IDs for RX parsing. Use \see __setPowerIds to update
 *       tranmission IDs.
 *
 * \param monitor Monitor object
 */
static void __generatePowerIds(skgMonitor_t *monitor)
{
	for (uint8_t i = 0 ; i < ADV_SET_SIZE; ++i)
		monitor->txPowIdentifiers[i] = WioPRNG_rand(&monitor->pidPrng);
}

/**

 * \brief Sets static PID array for transmission
 *
 * \note If called after \see advertiseProbes, this function will effectively
 *       update the probe set payloads without having to perform multiple calls
 *       to \see advertiseProbes.
 *
 * \param monitor Monitor object
 */
static void __setPowerIds(skgMonitor_t *monitor)
{
	memcpy(monitor->txPowIdentifiersArr, monitor->txPowIdentifiers,
	       sizeof(txPowersIds));
}

/**

 * \brief Randomly shuffle transmit power order using the device's TRNG
 *
 * \note If called after \see advertiseProbes, this function will effectively
 *       update the probe set tx power without having to perform multiple calls
 *       to \see advertiseProbes.
 *
 * \param monitor Monitor object
 */
static void __shuffleTxPowers(skgMonitor_t *monitor)
{
	uint32_t seed;

	__getRand32(&seed);
	WioPRNG_srand(&monitor->powPrng, seed);

	permute_bytes(monitor->txPowIndices, ADV_SET_SIZE, &monitor->powPrng);
	for (uint8_t i = 0 ; i < ADV_SET_SIZE ; ++i)
		probeSet[i].txp = __txPowers[monitor->txPowIndices[i]];
}

/**

 * \brief Translate from random PIDs to set indices
 *
 * \param monitor Monitor object
 * \param id 4 Byte identifier extracted from probe advertisement
 *
 * \return Probe index from 0 to (ADV_SET_SIZE - 1)
 *         \see UNKNOWN_ADV_ID if provided id is invalid
 */
static uint8_t __id2index(skgMonitor_t *monitor, uint32_t id)
{
	for (uint8_t i = 0 ; i < ADV_SET_SIZE; ++i) {
		if (id == monitor->txPowIdentifiers[i])
			return i;
	}

	return UNKNOWN_ADV_ID;
}

/**

 * \brief Common subroutine for probe processing
 *
 * \note This call takes care of token and channel data assignments as well as
 *       increasing probe size and echoCounter accordingly
 *
 * \param monitor Monitor object
 * \param probe Probe object to be processed
 * \param id Probe index of the processed probe
 */
static void __processProbe(skgMonitor_t *monitor, eventData_probe_t *probe,
			   uint8_t id)
{
	uint8_t pos;

	monitor->gotId[id] = true;
	monitor->probe.samples[id].RSSI = probe->rssi - RSSI_OFFSET;
	monitor->probe.samples[id].TSSI = __txPowers[monitor->txPowIndices[id]];

	pos = (monitor->echoCounter/ADV_SET_SIZE)*ADV_SET_SIZE + id;

	monitor->chanData.rssiValues[pos] = monitor->probe.samples[id].RSSI;
	monitor->chanData.txPowValues[pos] = monitor->probe.samples[id].TSSI;

	monitor->probe.size++;
	monitor->echoCounter++;
}

/**

 * \brief Prover quantization subroutine
 *
 * \note This call resets the gotId array, performs quantization, computes and
 *       sets new PIDs and shuffles their powers.
 *       If key is full, it writes to SKG:Probe to signal the verifier that it
 *       has finished extracting keys.
 *
 * \param machine FSM object
 *
 * \return Zero on success or negative (POSIX) in case of stack internal error.
 */
static int __prover_quantize(stateMachine_t *machine)
{
	skgMonitor_t *monitor = (skgMonitor_t *)machine->data;
	struct bt_gatt_write_params write_params;
	int err;

	memset(monitor->gotId, false,
	       ADV_SET_SIZE * sizeof(bool));

	runQuantization(&monitor->local,
			&monitor->probe,
			monitor->probe.size,
			&monitor->quant);
	monitor->probe.size = 0;

	__generatePowerIds(monitor);
	__shuffleTxPowers(monitor);
	__setPowerIds(monitor);

	if (monitor->local.bitLen >= monitor->nBitsKey) {
		err = stopScanning();
		if (err)
			return err;

		k_timer_stop(&probeTimer);

		// __truncateKey(&monitor->local);

		printk("Extracted Key:");
		for (uint8_t i = 0 ; i < monitor->local.byteLen ; ++i)
			printk(" %d", monitor->local.key[i]);
		printk("\n");

		monitor->temp[0] = BT_DAP_CONST_PROBE_ADVANCE;

		write_params.handle = monitor->handles.probe;
		write_params.data = monitor->temp;
		write_params.length = 1;

		return bt_dap_write(machine->conn, &write_params);
	}

	return 0;
}

/**

 * \brief Truncates key to requested size totalBits
 */
//static void __truncateKey(WioLink_CandidateKey_t *key)
//{
//	uint8_t diff;

//	if (key->bitLen <= key->totalBits)
//		return;

//	diff = key->bitLen - key->totalBits;
//	diff = (diff % 8) ? (diff / 8) + 1 : (diff / 8);

//	memset(key->key + key->byteLen - diff, 0, diff);
//	key->bitLen = key->totalBits;
//	key->byteLen -= diff;
//}

/**

 * \brief Hashes the generated key with SHA-256
 *
 * \param monitor Monitor object
 *
 * \return Zero on success or 1 if failure.
 */
static int __addKeyToCryptoStore(skgMonitor_t *monitor)
{
	struct tc_sha256_state_struct state;

	if (!tc_sha256_init(&state)) {
		LOG_ERR("Failed to initialize sha256 structure!");
		return 1;
	}

	if (!tc_sha256_update(&state, monitor->local.key,
			       monitor->local.byteLen)) {
		LOG_ERR("Failed to update sha256 structure!");
		return 1;
	}

	if (!tc_sha256_final(monitor->cryptoStore, &state)) {
		LOG_ERR("Failed to compute sha256!");
		return 1;
	}

	memset(state.leftover, 0, TC_SHA256_BLOCK_SIZE);

	return 0;
}

/**

 * \brief OTT AES-128 CBC PKCS7-padded encryption for non-OOB devices
 *
 * Encrypts a payload of up to 15 bytes
 *
 * \param key Pointer to encryption key
 * \param data Pointer to data to be encrypted
 * \param len Number of bytes to be encrypted
 *
 * \return Zero on success or -EINVAL
 */
static int __encryptBuff(uint8_t *key, uint8_t *data, uint8_t *len)
{
	static struct tc_aes_key_sched_struct sched;
	static uint8_t cipherText[2*TC_AES_BLOCK_SIZE];
	uint8_t tail = TC_AES_BLOCK_SIZE - (*len % TC_AES_BLOCK_SIZE);

	if (*len > MAX_ENCRYPT_PAYLOAD_LEN) {
		LOG_ERR("Encryption data too long");
		return -EINVAL;
	}

	//  PKCS7 Padding with block size = 16
	memset(data + *len, tail, tail);
	*len = *len + tail;

	if (!tc_aes128_set_encrypt_key(&sched, key)) {
		LOG_ERR("Failed to set encryption key!");
		return -EINVAL;
	}

	if (!tc_cbc_mode_encrypt(cipherText, TC_AES_BLOCK_SIZE + *len, data,
				 *len, iv, &sched)) {
		LOG_ERR("Failed to encrypt!");
		return -EINVAL;
	}

	memcpy(data, cipherText + TC_AES_BLOCK_SIZE, *len);

	return 0;
}

/**

 * \brief OTT AES-128 CBC PKCS7-padded decryption for non-OOB devices
 *
 * Decrypts a payload of up to 16 bytes
 *
 * \param key Pointer to encryption key
 * \param data Pointer to data to be decrypted
 * \param len Number of bytes to be decrypted
 *
 * \return Zero on success, -EINVAL or BT_DAP_ERR_KEY_MISMATCH
 */
static int __decryptBuff(uint8_t *key, uint8_t *data, uint8_t *len)
{
	static struct tc_aes_key_sched_struct sched;
	static uint8_t plainText[TC_AES_BLOCK_SIZE];

	if (*len > TC_AES_BLOCK_SIZE) {
		LOG_ERR("Faulty cipherText length!");
		return -EINVAL;
	}

	if (!tc_aes128_set_decrypt_key(&sched, key)) {
		LOG_ERR("Failed to set encryption key!");
		return -EINVAL;
	}

	if (!tc_cbc_mode_decrypt(plainText, *len,
				  data, *len, iv, &sched)) {
		LOG_ERR("Failed to decrypt!");
		return -EINVAL;
	}

	uint8_t pad = plainText[*len - 1];

	for (uint8_t i = 1 ; i < pad ; ++i) {
		if (plainText[*len - 1 - i] != pad) {
			LOG_ERR("Failed to decrypt! %02X != %02X", pad,
				plainText[*len - 1 - i]);
			return BT_DAP_ERR_ABORT;
		}
	}

	*len = *len - pad;
	memcpy(data, plainText, *len);

	return 0;
}
