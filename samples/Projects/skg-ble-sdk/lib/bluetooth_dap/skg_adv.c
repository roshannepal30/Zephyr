/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_adv.c
 * \brief Switching logic for multiple advertisements
 */

#include <zephyr.h>
#include <zephyr/types.h>

#include <settings/settings.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_vs.h>
#include <sys/byteorder.h>

#include "skg_adv.h"
#include "wio_uuid.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(skg_adv, CONFIG_SKG_LOG_LEVEL);

#define PROBE_PERIOD_MS             K_MSEC(20)
#define SEM_TIMEOUT_MS              K_MSEC(10)

/**
 * Internal state variables
 */
static bool broadcasting;
static bool probing;

static u8_t btLeMfgCon[] = {WIO_MAN_ID, 0x00, 0x00, 0x00, 0x00};
static u8_t privateID[16];

/**
 * Advertisement definitions
 */
static struct bt_data skgPrompt[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR | BT_LE_AD_GENERAL),
	WIO_UUIDS_SKG_PROMPT,
	BT_DATA(BT_DATA_MANUFACTURER_DATA, btLeMfgCon, ARRAY_SIZE(btLeMfgCon))
};

static struct bt_data skgPrompt_rsp[] = {
	BT_DATA(BT_DATA_UUID128_SOME, privateID, ARRAY_SIZE(privateID))
};

static const struct bt_le_adv_param *paramSkgPrompt = BT_LE_ADV_PARAM(
	BT_LE_ADV_OPT_CONNECTABLE | BT_LE_ADV_OPT_USE_NAME,
	0x0020, 0x0020);

/**
 * Probe definitions
 */
static struct bt_data probe[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR),
	WIO_UUID_PROBE,
	BT_DATA(BT_DATA_MANUFACTURER_DATA, btLeMfgCon, ARRAY_SIZE(btLeMfgCon))
};

static const struct bt_le_adv_param *paramProbe = BT_LE_ADV_PARAM(0,
								  0x0050,
								  0x0050);
/**
 * Scheduling
 */
static struct k_sem advertiseSem;
static struct k_timer probeTimer;
static bool pdsw;

struct bt_probe_set {
	uint8_t pid;
	struct bt_skg_data *pd;
	uint8_t len;
};

static struct bt_probe_set pset;

#if defined(CONFIG_BT_CTLR_TX_PWR_DYNAMIC_CONTROL)
static void set_tx_power(u8_t handle_type, u16_t handle, s8_t *tx_pwr_lvl)
{
	struct bt_hci_cp_vs_write_tx_power_level *cp;
	struct bt_hci_rp_vs_write_tx_power_level *rp;
	struct net_buf *buf, *rsp = NULL;
	int err;

	buf = bt_hci_cmd_create(BT_HCI_OP_VS_WRITE_TX_POWER_LEVEL,
				sizeof(*cp));
	if (!buf) {
		LOG_ERR("Set TXP - unable to allocate command buffer");
		return;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	cp->handle = sys_cpu_to_le16(handle);
	cp->handle_type = handle_type;
	cp->tx_power_level = *tx_pwr_lvl;

	err = bt_hci_cmd_send_sync(BT_HCI_OP_VS_WRITE_TX_POWER_LEVEL,
				   buf, &rsp);
	if (err) {
		u8_t reason = rsp ?
			((struct bt_hci_rp_vs_write_tx_power_level *)
			  rsp->data)->status : 0;
		LOG_ERR("Set TXP error %d (reason 0x%02x)", err, reason);
		return;
	}

	rp = (void *)rsp->data;
	*tx_pwr_lvl = rp->selected_tx_power;
	// LOG_DBG("Selected TXP: %d", *tx_pwr_lvl);

	net_buf_unref(rsp);
}
#endif  /* CONFIG_BT_CTLR_TX_PWR_DYNAMIC_CONTROL */

static void probeHandler(struct k_work *work)
{
	int err = 0;

	err = k_sem_take(&advertiseSem, SEM_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Semaphore busy (reason %d)", err);
		return;
	}

	if (!probing) {
		LOG_ERR("Probing failed (disabled)");
		k_timer_stop(&probeTimer);
		k_sem_give(&advertiseSem);
		return;
	}

	if (pset.pd[pset.pid].len !=
	    (ARRAY_SIZE(btLeMfgCon) - WIO_MAN_ID_LEN)) {
		/* Skip this probe - malformed! */
		pset.pid = (pset.pid + 1) % pset.len;
		LOG_WRN("Probe handle (%d) skipped - length %d (expected %d)!",
			pset.pid, pset.pd[pset.pid].len,
			(int) (ARRAY_SIZE(btLeMfgCon) - WIO_MAN_ID_LEN));
		k_sem_give(&advertiseSem);
		return;
	}
	/* Add TXP variation */

	memcpy(btLeMfgCon + WIO_MAN_ID_LEN, pset.pd[pset.pid].data,
	       pset.pd[pset.pid].len);

	if (pdsw) {
		err = bt_le_adv_stop();
		if (err) {
			/* At this point we warn and exit - it will be
			 * be retried next cycle over PROBE_PERIOD_MS
			 */
			LOG_WRN("Probe handle (%d) failed to stop (reason %d)",
			pset.pid, err);
			k_sem_give(&advertiseSem);
			return;
		}
		pdsw = false;
	}

	err = bt_le_adv_start(paramProbe, probe, ARRAY_SIZE(probe), NULL, 0);
	if (err) {
		/* At this point we warn and exit - it will be
		 * be retried next cycle over PROBE_PERIOD_MS
		 */
		LOG_WRN("Probing handle (%d) failed (reason %d)", pset.pid,
			err);
		k_sem_give(&advertiseSem);
		return;
	}
	pdsw = true;

	/* Add TXP variation */
#if defined(CONFIG_BT_CTLR_TX_PWR_DYNAMIC_CONTROL)
	set_tx_power(BT_HCI_VS_LL_HANDLE_TYPE_ADV, 0, &pset.pd[pset.pid].txp);
#endif  /* CONFIG_BT_CTLR_TX_PWR_DYNAMIC_CONTROL */

	/* Updated PID for next cycle */
	pset.pid = (pset.pid + 1) % pset.len;
	k_sem_give(&advertiseSem);

	return;
}

K_WORK_DEFINE(probeWork, probeHandler);

static void probeTimerExpiry(struct k_timer *timer_id)
{
	pdsw = true;
	k_work_submit(&probeWork);
}

/**
 * Public API
 */
int initAdvertiseLogic(void)
{
	k_sem_init(&advertiseSem, 1, 1);
	k_timer_init(&probeTimer, probeTimerExpiry, NULL);
	broadcasting = false;
	probing = false;

	LOG_DBG("Initialized Advertising Logic.");
	return 0;
}

int advertiseSkgPrompt(struct bt_skg_data *prompt)
{
	int err;

	err = k_sem_take(&advertiseSem, SEM_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Semaphore busy (reason %d)", err);
		return err;
	}

	if (probing)
		k_timer_stop(&probeTimer);

	if (broadcasting || probing) {
		err = bt_le_adv_stop();
		if (err) {
			LOG_ERR("Advertising stop error: %d", err);
			k_sem_give(&advertiseSem);
			return err;
		}
		LOG_DBG("Stopped Advertising");
		broadcasting = false;
		probing = false;
	}

	if (prompt) {
		if (prompt->data && prompt->len <=
		    (ARRAY_SIZE(btLeMfgCon) - WIO_MAN_ID_LEN)) {
			memcpy(btLeMfgCon + WIO_MAN_ID_LEN,
			       prompt->data, prompt->len);
			skgPrompt[2].data_len = prompt->len + WIO_MAN_ID_LEN;
		} else {
			LOG_WRN("Data skipped (invalid length %d, max is %d)",
				prompt->len,
				(int)(ARRAY_SIZE(btLeMfgCon) - WIO_MAN_ID_LEN));
		}
	}

	err = bt_le_adv_start(paramSkgPrompt, skgPrompt, ARRAY_SIZE(skgPrompt),
			      skgPrompt_rsp, ARRAY_SIZE(skgPrompt_rsp));
	if (err) {
		LOG_ERR("Advertising failed (error %d)", err);
		k_sem_give(&advertiseSem);
		return err;
	}

#if defined(CONFIG_BT_CTLR_TX_PWR_DYNAMIC_CONTROL)
	if (prompt)
		set_tx_power(BT_HCI_VS_LL_HANDLE_TYPE_ADV, 0, &prompt->txp);
#endif  /* CONFIG_BT_CTLR_TX_PWR_DYNAMIC_CONTROL */

	broadcasting = true;
	LOG_DBG("Advertising SKG prompt");

	k_sem_give(&advertiseSem);
	return 0;
}

int advertiseProbes(struct bt_skg_data *probe, const uint8_t len)
{
	int err;

	err = k_sem_take(&advertiseSem, SEM_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Semaphore busy (reason %d)", err);
		return err;
	}

	if (!probe && !len) {
		LOG_ERR("Probing failed (no probes)");
		k_sem_give(&advertiseSem);
		return err;
	}

	if (probing)
		k_timer_stop(&probeTimer);

	if (broadcasting || probing) {
		err = bt_le_adv_stop();
		if (err) {
			LOG_ERR("Advertising stop (error %d)", err);
			k_sem_give(&advertiseSem);
			return err;
		}
		LOG_DBG("Stopped Advertising");
		broadcasting = false;
		probing = false;
	}

	pdsw = false;
	pset.pid = 0;
	pset.pd = probe;
	pset.len = len;
	k_timer_start(&probeTimer, 0, PROBE_PERIOD_MS);
	probing = true;

	LOG_DBG("Probing dispatched");
	k_sem_give(&advertiseSem);

	return 0;
}

int stopAdvertising(void)
{
	int err;

	err = k_sem_take(&advertiseSem, SEM_TIMEOUT_MS);
	if (err) {
		LOG_ERR("Semaphore busy (reason %d)", err);
		return err;
	}

	if (!broadcasting && !probing) {
		k_sem_give(&advertiseSem);
		return 0;
	}

	if (probing)
		k_timer_stop(&probeTimer);

	err = bt_le_adv_stop();
	if (err) {
		LOG_ERR("Advertising stop error %d", err);
		k_sem_give(&advertiseSem);
		return err;
	}
	LOG_DBG("Stopped Advertising");

	broadcasting = false;
	probing = false;
	memset(btLeMfgCon+2, 0, ARRAY_SIZE(btLeMfgCon)-2);

	/* Flush contents of internal mfg buffer */
	memset(btLeMfgCon + WIO_MAN_ID_LEN, 0,
	       ARRAY_SIZE(btLeMfgCon) - WIO_MAN_ID_LEN);

	k_sem_give(&advertiseSem);
	return 0;
}

uint8_t *getPrivateIdentity(void)
{
	return privateID;
}

void setPrivateIdentity(uint8_t *data)
{
	memcpy(privateID, data, 16);
}
