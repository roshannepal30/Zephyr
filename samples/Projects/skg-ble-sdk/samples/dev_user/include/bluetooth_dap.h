/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file bluetooth_dap.h
 * \brief Main public API for SKG and relay detection
 */

#ifndef __BLUETOOTH_DAP_H__
#define __BLUETOOTH_DAP_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum bt_le_dap_mode {
	DAP_MODE_VERIFIER,
	DAP_MODE_PROVER,

	DAP_MODE_INVALID
} bt_le_dap_mode_t;

struct bt_le_dap_cb {
	void (*started)(struct bt_conn *conn);
	void (*finished)(struct bt_conn *conn, int result, uint32_t gtime_ms);
	struct bt_le_dap_cb *_next;
};

typedef void bt_le_dap_scan_cb_t(const bt_addr_le_t *addr, s8_t rssi);

int bt_le_dap_enable(bt_le_dap_mode_t mode);
int bt_le_dap_set_identity(u8_t *identity);

int bt_le_dap_adv_start(void);
int bt_le_dap_adv_stop(void);

int bt_le_dap_scan_start(const struct bt_le_scan_param *param,
			 bt_le_dap_scan_cb_t cb);
int bt_le_dap_scan_stop(void);
/**
 *  Returns -EINVAL if param or peer NULL
 *  Returns -ENXIO if a DAP attribute was not found
 */
int bt_conn_create_le_dap(const bt_addr_le_t *peer,
			  const struct bt_le_conn_param *param);

int bt_le_dap_abort(void);

void bt_le_dap_cb_register(struct bt_le_dap_cb *cb);
int bt_conn_dap_encrypt(uint8_t *dout, uint16_t olen, const uint8_t *din,
			const uint16_t ilen, const struct bt_conn *conn);
int bt_conn_dap_decrypt(uint8_t *dout, uint16_t olen, const uint8_t *din,
			const uint16_t ilen, const struct bt_conn *conn);


#ifdef __cplusplus
}
#endif

#endif /* __BLUETOOTH_DAP_H__ */
