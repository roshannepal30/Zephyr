/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file callbacks.h
 * \brief Headers for service read/write/notify, and scan callbacks
 */

#ifndef __CALLBACKS_H__
#define __CALLBACKS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <zephyr/types.h>
#include <bluetooth/conn.h>

#define MAX_CHAR_LEN                    20

void callback_wrotePID(u8_t *pid);
void callback_matchedProbe(s8_t rssi, u32_t id);
void callback_clientSubscribed(void);
void callback_wroteProbe(u8_t val);
void callback_wroteSyndrome(u8_t *data, u8_t len);
void callback_wroteRelayData(u8_t *data, u8_t len);

void set_capaPID(uint8_t capa);

int notify_probe(struct bt_conn *conn, u8_t val);
int notify_syndrome(struct bt_conn *conn, const u8_t *syndrome, const u8_t len,
		    const u8_t repeats);
int notify_relayData(struct bt_conn *conn, const u8_t *data, const u8_t len);

#ifdef __cplusplus
}
#endif

#endif /* __CALLBACKS_H__ */
