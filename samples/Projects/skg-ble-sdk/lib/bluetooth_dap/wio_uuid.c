/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 *file wio_uuid.c
 *brief UUID container for SKG related services/characteristics
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <errno.h>
#include <zephyr.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

#include "wio_uuid.h"

/**
 * Advertisements
 */
const struct bt_data wio_uuid_probe = WIO_UUID_PROBE;

/**
 * Services/Characteristics
 */
struct bt_uuid_128 wio_uuid_skg = BT_UUID_INIT_128(WIO_UUID_SKG_SERVICE);
struct bt_uuid_128 wio_uuid_skg_device = BT_UUID_INIT_128(
					0xdf, 0x2e, 0xbd, 0xda,
					0x84, 0x5a, 0xf0, 0xb2,
					0x12, 0x4b, 0x03, 0xaa,
					0x2f, 0x49, 0x58, 0x10);
struct bt_uuid_128 wio_uuid_skg_probe = BT_UUID_INIT_128(
					0xdf, 0x2e, 0xbd, 0xda,
					0x84, 0x5a, 0xf0, 0xb2,
					0x12, 0x4b, 0x03, 0xaa,
					0x41, 0x50, 0x58, 0x10);
struct bt_uuid_128 wio_uuid_skg_syndrome = BT_UUID_INIT_128(
					0xdf, 0x2e, 0xbd, 0xda,
					0x84, 0x5a, 0xf0, 0xb2,
					0x12, 0x4b, 0x03, 0xaa,
					0x59, 0x53, 0x58, 0x10);

struct bt_uuid_128 wio_uuid_relay = BT_UUID_INIT_128(WIO_UUID_RELAY_SERVICE);
struct bt_uuid_128 wio_uuid_relay_data = BT_UUID_INIT_128(
					0xdf, 0x2e, 0xbd, 0xda,
					0x84, 0x5a, 0xf0, 0xb2,
					0x12, 0x4b, 0x03, 0xaa,
					0x41, 0x52, 0x58, 0x10);
