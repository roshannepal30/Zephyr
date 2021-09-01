/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file wio_uuid.h
 * \brief UUID container for SKG related services/characteristics
 */

#ifndef __WIO_UUID_H__
#define __WIO_UUID_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <bluetooth/uuid.h>

#define WIO_MAN_ID			0x68, 0x08
#define WIO_MAN_ID_BK			0x08, 0x68
#define WIO_MAN_ID_U32			0x00000868
#define WIO_MAN_ID_LEN			2
#define WIO_DEVICE_PID_BYTE_LEN		4

#define WIO_UUID_SERVICE_COUNT		2
#define WIO_UUID_SKG_SERVICE		0xdf, 0x2e, 0xbd, 0xda,\
					0x84, 0x5a, 0xf0, 0xb2,\
					0x12, 0x4b, 0x03, 0xaa,\
					0x53, 0x57, 0x58, 0x10
#define WIO_UUID_RELAY_SERVICE		0xdf, 0x2e, 0xbd, 0xda,\
					0x84, 0x5a, 0xf0, 0xb2,\
					0x12, 0x4b, 0x03, 0xaa,\
					0x4c, 0x52, 0x58, 0x10

#define WIO_UUIDS_SKG_PROMPT		BT_DATA_BYTES(BT_DATA_UUID128_SOME,\
						      WIO_UUID_SKG_SERVICE)

#define WIO_UUID_PROBE			BT_DATA_BYTES(BT_DATA_UUID128_ALL,\
						      0xdf, 0x2e, 0xbd, 0xda,\
						      0x84, 0x5a, 0xf0, 0xb2,\
						      0x12, 0x4b, 0x03, 0xaa,\
						      0x15, 0x51, 0x50, 0x10)

/**
 * Advertisements
 */
extern const struct bt_data wio_uuid_probe;

/**
 * Services/Characteristics
 */
extern struct bt_uuid_128 wio_uuid_skg;
extern struct bt_uuid_128 wio_uuid_skg_device;
extern struct bt_uuid_128 wio_uuid_skg_probe;
extern struct bt_uuid_128 wio_uuid_skg_syndrome;

extern struct bt_uuid_128 wio_uuid_relay;
extern struct bt_uuid_128 wio_uuid_relay_data;

#ifdef __cplusplus
}
#endif

#endif /* __WIO_UUID_H__ */
