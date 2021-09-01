/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file bluetooth_dap_err.h
 * \brief Error code list for DAP
 */

#ifndef __BLUETOOTH_DAP_ERR_H__
#define __BLUETOOTH_DAP_ERR_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DAP Error code definitions
 */
#define BT_DAP_ERR_SUCCESS              0x00
#define BT_DAP_ERR_ABORT                0x01
#define BT_DAP_ERR_TIMEOUT              0x02
#define BT_DAP_ERR_PAIRING_DISCONNECT           0x03

#ifdef __cplusplus
}
#endif

#endif /* __BLUETOOTH_DAP_ERR_H__ */
