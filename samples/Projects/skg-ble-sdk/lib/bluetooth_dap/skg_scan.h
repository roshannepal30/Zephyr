/*
 * Copyright (c) 2018-2019, WIOsense GmbH & Co. KG
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in the
 * software license agreement which is part of this source code package.
 *
 */

/**
 * \file skg_scan.h
 * \brief LE Scanning and filtering logic implementation
 */

#ifndef __SKG_SCAN_H__
#define __SKG_SCAN_H__

#ifdef __cplusplus
extern "C" {
#endif

int initScanLogic(void);
int scanForProbes(void);
int stopScanning(void);

#ifdef __cplusplus
}
#endif

#endif /* __SKG_SCAN_H__ */
