

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
 * \def BT_DAP_ERR_SUCCESS
 * \brief DAP procedure concluded successfully
 */
#define BT_DAP_ERR_SUCCESS              0x00

/**
 * \def BT_DAP_ERR_ABORT
 * \brief DAP procedure was aborted
 *
 * This is a general catch-all error for an unsuccessful DAP procedure.
 */
#define BT_DAP_ERR_ABORT                0x01

/**
 * \def BT_DAP_ERR_TIMEOUT
 * \brief DAP procedure timed out
 */
#define BT_DAP_ERR_TIMEOUT              0x02

/**
 * \def BT_DAP_ERR_PAIRING_DISCONNECT
 * \brief Connection with DAP remote was terminated before DAP completed
 */
#define BT_DAP_ERR_PAIRING_DISCONNECT   0x03

/**
 * \def BT_DAP_ERR_DISCONNECT
 * \brief Connection with DAP remote was gracefully terminated
 */
#define BT_DAP_ERR_DISCONNECT           0x04

#ifdef __cplusplus
}
#endif

#endif /* __BLUETOOTH_DAP_ERR_H__ */
