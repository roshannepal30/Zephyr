

/**
 * \file bluetooth_dap.h
 * \brief Main public API for SKG and relay detection
 */

#ifndef __BLUETOOTH_DAP_H__
#define __BLUETOOTH_DAP_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief DAP roles
 **/
typedef enum bt_le_dap_mode {
	DAP_MODE_VERIFIER,
	DAP_MODE_PROVER,

	DAP_MODE_INVALID
} bt_le_dap_mode_t;

/**
 * \brief DAP connection callback structure
 *
 * This structure is used for tracking the state of a DAP connection.
 * It is registered with the help of \see bt_le_dap_cb_register() API.
 * In case different modules of an application are interested in
 * tracking the connection status, it is allowed to register multiple
 * instances of this callback. If a callback is not of interest for
 * an instance, it may be set to NULL and will as a consequence not be
 * used for that instance.
 */
struct bt_le_dap_cb {
	/**
	 * \brief A new connection with a DAP compliant device is established.
	 *
	 * This callback notifies the application of the beginning of the DAP
	 * procedure with a compliant device.
	 *
	 * \note Returns a reference that the the user is responsible for
	 *       managing.
	 *
	 * \param conn New connection object.
	 */
	void (*started)(struct bt_conn *conn);

	/**
	 * \brief The DAP authentication has concluded
	 *
	 * This callback notifies the application of the end of a DAP procedure.
	 * In case the error parameter is non-zero it means the DAP procedure
	 * has failed.
	 *
	 * \note The user is responsible for the external management of the
	 * connection object
	 *
	 * \param conn Connection object.
	 * \param err Zero on success or error code otherwise, positive in case
	 *            of DAP error or negative (POSIX) in case of stack
	 *            internal error.
	 */
	void (*finished)(struct bt_conn *conn, int err, uint32_t gtime_ms);

	struct bt_le_dap_cb *_next;
};

/**
 * \brief Enable BLE Distributed Authentication Protocol
 *
 * This function must be called before any calls that use WIOsense's key
 * distribution and authentication stack.
 *
 * \param mode Specific Role for the device to perform during DAP negotiations.
 *
 * \return Zero on success or negative (POSIX) in case of error.
 */
int bt_le_dap_enable(bt_le_dap_mode_t mode);

/**
 * \brief Set a unique 128-bit identifier for the device
 *
 * This function sets a 128-bit long unique identifier for the BLE DAP device.
 * This function shall be called only before initialization of the BLE stack,
 * i.e. before calling bt_enable().
 *
 * \note If this function is not called a new random identity string will always
 * be generated internally upon each reset.
 *
 * \param identity Pointer to 16 byte long array containing the new identity
 *
 * \return Zero on success, -EINVAL on identity NULL, -EAGAIN if the stack is
 * already initialized.
 */
int bt_le_dap_set_identity(u8_t *identity);

/**
 * \brief Starts DAP advertising
 * 
 * \note Uses the native bt_le_adv_start function for advertising.
 * \note You MUST use bt_le_dap_adv_stop to stop advertising.
 *       DO NOT use the native function bt_le_adv_stop to stop advertising.
 *
 * \return Zero on success or negative (POSIX) in case of error.
 */
int bt_le_dap_adv_start(void);

/**
 * \brief Stop advertising the DAP prompt
 *
 * Stops ongoing advertising.
 * 
 * \note Uses the native bt_le_adv_stop function to stop advertising.
 *
 * \return Zero on success or negative (POSIX) in case of error.
 */
int bt_le_dap_adv_stop(void);

/**
 * \typedef bt_le_dap_scan_cb_t
 * \brief Callback type for reporting LE DAP scan results.
 *
 * A function of this type is given to \see bt_le_dap_scan_start function and
 * will be called for any discovered LE DAP enabled device.
 *
 * \param addr Advertiser LE address and type.
 * \param rssi Strength of advertiser signal.
 */
typedef void bt_le_dap_scan_cb_t(const bt_addr_le_t *addr, s8_t rssi);

/**
 * \brief Start (LE) scanning of DAP enabled devices
 *
 * Start LE scanning of DAP enabled devices with given parameters, and provide
 * results through the specified callback.
 *
 * \note This function uses the native bt_le_scan_start call and bt_le_scan_cb_t
 * callback to automatically parse advertisements and only return the relevant
 * information of DAP enabled devices.
 * \note You MUST use bt_le_dap_scan_stop to stop scanning.
 *       DO NOT use the native function bt_le_scan_stop to stop scanning.
 *
 * \param param Scan parameters.
 * \param cb Callback to notify scan results.
 *
 * \return Zero on success or negative (POSIX) in case of error,
 * -EINVAL if NULL and -EALREADY if already scanning.
 */
int bt_le_dap_scan_start(const struct bt_le_scan_param *param,
			 bt_le_dap_scan_cb_t cb);

/**
 * \brief Stop (LE) scanning of DAP enabled devices
 *
 * Stop ongoing LE DAP scanning.
 *
 * \note Uses the native bt_le_scan_stop to stop scanning.
 *
 * \return Zero on success or error code otherwise, positive in case
 * of protocol error or negative (POSIX) in case of error.
 */
int bt_le_dap_scan_stop(void);

/**
 * \brief Initiate an LE DAP connection to a remote device.
 *
 * Allows to initiate a new MITM-secure LE link to a remote peer using its
 * address. The reference to the connection is returned in \see bt_le_dap_cb.
 *
 * \param peer Remote address.
 * \param param Initial connection parameters.
 *
 * \return -EINVAL if param or peer NULL or negative (POSIX) in case of stack
 * internal error, zero otherwise.
 */
int bt_conn_create_le_dap(const bt_addr_le_t *peer,
			  const struct bt_le_conn_param *param);

/**
 * \brief Abort DAP procedures after they have initiated
 *
 * Performs a dry stop on the DAP negotiation and returns in \see bt_le_dap_cb
 *
 * \return Negative (POSIX) in case of error, zero otherwise.
 */
int bt_le_dap_abort(void);

/**
 * \brief Register DAP callbacks.
 *
 * Register callbacks to monitor the state of a DAP procedure.
 *
 * \param cb Pointer to callback struct data.
 */
void bt_le_dap_cb_register(struct bt_le_dap_cb *cb);

/**
 * \brief Encrypt using AES-128 CBC and the 128bit key derived from DAP
 *
 * This function is based on TinyCrypt, specifically tc_cbc_mode_encrypt.
 *
 * \note Assumes: - out buffer is large enough to hold the ciphertext + iv
 *                - out buffer is a contiguous buffer
 *                - in holds the plaintext and is a contiguous buffer
 *                - inlen gives the number of bytes in the in buffer
 *
 * \param dout OUT -- buffer to receive the ciphertext
 * \param olen IN -- length of ciphertext buffer in bytes
 * \param din IN -- plaintext to encrypt
 * \param ilen IN -- length of plaintext buffer in bytes
 * \param conn Connection object
 *
 * \return returns 0 on success
 *         returns -EINVAL if:
 *               conn has not generated a DAP key or
 *               dout == NULL or
 *               din == NULL or
 *               ilen == 0 or
 *               (ilen % TC_AES_BLOCK_SIZE) != 0 or
 *               (olen % TC_AES_BLOCK_SIZE) != 0 or
 *               olen != ilen + TC_AES_BLOCK_SIZE
 */
int bt_conn_dap_encrypt(uint8_t *dout, uint16_t olen, const uint8_t *din,
			const uint16_t ilen, const struct bt_conn *conn);

/**
 * \brief Decrypt using AES-128 CBC and the 128bit key derived from DAP
 *
 * This function is based on TinyCrypt, specifically tc_cbc_mode_decrypt.
 *
 * \note Assumes:- out buffer is large enough to hold the decrypted plaintext
 *                 and is a contiguous buffer
 *               - inlen gives the number of bytes in the in buffer
 *
 * \param out OUT -- buffer to decrypted data
 * \param outlen IN -- length of plaintext buffer in bytes
 * \param in IN -- ciphertext to decrypt, including IV
 * \param inlen IN -- length of ciphertext buffer in bytes
 * \param conn Connection object
 *
 * \return returns 0 on success
 *         returns -EINVAL if:
 *                 conn has not generated a DAP key or
 *                 dout == NULL or
 *                 din == NULL or
 *                 olen == 0 or
 *                 (ilen % TC_AES_BLOCK_SIZE) != 0 or
 *                 (olen % TC_AES_BLOCK_SIZE) != 0 or
 *                 olen != ilen + TC_AES_BLOCK_SIZE
 */
int bt_conn_dap_decrypt(uint8_t *dout, uint16_t olen, const uint8_t *din,
			const uint16_t ilen, const struct bt_conn *conn);

/**
 * \brief Returns the version of the SDK
 *
 * The BLE DAP SDK follows the major.minor.patch  version numbering
 * scheme. This function returns the three numeric version identifiers
 * in place.
 *
 * \note This function can be called at any point in time without the need
 * to enable the BLE DAP stack.
 *
 * \param major Pointer to memory where SDK major release number will be written
 * \param minor Pointer to memory where SDK minor release number will be written
 * \param patch Pointer to memory where SDK patch release number will be written
 */
void bt_dap_version(uint8_t *major, uint8_t *minor, uint8_t *patch);

#ifdef __cplusplus
}
#endif

#endif /* __BLUETOOTH_DAP_H__ */
