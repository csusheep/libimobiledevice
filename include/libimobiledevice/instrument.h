/**
 * @file libimobiledevice/instrument.h
 * @brief Communicate with instrument remote server on the device.
 * \internal
 *
 * Copyright (c) 2020 Seasun Inc. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef IINTRUMENT_REMOTESERVER_LJJ_H
#define IINTRUMENT_REMOTESERVER_LJJ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define INSTRUMENT_REMOTESERVER_SERVICE_NAME "com.apple.instruments.remoteserver"

/** Error Codes */
typedef enum {
	INSTRUMENT_E_SUCCESS         =  0,
	INSTRUMENT_E_INVALID_ARG     = -1,
	INSTRUMENT_E_PLIST_ERROR     = -2,
	INSTRUMENT_E_MUX_ERROR       = -3,
	INSTRUMENT_E_SSL_ERROR       = -4,
	INSTRUMENT_E_RECEIVE_TIMEOUT = -5,
	INSTRUMENT_E_BAD_VERSION     = -6,
    INSTRUMENT_E_CONN_FAILED     = -7,
	INSTRUMENT_E_UNKNOWN_ERROR   = -256
} instrument_error_t;

typedef struct instrument_client_private instrument_client_private;
typedef instrument_client_private *instrument_client_t; /**< The client handle. */

/**
 * Connects to the instrument service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     instrument_client_t upon successful return.
 *
 * @note This service is only available if a developer disk image has been
 *     mounted.
 *
 * @return INSTRUMENT_E_SUCCESS on success, INSTRUMENT_E_INVALID_ARG if one
 *     or more parameters are invalid, or INSTRUMENT_E_CONN_FAILED if the
 *     connection to the device could not be established.
 */
instrument_error_t instrument_client_new(idevice_t device, lockdownd_service_descriptor_t service, instrument_client_t * client);

/**
 * Starts a new instrument service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     instrument_client_t upon successful return. Must be freed using
 *     instrument_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return INSTRUMENT_E_SUCCESS on success, or an INSTRUMENT_E_* error
 *     code otherwise.
 */
instrument_error_t instrument_client_start_service(idevice_t device, instrument_client_t* client, const char* label);

/**
 * Disconnects a instrument client from the device and frees up the
 * instrument client data.
 *
 * @param client The instrument client to disconnect and free.
 *
 * @return INSTRUMENT_E_SUCCESS on success, or INSTRUMENT_E_INVALID_ARG
 *     if client is NULL.
 */
instrument_error_t instrument_client_free(instrument_client_t client);

/**
 * Send command to the connected device.
 *
 * @param client The connection instrument service client.
 * @param data Data to send
 * @param size Size of the Data to send
 * @param sent Number of bytes sent (can be NULL to ignore)
 * @return INSTRUMENT_E_SUCCESS on success, or an INSTRUMENT_E_* error
 *     code otherwise.
 */
instrument_error_t instrument_send_command(instrument_client_t client, const char *data, uint32_t size, uint32_t *sent);

/**
 * Receives data using the given instrument client with specified timeout.
 *
 * @param client The instrument client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return INSTRUMENT_E_SUCCESS on success,
 *      INSTRUMENT_E_INVALID_ARG when one or more parameters are
 *      invalid, INSTRUMENT_E_MUX_ERROR when a communication error
 *      occurs, or INSTRUMENT_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
instrument_error_t instrument_receive_with_timeout(instrument_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);

/**
 * Receives data using the given instrument client.
 *
 * @param client The instrument client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 *
 * @return INSTRUMENT_E_SUCCESS on success,
 *      INSTRUMENT_E_INVALID_ARG when one or more parameters are
 *      invalid, INSTRUMENT_E_NOT_ENOUGH_DATA when not enough data
 *      received, INSTRUMENT_E_TIMEOUT when the connection times out,
 *      INSTRUMENT_E_MUX_ERROR when a communication error
 *      occurs, or INSTRUMENT_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
instrument_error_t instrument_receive(instrument_client_t client, char *data, uint32_t size, uint32_t *received);

#ifdef __cplusplus
}
#endif

#endif