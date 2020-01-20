/*
 * instrument.c
 * com.apple.instrument.remoteserver service implementation.
 *
 * Copyright (c) 2020 Seasun Inc., All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <plist/plist.h>
#include <string.h>
#include <stdlib.h>

#include "instrument.h"
#include "common/debug.h"

/**
 * Convert a service_error_t value to a instrument_error_t
 * value. Used internally to get correct error codes.
 *
 * @param err A service_error_t error code
 *
 * @return A matching instrument_error_t error code,
 *     INSTRUMENT_E_UNKNOWN_ERROR otherwise.
 */
static instrument_error_t instrument_error(service_error_t err)
{
	switch (err) {
		case SERVICE_E_SUCCESS:
			return INSTRUMENT_E_SUCCESS;
	    case SERVICE_E_INVALID_ARG:
            return INSTRUMENT_E_INVALID_ARG;
        case SERVICE_E_MUX_ERROR:
            return INSTRUMENT_E_MUX_ERROR;
        case SERVICE_E_SSL_ERROR:
            return INSTRUMENT_E_SSL_ERROR;
		default:
            // printf("unknown service error: %d\n", err);
			break;
	}
	return INSTRUMENT_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API instrument_error_t instrument_client_new(idevice_t device, lockdownd_service_descriptor_t service, instrument_client_t * client){
    service_client_t service_client = NULL;
    if (!device || !service || service->port == 0 || !client || *client)
		return INSTRUMENT_E_INVALID_ARG;
    instrument_error_t err = instrument_error(service_client_new(device, service, &service_client));
    if(err != INSTRUMENT_E_SUCCESS){
        return err;
    }
    err = service_disable_ssl_silently(service_client);
    if(err != INSTRUMENT_E_SUCCESS){
        return err;
    }
    instrument_client_t client_loc = (instrument_client_t) malloc(sizeof(struct instrument_client_private));
    client_loc->parent = service_client;
    *client = client_loc;

    return INSTRUMENT_E_SUCCESS;

}

LIBIMOBILEDEVICE_API instrument_error_t instrument_client_start_service(idevice_t device, instrument_client_t* client, const char* label){
    instrument_error_t err = INSTRUMENT_E_UNKNOWN_ERROR;
    instrument_error_t start_service_error = INSTRUMENT_E_UNKNOWN_ERROR;
	start_service_error = instrument_error(service_client_factory_start_service(device, INSTRUMENT_REMOTESERVER_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(instrument_client_new), &err));
    if (start_service_error == INSTRUMENT_E_SUCCESS){
        return err;
    }
    return start_service_error;
}

LIBIMOBILEDEVICE_API instrument_error_t instrument_client_free(instrument_client_t client){
    if (!client){
        return INSTRUMENT_E_INVALID_ARG;
    }
    if (client->parent){
        service_client_free(client->parent);
    }
    client->parent = NULL;
    free(client);
    return INSTRUMENT_E_SUCCESS;
}

LIBIMOBILEDEVICE_API instrument_error_t instrument_send_command(instrument_client_t client, const char *data, uint32_t size, uint32_t *sent){
    if (!client || !data || !client->parent){
        return INSTRUMENT_E_INVALID_ARG;
    }
    instrument_error_t err = instrument_error(service_send(client->parent, data, size, sent));
    return err;
}

LIBIMOBILEDEVICE_API instrument_error_t instrument_receive_with_timeout(instrument_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout){
    if (!client || !data || !client->parent){
        return INSTRUMENT_E_INVALID_ARG;
    }
    instrument_error_t err = instrument_error(service_receive_with_timeout(client->parent, data, size, received, timeout));
    return err;
}

LIBIMOBILEDEVICE_API instrument_error_t instrument_receive(instrument_client_t client, char *data, uint32_t size, uint32_t *received){
    if (!client || !data || !client->parent){
        return INSTRUMENT_E_INVALID_ARG;
    }
    instrument_error_t err = instrument_error(service_receive(client->parent, data, size, received));
    return err;
}