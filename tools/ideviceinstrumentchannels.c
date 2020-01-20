/*
 * idevicescreenshot.c
 * Gets a screenshot from a device
 *
 * Copyright (C) 2010 Nikias Bassen <nikias@gmx.li>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#ifndef WIN32
#include <signal.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/instrument.h>


static char table[] = "0123456789ABCDEF";
static void hexdump(const char* tag, void* conn, void* buf, int len) {
	int i;
	char buffer[3 * 32 + 1 + 32 + 1];
	uint8_t* _buf = (uint8_t*)buf;
	fprintf(stdout, "[%p]%s:\n", conn, tag);
	buffer[3 * 32] = '\t';
	buffer[sizeof(buffer) - 1] = '\0';
	for (i = 0; i < len; i++) {
		int t = i % 32;
		buffer[t * 3 + 0] = table[(_buf[i] >> 4) & 0xf];
		buffer[t * 3 + 1] = table[_buf[i] & 0xf];
		buffer[t * 3 + 2] = ' ';
		buffer[3 * 32 + 1 + t] = isprint(_buf[i]) ? _buf[i] : '.';
		if (t == 31) {
			fprintf(stdout, "\t%s\n", buffer);
		}
	}
	while (i % 32) {
		int t = i % 32;
		buffer[t * 3 + 0] = ' ';
		buffer[t * 3 + 1] = ' ';
		buffer[t * 3 + 2] = ' ';
		buffer[3 * 32 + 1 + t] = ' ';
		if (t == 31) {
			fprintf(stdout, "\t%s\n", buffer);
		}
		i++;
	}
}
void print_usage(int argc, char **argv);

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	instrument_error_t instrret = INSTRUMENT_E_UNKNOWN_ERROR;
	instrument_client_t instr = NULL;
	int result = -1;
	int i;
	const char *udid = NULL;
	char *filename = NULL;
    char buf[1024];
    int32_t received;

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
			i++;
			if (!argv[i] || !*argv[i]) {
				print_usage(argc, argv);
				return 0;
			}
			udid = argv[i];
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else if (argv[i][0] != '-' && !filename) {
			filename = strdup(argv[i]);
			continue;
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	if (IDEVICE_E_SUCCESS != idevice_new(&device, udid)) {
		if (udid) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
		} else {
			printf("No device found, is it plugged in?\n");
		}
		return -1;
	}
    
    if (INSTRUMENT_E_SUCCESS != (instrret = instrument_client_start_service(device, &instr, "NULL"))){
        idevice_free(device);
		printf("ERROR: Could not connect to instrument service, error code %d\n", instrret);
		return -1;
    }
    
    while(instrument_receive_with_timeout(instr, buf, sizeof(buf), &received, 3000) == INSTRUMENT_E_SUCCESS){
        hexdump("test", instr, buf, received);
    }

	instrument_client_free(instr);
	idevice_free(device);
	free(filename);

	return result;
}

void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] [FILE]\n", (name ? name + 1: argv[0]));
	printf("Gets a screenshot from a device.\n");
	printf("The screenshot is saved as a TIFF image with the given FILE name,\n");
	printf("where the default name is \"screenshot-DATE.tiff\", e.g.:\n");
	printf("   ./screenshot-2013-12-31-23-59-59.tiff\n\n");
	printf("NOTE: A mounted developer disk image is required on the device, otherwise\n");
	printf("the screenshotr service is not available.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by UDID\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <" PACKAGE_URL ">\n");
}
