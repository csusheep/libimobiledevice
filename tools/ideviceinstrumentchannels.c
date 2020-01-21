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

#define DTX_MAGIC 0x1f3d5b79
typedef struct DTXMessageHeader
{
  uint32_t magic;
  uint32_t cb;
  uint16_t fragmentId;
  uint16_t fragmentCount;
  uint32_t length;
  uint32_t identifier;
  uint32_t conversationIndex;
  uint32_t channelCode;
  uint32_t expectsReply;
} DTXMessageHeader;


typedef struct DTXMessagePayloadHeader{
    uint32_t magic;
    uint32_t auxiliaryLength;
    uint64_t totalLength;
} DTXMessagePayloadHeader;

typedef struct DTXMessageAuxiliaryHeader{
    uint32_t magic;
    uint32_t type;
} DTXMessageAuxiliaryHeader;

typedef enum{
    DTX_E_SUCCESS = 0,
    DTX_E_INVALID_ARG = -1,
    DTX_E_NO_MEMORY = -2,
    DTX_E_BAD_HEADER = -3,
    DTX_E_BUFF_TOO_SMALL = -4,
    DTX_E_BUFF_SIZE_NOT_MATCH = -5,
    DTX_E_PARSE_FAILED = -6,
    DTX_E_UNKNOWN = -7,
} dtx_error_t;

typedef enum{
    DTX_AUX_T_I32 = 3,
    DTX_AUX_T_I64 = 4,
    DTX_AUX_T_OBJ = 2,
} dtx_aux_type_t;

typedef struct DTXAuxiliary{
    struct DTXAuxiliary* next;
    dtx_aux_type_t type;
    union {
        int32_t d;
        int64_t ll;
        struct {
            uint32_t len;
            void* buffer;
        } obj;
    };
} DTXAuxiliary;

typedef struct DTXMsg
{
    uint32_t channel;
    uint32_t identifier;
    char* selector;
    DTXAuxiliary* auxiliaries;
    uint32_t auxiliaryCount;
} DTXMsg;




static dtx_error_t dtx_auxiliary_free(DTXAuxiliary* aux){
    if (!aux) return DTX_E_SUCCESS;
    if(aux->type == DTX_AUX_T_OBJ){
        if (aux->obj.buffer){
            free(aux->obj.buffer);
            aux->obj.buffer = 0;
        }
        aux->obj.len = 0;
    }
    free(aux);
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_new(DTXMsg **msg){
    if (!msg || *msg != NULL){
        return DTX_E_INVALID_ARG;
    }
    DTXMsg* ret = (DTXMsg*)malloc(sizeof(struct DTXMsg));
    if (!ret){
        return DTX_E_NO_MEMORY;
    }
    memset(ret, 0, sizeof(DTXMsg));
    *msg = ret;
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_free(DTXMsg *msg){
    if (!msg) return DTX_E_SUCCESS;
    if (msg->selector){
        free(msg->selector);
        msg->selector = NULL;
    }
    while (msg->auxiliaries){
        DTXAuxiliary* next = msg->auxiliaries->next;
        dtx_auxiliary_free(msg->auxiliaries);
        msg->auxiliaries = next;
    }
    free(msg);
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_set_selector(DTXMsg* msg, const char* selector){
    dtx_error_t err;
    char* old_selector;
    if (!msg || !selector) return DTX_E_INVALID_ARG;
    old_selector = msg->selector;
    msg->selector = NULL;
    msg->selector = strdup(selector);
    if (!msg->selector){
        msg->selector = old_selector;
        return DTX_E_NO_MEMORY;
    }
    free(old_selector);
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_get_selector(DTXMsg* msg, const char** selector){
    dtx_error_t err;
    if (!msg || !selector || *selector) return DTX_E_INVALID_ARG;
    if (msg->selector){
        *selector = strdup(msg->selector);
    }
    else{
        *selector = NULL;
    }
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_append_auxiliary_i32(DTXMsg* msg, int32_t value){
    if (!msg) return DTX_E_INVALID_ARG;
    DTXAuxiliary** cur = &msg->auxiliaries;
    DTXAuxiliary* node = NULL;
    while(*cur != NULL) cur = &(*cur)->next; // get to the end
    node = (DTXAuxiliary*)malloc(sizeof(DTXAuxiliary));
    if (!node){
        return DTX_E_NO_MEMORY;
    }
    memset(node, 0, sizeof(DTXAuxiliary));
    node->type = DTX_AUX_T_I32;
    node->d = value;
    *cur = node;
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_append_auxiliary_i64(DTXMsg* msg, int64_t value){
    if (!msg) return DTX_E_INVALID_ARG;
    DTXAuxiliary** cur = &msg->auxiliaries;
    DTXAuxiliary* node = NULL;
    while(*cur != NULL) cur = &(*cur)->next; // get to the end
    node = (DTXAuxiliary*)malloc(sizeof(DTXAuxiliary));
    if (!node){
        return DTX_E_NO_MEMORY;
    }
    memset(node, 0, sizeof(DTXAuxiliary));
    node->type = DTX_AUX_T_I64;
    node->ll = value;
    *cur = node;
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_append_auxiliary_obj(DTXMsg* msg, const void* buf, uint32_t len){
    if (!msg) return DTX_E_INVALID_ARG;
    DTXAuxiliary** cur = &msg->auxiliaries;
    DTXAuxiliary* node = NULL;
    while(*cur != NULL) cur = &(*cur)->next; // get to the end
    node = (DTXAuxiliary*)malloc(sizeof(DTXAuxiliary));
    if (!node){
        return DTX_E_NO_MEMORY;
    }
    memset(node, 0, sizeof(DTXAuxiliary));
    node->type = DTX_AUX_T_OBJ;
    node->obj.len = len;
    node->obj.buffer = malloc(len);
    if (!node->obj.buffer){
        free(node);
        return DTX_E_NO_MEMORY;
    }
    memcpy(node->obj.buffer, buf, len);
    *cur = node;
    return DTX_E_SUCCESS;
}

typedef enum{
    DTX_PARSE_SUCCESS = 0,
    DTX_PARSE_HEADER = 1,
    DTX_PARSE_PAYLOAD_HEADER = 2,
    DTX_PARSE_AUX = 3,
    DTX_PARSE_SELECTOR = 4,
    DTX_PARSE_ERROR = -1,
} dtx_parse_type_t;

typedef void (*dtx_parse_callback)(dtx_parse_type_t type, char* buf, uint32_t len, void* ctx);

static dtx_error_t dtx_try_parse_aux(char* buf, uint32_t len, dtx_parse_callback cb, void* ctx){
    int cur = 0;
    int more = 0;
    if (!cb || !buf){
        return DTX_E_INVALID_ARG;
    }
    // hexdump("dtx_try_parse_aux", buf, buf, len);
    cur += 16; // magic
    while (cur < len){
        if (len < cur + sizeof(DTXMessageAuxiliaryHeader) + 4){
            cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_TOO_SMALL, ctx);
            return DTX_E_PARSE_FAILED;
        }
        DTXMessageAuxiliaryHeader* hdr = (DTXMessageAuxiliaryHeader*)(buf + cur);
        cur += sizeof(DTXMessageAuxiliaryHeader);
        if (hdr->type == DTX_AUX_T_OBJ){
            int32_t* objlen = (int32_t*) (buf + cur);
            if (len < *objlen + cur + 4){
                cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_TOO_SMALL, ctx);
                return DTX_E_PARSE_FAILED;
            }
            cb(DTX_PARSE_AUX, (char*) hdr, *objlen + 4 + sizeof(DTXMessageAuxiliaryHeader), ctx);
            cur += *objlen + 4;
        } else if (hdr->type == DTX_AUX_T_I64){
            if (len < cur + 8){
                cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_TOO_SMALL, ctx);
                return DTX_E_PARSE_FAILED;
            }
            cb(DTX_PARSE_AUX, (char*) hdr, sizeof(DTXMessageAuxiliaryHeader) + 8, ctx);
            cur += 8;
        } else if (hdr->type == DTX_AUX_T_I32){
            if (len < cur + 4){
                cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_TOO_SMALL, ctx);
                return DTX_E_PARSE_FAILED;
            }
            cb(DTX_PARSE_AUX, (char*) hdr, sizeof(DTXMessageAuxiliaryHeader) + 4, ctx);
            cur += 4;
        } else {
            cb(DTX_PARSE_ERROR, NULL, DTX_E_UNKNOWN, ctx);
            return DTX_E_PARSE_FAILED;
        }
    }
    return cur == len ? DTX_E_SUCCESS : DTX_E_PARSE_FAILED;
}

static dtx_error_t dtx_try_parse(char* buf, uint32_t len, dtx_parse_callback cb, void* ctx){
    int cur = 0;
    if (!cb || !buf){
        return DTX_E_INVALID_ARG;
    }
    // parse header;
    if (len < cur + sizeof(DTXMessageHeader)){
        cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_TOO_SMALL, ctx);
        return DTX_E_PARSE_FAILED;
    }
    DTXMessageHeader* hdr = (DTXMessageHeader*)(buf + cur);
    cb(DTX_PARSE_HEADER, buf + cur, sizeof(DTXMessageHeader), ctx);
    cur += sizeof(DTXMessageHeader);

    // payload header
    if (len < cur + hdr->length || len < cur + sizeof(DTXMessagePayloadHeader)){
        cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_SIZE_NOT_MATCH, ctx);
        return DTX_E_PARSE_FAILED;
    }
    DTXMessagePayloadHeader* phdr = (DTXMessagePayloadHeader*)(buf + cur);
    cb(DTX_PARSE_PAYLOAD_HEADER, buf + cur, sizeof(DTXMessagePayloadHeader), ctx);
    cur += sizeof(DTXMessagePayloadHeader);

    // aux
    if (len < cur + phdr->totalLength || len < cur + phdr->auxiliaryLength){
        cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_TOO_SMALL, ctx);
        return DTX_E_PARSE_FAILED;
    }
    if (dtx_try_parse_aux(buf + cur, phdr->auxiliaryLength, cb, ctx) != DTX_E_SUCCESS){
        cb(DTX_PARSE_ERROR, NULL, DTX_E_UNKNOWN, ctx);
        return DTX_E_PARSE_FAILED;
    }
    if (phdr->totalLength < phdr->auxiliaryLength){
        cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_SIZE_NOT_MATCH, ctx);
        return DTX_E_PARSE_FAILED;
    }
    uint64_t selector_length = phdr->totalLength - phdr->auxiliaryLength;
    // selector
    cur += phdr->auxiliaryLength;
    if (len < cur + selector_length){
        cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_TOO_SMALL, ctx);
        return DTX_E_PARSE_FAILED;
    }
    cb(DTX_PARSE_SELECTOR, buf + cur, selector_length, ctx);
    cur += selector_length;
    if (cur != len){
        cb(DTX_PARSE_ERROR, NULL, DTX_E_BUFF_SIZE_NOT_MATCH, ctx);
        return DTX_E_PARSE_FAILED;
    }
    return DTX_E_SUCCESS;
}

dtx_error_t dtx_create_from_buffer(DTXMsg** msg, char* buf, uint32_t len){
    dtx_error_t err;
    DTXMsg* msg_loc;
    char* payload_buf;
    uint32_t payload_len;

    if (!msg || *msg || !buf || !len){
        return DTX_E_INVALID_ARG;
    }
    err = dtx_new(&msg_loc);
    if (err != DTX_E_SUCCESS){
        return err;
    }
    DTXMessageHeader* hdr = (DTXMessageHeader*)buf;
    if (len < sizeof(DTXMessageHeader)){
        dtx_free(msg_loc);
        return DTX_E_BUFF_TOO_SMALL;
    }
    if (hdr->magic != DTX_MAGIC || hdr->cb != sizeof(DTXMessageHeader)){
        dtx_free(msg_loc);
        return DTX_E_BAD_HEADER;
    }
    if (hdr->length + sizeof(DTXMessageHeader) != len){
        dtx_free(msg_loc);
        return DTX_E_BUFF_SIZE_NOT_MATCH;
    }
    msg_loc->channel = hdr->channelCode;
    msg_loc->identifier = hdr->identifier;
    if (hdr->length){
        payload_buf = buf + sizeof(DTXMessageHeader);
        payload_len = len - sizeof(DTXMessageHeader);
        if (payload_len < sizeof(DTXMessagePayloadHeader)){
            dtx_free(msg_loc);
            return DTX_E_BUFF_TOO_SMALL;
        }
        DTXMessagePayloadHeader* payload_hdr = (DTXMessagePayloadHeader*) payload_buf;
        if (payload_hdr->totalLength + sizeof(DTXMessagePayloadHeader) != payload_len){
            dtx_free(msg_loc);
            return DTX_E_BUFF_SIZE_NOT_MATCH;
        }

    }
    *msg = msg_loc;
    return DTX_E_SUCCESS;
}



void print_usage(int argc, char **argv);

void print_cb(dtx_parse_type_t type, char* buf, uint32_t len, void* ctx){
    if (type != DTX_PARSE_ERROR){
        printf("[%d] ==\n", type);
        hexdump("print_cb", buf, buf, len);
    } else {
        printf("[DTX_PARSE_ERROR] %d\n", len);
    }
}
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
    char* final_buf = NULL;
    uint32_t current_size = 0;
    while(instrument_receive_with_timeout(instr, buf, sizeof(buf), &received, 3000) == INSTRUMENT_E_SUCCESS){
        final_buf = (char*)realloc(final_buf, current_size + received);
        memcpy(final_buf + current_size, buf, received);
        current_size += received;
    }
    hexdump("test", instr, final_buf, current_size);
    dtx_try_parse(final_buf, current_size, print_cb, NULL);
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
