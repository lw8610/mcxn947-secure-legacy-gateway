/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROXY_REQUEST_H
#define PROXY_REQUEST_H

#include <stdbool.h>
#include <stddef.h>

#define PROXY_REQUEST_HEADER_SIZE 2048
#define PROXY_HOST_SIZE 128
#define PROXY_PATH_SIZE 1024
#define PROXY_USER_AGENT_SIZE 192
#define PROXY_POST_MAX_BODY_SIZE 16384

enum proxy_request_result {
    PROXY_REQUEST_OK = 0,
    PROXY_REQUEST_BAD = -1,
    PROXY_REQUEST_METHOD_NOT_ALLOWED = -2,
    PROXY_REQUEST_UNSUPPORTED_TARGET = -3,
    PROXY_REQUEST_URI_TOO_LONG = -4,
    PROXY_REQUEST_LENGTH_REQUIRED = -5,
    PROXY_REQUEST_PAYLOAD_TOO_LARGE = -6,
    PROXY_REQUEST_UNSUPPORTED_MEDIA_TYPE = -7,
    PROXY_REQUEST_UNSUPPORTED_TRANSFER_ENCODING = -8,
};

enum proxy_request_method {
    PROXY_METHOD_GET,
    PROXY_METHOD_HEAD,
    PROXY_METHOD_POST,
};

struct proxy_request {
    enum proxy_request_method method;
    char host[PROXY_HOST_SIZE];
    char path[PROXY_PATH_SIZE];
    char user_agent[PROXY_USER_AGENT_SIZE];
    size_t header_length;
    size_t content_length;
};

bool proxy_request_header_complete(const char *data, size_t length);
enum proxy_request_result proxy_request_parse(const char *data,
                                              size_t length,
                                              struct proxy_request *request);

#endif
