/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#include "proxy_request.h"

#include <stdint.h>
#include <string.h>
#include <strings.h>

static size_t find_header_length(const char *data, size_t length)
{
    if (length < 4) {
        return 0;
    }

    for (size_t i = 3; i < length; i++) {
        if (data[i - 3] == '\r' && data[i - 2] == '\n' &&
            data[i - 1] == '\r' && data[i] == '\n') {
            return i + 1;
        }
    }

    return 0;
}

bool proxy_request_header_complete(const char *data, size_t length)
{
    return find_header_length(data, length) != 0;
}

static bool valid_host(const char *host, size_t length)
{
    if (length == 0 || host[0] == '.' || host[0] == '-' ||
        host[length - 1] == '.' || host[length - 1] == '-') {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        char byte = host[i];
        bool alpha = (byte >= 'a' && byte <= 'z') ||
                     (byte >= 'A' && byte <= 'Z');
        bool digit = byte >= '0' && byte <= '9';
        if (!alpha && !digit && byte != '.' && byte != '-') {
            return false;
        }
    }

    return true;
}

static bool parse_decimal(const char *value, const char *end, size_t *result)
{
    size_t parsed = 0;

    while (value < end && (*value == ' ' || *value == '\t')) {
        value++;
    }
    const char *start = value;
    while (value < end && *value >= '0' && *value <= '9') {
        unsigned int digit = (unsigned int)(*value++ - '0');
        if (parsed > (SIZE_MAX - digit) / 10) {
            return false;
        }
        parsed = parsed * 10 + digit;
    }
    while (value < end && (*value == ' ' || *value == '\t')) {
        value++;
    }
    if (value == start || value != end) {
        return false;
    }
    *result = parsed;
    return true;
}

static bool media_type_is_form(const char *value, const char *end)
{
    static const char form[] = "application/x-www-form-urlencoded";

    while (value < end && (*value == ' ' || *value == '\t')) {
        value++;
    }
    if ((size_t)(end - value) < sizeof(form) - 1 ||
        strncasecmp(value, form, sizeof(form) - 1) != 0) {
        return false;
    }
    value += sizeof(form) - 1;
    while (value < end && (*value == ' ' || *value == '\t')) {
        value++;
    }
    return value == end || *value == ';';
}

static enum proxy_request_result parse_headers(const char *line,
                                                const char *header_end,
                                                struct proxy_request *request)
{
    bool have_content_length = false;
    bool form_content_type = false;

    while (line < header_end && *line != '\r') {
        const char *line_end = line;
        while (line_end + 1 < header_end &&
               !(line_end[0] == '\r' && line_end[1] == '\n')) {
            line_end++;
        }
        if (line_end + 1 >= header_end) {
            return PROXY_REQUEST_BAD;
        }

        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (colon == NULL) {
            return PROXY_REQUEST_BAD;
        }
        const char *value = colon + 1;
        const char *value_end = line_end;
        while (value < value_end && (*value == ' ' || *value == '\t')) {
            value++;
        }
        while (value_end > value &&
               (value_end[-1] == ' ' || value_end[-1] == '\t')) {
            value_end--;
        }

        size_t name_length = (size_t)(colon - line);
        if (name_length == sizeof("User-Agent") - 1 &&
            strncasecmp(line, "User-Agent", name_length) == 0 &&
            request->user_agent[0] == '\0') {
            size_t value_length = (size_t)(value_end - value);
            if (value_length >= sizeof(request->user_agent)) {
                value_length = sizeof(request->user_agent) - 1;
            }
            bool valid = true;
            for (size_t i = 0; i < value_length; i++) {
                unsigned char byte = (unsigned char)value[i];
                if ((byte < 0x20 && byte != '\t') || byte == 0x7f) {
                    valid = false;
                    break;
                }
            }
            if (valid) {
                memcpy(request->user_agent, value, value_length);
                request->user_agent[value_length] = '\0';
            }
        } else if (name_length == sizeof("Content-Length") - 1 &&
                   strncasecmp(line, "Content-Length", name_length) == 0) {
            if (have_content_length ||
                !parse_decimal(value, value_end, &request->content_length)) {
                return PROXY_REQUEST_BAD;
            }
            have_content_length = true;
        } else if (name_length == sizeof("Content-Type") - 1 &&
                   strncasecmp(line, "Content-Type", name_length) == 0) {
            form_content_type = media_type_is_form(value, value_end);
        } else if (name_length == sizeof("Transfer-Encoding") - 1 &&
                   strncasecmp(line, "Transfer-Encoding", name_length) == 0) {
            return PROXY_REQUEST_UNSUPPORTED_TRANSFER_ENCODING;
        }

        line = line_end + 2;
    }

    if (request->method == PROXY_METHOD_POST) {
        if (!have_content_length) {
            return PROXY_REQUEST_LENGTH_REQUIRED;
        }
        if (request->content_length > PROXY_POST_MAX_BODY_SIZE) {
            return PROXY_REQUEST_PAYLOAD_TOO_LARGE;
        }
        if (!form_content_type) {
            return PROXY_REQUEST_UNSUPPORTED_MEDIA_TYPE;
        }
    }

    return PROXY_REQUEST_OK;
}

enum proxy_request_result proxy_request_parse(const char *data,
                                              size_t length,
                                              struct proxy_request *request)
{
    memset(request, 0, sizeof(*request));

    size_t header_length = find_header_length(data, length);
    if (header_length == 0 ||
        memchr(data, '\0', header_length) != NULL) {
        return PROXY_REQUEST_BAD;
    }
    request->header_length = header_length;

    const char *line_end = NULL;
    for (size_t i = 1; i < length; i++) {
        if (data[i - 1] == '\r' && data[i] == '\n') {
            line_end = data + i - 1;
            break;
        }
    }
    if (line_end == NULL) {
        return PROXY_REQUEST_BAD;
    }

    const char *first_space = memchr(data, ' ', (size_t)(line_end - data));
    if (first_space == NULL) {
        return PROXY_REQUEST_BAD;
    }
    size_t method_length = (size_t)(first_space - data);
    if (method_length == 3 && memcmp(data, "GET", 3) == 0) {
        request->method = PROXY_METHOD_GET;
    } else if (method_length == 4 && memcmp(data, "HEAD", 4) == 0) {
        request->method = PROXY_METHOD_HEAD;
    } else if (method_length == 4 && memcmp(data, "POST", 4) == 0) {
        request->method = PROXY_METHOD_POST;
    } else {
        return PROXY_REQUEST_METHOD_NOT_ALLOWED;
    }

    const char *target = first_space + 1;
    const char *second_space = memchr(target, ' ',
                                      (size_t)(line_end - target));
    if (second_space == NULL || second_space == target) {
        return PROXY_REQUEST_BAD;
    }

    const char *version = second_space + 1;
    size_t version_length = (size_t)(line_end - version);
    if (version_length != 8 ||
        (memcmp(version, "HTTP/1.0", 8) != 0 &&
         memcmp(version, "HTTP/1.1", 8) != 0)) {
        return PROXY_REQUEST_BAD;
    }

    size_t target_length = (size_t)(second_space - target);
    if (target_length < 8 || strncasecmp(target, "http://", 7) != 0) {
        return PROXY_REQUEST_UNSUPPORTED_TARGET;
    }
    if (memchr(target, '#', target_length) != NULL) {
        return PROXY_REQUEST_BAD;
    }

    const char *authority = target + 7;
    const char *target_end = second_space;
    const char *path = target_end;
    for (const char *p = authority; p < target_end; p++) {
        if (*p == '/' || *p == '?') {
            path = p;
            break;
        }
    }

    const char *host_end = path;
    const char *colon = memchr(authority, ':', (size_t)(host_end - authority));
    if (colon != NULL) {
        if (memchr(colon + 1, ':', (size_t)(host_end - colon - 1)) != NULL ||
            (size_t)(host_end - colon - 1) != 2 ||
            memcmp(colon + 1, "80", 2) != 0) {
            return PROXY_REQUEST_UNSUPPORTED_TARGET;
        }
        host_end = colon;
    }

    size_t host_length = (size_t)(host_end - authority);
    if (!valid_host(authority, host_length)) {
        return PROXY_REQUEST_BAD;
    }
    if (host_length >= sizeof(request->host)) {
        return PROXY_REQUEST_URI_TOO_LONG;
    }
    memcpy(request->host, authority, host_length);
    request->host[host_length] = '\0';

    if (path == target_end) {
        memcpy(request->path, "/", 2);
    } else {
        size_t path_length = (size_t)(target_end - path);
        size_t prefix_length = *path == '?' ? 1 : 0;
        if (path_length + prefix_length >= sizeof(request->path)) {
            return PROXY_REQUEST_URI_TOO_LONG;
        }
        if (prefix_length != 0) {
            request->path[0] = '/';
        }
        memcpy(request->path + prefix_length, path, path_length);
        request->path[path_length + prefix_length] = '\0';
    }

    return parse_headers(line_end + 2, data + header_length, request);
}
