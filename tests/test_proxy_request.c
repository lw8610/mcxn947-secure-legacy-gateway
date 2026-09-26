/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#include "proxy_request.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void expect_ok(const char *raw, const char *host, const char *path)
{
    struct proxy_request request;
    assert(proxy_request_parse(raw, strlen(raw), &request) ==
           PROXY_REQUEST_OK);
    assert(strcmp(request.host, host) == 0);
    assert(strcmp(request.path, path) == 0);
    assert(request.method == PROXY_METHOD_GET);
}

static void expect_result(const char *raw, enum proxy_request_result expected)
{
    struct proxy_request request;
    assert(proxy_request_parse(raw, strlen(raw), &request) == expected);
}

static void test_valid_requests(void)
{
    expect_ok("GET http://example.com/ HTTP/1.1\r\n"
              "Host: example.com\r\n\r\n",
              "example.com", "/");
    expect_ok("GET http://example.com HTTP/1.0\r\n\r\n",
              "example.com", "/");
    expect_ok("GET HTTP://Example.COM:80/a/b?x=1 HTTP/1.1\r\n"
              "host: ignored.example\r\n\r\n",
              "Example.COM", "/a/b?x=1");
    expect_ok("GET http://example.com?query=yes HTTP/1.0\r\n\r\n",
              "example.com", "/?query=yes");
    expect_ok("GET http://192.168.1.10/path HTTP/1.1\r\n\r\n",
              "192.168.1.10", "/path");

    struct proxy_request request;
    static const char head[] =
        "HEAD http://example.com/style.css HTTP/1.0\r\n\r\n";
    assert(proxy_request_parse(head, strlen(head), &request) ==
           PROXY_REQUEST_OK);
    assert(request.method == PROXY_METHOD_HEAD);
    assert(strcmp(request.host, "example.com") == 0);
    assert(strcmp(request.path, "/style.css") == 0);

    static const char post[] =
        "POST http://lite.duckduckgo.com/lite/ HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 11\r\n\r\n"
        "q=macintosh";
    assert(proxy_request_parse(post, strlen(post), &request) ==
           PROXY_REQUEST_OK);
    assert(request.method == PROXY_METHOD_POST);
    assert(strcmp(request.host, "lite.duckduckgo.com") == 0);
    assert(strcmp(request.path, "/lite/") == 0);
    assert(request.content_length == 11);
    assert(strlen(post) - request.header_length == 11);
}

static void test_header_completion(void)
{
    static const char request[] =
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";

    for (size_t length = 0; length < sizeof(request) - 1; length++) {
        assert(!proxy_request_header_complete(request, length));
    }
    assert(proxy_request_header_complete(request, sizeof(request) - 1));
}

static void test_user_agent(void)
{
    struct proxy_request request;
    static const char with_user_agent[] =
        "GET http://example.com/ HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "user-agent:  Mozilla/4.0 (compatible; MSIE 5.0; Mac_PowerPC)  \r\n"
        "Accept: */*\r\n\r\n";

    assert(proxy_request_parse(with_user_agent, strlen(with_user_agent),
                               &request) == PROXY_REQUEST_OK);
    assert(strcmp(request.user_agent,
                  "Mozilla/4.0 (compatible; MSIE 5.0; Mac_PowerPC)") == 0);

    static const char without_user_agent[] =
        "GET http://example.com/ HTTP/1.0\r\n\r\n";
    assert(proxy_request_parse(without_user_agent,
                               strlen(without_user_agent),
                               &request) == PROXY_REQUEST_OK);
    assert(request.user_agent[0] == '\0');
}

static void test_invalid_requests(void)
{
    expect_result("PUT http://example.com/ HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_METHOD_NOT_ALLOWED);
    expect_result("CONNECT example.com:443 HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_METHOD_NOT_ALLOWED);
    expect_result("GET https://example.com/ HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_UNSUPPORTED_TARGET);
    expect_result("GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n",
                  PROXY_REQUEST_UNSUPPORTED_TARGET);
    expect_result("GET http://example.com:8080/ HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_UNSUPPORTED_TARGET);
    expect_result("GET http://user@example.com/ HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_BAD);
    expect_result("GET http://[::1]/ HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_UNSUPPORTED_TARGET);
    expect_result("GET http://bad_host/ HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_BAD);
    expect_result("GET http://example.com/#fragment HTTP/1.1\r\n\r\n",
                  PROXY_REQUEST_BAD);
    expect_result("GET http://example.com/ HTTP/2\r\n\r\n",
                  PROXY_REQUEST_BAD);
    expect_result("GET http://example.com/ HTTP/1.1\r\n",
                  PROXY_REQUEST_BAD);

    expect_result("POST http://example.com/ HTTP/1.1\r\n"
                  "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
                  PROXY_REQUEST_LENGTH_REQUIRED);
    expect_result("POST http://example.com/ HTTP/1.1\r\n"
                  "Content-Type: text/plain\r\n"
                  "Content-Length: 1\r\n\r\nx",
                  PROXY_REQUEST_UNSUPPORTED_MEDIA_TYPE);
    expect_result("POST http://example.com/ HTTP/1.1\r\n"
                  "Content-Type: application/x-www-form-urlencoded\r\n"
                  "Content-Length: 16385\r\n\r\n",
                  PROXY_REQUEST_PAYLOAD_TOO_LARGE);
    expect_result("POST http://example.com/ HTTP/1.1\r\n"
                  "Content-Type: application/x-www-form-urlencoded\r\n"
                  "Transfer-Encoding: chunked\r\n\r\n",
                  PROXY_REQUEST_UNSUPPORTED_TRANSFER_ENCODING);
    expect_result("POST http://example.com/ HTTP/1.1\r\n"
                  "Content-Type: application/x-www-form-urlencoded\r\n"
                  "Content-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                  PROXY_REQUEST_BAD);
}

static void test_length_limits(void)
{
    char request_text[1400];
    struct proxy_request request;
    size_t offset = (size_t)snprintf(request_text, sizeof(request_text),
                                     "GET http://example.com/");
    memset(request_text + offset, 'a', PROXY_PATH_SIZE);
    offset += PROXY_PATH_SIZE;
    memcpy(request_text + offset, " HTTP/1.1\r\n\r\n", 13);
    offset += 13;
    assert(proxy_request_parse(request_text, offset, &request) ==
           PROXY_REQUEST_URI_TOO_LONG);

    offset = (size_t)snprintf(request_text, sizeof(request_text),
                              "GET http://");
    memset(request_text + offset, 'a', PROXY_HOST_SIZE);
    offset += PROXY_HOST_SIZE;
    memcpy(request_text + offset, "/ HTTP/1.1\r\n\r\n", 14);
    offset += 14;
    assert(proxy_request_parse(request_text, offset, &request) ==
           PROXY_REQUEST_URI_TOO_LONG);
}

int main(void)
{
    test_valid_requests();
    test_header_completion();
    test_user_agent();
    test_invalid_requests();
    test_length_limits();
    puts("proxy_request tests passed");
    return 0;
}
