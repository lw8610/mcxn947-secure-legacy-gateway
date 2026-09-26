/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#include "html_stream.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sink {
    char *data;
    size_t length;
    size_t capacity;
};

static int sink_write(void *context, const char *data, size_t length)
{
    struct sink *sink = context;
    assert(length <= sink->capacity - sink->length);
    memcpy(sink->data + sink->length, data, length);
    sink->length += length;
    return 0;
}

static int rewrite_write(void *context, const char *data, size_t length)
{
    return html_rewriter_feed(context, data, length);
}

static void expect_rewrite_with_split(size_t split)
{
    static const char input[] = "before:https://example.test/ after";
    static const char expected[] = "before:http://example.test/ after";
    char output[sizeof(input)] = {0};
    struct sink sink = { output, 0, sizeof(output) };
    struct html_rewriter rewriter;

    html_rewriter_init(&rewriter, sink_write, &sink);
    assert(html_rewriter_feed(&rewriter, input, split) == 0);
    assert(html_rewriter_feed(&rewriter, input + split,
                              sizeof(input) - 1 - split) == 0);
    assert(html_rewriter_finish(&rewriter) == 0);
    assert(sink.length == sizeof(expected) - 1);
    assert(memcmp(output, expected, sink.length) == 0);
    assert(rewriter.replacements == 1);
}

static void test_every_rewrite_boundary(void)
{
    static const char input[] = "before:https://example.test/ after";

    for (size_t split = 0; split <= sizeof(input) - 1; split++) {
        expect_rewrite_with_split(split);
    }

    char output[64] = {0};
    struct sink sink = { output, 0, sizeof(output) };
    struct html_rewriter rewriter;
    html_rewriter_init(&rewriter, sink_write, &sink);
    for (size_t i = 0; i < sizeof(input) - 1; i++) {
        assert(html_rewriter_feed(&rewriter, input + i, 1) == 0);
    }
    assert(html_rewriter_finish(&rewriter) == 0);
    assert(memcmp(output, "before:http://example.test/ after", sink.length) == 0);
}

static void test_partial_prefix_and_large_body(void)
{
    const size_t input_size = 70000;
    char *input = malloc(input_size);
    char *output = malloc(input_size);
    assert(input != NULL && output != NULL);
    memset(input, 'x', input_size);
    memcpy(input + 32760, "https://", 8);
    memcpy(input + input_size - 7, "https:/", 7);

    struct sink sink = { output, 0, input_size };
    struct html_rewriter rewriter;
    html_rewriter_init(&rewriter, sink_write, &sink);
    for (size_t pos = 0; pos < input_size;) {
        size_t take = input_size - pos < 37 ? input_size - pos : 37;
        assert(html_rewriter_feed(&rewriter, input + pos, take) == 0);
        pos += take;
    }
    assert(html_rewriter_finish(&rewriter) == 0);
    assert(sink.length == input_size - 1);
    assert(rewriter.replacements == 1);
    assert(memcmp(output + 32760, "http://", 7) == 0);
    assert(memcmp(output + sink.length - 7, "https:/", 7) == 0);

    free(output);
    free(input);
}

static void test_chunked_one_byte_at_a_time(void)
{
    static const char encoded[] =
        "3;foo=bar\r\nhtt\r\n"
        "5\r\nps://\r\n"
        "c\r\nexample.test\r\n"
        "0\r\nX-Test: yes\r\nAnother: trailer\r\n\r\n";
    static const char expected[] = "http://example.test";
    char output[64] = {0};
    struct sink sink = { output, 0, sizeof(output) };
    struct html_rewriter rewriter;
    struct chunk_decoder decoder;

    html_rewriter_init(&rewriter, sink_write, &sink);
    chunk_decoder_init(&decoder, rewrite_write, &rewriter);
    for (size_t i = 0; i < sizeof(encoded) - 1; i++) {
        assert(chunk_decoder_feed(&decoder, encoded + i, 1) == 0);
    }
    assert(chunk_decoder_complete(&decoder));
    assert(chunk_decoder_finish(&decoder) == 0);
    assert(html_rewriter_finish(&rewriter) == 0);
    assert(sink.length == sizeof(expected) - 1);
    assert(memcmp(output, expected, sink.length) == 0);
    assert(rewriter.replacements == 1);
}

static void test_large_chunked_body(void)
{
    const size_t body_size = 70000;
    char *body = malloc(body_size);
    char *encoded = malloc(body_size + 64);
    char *output = malloc(body_size);
    assert(body != NULL && encoded != NULL && output != NULL);
    memset(body, 'a', body_size);
    memcpy(body + 40000, "https://", 8);
    int prefix = snprintf(encoded, 64, "%zx;large=yes\r\n", body_size);
    assert(prefix > 0);
    memcpy(encoded + prefix, body, body_size);
    memcpy(encoded + prefix + body_size, "\r\n0\r\n\r\n", 7);
    size_t encoded_size = (size_t)prefix + body_size + 7;

    struct sink sink = { output, 0, body_size };
    struct html_rewriter rewriter;
    struct chunk_decoder decoder;
    html_rewriter_init(&rewriter, sink_write, &sink);
    chunk_decoder_init(&decoder, rewrite_write, &rewriter);
    for (size_t pos = 0; pos < encoded_size;) {
        size_t take = encoded_size - pos < 509 ? encoded_size - pos : 509;
        assert(chunk_decoder_feed(&decoder, encoded + pos, take) == 0);
        pos += take;
    }
    assert(chunk_decoder_finish(&decoder) == 0);
    assert(html_rewriter_finish(&rewriter) == 0);
    assert(sink.length == body_size - 1);
    assert(memcmp(output + 40000, "http://", 7) == 0);

    free(output);
    free(encoded);
    free(body);
}

static void expect_bad_chunked(const char *encoded)
{
    char output[64];
    struct sink sink = { output, 0, sizeof(output) };
    struct chunk_decoder decoder;
    chunk_decoder_init(&decoder, sink_write, &sink);
    int ret = chunk_decoder_feed(&decoder, encoded, strlen(encoded));
    assert(ret < 0 || chunk_decoder_finish(&decoder) == -EAGAIN);
}

static void test_malformed_chunked(void)
{
    expect_bad_chunked("z\r\n");
    expect_bad_chunked("1\nx");
    expect_bad_chunked("1\r\nxX\r\n");
    expect_bad_chunked("1\r\nx\r\n0\r\n");
    expect_bad_chunked("0\r\n\rX");
    expect_bad_chunked("0\r\n\r\nextra");
}

int main(void)
{
    test_every_rewrite_boundary();
    test_partial_prefix_and_large_body();
    test_chunked_one_byte_at_a_time();
    test_large_chunked_body();
    test_malformed_chunked();
    puts("html_stream tests passed");
    return 0;
}
