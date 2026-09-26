/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef HTML_STREAM_H
#define HTML_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HTML_REWRITE_OUTPUT_SIZE 1024
#define HTTP_CHUNK_LINE_LIMIT 1024

typedef int (*stream_write_fn)(void *context, const char *data, size_t length);

struct html_rewriter {
    stream_write_fn write;
    void *context;
    char pending[8];
    size_t pending_length;
    char output[HTML_REWRITE_OUTPUT_SIZE];
    size_t output_length;
    size_t replacements;
};

void html_rewriter_init(struct html_rewriter *rewriter,
                        stream_write_fn write,
                        void *context);
int html_rewriter_feed(struct html_rewriter *rewriter,
                       const char *data,
                       size_t length);
int html_rewriter_finish(struct html_rewriter *rewriter);

enum chunk_decode_state {
    CHUNK_DECODE_SIZE,
    CHUNK_DECODE_SIZE_LF,
    CHUNK_DECODE_DATA,
    CHUNK_DECODE_DATA_CR,
    CHUNK_DECODE_DATA_LF,
    CHUNK_DECODE_TRAILER_START,
    CHUNK_DECODE_TRAILER_LINE,
    CHUNK_DECODE_TRAILER_LINE_LF,
    CHUNK_DECODE_TRAILER_FINAL_LF,
    CHUNK_DECODE_DONE,
};

struct chunk_decoder {
    enum chunk_decode_state state;
    stream_write_fn write;
    void *context;
    size_t chunk_size;
    size_t chunk_remaining;
    size_t line_length;
    bool have_digit;
    bool in_extension;
};

void chunk_decoder_init(struct chunk_decoder *decoder,
                        stream_write_fn write,
                        void *context);
int chunk_decoder_feed(struct chunk_decoder *decoder,
                       const char *data,
                       size_t length);
bool chunk_decoder_complete(const struct chunk_decoder *decoder);
int chunk_decoder_finish(const struct chunk_decoder *decoder);

#endif
