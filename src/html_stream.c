/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#include "html_stream.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

static const char https_prefix[] = "https://";
static const char http_prefix[] = "http://";

static int buffered_write(struct html_rewriter *rewriter,
                          const char *data,
                          size_t length)
{
    while (length > 0) {
        size_t available = sizeof(rewriter->output) - rewriter->output_length;
        size_t copy = length < available ? length : available;

        memcpy(rewriter->output + rewriter->output_length, data, copy);
        rewriter->output_length += copy;
        data += copy;
        length -= copy;

        if (rewriter->output_length == sizeof(rewriter->output)) {
            int ret = rewriter->write(rewriter->context, rewriter->output,
                                      rewriter->output_length);
            if (ret < 0) {
                return ret;
            }
            rewriter->output_length = 0;
        }
    }

    return 0;
}

void html_rewriter_init(struct html_rewriter *rewriter,
                        stream_write_fn write,
                        void *context)
{
    memset(rewriter, 0, sizeof(*rewriter));
    rewriter->write = write;
    rewriter->context = context;
}

int html_rewriter_feed(struct html_rewriter *rewriter,
                       const char *data,
                       size_t length)
{
    for (size_t i = 0; i < length; i++) {
        char byte = data[i];

        if (byte == https_prefix[rewriter->pending_length]) {
            rewriter->pending[rewriter->pending_length++] = byte;
            if (rewriter->pending_length == sizeof(https_prefix) - 1) {
                int ret = buffered_write(rewriter, http_prefix,
                                         sizeof(http_prefix) - 1);
                if (ret < 0) {
                    return ret;
                }
                rewriter->pending_length = 0;
                rewriter->replacements++;
            }
            continue;
        }

        if (rewriter->pending_length > 0) {
            int ret = buffered_write(rewriter, rewriter->pending,
                                     rewriter->pending_length);
            if (ret < 0) {
                return ret;
            }
            rewriter->pending_length = 0;

            if (byte == https_prefix[0]) {
                rewriter->pending[rewriter->pending_length++] = byte;
                continue;
            }
        }

        int ret = buffered_write(rewriter, &byte, 1);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

int html_rewriter_finish(struct html_rewriter *rewriter)
{
    if (rewriter->pending_length > 0) {
        int ret = buffered_write(rewriter, rewriter->pending,
                                 rewriter->pending_length);
        if (ret < 0) {
            return ret;
        }
        rewriter->pending_length = 0;
    }

    if (rewriter->output_length > 0) {
        int ret = rewriter->write(rewriter->context, rewriter->output,
                                  rewriter->output_length);
        if (ret < 0) {
            return ret;
        }
        rewriter->output_length = 0;
    }

    return 0;
}

static int hex_value(char byte)
{
    if (byte >= '0' && byte <= '9') {
        return byte - '0';
    }
    if (byte >= 'a' && byte <= 'f') {
        return byte - 'a' + 10;
    }
    if (byte >= 'A' && byte <= 'F') {
        return byte - 'A' + 10;
    }
    return -1;
}

void chunk_decoder_init(struct chunk_decoder *decoder,
                        stream_write_fn write,
                        void *context)
{
    memset(decoder, 0, sizeof(*decoder));
    decoder->state = CHUNK_DECODE_SIZE;
    decoder->write = write;
    decoder->context = context;
}

int chunk_decoder_feed(struct chunk_decoder *decoder,
                       const char *data,
                       size_t length)
{
    size_t pos = 0;

    while (pos < length) {
        char byte = data[pos];

        switch (decoder->state) {
        case CHUNK_DECODE_SIZE: {
            if (++decoder->line_length > HTTP_CHUNK_LINE_LIMIT) {
                return -EOVERFLOW;
            }
            if (byte == '\r') {
                if (!decoder->have_digit) {
                    return -EINVAL;
                }
                decoder->state = CHUNK_DECODE_SIZE_LF;
                pos++;
                break;
            }
            if (byte == '\n') {
                return -EINVAL;
            }
            if (decoder->in_extension) {
                pos++;
                break;
            }
            if (byte == ';') {
                if (!decoder->have_digit) {
                    return -EINVAL;
                }
                decoder->in_extension = true;
                pos++;
                break;
            }
            int value = hex_value(byte);
            if (value < 0 ||
                decoder->chunk_size > (SIZE_MAX - (size_t)value) / 16) {
                return -EINVAL;
            }
            decoder->have_digit = true;
            decoder->chunk_size = decoder->chunk_size * 16 + (size_t)value;
            pos++;
            break;
        }

        case CHUNK_DECODE_SIZE_LF:
            if (byte != '\n') {
                return -EINVAL;
            }
            pos++;
            decoder->line_length = 0;
            if (decoder->chunk_size == 0) {
                decoder->state = CHUNK_DECODE_TRAILER_START;
            } else {
                decoder->chunk_remaining = decoder->chunk_size;
                decoder->state = CHUNK_DECODE_DATA;
            }
            break;

        case CHUNK_DECODE_DATA: {
            size_t available = length - pos;
            size_t take = decoder->chunk_remaining < available
                        ? decoder->chunk_remaining : available;
            int ret = decoder->write(decoder->context, data + pos, take);
            if (ret < 0) {
                return ret;
            }
            pos += take;
            decoder->chunk_remaining -= take;
            if (decoder->chunk_remaining == 0) {
                decoder->state = CHUNK_DECODE_DATA_CR;
            }
            break;
        }

        case CHUNK_DECODE_DATA_CR:
            if (byte != '\r') {
                return -EINVAL;
            }
            decoder->state = CHUNK_DECODE_DATA_LF;
            pos++;
            break;

        case CHUNK_DECODE_DATA_LF:
            if (byte != '\n') {
                return -EINVAL;
            }
            decoder->state = CHUNK_DECODE_SIZE;
            decoder->chunk_size = 0;
            decoder->have_digit = false;
            decoder->in_extension = false;
            pos++;
            break;

        case CHUNK_DECODE_TRAILER_START:
            if (byte == '\r') {
                decoder->state = CHUNK_DECODE_TRAILER_FINAL_LF;
            } else if (byte == '\n') {
                return -EINVAL;
            } else {
                decoder->line_length = 1;
                decoder->state = CHUNK_DECODE_TRAILER_LINE;
            }
            pos++;
            break;

        case CHUNK_DECODE_TRAILER_LINE:
            if (byte == '\r') {
                decoder->state = CHUNK_DECODE_TRAILER_LINE_LF;
            } else if (byte == '\n' ||
                       ++decoder->line_length > HTTP_CHUNK_LINE_LIMIT) {
                return -EINVAL;
            }
            pos++;
            break;

        case CHUNK_DECODE_TRAILER_LINE_LF:
            if (byte != '\n') {
                return -EINVAL;
            }
            decoder->line_length = 0;
            decoder->state = CHUNK_DECODE_TRAILER_START;
            pos++;
            break;

        case CHUNK_DECODE_TRAILER_FINAL_LF:
            if (byte != '\n') {
                return -EINVAL;
            }
            decoder->state = CHUNK_DECODE_DONE;
            pos++;
            break;

        case CHUNK_DECODE_DONE:
            return -EINVAL;
        }
    }

    return 0;
}

bool chunk_decoder_complete(const struct chunk_decoder *decoder)
{
    return decoder->state == CHUNK_DECODE_DONE;
}

int chunk_decoder_finish(const struct chunk_decoder *decoder)
{
    return chunk_decoder_complete(decoder) ? 0 : -EAGAIN;
}
