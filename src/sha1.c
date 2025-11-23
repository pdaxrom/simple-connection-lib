/*
 *  SHA-1 helper for simple-connection library
 *
 *  Copyright (c) 2025 Alexander Chukov <sashz@pdaXrom.org>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include <string.h>

#include "sha1.h"

#define ROTL32(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_transform(uint32_t state[5], const unsigned char buffer[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e, temp;

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i * 4]) << 24;
        w[i] |= ((uint32_t)buffer[i * 4 + 1]) << 16;
        w[i] |= ((uint32_t)buffer[i * 4 + 2]) << 8;
        w[i] |= ((uint32_t)buffer[i * 4 + 3]);
    }

    for (int i = 16; i < 80; i++) {
        w[i] = ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        temp = ROTL32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void simple_connection_sha1_init(simple_connection_sha1_context *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void simple_connection_sha1_update(simple_connection_sha1_context *ctx, const unsigned char *data, size_t len)
{
    if (!len) {
        return;
    }

    size_t index = (size_t)((ctx->bitcount >> 3) % 64);
    ctx->bitcount += (uint64_t)len << 3;

    size_t part_len = 64 - index;
    size_t offset = 0;

    if (len >= part_len) {
        memcpy(&ctx->buffer[index], data, part_len);
        sha1_transform(ctx->state, ctx->buffer);

        for (offset = part_len; offset + 63 < len; offset += 64) {
            sha1_transform(ctx->state, &data[offset]);
        }

        index = 0;
    }

    memcpy(&ctx->buffer[index], &data[offset], len - offset);
}

void simple_connection_sha1_final(simple_connection_sha1_context *ctx, unsigned char digest[SIMPLE_CONNECTION_SHA1_DIGEST_LENGTH])
{
    static const unsigned char padding[64] = { 0x80 };
    unsigned char bits[8];

    for (int i = 0; i < 8; i++) {
        bits[7 - i] = (unsigned char)((ctx->bitcount >> (i * 8)) & 0xff);
    }

    size_t index = (size_t)((ctx->bitcount >> 3) % 64);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
    simple_connection_sha1_update(ctx, padding, pad_len);
    simple_connection_sha1_update(ctx, bits, sizeof(bits));

    for (int i = 0; i < 5; i++) {
        digest[i * 4] = (unsigned char)((ctx->state[i] >> 24) & 0xff);
        digest[i * 4 + 1] = (unsigned char)((ctx->state[i] >> 16) & 0xff);
        digest[i * 4 + 2] = (unsigned char)((ctx->state[i] >> 8) & 0xff);
        digest[i * 4 + 3] = (unsigned char)(ctx->state[i] & 0xff);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void simple_connection_sha1(const unsigned char *data, size_t len, unsigned char digest[SIMPLE_CONNECTION_SHA1_DIGEST_LENGTH])
{
    simple_connection_sha1_context ctx;

    simple_connection_sha1_init(&ctx);
    simple_connection_sha1_update(&ctx, data, len);
    simple_connection_sha1_final(&ctx, digest);
}
