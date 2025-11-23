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

#ifndef SIMPLE_CONNECTION_SHA1_H
#define SIMPLE_CONNECTION_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SIMPLE_CONNECTION_SHA1_DIGEST_LENGTH 20

typedef struct {
    uint32_t state[5];
    uint64_t bitcount;
    unsigned char buffer[64];
} simple_connection_sha1_context;

void simple_connection_sha1_init(simple_connection_sha1_context *ctx);
void simple_connection_sha1_update(simple_connection_sha1_context *ctx, const unsigned char *data, size_t len);
void simple_connection_sha1_final(simple_connection_sha1_context *ctx, unsigned char digest[SIMPLE_CONNECTION_SHA1_DIGEST_LENGTH]);
void simple_connection_sha1(const unsigned char *data, size_t len, unsigned char digest[SIMPLE_CONNECTION_SHA1_DIGEST_LENGTH]);

#endif /* SIMPLE_CONNECTION_SHA1_H */
