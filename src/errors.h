/*
 * Error codes for simple-connection library
 *
 * Copyright (c) 2008-2021 Alexander Chukov <sashz@pdaXrom.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef ERRORS_H
#define ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

enum simple_connection_error {
    SIMPLE_CONNECTION_SUCCESS = 0,
    SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT = -1,
    SIMPLE_CONNECTION_ERROR_MEMORY = -2,
    SIMPLE_CONNECTION_ERROR_SOCKET = -3,
    SIMPLE_CONNECTION_ERROR_BIND = -4,
    SIMPLE_CONNECTION_ERROR_LISTEN = -5,
    SIMPLE_CONNECTION_ERROR_CONNECT = -6,
    SIMPLE_CONNECTION_ERROR_ACCEPT = -7,
    SIMPLE_CONNECTION_ERROR_READ = -8,
    SIMPLE_CONNECTION_ERROR_WRITE = -9,
    SIMPLE_CONNECTION_ERROR_SSL = -10,
    SIMPLE_CONNECTION_ERROR_WS = -11,
    SIMPLE_CONNECTION_ERROR_TIMEOUT = -12,
    SIMPLE_CONNECTION_ERROR_UNKNOWN = -13
};

#ifdef __cplusplus
}
#endif

#endif /* ERRORS_H */

