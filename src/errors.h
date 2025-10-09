/*
 * Error codes and errno handling for simple-connection library
 *
 * Copyright (c) 2025 Alexander Chukov <sashz@pdaXrom.org>
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

/* Thread-local storage for thread safety */
#ifdef _WIN32
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

#include <errno.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes for simple-connection library */
enum {
    SIMPLE_CONNECTION_SUCCESS = 0,

    /* System errors (preserve errno values) */
    SIMPLE_CONNECTION_ERROR_SOCKET = -1,
    SIMPLE_CONNECTION_ERROR_BIND = -2,
    SIMPLE_CONNECTION_ERROR_LISTEN = -3,
    SIMPLE_CONNECTION_ERROR_CONNECT = -4,
    SIMPLE_CONNECTION_ERROR_ACCEPT = -5,
    SIMPLE_CONNECTION_ERROR_SEND = -6,
    SIMPLE_CONNECTION_ERROR_RECV = -7,
    SIMPLE_CONNECTION_ERROR_SENDTO = -8,
    SIMPLE_CONNECTION_ERROR_RECVFROM = -9,
    SIMPLE_CONNECTION_ERROR_SETSOCKOPT = -10,
    SIMPLE_CONNECTION_ERROR_GETADDRINFO = -11,
    SIMPLE_CONNECTION_ERROR_GETHOSTBYNAME = -12,
    SIMPLE_CONNECTION_ERROR_INET_ATON = -13,

    /* SSL/TLS errors */
    SIMPLE_CONNECTION_ERROR_SSL_CTX_NEW = -100,
    SIMPLE_CONNECTION_ERROR_SSL_CIPHER_LIST = -101,
    SIMPLE_CONNECTION_ERROR_SSL_PRIVATE_KEY = -102,
    SIMPLE_CONNECTION_ERROR_SSL_CERTIFICATE = -103,
    SIMPLE_CONNECTION_ERROR_SSL_NEW = -104,
    SIMPLE_CONNECTION_ERROR_SSL_CONNECT = -105,
    SIMPLE_CONNECTION_ERROR_SSL_ACCEPT = -106,
    SIMPLE_CONNECTION_ERROR_SSL_READ = -107,
    SIMPLE_CONNECTION_ERROR_SSL_WRITE = -108,
    SIMPLE_CONNECTION_ERROR_SSL_SET_FD = -109,

    /* WebSocket errors */
    SIMPLE_CONNECTION_ERROR_WS_HANDSHAKE = -200,
    SIMPLE_CONNECTION_ERROR_WS_INVALID_OPCODE = -201,
    SIMPLE_CONNECTION_ERROR_WS_PAYLOAD_TOO_LARGE = -202,
    SIMPLE_CONNECTION_ERROR_WS_CONNECTION_CLOSED = -203,
    SIMPLE_CONNECTION_ERROR_WS_PROTOCOL_ERROR = -204,

    /* Memory errors */
    SIMPLE_CONNECTION_ERROR_MALLOC = -300,
    SIMPLE_CONNECTION_ERROR_STRDUP = -301,

    /* Input validation errors */
    SIMPLE_CONNECTION_ERROR_INVALID_PORT = -400,
    SIMPLE_CONNECTION_ERROR_INVALID_ADDRESS = -401,
    SIMPLE_CONNECTION_ERROR_INVALID_MODE = -402,
    SIMPLE_CONNECTION_ERROR_INVALID_SSL_KEY = -403,
    SIMPLE_CONNECTION_ERROR_INVALID_SSL_CERT = -404,
    SIMPLE_CONNECTION_ERROR_INVALID_PATH = -405,

    /* Connection state errors */
    SIMPLE_CONNECTION_ERROR_NOT_CONNECTED = -500,
    SIMPLE_CONNECTION_ERROR_ALREADY_CONNECTED = -501,
    SIMPLE_CONNECTION_ERROR_CONNECTION_CLOSED = -502,
    SIMPLE_CONNECTION_ERROR_TIMEOUT = -503,

    /* Winsock errors (Windows only) */
    SIMPLE_CONNECTION_ERROR_WINSOCK_INIT = -600,
};

/* Structure to hold detailed error information */
typedef struct {
    int error_code;         /* SIMPLE_CONNECTION_* error code */
    int system_errno;       /* errno value from system call */
} simple_connection_error_info;

/* Global error info - thread local for thread safety */
extern THREAD_LOCAL simple_connection_error_info simple_connection_last_error;

/* Functions to get error information */
int simple_connection_get_last_error(void);
int simple_connection_get_last_errno(void);
const char *simple_connection_get_last_error_message(void);
const char *simple_connection_get_error_string(int error_code);

/* Internal functions for setting errors */
void simple_connection_set_error(int error_code, int system_errno);
void simple_connection_set_channel_error(void *channel,
                                         void (*error_callback)(const char *),
                                         int error_code, int system_errno);
void simple_connection_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif /* ERRORS_H */
