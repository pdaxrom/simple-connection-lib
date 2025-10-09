/*
 * Error handling implementation for simple-connection library
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "errors.h"

/* Global error info - thread local for thread safety */
THREAD_LOCAL simple_connection_error_info simple_connection_last_error = {
    .error_code = SIMPLE_CONNECTION_SUCCESS,
    .system_errno = 0,
    .function = NULL,
    .line = 0,
    .message = {0}
};

/* Set error information */
void simple_connection_set_error(int error_code, int system_errno,
                                 const char *function, int line,
                                 const char *format, ...)
{
    simple_connection_last_error.error_code = error_code;
    simple_connection_last_error.system_errno = system_errno;
    simple_connection_last_error.function = function;
    simple_connection_last_error.line = line;

    va_list args;
    va_start(args, format);
    vsnprintf(simple_connection_last_error.message,
              sizeof(simple_connection_last_error.message),
              format, args);
    va_end(args);
}

/* Set error with channel callback support */
void simple_connection_set_channel_error(void *channel,
                                         void (*error_callback)(const char *),
                                         int error_code, int system_errno,
                                         const char *function, int line,
                                         const char *format, va_list args)
{
    /* Set the global error information */
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    simple_connection_set_error(error_code, system_errno, function, line, "%s", buffer);

    /* Also call the error callback for backward compatibility */
    if (channel && error_callback) {
        error_callback(buffer);
    } else {
        vfprintf(stderr, format, args);
    }
}

/* Clear error information */
void simple_connection_clear_error(void)
{
    simple_connection_last_error.error_code = SIMPLE_CONNECTION_SUCCESS;
    simple_connection_last_error.system_errno = 0;
    simple_connection_last_error.function = NULL;
    simple_connection_last_error.line = 0;
    simple_connection_last_error.message[0] = '\0';
}

/* Get last error code */
int simple_connection_get_last_error(void)
{
    return simple_connection_last_error.error_code;
}

/* Get last system errno */
int simple_connection_get_last_errno(void)
{
    return simple_connection_last_error.system_errno;
}

/* Get last error message */
const char *simple_connection_get_last_error_message(void)
{
    return simple_connection_last_error.message;
}

/* Convert error code to string */
const char *simple_connection_get_error_string(int error_code)
{
    switch (error_code) {
    case SIMPLE_CONNECTION_SUCCESS:
        return "Success";

        /* System errors */
    case SIMPLE_CONNECTION_ERROR_SOCKET:
        return "Socket creation failed";
    case SIMPLE_CONNECTION_ERROR_BIND:
        return "Socket bind failed";
    case SIMPLE_CONNECTION_ERROR_LISTEN:
        return "Socket listen failed";
    case SIMPLE_CONNECTION_ERROR_CONNECT:
        return "Socket connect failed";
    case SIMPLE_CONNECTION_ERROR_ACCEPT:
        return "Socket accept failed";
    case SIMPLE_CONNECTION_ERROR_SEND:
        return "Socket send failed";
    case SIMPLE_CONNECTION_ERROR_RECV:
        return "Socket receive failed";
    case SIMPLE_CONNECTION_ERROR_SENDTO:
        return "Socket sendto failed";
    case SIMPLE_CONNECTION_ERROR_RECVFROM:
        return "Socket recvfrom failed";
    case SIMPLE_CONNECTION_ERROR_SETSOCKOPT:
        return "Socket setsockopt failed";
    case SIMPLE_CONNECTION_ERROR_GETADDRINFO:
        return "getaddrinfo failed";
    case SIMPLE_CONNECTION_ERROR_GETHOSTBYNAME:
        return "gethostbyname failed";
    case SIMPLE_CONNECTION_ERROR_INET_ATON:
        return "inet_aton failed";

        /* SSL/TLS errors */
    case SIMPLE_CONNECTION_ERROR_SSL_CTX_NEW:
        return "SSL context creation failed";
    case SIMPLE_CONNECTION_ERROR_SSL_CIPHER_LIST:
        return "SSL cipher list setting failed";
    case SIMPLE_CONNECTION_ERROR_SSL_PRIVATE_KEY:
        return "SSL private key loading failed";
    case SIMPLE_CONNECTION_ERROR_SSL_CERTIFICATE:
        return "SSL certificate loading failed";
    case SIMPLE_CONNECTION_ERROR_SSL_NEW:
        return "SSL object creation failed";
    case SIMPLE_CONNECTION_ERROR_SSL_CONNECT:
        return "SSL connect failed";
    case SIMPLE_CONNECTION_ERROR_SSL_ACCEPT:
        return "SSL accept failed";
    case SIMPLE_CONNECTION_ERROR_SSL_READ:
        return "SSL read failed";
    case SIMPLE_CONNECTION_ERROR_SSL_WRITE:
        return "SSL write failed";
    case SIMPLE_CONNECTION_ERROR_SSL_SET_FD:
        return "SSL set file descriptor failed";

        /* WebSocket errors */
    case SIMPLE_CONNECTION_ERROR_WS_HANDSHAKE:
        return "WebSocket handshake failed";
    case SIMPLE_CONNECTION_ERROR_WS_INVALID_OPCODE:
        return "WebSocket invalid opcode";
    case SIMPLE_CONNECTION_ERROR_WS_PAYLOAD_TOO_LARGE:
        return "WebSocket payload too large";
    case SIMPLE_CONNECTION_ERROR_WS_CONNECTION_CLOSED:
        return "WebSocket connection closed";
    case SIMPLE_CONNECTION_ERROR_WS_PROTOCOL_ERROR:
        return "WebSocket protocol error";

        /* Memory errors */
    case SIMPLE_CONNECTION_ERROR_MALLOC:
        return "Memory allocation failed";
    case SIMPLE_CONNECTION_ERROR_STRDUP:
        return "String duplication failed";

        /* Input validation errors */
    case SIMPLE_CONNECTION_ERROR_INVALID_PORT:
        return "Invalid port number";
    case SIMPLE_CONNECTION_ERROR_INVALID_ADDRESS:
        return "Invalid address";
    case SIMPLE_CONNECTION_ERROR_INVALID_MODE:
        return "Invalid connection mode";
    case SIMPLE_CONNECTION_ERROR_INVALID_SSL_KEY:
        return "Invalid SSL key file";
    case SIMPLE_CONNECTION_ERROR_INVALID_SSL_CERT:
        return "Invalid SSL certificate file";
    case SIMPLE_CONNECTION_ERROR_INVALID_PATH:
        return "Invalid path";

        /* Connection state errors */
    case SIMPLE_CONNECTION_ERROR_NOT_CONNECTED:
        return "Not connected";
    case SIMPLE_CONNECTION_ERROR_ALREADY_CONNECTED:
        return "Already connected";
    case SIMPLE_CONNECTION_ERROR_CONNECTION_CLOSED:
        return "Connection closed";
    case SIMPLE_CONNECTION_ERROR_TIMEOUT:
        return "Operation timed out";

        /* Winsock errors */
    case SIMPLE_CONNECTION_ERROR_WINSOCK_INIT:
        return "Winsock initialization failed";

    default:
        return "Unknown error";
    }
}
