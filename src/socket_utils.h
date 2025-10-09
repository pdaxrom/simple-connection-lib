/*
 * Common socket utilities for simple-connection library
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

#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Socket creation utilities */
int simple_connection_create_socket(int domain, int type, int protocol);
int simple_connection_bind_socket(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int simple_connection_connect_socket(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int simple_connection_listen_socket(int sockfd, int backlog);
int simple_connection_close_socket(int sockfd);

/* Address resolution utilities */
int simple_connection_resolve_address(const char *hostname, const char *service,
                                    int family, int socktype, int protocol, int flags,
                                    struct addrinfo **result);
void simple_connection_free_address(struct addrinfo *addr);

/* Socket option utilities */
int simple_connection_set_socket_reuseaddr(int sockfd, int reuse);
int simple_connection_set_socket_nonblocking(int sockfd, int nonblock);

#ifdef __cplusplus
}
#endif

#endif /* SOCKET_UTILS_H */
