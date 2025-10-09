/*
 * Common socket utilities implementation
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "socket_utils.h"
#include "platform.h"

/* Create a socket */
int simple_connection_create_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

/* Bind a socket to an address */
int simple_connection_bind_socket(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return bind(sockfd, addr, addrlen);
}

/* Connect a socket */
int simple_connection_connect_socket(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return connect(sockfd, addr, addrlen);
}

/* Listen on a socket */
int simple_connection_listen_socket(int sockfd, int backlog)
{
    return listen(sockfd, backlog);
}

/* Close a socket */
int simple_connection_close_socket(int sockfd)
{
    return closesocket(sockfd);
}

/* Resolve an address */
int simple_connection_resolve_address(const char *hostname, const char *service,
                                    int family, int socktype, int protocol, int flags,
                                    struct addrinfo **result)
{
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    hints.ai_flags = flags;

    return getaddrinfo(hostname, service, &hints, result);
}

/* Free address info */
void simple_connection_free_address(struct addrinfo *addr)
{
    freeaddrinfo(addr);
}

/* Set socket reuse address option */
int simple_connection_set_socket_reuseaddr(int sockfd, int reuse)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
}

/* Set socket non-blocking mode */
int simple_connection_set_socket_nonblocking(int sockfd, int nonblock)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }

    if (nonblock) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    return fcntl(sockfd, F_SETFL, flags);
}
