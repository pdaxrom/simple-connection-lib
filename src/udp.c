/*
 *  UDP IO wrapper
 *
 *  Copyright (c) 2008-2021 Alexander Chukov <sashz@pdaXrom.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#include "platform.h"
#include "udp.h"
#include "errors.h"



static void udp_set_error(udp_channel *u, int error_code, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    /* Set the global error information */
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    simple_connection_set_error(error_code, errno, __func__, __LINE__, "%s", buffer);

    /* Also call the error callback for backward compatibility */
    if (u && u->error_callback) {
        u->error_callback(buffer);
    } else {
        vfprintf(stderr, format, args);
    }
    va_end(args);
}

#ifdef _WIN32
typedef int socklen_t;
#endif

static udp_channel *udp_open_server(uint16_t port)
{
    udp_channel *u = (udp_channel *)malloc(sizeof(udp_channel));
    if (!u) {
        fprintf(stderr, "malloc() failed %s(%d)\n", __func__, __LINE__);
        return NULL;
    }
    u->error_callback = NULL;

    u->mode = UDP_SERVER;

#ifdef HAVE_IPV6
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(NULL, port_str, &hints, &res) != 0) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_GETADDRINFO, "getaddrinfo() failed\n");
        free(u);
        return NULL;
    }

    if ((u->s = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_SOCKET, "socket() failed\n");
        freeaddrinfo(res);
        free(u);
        return NULL;
    }

    memcpy(&u->my_addr, res->ai_addr, res->ai_addrlen);
    u->my_addrlen = res->ai_addrlen;

    freeaddrinfo(res);
#else
    if ((u->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        free(u);
        return NULL;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)&u->my_addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    u->my_addrlen = sizeof(*sin);
#endif

    if (bind(u->s, (struct sockaddr* ) &u->my_addr, u->my_addrlen) == -1) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_BIND, "bind() failed\n");
        closesocket(u->s);
        free(u);
        return NULL;
    }

    u->inp_addr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
    if (!u->inp_addr) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_MALLOC, "malloc() failed\n");
        closesocket(u->s);
        free(u);
        return NULL;
    }
    u->inp_addrlen = sizeof(struct sockaddr_storage);

    u->out_addr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
    if (!u->out_addr) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_MALLOC, "malloc() failed\n");
        closesocket(u->s);
        free(u->inp_addr);
        free(u);
        return NULL;
    }
    u->out_addrlen = sizeof(struct sockaddr_storage);

    u->forward = NULL;

    return u;
}

static udp_channel *udp_open_client(char *addr, uint16_t port)
{
    udp_channel *u = (udp_channel *)malloc(sizeof(udp_channel));
    if (!u) {
        fprintf(stderr, "malloc() failed %s(%d)\n", __func__, __LINE__);
        return NULL;
    }
    u->error_callback = NULL;

    u->mode = UDP_CLIENT;

#ifdef HAVE_IPV6
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Allow both IPv4 and IPv6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(addr, port_str, &hints, &res) != 0) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_GETADDRINFO, "getaddrinfo() failed\n");
        free(u);
        return NULL;
    }

    if ((u->s = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_SOCKET, "socket() failed\n");
        freeaddrinfo(res);
        free(u);
        return NULL;
    }

    memcpy(&u->my_addr, res->ai_addr, res->ai_addrlen);
    u->my_addrlen = res->ai_addrlen;

    freeaddrinfo(res);
#else
    if ((u->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        free(u);
        return NULL;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)&u->my_addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);

#ifdef _WIN32
    if ((sin->sin_addr.s_addr = inet_addr(addr)) == INADDR_NONE) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_INET_ATON, "inet_addr() failed\n");
#else
    if (inet_aton(addr, &sin->sin_addr) == 0) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_INET_ATON, "inet_aton() failed\n");
#endif
        closesocket(u->s);
        free(u);
        return NULL;
    }
    u->my_addrlen = sizeof(*sin);
#endif

    u->inp_addr = NULL;
    u->out_addr = NULL;
    u->forward = NULL;

    return u;
}

udp_channel *udp_open(int mode, char *addr, uint16_t port)
{
    // Input validation
    if (port == 0) {
        return NULL;
    }

    if (mode == UDP_CLIENT) {
        if (!addr) {
            return NULL;
        }
    }

#ifdef _WIN32
    if (simple_connection_winsock_init())
	return NULL;
#endif

    if (mode == UDP_SERVER) {
        return udp_open_server(port);
    } else {
        return udp_open_client(addr, port);
    }
}

int udp_close(udp_channel *u)
{
    if (u->forward) {
	udp_forward *tmp;
	while (u->forward) {
	    tmp = u->forward->next;
	    free(u->forward->label);
	    free(u->forward);
	    u->forward = tmp;
	}
    }
    if (u->inp_addr) {
	free(u->inp_addr);
    }
    if (u->out_addr) {
	free(u->out_addr);
    }
    if (u->s != -1) {
	closesocket(u->s);
    }
    free(u);

    return 0;
}

int udp_read(udp_channel *u, void *buf, size_t len)
{
    int r;
    socklen_t slen = u->inp_addrlen;

    if (u->mode == UDP_SERVER) {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)u->inp_addr, &slen)) == -1) {
     	    udp_set_error(u, SIMPLE_CONNECTION_ERROR_RECVFROM, "recvfrom()\n");
 	}
 	*u->out_addr = *u->inp_addr;
 	u->out_addrlen = slen;
    } else {
        slen = u->my_addrlen;
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, &slen))==-1) {
 	    udp_set_error(u, SIMPLE_CONNECTION_ERROR_RECVFROM, "recvfrom()\n");
 	}
    }

    return r;
}

int udp_write(udp_channel *u, void *buf, size_t len)
{
    int r;
    socklen_t slen;

    if (u->mode == UDP_SERVER) {
        slen = u->out_addrlen;
 	if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)u->out_addr, slen)) < 0) {
 	    udp_set_error(u, SIMPLE_CONNECTION_ERROR_SENDTO, "sendto()\n");
 	}
    } else {
        slen = u->my_addrlen;
 	if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, slen)) == -1) {
 	    udp_set_error(u, SIMPLE_CONNECTION_ERROR_SENDTO, "sendto()\n");
 	}
    }

    return r;
}

int udp_read_src(udp_channel *u, void *buf, size_t len)
{
    int r;
    socklen_t slen;

    if (u->mode == UDP_SERVER) {
        slen = u->inp_addrlen;
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)u->inp_addr, &slen)) == -1) {
    	    udp_set_error(u, SIMPLE_CONNECTION_ERROR_RECVFROM, "recvfrom()\n");
	}
    } else {
        slen = u->my_addrlen;
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, &slen))==-1) {
	    udp_set_error(u, SIMPLE_CONNECTION_ERROR_RECVFROM, "recvfrom()\n");
	}
    }

    return r;
}

void udp_commit_dst(udp_channel *u)
{
    if (u->mode == UDP_SERVER) {
	*u->out_addr = *u->inp_addr;
    }
}

int udp_forward_add(udp_channel *u, char *label)
{
    if (u->mode != UDP_SERVER) {
	return 0;
    }

    udp_forward *fwd = u->forward;
    udp_forward *prev = NULL;
    while (fwd) {
	if (!strcmp(fwd->label, label)) {
	    fwd->used++;
	    return 0;
	}
	prev = fwd;
	fwd = fwd->next;
    }

    fwd = (udp_forward *) malloc(sizeof(udp_forward));
    if (!fwd) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_MALLOC, "malloc() failed\n");
	return -1;
    }
    fwd->addr = *u->inp_addr;
    fwd->addrlen = u->inp_addrlen;
    fwd->label = strdup(label);
    if (!fwd->label) {
        udp_set_error(u, SIMPLE_CONNECTION_ERROR_STRDUP, "strdup() failed\n");
        free(fwd);
        return -1;
    }
    fwd->used = 1;
    fwd->total = 0;
    fwd->next = NULL;

    if (prev) {
	prev->next = fwd;
    } else {
	u->forward = fwd;
    }

    return 0;
}

int udp_forward_write(udp_channel *u, char *label, void *buf, size_t len)
{
    if (u->mode != UDP_SERVER) {
	return 0;
    }

    udp_forward *fwd = u->forward;
    while(fwd) {
	if (!strcmp(fwd->label, label)) {
	    socklen_t slen = fwd->addrlen;
	    int r;
	    if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)&fwd->addr, slen)) < 0) {
		udp_set_error(u, SIMPLE_CONNECTION_ERROR_SENDTO, "sendto()\n");
	    }

	fwd->total += len;

	    return r;
	}
	fwd = fwd->next;
    }
    return -1;
}

void udp_forward_show(udp_channel *u)
{
    udp_forward *fwd = u->forward;
    if (!fwd) {
 	return;
    }
    fprintf(stderr, "-- UDP forward table --\n");
    while (fwd) {
        char addr_str[INET6_ADDRSTRLEN];
        uint16_t port = 0;
        if (fwd->addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&fwd->addr;
            inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
            port = ntohs(sin->sin_port);
        } else if (fwd->addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&fwd->addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
            port = ntohs(sin6->sin6_port);
        } else {
            strcpy(addr_str, "unknown");
        }
  	fprintf(stderr, "%s %s:%d %d\n", fwd->label, addr_str, port, fwd->total);
 	fwd = fwd->next;
    }
    fprintf(stderr, "-----------------------\n");
}

void udp_forward_remove_inactive(udp_channel *u)
{
    udp_forward *fwd = u->forward;
    udp_forward *prev = NULL;
    if (!fwd) {
	return;
    }
    while (fwd) {
	if (!fwd->used) {
	    if (prev) {
		prev->next = fwd->next;
	    } else {
		u->forward = fwd->next;
	    }
	    free(fwd->label);
	    free(fwd);
	    if (prev) {
		fwd = prev->next;
	    } else {
		fwd = u->forward;
	    }
	    continue;
	}
	fwd->used = 0;
	prev = fwd;
	fwd = fwd->next;
    }
}

void udp_set_error_callback(udp_channel *u, udp_error_callback cb)
{
    if (u) {
        u->error_callback = cb;
    }
}

/* Error handling functions */
int udp_get_last_error(void)
{
    return simple_connection_get_last_error();
}

int udp_get_last_errno(void)
{
    return simple_connection_get_last_errno();
}

const char *udp_get_last_error_message(void)
{
    return simple_connection_get_last_error_message();
}
