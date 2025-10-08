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
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#define closesocket close
#else
#include <windows.h>
#endif

#define PORT 9930

#include "udp.h"

static void udp_report_error(udp_channel *u, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (u && u->error_callback) {
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        u->error_callback(buffer);
    } else {
        vfprintf(stderr, format, args);
    }
    va_end(args);
}

#ifdef _WIN32
typedef int socklen_t;

static int winsock_inited = 0;
static int winsock_init(void)
{
    WSADATA w;

    if (winsock_inited)
	return 0;

    if (WSAStartup(0x0101, &w) != 0) {
	fprintf(stderr, "Could not open Windows connection.\n");
	return -1;
    }
    
    winsock_inited = 1;
    return 0;
}
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

    if ((u->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        free(u);
        return NULL;
    }

    memset(&u->my_addr, 0, sizeof(u->my_addr));
    u->my_addr.sin_family = AF_INET;
    u->my_addr.sin_port = htons(port);
    u->my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(u->s, (struct sockaddr* ) &u->my_addr, sizeof(u->my_addr)) == -1) {
        udp_report_error(u, "bind() failed\n");
        closesocket(u->s);
        free(u);
        return NULL;
    }

    u->inp_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    if (!u->inp_addr) {
        udp_report_error(u, "malloc() failed\n");
        closesocket(u->s);
        free(u);
        return NULL;
    }
    u->out_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    if (!u->out_addr) {
        udp_report_error(u, "malloc() failed\n");
        closesocket(u->s);
        free(u->inp_addr);
        free(u);
        return NULL;
    }

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

    if ((u->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        free(u);
        return NULL;
    }

    memset(&u->my_addr, 0, sizeof(u->my_addr));
    u->my_addr.sin_family = AF_INET;
    u->my_addr.sin_port = htons(port);

#ifdef _WIN32
    if ((u->my_addr.sin_addr.s_addr = inet_addr(addr)) == INADDR_NONE) {
        udp_report_error(u, "inet_addr() failed\n");
#else
    if (inet_aton(addr, &u->my_addr.sin_addr) == 0) {
        udp_report_error(u, "inet_aton() failed\n");
#endif
        closesocket(u->s);
        free(u);
        return NULL;
    }

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
    if (winsock_init())
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
    socklen_t slen = sizeof(u->my_addr);

    if (u->mode == UDP_SERVER) {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)u->inp_addr, &slen)) == -1) {
    	    udp_report_error(u, "recvfrom()\n");
	}
	*u->out_addr = *u->inp_addr;
    } else {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, &slen))==-1) {
	    udp_report_error(u, "recvfrom()\n");
	}
    }

    return r;
}

int udp_write(udp_channel *u, void *buf, size_t len)
{
    int r;
    socklen_t slen = sizeof(u->my_addr);

    if (u->mode == UDP_SERVER) {
	if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)u->out_addr, slen)) < 0) {
	    udp_report_error(u, "sendto()\n");
	}
    } else {
	if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, slen)) == -1) {
	    udp_report_error(u, "sendto()\n");
	}
    }

    return r;
}

int udp_read_src(udp_channel *u, void *buf, size_t len)
{
    int r;
    socklen_t slen = sizeof(u->my_addr);

    if (u->mode == UDP_SERVER) {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)u->inp_addr, &slen)) == -1) {
    	    udp_report_error(u, "recvfrom()\n");
	}
    } else {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, &slen))==-1) {
	    udp_report_error(u, "recvfrom()\n");
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
        udp_report_error(u, "malloc() failed\n");
	return -1;
    }
    fwd->addr = *u->inp_addr;
    fwd->label = strdup(label);
    if (!fwd->label) {
        udp_report_error(u, "strdup() failed\n");
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
	    socklen_t slen = sizeof(fwd->addr);
	    int r;
	    if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)&fwd->addr, slen)) < 0) {
		udp_report_error(u, "sendto()\n");
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
    udp_report_error(u, "-- UDP forward table --\n");
    while (fwd) {
	udp_report_error(u, "%s %s:%d %d\n", fwd->label, inet_ntoa(fwd->addr.sin_addr), ntohs(fwd->addr.sin_port), fwd->total);
	fwd = fwd->next;
    }
    udp_report_error(u, "-----------------------\n");
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
