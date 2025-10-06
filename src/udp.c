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
#include <unistd.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#define closesocket close
#else
#include <windows.h>
#endif

#define PORT 9930

#include "udp.h"

/* Logging extern */
extern enum log_level current_log_level;
extern void simple_connection_log(enum log_level level, const char *format, ...);

#ifdef _WIN32
typedef int socklen_t;

static int winsock_inited = 0;
static int winsock_init(void)
{
    WSADATA w;

    if (winsock_inited)
	return 0;

    /* Open windows connection */
    if (WSAStartup(0x0101, &w) != 0) {
	fprintf(stderr, "Could not open Windows connection.\n");
	return -1;
    }
    
    winsock_inited = 1;
    return 0;
}
#endif

udp_channel *udp_open(int mode, char *addr, int port)
{
    if (port <= 0 || port > 65535) {
	return NULL;
    }
#ifdef _WIN32
    if (winsock_init())
	return NULL;
#endif

    udp_channel *u = (udp_channel *)malloc(sizeof(udp_channel));

    u->mode = mode;

    if (mode == UDP_SERVER) {
#ifndef sgi
	if ((u->s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	    free(u);
	    return NULL;
	}
#ifndef _WIN32
	int no = 0;
	if(setsockopt(u->s, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(int)) == -1) {
	    log_error("setsockopt() IPV6_V6ONLY failed");
	    free(u);
	    return NULL;
	}
#endif

	memset(&u->my_addr, 0, sizeof(u->my_addr));
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&u->my_addr;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = in6addr_any;
	sin6->sin6_port = htons(port);
	u->addrlen = sizeof(struct sockaddr_in6);

 	if (bind(u->s, (struct sockaddr* ) &u->my_addr, u->addrlen) == -1) {
      	    log_error("bind() failed");
  	    closesocket(u->s);
  	    free(u);
  	    return NULL;
  	}

	u->inp_addr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
	u->out_addr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
#else
	if ((u->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	    free(u);
	    return NULL;
	}

	memset(&u->my_addr, 0, sizeof(u->my_addr));
	struct sockaddr_in *sin = (struct sockaddr_in *)&u->my_addr;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_port = htons(port);
	u->addrlen = sizeof(struct sockaddr_in);

 	if (bind(u->s, (struct sockaddr* ) &u->my_addr, u->addrlen) == -1) {
      	    log_error("bind() failed");
  	    closesocket(u->s);
  	    free(u);
  	    return NULL;
  	}

	u->inp_addr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
	u->out_addr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
#endif
    } else {
#ifndef sgi
	char port_str[6];
	struct addrinfo hints = {0}, *res, *p;
	int success = 0;

	snprintf(port_str, sizeof(port_str), "%d", port);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	if (getaddrinfo(addr, port_str, &hints, &res) != 0) {
	    log_error("getaddrinfo() failed");
	    free(u);
	    return NULL;
	}

	for (p = res; p != NULL; p = p->ai_next) {
	    if ((u->s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
		continue;
	    }
	    memcpy(&u->my_addr, p->ai_addr, p->ai_addrlen);
	    u->addrlen = p->ai_addrlen;
	    success = 1;
	    break;
	}
	freeaddrinfo(res);
	if (!success) {
	    log_error("socket() failed");
	    free(u);
	    return NULL;
	}
	u->inp_addr = NULL;
	u->out_addr = NULL;
#else
	if ((u->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
	    free(u);
	    return NULL;
	}

	memset(&u->my_addr, 0, sizeof(u->my_addr));
	struct sockaddr_in *sin = (struct sockaddr_in *)&u->my_addr;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	u->addrlen = sizeof(struct sockaddr_in);

	if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
	    log_error("inet_pton() failed");
    	    closesocket(u->s);
    	    free(u);
    	    return NULL;
	}
	u->inp_addr = NULL;
	u->out_addr = NULL;
#endif
    }

    u->forward = NULL;

    return u;
}

int udp_close(udp_channel *u)
{
    if (!u) {
	return -1;
    }
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
    if (u->s >= 0) {
	closesocket(u->s);
    }
    free(u);
/*
#ifdef _WIN32
    if (winsock_inited) {
	WSACleanup();
	winsock_inited = 0;
    }
#endif
 */
    return 0;
}

int udp_read(udp_channel *u, void *buf, size_t len)
{
    if (!u || !buf) {
	return -1;
    }
    int r;
    socklen_t slen = sizeof(struct sockaddr_storage);

    if (u->mode == UDP_SERVER) {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)u->inp_addr, &slen)) == -1) {
      	    log_error("recvfrom() failed");
	} else {
#ifdef DEBUG
	    char ipstr[INET6_ADDRSTRLEN];
	    if (((struct sockaddr *)u->inp_addr)->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)u->inp_addr;
		inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from %s:%d size %d", ipstr, ntohs(sin->sin_port), r);
	    } else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)u->inp_addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from [%s]:%d size %d", ipstr, ntohs(sin6->sin6_port), r);
	    }
#endif
	}
	u->inp_addrlen = slen;
	*u->out_addr = *u->inp_addr;
	u->out_addrlen = u->inp_addrlen;
    } else {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, &u->addrlen))==-1) {
	    log_error("recvfrom() failed");
	} else {
#ifdef DEBUG
	    char ipstr[INET6_ADDRSTRLEN];
	    if (u->my_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&u->my_addr;
		inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from %s:%d size %d", ipstr, ntohs(sin->sin_port), r);
	    } else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&u->my_addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from [%s]:%d size %d", ipstr, ntohs(sin6->sin6_port), r);
	    }
#endif
	}
    }

    return r;
}

int udp_write(udp_channel *u, void *buf, size_t len)
{
    if (!u || !buf) {
	return -1;
    }
    int r;
    socklen_t slen;

    if (u->mode == UDP_SERVER) {
	slen = u->out_addrlen;
	if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)u->out_addr, slen)) < 0) {
	    log_error("sendto() failed");
	}
    } else {
	slen = u->addrlen;
	if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, slen)) == -1) {
	    log_error("sendto() failed");
	}
    }

    return r;
}

/*
 *
 */

int udp_read_src(udp_channel *u, void *buf, size_t len)
{
    int r;
    socklen_t slen = sizeof(struct sockaddr_storage);

    if (u->mode == UDP_SERVER) {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)u->inp_addr, &slen)) == -1) {
      	    log_error("recvfrom() failed");
	} else {
#ifdef DEBUG
	    char ipstr[INET6_ADDRSTRLEN];
	    if (((struct sockaddr *)u->inp_addr)->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)u->inp_addr;
		inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from %s:%d size %d", ipstr, ntohs(sin->sin_port), r);
	    } else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)u->inp_addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from [%s]:%d size %d", ipstr, ntohs(sin6->sin6_port), r);
	    }
#endif
	}
	u->inp_addrlen = slen;
    } else {
        if ((r = recvfrom(u->s, buf, len, 0, (struct sockaddr*)&u->my_addr, &u->addrlen))==-1) {
	    log_error("recvfrom() failed");
	} else {
#ifdef DEBUG
	    char ipstr[INET6_ADDRSTRLEN];
	    if (u->my_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&u->my_addr;
		inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from %s:%d size %d", ipstr, ntohs(sin->sin_port), r);
	    } else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&u->my_addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, ipstr, sizeof(ipstr));
		log_debug("Received packet from [%s]:%d size %d", ipstr, ntohs(sin6->sin6_port), r);
	    }
#endif
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
	if (!strncmp(fwd->label, label, 13)) {
	    fwd->used++;
	    return 0;
	}
	prev = fwd;
	fwd = fwd->next;
    }

    fwd = (udp_forward *) malloc(sizeof(udp_forward));
    if (!fwd) {
	return -1;
    }
    fwd->addr = *u->inp_addr;
    fwd->addrlen = u->inp_addrlen;
    fwd->label = strdup(label);
    fwd->used = 1;
    fwd->total = 0;
    fwd->next = NULL;

    if (prev) {
	prev->next = fwd;
    } else {
	u->forward = fwd;
    }

#ifdef DEBUG
    fprintf(stderr, "Added forward for %s\n", fwd->label);
#endif

    return 0;
}

int udp_forward_write(udp_channel *u, char *label, void *buf, size_t len)
{
    if (u->mode != UDP_SERVER) {
	return 0;
    }

    udp_forward *fwd = u->forward;
    while(fwd) {
	if (!strncmp(fwd->label, label, 13)) {
	    socklen_t slen = fwd->addrlen;
	    int r;
#ifdef DEBUG
	    fprintf(stderr, "Forward to %s\n", fwd->label);
#endif
	    if ((r = sendto(u->s, buf, len, 0, (struct sockaddr*)&fwd->addr, slen)) < 0) {
		fprintf(stderr, "sendto()\n");
	    }

	    fwd->total += len;

	    return r;
	}
	fwd = fwd->next;
    }
#ifdef DEBUG
    fprintf(stderr, "No forward destination!\n");
#endif
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
	char ipstr[INET6_ADDRSTRLEN];
	if (fwd->addr.ss_family == AF_INET) {
	    struct sockaddr_in *sin = (struct sockaddr_in *)&fwd->addr;
	    inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
	    fprintf(stderr, "%s %s:%d %d\n", fwd->label, ipstr, ntohs(sin->sin_port), fwd->total);
	} else {
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&fwd->addr;
	    inet_ntop(AF_INET6, &sin6->sin6_addr, ipstr, sizeof(ipstr));
	    fprintf(stderr, "%s [%s]:%d %d\n", fwd->label, ipstr, ntohs(sin6->sin6_port), fwd->total);
	}
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
