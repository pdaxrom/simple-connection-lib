/*
 *  TCP IO wrapper
 *
 *  Copyright (C) 2008-2013 Alexander Chukov <sash@pdaXrom.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <netdb.h>
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

#include "tcp.h"

static const char *SSL_CIPHER_LIST = "ALL:!LOW";

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

static SSL_CTX *ssl_initialize(char *sslkeyfile, char *sslcertfile)
{
    SSL_CTX *ssl_context;

    /* 0. initialize library */
    SSL_library_init();
    SSL_load_error_strings();

    /* 1. initialize context */
    if ((ssl_context = SSL_CTX_new(SSLv23_server_method())) == NULL) {
	fprintf(stderr, "Failed to initialize SSL context.\n");
	return NULL;
    }

    SSL_CTX_set_options(ssl_context, SSL_OP_ALL);

    if (!SSL_CTX_set_cipher_list(ssl_context, SSL_CIPHER_LIST)) {
	fprintf(stderr, "Failed to set SSL cipher list.\n");
	goto error1;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_context, sslkeyfile, SSL_FILETYPE_PEM) <= 0) {
	fprintf(stderr, "Failed to load private key file.\n");
	goto error1;
    }

    if (SSL_CTX_use_certificate_file(ssl_context, sslcertfile, SSL_FILETYPE_PEM) <= 0) {
	fprintf(stderr, "Failed to load certificate key file.\n");
	goto error1;
    }

    return ssl_context;
 error1:
    SSL_CTX_free(ssl_context);
    return NULL;
}

static SSL_CTX *ssl_client_initialize(void)
{
    SSL_CTX *ctx;
    /* Set up the library */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    static const SSL_METHOD *meth;
    meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);

    if (!ctx) {
	ERR_print_errors_fp(stderr);
    }

    return ctx;
}

static void ssl_tear_down(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}

tcp_channel *tcp_open(int mode, const char *addr, int port, char *sslkeyfile, char *sslcertfile)
{
#ifdef _WIN32
    if (winsock_init()) {
	return NULL;
    }
#endif

    tcp_channel *u = (tcp_channel *)malloc(sizeof(tcp_channel));
    memset(u, 0, sizeof(tcp_channel));

    u->mode = mode;

    if ((u->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	fprintf(stderr, "socket() error!\n");
	free(u);
	return NULL;
    }

    if ((mode == TCP_SERVER) || (mode == TCP_SSL_SERVER)) {
#ifndef _WIN32
	int yes = 1;
	if(setsockopt(u->s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
	    fprintf(stderr, "setsockopt() error!\n");
	    free(u);
	    return NULL;
	}
#endif

	memset(&u->my_addr, 0, sizeof(u->my_addr));
	u->my_addr.sin_family = AF_INET;
        u->my_addr.sin_addr.s_addr = INADDR_ANY;
        u->my_addr.sin_port = htons(port);

	if(bind(u->s, (struct sockaddr *)&u->my_addr, sizeof(u->my_addr)) == -1) {
	    fprintf(stderr, "bind() error!\n");
	    closesocket(u->s);
	    free(u);
	    return NULL;
	}

	if (listen(u->s, 10) == -1) {
	    fprintf(stderr, "listen() error!\n");
	    closesocket(u->s);
	    free(u);
	    return NULL;
	}
	
	if (mode == TCP_SSL_SERVER) {
	    u->ctx = ssl_initialize(sslkeyfile, sslcertfile);
	}
    } else {
	struct hostent *server = gethostbyname(addr);
	if (server == NULL) {
	    fprintf(stderr, "gethostbyname() no such host\n");
	    free(u);
	    return NULL;
	}

	memset(&u->my_addr, 0, sizeof(u->my_addr));
	u->my_addr.sin_family = AF_INET;
        u->my_addr.sin_addr = *((struct in_addr *)server->h_addr);
        u->my_addr.sin_port = htons(port);

	if (connect(u->s, (struct sockaddr *)&u->my_addr, sizeof(struct sockaddr)) == -1) {
	    fprintf(stderr, "connect()\n");
	    closesocket(u->s);
	    free(u);
	    return NULL;
	}

	if (mode == TCP_SSL_CLIENT) {
	    u->ctx = ssl_client_initialize();
	    u->ssl = SSL_new(u->ctx);
	    SSL_set_tlsext_host_name(u->ssl, addr);
	    SSL_set_fd(u->ssl, u->s);
	    int retval;
	    if ((retval = SSL_connect(u->ssl)) < 0) {
		fprintf(stderr, "SSL_connect(): %d\n", SSL_get_error(u->ssl, retval));
		SSL_free(u->ssl);
		ssl_tear_down(u->ctx);
		free(u);
		return NULL;
	    }
	}
    }

    return u;
}

int tcp_close(tcp_channel *u)
{
    if (u->s >= 0) {
	if ((u->mode == TCP_SSL_CLIENT) || (u->mode == TCP_SSL_SERVER)) {
	    if (u->mode == TCP_SSL_CLIENT) {
		SSL_shutdown(u->ssl);
		SSL_free(u->ssl);
	    }
	    if (u->ctx) {
		ssl_tear_down(u->ctx);
	    }
	}
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

tcp_channel *tcp_accept(tcp_channel *u)
{
    tcp_channel *n = (tcp_channel *)malloc(sizeof(tcp_channel));
    memset(n, 0, sizeof(tcp_channel));

    if (u->mode == TCP_SSL_SERVER) {
	n->mode = TCP_SSL_CLIENT;
    } else {
	n->mode = TCP_CLIENT;
    }

    socklen_t l = sizeof(struct sockaddr);
    if ((n->s = accept(u->s, (struct sockaddr *)&n->my_addr, &l)) < 0) {
	fprintf(stderr, "accept()\n");
	free(n);
	return NULL;
    }

    if (u->mode == TCP_SSL_SERVER) {
	if ((n->ssl = SSL_new(u->ctx)) == NULL) {
	    fprintf(stderr, "Failed to create SSL connection.\n");
	    closesocket(n->s);
	    free(n);
	    return NULL;
	}

	SSL_set_fd(n->ssl, n->s);

	if (SSL_accept(n->ssl) < 0) {
	    fprintf(stderr, "Unable to accept SSL connection.\n");
	    ERR_print_errors_fp(stderr);
	    SSL_free(n->ssl);
	    closesocket(n->s);
	    free(n);
	    return NULL;
	}
    }

    return n;
}

int tcp_read(tcp_channel *u, char *buf, size_t len)
{
    int r;

    if ((u->mode == TCP_SSL_CLIENT) || (u->mode == TCP_SSL_SERVER)) {
	if ((r = SSL_read(u->ssl, buf, len)) < 0) {
	    fprintf(stderr, "SSL_read()\n");
	}
    } else {
	if ((r = recv(u->s, buf, len, 0)) == -1) {
	    fprintf(stderr, "recvfrom()\n");
	}
    }

    return r;
}

int tcp_write(tcp_channel *u, char *buf, size_t len)
{
    int r;
    if ((u->mode == TCP_SSL_CLIENT) || (u->mode == TCP_SSL_SERVER)) {
	if ((r = SSL_write(u->ssl, buf, len)) < 0) {
	    fprintf(stderr, "SSL_write()\n");
	}
    } else {
	if ((r = send(u->s, buf, len, 0)) < 0) {
	    fprintf(stderr, "sendto()\n");
	}
    }

    return r;
}
