/*
 * TCP client IPv6
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../src/tcp.h"

#define BUF_SIZE	256

int main(int argc, char *argv[])
{
    char buf[BUF_SIZE];
    int r;
    tcp_channel *server = tcp_open(TCP_CLIENT, "::1", 9999, NULL, NULL);
    if (!server) {
	fprintf(stderr, "tcp_open() IPv6\n");
	return -1;
    }

    strcpy(buf, "Hello IPv6 server!");

    if ((r = tcp_write(server, buf, strlen(buf) + 1)) <= 0) {
	fprintf(stderr, "tcp_write()\n");
    }

    if ((r = tcp_read(server, buf, BUF_SIZE)) > 0) {
	fprintf(stderr, "buf[%d]=%s\n", r, buf);
    }

    tcp_close(server);

    return 0;
}
