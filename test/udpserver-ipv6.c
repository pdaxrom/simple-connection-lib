/*
 * UDP server IPv6
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../src/udp.h"

#define BUF_SIZE	256

int main(int argc, char *argv[])
{
    char buf[BUF_SIZE];
    int r;
    udp_channel *server = udp_open(UDP_SERVER, NULL, 9999);
    if (!server) {
	fprintf(stderr, "udp_open() IPv6 server\n");
	return -1;
    }

    if ((r = udp_read(server, (uint8_t *)buf, BUF_SIZE)) > 0) {
	fprintf(stderr, "buf[%d]=%s\n", r, buf);
    }

    strcpy(buf, "Hello UDP IPv6 client!");
    if ((r = udp_write(server, (uint8_t *)buf, strlen(buf) + 1)) <= 0) {
	fprintf(stderr, "udp_write()\n");
    }

    udp_close(server);

    return 0;
}
