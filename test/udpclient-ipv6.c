/*
 * UDP client IPv6
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
    udp_channel *client = udp_open(UDP_CLIENT, "::1", 9999);
    if (!client) {
	fprintf(stderr, "udp_open() IPv6\n");
	return -1;
    }

    strcpy(buf, "Hello UDP IPv6!");

    if ((r = udp_write(client, buf, strlen(buf) + 1)) <= 0) {
	fprintf(stderr, "udp_write()\n");
    }

    if ((r = udp_read(client, buf, BUF_SIZE)) > 0) {
	fprintf(stderr, "buf[%d]=%s\n", r, buf);
    }

    udp_close(client);

    return 0;
}
