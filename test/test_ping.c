/*
 * Simple test for PING PONG functionality
 */

#include <stdio.h>
#include <string.h>
#include "../src/tcp.h"

int main() {
    tcp_channel *client = tcp_open(TCP_CLIENT, "127.0.0.1", 9999, NULL, NULL);
    if (!client) {
        printf("Failed to connect\n");
        return 1;
    }

    if (!tcp_connection_upgrade(client, SIMPLE_CONNECTION_METHOD_WS, "/", NULL, 0)) {
        printf("Failed to upgrade to WS\n");
        tcp_close(client);
        return 1;
    }

    printf("Connected to WebSocket\n");

    // Test empty PING
    printf("Sending empty PING...\n");
    int ret = tcp_ping(client, NULL, 0);
    printf("tcp_ping returned: %d\n", ret);

    if (ret > 0) {
        printf("✓ Empty PING sent successfully\n");
    } else {
        printf("✗ Empty PING failed\n");
    }

    tcp_close(client);
    return 0;
}