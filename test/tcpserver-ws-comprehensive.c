/*
 * Comprehensive WebSocket Server Test
 * Tests PING/PONG, message exchange, and connection handling
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/select.h>
#endif

#include "../src/tcp.h"

#define BUF_SIZE 4096
#define TEST_PORT 9999

int main(int argc, char *argv[])
{
    char buf[BUF_SIZE];
    int r, test_count = 0;
    tcp_channel *server = tcp_open(TCP_SERVER, NULL, TEST_PORT, NULL, NULL);
    if (!server) {
        fprintf(stderr, "tcp_open() failed\n");
        return -1;
    }

    printf("WebSocket server started on port %d\n", TEST_PORT);

    tcp_channel *client = tcp_accept(server);
    if (!client) {
        fprintf(stderr, "tcp_accept() failed\n");
        tcp_close(server);
        return -1;
    }

    if (!tcp_connection_upgrade(client, SIMPLE_CONNECTION_METHOD_WS, "/", NULL, 0)) {
        fprintf(stderr, "tcp_connection_upgrade() failed\n");
        tcp_close(client);
        tcp_close(server);
        return -1;
    }

    printf("WebSocket connection established\n");

    // Test 1: Receive initial message from client
    printf("Test %d: Receiving initial message from client\n", ++test_count);
    if ((r = tcp_read(client, buf, BUF_SIZE)) > 0) {
        buf[r] = 0;
        printf("Received: %s\n", buf);
        if (strcmp(buf, "Hello server!") == 0) {
            printf("✓ Test %d passed\n", test_count);
        } else {
            printf("✗ Test %d failed: expected 'Hello server!', got '%s'\n", test_count, buf);
        }
    } else {
        printf("✗ Test %d failed: tcp_read() returned %d\n", test_count, r);
    }

    // Test 2: Send response
    printf("Test %d: Sending response to client\n", ++test_count);
    strcpy(buf, "Hello client!");
    if ((r = tcp_write(client, buf, strlen(buf) + 1)) > 0) {
        printf("✓ Test %d passed: sent response\n", test_count);
    } else {
        printf("✗ Test %d failed: tcp_write() returned %d\n", test_count, r);
    }

    // Test 3: Send PING and expect PONG (automatic)
    printf("Test %d: Sending PING to client\n", ++test_count);
    strcpy(buf, "ping test");
    if (tcp_ping(client, buf, strlen(buf)) > 0) {
        printf("✓ Test %d passed: PING sent\n", test_count);
        // PONG should be handled automatically
    } else {
        printf("✗ Test %d failed: tcp_ping() failed\n", test_count);
    }

    // Test 4: Receive multiple messages
    printf("Test %d: Receiving multiple messages\n", ++test_count);
    int messages_received = 0;
    for (int i = 0; i < 3; i++) {
        if ((r = tcp_read(client, buf, BUF_SIZE)) > 0) {
            buf[r] = 0;
            printf("Received message %d: %s\n", i+1, buf);
            messages_received++;
        } else {
            printf("Failed to receive message %d: tcp_read() returned %d\n", i+1, r);
            break;
        }
    }
    if (messages_received == 3) {
        printf("✓ Test %d passed: received %d messages\n", test_count, messages_received);
    } else {
        printf("✗ Test %d failed: expected 3 messages, got %d\n", test_count, messages_received);
    }

    // Test 5: Send large message
    printf("Test %d: Sending large message\n", ++test_count);
    memset(buf, 'A', BUF_SIZE - 1);
    buf[BUF_SIZE - 1] = 0;
    if ((r = tcp_write(client, buf, BUF_SIZE)) > 0) {
        printf("✓ Test %d passed: sent large message (%d bytes)\n", test_count, r);
    } else {
        printf("✗ Test %d failed: tcp_write() returned %d\n", test_count, r);
    }

    // Test 6: Receive large message
    printf("Test %d: Receiving large message\n", ++test_count);
    if ((r = tcp_read(client, buf, BUF_SIZE)) > 0) {
        printf("✓ Test %d passed: received large message (%d bytes)\n", test_count, r);
    } else {
        printf("✗ Test %d failed: tcp_read() returned %d\n", test_count, r);
    }

    // Test 7: Send PING with empty payload
    printf("Test %d: Sending PING with empty payload\n", ++test_count);
    if (tcp_ping(client, NULL, 0) > 0) {
        printf("✓ Test %d passed: empty PING sent\n", test_count);
    } else {
        printf("✗ Test %d failed: tcp_ping() failed\n", test_count);
    }

    // Test 8: Wait a bit and send final message
    printf("Test %d: Sending final message\n", ++test_count);
    strcpy(buf, "Test complete");
    if ((r = tcp_write(client, buf, strlen(buf) + 1)) > 0) {
        printf("✓ Test %d passed: final message sent\n", test_count);
    } else {
        printf("✗ Test %d failed: tcp_write() returned %d\n", test_count, r);
    }

    // Wait for client to close or send close frame
    printf("Waiting for connection to close...\n");
    sleep(1);

    tcp_close(client);
    tcp_close(server);

    printf("WebSocket server test completed\n");
    return 0;
}
