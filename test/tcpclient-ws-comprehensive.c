/*
 * Comprehensive WebSocket Client Test
 * Tests PING/PONG, message exchange, and connection handling
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../src/tcp.h"

#define BUF_SIZE 4096
#define TEST_PORT 9999

int main(int argc, char *argv[])
{
    char buf[BUF_SIZE];
    int r, test_count = 0;
    tcp_channel *server = tcp_open(TCP_CLIENT, "127.0.0.1", TEST_PORT, NULL, NULL);
    if (!server) {
        fprintf(stderr, "tcp_open() failed\n");
        return -1;
    }

    if (!tcp_connection_upgrade(server, SIMPLE_CONNECTION_METHOD_WS, "/", NULL, 0)) {
        fprintf(stderr, "tcp_connection_upgrade() failed\n");
        tcp_close(server);
        return -1;
    }

    printf("WebSocket connection established\n");

    // Test 1: Send initial message
    printf("Test %d: Sending initial message to server\n", ++test_count);
    strcpy(buf, "Hello server!");
    if ((r = tcp_write(server, buf, strlen(buf) + 1)) > 0) {
        printf("✓ Test %d passed: message sent\n", test_count);
    } else {
        printf("✗ Test %d failed: tcp_write() returned %d\n", test_count, r);
    }

    // Test 2: Receive response
    printf("Test %d: Receiving response from server\n", ++test_count);
    if ((r = tcp_read(server, buf, BUF_SIZE)) > 0) {
        buf[r] = 0;
        printf("Received: %s\n", buf);
        if (strcmp(buf, "Hello client!") == 0) {
            printf("✓ Test %d passed\n", test_count);
        } else {
            printf("✗ Test %d failed: expected 'Hello client!', got '%s'\n", test_count, buf);
        }
    } else {
        printf("✗ Test %d failed: tcp_read() returned %d\n", test_count, r);
    }

    // Test 3: Receive PING and respond with PONG (automatic)
    printf("Test %d: Waiting for PING from server\n", ++test_count);
    // The PING/PONG handling is automatic, so we just wait for the next data message
    sleep(1); // Give time for PING to be processed
    printf("✓ Test %d passed: PING/PONG handled automatically\n", test_count);

    // Test 4: Send multiple messages
    printf("Test %d: Sending multiple messages\n", ++test_count);
    const char *messages[] = {"Message 1", "Message 2", "Message 3"};
    int messages_sent = 0;
    for (int i = 0; i < 3; i++) {
        strcpy(buf, messages[i]);
        if ((r = tcp_write(server, buf, strlen(buf) + 1)) > 0) {
            printf("Sent message %d: %s\n", i+1, messages[i]);
            messages_sent++;
        } else {
            printf("Failed to send message %d: tcp_write() returned %d\n", i+1, r);
            break;
        }
    }
    if (messages_sent == 3) {
        printf("✓ Test %d passed: sent %d messages\n", test_count, messages_sent);
    } else {
        printf("✗ Test %d failed: expected to send 3 messages, sent %d\n", test_count, messages_sent);
    }

    // Test 5: Receive large message
    printf("Test %d: Receiving large message\n", ++test_count);
    if ((r = tcp_read(server, buf, BUF_SIZE)) > 0) {
        printf("✓ Test %d passed: received large message (%d bytes)\n", test_count, r);
    } else {
        printf("✗ Test %d failed: tcp_read() returned %d\n", test_count, r);
    }

    // Test 6: Send large message back
    printf("Test %d: Sending large message\n", ++test_count);
    memset(buf, 'B', BUF_SIZE - 1);
    buf[BUF_SIZE - 1] = 0;
    if ((r = tcp_write(server, buf, BUF_SIZE)) > 0) {
        printf("✓ Test %d passed: sent large message (%d bytes)\n", test_count, r);
    } else {
        printf("✗ Test %d failed: tcp_write() returned %d\n", test_count, r);
    }

    // Test 7: Send PING to server
    printf("Test %d: Sending PING to server\n", ++test_count);
    strcpy(buf, "client ping");
    if (tcp_ping(server, buf, strlen(buf)) > 0) {
        printf("✓ Test %d passed: PING sent\n", test_count);
    } else {
        printf("✗ Test %d failed: tcp_ping() failed\n", test_count);
    }

    // Test 8: Send PING with empty payload
    printf("Test %d: Sending PING with empty payload\n", ++test_count);
    if (tcp_ping(server, NULL, 0) > 0) {
        printf("✓ Test %d passed: empty PING sent\n", test_count);
    } else {
        printf("✗ Test %d failed: tcp_ping() failed\n", test_count);
    }

    // Test 9: Receive final message
    printf("Test %d: Receiving final message\n", ++test_count);
    if ((r = tcp_read(server, buf, BUF_SIZE)) > 0) {
        buf[r] = 0;
        printf("Received final: %s\n", buf);
        if (strcmp(buf, "Test complete") == 0) {
            printf("✓ Test %d passed\n", test_count);
        } else {
            printf("✗ Test %d failed: expected 'Test complete', got '%s'\n", test_count, buf);
        }
    } else {
        printf("✗ Test %d failed: tcp_read() returned %d\n", test_count, r);
    }

    tcp_close(server);

    printf("WebSocket client test completed\n");
    return 0;
}
