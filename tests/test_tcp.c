#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/tcp.h"
#include "../src/errors.h"

// Mock or stub functions if needed

static void test_tcp_open_invalid_port(void **state) {
    (void) state;
    tcp_channel *ch = tcp_open(TCP_CLIENT, "127.0.0.1", 0, NULL, NULL);
    assert_null(ch);
}

static void test_tcp_open_invalid_port_high(void **state) {
    (void) state;
    tcp_channel *ch = tcp_open(TCP_CLIENT, "127.0.0.1", 70000, NULL, NULL);
    assert_null(ch);
}

static void test_tcp_open_null_addr_for_client(void **state) {
    (void) state;
    tcp_channel *ch = tcp_open(TCP_CLIENT, NULL, 9930, NULL, NULL);
    assert_null(ch);
}

static void test_tcp_read_null_channel(void **state) {
    (void) state;
    char buf[10];
    int ret = tcp_read(NULL, buf, sizeof(buf));
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_tcp_read_null_buf(void **state) {
    (void) state;
    // Need a mock channel, but for simplicity, assume
    int ret = tcp_read(NULL, NULL, 10);
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_tcp_write_null_channel(void **state) {
    (void) state;
    char buf[10] = "test";
    int ret = tcp_write(NULL, buf, sizeof(buf));
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_tcp_write_null_buf(void **state) {
    (void) state;
    int ret = tcp_write(NULL, NULL, 10);
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_tcp_write_large_buf(void **state) {
    (void) state;
    char buf[1024 * 1024 + 1];
    int ret = tcp_write(NULL, buf, sizeof(buf));
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_tcp_send_ping_null_channel(void **state) {
    (void) state;
    int ret = tcp_send_ping(NULL);
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tcp_open_invalid_port),
        cmocka_unit_test(test_tcp_open_invalid_port_high),
        cmocka_unit_test(test_tcp_open_null_addr_for_client),
        cmocka_unit_test(test_tcp_read_null_channel),
        cmocka_unit_test(test_tcp_read_null_buf),
        cmocka_unit_test(test_tcp_write_null_channel),
        cmocka_unit_test(test_tcp_write_null_buf),
        cmocka_unit_test(test_tcp_write_large_buf),
        cmocka_unit_test(test_tcp_send_ping_null_channel),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
