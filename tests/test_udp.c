#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/udp.h"
#include "../src/errors.h"

static void test_udp_open_invalid_port(void **state) {
    (void) state;
    udp_channel *ch = udp_open(UDP_CLIENT, "127.0.0.1", 0);
    assert_null(ch);
}

static void test_udp_open_invalid_port_high(void **state) {
    (void) state;
    udp_channel *ch = udp_open(UDP_CLIENT, "127.0.0.1", 70000);
    assert_null(ch);
}

static void test_udp_open_null_addr_for_client(void **state) {
    (void) state;
    udp_channel *ch = udp_open(UDP_CLIENT, NULL, 9930);
    assert_null(ch);
}

static void test_udp_read_null_channel(void **state) {
    (void) state;
    char buf[10];
    int ret = udp_read(NULL, buf, sizeof(buf));
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_udp_read_null_buf(void **state) {
    (void) state;
    int ret = udp_read(NULL, NULL, 10);
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_udp_write_null_channel(void **state) {
    (void) state;
    char buf[10] = "test";
    int ret = udp_write(NULL, buf, sizeof(buf));
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

static void test_udp_write_null_buf(void **state) {
    (void) state;
    int ret = udp_write(NULL, NULL, 10);
    assert_int_equal(ret, SIMPLE_CONNECTION_ERROR_INVALID_ARGUMENT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_udp_open_invalid_port),
        cmocka_unit_test(test_udp_open_invalid_port_high),
        cmocka_unit_test(test_udp_open_null_addr_for_client),
        cmocka_unit_test(test_udp_read_null_channel),
        cmocka_unit_test(test_udp_read_null_buf),
        cmocka_unit_test(test_udp_write_null_channel),
        cmocka_unit_test(test_udp_write_null_buf),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
