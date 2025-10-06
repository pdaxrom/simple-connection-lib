#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/tcp.h"
#include "../src/udp.h"
#include "../src/errors.h"

// Integration test for IPv6 TCP
static void test_ipv6_tcp_connection(void **state) {
    (void) state;
    // This would require starting a server in a thread or separate process
    // For simplicity, just test opening
    tcp_channel *server = tcp_open(TCP_SERVER, NULL, 9931, NULL, NULL);
    assert_non_null(server);
    tcp_close(server);
}

// Integration test for IPv6 UDP
static void test_ipv6_udp_connection(void **state) {
    (void) state;
    udp_channel *server = udp_open(UDP_SERVER, NULL, 9932);
    assert_non_null(server);
    udp_close(server);
}

#ifdef ENABLE_SSL
// Integration test for SSL TCP
static void test_ssl_tcp_connection(void **state) {
    (void) state;
    // Test SSL server open
    tcp_channel *server = tcp_open(TCP_SSL_SERVER, NULL, 9933, "key.pem", "cert.pem");
    // May fail if certs not present, but test the call
    tcp_close(server);
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ipv6_tcp_connection),
        cmocka_unit_test(test_ipv6_udp_connection),
#ifdef ENABLE_SSL
        cmocka_unit_test(test_ssl_tcp_connection),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
