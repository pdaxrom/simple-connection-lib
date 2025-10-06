if ENABLE_TESTS
TESTS = test_tcp test_udp test_utils test_integration
check_PROGRAMS = test_tcp test_udp test_utils test_integration

test_tcp_SOURCES = test_tcp.c
test_tcp_CFLAGS = $(CMOCKA_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/src
test_tcp_LDADD = $(CMOCKA_LIBS) $(top_builddir)/src/libsimple_connection.la

test_udp_CFLAGS = $(CMOCKA_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/src
test_udp_LDADD = $(CMOCKA_LIBS) $(top_builddir)/src/libsimple_connection.la

test_utils_CFLAGS = $(CMOCKA_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/src
test_utils_LDADD = $(CMOCKA_LIBS) $(top_builddir)/src/libsimple_connection.la

test_integration_CFLAGS = $(CMOCKA_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/src
test_integration_LDADD = $(CMOCKA_LIBS) $(top_builddir)/src/libsimple_connection.la
endif