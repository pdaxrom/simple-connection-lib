AM_CFLAGS = $(SIMPLE_CONNECTION_CFLAGS)
LIBS = $(SIMPLE_CONNECTION_LIBS)

lib_LTLIBRARIES = libsimple_connection.la 
libsimple_connection_la_SOURCES = tcp.c tcp.h udp.c udp.h

libsimple_connectionincludedir = $(includedir)/simple-connection
libsimple_connectioninclude_HEADERS = $(top_srcdir)/src/tcp.h $(top_srcdir)/src/udp.h
