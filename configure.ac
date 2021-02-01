AC_INIT(libsimple_connection, 1.0)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL

AC_PATH_PROG([PKG_CONFIG], [pkg-config])
found=false
if test x"$PKG_CONFIG" != x""; then
    OPENSSL_LDFLAGS=`$PKG_CONFIG openssl --libs-only-L 2>/dev/null`
    if test $? = 0; then
        OPENSSL_LIBS=`$PKG_CONFIG openssl --libs-only-l 2>/dev/null`
        OPENSSL_INCLUDES=`$PKG_CONFIG openssl --cflags-only-I 2>/dev/null`
        found=true
        echo "openssl includes $OPENSSL_INCLUDES"
        echo "openssl ldflags  $OPENSSL_LDFLAGS"
        echo "openssl libs     $OPENSSL_LIBS"
    fi
fi

AC_SUBST(LIBTOOL_DEPS)
AC_SUBST([OPENSSL_INCLUDES])
AC_SUBST([OPENSSL_LIBS])
AC_LTDL_DLLIB
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([test/Makefile])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
