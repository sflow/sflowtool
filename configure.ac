#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([sflowtool],[6.07])
AC_CONFIG_SRCDIR([src/sflowtool.c])
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_CONFIG_HEADERS(config.h)

# Checks for libraries.

AC_CANONICAL_HOST
case "$host" in
*-*-solaris*)
	LDFLAGS="$LDFLAGS -lsocket -lnsl" 
	;;
esac

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h byteswap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_CHECK_HEADERS_ONCE([sys/time.h])

# Checks for library functions.
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getaddrinfo memset select socket strdup strerror strspn strtol])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
