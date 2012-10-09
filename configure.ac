#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([ossfs], [0.1], [samsong8610@gmail.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([src/http.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
#AC_CHECK_LIB([glib-2.0], [g_hash_table_new], [GLIB=-lglib-2.0])
#AC_SUBST([GLIB])
PKG_CHECK_MODULES([DEPS], [fuse >= 2.8.4 libcurl >= 4 glib-2.0 >= 2.24 libxml-2.0 >= 2.7.8])

# Checks for header files.
AC_CHECK_HEADERS([glib.h curl/curl.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT
