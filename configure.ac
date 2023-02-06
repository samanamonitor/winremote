#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([Samana Check WinRM], [1.0], [info@samanagroup.com])
AC_CONFIG_SRCDIR([src/check_wr_cpu.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

AC_ARG_VAR(NP_PATH,Path to nagios-plugin static libraries)

# Checks for libraries.
AC_CHECK_LIB([crypto], [BIO_new],,[AC_MSG_ERROR(libcrypto is required for this packages)])
AC_CHECK_LIB([curl], [curl_easy_init],,[AC_MSG_ERROR(libcurl is required for this packages)])
AC_CHECK_LIB([gssapi_krb5], [gss_import_name],,[AC_MSG_ERROR(libgssapi_krb5 is required for this packages)])
AC_CHECK_LIB([uuid], [uuid_unparse_upper],,[AC_MSG_ERROR(libuuid is required for this packages)])
AC_CHECK_LIB([xml2], [xmlNewDoc],,[AC_MSG_ERROR(libxml2 is required for this packages)])

AC_CHECK_FILE([[$NP_PATH]/plugins/libnpcommon.a],,[AC_MSG_ERROR(Need to provide location for nagios-plugin source code.)])
AC_CHECK_FILE([[$NP_PATH]/lib/libnagiosplug.a],,[AC_MSG_ERROR(Need to provide location for nagios-plugin source code.)])
AC_CHECK_FILE([[$NP_PATH]/gl/libgnu.a],,[AC_MSG_ERROR(Need to provide location for nagios-plugin source code.)])

AC_CHECK_HEADERS([stdint.h unistd.h gssapi/gssapi_ntlmssp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_PROG_RANLIB
# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm clock_gettime gettimeofday memset regcomp setlocale strdup strndup strpbrk strtol strtoul])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/lib/Makefile])
AC_OUTPUT
