#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Samana Check WinRM], [1.3.0], [info@samanagroup.com])

AC_ARG_WITH(nagios-plugins,AC_HELP_STRING([--with-nagios-plugins=<path to nagios plugin source>],[sets the path to find nagios-plugins libraries]),np_path=$withval,[AC_MSG_ERROR(nagios-plugin path is mandatory)])
AC_SUBST(np_path)

AC_CONFIG_SRCDIR([src/check_wr_cpu.c])
AC_CONFIG_HEADERS([config.h])

m4_include([autoconf-macros/ax_nagios_get_os])
m4_include([autoconf-macros/ax_nagios_get_distrib])

AC_PREFIX_DEFAULT(/usr/local/nagios)
AC_CONFIG_MACRO_DIR(./autoconf-macros)
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC


# Checks for libraries.
AC_CHECK_LIB([crypto], [BIO_new],,[AC_MSG_ERROR(libcrypto is required for this packages)])
AC_CHECK_LIB([curl], [curl_easy_init],,[AC_MSG_ERROR(libcurl is required for this packages)])
AC_CHECK_LIB([gssapi_krb5], [gss_import_name],,[AC_MSG_ERROR(libgssapi_krb5 is required for this packages)])
AC_CHECK_LIB([uuid], [uuid_unparse_upper],,[AC_MSG_ERROR(libuuid is required for this packages)])
AC_CHECK_LIB([xml2], [xmlNewDoc],,[AC_MSG_ERROR(libxml2 is required for this packages)])

AC_CHECK_FILE([[$np_path]/plugins/libnpcommon.a],,[AC_MSG_ERROR(Need to provide location for nagios-plugin source code.)])
AC_CHECK_FILE([[$np_path]/lib/libnagiosplug.a],,[AC_MSG_ERROR(Need to provide location for nagios-plugin source code.)])
AC_CHECK_FILE([[$np_path]/gl/libgnu.a],,[AC_MSG_ERROR(Need to provide location for nagios-plugin source code.)])

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

AC_ARG_WITH(nagios_user,AC_HELP_STRING([--with-nagios-user=<user>],[sets user name to run nagios]),nagios_user=$withval,nagios_user=nagios)
AC_ARG_WITH(nagios_group,AC_HELP_STRING([--with-nagios-group=<grp>],[sets group name to run nagios]),nagios_grp=$withval,nagios_grp=nagios)


AC_SUBST(nagios_user)
AC_SUBST(nagios_grp)
AC_DEFINE_UNQUOTED(DEFAULT_NAGIOS_USER,"$nagios_user",[user name to run nagios])
AC_DEFINE_UNQUOTED(DEFAULT_NAGIOS_GROUP,"$nagios_grp",[group name to run nagios])
INSTALL_OPTS="-o $nagios_user -g $nagios_grp"
AC_SUBST(INSTALL_OPTS)


AC_NAGIOS_GET_OS
AC_NAGIOS_GET_DISTRIB_TYPE

VERSION=$PACKAGE_VERSION
AC_SUBST(VERSION)

AC_CONFIG_FILES([
    Makefile
    etc/Makefile
    scripts/Makefile
    src/Makefile
    src/lib/Makefile])
AC_OUTPUT
