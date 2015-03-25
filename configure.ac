AC_INIT([tracebox], [0.3], [olivier.tilmans@uclouvain.be],
		[tracebox], [http://tracebox.org])

AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Werror -Wall no-define foreign])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT

AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_HEADER_STDC
AC_HEADER_ASSERT

AX_PROG_LUA
AX_LUA_HEADERS
AX_LUA_LIBS
if test x"$LUA_LIB" = x; then
    AC_MSG_ERROR([Lua library not found. You may try option --with-lua-suffix.])
fi

AC_ARG_ENABLE(tests, AS_HELP_STRING([--enable-tests], [Enable tests]))
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" == "xyes"])

AC_ARG_ENABLE(deb, AC_HELP_STRING([--enable-deb], [build deb and debsrc packages (no)]))
AM_CONDITIONAL([ENABLE_DEB], [test "x$enable_deb" == "xyes"])

AS_IF([test "x$enable_deb" = "xyes"], [
	AC_PATH_PROG([DPKG_BUILDPACKAGE], [dpkg-buildpackage], [no])
	AS_IF([test "X$DPKG_BUILDPACKAGE" = "xno"], [
		AC_MSG_ERROR(Cannot find dpkg-buildpackage. Install dpkg-dev.)
	])
])

# Make sure libcrafter build a static library by adding the --disable-shared
# argument to the configure script.
ac_configure_args_pre="$ac_configure_args"
ac_configure_args_post="$ac_configure_args --disable-shared"
ac_configure_args="$ac_configure_args_post"

AC_CONFIG_COMMANDS_PRE([ac_configure_args="$ac_configure_args_pre"])
AC_CONFIG_COMMANDS_POST([ac_configure_args="$ac_configure_args_post"])
AC_CONFIG_SUBDIRS(noinst/libcrafter/libcrafter)

# Enable click submodule
AS_IF([test "x$enable_tests" = "xyes"], [
	ac_configure_args_pre="$ac_configure_args"
	ac_configure_args_post="$ac_configure_args --disable-shared --enable-local --disable-linuxmodule --disable-netisr"
	ac_configure_args="$ac_configure_args_post"

	AC_CONFIG_COMMANDS_PRE([ac_configure_args="$ac_configure_args_pre"])
	AC_CONFIG_COMMANDS_POST([ac_configure_args="$ac_configure_args_post"])
	AC_CONFIG_SUBDIRS(tests/tools/click)

])

AC_SUBST(LUA_INCLUDE)
AC_SUBST(LUA_LIB)

AC_ARG_ENABLE([sniffer], AS_HELP_STRING([--enable-sniffer], [Build the sniffer component]))
AM_CONDITIONAL([ENABLE_SNIFFER], [test "x$enable_sniffer" = "xyes"])

AS_IF([test "x$enable_sniffer" = "xyes"], [
	_NFQ=""
	AC_CHECK_LIB([netfilter_queue], [nfq_open], , _NFQ="no")
	AS_IF([test "$_NFQ" = "no"], [
		   AC_MSG_ERROR(Cannot find libnetfilter_queue)
	   	])
	AC_DEFINE([HAVE_SNIFFER], [1], [The Sniffer module is enabled.])
])


AC_CONFIG_FILES([
	Makefile
	noinst/Makefile
	src/Makefile
	src/tracebox/Makefile
	tests/Makefile
	tests/tools/Makefile
	src/tracebox/examples/Makefile
])
AC_OUTPUT
