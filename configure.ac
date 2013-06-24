AC_INIT([tracebox], [0.1], [gregory.detal@uclouvain.be])

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


# Make sure libcrafter build a static library by adding the --disable-shared
# argument to the configure script.
ac_configure_args_pre="$ac_configure_args"
ac_configure_args_post="$ac_configure_args --disable-shared"
ac_configure_args="$ac_configure_args_post"

AC_CONFIG_COMMANDS_PRE([ac_configure_args="$ac_configure_args_pre"])
AC_CONFIG_COMMANDS_POST([ac_configure_args="$ac_configure_args_post"])
AC_CONFIG_SUBDIRS(src/libcrafter/libcrafter)

AC_SUBST(LUA_INCLUDE)
AC_SUBST(LUA_LIB)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/tracebox/Makefile
])
AC_OUTPUT
