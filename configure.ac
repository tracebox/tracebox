AC_INIT([tracebox], [0.4.3], [olivier.tilmans@uclouvain.be],
		[tracebox], [http://tracebox.org])
AC_CONFIG_SRCDIR([src/tracebox/tracebox.cc])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 tar-pax -Werror -Wall no-define foreign])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_CONFIG_HEADERS([config.h])
LT_INIT

AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_HEADER_STDC
AC_HEADER_ASSERT

AX_CXX_COMPILE_STDCXX_11

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([gettimeofday memset select socket strtol])

AC_ARG_WITH(lua,
[  --with-lua=DIR      use lua in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/lua.h -a -f $withval/liblua.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        LUA_INCLUDE="-I$withval"
        LUA_LIB="-L$withval -llua"
        LIBS="$LIBS -lm"
     elif test -f $withval/include/lua.h -a -f $withval/lib/liblua.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        LUA_INCLUDE="-I$withval/include"
        LUA_LIB="-L$withval/lib -llua"
        LIBS="$LIBS -lm"
     else
        AC_ERROR("lua.h or liblua.a not found in $withval")
     fi
     ;;
  esac ],
    [
        AX_PROG_LUA
        AX_LUA_HEADERS
        AX_LUA_LIBS
        if test x"$LUA_LIB" = x; then
            AC_MSG_ERROR([Lua library not found. You may try option --with-lua-suffix.])
        fi
    ]
)
AC_SUBST(LUA_INCLUDE)
AC_SUBST(LUA_LIB)

AC_ARG_WITH(pcap-filename,
            [  --with-pcap-filename="/default/capture/path"],
            [ default_pcap_filename="$withval" ],
            [ default_pcap_filename="/tmp/capture.pcap" ]
)
AC_DEFINE_UNQUOTED([DEFAULT_PCAP_FILENAME], "$default_pcap_filename",
          [Default filename for the pcap capture file.])

AC_ARG_WITH(upload-url,
            [  --with-upload-url="/default/capture/path"],
            [ default_url="$withval" ],
            [ default_url="http://test1.multipath-tcp.org:18080/curl" ]
)
AC_DEFINE_UNQUOTED([DEFAULT_URL], "$default_url",
          [Default URL used when curl upload is enabled and no other URL is
           specified as argument.])


AC_MSG_CHECKING(lua_pushglobaltable)
save_flags="$CFLAGS"
save_xxflags="$CXXFLAGS"
save_lib="$LIBS"
LIBS="$LUA_LIB $LIBS"
CFLAGS="$LUA_INCLUDE $FLAGS"
CXXFLAGS="$LUA_INCLUDE $CXXFLAGS"
AC_TRY_LINK([#include <lua.h>],
            [lua_pushglobaltable(NULL);],
            [AC_MSG_RESULT(yes)
            AC_DEFINE([HAVE_LUA_PUSHGLOBALTABLE], [1],
                       [Lua version supports lua_pushglobaltable])
            ], [AC_MSG_RESULT(no)])
LIBS="$save_lib"
CFLAGS="$save_flags"
CXXFLAGS="$save_xxflags"

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


AC_ARG_WITH(json,
[  --with-json=DIR      use json-c in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/json.h -a -f $withval/libjson-c.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        JSON_INCLUDE="-I$withval"
        JSON_LIB="-L$withval -ljson-c"
     elif test -f $withval/include/json-c/json.h -a -f $withval/lib/libjson-c.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        JSON_INCLUDE="-I$withval/include"
        JSON_LIB="-L$withval/lib -ljson-c"
     else
        AC_ERROR("json.h or libjson-c.a not found in $withval")
     fi
     AC_SUBST(JSON_INCLUDE)
     AC_SUBST(JSON_LIB)
     AC_DEFINE([HAVE_JSONC], [1], [Using json-c])
     ;;
  esac ],
    [
        AC_SEARCH_LIBS([json_tokener_parse_ex], [json-c json], [], [
            AC_MSG_ERROR(json-c/libjson is not found. RE-run with --with-json=DIR)
            ])
        AC_CHECK_LIB([json-c], [json_tokener_parse_ex], [AC_DEFINE([HAVE_JSONC], [1], [Using json-c])])
        AC_CHECK_LIB([json], [json_tokener_parse_ex], [AC_DEFINE([HAVE_LIBJSON], [1], [Using libjson])])
    ]
)

AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[  --with-libpcap=DIR      use libpcap in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a \
         -f $withval/libpcap.a -a \
         -d $withval/pcap; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        PCAPINC="-I$withval -I$withval/bpf"
        PCAPLIB="-L$withval -lpcap"
     else
        AC_ERROR(pcap.h, net/bpf.h, or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     PCAPLIB="-L${prefix}/lib -lpcap"
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libpcap not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)



AC_MSG_CHECKING(for the inclusion of extra libs)
AC_ARG_WITH(libs,
[  --with-libs=DIR      use these static libs],
[ case "$withval" in
  yes|no)
    AC_MSG_RESULT(no)
    EXTRALIBS=""
    ;;
  *)
    AC_MSG_RESULT($withval)
    EXTRALIBS="$withval"
    ;;
  esac ],
[
    EXTRALIBS=""
    AC_MSG_RESULT(no) ]
)
AC_SUBST(EXTRALIBS)

AC_ARG_ENABLE([curl], AS_HELP_STRING([--enable-curl], [Build the curl component]))
AM_CONDITIONAL([ENABLE_CURL], [test "x$enable_curl" = "xyes"])

AS_IF([test "x$enable_curl" = "xyes"], [
	LIBCURL_CHECK_CONFIG(, 7.10.1, ,
  [AC_MSG_ERROR([Missing required libcurl >= 7.10.1])])
  AC_DEFINE([HAVE_CURL], [1], [Curl library is available.])
])

AC_ARG_ENABLE([sniffer], AS_HELP_STRING([--enable-sniffer], [Build the sniffer component]))
AM_CONDITIONAL([ENABLE_SNIFFER], [test "x$enable_sniffer" = "xyes"])

AS_IF([test "x$enable_sniffer" = "xyes"], [
    _NFQ=""
    AC_CHECK_LIB([netfilter_queue], [nfq_open], , _NFQ="no")
    AS_IF([test "$_NFQ" = "no"], [
           AC_MSG_ERROR(Cannot find libnetfilter_queue)
        ])
    AC_DEFINE([HAVE_SNIFFER], [1], [The Sniffer module is enabled.])
    AC_CHECK_LIB([pthread], [pthread_create])
])

# Make sure libcrafter build a static library by adding the --disable-shared
# argument to the configure script.
ac_configure_args_pre="$ac_configure_args"
ac_configure_args_post="$ac_configure_args --disable-shared"
ac_configure_args="$ac_configure_args_post"

AC_CONFIG_COMMANDS_PRE([ac_configure_args="$ac_configure_args_pre"])
AC_CONFIG_COMMANDS_POST([ac_configure_args="$ac_configure_args_post"])
AC_CONFIG_SUBDIRS(noinst/libcrafter/libcrafter)

ac_configure_args="$ac_configure_args_pre"

# Enable click submodule
AS_IF([test "x$enable_tests" = "xyes"], [
    ac_configure_args_pre="$ac_configure_args"
    ac_configure_args_post="$ac_configure_args --disable-shared --enable-local --disable-linuxmodule --disable-netisr"
    ac_configure_args="$ac_configure_args_post"

    AC_CONFIG_COMMANDS_PRE([ac_configure_args="$ac_configure_args_pre"])
    AC_CONFIG_COMMANDS_POST([ac_configure_args="$ac_configure_args_post"])
    AC_CONFIG_SUBDIRS(tests/tools/click)

    ac_configure_args="$ac_configure_args_pre"
])

AC_CHECK_PROGS([LDOC], [ldoc])
if test -z "$LDOC";
    then AC_MSG_WARN([ldoc not found - not building the Lua bindings documentation])
fi
AM_CONDITIONAL([HAVE_LDOC],[test -n "$LDOC"])

AC_DEFINE_UNQUOTED([_REV_PARSE], 
          ["$(git describe --abbrev=16 --always --tags)"],
          ["Version number: tag-commits-g revision-branch status"])

AC_CONFIG_FILES([
	Makefile
	noinst/Makefile
	src/Makefile
	src/tracebox/Makefile
	tests/Makefile
	tests/tools/Makefile
	src/tracebox/examples/Makefile
    doc/Makefile
])
AC_OUTPUT
