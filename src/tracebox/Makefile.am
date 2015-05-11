AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = tracebox

dist_man_MANS = tracebox.1

dist_bin_SCRIPTS = luatracebox

SUBDIRS = examples

tracebox_SOURCES = \
	tracebox.cc \
	lua.cc \
	PartialHeader.cc \
	PacketModification.cc \
	lua/lua_base.cpp \
	lua/lua_crafter.cpp \
	lua/lua_arg.cpp \
	lua/lua_fwfilter.cpp \
	lua/lua_icmp.cpp \
	lua/lua_init.cpp \
	lua/lua_ip.cpp \
	lua/lua_ipoption.cpp \
	lua/lua_ipv6.cpp \
	lua/lua_ipv6segmentroutingheader.cpp \
	lua/lua_packetmodifications.cpp \
	lua/lua_packet.cpp \
	lua/lua_raw.cpp \
	lua/lua_tcp.cpp \
	lua/lua_tcpoption.cpp \
	lua/lua_udp.cpp \
	lua/lua_tracebox.cpp \
	lua/lua_utils.cpp \
	lua/lua_dns.cpp \
	lua/lua_tcptimestamp.cpp \
	lua/lua_tcpedo.cpp \
	lua/lua_tcptfo.cpp

noinst_HEADERS = \
	script.h \
	PartialHeader.h \
	PacketModification.h \
	tracebox.h \
	lua/lua_base.hpp \
	lua/lua_crafter.hpp \
	lua/lua_arg.h \
	lua/lua_fwfilter.h \
	lua/lua_icmp.h \
	lua/lua_ip.h \
	lua/lua_ipoption.hpp \
	lua/lua_ipv6.h \
	lua/lua_ipv6segmentroutingheader.h \
	lua/lua_packet.hpp \
	lua/lua_packetmodifications.h \
	lua/lua_raw.h \
	lua/lua_tcp.h \
	lua/lua_tcpoption.hpp \
	lua/lua_udp.h \
	lua/lua_dns.h \
	lua/lua_tcptimestamp.h \
	lua/lua_tcpedo.h \
	lua/lua_tcptfo.h \
	tracebox.h

if ENABLE_SNIFFER
tracebox_SOURCES += \
	sniffer.cpp \
	lua/lua_sniffer.cpp

noinst_HEADERS += \
	sniffer.h \
	lua/lua_sniffer.h

endif

tracebox_LDADD = \
	$(EXTRALIBS) \
	$(abs_top_builddir)/noinst/libcrafter/libcrafter/libcrafter.la \
	$(LUA_LIB) \
	$(PCAPLIB) \
	$(JSON_LIB)

tracebox_CPPFLAGS = \
	-I$(top_srcdir)/noinst/libcrafter/libcrafter \
	$(LUA_INCLUDE) \
	$(PCAPINC) \
	$(JSON_INCLUDE) \
	-fno-omit-frame-pointer \
	-Wall

if ENABLE_CURL
tracebox_LDADD += \
	$(LIBCURL)

tracebox_CPPFLAGS += \
	$(LIBCURL_CPPFLAGS)

tracebox_SOURCES += curl.cc
endif
