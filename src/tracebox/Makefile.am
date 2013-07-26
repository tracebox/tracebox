bin_PROGRAMS = tracebox

dist_man_MANS = tracebox.1

bin_SCRIPTS = luatracebox

tracebox_SOURCES = \
	tracebox.cc \
	lua.cc \
	PartialHeader.cc \
	PacketModification.cc
noinst_HEADERS = \
	script.h \
	PartialHeader.h \
	PacketModification.h \
	tracebox.h

tracebox_LDADD = \
	$(abs_top_builddir)/src/libcrafter/libcrafter/libcrafter.la \
	$(LUA_LIB)
tracebox_CPPFLAGS = \
	-I$(top_srcdir)/src/libcrafter/libcrafter \
	$(LUA_INCLUDE)
