bin_PROGRAMS = tracebox

dist_man_MANS = tracebox.1

dist_bin_SCRIPTS = luatracebox

SUBDIRS = examples

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
	$(abs_top_builddir)/noinst/libcrafter/libcrafter/libcrafter.la \
	$(LUA_LIB)
tracebox_CPPFLAGS = \
	-I$(top_srcdir)/noinst/libcrafter/libcrafter \
	$(LUA_INCLUDE)
