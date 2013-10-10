ACLOCAL_AMFLAGS = -I m4

if ENABLE_TESTS
MAYBE_OPT = tests
endif

SUBDIRS = noinst src $(MAYBE_OPT)
DIST_SUBDIRS = noinst src tests

debian-package:
	dpkg-buildpackage -rfakeroot -tc -us -uc
