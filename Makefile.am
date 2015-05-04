ACLOCAL_AMFLAGS = -I m4

if ENABLE_TESTS
MAYBE_OPT = tests
endif

if HAVE_LDOC
MAYBE_DOC = doc
endif

SUBDIRS = noinst src $(MAYBE_OPT) $(MAYBE_DOC)
DIST_SUBDIRS = noinst src tests doc

debian-package:
	dpkg-buildpackage -rfakeroot -tc -us -uc

force-update-doc:
	cd doc && $(MAKE) $(AM_MAKEFLAGS) force-update-doc

.PHONY: force-update-doc
