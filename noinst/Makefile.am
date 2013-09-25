DIST_SUBDIRS = libcrafter/libcrafter

all-local:
	cd libcrafter/libcrafter && $(MAKE) $(AM_MAKEFLAGS) all

clean-local:
	@if [ -e libcrafter/libcrafter/Makefile ]; then \
		cd libcrafter/libcrafter && $(MAKE) $(AM_MAKEFLAGS) clean; \
	fi

