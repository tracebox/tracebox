#!/bin/sh

if [ ! -d "m4" ]; then 
		mkdir m4
fi

git submodule init || exit 1
git submodule update || exit 1

AUTOHEADER=true autoreconf --install || exit 1

./configure $@
