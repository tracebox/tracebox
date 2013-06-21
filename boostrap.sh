#!/bin/sh

if [ ! -d "m4" ]; then 
		mkdir m4
fi

autoreconf --install || exit 1

./configure $@
