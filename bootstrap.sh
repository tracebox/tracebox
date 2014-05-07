#!/bin/sh

git submodule init || exit 1
git submodule update || exit 1

AUTOHEADER=true autoreconf --force --install --verbose || exit 1

./configure $@
