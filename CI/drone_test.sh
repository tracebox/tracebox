#!/bin/sh
sh "$(dirname "$0")/prepare_common.sh"
echo 2 | sudo update-alternatives --config gcc

./bootstrap.sh
./configure --enable-deb --enable-sniffer --enable-curl

make -j3 distcheck
make -j3 debian-package

mv ../*.deb .
