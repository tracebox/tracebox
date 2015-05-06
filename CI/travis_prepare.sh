#!/bin/sh
sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sh "$(dirname "$0")/prepare_common.sh"

sudo apt-get install gcc-4.8 g++-4.8
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 90

sh bootstrap.sh
./configure $@
