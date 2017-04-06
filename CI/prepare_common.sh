#!/bin/sh
sudo apt-get -qq -y --force-yes update
sudo apt-get -qq -y --force-yes install automake libtool lua5.1 liblua5.1-dev liblua5.1 liblua5.1-0-dbg libpcap-dev g++ autoconf gdb libnetfilter-queue-dev libjson0-dev libcurl4-gnutls-dev luarocks lua-sec

sudo luarocks install penlight

git clone https://github.com/stevedonovan/LDoc.git
sudo make -C LDoc install
