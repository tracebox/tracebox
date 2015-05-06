#!/bin/sh
sudo apt-get update -qq
sudo apt-get install -qq automake libtool lua5.1 liblua5.1-dev liblua5.1 liblua5.1-0-dbg libpcap-dev g++ autoconf gdb libnetfilter-queue-dev libjson0-dev libcurl4-gnutls-dev luarocks

sudo luarocks install penlight

git clone https://github.com/stevedonovan/LDoc.git
sudo make -C LDoc install
