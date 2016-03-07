#!/bin/sh
sh "$(dirname "$0")/prepare_common.sh"

sh bootstrap.sh
./configure $@
