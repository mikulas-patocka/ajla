#!/bin/sh
#
# Copyright (C) 2024 Mikulas Patocka
#
# This file is part of Ajla.
#
# Ajla is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# Ajla is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Ajla. If not, see <https://www.gnu.org/licenses/>.

set -e
export CC=gcc.exe
export CPP=cpp.exe
export CFLAGS='-O1 -Zsys -Zomf -Zstack 1024 -Wall -W'
export PATH_SEPARATOR=';'
./configure --disable-dependency-tracking
sleep 2
touch config.status
sleep 2
touch Makefile config.h
sleep 2
make -j12
VERSION="`sed -n 's/^.*"\(.*\)"$/\1/p' <version.h`"
rm -rf ajla
mkdir ajla
cat ajla.exe >ajla/ajla.exe
cp -r builtin.pcd AUTHORS COPYING ChangeLog README charsets stdlib ajla
mkdir ajla/programs
cp -r programs/acmd ajla/programs
rm -f ajla-$VERSION-os2.zip
zip -r ajla-$VERSION-os2.zip ajla
rm -rf ajla
