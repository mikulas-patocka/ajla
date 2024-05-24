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
rm -rf ajla
cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libffi-6.dll .
cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libgcc_s_seh-1.dll .
cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libgmp-10.dll .
cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libquadmath-0.dll .
cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libwinpthread-1.dll .
CC=x86_64-w64-mingw32-gcc ./rebuild
VERSION="`sed -n 's/^.*"\(.*\)"$/\1/p' <version.h`"
mkdir ajla
cp -r ajla.exe libffi-6.dll libgcc_s_seh-1.dll libgmp-10.dll libquadmath-0.dll libwinpthread-1.dll builtin.pcd AUTHORS COPYING ChangeLog README charsets stdlib ajla
mkdir ajla/programs
cp -r programs/acmd ajla/programs
rm -f ajla-$VERSION-win64.zip
zip -r ajla-$VERSION-win64.zip ajla
rm -rf ajla
