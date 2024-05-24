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

set -ex
ALL=false
if test "$1" = all; then
	ALL=true
	shift
fi
rm -rf ~/.cache/ajla/ /tmp/ajla/
if $ALL; then
	./ajla "$@" scripts/charset/gen_charset8.ajla &
	./ajla --privileged "$@" scripts/consts.ajla &
	wait
	g++ -O2 -Wall -Wextra scripts/charset/widechar_width.c -o scripts/charset/widechar_width
	scripts/charset/widechar_width >newlib/uni_table.ajla
	rm scripts/charset/widechar_width
	rm -rf newcomp
	mkdir newcomp
	cp -a newlib/compiler newlib/pcode.ajla newlib/ex_codes.ajla newcomp
	./ajla --privileged "$@" selfopt-all.ajla
	rm -rf newcomp
else
	./ajla --privileged "$@" selfopt.ajla
fi
rm -rf stdlib
cp -r newlib stdlib
chmod 644 builtin.pcd
if which gmake >/dev/null 2>/dev/null; then
	MAK=gmake
else
	MAK=make
fi
"$MAK"
