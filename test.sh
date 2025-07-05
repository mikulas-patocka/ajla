#!/bin/sh -ex
#
# Copyright (C) 2024, 2025 Mikulas Patocka
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

targets=" 				\
	aarch64-linux-gnu		\
	alpha-linux-gnu			\
	arm-linux-gnueabi		\
	arm-linux-gnueabihf		\
	hppa-linux-gnu			\
	loongarch64-linux-gnu		\
	m68k-linux-gnu			\
	mips-linux-gnu			\
	mips64-linux-gnuabi64		\
	mips64el-linux-gnuabi64		\
	mipsel-linux-gnu		\
	mipsisa32r6-linux-gnu		\
	mipsisa32r6el-linux-gnu		\
	mipsisa64r6-linux-gnuabi64	\
	mipsisa64r6el-linux-gnuabi64	\
	powerpc-linux-gnu		\
	powerpc64-linux-gnu		\
	powerpc64le-linux-gnu		\
	riscv64-linux-gnu		\
	s390x-linux-gnu			\
	sh4-linux-gnu			\
	sparc64-linux-gnu		\
	x86_64-linux-gnu		\
"
if [ "$#" -gt 0 ]; then
	targets="$@"
fi
AJLA="`pwd`/ajla"
export AJLA
for a in $targets; do
	if ! which $a-gcc; then
		echo $a-gcc not found
		continue
	fi
	PFX=""
	MLIB=""
	case "$a" in
		mips-linux-gnu)			MLIB="-mabi=n32";;
		mipsel-linux-gnu)		MLIB="-mabi=n32";;
		mipsisa32r6-linux-gnu)		PFX="qemu-mips -L /usr/mipsisa32r6-linux-gnu/";;
		mipsisa32r6el-linux-gnu)	PFX="qemu-mipsel -L /usr/mipsisa32r6el-linux-gnu/";;
		mipsisa64r6-linux-gnuabi64)	PFX="qemu-mips64 -L /usr/mipsisa64r6-linux-gnuabi64/";;
		mipsisa64r6el-linux-gnuabi64)	PFX="qemu-mips64el -L /usr/mipsisa64r6el-linux-gnuabi64/";;
		x86_64-linux-gnu)		MLIB="-m32 -mx32";;
	esac
	export PFX
	for m in '' $MLIB; do
		for b in '' --enable-bitwise-frame; do
			CC="$a-gcc $m" CF='-O1 -DDEBUG_ENV' ./rebuild --disable-rwx-mappings --enable-debuglevel=2 --host=$a $b
			do_ptrcomp=true
			case "$a" in
				arm-linux-gnueabi |\
				arm-linux-gnueabihf |\
				hppa-linux-gnu |\
				m68k-linux-gnu |\
				mips-linux-gnu |\
				mipsel-linux-gnu |\
				mipsisa32r6-linux-gnu |\
				mipsisa32r6el-linux-gnu |\
				powerpc-linux-gnu)	do_ptrcomp=false;;
				x86_64-linux-gnu)	if [ "$m" = -m32 -o "$m" = -mx32 ]; then do_ptrcomp=false; fi;;
			esac
			$PFX ./ajla $ARG programs/test/empty.ajla
			$PFX ./ajla $ARG programs/test/test.ajla 2
			$PFX ./ajla $ARG programs/test/test.ajla 100
			$PFX ./ajla $ARG programs/test/test-fp.ajla 2
			$PFX ./ajla $ARG programs/test/test-fp.ajla 50
			if [ -f ~/ajla/advent-2023/test.sh ]; then (cd ~/ajla/advent-2023/; ./test.sh $ARG); fi
			if [ -f ~/ajla/advent-2024/test.sh ]; then (cd ~/ajla/advent-2024/; ./test.sh $ARG); fi
			if $do_ptrcomp; then
				$PFX ./ajla $ARG --ptrcomp programs/test/empty.ajla
				$PFX ./ajla $ARG --ptrcomp programs/test/test.ajla 2
				$PFX ./ajla $ARG --ptrcomp programs/test/test.ajla 100
				$PFX ./ajla $ARG --ptrcomp programs/test/test-fp.ajla 2
				$PFX ./ajla $ARG --ptrcomp programs/test/test-fp.ajla 50
				if [ -f ~/ajla/advent-2023/test.sh ]; then (cd ~/ajla/advent-2023/; ./test.sh $ARG --ptrcomp); fi
				if [ -f ~/ajla/advent-2024/test.sh ]; then (cd ~/ajla/advent-2024/; ./test.sh $ARG --ptrcomp); fi
			fi
		done
	done
done
