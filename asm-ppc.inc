/*
 * Copyright (C) 2024 Mikulas Patocka
 *
 * This file is part of Ajla.
 *
 * Ajla is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * Ajla is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Ajla. If not, see <https://www.gnu.org/licenses/>.
 */

#define feature_name		p2
#define static_test_p2		_ARCH_PWR4
#define dynamic_test		trap_insn("fc00002c") /* fsqrt */
#include "asm-1.inc"

#define feature_name		ppc
#define static_test_ppc		_ARCH_PWR4
#define dynamic_test		trap_insn("380000017c0003d6") /* divw */
#include "asm-1.inc"

#define feature_name		v203
#define static_test_v203	0
#define dynamic_test		trap_insn("7c00001e")	/* isellt */
#include "asm-1.inc"

#define feature_name		v206
#define static_test_v206	_ARCH_PWR7
#define dynamic_test		trap_insn("7c0002f4")	/* popcntw */
#include "asm-1.inc"

#define feature_name		v30
#define static_test_v30		_ARCH_PWR9
#define dynamic_test		trap_insn("7c000434")	/* cnttzw */
#include "asm-1.inc"
