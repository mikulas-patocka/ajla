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

#ifndef START_BLOCK
#define START_BLOCK(declarations)
#endif
#ifndef END_BLOCK
#define END_BLOCK()
#endif
#ifndef DEFINE_LABEL
#define DEFINE_LABEL(lbl, code)
#endif
#ifndef DEFINE_OPCODE_START_LBL
#define DEFINE_OPCODE_START_LBL(opcode, lbl)
#endif
#ifndef DEFINE_OPCODE_END
#define DEFINE_OPCODE_END(opcode)
#endif

#ifdef EMIT_CODE
#define DEFINE_OPCODE(opcode, lbl, code)	\
	DEFINE_OPCODE_START_LBL(opcode, lbl)	\
	code					\
	DEFINE_OPCODE_END(opcode)
#else
#define DEFINE_OPCODE(opcode, lbl, code)	\
	DEFINE_OPCODE_START_LBL(opcode, lbl)	\
	DEFINE_OPCODE_END(opcode)
#endif

#define ARG_MODE	0
#define DEFINE_OPCODE_START(opcode)	DEFINE_OPCODE_START_LBL(opcode, opcode##0)
#include "ipret-1.inc"

#ifndef EMIT_ALTTABLE

#if ARG_MODE_N >= 2
#define ARG_MODE	1
#define DEFINE_OPCODE_START(opcode)	DEFINE_OPCODE_START_LBL(opcode, opcode##1)
#include "ipret-1.inc"
#endif

#if ARG_MODE_N >= 3
#define ARG_MODE	2
#define DEFINE_OPCODE_START(opcode)	DEFINE_OPCODE_START_LBL(opcode, opcode##2)
#include "ipret-1.inc"
#endif

#endif

#undef START_BLOCK
#undef END_BLOCK
#undef DEFINE_LABEL
#undef DEFINE_OPCODE_START_LBL
#undef DEFINE_OPCODE_START
#undef DEFINE_OPCODE_END
#undef DEFINE_OPCODE

#ifdef EMIT_FUNCTIONS
#undef EMIT_FUNCTIONS
#endif
#ifdef EMIT_ALTTABLE
#undef EMIT_ALTTABLE
#endif
#ifdef EMIT_CODE
#undef EMIT_CODE
#endif
