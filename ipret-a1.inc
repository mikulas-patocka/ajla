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

#define OPC(op)		(OPCODE_FIXED_OP + cat(OPCODE_FIXED_OP_,op) * OPCODE_FIXED_OP_MULT + cat(OPCODE_FIXED_TYPE_,type) * OPCODE_FIXED_TYPE_MULT)

#define orig_op		divide
#define op		divide_alt1
#define OPF		FIXED_DIVIDE_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		udivide
#define op		udivide_alt1
#define OPF		FIXED_UDIVIDE_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		modulo
#define op		modulo_alt1
#define OPF		FIXED_MODULO_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		umodulo
#define op		umodulo_alt1
#define OPF		FIXED_UMODULO_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		bswap
#define op		bswap_alt1
#define OPF		FIXED_BSWAP_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		brev
#define op		brev_alt1
#define OPF		FIXED_BREV_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		bsf
#define op		bsf_alt1
#define OPF		FIXED_BSF_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		bsr
#define op		bsr_alt1
#define OPF		FIXED_BSR_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#define orig_op		popcnt
#define op		popcnt_alt1
#define OPF		FIXED_POPCNT_ALT1_
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, op)
#include "ipret-b1.inc"

#undef OPC
