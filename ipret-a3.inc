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

#define OPC(op)         (OPCODE_REAL_OP + cat(OPCODE_REAL_OP_,op) * OPCODE_REAL_OP_MULT + cat(OPCODE_REAL_TYPE_,type) * OPCODE_REAL_TYPE_MULT)

#if cat3(REAL,TYPE_BITS,_ALT1_TYPES) & TYPE_MASK

#define orig_op		add
#define op		add_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		add
#define op		add_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		subtract
#define op		subtract_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		subtract
#define op		subtract_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		multiply
#define op		multiply_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		multiply
#define op		multiply_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		divide
#define op		divide_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		divide
#define op		divide_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		equal
#define op		equal_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		equal
#define op		equal_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		not_equal
#define op		not_equal_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		not_equal
#define op		not_equal_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		less
#define op		less_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		less
#define op		less_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		less_equal
#define op		less_equal_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		less_equal
#define op		less_equal_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		greater
#define op		greater_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		greater
#define op		greater_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		greater_equal
#define op		greater_equal_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		greater_equal
#define op		greater_equal_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#if TYPE_MASK != 1
#define orig_op		neg
#define op		neg_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		neg
#define op		neg_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		sqrt
#define op		sqrt_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		sqrt
#define op		sqrt_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"
#endif

#define orig_op		to_int
#define op		to_int_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_REAL_TO_INT(type, op)
#include "ipret-b1.inc"

#if TYPE_MASK != 1
#define orig_op		to_int
#define op		to_int_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_REAL_TO_INT(type, op)
#include "ipret-b1.inc"
#endif

#define orig_op		from_int
#define op		from_int_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_REAL_FROM_INT(type, op)
#include "ipret-b1.inc"

#if TYPE_MASK != 1
#define orig_op		from_int
#define op		from_int_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_REAL_FROM_INT(type, op)
#include "ipret-b1.inc"
#endif

#if TYPE_MASK != 1
#define orig_op		is_exception
#define op		is_exception_alt1
#define OPF		cat4(REAL,TYPE_BITS,_,ALT1_)
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"

#define orig_op		is_exception
#define op		is_exception_alt2
#define OPF		cat4(REAL,TYPE_BITS,_,ALT2_)
#define DEF(type)	DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, op)
#include "ipret-b1.inc"
#endif

#endif

#undef OPC
