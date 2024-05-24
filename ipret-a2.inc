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

#define OPC(op)		(OPCODE_INT_OP + cat(OPCODE_INT_OP_,op) * OPCODE_INT_OP_MULT + cat(OPCODE_INT_TYPE_,type) * OPCODE_INT_TYPE_MULT)

#define orig_op		divide
#define op		divide_alt1
#define OPF		INT_DIVIDE_ALT1_
#define DEF(type)	DEFINE_INT_BINARY_OPCODE(type, op)
#include "ipret-b1.inc"

#define orig_op		modulo
#define op		modulo_alt1
#define OPF		INT_MODULO_ALT1_
#define DEF(type)	DEFINE_INT_BINARY_OPCODE(type, op)
#include "ipret-b1.inc"

#define orig_op		popcnt
#define op		popcnt_alt1
#define OPF		INT_POPCNT_ALT1_
#define DEF(type)	DEFINE_INT_UNARY_OPCODE(type, op)
#include "ipret-b1.inc"

#undef OPC
