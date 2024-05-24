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

#define feature_name			z
#define static_test_z			__zarch__
#define dynamic_test			test_facility(2)
#include "asm-1.inc"

#define feature_name			long_displacement
#define static_test_long_displacement	(__ARCH__ >= 6)
#define dynamic_test			test_facility(18)
#include "asm-1.inc"

#define feature_name			extended_imm
#define static_test_extended_imm	(__ARCH__ >= 7)
#define dynamic_test			test_facility(21)
#include "asm-1.inc"

#define feature_name			misc_45
#define static_test_misc_45		(__ARCH__ >= 9)
#define dynamic_test			test_facility(45)
#include "asm-1.inc"

#define feature_name			misc_insn_ext_2
#define static_test_misc_insn_ext_2	(__ARCH__ >= 12)
#define dynamic_test			test_facility(58)
#include "asm-1.inc"

#define feature_name			misc_insn_ext_3
#define static_test_misc_insn_ext_3	(__ARCH__ >= 13)
#define dynamic_test			test_facility(61)
#include "asm-1.inc"
