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

#define feature_name		c
#define static_test_c		(__riscv_c)
#define dynamic_test		(riscv_hwp[0].key >= 0 ? riscv_hwp[0].value & (1ULL << 1) : trap_insn("01000100"))
#include "asm-1.inc"

#define feature_name		zba
#define static_test_zba		(__riscv_zba)
#define dynamic_test		(riscv_hwp[0].key >= 0 ? riscv_hwp[0].value & (1ULL << 3) : trap_insn("33200020"))
#include "asm-1.inc"

#define feature_name		zbb
#define static_test_zbb		(__riscv_zbb)
#define dynamic_test		(riscv_hwp[0].key >= 0 ? riscv_hwp[0].value & (1ULL << 4) : trap_insn("13100060"))
#include "asm-1.inc"

#define feature_name		zbs
#define static_test_zbs		(__riscv_zbs)
#define dynamic_test		(riscv_hwp[0].key >= 0 ? riscv_hwp[0].value & (1ULL << 5) : trap_insn("33100048"))
#include "asm-1.inc"

#define feature_name		unaligned
#define static_test_unaligned	0
#define dynamic_test		(riscv_hwp[1].key >= 0 && (riscv_hwp[1].value & 7) == 3)
#include "asm-1.inc"

/* riscv_zicond = trap_insn("3350000e"); */
