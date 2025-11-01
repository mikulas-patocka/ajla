/*
 * Copyright (C) 2024, 2025 Mikulas Patocka
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

#define feature_name		neon
#define static_test_neon	(__ARM_NEON)
#define dynamic_test		(elf_hwcap & (1 << 1))
#include "asm-1.inc"

#define feature_name		fphp
#define static_test_fphp	(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC)
#define dynamic_test		(elf_hwcap & (1 << 9))
#include "asm-1.inc"
