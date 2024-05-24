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

#define feature_name		bwx
#define static_test_bwx		(__alpha_bwx__)
#define dynamic_test		(amask & (1U << 0))
#include "asm-1.inc"

#define feature_name		fix
#define static_test_fix		(__alpha_fix__)
#define dynamic_test		(amask & (1U << 1))
#include "asm-1.inc"

#define feature_name		cix
#define static_test_cix		(__alpha_cix__)
#define dynamic_test		(amask & (1U << 2))
#include "asm-1.inc"

#define feature_name		precise_trap
#define static_test_precise_trap 0
#define dynamic_test		(amask & (1U << 9))
#include "asm-1.inc"
