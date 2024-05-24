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

#ifndef ARCH_ARM64
#define feature_name		armv5
#define static_test_armv5	(ARM_VERSION >= 5)
#define dynamic_test		(arm_arch >= 5)
#include "asm-1.inc"
#endif

#ifndef ARCH_ARM64
#define feature_name		armv6
#define static_test_armv6	(ARM_VERSION >= 6)
#define dynamic_test		(arm_arch >= 6)
#include "asm-1.inc"
#endif

#ifndef ARCH_ARM64
#define feature_name		armv6t2
#define static_test_armv6t2	(ARM_VERSION >= 7 || (ARM_VERSION >= 6 && (__ARM_ARCH_ISA_THUMB) && __ARM_ARCH_ISA_THUMB >= 2) || (__ARM_ARCH_6T2__))
#if static_test_armv6t2
#define dynamic_test		(arm_arch >= 6)
#else
#define dynamic_test		(arm_arch >= 7)
#endif
#include "asm-1.inc"
#endif

#ifndef ARCH_ARM64
#define feature_name		vfp
#define static_test_vfp		(__ARM_PCS_VFP)
#define dynamic_test		(elf_hwcap & (1 << 6))
#include "asm-1.inc"
#endif

#ifndef ARCH_ARM64
#define feature_name		half
#define static_test_half	(__ARM_FP & 2)
#if static_test_half
#define dynamic_test		(elf_hwcap & ((1 << 13) | (1 << 14) | (1 << 16)))
#else
#define dynamic_test		(elf_hwcap & (1 << 16))
#endif
#include "asm-1.inc"
#endif

#define feature_name		neon
#define static_test_neon	(__ARM_NEON)
#ifdef ARCH_ARM64
#define dynamic_test		(elf_hwcap & (1 << 1))
#else
#define dynamic_test		(elf_hwcap & (1 << 12))
#endif
#include "asm-1.inc"

#ifndef ARCH_ARM64
#define feature_name		idiv
#define static_test_idiv	0
#define dynamic_test		(elf_hwcap & (1 << 18) && elf_hwcap & (1 << 17))
#include "asm-1.inc"
#endif
