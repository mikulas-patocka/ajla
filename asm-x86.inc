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

#define feature_name		bswap
#define static_test_bswap	((__i486__) || (__i586__) || (__i686__) || (__MMX__) || (__x86_64__))
#define dynamic_test		(eflags_bits & (1 << 18U))
#include "asm-1.inc"

#define feature_name		cmov
#define static_test_cmov	((__i686__) || (__athlon__) || (__SSE__) || (__x86_64__))
#define dynamic_test		(cpuid_1[3] & (1U << 15))
#include "asm-1.inc"

#define feature_name		popcnt
#define static_test_popcnt	(__POPCNT__)
#define dynamic_test		(cpuid_1[2] & (1U << 23))
#include "asm-1.inc"

#define feature_name		lzcnt
#define static_test_lzcnt	(__LZCNT__)
#define dynamic_test		(cpuid_80000001[2] & (1U << 5))
#include "asm-1.inc"

#define feature_name		sse
#define static_test_sse		((__SSE__) || (__x86_64__))
#define dynamic_test		(likely(cpuid_1[3] & (1U << 25)) && likely(test_fxsave()))
#include "asm-1.inc"

#define feature_name		sse2
#define static_test_sse2	((__SSE2__) || (__x86_64__))
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_sse)) && likely(cpuid_1[3] & (1U << 26)))
#include "asm-1.inc"

#define feature_name		sse3
#define static_test_sse3	(__SSE3__)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_sse2)) && likely(cpuid_1[2] & (1U << 0)))
#include "asm-1.inc"

#define feature_name		sse41
#define static_test_sse41	(__SSE4_1__)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_sse2)) && likely(cpuid_1[2] & (1U << 19)))
#include "asm-1.inc"

#define feature_name		avx
#define static_test_avx		(__AVX__)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_sse2)) && likely((cpuid_1[2] & (7U << 26)) == (7U << 26)) && likely(test_xcr0(6)))
#include "asm-1.inc"

#define feature_name		f16c
#define static_test_f16c	(__F16C__)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_avx)) && likely(cpuid_1[2] & (1U << 29)))
#include "asm-1.inc"

#define feature_name		bmi2
#define static_test_bmi2	(__BMI2__)
#define dynamic_test		(cpuid_7[1] & (1U << 8))
#include "asm-1.inc"

#define feature_name		erms
#define static_test_erms	0
#define dynamic_test		(cpuid_7[1] & (1U << 9))
#include "asm-1.inc"

#define feature_name		avx512
#define static_test_avx512	(__AVX512F__)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_avx)) && likely(cpuid_7[1] & (1U << 16)) && likely(test_xcr0(0xe0)))
#include "asm-1.inc"

#define feature_name		avx512vl
#define static_test_avx512vl	(__AVX512VL__)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_avx512)) && likely(cpuid_7[1] & (1U << 31)))
#include "asm-1.inc"

#define feature_name		avx10
#define static_test_avx10	(__AVX10_1__)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_avx)) && likely(cpuid_7_1[3] & (1U << 21)) && likely(test_xcr0(0xa0)))
#include "asm-1.inc"

#define feature_name		fp_regs_32
#define static_test_fp_regs_32	(static_test_avx512vl || static_test_avx10)
#define dynamic_test		(likely(cpu_test_feature(CPU_FEATURE_avx512vl)) || likely(cpu_test_feature(CPU_FEATURE_avx10)))
#include "asm-1.inc"

#define feature_name		apx
#if defined(ARCH_X86_64) && !defined(ARCH_X86_WIN_ABI)
#define static_test_apx		(__APX_F__)
#define dynamic_test		(cpuid_7_1[3] & (1U << 21) && likely(test_xcr0(1U << 19)))
#else
#define static_test_apx		0
#define dynamic_test		false
#endif
#include "asm-1.inc"
