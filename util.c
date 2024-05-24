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

#include "ajla.h"

#include "asm.h"
#include "str.h"
#include "arithm-b.h"
#include "arithm-i.h"
#include "arithm-r.h"

#include "util.h"

#include <stdio.h>

#if GNUC_ATLEAST(3,3,0) && !defined(__OPTIMIZE_SIZE__) && (defined(UNALIGNED_ACCESS_EFFICIENT) || defined(HAVE_BUILTIN_ASSUME_ALIGNED))
#define MEMCPY_FAST
#endif

void attr_fastcall memcpy_fast(void *dest, const void *src, size_t size)
{
	if (unlikely(dest == src))
		return;
#ifdef MEMCPY_FAST
#ifdef __BIGGEST_ALIGNMENT__
#define al(n)		minimum(n, __BIGGEST_ALIGNMENT__)
#else
#define al(n)		(n)
#endif
#ifndef UNALIGNED_ACCESS_EFFICIENT
#define check_alignment(n)						\
			if (unlikely(((ptr_to_num(dest) | ptr_to_num(src)) & ((al(n)) - 1)) != 0)) break;\
			dest = __builtin_assume_aligned(dest, al(n));	\
			src = __builtin_assume_aligned(src, al(n));
#else
#define check_alignment(n)
#endif
	switch (size) {
		case 1:
			(void)memcpy(dest, src, 1);
			return;
		case 2:
			check_alignment(2)
			(void)memcpy(dest, src, 2);
			return;
		case 4:
			check_alignment(4)
			(void)memcpy(dest, src, 4);
			return;
#if (defined(__i386__) || (defined(__SIZEOF_LONG_DOUBLE__) && __SIZEOF_LONG_DOUBLE__ == 12)) && defined(UNALIGNED_ACCESS_EFFICIENT)
		case 12:
			(void)memcpy(cast_ptr(char *, dest) + 8, cast_ptr(const char *, src) + 8, 4);
#endif
			/*-fallthrough*/
		case 8:
			check_alignment(8)
			(void)memcpy(dest, src, 8);
			return;
		case 16:
			check_alignment(16)
			(void)memcpy(dest, src, 16);
			return;
	}
#undef al
#undef check_alignment
#endif
	(void)memcpy(dest, src, size);
}

float half_to_float(uint16_t attr_unused x)
{
#if !REAL_MASK
	return 0;
#else
	float res;
	uint16_t pos;

#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_F16C)
	if (likely(cpu_test_feature(CPU_FEATURE_f16c))) {
		float r;
#ifdef __SSE__
		__asm__ ("vmovd %k1, %0; vcvtph2ps %0, %0" : "=x"(r) : "r"(x));
#else
		__asm__ ("vmovd %k1, %%xmm0; vcvtph2ps %%xmm0, %%xmm0; vmovss %%xmm0, %0" : "=m"(r) : "r"(x));
#endif
		return r;
	}
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_HALF_PRECISION)
	if (likely(cpu_test_feature(CPU_FEATURE_half))) {
#if defined(__SOFTFP__) || (CLANG_ATLEAST(0,0,0) && !CLANG_ATLEAST(6,0,0))
		__asm__ (ARM_ASM_PREFIX "vmov s0, %1; vcvtb.f32.f16 s0, s0; vmov %0, s0" : "=r"(res) : "r"((uint32_t)x) : "s0");
#else
		__asm__ (ARM_ASM_PREFIX "vcvtb.f32.f16 %0, %1" : "=t"(res) : "t"((uint32_t)x));
#endif
		return res;
	}
#endif

	res = 0;
	pos = x & 0x7fff;
	if (likely((uint16_t)(pos - 0x400) < 0x7800)) {
#if defined(HAVE_UNION_FLOAT_UINT32_T) && !defined(UNUSUAL)
		union {
			float f;
			uint32_t i;
		} u;
		u.i = ((uint32_t)(x & (uint32_t)0x8000UL) << 16) | ((pos + (uint32_t)0x1c000UL) << 13);
		return u.f;
#else
		res = (float)((x & 0x3ff) | 0x400) * (float)(1. / (1L << 25)) * (float)((int32_t)1 << (pos >> 10));
#endif
	} else if (pos < 0x400) {
		res = (float)pos * (float)(1. / (1L << 24));
	} else if (pos == 0x7c00) {
#ifdef HUGE_VAL
		res = HUGE_VAL;
#else
		res = 1. / 0.;
#endif
	} else {
#ifdef NAN
		res = NAN;
#else
		double z = 0.;
		res = z / z;
#endif
	}
#if defined(HAVE_COPYSIGNF) && (defined(__x86_64__) ^ defined(UNUSUAL_ARITHMETICS))
	res = copysignf(res, (float)(int16_t)x);
#else
	if (unlikely((int16_t)x < 0))
		res = -res;
#endif
	return res;
#endif
}

uint16_t float_to_half(float attr_unused x)
{
#if !REAL_MASK
	return 0;
#else
	float a, mant;
	float limit;
	uint16_t res;

#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_F16C)
	if (likely(cpu_test_feature(CPU_FEATURE_f16c))) {
		uint32_t r;
#ifdef __SSE__
		__asm__ ("vcvtps2ph $4, %1, %1; vmovd %1, %0" : "=r"(r), "+x"(x));
#else
		__asm__ ("vmovss %1, %%xmm0; vcvtps2ph $4, %%xmm0, %%xmm0; vmovd %%xmm0, %0" : "=r"(r) : "m"(x));
#endif
		return r;
	}
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_HALF_PRECISION)
	if (likely(cpu_test_feature(CPU_FEATURE_half))) {
		uint32_t r;
#if defined(__SOFTFP__) || (CLANG_ATLEAST(0,0,0) && !CLANG_ATLEAST(6,0,0))
		__asm__ (ARM_ASM_PREFIX "vmov s0, %1; vcvtb.f16.f32 s0, s0; vmov %0, s0" : "=r"(r) : "r"(x) : "s0");
#else
		__asm__ (ARM_ASM_PREFIX "vcvtb.f16.f32 %1, %1; vmov %0, %1" : "=r"(r), "+t"(x));
#endif
		return r;
	}
#endif

	res = (uint16_t)!!signbit(x) << 15;
	a = fabs(x);
	limit = 65520.;
#if defined(use_is_macros) && !defined(UNUSUAL_ARITHMETICS)
	if (unlikely(isunordered(a, limit)))
#else
	if (unlikely(isnan_real32_t(a)))
#endif
	{
		res |= 0x200;
		goto inf;
	}
#if defined(use_is_macros) && !defined(UNUSUAL_ARITHMETICS)
	if (unlikely(isgreaterequal(a, limit)))
#else
	if (unlikely(a >= limit))
#endif
	{
inf:
		res |= 0x7c00;
	} else if (unlikely(a < (float)(1. / (1 << 14)))) {
		mant = a * (float)(1L << 24);
		res |= 0x400;
		goto do_round;
	} else {
		int ex, im;
#if defined(HAVE_UNION_FLOAT_UINT32_T) && !defined(UNUSUAL)
		union {
			float f;
			uint32_t i;
		} u;
		u.f = a;
		ex = (u.i >> 23) - 126;
		u.i &= 0x007fffffUL;
		u.i |= 0x44800000UL;
		mant = u.f;
#else
		mant = frexpf(a, &ex);
		mant *= 1 << 11;
#endif
		res += (ex + 14) << 10;
do_round:
#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_SSE) && static_test_sse
		__asm__ (X86_ASM_V"cvtss2si %1, %0" : "=r"(im) :
#ifdef __SSE__
			"x"X86_ASM_M
#else
			"m"
#endif
			(mant));
#elif defined(HAVE_LRINTF) && !defined(UNUSUAL_ARITHMETICS)
		im = (int)lrintf(mant);
#else
		im = (int)mant;
		mant -= (float)im;
		if (mant > 0.5 || (unlikely(mant == 0.5) && im & 1))
			im++;
#endif
		im -= 0x400;
		res += im;
	}
	return res;
#endif
}

#ifdef need_signbit_d
int signbit_d(double d)
{
#ifdef HAVE_COPYSIGN
	return copysign(1, d) < 0;
#else
	char s[256];
	if (likely(d > 0)) return 0;
	if (likely(d < 0)) return 1;
	sprintf(s, "%f", d);
	return s[0] == '-';
#endif
}
#endif


#define DEFINE_OPCODE_START_LBL(opcode, lbl)			\
	{ (opcode) + ARG_MODE * OPCODE_MODE_MULT, stringify(lbl) },
const char attr_cold *decode_opcode(code_t o, bool allow_invalid)
{
	static const struct {
		code_t opcode;
		const char *string;
	} table[] = {
#include "ipret.inc"
	};
	static atomic_type code_t rmap[ARG_MODE_N * OPCODE_MODE_MULT];

	code_t i;

	if (unlikely(o >= n_array_elements(rmap)))
		goto unknown;

	if (likely(rmap[o]))
		return table[rmap[o] - 1].string;

	for (i = 0; i < n_array_elements(table); i++) {
		if (unlikely(table[i].opcode == o)) {
			rmap[o] = i + 1;
			return table[i].string;
		}
	}
unknown:
	if (!allow_invalid) {
		/*for (i = 0; i < n_array_elements(table); i++) {
			debug("%04x - %s", table[i].opcode, table[i].string);
		}*/
		internal(file_line, "decode_opcode: invalid opcode %04x", o);
	}
	return NULL;
}
