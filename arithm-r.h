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

#ifndef AJLA_ARITHM_R_H
#define AJLA_ARITHM_R_H

#include "asm.h"
#include "arithm-b.h"

#define sse_one_param(x)	stringify(x)
#define avx_two_params(x)	stringify(x)", "stringify(x)

#define gen_sse_binary(fn, type, v, instr, s, p)			\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	__asm__ ("							\n\
		"v"movs"#s"		%1, %%xmm0			\n\
		"v""#instr"s"#s"	%2, "p(%%xmm0)"			\n\
		"v"movs"#s"		%%xmm0, %0			\n\
	" : "=m"(*res) : "m"(*op1), "m"(*op2) X86_ASM_XMM0_CLOB);	\
	return true;							\
}

#ifdef INLINE_ASM_GCC_LABELS
#define gen_sse_logical(fn, type, v, instr, s)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	if (sizeof(ajla_flat_option_t) != 1)				\
		*res = 0;						\
	__asm__ goto ("							\n\
		"v"movs"#s"		%1, %%xmm0			\n\
		"v"ucomis"#s"		%2, %%xmm0			\n\
		jp			%l[unordered]			\n\
		"#instr"		%0				\n\
	" : : "m"(*res), "m"(*op1), "m"(*op2) : "memory", "cc" X86_ASM_XMM0_CLOBC : unordered);\
	return true;							\
unordered:								\
	return false;							\
}
#else
#define gen_sse_logical(fn, type, v, instr, s)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	unsigned char unordered, r;					\
	__asm__ ("							\n\
		"v"movs"#s"		%2, %%xmm0			\n\
		"v"ucomis"#s"		%3, %%xmm0			\n\
		setp			%1				\n\
		"#instr"		%0				\n\
	" : "=r"(r), "=r"(unordered) : "m"(*op1), "m"(*op2) : "cc" X86_ASM_XMM0_CLOBC);\
	if (unlikely(unordered))					\
		return false;						\
	*res = r;							\
	return true;							\
}
#endif

#define gen_sse_neg(fn, type, v, s, p)					\
static ipret_inline void attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, type *res)\
{									\
	static const type x = -0.0;					\
	__asm__ ("							\
		"v"movs"#s"	%1, %%xmm0				\n\
		"v"movs"#s"	%2, %%xmm1				\n\
		"v"xorp"#s"	%%xmm1, "p(%%xmm0)"			\n\
		"v"movs"#s"	%%xmm0, %0				\n\
	" : "=m"(*res) : "m"(*op1), "m"(x) X86_ASM_XMM0_CLOB X86_ASM_XMM1_CLOBC);\
}

#define gen_sse_sqrt(fn, type, v, s, p)					\
static ipret_inline void attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, type *res)\
{									\
	__asm__ ("							\
		"v"sqrts"#s"	%1, "p(%%xmm0)"				\n\
		"v"movs"#s"	%%xmm0, %0				\n\
	" : "=m"(*res) : "m"(*op1) X86_ASM_XMM0_CLOB X86_ASM_XMM1_CLOBC);\
}

#define gen_sse_to_int(fn, type, v, s)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, int_default_t *res)\
{									\
	int_default_t r;						\
	__asm__ ("							\n\
		"v"cvtts"#s"2si	%1, %0					\n\
	" : "=r"(r) : "m"(*op1));					\
	if (unlikely(r == sign_bit(int_default_t)))			\
		return false;						\
	*res = r;							\
	return true;							\
}

#define gen_sse_from_int(fn, type, v, s, z, p)				\
static ipret_inline void attr_unused cat4(REAL_unary_,fn,_,type)(const int_default_t *op1, type *res)\
{									\
	__asm__ ("							\n\
		"v"cvtsi2s"#s""#z"	%1, "p(%%xmm0)"			\n\
		"v"movs"#s"		%%xmm0, %0			\n\
	" : "=m"(*res) : "rm"(*op1) X86_ASM_XMM0_CLOB);			\
}

#define gen_sse_is_exception(fn, type, v, s)				\
static ipret_inline void attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, ajla_flat_option_t *res)\
{									\
	if (sizeof(ajla_flat_option_t) != 1)				\
		*res = 0;						\
	__asm__ ("							\
		"v"movs"#s"		%1, %%xmm0			\n\
		"v"ucomis"#s"		%%xmm0, %%xmm0			\n\
		setp			%0				\n\
	" : "=m"(*res) : "m"(*op1) : "cc" X86_ASM_XMM0_CLOBC);		\
}

#define gen_f16c_binary(fn, type, instr)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	__asm__ ("							\n\
		vpinsrw			$0, %1, %%xmm7, %%xmm0		\n\
		vpinsrw			$0, %2, %%xmm7, %%xmm1		\n\
		vcvtph2ps		%%xmm0, %%xmm0			\n\
		vcvtph2ps		%%xmm1, %%xmm1			\n\
		v"#instr"ss		%%xmm1, %%xmm0, %%xmm0		\n\
		vcvtps2ph		$4, %%xmm0, %%xmm0		\n\
		vpextrw			$0, %%xmm0, %0			\n\
	" : "=m"(*res) : "m"(*op1), "m"(*op2) X86_ASM_XMM0_CLOB X86_ASM_XMM1_CLOBC);\
	return true;							\
}

#define gen_f16c_sqrt(fn, type)						\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, type *res)\
{									\
	__asm__ ("							\n\
		vpinsrw			$0, %1, %%xmm7, %%xmm0		\n\
		vcvtph2ps		%%xmm0, %%xmm0			\n\
		vsqrtss			%%xmm0, %%xmm0, %%xmm0		\n\
		vcvtps2ph		$4, %%xmm0, %%xmm0		\n\
		vpextrw			$0, %%xmm0, %0			\n\
	" : "=m"(*res) : "m"(*op1) X86_ASM_XMM0_CLOB);			\
	return true;							\
}

#ifdef INLINE_ASM_GCC_LABELS
#define gen_f16c_logical(fn, type, instr)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	if (sizeof(ajla_flat_option_t) != 1)				\
		*res = 0;						\
	__asm__ goto ("							\n\
		vpinsrw			$0, %1, %%xmm7, %%xmm0		\n\
		vpinsrw			$0, %2, %%xmm7, %%xmm1		\n\
		vcvtph2ps		%%xmm0, %%xmm0			\n\
		vcvtph2ps		%%xmm1, %%xmm1			\n\
		vucomiss		%%xmm1, %%xmm0			\n\
		jp			%l[unordered]			\n\
		"#instr"		%0				\n\
	" : : "m"(*res), "m"(*op1), "m"(*op2) : "memory", "cc" X86_ASM_XMM0_CLOBC X86_ASM_XMM1_CLOBC : unordered);\
	return true;							\
unordered:								\
	return false;							\
}
#else
#define gen_f16c_logical(fn, type, instr)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	unsigned char unordered, r;					\
	__asm__ ("							\n\
		vpinsrw			$0, %2, %%xmm7, %%xmm0		\n\
		vpinsrw			$0, %3, %%xmm7, %%xmm1		\n\
		vcvtph2ps		%%xmm0, %%xmm0			\n\
		vcvtph2ps		%%xmm1, %%xmm1			\n\
		vucomiss		%%xmm1, %%xmm0			\n\
		setp			%1				\n\
		"#instr"		%0				\n\
	" : "=r"(r), "=r"(unordered) : "m"(*op1), "m"(*op2) : "cc" X86_ASM_XMM0_CLOBC);\
	if (unlikely(unordered))					\
		return false;						\
	*res = r;							\
	return true;							\
}
#endif

#define gen_f16c_to_int(fn, type)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, int_default_t *res)\
{									\
	int_default_t r;						\
	__asm__ ("							\n\
		vpinsrw			$0, %1, %%xmm7, %%xmm0		\n\
		vcvtph2ps		%%xmm0, %%xmm0			\n\
		vcvttss2si		%%xmm0, %0			\n\
	" : "=r"(r) : "m"(*op1) X86_ASM_XMM0_CLOB);			\
	if (unlikely(r == sign_bit(int_default_t)))			\
		return false;						\
	*res = r;							\
	return true;							\
}

#define gen_f16c_from_int(fn, type, z)					\
static ipret_inline void attr_unused cat4(REAL_unary_,fn,_,type)(const int_default_t *op1, type *res)\
{									\
	__asm__ ("							\n\
		vcvtsi2ss"#z"		%1, %%xmm7, %%xmm0		\n\
		vcvtps2ph		$4, %%xmm0, %%xmm0		\n\
		vpextrw			$0, %%xmm0, %0			\n\
	" : "=m"(*res) : "rm"(*op1) X86_ASM_XMM0_CLOB);			\
}

#define gen_fp16_binary(fn, type, instr)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	__asm__ ("							\n\
		vmovsh			%1, %%xmm0			\n\
		v"#instr"sh		%2, %%xmm0, %%xmm0		\n\
		vmovsh			%%xmm0, %0			\n\
	" : "=m"(*res) : "m"(*op1), "m"(*op2) X86_ASM_XMM0_CLOB);	\
	return true;							\
}

#define gen_fp16_sqrt(fn, type)						\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, type *res)\
{									\
	__asm__ ("							\n\
		vsqrtsh			%1, %%xmm7, %%xmm0		\n\
		vmovsh			%%xmm0, %0			\n\
	" : "=m"(*res) : "m"(*op1) X86_ASM_XMM0_CLOB);			\
	return true;							\
}

#ifdef INLINE_ASM_GCC_LABELS
#define gen_fp16_logical(fn, type, instr)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	if (sizeof(ajla_flat_option_t) != 1)				\
		*res = 0;						\
	__asm__ goto ("							\n\
		vmovsh			%1, %%xmm0			\n\
		vucomish		%2, %%xmm0			\n\
		jp			%l[unordered]			\n\
		"#instr"		%0				\n\
	" : : "m"(*res), "m"(*op1), "m"(*op2) : "memory", "cc" X86_ASM_XMM0_CLOBC : unordered);\
	return true;							\
unordered:								\
	return false;							\
}
#else
#define gen_fp16_logical(fn, type, instr)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	unsigned char unordered, r;					\
	__asm__ ("							\n\
		vmovsh			%2, %%xmm0			\n\
		vucomish		%3, %%xmm0			\n\
		setp			%1				\n\
		"#instr"		%0				\n\
	" : "=r"(r), "=r"(unordered) : "m"(*op1), "m"(*op2) : "cc" X86_ASM_XMM0_CLOBC);\
	if (unlikely(unordered))					\
		return false;						\
	*res = r;							\
	return true;							\
}
#endif

#define gen_fp16_to_int(fn, type)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, int_default_t *res)\
{									\
	int_default_t r;						\
	__asm__ ("							\n\
		vcvttsh2si	%1, %0					\n\
	" : "=r"(r) : "m"(*op1));					\
	if (unlikely(r == sign_bit(int_default_t)))			\
		return false;						\
	*res = r;							\
	return true;							\
}

#define gen_fp16_from_int(fn, type, z)					\
static ipret_inline void attr_unused cat4(REAL_unary_,fn,_,type)(const int_default_t *op1, type *res)\
{									\
	__asm__ ("							\n\
		vcvtsi2sh		%1, %%xmm7, %%xmm0		\n\
		vmovsh			%%xmm0, %0			\n\
	" : "=m"(*res) : "rm"(*op1) X86_ASM_XMM0_CLOB);			\
}

#define gen_vfp_binary(fn, type, op, f, s)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vldr			"s"0, [ %1 ]			\n\
		vldr			"s"1, [ %2 ]			\n\
		"op"."f"		"s"0, "s"0, "s"1		\n\
		vstr			"s"0, [ %0 ]			\n\
	" :: "r"(res), "r"(op1), "r"(op2) : s"0", s"1", "memory");	\
	return true;							\
}

#define gen_vfp_unary(fn, type, op, f, s)				\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, type *res)\
{									\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vldr			"s"0, [ %1 ]			\n\
		"op"."f"		"s"0, "s"0			\n\
		vstr			"s"0, [ %0 ]			\n\
	" :: "r"(res), "r"(op1) : s"0", "memory");			\
	return true;							\
}

#ifdef INLINE_ASM_GCC_LABELS
#define gen_vfp_logical(fn, type, cond, f, s)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		vldr			"s"0, [ %1 ]			\n\
		vldr			"s"1, [ %2 ]			\n\
		mov			r0, #0				\n\
		vcmp."f"		"s"0, "s"1			\n\
		vmrs			APSR_nzcv, fpscr		\n\
		bvs			%l[unordered]			\n\
		it			"#cond"				\n\
		mov"#cond"		r0, #1				\n\
		strb			r0, [ %0 ]			\n\
	" : : "r"(res), "r"(op1), "r"(op2) : s"0", s"1", "r0", "memory", "cc" : unordered);\
	return true;							\
unordered:								\
	return false;							\
}
#define gen_vfp_to_int(fn, type, f, s)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, int_default_t *res)\
{									\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		vldr			"s"0, [ %1 ]			\n\
		vcmp."f"		"s"0, "s"0			\n\
		vmrs			APSR_nzcv, fpscr		\n\
		bvs			%l[unordered]			\n\
		vcvt.s32."f"		s1, "s"0			\n\
		vmov			r0, s1				\n\
		add			r0, r0, #0x80000000		\n\
		add			r0, r0, #0x00000001		\n\
		cmp			r0, #1				\n\
		bls			%l[unordered]			\n\
		vstr			s1, [ %0 ]			\n\
	" : : "r"(res), "r"(op1) : s"0", s"1", "r0", "memory", "cc" : unordered);\
	return true;							\
unordered:								\
	return false;							\
}
#else
#define gen_vfp_logical(fn, type, cond, f, s)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	unsigned unordered, r;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vldr			"s"0, [ %2 ]			\n\
		vldr			"s"1, [ %3 ]			\n\
		mov			%0, #0				\n\
		mov			%1, #0				\n\
		vcmp."f"		"s"0, "s"1			\n\
		vmrs			APSR_nzcv, fpscr		\n\
		it			vs				\n\
		movvs			%0, #1				\n\
		it			"#cond"				\n\
		mov"#cond"		%1, #1				\n\
	" : "=r"(unordered), "=r"(r) : "r"(op1), "r"(op2) : s"0", s"1", "r0", "memory", "cc");\
	if (unlikely(unordered))					\
		return false;						\
	*res = r;							\
	return true;							\
}
#define gen_vfp_to_int(fn, type, f, s)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, int_default_t *res)\
{									\
	unsigned unordered;						\
	int_default_t r;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vldr			"s"0, [ %2 ]			\n\
		mov			%0, #0				\n\
		vcmp."f"		"s"0, "s"0			\n\
		vmrs			APSR_nzcv, fpscr		\n\
		it			vs				\n\
		movvs			%0, #1				\n\
		vcvt.s32."f"		s0, "s"0			\n\
		vmov			%1, s0				\n\
	" : "=r"(unordered), "=r"(r) : "r"(op1) : s"0", s"1", "r0", "memory", "cc");\
	if (unlikely(unordered) || (unlikely((unsigned)r + 0x80000001U < 1)))\
		return false;						\
	*res = r;							\
	return true;							\
}
#endif

#define gen_vfp_from_int(fn, type, f, s)				\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const int_default_t *op1, type *res)\
{									\
	__asm__ ("							\n\
		vldr			s0, [ %1 ]			\n\
		vcvt."f".s32		"s"0, s0			\n\
		vstr			"s"0, [ %0 ]			\n\
	" : : "r"(res), "r"(op1) : "d0", "memory");			\
	return true;							\
}

#define gen_vfp_is_exception(fn, type, f, s)				\
static ipret_inline void attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, ajla_flat_option_t *res)\
{									\
	unsigned unordered;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vldr			"s"0, [ %1 ]			\n\
		mov			%0, #0				\n\
		vcmp."f"		"s"0, "s"0			\n\
		vmrs			APSR_nzcv, fpscr		\n\
		it			vs				\n\
		movvs			%0, #1				\n\
	" : "=r"(unordered) : "r"(op1) : s"0", s"1", "cc");		\
	*res = unordered;						\
}

#define gen_vfp_half_binary(fn, type, op)					\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vld1.16			d0[0], [ %1 ]			\n\
		vld1.16			d0[2], [ %2 ]			\n\
		vcvtb.f32.f16		s0, s0				\n\
		vcvtb.f32.f16		s1, s1				\n\
		"op".f32		s0, s0, s1			\n\
		vcvtb.f16.f32		s0, s0				\n\
		vst1.16			d0[0], [ %0 ]			\n\
	" :: "r"(res), "r"(op1), "r"(op2) : "d0", "memory");		\
	return true;							\
}

#ifdef INLINE_ASM_GCC_LABELS
#define gen_vfp_half_logical(fn, type, cond)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		vld1.16			d0[0], [ %1 ]			\n\
		vld1.16			d0[2], [ %2 ]			\n\
		mov			r0, #0				\n\
		vcvtb.f32.f16		s0, s0				\n\
		vcvtb.f32.f16		s1, s1				\n\
		vcmp.f32		s0, s1				\n\
		vmrs			APSR_nzcv, fpscr		\n\
		bvs			%l[unordered]			\n\
		it			"#cond"				\n\
		mov"#cond"		r0, #1				\n\
		strb			r0, [ %0 ]			\n\
	" : : "r"(res), "r"(op1), "r"(op2) : "d0", "r0", "memory", "cc" : unordered);\
	return true;							\
unordered:								\
	return false;							\
}
#define gen_vfp_half_to_int(fn, type)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, int_default_t *res)\
{									\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		vld1.16			d0[0], [ %1 ]			\n\
		vcvtb.f32.f16		s0, s0				\n\
		vcmp.f32		s0, s0				\n\
		vmrs			APSR_nzcv, fpscr		\n\
		bvs			%l[unordered]			\n\
		vcvt.s32.f32		s1, s0				\n\
		vmov			r0, s1				\n\
		add			r0, r0, #0x80000000		\n\
		add			r0, r0, #0x00000001		\n\
		cmp			r0, #1				\n\
		bls			%l[unordered]			\n\
		vstr			s1, [ %0 ]			\n\
	" : : "r"(res), "r"(op1) : "d0", "r0", "memory", "cc" : unordered);\
	return true;							\
unordered:								\
	return false;							\
}
#else
#define gen_vfp_half_logical(fn, type, cond)				\
static ipret_inline bool attr_unused cat4(REAL_binary_,fn,_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	unsigned unordered, r;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vld1.16			d0[0], [ %2 ]			\n\
		vld1.16			d0[2], [ %3 ]			\n\
		mov			%0, #0				\n\
		mov			%1, #0				\n\
		vcvtb.f32.f16		s0, s0				\n\
		vcvtb.f32.f16		s1, s1				\n\
		vcmp.f32		s0, s1				\n\
		vmrs			APSR_nzcv, fpscr		\n\
		it			vs				\n\
		movvs			%0, #1				\n\
		it			"#cond"				\n\
		mov"#cond"		%1, #1				\n\
	" : "=r"(unordered), "=r"(r) : "r"(op1), "r"(op2) : "d0", "memory", "cc");\
	if (unlikely(unordered))					\
		return false;						\
	*res = r;							\
	return true;							\
}
#define gen_vfp_half_to_int(fn, type)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const type *op1, int_default_t *res)\
{									\
	unsigned unordered;						\
	int_default_t r;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vld1.16			d0[0], [ %2 ]			\n\
		mov			%0, #0				\n\
		vcvtb.f32.f16		s0, s0				\n\
		vcmp.f32		s0, s0				\n\
		vmrs			APSR_nzcv, fpscr		\n\
		it			vs				\n\
		movvs			%0, #1				\n\
		vcvt.s32.f32		s0, s0				\n\
		vmov			%1, s0				\n\
	" : "=r"(unordered), "=r"(r) : "r"(op1) : "d0", "r0", "memory", "cc");\
	if (unlikely(unordered) || (unlikely((unsigned)r + 0x80000001U < 1)))\
		return false;						\
	*res = r;							\
	return true;							\
}
#endif

#define gen_vfp_half_from_int(fn, type)					\
static ipret_inline bool attr_unused cat4(REAL_unary_,fn,_,type)(const int_default_t *op1, type *res)\
{									\
	__asm__ (ARM_ASM_PREFIX "					\n\
		vldr			s0, [ %1 ]			\n\
		vcvt.f32.s32		s0, s0				\n\
		vcvtb.f16.f32		s0, s0				\n\
		vst1.16			d0[0], [ %0 ]			\n\
	" : : "r"(res), "r"(op1) : "d0", "memory");			\
	return true;							\
}


#ifdef INT_DEFAULT_BITS

#define gen_sse_ops(type, s, z)						\
gen_sse_binary(add_alt1, type, "", add, s, sse_one_param)		\
gen_sse_binary(subtract_alt1, type, "", sub, s, sse_one_param)		\
gen_sse_binary(multiply_alt1, type, "", mul, s, sse_one_param)		\
gen_sse_binary(divide_alt1, type, "", div, s, sse_one_param)		\
gen_sse_logical(equal_alt1, type, "", sete, s)				\
gen_sse_logical(not_equal_alt1, type, "", setne, s)			\
gen_sse_logical(less_alt1, type, "", setb, s)				\
gen_sse_logical(less_equal_alt1, type, "", setbe, s)			\
gen_sse_logical(greater_alt1, type, "", seta, s)			\
gen_sse_logical(greater_equal_alt1, type, "", setae, s)			\
gen_sse_neg(neg_alt1, type, "", s, sse_one_param)			\
gen_sse_sqrt(sqrt_alt1, type, "", s, sse_one_param)			\
gen_sse_to_int(to_int_alt1, type, "", s)				\
gen_sse_from_int(from_int_alt1, type, "", s, z, sse_one_param)		\
gen_sse_is_exception(is_exception_alt1, type, "", s)

#define gen_avx_ops(type, s, z)						\
gen_sse_binary(add_alt2, type, "v", add, s, avx_two_params)		\
gen_sse_binary(subtract_alt2, type, "v", sub, s, avx_two_params)	\
gen_sse_binary(multiply_alt2, type, "v", mul, s, avx_two_params)	\
gen_sse_binary(divide_alt2, type, "v", div, s, avx_two_params)		\
gen_sse_logical(equal_alt2, type, "v", sete, s)				\
gen_sse_logical(not_equal_alt2, type, "v", setne, s)			\
gen_sse_logical(less_alt2, type, "v", setb, s)				\
gen_sse_logical(less_equal_alt2, type, "v", setbe, s)			\
gen_sse_logical(greater_alt2, type, "v", seta, s)			\
gen_sse_logical(greater_equal_alt2, type, "v", setae, s)		\
gen_sse_neg(neg_alt2, type, "v", s, avx_two_params)			\
gen_sse_sqrt(sqrt_alt2, type, "v", s, avx_two_params)			\
gen_sse_to_int(to_int_alt2, type, "v", s)				\
gen_sse_from_int(from_int_alt2, type, "v", s, z, avx_two_params)	\
gen_sse_is_exception(is_exception_alt2, type, "v", s)

#define gen_f16c_ops(z)							\
gen_f16c_binary(add_alt1, real16_t, add)				\
gen_f16c_binary(subtract_alt1, real16_t, sub)				\
gen_f16c_binary(multiply_alt1, real16_t, mul)				\
gen_f16c_binary(divide_alt1, real16_t, div)				\
gen_f16c_sqrt(sqrt_alt1, real16_t)					\
gen_f16c_logical(equal_alt1, real16_t, sete)				\
gen_f16c_logical(not_equal_alt1, real16_t, setne)			\
gen_f16c_logical(less_alt1, real16_t, setb)				\
gen_f16c_logical(less_equal_alt1, real16_t, setbe)			\
gen_f16c_logical(greater_alt1, real16_t, seta)				\
gen_f16c_logical(greater_equal_alt1, real16_t, setae)			\
gen_f16c_to_int(to_int_alt1, real16_t)					\
gen_f16c_from_int(from_int_alt1, real16_t, z)

#define gen_fp16_ops(z)							\
gen_fp16_binary(add_alt2, real16_t, add)				\
gen_fp16_binary(subtract_alt2, real16_t, sub)				\
gen_fp16_binary(multiply_alt2, real16_t, mul)				\
gen_fp16_binary(divide_alt2, real16_t, div)				\
gen_fp16_sqrt(sqrt_alt2, real16_t)					\
gen_fp16_logical(equal_alt2, real16_t, sete)				\
gen_fp16_logical(not_equal_alt2, real16_t, setne)			\
gen_fp16_logical(less_alt2, real16_t, setb)				\
gen_fp16_logical(less_equal_alt2, real16_t, setbe)			\
gen_fp16_logical(greater_alt2, real16_t, seta)				\
gen_fp16_logical(greater_equal_alt2, real16_t, setae)			\
gen_fp16_to_int(to_int_alt2, real16_t)					\
gen_fp16_from_int(from_int_alt2, real16_t, z)

#define gen_vfp_ops(type, f, s)						\
gen_vfp_binary(add_alt1, type, "vadd", f, s)				\
gen_vfp_binary(subtract_alt1, type, "vsub", f, s)			\
gen_vfp_binary(multiply_alt1, type, "vmul", f, s)			\
gen_vfp_binary(divide_alt1, type, "vdiv", f, s)				\
gen_vfp_unary(neg_alt1, type, "vneg", f, s)				\
gen_vfp_unary(sqrt_alt1, type, "vsqrt", f, s)				\
gen_vfp_logical(equal_alt1, type, eq, f, s)				\
gen_vfp_logical(not_equal_alt1, type, ne, f, s)				\
gen_vfp_logical(less_alt1, type, mi, f, s)				\
gen_vfp_logical(less_equal_alt1, type, ls, f, s)			\
gen_vfp_logical(greater_alt1, type, gt, f, s)				\
gen_vfp_logical(greater_equal_alt1, type, ge, f, s)			\
gen_vfp_to_int(to_int_alt1, type, f, s)					\
gen_vfp_from_int(from_int_alt1, type, f, s)				\
gen_vfp_is_exception(is_exception_alt1, type, f, s)

#define gen_vfp_half_ops()						\
gen_vfp_half_binary(add_alt1, real16_t, "vadd")				\
gen_vfp_half_binary(subtract_alt1, real16_t, "vsub")			\
gen_vfp_half_binary(multiply_alt1, real16_t, "vmul")			\
gen_vfp_half_binary(divide_alt1, real16_t, "vdiv")			\
gen_vfp_half_logical(equal_alt1, real16_t, eq)				\
gen_vfp_half_logical(not_equal_alt1, real16_t, ne)			\
gen_vfp_half_logical(less_alt1, real16_t, mi)				\
gen_vfp_half_logical(less_equal_alt1, real16_t, ls)			\
gen_vfp_half_logical(greater_alt1, real16_t, gt)			\
gen_vfp_half_logical(greater_equal_alt1, real16_t, ge)			\
gen_vfp_half_to_int(to_int_alt1, real16_t)				\
gen_vfp_half_from_int(from_int_alt1, real16_t)

#else

#define gen_sse_ops(type, s, z)
#define gen_avx_ops(type, s, z)
#define gen_f16c_ops(z)
#define gen_fp16_ops(z)
#define gen_vfp_ops(type, f, s)
#define gen_vfp_half_ops()

#endif

#define file_inc "arithm-r.inc"
#include "for-real.inc"

#endif
