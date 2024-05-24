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

#ifndef AJLA_ARITHM_H
#define AJLA_ARITHM_H

#include "asm.h"
#include "arithm-b.h"

#if (defined(__HP_cc) && EFFICIENT_WORD_SIZE >= 64) ^ defined(UNUSUAL_ARITHMETICS)
#define add_subtract_overflow_test_mode	1
#define neg_overflow_test_mode		1
#else
#define add_subtract_overflow_test_mode	0
#define neg_overflow_test_mode		0
#endif


#if defined(HAVE_BUILTIN_ADD_SUB_OVERFLOW) && !defined(UNUSUAL)

#define gen_generic_addsub(fn, type, utype, mode)			\
static maybe_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type r;								\
	if (!mode) {							\
		if (unlikely(__builtin_add_overflow(*op1, *op2, &r)))	\
			return false;					\
	} else {							\
		if (unlikely(__builtin_sub_overflow(*op1, *op2, &r)))	\
			return false;					\
	}								\
	*res = r;							\
	return true;							\
}

#define gen_generic_inc_dec(type, utype)				\
static maybe_inline bool attr_unused cat(INT_unary_inc_,type)(const type *op, type *res)\
{									\
	type r;								\
	if (unlikely(__builtin_add_overflow(*op, 1, &r)))		\
		return false;						\
	*res = r;							\
	return true;							\
}									\
static maybe_inline bool attr_unused cat(INT_unary_dec_,type)(const type *op, type *res)\
{									\
	type r;								\
	if (unlikely(__builtin_sub_overflow(*op, 1, &r)))		\
		return false;						\
	*res = r;							\
	return true;							\
}

#else

#define gen_generic_addsub(fn, type, utype, mode)			\
static maybe_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1 = *op1, o2 = *op2;					\
	type r;								\
	if (!mode) {							\
		if (sizeof(type) < sizeof(int_efficient_t)) {		\
			int_efficient_t lr = (int_efficient_t)o1 + (int_efficient_t)o2;\
			r = (type)lr;					\
			if (unlikely(r != lr))				\
				return false;				\
		} else {						\
			r = (utype)o1 + (utype)o2;			\
			if (!(add_subtract_overflow_test_mode)) {	\
				if (unlikely((~(o1 ^ o2) & (o2 ^ r) & sign_bit(utype)) != 0))\
					return false;			\
			} else {					\
				if ((r >= o1) != (o2 >= 0))		\
					return false;			\
			}						\
		}							\
	} else {							\
		if (sizeof(type) < sizeof(int_efficient_t)) {		\
			int_efficient_t lr = (int_efficient_t)o1 - (int_efficient_t)o2;\
			r = (type)lr;					\
			if (unlikely(r != lr))				\
				return false;				\
		} else {						\
			r = (utype)o1 - (utype)o2;			\
			if (!(add_subtract_overflow_test_mode)) {	\
				if (unlikely((~(o2 ^ r) & (o1 ^ r) & sign_bit(utype)) != 0))\
					return false;			\
			} else {					\
				if ((r <= o1) != (o2 >= 0))		\
					return false;			\
			}						\
		}							\
	}								\
	*res = r;							\
	return true;							\
}

#define gen_generic_inc_dec(type, utype)				\
static maybe_inline bool attr_unused cat(INT_unary_inc_,type)(const type *op, type *res)\
{									\
	type o = *op;							\
	if (unlikely(o == signed_maximum(type)))			\
		return false;						\
	*res = (utype)o + 1;						\
	return true;							\
}									\
static maybe_inline bool attr_unused cat(INT_unary_dec_,type)(const type *op, type *res)\
{									\
	type o = *op;							\
	if (unlikely(o == sign_bit(type)))				\
		return false;						\
	*res = (utype)o - 1;						\
	return true;							\
}

#endif


#if defined(HAVE_BUILTIN_MUL_OVERFLOW) && !defined(UNUSUAL)

#define gen_generic_multiply(type, utype)				\
static maybe_inline bool attr_unused cat(INT_binary_multiply_,type)(const type *op1, const type *op2, type *res)\
{									\
	type r;								\
	if (unlikely(__builtin_mul_overflow(*op1, *op2, &r)))		\
		return false;						\
	*res = r;							\
	return true;							\
}

#else

#define generic_multiply_(n, s, u, sz, bits)				\
	if (sz >= sizeof(unsigned) && sizeof(type) * 2 <= sz) {		\
		u lres = (u)o1 * (u)o2;					\
		if (unlikely(lres != (u)(type)lres))			\
			return false;					\
		*res = (type)(s)lres;					\
		return true;						\
	}

#define gen_generic_multiply(type, utype)				\
static maybe_inline bool attr_unused cat(INT_binary_multiply_,type)(const type *op1, const type *op2, type *res)\
{									\
	const utype half_sign = (utype)1 << (sizeof(type) * 4);		\
	type o1 = *op1, o2 = *op2;					\
	type r;								\
	for_all_fixed(generic_multiply_)				\
	r = (utype)o1 * (utype)o2;					\
	if (likely(!(((utype)(o1 + half_sign / 2) | (utype)(o2 + half_sign / 2)) & -half_sign)))\
		goto succeed;						\
	if (likely(o1 != 0)) {						\
		if (unlikely(o1 == -1) && unlikely(r == sign_bit(type)))\
			return false;					\
		if (r / o1 != o2)					\
			return false;					\
	}								\
succeed:								\
	*res = r;							\
	return true;							\
}

#endif


#define gen_generic_divmod(fn, type, utype, operator)			\
static maybe_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1 = *op1, o2 = *op2;					\
	if (unlikely(!o2))						\
		return false;						\
	if (unlikely(o2 == -1) && unlikely(o1 == sign_bit(type)))	\
		return false;						\
	if (DIVIDE_ROUNDS_TO_ZERO)	 				\
		*res = o1 operator o2;					\
	else								\
		cat4(FIXED_binary_,fn,_,type)(cast_ptr(const utype *, op1), cast_ptr(const utype *, op2), cast_ptr(utype *, res));\
	return true;							\
}

#define gen_generic_divmod_alt1(fn, type, utype)			\
static maybe_inline bool attr_unused cat4(INT_binary_,fn,_alt1_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1 = *op1, o2 = *op2;					\
	if (unlikely(!o2))						\
		return false;						\
	if (unlikely(o2 == -1) && unlikely(o1 == sign_bit(type)))	\
		return false;						\
	cat4(FIXED_binary_,fn,_alt1_,type)(cast_ptr(const utype *, op1), cast_ptr(const utype *, op2), cast_ptr(utype *, res));\
	return true;							\
}


#define gen_generic_int_power(type, utype)				\
static bool attr_unused cat(INT_binary_power_,type)(const type *op1, const type *op2, type *res)\
{									\
	type r = 1;							\
	type o1 = *op1;							\
	type o2 = *op2;							\
	if (unlikely(o2 < 0))						\
		return false;						\
	while (1) {							\
		if (o2 & 1) {						\
			if (unlikely(!cat(INT_binary_multiply_,type)(&r, &o1, &r)))\
				return false;				\
		}							\
		o2 >>= 1;						\
		if (!o2)						\
			break;						\
		if (unlikely(!cat(INT_binary_multiply_,type)(&o1, &o1, &o1)))	\
			return false;					\
	}								\
	*res = r;							\
	return true;							\
}


#define gen_generic_shr(type, utype)					\
static maybe_inline bool attr_unused cat(INT_binary_shr_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1 = *op1, o2 = *op2;					\
	type r;								\
	if (unlikely((utype)o2 >= (int)sizeof(type) * 8))		\
		return false;						\
	if (!RIGHT_SHIFT_KEEPS_SIGN)					\
		if (unlikely(o1 < 0))					\
			return false;					\
	r = o1 >> o2;							\
	*res = r;							\
	return true;							\
}

#define gen_generic_shl(type, utype)					\
static maybe_inline bool attr_unused cat(INT_binary_shl_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1 = *op1, o2 = *op2;					\
	if (unlikely((utype)o2 >= (int)sizeof(type) * 8))		\
		return false;						\
	if (sizeof(type) <= sizeof(int_efficient_t) / 2) {		\
		int_efficient_t r = (int_efficient_t)o1 << o2;		\
		if (unlikely(r != (type)r))				\
			return false;					\
		*res = (type)r;						\
		return true;						\
	} else {							\
		type r = (utype)o1 << o2;				\
		if (!RIGHT_SHIFT_KEEPS_SIGN)				\
			if (unlikely(r < 0))				\
				return false;				\
		if (unlikely(r >> o2 != o1))				\
			return false;					\
		*res = r;						\
		return true;						\
	}								\
}

#define gen_generic_btx(fn, type, utype, mode)				\
static maybe_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	if (unlikely((utype)*op2 >= sizeof(type) * 8 - 1)) {		\
		if (unlikely(*op2 < 0))					\
			return false;					\
		if (mode == 0 && *op1 < 0) {				\
			*res = *op1;					\
			return true;					\
		}							\
		if (mode == 1 && *op1 >= 0) {				\
			*res = *op1;					\
			return true;					\
		}							\
		return false;						\
	}								\
	cat4(FIXED_binary_,fn,_,type)(cast_ptr(utype *, op1), cast_ptr(const utype *, op2), cast_ptr(utype *, res));\
	return true;							\
}

#define gen_generic_bt(type, utype)					\
static maybe_inline bool attr_unused cat(INT_binary_bt_,type)(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	type o1 = *cast_ptr(type *, op1);				\
	type o2 = *cast_ptr(type *, op2);				\
	if (unlikely((utype)o2 >= sizeof(type) * 8)) {			\
		if (unlikely(o2 < 0))					\
			return false;					\
		*res = o1 < 0;						\
	} else {							\
		*res = (ajla_flat_option_t)(((utype)o1 >> o2) & 1);	\
	}								\
	return true;							\
}

#define gen_generic_not(type, utype)					\
static ipret_inline bool attr_unused cat(INT_unary_not_,type)(const type *op, type *res)\
{									\
	*res = ~(utype)*op;						\
	return true;							\
}

#define gen_generic_neg(type, utype)					\
static maybe_inline bool attr_unused cat(INT_unary_neg_,type)(const type *op, type *res)\
{									\
	type o = *op;							\
	type neg;							\
	if (!(neg_overflow_test_mode)) {				\
		if (unlikely(o == sign_bit(type)))			\
			return false;					\
		neg = -(utype)o;					\
	} else {							\
		neg = -(utype)o;					\
		if (unlikely((o & neg) < 0))				\
			return false;					\
	}								\
	*res = neg;							\
	return true;							\
}

#define gen_generic_int_bsfr(fn, type, utype, bits, mode)		\
static maybe_inline bool attr_unused cat4(INT_unary_,fn,_,type)(const type *op, type *res)\
{									\
	if (!(mode) && unlikely(!*op))					\
		return false;						\
	if ((mode) && unlikely(*op <= 0))				\
		return false;						\
	if (!(mode))							\
		cat(FIXED_unary_bsf_,type)(cast_ptr(const utype *, op), cast_ptr(utype *, res));\
	else								\
		cat(FIXED_unary_bsr_,type)(cast_ptr(const utype *, op), cast_ptr(utype *, res));\
	return true;							\
}

#define gen_generic_int_popcnt(type, utype, bits)			\
static maybe_inline bool attr_unused cat(INT_unary_popcnt_,type)(const type *op, type *res)\
{									\
	if (unlikely(*op < 0))						\
		return false;						\
	cat(FIXED_unary_popcnt_,type)(cast_ptr(const utype *, op), cast_ptr(utype *, res));\
	return true;							\
}

#define gen_generic_int_popcnt_alt1(type, utype, bits)			\
static ipret_inline bool attr_unused cat(INT_unary_popcnt_alt1_,type)(const type *op, type *res)\
{									\
	if (unlikely(*op < 0))						\
		return false;						\
	cat(FIXED_unary_popcnt_alt1_,type)(cast_ptr(const utype *, op), cast_ptr(utype *, res));\
	return true;							\
}

/*
 * X86
 */

#if defined(INLINE_ASM_GCC_X86)

#if defined(INLINE_ASM_GCC_LABELS)

	/*
	 * This is a trick. The asm goto syntax doesn't allow us to
	 * specify that the %0 register changed.
	 *
	 * We copy the variable op1 to o1 using an asm statement,
	 * so that the compiler doesn't know that *op1 == o1. We
	 * never ever reference o1 again, so the compiler won't
	 * reuse the value in the register %0.
	 */
#define gen_x86_binary(fn, type, utype, instr, suffix, c1, c2, c3)	\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1;							\
	asm_copy(o1, *op1);						\
	__asm__ goto ("							\n\
		"#instr #suffix"	%1, %0				\n\
		jo			%l[overflow]			\n\
		mov"#suffix"		%0, %2				\n\
	" : : c2(o1), c3(*op2), "m"(*res) : "memory", "cc" : overflow);	\
	return true;							\
overflow:								\
	return false;							\
}

#define gen_x86_binary_2reg(fn, type, utype, instr1, instr2, suffix, reg)\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1;							\
	asm_copy(o1, *op1);						\
	__asm__ goto ("							\n\
		"#instr1 #suffix"	%1, %%"#reg"ax			\n\
		"#instr2 #suffix"	%2, %%"#reg"dx			\n\
		jo			%l[overflow]			\n\
		mov"#suffix"		%%"#reg"ax, %3			\n\
		mov"#suffix"		%%"#reg"dx, %4			\n\
	" : : "A"(o1),							\
		"m"(*op2), "m"(*(cast_ptr(char *, op2) + sizeof(type) / 2)),\
		"m"(*res), "m"(*(cast_ptr(char *, res) + sizeof(type) / 2))\
		: "memory", "cc" : overflow);				\
	return true;							\
overflow:								\
	return false;							\
}


#else

#define gen_x86_binary(fn, type, utype, instr, suffix, c1, c2, c3)	\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type r;								\
	uint8_t overflow;						\
	__asm__ ("							\n\
		"#instr #suffix"	%2, %1				\n\
		setob			%0				\n\
	" : "=q"X86_ASM_M(overflow), c1(r) : c3(*op2), "1"(*op1) : "cc");\
	if (unlikely(overflow))						\
		return false;						\
	*res = r;							\
	return true;							\
}

#define gen_x86_binary_2reg(fn, type, utype, instr1, instr2, suffix, reg)\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type r;								\
	uint8_t overflow;						\
	__asm__ ("							\n\
		"#instr1 #suffix"	%2, %%"#reg"ax			\n\
		"#instr2 #suffix"	%3, %%"#reg"dx			\n\
		setob			%0				\n\
	" : "=q"X86_ASM_M(overflow), "=A"(r)				\
		: "m"(*op2), "m"(*(cast_ptr(char *, op2) + sizeof(type) / 2)),\
		"1"(*op1)						\
		: "memory", "cc");					\
	if (unlikely(overflow))						\
		return false;						\
	*res = r;							\
	return true;							\
}

#endif

#if defined(INLINE_ASM_GCC_LABELS)

#define gen_x86_neg(type, utype, suffix, constr)			\
static ipret_inline bool attr_unused cat(INT_unary_neg_,type)(const type *op, type *res)\
{									\
	type o;								\
	asm_copy(o, *op);						\
	__asm__ goto ("							\n\
		neg"#suffix"		%0				\n\
		jo			%l[overflow]			\n\
		mov"#suffix"		%0, %1				\n\
	" : : constr(o), "m"(*res) : "memory", "cc" : overflow);	\
	return true;							\
overflow:								\
	return false;							\
}

#define gen_x86_neg_2reg(type, utype, suffix, reg)			\
static ipret_inline bool attr_unused cat(INT_unary_neg_,type)(const type *op, type *res)\
{									\
	type o;								\
	asm_copy(o, *op);						\
	__asm__ goto ("							\n\
		neg"#suffix"		%%"#reg"ax			\n\
		not"#suffix"		%%"#reg"dx			\n\
		sbb"#suffix"		$-1, %%"#reg"dx			\n\
		jo			%l[overflow]			\n\
		mov"#suffix"		%%"#reg"ax, %1			\n\
		mov"#suffix"		%%"#reg"dx, %2			\n\
	" : : "A"(o),							\
		"m"(*res), "m"(*(cast_ptr(char *, res) + sizeof(type) / 2))\
		: "memory", "cc" : overflow);				\
	return true;							\
overflow:								\
	return false;							\
}

#define gen_x86_inc_dec(fn, type, utype, suffix, constr)		\
static ipret_inline bool attr_unused cat4(INT_unary_,fn,_,type)(const type *op, type *res)\
{									\
	type o;								\
	asm_copy(o, *op);						\
	__asm__ goto ("							\n\
		"#fn""#suffix"		%0				\n\
		jo			%l[overflow]			\n\
		mov"#suffix"		%0, %1				\n\
	" : : constr(o), "m"(*res) : "memory", "cc" : overflow);	\
	return true;							\
overflow:								\
	return false;							\
}

#endif

#endif

/*
 * ARM
 */

#if defined(INLINE_ASM_GCC_ARM) || defined(INLINE_ASM_GCC_ARM64)

#if defined(INLINE_ASM_GCC_LABELS)

#define gen_arm_addsub(fn, type, utype, instr, s)			\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1;							\
	asm_copy(o1, *op1);						\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		"#instr"		%"s"0, %"s"0, %"s"1		\n\
		bvs			%l[overflow]			\n\
		str			%"s"0, %2			\n\
	" : : "r"(o1), "r"(*op2), "m"(*res) : "memory", "cc" : overflow);\
	return true;							\
overflow:								\
	return false;							\
}

#else

#define gen_arm_addsub(fn, type, utype, instr, s)			\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type r;								\
	unsigned long overflow;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		"#instr"		%"s"1, %"s"2, %"s"3		\n\
		mrs			%0, "ARM_ASM_APSR"		\n\
	" : "=r"(overflow), "=r"(r) : "r"(*op1), "r"(*op2) : "cc");	\
	if (unlikely(overflow & (1 << 28)))				\
		return false;						\
	*res = r;							\
	return true;							\
}

#endif

#if defined(INLINE_ASM_GCC_LABELS) && defined(ARM_ASM_STRD)

#define gen_arm_addsub_2reg(fn, type, utype, instr, instr2)		\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1;							\
	asm_copy(o1, *op1);						\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		"#instr"		%"ARM_ASM_LO"0, %"ARM_ASM_LO"0, %"ARM_ASM_LO"1 \n\
		"#instr2"		%"ARM_ASM_HI"0, %"ARM_ASM_HI"0, %"ARM_ASM_HI"1 \n\
		bvs			%l[overflow]			\n\
		"ARM_ASM_STRD"		%"ARM_ASM_LO"0, %"ARM_ASM_HI"0, [ %2 ] \n\
	" : : "r"(o1), "r"(*op2), "r"(res) : "memory", "cc" : overflow);\
	return true;							\
overflow:								\
	return false;							\
}

#else

#define gen_arm_addsub_2reg(fn, type, utype, instr, instr2)		\
static ipret_inline bool attr_unused cat4(INT_binary_,fn,_,type)(const type *op1, const type *op2, type *res)\
{									\
	type r;								\
	unsigned long overflow;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		"#instr"		%"ARM_ASM_LO"1, %"ARM_ASM_LO"2, %"ARM_ASM_LO"3 \n\
		"#instr2"		%"ARM_ASM_HI"1, %"ARM_ASM_HI"2, %"ARM_ASM_HI"3 \n\
		mrs			%0, "ARM_ASM_APSR"		\n\
	" : "=r"(overflow), "=r"(r) : "1"(*op1), "r"(*op2) : "cc");	\
	if (unlikely(overflow & (1 << 28)))				\
		return false;						\
	*res = r;							\
	return true;							\
}

#endif

#if defined(INLINE_ASM_GCC_LABELS) && ARM_VERSION >= 6

#define gen_arm_multiply(type, utype)					\
static ipret_inline bool attr_unused cat(INT_binary_multiply_,type)(const type *op1, const type *op2, type *res)\
{									\
	type o1, o2;							\
	asm_copy(o1, *op1);						\
	asm_copy(o2, *op2);						\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		smull			%0, %1, %0, %1			\n\
		cmp			%1, %0, asr #31			\n\
		bne			%l[overflow]			\n\
		str			%0, %2				\n\
	" : : "r"(o1), "r"(o2), "m"(*res) : "memory", "cc" : overflow);	\
	return true;							\
overflow:								\
	return false;							\
}

#else

#define gen_arm_multiply(type, utype)					\
static ipret_inline bool attr_unused cat(INT_binary_multiply_,type)(const type *op1, const type *op2, type *res)\
{									\
	uint32_t r, overflow;						\
	__asm__ (ARM_ASM_PREFIX "					\n\
		smull			%0, %1, %2, %3			\n\
		eor			%1, %1, %0, asr #31		\n\
	" : "=&r"(r), "=&r"(overflow) : "r"(*op1), "r"(*op2));		\
	if (unlikely(overflow != 0))					\
		return false;						\
	*res = r;							\
	return true;							\
}

#endif

#if defined(INLINE_ASM_GCC_LABELS)

#define gen_arm_neg(type, utype, s)					\
static ipret_inline bool attr_unused cat(INT_unary_neg_,type)(const type *op, type *res)\
{									\
	type o;								\
	asm_copy(o, *op);						\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		negs			%"s"0, %"s"0			\n\
		bvs			%l[overflow]			\n\
		str			%"s"0, %1			\n\
	" : : "r"(o), "m"(*res) : "memory", "cc" : overflow);		\
	return true;							\
overflow:								\
	return false;							\
}

#if defined(INLINE_ASM_GCC_ARM64)
#define arm_neg_2nd	"ngcs		%"ARM_ASM_HI"0, %"ARM_ASM_HI"0"
#define arm_neg_zreg
#elif defined(INLINE_ASM_GCC_ARM_THUMB2)
#define arm_neg_2nd	"sbcs		%"ARM_ASM_HI"0, %2, %"ARM_ASM_HI"0"
#define arm_neg_zreg	, "r"(0L)
#else
#define arm_neg_2nd	"rscs		%"ARM_ASM_HI"0, %"ARM_ASM_HI"0, #0"
#define arm_neg_zreg
#endif

#define gen_arm_neg_2reg(type, utype)					\
static ipret_inline bool attr_unused cat(INT_unary_neg_,type)(const type *op, type *res)\
{									\
	type o;								\
	asm_copy(o, *op);						\
	__asm__ goto (ARM_ASM_PREFIX "					\n\
		negs			%"ARM_ASM_LO"0, %"ARM_ASM_LO"0	\n\
		"arm_neg_2nd"						\n\
		bvs			%l[overflow]			\n\
		"ARM_ASM_STRD"		%"ARM_ASM_LO"0, %"ARM_ASM_HI"0, [ %1 ] \n\
	" : : "r"(o), "r"(res) arm_neg_zreg : "memory", "cc" : overflow);\
	return true;							\
overflow:								\
	return false;							\
}

#endif

#endif

#ifdef FIXED_DIVIDE_ALT1_TYPES
#define INT_DIVIDE_ALT1_TYPES		FIXED_DIVIDE_ALT1_TYPES
#define INT_DIVIDE_ALT1_FEATURES	FIXED_DIVIDE_ALT1_FEATURES
#endif
#ifdef FIXED_MODULO_ALT1_TYPES
#define INT_MODULO_ALT1_TYPES		FIXED_MODULO_ALT1_TYPES
#define INT_MODULO_ALT1_FEATURES	FIXED_MODULO_ALT1_FEATURES
#endif
#ifdef FIXED_POPCNT_ALT1_TYPES
#define INT_POPCNT_ALT1_TYPES		FIXED_POPCNT_ALT1_TYPES
#define INT_POPCNT_ALT1_FEATURES	FIXED_POPCNT_ALT1_FEATURES
#endif

#define file_inc "arithm-i.inc"
#include "for-int.inc"

#endif
