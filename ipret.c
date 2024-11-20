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

#ifndef FILE_OMIT

#include "mem_al.h"
#include "data.h"
#include "array.h"
#include "code-op.h"
#include "funct.h"
#include "arithm-b.h"
#include "arithm-i.h"
#include "arithm-r.h"
#include "tick.h"
#include "task.h"
#include "ipfn.h"
#include "ipio.h"
#include "util.h"
#include "os.h"
#include "codegen.h"

#include "ipret.h"

#if defined(HAVE_COMPUTED_GOTO) && !defined(DEBUG_TRACE)
#define COMPUTED_GOTO
/*#define COMPUTED_GOTO_RELATIVE*/
#endif

#if defined(C_LITTLE_ENDIAN)
#define get_lo(p)	(((const unsigned char *)(p))[0])
#elif defined(C_BIG_ENDIAN)
#define get_lo(p)	(((const unsigned char *)(p))[1])
#else
#define get_lo(p)	(*(p) & 0xff)
#endif

#if defined(C_LITTLE_ENDIAN)
#define get_hi(p)	(((const unsigned char *)(p))[1])
#elif defined(C_BIG_ENDIAN)
#define get_hi(p)	(((const unsigned char *)(p))[0])
#else
#define get_hi(p)	(*(p) >> 8)
#endif

#define ADVANCE_IP(n)		(ip += (n))


#define op_add(type, utype, op1, op2)		op1 + op2
#define op_subtract(type, utype, op1, op2)	op1 - op2
#define op_multiply(type, utype, op1, op2)	op1 * op2
#define op_divide(type, utype, op1, op2)	op1 / op2
/* EMX has a bug - fmod doesn't return NaN */
#if defined(_MSC_VER)
#define op_modulo(type, utype, op1, op2)	(!isnan_any(type, op1, op2) && cat(isfinite_,type)(op1) && !cat(isfinite_,type)(op2) ? op1 :\
						!isnan_any(type, op1, op2) && op1 == 0 && op2 != 0 ? op1 :\
						cat(mathfunc_,type)(fmod)(op1, op2))
#elif defined(HAVE_BUGGY_FMOD)
#define op_modulo(type, utype, op1, op2)	(op2 == 0 ? 0./0. : cat(mathfunc_,type)(fmod)(op1, op2))
#else
#define op_modulo(type, utype, op1, op2)	cat(mathfunc_,type)(fmod)(op1, op2)
#endif
#define op_atan2(type, utype, op1, op2)		cat(mathfunc_,type)(atan2)(op1, op2)
#define op_and(type, utype, op1, op2)		op1 & op2
#define op_or(type, utype, op1, op2)		op1 | op2
#define op_xor(type, utype, op1, op2)		op1 ^ op2
#define op_shl(type, utype, op1, op2)		op1 << (op2 & (sizeof(utype) * 8 - 1))
#define op_shr(type, utype, op1, op2)					\
	RIGHT_SHIFT_KEEPS_SIGN || (type)op1 >= 0 ?			\
		(utype)((type)op1 >> (op2 & (sizeof(utype) * 8 - 1)))	\
	:								\
		~(~(utype)op1 >> (op2 & (sizeof(utype) * 8 - 1)))
#define op_ushr(type, utype, op1, op2)		op1 >> (op2 & (sizeof(utype) * 8 - 1))
#define op_equal(type, utype, op1, op2)		op1 == op2
#define op_not_equal(type, utype, op1, op2)	op1 != op2
#define op_less(type, utype, op1, op2)		(type)op1 < (type)op2
#define op_less_equal(type, utype, op1, op2)	(type)op1 <= (type)op2
#define op_greater(type, utype, op1, op2)	(type)op1 > (type)op2
#define op_greater_equal(type, utype, op1, op2)	(type)op1 >= (type)op2
#define op_uless(type, utype, op1, op2)		op1 < op2
#define op_uless_equal(type, utype, op1, op2)	op1 <= op2
#define op_ugreater(type, utype, op1, op2)	op1 > op2
#define op_ugreater_equal(type, utype, op1, op2) op1 >= op2
#define op_not(type, utype, op1)		~op1
#define op_neg(type, utype, op1)		-op1
#define op_sqrt(type, utype, op1)		cat(mathfunc_,type)(sqrt)(op1)
#define op_cbrt(type, utype, op1)		cat(mathfunc_,type)(cbrt)(op1)
#define op_sin(type, utype, op1)		cat(mathfunc_,type)(sin)(op1)
#define op_cos(type, utype, op1)		cat(mathfunc_,type)(cos)(op1)
#define op_tan(type, utype, op1)		cat(mathfunc_,type)(tan)(op1)
#define op_asin(type, utype, op1)		cat(mathfunc_,type)(asin)(op1)
#define op_acos(type, utype, op1)		cat(mathfunc_,type)(acos)(op1)
#define op_atan(type, utype, op1)		cat(mathfunc_,type)(atan)(op1)
#define op_sinh(type, utype, op1)		cat(mathfunc_,type)(sinh)(op1)
#define op_cosh(type, utype, op1)		cat(mathfunc_,type)(cosh)(op1)
#define op_tanh(type, utype, op1)		cat(mathfunc_,type)(tanh)(op1)
#define op_asinh(type, utype, op1)		cat(mathfunc_,type)(asinh)(op1)
#define op_acosh(type, utype, op1)		cat(mathfunc_,type)(acosh)(op1)
#define op_atanh(type, utype, op1)		cat(mathfunc_,type)(atanh)(op1)
#define op_exp2(type, utype, op1)		cat(mathfunc_,type)(exp2)(op1)
#define op_exp(type, utype, op1)		cat(mathfunc_,type)(exp)(op1)
#define op_exp10(type, utype, op1)		cat(mathfunc_,type)(exp10)(op1)
#define op_log2(type, utype, op1)		cat(mathfunc_,type)(log2)(op1)
#define op_log(type, utype, op1)		cat(mathfunc_,type)(log)(op1)
#define op_log10(type, utype, op1)		cat(mathfunc_,type)(log10)(op1)
#define op_round(type, utype, op1)		cat(mathfunc_,type)(rint)(op1)
#define op_ceil(type, utype, op1)		cat(mathfunc_,type)(ceil)(op1)
#define op_floor(type, utype, op1)		cat(mathfunc_,type)(floor)(op1)
#define op_trunc(type, utype, op1)		cat(mathfunc_,type)(trunc)(op1)
#define op_fract(type, utype, op1)		cat(mathfunc_,type)(fract)(op1)
#define op_mantissa(type, utype, op1)		cat(mathfunc_,type)(mantissa)(op1)
#define op_exponent(type, utype, op1)		cat(mathfunc_,type)(exponent)(op1)

#define generate_fixed_binary(type, utype, op)				\
static ipret_inline bool cat4(FIXED_binary_,op,_,type)			\
				(const utype *op1, const utype *op2, utype *res)\
{									\
	*(utype *)res = cat(op_,op)(type, utype, (*(const utype *)op1), (*(const utype *)op2));\
	return true;							\
}

#define generate_fixed_binary_logical(type, utype, op)			\
static ipret_inline bool cat4(FIXED_binary_,op,_,type)			\
				(const utype *op1, const utype *op2, ajla_flat_option_t *res)\
{									\
	*(ajla_flat_option_t *)res = cat(op_,op)(type, utype, (*(const utype *)op1), (*(const utype *)op2));\
	return true;							\
}

#define generate_fixed_unary(type, utype, op)				\
static ipret_inline void cat4(FIXED_unary_,op,_,type)			\
				(const utype *op1, utype *res)		\
{									\
	*(utype *)res = cat(op_,op)(type, utype, (*(utype *)op1));	\
}

#define generate_fixed_ldc(type, utype, sz, bits)			\
static ipret_inline ip_t cat(fixed_ldc_,type)				\
				(utype *res, const code_t *ip, bool small)\
{									\
	if (small && sz > 2) {						\
		*res = (utype)(int16_t)ip[0];				\
		return 1;						\
	}								\
	*res = (utype)cat(get_unaligned_,bits)(ip);			\
	return (sz + 1) / 2;						\
}

#define generate_fixed_functions(n, type, utype, sz, bits)		\
generate_fixed_binary(type, utype, add)					\
generate_fixed_binary(type, utype, subtract)				\
generate_fixed_binary(type, utype, multiply)				\
generate_fixed_binary(type, utype, and)					\
generate_fixed_binary(type, utype, or)					\
generate_fixed_binary(type, utype, xor)					\
generate_fixed_binary(type, utype, shl)					\
generate_fixed_binary(type, utype, shr)					\
generate_fixed_binary(type, utype, ushr)				\
generate_fixed_binary_logical(type, utype, equal)			\
generate_fixed_binary_logical(type, utype, not_equal)			\
generate_fixed_binary_logical(type, utype, less)			\
generate_fixed_binary_logical(type, utype, less_equal)			\
generate_fixed_binary_logical(type, utype, greater)			\
generate_fixed_binary_logical(type, utype, greater_equal)		\
generate_fixed_binary_logical(type, utype, uless)			\
generate_fixed_binary_logical(type, utype, uless_equal)			\
generate_fixed_binary_logical(type, utype, ugreater)			\
generate_fixed_binary_logical(type, utype, ugreater_equal)		\
generate_fixed_unary(type, utype, not)					\
generate_fixed_unary(type, utype, neg)					\
generate_fixed_ldc(type, utype, sz, bits)
for_all_fixed(generate_fixed_functions)
#undef generate_fixed_functions


#define generate_int_binary(type, utype, op, operator)			\
static ipret_inline bool						\
	cat4(INT_binary_,op,_,type)(const void *op1, const void *op2, void *res)\
{									\
	*cast_ptr(type *, res) =					\
		*cast_ptr(const type *, op1) operator			\
		*cast_ptr(const type *, op2);				\
	return true;							\
}

#define generate_int_binary_logical(type, utype, op, operator)		\
static ipret_inline bool						\
	cat4(INT_binary_,op,_,type)(const void *op1, const void *op2, ajla_flat_option_t *res)\
{									\
	*res = *cast_ptr(const type *, op1) operator			\
		*cast_ptr(const type *, op2);				\
	return true;							\
}

#define generate_int_ldc(type, utype, bits)				\
static ipret_inline ip_t cat(int_ldc_,type)				\
				(type *res, const code_t *ip, bool small)\
{									\
	return cat(fixed_ldc_,type)(cast_ptr(utype *, res), ip, small);	\
}


#define generate_int_functions(typeid, type, utype, sz, bits)		\
generate_int_binary(type, utype, and, &)				\
generate_int_binary(type, utype, or, |)					\
generate_int_binary(type, utype, xor, ^)				\
generate_int_binary_logical(type, utype, equal, ==)			\
generate_int_binary_logical(type, utype, not_equal, !=)			\
generate_int_binary_logical(type, utype, less, <)			\
generate_int_binary_logical(type, utype, less_equal, <=)		\
generate_int_binary_logical(type, utype, greater, >)			\
generate_int_binary_logical(type, utype, greater_equal, >=)		\
generate_int_ldc(type, utype, bits)
for_all_int(generate_int_functions, for_all_empty)
#undef generate_int_binary_functions


#if defined(use_is_macros)
#ifdef HAVE_REAL_GNUC
#define isnan_any(type, a, b)	(unlikely(isunordered(b, a)))
#else
#define isnan_any(type, a, b)	(unlikely(isunordered(a, b)))
#endif
#else
#define isnan_any(type, a, b)	(unlikely(cat(isnan_,type)(a)) || unlikely(cat(isnan_,type)(b)))
#endif

#if REAL_MASK & 0x1
static attr_always_inline bool do_nextafter_real16_t(real16_t attr_unused x, int attr_unused dir, real16_t attr_unused *res)
{
	return false;
}
#endif

#if REAL_MASK & 0x2
static attr_always_inline bool do_nextafter_real32_t(real32_t attr_unused x, int attr_unused dir, real32_t attr_unused *res)
{
#ifdef HAVE_NEXTAFTERF
	*res = nextafterf(x, HUGE_VALF * dir);
	return true;
#else
	return false;
#endif
}
#endif

#if REAL_MASK & 0x4
static attr_always_inline bool do_nextafter_real64_t(real64_t attr_unused x, int attr_unused dir, real64_t attr_unused *res)
{
#ifdef HAVE_NEXTAFTER
	*res = nextafter(x, HUGE_VAL * dir);
	return true;
#else
	return false;
#endif
}
#endif

#if REAL_MASK & 0x8
static attr_always_inline bool do_nextafter_real80_t(real80_t attr_unused x, int dir, real80_t attr_unused *res)
{
#ifdef HAVE_NEXTAFTERL
	*res = nextafterl(x, HUGE_VALL * dir);
	return true;
#else
	return false;
#endif
}
#endif

#if REAL_MASK & 0x10
static attr_always_inline bool do_nextafter_real128_t(real128_t attr_unused x, int dir, real128_t attr_unused *res)
{
#ifndef HAVE_NATIVE_FLOAT128
#ifdef HAVE_NEXTAFTERL
	*res = nextafterl(x, HUGE_VALL * dir);
	return true;
#else
	return false;
#endif
#else
	*res = nextafterq(x, HUGE_VAL * dir);
	return true;
#endif
}
#endif

#define generate_real_binary(type, ntype, pack, unpack, op)		\
static ipret_inline bool cat4(REAL_binary_,op,_,type)			\
				(const type *op1, const type *op2, type *res)\
{									\
	*res = pack(cat(op_,op)(ntype, ntype, (unpack(*op1)), (unpack(*op2))));\
	return true;							\
}

#define generate_real_binary_logical(type, ntype, pack, unpack, op)	\
static ipret_inline bool cat4(REAL_binary_,op,_,type)			\
				(const type *op1, const type *op2, ajla_flat_option_t *res)\
{									\
	ntype o1 = unpack(*op1);					\
	ntype o2 = unpack(*op2);					\
	if (isnan_any(ntype, o1, o2))					\
		return false;						\
	*res = cat(op_real_,op)(ntype, ntype, o1, o2);			\
	return true;							\
}

#define generate_real_unary(n, type, ntype, pack, unpack, op, op_n)	\
static ipret_inline void cat4(REAL_unary_,op,_,type)			\
				(const type *op1, type *res)		\
{									\
	if (!n && REAL16_T_IS_UINT16_T) {				\
		if (!op_n) {						\
			*(uint16_t *)res = *(uint16_t *)op1 ^ 0x8000U;	\
			return;						\
		}							\
	}								\
	*res = pack(cat(op_,op)(type, type, (unpack(*op1))));		\
}

/* EMX has a bug - modf(infinity) return NaN instead of 0. */
#ifdef HAVE_BUGGY_MODF
#define need_modf_hack true
#else
#define need_modf_hack false
#endif

#define generate_real_fns(n, type, ntype, pack, unpack)			\
static ipret_inline bool cat(REAL_binary_power_,type)			\
				(const type *op1, const type *op2, type *res)\
{									\
	ntype o1 = unpack(*op1);					\
	ntype o2 = unpack(*op2);					\
	ntype r;							\
	if (unlikely(isnan_any(ntype, o1, o2)))				\
		return false;						\
	r = cat(mathfunc_,type)(pow)(o1, o2);				\
	*res = pack(r);							\
	return true;							\
}									\
static ipret_inline bool cat(REAL_binary_ldexp_,type)			\
				(const type *op1, const type *op2, type *res)\
{									\
	ntype m;							\
	ntype o1 = unpack(*op1);					\
	ntype o2 = unpack(*op2);					\
	if (unlikely(isnan_any(ntype, o1, o2)))				\
		return false;						\
	if (likely(o2 >= (ntype)sign_bit(int)) && likely(o2 <= (ntype)signed_maximum(int)) && likely(o2 == (int)o2)) {\
		*res = pack(cat(mathfunc_,type)(ldexp)(o1, (int)o2));	\
	} else {							\
		m = cat(mathfunc_,type)(exp2)(o2);			\
		m *= o1;						\
		*res = pack(m);						\
	}								\
	return true;							\
}									\
static ipret_inline void cat(REAL_unary_fract_,type)			\
				(const type *op1, type *res)		\
{									\
	ntype m = unpack(*op1);						\
	union {								\
		ntype i;						\
		float f;						\
	} u;								\
	if (need_modf_hack) {						\
		if (likely(!cat(isnan_,ntype)(m)) && unlikely(!cat(isfinite_,ntype)(m))) {\
			*res = pack(m >= 0 ? 0. : -0.);			\
			return;						\
		}							\
	}								\
	*res = pack(cat(mathfunc_,type)(modf)(m, (void *)&u));		\
}									\
static ipret_inline void cat(REAL_unary_mantissa_,type)			\
				(const type *op1, type *res)		\
{									\
	int i;								\
	*res = pack(cat(mathfunc_,type)(frexp)(unpack(*op1), &i));	\
}									\
static ipret_inline void cat(REAL_unary_exponent_,type)			\
				(const type *op1, type *res)		\
{									\
	int i;								\
	ntype m = cat(mathfunc_,type)(frexp)(unpack(*op1), &i);		\
	if (unlikely(cat(isnan_,ntype)(m))) {				\
		*res = pack(m);						\
		return;							\
	}								\
	if (unlikely(!cat(isfinite_,ntype)(m))) {			\
		*res = pack((ntype)0.);					\
		return;							\
	}								\
	*res = pack((ntype)i);						\
}									\
static ipret_inline type cat(REAL_unary_next_prev_number_,type)		\
				(type op1, int dir)			\
{									\
	int ex, bit;							\
	volatile ntype m, mm, n1;					\
	volatile type res, o;						\
	if (unlikely(cat(isnan_,type)(op1)))				\
		return op1;						\
	n1 = unpack(op1);						\
	if (unlikely(!cat(isfinite_,type)(op1))) {			\
		if ((n1 >= 0) == (dir >= 0))				\
			return op1;					\
		m = cat(mathfunc_,ntype)(ldexp)(1, cat(bits_,type)) - 1;\
		while (1) {						\
			mm = m * 2;					\
			res = pack(mm);					\
			if (unlikely(!cat(isfinite_,type)(res)))	\
				break;					\
			m = mm;						\
		}							\
		return pack(m * -dir);					\
	}								\
	if (unlikely(!n1)) {						\
		res = pack(1);						\
		o = pack(1);						\
		while (1) {						\
			o = pack(unpack(o) * 0.5);			\
			m = unpack(o);					\
			if (m == 0)					\
				break;					\
			res = o;					\
		}							\
		return pack(unpack(res) * dir);				\
	}								\
	m = cat(mathfunc_,type)(frexp)(n1, &ex);			\
	bit = cat(bits_,type);						\
again:									\
	mm = m + cat(mathfunc_,ntype)(ldexp)(dir, -bit);		\
	o = pack(cat(mathfunc_,ntype)(ldexp)(mm, ex));			\
	res = o;							\
	if (unpack(res) == n1) {					\
		bit--;							\
		goto again;						\
	}								\
	return res;							\
}									\
static ipret_inline void cat(REAL_unary_next_number_,type)		\
				(const type *op1, type *res)		\
{									\
	if (cat(do_nextafter_,type)(*op1, 1, res))			\
		return;							\
	*res = cat(REAL_unary_next_prev_number_,type)(*op1, 1);		\
}									\
static ipret_inline void cat(REAL_unary_prev_number_,type)		\
				(const type *op1, type *res)		\
{									\
	if (cat(do_nextafter_,type)(*op1, -1, res))			\
		return;							\
	*res = cat(REAL_unary_next_prev_number_,type)(*op1, -1);	\
}

#define generate_real_unary_logical(n, type, ntype, pack, unpack, op, op_n)\
static ipret_inline void cat4(REAL_unary_,op,_,type)			\
				(const type *op1, ajla_flat_option_t *res)\
{									\
	*res = cat(isnan_,type)(*op1);					\
}

#define op_real_equal					op_equal
#if defined(use_is_macros) && defined(ARCH_X86)
#define op_real_not_equal(type, utype, op1, op2)	islessgreater(op1, op2)
#else
#define op_real_not_equal				op_not_equal
#endif
#if defined(use_is_macros)
#define op_real_less(type, utype, op1, op2)		isless(op1, op2)
#else
#define op_real_less					op_less
#endif
#if defined(use_is_macros)
#define op_real_less_equal(type, utype, op1, op2)	islessequal(op1, op2)
#else
#define op_real_less_equal				op_less_equal
#endif
#if defined(use_is_macros)
#define op_real_greater(type, utype, op1, op2)		isgreater(op1, op2)
#else
#define op_real_greater					op_greater
#endif
#if defined(use_is_macros)
#define op_real_greater_equal(type, utype, op1, op2)	isgreaterequal(op1, op2)
#else
#define op_real_greater_equal				op_greater_equal
#endif

#define generate_real_ldc(n, rtype, ntype, pack, unpack)		\
static ipret_inline size_t cat(fixed_ldc_,rtype)			\
			(rtype *res, const code_t *ip, bool attr_unused shrt)\
{									\
	memcpy(res, ip, sizeof(rtype));					\
	return round_up(sizeof(rtype), sizeof(code_t)) / sizeof(code_t);\
}

#define generate_real_int(type, ntype, pack, unpack)			\
static ipret_inline bool cat(REAL_unary_to_int_,type)(const type *val, int_default_t *r)\
{									\
	ntype val1;							\
	val1 = unpack(*val);						\
	if (likely(val1 > (ntype)sign_bit(int_default_t)) && likely(val1 < (ntype)signed_maximum(int_default_t))) {\
		*r = val1;						\
		return true;						\
	}								\
	return false;							\
}									\
static ipret_inline void cat(REAL_unary_from_int_,type)(const int_default_t *val, type *r)\
{									\
	*r = pack(*val);						\
}

#define generate_real_functions(n, type, ntype, pack, unpack)		\
generate_real_binary(type, ntype, pack, unpack, add)			\
generate_real_binary(type, ntype, pack, unpack, subtract)		\
generate_real_binary(type, ntype, pack, unpack, multiply)		\
generate_real_binary(type, ntype, pack, unpack, divide)			\
generate_real_binary(type, ntype, pack, unpack, modulo)			\
generate_real_binary(type, ntype, pack, unpack, atan2)			\
generate_real_binary_logical(type, ntype, pack, unpack, equal)		\
generate_real_binary_logical(type, ntype, pack, unpack, not_equal)	\
generate_real_binary_logical(type, ntype, pack, unpack, less)		\
generate_real_binary_logical(type, ntype, pack, unpack, less_equal)	\
generate_real_binary_logical(type, ntype, pack, unpack, greater)	\
generate_real_binary_logical(type, ntype, pack, unpack, greater_equal)	\
generate_real_unary(n, type, ntype, pack, unpack, neg, 0)		\
generate_real_unary(n, type, ntype, pack, unpack, sqrt, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, cbrt, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, sin, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, cos, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, tan, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, asin, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, acos, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, atan, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, sinh, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, cosh, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, tanh, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, asinh, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, acosh, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, atanh, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, exp2, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, exp, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, exp10, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, log2, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, log, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, log10, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, round, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, ceil, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, floor, 1)		\
generate_real_unary(n, type, ntype, pack, unpack, trunc, 1)		\
generate_real_fns(n, type, ntype, pack, unpack)				\
generate_real_int(type, ntype, pack, unpack)				\
generate_real_unary_logical(n, type, ntype, pack, unpack, is_exception, 0)\
generate_real_ldc(n, type, ntype, pack, unpack)

for_all_real(generate_real_functions, for_all_empty)
#undef generate_real_functions


static inline frame_s *frame_build(frame_s *fp, struct data *function, ajla_error_t *mayfail)
{
	frame_t new_frame_slots = da(function,function)->frame_slots;
	if (likely(new_frame_slots <= get_frame(fp)->available_slots)) {
		frame_s *new_fp = cast_ptr(frame_s *, cast_ptr(char *, fp) - new_frame_slots * slot_size);
		get_frame(new_fp)->available_slots = get_frame(fp)->available_slots - new_frame_slots;
		get_frame(new_fp)->function = function;
		return new_fp;
	} else {
		return stack_expand(fp, function, mayfail);
	}
}


#define ipret_checkpoint_forced						\
do {									\
	void *ex_ = ipret_tick(fp, ip);					\
	RELOAD_EX_POSITION(ex_);					\
} while (0)


#define OPCODE_ARG_MODE(opcode)	((opcode) + ARG_MODE * OPCODE_MODE_MULT)

#define EMIT_FUNCTIONS
#include "ipret.inc"

void attr_hot_fastcall run(frame_s *fp_, ip_t ip_)
{
	ajla_error_t ajla_error;
	tick_stamp_t ts;
#if defined(DEBUG) && !defined(COMPUTED_GOTO)
	const code_t *last_stack[20];
#endif

	register frame_s *fp
#if ((defined(INLINE_ASM_GCC_I386) && !defined(__PIC__)) || defined(INLINE_ASM_GCC_X32)) && defined(__OPTIMIZE__) && defined(HAVE_REAL_GNUC)
	/*
	 * GCC usually uses ebp for the variable fp. It is bad choice because
	 * ebp can't be used as a base register without immediate offset. So,
	 * the assembler adds offset 0 to every instruction using ebp as base.
	 * Doing two additions and one shift in one instruction is too much and
	 * it causes performance drop on both Intel and AMD architectures.
	 */
		__asm__("ebx")
#endif
#if defined(INLINE_ASM_GCC_X86_64) && defined(__OPTIMIZE__) && defined(HAVE_REAL_GNUC)
		/*__asm__("rbx")*/
#endif
#if defined(INLINE_ASM_GCC_ARM_THUMB2) && defined(__OPTIMIZE__) && defined(HAVE_REAL_GNUC)
		/* peg this to a register in lower bank to reduce code size and improve performance */
		__asm__("r6")
#endif
		;
	register const code_t *ip
#if defined(INLINE_ASM_GCC_ARM_THUMB2) && defined(__OPTIMIZE__) && defined(HAVE_REAL_GNUC) && 0
		/* don't use it for now, it causes too much register pressure */
		__asm__("r5")
#endif
		;
	code_t code;

#ifdef COMPUTED_GOTO
	const void *next_label;
#ifdef COMPUTED_GOTO_RELATIVE
	static const int dispatch[OPCODE_MODE_MULT * ARG_MODE_N - (OPCODE_MODE_MULT - OPCODE_N)] = {
#define DEFINE_OPCODE_START_LBL(opcode, lbl)			\
		[OPCODE_ARG_MODE(opcode)] = (const char *)&&cat(label_,lbl) - (const char *)&&label_unknown,
#else
	static const void *dispatch[OPCODE_MODE_MULT * ARG_MODE_N - (OPCODE_MODE_MULT - OPCODE_N)] = {
#define DEFINE_OPCODE_START_LBL(opcode, lbl)			\
		[OPCODE_ARG_MODE(opcode)] = &&cat(label_,lbl),
#endif
#include "ipret.inc"
#ifdef COMPUTED_GOTO_RELATIVE
	};
#else
	};
#endif
#endif

#if defined(DEBUG) && !defined(COMPUTED_GOTO)
	memset(last_stack, 0, sizeof last_stack);
#endif

	fp = fp_;
	ip = &da(get_frame(fp)->function,function)->code[ip_];
	tick_start(&ts);

#define RELOAD_EX_POSITION(ex)					\
do {								\
	if ((ex) != POINTER_FOLLOW_THUNK_EXIT) {		\
		ajla_assert((ex) != POINTER_FOLLOW_THUNK_RETRY && (ex) != POINTER_FOLLOW_THUNK_EXCEPTION && (ex) != POINTER_FOLLOW_THUNK_GO, (file_line, "RELOAD_EX_POSITION: invalid pointer: %p", (ex)));\
		fp = cast_ptr(struct execution_control *, (ex))->current_frame;\
		ip = da(get_frame(fp)->function,function)->code + cast_ptr(struct execution_control *, (ex))->current_ip;\
		tick_start(&ts);				\
		goto next_code;					\
	} else {						\
		goto exit_ipret;				\
	}							\
} while (0)

#ifdef COMPUTED_GOTO

#ifdef COMPUTED_GOTO_RELATIVE
#define GOTO_NEXT(opcode)					\
	code = *ip;						\
	next_label = (const char *)&&label_unknown + dispatch[code & OPCODE_MASK];\
	ASM_PREVENT_JOIN(OPCODE_ARG_MODE(opcode));		\
	goto *(void *)next_label;
#else
#define GOTO_NEXT(opcode)					\
	code = *ip;						\
	next_label = dispatch[code & OPCODE_MASK];		\
	ASM_PREVENT_JOIN(OPCODE_ARG_MODE(opcode));		\
	goto *(void *)next_label;
#endif

	next_code:
#define ARG_MODE 0
	GOTO_NEXT(-1);
#undef ARG_MODE

#define EMIT_CODE
#define START_BLOCK(declarations)				{ declarations
#define END_BLOCK()						}
#define DEFINE_LABEL(lbl, code)					\
	lbl: do {						\
		code						\
	} while (0);						\
	GOTO_NEXT(-2);
#define DEFINE_OPCODE_START_LBL(opcode, lbl)			\
	cat(label_,lbl): do {
#define DEFINE_OPCODE_END(opcode)				\
	} while (0);						\
	GOTO_NEXT(OPCODE_ARG_MODE(opcode));
#include "ipret.inc"

#ifdef COMPUTED_GOTO_RELATIVE
	label_unknown:
		internal(file_line, "run: invalid opcode %04x", (int)code);
#endif

#else
	next_code:
	code = *ip;
#if defined(DEBUG) && !defined(COMPUTED_GOTO)
	memmove(last_stack + 1, last_stack, (sizeof last_stack) - sizeof(*last_stack));
	last_stack[0] = ip;
#endif
#ifdef DEBUG_TRACE
	if (unlikely(load_relaxed(&trace_enabled))) {
		struct stack_trace st;
		const char *fn = "";
		unsigned ln = 0;
		stack_trace_capture(&st, fp, ip, 1);
		if (st.trace_n >= 1) {
			fn = st.trace[0].function_name;
			ln = st.trace[0].line;
		}
#define xip(n)	(frame_ip(fp, ip) + n >= da(get_frame(fp)->function,function)->code_size ? 0xffff : ip[n])
		trace("%-24s %-5u %-32s at %u %p %p %04x %04x %04x %04x %04x %04x %04x %04x", fn, ln, decode_opcode(code, true), frame_ip(fp, ip), fp, frame_execution_control(fp), xip(1), xip(2), xip(3), xip(4), xip(5), xip(6), xip(7), xip(8));
#undef xip
		stack_trace_free(&st);
	}
#endif
	switch (code & OPCODE_MASK) {
#define EMIT_CODE
#define START_BLOCK(declarations)				{ declarations
#define END_BLOCK()						}
#define DEFINE_LABEL(lbl, code)					\
	lbl: {							\
			code					\
		}						\
		break;
#define DEFINE_OPCODE_START_LBL(opcode, lbl)			\
	case OPCODE_ARG_MODE(opcode): {
#define DEFINE_OPCODE_END(opcode)				\
		}						\
		break;
#include "ipret.inc"
		default:
#if defined(HAVE___BUILTIN_UNREACHABLE) && !defined(DEBUG)
			__builtin_unreachable();
#else
			{
				ip_t l = ip - da(get_frame(fp)->function,function)->code;
				ip_t x;
				for (x = 0; x <= l; x++) {
					code_t v = da(get_frame(fp)->function,function)->code[x];
					const char *opc = decode_opcode(v, true);
					char c = ' ';
#if defined(DEBUG) && !defined(COMPUTED_GOTO)
					size_t lso;
					for (lso = 0; lso < n_array_elements(last_stack); lso++)
						if (&da(get_frame(fp)->function,function)->code[x] == last_stack[lso])
							c = '*';
#endif
					if (opc)
						debug("%c %04x (%s)", c, v, opc);
					else
						debug("%c %04x", c, v);
				}
				internal(file_line, "run: invalid opcode %04x (mode %x, int %x, real %x, bool %x, extra %x)", code, OPCODE_MODE_MULT, OPCODE_INT_OP, OPCODE_REAL_OP, OPCODE_BOOL_OP, OPCODE_EXTRA);
			}
#endif
	}
	goto next_code;
#endif

exit_ipret:;
}


#ifdef HAVE_CODEGEN

static void cg_upcall_mem_copy(void *dest, const void *src, size_t size)
{
	memcpy(dest, src, size);
}

static void cg_upcall_mem_clear(void *ptr, size_t len)
{
	memset(ptr, 0, len);
}

static void cg_upcall_pointer_dereference(pointer_t_upcall ptr)
{
	pointer_dereference(ptr);
}

static void cg_upcall_pointer_reference_owned(pointer_t_upcall ptr)
{
	pointer_reference_owned(ptr);
}

static pointer_t cg_upcall_flat_to_data(frame_s *fp, uintptr_t slot, const unsigned char *flat)
{
	const struct type *type = frame_get_type_of_local(fp, slot);
	return flat_to_data(type, flat);
}

static unsigned char *cg_upcall_data_alloc_function_reference_mayfail(uintptr_t n_curried_arguments)
{
	ajla_error_t sink;
	return cast_ptr(unsigned char *, data_alloc_function_reference_mayfail(n_curried_arguments, &sink pass_file_line));
}

static unsigned char *cg_upcall_data_alloc_record_mayfail(frame_s *fp, uintptr_t slot)
{
	ajla_error_t sink;
	const struct type *type = frame_get_type_of_local(fp, slot);
	return cast_ptr(unsigned char *, data_alloc_record_mayfail(type_def(type,record), &sink pass_file_line));
}

static unsigned char *cg_upcall_data_alloc_option_mayfail(void)
{
	ajla_error_t sink;
	return cast_ptr(unsigned char *, data_alloc(option, &sink));
}

static unsigned char *cg_upcall_data_alloc_array_flat_tag_mayfail(uintptr_t tag, int_default_t_upcall n_entries)
{
	ajla_error_t sink;
	const struct type *type = type_get_from_tag(tag);
	return cast_ptr(unsigned char *, data_alloc_array_flat_mayfail(type, n_entries, n_entries, false, &sink pass_file_line));
}

static unsigned char *cg_upcall_data_alloc_array_flat_slot_mayfail(frame_s *fp, uintptr_t slot, int_default_t_upcall n_entries)
{
	ajla_error_t sink;
	const struct type *type = frame_get_type_of_local(fp, slot);
	return cast_ptr(unsigned char *, data_alloc_array_flat_mayfail(type, n_entries, n_entries, false, &sink pass_file_line));
}

static unsigned char *cg_upcall_data_alloc_array_flat_types_ptr_mayfail(frame_s *fp, uintptr_t local_type, int_default_t_upcall n_allocated, int_default_t_upcall n_used)
{
	ajla_error_t sink;
	const struct type *type = da_type(get_frame(fp)->function, local_type);
	return cast_ptr(unsigned char *, data_alloc_array_flat_mayfail(type, n_allocated, n_used, false, &sink pass_file_line));
}

static unsigned char *cg_upcall_data_alloc_array_pointers_mayfail(int_default_t_upcall n_allocated, int_default_t_upcall n_used)
{
	ajla_error_t sink;
	return cast_ptr(unsigned char *, data_alloc_array_pointers_mayfail(n_allocated, n_used, &sink pass_file_line));
}

static pointer_t cg_upcall_array_create_flat(frame_s *fp, int_default_t_upcall length, uintptr_t content_slot)
{
	array_index_t idx;
	const struct type *content_type = frame_get_type_of_local(fp, content_slot);
	index_from_int(&idx, length);
	return array_create(idx, content_type, frame_var(fp, content_slot), pointer_empty());
}

static pointer_t cg_upcall_array_create_pointers(frame_s *fp, uintptr_t ip_offset, uintptr_t length_slot, pointer_t_upcall ptr)
{
	array_index_t idx;
	int_default_t length = *frame_slot(fp, length_slot, int_default_t);
	if (unlikely(length < 0)) {
		code_t *ip;
		pointer_dereference(ptr);
		ip = da(get_frame(fp)->function,function)->code + ip_offset;
		return pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX), fp, ip pass_file_line);
	}
	index_from_int(&idx, length);
	return array_create(idx, NULL, NULL, ptr);
}

static pointer_t cg_upcall_array_create_sparse(int_default_t_upcall length, pointer_t_upcall ptr)
{
	array_index_t idx;
	index_from_int(&idx, length);
	return array_create_sparse(idx, ptr);
}

static pointer_t cg_upcall_array_sub(pointer_t_upcall array, int_default_t_upcall start, int_default_t_upcall end, bool deref)
{
	pointer_t res_ptr;
	ajla_error_t err;
	struct data *d, *s;
	array_index_t idx_start, idx_end, idx_len, idx_array_len;
	if (unlikely((start | end) < 0))
		goto fail1;
	if (unlikely(start > end))
		goto fail1;
	if (unlikely(pointer_is_thunk(array)))
		goto fail1;
	index_from_int(&idx_start, start);
	index_from_int(&idx_end, end);
	index_from_int(&idx_len, end - start);
	d = pointer_get_data(array);
	if (unlikely(da_tag(d) == DATA_TAG_array_incomplete))
		goto fail2;
	idx_array_len = array_len(d);
	if (unlikely(!index_ge_index(idx_array_len, idx_end))) {
		index_free(&idx_array_len);
		goto fail2;
	}
	index_free(&idx_array_len);
	index_free(&idx_end);
	s = array_sub(d, idx_start, idx_len, deref, &err);
	if (unlikely(!s)) {
		res_ptr = pointer_error(err, NULL, 0 pass_file_line);
	} else {
		res_ptr = pointer_data(s);
	}
	return res_ptr;
fail2:
	index_free(&idx_start);
	index_free(&idx_end);
	index_free(&idx_len);
fail1:
	return pointer_empty();
}

static pointer_t cg_upcall_array_skip(pointer_t_upcall array, int_default_t_upcall start, bool deref)
{
	pointer_t res_ptr;
	ajla_error_t err;
	struct data *d, *s;
	array_index_t idx_start, idx_array_len;
	if (unlikely(start < 0))
		goto fail1;
	if (unlikely(pointer_is_thunk(array)))
		goto fail1;
	d = pointer_get_data(array);
	if (unlikely(da_tag(d) == DATA_TAG_array_incomplete))
		goto fail1;
	index_from_int(&idx_start, start);
	idx_array_len = array_len(d);
	if (unlikely(!index_ge_index(idx_array_len, idx_start))) {
		goto fail2;
	}
	index_sub_int(&idx_array_len, start);
	s = array_sub(d, idx_start, idx_array_len, deref, &err);
	if (unlikely(!s)) {
		res_ptr = pointer_error(err, NULL, 0 pass_file_line);
	} else {
		res_ptr = pointer_data(s);
	}
	return res_ptr;
fail2:
	index_free(&idx_array_len);
	index_free(&idx_start);
fail1:
	return pointer_empty();
}

static pointer_t cg_upcall_array_join(pointer_t_upcall ptr1, pointer_t_upcall ptr2)
{
	ajla_error_t err;
	struct data *d1 = pointer_get_data(ptr1);
	struct data *d2 = pointer_get_data(ptr2);
	struct data *d = array_join(d1, d2, &err);
	if (unlikely(!d))
		return pointer_error(err, NULL, NULL pass_file_line);
	return pointer_data(d);
}

static void *cg_upcall_ipret_io(frame_s *fp, uintptr_t ip_offset, uintptr_t code_params)
{
	void *ret;
	code_t *ip = da(get_frame(fp)->function,function)->code + ip_offset;
	unsigned char io_code = code_params >> 24;
	unsigned char n_outputs = code_params >> 16;
	unsigned char n_inputs = code_params >> 8;
	unsigned char n_params = code_params;
	/*debug("cg_upcall_ipret_io start: %p, %u %u %u %u", ip, io_code, n_outputs, n_inputs, n_params);*/
	ret = ipret_io(fp, ip, io_code, n_outputs, n_inputs, n_params);
	/*debug("cg_upcall_ipret_io end: %u %u %u %u -> %p", io_code, n_outputs, n_inputs, n_params, ret);*/
	return ret;
}

static pointer_t cg_upcall_ipret_copy_variable_to_pointer(frame_s *src_fp, uintptr_t src_slot, bool deref)
{
	return ipret_copy_variable_to_pointer(src_fp, src_slot, deref);
}

static int_default_t cg_upcall_ipret_system_property(int_default_t_upcall idx)
{
	return ipret_system_property(idx);
}

#define f(n, s, u, sz, bits)						\
static bool cat(INT_binary_const_,s)(const s *v1, int_default_t_upcall v2, s *r, bool (*op)(const void *, const void *, void *))\
{									\
	s c = v2;							\
	return op(v1, &c, r);						\
}
for_all_int(f, for_all_empty)
#undef f

#define f(n, s, u, sz, bits)						\
static bool cat(FIXED_uto_int_,s)(const u *v1, int_default_t *r)	\
{									\
	int_default_t ret;						\
	ret = (int_default_t)*v1;					\
	if (unlikely((u)ret != *v1) || unlikely(ret < 0))		\
		return false;						\
	*r = ret;							\
	return true;							\
}									\
static bool cat(FIXED_ufrom_int_,s)(const int_default_t *v1, u *r)	\
{									\
	u ret;								\
	ret = (u)*v1;							\
	if (unlikely((int_default_t)ret != *v1) || unlikely(*v1 < 0))	\
		return false;						\
	*r = ret;							\
	return true;							\
}
for_all_fixed(f)
#undef f

#ifdef DEBUG_UPCALL
static void cg_upcall_debug(unsigned long x1, unsigned long x2, unsigned long x3, unsigned long x4)
{
	debug("cg upcall: %lx, %lx, %lx, %lx", x1, x2, x3, x4);
}
#endif

#endif

#define nf(n, t) NULL,

struct cg_upcall_vector_s cg_upcall_vector = {
	0,
#ifdef HAVE_CODEGEN
	cg_upcall_mem_copy,
	cg_upcall_mem_clear,
	cg_upcall_pointer_dereference,
	cg_upcall_pointer_reference_owned,
	cg_upcall_flat_to_data,
	cg_upcall_data_alloc_function_reference_mayfail,
	cg_upcall_data_alloc_record_mayfail,
	cg_upcall_data_alloc_option_mayfail,
	cg_upcall_data_alloc_array_flat_tag_mayfail,
	cg_upcall_data_alloc_array_flat_slot_mayfail,
	cg_upcall_data_alloc_array_flat_types_ptr_mayfail,
	cg_upcall_data_alloc_array_pointers_mayfail,
	cg_upcall_array_create_flat,
	cg_upcall_array_create_pointers,
	cg_upcall_array_create_sparse,
	cg_upcall_array_sub,
	cg_upcall_array_skip,
	cg_upcall_array_join,
	cg_upcall_ipret_io,
	cg_upcall_ipret_copy_variable_to_pointer,
	cg_upcall_ipret_system_property,
#define f(n, s, u, sz, bits) \
	cat(INT_binary_const_,s),
	for_all_int(f, for_all_empty)
#undef f
	cat(FIXED_binary_add_,TYPE_INT_MAX),
	cat(FIXED_binary_subtract_,TYPE_INT_MAX),
#define f(n, s, u, sz, bits) \
	cat(FIXED_binary_multiply_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_binary_divide_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_binary_udivide_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_binary_modulo_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_binary_umodulo_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_binary_power_,s),
	for_all_fixed(f)
#undef f
	cat(FIXED_binary_shl_,TYPE_INT_MAX),
	cat(FIXED_binary_shr_,TYPE_INT_MAX),
	cat(FIXED_binary_ushr_,TYPE_INT_MAX),
	cat(FIXED_binary_rol_,TYPE_INT_MAX),
	cat(FIXED_binary_ror_,TYPE_INT_MAX),
	cat(FIXED_binary_bts_,TYPE_INT_MAX),
	cat(FIXED_binary_btr_,TYPE_INT_MAX),
	cat(FIXED_binary_btc_,TYPE_INT_MAX),
	cat(FIXED_binary_less_,TYPE_INT_MAX),
	cat(FIXED_binary_less_equal_,TYPE_INT_MAX),
	cat(FIXED_binary_greater_,TYPE_INT_MAX),
	cat(FIXED_binary_greater_equal_,TYPE_INT_MAX),
	cat(FIXED_binary_uless_,TYPE_INT_MAX),
	cat(FIXED_binary_uless_equal_,TYPE_INT_MAX),
	cat(FIXED_binary_ugreater_,TYPE_INT_MAX),
	cat(FIXED_binary_ugreater_equal_,TYPE_INT_MAX),
	cat(FIXED_binary_bt_,TYPE_INT_MAX),
	cat(FIXED_unary_neg_,TYPE_INT_MAX),
#define f(n, s, u, sz, bits) \
	cat(FIXED_unary_bswap_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_unary_brev_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_unary_bsf_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_unary_bsr_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_unary_popcnt_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_uto_int_,s),
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	cat(FIXED_ufrom_int_,s),
	for_all_fixed(f)
#undef f
	cat(INT_binary_add_,TYPE_INT_MAX),
	cat(INT_binary_subtract_,TYPE_INT_MAX),
#define f(n, s, u, sz, bits) \
	cat(INT_binary_multiply_,s),
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	cat(INT_binary_divide_,s),
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	cat(INT_binary_modulo_,s),
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	cat(INT_binary_power_,s),
	for_all_int(f, for_all_empty)
#undef f
	cat(INT_binary_shl_,TYPE_INT_MAX),
	cat(INT_binary_shr_,TYPE_INT_MAX),
	cat(INT_binary_bts_,TYPE_INT_MAX),
	cat(INT_binary_btr_,TYPE_INT_MAX),
	cat(INT_binary_btc_,TYPE_INT_MAX),
	cat(INT_binary_bt_,TYPE_INT_MAX),
	cat(INT_unary_neg_,TYPE_INT_MAX),
#define f(n, s, u, sz, bits) \
	cat(INT_unary_bsf_,s),
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	cat(INT_unary_bsr_,s),
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	cat(INT_unary_popcnt_,s),
	for_all_int(f, for_all_empty)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_add_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_subtract_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_multiply_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_divide_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_modulo_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_power_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_ldexp_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_atan2_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_equal_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_not_equal_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_less_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_less_equal_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_greater_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_binary_greater_equal_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_neg_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_sqrt_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_cbrt_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_sin_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_cos_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_tan_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_asin_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_acos_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_atan_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_sinh_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_cosh_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_tanh_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_asinh_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_acosh_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_atanh_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_exp2_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_exp_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_exp10_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_log2_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_log_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_log10_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_round_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_ceil_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_floor_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_trunc_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_fract_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_mantissa_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_exponent_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_next_number_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_prev_number_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_to_int_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_from_int_,t),
	for_all_real(f, nf)
#undef f
#define f(n, t, nt, pack, unpack) \
	cat(REAL_unary_is_exception_,t),
	for_all_real(f, nf)
#undef f
#endif
#ifdef DEBUG_UPCALL
	cg_upcall_debug,
#endif
};

bool asm_generated_upcalls = false;
static size_t cg_upcall_pointer_dereference_size;
static size_t cg_upcall_pointer_reference_owned_size;
static size_t cg_upcall_ipret_copy_variable_to_pointer_size;

void name(ipret_init)(void)
{
#if 0
	unsigned __int128 a = ((unsigned __int128)0x285C1889155FULL << 64) + 0xC6DCBCCF1106E0C5ULL;
	unsigned __int128 b = 0x374AC42721E9E9BFULL;
	unsigned __int128 c = 1;
	char *s;
	FIXED_binary_power_int128_t(&a, &b, &c);
	s = str_from_signed(c, 16);
	debug("%s", s);
	mem_free(s);
#endif
#if 0
	int i;
	for (i = 0; i < OPCODE_MODE_MULT * ARG_MODE_N - (OPCODE_MODE_MULT - OPCODE_N); i++) {
		debug("%04x - %s", i, decode_opcode(i, true));
	}
#endif
	tick_stamp_ptr = &tick_stamp;
#if defined(ARCH_X86_64) && !defined(ARCH_X86_WIN_ABI) && !defined(POINTER_COMPRESSION)
	if (!offsetof(struct data, refcount_) && REFCOUNT_STEP == 256) {
		const char *id = "codegen";
		void *pde = (void *)pointer_dereference_;
		void *icvtp = (void *)ipret_copy_variable_to_pointer;
		char *c;
		size_t cs;
		asm_generated_upcalls = true;

		str_init(&c, &cs);
		str_add_hex(&c, &cs, "4889d04883e0fe488b084881f9fffeffff77324881f9ff000000772a565741504151415248b8000000000000000048be00000000000000004889d7ffd0415a415941585f5ec3f04881280001000073f548810000010000ebc3");
		memcpy(&c[0x26], &pde, 8);
		memcpy(&c[0x30], &id, 8);
		cg_upcall_vector.cg_upcall_pointer_dereference = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
		cg_upcall_pointer_dereference_size = cs;

		str_init(&c, &cs);
		str_add_hex(&c, &cs, "4883e2fe488b02483dfffeffff7708f048810200010000c3");
		cg_upcall_vector.cg_upcall_pointer_reference_owned = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
		cg_upcall_pointer_reference_owned_size = cs;

		str_init(&c, &cs);
		str_add_hex(&c, &cs, "56574150415141524889d74889ce0fb6d048b80000000000000000ffd0415a415941585f5ec3");
		memcpy(&c[0x13], &icvtp, 8);
		cg_upcall_vector.cg_upcall_ipret_copy_variable_to_pointer = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
		cg_upcall_ipret_copy_variable_to_pointer_size = cs;
	}
#endif
}

void name(ipret_done)(void)
{
	if (asm_generated_upcalls) {
		os_code_unmap(cg_upcall_vector.cg_upcall_pointer_dereference, cg_upcall_pointer_dereference_size);
		os_code_unmap(cg_upcall_vector.cg_upcall_pointer_reference_owned, cg_upcall_pointer_reference_owned_size);
		os_code_unmap(cg_upcall_vector.cg_upcall_ipret_copy_variable_to_pointer, cg_upcall_ipret_copy_variable_to_pointer_size);
	}
}

#endif
