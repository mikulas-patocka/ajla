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

#ifndef AJLA_ARITHM_B_H
#define AJLA_ARITHM_B_H

#include "asm.h"

#ifndef DEBUG_NOINLINE
#define ipret_inline    attr_always_inline
#else
#define ipret_inline    attr_noinline attr_noclone
#endif

/*
 * DIV
 */

#define gen_generic_div_mod(fn, type, utype, op, us)			\
static maybe_inline bool attr_unused cat4(FIXED_binary_,fn,_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	const bool mod = !(1 op 1);					\
	if (unlikely(!*op2)) {						\
		*res = !mod ? 0 : *op1;					\
		return true;						\
	}								\
	if (us) {							\
		*res = *op1 op *op2;					\
	} else if (DIVIDE_ROUNDS_TO_ZERO) {				\
		if (sizeof(type) >= sizeof(int) &&			\
		    unlikely(*op2 == (utype)-1) &&			\
		    unlikely(*op1 == sign_bit(utype))) {		\
			*res = !mod ? *op1 : 0;				\
			return true;					\
		}							\
		*res = (type)*op1 op (type)*op2;			\
	} else {							\
		utype o1 = (type)*op1 < 0 ? -*op1 : *op1;		\
		utype o2 = (type)*op2 < 0 ? -*op2 : *op2;		\
		utype neg = !mod					\
			? (*op1 ^ *op2) & sign_bit(type)		\
			: (utype)((type)*op1 < 0);			\
		utype r = o1 op o2;					\
		if (unlikely(neg != 0))					\
			r = -r;						\
		*res = r;						\
	}								\
	return true;							\
}

#define gen_generic_div_functions(type, utype)				\
gen_generic_div_mod(divide, type, utype, /, 0)				\
gen_generic_div_mod(udivide, type, utype, /, 1)				\
gen_generic_div_mod(modulo, type, utype, %, 0)				\
gen_generic_div_mod(umodulo, type, utype, %, 1)

#define gen_arm_div_mod(type, utype, int_type, s, alt)			\
static ipret_inline bool attr_unused cat3(FIXED_binary_divide,alt,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	int_type r;							\
	if (!ARM_ASM_DIV_NO_TRAP && unlikely(!op2)) { *res = 0; return true; }\
	__asm__ (ARM_ASM_PREFIX "sdiv %"s"0, %"s"1, %"s"2" :		\
		"=r"(r) : "r"((int_type)(type)*op1), "r"((int_type)(type)*op2));\
	*res = r;							\
	return true;							\
}									\
static ipret_inline bool attr_unused cat3(FIXED_binary_udivide,alt,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	int_type r;							\
	if (!ARM_ASM_DIV_NO_TRAP && unlikely(!op2)) { *res = 0; return true; }\
	__asm__ (ARM_ASM_PREFIX "udiv %"s"0, %"s"1, %"s"2" :		\
		"=r"(r) : "r"((int_type)*op1), "r"((int_type)*op2));	\
	*res = r;							\
	return true;							\
}									\
static ipret_inline bool attr_unused cat3(FIXED_binary_modulo,alt,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	int_type r;							\
	if (!ARM_ASM_DIV_NO_TRAP && unlikely(!op2)) { *res = *op1; return true; }\
	__asm__ (ARM_ASM_PREFIX "sdiv %"s"0, %"s"1, %"s"2" :		\
		"=r"(r) : "r"((int_type)(type)*op1), "r"((int_type)(type)*op2));\
	*res = *op1 - (type)*op2 * r;					\
	return true;							\
}									\
static ipret_inline bool attr_unused cat3(FIXED_binary_umodulo,alt,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	int_type r;							\
	if (!ARM_ASM_DIV_NO_TRAP && unlikely(!op2)) { *res = *op1; return true; }\
	__asm__ (ARM_ASM_PREFIX "udiv %"s"0, %"s"1, %"s"2" :		\
		"=r"(r) : "r"((int_type)*op1), "r"((int_type)*op2));	\
	*res = *op1 - *op2 * r;						\
	return true;							\
}

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_SDIV_UDIV)
#define FIXED_DIVIDE_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_idiv))
#define FIXED_DIVIDE_ALT1_TYPES		0x7
#define FIXED_UDIVIDE_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_idiv))
#define FIXED_UDIVIDE_ALT1_TYPES	0x7
#define FIXED_MODULO_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_idiv))
#define FIXED_MODULO_ALT1_TYPES		0x7
#define FIXED_UMODULO_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_idiv))
#define FIXED_UMODULO_ALT1_TYPES	0x7
gen_arm_div_mod(int8_t, uint8_t, uint32_t, "", _alt1_)
gen_arm_div_mod(int16_t, uint16_t, uint32_t, "", _alt1_)
gen_arm_div_mod(int32_t, uint32_t, uint32_t, "", _alt1_)
#endif

/*
 * POWER
 */

#define gen_generic_power(type, utype)					\
static bool attr_unused cat(FIXED_binary_power_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	broken_128bit_multiply utype r = 1;				\
	broken_128bit_multiply utype o1 = *op1;				\
	utype o2 = *op2;						\
	do {								\
		if (o2 & 1)						\
			r *= o1;					\
		o1 *= o1;						\
		o2 >>= 1;						\
	} while (o2);							\
	*res = r;							\
	return true;							\
}

/*
 * ROL/ROR
 */

#define gen_generic_rot(fn, type, utype, mode)				\
static maybe_inline bool attr_unused cat4(FIXED_binary_,fn,_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	const uint8_t mask = sizeof(type) * 8 - 1;			\
	if (!(mode))							\
		*res = (*op1 << (*op2 & mask)) | (*op1 >> (-*op2 & mask));\
	else								\
		*res = (*op1 >> (*op2 & mask)) | (*op1 << (-*op2 & mask));\
	return true;							\
}

#define gen_x86_rot(fn, type, utype, asmtag, constr)			\
static ipret_inline bool attr_unused cat4(FIXED_binary_,fn,_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	__asm__ (#fn #asmtag " %2, %0" : constr(*res) : "0"(*op1), "cN"((uint8_t)*op2) : "cc");\
	return true;							\
}

#define gen_arm_rot(fn, type, utype, int_type, right, s)		\
static ipret_inline bool attr_unused cat4(FIXED_binary_,fn,_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	int_type o1;							\
	int_type o2 = (uint8_t)*op2;					\
	int_type r;							\
	if (!(right))							\
		o2 = -o2;						\
	o1 = *op1 & (utype)(-1);					\
	if (sizeof(type) == 1) {					\
		o2 &= sizeof(type) * 8 - 1;				\
		o1 |= o1 << 8;						\
		__asm__(ARM_ASM_PREFIX "lsr"ARM_ASM_S" %"s"0, %"s"1, %"s"2" : \
		"=r"(r) : ARM_ASM_IF_T12("0","r")(o1), "r"(o2) ARM_ASM_S_CLOB);\
	} else {							\
		if (sizeof(type) == 2)					\
			o1 |= o1 << 16;					\
		__asm__(ARM_ASM_PREFIX "ror"ARM_ASM_S" %"s"0, %"s"1, %"s"2" : \
		"=r"(r) : ARM_ASM_IF_T12("0","r")(o1), "r"(o2) ARM_ASM_S_CLOB);\
	}								\
	*res = (utype)r;						\
	return true;							\
}

/*
 * BTS/BTR/BTC
 */

#define gen_generic_bit_mask(type, utype)				\
static attr_always_inline utype cat(bits_mask_,type)(uint8_t num)	\
{									\
	return (utype)1 << (num & (sizeof(type) * 8 - 1));		\
}									\
static attr_always_inline utype cat(bitr_mask_,type)(uint8_t num)	\
{									\
	return ~((utype)1 << (num & (sizeof(type) * 8 - 1)));		\
}									\
static attr_always_inline utype cat(bitt_ror_,type)(utype val, uint8_t num)\
{									\
	return val >> ((num & (sizeof(type) * 8 - 1)));			\
}

#define gen_x86_bit_mask(type, utype, asmtag, constr)			\
static attr_always_inline utype cat(bits_mask_,type)(uint8_t num)	\
{									\
	utype result;							\
	__asm__ ("rol"#asmtag" %2, %1":constr(result):"0"((utype)1),"c"(num):"cc");\
	return result;							\
}									\
static attr_always_inline utype cat(bitr_mask_,type)(uint8_t num)	\
{									\
	utype result;							\
	__asm__ ("rol"#asmtag" %2, %1":constr(result):"0"((utype)-2),"c"(num):"cc");\
	return result;							\
}									\
static attr_always_inline utype cat(bitt_ror_,type)(utype val, uint8_t num)\
{									\
	utype result;							\
	__asm__ ("ror"#asmtag" %2, %1":constr(result):"0"(val),"c"(num):"cc");\
	return result;							\
}

#define gen_generic_bit_functions(type, utype)				\
static maybe_inline bool attr_unused cat(FIXED_binary_bts_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	*res = *op1 | cat(bits_mask_,type)((uint8_t)*op2);		\
	return true;							\
}									\
static maybe_inline bool attr_unused cat(FIXED_binary_btr_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	*res = *op1 & cat(bitr_mask_,type)((uint8_t)*op2);		\
	return true;							\
}									\
static maybe_inline bool attr_unused cat(FIXED_binary_btc_,type)(const utype *op1, const utype *op2, utype *res)\
{									\
	*res = *op1 ^ cat(bits_mask_,type)((uint8_t)*op2);		\
	return true;							\
}									\
static maybe_inline bool attr_unused cat(FIXED_binary_bt_,type)(const utype *op1, const utype *op2, ajla_flat_option_t *res)\
{									\
	*res = cat(bitt_ror_,type)(*op1, (uint8_t)*op2) & 1;		\
	return true;							\
}									\

/*
 * BSWAP
 */

#define gen_generic_bswap_8()						\
static ipret_inline void attr_unused FIXED_unary_bswap_int8_t(const uint8_t *op, uint8_t *res)\
{									\
	*res = *op;							\
}
#define gen_generic_bswap_16()						\
static ipret_inline void attr_unused FIXED_unary_bswap_int16_t(const uint16_t *op, uint16_t *res)\
{									\
	*res = (*op << 8 | *op >> 8);					\
}
#if defined(HAVE___BUILTIN_BSWAP32) && defined(HAVE___BUILTIN_BSWAP64) && !defined(UNUSUAL_ARITHMETICS)
#define gen_generic_bswap_32()						\
static ipret_inline void attr_unused FIXED_unary_bswap_int32_t(const uint32_t *op, uint32_t *res)\
{									\
	*res = __builtin_bswap32(*op);					\
}
#define gen_generic_bswap_64()						\
static ipret_inline void attr_unused FIXED_unary_bswap_int64_t(const uint64_t *op, uint64_t *res)\
{									\
	*res = __builtin_bswap64(*op);					\
}
#else
#define gen_generic_bswap_32()						\
static ipret_inline void attr_unused FIXED_unary_bswap_int32_t(const uint32_t *op, uint32_t *res)\
{									\
	*res =	(*op >> 24) |						\
		((*op >> 8) & 0xff00U) |				\
		((*op & 0xff00U) << 8) |				\
		(*op << 24);						\
}
#define gen_generic_bswap_64()						\
static ipret_inline void attr_unused FIXED_unary_bswap_int64_t(const uint64_t *op, uint64_t *res)\
{									\
	uint32_t o_lo = (uint32_t)*op;					\
	uint32_t o_hi = (uint32_t)(*op >> 32);				\
	FIXED_unary_bswap_int32_t(&o_lo, &o_lo);			\
	FIXED_unary_bswap_int32_t(&o_hi, &o_hi);			\
	*res = o_hi | ((uint64_t)o_lo << 32);				\
}
#endif
#define gen_generic_bswap_128()						\
static ipret_inline void attr_unused FIXED_unary_bswap_int128_t(const uint128_t *op, uint128_t *res)\
{									\
	uint64_t o_lo = *op;						\
	uint64_t o_hi = *op >> 64;					\
	FIXED_unary_bswap_int64_t(&o_lo, &o_lo);			\
	FIXED_unary_bswap_int64_t(&o_hi, &o_hi);			\
	*res = o_hi | ((uint128_t)o_lo << 64);				\
}

#if defined(INLINE_ASM_GCC_I386) && !(defined(HAVE___BUILTIN_BSWAP32) && defined(HAVE___BUILTIN_BSWAP64) && static_test_bswap)
#define FIXED_BSWAP_ALT1_FEATURES	cpu_feature_mask(CPU_FEATURE_bswap)
#define FIXED_BSWAP_ALT1_TYPES		0xc
static ipret_inline void attr_unused FIXED_unary_bswap_alt1_int32_t(const uint32_t *op, uint32_t *res)
{
	__asm__ ("bswap %0":"=r"(*res):"0"(*op));
}
#if TYPE_FIXED_N >= 4
static ipret_inline void attr_unused FIXED_unary_bswap_alt1_int64_t(const uint64_t *op, uint64_t *res)
{
	__asm__ ("bswap %%eax; bswap %%edx; xchg %%eax, %%edx":"=A"(*res):"0"(*op));
}
#endif
#endif

/*
 * BREV
 */

#define brev_distribute_mask(utype, m)	((utype)(m) * 0x01010101UL * ((one << 15 << 15 << 2) + 1) * ((one << 15 << 15 << 15 << 15 << 4) + 1))

#define gen_generic_brev(type, utype)					\
static maybe_inline void attr_unused cat(FIXED_unary_brev_,type)(const utype *op, utype *res)\
{									\
	utype one = 1; /* avoid shift overflow warning in clang */	\
	utype mask;							\
	utype o = *op;							\
	mask = (utype)brev_distribute_mask(utype, 0x55);		\
	o = ((o & mask) << 1) | ((o & ~mask) >> 1);			\
	mask = (utype)brev_distribute_mask(utype, 0x33);		\
	o = ((o & mask) << 2) | ((o & ~mask) >> 2);			\
	mask = (utype)brev_distribute_mask(utype, 0x0f);		\
	o = ((o & mask) << 4) | ((o & ~mask) >> 4);			\
	cat(FIXED_unary_bswap_,type)(&o, res);				\
}

#define gen_arm_brev(type, utype, int_type, s, alt)			\
static ipret_inline void attr_unused cat3(FIXED_unary_brev,alt,type)(const utype *op, utype *res)\
{									\
	int_type r;							\
	__asm__ (ARM_ASM_PREFIX "rbit %"s"0, %"s"1" : "=r"(r) : "r"((int_type)*op));\
	*res = r >> ((sizeof(int_type) - sizeof(type)) * 8);		\
}
#define gen_arm_brev_2reg(type, utype, int_type, s, alt)		\
static ipret_inline void attr_unused cat3(FIXED_unary_brev,alt,type)(const utype *op, utype *res)\
{									\
	const int shift = (int)sizeof(int_type) * 8;			\
	utype o1 = *op;							\
	int_type r1, r2;						\
	__asm__ (ARM_ASM_PREFIX "rbit %"s"0, %"s"1" : "=r"(r2) : "r"((int_type)o1));\
	__asm__ (ARM_ASM_PREFIX "rbit %"s"0, %"s"1" : "=r"(r1) : "r"((int_type)(o1 >> shift)));\
	*res = ((utype)r2 << shift) | r1;				\
}
#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_RBIT)
#define FIXED_BREV_ALT1_FEATURES	cpu_feature_mask(CPU_FEATURE_armv6t2)
#define FIXED_BREV_ALT1_TYPES		0xf
gen_arm_brev(int8_t, uint8_t, uint32_t, "", _alt1_)
gen_arm_brev(int16_t, uint16_t, uint32_t, "", _alt1_)
gen_arm_brev(int32_t, uint32_t, uint32_t, "", _alt1_)
#if TYPE_FIXED_N >= 4
gen_arm_brev_2reg(int64_t, uint64_t, uint32_t, "", _alt1_)
#endif
#endif

/*
 * BSF/BSR
 */

#if defined(HAVE_STDBIT_H)
#define libc_ffs_int8_t		if (unlikely(!o)) { *res = -1; return; } else { *res = stdc_trailing_zeros_uc(o); return; }
#define libc_ffs_int16_t	if (unlikely(!o)) { *res = -1; return; } else { *res = stdc_trailing_zeros_us(o); return; }
#elif defined(HAVE_BUILTIN_CTZ)
#define libc_ffs_int8_t		if (unlikely(!o)) { *res = -1; return; } else { *res = __builtin_ctz(o); return; }
#define libc_ffs_int16_t	if (unlikely(!o)) { *res = -1; return; } else { *res = __builtin_ctz(o); return; }
#elif defined(HAVE_FFS)
#define libc_ffs_int8_t		*res = ffs(o) - 1; return;
#define libc_ffs_int16_t	*res = ffs(o) - 1; return;
#else
#define libc_ffs_int8_t
#define libc_ffs_int16_t
#endif
#if defined(HAVE_STDBIT_H) && SIZEOF_UNSIGNED >= 4
#define libc_ffs_int32_t	if (unlikely(!o)) { *res = -1; return; } else { *res = stdc_trailing_zeros_ui(o); return; }
#elif defined(HAVE_BUILTIN_CTZ) && SIZEOF_UNSIGNED >= 4
#define libc_ffs_int32_t	if (unlikely(!o)) { *res = -1; return; } else { *res = __builtin_ctz(o); return; }
#elif defined(HAVE_FFS) && SIZEOF_UNSIGNED >= 4
#define libc_ffs_int32_t	*res = ffs(o) - 1; return;
#elif defined(HAVE_FFSL)
#define libc_ffs_int32_t	*res = ffsl(o) - 1; return;
#else
#define libc_ffs_int32_t
#endif
#if defined(HAVE_STDBIT_H) && SIZEOF_UNSIGNED_LONG_LONG == 8
#define libc_ffs_int64_t	if (unlikely(!o)) { *res = -1; return; } else { *res =  stdc_trailing_zeros_ull(o); return; }
#define libc_ffs_int128_t	if ((uint64_t)o) { *res = stdc_trailing_zeros_ull(o); return; } else if (o >> 64) { *res = stdc_trailing_zeros_ull(o >> 64) + 64; return; } else { *res = -1; return; }
#elif defined(HAVE_BUILTIN_CTZ) && SIZEOF_UNSIGNED_LONG_LONG == 8
#define libc_ffs_int64_t	if (unlikely(!o)) { *res = -1; return; } else { *res =  __builtin_ctzll(o); return; }
#define libc_ffs_int128_t	if ((uint64_t)o) { *res = __builtin_ctzll(o); return; } else if (o >> 64) { *res = __builtin_ctzll(o >> 64) + 64; return; } else { *res = -1; return; }
#elif defined(HAVE_FFSL) && SIZEOF_UNSIGNED_LONG >= 8
#define libc_ffs_int64_t	*res = ffsl(o) - 1; return;
#define libc_ffs_int128_t	if ((uint64_t)o) { *res = ffsl(o) - 1; return; } else if (o >> 64) { *res = ffsl(o >> 64) + 63; return; } else { *res = -1; return; }
#elif defined(HAVE_FFSLL) && SIZEOF_UNSIGNED_LONG_LONG >= 8
#define libc_ffs_int64_t	*res = ffsll(o) - 1; return;
#define libc_ffs_int128_t	if ((uint64_t)o) { *res = ffsll(o) - 1; return; } else if (o >> 64) { *res = ffsll(o >> 64) + 63; return; } else { *res = -1; return; }
#else
#define libc_ffs_int64_t
#define libc_ffs_int128_t
#endif

#if defined(HAVE_STDBIT_H) && SIZEOF_UNSIGNED_SHORT == 2
#define libc_fls_int8_t		if (unlikely(!o)) { *res = -1; return; } else { *res = 7 - stdc_leading_zeros_uc(o); return; }
#define libc_fls_int16_t	if (unlikely(!o)) { *res = -1; return; } else { *res = 15 - stdc_leading_zeros_us(o); return; }
#elif defined(HAVE_BUILTIN_CLZ) && SIZEOF_UNSIGNED >= 2 && !(SIZEOF_UNSIGNED & (SIZEOF_UNSIGNED - 1))
#define libc_fls_int8_t		if (unlikely(!o)) { *res = -1; return; } else { *res = ((unsigned)sizeof(unsigned) * 8 - 1) CLZ_BSR_OP __builtin_clz(o); return; }
#define libc_fls_int16_t	if (unlikely(!o)) { *res = -1; return; } else { *res = ((unsigned)sizeof(unsigned) * 8 - 1) CLZ_BSR_OP __builtin_clz(o); return; }
#elif defined(HAVE_FLS)
#define libc_fls_int8_t		*res = fls(o) - 1; return;
#define libc_fls_int16_t	*res = fls(o) - 1; return;
#else
#define libc_fls_int8_t
#define libc_fls_int16_t
#endif
#if defined(HAVE_STDBIT_H) && SIZEOF_UNSIGNED == 4
#define libc_fls_int32_t	if (unlikely(!o)) { *res = -1; return; } else { *res = 31 - stdc_leading_zeros_ui(o); return; }
#elif defined(HAVE_BUILTIN_CLZ) && SIZEOF_UNSIGNED >= 4 && !(SIZEOF_UNSIGNED & (SIZEOF_UNSIGNED - 1))
#define libc_fls_int32_t	if (unlikely(!o)) { *res = -1; return; } else { *res = ((unsigned)sizeof(unsigned) * 8 - 1) CLZ_BSR_OP __builtin_clz(o); return; }
#elif defined(HAVE_FLS) && SIZEOF_UNSIGNED >= 4
#define libc_fls_int32_t	*res = fls(o) - 1; return;
#elif defined(HAVE_FLSL)
#define libc_fls_int32_t	*res = flsl(o) - 1; return;
#else
#define libc_fls_int32_t
#endif
#if defined(HAVE_STDBIT_H) && SIZEOF_UNSIGNED_LONG_LONG == 8
#define libc_fls_int64_t	if (unlikely(!o)) { *res = -1; return; } else { *res = 63 - stdc_leading_zeros_ull(o); return; }
#define libc_fls_int128_t	if (o >> 64) { *res = (127 CLZ_BSR_OP stdc_leading_zeros_ull((uint64_t)(o >> 64))); return; } else if (likely((uint64_t)o != 0)) { *res = 63 CLZ_BSR_OP stdc_leading_zeros_ull((uint64_t)o); return; } else { *res = -1; return; }
#elif defined(HAVE_BUILTIN_CLZ) && SIZEOF_UNSIGNED_LONG_LONG == 8
#define libc_fls_int64_t	if (unlikely(!o)) { *res = -1; return; } else { *res = ((unsigned)sizeof(unsigned long long) * 8 - 1) CLZ_BSR_OP __builtin_clzll(o); return; }
#define libc_fls_int128_t	if (o >> 64) { *res = (127 CLZ_BSR_OP __builtin_clzll((uint64_t)(o >> 64))); return; } else if (likely((uint64_t)o != 0)) { *res = ((unsigned)sizeof(unsigned long long) * 8 - 1) CLZ_BSR_OP __builtin_clzll((uint64_t)o); return; } else { *res = -1; return; }
#elif defined(HAVE_FLSL) && SIZEOF_UNSIGNED_LONG >= 8
#define libc_fls_int64_t	*res = flsl(o) - 1; return;
#define libc_fls_int128_t
#elif defined(HAVE_FLSLL) && SIZEOF_UNSIGNED_LONG_LONG >= 8
#define libc_fls_int64_t	*res = flsll(o) - 1; return;
#define libc_fls_int128_t
#else
#define libc_fls_int64_t
#define libc_fls_int128_t
#endif

#define gen_generic_bsfr_functions(type, utype)				\
static maybe_inline void attr_unused cat(FIXED_unary_bsf_,type)(const utype *op, utype *res)\
{									\
	int i;								\
	utype o = *op;							\
	cat(libc_ffs_,type)						\
	for (i = 0; i < (int)sizeof(type) * 8; i++)			\
		if (o & ((utype)1 << i)) {				\
			*res = (utype)i;				\
			return;						\
		}							\
	*res = (utype)-1;						\
}									\
static maybe_inline void attr_unused cat(FIXED_unary_bsr_,type)(const utype *op, utype *res)\
{									\
	int i;								\
	utype o = *op;							\
	cat(libc_fls_,type)						\
	for (i = (int)sizeof(type) * 8 - 1; i >= 0; i--)		\
		if (o & ((utype)1 << i)) {				\
			*res = (utype)i;				\
			return;						\
		}							\
	*res = (utype)-1;						\
}

#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_LZCNT)
#define FIXED_BSR_ALT1_FEATURES		(cpu_feature_mask(CPU_FEATURE_cmov) | cpu_feature_mask(CPU_FEATURE_lzcnt))
#if defined(INLINE_ASM_GCC_I386) || !defined(HAVE_ASSEMBLER___INT128)
#define FIXED_BSR_ALT1_TYPES		0xf
#else
#define FIXED_BSR_ALT1_TYPES		0x1f
#endif

#define gen_x86_lzcnt(type, utype, internal_type, asmtag)		\
static ipret_inline void attr_unused cat(FIXED_unary_bsr_alt1_,type)(const utype *op, utype *res)\
{									\
	internal_type r;						\
	__asm__ ("							\n\
		lzcnt"#asmtag"	%1, %0					\n\
	":"=r"(r):"r"X86_ASM_M((internal_type)*op):"cc");		\
	*res = (internal_type)(sizeof(internal_type) * 8 - 1 - r);	\
}
#define gen_x86_lzcnt_split(type, utype, asmtag, ax, dx, n, ctd)	\
static ipret_inline void attr_unused cat(FIXED_unary_bsr_alt1_,type)(const utype *op, utype *res)\
{									\
	__asm__ ("							\n\
		test"#asmtag"	%%"#dx", %%"#dx"			\n\
		cmovz"#asmtag"	%%"#ax", %%"#dx"			\n\
		setz		%%cl					\n\
		lzcnt"#asmtag"	%%"#dx", %%"#dx"			\n\
		movl		$"#n", %%eax				\n\
		shrl		%%cl, %%eax				\n\
		sub"#asmtag"	%%"#dx", %%"#ax"			\n\
		"#ctd"							\n\
	":"=A"(*res):"0"(*op):"ecx","cc");				\
}
gen_x86_lzcnt(int8_t, uint8_t, int16_t, w)
gen_x86_lzcnt(int16_t, uint16_t, int16_t, w)
gen_x86_lzcnt(int32_t, uint32_t, int32_t, l)
#if TYPE_FIXED_N >= 4
#ifdef INLINE_ASM_GCC_I386
gen_x86_lzcnt_split(int64_t, uint64_t, l, eax, edx, 63, cltd)
#else
gen_x86_lzcnt(int64_t, uint64_t, int64_t, q)
#if TYPE_FIXED_N >= 5 && defined(HAVE_ASSEMBLER___INT128)
gen_x86_lzcnt_split(int128_t, uint128_t, q, rax, rdx, 127, cqto)
#endif
#endif
#endif
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_CLZ) && defined(HAVE_ARM_ASSEMBLER_RBIT)
#define FIXED_BSF_ALT1_FEATURES		(cpu_feature_mask(CPU_FEATURE_armv6t2))
#define FIXED_BSF_ALT1_TYPES		0xf

#define gen_arm_rbit_clz(type, utype)					\
static ipret_inline void attr_unused cat(FIXED_unary_bsf_alt1_,type)(const utype *op, utype *res)\
{									\
	uint32_t clz;							\
	if (unlikely(!*op)) { *res = -1; return; }			\
	__asm__ (ARM_ASM_PREFIX "rbit %0, %1; clz %0, %0":"=r"(clz):"r"((uint32_t)*op));\
	*res = clz;							\
}
#define gen_arm_rbit_clz_split()					\
static ipret_inline void attr_unused FIXED_unary_bsf_alt1_int64_t(const uint64_t *op, uint64_t *res)\
{									\
	uint32_t clz;							\
	uint64_t o = *op;						\
	if ((uint32_t)o) {						\
		__asm__ (ARM_ASM_PREFIX "rbit %0, %1; clz %0, %0":"=r"(clz):"r"((uint32_t)o));\
		*res = clz;						\
	} else {							\
		uint32_t o_hi = o >> 32;				\
		if (unlikely(!o_hi)) {					\
			*res = -1;					\
			return;						\
		}							\
		__asm__ (ARM_ASM_PREFIX "rbit %0, %1; clz %0, %0":"=r"(clz):"r"(o_hi));\
		*res = clz + 32;					\
	}								\
}
gen_arm_rbit_clz(int8_t, uint8_t)
gen_arm_rbit_clz(int16_t, uint16_t)
gen_arm_rbit_clz(int32_t, uint32_t)
#if TYPE_FIXED_N >= 4
gen_arm_rbit_clz_split()
#endif
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_CLZ)
#define FIXED_BSR_ALT1_FEATURES		(cpu_feature_mask(CPU_FEATURE_armv5))
#define FIXED_BSR_ALT1_TYPES		0xf

#define gen_arm_clz(type, utype)					\
static ipret_inline void attr_unused cat(FIXED_unary_bsr_alt1_,type)(const utype *op, utype *res)\
{									\
	int clz;							\
	__asm__ (ARM_ASM_PREFIX "clz %0, %1":"=r"(clz):"r"((uint32_t)*op));\
	*res = 31 - clz;						\
}
#define gen_arm_clz_split()						\
static ipret_inline void attr_unused FIXED_unary_bsr_alt1_int64_t(const uint64_t *op, uint64_t *res)\
{									\
	int clz;							\
	uint64_t o = *op;						\
	uint32_t o_hi = o >> 32;					\
	if (o_hi) {							\
		__asm__ (ARM_ASM_PREFIX "clz %0, %1":"=r"(clz):"r"(o_hi));\
		*res = (unsigned)(63 - clz);				\
	} else {							\
		__asm__ (ARM_ASM_PREFIX "clz %0, %1":"=r"(clz):"r"((uint32_t)o));\
		*res = 31 - clz;					\
	}								\
}
gen_arm_clz(int8_t, uint8_t)
gen_arm_clz(int16_t, uint16_t)
gen_arm_clz(int32_t, uint32_t)
#if TYPE_FIXED_N >= 4
gen_arm_clz_split()
#endif
#endif

/*
 * POPCNT
 */

#if defined(HAVE_STDBIT_H) && SIZEOF_UNSIGNED >= 4 && SIZEOF_UNSIGNED_LONG_LONG >= 8
#define libc_popcnt_int8_t	*res = (unsigned)stdc_count_ones_uc(o); return;
#define libc_popcnt_int16_t	*res = (unsigned)stdc_count_ones_us(o); return;
#define libc_popcnt_int32_t	*res = (unsigned)stdc_count_ones_ui(o); return;
#define libc_popcnt_int64_t	*res = (unsigned)stdc_count_ones_ull(o); return;
#define libc_popcnt_int128_t	*res = (unsigned)stdc_count_ones_ull((uint64_t)o) + (unsigned)stdc_count_ones_ull((uint64_t)(o >> 64)); return;
#elif defined(HAVE_BUILTIN_POPCOUNT) && SIZEOF_UNSIGNED >= 4 && SIZEOF_UNSIGNED_LONG_LONG >= 8
#define libc_popcnt_int8_t	*res = (unsigned)__builtin_popcount(o); return;
#define libc_popcnt_int16_t	*res = (unsigned)__builtin_popcount(o); return;
#define libc_popcnt_int32_t	*res = (unsigned)__builtin_popcount(o); return;
#define libc_popcnt_int64_t	*res = (unsigned)__builtin_popcountll(o); return;
#define libc_popcnt_int128_t	*res = (unsigned)__builtin_popcountll((uint64_t)o) + (unsigned)__builtin_popcountll((uint64_t)(o >> 64)); return;
#else
#define libc_popcnt_int8_t
#define libc_popcnt_int16_t
#define libc_popcnt_int32_t
#define libc_popcnt_int64_t
#define libc_popcnt_int128_t
#endif

#define gen_generic_popcnt(type, utype)					\
static maybe_inline void attr_unused cat(FIXED_unary_popcnt_,type)(const utype *op, utype *res)\
{									\
	unsigned r;							\
	utype o = *op;							\
	cat(libc_popcnt_,type)						\
	r = 0;								\
	while (o)							\
		o &= o - 1, r++;					\
	*res = (utype)r;						\
}

#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_POPCNT) && !(defined(HAVE_BUILTIN_POPCOUNT) && static_test_popcnt)
#define FIXED_POPCNT_ALT1_FEATURES	cpu_feature_mask(CPU_FEATURE_popcnt)
#if defined(INLINE_ASM_GCC_I386)
#define FIXED_POPCNT_ALT1_TYPES		0xf
#else
#define FIXED_POPCNT_ALT1_TYPES		0x1f
#endif

#define gen_x86_popcnt(type, utype, internal_type, asmtag)		\
static ipret_inline void attr_unused cat(FIXED_unary_popcnt_alt1_,type)(const utype *op, utype *res)\
{									\
	internal_type r;						\
	__asm__ ("							\n\
		popcnt"#asmtag"	%1, %0					\n\
	":"=r"(r):"r"X86_ASM_M((internal_type)*op):"cc");		\
	*res = r;							\
}
#define gen_x86_popcnt_split(type, utype, half, asmtag)			\
static ipret_inline void attr_unused cat(FIXED_unary_popcnt_alt1_,type)(const utype *op, utype *res)\
{									\
	half r1, r2;							\
	__asm__ ("							\n\
		popcnt"#asmtag"	%1, %0					\n\
	":"=r"(r1):"r"X86_ASM_M(cast_ptr(half *, op)[0]):"cc");		\
	__asm__ ("							\n\
		popcnt"#asmtag"	%1, %0					\n\
	":"=r"(r2):"r"X86_ASM_M(cast_ptr(half *, op)[1]):"cc");		\
	*res = (unsigned)r1 + (unsigned)r2;				\
}
gen_x86_popcnt(int8_t, uint8_t, uint16_t, w)
gen_x86_popcnt(int16_t, uint16_t, uint16_t, w)
gen_x86_popcnt(int32_t, uint32_t, uint32_t, l)
#if TYPE_FIXED_N >= 4
#ifdef INLINE_ASM_GCC_I386
gen_x86_popcnt_split(int64_t, uint64_t, uint32_t, l)
#else
gen_x86_popcnt(int64_t, uint64_t, uint64_t, q)
#if TYPE_FIXED_N >= 5
gen_x86_popcnt_split(int128_t, uint128_t, uint64_t, q)
#endif
#endif
#endif
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_VFP)
#define FIXED_POPCNT_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_neon))
#define FIXED_POPCNT_ALT1_TYPES		0xf

#define gen_arm_popcnt(type, utype, wtag, field, vpaddl)		\
static ipret_inline void attr_unused cat(FIXED_unary_popcnt_alt1_,type)(const utype *op, utype *res)\
{									\
	__asm__ volatile (ARM_ASM_PREFIX "				\n\
		vld1."#wtag"	d0"field", [ %1 ]			\n\
		vcnt.8		d0, d0					\n\
		" vpaddl "						\n\
		vst1."#wtag"	d0"field", [ %0 ]			\n\
	": : "r"(res), "r"(op) : "d0", "memory");			\
}

gen_arm_popcnt(int8_t, uint8_t, 8, "[0]", "")
gen_arm_popcnt(int16_t, uint16_t, 16, "[0]", "vpaddl.u8 d0, d0")
gen_arm_popcnt(int32_t, uint32_t, 32, "[0]", "vpaddl.u8 d0, d0 \n vpaddl.u16 d0, d0")
#if TYPE_FIXED_N >= 4
gen_arm_popcnt(int64_t, uint64_t, 64, "", "vpaddl.u8 d0, d0 \n vpaddl.u16 d0, d0 \n vpaddl.u32 d0, d0")
#endif
#endif

#if defined(INLINE_ASM_GCC_ARM64)
#define FIXED_POPCNT_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_neon))
#define FIXED_POPCNT_ALT1_TYPES		0x1f

#define gen_arm64_popcnt(type, utype, reg, cntw, vpaddl)		\
static ipret_inline void attr_unused cat(FIXED_unary_popcnt_alt1_,type)(const utype *op, utype *res)\
{									\
	__asm__ volatile (ARM_ASM_PREFIX "				\n\
		ldr		"reg", [ %1 ]				\n\
		cnt		v0."cntw"b, v0."cntw"b			\n\
		"vpaddl"						\n\
		str		"reg", [ %0 ]				\n\
	": : "r"(res), "r"(op) : "v0", "memory");			\
}

gen_arm64_popcnt(int8_t, uint8_t, "b0", "8", "")
gen_arm64_popcnt(int16_t, uint16_t, "h0", "8", "uaddlp v0.4h, v0.8b")
gen_arm64_popcnt(int32_t, uint32_t, "s0", "8", "uaddlv h0, v0.8b")
#if TYPE_FIXED_N >= 4
gen_arm64_popcnt(int64_t, uint64_t, "d0", "8", "uaddlv h0, v0.8b")
#if TYPE_FIXED_N >= 5
gen_arm64_popcnt(int128_t, uint128_t, "q0", "16", "uaddlv h0, v0.16b")
#endif
#endif

#endif

#define file_inc "arithm-b.inc"
#include "for-fix.inc"

#endif
