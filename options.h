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

#define MINIMUM_STACK_SIZE		0x100000


#ifndef UNUSUAL_DISABLE_INT128_T
#if defined(SIZEOF_UNSIGNED___INT128) && SIZEOF_UNSIGNED___INT128 == 16
#define TYPE_FIXED_N	5
typedef signed __int128 int128_t;
typedef unsigned __int128 uint128_t;
#endif
#endif

#ifndef TYPE_FIXED_N
#define TYPE_FIXED_N	4
#endif


#define TYPE_INT_N		TYPE_FIXED_N
#define INT_MASK		((1 << TYPE_INT_N) - 1)
#if INT_MASK & 0x10
#define TYPE_INT_MAX		int128_t
#elif INT_MASK & 0x8
#define TYPE_INT_MAX		int64_t
#elif INT_MASK & 0x4
#define TYPE_INT_MAX		int32_t
#elif INT_MASK & 0x2
#define TYPE_INT_MAX		int16_t
#elif INT_MASK & 0x1
#define TYPE_INT_MAX		int8_t
#endif


#define ajla_time_t		int64_t
#define ajla_utime_t		uint64_t


#if (defined(HAVE_GMP_H) || defined(HAVE_GMP_GMP_H)) && defined(HAVE_LIBGMP)
#define MPINT_GMP
#endif


#ifdef __MINGW32__
#undef HAVE_ISNANF
#undef HAVE_ISNANL
#endif

#if !defined(HAVE_FABSF)
#define fabsf			fabs
#endif
#if !defined(HAVE_SQRTF)
#define sqrtf			sqrt
#endif

#if !defined(HAVE_SINF)
#define sinf			sin
#endif
#if !defined(HAVE_COSF)
#define cosf			cos
#endif
#if !defined(HAVE_TANF)
#define tanf			tan
#endif
#if !defined(HAVE_ASINF)
#define asinf			asin
#endif
#if !defined(HAVE_ACOSF)
#define acosf			acos
#endif
#if !defined(HAVE_ATANF)
#define atanf			atan
#endif

#if !defined(HAVE_SINHF)
#define sinhf			sinh
#endif
#if !defined(HAVE_COSHF)
#define coshf			cosh
#endif
#if !defined(HAVE_TANHF)
#define tanhf			tanh
#endif
#if !defined(HAVE_ASINHF)
#define asinhf			asinh
#endif
#if !defined(HAVE_ACOSHF)
#define acoshf			acosh
#endif
#if !defined(HAVE_ATANHF)
#define atanhf			atanh
#endif

#if !defined(HAVE_EXPF)
#define expf			exp
#endif
#if !defined(HAVE_LOGF)
#define logf			log
#endif
#if !defined(HAVE_LOG10F)
#define log10f			log10
#endif

#if !defined(HAVE_CEILF)
#define ceilf			ceil
#endif
#if !defined(HAVE_FLOORF)
#define floorf			floor
#endif
#if !defined(HAVE_FMODF)
#define fmodf			fmod
#endif
#if !defined(HAVE_FREXPF)
#define frexpf			frexp
#endif

#if !defined(HAVE_ATAN2F)
#define atan2f			atan2
#endif
#if !defined(HAVE_POWF)
#define powf			pow
#endif
#if !defined(HAVE_LDEXPF)
#define ldexpf			ldexp
#endif

float half_to_float(uint16_t x);
uint16_t float_to_half(float x);

#if FLT_RAFIX == 2 && (defined(HAVE___FP16) || defined(HAVE__FLOAT16)) && \
	!(defined(__ARM_FP) && !defined(__ARM_FP16_FORMAT_IEEE)) && \
	!(defined(ARCH_ARM32) && CLANG_ATLEAST(5,0,0))	/* clang 5, 6, 7 fail fp16 bist */
#define TEST_HALF_FLOAT_CONVERSION
#if (defined(__ARM_FP) && __ARM_FP & 2) || defined(__F16C__)
#define HAVE_NATIVE_FP16
#ifdef HAVE___FP16
typedef __fp16 real16_t;
#else
typedef _Float16 real16_t;
#endif
#define mathfunc_real16_t(fn)	cat(fn,f)
#define bits_real16_t		11
#define isfinite_real16_t(x)	isfinite_real32_t(x)
#define isnan_real16_t(x)	isnan_real32_t(x)
#define REAL_MASK_0		(1 << 0)
#endif
#endif

#if FLT_RADIX == 2
typedef float real32_t;
#define mathfunc_real32_t(fn)	cat(fn,f)
#define bits_real32_t		FLT_MANT_DIG
#if defined(HAVE_ISFINITEF)
#define isfinite_real32_t(x)	isfinitef(x)
#endif
#if defined(HAVE_ISNANF)
#define isnan_real32_t(x)	isnanf(x)
#elif defined(isnan)
#define isnan_real32_t(x)	isnan(x)
#endif
#define REAL_MASK_1		(1 << 1)
#endif

#if FLT_RADIX == 2
typedef double real64_t;
#define mathfunc_real64_t(fn)	fn
#define bits_real64_t		DBL_MANT_DIG
#if defined(HAVE_ISFINITE)
#define isfinite_real64_t(x)	isfinite(x)
#endif
#if defined(HAVE_ISNAN) || defined(isnan)
#define isnan_real64_t(x)	isnan(x)
#endif
#define REAL_MASK_2		(1 << 2)
#endif

#if !defined(HAVE_FABSL) || !defined(HAVE_FREXPL) || !defined(HAVE_LDEXPL) || !defined(HAVE_POWL) || !defined(HAVE_SQRTL) || !defined(HAVE_RINTL) || !defined(HAVE_MODFL)
#ifdef HAVE_LONG_DOUBLE
#undef HAVE_LONG_DOUBLE
#endif
#endif

#if FLT_RADIX == 2 && defined(HAVE_LONG_DOUBLE) && \
	(defined(LDBL_MIN_EXP) && LDBL_MIN_EXP <= -16381 && defined(LDBL_MAX_EXP) && LDBL_MAX_EXP >= 16384 && defined(LDBL_MANT_DIG) && LDBL_MANT_DIG >= 64) && \
	!(defined(LDBL_MIN_EXP) && LDBL_MIN_EXP <= -16381 && defined(LDBL_MAX_EXP) && LDBL_MAX_EXP >= 16384 && defined(LDBL_MANT_DIG) && LDBL_MANT_DIG >= 113)
typedef long double real80_t;
#define mathfunc_real80_t(fn)	cat(fn,l)
#define bits_real80_t		LDBL_MANT_DIG
#if defined(HAVE_ISFINITEL)
#define isfinite_real80_t(x)	isfinitel(x)
#endif
#if defined(HAVE_ISNANL) && !defined(__HAIKU__)
#define isnan_real80_t(x)	isnanl(x)
#endif
#define REAL_MASK_3		(1 << 3)
#endif

#if defined(HAVE___FLOAT128) && \
	defined(FLT128_MIN_EXP) && FLT128_MIN_EXP <= -16381 && defined(FLT128_MAX_EXP) && FLT128_MAX_EXP >= 16384 && defined(FLT128_MANT_DIG) && FLT128_MANT_DIG >= 113 && \
	defined(HAVE_FABSQ) && defined(HAVE_FREXPQ) && defined(HAVE_LDEXPQ) && defined(HAVE_POWQ) && defined(HAVE_SQRTQ)
#define USEABLE___FLOAT128
#endif

#if FLT_RADIX == 2 && defined(HAVE_LONG_DOUBLE) && \
	defined(LDBL_MIN_EXP) && LDBL_MIN_EXP <= -16381 && defined(LDBL_MAX_EXP) && LDBL_MAX_EXP >= 16384 && defined(LDBL_MANT_DIG) && LDBL_MANT_DIG >= 113 && \
	!(!defined(HAVE_ISNANL) && defined(HAVE_ISNANQ) && defined(USEABLE___FLOAT128))
typedef long double real128_t;
#define mathfunc_real128_t(fn)	cat(fn,l)
#define bits_real128_t		LDBL_MANT_DIG
#if defined(HAVE_ISFINITEL)
#define isfinite_real128_t(x)	isfinitel(x)
#endif
#if defined(HAVE_ISNANL)
#define isnan_real128_t(x)	isnanl(x)
#endif
#define REAL_MASK_4		(1 << 4)
#elif FLT_RADIX == 2 && defined(USEABLE___FLOAT128)
#define HAVE_NATIVE_FLOAT128
typedef __float128 real128_t;
#define mathfunc_real128_t(fn)	cat(fn,q)
#define bits_real128_t		113
#if defined(HAVE_ISFINITEQ)
#define isfinite_real128_t(x)	isfiniteq(x)
#endif
#if defined(HAVE_ISNANQ)
#define isnan_real128_t(x)	isnanq(x)
#endif
#define REAL_MASK_4		(1 << 4)
#endif

#if !defined(REAL_MASK_0) && defined(REAL_MASK_1)
#define HALF_FLOAT_CONVERSION
#ifdef DEBUG
typedef struct {
	uint16_t val;
} real16_t;
#define native_real16_t		real32_t
static inline native_real16_t unpack_real16_t(real16_t x)
{
	return half_to_float(x.val);
}
static inline real16_t pack_real16_t(native_real16_t x)
{
	real16_t v;
	v.val = float_to_half(x);
	return v;
}
#define mathfunc_real16_t(fn)	cat(fn,f)
#define bits_real16_t		11
#define isfinite_real16_t(x)	(((x).val & 0x7fff) < 0x7c00)
#define isnan_real16_t(x)	(((x).val & 0x7fff) > 0x7c00)
#else
#define REAL16_T_IS_UINT16_T	1
typedef uint16_t real16_t;
#define native_real16_t		real32_t
#define unpack_real16_t(x)	(half_to_float(x))
#define pack_real16_t(x)	(float_to_half(x))
#define mathfunc_real16_t(fn)	cat(fn,f)
#define bits_real16_t		11
#define isfinite_real16_t(x)	(((x) & 0x7fff) < 0x7c00)
#define isnan_real16_t(x)	(((x) & 0x7fff) > 0x7c00)
#endif
#define REAL_MASK_0		(1 << 0)
#endif

#ifndef REAL16_T_IS_UINT16_T
#define REAL16_T_IS_UINT16_T	0
#endif

#ifndef native_real16_t
#define native_real16_t		real16_t
#define unpack_real16_t(x)	(x)
#define pack_real16_t(x)	(x)
#endif
#ifndef native_real32_t
#define native_real32_t		real32_t
#define unpack_real32_t(x)	(x)
#define pack_real32_t(x)	(x)
#endif
#ifndef native_real64_t
#define native_real64_t		real64_t
#define unpack_real64_t(x)	(x)
#define pack_real64_t(x)	(x)
#endif
#ifndef native_real80_t
#define native_real80_t		real80_t
#define unpack_real80_t(x)	(x)
#define pack_real80_t(x)	(x)
#endif
#ifndef native_real128_t
#define native_real128_t	real128_t
#define unpack_real128_t(x)	(x)
#define pack_real128_t(x)	(x)
#endif

#define FP_HAVE_INFINITY	(HUGE_VAL == HUGE_VAL / 2)

#ifndef isfinite_real16_t
#define isfinite_real16_t(x)	(FP_HAVE_INFINITY && cat(mathfunc_,real16_t)(fabs)(x) < HUGE_VAL)
#endif
#ifndef isfinite_real32_t
#define isfinite_real32_t(x)	(FP_HAVE_INFINITY && cat(mathfunc_,real32_t)(fabs)(x) < HUGE_VAL)
#endif
#ifndef isfinite_real64_t
#define isfinite_real64_t(x)	(FP_HAVE_INFINITY && cat(mathfunc_,real64_t)(fabs)(x) < HUGE_VAL)
#endif
#ifndef isfinite_real80_t
#define isfinite_real80_t(x)	(FP_HAVE_INFINITY && cat(mathfunc_,real80_t)(fabs)(x) < HUGE_VAL)
#endif
#ifndef isfinite_real128_t
#define isfinite_real128_t(x)	(FP_HAVE_INFINITY && cat(mathfunc_,real128_t)(fabs)(x) < HUGE_VAL)
#endif

#if defined(__BORLANDC__) || defined(_MSC_VER)
#define isnan_real32_t(x)	_isnan(x)
#define isnan_real64_t(x)	_isnan(x)
#define isnan_real80_t(x)	_isnanl(x)
#endif

#ifndef isnan_real16_t
#define isnan_real16_t(x)	((x) != (x))
#endif
#ifndef isnan_real32_t
#define isnan_real32_t(x)	((x) != (x))
#endif
#ifndef isnan_real64_t
#define isnan_real64_t(x)	((x) != (x))
#endif
#ifndef isnan_real80_t
#define isnan_real80_t(x)	((x) != (x))
#endif
#ifndef isnan_real128_t
#define isnan_real128_t(x)	((x) != (x))
#endif

#ifndef REAL_MASK_0
#define REAL_MASK_0		0
#endif
#ifndef REAL_MASK_1
#define REAL_MASK_1		0
#endif
#ifndef REAL_MASK_2
#define REAL_MASK_2		0
#endif
#ifndef REAL_MASK_3
#define REAL_MASK_3		0
#endif
#ifndef REAL_MASK_4
#define REAL_MASK_4		0
#endif

#define REAL_MASK		(REAL_MASK_0 | REAL_MASK_1 | REAL_MASK_2 | REAL_MASK_3 | REAL_MASK_4)
#if REAL_MASK & 0x10
#define TYPE_REAL_N		5
#define real_max_t		real128_t
#elif REAL_MASK & 0x8
#define TYPE_REAL_N		4
#define real_max_t		real80_t
#elif REAL_MASK & 0x4
#define TYPE_REAL_N		3
#define real_max_t		real64_t
#elif REAL_MASK & 0x2
#define TYPE_REAL_N		2
#define real_max_t		real32_t
#elif REAL_MASK & 0x1
#define TYPE_REAL_N		1
#define real_max_t		real16_t
#else
#define TYPE_REAL_N		0
#endif

#if !defined(signbit) || (defined(HAVE___FLOAT128) && !defined(HAVE_SIGNBIT___FLOAT128))
#ifdef signbit
#undef signbit
#endif
int signbit_d(double d);
#define signbit(x)		signbit_d((double)(x))
#define need_signbit_d
#endif


/* these macros cause a crash on 64-bit HPUX */
#if defined(isunordered) && defined(islessgreater) && defined(isgreater) && defined(isgreaterequal) && defined(isless) && defined(islessequal)
#if GNUC_ATLEAST(3,0,0) && defined(__linux__)
#define use_is_macros
#endif
#endif

typedef uchar_efficient_t ajla_flat_option_t;


typedef int32_t pcode_t;
typedef uint32_t upcode_t;

#define SIZEOF_IP_T		4
typedef uint32_t ip_t;
typedef uint32_t frame_t;
typedef uint32_t stack_size_t;
#define ARG_MODE_N		3
typedef uint32_t arg_t;
#define NO_FRAME_T		((frame_t)-1)

typedef frame_t ajla_option_t;	/* some code casts ajla_option_t to frame_t */

#if (defined(HAVE_SYS_MMAN_H) && defined(HAVE_MMAP)) || defined(OS_OS2) || defined(OS_WIN32)
#define USE_AMALLOC
#endif

#if defined(SIZEOF_VOID_P) && SIZEOF_VOID_P >= 8 && !defined(UNUSUAL_NO_POINTER_COMPRESSION) && defined(USE_AMALLOC) && !defined(__hpux) && !defined(__OpenBSD__)
#define POINTER_COMPRESSION_POSSIBLE	3
#endif

#if defined(POINTER_COMPRESSION_POSSIBLE) && defined(HAVE_SYS_MMAN_H) && (defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__APPLE__))
#include <sys/mman.h>
#ifndef MAP_EXCL
#undef POINTER_COMPRESSION_POSSIBLE
#endif
#endif


#if defined(C_BIG_ENDIAN) ^ defined(UNUSUAL)
#define CODE_ENDIAN	1
#else
#define CODE_ENDIAN	0
#endif

#if !defined(UNUSUAL)
#define STACK_INITIAL_SIZE		1024
#else
#define STACK_INITIAL_SIZE		1
#endif

/* valid values: 16 - 128 */
#if !defined(UNUSUAL)
#define BTREE_MAX_SIZE			16
#else
#define BTREE_MAX_SIZE			128
#endif

#define DEFAULT_TICK_US			10000
