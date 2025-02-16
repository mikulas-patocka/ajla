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

#ifdef HAVE_STDINT_H

#include <stdint.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#else

#ifdef HAVE_INT_T_U_INT_T

typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;

#else

typedef signed char int8_t;
typedef unsigned char uint8_t;

#if SIZEOF_UNSIGNED_SHORT == 2
typedef signed short int16_t;
typedef unsigned short uint16_t;
#else
no type for int16_t
#endif

#if SIZEOF_UNSIGNED == 4
typedef signed int32_t;
typedef unsigned uint32_t;
#elif SIZEOF_UNSIGNED_LONG == 4
typedef signed long int32_t;
typedef unsigned long uint32_t;
#else
no type for int32_t
#endif

#endif

#if defined(SIZEOF_UNSIGNED) && defined(SIZEOF_VOID_P) && SIZEOF_UNSIGNED && SIZEOF_UNSIGNED == SIZEOF_VOID_P
typedef int intptr_t;
typedef unsigned uintptr_t;
#elif defined(SIZEOF_UNSIGNED_LONG) && defined(SIZEOF_VOID_P) && SIZEOF_UNSIGNED_LONG && SIZEOF_UNSIGNED_LONG == SIZEOF_VOID_P
typedef long intptr_t;
typedef unsigned long uintptr_t;
#elif defined(SIZEOF_UNSIGNED_LONG_LONG) && defined(SIZEOF_VOID_P) && SIZEOF_UNSIGNED_LONG_LONG && SIZEOF_UNSIGNED_LONG_LONG == SIZEOF_VOID_P
typedef long long intptr_t;
typedef unsigned long long uintptr_t;
#else
typedef long intptr_t;
typedef unsigned long uintptr_t;
#endif


#ifndef HAVE_INT64_T_UINT64_T
#ifdef HAVE_INT64_T_U_INT64_T
typedef u_int64_t uint64_t;
#define HAVE_INT64_T_UINT64_T	1
#elif defined(SIZEOF_UNSIGNED_LONG) && SIZEOF_UNSIGNED_LONG == 8
typedef signed long int64_t;
typedef unsigned long uint64_t;
#define HAVE_INT64_T_UINT64_T	1
#elif defined(SIZEOF_UNSIGNED_LONG_LONG) && SIZEOF_UNSIGNED_LONG_LONG == 8
typedef signed long long int64_t;
typedef unsigned long long uint64_t;
#define HAVE_INT64_T_UINT64_T	1
#elif defined(_MSC_VER) || defined(__BORLANDC__)
typedef signed __int64 int64_t;
typedef unsigned __int64 uint64_t;
#define HAVE_INT64_T_UINT64_T	1
#endif
#endif

#ifdef HAVE_INT64_T_UINT64_T
typedef int64_t intmax_t;
typedef uint64_t uintmax_t;
#else
typedef long intmax_t;
typedef unsigned long uintmax_t;
#endif

#endif


#if defined(SIZEOF_UNSIGNED___INT128) && SIZEOF_UNSIGNED___INT128 > 8
typedef __int128 intbig_t;
typedef unsigned __int128 uintbig_t;
#else
typedef intmax_t intbig_t;
typedef uintmax_t uintbig_t;
#endif


#ifdef int8_t
#undef int8_t
#endif
#ifdef int16_t
#undef int16_t
#endif
#ifdef int32_t
#undef int32_t
#endif
#ifdef int64_t
#undef int64_t
#endif
#ifdef int128_t
#undef int128_t
#endif
#ifdef uint8_t
#undef uint8_t
#endif
#ifdef uint16_t
#undef uint16_t
#endif
#ifdef uint32_t
#undef uint32_t
#endif
#ifdef uint64_t
#undef uint64_t
#endif
#ifdef uint128_t
#undef uint128_t
#endif


#ifndef PRIdMAX
#ifdef HAVE_LONG_LONG
#define PRIdMAX	"lld"
#else
#define PRIdMAX	"ld"
#endif
#endif

#ifndef PRIuMAX
#ifdef HAVE_LONG_LONG
#define PRIuMAX	"llu"
#else
#define PRIuMAX	"lu"
#endif
#endif

#ifndef PRIxMAX
#ifdef HAVE_LONG_LONG
#define PRIxMAX	"llx"
#else
#define PRIxMAX	"lx"
#endif
#endif

#ifndef PRIXMAX
#ifdef HAVE_LONG_LONG
#define PRIXMAX	"llX"
#else
#define PRIXMAX	"lX"
#endif
#endif


#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
#ifndef __bool_true_false_are_defined
#define bool	char
#define false	0
#define true	1
#endif

#ifndef HAVE_SOCKLEN_T
#define socklen_t	int
#endif

#ifndef HAVE_SIG_ATOMIC_T
#define sig_atomic_t	int
#endif

#ifdef HAVE_C11_ATOMICS
#ifndef __cplusplus
#include <stdatomic.h>
#endif
#define atomic_type		_Atomic
#define load_relaxed(p)		atomic_load_explicit(p, memory_order_relaxed)
#define store_relaxed(p, v)	atomic_store_explicit(p, v, memory_order_relaxed)
#else
#define atomic_type		volatile
#define load_relaxed(p)		(*(p))
#define store_relaxed(p, v)	(*(p) = (v))
#endif


#if defined(HAVE_STDBIT_H)
#include <stdbit.h>
#endif


#if defined(SIZEOF_VOID_P) && SIZEOF_VOID_P > 0
#if SIZEOF_VOID_P >= 8
#define BIT64
#endif
#elif defined(__INITIAL_POINTER_SIZE)
#if __INITIAL_POINTER_SIZE >= 64
#define BIT64
#endif
#elif defined(_LP64) || defined(__LP64__) || defined(_WIN64)
#define BIT64
#endif


#ifndef UNUSUAL_UNKNOWN_ENDIAN
#if defined(HAVE_STDBIT_H) && __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_LITTLE__
#define C_LITTLE_ENDIAN
#elif defined(HAVE_STDBIT_H) && __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__
#define C_BIG_ENDIAN
#elif defined(CONFIG_LITTLE_ENDIAN)
#define C_LITTLE_ENDIAN
#elif defined(CONFIG_BIG_ENDIAN)
#define C_BIG_ENDIAN
#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define C_LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define C_BIG_ENDIAN
#endif
#endif


#define extern_const		const


#define stringify_internal(arg)	#arg
#define stringify(arg)		stringify_internal(arg)
#define file_line		__FILE__ ":" stringify(__LINE__)


/*
 * The defined() operator in macro expansion is not portable.
 */
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define DEFINED___GNUC____GNUC_MINOR__	1
#else
#define DEFINED___GNUC____GNUC_MINOR__	0
#endif

#if defined(__GNUC_PATCHLEVEL__)
#define DEFINED___GNUC_PATCHLEVEL__	1
#else
#define DEFINED___GNUC_PATCHLEVEL__	0
#endif

#define GNUC_ATLEAST(x, y, z)					\
	(DEFINED___GNUC____GNUC_MINOR__ &&			\
	 (__GNUC__ > (x) ||					\
	  (__GNUC__ == (x) &&					\
	   (__GNUC_MINOR__ > (y) ||				\
	    (__GNUC_MINOR__ == (y) &&				\
	     (!DEFINED___GNUC_PATCHLEVEL__ ||			\
	      __GNUC_PATCHLEVEL__ >= (z)			\
	     )							\
	    )							\
	   )							\
	  )							\
	 )							\
	)

#if defined(__clang__) && defined(__clang_major__) && defined(__clang_minor__)
#define DEFINED___CLANG____CLANG_MAJOR____CLANG_MINOR__	1
#else
#define DEFINED___CLANG____CLANG_MAJOR____CLANG_MINOR__ 0
#endif

#if defined(__clang_patchlevel__)
#define DEFINED___CLANG_PATCHLEVEL__			1
#else
#define DEFINED___CLANG_PATCHLEVEL__			0
#endif

#define CLANG_ATLEAST(x, y, z)					\
	(DEFINED___CLANG____CLANG_MAJOR____CLANG_MINOR__ &&	\
	 (__clang_major__ > (x) ||				\
	  (__clang_major__ == (x) &&				\
	   (__clang_minor__ > (y) ||				\
	    (__clang_minor__ == (y) &&				\
	     (!DEFINED___CLANG_PATCHLEVEL__ ||			\
	      __clang_patchlevel__ >= (z)			\
	     )							\
	    )							\
	   )							\
	  )							\
	 )							\
	)

#if defined(__GNUC__) && !(defined(__clang__) || defined(__llvm__) || defined(__ICC) || defined(__OPEN64__) || defined(__PATHSCALE__) || defined(__PGI) || defined(__PGIC__))
#define HAVE_REAL_GNUC
#endif

#if GNUC_ATLEAST(2,0,0)
#define return_address		__builtin_return_address(0)
#endif

#if GNUC_ATLEAST(2,0,0)
#define is_constant(expression)	__builtin_constant_p(expression)
#else
#define is_constant(expression)	(false)
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && __GNUC__ == 2 && __GNUC_MINOR__ <= 7
/*
 * Verify that the __attribute__ directive is properly placed. GCC 2 has more
 * strict attribute placing rules than gcc 3 and following versions.
 *
 * egcs crashes on empty __attribute__ directive
 */
#define attr_nothing		__attribute__(())
#else
#define attr_nothing
#endif

#if GNUC_ATLEAST(2,0,0)
#define attr_unaligned		__attribute__((packed))
#endif

#if GNUC_ATLEAST(2,0,0) && !defined(__MINGW32__)
#define attr_printf(x, y)	__attribute__((format(printf, x, y)))
#else
#define attr_printf(x, y)
#endif

#if defined(HAVE_STDNORETURN_H) && !defined(__cplusplus) && !defined(__ICC)
#include <stdnoreturn.h>
#define attr_noreturn		noreturn void
#elif GNUC_ATLEAST(2,5,0)
#define attr_noreturn		void __attribute__((noreturn))
#elif defined(_MSC_VER) && _MSC_VER >= 1600	/* not sure */
#define attr_noreturn		void __declspec(noreturn)
#else
#define attr_noreturn		void
#endif

#if GNUC_ATLEAST(2,7,0)
#define attr_unused		__attribute__((__unused__))
#else
#define attr_unused		attr_nothing
#endif

#if GNUC_ATLEAST(2,96,0)
#define likely(x)		(__builtin_expect((int)(x), 1))
#define unlikely(x)		(__builtin_expect((int)(x), 0))
#else
#define likely(x)		((int)(x))
#define unlikely(x)		((int)(x))
#endif

#if GNUC_ATLEAST(3,0,0) && !defined(__DJGPP__)	/* not sure */
#define attr_aligned(x)		__attribute__((__aligned__(x)))
#elif defined(_MSC_VER) && _MSC_VER >= 1600       /* not sure */
#define attr_aligned(x)		__declspec(align(x))
#else
#define attr_aligned(x)		attr_nothing
#endif

#if GNUC_ATLEAST(3,1,0)
#define attr_noinline		__attribute__((__noinline__))
#elif defined(_MSC_VER) && _MSC_VER >= 1600	/* not sure */
#define attr_noinline		__declspec(noinline)
#else
#define attr_noinline
#endif

#if GNUC_ATLEAST(3,1,0)
#define attr_always_inline	inline __attribute__((__always_inline__))
#elif defined(_MSC_VER) && _MSC_VER >= 1600	/* not sure */
#define attr_always_inline	__forceinline
#else
#define attr_always_inline	inline
#endif

#if defined(HAVE_REAL_GNUC) && !defined(UNUSUAL)
#define INLINE_WORKS
#endif

#if GNUC_ATLEAST(3,4,0)
#define attr_w			__attribute__((__warn_unused_result__))
#else
#define attr_w			attr_nothing
#endif

#if GNUC_ATLEAST(4,3,0)
#define attr_cold		__attribute__((__noinline__,__cold__))
#define attr_hot		__attribute__((/*__hot__*/))
#elif GNUC_ATLEAST(3,1,0)
#define attr_cold		__attribute__((__noinline__))
#define attr_hot		attr_nothing
#else
#define attr_cold		attr_nothing
#define attr_hot		attr_nothing
#endif

#if GNUC_ATLEAST(4,5,0)
#define attr_noclone		__attribute__((__noclone__))
#else
#define attr_noclone		attr_nothing
#endif

#if GNUC_ATLEAST(3,0,0) && !defined(__PCC__) && defined(__i386__)
#if GNUC_ATLEAST(4,1,0) && defined(HAVE_REAL_GNUC) && defined(__SSE__) && defined(__SSE_MATH__)
#define attr_fastcall		__attribute__((__regparm__(3),__sseregparm__))
#else
#define attr_fastcall		__attribute__((__regparm__(3)))
#endif
#elif GNUC_ATLEAST(4,4,0) && defined(__x86_64__) && (defined(__CYGWIN__) || defined(__WIN32))
/*#define attr_fastcall		__attribute__((__sysv_abi__))*/
#define attr_fastcall		attr_nothing
#elif defined(_MSC_VER)
#define attr_fastcall		__fastcall
#elif defined(__TURBOC__) || defined(__BORLANDC__)
#define attr_fastcall		__fastcall
#else
#define attr_fastcall		attr_nothing
#endif

#define attr_hot_fastcall	attr_hot attr_fastcall

#if defined(__GNUC__) && defined(__OPTIMIZE__) && !defined(__OPEN64__)
attr_noreturn not_reached(void);
#else
#define not_reached()		internal(file_line, "this location should not be reached")
#endif

/* Borland C has preprocessor expansion size limits */
#if (defined(__TURBOC__) || defined(__BORLANDC__)) && !defined(__BIGGEST_ALIGNMENT__)
#define __BIGGEST_ALIGNMENT__	8
#endif

#define HEAP_ALIGN		(is_power_of_2(sizeof(void *)) ? sizeof(void *) * 2 : 16)

#if GNUC_ATLEAST(1,36,0)
#define align_of(type)		__alignof__(type)
#elif defined(HAVE_STDALIGN_H)
#include <stdalign.h>
#define align_of(type)		alignof(type)
#else
#define align_of(type)		minimum(HEAP_ALIGN,			\
				!sizeof(type) ? 1 :			\
				sizeof(type) & -sizeof(type))
#endif

#if defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901
#define FLEXIBLE_ARRAY
#elif defined(__GNUC__) && !defined(GNUC_PEDANTIC)
#define FLEXIBLE_ARRAY		0
#else
#define FLEXIBLE_ARRAY		1
#endif

#if defined(__GNUC__) && !defined(GNUC_PEDANTIC)
#define FLEXIBLE_ARRAY_GCC	0
#define EMPTY_TYPE		struct { }
#else
#define FLEXIBLE_ARRAY_GCC	1
#define EMPTY_TYPE		char
#endif

static attr_always_inline void *return_ptr(const void *ptr)
{
	return (void *)ptr;
}

#if defined(HAVE_REAL_GNUC)
#define cast_ptr(type, ptr)	((type)return_ptr(ptr))
#else
#define cast_ptr(type, ptr)	((type)(void *)(ptr))
#endif

#if 1
#define cast_cpp		cast_ptr
#else
#define cast_cpp(type, ptr)	(ptr)
#endif

#ifndef HAVE___BUILTIN_ASSUME_ALIGNED
#define __builtin_assume_aligned(p, align)		(p)
#endif


/*
 * We allocate partial structures with union as the last member.
 * If this causes problems with any compiler, enable this.
 */
#if 0
#define partial_sizeof_lower_bound(full)		sizeof(full)
#define partial_sizeof(full, part)			sizeof(full)
#define partial_sizeof_array(full, part, extra)		maximum_maybe0(sizeof(full), (offsetof(full, part) + (extra) * sizeof(((full *)NULL)->part[0])))
#else
#define partial_sizeof_lower_bound(full)		((size_t)0)
#define partial_sizeof(full, part)			(offsetof(full, part) + sizeof(((full *)NULL)->part))
#define partial_sizeof_array(full, part, extra)		(offsetof(full, part) + (extra) * sizeof(((full *)NULL)->part[0]))
#endif

#if defined(_MSC_VER)
#define barrier_aliasing()	do { } while (0)
#elif defined(HAVE_GCC_ASSEMBLER)
#define barrier_aliasing()	__asm__ volatile ("":::"memory")
#else
#define NEED_EXPLICIT_ALIASING_BARRIER
extern volatile char * volatile alias_ptr;
#define barrier_aliasing()	\
do {				\
	*alias_ptr = 0;		\
} while (0)
#endif

#if defined(HAVE_GCC_ASSEMBLER)
#define ASM_PREVENT_CSE		__asm__ volatile ("":::"memory")
#else
#define ASM_PREVENT_CSE		do { } while (0)
#endif

#if defined(HAVE_GCC_ASSEMBLER) && 0
#define ASM_PREVENT_JOIN(i)	__asm__ (""::"i"(i))
#else
#define ASM_PREVENT_JOIN(i)	do { } while (0)
#endif

#if defined(HAVE_GCC_ASSEMBLER)
#define asm_copy(dest, src)	__asm__ volatile (".if 0 \n .endif" : "=r"(dest) : "0"(src))
#endif

#if !defined(HAVE_INT64_T_UINT64_T)
#define EFFICIENT_WORD_SIZE	32
#elif defined(BIT64) || defined(__x86_64__) || defined(__aarch64__) || (defined(_PA_RISC2_0) && defined(__HP_cc)) || (defined(__VMS) && !defined(__VAX))
#define EFFICIENT_WORD_SIZE	64
#else
#define EFFICIENT_WORD_SIZE	32
#endif

#define int_efficient_t		cat4(int,EFFICIENT_WORD_SIZE,_,t)
#define uint_efficient_t	cat4(uint,EFFICIENT_WORD_SIZE,_,t)

#if defined(__alpha__) && (!defined(__alpha_bwx__) || defined(DEBUG_ENV))
typedef int32_t char_efficient_t;
typedef uint32_t uchar_efficient_t;
typedef int32_t short_efficient_t;
typedef uint32_t ushort_efficient_t;
#else
typedef int8_t char_efficient_t;
typedef uint8_t uchar_efficient_t;
typedef int16_t short_efficient_t;
typedef uint16_t ushort_efficient_t;
#endif


#if defined(HAVE_COMPUTED_GOTO) && defined(__clang__) && 0
/* Clang supports computed goto but it increases compilation time extremely. */
#undef HAVE_COMPUTED_GOTO
#endif

#if defined(HAVE_COMPUTED_GOTO) && defined(GNUC_PEDANTIC)
#undef HAVE_COMPUTED_GOTO
#endif


#if !defined(UNUSUAL_NO_ASSEMBLER)

#if defined(HAVE_GCC_ASSEMBLER) && (defined(__i386__) || defined(__x86_64__))

#define ARCH_X86
#ifdef HAVE_GCC_ASSEMBLER
#define INLINE_ASM_GCC_X86
#endif

#if defined(__i386__)
#define ARCH_X86_32
#define ARCH_NAME	"i386"
#ifdef HAVE_GCC_ASSEMBLER
#define INLINE_ASM_GCC_I386
#endif
#elif defined(__x86_64__) && !defined(__ILP32__)
#define ARCH_X86_64
#define ARCH_NAME	"x86_64"
#ifdef HAVE_GCC_ASSEMBLER
#define INLINE_ASM_GCC_X86_64
#endif
#else
#define ARCH_X86_X32
#define ARCH_NAME	"x86_x32"
#ifdef HAVE_GCC_ASSEMBLER
#define INLINE_ASM_GCC_X32
#endif
#endif

#ifdef HAVE_GCC_ASSEMBLER

#if defined(__clang__) || defined(__llvm__) || !GNUC_ATLEAST(4,0,0)	/* !!! TODO: check GCC version exactly */
/*
 * LLVM has inefficient "rm" implementation - it always references memory
 * on the stack - https://bugs.llvm.org/show_bug.cgi?id=9723
 *
 * gcc 2.7 and 3.0 can't concatenate strings in asm constraint
 */
#define X86_ASM_M
#else
#define X86_ASM_M		"m"
#endif

#ifndef __SSE__
#define X86_ASM_XMM0_CLOB
#define X86_ASM_XMM0_CLOBC
#define X86_ASM_XMM1_CLOBC
#else
#define X86_ASM_XMM0_CLOB	: "xmm0"
#define X86_ASM_XMM0_CLOBC	, "xmm0"
#define X86_ASM_XMM1_CLOBC	, "xmm1"
#endif

#ifndef __AVX__
#define X86_ASM_V
#define X86_ASM_AVX_PARAM(x)	#x
#else
#define X86_ASM_V		"v"
#define X86_ASM_AVX_PARAM(x)	#x ", " #x
#endif

#endif

#elif defined(_M_IX86)

#define ARCH_X86
#define ARCH_X86_32
#define ARCH_NAME	"i386"

#elif defined(_M_X64)

#define ARCH_X86
#define ARCH_X86_64
#define ARCH_NAME	"x86_64"

#elif defined(__alpha__)

#define ARCH_ALPHA
#define ARCH_NAME	"alpha"

#elif (defined(__arm__) && defined(__ARM_EABI__) && (!defined(__thumb__) || defined(__thumb2__))) || defined(__aarch64__)

#define ARCH_ARM
#ifdef __aarch64__
#define ARCH_ARM64
#define ARCH_NAME	"aarchc64"
#else
#define ARCH_ARM32
#define ARCH_NAME	"arm"
#endif

#ifdef __ARM_ARCH
#define ARM_VERSION	__ARM_ARCH
#elif defined(__ARM_ARCH_8A__) || defined(__ARM_ARCH_8A)
#define ARM_VERSION		8
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
#define ARM_VERSION		7
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__ARM_ARCH_6T2__) || defined(__ARM_ARCH_6M__)
#define ARM_VERSION		6
#elif defined(__ARM_ARCH_5__) || defined(__ARM_ARCH_5T__) || defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__)
#define ARM_VERSION		5
#elif defined(__ARM_ARCH_4__) || defined(__ARM_ARCH_4T__) || defined(__ARM_ARCH_3M__)
#define ARM_VERSION		4
#elif defined(__ARM_ARCH_3__)
#define ARM_VERSION		3
#elif defined(__ARM_ARCH_2__)
#define ARM_VERSION		2
#else
#define ARM_VERSION		1
#define ARM_VERSION_UNKNOWN
#endif

#if defined(HAVE_GCC_ASSEMBLER) && defined(HAVE_ARM_ASSEMBLER) && !defined(ARCH_ARM64)
#define INLINE_ASM_GCC_ARM
#if ARM_VERSION < 8
#define ARM_ASM_PREFIX		".cpu cortex-a15\n .fpu neon-vfpv4\n;;;;;;;;;;;;;;;;\n"
#else
#define ARM_ASM_PREFIX		".fpu neon-vfpv4\n;;;;;;;;;;;;;;;;\n"
#endif
#define ARM_ASM_APSR		"apsr"
#define ARM_ASM_LO		"Q"
#define ARM_ASM_HI		"R"
#if !defined(__thumb2__)
#define ARM_ASM_S		""
#define ARM_ASM_S_CLOB
#define ARM_ASM_IF_T12(x,y)	y
#else
#define INLINE_ASM_GCC_ARM_THUMB2
#define ARM_ASM_STRD		"strd"
#define ARM_ASM_S		"s"
#define ARM_ASM_S_CLOB		: "cc"
#define ARM_ASM_IF_T12(x,y)	x
#endif
#endif

#if defined(HAVE_GCC_ASSEMBLER) && defined(ARCH_ARM64)
#define INLINE_ASM_GCC_ARM64
#define ARM_ASM_PREFIX
#define ARM_ASM_APSR		"nzcv"
#define ARM_ASM_LO		"x"
#define ARM_ASM_HI		"H"
#define ARM_ASM_STRD		"stp"
#define ARM_ASM_S		""
#define ARM_ASM_S_CLOB
#define ARM_ASM_IF_T12(x,y)	y
#endif

#if defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_8A__) || defined(__ARM_ARCH_8A) || (defined(__ARM_ARCH_PROFILE) && __ARM_ARCH_PROFILE == 'A')
#define ARM_ASM_DIV_NO_TRAP	1
#else
#define ARM_ASM_DIV_NO_TRAP	0
#endif

#elif defined(__ia64) && defined(__linux__)

#define ARCH_IA64
#define ARCH_NAME	"ia64"

#elif defined(__loongarch64)

#define ARCH_LOONGARCH64
#define ARCH_NAME	"loongarch64"

#elif defined(__mips) && defined(_MIPS_SIM) && (_MIPS_SIM == 1 || _MIPS_SIM == 2 || _MIPS_SIM == 3)

#define ARCH_MIPS
#if defined(__LP64__)
#define ARCH_MIPS64
#define ARCH_NAME	"mips64"
#else
#define ARCH_MIPS32
#define ARCH_NAME	"mips"
#if _MIPS_SIM == 1
#define ARCH_MIPS_O32
#else
#define ARCH_MIPS_N32
#endif
#endif

#elif defined(__hppa)

#define ARCH_PARISC
#if defined(__LP64__)
#define ARCH_PARISC64
#define ARCH_NAME	"parisc64"
#define PA_SPACES		0
#else
#define ARCH_PARISC32
#define ARCH_NAME	"parisc"
#ifdef __hpux
#define PA_SPACES		1
#else
#define PA_SPACES		0
#endif
#endif

#elif defined(__PPC__)

#define ARCH_POWER
#if defined(__LP64__)
#define ARCH_POWER64
#define ARCH_NAME	"power64"
#else
#define ARCH_POWER32
#define ARCH_NAME	"power"
#endif

#elif defined(__s390__)

#define ARCH_S390
#if defined(__LP64__)
#define ARCH_S390_64
#define ARCH_NAME	"s390x"
#else
#define ARCH_S390_32
#define ARCH_NAME	"s390"
#endif

#elif defined(__sparc__)

#define ARCH_SPARC
#if defined(__LP64__)
#define ARCH_SPARC64
#define ARCH_NAME	"sparc64"
#else
#define ARCH_SPARC32
#define ARCH_NAME	"sparc"
#endif

#elif defined(__riscv) && defined(_LP64)

#define ARCH_RISCV64
#define ARCH_NAME	"riscv64"

#endif


#ifdef ARCH_X86
#if defined(OS_CYGWIN) || defined(OS_WIN32)
#define ARCH_X86_WIN_ABI
#endif
#endif


#if defined(HAVE_ASM_GOTO) && !defined(UNUSUAL_NO_ASSEMBLER_GOTO)
#define INLINE_ASM_GCC_LABELS
#endif

#endif


#if !defined(UNUSUAL_NO_TAGGED_POINTERS)
#if defined(HAVE_MMAP) || defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32)
#if defined(ARCH_ALPHA)
#define HAVE_CODEGEN
#define HAVE_CODEGEN_TRAPS
#endif
#if defined(ARCH_ARM32) && defined(__ARMEL__)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_ARM64) && !defined(__ILP32__) && defined(HAVE___BUILTIN___CLEAR_CACHE)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_IA64)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_LOONGARCH64)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_MIPS)
#define HAVE_CODEGEN
#define HAVE_CODEGEN_TRAPS
#endif
#if defined(ARCH_PARISC)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_POWER)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_S390)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_SPARC)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_RISCV64)
#define HAVE_CODEGEN
#endif
#if defined(ARCH_X86)
#define HAVE_CODEGEN
#endif
#endif
#endif

#if defined(HAVE_CODEGEN) && (defined(HAVE_MPROTECT) || defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32))
#if defined(ARCH_ARM) && defined(HAVE___BUILTIN___CLEAR_CACHE)
#define CODEGEN_USE_HEAP
#endif
#if defined(ARCH_PARISC) && defined(HAVE_GCC_ASSEMBLER)
#define CODEGEN_USE_HEAP
#endif
#if defined(ARCH_RISCV64) && defined(HAVE___BUILTIN___CLEAR_CACHE)
#define CODEGEN_USE_HEAP
#endif
#if defined(ARCH_S390)
#define CODEGEN_USE_HEAP
#endif
#if defined(ARCH_SPARC64) && defined(HAVE_GCC_ASSEMBLER)
#define CODEGEN_USE_HEAP
#endif
#if defined(ARCH_X86)
#define CODEGEN_USE_HEAP
#endif
#endif

#if defined(CODEGEN_USE_HEAP) && defined(DISABLE_RWX_MAPPINGS)
#undef CODEGEN_USE_HEAP
#endif

#define CODE_ALIGNMENT		16


#ifdef attr_unaligned
#if defined(__i386__) || defined(__x86_64__) || defined(__ARM_FEATURE_UNALIGNED) || defined(__alpha__) || defined(__m68k__) || defined(__mips) || defined(__powerpc__) || defined(__s390__)
/* define if unaligned access to code array is faster then assembling the value from 16-bit code_t entries */
#define UNALIGNED_ACCESS
#endif
#endif
#if defined(__i386__) || defined(__x86_64__) || defined(__ARM_FEATURE_UNALIGNED) || defined(__m68k__) || defined(__powerpc__) || defined(__s390__)
/* define if unaligned access results in the same instructions as aligned access */
#define UNALIGNED_ACCESS_EFFICIENT
#endif


#ifdef THREAD_NONE
#define SMP_ALIAS_ALIGNMENT	1
#else
#define SMP_ALIAS_ALIGNMENT	128
#ifdef __SANITIZE_THREAD__
#define THREAD_SANITIZER
#endif
#endif


#ifdef UNUSUAL_ARITHMETICS
#define DIVIDE_ROUNDS_TO_ZERO	0
#define RIGHT_SHIFT_KEEPS_SIGN	0
#else
#define DIVIDE_ROUNDS_TO_ZERO	((intmax_t)9 / -4 == -2 &&	\
				 (intmax_t)-9 / 4 == -2 &&	\
				 (intmax_t)-9 / -4 == 2 &&	\
				 (intmax_t)9 % -4 == 1 &&	\
				 (intmax_t)-9 % 4 == -1 &&	\
				 (intmax_t)-9 % -4 == -1)
#define RIGHT_SHIFT_KEEPS_SIGN	((~(intmax_t)0x1234U >> 1) == ~(intmax_t)0x91aU)
#endif


/* Define if volatile access to pointer, uintptr_t and uint32_t is atomic */
#if (SIZEOF_UNSIGNED >= 4 || defined(THREAD_NONE)) && !defined(THREAD_SANITIZER)
#define POINTERS_ARE_ATOMIC
#endif


#define BAD_POINTER_1		((void *)(uintptr_t)1)
#define BAD_POINTER_2		((void *)(uintptr_t)2)
#define BAD_POINTER_3		((void *)(uintptr_t)3)
#define SPECIAL_POINTER_1	BAD_POINTER_1
#define SPECIAL_POINTER_2	BAD_POINTER_2
#define SPECIAL_POINTER_3	BAD_POINTER_3
#if !defined(UNUSUAL_NO_TAGGED_POINTERS) && !defined(UNUSUAL_NO_ARCH_TAGGED_POINTERS)
#if defined(HAVE_POINTER_TAGS) && defined(__aarch64__) && !defined(__ILP32__)
#define POINTER_IGNORE_START	56
#define POINTER_IGNORE_BITS	8
#elif defined(HAVE_POINTER_TAGS) && defined(__s390__) && !defined(__LP64__)
#define POINTER_IGNORE_START	31
#define POINTER_IGNORE_BITS	1
#else
#define POINTER_TAG_BIT		0
#define POINTER_TAG		((uintptr_t)1 << POINTER_TAG_BIT)
#endif
#endif

#ifdef POINTER_TAG
static inline void *POINTER_TAG_ADD(void *ptr)
{
	return (void *)((uintptr_t)ptr + POINTER_TAG);
}
static inline void *POINTER_TAG_CLEAR(void *ptr)
{
	return (void *)((uintptr_t)ptr & ~(uintptr_t)POINTER_TAG);
}
static inline void *POINTER_TAG_SUB(void *ptr)
{
	return (void *)((uintptr_t)ptr - POINTER_TAG);
}
static inline uintptr_t POINTER_TAG_GET(const void *ptr)
{
	return (uintptr_t)ptr & POINTER_TAG;
}
#endif
#ifdef POINTER_IGNORE_START
#define POINTER_IGNORE_TOP_BIT		(POINTER_IGNORE_START + POINTER_IGNORE_BITS - 1)
#define POINTER_IGNORE_MASK		((((uintptr_t)1 << POINTER_IGNORE_BITS) - 1) << POINTER_IGNORE_START)
#define POINTER_IGNORE_TOP		((uintptr_t)1 << POINTER_IGNORE_TOP_BIT)
#endif


#ifdef __ICC
#define CLZ_BSR_OP	-
#else
#define CLZ_BSR_OP	^
#endif

#if defined(HAVE_REAL_GNUC) && defined(__mips_isa_rev) && __mips_isa_rev >= 6
#define broken_128bit_multiply		volatile
#else
#define broken_128bit_multiply
#endif
