# Copyright (C) 2024 Mikulas Patocka
#
# This file is part of Ajla.
#
# Ajla is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# Ajla is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Ajla. If not, see <https://www.gnu.org/licenses/>.

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(ajla, 0.1.5)
AC_CONFIG_SRCDIR(ajla.c)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE(-Wall -Werror)

if uname 2>/dev/null | grep -i OS/2 >/dev/null || uname 2>/dev/null | grep -i Dos >/dev/null; then
	ac_cv_path_GREP=grep
fi

ACLOCAL="touch aclocal.m4; echo >/dev/null"
AUTOCONF="touch configure; echo >/dev/null"
AUTOMAKE="touch Makefile.in; echo >/dev/null"
AUTOHEADER="touch config.h.in; echo >/dev/null"

AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC

CPPFLAGS="-D_GNU_SOURCE -D_ALL_SOURCE $CPPFLAGS"

case ${host_os} in
	*bsd*)
		CPPFLAGS="$CPPFLAGS -I/usr/local/include"
		LDFLAGS="$LDFLAGS -L/usr/local/lib"
		;;
esac

AC_CACHE_CHECK([for EMX], ac_cv_have_emx,
	AC_TRY_COMPILE(, [#ifndef __EMX__
	kill me!
	#endif ], ac_cv_have_emx=yes, ac_cv_have_emx=no)
)
AC_CACHE_CHECK([for WIN32], ac_cv_have_win32,
	AC_TRY_COMPILE(, [#ifndef _WIN32
	kill me!
	#endif ], ac_cv_have_win32=yes, ac_cv_have_win32=no)
)
AC_CACHE_CHECK([for Minix 3], ac_cv_have_minix3,
	AC_TRY_COMPILE(, [#ifndef __minix__
	kill me!
	#endif ], ac_cv_have_minix3=yes, ac_cv_have_minix3=no)
)

AC_ARG_ENABLE(threads, [  --disable-threads       disable threads], enable_threads="$enableval", enable_threads=yes)

if test "$enable_threads" != no && test "$ac_cv_have_minix3" = no; then
	if test "$enable_threads" = pthread || test "$ac_cv_have_emx" != yes -a "$ac_cv_have_win32" != yes; then
		AX_PTHREAD
		LIBS="$PTHREAD_LIBS $LIBS"
		CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
		CC="$PTHREAD_CC"
	fi
	if test "$ax_pthread_ok" != yes -a "$ac_cv_have_emx" = yes; then
		CFLAGS="$CFLAGS -Zmt"
	fi
	if test "$ax_pthread_ok" = yes -a "$enable_threads" = pthread; then
		AC_DEFINE([HAVE_PTHREAD_PREFER], 1, [Prefer pthreads])
	fi
fi

AC_ARG_ENABLE(computed-goto, [  --disable-computed-goto disable computed goto], enable_computed_goto="$enableval", enable_computed_goto=yes)

AC_ARG_ENABLE(bitwise-frame, [  --enable-bitwise-frame  use bitwise tags on the frame], enable_bitwise_frame="$enableval", enable_bitwise_frame=no)
test "$enable_bitwise_frame" = yes && AC_DEFINE(HAVE_BITWISE_FRAME, 1, Use bitwise frame)

AC_ARG_ENABLE(debuglevel, [  --enable-debuglevel     set internal checking level
	0 - no checks
	1 - checks that don't degrade performane (default)
	2 - checks that degrade performance
	3 - checks that degrade performance seriously], enable_debuglevel="$enableval", enable_debuglevel=1)
if test "$enable_debuglevel" = no; then enable_debuglevel=0; fi
if test "$enable_debuglevel" = yes; then enable_debuglevel=2; fi
AC_DEFINE_UNQUOTED(HAVE_DEBUGLEVEL, $enable_debuglevel, Debugging level)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AX_C_LONG_LONG
AC_C_LONG_DOUBLE
AC_CACHE_CHECK(for __float128, ac_cv_have___float128,
AC_TRY_LINK([
	volatile __float128 a = 0.1;
	volatile __float128 b = 0.2;
	volatile __float128 c, d, e, f;
	volatile int g, h, i, j;
], [
	c = a + b;
	d = a - b;
	e = a * b;
	f = a / b;
	g = e == f;
	h = e != f;
	i = e < f;
	j = e <= f;
], ac_cv_have___float128=yes, ac_cv_have___float128=no))
test "$ac_cv_have___float128" = yes && AC_DEFINE(HAVE___FLOAT128, 1, Have __float128)

AC_CACHE_CHECK(for signbit(__float128), ac_cv_have_signbit__float128,
AC_TRY_RUN([
#include <math.h>
volatile __float128 a = 0.1;
int main(void)
{
	return signbit(a);
}
], ac_cv_have_signbit__float128=yes, ac_cv_have_signbit__float128=no, ac_cv_have_signbit__float128=no))
test "$ac_cv_have_signbit__float128" = yes && AC_DEFINE(HAVE_SIGNBIT___FLOAT128, 1, Have signbit(__float128))

AC_CHECK_TYPES([max_align_t], [], [], [[#include <stddef.h>]])
AC_CHECK_TYPES([sig_atomic_t], [], [], [[#include <signal.h>]])
AC_CHECK_TYPES([sigset_t], [], [], [[#include <signal.h>]])
AC_CHECK_TYPES([socklen_t], [], [], [[
#include <sys/types.h>
#include <sys/socket.h>]])
AC_CHECK_TYPES([_Float16], [], [], [])

default_short=0
default_int=0
default_long=0
default_long_long=0
default_unsigned__int128=0
default_void=0
default_size_t=0

AC_CHECK_SIZEOF(unsigned short,"$default_short")
AC_CHECK_SIZEOF(unsigned, "$default_int")
AC_CHECK_SIZEOF(unsigned long, "$default_long")
AC_CHECK_SIZEOF(unsigned long long, "$default_long_long")
AC_CHECK_SIZEOF(unsigned __int128, "$default_unsigned__int128")
AC_CHECK_SIZEOF(void *, "$default_void")
AC_CHECK_SIZEOF(size_t, "$default_size_t")

if test "$ax_pthread_ok" = yes; then
	AC_CACHE_CHECK([for PTHREAD_MUTEX_ERRORCHECK],
	    ax_cv_PTHREAD_MUTEX_ERRORCHECK, [
		AC_LINK_IFELSE([
		    AC_LANG_PROGRAM([[#include <pthread.h>]], [[int i = PTHREAD_MUTEX_ERRORCHECK;]])],
		    [ax_cv_PTHREAD_MUTEX_ERRORCHECK=yes],
		    [ax_cv_PTHREAD_MUTEX_ERRORCHECK=no])
	    ])
	AS_IF([test "x$ax_cv_PTHREAD_MUTEX_ERRORCHECK" = "xyes"],
	    AC_DEFINE([HAVE_PTHREAD_MUTEX_ERRORCHECK], 1, [Have PTHREAD_MUTEX_ERRORCHECK]))


	AC_CACHE_CHECK([for PTHREAD_MUTEX_ERRORCHECK_NP],
	    ax_cv_PTHREAD_MUTEX_ERRORCHECK_NP, [
		AC_LINK_IFELSE([
		    AC_LANG_PROGRAM([[#include <pthread.h>]], [[int i = PTHREAD_MUTEX_ERRORCHECK_NP;]])],
		    [ax_cv_PTHREAD_MUTEX_ERRORCHECK_NP=yes],
		    [ax_cv_PTHREAD_MUTEX_ERRORCHECK_NP=no])
	    ])
	AS_IF([test "x$ax_cv_PTHREAD_MUTEX_ERRORCHECK_NP" = "xyes"],
	    AC_DEFINE([HAVE_PTHREAD_MUTEX_ERRORCHECK_NP], 1, [Have PTHREAD_MUTEX_ERRORCHECK_NP]))

	AC_CACHE_CHECK([if we can assign to pthread_key_t],
	    ax_cv_pthread_key_t_assign, [
		AC_COMPILE_IFELSE([
		    AC_LANG_PROGRAM([[#include <pthread.h>]], [[pthread_key_t key = (pthread_key_t)-1;]])],
		    [ax_cv_pthread_key_t_assign=yes],
		    [ax_cv_pthread_key_t_assign=no])
	    ])
	AS_IF([test "x$ax_cv_pthread_key_t_assign" = "xyes"],
	    AC_DEFINE([HAVE_PTHREAD_KEY_T_ASSIGN], 1, [Can assign to pthread_key_t]))
fi


AC_CACHE_CHECK(for __thread, ac_cv_have___thread,
AC_TRY_LINK([
	__thread int i = 0;
	static __thread int j = 0;
], [
	return i + j;
], ac_cv_have___thread=yes, ac_cv_have___thread=no))
test "$ac_cv_have___thread" = yes && AC_DEFINE(HAVE___THREAD, __thread, Have thread local storage)

AC_CACHE_CHECK(for computed goto, ac_cv_have_computed_goto,
AC_TRY_LINK([
], [
	static const void *dispatch[[4096]] = {
		[[10]] = &&label_10,
	};
	goto *(void *)dispatch[[10]];
label_10:
	return 0;
#if defined(__GNUC__) && __GNUC__ <= 2
	kill me!
#endif
], ac_cv_have_computed_goto=yes, ac_cv_have_computed_goto=no))
test "$ac_cv_have_computed_goto" = yes && test "$enable_computed_goto" != no && AC_DEFINE(HAVE_COMPUTED_GOTO, 1, Have computed goto)

if echo "$CC" | grep clang >/dev/null; then
	AC_CACHE_CHECK(for -no-integrated-as, ac_cv_have_no_integrated_as,
	save_CFLAGS="$CFLAGS"
	CFLAGS="-no-integrated-as $CFLAGS"
	AC_TRY_LINK([ ], [ ], ac_cv_have_no_integrated_as=yes, ac_cv_have_no_integrated_as=no)
	CFLAGS="$save_CFLAGS"
	)
	test "$ac_cv_have_no_integrated_as" = yes && CFLAGS="-no-integrated-as $CFLAGS"
fi

AC_CACHE_CHECK(for gcc assembler, ac_cv_have_gcc_assembler,
AC_TRY_LINK([
], [
	int src, dest;
	src = 0;
	__asm__ (""::"i"(63355));
	__asm__ volatile ("":::"memory");
	__asm__ (".if 0 \n .endif" : "=r"(dest) : "0"(src));
#ifdef __OPEN64__
	kill me!
#endif
	return dest;
], ac_cv_have_gcc_assembler=yes, ac_cv_have_gcc_assembler=no))
test "$ac_cv_have_gcc_assembler" = yes && AC_DEFINE(HAVE_GCC_ASSEMBLER, 1, Have gcc assembler)

if test "$ac_cv_have_gcc_assembler" = yes; then
	AC_CACHE_CHECK(for asm goto, ac_cv_have_asm_goto,
	AC_TRY_LINK([
	], [
		__asm__ goto("" : : : : label);
		label:
		return 0;
	], ac_cv_have_asm_goto=yes, ac_cv_have_asm_goto=no))
	test "$ac_cv_have_asm_goto" = yes && AC_DEFINE(HAVE_ASM_GOTO, 1, Have asm goto)

	if test "$ac_cv_sizeof_unsigned___int128" != 0; then
		AC_CACHE_CHECK(for assembler __int128, ac_cv_have_assembler___int128,
		AC_TRY_COMPILE([
		], [
			volatile __int128 a, b;
			a = 1;
#if defined(__aarch64__)
			__asm__ ("mov %H0, %H1; mov %x0, %x1" : "=&r"(b) : "r"(a));
#elif defined(__x86_64__)
			__asm__ ("" : "=A"(b) : "A"(a));
#else
			__asm__ ("" : "=r"(b) : "0"(a));
#endif
			return (int)b;
		], ac_cv_have_assembler___int128=yes, ac_cv_have_assembler___int128=no))
		test "$ac_cv_have_assembler___int128" = yes && AC_DEFINE(HAVE_ASSEMBLER___INT128, 1, Have assembler __int128)
	fi

	AC_CACHE_CHECK(for X86 assembler popcnt, ac_cv_have_x86_assembler_popcnt,
	AC_TRY_LINK([
	], [
		__asm__ volatile ("popcntw %%ax, %%bx \n popcntl %%eax, %%ebx":::"eax", "ebx", "cc");
	], ac_cv_have_x86_assembler_popcnt=yes, ac_cv_have_x86_assembler_popcnt=no))
	test "$ac_cv_have_x86_assembler_popcnt" = yes && AC_DEFINE(HAVE_X86_ASSEMBLER_POPCNT, 1, Have X86 popcnt)

	AC_CACHE_CHECK(for X86 assembler lzcnt, ac_cv_have_x86_assembler_lzcnt,
	AC_TRY_LINK([
	], [
		__asm__ volatile ("lzcntw %%ax, %%bx \n lzcntl %%eax, %%ebx":::"eax", "ebx", "cc");
	], ac_cv_have_x86_assembler_lzcnt=yes, ac_cv_have_x86_assembler_lzcnt=no))
	test "$ac_cv_have_x86_assembler_lzcnt" = yes && AC_DEFINE(HAVE_X86_ASSEMBLER_LZCNT, 1, Have X86 lzcnt)

	AC_CACHE_CHECK(for X86 assembler sse, ac_cv_have_x86_assembler_sse,
	AC_TRY_LINK([
	], [
		int i;
		float a = 0;
		__asm__ volatile ("cvtss2si (%1), %0":"=r"(i):"r"(&a));
	], ac_cv_have_x86_assembler_sse=yes, ac_cv_have_x86_assembler_sse=no))
	test "$ac_cv_have_x86_assembler_sse" = yes && AC_DEFINE(HAVE_X86_ASSEMBLER_SSE, 1, Have X86 sse)

	AC_CACHE_CHECK(for X86 assembler sse2, ac_cv_have_x86_assembler_sse2,
	AC_TRY_LINK([
	], [
		int i;
		float a = 0;
		__asm__ volatile ("cvtsd2si (%1), %0":"=r"(i):"r"(&a));
	], ac_cv_have_x86_assembler_sse2=yes, ac_cv_have_x86_assembler_sse2=no))
	test "$ac_cv_have_x86_assembler_sse2" = yes && AC_DEFINE(HAVE_X86_ASSEMBLER_SSE2, 1, Have X86 sse2)

	AC_CACHE_CHECK(for X86 assembler avx, ac_cv_have_x86_assembler_avx,
	AC_TRY_LINK([
	], [
		int i;
		float a = 0;
		__asm__ volatile ("vcvtss2si (%1), %0":"=r"(i):"r"(&a));
	], ac_cv_have_x86_assembler_avx=yes, ac_cv_have_x86_assembler_avx=no))
	test "$ac_cv_have_x86_assembler_avx" = yes && AC_DEFINE(HAVE_X86_ASSEMBLER_AVX, 1, Have X86 avx)

	AC_CACHE_CHECK(for X86 assembler f16c, ac_cv_have_x86_assembler_f16c,
	AC_TRY_LINK([
	], [
		__asm__ volatile ("vcvtps2ph \$0, %%xmm0, %%xmm0":::"memory");
	], ac_cv_have_x86_assembler_f16c=yes, ac_cv_have_x86_assembler_f16c=no))
	test "$ac_cv_have_x86_assembler_f16c" = yes && AC_DEFINE(HAVE_X86_ASSEMBLER_F16C, 1, Have X86 f16c)

	AC_CACHE_CHECK(for ARM assembler, ac_cv_have_arm_assembler,
	AC_TRY_LINK([
	], [
		__asm__ volatile (".cpu cortex-a15 \n .fpu neon-vfpv4 \n mov r1, r2":::"r1", "r2");
	], ac_cv_have_arm_assembler=yes, ac_cv_have_arm_assembler=no))
	test "$ac_cv_have_arm_assembler" = yes && AC_DEFINE(HAVE_ARM_ASSEMBLER, 1, Have ARM assembler)

	if test "$ac_cv_have_arm_assembler" = yes; then
		AC_CACHE_CHECK(for ARM assembler clz, ac_cv_have_arm_assembler_clz,
		AC_TRY_LINK([
		], [
			__asm__ volatile (".cpu cortex-a15 \n .fpu neon-vfpv4 \n clz r1, r2":::"r1", "r2");
		], ac_cv_have_arm_assembler_clz=yes, ac_cv_have_arm_assembler_clz=no))
		test "$ac_cv_have_arm_assembler_clz" = yes && AC_DEFINE(HAVE_ARM_ASSEMBLER_CLZ, 1, Have ARM clz)

		AC_CACHE_CHECK(for ARM assembler rbit, ac_cv_have_arm_assembler_rbit,
		AC_TRY_LINK([
		], [
			__asm__ volatile (".cpu cortex-a15 \n .fpu neon-vfpv4 \n rbit r1, r2":::"r1", "r2");
		], ac_cv_have_arm_assembler_rbit=yes, ac_cv_have_arm_assembler_rbit=no))
		test "$ac_cv_have_arm_assembler_rbit" = yes && AC_DEFINE(HAVE_ARM_ASSEMBLER_RBIT, 1, Have ARM rbit)

		AC_CACHE_CHECK(for ARM assembler sdiv udiv, ac_cv_have_arm_assembler_sdiv_udiv,
		AC_TRY_LINK([
		], [
			__asm__ volatile (".cpu cortex-a15 \n .fpu neon-vfpv4 \n sdiv r1, r2, r3 \n udiv r1, r2, r3":::"r1", "r2", "r3");
		], ac_cv_have_arm_assembler_sdiv_udiv=yes, ac_cv_have_arm_assembler_sdiv_udiv=no))
		test "$ac_cv_have_arm_assembler_sdiv_udiv" = yes && AC_DEFINE(HAVE_ARM_ASSEMBLER_SDIV_UDIV, 1, Have ARM sdiv udiv)

		AC_CACHE_CHECK(for ARM assembler half-precision, ac_cv_have_arm_assembler_half_precision,
		AC_TRY_LINK([
		], [
			__asm__ volatile (".cpu cortex-a15 \n .fpu neon-vfpv4 \n vcvtb.f16.f32 s0, s0 \n vcvtb.f32.f16 s0, s0":::"s0");
		], ac_cv_have_arm_assembler_half_precision=yes, ac_cv_have_arm_assembler_half_precision=no))
		test "$ac_cv_have_arm_assembler_half_precision" = yes && AC_DEFINE(HAVE_ARM_ASSEMBLER_HALF_PRECISION, 1, Have ARM half precision)

		AC_CACHE_CHECK(for ARM assembler vfp, ac_cv_have_arm_assembler_vfp,
		AC_TRY_LINK([
		], [
			__asm__ volatile (".cpu cortex-a15 \n .fpu neon-vfpv4 \n vld1.8 d0[[0]], [[r1]] \n vcnt.8 d0, d0 \n vpaddl.u8 d0, d0 \n vst1.8 d0[[0]], [[r1]]":::"r1", "d0");
		], ac_cv_have_arm_assembler_vfp=yes, ac_cv_have_arm_assembler_vfp=no))
		test "$ac_cv_have_arm_assembler_vfp" = yes && AC_DEFINE(HAVE_ARM_ASSEMBLER_VFP, 1, Have ARM VFP)
	fi
fi

# Checks for header files.
AC_CHECK_HEADERS(asm/prctl.h ffi.h gmp.h gmp/gmp.h linux/falloc.h linux/fs.h malloc.h netdb.h netinet/in.h os2thunk.h quadmath.h signal.h stdalign.h stdatomic.h stdnoreturn.h sys/auxv.h sys/builtin.h sys/epoll.h sys/event.h sys/fmutex.h sys/inotify.h sys/mman.h sys/mount.h sys/netinet.in sys/param.h sys/pstat.h sys/select.h sys/socket.h sys/statvfs.h sys/syscall.h sys/sysctl.h sys/sysmacros.h sys/time.h sys/ucred.h sys/utsname.h sys/vfs.h ucontext.h x86/sysarch.h)

# Checks for libraries.
AC_CHECK_LIB(m, frexp)
if test "$ac_cv_have___float128" = yes && test "$ac_cv_header_quadmath_h" = yes; then
	AC_CHECK_LIB(quadmath, frexpq)
fi
AC_ARG_WITH(gmp, [  --without-gmp           use built-in gmp])
if test "$with_gmp" != "no"; then
	if test "$ac_cv_header_gmp_h" = yes || test "$ac_cv_header_gmp_gmp_h" = yes; then
		AC_CHECK_LIB(gmp, __gmpz_init2)
	fi
fi
if test "$ac_cv_header_ffi_h" = yes; then
	AC_CHECK_LIB(ffi, ffi_prep_cif)
	AC_CHECK_FUNCS(ffi_prep_cif_var)
	if test "$ac_cv_have_emx" = no -a "$ac_cv_have_win32" = no; then
		AC_CHECK_FUNCS(dlopen)
		if test "$ac_cv_have_dlopen" != yes; then
			AC_CHECK_LIB(dl, dlopen)
		fi
	fi
fi

AC_FUNC_MALLOC

AC_CHECK_LIB(xnet, getpeername)

# Checks for library functions.
AC_CHECK_FUNCS(accept4 aligned_alloc amd64_set_gsbase cfmakeraw chown clock_gettime epoll_create fallocate fchdir fchmodat fchownat fdatasync ffs ffsl ffsll fls flsl flsll fstat64 fstatat fstatfs fstatvfs fstatvfs64 ftruncate64 getauxval getenv getfsstat gethostname getpagesize getpeername getvfsstat gmtime_r inotify_init isatty kqueue lchown link linkat localtime_r lseek64 lstat lstat64 madvise memalign mempcpy mkdirat mknod mknodat mkostemp mmap mmap64 mprotect mremap open64 openat pipe2 posix_memalign pread pread64 pstat_getdynamic pthread_condattr_setclock pthread_sigmask pthread_spin_init pwrite pwrite64 raise readlink readlinkat renameat setitimer setvbuf sigaction sigblock sigfillset sigprocmask sigsetmask socket stat64 statfs statvfs statvfs64 strerror strerror_r strnlen strverscmp symlink symlinkat syncfs sysarch syscall sysconf sysctl timegm timer_create truncate64 uname unlinkat utime utimensat utimes vsnprintf _beginthreadex _fmutex_create _threadstore)

AC_CHECK_FUNCS(
	copysign copysignf						\
	nextafter nextafterf nextafterl					\
	fabsf fabsl fabsq						\
	finite finitef finitel finiteq					\
	isnan isnanf isnanl isnanq					\
	lrintf								\
									\
	sqrtf sqrtl sqrtq						\
	cbrt cbrtf cbrtl						\
									\
	sinf sinl							\
	cosf cosl							\
	tanf tanl							\
	asinf asinl							\
	acosf acosl							\
	atanf atanl							\
									\
	sinhf sinhl							\
	coshf coshl							\
	tanhf tanhl							\
	asinh asinhf asinhl						\
	acosh acoshf acoshl						\
	atanh atanhf atanhl						\
									\
	exp2 exp2f exp2l exp2q						\
	expf expl							\
	exp10 exp10f exp10l exp10q					\
	log2 log2f log2l						\
	logf logl							\
	log10f log10l							\
									\
	rint rintf rintl						\
	ceilf ceill							\
	floorf floorl							\
	trunc truncf truncl						\
	modff modfl							\
	frexpf frexpl frexpq						\
									\
	fmodf fmodl							\
	powf powl powq							\
	ldexpf ldexpl ldexpq						\
	atan2f atan2l							\
)

cf_have_socket=yes
if test "$ac_cv_func_socket" != yes; then
	AC_CHECK_LIB(socket, socket)
	if test "$ac_cv_lib_socket_socket" != yes; then
		AC_CHECK_LIB(watt, socket)
		if test "$ac_cv_lib_watt_socket" != yes; then
			AC_CHECK_LIB(wsock32, socket)
			if test "$ac_cv_lib_wsock32_socket" != yes; then
				if echo "$CC" | grep -i mingw >/dev/null; then
					LIBS="-lwsock32 $LIBS"
				else
					cf_have_socket=no
				fi
			fi
		fi
	fi
fi
AC_CHECK_FUNCS(gethostbyname)
if test "$ac_cv_func_gethostbyname" != yes; then
	AC_CHECK_LIB(socket, gethostbyname)
	if test "$ac_cv_lib_socket_gethostbyname" != yes; then
		AC_CHECK_LIB(nsl, gethostbyname)
		if test "$ac_cv_lib_nsl_gethostbyname" != yes; then
			cf_have_socket=no
		fi
	fi
fi
if test "$cf_have_socket" = yes && test "$ac_cv_header_sys_socket_h" = yes && test "$ac_cv_header_netinet_in_h" = yes && test "$ac_cv_header_netdb_h" = yes; then
	AC_DEFINE(HAVE_NETWORK, 1, Have networking)
fi
AC_CHECK_FUNCS(gethostbyaddr getaddrinfo getnameinfo hstrerror h_errno)

AC_CACHE_CHECK(for struct timespec, ac_cv_have_struct_timespec,
AC_TRY_COMPILE([
	#include <time.h>
] , [
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	ts = ts;
	return 0;
], ac_cv_have_struct_timespec=yes, ac_cv_have_struct_timespec=no))
test "$ac_cv_have_struct_timespec" = yes && AC_DEFINE(HAVE_STRUCT_TIMESPEC, 1, Have struct timespec)

AC_CACHE_CHECK(if struct stat has st_atim, ac_cv_have_struct_stat_st_atim,
AC_TRY_COMPILE([
	#include <sys/stat.h>
] , [
	volatile struct stat st;
	volatile struct timespec a = st.st_atim;
	return 0;
], ac_cv_have_struct_stat_st_atim=yes, ac_cv_have_struct_stat_st_atim=no))
test "$ac_cv_have_struct_stat_st_atim" = yes && AC_DEFINE(HAVE_STRUCT_STAT_ST_ATIM, 1, Struct stat has st_atim)

AC_CACHE_CHECK(if struct stat has st_atimespec, ac_cv_have_struct_stat_st_atimespec,
AC_TRY_COMPILE([
	#include <sys/stat.h>
] , [
	volatile struct stat st;
	volatile struct timespec a = st.st_atimespec;
	return 0;
], ac_cv_have_struct_stat_st_atimespec=yes, ac_cv_have_struct_stat_st_atimespec=no))
test "$ac_cv_have_struct_stat_st_atimespec" = yes && AC_DEFINE(HAVE_STRUCT_STAT_ST_ATIMESPEC, 1, Struct stat has st_atimespec)


if test "$ac_cv_func_clock_gettime" = no -a "$ax_pthread_ok" = yes -a "$ac_cv_func_pthread_condattr_setclock" = yes; then
	AC_CHECK_LIB(rt, clock_gettime)
	if test "$ac_cv_lib_rt_clock_gettime" = yes; then
		AC_DEFINE(HAVE_CLOCK_GETTIME)
	fi
fi

AC_CACHE_CHECK(for struct sigevent, ac_cv_have_struct_sigevent,
AC_TRY_COMPILE([
	#include <time.h>
	#include <signal.h>
] , [
	timer_t timer_id;
	struct sigevent sev;
	timer_create(CLOCK_MONOTONIC, &sev, &timer_id);
	return 0;
], ac_cv_have_struct_sigevent=yes, ac_cv_have_struct_sigevent=no))
test "$ac_cv_have_struct_sigevent" = yes && AC_DEFINE(HAVE_STRUCT_SIGEVENT, 1, Have struct sigevent)

if test "$ac_cv_have_struct_sigevent" = yes -a "$ac_cv_func_timer_create" = no; then
	AC_CHECK_LIB(rt, timer_create)
	if test "$ac_cv_lib_rt_timer_create" = yes; then
		AC_DEFINE(HAVE_TIMER_CREATE)
	fi
fi


AC_CACHE_CHECK(for CLOCK_MONOTONIC, ac_cv_have_clock_monotonic,
AC_TRY_LINK([
	#include <time.h>
] , [
	clockid_t id = CLOCK_MONOTONIC;
	return 0;
], ac_cv_have_clock_monotonic=yes, ac_cv_have_clock_monotonic=no))
test "$ac_cv_have_clock_monotonic" = yes && AC_DEFINE(HAVE_CLOCK_MONOTONIC, 1, Have CLOCK_MONOTONIC)

AC_CACHE_CHECK(for CLOCK_MONOTONIC_RAW, ac_cv_have_clock_monotonic_raw,
AC_TRY_LINK([
	#include <time.h>
] , [
	clockid_t id = CLOCK_MONOTONIC_RAW;
	return 0;
], ac_cv_have_clock_monotonic_raw=yes, ac_cv_have_clock_monotonic_raw=no))
test "$ac_cv_have_clock_monotonic_raw" = yes && AC_DEFINE(HAVE_CLOCK_MONOTONIC_RAW, 1, Have CLOCK_MONOTONIC_RAW)


AC_CACHE_CHECK(for intX_t and u_intX_t, ac_cv_have_intx_t_u_intx_t,
AC_TRY_COMPILE([
	#include <sys/types.h>
] , [
	int8_t a = 0x7f;
	u_int8_t b = 0x7f;
	int16_t c = 0x7f;
	u_int16_t d = 0x7f;
	int32_t e = 0x7f;
	u_int32_t f = 0x7f;
	return (int)(a + b + c + d + e + f);
], ac_cv_have_intx_t_u_intx_t=yes, ac_cv_have_intx_t_u_intx_t=no))
test "$ac_cv_have_intx_t_u_intx_t" = yes && AC_DEFINE(HAVE_INT_T_U_INT_T, 1, Have intX_t and u_intX_t)

AC_CACHE_CHECK(for int64_t and u_int64_t, ac_cv_have_int64_t_u_int64_t,
AC_TRY_COMPILE([
	#include <sys/types.h>
] , [
	int64_t a = 0x12345678;
	u_int64_t b = 0x9abcdef0;
	return (int)(a + b);
], ac_cv_have_int64_t_u_int64_t=yes, ac_cv_have_int64_t_u_int64_t=no))
test "$ac_cv_have_int64_t_u_int64_t" = yes && AC_DEFINE(HAVE_INT64_T_U_INT64_T, 1, Have int64_t and u_int64_t)

AC_CACHE_CHECK(for int64_t and uint64_t, ac_cv_have_int64_t_uint64_t,
AC_TRY_COMPILE([
	#include <stdint.h>
] , [
	int64_t a = 0x12345678;
	uint64_t b = 0x9abcdef0;
	return (int)(a + b);
], ac_cv_have_int64_t_uint64_t=yes, ac_cv_have_int64_t_uint64_t=no))
test "$ac_cv_have_int64_t_uint64_t" = yes && AC_DEFINE(HAVE_INT64_T_UINT64_T, 1, Have int64_t and uint64_t)

AC_CACHE_CHECK([for big endian], ac_cv_big_endian,
	AC_TRY_RUN([
	long l;
	char *c = (char *)&l;
	int main(void)
	{
		l = 0x12345678L;
		return !(c[[sizeof(long) - 1]] == 0x78 && c[[sizeof(long) - 2]] == 0x56 && c[[sizeof(long) - 3]] == 0x34 && c[[sizeof(long) - 4]] == 0x12);
	}
	], ac_cv_big_endian=yes, ac_cv_big_endian=no, ac_cv_big_endian=unknown)
)
AC_CACHE_CHECK([for little endian], ac_cv_little_endian,
	AC_TRY_RUN([
	long l;
	char *c = (char *)&l;
	int main(void)
	{
		l = 0x12345678L;
		return !(c[[0]] == 0x78 && c[[1]] == 0x56 && c[[2]] == 0x34 && c[[3]] == 0x12);
	}
	], ac_cv_little_endian=yes, ac_cv_little_endian=no, ac_cv_little_endian=unknown)
)

if test "$ac_cv_big_endian" = yes -a "$ac_cv_little_endian" = yes; then
	AC_ERROR([The endianity test is broken])
elif test "$ac_cv_big_endian" = yes; then
	AC_DEFINE(CONFIG_BIG_ENDIAN, 1, Define if the system is big endian)
elif test "$ac_cv_little_endian" = yes; then
	AC_DEFINE(CONFIG_LITTLE_ENDIAN, 1, Define if the system is little endian)
fi

AC_CACHE_CHECK([if rwx mappings work], ac_cv_rwx_mmap,
	AC_TRY_RUN([
#include <unistd.h>
#include <sys/mman.h>
	int main(void)
	{
		return mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED;
	}
	], ac_cv_rwx_mmap=yes, ac_cv_rwx_mmap=no, ac_cv_rwx_mmap=no))
test "$ac_cv_func_mmap" = yes && test "$ac_cv_rwx_mmap" = no && AC_DEFINE(DISABLE_RWX_MAPPINGS, 1, Disable rwx mappings)

AC_CACHE_CHECK([for pointer tags], ac_cv_pointer_tags,
	AC_TRY_RUN([
	int main(void)
	{
		volatile unsigned val = 0x12345678U;
		volatile unsigned * volatile ptr, * volatile tagged_ptr;
		unsigned long want_tag = 0;
#if defined(__aarch64__) && !defined(__ILP32__)
		want_tag = 0xFF00000000000000UL;
#endif
#if defined(__s390__) && !defined(__LP64__)
		want_tag = 0x80000000UL;
#endif
		if (!want_tag)
			return 1;
		ptr = &val;
		if ((unsigned long)ptr & want_tag)
			return 1;
		tagged_ptr = (unsigned *)((unsigned long)ptr | want_tag);
		return *tagged_ptr == 0x12345678U ? 0 : 1;
	}
	], ac_cv_pointer_tags=yes, ac_cv_pointer_tags=no, ac_cv_pointer_tags=unknown)
)
test "$ac_cv_pointer_tags" = yes && AC_DEFINE(HAVE_POINTER_TAGS, 1, Have pointer tags)

AC_CACHE_CHECK(for __sync_add_and_fetch __sync_sub_and_fetch __sync_bool_compare_and_swap __sync_synchronize, ac_cv_have_sync_and_fetch,
AC_TRY_LINK(, [
	unsigned long val = 0;
	__sync_synchronize();
	__sync_add_and_fetch(&val, 1);
	__sync_bool_compare_and_swap(&val, 1, 2);
	return __sync_sub_and_fetch(&val, 1);
], ac_cv_have_sync_and_fetch=yes, ac_cv_have_sync_and_fetch=no))
test "$ac_cv_have_sync_and_fetch" = yes && AC_DEFINE(HAVE_SYNC_AND_FETCH, 1, Have __sync_add_and_fetch __sync_sub_and_fetch)

if test "$ac_cv_header_stdatomic_h" = yes; then
	AC_CACHE_CHECK(for C11 atomics, ac_cv_have_c11_atomics,
	AC_TRY_LINK([
		#include <stdint.h>
		#include <stdatomic.h>
		atomic_uintptr_t val;
		_Atomic uintptr_t val2;
	], [
		uintptr_t ld = atomic_load_explicit(&val, memory_order_relaxed);
		uintptr_t fld = atomic_fetch_add_explicit(&val, 4, memory_order_acq_rel);
		uintptr_t fld2 = atomic_fetch_sub_explicit(&val2, 8, memory_order_release);
		uintptr_t xch = atomic_exchange_explicit(&val2, 12, memory_order_acquire);
		atomic_thread_fence(memory_order_seq_cst);
		return (int)(ld + fld + fld2 + xch);
	], ac_cv_have_c11_atomics=yes, ac_cv_have_c11_atomics=no))
	if test "$ac_cv_have_c11_atomics" = yes; then
		AC_DEFINE(HAVE_C11_ATOMICS, 1, Have C11 atomics)
	else
		save_LIBS="$LIBS"
		LIBS="-latomic $LIBS"
		AC_CACHE_CHECK(for C11 atomics with -latomic, ac_cv_have_c11_atomics_latomic,
		AC_TRY_LINK([
			#include <stdint.h>
			#include <stdatomic.h>
			atomic_uintptr_t val;
		], [
			uintptr_t ld = atomic_load_explicit(&val, memory_order_relaxed);
			uintptr_t fld = atomic_fetch_add_explicit(&val, 4, memory_order_acq_rel);
			uintptr_t fld2 = atomic_fetch_sub_explicit(&val, 8, memory_order_release);
			uintptr_t xch = atomic_exchange_explicit(&val, 12, memory_order_acquire);
			atomic_thread_fence(memory_order_seq_cst);
			return (int)(ld + fld + fld2 + xch);
		], ac_cv_have_c11_atomics_latomic=yes, ac_cv_have_c11_atomics_latomic=no))
		if test "$ac_cv_have_c11_atomics_latomic" = yes; then
			AC_DEFINE(HAVE_C11_ATOMICS, 1, Have C11 atomics)
		else
			LIBS="$save_LIBS"
		fi
	fi
fi

AX_GCC_BUILTIN(__builtin_unreachable)
AX_GCC_BUILTIN(__builtin_bswap32)
AX_GCC_BUILTIN(__builtin_bswap64)
AX_GCC_BUILTIN(__builtin_assume_aligned)
AX_GCC_BUILTIN(__builtin___clear_cache)

AC_CACHE_CHECK(for __builtin_clz __builtin_clzl __builtin_clzll, ac_cv_have_builtin_clz,
AC_TRY_LINK([
	volatile unsigned a = 0x12345678;
	volatile unsigned long b = 0x567890ab;
	volatile unsigned long long c = 0x9abcdef0;
] , [
	return __builtin_clz(a) + __builtin_clzl(b) + __builtin_clzll(c);
], ac_cv_have_builtin_clz=yes, ac_cv_have_builtin_clz=no))
test "$ac_cv_have_builtin_clz" = yes && AC_DEFINE(HAVE_BUILTIN_CLZ, 1, Have __builtin_clz __builtin_clzl __builtin_clzll)

AC_CACHE_CHECK(for __builtin_ctz __builtin_ctzl __builtin_ctzll, ac_cv_have_builtin_ctz,
AC_TRY_LINK([
	volatile unsigned a = 0x12345678;
	volatile unsigned long b = 0x567890ab;
	volatile unsigned long long c = 0x9abcdef0;
] , [
	return __builtin_ctz(a) + __builtin_ctzl(b) + __builtin_ctzll(c);
], ac_cv_have_builtin_ctz=yes, ac_cv_have_builtin_ctz=no))
test "$ac_cv_have_builtin_ctz" = yes && AC_DEFINE(HAVE_BUILTIN_CTZ, 1, Have __builtin_ctz __builtin_ctzl __builtin_ctzll)

AC_CACHE_CHECK(for __builtin_popcount __builtin_popcountll, ac_cv_have_builtin_popcount,
AC_TRY_LINK([
	volatile unsigned a = 0x12345678;
	volatile unsigned long long b = 0x9abcdef0;
] , [
	return __builtin_popcount(a) + __builtin_popcountll(b);
], ac_cv_have_builtin_popcount=yes, ac_cv_have_builtin_popcount=no))
test "$ac_cv_have_builtin_popcount" = yes && AC_DEFINE(HAVE_BUILTIN_POPCOUNT, 1, Have __builtin_popcount __builtin_popcountll)


if test "$ac_cv_sizeof_unsigned___int128" != 0; then
	max_type=__int128
elif test "$ac_cv_c_long_long" = yes; then
	max_type='long long'
else
	max_type=long
fi

AC_CACHE_CHECK(for __builtin_mul_overflow, ac_cv_have_builtin_mul_overflow,
AC_TRY_LINK([
	volatile $max_type a = 0x12345678;
	volatile $max_type b = 0x9abcdef;
	volatile $max_type c;
] , [
	int o1 = __builtin_mul_overflow(a, b, &c);
	return o1;
], ac_cv_have_builtin_mul_overflow=yes, ac_cv_have_builtin_mul_overflow=no))

if test "$ac_cv_have_builtin_mul_overflow" = yes; then
	AC_DEFINE(HAVE_BUILTIN_MUL_OVERFLOW, 1, Have __builtin_mul_overflow)
else
	AC_CACHE_CHECK(for __builtin_mul_overflow with -rtlib=compiler-rt, ac_cv_have_builtin_mul_overflow_rtlib_compiler_rt,
	save_LDFLAGS="$LDFLAGS"
	LDFLAGS="-rtlib=compiler-rt $LDFLAGS"
	AC_TRY_LINK([
		volatile $max_type a = 0x12345678;
		volatile $max_type b = 0x9abcdef;
		volatile $max_type c;
	] , [
		int o1 = __builtin_mul_overflow(a, b, &c);
		return o1;
	], ac_cv_have_builtin_mul_overflow_rtlib_compiler_rt=yes, ac_cv_have_builtin_mul_overflow_rtlib_compiler_rt=no)
	LDFLAGS="$save_LDFLAGS"
	)

	if test "$ac_cv_have_builtin_mul_overflow_rtlib_compiler_rt" = yes; then
		use_compiler_rt=true
		if test "$ac_cv_have___float128" = yes; then
			AC_CHECK_LIB(gcc, __addtf3)
			if test "$ac_cv_lib_gcc___addtf3" != yes; then
				use_compiler_rt=false
			fi
		fi
		if $use_compiler_rt; then
			LDFLAGS="-rtlib=compiler-rt $LDFLAGS"
			AC_DEFINE(HAVE_BUILTIN_MUL_OVERFLOW, 1, Have __builtin_mul_overflow)
		fi
	fi
fi

AC_CACHE_CHECK(for __builtin_add_overflow __builtin_sub_overflow, ac_cv_have_builtin_add_sub_overflow,
AC_TRY_LINK([
	volatile $max_type a = 0x12345678;
	volatile $max_type b = 0x9abcdef;
	volatile $max_type c;
] , [
	int o1 = __builtin_add_overflow(a, b, &c);
	int o2 = __builtin_sub_overflow(a, b, &c);
	return o1 + o2;
], ac_cv_have_builtin_add_sub_overflow=yes, ac_cv_have_builtin_add_sub_overflow=no))
test "$ac_cv_have_builtin_add_sub_overflow" = yes && AC_DEFINE(HAVE_BUILTIN_ADD_SUB_OVERFLOW, 1, Have __builtin_add_overflow __builtin_sub_overflow)

case ${host_cpu} in
	alpha | sh*)
		AC_CACHE_CHECK(for -mieee, ac_cv_have_mieee,
		save_CFLAGS="$CFLAGS"
		CFLAGS="-mieee $CFLAGS"
		AC_TRY_LINK([ ], [ ], ac_cv_have_mieee=yes, ac_cv_have_mieee=no)
		CFLAGS="$save_CFLAGS"
		)
		test "$ac_cv_have_mieee" = yes && CFLAGS="-mieee $CFLAGS"
		;;
esac

AC_CACHE_CHECK(if we can use union of float and uint32_t, ac_cv_union_float_uint32_t,
AC_TRY_RUN([
#include <stdint.h>

	volatile union {
		float f;
		uint32_t i;
	} u;

	int main(void)
	{
		u.f = -0.1640625;
		return !(u.i == 0xBE280000UL);
	}
], ac_cv_union_float_uint32_t=yes, ac_cv_union_float_uint32_t=no, ac_cv_union_float_uint32_t=unknown))
test "$ac_cv_union_float_uint32_t" = yes && AC_DEFINE(HAVE_UNION_FLOAT_UINT32_T, 1, Can use union of float and uint32_t)

dnl gcc-4.* on ARM has buggy infinity float to __fp16 conversion (it incorrectly returns NaN)
dnl clang-6 on ARM64 generates invalid instruction when storing fp16 zero
AC_CACHE_CHECK(for __fp16, ac_cv_have___fp16,
AC_TRY_RUN([
#include <math.h>

	volatile float a = HUGE_VAL;
	volatile __fp16 b;

	static __fp16 store0(__fp16 *fp, __fp16 arg)
	{
		*fp = 0;
		return arg;
	}

	__fp16 (*volatile ptr_store0)(__fp16 *, __fp16) = store0;

	int main(void)
	{
		__fp16 f;
		ptr_store0(&f, 0);
		b = (__fp16)a;
		return !(f == 0 && b == HUGE_VAL);
	}
], ac_cv_have___fp16=yes, ac_cv_have___fp16=no, ac_cv_have___fp16=unknown))
cf_have_fp16="$ac_cv_have___fp16"

if test "$ac_cv_have___fp16" = no; then
	save_CFLAGS="$CFLAGS"
	CFLAGS="-mfp16-format=ieee $CFLAGS"
	AC_CACHE_CHECK(for __fp16 with -mfp16-format=ieee, ac_cv_have___fp16_2,
	AC_TRY_RUN([
	#include <math.h>

		volatile float a = HUGE_VAL;
		volatile __fp16 b;

		static __fp16 store0(__fp16 *fp, __fp16 arg)
		{
			*fp = 0;
			return arg;
		}

		__fp16 (*volatile ptr_store0)(__fp16 *, __fp16) = store0;

		int main(void)
		{
			__fp16 f;
			ptr_store0(&f, 0);
			b = (__fp16)a;
			return !(f == 0 && b == HUGE_VAL);
		}
	], ac_cv_have___fp16_2=yes, ac_cv_have___fp16_2=no, ac_cv_have___fp16_2=unknown))
	if test "$ac_cv_have___fp16_2" = yes; then
		cf_have_fp16=yes
	else
		CFLAGS="$save_CFLAGS"
	fi
fi

if test "$cf_have_fp16" = yes; then
	dnl libgcc-6 on ARM64 lacks the functions __extendhftf2 and __trunctfhf2
	dnl clang-6 on X86 lacks the function __truncxfhf2
	AC_CACHE_CHECK(if conversion between __fp16 and long double works, ac_cv_conversion___fp16_long_double,
	AC_TRY_LINK([
		volatile __fp16 a = 1.2;
		volatile long double b;
		volatile __fp16 c;
	] , [
		b = (long double)a;
		c = (__fp16)b;
		return c;
	], ac_cv_conversion___fp16_long_double=yes, ac_cv_conversion___fp16_long_double=no))
	test "$ac_cv_conversion___fp16_long_double" = no && cf_have_fp16=no

	dnl libgcc-6 on ARM64 lacks the function __floatundihf
	AC_CACHE_CHECK(if conversion from unsigned long to __fp16 works, ac_cv_conversion_unsigned_long___fp16,
	AC_TRY_LINK([
		volatile unsigned long a = 10;
		volatile __fp16 b = 1.2;
	] , [
		b = (__fp16)a;
		return b;
	], ac_cv_conversion_unsigned_long___fp16=yes, ac_cv_conversion_unsigned_long___fp16=no))
	test "$ac_cv_conversion_unsigned_long___fp16" = no && cf_have_fp16=no

	if test "$ac_cv_sizeof_unsigned___int128" != 0; then
		dnl libgcc-6 on ARM64 lacks the functions __fixhfti and __fixunshfti
		AC_CACHE_CHECK(if conversion from __fp16 to __int128 works, ac_cv_conversion___fp16___int128,
		AC_TRY_LINK([
			volatile __fp16 a = 1.2;
			volatile __int128 b;
			volatile unsigned __int128 c;
		] , [
			b = (__int128)a;
			c = (unsigned __int128)a;
			return b + c;
		], ac_cv_conversion___fp16___int128=yes, ac_cv_conversion___fp16___int128=no))
		test "$ac_cv_conversion___fp16___int128" = no && cf_have_fp16=no

		dnl libgcc-6 on ARM64 lacks the functions __floattihf and __floattihf
		AC_CACHE_CHECK(if conversion from __int128 to __fp16 works, ac_cv_conversion___int128___fp16,
		AC_TRY_LINK([
			volatile __int128 a = 12;
			volatile unsigned __int128 b = 34;
			__fp16 c, d;
		] , [
			c = (__fp16)a;
			d = (__fp16)a;
			return c + d;
		], ac_cv_conversion___int128___fp16=yes, ac_cv_conversion___int128___fp16=no))
		test "$ac_cv_conversion___int128___fp16" = no && cf_have_fp16=no
	fi
fi
test "$cf_have_fp16" = yes && AC_DEFINE(HAVE___FP16, 1, Have __fp16)

AC_CACHE_CHECK(if sqrt sets errno, ac_cv_have_sqrt_errno,
AC_TRY_RUN([
#include <errno.h>
#include <math.h>

	volatile double a = -1;

	int main(void)
	{
		errno = 0;
		a = sqrt(a);
		return !errno;
	}
], ac_cv_have_sqrt_errno=yes, ac_cv_have_sqrt_errno=no, ac_cv_have_sqrt_errno=unknown))

if test "$ac_cv_have_sqrt_errno" = yes; then
	save_CFLAGS="$CFLAGS"
	CFLAGS="-fno-math-errno $CFLAGS"
	AC_CACHE_CHECK(for -fno-math-errno, ac_cv_have__fno_math_errno,
	AC_TRY_RUN([
	#include <errno.h>
	#include <math.h>

		volatile double a = -1;

		int main(void)
		{
			errno = 0;
			a = sqrt(a);
			return !!errno;
		}
	], ac_cv_have__fno_math_errno=yes, ac_cv_have__fno_math_errno=no, ac_cv_have__fno_math_errno=unknown))
	if test "$ac_cv_have__fno_math_errno" != yes; then
		CFLAGS="$save_CFLAGS"
	fi
fi

AC_CACHE_CHECK(if fmod is buggy, ac_cv_have_buggy_fmod,
AC_TRY_RUN([
#include <math.h>
volatile double a = 0.;
volatile double b = 0.;
int main(void)
{
	return fmod(a, b) == 0;
}
], ac_cv_have_buggy_fmod=no, ac_cv_have_buggy_fmod=yes, ac_cv_have_buggy_fmod=yes))
test "$ac_cv_have_buggy_fmod" = yes && AC_DEFINE(HAVE_BUGGY_FMOD, 1, Have buggy fmod)

AC_CACHE_CHECK(if modf is buggy, ac_cv_have_buggy_modf,
AC_TRY_RUN([
#include <math.h>
volatile double a = 1.;
volatile double b = 0.;
int main(void)
{
	double d;
	return !(modf(a / b, &d) == 0);
}
], ac_cv_have_buggy_modf=no, ac_cv_have_buggy_modf=yes, ac_cv_have_buggy_modf=yes))
test "$ac_cv_have_buggy_modf" = yes && AC_DEFINE(HAVE_BUGGY_MODF, 1, Have buggy modf)


AC_CONFIG_FILES(Makefile)
AC_OUTPUT

if test "$ac_cv_lib_ffi_ffi_prep_cif" != yes; then
	AC_MSG_WARN([libffi is not present, ffi functionality will be disabled])
fi
if test "$ac_cv_lib_gmp___gmpz_init2" != yes; then
	AC_MSG_WARN([libgmp is not present, slow built-in emulation will be used])
fi
