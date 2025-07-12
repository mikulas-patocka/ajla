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

/* gcc 2.7.2.1 will throw "internal error--unrecognizable insn" if we enable this
#ifndef HAVE_LONG_DOUBLE
#if defined(ARCH_X86) && defined(HAVE_REAL_GNUC)
#define HAVE_LONG_DOUBLE	1
#endif
#endif
*/

#ifndef HAVE_GETENV
char *getenv(const char *name);
#endif

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dst, const void *src, size_t length);
#endif

#if defined(__EMX__) || defined(__BORLANDC__)
#define strcasecmp	stricmp
#endif

#if defined(_MSC_VER)
#define strcasecmp	_stricmp
#endif

#ifndef HAVE_STRERROR
char *strerror(int errnum);
#endif

#ifdef __ICC
#undef HAVE_STRNLEN
#define strnlen	my_strnlen
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen);
#endif

#if !defined(HAVE_CBRT)
double cbrt(double x);
#endif

#if !defined(HAVE_CBRTF)
float cbrtf(float x);
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_CBRTL)
#define cbrtl	my_cbrtl	/* fix conflicting types for built-in function cbrtl */
float cbrtl(float x);
#endif

#if !defined(HAVE_ASINH)
double asinh(double x);
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_ASINHL)
long double asinhl(long double x);
#endif

#if !defined(HAVE_ACOSH)
double acosh(double x);
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_ACOSHL)
long double acoshl(long double x);
#endif

#if !defined(HAVE_ATANH)
double atanh(double x);
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_ATANHL)
long double atanhl(long double x);
#endif

#if !defined(HAVE_EXP2)
double exp2(double x);
#endif

#if !defined(HAVE_EXP2F)
float exp2f(float x);
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_EXP2L)
long double exp2l(long double x);
#endif

#if defined(HAVE___FLOAT128) && defined(HAVE_QUADMATH) && defined(HAVE_QUADMATH_H) && !defined(HAVE_EXP2Q)
__float128 exp2q(__float128 x);
#endif

#if !defined(HAVE_EXP10)
double exp10(double x);
#endif
#if !defined(HAVE_EXP10F)
float exp10f(float x);
#endif
#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_EXP10L)
long double exp10l(long double x);
#endif
#if defined(HAVE___FLOAT128) && defined(HAVE_QUADMATH) && defined(HAVE_QUADMATH_H) && !defined(HAVE_EXP10Q)
__float128 exp10q(__float128 x);
#endif

#if !defined(HAVE_LOG2)
double log2(double x);
#endif

#if !defined(HAVE_LOG2F)
float log2f(float x);
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_LOG2L)
long double log2l(long double x);
#endif

#if !defined(HAVE_TRUNC)
double trunc(double x);
#endif

#if !defined(HAVE_TRUNCF)
float truncf(float x);
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_TRUNCL)
long double truncl(long double x);
#endif

#if !defined(HAVE_RINT)
double rint(double x);
#endif

#if !defined(HAVE_RINTF)
float rintf(float x);
#endif

#if !defined(HAVE_MODFF)
float modff(float x, float *iflt);
#endif
