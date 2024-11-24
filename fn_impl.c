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

#include "str.h"

#ifndef HAVE_GETENV
char *getenv(const char attr_unused *name)
{
	return NULL;
}
#endif

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dst, const void *src, size_t length)
{
	(void)memcpy(dst, src, length);
	return (char *)dst + length;
}
#endif

#ifndef HAVE_STRERROR
char *strerror(int errnum)
{
	static char buffer[6 + 1 + (sizeof(int) * 5 / 2 + 1) + 1] = "error ";
	char *b = buffer + 6;
	str_add_signed(&b, NULL, (intbig_t)errnum, 10);
	return buffer;
}
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen)
{
	size_t l;
	for (l = 0; l < maxlen; l++)
		if (unlikely(!s[l]))
			break;
	return l;
}
#endif

#if !defined(HAVE_CBRT)
double cbrt(double x)
{
	if (unlikely(x <= 0)) {
		if (x == 0)
			return x;
		else
			return -pow(-x, 1./3.);
	}
	return pow(x, 1./3.);
}
#endif

#if !defined(HAVE_CBRTF)
float cbrtf(float x)
{
	if (unlikely(x <= 0)) {
		if (x == 0)
			return x;
		else
			return -powf(-x, 1./3.);
	}
	return powf(x, 1./3.);
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_CBRTL)
float cbrtl(float x)
{
	if (unlikely(x <= 0)) {
		if (x == 0)
			return x;
		else
			return -powl(-x, 1./3.);
	}
	return powl(x, 1.L/3.L);
}
#endif

#if !defined(HAVE_ASINH)
double asinh(double x)
{
	return log(x + sqrt(x * x + 1));
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_ASINHL)
long double asinhl(long double x)
{
	return logl(x + sqrtl(x * x + 1));
}
#endif

#if !defined(HAVE_ACOSH)
double acosh(double x)
{
	return log(x + sqrt(x * x - 1));
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_ACOSHL)
long double acoshl(long double x)
{
	return logl(x + sqrtl(x * x - 1));
}
#endif

#if !defined(HAVE_ATANH)
double atanh(double x)
{
	return 0.5 * log((1 + x) / (1 - x));
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_ATANHL)
long double atanhl(long double x)
{
	return 0.5 * logl((1 + x) / (1 - x));
}
#endif

#if !defined(HAVE_EXP2)
double exp2(double x)
{
	return pow(2, x);
}
#endif

#if !defined(HAVE_EXP2F)
float exp2f(float x)
{
	return powf(2, x);
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_EXP2L)
long double exp2l(long double x)
{
	return powl(2, x);
}
#endif

#if defined(HAVE___FLOAT128) && defined(HAVE_LIBQUADMATH) && defined(HAVE_QUADMATH_H) && !defined(HAVE_EXP2Q)
__float128 exp2q(__float128 x)
{
	return powq(2, x);
}
#endif

#if !defined(HAVE_EXP10)
double exp10(double x)
{
	return pow(10, x);
}
#endif

#if !defined(HAVE_EXP10F)
float exp10f(float x)
{
	return powf(10, x);
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_EXP10L)
long double exp10l(long double x)
{
	return powl(10, x);
}
#endif

#if defined(HAVE___FLOAT128) && defined(HAVE_LIBQUADMATH) && defined(HAVE_QUADMATH_H) && !defined(HAVE_EXP10Q)
__float128 exp10q(__float128 x)
{
	return powq(10, x);
}
#endif

#if !defined(HAVE_LOG2)
double log2(double x)
{
	return log(x) / log(2);
}
#endif

#if !defined(HAVE_LOG2F)
float log2f(float x)
{
	return logf(x) / logf(2);
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_LOG2L)
long double log2l(long double x)
{
	return logl(x) / logl(2);
}
#endif

#if !defined(HAVE_TRUNC)
double trunc(double x)
{
	if (x >= 0)
		return floor(x);
	else
		return ceil(x);
}
#endif

#if !defined(HAVE_TRUNCF)
float truncf(float x)
{
	if (x >= 0)
		return floorf(x);
	else
		return ceilf(x);
}
#endif

#if defined(HAVE_LONG_DOUBLE) && !defined(HAVE_TRUNCL)
long double truncl(long double x)
{
	if (x >= 0)
		return floorl(x);
	else
		return ceill(x);
}
#endif

#if !defined(HAVE_RINT)
double rint(double x)
{
	if (x >= 0)
		return floor(x + 0.5);
	else
		return ceil(x - 0.5);
}
#endif

#if !defined(HAVE_RINTF)
float rintf(float x)
{
	return rint(x);
}
#endif

#if !defined(HAVE_MODFF)
float modff(float x, float *iflt)
{
	double idbl;
	double r = modf(x, &idbl);
	*iflt = idbl;
	return r;
}
#endif

#if defined(HAVE_BUGGY_LDEXP) && defined(SIZEOF_LONG_DOUBLE) && SIZEOF_LONG_DOUBLE > 8 && defined(HAVE_LDEXPL)
double ldexp(double x, int exp)
{
	return ldexpl(x, exp);
}
#endif
