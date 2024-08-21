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

#if defined(__hpux) && !defined(__LP64__)
#define _LARGEFILE64_SOURCE	1
#else
#define _FILE_OFFSET_BITS	64
#define _TIME_BITS		64
#endif

#ifdef __hpux
#define _XOPEN_SOURCE_EXTENDED	1
#endif

#ifdef __APPLE__
#define _DARWIN_UNLIMITED_SELECT
#endif

#if defined(__TURBOC__) || defined(__BORLANDC__)
#include <_defs.h>
#endif

#if defined _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4018 4022 4054 4055 4090 4100 4101 4127 4132 4146 4152 4189 4244 4245 4267 4305 4306 4307 4310 4324 4702 4706 4761 4820)
#endif

#if defined(__DOS__) || defined(__DJGPP__)
#define OS_DOS
#endif

#if defined(__EMX__) || defined(__OS2__)
#define OS_OS2
#endif

#if defined(__CYGWIN__)
#define OS_CYGWIN
#elif defined(_WIN32)
#define OS_WIN32
#endif

#include "version.h"

#ifdef HAVE_CONFIG_H

#include "config.h"

#if defined(malloc)
#undef malloc
#endif

#else

#if defined(OS_DOS) || defined(OS_OS2)
#define CONFIG_LITTLE_ENDIAN	1
#elif defined(_M_ALPHA) || defined(_M_ARM) || defined(_M_IA64) || defined(_M_IX86) || defined(_M_X64)
#define CONFIG_LITTLE_ENDIAN	1
#endif

#define SIZEOF_UNSIGNED_SHORT		2
#define SIZEOF_UNSIGNED			4
#if (defined(__WATCOMC__) && __WATCOMC__ >= 1220) || defined(__IBMC__)
#define SIZEOF_UNSIGNED_LONG_LONG	8
#define HAVE_LONG_LONG			1
#endif

#if defined(OS_OS2) || (defined(OS_WIN32) && !defined(_WIN64))
#define SIZEOF_VOID_P		4
#define SIZEOF_SIZE_T		4
#elif defined(OS_WIN32) && defined(_WIN64)
#define SIZEOF_VOID_P		8
#define SIZEOF_SIZE_T		8
#endif

#define HAVE_STDLIB_H		1
#define HAVE_STRING_H		1
#if defined(__STDC__) && __STDC_VERSION__ >= 199901
#define HAVE_STDBOOL_H		1
#define HAVE_STDINT_H		1
#define HAVE_INTTYPES_H		1
#define HAVE_INT64_T_UINT64_T	1
#elif defined(_MSC_VER) && _MSC_VER >= 1600
/* I'm not sure about versions */
#define HAVE_STDINT_H		1
#define HAVE_INT64_T_UINT64_T	1
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1600
#define HAVE___THREAD		__declspec(thread)
#endif

#if defined(__STDC__) && __STDC_VERSION__ >= 199901
#elif defined(__cplusplus)
#elif defined(__WATCOMC__) && __WATCOMC__ >= 1220
#elif defined(__IBMC__) || defined(_MSC_VER)
#define inline __inline
#elif defined(__BORLANDC__) && __BORLANDC__ >= 0x550	/* not sure */
#define inline __inline
#else
#define inline
#endif


#define HAVE_FOPEN		1
#define HAVE_GETENV		1
#define HAVE_STRERROR		1
#if defined(_MSC_VER) && _MSC_VER >= 1600
#define HAVE_STRNLEN		1
#define HAVE_MODFF		1
#endif
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define HAVE_VSNPRINTF		1
#endif

#if !(defined(__BORLANDC__) || (defined _MSC_VER && _MSC_VER < 1600))
#define HAVE_FABSF		1
#define HAVE_FREXPF		1
#define HAVE_LDEXPF		1
#define HAVE_POWF		1
#endif

#if defined(_MSC_VER) || defined(__BORLANDC__)
#define ssize_t			intptr_t
#endif

#if defined(OS_WIN32) && defined(_MT)
#define HAVE__BEGINTHREADEX	1
#endif

#endif
