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

#ifndef EWOULDBLOCK
#define EWOULDBLOCK	EAGAIN
#endif

#define THREAD_WIN32_CYGWIN

#if defined(DEBUG_THREAD_NONE)
#define THREAD_NONE
#elif defined(__HAIKU__)
#define THREAD_HAIKU
#elif ((defined(OS_WIN32) && defined(HAVE__BEGINTHREADEX)) || (defined(OS_CYGWIN) && defined(THREAD_WIN32_CYGWIN) && defined(HAVE_PTHREAD))) && !defined(HAVE_PTHREAD_PREFER)
#define THREAD_WIN32
#elif defined(HAVE_PTHREAD)
#define THREAD_POSIX
#elif defined(OS_OS2) && (defined(_MT) || defined(__MULTI__) || defined(__MT__))
#define THREAD_OS2
#else
#define THREAD_NONE
#endif

#if defined(OS_OS2)
#define INCL_DOS
#define INCL_DOSERRORS
#define INCL_KBD
#define INCL_MOU
#define INCL_VIO
#include <os2.h>
#endif

#if defined(OS_WIN32) || defined(OS_CYGWIN)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#if defined(OS_WIN32)
#include <winsock.h>
#endif

#if defined(__WATCOMC__) || defined(_WIN32)
#include <process.h>
#endif

#if defined(__STRICT_ANSI__) && !defined(mempcpy)
#undef HAVE_MEMPCPY
#endif
