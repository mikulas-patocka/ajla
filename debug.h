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

#ifndef HAVE_DEBUGLEVEL
#define HAVE_DEBUGLEVEL	1
#endif

/*#define DEBUG_BIST*/
/*#define DEBUG_INFO*/
/*#define DEBUG_ENV*/
/*#define DEBUG_CRASH_HANDLER*/

#if HAVE_DEBUGLEVEL >= 1
#define DEBUG_TRACK_FILE_LINE
#define DEBUG_MEMORY_POSSIBLE
#define DEBUG_OBJECT_POSSIBLE
#define DEBUG_LOW_OVERHEAD
#endif
#if HAVE_DEBUGLEVEL >= 2
#define DEBUG_REFCOUNTS
#define DEBUG_LIST
#define DEBUG_RBTREE
#define DEBUG_ERROR
#define DEBUG
#endif
#if HAVE_DEBUGLEVEL >= 3
/*#define DEBUG_ALLOC_INSIDE_LOCKS	currently, this doesn't work */
#define DEBUG_ARRAY_INDICES
#endif

/*#define DEBUG_THREAD_NONE*/
/*#define DEBUG_TRACE*/
/*#define DEBUG_NOINLINE*/

/*#define UNUSUAL_NO_TAGGED_POINTERS*/
/*#define UNUSUAL_DISABLE_INT128_T
#define UNUSUAL_ARITHMETICS
#define UNUSUAL_UNKNOWN_ENDIAN
#define UNUSUAL_REFCOUNTS
#define UNUSUAL_NO_ASSEMBLER
#define UNUSUAL_NO_ASSEMBLER_GOTO
#define UNUSUAL
#define UNUSUAL_THREAD
#define UNUSUAL_NO_MEMALIGN
#define UNUSUAL_NO_ARCH_TAGGED_POINTERS
#define UNUSUAL_MPINT_ARRAY_INDICES
#define UNUSUAL_NO_POINTER_COMPRESSION
#define UNUSUAL_SPINLOCK
#define UNUSUAL_NO_DIR_HANDLES*/
