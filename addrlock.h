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

#ifndef AJLA_ADDRLOCK_H
#define AJLA_ADDRLOCK_H

#include "thread.h"

#if	defined(barrier_data_dependency) &&		\
	defined(barrier_write_before_unlock_lock) &&	\
	((defined(POINTERS_ARE_ATOMIC) &&		\
	  (defined(POINTER_TAG) ||			\
	   defined(POINTER_IGNORE_BITS))) ||		\
	 defined(THREAD_NONE))
#define POINTER_FOLLOW_IS_LOCKLESS
#endif

/*
 * We need to determine refcount method here, so that we enable or disable
 * DEPTH_REFCOUNT
 */
#if !defined(THREAD_NONE) && defined(POINTERS_ARE_ATOMIC) && defined(INLINE_ASM_GCC_X86) && !defined(UNUSUAL_REFCOUNTS)

#if defined(INLINE_ASM_GCC_LABELS)
#define REFCOUNT_ASM_X86_LABELS
#elif defined(HAVE_C11_ATOMICS)
#define REFCOUNT_ATOMIC
#else
#define REFCOUNT_ASM_X86
#endif

#elif !defined(THREAD_NONE) && defined(HAVE_C11_ATOMICS) && !defined(UNUSUAL_REFCOUNTS)

#define REFCOUNT_ATOMIC

#elif !defined(THREAD_NONE) && defined(HAVE_SYNC_AND_FETCH) && !defined(UNUSUAL)

#define REFCOUNT_SYNC

#elif !defined(THREAD_NONE) && (defined(OS_WIN32) || defined(OS_CYGWIN)) && !defined(UNUSUAL_THREAD)

#define REFCOUNT_WIN32

#else

#define REFCOUNT_LOCK

#endif

#if defined(REFCOUNT_ATOMIC) || defined(REFCOUNT_WIN32) || defined(POINTERS_ARE_ATOMIC)
#define REFCOUNTS_ARE_ATOMIC
#endif


typedef enum {
	DEPTH_THUNK,
#ifndef POINTER_FOLLOW_IS_LOCKLESS
	DEPTH_POINTER,
#endif
#ifdef REFCOUNT_LOCK
	DEPTH_REFCOUNT,
#endif
#ifdef USE_AMALLOC
	DEPTH_ARENA,
#endif
#if (!defined(HAVE_PREAD) || !defined(HAVE_PWRITE)) && !defined(OS_OS2)
#define DO_LOCK_HANDLES
	DEPTH_HANDLE,
#endif
	DEPTH_AUX,
	N_POINTER_DEPTHS
} addrlock_depth;


#if defined(THREAD_NONE) || defined(DEBUG_ALLOC_INSIDE_LOCKS)
#define POINTER_HASH_BITS	0
#else
#define POINTER_HASH_BITS	10
#endif
#define POINTER_HASH_SIZE	(1 << POINTER_HASH_BITS)

#define mutex_padding_size	(sizeof(mutex_t) <= 1 ? 1 :	\
				 sizeof(mutex_t) <= 2 ? 2 :	\
				 sizeof(mutex_t) <= 4 ? 4 :	\
				 sizeof(mutex_t) <= 8 ? 8 :	\
				 sizeof(mutex_t) <= 16 ? 16 :	\
				 sizeof(mutex_t) <= 32 ? 32 :	\
				 sizeof(mutex_t) <= 64 ? 64 :	\
				 sizeof(mutex_t) <= 128 ? 128 :	\
				 sizeof(mutex_t) <= 256 ? 256 :	\
				 1)

#define rwmutex_padding_size	(sizeof(rwmutex_t) <= 1 ? 1 :	\
				 sizeof(rwmutex_t) <= 2 ? 2 :	\
				 sizeof(rwmutex_t) <= 4 ? 4 :	\
				 sizeof(rwmutex_t) <= 8 ? 8 :	\
				 sizeof(rwmutex_t) <= 16 ? 16 :	\
				 sizeof(rwmutex_t) <= 32 ? 32 :	\
				 sizeof(rwmutex_t) <= 64 ? 64 :	\
				 sizeof(rwmutex_t) <= 128 ? 128 :\
				 sizeof(rwmutex_t) <= 256 ? 256 :\
				 1)


void attr_fastcall address_lock(const void *, addrlock_depth);
void attr_fastcall address_unlock(const void *, addrlock_depth);
void attr_fastcall address_lock_two(const void *, const void *, addrlock_depth);
bool attr_fastcall address_trylock_second(const void *, const void *, addrlock_depth);
void attr_fastcall address_unlock_second(const void *, const void *, addrlock_depth);
mutex_t * attr_fastcall address_get_mutex(const void *, addrlock_depth);

void address_read_lock(const void *p);
void address_read_unlock(const void *p);
void address_write_lock(const void *p);
void address_write_unlock(const void *p);

#ifdef DEBUG_ALLOC_INSIDE_LOCKS
void address_lock_verify(void);
#else
static inline void address_lock_verify(void) { }
#endif

void address_lock_init(void);
void address_lock_done(void);

#endif
