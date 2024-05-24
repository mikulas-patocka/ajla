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

#ifndef AJLA_THREAD_H
#define AJLA_THREAD_H

#include "list.h"
#include "asm.h"

#if defined(__BIONIC__) || defined(__minix__) || defined(UNUSUAL_THREAD)
#undef HAVE___THREAD
#endif

#if defined(THREAD_NONE)
#define thread_volatile
#else
#define thread_volatile	volatile
#endif

#if defined(THREAD_NONE)
#undef HAVE___THREAD
#define HAVE___THREAD
#endif

#define tls_verify_type_common_(type)				\
	ajla_assert(sizeof(type) <= sizeof(void *), (file_line, "tls_verify_type_common_: too big type: %d > %d", (int)sizeof(type), (int)sizeof(type)))

#if defined(HAVE___THREAD)
#define tls_verify_type_(type, variable)	((void)(&variable - (type *)&variable), tls_verify_type_common_(type))
#define tls_decl(type, variable)		HAVE___THREAD type variable = (type)0
#define tls_decl_extern(type, variable)		extern HAVE___THREAD type variable
typedef void tls_t_;
#define tls_get_(variable)			(*variable)
#define tls_get__nocheck			tls_get_
#define tls_get_cast(type)
#define tls_set_(variable, value)		do { (*variable = (value)); } while (0)
#define tls_set__nocheck			tls_set_
#define tls_set_cast
#else
#define tls_verify_type_(type, variable)	tls_verify_type_common_(type)
#endif

#ifndef THREAD_NONE
void tls_destructor_call(void);
#endif

#if defined(OS_WIN32) || defined(OS_CYGWIN)

#define thread_concurrency_win32_				\
do {								\
	SYSTEM_INFO info;					\
	GetSystemInfo(&info);					\
	if (info.dwNumberOfProcessors > 0)			\
		return info.dwNumberOfProcessors;		\
	warning("GetSystemInfo returned zero processors");	\
} while (0)

#endif

#if defined(THREAD_OS2)

#if defined(HAVE_SYS_BUILTIN_H) && defined(HAVE_SYS_FMUTEX_H) && defined(HAVE__FMUTEX_CREATE) && !defined(UNUSUAL_THREAD)
#define OS2_USE_FMUTEX
#endif

#ifdef OS2_USE_FMUTEX
#include <sys/builtin.h>
#include <sys/fmutex.h>
typedef _fmutex mutex_t;
#else
typedef HMTX mutex_t;
#endif

typedef struct {
	mutex_t mutex;
	struct list wait_list;
} cond_t;

typedef struct os2_thread *thread_t;
typedef void thread_function_t(void *arg);
#define thread_function_decl(name, content)	static void name(void attr_unused *arg) { content }

extern mutex_t thread_spawn_mutex;

#if !defined(HAVE___THREAD)
typedef unsigned char os2_tls_key_t;
#define OS2_THREAD_KEY_MAX		16
#define tls_decl(type, variable)	os2_tls_key_t variable
#define tls_decl_extern(type, variable)	extern os2_tls_key_t variable
typedef os2_tls_key_t tls_t_;
#endif

#define rwmutex_fallback

#elif defined(THREAD_WIN32)

typedef CRITICAL_SECTION mutex_t;
typedef CRITICAL_SECTION rwmutex_t;
extern bool rwmutex_supported;

typedef struct {
	mutex_t mutex;
	struct list wait_list;
} cond_t;

typedef struct win32_thread *thread_t;
typedef void thread_function_t(void *arg);
#define thread_function_decl(name, content)	static void name(void attr_unused *arg) { content }

#if !defined(HAVE___THREAD)
typedef DWORD win32_tls_key_t;
#define tls_decl(type, variable)	win32_tls_key_t variable
#define tls_decl_extern(type, variable)	extern win32_tls_key_t variable
typedef win32_tls_key_t tls_t_;
#endif

#elif defined(THREAD_POSIX)

#include <pthread.h>
#ifndef UNUSUAL_SPINLOCK
typedef pthread_mutex_t	mutex_t;
#else
typedef pthread_spinlock_t mutex_t;
#endif
typedef pthread_rwlock_t rwmutex_t;
#define rwmutex_supported	1
typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} cond_t;
typedef pthread_t thread_t;
typedef void *thread_function_t(void *arg);
#define thread_function_decl(name, content)	static void *name(void attr_unused *arg) { asm_setup_thread(); { content } tls_destructor_call(); return NULL; }

#if !defined(HAVE___THREAD)
#ifdef HAVE_PTHREAD_KEY_T_ASSIGN
#define tls_decl_initializer_	= (pthread_key_t)-1	/* catch uninitialized tls's */
#else
#define tls_decl_initializer_
#endif
#define tls_decl(type, variable)	pthread_key_t variable tls_decl_initializer_
#define tls_decl_extern(type, variable)	extern pthread_key_t variable
typedef pthread_key_t tls_t_;
#endif

#elif defined(THREAD_NONE)

#if defined(DEBUG_OBJECT_POSSIBLE)
typedef struct {
	unsigned char state;
} mutex_t;
typedef struct {
	int state;
} rwmutex_t;
#else
typedef EMPTY_TYPE mutex_t;
typedef EMPTY_TYPE rwmutex_t;
#endif
#define rwmutex_supported	0

typedef struct {
	mutex_t mutex;
} cond_t;

#else

error: no threads

#endif


#ifdef rwmutex_fallback
typedef mutex_t rwmutex_t;
#define rwmutex_supported	0
#define do_rwmutex_init		do_mutex_init
#define do_rwmutex_done		do_mutex_done
#define do_rwmutex_lock_read	do_mutex_lock
#define do_rwmutex_unlock_read	do_mutex_unlock
#define do_rwmutex_lock_write	do_mutex_lock
#define do_rwmutex_unlock_write	do_mutex_unlock
#endif


#if defined(DEBUG_OBJECT_POSSIBLE) || !defined(THREAD_NONE)
void mutex_init_position(mutex_t * argument_position);
void mutex_done_position(mutex_t * argument_position);
void attr_fastcall mutex_lock_position(mutex_t * argument_position);
bool attr_fastcall mutex_trylock_position(mutex_t * argument_position);
void attr_fastcall mutex_unlock_position(mutex_t * argument_position);
#else
static inline void mutex_init_position(mutex_t attr_unused *m argument_position) { }
static inline void mutex_done_position(mutex_t attr_unused *m argument_position) { }
static inline void mutex_lock_position(mutex_t attr_unused *m argument_position) { }
static inline bool mutex_trylock_position(mutex_t attr_unused *m argument_position) { return true; }
static inline void mutex_unlock_position(mutex_t attr_unused *m argument_position) { }
#endif
#define mutex_init(x)		mutex_init_position(x pass_file_line)
#define mutex_done(x)		mutex_done_position(x pass_file_line)
#define mutex_lock(x)		mutex_lock_position(x pass_file_line)
#define mutex_trylock(x)	mutex_trylock_position(x pass_file_line)
#define mutex_unlock(x)		mutex_unlock_position(x pass_file_line)


#if defined(DEBUG_OBJECT_POSSIBLE) || !defined(THREAD_NONE)
void rwmutex_init_position(rwmutex_t * argument_position);
void rwmutex_done_position(rwmutex_t * argument_position);
void attr_fastcall rwmutex_lock_read_position(rwmutex_t * argument_position);
void attr_fastcall rwmutex_unlock_read_position(rwmutex_t * argument_position);
void attr_fastcall rwmutex_lock_write_position(rwmutex_t * argument_position);
void attr_fastcall rwmutex_unlock_write_position(rwmutex_t * argument_position);
#else
static inline void rwmutex_init_position(rwmutex_t attr_unused *m argument_position) { }
static inline void rwmutex_done_position(rwmutex_t attr_unused *m argument_position) { }
static inline void rwmutex_lock_read_position(rwmutex_t attr_unused *m argument_position) { }
static inline void rwmutex_unlock_read_position(rwmutex_t attr_unused *m argument_position) { }
static inline void rwmutex_lock_write_position(rwmutex_t attr_unused *m argument_position) { }
static inline void rwmutex_unlock_write_position(rwmutex_t attr_unused *m argument_position) { }
#endif
#define rwmutex_init(x)		rwmutex_init_position(x pass_file_line)
#define rwmutex_done(x)		rwmutex_done_position(x pass_file_line)
#define rwmutex_lock_read(x)	rwmutex_lock_read_position(x pass_file_line)
#define rwmutex_unlock_read(x)	rwmutex_unlock_read_position(x pass_file_line)
#define rwmutex_lock_write(x)	rwmutex_lock_write_position(x pass_file_line)
#define rwmutex_unlock_write(x)	rwmutex_unlock_write_position(x pass_file_line)


#if defined(DEBUG_OBJECT_POSSIBLE) || !defined(THREAD_NONE)
void cond_init_position(cond_t * argument_position);
void cond_done_position(cond_t * argument_position);
void attr_fastcall cond_lock_position(cond_t * argument_position);
void attr_fastcall cond_unlock_position(cond_t * argument_position);
void attr_fastcall cond_unlock_signal_position(cond_t * argument_position);
void attr_fastcall cond_unlock_broadcast_position(cond_t * argument_position);
void attr_fastcall cond_wait_position(cond_t * argument_position);
bool attr_fastcall cond_wait_us_position(cond_t *, uint32_t argument_position);
#else
static inline void cond_init_position(cond_t attr_unused *c argument_position) { }
static inline void cond_done_position(cond_t attr_unused *c argument_position) { }
static inline void cond_lock_position(cond_t attr_unused *c argument_position) { }
static inline void cond_unlock_position(cond_t attr_unused *c argument_position) { }
static inline void cond_unlock_signal_position(cond_t attr_unused *c argument_position) { }
static inline void cond_unlock_broadcast_position(cond_t attr_unused *c argument_position) { }
static inline void cond_wait_position(cond_t attr_unused *c argument_position) { }
static inline bool cond_wait_us_position(cond_t attr_unused *c, uint32_t attr_unused us argument_position) { return false; }
#endif
#define cond_init(x)			cond_init_position(x pass_file_line)
#define cond_done(x)			cond_done_position(x pass_file_line)
#define cond_lock(x)			cond_lock_position(x pass_file_line)
#define cond_unlock(x)			cond_unlock_position(x pass_file_line)
#define cond_unlock_signal(x)		cond_unlock_signal_position(x pass_file_line)
#define cond_unlock_broadcast(x)	cond_unlock_broadcast_position(x pass_file_line)
#define cond_wait(x)			cond_wait_position(x pass_file_line)
#define cond_wait_us(x, y)		cond_wait_us_position(x, y pass_file_line)


#ifdef THREAD_NONE
#define thread_needs_barriers		false
static inline unsigned thread_concurrency(void) { return 1; }
#else
extern uchar_efficient_t thread_needs_barriers;
unsigned thread_concurrency(void);
#endif


#ifndef THREAD_NONE
typedef enum {
	PRIORITY_COMPUTE,
	PRIORITY_IO,
	PRIORITY_TIMER,
} thread_priority_t;
bool thread_spawn_position(thread_t *, thread_function_t *, void *, thread_priority_t priority, ajla_error_t *err argument_position);
void thread_join_position(thread_t * argument_position);
#define thread_spawn(t, fn, data, priority, err)	thread_spawn_position(t, fn, data, priority, err pass_file_line)
#define thread_join(t)					thread_join_position(t pass_file_line)
#endif


void tls_init__position(tls_t_ * argument_position);
void tls_done__position(tls_t_ * argument_position);
#if !defined(HAVE___THREAD)
uintptr_t attr_fastcall tls_get__position(const tls_t_ * argument_position);
void attr_fastcall tls_set__position(const tls_t_ *, uintptr_t argument_position);
uintptr_t attr_fastcall tls_get__nocheck(const tls_t_ *);
void attr_fastcall tls_set__nocheck(const tls_t_ *, uintptr_t);
#define tls_get_cast(type)	(type)
#define tls_set_cast		(uintptr_t)
#endif
#define tls_init_(x)		tls_init__position(x pass_file_line)
#define tls_done_(x)		tls_done__position(x pass_file_line)
#if !defined(HAVE___THREAD)
#define tls_get_(x)		tls_get__position(x pass_file_line)
#define tls_set_(x, y)		tls_set__position(x, y pass_file_line)
#endif

#define tls_init(type, variable)					\
do {									\
	tls_verify_type_(type, variable);				\
	tls_init_(&variable);						\
} while (0)

#define tls_done(type, variable)					\
do {									\
	tls_verify_type_(type, variable);				\
	tls_done_(&variable);						\
} while (0)

#define tls_get(type, variable)						\
	(tls_verify_type_(type, variable), tls_get_cast(type)tls_get_(&variable))

#define tls_set(type, variable, value)					\
do {									\
	tls_verify_type_(type, variable);				\
	tls_set_(&variable, tls_set_cast(value));			\
} while (0)

#define tls_get_nocheck(type, variable)					\
	(tls_verify_type_(type, variable), tls_get_cast(type)tls_get__nocheck(&variable))

#define tls_set_nocheck(type, variable, value)				\
do {									\
	tls_verify_type_(type, variable);				\
	tls_set__nocheck(&variable, tls_set_cast(value));		\
} while (0)

#ifdef THREAD_NONE
typedef EMPTY_TYPE tls_destructor_t;
typedef void tls_destructor_fn(tls_destructor_t *);
static inline void tls_destructor_position(tls_destructor_t attr_unused *destr, tls_destructor_fn attr_unused *fn argument_position) { }
#else
struct tls_destructor_s;
typedef void tls_destructor_fn(struct tls_destructor_s *);
typedef struct tls_destructor_s {
	struct tls_destructor_s *previous;
	tls_destructor_fn *fn;
} tls_destructor_t;
void tls_destructor_position(tls_destructor_t *, tls_destructor_fn * argument_position);
#endif
#define tls_destructor(dest, fn)			tls_destructor_position(dest, fn pass_file_line)

/*
 * See smp_read_barrier_depends() in Linux for explanation.
 * If we don't know how to do this barrier, we don't define this macro and
 * the user must not use lockless access model.
 */
#if defined(THREAD_NONE)
#define barrier_data_dependency()		do { } while (0)
#elif defined(__alpha)
#if defined(HAVE_C11_ATOMICS) && !defined(UNUSUAL)
#define barrier_data_dependency()		atomic_thread_fence(memory_order_seq_cst)
#elif defined(HAVE_SYNC_AND_FETCH) && !defined(UNUSUAL)
#define barrier_data_dependency()		__sync_synchronize()
#elif defined(HAVE_GCC_ASSEMBLER) && !defined(UNUSUAL)
#define barrier_data_dependency()		__asm__ volatile ("mb":::"memory")
#endif
#elif defined(__ADSPBLACKFIN__)
#else
#define barrier_data_dependency()		do { } while (0)
#endif

/*
 * The mutex_unlock/mutex_lock sequence serves as a memory write barrier.
 *
 * On powerpc, mutex_unlock/mutex_lock doesn't serve as a memory barrier for
 * threads that don't take the lock, so we must add barrier explicitly.
 *
 * See smp_mb__after_unlock_lock() in Linux for explanation.
 */
#if defined(THREAD_NONE)
#define barrier_write_before_unlock_lock()	do { } while (0)
#elif defined(__powerpc__)
#if defined(HAVE_C11_ATOMICS) && !defined(UNUSUAL)
#define barrier_write_before_unlock_lock()	atomic_thread_fence(memory_order_seq_cst)
#elif defined(HAVE_SYNC_AND_FETCH) && !defined(UNUSUAL)
#define barrier_write_before_unlock_lock()	__sync_synchronize()
#elif defined(HAVE_GCC_ASSEMBLER)
#define barrier_write_before_unlock_lock()	__asm__ volatile("sync":::"memory")
#else
#endif
#else
#define barrier_write_before_unlock_lock()	do { } while (0)
#endif

/*
 * A write barrier before lock, it makes sure that previous writes are not
 * reordered with the following content of locked region.
 */
#if defined(THREAD_NONE) || defined(THREAD_OS2) || (defined(ARCH_X86) && !defined(UNUSUAL))
#define barrier_write_before_lock()		do { } while (0)
#elif defined(HAVE_C11_ATOMICS) && !defined(UNUSUAL)
#define barrier_write_before_lock()		atomic_thread_fence(memory_order_seq_cst)
#elif defined(HAVE_SYNC_AND_FETCH) && !defined(UNUSUAL)
#define barrier_write_before_lock()		__sync_synchronize()
#elif defined(THREAD_WIN32)
#if (defined(MemoryBarrier) || defined(__buildmemorybarrier)) && !defined(UNUSUAL_THREAD)
#define barrier_write_before_lock()		MemoryBarrier()
#else
#define barrier_write_before_lock()		\
do {						\
	LONG x;					\
	InterlockedExchange(&x, 0);		\
} while (0)
#endif
#else
void barrier_write_before_lock(void);
#endif


#if !defined(THREAD_NONE) && defined(DEBUG_TRACE)
void thread_set_id(int id);
int thread_get_id(void);
#else
#define thread_set_id(id)			do { } while (0)
#define thread_get_id()				0
#endif


bool thread_enable_debugging_option(const char *option, size_t l);

void thread_init(void);
void thread_done(void);

#endif
