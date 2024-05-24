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

#include "obj_reg.h"
#include "mem_al.h"
#include "os.h"

#include "thread.h"

#ifdef THREAD_WIN32

#if !defined(HAVE__BEGINTHREADEX) || defined(__CYGWIN__)
#include <pthread.h>
#endif

#define WIN32_STACK_SIZE	65536

struct win32_thread {
	struct list wait_entry;
	HANDLE wakeup;
#ifdef HAVE__BEGINTHREADEX
	HANDLE thread_handle;	/* warning: not useable within the thread */
#else
	pthread_t pthread_handle;
#endif
	void (*function)(void *);
	void *arg;
	thread_priority_t priority;
};

bool rwmutex_supported;

static struct win32_thread thread_1;

static tls_decl(struct win32_thread *, current_tcb);

unsigned thread_concurrency(void)
{
	thread_concurrency_win32_;
	return 1;
}

static BOOL(WINAPI *fn_TryEnterCriticalSection)(LPCRITICAL_SECTION);
static BOOL(WINAPI *fn_InitializeCriticalSectionAndSpinCount)(LPCRITICAL_SECTION, DWORD);
static VOID (WINAPI *fn_InitializeSRWLock)(void *);
static VOID (WINAPI *fn_AcquireSRWLockShared)(void *);
static VOID (WINAPI *fn_ReleaseSRWLockShared)(void *);
static VOID (WINAPI *fn_AcquireSRWLockExclusive)(void *);
static VOID (WINAPI *fn_ReleaseSRWLockExclusive)(void *);


#define do_mutex_init(m)						\
do {									\
	BOOL r;								\
	if (likely(fn_InitializeCriticalSectionAndSpinCount != NULL)) {	\
		r = fn_InitializeCriticalSectionAndSpinCount(m, 200);	\
		if (unlikely(!r))					\
			InitializeCriticalSection(m);			\
	} else {							\
		InitializeCriticalSection(m);				\
	}								\
} while (0)

#define do_mutex_done(m)						\
do {									\
	DeleteCriticalSection(m);					\
} while (0)

#define do_mutex_lock(m)						\
do {									\
	EnterCriticalSection(m);					\
} while (0)

#define do_mutex_trylock(m)						\
do {									\
	if (fn_TryEnterCriticalSection)					\
		return !!fn_TryEnterCriticalSection(m);			\
	return false;							\
} while (0)

#define do_mutex_unlock(m)						\
do {									\
	LeaveCriticalSection(m);					\
} while (0)


#define do_rwmutex_init(m)						\
do {									\
	if (unlikely(!rwmutex_supported))				\
		InitializeCriticalSection(m);				\
	else								\
		fn_InitializeSRWLock(m);				\
} while (0)

#define do_rwmutex_done(m)						\
do {									\
	if (unlikely(!rwmutex_supported))				\
		DeleteCriticalSection(m);				\
} while (0)

#define do_rwmutex_lock_read(m)						\
do {									\
	if (unlikely(!rwmutex_supported))				\
		EnterCriticalSection(m);				\
	else								\
		fn_AcquireSRWLockShared(m);				\
} while (0)

#define do_rwmutex_unlock_read(m)					\
do {									\
	if (unlikely(!rwmutex_supported))				\
		LeaveCriticalSection(m);				\
	else								\
		fn_ReleaseSRWLockShared(m);				\
} while (0)

#define do_rwmutex_lock_write(m)					\
do {									\
	if (unlikely(!rwmutex_supported))				\
		EnterCriticalSection(m);				\
	else								\
		fn_AcquireSRWLockExclusive(m);				\
} while (0)

#define do_rwmutex_unlock_write(m)					\
do {									\
	if (unlikely(!rwmutex_supported))				\
		LeaveCriticalSection(m);				\
	else								\
		fn_ReleaseSRWLockExclusive(m);				\
} while (0)


#define do_cond_init(c)							\
do {									\
	mutex_init_position(&(c)->mutex pass_position);			\
	list_init(&(c)->wait_list);					\
} while (0)

#define do_cond_done(c)							\
do {									\
	mutex_done_position(&(c)->mutex pass_position);			\
	ajla_assert(list_is_empty(&(c)->wait_list), (caller_file_line, "cond_done: wait list is not empty"));\
} while (0)

#define do_cond_lock(c)							\
do {									\
	mutex_lock_position(&(c)->mutex pass_position);			\
} while (0)

#define do_cond_unlock(c)						\
do {									\
	mutex_unlock_position(&(c)->mutex pass_position);		\
} while (0)

#define do_cond_unlock_signal(c)					\
do {									\
	BOOL r;								\
	struct win32_thread *tcb;					\
	if (unlikely(!list_is_empty(&(c)->wait_list))) {		\
		tcb = get_struct((c)->wait_list.next, struct win32_thread, wait_entry);\
		list_del(&tcb->wait_entry);				\
		tcb->wait_entry.prev = NULL;				\
	} else {							\
		tcb = NULL;						\
	}								\
	mutex_unlock_position(&(c)->mutex pass_position);		\
	if (unlikely(tcb != NULL)) {					\
		r = SetEvent(tcb->wakeup);				\
		if (unlikely(!r))					\
			internal(caller_file_line, "cond_unlock_signal: SetEvent failed: %u", (unsigned)GetLastError());\
	}								\
} while (0)

#define do_cond_unlock_broadcast(c)					\
do {									\
	BOOL r;								\
	struct list list;						\
	struct list *l;							\
	list_take(&list, &(c)->wait_list);				\
	for (l = list.next; l != &list; l = l->next)			\
		l->prev = NULL;						\
	mutex_unlock_position(&(c)->mutex pass_position);		\
	while (list.next != &list) {					\
		struct win32_thread *tcb = get_struct(list.next, struct win32_thread, wait_entry);\
		list.next = tcb->wait_entry.next;			\
		r = SetEvent(tcb->wakeup);				\
		if (unlikely(!r))					\
			internal(caller_file_line, "cond_unlock_signal: SetEvent failed: %u", (unsigned)GetLastError());\
	}								\
} while (0)

static attr_noreturn attr_cold win32_wait_failed(const char *str, DWORD r argument_position)
{
	if (r == WAIT_FAILED)
		internal(caller_file_line, "win32_cond_wait_failed: %s failed: error %u", str, (unsigned)GetLastError());
	else
		internal(caller_file_line, "win32_cond_wait_failed: %s failed: status %u", str, (unsigned)r);
}

static bool win32_cond_wait(cond_t *c, DWORD timeout argument_position)
{
	DWORD r;
	struct win32_thread *tcb;
	tcb = tls_get(struct win32_thread *, current_tcb);
	list_add(&(c)->wait_list, &tcb->wait_entry);
	mutex_unlock_position(&(c)->mutex pass_position);
	r = WaitForSingleObjectEx(tcb->wakeup, timeout, TRUE);
	mutex_lock_position(&(c)->mutex pass_position);
	if (r != WAIT_OBJECT_0) {
		if (r != WAIT_IO_COMPLETION && unlikely(r != WAIT_TIMEOUT))
			win32_wait_failed("WaitForSingleObjectEx", r pass_position);
		if (likely(tcb->wait_entry.prev != NULL)) {
			list_del(&tcb->wait_entry);
			return false;
		} else {
			r = WaitForSingleObject(tcb->wakeup, INFINITE);
			if (unlikely(r != WAIT_OBJECT_0))
				win32_wait_failed("WaitForSingleObject", r pass_position);
		}
	}
	return true;
}

#define do_cond_wait(c)							\
do {									\
	win32_cond_wait(c, INFINITE pass_position);			\
} while (0)

#define do_cond_wait_us(c, us)						\
do {									\
	return win32_cond_wait(c, (us + 999) / 1000 pass_position);	\
} while (0)

static void win32_thread_init(struct win32_thread *tcb argument_position)
{
	tcb->wakeup = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (unlikely(!tcb->wakeup))
		fatal("CreateEventA failed at %s: %u", caller_file_line, (unsigned)GetLastError());
}

static void win32_thread_done(struct win32_thread *tcb argument_position)
{
	if (unlikely(!CloseHandle(tcb->wakeup)))
		internal(caller_file_line, "win32_thread_done: CloseHandle failed: %u", (unsigned)GetLastError());
}

static inline void win32_thread_common(struct win32_thread *tcb)
{
	if (tcb->priority == PRIORITY_TIMER) {
		if (unlikely(!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST)))
			warning("SetThreadPriority(THREAD_PRIORITY_HIGHEST) failed: %u", (unsigned)GetLastError());
	}
	tls_set(struct win32_thread *, current_tcb, tcb);
	asm_setup_thread();
	tcb->function(tcb->arg);
	tls_destructor_call();
}

#ifdef HAVE__BEGINTHREADEX

static unsigned __stdcall win32_thread_function(void *tcb_)
{
	struct win32_thread *tcb = cast_cpp(struct win32_thread *, tcb_);
	win32_thread_common(tcb);
	return 0;
}

#define do_thread_spawn(t, function, arg, priority, err)		\
do {									\
	struct win32_thread *tcb;					\
	unsigned thrd;							\
	tcb = mem_alloc_mayfail(struct win32_thread *, sizeof(struct win32_thread), err);\
	if (unlikely(!tcb))						\
		return false;						\
	win32_thread_init(tcb pass_position);				\
	tcb->function = function;					\
	tcb->arg = arg;							\
	tcb->priority = priority;					\
	tcb->thread_handle = (HANDLE)_beginthreadex(NULL, WIN32_STACK_SIZE, win32_thread_function, tcb, 0, &thrd);\
	if (unlikely(!tcb->thread_handle)) {				\
		int er = errno;						\
		ajla_error_t e = error_from_errno(EC_SYSCALL, er);	\
		fatal_mayfail(e, err, "_beginthreadex failed at %s: %u, %d, %s", position_string(position_arg), GetLastError(), er, error_decode(e));\
		mem_free(tcb);						\
		return false;						\
	}								\
	*(t) = tcb;							\
} while (0)

#define do_thread_join(t)						\
do {									\
	DWORD r;							\
	struct win32_thread *tcb = *(t);				\
	r = WaitForSingleObject(tcb->thread_handle, INFINITE);		\
	if (unlikely(r != WAIT_OBJECT_0))				\
		win32_wait_failed("WaitForSingleObject", r pass_position);\
	win32_thread_done(tcb pass_position);				\
	if (unlikely(!CloseHandle(tcb->thread_handle)))			\
		internal(caller_file_line, "thread_join: CloseHandle failed: %u", (unsigned)GetLastError());\
	mem_free(tcb);							\
} while (0)

#else

static void *pthread_thread_function(void *tcb_)
{
	struct win32_thread *tcb = cast_cpp(struct win32_thread *, tcb_);
	win32_thread_common(tcb);
	return NULL;
}

#define do_thread_spawn(t, function, arg, priority, err)		\
do {									\
	int r;								\
	struct win32_thread *tcb;					\
	tcb = mem_alloc_mayfail(struct win32_thread *, sizeof(struct win32_thread), err);\
	if (unlikely(!tcb))						\
		return false;						\
	win32_thread_init(tcb pass_position);				\
	tcb->function = function;					\
	tcb->arg = arg;							\
	tcb->priority = priority;					\
	r = pthread_create(&tcb->pthread_handle, NULL, pthread_thread_function, tcb);\
	if (unlikely(r)) {						\
		ajla_error_t e = error_from_errno(EC_SYSCALL, r);	\
		fatal_mayfail(e, err, "pthread_create failed at %s: %d, %s", position_string(position_arg), r, error_decode(e));\
		mem_free(tcb);						\
		return false;						\
	}								\
	*(t) = tcb;							\
} while (0)

#define do_thread_join(t)						\
do {									\
	int r;								\
	struct win32_thread *tcb = *(t);				\
	r = pthread_join(tcb->pthread_handle, NULL);			\
	if (unlikely(r))						\
		internal(caller_file_line, "thread_join: pthread_join failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
	win32_thread_done(tcb pass_position);				\
	mem_free(tcb);							\
} while (0)

#endif

#ifndef HAVE___THREAD

#define do_tls_init(tl)							\
do {									\
	DWORD r = TlsAlloc();						\
	if (unlikely(!r))						\
		fatal("TlsAlloc failed at %s: %u", caller_file_line, (unsigned)GetLastError());\
	*(tl) = r;							\
} while (0)

#define do_tls_done(tl)							\
do {									\
	if (unlikely(!TlsFree(*(tl))))					\
		internal(caller_file_line, "TlsFree failed: %u", (unsigned)GetLastError());\
} while (0)

#define do_tls_get(tl, ret)						\
do {									\
	void *r = TlsGetValue(*(tl));					\
	if (unlikely(!r)) {						\
		DWORD le = GetLastError();				\
		if (unlikely(le != 0))					\
			internal(caller_file_line, "TlsGetValue(%u) failed: %u", (unsigned)*(tl), (unsigned)GetLastError());\
	}								\
	*(ret) = ptr_to_num(r);						\
} while (0)

#define do_tls_set(tl, val)						\
do {									\
	if (unlikely(!TlsSetValue(*(tl), (void *)(val))))		\
		internal(caller_file_line, "TlsSetValue(%u) failed: %u", (unsigned)*(tl), (unsigned)GetLastError());\
} while (0)

#endif


#include "th_com.inc"


#include "th_sig.inc"


void thread_init(void)
{
	fn_TryEnterCriticalSection = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TryEnterCriticalSection");
	fn_InitializeCriticalSectionAndSpinCount = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "InitializeCriticalSectionAndSpinCount");
	fn_InitializeSRWLock = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "InitializeSRWLock");
	fn_AcquireSRWLockShared = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AcquireSRWLockShared");
	fn_ReleaseSRWLockShared = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReleaseSRWLockShared");
	fn_AcquireSRWLockExclusive = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AcquireSRWLockExclusive");
	fn_ReleaseSRWLockExclusive = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReleaseSRWLockExclusive");
	rwmutex_supported = fn_InitializeSRWLock && fn_AcquireSRWLockShared && fn_ReleaseSRWLockShared && fn_AcquireSRWLockExclusive && fn_ReleaseSRWLockExclusive;

	thread_signal_init();
	win32_thread_init(&thread_1 pass_file_line);
	tls_init(struct win32_thread *, current_tcb);
	tls_set(struct win32_thread *, current_tcb, &thread_1);
	thread_common_init();
}

void thread_done(void)
{
	thread_common_done();
	win32_thread_done(&thread_1 pass_file_line);
	tls_done(struct win32_thread *, current_tcb);
	thread_signal_done();
}

#endif
