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

#include "thread.h"

#ifdef THREAD_OS2

struct os2_thread {
	struct list wait_entry;
	HEV wakeup;
	HEV terminate;
#ifndef HAVE___THREAD
	uintptr_t tls[OS2_THREAD_KEY_MAX];
#endif
	void (*function)(void *);
	void *arg;
	thread_priority_t priority;
};

static struct os2_thread thread_1;

#ifndef HAVE___THREAD
static os2_tls_key_t os2_tls_used;
#endif

mutex_t thread_spawn_mutex;

#ifdef HAVE__THREADSTORE

static void os2_tcb_set(struct os2_thread *tcb)
{
	*_threadstore() = tcb;
}

static inline struct os2_thread *os2_tcb(void)
{
	return cast_cpp(struct os2_thread *, *_threadstore());
}

#else

#define OS2_MAX_THREADS		256

static struct os2_thread *os2_thread_array[OS2_MAX_THREADS];

static void os2_tcb_set(struct os2_thread *tcb)
{
	unsigned id = (unsigned)*_threadid;
	if (unlikely(id >= OS2_MAX_THREADS))
		fatal("too high thread id: %u", id);
	os2_thread_array[id] = tcb;
}

static inline struct os2_thread *os2_tcb(void)
{
	unsigned id = (unsigned)*_threadid;
	ajla_assert(id < OS2_MAX_THREADS, (file_line, "too high thread id: %u", id));
	return os2_thread_array[id];
}

#endif

unsigned thread_concurrency(void)
{
	APIRET r;
	ULONG n_cpus = 0;
	r = DosQuerySysInfo(26, 26, &n_cpus, sizeof(n_cpus));
	if (unlikely(r != 0)) {
		/*warning("DosQuerySysInfo(26) failed: %lu", r);*/
		return 1;
	}
	if (unlikely(!n_cpus)) {
		warning("DosQuerySysInfo(26) returned zero");
		return 1;
	}
#ifdef OS2_MAX_THREADS
	if (unlikely(n_cpus > OS2_MAX_THREADS / 2))
		return OS2_MAX_THREADS / 2;
#endif
	return (unsigned)n_cpus;
}

#ifdef OS2_USE_FMUTEX

#define do_mutex_init(m)						\
do {									\
	unsigned r;							\
	r = _fmutex_create(m, 0);					\
	if (unlikely(r != 0))						\
		fatal("_fmutex_cerate failed at %s: %u", position_string(position_arg), r);\
} while (0)

#define do_mutex_done(m)						\
do {									\
	int av;								\
	unsigned r;							\
	av = _fmutex_available(m);					\
	if (unlikely(!av))						\
		internal(caller_file_line, "mutex_done: _fmutex is still locked");\
	r = _fmutex_close(m);						\
	if (unlikely(r != 0))						\
		internal(caller_file_line, "mutex_done: _fmutex_close failed: %u", r);\
} while (0)

#define do_mutex_lock(m)						\
do {									\
	unsigned r;							\
	r = _fmutex_request(m, _FMR_IGNINT);				\
	if (unlikely(r != 0))						\
		internal(caller_file_line, "mutex_lock: _fmutex_request failed: %u", r);\
} while (0)

#define do_mutex_trylock(m)						\
do {									\
	unsigned r;							\
	r = _fmutex_request(m, _FMR_IGNINT | _FMR_NOWAIT);		\
	if (unlikely(r != 0)) {						\
		if (likely(r == ERROR_MUTEX_OWNED))			\
			return false;					\
		internal(caller_file_line, "mutex_trylock: _fmutex_request failed: %u", r);\
	}								\
	return true;							\
} while (0)

#define do_mutex_unlock(m)						\
do {									\
	unsigned r;							\
	r = _fmutex_release(m);						\
	if (unlikely(r != 0))						\
		internal(caller_file_line, "mutex_unlock: _fmutex_release failed: %u", r);\
} while (0)

#else

#define do_mutex_init(m)						\
do {									\
	APIRET r;							\
	r = DosCreateMutexSem(NULL, m, 0, FALSE);			\
	if (unlikely(r != 0))						\
		fatal("DosCreateMutexSem failed at %s: %lu", position_string(position_arg), r);\
} while (0)

#define do_mutex_done(m)						\
do {									\
	APIRET r;							\
	r = DosCloseMutexSem(*m);					\
	if (unlikely(r != 0))						\
		internal(caller_file_line, "mutex_done: DosCloseMutexSem failed: %lu", r);\
} while (0)

#define do_mutex_lock(m)						\
do {									\
	APIRET r;							\
again:									\
	r = DosRequestMutexSem(*m, SEM_INDEFINITE_WAIT);		\
	if (unlikely(r != 0)) {						\
		if (r == ERROR_INTERRUPT || r == ERROR_TIMEOUT)		\
			goto again;					\
		internal(caller_file_line, "mutex_lock: DosRequestMutexSem failed: %lu", r);\
	}								\
} while (0)

#define do_mutex_trylock(m)						\
do {									\
	APIRET r;							\
again:									\
	r = DosRequestMutexSem(*m, SEM_IMMEDIATE_RETURN);		\
	if (unlikely(r != 0)) {						\
		if (likely(r == ERROR_TIMEOUT))				\
			return false;					\
		if (r == ERROR_INTERRUPT)				\
			goto again;					\
		internal(caller_file_line, "mutex_trylock: DosRequestMutexSem failed: %lu", r);\
	}								\
	return true;							\
} while (0)

#define do_mutex_unlock(m)						\
do {									\
	APIRET r;							\
	r = DosReleaseMutexSem(*m);					\
	if (unlikely(r != 0))						\
		internal(caller_file_line, "mutex_unlock: DosReleaseMutexSem failed: %lu", r);\
} while (0)

#endif

#define do_cond_init(c)							\
do {									\
	mutex_init_position(&(c)->mutex pass_position);			\
	list_init(&(c)->wait_list);					\
} while (0)

#define do_cond_done(c)							\
do {									\
	mutex_done_position(&(c)->mutex pass_position);			\
	ajla_assert_lo(list_is_empty(&(c)->wait_list), (caller_file_line, "cond_done: wait list is not empty"));\
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
	APIRET r;							\
	struct os2_thread *tcb;						\
	if (unlikely(!list_is_empty(&(c)->wait_list))) {		\
		tcb = get_struct((c)->wait_list.next, struct os2_thread, wait_entry);\
		list_del(&tcb->wait_entry);				\
		tcb->wait_entry.prev = NULL;				\
	} else {							\
		tcb = NULL;						\
	}								\
	mutex_unlock_position(&(c)->mutex pass_position);		\
	if (unlikely(tcb != NULL)) {					\
		r = DosPostEventSem(tcb->wakeup);			\
		if (unlikely(r != 0))					\
			internal(caller_file_line, "cond_unlock_signal: DosPostEventSem failed: %lu", r);\
	}								\
} while (0)

#define do_cond_unlock_broadcast(c)					\
do {									\
	APIRET r;							\
	struct list list;						\
	struct list *l;							\
	list_take(&list, &(c)->wait_list);				\
	for (l = list.next; l != &list; l = l->next)			\
		l->prev = NULL;						\
	mutex_unlock_position(&(c)->mutex pass_position);		\
	while (list.next != &list) {					\
		struct os2_thread *tcb = get_struct(list.next, struct os2_thread, wait_entry);\
		list.next = tcb->wait_entry.next;			\
		r = DosPostEventSem(tcb->wakeup);			\
		if (unlikely(r != 0))					\
			internal(caller_file_line, "cond_broadcast: DosPostEventSem failed: %lu", r);\
	}								\
} while (0)

#define do_cond_wait(c)							\
do {									\
	APIRET r;							\
	ULONG sink;							\
	struct os2_thread *tcb;						\
	tcb = os2_tcb();						\
	list_add(&(c)->wait_list, &tcb->wait_entry);			\
	mutex_unlock_position(&(c)->mutex pass_position);		\
again:									\
	r = DosWaitEventSem(tcb->wakeup, SEM_INDEFINITE_WAIT);		\
	if (unlikely(r != 0)) {						\
		if (r == ERROR_INTERRUPT || r == ERROR_TIMEOUT)		\
			goto again;					\
		internal(caller_file_line, "cond_wait: DosWaitEventSem failed: %lu", r);\
	}								\
	r = DosResetEventSem(tcb->wakeup, &sink);			\
	if (unlikely(r != 0))						\
		internal(caller_file_line, "cond_wait: DosResetEventSem failed: %lu", r);\
	mutex_lock_position(&(c)->mutex pass_position);			\
} while (0)

/* warning: this function can end prematurely on ERROR_INTERRUPT */
#define do_cond_wait_us(c, us)						\
do {									\
	APIRET r;							\
	ULONG sink;							\
	struct os2_thread *tcb;						\
	tcb = os2_tcb();						\
	list_add(&(c)->wait_list, &tcb->wait_entry);			\
	mutex_unlock_position(&(c)->mutex pass_position);		\
	r = DosWaitEventSem(tcb->wakeup, (us + 999) / 1000);		\
	if (likely(r != 0)) {						\
		if (unlikely(!(likely(r == ERROR_TIMEOUT) || r == ERROR_INTERRUPT)))\
			internal(caller_file_line, "cond_wait_us: DosWaitEventSem 1 failed: %lu", r);\
		mutex_lock_position(&(c)->mutex pass_position);		\
		if (likely(tcb->wait_entry.prev != NULL)) {		\
			list_del(&tcb->wait_entry);			\
			return false;					\
		} else {						\
again:									\
			r = DosWaitEventSem(tcb->wakeup, SEM_INDEFINITE_WAIT);\
			if (unlikely(r != 0)) {				\
				if (r == ERROR_INTERRUPT || r == ERROR_TIMEOUT)\
					goto again;			\
				internal(caller_file_line, "cond_wait: DosWaitEventSem 2 failed: %lu", r);\
			}						\
			r = DosResetEventSem(tcb->wakeup, &sink);	\
			if (unlikely(r != 0))				\
				internal(caller_file_line, "cond_wait_us: DosResetEventSem 2 failed: %lu", r);\
			return true;					\
		}							\
	} else {							\
		r = DosResetEventSem(tcb->wakeup, &sink);		\
		if (unlikely(r != 0))					\
			internal(caller_file_line, "cond_wait_us: DosResetEventSem 1 failed: %lu", r);\
		mutex_lock_position(&(c)->mutex pass_position);		\
		return true;						\
	}								\
} while (0)

static void os2_thread_init(struct os2_thread *tcb, bool t1 argument_position)
{
	APIRET r;
	r = DosCreateEventSem(NULL, &tcb->wakeup, 0, FALSE);
	if (unlikely(r != 0))
		fatal("DosCreateEventSem 1 failed at %s: %lu", caller_file_line, r);
	if (!t1) {
		r = DosCreateEventSem(NULL, &tcb->terminate, 0, FALSE);
		if (unlikely(r != 0))
			fatal("DosCreateEventSem 2 failed at %s: %lu", caller_file_line, r);
	}
#ifndef HAVE___THREAD
	(void)memset(&tcb->tls, 0, sizeof tcb->tls);
#endif
}

static void os2_thread_done(struct os2_thread *tcb, bool t1 argument_position)
{
	APIRET r;
	ULONG cnt;
	r = DosQueryEventSem(tcb->wakeup, &cnt);
	if (unlikely(r != 0))
		internal(caller_file_line, "os2_thread_done: DosQueryEventSem 1 failed: %lu", r);
	if (unlikely(cnt != 0))
		internal(caller_file_line, "os2_thread_done: wakeup semaphore set: %lu", cnt);
	r = DosCloseEventSem(tcb->wakeup);
	if (unlikely(r != 0))
		internal(caller_file_line, "os2_thread_done: DosCloseEventSem 1 failed: %lu", r);
	if (!t1) {
		r = DosQueryEventSem(tcb->terminate, &cnt);
		if (unlikely(r != 0))
			internal(caller_file_line, "os2_thread_done: DosQueryEventSem 2 failed: %lu", r);
		if (unlikely(cnt != 1))
			internal(caller_file_line, "os2_thread_done: terminate semaphore not set: %lu", cnt);
		r = DosCloseEventSem(tcb->terminate);
		if (unlikely(r != 0))
			internal(caller_file_line, "os2_thread_done: DosCloseEventSem 2 failed: %lu", r);
	}
}

static void os2_thread_function(void *tcb_)
{
	APIRET r;
	struct os2_thread *tcb = cast_cpp(struct os2_thread *, tcb_);
	ULONG cls;
	LONG del;
	os2_tcb_set(tcb);
	cls = PRTYC_NOCHANGE;
	del = 0;
	if (tcb->priority == PRIORITY_TIMER) {
#if 0
		cls = PRTYC_TIMECRITICAL;
#else
		del = 31;
#endif
	}
	r = DosSetPriority(PRTYS_THREAD, cls, del, 0);
	if (unlikely(r != 0))
		warning("DosSetPriority(%ld,%lu) failed: %lu", cls, del, r);
	asm_setup_thread();
	tcb->function(tcb->arg);
	tls_destructor_call();
	r = DosPostEventSem(tcb->terminate);
	if (unlikely(r != 0))
		internal(file_line, "os2_thread_function: DosPostEventSem failed: %lu", r);
}

#define do_thread_spawn(t, function, arg, priority, err)		\
do {									\
	struct os2_thread *tcb;						\
	int btr;							\
	tcb = mem_alloc_mayfail(struct os2_thread *, sizeof(struct os2_thread), err);\
	if (unlikely(!tcb))						\
		return false;						\
	os2_thread_init(tcb, false pass_position);			\
	tcb->function = function;					\
	tcb->arg = arg;							\
	tcb->priority = priority;					\
	mutex_lock(&thread_spawn_mutex);				\
	btr = _beginthread(os2_thread_function, NULL, MINIMUM_STACK_SIZE, tcb);\
	mutex_unlock(&thread_spawn_mutex);				\
	if (unlikely(btr == -1)) {					\
		int er = errno;						\
		ajla_error_t e = error_from_errno(EC_SYSCALL, er);	\
		fatal("_beginthread failed at %s: %d, %s", position_string(position_arg), er, error_decode(e));\
		mem_free(tcb);						\
		return false;						\
	}								\
	*(t) = tcb;							\
} while (0)

#define do_thread_join(t)						\
do {									\
	APIRET r;							\
	struct os2_thread *tcb = *(t);					\
again:									\
	r = DosWaitEventSem(tcb->terminate, SEM_INDEFINITE_WAIT);	\
	if (unlikely(r != 0)) {						\
		if (r == ERROR_INTERRUPT || r == ERROR_TIMEOUT)		\
			goto again;					\
		internal(caller_file_line, "thread_join: DosWaitEventSem failed: %lu", r);\
	}								\
	os2_thread_done(tcb, false pass_position);			\
	mem_free(tcb);							\
} while (0)

#ifndef HAVE___THREAD

#define do_tls_init(tl)							\
do {									\
	ajla_assert_lo(os2_tls_used < OS2_THREAD_KEY_MAX, (caller_file_line, "tls_init: too many tls keys: %d", os2_tls_used));\
	*(tl) = os2_tls_used++;						\
} while (0)

#define do_tls_done(tl)							\
do {									\
	ajla_assert_lo(*(tl) < os2_tls_used, (caller_file_line, "tls_done: invalid tls key: %d >= %d", *(tl), os2_tls_used));\
} while (0)

#define do_tls_get(tl, ret)						\
do {									\
	ajla_assert(*(tl) < os2_tls_used, (caller_file_line, "tls_get: invalid tls key: %d >= %d", *(tl), os2_tls_used));\
	*(ret) = os2_tcb()->tls[*(tl)];					\
} while (0)

#define do_tls_set(tl, val)						\
do {									\
	ajla_assert(*(tl) < os2_tls_used, (caller_file_line, "tls_set: invalid tls key: %d >= %d", *(tl), os2_tls_used));\
	os2_tcb()->tls[*(tl)] = (val);					\
} while (0)

#endif

#include "th_com.inc"

void thread_init(void)
{
#ifndef HAVE___THREAD
	os2_tls_used = 0;
#endif
	os2_thread_init(&thread_1, true pass_file_line);
	os2_tcb_set(&thread_1);
	thread_common_init();
	mutex_init(&thread_spawn_mutex);
}

void thread_done(void)
{
	ajla_assert_lo(os2_tcb() == &thread_1, (file_line, "thread_done: mismatching thread 1: %p != %p", os2_tcb(), &thread_1));
	mutex_done(&thread_spawn_mutex);
	thread_common_done();
#if defined(DEBUG_LOW_OVERHEAD)
	os2_tcb_set(NULL);
#endif
	os2_thread_done(&thread_1, true pass_file_line);
}

#endif
