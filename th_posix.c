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
#include "str.h"
#include "os.h"
#include "os_util.h"

#include "thread.h"

#ifdef THREAD_POSIX

#if defined(HAVE_PTHREAD_CONDATTR_SETCLOCK) && defined(HAVE_CLOCK_GETTIME) && defined(HAVE_CLOCK_MONOTONIC)
#define USE_PTHREAD_CONDATTR
#endif

#ifndef USE_PTHREAD_CONDATTR
#include <sys/time.h>
#else
#include <time.h>
static clockid_t clock_id;
#endif

#if defined(HAVE_SYS_PARAM_H)
#include <sys/param.h>
#endif
#if defined(HAVE_SYS_PSTAT_H)
#include <sys/pstat.h>
#endif
#if defined(HAVE_SYS_SYSCTL_H) && defined(HAVE_SYSCTL) && defined(CTL_HW) && defined(HW_NCPU)
#include <sys/sysctl.h>
#endif

uchar_efficient_t thread_needs_barriers = true;

static inline unsigned thread_concurrency_getdynamic(void)
{
#if defined(HAVE_SYS_PSTAT_H) && defined(HAVE_PSTAT_GETDYNAMIC)
	struct pst_dynamic pst;
	int ir;
	EINTR_LOOP(ir, pstat_getdynamic(&pst, sizeof(pst), 1, 0));
	if (ir == 1) {
		if (unlikely(pst.psd_proc_cnt <= 0)) {
			warning("pstat_getdynamic returned invalid value %d", (int)pst.psd_proc_cnt);
			return 0;
		}
		return (unsigned)pst.psd_proc_cnt;
	}
#endif
	return 0;

}

static inline unsigned thread_concurrency_sysctl(void)
{
#if defined(HAVE_SYSCTL) && defined(CTL_HW) && defined(HW_NCPU)
	int n_cpus;
	int mib[2];
	size_t sz;
	int ir;
	n_cpus = 0;
	mib[0] = CTL_HW;
	mib[1] = HW_NCPU;
	sz = sizeof(n_cpus);
	EINTR_LOOP(ir, sysctl(mib, 2, &n_cpus, &sz, NULL, 0));
	if (likely(!ir)) {
		if (likely(n_cpus > 0))
			return (unsigned)n_cpus;
		warning("sysctl(CTL_HW,HW_NCPU) returned invalid value %d", n_cpus);
	} else {
		/*
		int er = errno;
		warning("sysctl(CTL_HW,HW_NCPU) returned error: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		*/
	}
#endif
	return 0;
}

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static inline unsigned thread_concurrency_sysconf(void)
{
#if !(defined(UNUSUAL) && defined(__linux__))
	int attr_unused ir;
	const char attr_unused *str;
#if defined(HAVE_SYSCONF) && defined(_SC_NPROCESSORS_ONLN)
	errno = 0;
	str = "sysconf(_SC_NPROCESSORS_ONLN)";
	EINTR_LOOP(ir, sysconf(_SC_NPROCESSORS_ONLN));
#elif defined(HAVE_SYSCONF) && defined(_SC_NPROC_ONLN)
	errno = 0;
	str = "sysconf(_SC_NPROC_ONLN)";
	EINTR_LOOP(ir, sysconf(_SC_NPROC_ONLN));
#else
	return 0;
#endif
	if (likely(ir > 0))
		return ir;
	if (ir == -1) {
		/*
		int er = errno;
		warning("%s returned error: %d, %s", str, er, error_decode(error_from_errno(EC_SYSCALL, er)));
		*/
	} else {
		warning("%s returned invalid value %d", str, ir);
	}
#endif
	return 0;
}

static inline unsigned thread_concurrency_linux(void)
{
#if defined(__linux__)
	ajla_error_t sink;
	char *str;
	const char *p;
	size_t len;
	unsigned n_cpus;
	if (unlikely(!os_read_file("/proc/cpuinfo", &str, &len, &sink)))
		return 0;
	array_add(char, &str, &len, 0);
	p = str;
	n_cpus = 0;
	while (1) {
		if (!strncmp(p, "processor", 9)) {
			n_cpus++;
		}
		p = strchr(p, '\n');
		if (unlikely(!p))
			break;
		p++;
	}
	mem_free(str);
	return n_cpus;
#endif
	return 0;
}

unsigned thread_concurrency(void)
{
	unsigned ret;
#ifdef thread_concurrency_win32_
	thread_concurrency_win32_;
#endif
	if ((ret = thread_concurrency_getdynamic()))
		return ret;
	if ((ret = thread_concurrency_sysctl()))
		return ret;
	if ((ret = thread_concurrency_sysconf()))
		return ret;
	if ((ret = thread_concurrency_linux()))
		return ret;
	return 1;
}

static pthread_mutexattr_t mutex_attr;
static pthread_rwlockattr_t rwmutex_attr;
#ifdef USE_PTHREAD_CONDATTR
static pthread_condattr_t cond_attr;
#define cond_attr_p	(&cond_attr)
#else
#define cond_attr_p	NULL
#endif
static pthread_attr_t thread_attr;

#define do_pthread_mutex_init(m)					\
do {									\
	int r;								\
	r = pthread_mutex_init(m, &mutex_attr);				\
	if (unlikely(r))						\
		fatal("pthread_mutex_init failed at %s: %d, %s", position_string(position_arg), r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_pthread_mutex_done(m)					\
do {									\
	int r;								\
	r = pthread_mutex_destroy(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_done: pthread_mutex_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_pthread_mutex_lock(m)					\
do {									\
	int r;								\
	r = pthread_mutex_lock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_lock: pthread_mutex_lock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_pthread_mutex_trylock(m)					\
do {									\
	int r;								\
	r = pthread_mutex_trylock(m);					\
	if (unlikely(r)) {						\
		if (unlikely(r != EBUSY) && unlikely(r != EDEADLK))	\
			internal(caller_file_line, "mutex_trylock: pthread_mutex_trylock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
		return false;						\
	}								\
	return true;							\
} while (0)

#define do_pthread_mutex_unlock(m)					\
do {									\
	int r;								\
	r = pthread_mutex_unlock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_unlock: pthread_mutex_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#ifndef UNUSUAL_SPINLOCK

#define do_mutex_init		do_pthread_mutex_init
#define do_mutex_done		do_pthread_mutex_done
#define do_mutex_lock		do_pthread_mutex_lock
#define do_mutex_trylock	do_pthread_mutex_trylock
#define do_mutex_unlock		do_pthread_mutex_unlock

#else

#define do_mutex_init(m)						\
do {									\
	int r;								\
	r = pthread_spin_init(m, PTHREAD_PROCESS_PRIVATE);		\
	if (unlikely(r))						\
		fatal("pthread_spin_init failed at %s: %d, %s", position_string(position_arg), r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_mutex_done(m)						\
do {									\
	int r;								\
	r = pthread_spin_destroy(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_done: pthread_spin_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_mutex_lock(m)						\
do {									\
	int r;								\
	r = pthread_spin_lock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_lock: pthread_spin_lock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_mutex_trylock(m)						\
do {									\
	int r;								\
	r = pthread_spin_trylock(m);					\
	if (unlikely(r)) {						\
		if (unlikely(r != EBUSY) && unlikely(r != EDEADLK))	\
			internal(caller_file_line, "mutex_trylock: pthread_spin_trylock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
		return false;						\
	}								\
	return true;							\
} while (0)

#define do_mutex_unlock(m)						\
do {									\
	int r;								\
	r = pthread_spin_unlock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_unlock: pthread_spin_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#endif

#define do_rwmutex_init(m)						\
do {									\
	int r;								\
	r = pthread_rwlock_init(m, &rwmutex_attr);			\
	if (unlikely(r))						\
		fatal("pthread_rwlock_init failed at %s: %d, %s", position_string(position_arg), r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_rwmutex_done(m)						\
do {									\
	int r;								\
	r = pthread_rwlock_destroy(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "rwmutex_done: pthread_rwlock_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_rwmutex_lock_read(m)						\
do {									\
	int r;								\
	r = pthread_rwlock_rdlock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "rwmutex_lock_read: pthread_rwlock_rdlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_rwmutex_unlock_read(m)					\
do {									\
	int r;								\
	r = pthread_rwlock_unlock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "rwmutex_unlock_read: pthread_rwlock_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_rwmutex_lock_write(m)					\
do {									\
	int r;								\
	r = pthread_rwlock_wrlock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "rwmutex_lock_write: pthread_rwlock_wrlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_rwmutex_unlock_write(m)					\
do {									\
	int r;								\
	r = pthread_rwlock_unlock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "rwmutex_unlock_write: pthread_rwlock_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_cond_init(c)							\
do {									\
	int r;								\
	do_pthread_mutex_init(&(c)->mutex);				\
	r = pthread_cond_init(&(c)->cond, cond_attr_p);			\
	if (unlikely(r))						\
		fatal("pthread_cond_init failed at %s: %d, %s", position_string(position_arg), r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_cond_done(c)							\
do {									\
	int r;								\
	do_pthread_mutex_done(&(c)->mutex);				\
	r = pthread_cond_destroy(&(c)->cond);				\
	if (unlikely(r))						\
		internal(caller_file_line, "cond_done: pthread_cond_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_cond_lock(c)							\
do {									\
	do_pthread_mutex_lock(&(c)->mutex);				\
} while (0)

#define do_cond_unlock(c)						\
do {									\
	do_pthread_mutex_unlock(&(c)->mutex);				\
} while (0)

#define do_cond_unlock_signal(c)					\
do {									\
	int r;								\
	do_pthread_mutex_unlock(&(c)->mutex);				\
	r = pthread_cond_signal(&(c)->cond);				\
	if (unlikely(r))						\
		internal(caller_file_line, "cond_unlock_signal: pthread_cond_signal failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_cond_unlock_broadcast(c)					\
do {									\
	int r;								\
	do_pthread_mutex_unlock(&(c)->mutex);				\
	r = pthread_cond_broadcast(&(c)->cond);				\
	if (unlikely(r))						\
		internal(caller_file_line, "cond_unlock_broadcast: pthread_cond_broadcast failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_cond_wait(c)							\
do {									\
	int r;								\
again:									\
	r = pthread_cond_wait(&(c)->cond, &(c)->mutex);			\
	if (unlikely(r)) {						\
		if (r == EINTR) goto again;				\
		internal(caller_file_line, "cond_wait: pthread_cond_wait failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
	}								\
} while (0)

#if !defined(USE_PTHREAD_CONDATTR)

static struct timespec cond_getts(uint32_t us)
{
	int r;
	struct timeval tv;
	struct timespec ts;

	EINTR_LOOP(r, gettimeofday(&tv, NULL));
	if (unlikely(r == -1)) {
		int e = errno;
		fatal("gettimeofday failed: %d, %s", e, error_decode(error_from_errno(EC_SYSCALL, e)));
	}
	if (unlikely(us >= 1000000)) {
		tv.tv_sec += us / 1000000;
		us %= 1000000;
	}
	tv.tv_usec += us;
	if (unlikely(tv.tv_usec >= 1000000)) {
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
	}
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = (uint32_t)tv.tv_usec * 1000;

	return ts;
}

#else

static struct timespec cond_getts(uint32_t us)
{
	int r;
	struct timespec ts;

	EINTR_LOOP(r, clock_gettime(clock_id, &ts));
	if (unlikely(r == -1)) {
		int e = errno;
		fatal("clock_gettime(%d) failed: %d, %s", (int)clock_id, e, error_decode(error_from_errno(EC_SYSCALL, e)));
	}
	if (unlikely(us >= 1000000)) {
		ts.tv_sec += us / 1000000;
		us %= 1000000;
	}
	ts.tv_nsec += us * 1000;
	if (unlikely(ts.tv_nsec >= 1000000000)) {
		ts.tv_nsec -= 1000000000;
		ts.tv_sec++;
	}

	return ts;
}

#endif

#define do_cond_wait_us(c, us)						\
do {									\
	int r;								\
	struct timespec ts;						\
									\
	ts = cond_getts(us);						\
again:									\
	r = pthread_cond_timedwait(&(c)->cond, &(c)->mutex, &ts);	\
	if (unlikely(r)) {						\
		if (likely(r == ETIMEDOUT)) return false;		\
		if (r == EINTR) goto again;				\
		internal(caller_file_line, "cond_wait_us: pthread_cond_timedwait failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
	}								\
	return true;							\
} while (0)


#define do_thread_spawn(t, function, arg, priority, err)		\
do {									\
	int r;								\
	r = pthread_create(t, &thread_attr, function, arg);		\
	if (unlikely(r)) {						\
		ajla_error_t e = error_from_errno(EC_SYSCALL, r);	\
		fatal_mayfail(e, err, "pthread_create failed at %s: %d, %s", position_string(position_arg), r, error_decode(e));\
		return false;						\
	}								\
} while (0)

#define do_thread_join(t)						\
do {									\
	int r;								\
	r = pthread_join(*t, NULL);					\
	if (unlikely(r))						\
		internal(caller_file_line, "thread_join: pthread_join failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)


#if !defined(HAVE___THREAD)

#define do_tls_init(tl)							\
do {									\
	int r;								\
	r = pthread_key_create(tl, NULL);				\
	if (unlikely(r))						\
		fatal("pthread_key_create failed at %s: %d, %s", position_string(position_arg), r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_tls_done(tl)							\
do {									\
	int r;								\
	r = pthread_key_delete(*(tl));					\
	if (unlikely(r))						\
		internal(caller_file_line, "tls_done: pthread_key_delete failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_tls_get(tl, ret)						\
do {									\
	*(ret) = ptr_to_num(pthread_getspecific(*(tl)));		\
} while (0)

#define do_tls_set(tl, val)						\
do {									\
	int r;								\
	r = pthread_setspecific(*(tl), (void *)(val));			\
	if (unlikely(r))						\
		internal(caller_file_line, "tls_set: pthread_setspecific failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#endif

#include "th_com.inc"


#ifndef barrier_write_before_lock

#if defined(HAVE_PTHREAD_SPIN_INIT) && !defined(UNUSUAL_ARITHMETICS)

void barrier_write_before_lock(void)
{
	pthread_spinlock_t lock;
	int r;
#ifdef barrier_write_before_unlock_lock
	barrier_write_before_unlock_lock();
#endif
	r = pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
	if (unlikely(r))
		fatal("pthread_spin_init failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_spin_lock(&lock);
	if (unlikely(r))
		internal(file_line, "pthread_spin_lock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_spin_unlock(&lock);
	if (unlikely(r))
		internal(file_line, "pthread_spin_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_spin_destroy(&lock);
	if (unlikely(r))
		internal(file_line, "pthread_spin_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
}

#else

#define barrier_lock_need_tls
struct barrier_lock {
	mutex_t mutex;
	tls_destructor_t destructor;
};
static tls_decl(struct barrier_lock *, barrier_lock);

static void barrier_lock_destructor(tls_destructor_t *destr)
{
	struct barrier_lock *lock = get_struct(destr, struct barrier_lock, destructor);
	mutex_done(&lock->mutex);
	mem_free(lock);
}

void barrier_write_before_lock(void)
{
	struct barrier_lock *lock = tls_get(struct barrier_lock *, barrier_lock);
	if (unlikely(!lock)) {
		lock = mem_alloc(struct barrier_lock *, sizeof(struct barrier_lock));
		mutex_init(&lock->mutex);
		tls_set(struct barrier_lock *, barrier_lock, lock);
		tls_destructor(&lock->destructor, barrier_lock_destructor);
	}
#ifdef barrier_write_before_unlock_lock
	barrier_write_before_unlock_lock();
#endif
	mutex_lock(&lock->mutex);
	mutex_unlock(&lock->mutex);
}

#endif

#endif


#include "th_sig.inc"


#ifdef USE_PTHREAD_CONDATTR
static bool pthread_condattr_try_clock(clockid_t c, bool mayfail)
{
	int r = pthread_condattr_setclock(cond_attr_p, c);
	if (r) {
		if (unlikely(!mayfail))
			fatal("pthread_condattr_setclock(%d) failed: %d, %s", (int)c, r, error_decode(error_from_errno(EC_SYSCALL, r)));
		return false;
	} else {
		pthread_cond_t cond;
		r = pthread_cond_init(&cond, cond_attr_p);
		if (unlikely(r)) {
			(!mayfail ? fatal : warning)("pthread_cond_init (clock %d) failed: %d, %s", (int)c, r, error_decode(error_from_errno(EC_SYSCALL, r)));
			return false;
		}
		r = pthread_cond_destroy(&cond);
		if (unlikely(r))
			internal(file_line, "pthread_condattr_try_clock: pthread_cond_destroy (clock %d) failed: %d, %s", (int)c, r, error_decode(error_from_errno(EC_SYSCALL, r)));
		clock_id = c;
		return true;
	}
}
#endif

void thread_init(void)
{
	int r;
	size_t stack;

#if defined(__linux__)
	ajla_error_t sink;
	char *str;
	size_t len;
	if (likely(os_read_file("/sys/devices/system/cpu/possible", &str, &len, &sink))) {
		array_add(char, &str, &len, 0);
		if (!strcmp(str, "0\n"))
			thread_needs_barriers = false;
		mem_free(str);
	}
#endif

	r = pthread_mutexattr_init(&mutex_attr);
	if (unlikely(r))
		fatal("pthread_mutexattr_init failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
#ifdef DEBUG_OBJECT_POSSIBLE
	if (mutex_debug) {
#if defined(HAVE_PTHREAD_MUTEX_ERRORCHECK)
		r = pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_ERRORCHECK);
#elif defined(HAVE_PTHREAD_MUTEX_ERRORCHECK_NP)
		r = pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_ERRORCHECK_NP);
#else
		r = 0;
#endif
		if (unlikely(r))
			fatal("pthread_mutexattr_settype failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	}
#endif

	r = pthread_rwlockattr_init(&rwmutex_attr);
	if (unlikely(r))
		fatal("pthread_rwlockattr_init failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));

#ifdef USE_PTHREAD_CONDATTR
	r = pthread_condattr_init(&cond_attr);
	if (unlikely(r))
		fatal("pthread_condattr_init failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
#ifdef HAVE_CLOCK_MONOTONIC_RAW
	if (likely(!pthread_condattr_try_clock(CLOCK_MONOTONIC_RAW, true)))
#endif
	{
		if (unlikely(!pthread_condattr_try_clock(CLOCK_MONOTONIC, true))) {
			pthread_condattr_try_clock(CLOCK_REALTIME, false);
		}
	}
#endif

	r = pthread_attr_init(&thread_attr);
	if (unlikely(r))
		fatal("pthread_attr_init failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));

	r = pthread_attr_getstacksize(&thread_attr, &stack);
	if (unlikely(r))
		fatal("pthread_attr_getstacksize failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	if (stack < MINIMUM_STACK_SIZE) {
		r = pthread_attr_setstacksize(&thread_attr, MINIMUM_STACK_SIZE);
		if (unlikely(r))
			fatal("pthread_attr_setstacksize failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	}

	thread_signal_init();
	thread_common_init();
#ifdef barrier_lock_need_tls
	tls_init(struct barrier_lock *, barrier_lock);
#endif
}

void thread_done(void)
{
	int r;
	thread_common_done();
	thread_signal_done();
#ifdef barrier_lock_need_tls
	tls_done(struct barrier_lock *, barrier_lock);
#endif
	r = pthread_attr_destroy(&thread_attr);
	if (unlikely(r))
		fatal("pthread_attr_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_mutexattr_destroy(&mutex_attr);
	if (unlikely(r))
		fatal("pthread_mutexattr_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_rwlockattr_destroy(&rwmutex_attr);
	if (unlikely(r))
		fatal("pthread_rwlockattr_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
#ifdef USE_PTHREAD_CONDATTR
	r = pthread_condattr_destroy(&cond_attr);
	if (unlikely(r))
		fatal("pthread_condattr_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
#endif
}

#endif
