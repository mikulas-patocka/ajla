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

#include "thread.h"

#include "tick.h"

#include <time.h>

uint32_t tick_us = DEFAULT_TICK_US;
uint32_t thread_tick = 0;
atomic_type tick_stamp_t *tick_stamp_ptr;

static attr_always_inline void increment_stamp(void)
{
	store_relaxed(tick_stamp_ptr, load_relaxed(tick_stamp_ptr) + 1);
}

#ifndef USEABLE_SIGNAL

#define use_signal	false

#else

#ifdef THREAD_NONE
#define use_signal	true
#else
#define use_signal	(!dll && !thread_tick)
#endif

/*
 * SIGVTALRM and SIGPROF is unuseable due to a bug:
 * it doesn't count if the main thread is idle, even though other threads are active
 */
#if 1
#define SIGNAL		SIGALRM
#define TIMER		ITIMER_REAL
#elif 0
#define SIGNAL		SIGVTALRM
#define TIMER		ITIMER_VIRTUAL
#else
#define SIGNAL		SIGPROF
#define TIMER		ITIMER_PROF
#endif

#include <sys/time.h>
#include <signal.h>

static void tick_signal_handler(int attr_unused sig)
{
#if 0
	struct timeval tv;
	gettimeofday(&tv, NULL);
	debug("tick: %lu.%06lu %u", tv.tv_sec, tv.tv_usec, load_relaxed(tick_stamp_ptr));
#endif
	increment_stamp();
}

static struct sigaction old_sigaction;

#endif

#ifndef THREAD_NONE

static thread_t tick_thread;
static cond_t tick_cond;
static uchar_efficient_t tick_end;
static uchar_efficient_t tick_suspended;

/*#include <sys/time.h>*/

thread_function_decl(tick_thread_function,
	thread_set_id(-2);
	cond_lock(&tick_cond);
	while (!tick_end) {
		/*struct timeval tv;
		gettimeofday(&tv, NULL);
		debug("tick: %lu.%06lu %u", tv.tv_sec, tv.tv_usec, tick_stamp);*/
		if (tick_suspended) {
			cond_wait(&tick_cond);
		} else {
			cond_wait_us(&tick_cond, tick_us);
			increment_stamp();
		}
	}
	cond_unlock(&tick_cond);
)

#endif

#ifdef USE_TIMER_CREATE
static timer_t timer_id;
static int using_timer_create;
#endif

void tick_suspend(void)
{
#ifdef USE_TIMER_CREATE
	if (use_signal && using_timer_create) {
		int ir;
		struct itimerspec its;
		memset(&its, 0, sizeof its);
		EINTR_LOOP(ir, timer_settime(timer_id, 0, &its, NULL));
		return;
	}
#endif
	if (use_signal) {
#ifdef THREAD_NONE
		int ir;
		struct itimerval itv;
		itv.it_interval.tv_sec = 0;
		itv.it_interval.tv_usec = 0;
		itv.it_value = itv.it_interval;
		EINTR_LOOP(ir, setitimer(TIMER, &itv, NULL));
		if (unlikely(ir == -1)) {
			int er = errno;
			fatal("setitimer failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
#endif
		return;
	}
#ifndef THREAD_NONE
	if (!use_signal) {
		cond_lock(&tick_cond);
		tick_suspended = true;
		cond_unlock(&tick_cond);
		return;
	}
#endif
}

void tick_resume(void)
{
#ifdef USE_TIMER_CREATE
	if (use_signal && using_timer_create) {
		int ir;
		struct itimerspec its;
		its.it_interval.tv_sec = tick_us / 1000000;
		its.it_interval.tv_nsec = tick_us % 1000000 * 1000;
		its.it_value = its.it_interval;
		EINTR_LOOP(ir, timer_settime(timer_id, 0, &its, NULL));
		return;
	}
#endif
	if (use_signal) {
#ifdef THREAD_NONE
		int ir;
		struct itimerval itv;
		itv.it_interval.tv_sec = tick_us / 1000000;
		itv.it_interval.tv_usec = tick_us % 1000000;
		itv.it_value = itv.it_interval;
		EINTR_LOOP(ir, setitimer(TIMER, &itv, NULL));
		if (unlikely(ir == -1)) {
			int er = errno;
			fatal("setitimer failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
#endif
		return;
	}
#ifndef THREAD_NONE
	if (!use_signal) {
		cond_lock(&tick_cond);
		tick_suspended = false;
		cond_unlock_signal(&tick_cond);
		return;
	}
#endif
}

void tick_init(void)
{
#ifdef USEABLE_SIGNAL
	if (use_signal) {
		int ir;
		struct sigaction sa;
		(void)memset(&sa, 0, sizeof sa);
		sa.sa_handler = tick_signal_handler;
		sigemptyset(&sa.sa_mask);
#ifdef SA_RESTART
		sa.sa_flags |= SA_RESTART;
#endif
		EINTR_LOOP(ir, sigaction(SIGNAL, &sa, &old_sigaction));
		if (unlikely(ir == -1)) {
			int er = errno;
			fatal("sigaction failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
#ifdef USE_TIMER_CREATE
		if (1) {
			struct sigevent sev;
			struct itimerspec its;
			memset(&sev, 0, sizeof sev);
			sev.sigev_notify = SIGEV_SIGNAL;
			sev.sigev_signo = SIGNAL;
#ifdef HAVE_CLOCK_MONOTONIC
			EINTR_LOOP(ir, timer_create(CLOCK_MONOTONIC, &sev, &timer_id));
#else
			EINTR_LOOP(ir, timer_create(CLOCK_REALTIME, &sev, &timer_id));
#endif
			if (ir == -1) {
#ifdef THREAD_NONE
				goto try_setitimer;
#else
				goto try_thread;
#endif
			}
			its.it_interval.tv_sec = tick_us / 1000000;
			its.it_interval.tv_nsec = tick_us % 1000000 * 1000;
			its.it_value = its.it_interval;
			EINTR_LOOP(ir, timer_settime(timer_id, 0, &its, NULL));
			if (ir == -1) {
				int er = errno;
				fatal("timer_settime failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
			}
			using_timer_create = 1;
		} else
#endif
		{
			struct itimerval itv;
			goto try_setitimer;
try_setitimer:
			itv.it_interval.tv_sec = tick_us / 1000000;
			itv.it_interval.tv_usec = tick_us % 1000000;
			itv.it_value = itv.it_interval;
			EINTR_LOOP(ir, setitimer(TIMER, &itv, NULL));
			if (unlikely(ir == -1)) {
				int er = errno;
				fatal("setitimer failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
			}
		}
	} else
#endif
	{
#ifdef THREAD_NONE
		not_reached();
#else
		goto try_thread;
try_thread:
		cond_init(&tick_cond);
		tick_end = false;
		tick_suspended = false;
		thread_spawn(&tick_thread, tick_thread_function, NULL, PRIORITY_TIMER, NULL);
#endif
	}
}

void tick_done(void)
{
	/*debug("ticks: %u", tick_stamp);*/
#ifdef USEABLE_SIGNAL
	if (use_signal) {
		int ir;
#ifdef USE_TIMER_CREATE
		if (using_timer_create) {
			EINTR_LOOP(ir, timer_delete(timer_id));
			if (ir == -1) {
				int er = errno;
				fatal("timer_delete failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
			}
		} else
#endif
		{
			struct itimerval itv;
			itv.it_interval.tv_sec = 0;
			itv.it_interval.tv_usec = 0;
			itv.it_value = itv.it_interval;
			EINTR_LOOP(ir, setitimer(TIMER, &itv, NULL));
			if (unlikely(ir == -1)) {
				int er = errno;
				fatal("setitimer failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
			}
		}
#ifndef THREAD_NONE
		/*
		 * If we have threads, the signal handler may be queued for another
		 * theread. So, we must set it to ignore to avoid damage.
		 */
		old_sigaction.sa_handler = SIG_IGN;
#endif
		EINTR_LOOP(ir, sigaction(SIGNAL, &old_sigaction, NULL));
		if (unlikely(ir == -1)) {
			int er = errno;
			fatal("sigaction failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	} else
#endif
	{
#ifdef THREAD_NONE
		not_reached();
#else
		cond_lock(&tick_cond);
		tick_end = true;
		cond_unlock_broadcast(&tick_cond);
		thread_join(&tick_thread);
		cond_done(&tick_cond);
#endif
	}
}
