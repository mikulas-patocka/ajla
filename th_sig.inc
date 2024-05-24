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

#if defined(__CYGWIN__) || (defined(__linux__) && (defined(__alpha__) || defined(__hppa)))

/*
 * In Cygwin, signals must not be delivered to threads doing Win32 waiting
 * functions. We have to spawn an extra thread specifically for signals.
 * This piece of code improves signal reliability, but doesn't fix the problem
 * completely, so we must not use native Win32 threads with cygwin.
 *
 * Alpha Linux has a bug that it may crash if a thread is spawned and a signal
 * is received at the same time.
 *
 * PA-RISC Linux crashes in libgmp if a signal is received.
 */

#include <signal.h>

static uchar_efficient_t signal_thread_end;
static uchar_efficient_t signal_thread_enabled;
static sigset_t signal_saved_sigset;
static pthread_t signal_thread;
static pthread_cond_t signal_cond;
static pthread_mutex_t signal_mutex;

static void *signal_thread_function(void attr_unused *ptr)
{
	int r;
	os_unblock_signals(&signal_saved_sigset);
	r = pthread_mutex_lock(&signal_mutex);
	if (unlikely(r))
		internal(file_line, "pthread_mutex_lock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	while (!signal_thread_end) {
		r = pthread_cond_wait(&signal_cond, &signal_mutex);
		if (unlikely(r) && unlikely(r != EINTR))
			internal(file_line, "pthread_cond_wait failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	}
	r = pthread_mutex_unlock(&signal_mutex);
	if (unlikely(r))
		internal(file_line, "pthread_mutex_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	os_block_signals(NULL);
	return NULL;
}

static void thread_signal_init(void)
{
	int r;
	signal_thread_end = false;

#if defined(__linux__) && defined(__alpha__)
	if (os_kernel_version("Linux", "5") ||
	    os_kernel_version("Linux", "4.16") ||
	    os_kernel_version("Linux", "4.15.4") ||
	    os_kernel_version("Linux", "4.14.20") ||
	    os_kernel_version("Linux", "4.9.82") ||
	    os_kernel_version("Linux", "4.4.116") ||
	    os_kernel_version("Linux", "4.1.50") ||
	    os_kernel_version("Linux", "3.18.95"))
		return;
#endif
#if defined(__linux__) && defined(__hppa)
	if (os_kernel_version("Linux", "6") ||
	    os_kernel_version("Linux", "5.15") ||
	    os_kernel_version("Linux", "5.14.6") ||
	    os_kernel_version("Linux", "5.13.19") ||
	    os_kernel_version("Linux", "5.10.67") ||
	    os_kernel_version("Linux", "5.4.148") ||
	    os_kernel_version("Linux", "4.19.207") ||
	    os_kernel_version("Linux", "4.14.247") ||
	    os_kernel_version("Linux", "4.9.283") ||
	    os_kernel_version("Linux", "4.4.284"))
		return;
#endif

	r = pthread_mutex_init(&signal_mutex, NULL);
	if (unlikely(r))
		fatal("pthread_mutex_init failed at %s: %d, %s", file_line, r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_cond_init(&signal_cond, NULL);
	if (unlikely(r))
		fatal("pthread_cond_init failed at %s: %d, %s", file_line, r, error_decode(error_from_errno(EC_SYSCALL, r)));
	os_block_signals(&signal_saved_sigset);
	r = pthread_create(&signal_thread, NULL, signal_thread_function, NULL);
	if (unlikely(r))
		fatal("pthread_create failed at %s: %d, %s", file_line, r, error_decode(error_from_errno(EC_SYSCALL, r)));
	signal_thread_enabled = true;
}

static void thread_signal_done(void)
{
	int r;

	if (!signal_thread_enabled)
		return;

	r = pthread_mutex_lock(&signal_mutex);
	if (unlikely(r))
		internal(file_line, "pthread_mutex_lock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	signal_thread_end = true;
	r = pthread_mutex_unlock(&signal_mutex);
	if (unlikely(r))
		internal(file_line, "pthread_mutex_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_cond_signal(&signal_cond);
	if (unlikely(r))
		internal(file_line, "pthread_cond_signal failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_join(signal_thread, NULL);
	if (unlikely(r))
		internal(file_line, "pthread_join failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));
	os_unblock_signals(&signal_saved_sigset);
	r = pthread_mutex_destroy(&signal_mutex);
	if (unlikely(r))
		fatal("pthread_mutex_destroy failed at %s: %d, %s", file_line, r, error_decode(error_from_errno(EC_SYSCALL, r)));
	r = pthread_cond_destroy(&signal_cond);
	if (unlikely(r))
		fatal("pthread_cond_destroy failed at %s: %d, %s", file_line, r, error_decode(error_from_errno(EC_SYSCALL, r)));
}

#else

#define thread_signal_init()	do { } while (0)
#define thread_signal_done()	do { } while (0)

#endif
