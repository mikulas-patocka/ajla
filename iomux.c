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

#include "list.h"
#include "mem_al.h"
#include "thread.h"
#include "addrlock.h"
#include "rwlock.h"
#include "str.h"
#include "os.h"
#include "timer.h"

#include "iomux.h"

#ifdef IOMUX_SELECT

#include <unistd.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

struct iomux_wait {
	struct list wait_list[2];
};

static void iomux_wait_init(struct iomux_wait *iow, handle_t attr_unused handle)
{
	list_init(&iow->wait_list[0]);
	list_init(&iow->wait_list[1]);
}

#include "iomux.inc"

void iomux_register_wait(handle_t handle, bool wr, mutex_t **mutex_to_lock, struct list *list_entry)
{
	struct iomux_wait *iow = iomux_get_iowait(handle);
	address_lock(iow, DEPTH_THUNK);
	*mutex_to_lock = address_get_mutex(iow, DEPTH_THUNK);
	list_add(&iow->wait_list[(int)wr], list_entry);
	address_unlock(iow, DEPTH_THUNK);
#ifndef THREAD_NONE
	os_notify();
#endif
}


#define handle_to_fd_set_size(h)	(((size_t)(h) + FD_SETSIZE) / FD_SETSIZE * sizeof(fd_set))

bool iomux_test_handle(handle_t h, bool wr)
{
	size_t size;
	fd_set *fds;
	struct timeval tv;
	int r;

	size = handle_to_fd_set_size(h);
	fds = mem_calloc(fd_set *, size);

	FD_SET(h, fds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
again:
	EINTR_LOOP(r, select(h + 1, !wr ? fds : NULL, !wr ? NULL : fds, NULL, &tv));
	if (unlikely(r == -1) && errno == EAGAIN)
		goto again;

	mem_free(fds);

	return r > 0;
}


static fd_set *read_fd_set;
static fd_set *write_fd_set;
static size_t fd_set_size;

static void attr_cold fd_set_realloc(size_t new_size)
{
	fd_set *f;

	f = mem_realloc(fd_set *, read_fd_set, new_size);
	memset((char *)f + fd_set_size, 0, new_size - fd_set_size);
	read_fd_set = f;

	f = mem_realloc(fd_set *, write_fd_set, new_size);
	memset((char *)f + fd_set_size, 0, new_size - fd_set_size);
	write_fd_set = f;
}

void iomux_check_all(uint32_t us)
{
	size_t need_fd_set_size;
	handle_t h, max_handle;
	struct timeval tv;
	int n;

	rwlock_lock_read(&iomux_rwlock);

	h = (handle_t)iowait_directory_size;
#ifdef OS_HAVE_NOTIFY_PIPE
	if (os_notify_pipe[0] > h)
		h = (size_t)os_notify_pipe[0];
#endif

	need_fd_set_size = handle_to_fd_set_size(h);
	if (unlikely(need_fd_set_size > fd_set_size))
		fd_set_realloc(need_fd_set_size);

	max_handle = 0;
	for (h = 0; (size_t)h < iowait_directory_size; h++) {
		struct iomux_wait *iow = iowait_directory[h];
		if (iow) {
			address_lock(iow, DEPTH_THUNK);
			if (!list_is_empty(&iow->wait_list[0])) {
				FD_SET(h, read_fd_set);
				max_handle = h + 1;
			}
			if (!list_is_empty(&iow->wait_list[1])) {
				FD_SET(h, write_fd_set);
				max_handle = h + 1;
			}
			address_unlock(iow, DEPTH_THUNK);
		}
	}

	rwlock_unlock_read(&iomux_rwlock);

#ifdef OS_HAVE_NOTIFY_PIPE
	FD_SET(os_notify_pipe[0], read_fd_set);
	if (os_notify_pipe[0] >= max_handle)
		max_handle = os_notify_pipe[0] + 1;
#endif

	us = iomux_get_time(us);

#if defined(OS_DOS)
	if (dos_poll_devices()) {
		n = 0;
	} else if (!max_handle) {
		if (us)
			dos_yield();
		n = 0;
	} else {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		n = select(max_handle, read_fd_set, write_fd_set, NULL, &tv);
		if (!n && us)
			dos_yield();
	}
#else
	if (us != IOMUX_INDEFINITE_WAIT) {
		tv.tv_sec = us / 1000000;
		tv.tv_usec = us % 1000000;
	}
	n = select(max_handle, read_fd_set, write_fd_set, NULL, us != IOMUX_INDEFINITE_WAIT ? &tv : NULL);
#endif

	if (unlikely(n == -1)) {
		int er = errno;
		if (unlikely(er != EINTR) && unlikely(er != EAGAIN) && unlikely(er != EBADF))
			fatal("select failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		if (unlikely(er == EBADF))
			n = signed_maximum(int);
		/* with n == -1, we are going to scan the whole array */
	}

#ifdef OS_HAVE_NOTIFY_PIPE
	if (FD_ISSET(os_notify_pipe[0], read_fd_set)) {
#ifdef THREAD_NONE
		os_drain_notify_pipe();
#endif
		FD_CLR(os_notify_pipe[0], read_fd_set);
		n--;
	}
#endif

	/*
	 * EMX has broken select. It should return the total number of bits set,
	 * but instead it returns the number of handles for which some activity
	 * is reported. Sometimes it returns unusually high values.
	 */

	rwlock_lock_read(&iomux_rwlock);

	for (h = 0; n && (size_t)h < iowait_directory_size; h++) {
		if (FD_ISSET(h, read_fd_set)) {
			if (n >= 0) {
				struct iomux_wait *iow = iowait_directory[h];
				address_lock(iow, DEPTH_THUNK);
				call(wake_up_wait_list)(&iow->wait_list[0], address_get_mutex(iow, DEPTH_THUNK), true);
			}
			FD_CLR(h, read_fd_set);
#ifndef __EMX__
			n--;
#endif
		}
		if (FD_ISSET(h, write_fd_set)) {
			if (n >= 0) {
				struct iomux_wait *iow = iowait_directory[h];
				address_lock(iow, DEPTH_THUNK);
				call(wake_up_wait_list)(&iow->wait_list[1], address_get_mutex(iow, DEPTH_THUNK), true);
			}
			FD_CLR(h, write_fd_set);
#ifndef __EMX__
			n--;
#endif
		}
	}

	rwlock_unlock_read(&iomux_rwlock);
}


void iomux_init(void)
{
	rwlock_init(&iomux_rwlock);
	array_init(struct iomux_wait *, &iowait_directory, &iowait_directory_size);
	read_fd_set = mem_alloc(fd_set *, 0);
	write_fd_set = mem_alloc(fd_set *, 0);
	fd_set_size = 0;
#ifndef THREAD_NONE
	thread_spawn(&iomux_thread, iomux_poll_thread, NULL, PRIORITY_IO, NULL);
#endif
}

void iomux_done(void)
{
	size_t h;
	os_shutdown_notify_pipe();
#ifndef THREAD_NONE
	thread_join(&iomux_thread);
#endif
	mem_free(read_fd_set);
	mem_free(write_fd_set);
	for (h = 0; h < iowait_directory_size; h++)
		if (iowait_directory[h])
			mem_free(iowait_directory[h]);
	mem_free(iowait_directory);
	rwlock_done(&iomux_rwlock);
}

#endif
