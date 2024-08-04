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
#include "obj_reg.h"

#include "iomux.h"

#ifdef IOMUX_KQUEUE

#include <unistd.h>
#include <sys/poll.h>
#include <sys/event.h>

#define KQUEUE_MAX_EVENTS		64

struct iomux_wait {
	struct list wait_list[3];
	uint64_t seq;
	handle_t self;
};

static handle_t kq_fd;

static void iomux_wait_init(struct iomux_wait *iow, handle_t handle)
{
	list_init(&iow->wait_list[0]);
	list_init(&iow->wait_list[1]);
	list_init(&iow->wait_list[2]);
	iow->seq = 0;
	iow->self = handle;
}

#include "iomux.inc"

void iomux_register_wait(handle_t handle, bool wr, mutex_t **mutex_to_lock, struct list *list_entry)
{
	int r;
	struct iomux_wait *iow = iomux_get_iowait(handle);
	struct kevent event;

	EV_SET(&event, handle, !wr ? EVFILT_READ : EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, 0);

	address_lock(iow, DEPTH_THUNK);

	EINTR_LOOP(r, kevent(kq_fd, &event, 1, NULL, 0, NULL));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("kevent failed adding a new handle: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}

	*mutex_to_lock = address_get_mutex(iow, DEPTH_THUNK);
	list_add(&iow->wait_list[(int)wr], list_entry);

	address_unlock(iow, DEPTH_THUNK);

#if !defined(THREAD_NONE) && defined(__APPLE__)
	os_notify();
#endif
}


bool iomux_test_handle(handle_t handle, bool wr)
{
	struct pollfd p;
	int r;
	p.fd = handle;
	p.events = !wr ? POLLIN : POLLOUT;
again:
	EINTR_LOOP(r, poll(&p, 1, 0));
	if (unlikely(r == -1)) {
		int er = errno;
		if (er == EAGAIN)
			goto again;
		fatal("poll failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	return !!r;
}


bool iomux_directory_handle_alloc(dir_handle_t attr_unused handle, notify_handle_t attr_unused *h, uint64_t attr_unused *seq, ajla_error_t *err)
{
#ifndef NO_DIR_HANDLES
	int r;
	int newfd;
	struct iomux_wait *iow;
	struct kevent event;

	EINTR_LOOP(newfd, dup(handle));
	if (unlikely(newfd == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "dup failed: %s", error_decode(e));
		return false;
	}
	iow = iomux_get_iowait(newfd);

	EV_SET(&event, newfd, EVFILT_VNODE, EV_ADD | EV_ONESHOT, NOTE_WRITE, 0, 0);

	address_lock(iow, DEPTH_THUNK);

	EINTR_LOOP(r, kevent(kq_fd, &event, 1, NULL, 0, NULL));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		address_unlock(iow, DEPTH_THUNK);
		os_close_handle(newfd);
		fatal_mayfail(e, err, "adding a directory watch failed: %s", error_decode(e));
		return false;
	}

	*h = iow;
	*seq = iow->seq;

	address_unlock(iow, DEPTH_THUNK);
#if !defined(THREAD_NONE) && defined(__APPLE__)
	os_notify();
#endif
	return true;
#else
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "directory monitoring not supported");
	return false;
#endif
}

bool iomux_directory_handle_wait(notify_handle_t h, uint64_t seq, mutex_t **mutex_to_lock, struct list *list_entry)
{
	struct iomux_wait *iow = h;

	address_lock(iow, DEPTH_THUNK);
	if (iow->seq != seq) {
		address_unlock(iow, DEPTH_THUNK);
		return true;
	}

	*mutex_to_lock = address_get_mutex(iow, DEPTH_THUNK);
	list_add(&iow->wait_list[2], list_entry);
	address_unlock(iow, DEPTH_THUNK);

	return false;
}

void iomux_directory_handle_free(notify_handle_t h)
{
	struct iomux_wait *iow = h;
	os_close_handle(iow->self);
}


void iomux_check_all(uint32_t us)
{
	struct kevent events[KQUEUE_MAX_EVENTS];
	int n_ev, i;
	struct timespec ts;

	us = iomux_get_time(us);

	if (us != IOMUX_INDEFINITE_WAIT) {
		ts.tv_sec = us / 1000000;
		ts.tv_nsec = us % 1000000 * 1000;
	}

	n_ev = kevent(kq_fd, NULL, 0, events, KQUEUE_MAX_EVENTS, us != IOMUX_INDEFINITE_WAIT ? &ts : NULL);
	if (unlikely(n_ev == -1)) {
		int er;
		if (likely(errno == EINTR))
			goto no_events;
		er = errno;
		fatal("kevent failed getting events: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}

	rwlock_lock_read(&iomux_rwlock);
	for (i = 0; i < n_ev; i++) {
		struct kevent *ev = &events[i];
		handle_t handle = ev->ident;
		struct iomux_wait *iow;
		if (handle == os_notify_pipe[0]) {
#ifdef THREAD_NONE
			os_drain_notify_pipe();
#endif
			continue;
		}
		iow = iowait_directory[handle];
		/*debug("handle: %d, iow: %p", handle, iow);*/

		address_lock(iow, DEPTH_THUNK);
		if (ev->filter == EVFILT_READ) {
			call(wake_up_wait_list)(&iow->wait_list[0], address_get_mutex(iow, DEPTH_THUNK), true);
		} else if (ev->filter == EVFILT_WRITE) {
			call(wake_up_wait_list)(&iow->wait_list[1], address_get_mutex(iow, DEPTH_THUNK), true);
		} else if (ev->filter == EVFILT_VNODE) {
			iow->seq++;
			call(wake_up_wait_list)(&iow->wait_list[2], address_get_mutex(iow, DEPTH_THUNK), true);
		} else {
			fatal("kevent returned unknown event %d", ev->filter);
		}
	}
	rwlock_unlock_read(&iomux_rwlock);

no_events:;
}


void iomux_init(void)
{
	struct kevent pipe_ev;
	int r;
	rwlock_init(&iomux_rwlock);
	array_init(struct iomux_wait *, &iowait_directory, &iowait_directory_size);

	EINTR_LOOP(kq_fd, kqueue());
	if (unlikely(kq_fd == -1)) {
		int er = errno;
		fatal("kqueue failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	os_set_cloexec(kq_fd);
	obj_registry_insert(OBJ_TYPE_HANDLE, kq_fd, file_line);

	EV_SET(&pipe_ev, os_notify_pipe[0], EVFILT_READ, EV_ADD, 0, 0, 0);
	EINTR_LOOP(r, kevent(kq_fd, &pipe_ev, 1, NULL, 0, NULL));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("kevent failed adding notify pipe: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
#ifndef THREAD_NONE
	thread_spawn(&iomux_thread, iomux_poll_thread, NULL, PRIORITY_IO, NULL);
#endif
}

void iomux_done(void)
{
	struct kevent pipe_ev;
	int r;
	size_t h;
	os_shutdown_notify_pipe();
#ifndef THREAD_NONE
	thread_join(&iomux_thread);
#endif
	EV_SET(&pipe_ev, os_notify_pipe[0], EVFILT_READ, EV_DELETE, 0, 0, 0);
	EINTR_LOOP(r, kevent(kq_fd, &pipe_ev, 1, NULL, 0, NULL));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("kevent failed removing notify pipe: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	os_close(kq_fd);

	for (h = 0; h < iowait_directory_size; h++)
		if (iowait_directory[h])
			mem_free(iowait_directory[h]);
	mem_free(iowait_directory);
	rwlock_done(&iomux_rwlock);
}

#endif
