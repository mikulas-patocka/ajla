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

#ifdef IOMUX_EPOLL

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#ifdef IOMUX_EPOLL_INOTIFY
#include <sys/inotify.h>
#endif
#include <limits.h>

#ifndef NAME_MAX
#define NAME_MAX			255
#endif

#define EPOLL_MAX_EVENTS		64

struct iomux_wait {
	struct list wait_list;
	struct epoll_event event;
};
static handle_t ep_fd;

#ifdef IOMUX_EPOLL_INOTIFY
static handle_t inotify_fd;
struct tree inotify_wds;
static mutex_t inotify_wds_mutex;
struct inotify_wd {
	struct tree_entry entry;
	struct list wait_list;
	int wd;
	uintptr_t refcount;
	uint64_t seq;
};
#endif

static void iomux_wait_init(struct iomux_wait *iow, handle_t handle)
{
	list_init(&iow->wait_list);
	iow->event.events = 0;
	iow->event.data.fd = handle;
}

#include "iomux.inc"

void iomux_register_wait(handle_t handle, bool wr, mutex_t **mutex_to_lock, struct list *list_entry)
{
	int r;
	struct iomux_wait *iow = iomux_get_iowait(handle);
	uint32_t event = !wr ? EPOLLIN : EPOLLOUT;

	address_lock(iow, DEPTH_THUNK);

#ifdef EPOLLONESHOT
	event |= EPOLLONESHOT;
#endif
	iow->event.events |= event;
	EINTR_LOOP(r, epoll_ctl(ep_fd, EPOLL_CTL_ADD, handle, &iow->event));
	if (unlikely(r == -1)) {
		int er = errno;
		if (unlikely(er != EEXIST))
			fatal("epoll_ctl(EPOLL_CTL_ADD) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		EINTR_LOOP(r, epoll_ctl(ep_fd, EPOLL_CTL_MOD, handle, &iow->event));
		if (unlikely(r == -1)) {
			int er = errno;
			fatal("epoll_ctl(EPOLL_CTL_MOD) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	}

	*mutex_to_lock = address_get_mutex(iow, DEPTH_THUNK);
	list_add(&iow->wait_list, list_entry);

	address_unlock(iow, DEPTH_THUNK);
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


#ifdef IOMUX_EPOLL_INOTIFY

static int inotify_wd_compare(const struct tree_entry *e, uintptr_t v)
{
	struct inotify_wd *wd = get_struct(e, struct inotify_wd, entry);
	return wd->wd - (int)v;
}

static void process_inotify(void)
{
	union {
		struct inotify_event ev;
		char alloc[sizeof(struct inotify_event) + NAME_MAX + 1];
	} buffer;
	int offset;
	int r;
	EINTR_LOOP(r, read(inotify_fd, &buffer, sizeof buffer));
	if (unlikely(r == -1)) {
		int er = errno;
		if (er == EAGAIN)
			return;
		fatal("inotify: read failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	offset = 0;
	while (offset < r) {
		struct inotify_event *ptr;
		struct tree_entry *e;

		if (unlikely(offset + (int)sizeof(struct inotify_event) > r)) {
			fatal("inotify: read returned partial buffer");
		}
		ptr = cast_ptr(struct inotify_event *, &buffer.alloc[offset]);
		if (unlikely(offset + (int)sizeof(struct inotify_event) + (int)ptr->len > r)) {
			fatal("inotify: file name overruns the buffer");
		}
		/*debug("read id: %d, %08x", ptr->wd, ptr->mask);*/

		mutex_lock(&inotify_wds_mutex);
		e = tree_find(&inotify_wds, inotify_wd_compare, ptr->wd);
		if (unlikely(!e)) {
			/*debug("not found");*/
			mutex_unlock(&inotify_wds_mutex);
		} else {
			struct inotify_wd *wd = get_struct(e, struct inotify_wd, entry);
			/*debug("found seq %llx", (unsigned long long)wd->seq);*/
			wd->seq++;
			call(wake_up_wait_list)(&wd->wait_list, &inotify_wds_mutex, true);
		}

		offset += sizeof(struct inotify_event) + ptr->len;
	}
}

bool iomux_directory_handle_alloc(dir_handle_t handle, notify_handle_t *h, uint64_t *seq, ajla_error_t *err)
{
	int w;
	struct inotify_wd *wd;
	struct tree_entry *e;
	struct tree_insert_position ins;

#ifdef NO_DIR_HANDLES
	char *pathname = handle;
#else
	char pathname[14 + 10 + 1];
	sprintf(pathname, "/proc/self/fd/%d", handle);
#endif

	if (unlikely(inotify_fd == -1)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "directory monitoring not supported");
		return false;
	}

	mutex_lock(&inotify_wds_mutex);
	/* IN_MODIFY causes an infinite loop in the /dev directory */
	EINTR_LOOP(w, inotify_add_watch(inotify_fd, pathname, IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO));
	/*debug("add watch: %d", w);*/
	if (unlikely(w == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		mutex_unlock(&inotify_wds_mutex);
		fatal_mayfail(e, err, "inotify_add_watch failed: %s", error_decode(e));
		return false;
	}

	e = tree_find_for_insert(&inotify_wds, inotify_wd_compare, w, &ins);
	if (!e) {
		wd = mem_alloc_mayfail(struct inotify_wd *, sizeof(struct inotify_wd), err);
		if (unlikely(!wd)) {
			int r;
			EINTR_LOOP(r, inotify_rm_watch(inotify_fd, w));
			/*debug("rm watch oom: %d", w);*/
			if (unlikely(r == -1) && errno != EINVAL) {
				int er = errno;
				fatal("inotify_rm_watch failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
			}
			mutex_unlock(&inotify_wds_mutex);
			return false;
		}
		list_init(&wd->wait_list);
		wd->wd = w;
		wd->refcount = 1;
		wd->seq = 0;
		tree_insert_after_find(&wd->entry, &ins);
	} else {
		wd = get_struct(e, struct inotify_wd, entry);
		wd->refcount++;
	}

	*h = wd;
	*seq = wd->seq;

	mutex_unlock(&inotify_wds_mutex);
	return true;
}

bool iomux_directory_handle_wait(notify_handle_t w, uint64_t seq, mutex_t **mutex_to_lock, struct list *list_entry)
{
	struct inotify_wd *wd = w;

	mutex_lock(&inotify_wds_mutex);
	if (wd->seq != seq) {
		mutex_unlock(&inotify_wds_mutex);
		return true;
	}
	*mutex_to_lock = &inotify_wds_mutex;
	list_add(&wd->wait_list, list_entry);
	mutex_unlock(&inotify_wds_mutex);
	return false;
}

void iomux_directory_handle_free(notify_handle_t w)
{
	struct inotify_wd *wd = w;

	mutex_lock(&inotify_wds_mutex);
	if (!--wd->refcount) {
		int r;
		EINTR_LOOP(r, inotify_rm_watch(inotify_fd, wd->wd));
		/*debug("rm watch: %d", wd->wd);*/
		if (unlikely(r == -1) && errno != EINVAL) {
			int er = errno;
			fatal("inotify_rm_watch failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
		tree_delete(&wd->entry);
		mem_free(wd);
	}
	mutex_unlock(&inotify_wds_mutex);
}

#endif


void iomux_check_all(uint32_t us)
{
	struct epoll_event events[EPOLL_MAX_EVENTS];
	int n_ev, i;
	int ms;

	us = iomux_get_time(us);
	/*debug("iomux_check_all: %u", us);
	us = minimum(us, 1000000);*/

	if (us != IOMUX_INDEFINITE_WAIT)
		ms = (us + 999) / 1000;
	else
		ms = -1;

	n_ev = epoll_wait(ep_fd, events, EPOLL_MAX_EVENTS, ms);
	if (n_ev == -1) {
		int er;
		if (likely(errno == EINTR))
			goto no_events;
		er = errno;
		fatal("epoll_wait failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}

	rwlock_lock_read(&iomux_rwlock);
	for (i = 0; i < n_ev; i++) {
#ifndef EPOLLONESHOT
		int r;
#endif
		handle_t handle = events[i].data.fd;
		struct iomux_wait *iow;
		if (handle == os_notify_pipe[0]) {
#ifdef THREAD_NONE
			os_drain_notify_pipe();
#endif
			continue;
		}

#ifdef IOMUX_EPOLL_INOTIFY
		if (handle == inotify_fd) {
			process_inotify();
			continue;
		}
#endif
		iow = iowait_directory[handle];

		address_lock(iow, DEPTH_THUNK);
#ifndef EPOLLONESHOT
		EINTR_LOOP(r, epoll_ctl(ep_fd, EPOLL_CTL_DEL, handle, &events[i]));
		if (unlikely(r == -1)) {
			int er = errno;
			fatal("epoll_ctl(EPOLL_CTL_DEL) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
#endif
		iow->event.events = 0;
		call(wake_up_wait_list)(&iow->wait_list, address_get_mutex(iow, DEPTH_THUNK), true);
	}
	rwlock_unlock_read(&iomux_rwlock);

no_events:;
}


void iomux_init(void)
{
	struct epoll_event pipe_ev;
	int r;
	rwlock_init(&iomux_rwlock);
	array_init(struct iomux_wait *, &iowait_directory, &iowait_directory_size);

	EINTR_LOOP(ep_fd, epoll_create(EPOLL_MAX_EVENTS));
	if (unlikely(ep_fd == -1)) {
		int er = errno;
		fatal("epoll_create failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	os_set_cloexec(ep_fd);
	obj_registry_insert(OBJ_TYPE_HANDLE, ep_fd, file_line);

#ifdef IOMUX_EPOLL_INOTIFY
	tree_init(&inotify_wds);
	mutex_init(&inotify_wds_mutex);
	EINTR_LOOP(inotify_fd, inotify_init());
	if (likely(inotify_fd != -1)) {
		os_set_cloexec(inotify_fd);
		obj_registry_insert(OBJ_TYPE_HANDLE, inotify_fd, file_line);
		EINTR_LOOP(r, fcntl(inotify_fd, F_SETFL, O_NONBLOCK));
		if (unlikely(r == -1)) {
			int er = errno;
			fatal("fcntl(F_SETFL, O_NONBLOCK) on an inotify descriptor failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
		pipe_ev.events = EPOLLIN;
		pipe_ev.data.fd = inotify_fd;
		EINTR_LOOP(r, epoll_ctl(ep_fd, EPOLL_CTL_ADD, inotify_fd, &pipe_ev));
		if (unlikely(r == -1)) {
			int er = errno;
			fatal("epoll_ctl(EPOLL_CTL_ADD) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	}
#endif

	pipe_ev.events = EPOLLIN;
	pipe_ev.data.fd = os_notify_pipe[0];
	EINTR_LOOP(r, epoll_ctl(ep_fd, EPOLL_CTL_ADD, os_notify_pipe[0], &pipe_ev));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("epoll_ctl(EPOLL_CTL_ADD) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
#ifndef THREAD_NONE
	thread_spawn(&iomux_thread, iomux_poll_thread, NULL, PRIORITY_IO, NULL);
#endif
}

void iomux_done(void)
{
	struct epoll_event pipe_ev;
	int r;
	size_t h;
	os_shutdown_notify_pipe();
#ifndef THREAD_NONE
	thread_join(&iomux_thread);
#endif
	EINTR_LOOP(r, epoll_ctl(ep_fd, EPOLL_CTL_DEL, os_notify_pipe[0], &pipe_ev));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("epoll_ctl(EPOLL_CTL_DEL) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}

#ifdef IOMUX_EPOLL_INOTIFY
	if (likely(inotify_fd != -1)) {
		EINTR_LOOP(r, epoll_ctl(ep_fd, EPOLL_CTL_DEL, inotify_fd, &pipe_ev));
		if (unlikely(r == -1)) {
			int er = errno;
			fatal("epoll_ctl(EPOLL_CTL_DEL) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
		os_close(inotify_fd);
	}
	if (unlikely(!tree_is_empty(&inotify_wds)))
		internal(file_line, "iomux_done: inotify tree is not empty");
	mutex_done(&inotify_wds_mutex);
#endif

	os_close(ep_fd);

	for (h = 0; h < iowait_directory_size; h++)
		if (iowait_directory[h])
			mem_free(iowait_directory[h]);
	mem_free(iowait_directory);
	rwlock_done(&iomux_rwlock);
}

#endif
