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

#ifndef AJLA_IOMUX_H
#define AJLA_IOMUX_H

#include "os.h"

#define POLL_US		10000
#define POLL_WINCH_US	3000000

#if defined(OS_OS2) || defined(OS_WIN32)
#elif defined(HAVE_KQUEUE) && defined(HAVE_SYS_EVENT_H) && !defined(NO_DIR_HANDLES)

#define IOMUX_KQUEUE

#elif defined(HAVE_EPOLL_CREATE) && defined(HAVE_SYS_EPOLL_H)

#define IOMUX_EPOLL
#if defined(HAVE_INOTIFY_INIT) && defined(HAVE_SYS_INOTIFY_H)
#define IOMUX_EPOLL_INOTIFY
#endif

#else

#define IOMUX_SELECT

#endif

struct iomux_wait;

void iomux_enable_poll(void);
void iomux_never(mutex_t **mutex_to_lock, struct list *list_entry);
void iomux_register_wait(handle_t handle, bool wr, mutex_t **address_to_lock, struct list *list_entry);

typedef void *notify_handle_t;
#if defined(IOMUX_EPOLL_INOTIFY) || defined(IOMUX_KQUEUE) || defined(OS_WIN32)
bool iomux_directory_handle_alloc(dir_handle_t handle, notify_handle_t *h, uint64_t *seq, ajla_error_t *err);
bool iomux_directory_handle_wait(notify_handle_t h, uint64_t seq, mutex_t **mutex_to_lock, struct list *list_entry);
void iomux_directory_handle_free(notify_handle_t h);
#else
static inline bool iomux_directory_handle_alloc(dir_handle_t attr_unused handle, notify_handle_t attr_unused *h, uint64_t attr_unused *seq, ajla_error_t attr_unused *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "directory monitoring not supported");
	return false;
}
static inline bool iomux_directory_handle_wait(notify_handle_t attr_unused h, uint64_t attr_unused seq, mutex_t attr_unused **mutex_to_lock, struct list attr_unused *list_entry)
{
	internal(file_line, "iomux_directory_handle_wait: the system doesn't support directory monitoring");
}
static inline void iomux_directory_handle_free(notify_handle_t attr_unused h)
{
	internal(file_line, "iomux_directory_handle_free: the system doesn't support directory monitoring");
}
#endif

bool iomux_test_handle(handle_t h, bool wr);

void iomux_check_all(uint32_t us);
#define IOMUX_INDEFINITE_WAIT	((uint32_t)-1)

#ifndef wake_up_wait_list
void u_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory);
void c_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory);
#endif

void iomux_init(void);
void iomux_done(void);

#endif
