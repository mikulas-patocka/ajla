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

rwlock_decl(iomux_rwlock);

static struct iomux_wait **iowait_directory;
static size_t iowait_directory_size;

static bool iomux_poll = false;

void iomux_enable_poll(void)
{
	bool was_poll = iomux_poll;
	if (unlikely(!was_poll)) {
		iomux_poll = true;
		os_notify();
	}
}

void iomux_never(mutex_t **mutex_to_lock, struct list *list_entry)
{
	*mutex_to_lock = address_get_mutex(NULL, DEPTH_THUNK);
	list_init(list_entry);
}

static struct iomux_wait *iomux_get_iowait(handle_t handle)
{
	struct iomux_wait *result;

	rwlock_lock_read(&iomux_rwlock);
	if (likely((size_t)handle < iowait_directory_size) && likely((result = iowait_directory[handle]) != NULL)) {
		rwlock_unlock_read(&iomux_rwlock);
		return result;
	}
	rwlock_unlock_read(&iomux_rwlock);

	rwlock_lock_write(&iomux_rwlock);
	while ((size_t)handle >= iowait_directory_size) {
		array_add(struct iomux_wait *, &iowait_directory, &iowait_directory_size, NULL);
	}

	if (!(result = iowait_directory[handle])) {
		result = iowait_directory[handle] = mem_alloc(struct iomux_wait *, sizeof(struct iomux_wait));
		iomux_wait_init(result, handle);
	}

	rwlock_unlock_write(&iomux_rwlock);
	return result;
}

static uint32_t iomux_get_time(uint32_t us)
{
	if (unlikely(iomux_poll))
		us = minimum(us, POLL_US);

#ifndef TIMER_THREAD
	{
		uint32_t tm = timer_wait_now();
		us = minimum(us, tm);
	}
#endif

	return us;
}


#ifndef THREAD_NONE

static thread_t iomux_thread;

#ifndef TIMER_THREAD
#define do_timer_check_all	timer_check_all()
#else
#define do_timer_check_all	do { } while (0)
#endif

/*
 * select doesn't work well with signals, the standard says that it's
 * implementation-defined whether SA_RESTART restarts select or not.
 *
 * If SA_RESTART signal restarts select with the original timeval, it causes
 * livelock.
 *
 * So, we'd better disable signals for the iomux thread and let the system
 * deliver them to another thread.
 */
#if defined(IOMUX_SELECT)
#define iomux_block_signals	true
#else
#define iomux_block_signals	false
#endif

thread_function_decl(iomux_poll_thread,
	sig_state_t set;
	if (iomux_block_signals)
		os_block_signals(&set);
	thread_set_id(-1);
	while (likely(!os_drain_notify_pipe())) {
		do_timer_check_all;
		os_proc_check_all();
		os_signal_check_all();
		iomux_check_all(IOMUX_INDEFINITE_WAIT);
	}
	if (iomux_block_signals)
		os_unblock_signals(&set);
)

#endif
