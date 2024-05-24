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

#include "thread.h"

#ifdef THREAD_NONE

#define MUTEX_INVALID		0
#define MUTEX_UNLOCKED		1
#define MUTEX_LOCKED		2
#define MUTEX_LOCKED_WRITE	-1

#define do_mutex_init(m)						\
do {									\
	(m)->state = MUTEX_UNLOCKED;					\
} while (0)

#define do_mutex_done(m)						\
do {									\
	if (unlikely((m)->state != MUTEX_UNLOCKED))			\
		internal(position_string(position_arg), "mutex_done: invalid mutex state %d", (m)->state);\
	(m)->state = MUTEX_INVALID;					\
} while (0)

#define do_mutex_lock(m)						\
do {									\
	if (unlikely((m)->state != MUTEX_UNLOCKED))			\
		internal(position_string(position_arg), "mutex_lock: invalid mutex state %d", (m)->state);\
	(m)->state = MUTEX_LOCKED;					\
} while (0)

#define do_mutex_trylock(m)						\
do {									\
	if (likely((m)->state == MUTEX_UNLOCKED)) {			\
		(m)->state = MUTEX_LOCKED;				\
		return true;						\
	}								\
	if (unlikely((m)->state != MUTEX_LOCKED))			\
		internal(position_string(position_arg), "mutex_trylock: invalid mutex state %d", (m)->state);\
	return false;							\
} while (0)

#define do_mutex_unlock(m)						\
do {									\
	if (unlikely((m)->state != MUTEX_LOCKED))			\
		internal(position_string(position_arg), "mutex_unlock: invalid mutex state %d", (m)->state);\
	(m)->state = MUTEX_UNLOCKED;					\
} while (0)


#define do_rwmutex_init(m)						\
do {									\
	(m)->state = MUTEX_UNLOCKED;					\
} while (0)

#define do_rwmutex_done(m)						\
do {									\
	if (unlikely((m)->state != MUTEX_UNLOCKED))			\
		internal(position_string(position_arg), "rwmutex_done: invalid mutex state %d", (m)->state);\
	(m)->state = MUTEX_INVALID;					\
} while (0)

#define do_rwmutex_lock_read(m)						\
do {									\
	if (unlikely((m)->state < MUTEX_UNLOCKED))			\
		internal(position_string(position_arg), "rwmutex_lock_read: invalid mutex state %d", (m)->state);\
	(m)->state++;							\
} while (0)

#define do_rwmutex_unlock_read(m)					\
do {									\
	if (unlikely((m)->state < MUTEX_LOCKED))			\
		internal(position_string(position_arg), "rwmutex_unlock_read: invalid mutex state %d", (m)->state);\
	(m)->state--;							\
} while (0)

#define do_rwmutex_lock_write(m)					\
do {									\
	if (unlikely((m)->state != MUTEX_UNLOCKED))			\
		internal(position_string(position_arg), "rwmutex_lock_write: invalid mutex state %d", (m)->state);\
	(m)->state = MUTEX_LOCKED_WRITE;				\
} while (0)

#define do_rwmutex_unlock_write(m)					\
do {									\
	if (unlikely((m)->state != MUTEX_LOCKED_WRITE))			\
		internal(position_string(position_arg), "rwmutex_unlock_write: invalid mutex state %d", (m)->state);\
	(m)->state = MUTEX_UNLOCKED;					\
} while (0)


#define do_cond_init(c)							\
do {									\
	mutex_init_position(&(c)->mutex pass_position);			\
} while (0)

#define do_cond_done(c)							\
do {									\
	mutex_done_position(&(c)->mutex pass_position);			\
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
	mutex_unlock_position(&(c)->mutex pass_position);		\
} while (0)

#define do_cond_unlock_broadcast(c)					\
do {									\
	mutex_unlock_position(&(c)->mutex pass_position);		\
} while (0)

#define do_cond_wait(c)							\
do {									\
	if (unlikely((c)->mutex.state != MUTEX_LOCKED))			\
		internal(position_string(position_arg), "cond_wait: invalid mutex state %d", (c)->mutex.state);\
} while (0)

#define do_cond_wait_us(c, us)						\
do {									\
	if (unlikely((c)->mutex.state != MUTEX_LOCKED))			\
		internal(position_string(position_arg), "do_cond_wait_us: invalid mutex state %d", (c)->mutex.state);\
	us = us + 1; /* avoid warning */				\
	return false;							\
} while (0)


#include "th_com.inc"

void thread_init(void)
{
}

void thread_done(void)
{
}

#endif
