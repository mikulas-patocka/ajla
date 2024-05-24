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

#ifndef AJLA_RWLOCK_H
#define AJLA_RWLOCK_H

#include "list.h"
#include "thread.h"

#ifndef THREAD_NONE
#define RWLOCK_IMPLEMENTED
#endif

#ifndef RWLOCK_IMPLEMENTED

#define rwlock_decl(name)	static mutex_t name
#define rwlock_init		mutex_init
#define rwlock_done		mutex_done
#define rwlock_lock_read	mutex_lock
#define rwlock_unlock_read	mutex_unlock
#define rwlock_lock_write	mutex_lock
#define rwlock_unlock_write	mutex_unlock

#else

struct rwlock_per_thread {
	mutex_t mutex;
	struct list entry;
};

#define rwlock_decl(name)						\
static tls_decl(struct rwlock_per_thread *, name##_per_thread);		\
static void name##_set_tls(struct rwlock_per_thread *pt)		\
{									\
	tls_set(struct rwlock_per_thread *, name##_per_thread, pt);	\
}									\
static struct rwlock_per_thread name

#define rwlock_init(name)						\
do {									\
	mutex_init(name.mutex);						\
	list_init(name.entry);						\
	tls_init(struct rwlock_per_thread *, *name##_per_thread);	\
	/*tls_set(struct rwlock_per_thread *, *name##_per_thread, name);*/\
	(*name##_set_tls)(name);					\
} while (0)

#define rwlock_done(name)						\
do {									\
	tls_done(struct rwlock_per_thread *, *name##_per_thread);	\
	ajla_assert_lo(list_is_empty(name.entry), (file_line, "rwlock list is not empty"));\
	mutex_done(name.mutex);						\
} while (0)

struct rwlock_per_thread *rwlock_per_thread_alloc(struct rwlock_per_thread *thread1, void (*set_tls)(struct rwlock_per_thread *));

#define rwlock_lock_read(name)						\
do {									\
	struct rwlock_per_thread *pt_ = tls_get(struct rwlock_per_thread *, *name##_per_thread);\
	if (unlikely(!pt_)) {						\
		pt_ = rwlock_per_thread_alloc(name, name##_set_tls);	\
	}								\
	mutex_lock(&pt_->mutex);					\
} while (0)

#define rwlock_unlock_read(name)					\
do {									\
	struct rwlock_per_thread *pt_ = tls_get(struct rwlock_per_thread *, *name##_per_thread);\
	mutex_unlock(&pt_->mutex);					\
} while (0)

void attr_fastcall rwlock_lock_write(struct rwlock_per_thread *thread1);
void attr_fastcall rwlock_unlock_write(struct rwlock_per_thread *thread1);

#endif

#endif
