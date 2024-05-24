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

#include "mem_al.h"
#include "thread.h"
#include "obj_reg.h"

#include "rwlock.h"

#ifdef RWLOCK_IMPLEMENTED

struct rwlock_per_thread_allocated {
	struct rwlock_per_thread pt;
	struct rwlock_per_thread *thread1;
	void (*set_tls)(struct rwlock_per_thread *);
	tls_destructor_t destructor;
};

static void rwlock_per_thread_destructor(tls_destructor_t *destr)
{
	struct rwlock_per_thread_allocated *pta = get_struct(destr, struct rwlock_per_thread_allocated, destructor);
	struct rwlock_per_thread *thread1 = pta->thread1;
	pta->set_tls(thread1);
	obj_registry_start_recursion();
	mutex_lock(&thread1->mutex);
	list_del(&pta->pt.entry);
	mutex_unlock(&thread1->mutex);
	obj_registry_end_recursion();
	mutex_done(&pta->pt.mutex);
	mem_free_aligned(pta);
}

struct rwlock_per_thread *rwlock_per_thread_alloc(struct rwlock_per_thread *thread1, void (*set_tls)(struct rwlock_per_thread *))
{
	struct rwlock_per_thread_allocated *pta;
	ajla_error_t sink;
	set_tls(thread1);
	pta = mem_align_mayfail(struct rwlock_per_thread_allocated *, round_up(sizeof(struct rwlock_per_thread_allocated), SMP_ALIAS_ALIGNMENT), SMP_ALIAS_ALIGNMENT, &sink);
	if (unlikely(!pta))
		return thread1;
	mutex_init(&pta->pt.mutex);
	pta->thread1 = thread1;
	pta->set_tls = set_tls;
	mutex_lock(&thread1->mutex);
	list_add(&thread1->entry, &pta->pt.entry);
	mutex_unlock(&thread1->mutex);
	tls_destructor(&pta->destructor, rwlock_per_thread_destructor);
	set_tls(&pta->pt);
	return &pta->pt;
}

void attr_fastcall rwlock_lock_write(struct rwlock_per_thread *thread1)
{
	struct list *l;
	mutex_lock(&thread1->mutex);
	list_for_each(l, &thread1->entry) {
		struct rwlock_per_thread *pt = get_struct(l, struct rwlock_per_thread, entry);
		mutex_lock(&pt->mutex);
	}
}

void attr_fastcall rwlock_unlock_write(struct rwlock_per_thread *thread1)
{
	struct list *l;
	list_for_each(l, &thread1->entry) {
		struct rwlock_per_thread *pt = get_struct(l, struct rwlock_per_thread, entry);
		mutex_unlock(&pt->mutex);
	}
	mutex_unlock(&thread1->mutex);
}

#endif
