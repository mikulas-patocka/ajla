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
#include "addrlock.h"
#include "tree.h"
#include "list.h"
#include "iomux.h"

#include "timer.h"

struct timer {
	struct tree_entry entry;
	ajla_time_t t;
	struct list wait_list;
};

static struct tree timer_tree;
static mutex_t timer_tree_mutex;

#ifdef TIMER_THREAD
static thread_t timer_thread;
static cond_t timer_cond;
static uchar_efficient_t timer_thread_exit;
#endif

static inline void timer_lock(void)
{
	mutex_lock(&timer_tree_mutex);
}

static inline void timer_unlock(void)
{
	mutex_unlock(&timer_tree_mutex);
}

static bool timer_first(ajla_time_t *f)
{
	struct tree_entry *e;
	struct timer *t;

	e = tree_first(&timer_tree);
again:
	if (!e)
		return false;
	t = get_struct(e, struct timer, entry);
	if (list_is_empty(&t->wait_list)) {
		e = tree_next(&t->entry);
		tree_delete(&t->entry);
		mem_free(t);
		goto again;
	}

	*f = t->t;
	return true;
}

#ifdef TIMER_THREAD
static
#endif
uint32_t timer_wait_now(void)
{
	uint32_t u = IOMUX_INDEFINITE_WAIT;
	ajla_time_t mt;
	timer_lock();
	if (timer_first(&mt)) {
		ajla_time_t m = os_time_monotonic();
		if (m >= mt) {
			u = 0;
		} else if (unlikely(mt - m >= IOMUX_INDEFINITE_WAIT - 1)) {
			u = IOMUX_INDEFINITE_WAIT - 1;
		} else {
			u = mt - m;
		}
	}
	timer_unlock();
	return u;
}

static int timer_compare(const struct tree_entry *e, uintptr_t mtp)
{
	struct timer *t = get_struct(e, struct timer, entry);
	ajla_time_t mt = *cast_ptr(ajla_time_t *, num_to_ptr(mtp));
	if (t->t < mt)
		return -1;
	if (t->t > mt)
		return 1;
	return 0;
}

bool timer_register_wait(ajla_time_t mt, mutex_t **mutex_to_lock, struct list *list_entry, ajla_error_t *err)
{
	struct tree_insert_position ins;
	struct timer *t;
	struct tree_entry *e;

	timer_lock();

	e = tree_find_for_insert(&timer_tree, timer_compare, ptr_to_num(&mt), &ins);
	if (unlikely(e != NULL)) {
		t = get_struct(e, struct timer, entry);
	} else {
		t = mem_alloc_mayfail(struct timer *, sizeof(struct timer), err);
		if (unlikely(!t)) {
			timer_unlock();
			return false;
		}
		t->t = mt;
		list_init(&t->wait_list);
		tree_insert_after_find(&t->entry, &ins);
	}

	*mutex_to_lock = &timer_tree_mutex;
	list_add(&t->wait_list, list_entry);

#ifndef THREAD_NONE
	if (tree_first(&timer_tree) == &t->entry) {
#ifndef TIMER_THREAD
		os_notify();
#else
		timer_unlock();
		cond_lock(&timer_cond);
		cond_unlock_signal(&timer_cond);
		return true;
#endif
	}
#endif

	timer_unlock();
	return true;
}

#ifdef TIMER_THREAD
static
#endif
void timer_check_all(void)
{
	struct tree_entry *e;
again:
	timer_lock();
	e = tree_first(&timer_tree);
	if (unlikely(e != NULL)) {
		ajla_time_t m = os_time_monotonic();
		struct timer *t;
		t = get_struct(e, struct timer, entry);
		if (t->t <= m) {
			tree_delete(&t->entry);
			call(wake_up_wait_list)(&t->wait_list, &timer_tree_mutex, TASK_SUBMIT_MAY_SPAWN);
			mem_free(t);
			goto again;
		}
	}
	timer_unlock();
}

#ifdef TIMER_THREAD
thread_function_decl(timer_thread_fn,
	cond_lock(&timer_cond);
	while (likely(!timer_thread_exit)) {
		uint32_t us;
		us = timer_wait_now();
		if (us == IOMUX_INDEFINITE_WAIT)
			cond_wait(&timer_cond);
		else
			cond_wait_us(&timer_cond, us);
		timer_check_all();
	}
	cond_unlock(&timer_cond);
)
#endif

void timer_init(void)
{
	tree_init(&timer_tree);
	mutex_init(&timer_tree_mutex);
#ifdef TIMER_THREAD
	cond_init(&timer_cond);
	timer_thread_exit = 0;
	thread_spawn(&timer_thread, timer_thread_fn, NULL, PRIORITY_TIMER, NULL);
#endif
}

void timer_done(void)
{
#ifdef TIMER_THREAD
	cond_lock(&timer_cond);
	timer_thread_exit = 1;
	cond_unlock_signal(&timer_cond);
	thread_join(&timer_thread);
	cond_done(&timer_cond);
#endif
	while (unlikely(!tree_is_empty(&timer_tree))) {
		struct timer *t = get_struct(tree_any(&timer_tree), struct timer, entry);
		tree_delete(&t->entry);
		mem_free(t);
	}
	mutex_done(&timer_tree_mutex);
}
