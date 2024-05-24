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

#ifndef FILE_OMIT

#include "list.h"
#include "thread.h"
#include "ipret.h"
#include "refcount.h"
#include "tick.h"
#include "iomux.h"
#include "timer.h"
#include "ipfn.h"

#include "task.h"

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

shared_var unsigned nr_cpus;
shared_var unsigned nr_active_cpus;
shared_var uint32_t nr_cpus_override shared_init(0);

struct task_percpu {
	mutex_t waiting_list_mutex;
	struct list waiting_list;
};

struct thread_pointers {
#ifndef THREAD_NONE
	thread_t thread;
#endif
	struct task_percpu *tpc;
};

shared_var struct thread_pointers *thread_pointers;

shared_var refcount_t n_ex_controls;
shared_var refcount_t n_programs;
shared_var cond_t task_mutex;
shared_var unsigned n_deep_sleep;
shared_var struct list task_list;
shared_var tick_stamp_t task_list_stamp;
shared_var thread_volatile sig_atomic_t task_list_nonempty;

static tls_decl(struct task_percpu *, task_tls);

static void spawn_another_cpu(void);

static bool task_is_useless(struct execution_control *ex)
{
	struct thunk *thunk = ex->thunk;
	if (refcount_is_one(&n_programs))
		goto ret_true;
	if (unlikely(!thunk))
		return false;
	if (likely(thunk_tag_volatile(thunk) != THUNK_TAG_BLACKHOLE_DEREFERENCED))
		return false;
	address_lock(thunk, DEPTH_THUNK);
	if (unlikely(thunk_tag(thunk) != THUNK_TAG_BLACKHOLE_DEREFERENCED)) {
		address_unlock(thunk, DEPTH_THUNK);
		return false;
	}
	address_unlock(thunk, DEPTH_THUNK);
ret_true:
	if (unlikely(ex->atomic != 0)) {
		ex->atomic_interrupted = true;
		return false;
	}
	return true;
}

static bool task_useless(struct execution_control *ex)
{
	if (unlikely(task_is_useless(ex))) {
		pointer_t ptr = pointer_thunk(thunk_alloc_exception_error(error_ajla(EC_ASYNC, AJLA_ERROR_NOT_SUPPORTED), NULL, NULL, NULL pass_file_line));
		execution_control_terminate(ex, ptr);
		pointer_dereference(ptr);
		return true;
	}
	return false;
}

#if 0
void task_list_print(void)
{
	char *s;
	size_t l;
	struct list *t;
	str_init(&s, &l);
	list_for_each(t, &task_list) {
		struct execution_control *ex = get_struct(t, struct execution_control, wait[0].wait_entry);
		if (l) str_add_string(&s, &l, ", ");
		str_add_unsigned(&s, &l, ptr_to_num(ex), 16);
	}
	str_finish(&s, &l);
	mem_free(s);
}
#endif

void attr_fastcall task_submit(struct execution_control *ex, bool can_allocate_memory)
{
	ajla_assert(ex == frame_execution_control(ex->current_frame), (file_line, "task_submit: submitting task with improper execution control: %p != %p", ex, frame_execution_control(ex->current_frame)));

	cond_lock(&task_mutex);
	if (!task_list_nonempty) {
		task_list_stamp = tick_stamp;
	} else {
		if (tick_stamp - task_list_stamp >= 2 && likely(can_allocate_memory)) {
			spawn_another_cpu();
			task_list_stamp = tick_stamp;
		}
	}
	list_add(&task_list, &ex->wait[0].wait_entry);
	task_list_nonempty = 1;
	cond_unlock_signal(&task_mutex);
}

static struct execution_control *task_list_pop(void)
{
	struct execution_control *ex;
	if (!task_list_nonempty)
		return NULL;
	ex = get_struct(task_list.prev, struct execution_control, wait[0].wait_entry);
	list_del(&ex->wait[0].wait_entry);
	task_list_nonempty = !list_is_empty(&task_list);
	return ex;
}

void * attr_fastcall task_schedule(struct execution_control *old_ex)
{
	struct execution_control *new_ex;

	if (unlikely(task_useless(old_ex)))
		return POINTER_FOLLOW_THUNK_EXIT;

#ifndef THREAD_SANITIZER
	if (!task_list_nonempty)
		goto no_sched;
#endif

	cond_lock(&task_mutex);
	new_ex = task_list_pop();
	if (unlikely(!new_ex))
		goto unlock_no_sched;

	list_add(&task_list, &old_ex[0].wait->wait_entry);

	ajla_assert(new_ex != old_ex, (file_line, "task_schedule: submitting already submitted task"));

	task_list_nonempty = 1;
	cond_unlock(&task_mutex);

	if (unlikely(task_useless(new_ex)))
		return POINTER_FOLLOW_THUNK_EXIT;

	return new_ex;

unlock_no_sched:
	cond_unlock(&task_mutex);
#ifndef THREAD_SANITIZER
no_sched:
#endif
	return old_ex;
}

void waiting_list_add(struct execution_control *ex)
{
	struct task_percpu *tpc = tls_get(struct task_percpu *, task_tls);

	mutex_lock(&tpc->waiting_list_mutex);
	list_add(&tpc->waiting_list, &ex->waiting_list_entry);
	ex->waiting_list_head = tpc;
	mutex_unlock(&tpc->waiting_list_mutex);
}

void waiting_list_remove(struct execution_control *ex)
{
	struct task_percpu *tpc = ex->waiting_list_head;

	mutex_lock(&tpc->waiting_list_mutex);
	list_del(&ex->waiting_list_entry);
	mutex_unlock(&tpc->waiting_list_mutex);

#ifdef DEBUG
	ex->waiting_list_head = NULL;
#endif
}

bool waiting_list_break(void)
{
	struct task_percpu *tpc = tls_get(struct task_percpu *, task_tls);
	struct list *l;
	bool ret;

#ifdef THREAD_NONE
	timer_check_all();
	os_proc_check_all();
	os_signal_check_all();
	iomux_check_all(0);
#endif

again:
	mutex_lock(&tpc->waiting_list_mutex);

	list_for_each_back(l, &tpc->waiting_list) {
		struct execution_control *ex = get_struct(l, struct execution_control, waiting_list_entry);
		if (unlikely(task_is_useless(ex))) {
			if (execution_control_acquire(ex)) {
				mutex_unlock(&tpc->waiting_list_mutex);
				execution_control_unlink_and_submit(ex, true);
				goto again;
			}
		}
		if (!ipret_break_waiting_chain(ex->current_frame, ex->current_ip)) {
			l = l->next;
			list_del(&ex->waiting_list_entry);
			list_init(&ex->waiting_list_entry);
		}
	}

	ret = !list_is_empty(&tpc->waiting_list);
	mutex_unlock(&tpc->waiting_list_mutex);

	return ret;
}

static void task_worker_core(void)
{
	if (unlikely(profiling))
		profile_unblock();
	cond_lock(&task_mutex);
	while (likely(!refcount_is_one(&n_ex_controls))) {
		struct execution_control *ex;
		if (!(ex = task_list_pop())) {
			bool more;
			cond_unlock(&task_mutex);
			more = waiting_list_break();
			cond_lock(&task_mutex);
			if (!(ex = task_list_pop())) {
				if (likely(refcount_is_one(&n_ex_controls))) {
					break;
				}
#ifndef THREAD_NONE
				if (!more) {
					if (++n_deep_sleep == nr_active_cpus) {
						tick_suspend();
					}
					cond_wait(&task_mutex);
					if (n_deep_sleep-- == nr_active_cpus) {
						tick_resume();
					}
				} else {
					cond_wait_us(&task_mutex, tick_us);
				}
#else
				cond_unlock(&task_mutex);
				if (!more)
					tick_suspend();
				iomux_check_all(more ? tick_us : IOMUX_INDEFINITE_WAIT);
				if (!more)
					tick_resume();
				cond_lock(&task_mutex);
#endif
				if (unlikely(profiling))
					profile_unblock();
				continue;
			}
		}
		cond_unlock(&task_mutex);
		if (likely(!task_useless(ex)))
			run(ex->current_frame, ex->current_ip);
		cond_lock(&task_mutex);
	}
	cond_unlock(&task_mutex);
}

static void set_per_thread_data(struct thread_pointers *tp)
{
	struct task_percpu *tpc;
	thread_set_id((int)(tp - thread_pointers));
	tpc = tp->tpc;
	tls_set(struct task_percpu *, task_tls, tpc);
}

#ifndef THREAD_NONE
thread_function_decl(task_worker,
	set_per_thread_data(arg);
	task_worker_core();
)
#endif

static void spawn_another_cpu(void)
{
#ifndef THREAD_NONE
	if (nr_active_cpus < nr_cpus) {
		ajla_error_t err;
		/*debug("spawning cpu %d", nr_active_cpus);*/
		if (unlikely(!thread_spawn(&thread_pointers[nr_active_cpus].thread, task_worker, &thread_pointers[nr_active_cpus], PRIORITY_COMPUTE, &err)))
			return;
		nr_active_cpus++;
	}
#endif
}

void name(task_run)(void)
{
#ifndef THREAD_NONE
	unsigned i;
#endif
	nr_active_cpus = 1;
	set_per_thread_data(&thread_pointers[0]);
#if 0
	cond_lock(&task_mutex);
	while (nr_active_cpus < nr_cpus)
		spawn_another_cpu();
	cond_unlock(&task_mutex);
#endif
	task_worker_core();
#ifndef THREAD_NONE
	cond_lock(&task_mutex);
	for (i = 1; i < nr_active_cpus; i++) {
		cond_unlock(&task_mutex);
		thread_join(&thread_pointers[i].thread);
		cond_lock(&task_mutex);
	}
	cond_unlock(&task_mutex);
#endif
}

void task_ex_control_started(void)
{
	refcount_inc(&n_ex_controls);
}

void task_ex_control_exited(void)
{
	ajla_assert_lo(!refcount_is_one(&n_ex_controls), (file_line, "task_ex_control_exit: n_ex_controls underflow"));
	refcount_add(&n_ex_controls, -1);
	if (unlikely(refcount_is_one(&n_ex_controls))) {
		cond_lock(&task_mutex);
		cond_unlock_broadcast(&task_mutex);
	}
}

void task_program_started(void)
{
	refcount_inc(&n_programs);
}

void task_program_exited(void)
{
	ajla_assert_lo(!refcount_is_one(&n_programs), (file_line, "task_program_exited: n_programs underflow"));
	refcount_add(&n_programs, -1);
}


void name(task_init)(void)
{
	unsigned i;

	refcount_init(&n_ex_controls);
	refcount_init(&n_programs);
	n_deep_sleep = 0;
	cond_init(&task_mutex);
	list_init(&task_list);
	task_list_nonempty = 0;

	nr_cpus = thread_concurrency();
#ifndef THREAD_NONE
	if (nr_cpus_override)
		nr_cpus = nr_cpus_override;
#endif
#ifdef DEBUG_INFO
	debug("concurrency: %u", nr_cpus);
#endif

	thread_pointers = mem_alloc_array_mayfail(mem_calloc_mayfail, struct thread_pointers *, 0, 0, nr_cpus, sizeof(struct thread_pointers), NULL);
	for (i = 0; i < nr_cpus; i++) {
		struct task_percpu *tpc;
		tpc = thread_pointers[i].tpc = mem_alloc(struct task_percpu *, sizeof(struct task_percpu));
		list_init(&tpc->waiting_list);
		mutex_init(&tpc->waiting_list_mutex);
	}
	tls_init(struct task_percpu *, task_tls);
}

void name(task_done)(void)
{
	unsigned i;

	ajla_assert_lo(refcount_is_one(&n_programs), (file_line, "task_done: programs leaked: %"PRIuMAX"", (uintmax_t)refcount_get_nonatomic(&n_programs)));

	tls_done(struct task_percpu *, task_tls);
	for (i = 0; i < nr_cpus; i++) {
		struct task_percpu *tpc = thread_pointers[i].tpc;
		mutex_done(&tpc->waiting_list_mutex);
		mem_free(tpc);
	}
	mem_free(thread_pointers);

	cond_done(&task_mutex);
}

#endif
