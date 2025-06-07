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
shared_var uint32_t nr_cpus_override shared_init(0);
shared_var uchar_efficient_t shutting_down;

#define STATE_ALL_BUSY	0
#define STATE_SOME_BUSY	1
#define STATE_ALL_IDLE	2

struct node_state {
	thread_volatile unsigned char public_state_[128];
#define public_state	public_state_[0]
	cond_t task_mutex;
	struct list task_list;
	thread_volatile sig_atomic_t task_list_nonempty;
	unsigned num;
	unsigned nr_deep_sleep;
	unsigned nr_active_cpus;
	unsigned starting_cpu;
	unsigned nr_node_cpus;
	tick_stamp_t task_list_stamp;
	atomic_type size_t n_ex_controls;
};

struct task_percpu {
	mutex_t waiting_list_mutex;
	struct list waiting_list;
	struct node_state *node;
	unsigned last_node;
	int membind;
};

struct thread_pointers {
#ifndef THREAD_NONE
	thread_t thread;
#endif
	struct task_percpu *tpc;
};

shared_var struct node_state **nodes;
shared_var unsigned nr_nodes;
shared_var unsigned nr_real_nodes;
shared_var uint32_t nr_nodes_override shared_init(0);
shared_var unsigned nr_idle_nodes;
shared_var struct thread_pointers *thread_pointers;
shared_var bool task_initialized shared_init(false);

shared_var refcount_t n_programs;

shared_var mutex_t mutex_idle_nodes;

static tls_decl(struct task_percpu *, task_tls);

static bool spawn_another_cpu(struct node_state *node, ajla_error_t *err);

int task_get_numa_node(void)
{
	if (likely(task_initialized)) {
		struct task_percpu *tpc = tls_get(struct task_percpu *, task_tls);
		if (likely(tpc != NULL))
			return tpc->membind;
	}
	return -1;
}

static inline unsigned get_any_node(struct task_percpu *tpc)
{
	unsigned n = ++tpc->last_node;
	if (likely(!(nr_nodes & (nr_nodes - 1))))
		return n & (nr_nodes - 1);
	else
		return n % nr_nodes;
}

static bool no_ex_controls(void)
{
	unsigned n;
	size_t sum = 0;
	for (n = 0; n < nr_nodes; n++)
		sum += load_relaxed(&nodes[n]->n_ex_controls);
	return !sum;
}

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

static void task_list_add(struct node_state *node, struct execution_control *ex, bool nonempty, unsigned spawn_mode)
{
	if (!nonempty) {
		node->task_list_stamp = tick_stamp;
	} else {
		if ((likely(spawn_mode == TASK_SUBMIT_MAY_SPAWN) && (tick_stamp - node->task_list_stamp >= 2)) || spawn_mode == TASK_SUBMIT_MUST_SPAWN) {
			ajla_error_t err;
			spawn_another_cpu(node, &err);
			node->task_list_stamp = tick_stamp;
		}
	}
	list_add(&node->task_list, &ex->wait[0].wait_entry);
	node->task_list_nonempty = 1;
}

void attr_fastcall task_submit(struct execution_control *ex, unsigned spawn_mode)
{
	struct task_percpu *tpc;
	struct node_state *node;
	if (spawn_mode != TASK_SUBMIT_MUST_NOT_SPAWN && (tpc = tls_get(struct task_percpu *, task_tls))) {
		node = tpc->node;
	} else {
		node = nodes[0];
	}

	ajla_assert(ex == frame_execution_control(ex->current_frame), (file_line, "task_submit: submitting task with improper execution control: %p != %p", ex, frame_execution_control(ex->current_frame)));

	if (node->public_state == STATE_ALL_BUSY && tpc) {
		unsigned n;
		for (n = 0; n < nr_nodes; n++) {
			unsigned nn = get_any_node(tpc);
			if (nodes[nn]->public_state != STATE_ALL_BUSY) {
				node = nodes[nn];
				goto found;
			}
		}
		/*for (n = 0; n < nr_nodes; n++) {
			unsigned nn = get_any_node(tpc);
			if (nodes[nn]->public_state == STATE_SOME_BUSY) {
				node = nodes[nn];
				goto found;
			}
		}*/
		node = nodes[get_any_node(tpc)];
	}

found:
	cond_lock(&node->task_mutex);
	task_list_add(node, ex, node->task_list_nonempty, spawn_mode);
	cond_unlock_signal(&node->task_mutex);
}

static struct execution_control *task_list_pop(struct node_state *node)
{
	struct execution_control *ex;
	if (!node->task_list_nonempty)
		return NULL;
	ex = get_struct(node->task_list.prev, struct execution_control, wait[0].wait_entry);
	list_del(&ex->wait[0].wait_entry);
	node->task_list_nonempty = !list_is_empty(&node->task_list);
	return ex;
}

static struct execution_control *task_list_steal(void)
{
	unsigned n;
	struct task_percpu *tpc = tls_get(struct task_percpu *, task_tls);
	for (n = 0; n < nr_nodes; n++) {
		struct node_state *node = nodes[get_any_node(tpc)];
		if (node->public_state == STATE_ALL_BUSY) {
			struct execution_control *ex;
			if (!node->task_list_nonempty)
				continue;
			cond_lock(&node->task_mutex);
			ex = task_list_pop(node);
			cond_unlock(&node->task_mutex);
			if (ex)
				return ex;
		}
	}
	return NULL;
}

void * attr_fastcall task_schedule(struct execution_control *old_ex)
{
	struct task_percpu *tpc = tls_get(struct task_percpu *, task_tls);
	struct node_state *node = tpc->node;
	struct execution_control *new_ex;

	if (unlikely(task_useless(old_ex)))
		return POINTER_FOLLOW_THUNK_EXIT;

#ifndef THREAD_SANITIZER
	if (!node->task_list_nonempty)
		goto no_sched;
#endif

	cond_lock(&node->task_mutex);
	new_ex = task_list_pop(node);
	if (unlikely(!new_ex))
		goto unlock_no_sched;
	ajla_assert(new_ex != old_ex, (file_line, "task_schedule: submitting already submitted task"));
	task_list_add(node, old_ex, true, TASK_SUBMIT_MAY_SPAWN);
	cond_unlock(&node->task_mutex);

	if (unlikely(task_useless(new_ex)))
		return POINTER_FOLLOW_THUNK_EXIT;

	return new_ex;

unlock_no_sched:
	cond_unlock(&node->task_mutex);
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
				execution_control_unlink_and_submit(ex, TASK_SUBMIT_MAY_SPAWN);
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

static inline bool enter_deep_sleep(void)
{
	bool ret = false;
	if (nr_nodes > 1)
		mutex_lock(&mutex_idle_nodes);
	if (++nr_idle_nodes == nr_nodes) {
		if (unlikely(no_ex_controls()) && !shutting_down) {
			shutting_down = true;
			ret = true;
		}
		tick_suspend();
	}
	if (nr_nodes > 1)
		mutex_unlock(&mutex_idle_nodes);
	return ret;
}

static inline void exit_deep_sleep(void)
{
	if (nr_nodes > 1)
		mutex_lock(&mutex_idle_nodes);
	if (nr_idle_nodes-- == nr_nodes)
		tick_resume();
	if (nr_nodes > 1)
		mutex_unlock(&mutex_idle_nodes);
}

static void task_worker_core(void)
{
	struct task_percpu *tpc = tls_get(struct task_percpu *, task_tls);
	struct node_state *node = tpc->node;
	bool wake_all = false;
	if (unlikely(profiling))
		profile_unblock();
	cond_lock(&node->task_mutex);
	while (likely(!shutting_down)) {
		struct execution_control *ex;
		if (!(ex = task_list_pop(node))) {
			bool more;
			cond_unlock(&node->task_mutex);
			ex = task_list_steal();
			if (ex)
				goto run_task;
			more = waiting_list_break();
			cond_lock(&node->task_mutex);
			if (!(ex = task_list_pop(node))) {
#ifndef THREAD_NONE
				if (!more) {
					bool full_idle = ++node->nr_deep_sleep == node->nr_active_cpus;
					unsigned char new_public_state = full_idle ? STATE_ALL_IDLE : STATE_SOME_BUSY;
					if (node->public_state != new_public_state)
						node->public_state = new_public_state;
					if (full_idle) {
						wake_all |= enter_deep_sleep();
					}
					if (likely(!shutting_down)) {
						cond_wait(&node->task_mutex);
						/*spawn_another_cpu(node, NULL);*/
					}
					if (node->nr_deep_sleep-- == node->nr_active_cpus) {
						exit_deep_sleep();
						node->public_state = STATE_SOME_BUSY;
					}
					if (!node->nr_deep_sleep)
						node->public_state = STATE_ALL_BUSY;
				} else {
					cond_wait_us(&node->task_mutex, tick_us);
				}
#else
				cond_unlock(&node->task_mutex);
				if (!more) {
					wake_all |= enter_deep_sleep();
				}
				iomux_check_all(unlikely(shutting_down) ? 0 : more ? tick_us : IOMUX_INDEFINITE_WAIT);
				if (!more)
					exit_deep_sleep();
				cond_lock(&node->task_mutex);
#endif
				if (unlikely(profiling))
					profile_unblock();
				continue;
			}
		}
		cond_unlock(&node->task_mutex);
run_task:
		if (likely(!task_useless(ex)))
			run(ex->current_frame, ex->current_ip);
		cond_lock(&node->task_mutex);
	}
	cond_unlock(&node->task_mutex);
	if (wake_all) {
		unsigned nn;
		for (nn = 0; nn < nr_nodes; nn++) {
			struct node_state *nnode = nodes[nn];
			cond_lock(&nnode->task_mutex);
			cond_unlock_broadcast(&nnode->task_mutex);
		}
	}
	/*{
		struct bitmask *bmp = numa_get_run_node_mask();
		debug("mask: %lx", bmp->maskp[0]);
	}*/
}

static void set_per_thread_data(struct thread_pointers *tp)
{
	struct task_percpu *tpc;
	struct node_state *node;
	thread_set_id((int)(tp - thread_pointers));
	tpc = tp->tpc;
	tls_set(struct task_percpu *, task_tls, tpc);
	node = tpc->node;
	node->task_list_stamp = tick_stamp;
	if (likely(!(nr_nodes % nr_real_nodes))) {
		tpc->membind = node->num / (nr_nodes / nr_real_nodes);
		os_numa_bind(tpc->membind);
	}
}

#ifndef THREAD_NONE
thread_function_decl(task_worker,
	set_per_thread_data(arg);
	task_worker_core();
)
#endif

static bool spawn_another_cpu(struct node_state attr_unused *node, ajla_error_t attr_unused *err)
{
#ifndef THREAD_NONE
	if (node->nr_active_cpus < node->nr_node_cpus) {
		unsigned c = node->starting_cpu + node->nr_active_cpus;
		/*debug("spawning cpu %d", node->nr_active_cpus);*/
		if (unlikely(!thread_spawn(&thread_pointers[c].thread, task_worker, &thread_pointers[c], PRIORITY_COMPUTE, err)))
			return false;
		if (node->nr_active_cpus++ == node->nr_deep_sleep && node->nr_active_cpus > 1) {
			exit_deep_sleep();
			node->public_state = STATE_SOME_BUSY;
		}
	}
#endif
	return true;
}

void name(task_run)(void)
{
	unsigned n;
	set_per_thread_data(&thread_pointers[0]);
	nodes[0]->nr_active_cpus = 1;
	for (n = 0; n < nr_nodes; n++) {
		unsigned c;
		struct node_state *node = nodes[n];
		cond_lock(&node->task_mutex);
#if 0
		for (c = 0; c < node->nr_node_cpus; c++)
#else
		for (c = 0; c < 1; c++)
#endif
		{
			if (n == 0 && c == 0)
				continue;
			spawn_another_cpu(node, NULL);
		}
		cond_unlock(&node->task_mutex);
	}
	task_worker_core();
#ifndef THREAD_NONE
	for (n = 0; n < nr_nodes; n++) {
		unsigned c;
		struct node_state *node = nodes[n];
		for (c = 0; c < node->nr_active_cpus; c++) {
			if (n == 0 && c == 0)
				continue;
			thread_join(&thread_pointers[node->starting_cpu + c].thread);
		}
	}
#endif
	if (likely(!(nr_nodes % nr_real_nodes)))
		os_numa_unbind();
}

void task_ex_control_started(void)
{
	struct task_percpu *tpc;
	struct node_state *node;
	tpc = tls_get(struct task_percpu *, task_tls);
	if (unlikely(!tpc))
		node = nodes[0];
	else
		node = tpc->node;
#ifdef HAVE_C11_ATOMICS
	atomic_fetch_add_explicit(&node->n_ex_controls, 1, memory_order_relaxed);
#else
	cond_lock(&node->task_mutex);
	node->n_ex_controls++;
	cond_unlock(&node->task_mutex);
#endif
}

void task_ex_control_exited(void)
{
	struct task_percpu *tpc;
	struct node_state *node;
	tpc = tls_get(struct task_percpu *, task_tls);
	node = tpc->node;
#ifdef HAVE_C11_ATOMICS
	atomic_fetch_sub_explicit(&node->n_ex_controls, 1, memory_order_release);
#else
	cond_lock(&node->task_mutex);
	node->n_ex_controls--;
	cond_unlock(&node->task_mutex);
#endif
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
	unsigned n, c;

	refcount_init(&n_programs);

	mutex_init(&mutex_idle_nodes);
	nr_idle_nodes = 0;
	shutting_down = false;

	nr_cpus = thread_concurrency();
#ifndef THREAD_NONE
	if (unlikely(nr_cpus_override))
		nr_cpus = nr_cpus_override;
#endif
#ifdef DEBUG_INFO
	debug("concurrency: %u", nr_cpus);
#endif

	/*debug("available: %d", numa_available());
	debug("max nodes: %d", numa_max_possible_node());
	debug("num nodes: %d", numa_num_possible_nodes());
	debug("cnf nodes: %d", numa_num_configured_nodes());
	debug("cnf cpus: %d", numa_num_configured_cpus());*/

	nr_nodes = nr_real_nodes = os_numa_nodes();
	if (unlikely(nr_nodes_override != 0))
		nr_nodes = nr_nodes_override;
	if (unlikely(nr_nodes > nr_cpus))
		nr_nodes = nr_cpus;
#ifdef DEBUG_INFO
	debug("numa nodes: %u", nr_nodes);
#endif
	nodes = mem_alloc_array_mayfail(mem_alloc_mayfail, struct node_state **, 0, 0, nr_nodes, sizeof(struct node_state *), NULL);
	for (n = 0; n < nr_nodes; n++) {
		struct node_state *node = nodes[n] = os_numa_alloc(n * nr_real_nodes / nr_nodes, sizeof(struct node_state));
		memset(node, 0, sizeof(struct node_state));
		node->public_state = STATE_ALL_BUSY;
		cond_init(&node->task_mutex);
		list_init(&node->task_list);
		node->num = n;
		if (unlikely(!nr_nodes_override)) {
			node->starting_cpu = !n ? 0 : nodes[n - 1]->starting_cpu + nodes[n - 1]->nr_node_cpus;
			node->nr_node_cpus = os_numa_cpus_per_node(n);
		}
	}
	if (unlikely(nodes[nr_nodes - 1]->starting_cpu + nodes[nr_nodes - 1]->nr_node_cpus != nr_cpus)) {
		unsigned x1 = nr_cpus % nr_nodes;
		unsigned y1 = nr_cpus / nr_nodes;
		for (n = 0; n < nr_nodes; n++) {
			struct node_state *node = nodes[n];
			node->starting_cpu = !n ? 0 : nodes[n - 1]->starting_cpu + nodes[n - 1]->nr_node_cpus;
			node->nr_node_cpus = y1 + (n < x1);
		}
	}

	thread_pointers = mem_alloc_array_mayfail(mem_alloc_mayfail, struct thread_pointers *, 0, 0, nr_cpus, sizeof(struct thread_pointers), NULL);
	n = 0;
	for (c = 0; c < nr_cpus; c++) {
		struct node_state *node = nodes[n];
		struct task_percpu *tpc;
		tpc = thread_pointers[c].tpc = os_numa_alloc(n * nr_real_nodes / nr_nodes, sizeof(struct task_percpu));
		list_init(&tpc->waiting_list);
		mutex_init(&tpc->waiting_list_mutex);
		tpc->node = node;
		tpc->last_node = 0;
		tpc->membind = -1;
		if (c + 1 == node->starting_cpu + node->nr_node_cpus)
			n++;
	}
	tls_init(struct task_percpu *, task_tls);
	task_initialized = true;
}

void name(task_done)(void)
{
	unsigned n, c;

	ajla_assert_lo(refcount_is_one(&n_programs), (file_line, "task_done: programs leaked: %"PRIuMAX"", (uintmax_t)refcount_get_nonatomic(&n_programs)));

	task_initialized = false;
	tls_done(struct task_percpu *, task_tls);

	for (c = 0; c < nr_cpus; c++) {
		struct task_percpu *tpc = thread_pointers[c].tpc;
		mutex_done(&tpc->waiting_list_mutex);
		os_numa_free(tpc, sizeof(struct task_percpu));
	}
	mem_free(thread_pointers);
	for (n = 0; n < nr_nodes; n++) {
		struct node_state *node = nodes[n];
		cond_done(&node->task_mutex);
		os_numa_free(node, sizeof(struct node_state));
	}
	mem_free(nodes);

	mutex_done(&mutex_idle_nodes);
}

#endif
