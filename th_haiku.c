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
#include "mem_al.h"
#include "os.h"

#include "thread.h"

#ifdef THREAD_HAIKU

struct haiku_thread {
	struct list wait_entry;
	sem_id wakeup;
	thread_id id;
	void (*function)(void *);
	void *arg;
};

static struct haiku_thread thread_1;

static tls_decl(struct haiku_thread *, current_tcb);

unsigned thread_concurrency(void)
{
	int ir;
	EINTR_LOOP(ir, sysconf(_SC_NPROCESSORS_ONLN));
	if (likely(ir > 0))
		return ir;
	warning("sysconf(_SC_NPROCESSORS_ONLN) returned invalid value %d", ir);
	return 1;
}


#define do_mutex_init(m)						\
do {									\
	int r;								\
	r = pthread_mutex_init(m, NULL);				\
	if (unlikely(r))						\
		fatal("pthread_mutex_init failed at %s: %d, %s", position_string(position_arg), r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_mutex_done(m)						\
do {									\
	int r;								\
	r = pthread_mutex_destroy(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_done: pthread_mutex_destroy failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_mutex_lock(m)						\
do {									\
	int r;								\
	r = pthread_mutex_lock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_lock: pthread_mutex_lock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)

#define do_mutex_trylock(m)						\
do {									\
	int r;								\
	r = pthread_mutex_trylock(m);					\
	if (unlikely(r)) {						\
		if (unlikely(r != EBUSY) && unlikely(r != EDEADLK))	\
			internal(caller_file_line, "mutex_trylock: pthread_mutex_trylock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
		return false;						\
	}								\
	return true;							\
} while (0)

#define do_mutex_unlock(m)						\
do {									\
	int r;								\
	r = pthread_mutex_unlock(m);					\
	if (unlikely(r))						\
		internal(caller_file_line, "mutex_unlock: pthread_mutex_unlock failed: %d, %s", r, error_decode(error_from_errno(EC_SYSCALL, r)));\
} while (0)


/* Warning - too big values cause overflow in the kernel and races. */
#define RWMUTEX_NUMBER		32768

#define do_rwmutex_init(m)						\
do {									\
	*m = create_sem(RWMUTEX_NUMBER, NULL);				\
	if (unlikely(*m < 0))						\
		fatal("create_sem failed at %s: %x", position_string(position_arg), *m);\
} while (0)

#define do_rwmutex_done(m)						\
do {									\
	status_t s = delete_sem(*m);					\
	if (unlikely(s != B_NO_ERROR))					\
		fatal("delete_sem failed at %s: %x", position_string(position_arg), s);\
} while (0)

#define do_rwmutex_lock_read(m)						\
do {									\
	status_t s;							\
	do {								\
		s = acquire_sem(*m);					\
	} while (unlikely(s == B_INTERRUPTED));				\
	if (unlikely(s != B_NO_ERROR))					\
		fatal("acquire_sem failed at %s: %x", position_string(position_arg), s);\
} while (0)

#define do_rwmutex_unlock_read(m)					\
do {									\
	status_t s = release_sem(*m);					\
	if (unlikely(s != B_NO_ERROR))					\
		fatal("release_sem failed at %s: %x", position_string(position_arg), s);\
} while (0)

#define do_rwmutex_lock_write(m)					\
do {									\
	status_t s;							\
	do {								\
		s = acquire_sem_etc(*m, RWMUTEX_NUMBER, B_RELATIVE_TIMEOUT, B_INFINITE_TIMEOUT);\
	} while (unlikely(s == B_INTERRUPTED));				\
	if (unlikely(s != B_NO_ERROR))					\
		fatal("acquire_sem failed at %s: %x", position_string(position_arg), s);\
} while (0)

#define do_rwmutex_unlock_write(m)					\
do {									\
	status_t s = release_sem_etc(*m, RWMUTEX_NUMBER, 0);		\
	if (unlikely(s != B_NO_ERROR))					\
		fatal("release_sem failed at %s: %x", position_string(position_arg), s);\
} while (0)


#define do_cond_init(c)							\
do {									\
	mutex_init_position(&c->mutex pass_position);			\
	list_init(&c->wait_list);					\
} while (0)

#define do_cond_done(c)							\
do {									\
	mutex_done_position(&c->mutex pass_position);			\
	ajla_assert_lo(list_is_empty(&c->wait_list), (caller_file_line, "cond_done: wait list is not empty"));\
} while (0)

#define do_cond_lock(c)							\
do {									\
	mutex_lock_position(&c->mutex pass_position);			\
} while (0)

#define do_cond_unlock(c)						\
do {									\
	mutex_unlock_position(&c->mutex pass_position);			\
} while (0)

#define do_cond_unlock_signal(c)					\
do {									\
	struct haiku_thread *tcb;					\
	if (unlikely(!list_is_empty(&c->wait_list))) {			\
		tcb = get_struct(c->wait_list.next, struct haiku_thread, wait_entry);\
		list_del(&tcb->wait_entry);				\
		tcb->wait_entry.prev = NULL;				\
	} else {							\
		tcb = NULL;						\
	}								\
	mutex_unlock_position(&c->mutex pass_position);			\
	if (unlikely(tcb != NULL)) {					\
		status_t s = release_sem(tcb->wakeup);			\
		if (unlikely(s != B_NO_ERROR))				\
			fatal("release_sem failed at %s: %x", position_string(position_arg), s);\
	}								\
} while (0)

#define do_cond_unlock_broadcast(c)					\
do {									\
	struct list list;						\
	struct list *l;							\
	list_take(&list, &c->wait_list);				\
	for (l = list.next; l != &list; l = l->next)			\
		l->prev = NULL;						\
	mutex_unlock_position(&c->mutex pass_position);			\
	while (list.next != &list) {					\
		status_t s;						\
		struct haiku_thread *tcb = get_struct(list.next, struct haiku_thread, wait_entry);\
		list.next = tcb->wait_entry.next;			\
		s = release_sem(tcb->wakeup);				\
		if (unlikely(s != B_NO_ERROR))				\
			fatal("release_sem failed at %s: %x", position_string(position_arg), s);\
	}								\
} while (0)

static bool haiku_cond_wait(cond_t *c, bigtime_t timeout argument_position)
{
	int32 count;
	status_t s;
	struct haiku_thread *tcb = tls_get(struct haiku_thread *, current_tcb);

	s = get_sem_count(tcb->wakeup, &count);
	if (unlikely(s != B_NO_ERROR))
		fatal("get_sem_count failed at %s: %x", position_string(position_arg), s);

	if (unlikely(count > 0)) {
		do {
			s = acquire_sem_etc(tcb->wakeup, count, B_RELATIVE_TIMEOUT, B_INFINITE_TIMEOUT);
		} while (unlikely(s == B_INTERRUPTED));
		if (unlikely(s != B_NO_ERROR))
			fatal("acquire_sem_etc failed at %s: %x", position_string(position_arg), s);
	}

	list_add(&c->wait_list, &tcb->wait_entry);
	mutex_unlock_position(&c->mutex pass_position);

	do {
		s = acquire_sem_etc(tcb->wakeup, 1, B_RELATIVE_TIMEOUT, timeout);
	} while (unlikely(s == B_INTERRUPTED));

	mutex_lock_position(&c->mutex pass_position);

	if (unlikely(s != B_NO_ERROR)) {
		if (s == B_TIMED_OUT || s == B_WOULD_BLOCK) {
			if (likely(tcb->wait_entry.prev != NULL)) {
				list_del(&tcb->wait_entry);
				return false;
			}
			do {
				s = acquire_sem(tcb->wakeup);
			} while (unlikely(s == B_INTERRUPTED));
			if (unlikely(s != B_NO_ERROR))
				fatal("acquire_sem failed at %s: %x", position_string(position_arg), s);
			return true;
		}
		fatal("acquire_sem_etc failed at %s: %x", position_string(position_arg), s);
	}

	return true;
}

#define do_cond_wait(c)							\
do {									\
	haiku_cond_wait(c, B_INFINITE_TIMEOUT pass_position);		\
} while (0)

#define do_cond_wait_us(c, us)						\
do {									\
	return haiku_cond_wait(c, us pass_position);			\
} while (0)


static void haiku_thread_init(struct haiku_thread *tcb argument_position)
{
	tcb->wakeup = create_sem(0, NULL);
	if (unlikely(tcb->wakeup < 0))
		fatal("create_sem failed at %s: %x", caller_file_line, tcb->wakeup);
}

static void haiku_thread_done(struct haiku_thread *tcb argument_position)
{
	status_t s = delete_sem(tcb->wakeup);
	if (unlikely(s != B_NO_ERROR))
		fatal("delete_sem failed at %s: %x", caller_file_line, tcb->wakeup);
}

static int32 haiku_thread_function(void *tcb_)
{
	struct haiku_thread *tcb = cast_cpp(struct haiku_thread *, tcb_);
	tls_set(struct haiku_thread *, current_tcb, tcb);
	asm_setup_thread();
	tcb->function(tcb->arg);
	tls_destructor_call();
	return 0;
}

#define do_thread_spawn(t, function, arg, priority, err)		\
do {									\
	status_t s;							\
	int32 b;							\
	struct haiku_thread *tcb;					\
	tcb = mem_alloc_mayfail(struct haiku_thread *, sizeof(struct haiku_thread), err);\
	if (unlikely(!tcb))						\
		return false;						\
	haiku_thread_init(tcb pass_position);				\
	tcb->function = function;					\
	tcb->arg = arg;							\
	switch (priority) {						\
		case PRIORITY_COMPUTE:					\
			b = B_NORMAL_PRIORITY; break;			\
		case PRIORITY_IO:					\
			b = B_DISPLAY_PRIORITY; break;			\
		case PRIORITY_TIMER:					\
			b = B_URGENT_DISPLAY_PRIORITY; break;		\
		default:						\
			b = B_NORMAL_PRIORITY; break;			\
	}								\
	tcb->id = spawn_thread(haiku_thread_function, NULL, b, tcb);	\
	if (unlikely(tcb->id < 0)) {					\
		ajla_error_t e = error_from_errno(EC_SYSCALL, tcb->id);	\
		fatal_mayfail(e, err, "spawn_thread failed at %s: %x", position_string(position_arg), tcb->id);\
		mem_free(tcb);						\
		return false;						\
	}								\
	s = resume_thread(tcb->id);					\
	if (unlikely(s != B_NO_ERROR))					\
		fatal("resume_thread failed at %s: %x", caller_file_line, s);\
	*t = tcb;							\
} while (0)

#define do_thread_join(t)						\
do {									\
	struct haiku_thread *tcb = *t;					\
	status_t s, r;							\
	do {								\
		s = wait_for_thread(tcb->id, &r);			\
	} while (unlikely(s == B_INTERRUPTED));				\
	if (unlikely(s != B_NO_ERROR))					\
		fatal("wait_for_thread failed at %s: %x", caller_file_line, s);\
	haiku_thread_done(tcb pass_position);				\
	mem_free(tcb);							\
} while (0)


#include "th_com.inc"


void thread_init(void)
{
	haiku_thread_init(&thread_1 pass_file_line);
	tls_init(struct haiku_thread *, current_tcb);
	tls_set(struct haiku_thread *, current_tcb, &thread_1);
	thread_common_init();
}

void thread_done(void)
{
	thread_common_done();
	haiku_thread_done(&thread_1 pass_file_line);
	tls_done(struct haiku_thread *, current_tcb);
}

#endif
