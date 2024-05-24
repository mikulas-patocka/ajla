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

#ifdef DEBUG_OBJECT_POSSIBLE
#include "obj_reg.h"
#endif

#ifdef DEBUG_OBJECT_POSSIBLE
static bool mutex_debug = false;
static bool thread_debug = false;
#else
static const bool mutex_debug = false;
static const bool thread_debug = false;
#endif

#if defined(DEBUG_OBJECT_POSSIBLE) || !defined(THREAD_NONE)

void mutex_init_position(mutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_insert(OBJ_TYPE_MUTEX, ptr_to_num((void *)m), position_arg);
	do_mutex_init(m);
}

void mutex_done_position(mutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_remove(OBJ_TYPE_MUTEX, ptr_to_num((void *)m), position_arg);
	do_mutex_done(m);
}

void attr_fastcall mutex_lock_position(mutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_MUTEX, ptr_to_num((void *)m), position_arg);
	do_mutex_lock(m);
}

bool attr_fastcall mutex_trylock_position(mutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_MUTEX, ptr_to_num((void *)m), position_arg);
	do_mutex_trylock(m);
	not_reached();
	return false;
}

void attr_fastcall mutex_unlock_position(mutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_MUTEX, ptr_to_num((void *)m), position_arg);
	do_mutex_unlock(m);
}

#endif


#if defined(DEBUG_OBJECT_POSSIBLE) || !defined(THREAD_NONE)

void rwmutex_init_position(rwmutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_insert(OBJ_TYPE_RWMUTEX, ptr_to_num((void *)m), position_arg);
	do_rwmutex_init(m);
}

void rwmutex_done_position(rwmutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_remove(OBJ_TYPE_RWMUTEX, ptr_to_num((void *)m), position_arg);
	do_rwmutex_done(m);
}

void attr_fastcall rwmutex_lock_read_position(rwmutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_RWMUTEX, ptr_to_num((void *)m), position_arg);
	do_rwmutex_lock_read(m);
}

void attr_fastcall rwmutex_unlock_read_position(rwmutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_RWMUTEX, ptr_to_num((void *)m), position_arg);
	do_rwmutex_unlock_read(m);
}

void attr_fastcall rwmutex_lock_write_position(rwmutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_RWMUTEX, ptr_to_num((void *)m), position_arg);
	do_rwmutex_lock_write(m);
}

void attr_fastcall rwmutex_unlock_write_position(rwmutex_t *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_RWMUTEX, ptr_to_num((void *)m), position_arg);
	do_rwmutex_unlock_write(m);
}

#endif


#if defined(DEBUG_OBJECT_POSSIBLE) || !defined(THREAD_NONE)

void cond_init_position(cond_t *c argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_insert(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_init(c);
}

void cond_done_position(cond_t *c argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_remove(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_done(c);
}

void attr_fastcall cond_lock_position(cond_t *c argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_lock(c);
}

void attr_fastcall cond_unlock_position(cond_t *c argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_unlock(c);
}

void attr_fastcall cond_unlock_signal_position(cond_t *c argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_unlock_signal(c);
}

void attr_fastcall cond_unlock_broadcast_position(cond_t *c argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_unlock_broadcast(c);
}

void attr_fastcall cond_wait_position(cond_t *c argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_wait(c);
}

bool attr_fastcall cond_wait_us_position(cond_t *c, uint32_t us argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_COND, ptr_to_num(c), position_arg);
	do_cond_wait_us(c, us);
	not_reached();
	return false;
}

#endif


#ifndef THREAD_NONE
bool thread_spawn_position(thread_t *t, thread_function_t *function, void *arg, thread_priority_t attr_unused priority, ajla_error_t *err argument_position)
{
	do_thread_spawn(t, function, arg, priority, err);
	if (unlikely(thread_debug) && sizeof(thread_t) <= sizeof(obj_id)) {
		obj_id id = 0;
		memcpy(&id, t, sizeof(thread_t));
		obj_registry_insert(OBJ_TYPE_THREAD, id, position_arg);
	}
	return true;
}

void thread_join_position(thread_t *t argument_position)
{
	if (unlikely(thread_debug) && sizeof(thread_t) <= sizeof(obj_id)) {
		obj_id id = 0;
		memcpy(&id, t, sizeof(thread_t));
		obj_registry_remove(OBJ_TYPE_THREAD, id, position_arg);
	}
	do_thread_join(t);
}
#endif


#if defined(HAVE___THREAD)
#define do_tls_init(m)		do { } while (0)
#define do_tls_done(m)		do { } while (0)
#endif

void tls_init__position(tls_t_ attr_unused *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_insert(OBJ_TYPE_TLS, ptr_to_num(m), position_arg);
	do_tls_init(m);
}

void tls_done__position(tls_t_ attr_unused *m argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_remove(OBJ_TYPE_TLS, ptr_to_num(m), position_arg);
	do_tls_done(m);
}

#if !defined(HAVE___THREAD)

uintptr_t attr_fastcall tls_get__position(const tls_t_ *m argument_position)
{
	uintptr_t ret;
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_TLS, ptr_to_num(m), position_arg);
	do_tls_get(m, &ret);
	return ret;
}

void attr_fastcall tls_set__position(const tls_t_ *m, uintptr_t val argument_position)
{
	if (unlikely(mutex_debug))
		obj_registry_verify(OBJ_TYPE_TLS, ptr_to_num(m), position_arg);
	do_tls_set(m, val);
}

uintptr_t attr_fastcall tls_get__nocheck(const tls_t_ *m)
{
#ifdef DEBUG_TRACK_FILE_LINE
	const char attr_unused *position_arg = "tls_get__nocheck";
#endif
	uintptr_t ret;
	do_tls_get(m, &ret);
	return ret;
}

void attr_fastcall tls_set__nocheck(const tls_t_ *m, uintptr_t val)
{
#ifdef DEBUG_TRACK_FILE_LINE
	const char attr_unused *position_arg = "tls_set__nocheck";
#endif
	do_tls_set(m, val);
}

#endif


#ifndef THREAD_NONE

static tls_decl(tls_destructor_t *, tls_destructors);

void tls_destructor_position(tls_destructor_t *destr, tls_destructor_fn *fn argument_position)
{
	destr->fn = fn;
	destr->previous = tls_get(tls_destructor_t *, tls_destructors);
	tls_set(tls_destructor_t *, tls_destructors, destr);
}

void tls_destructor_call(void)
{
	tls_destructor_t *destr;
	while ((destr = tls_get(tls_destructor_t *, tls_destructors))) {
		tls_set(tls_destructor_t *, tls_destructors, destr->previous);
		destr->fn(destr);
	}
}

#ifdef DEBUG_TRACE
static tls_decl(int, thread_id);

void thread_set_id(int id)
{
	tls_set(int, thread_id, id);
}

int thread_get_id(void)
{
	return tls_get(int, thread_id);
}
#endif

static void thread_common_init(void)
{
	tls_init(tls_destructor_t *, tls_destructors);
#ifdef DEBUG_TRACE
	tls_init(int, thread_id);
#endif
}

static void thread_common_done(void)
{
	tls_destructor_call();
	tls_done(tls_destructor_t *, tls_destructors);
#ifdef DEBUG_TRACE
	tls_done(int, thread_id);
#endif
}

#endif


bool thread_enable_debugging_option(const char *option, size_t l)
{
#ifndef DEBUG_OBJECT_POSSIBLE
	bool attr_unused mutex_debug = false;
	bool attr_unused thread_debug = false;
#endif
	if (!option)
		mutex_debug = thread_debug = true;
	else if (l == 5 && !strncmp(option, "mutex", 5))
		mutex_debug = true;
	else if (l == 16 && !strncmp(option, "mutex-errorcheck", 16))
		mutex_debug = true;
	else if (l == 6 && !strncmp(option, "thread", 6))
		thread_debug = true;
	else
		return false;
#if defined(OS_OS2) || defined(OS_WIN32)
	mutex_debug = false;
#endif
	return true;
}
