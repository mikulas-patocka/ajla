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

#include "tree.h"
#include "list.h"
#include "str.h"
#include "thread.h"
#include "rwlock.h"
#include "os.h"

#include "obj_reg.h"

#ifdef DEBUG_OBJECT_POSSIBLE

static int obj_registry_active = 0;

struct registry {
	struct tree head;
};

struct object {
	struct tree_entry entry;
	obj_id id;
	position_t position;
};

static struct registry registry[N_OBJ_TYPES];

static bool registry_threads_initialized;

static unsigned obj_registry_recursion_singlethreaded = 0;
static tls_decl(unsigned, obj_registry_recursion);

rwlock_decl(obj_registry_rwlock);

bool obj_registry_start_recursion(void)
{
	unsigned recursion;
	if (unlikely(!registry_threads_initialized)) {
		return obj_registry_recursion_singlethreaded++ != 0;
	}
	recursion = tls_get_nocheck(unsigned, obj_registry_recursion);
	tls_set_nocheck(unsigned, obj_registry_recursion, recursion + 1);
	return recursion != 0;
}

void obj_registry_end_recursion(void)
{
	unsigned recursion;
	if (unlikely(!registry_threads_initialized)) {
		if (unlikely(!obj_registry_recursion_singlethreaded))
			internal(file_line, "obj_registry_end_recursion: obj_registry_recursion_singlethreaded underflow");
		obj_registry_recursion_singlethreaded--;
		return;
	}
	recursion = tls_get_nocheck(unsigned, obj_registry_recursion);
	if (unlikely(!recursion))
		internal(file_line, "obj_registry_end_recursion: obj_registry_recursion underflow");
	tls_set_nocheck(unsigned, obj_registry_recursion, recursion - 1);
}

/*
 * warning: memory allocation or freeing must not be done when holding
 * the object registry lock
 */
static void obj_registry_lock_read(void)
{
	if (unlikely(!registry_threads_initialized))
		return;
	rwlock_lock_read(&obj_registry_rwlock);
}

static void obj_registry_unlock_read(void)
{
	if (unlikely(!registry_threads_initialized))
		return;
	rwlock_unlock_read(&obj_registry_rwlock);
}

static void obj_registry_lock_write(void)
{
	if (unlikely(!registry_threads_initialized))
		return;
	rwlock_lock_write(&obj_registry_rwlock);
}

static void obj_registry_unlock_write(void)
{
	if (unlikely(!registry_threads_initialized))
		return;
	rwlock_unlock_write(&obj_registry_rwlock);
}


static char attr_cold *print_obj_id(obj_id id)
{
#if 1
	static char buffer[sizeof(obj_id) * 2 + 1];
	char *b = buffer;
	str_add_unsigned(&b, NULL, (uintbig_t)id, 16);
	return buffer;
#else
	/* this causes memory allocation and may trigger infinite recursion on some errors */
	return str_from_unsigned(id, 16);
#endif
}

static struct registry *obj_registry_get(obj_id type, position_t position)
{
	if (unlikely(type >= N_OBJ_TYPES))
		internal(position_string(position), "obj_registry_get: invalid type %u", (unsigned)type);
	return &registry[type];
}


static int object_test(const struct tree_entry *e, uintptr_t id)
{
	const struct object *o = get_struct(e, struct object, entry);
	if (o->id == id) return 0;
	if (o->id > id) return 1;
	return -1;
}

static struct object *obj_registry_find(struct registry *r, obj_id id)
{
	struct tree_entry *e;

	e = tree_find(&r->head, object_test, id);
	if (likely(e != NULL))
		return get_struct(e, struct object, entry);
	else
		return NULL;
}

void obj_registry_insert(obj_type type, obj_id id, position_t position)
{
	struct registry *r;
	struct tree_entry *e;
	struct tree_insert_position ins;
	struct object *o;

	if (likely(!((obj_registry_active >> (int)type) & 1)))
		return;

	o = malloc(sizeof(struct object));
	if (unlikely(!o))
		fatal("unable to allocate struct object");
	o->id = id;
	o->position = position;

	obj_registry_start_recursion();
	obj_registry_lock_write();

	r = obj_registry_get(type, position);
	e = tree_find_for_insert(&r->head, object_test, o->id, &ins);
	if (unlikely(e != NULL)) {
		struct object *of = get_struct(e, struct object, entry);
		obj_registry_unlock_write();
		internal(position_string(position), "object already present, type %u, id %s, allocated at %s", (unsigned)type, print_obj_id(id), position_string(of->position));
	}
	tree_insert_after_find(&o->entry, &ins);

	obj_registry_unlock_write();
	obj_registry_end_recursion();
}

void obj_registry_remove(obj_type type, obj_id id, position_t position)
{
	struct registry *r;
	struct object *o;

	if (likely(!((obj_registry_active >> (int)type) & 1)))
		return;

	obj_registry_start_recursion();
	obj_registry_lock_write();

	r = obj_registry_get(type, position);
	if (unlikely(!(o = obj_registry_find(r, id)))) {
		obj_registry_unlock_write();
		internal(position_string(position), "object not found, type %u, id %s", (unsigned)type, print_obj_id(id));
	}
	tree_delete(&o->entry);

	obj_registry_unlock_write();
	obj_registry_end_recursion();

	free(o);
}

void obj_registry_verify(obj_type type, obj_id id, position_t position)
{
	struct registry *r;

	if (likely(!((obj_registry_active >> (int)type) & 1)))
		return;

	if (obj_registry_start_recursion()) {
		obj_registry_end_recursion();
		return;
	}
	obj_registry_lock_read();

	r = obj_registry_get(type, position);
	if (unlikely(!obj_registry_find(r, id))) {
		obj_registry_unlock_read();
		internal(position_string(position), "object not found, type %u, id %s", (unsigned)type, print_obj_id(id));
	}

	obj_registry_unlock_read();
	obj_registry_end_recursion();
}

static attr_noreturn attr_cold obj_registry_dump_leaks(void)
{
	obj_id t;
	char *s;
	size_t sl;
	bool first = true;
	const char *first_pos = "";

	str_init(&s, &sl);
	str_add_string(&s, &sl, "object leak, list of objects: ");

	for (t = 0; t < N_OBJ_TYPES; t++) {
		struct tree_entry *lv;
		for (lv = tree_first(&registry[t].head); lv; lv = tree_next(lv)) {
			struct object *o = get_struct(lv, struct object, entry);
			const char *pos_str = position_string(o->position);

			if (first) first_pos = pos_str;
			else str_add_string(&s, &sl, ", ");
			first = false;

			str_add_unsigned(&s, &sl, t, 10);
			str_add_string(&s, &sl, ":");
			str_add_string(&s, &sl, print_obj_id(o->id));
			str_add_string(&s, &sl, " @ ");
			str_add_string(&s, &sl, pos_str);
		}
	}

	str_finish(&s, &sl);

	internal(first_pos, "%s", s);
}

void obj_registry_init(void)
{
	obj_id t;
	registry_threads_initialized = false;
	for (t = 0; t < N_OBJ_TYPES; t++)
		tree_init(&registry[t].head);
}

void obj_registry_init_multithreaded(void)
{
	if (unlikely(registry_threads_initialized))
		internal(file_line, "obj_registry_init_multithreaded: registry_threads_initialized already set");
	tls_init(unsigned, obj_registry_recursion);
	rwlock_init(&obj_registry_rwlock);
	registry_threads_initialized = true;
}

void obj_registry_done_multithreaded(void)
{
	if (unlikely(!registry_threads_initialized))
		internal(file_line, "obj_registry_done_multithreaded: registry_threads_initialized not set");
	registry_threads_initialized = false;
	rwlock_done(&obj_registry_rwlock);
	tls_done(unsigned, obj_registry_recursion);
}

void obj_registry_done(void)
{
	obj_id t;
	if (unlikely(registry_threads_initialized))
		internal(file_line, "obj_registry_done: registry_threads_initialized set");
	for (t = 0; t < N_OBJ_TYPES; t++) {
		if (!tree_is_empty(&registry[t].head))
			obj_registry_dump_leaks();
	}
}

#endif

bool obj_registry_enable_debugging_option(const char *option, size_t l)
{
#ifndef DEBUG_OBJECT_POSSIBLE
	int obj_registry_active = 0;
#endif
	if (!option)
		obj_registry_active = -1;
	else if (l == 5 && !strncmp(option, "mutex", l))
		obj_registry_active |= 1 << OBJ_TYPE_MUTEX;
	else if (l == 4 && !strncmp(option, "cond", l))
		obj_registry_active |= 1 << OBJ_TYPE_COND;
	else if (l == 6 && !strncmp(option, "thread", l))
		obj_registry_active |= 1 << OBJ_TYPE_THREAD;
	else if (l == 3 && !strncmp(option, "tls", l))
		obj_registry_active |= 1 << OBJ_TYPE_TLS;
	else if (l == 7 && !strncmp(option, "handles", l))
		obj_registry_active |= 1 << OBJ_TYPE_HANDLE;
	else if (l == 7 && !strncmp(option, "objects", l))
		obj_registry_active = -1;
	else
		return false;
	return true;
}
