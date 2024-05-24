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

#ifndef AJLA_OBJ_REG_H
#define AJLA_OBJ_REG_H

typedef enum {
	OBJ_TYPE_MUTEX,
	OBJ_TYPE_RWMUTEX,
	OBJ_TYPE_COND,
	OBJ_TYPE_THREAD,
	OBJ_TYPE_TLS,
	OBJ_TYPE_HANDLE,
	N_OBJ_TYPES
} obj_type;

typedef uintptr_t obj_id;

bool obj_registry_enable_debugging_option(const char *option, size_t l);

#if !defined(DEBUG_OBJECT_POSSIBLE)

#define obj_registry_start_recursion()		do { } while (0)
#define obj_registry_end_recursion()		do { } while (0)

#define obj_registry_insert(type, id, pos)	do { } while (0)
#define obj_registry_remove(type, id, pos)	do { } while (0)
#define obj_registry_verify(type, id, pos)	do { obj_type avoid_warning = (id); avoid_warning = avoid_warning + 1; } while (0)

#define obj_registry_init()			do { } while (0)
#define obj_registry_init_multithreaded()	do { } while (0)
#define obj_registry_done_multithreaded()	do { } while (0)
#define obj_registry_done()			do { } while (0)

#else

void obj_registry_insert(obj_type type, obj_id id, position_t position);
void obj_registry_remove(obj_type type, obj_id id, position_t position);
void obj_registry_verify(obj_type type, obj_id id, position_t position);

bool obj_registry_start_recursion(void);
void obj_registry_end_recursion(void);

void obj_registry_init(void);
void obj_registry_init_multithreaded(void);
void obj_registry_done_multithreaded(void);
void obj_registry_done(void);

#endif

#endif
