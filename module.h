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

#ifndef AJLA_MODULE_H
#define AJLA_MODULE_H

#include "data.h"

#define start_fn			name(start_fn)
#define module_designator_alloc		name(module_designator_alloc)
#define module_designator_free		name(module_designator_free)
#define module_designator_length	name(module_designator_length)
#define module_designator_compare	name(module_designator_compare)
#define function_designator_alloc	name(function_designator_alloc)
#define function_designator_alloc_single name(function_designator_alloc_single)
#define function_designator_free	name(function_designator_free)
#define function_designator_length	name(function_designator_length)
#define function_designator_copy	name(function_designator_copy)
#define function_designator_compare	name(function_designator_compare)
#define module_load_function		name(module_load_function)

extern pointer_t *start_fn;

struct module_designator {
	size_t path_len;
	unsigned path_idx;
	bool program;
	uint8_t path[FLEXIBLE_ARRAY];
};

struct module_designator *module_designator_alloc(unsigned path_idx, const uint8_t *path, size_t path_len, bool program, ajla_error_t *mayfail);
void module_designator_free(struct module_designator *md);
size_t module_designator_length(const struct module_designator *md);
int module_designator_compare(const struct module_designator *md1, const struct module_designator *md2);

struct function_designator {
	size_t n_entries;
	size_t n_spec_data;
	pcode_t entries[FLEXIBLE_ARRAY];
};

struct function_designator *function_designator_alloc(const pcode_t *p, ajla_error_t *mayfail);
struct function_designator *function_designator_alloc_single(pcode_t idx, ajla_error_t *mayfail);
void function_designator_free(struct function_designator *fd);
size_t function_designator_length(const struct function_designator *fd);
struct function_designator *function_designator_copy(const struct function_designator *fd, ajla_error_t *mayfail);
int function_designator_compare(const struct function_designator *fd1, const struct function_designator *fd2);

/* returns a pointer to pointer_t */
pointer_t *module_load_function(const struct module_designator *md, const struct function_designator *fd, bool get_fn, bool optimizer, ajla_error_t *mayfail);

#endif
