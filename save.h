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

#ifndef AJLA_SAVE_H
#define AJLA_SAVE_H

#include "data.h"
#include "module.h"

#define save_prepare			name(save_prepare)
#define save_start_function		name(save_start_function)
#define save_cache_entry		name(save_cache_entry)
#define save_finish_function		name(save_finish_function)
#define save_find_function_descriptor	name(save_find_function_descriptor)
#define save_register_dependence	name(save_register_dependence)

void save_prepare(void);
void save_start_function(struct data *d, bool new_cache);
void save_cache_entry(struct data *d, struct cache_entry *ce);
void save_finish_function(struct data *d);

struct function_descriptor {
	struct data *data_saved_cache;
	code_t *code;
	ip_t code_size;
	const struct local_variable_flags *local_variables_flags;
	frame_t n_slots;
	struct data *types;
	struct line_position *lp;
	size_t lp_size;
	void *unoptimized_code_base;
	size_t unoptimized_code_size;
	size_t *entries;
	size_t n_entries;
	struct trap_record *trap_records;
	size_t trap_records_size;
	struct module_designator *md;
	struct function_designator *fd;
};

struct function_descriptor *save_find_function_descriptor(const struct module_designator *md, const struct function_designator *fd);

void save_register_dependence(const char *path_name);

#endif
