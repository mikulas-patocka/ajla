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
#define save_cache_entry		name(save_cache_entry)
#define save_finish_function		name(save_finish_function)
#define save_find_cache			name(save_find_cache)
#define save_register_dependence	name(save_register_dependence)

void save_prepare(void);
void save_cache_entry(struct data *d, struct cache_entry *ce);
void save_finish_function(struct data *d);

struct data *save_find_cache(const struct module_designator *md, const struct function_designator *fd);

void save_register_dependence(const char *path_name);

#endif
