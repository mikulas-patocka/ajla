/*
 * Copyright (C) 2024 - 2026 Mikulas Patocka
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
#include "md.h"

#define start_fn			name(start_fn)
#define module_load_function		name(module_load_function)
#define module_load_function_reference	name(module_load_function_reference)
#define module_finish_functions		name(module_finish_functions)

extern struct function_pointer *start_fn;

struct function_pointer *module_load_function(const struct module_designator *md, const struct function_designator *fd, ajla_error_t *mayfail);
pointer_t *module_load_function_reference(const struct module_designator *md, const struct function_designator *fd, bool optimizer, ajla_error_t *mayfail);
void module_finish_functions(bool compsave);

#endif
