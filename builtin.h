/*
 * Copyright (C) 2024, 2025 Mikulas Patocka
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

#ifndef AJLA_BUILTIN_H
#define AJLA_BUILTIN_H

#include "md.h"

extern const char *builtin_lib_path;

void builtin_find_function(const uint8_t *path, size_t path_len, size_t n_entries, const pcode_t *entries, const pcode_t **start, size_t *size);
bool builtin_find_spec_function(struct module_designator *md, struct function_designator *fd, const pcode_t **start, size_t *size);

void builtin_init(void);
void builtin_done(void);

#endif
