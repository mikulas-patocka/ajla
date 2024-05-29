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

#ifndef AJLA_CODEGEN_H
#define AJLA_CODEGEN_H

#include "data.h"

#ifdef HAVE_CODEGEN

#define codegen_fn			name(codegen_fn)
#define codegen_free			name(codegen_free)
#define codegen_entry			name(codegen_entry)

void *codegen_fn(frame_s *fp, const code_t *ip, union internal_arg ia[]);
void codegen_free(struct data *codegen);
typedef code_return_t (*codegen_type)(frame_s *, struct cg_upcall_vector_s *, tick_stamp_t, void *);
extern codegen_type codegen_entry;

#endif

#endif
