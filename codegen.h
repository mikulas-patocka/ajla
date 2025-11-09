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

#ifndef AJLA_CODEGEN_H
#define AJLA_CODEGEN_H

#include "data.h"

extern const char *dump_code;

#ifdef HAVE_CODEGEN

#define codegen_fn			name(codegen_fn)
#define codegen_free			name(codegen_free)
#define codegen_entry			name(codegen_entry)
#define codegen_callback_init		name(codegen_callback_init)
#define codegen_callback_done		name(codegen_callback_done)

#if !defined(ARCH_IA64)
#define HAVE_CODEGEN_CALLBACK
#endif

struct codegen_callback {
	void *code;
	size_t code_size;
	void *fn;
	uintptr_t stub[4];
};

void *codegen_fn(frame_s *fp, const code_t *ip, union internal_arg ia[]);
void codegen_free(struct data *codegen);
typedef code_return_t (*codegen_type)(frame_s *, struct cg_upcall_vector_s *, tick_stamp_t, void *);
extern codegen_type codegen_entry;

bool codegen_callback_init(struct codegen_callback *cb, void (*callback)(void *ptr), void *ptr, ajla_error_t *err);
void codegen_callback_done(struct codegen_callback *cb);

#endif

#endif
