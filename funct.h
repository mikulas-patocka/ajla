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

#ifndef AJLA_FUNCT_H
#define AJLA_FUNCT_H

#include "data.h"

#define function_build_internal_thunk		name(function_build_internal_thunk)
#define function_evaluate_prepare		name(function_evaluate_prepare)
#define function_evaluate_submit		name(function_evaluate_submit)
#define function_return				name(function_return)
#define function_call_internal			name(function_call_internal)
#define function_init_common			name(function_init_common)

pointer_t attr_fastcall function_build_internal_thunk(void *(*fn)(frame_s *fp, const code_t *ip, union internal_arg arguments[]), unsigned n_arguments, union internal_arg arguments[]);

struct execution_control *function_evaluate_prepare(ajla_error_t *mayfail);
void function_evaluate_submit(struct execution_control *ex, pointer_t ptr, void (*callback)(void *, pointer_t), void *callback_cookie);

void * attr_fastcall function_return(frame_s *fp, pointer_t ptr);

void * attr_fastcall function_call_internal(frame_s *fp, const code_t *ip);

void function_init_common(struct data *fn);

#endif
