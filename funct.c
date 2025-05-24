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

#ifndef FILE_OMIT

#include "layout.h"
#include "data.h"
#include "code-op.h"
#include "task.h"

#include "funct.h"

#define N_ARGUMENTS			1
#define N_RETURN_VALUES			1
#define N_SLOTS				2

shared_var uchar_efficient_t function_slots[N_SLOTS];
#define FUNCTION_CALL_SLOT		(function_slots[0])
#define FUNCTION_RETURN_SLOT		(function_slots[1])

shared_var uchar_efficient_t function_ip_return;
shared_var uchar_efficient_t function_ip_eval;

static pointer_t internal_function_ptr;
#define internal_function		pointer_get_data(internal_function_ptr)

void * attr_fastcall function_call_internal(frame_s *fp, const code_t *ip)
{
	struct data *in;
	void *ret;

	in = pointer_get_data(*frame_pointer(fp, FUNCTION_CALL_SLOT));

	ret = da(in,internal)->fn(fp, ip, da(in,internal)->arguments);

	return ret;
}

static void function_free_argument(frame_s *fp)
{
	frame_free_and_clear(fp, FUNCTION_CALL_SLOT);
}

static void * function_jump_to(frame_s *fp, ip_t ip)
{
	struct execution_control *ex = frame_execution_control(fp);
	ex->current_frame = fp;
	ex->current_ip = ip;
	return ex;
}

void * attr_fastcall function_return(frame_s *fp, pointer_t ptr)
{
	function_free_argument(fp);
	frame_set_pointer(fp, FUNCTION_RETURN_SLOT, ptr);
	return function_jump_to(fp, function_ip_return);
}

static struct data *data_alloc_internal(void *(*fn)(frame_s *fp, const code_t *ip, union internal_arg arguments[]), unsigned n_arguments, union internal_arg arguments[], ajla_error_t *mayfail)
{
	struct data *in;

	in = data_alloc_flexible(internal, arguments, n_arguments, mayfail);
	if (unlikely(!in))
		return NULL;

	da(in,internal)->fn = fn;
	if (n_arguments)
		memcpy(da(in,internal)->arguments, arguments, n_arguments * sizeof(union internal_arg));

	return in;
}

pointer_t attr_fastcall function_build_internal_thunk(void *(*fn)(frame_s *fp, const code_t *ip, union internal_arg arguments[]), unsigned n_arguments, union internal_arg arguments[])
{
	ajla_error_t err;
	struct data *in;
	struct data *function_reference;
	struct thunk *result;

	in = data_alloc_internal(fn, n_arguments, arguments, &err);
	if (unlikely(!in))
		goto exception_err;

	function_reference = data_alloc_function_reference_mayfail(1, &err pass_file_line);
	if (unlikely(!function_reference)) {
		data_dereference(in);
		goto exception_err;
	}
	da(function_reference,function_reference)->is_indirect = false;
	da(function_reference,function_reference)->u.direct = &internal_function_ptr;

	da(function_reference,function_reference)->arguments[0].tag = TYPE_TAG_unknown;
	da(function_reference,function_reference)->arguments[0].u.ptr = pointer_data(in);

	if (unlikely(!thunk_alloc_function_call(pointer_data(function_reference), 1, &result, &err))) {
		data_dereference(function_reference);
		goto exception_err;
	}

	return pointer_thunk(result);

exception_err:
	return pointer_error(err, NULL, NULL pass_file_line);
}

struct execution_control *function_evaluate_prepare(ajla_error_t *mayfail)
{
	struct execution_control *ex;
	frame_s *fp;

	ex = execution_control_alloc(mayfail);
	if (!ex)
		goto fail;

	fp = stack_alloc(ex, internal_function, mayfail);
	if (unlikely(!fp))
		goto fail_free_ex;

	ex->current_frame = fp;
	frame_init(fp, internal_function, 0, CALL_MODE_NORMAL);

	ex->current_ip = function_ip_eval;
	ex->thunk = NULL;

	return ex;

fail_free_ex:
	execution_control_free(ex);
fail:
	return NULL;
}

void function_evaluate_submit(struct execution_control *ex, pointer_t ptr, void (*callback)(void *, pointer_t), void *callback_cookie)
{
	ex->callback = callback;
	ex->callback_cookie = callback_cookie;
	frame_set_pointer(ex->current_frame, FUNCTION_RETURN_SLOT, ptr);
	task_submit(ex, TASK_SUBMIT_MAY_SPAWN);
}

void function_init_common(struct data *fn)
{
	da(fn,function)->loaded_cache = NULL;
	tree_init(&da(fn,function)->cache);
	store_relaxed(&da(fn,function)->profiling_counter, 0);
	store_relaxed(&da(fn,function)->call_counter, 0);
	da(fn,function)->is_saved = false;
}

void name(function_init)(void)
{
	struct layout *layout;
	struct data *ft, *int_fn;
	frame_t n_slots;
	struct local_variable *lv;
	struct local_arg *ar;
	arg_t ia;
	ip_t ip;
	ip_t code_size = 6;

	layout = layout_start(slot_bits, frame_flags_per_slot_bits, frame_align, frame_offset, NULL);
	for (ia = 0; ia < N_SLOTS; ia++) {
		layout_add(layout, 1, 1, NULL);
	}
	layout_compute(layout, false, NULL);

	ft = data_alloc_flexible(function_types, types, 0, NULL);
	da(ft,function_types)->n_types = 0;

	int_fn = data_alloc_flexible(function, local_directory, 0, NULL);

	n_slots = layout_size(layout);
	da(int_fn,function)->frame_slots = frame_offset / slot_size + n_slots;
	da(int_fn,function)->n_bitmap_slots = bitmap_slots(n_slots);
	da(int_fn,function)->n_arguments = N_ARGUMENTS;
	da(int_fn,function)->n_return_values = N_RETURN_VALUES;
	da(int_fn,function)->code = mem_alloc_array_mayfail(mem_alloc_mayfail, code_t *, 0, 0, code_size, sizeof(code_t), NULL);
	da(int_fn,function)->code_size = code_size;
	da(int_fn,function)->local_variables = lv = mem_alloc_array_mayfail(mem_calloc_mayfail, struct local_variable *, 0, 0, n_slots, sizeof(struct local_variable), NULL);
	da(int_fn,function)->local_variables_flags = mem_alloc_array_mayfail(mem_calloc_mayfail, struct local_variable_flags *, 0, 0, n_slots, sizeof(struct local_variable_flags), NULL);
	da(int_fn,function)->args = ar = mem_alloc(struct local_arg *, N_ARGUMENTS * sizeof(struct local_arg));
	da(int_fn,function)->types_ptr = pointer_data(ft);
	da(int_fn,function)->record_definition = NULL;
	da(int_fn,function)->function_name = str_dup("internal_function", -1, NULL);
	da(int_fn,function)->lp = NULL;
	da(int_fn,function)->lp_size = 0;
	da(int_fn,function)->local_directory_size = 0;
#ifdef HAVE_CODEGEN
	da(int_fn,function)->codegen = pointer_thunk(thunk_alloc_exception_error(error_ajla(EC_ASYNC, AJLA_ERROR_NOT_SUPPORTED), NULL, NULL, NULL pass_file_line));
	store_relaxed(&da(int_fn,function)->codegen_failed, 0);
#endif
	function_init_common(int_fn);
	if (profiling_escapes)
		da(int_fn,function)->escape_data = mem_alloc_array_mayfail(mem_calloc_mayfail, struct escape_data *, 0, 0, code_size, sizeof(struct escape_data), NULL);
	da(int_fn,function)->leaf = true;

	for (ia = 0; ia < N_SLOTS; ia++) {
		function_slots[ia] = layout_get(layout, ia);
		lv[function_slots[ia]].type = type_get_unknown();
		if (likely(ia < N_ARGUMENTS)) {
			ar[ia].slot = function_slots[ia];
			ar[ia].may_be_borrowed = false;
			ar[ia].may_be_flat = false;
		}
	}

	ip = 0;
#define gen_code(n)	(da(int_fn,function)->code[ip++] = (n))
	gen_code(OPCODE_INTERNAL_FUNCTION);
	gen_code(OPCODE_UNREACHABLE);
	function_ip_return = ip;
	gen_code(OPCODE_RETURN);
	if (N_RETURN_VALUES != 1)
		internal(file_line, "function_init: N_RETURN_VALUES is %d", N_RETURN_VALUES);
	gen_code(FUNCTION_RETURN_SLOT | (OPCODE_FLAG_FREE_ARGUMENT << 8));
	function_ip_eval = ip;
	gen_code(OPCODE_EXIT_THREAD);
	gen_code(FUNCTION_RETURN_SLOT);
#undef gen_code

	if (unlikely(ip != code_size))
		internal(file_line, "function_init: code size mismatch: %"PRIuMAX" != %"PRIuMAX"", (uintmax_t)ip, (uintmax_t)code_size);

	internal_function_ptr = pointer_data(int_fn);

	layout_free(layout);
}

void name(function_done)(void)
{
	pointer_dereference(internal_function_ptr);
	pointer_poison(&internal_function_ptr);
}

#endif
