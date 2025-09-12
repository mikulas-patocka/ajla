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

#ifndef AJLA_IPFN_H
#define AJLA_IPFN_H

#include "data.h"
#include "ipunalg.h"

#define eval_both				name(eval_both)
#define ipret_fill_function_reference_from_slot	name(ipret_fill_function_reference_from_slot)
#define thunk_fixed_operator			name(thunk_fixed_operator)
#define is_thunk_operator			name(is_thunk_operator)
#define thunk_get_param				name(thunk_get_param)
#define ipret_system_property			name(ipret_system_property)
#define ipret_get_system_property		name(ipret_get_system_property)
#define thunk_int_binary_operator		name(thunk_int_binary_operator)
#define thunk_int_binary_logical_operator	name(thunk_int_binary_logical_operator)
#define thunk_int_unary_operator		name(thunk_int_unary_operator)
#define ipret_int_ldc_long			name(ipret_int_ldc_long)
#define convert_fixed_to_mpint			name(convert_fixed_to_mpint)
#define convert_real_to_mpint			name(convert_real_to_mpint)
#define thunk_convert				name(thunk_convert)
#define thunk_bool_operator			name(thunk_bool_operator)
#define thunk_bool_jump				name(thunk_bool_jump)
#define ipret_copy_variable			name(ipret_copy_variable)
#define ipret_copy_variable_to_pointer		name(ipret_copy_variable_to_pointer)
#define ipret_call_cache			name(ipret_call_cache)
#define ipret_get_index				name(ipret_get_index)
#define ipret_record_load_create_thunk		name(ipret_record_load_create_thunk)
#define ipret_option_load_create_thunk		name(ipret_option_load_create_thunk)
#define ipret_array_load_create_thunk		name(ipret_array_load_create_thunk)
#define thunk_option_test			name(thunk_option_test)
#define thunk_option_ord			name(thunk_option_ord)
#define ipret_array_len				name(ipret_array_len)
#define ipret_array_len_greater_than		name(ipret_array_len_greater_than)
#define ipret_array_sub				name(ipret_array_sub)
#define ipret_array_skip			name(ipret_array_skip)
#define ipret_array_append			name(ipret_array_append)
#define ipret_array_append_one_flat		name(ipret_array_append_one_flat)
#define ipret_array_append_one			name(ipret_array_append_one)
#define ipret_array_flatten			name(ipret_array_flatten)
#define ipret_prefetch_functions		name(ipret_prefetch_functions)
#define ipret_break_waiting_chain		name(ipret_break_waiting_chain)
#define ipret_tick				name(ipret_tick)
#define upcall_vector				name(upcall_vector)


#if ARG_MODE_N >= 3
#define max_param_size(n)	((n) * 2)
#define get_max_param(ip, n)	get_unaligned_32(&(ip)[(n) * 2])
#else
#define max_param_size(n)	(n)
#define get_max_param(ip, n)	((ip)[n])
#endif
#define get_max_i_param(ip, n)	get_max_param(ip + 1, n)


extern bool ipret_strict_calls;
extern bool ipret_is_privileged;
extern bool ipret_sandbox;
extern bool ipret_compile;
extern bool ipret_noinline;
extern bool ipret_verify_light;
extern uint32_t ipret_verify_timeout;

void eval_both(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2);

void attr_hot_fastcall ipret_fill_function_reference_from_slot(struct data *function_reference, arg_t a, frame_s *fp, frame_t slot, bool deref);

void * attr_hot_fastcall thunk_fixed_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag);
void * attr_hot_fastcall is_thunk_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r, unsigned strict_flag);
void * attr_hot_fastcall thunk_get_param(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r, unsigned strict_flag, unsigned mode);
int_default_t ipret_system_property(int_default_t idx);
void * attr_hot_fastcall ipret_get_system_property(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r);

void * attr_hot_fastcall thunk_int_binary_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag, bool (attr_fastcall *do_op)(const mpint_t *op1, const mpint_t *op2, mpint_t *res, ajla_error_t *err));
void * attr_hot_fastcall thunk_int_binary_logical_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag, bool (attr_fastcall *do_op)(const mpint_t *op1, const mpint_t *op2, ajla_flat_option_t *res, ajla_error_t *err));
void * attr_hot_fastcall thunk_int_unary_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r, unsigned strict_flag, bool (attr_fastcall *do_op)(const mpint_t *op1, mpint_t *res, ajla_error_t *err));
ip_t attr_hot_fastcall ipret_int_ldc_long(frame_s *fp, frame_t slot, const code_t *ip);
pointer_t attr_fastcall convert_fixed_to_mpint(uintbig_t val, bool uns);
pointer_t attr_fastcall convert_real_to_mpint(frame_s *fp, frame_t src_slot, const struct type *src_type);
void * attr_hot_fastcall thunk_convert(frame_s *fp, const code_t *ip, frame_t src_slot, frame_t dest_slot, unsigned strict_flag);

void * attr_hot_fastcall thunk_bool_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag);
void * attr_hot_fastcall thunk_bool_jump(frame_s *fp, const code_t *ip, frame_t slot);

void attr_fastcall ipret_copy_variable(frame_s *src_fp, frame_t src_slot, frame_s *dst_fp, frame_t dst_slot, bool deref);
pointer_t ipret_copy_variable_to_pointer(frame_s *src_fp, frame_t src_slot, bool deref);

struct ipret_call_cache_arg {
	struct function_argument *f_arg;
	frame_t slot;
	bool deref;
	bool need_free_ptr;
	pointer_t ptr;
};
void * attr_fastcall ipret_call_cache(frame_s *fp, const code_t *ip, pointer_t *direct_function, struct ipret_call_cache_arg *arguments, frame_t *return_values, frame_t free_fn_slot);

void * attr_hot_fastcall ipret_get_index(frame_s *fp, const code_t *ip, frame_s *fp_slot, frame_t slot, bool *is_negative, array_index_t *idx, pointer_t *thunk argument_position);

void * attr_hot_fastcall ipret_record_load_create_thunk(frame_s *fp, const code_t *ip, frame_t record, frame_t record_slot, frame_t result_slot);
void * attr_hot_fastcall ipret_option_load_create_thunk(frame_s *fp, const code_t *ip, frame_t option, frame_t option_idx, frame_t result_slot);
void * attr_hot_fastcall thunk_option_test(frame_s *fp, const code_t *ip, frame_t slot_1, ajla_option_t option, frame_t slot_r);
void * attr_hot_fastcall thunk_option_ord(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r);
void * attr_hot_fastcall ipret_array_load_create_thunk(frame_s *fp, const code_t *ip, frame_t array, frame_t index, frame_t result_slot);
void * attr_hot_fastcall ipret_array_len(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, unsigned flags);
void * attr_hot_fastcall ipret_array_len_greater_than(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, frame_t l, unsigned flags);
void * attr_hot_fastcall ipret_array_sub(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, frame_t slot_start, frame_t slot_end, unsigned flags);
void * attr_hot_fastcall ipret_array_skip(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, frame_t slot_start, unsigned flags);
void * attr_hot_fastcall ipret_array_append(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, frame_t slot_2, unsigned flags);
void * attr_hot_fastcall ipret_array_append_one_flat(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, frame_t slot_2, unsigned flags);
void * attr_hot_fastcall ipret_array_append_one(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, frame_t slot_2, unsigned flags);
void * attr_fastcall ipret_array_flatten(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, unsigned flags);

void attr_fastcall ipret_prefetch_functions(struct data *function);
bool attr_fastcall ipret_break_waiting_chain(frame_s *fp, ip_t ip);
void * attr_hot_fastcall ipret_tick(frame_s *fp, const code_t *ip);

#endif
