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

#include "ajla.h"

#ifndef FILE_OMIT

#include "args.h"
#include "mem_al.h"
#include "data.h"
#include "array.h"
#include "arrayu.h"
#include "task.h"
#include "pcode.h"
#include "ipio.h"
#include "funct.h"
#include "os.h"

#include "ipfn.h"

shared_var bool ipret_strict_calls shared_init(false);
shared_var bool ipret_is_privileged shared_init(false);
shared_var bool ipret_sandbox shared_init(false);
shared_var bool ipret_compile shared_init(false);
shared_var bool ipret_noinline shared_init(false);
shared_var bool ipret_verify_light shared_init(false);
shared_var uint32_t ipret_verify_timeout shared_init(0);

static const timestamp_t break_ticks = 1;

void eval_both(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2)
{
	struct execution_control *ex = frame_execution_control(fp);
	if (slot_1 != NO_FRAME_T) {
		if (!frame_variable_is_flat(fp, slot_1)) {
			pointer_t *ptr = frame_pointer(fp, slot_1);
			struct data attr_unused *result;
			pointer_follow(ptr, true, result, PF_PREPARE0, fp, ip,
				SUBMIT_EX(ex_); goto brk1,
				break);
		}
		execution_control_acquire(ex);
	}
brk1:
	if (slot_2 != NO_FRAME_T) {
		if (!frame_variable_is_flat(fp, slot_2)) {
			pointer_t *ptr = frame_pointer(fp, slot_2);
			struct data attr_unused *result;
			pointer_follow(ptr, true, result, PF_PREPARE1, fp, ip,
				SUBMIT_EX(ex_); goto brk2,
				break);
		}
		execution_control_acquire(ex);
	}
brk2:
	pointer_follow_wait(fp, ip);
}

static void pointer_copy_owned(frame_s *fp, frame_t src_slot, frame_t dest_slot)
{
	pointer_t ptr;
	if (dest_slot == src_slot)
		return;
	ptr = *frame_pointer(fp, src_slot);
	frame_free_and_set_pointer(fp, dest_slot, ptr);
	pointer_reference_owned(ptr);
}

void attr_hot_fastcall ipret_fill_function_reference_from_slot(struct data *function_reference, arg_t a, frame_s *fp, frame_t slot, bool deref)
{
	const struct type *type;
	pointer_t ptr;

	if (unlikely(!function_reference)) {
		if (deref)
			frame_free_and_clear(fp, slot);
		return;
	}

	ajla_assert(a < da(function_reference,function_reference)->n_curried_arguments, (file_line, "ipret_fill_function_reference_from_slot: invalid argument %"PRIuMAX" (%"PRIuMAX" arguments)", (uintmax_t)a, (uintmax_t)da(function_reference,function_reference)->n_curried_arguments));

	if (frame_variable_is_flat(fp, slot)) {
		type = frame_get_type_of_local(fp, slot);
		data_fill_function_reference_flat(function_reference, a, type, frame_var(fp, slot));
	} else {
		ptr = frame_get_pointer_reference(fp, slot, deref);
		data_fill_function_reference(function_reference, a, ptr);
	}
}


static struct thunk *build_thunk(pointer_t *fn_ptr, arg_t n_arguments, struct data **function_reference)
{
	struct thunk *result;
	ajla_error_t err;

	*function_reference = data_alloc_function_reference_mayfail(n_arguments, &err pass_file_line);
	if (unlikely(!*function_reference))
		goto fail_err;
	da(*function_reference,function_reference)->is_indirect = false;
	da(*function_reference,function_reference)->u.direct = fn_ptr;

	if (unlikely(!thunk_alloc_function_call(pointer_data(*function_reference), 1, &result, &err))) {
		data_dereference(*function_reference);
		goto fail_err;
	}

	return result;

fail_err:
	*function_reference = NULL;
	return thunk_alloc_exception_error(err, NULL, NULL, NULL pass_file_line);
}

static void *ipret_op_build_thunk(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag)
{
	unsigned flags;
	pointer_t *fn_ptr;
	code_t code;
	void *ex;
	struct data *function_reference;
	struct thunk *result;
	frame_t slot_1_eval = NO_FRAME_T;
	frame_t slot_2_eval = NO_FRAME_T;

	code = *ip % OPCODE_MODE_MULT;
	if (code == OPCODE_IS_EXCEPTION)
		strict_flag |= FLAG_TESTING_FOR_EXCEPTION;
	if (code >= OPCODE_FIXED_OP + zero && code < OPCODE_FIXED_OP + OPCODE_FIXED_TYPE_MULT * TYPE_FIXED_N) {
		code_t op = (code - OPCODE_FIXED_OP) % OPCODE_FIXED_TYPE_MULT;
		if (op >= OPCODE_FIXED_OP_C && op < OPCODE_FIXED_OP_UNARY) {
			code -= OPCODE_FIXED_OP_C;
		}
	}
	if (code >= OPCODE_INT_OP && code < OPCODE_INT_OP + OPCODE_INT_TYPE_MULT * TYPE_INT_N) {
		code_t op = (code - OPCODE_INT_OP) % OPCODE_INT_TYPE_MULT;
		if (op >= OPCODE_INT_OP_C && op < OPCODE_INT_OP_UNARY) {
			code -= OPCODE_INT_OP_C;
		}
	}
	if (code >= OPCODE_REAL_OP && code < OPCODE_REAL_OP + OPCODE_REAL_TYPE_MULT * TYPE_REAL_N) {
		code_t op = (code - OPCODE_REAL_OP) % OPCODE_REAL_TYPE_MULT;
		if (op == OPCODE_REAL_OP_is_exception || op == OPCODE_REAL_OP_is_exception_alt1 || op == OPCODE_REAL_OP_is_exception_alt2)
			strict_flag |= FLAG_TESTING_FOR_EXCEPTION;
	}

	if (frame_test_flag(fp, slot_1) && pointer_is_thunk(*frame_pointer(fp, slot_1))) {
		pointer_follow_thunk_noeval(frame_pointer(fp, slot_1),
			return POINTER_FOLLOW_THUNK_RETRY,
			if (strict_flag & FLAG_TESTING_FOR_EXCEPTION) {
				frame_free(fp, slot_r);
				barrier_aliasing();
				*frame_slot(fp, slot_r, ajla_flat_option_t) = 1;
				barrier_aliasing();
				return POINTER_FOLLOW_THUNK_GO;
			}
			if (!(strict_flag & FLAG_NEED_BOTH_EXCEPTIONS_TO_FAIL)) {
				pointer_copy_owned(fp, slot_1, slot_r);
				return POINTER_FOLLOW_THUNK_GO;
			}
			strict_flag |= FLAG_FIRST_EXCEPTION;
			break,
			slot_1_eval = slot_1; break
		);
	}

	if (slot_2 != NO_FRAME_T && !frame_t_is_const(slot_2) && frame_test_flag(fp, slot_2) && pointer_is_thunk(*frame_pointer(fp, slot_2))) {
		pointer_follow_thunk_noeval(frame_pointer(fp, slot_2),
			return POINTER_FOLLOW_THUNK_RETRY,
			if ((strict_flag & (FLAG_NEED_BOTH_EXCEPTIONS_TO_FAIL | FLAG_FIRST_EXCEPTION)) != FLAG_NEED_BOTH_EXCEPTIONS_TO_FAIL) {
				pointer_copy_owned(fp, slot_2, slot_r);
				return POINTER_FOLLOW_THUNK_GO;
			}
			break,
			slot_2_eval = slot_2; break
		);
	}

	if (strict_flag & OPCODE_OP_FLAG_STRICT) {
		if (slot_1_eval != NO_FRAME_T || slot_2_eval != NO_FRAME_T) {
			eval_both(fp, ip, slot_1_eval, slot_2_eval);
			return POINTER_FOLLOW_THUNK_EXIT;
		}
		return POINTER_FOLLOW_THUNK_RETRY;
	}

	flags = 0;
	if (slot_2 == NO_FRAME_T) {
		flags |= PCODE_FIND_OP_UNARY;
		if (type_is_equal(frame_get_type_of_local(fp, slot_1), type_get_int(INT_DEFAULT_N)) &&
		   !type_is_equal(frame_get_type_of_local(fp, slot_r), type_get_int(INT_DEFAULT_N)))
			flags |= PCODE_CONVERT_FROM_INT;
	}
	if (code == OPCODE_IS_EXCEPTION)
		ex = pcode_find_is_exception(fp, ip, &fn_ptr);
	else if (code == OPCODE_EXCEPTION_CLASS || code == OPCODE_EXCEPTION_TYPE || code == OPCODE_EXCEPTION_AUX)
		ex = pcode_find_get_exception(code - OPCODE_EXCEPTION_CLASS, fp, ip, &fn_ptr);
	else
		ex = pcode_find_op_function(frame_get_type_of_local(fp, slot_1), frame_get_type_of_local(fp, slot_r), code, flags, fp, ip, &fn_ptr);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, slot_2 != NO_FRAME_T ? 2 : 1, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, slot_1, false);
	if (slot_2 != NO_FRAME_T) {
		ajla_error_t err;
		struct data *d;
		const struct type *type = frame_get_type_of_local(fp, slot_1);
		if (!frame_t_is_const(slot_2)) {
			ipret_fill_function_reference_from_slot(function_reference, 1, fp, slot_2, false);
		} else {
			int32_t c = frame_t_get_const(slot_2);
			union {
#define f(n, s, u, sz, bits)						\
				s cat(int_val_,bits);
				for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits)						\
				s cat(sfixed_val_,bits);		\
				u cat(ufixed_val_,bits);
				for_all_fixed(f)
#undef f
				unsigned char flat[1 << (TYPE_INT_N - 1)];
			} un;
			switch (type->tag) {
#define f(n, s, u, sz, bits)						\
				case TYPE_TAG_integer + n:		\
					un.cat(int_val_,bits) = c;	\
					if (unlikely(c != un.cat(int_val_,bits)))\
						goto do_mpint;		\
					break;				\
				case TYPE_TAG_fixed + 2 * n + TYPE_TAG_fixed_signed:\
					un.cat(sfixed_val_,bits) = c;	\
					if (unlikely(c != un.cat(sfixed_val_,bits)))\
						internal(file_line, "ipret_op_build_thunk: invalid constant %ld for type %u", (long)c, type->tag);\
					break;				\
				case TYPE_TAG_fixed + 2 * n + TYPE_TAG_fixed_unsigned:\
					un.cat(ufixed_val_,bits) = c;	\
					if (unlikely(c < 0) || unlikely((u)c != un.cat(ufixed_val_,bits)))\
						internal(file_line, "ipret_op_build_thunk: invalid constant %ld for type %u", (long)c, type->tag);\
					break;
				for_all_fixed(f)
#undef f
				default:
					internal(file_line, "ipret_op_build_thunk: invalid type tag %u", type->tag);
			}
			d = data_alloc_flat_mayfail(type->tag, un.flat, type->size, &err pass_file_line);
			if (unlikely(!d)) {
				data_fill_function_reference(function_reference, 1, pointer_error(err, NULL, NULL pass_file_line));
			} else {
				data_fill_function_reference(function_reference, 1, pointer_data(d));
			}
		}
		if (false) {
do_mpint:
			d = data_alloc_longint_mayfail(32, &err pass_file_line);
			if (unlikely(!d)) {
				data_fill_function_reference(function_reference, 1, pointer_error(err, NULL, NULL pass_file_line));
			} else {
				int32_t c = frame_t_get_const(slot_2);
				mpint_import_from_variable(&da(d,longint)->mp, int32_t, c);
				data_fill_function_reference(function_reference, 1, pointer_data(d));
			}
		}
	}

	frame_free_and_set_pointer(fp, slot_r, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

#define UNBOX_THUNK		1
#define UNBOX_DID_SOMETHING	2
#define UNBOX_LONGINT		4
static int attr_hot_fastcall ipret_unbox_value(frame_s *fp, const struct type *type, frame_t slot)
{
	ajla_assert(TYPE_IS_FLAT(type), (file_line, "ipret_unbox_value: non-flat type %u", type->tag));
	if (frame_test_flag(fp, slot)) {
		pointer_t ptr = *frame_pointer(fp, slot);
		if (pointer_is_thunk(ptr))
			return UNBOX_THUNK;
		if (da_tag(pointer_get_data(ptr)) == DATA_TAG_longint) {
			ajla_assert(TYPE_TAG_IS_INT(type->tag), (file_line, "ipret_unbox_value: unexpected longint, type %u", type->tag));
			return UNBOX_LONGINT;
		}
		memcpy_fast(frame_var(fp, slot), da_flat(pointer_get_data(ptr)), type->size);
		frame_clear_flag(fp, slot);
		pointer_dereference(ptr);
		return UNBOX_DID_SOMETHING;
	}
	return 0;
}

static bool test_and_copy_nan(frame_s attr_unused *fp, const code_t attr_unused *ip,  unsigned char type_tag, frame_t attr_unused slot, frame_t attr_unused slot_r)
{
	switch (type_tag) {
#define f(n, t, nt, pack, unpack)					\
		case TYPE_TAG_real + n: {				\
			t val;						\
			barrier_aliasing();				\
			val = *frame_slot(fp, slot, t);			\
			barrier_aliasing();				\
			if (unlikely(cat(isnan_,t)(val))) {		\
				if (type_tag == frame_get_type_of_local(fp, slot_r)->tag) {\
					barrier_aliasing();		\
					*frame_slot(fp, slot_r, t) = val;\
					barrier_aliasing();		\
				} else {				\
					frame_set_pointer(fp, slot_r, pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_NAN), fp, ip pass_file_line));\
				}					\
				return true;				\
			}						\
			break;						\
		}
		for_all_real(f, for_all_empty)
#undef f
	}
	return false;
}

void * attr_hot_fastcall thunk_fixed_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag)
{
	const struct type *type;
	int converted;

	type = frame_get_type_of_local(fp, slot_1);
	ajla_assert((TYPE_TAG_IS_FIXED(type->tag) || TYPE_TAG_IS_REAL(type->tag)) &&
		    (slot_2 == NO_FRAME_T || frame_t_is_const(slot_2) || frame_get_type_of_local(fp, slot_2) == type),
		    (file_line, "thunk_fixed_operator: invalid types on opcode %04x: %u, %u, %u",
		    *ip,
		    type->tag,
		    slot_2 == NO_FRAME_T || frame_t_is_const(slot_2) ? type->tag : frame_get_type_of_local(fp, slot_2)->tag,
		    frame_get_type_of_local(fp, slot_r)->tag));

	converted = ipret_unbox_value(fp, type, slot_1);
	if (!frame_test_flag(fp, slot_1) && unlikely(test_and_copy_nan(fp, ip, type->tag, slot_1, slot_r)))
		return POINTER_FOLLOW_THUNK_GO;
	if (slot_2 != NO_FRAME_T && !frame_t_is_const(slot_2)) {
		converted |= ipret_unbox_value(fp, type, slot_2);
		if (!frame_test_flag(fp, slot_2) && unlikely(test_and_copy_nan(fp, ip, type->tag, slot_2, slot_r)))
			return POINTER_FOLLOW_THUNK_GO;
	}
	if (converted & UNBOX_THUNK)
		return ipret_op_build_thunk(fp, ip, slot_1, slot_2, slot_r, strict_flag);

	return POINTER_FOLLOW_THUNK_RETRY;
}


void * attr_hot_fastcall is_thunk_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r, unsigned strict_flag)
{
	ajla_flat_option_t value;
	pointer_t *ptr = frame_pointer(fp, slot_1);
	if (!pointer_is_thunk(*ptr)) {
		struct data *d = pointer_get_data(*ptr);
		value = 0;
		if (da_tag(d) == DATA_TAG_flat) {
			value = data_is_nan(da(d,flat)->data_type, da_flat(d));
		}
		goto return_val;
	}

	pointer_follow_thunk_noeval(ptr,
		return POINTER_FOLLOW_THUNK_RETRY,
		value = 1; goto return_val,
		goto create_thunk;
	);

return_val:
	frame_free(fp, slot_r);
	barrier_aliasing();
	*frame_slot(fp, slot_r, ajla_flat_option_t) = value;
	barrier_aliasing();
	return POINTER_FOLLOW_THUNK_GO;

create_thunk:
	return ipret_op_build_thunk(fp, ip, slot_1, NO_FRAME_T, slot_r, strict_flag);
}

void * attr_hot_fastcall thunk_get_param(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r, unsigned strict_flag, unsigned mode)
{
	struct thunk *ex;
	pointer_t *ptr;
	int result;

	ajla_assert(slot_r == slot_1 || !frame_test_flag(fp, slot_r), (file_line, "thunk_get_param: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));

	if (unlikely(!frame_test_flag(fp, slot_1))) {
		const struct type *type;
		type = frame_get_type_of_local(fp, slot_1);
		if (likely(data_is_nan(type->tag, frame_var(fp, slot_1)))) {
have_nan:
			switch (mode) {
				case 0:
					result = EC_SYNC;
					break;
				case 1:
					result = AJLA_ERROR_NAN;
					break;
				case 2:
					result = 0;
					break;
				default:
					internal(file_line, "thunk_get_param: invalid mode %u", mode);
			}
			goto set_result;
		}
		goto not_thunk;
	}

	ptr = frame_pointer(fp, slot_1);
	if (!pointer_is_thunk(*ptr)) {
		struct data *data = pointer_get_data(*ptr);
		if (likely(da_tag(data) == DATA_TAG_flat)) {
			if (likely(data_is_nan(da(data,flat)->data_type, da_flat(data)))) {
				goto have_nan;
			}
		}
		goto not_thunk;
	}
	pointer_follow_thunk_noeval(ptr,
		return POINTER_FOLLOW_THUNK_RETRY,
		goto have_ex,
		goto create_thunk;
	);

have_ex:
	ex = pointer_get_thunk(*ptr);
	switch (mode) {
		case 0:
			result = ex->u.exception.err.error_class;
			break;
		case 1:
			result = ex->u.exception.err.error_type;
			break;
		case 2:
			result = ex->u.exception.err.error_aux;
			break;
		default:
			internal(file_line, "thunk_get_param: invalid mode %u", mode);
	}

set_result:
	frame_free(fp, slot_r);
	barrier_aliasing();
	*frame_slot(fp, slot_r, int_default_t) = result;
	barrier_aliasing();

	return POINTER_FOLLOW_THUNK_GO;

not_thunk:
	frame_free_and_set_pointer(fp, slot_r, pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), fp, ip pass_file_line));

	return POINTER_FOLLOW_THUNK_GO;

create_thunk:
	return ipret_op_build_thunk(fp, ip, slot_1, NO_FRAME_T, slot_r, strict_flag);
}

int_default_t ipret_system_property(int_default_t idx)
{
	int_default_t result;

	switch (idx) {
		case SystemProperty_OS:
#if defined(OS_DOS)
			result = SystemProperty_OS_DOS;
#elif defined(OS_OS2)
			result = SystemProperty_OS_OS2;
#elif defined(OS_CYGWIN)
			result = SystemProperty_OS_Cygwin;
#elif defined(OS_WIN32)
			result = SystemProperty_OS_Windows;
#else
			result = SystemProperty_OS_Posix;
#endif
			break;
#if defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32)
		case SystemProperty_Charset:
			result = os_charset();
			break;
#endif
#if defined(OS_WIN32)
		case SystemProperty_Charset_Console:
			result = os_charset_console();
			break;
#endif
		case SystemProperty_Fixed:
			result = INT_MASK;
			break;
		case SystemProperty_Real:
			result = REAL_MASK;
			break;
		case SystemProperty_Privileged:
			result = ipret_is_privileged;
			break;
		case SystemProperty_Sandbox:
			result = ipret_sandbox;
			break;
		case SystemProperty_Compile:
			result = ipret_compile;
			break;
		case SystemProperty_NoInline:
			result = ipret_noinline;
			break;
		case SystemProperty_Verify_Light:
			result = ipret_verify_light;
			break;
		case SystemProperty_Verify_Timeout:
			result = ipret_verify_timeout;
			break;
		default:
			return -1;
	}

	return result;
}

void * attr_hot_fastcall ipret_get_system_property(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r)
{
	void *ex;
	array_index_t idx_l;
	int_default_t idx, result;
	pointer_t result_ptr;

	ex = ipret_get_index(fp, ip, fp, slot_1, NULL, &idx_l, &result_ptr pass_file_line);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION) {
			frame_free_and_set_pointer(fp, slot_r, result_ptr);
			return POINTER_FOLLOW_THUNK_GO;
		}
	}
	idx = index_to_int(idx_l);
	index_free(&idx_l);

	result = ipret_system_property(idx);

	frame_free(fp, slot_r);
	barrier_aliasing();
	*frame_slot(fp, slot_r, int_default_t) = result;
	barrier_aliasing();

	return POINTER_FOLLOW_THUNK_GO;
}


static bool int_to_mpint(mpint_t *m, const unsigned char *ptr, unsigned intx, ajla_error_t *err)
{
#define f(n, s, u, sz, bits)						\
		case n: {						\
			bool ret;					\
			barrier_aliasing();				\
			ret = cat(mpint_init_from_,s)(m, *cast_ptr(const s *, ptr), err);\
			barrier_aliasing();				\
			return ret;					\
		}
	switch (intx) {
		for_all_int(f, for_all_empty)
		default:
			internal(file_line, "int_to_mpint: invalid type %d", intx);
	}
#undef f
	not_reached();
	return false;
}

static mpint_t * attr_hot_fastcall int_get_mpint(frame_s *fp, frame_t slot, mpint_t *storage, unsigned intx, ajla_error_t *err)
{
	unsigned char *flat;
	if (frame_t_is_const(slot)) {
		if (unlikely(!mpint_init_from_int32_t(storage, frame_t_get_const(slot), err)))
			return NULL;
		return storage;
	}
	if (frame_test_flag(fp, slot)) {
		struct data *d = pointer_get_data(*frame_pointer(fp, slot));
		if (likely(da_tag(d) == DATA_TAG_longint))
			return &da(d,longint)->mp;
		flat = da_flat(d);
	} else {
		flat = frame_var(fp, slot);
	}
	if (unlikely(!int_to_mpint(storage, flat, intx, err)))
		return NULL;
	return storage;
}

static struct data * attr_hot_fastcall int_allocate_result(frame_s *fp, frame_t slot, unsigned long bits, pointer_t *to_free, ajla_error_t *err)
{
	struct data *d;

	*to_free = pointer_empty();

	if (frame_test_and_set_flag(fp, slot)) {
		pointer_t ptr = *frame_pointer(fp, slot);
		if (!pointer_is_thunk(ptr)) {
			d = pointer_get_data(ptr);
			if (da_tag(d) == DATA_TAG_longint && data_is_writable(d))
				return d;
		}
		*to_free = ptr;
	}

	d = data_alloc_longint_mayfail(bits, err pass_file_line);
	if (unlikely(!d)) {
		frame_clear_flag(fp, slot);
		return NULL;
	}
	*frame_pointer(fp, slot) = pointer_data(d);
	return d;
}

void * attr_hot_fastcall thunk_int_binary_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag, bool (attr_fastcall *do_op)(const mpint_t *op1, const mpint_t *op2, mpint_t *res, ajla_error_t *err))
{
	ajla_error_t err;
	const struct type *type;
	unsigned intx;
	int converted;
	mpint_t s1, s2;
	mpint_t *val1, *val2;
	struct data *result;
	pointer_t to_free;

	type = frame_get_type_of_local(fp, slot_1);
	if (!frame_t_is_const(slot_2)) {
		ajla_assert(TYPE_TAG_IS_INT(type->tag) &&
			    frame_get_type_of_local(fp, slot_2) == type &&
			    frame_get_type_of_local(fp, slot_r) == type,
			    (file_line, "thunk_int_binary_operator: invalid types on opcode %04x: %u, %u, %u",
			    *ip,
			    type->tag,
			    frame_get_type_of_local(fp, slot_2)->tag,
			    frame_get_type_of_local(fp, slot_r)->tag));
	} else {
		ajla_assert(TYPE_TAG_IS_INT(type->tag) &&
			    frame_get_type_of_local(fp, slot_r) == type,
			    (file_line, "thunk_int_binary_operator: invalid types on opcode %04x: %u, %u",
			    *ip,
			    type->tag,
			    frame_get_type_of_local(fp, slot_r)->tag));
	}

	converted = 0;

	converted |= ipret_unbox_value(fp, type, slot_1);
	if (!frame_t_is_const(slot_2))
		converted |= ipret_unbox_value(fp, type, slot_2);

	if (converted & UNBOX_THUNK)
		return ipret_op_build_thunk(fp, ip, slot_1, slot_2, slot_r, strict_flag);

	if (converted == UNBOX_DID_SOMETHING)
		return POINTER_FOLLOW_THUNK_RETRY;

	intx = TYPE_TAG_IDX_INT(type->tag);

	if (unlikely(!(val1 = int_get_mpint(fp, slot_1, &s1, intx, &err))))
		goto fail_oom_1;
	if (unlikely(!(val2 = int_get_mpint(fp, slot_2, &s2, intx, &err))))
		goto fail_oom_2;
	if (unlikely(!(result = int_allocate_result(fp, slot_r, maximum(mpint_estimate_bits(val1), mpint_estimate_bits(val2)), &to_free, &err))))
		goto fail_oom_3;
	if (unlikely(!do_op(val1, val2, &da(result,longint)->mp, &err)))
		goto fail_oom_3;
	if (val1 == &s1)
		mpint_free(&s1);
	if (val2 == &s2)
		mpint_free(&s2);
	if (!pointer_is_empty(to_free))
		pointer_dereference(to_free);

	if (mpint_export(&da(result,longint)->mp, frame_var(fp, slot_r), intx, &err)) {
		frame_clear_flag(fp, slot_r);
		data_dereference(result);
	}
	return POINTER_FOLLOW_THUNK_GO;

fail_oom_3:
	if (!pointer_is_empty(to_free))
		pointer_dereference(to_free);
	if (val2 == &s2)
		mpint_free(&s2);
fail_oom_2:
	if (val1 == &s1)
		mpint_free(&s1);
fail_oom_1:
	frame_free_and_set_pointer(fp, slot_r, pointer_error(err, fp, ip pass_file_line));
	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall thunk_int_binary_logical_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag, bool (attr_fastcall *do_op)(const mpint_t *op1, const mpint_t *op2, ajla_flat_option_t *res, ajla_error_t *err))
{
	ajla_error_t err;
	const struct type *type;
	unsigned intx;
	int converted;
	mpint_t s1, s2;
	mpint_t *val1, *val2;

	type = frame_get_type_of_local(fp, slot_1);
	if (!frame_t_is_const(slot_2)) {
		ajla_assert(TYPE_TAG_IS_INT(type->tag) &&
			    frame_get_type_of_local(fp, slot_2) == type &&
			    frame_get_type_of_local(fp, slot_r)->tag == TYPE_TAG_flat_option,
			    (file_line, "thunk_int_binary_logical_operator: invalid types on opcode %04x: %u, %u, %u",
			    *ip,
			    type->tag,
			    frame_get_type_of_local(fp, slot_2)->tag,
			    frame_get_type_of_local(fp, slot_r)->tag));
	} else {
		ajla_assert(TYPE_TAG_IS_INT(type->tag) &&
			    frame_get_type_of_local(fp, slot_r)->tag == TYPE_TAG_flat_option,
			    (file_line, "thunk_int_binary_logical_operator: invalid types on opcode %04x: %u, %u",
			    *ip,
			    type->tag,
			    frame_get_type_of_local(fp, slot_r)->tag));
	}

	converted = 0;

	converted |= ipret_unbox_value(fp, type, slot_1);
	if (!frame_t_is_const(slot_2))
		converted |= ipret_unbox_value(fp, type, slot_2);

	if (converted & UNBOX_THUNK)
		return ipret_op_build_thunk(fp, ip, slot_1, slot_2, slot_r, strict_flag);

	if (converted == UNBOX_DID_SOMETHING)
		return POINTER_FOLLOW_THUNK_RETRY;

	intx = TYPE_TAG_IDX_INT(type->tag);

	if (unlikely(!(val1 = int_get_mpint(fp, slot_1, &s1, intx, &err))))
		goto fail_oom_1;
	if (unlikely(!(val2 = int_get_mpint(fp, slot_2, &s2, intx, &err))))
		goto fail_oom_2;
	barrier_aliasing();
	if (unlikely(!do_op(val1, val2, frame_slot(fp, slot_r, ajla_flat_option_t), &err))) {
		barrier_aliasing();
		goto fail_oom_3;
	}
	barrier_aliasing();
	if (val1 == &s1)
		mpint_free(&s1);
	if (val2 == &s2)
		mpint_free(&s2);

	return POINTER_FOLLOW_THUNK_GO;

fail_oom_3:
	if (val2 == &s2)
		mpint_free(&s2);
fail_oom_2:
	if (val1 == &s1)
		mpint_free(&s1);
fail_oom_1:
	frame_free_and_set_pointer(fp, slot_r, pointer_error(err, fp, ip pass_file_line));
	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall thunk_int_unary_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r, unsigned strict_flag, bool (attr_fastcall *do_op)(const mpint_t *op1, mpint_t *res, ajla_error_t *err))
{
	ajla_error_t err;
	const struct type *type;
	unsigned intx;
	int converted;
	mpint_t s1;
	mpint_t *val1;
	struct data *result;
	pointer_t to_free;

	type = frame_get_type_of_local(fp, slot_1);
	ajla_assert(TYPE_TAG_IS_INT(type->tag) &&
		    frame_get_type_of_local(fp, slot_r) == type,
		    (file_line, "thunk_int_unary_operator: invalid types on opcode %04x: %u, %u",
		    *ip,
		    type->tag,
		    frame_get_type_of_local(fp, slot_r)->tag));

	converted = 0;

	converted |= ipret_unbox_value(fp, type, slot_1);

	if (converted & UNBOX_THUNK)
		return ipret_op_build_thunk(fp, ip, slot_1, NO_FRAME_T, slot_r, strict_flag);

	if (converted == UNBOX_DID_SOMETHING)
		return POINTER_FOLLOW_THUNK_RETRY;

	intx = TYPE_TAG_IDX_INT(type->tag);

	if (unlikely(!(val1 = int_get_mpint(fp, slot_1, &s1, intx, &err))))
		goto fail_oom_1;
	if (unlikely(!(result = int_allocate_result(fp, slot_r, mpint_estimate_bits(val1), &to_free, &err))))
		goto fail_oom_3;
	if (unlikely(!do_op(val1, &da(result,longint)->mp, &err)))
		goto fail_oom_3;
	if (val1 == &s1)
		mpint_free(&s1);
	if (!pointer_is_empty(to_free))
		pointer_dereference(to_free);

	if (mpint_export(&da(result,longint)->mp, frame_var(fp, slot_r), intx, &err)) {
		frame_clear_flag(fp, slot_r);
		data_dereference(result);
	}
	return POINTER_FOLLOW_THUNK_GO;

fail_oom_3:
	if (!pointer_is_empty(to_free))
		pointer_dereference(to_free);
	if (val1 == &s1)
		mpint_free(&s1);
fail_oom_1:
	frame_free_and_set_pointer(fp, slot_r, pointer_error(err, fp, ip pass_file_line));
	return POINTER_FOLLOW_THUNK_GO;
}

ip_t attr_hot_fastcall ipret_int_ldc_long(frame_s *fp, frame_t slot, const code_t *ip)
{
	ajla_error_t err;

	uint32_t n_words_32;
	ip_t n_words;
	struct data *d;

	n_words_32 = get_unaligned_32(ip);
	n_words = (ip_t)n_words_32;
	ajla_assert(n_words == n_words_32, (file_line, "ipret_int_ldc_long: n_words overflow: %lu != %lu", (unsigned long)n_words_32, (unsigned long)n_words));

	d = data_alloc_longint_mayfail((n_words + sizeof(code_t) - 1) / sizeof(code_t), &err pass_file_line);
	if (unlikely(!d))
		goto fail;

	if (unlikely(!mpint_import_from_code(&da(d,longint)->mp, ip + 2, n_words, &err))) {
		data_dereference(d);
		goto fail;
	}

	frame_set_pointer(fp, slot, pointer_data(d));

	return 2 + n_words;

fail:
	frame_set_pointer(fp, slot, pointer_error(err, fp, ip pass_file_line));

	return 2 + n_words;
}


pointer_t attr_fastcall convert_fixed_to_mpint(uintbig_t val, bool uns)
{
	ajla_error_t err;
	struct data *d;

	d = data_alloc_longint_mayfail(sizeof(uintbig_t) * 8 + uns, &err pass_file_line);
	if (unlikely(!d))
		goto fail;
	if (unlikely(!cat(mpint_set_from_,TYPE_INT_MAX)(&da(d,longint)->mp, (intbig_t)val, uns, &err))) {
		goto fail_deref;
	}
	return pointer_data(d);

fail_deref:
	data_dereference(d);
fail:
	return pointer_error(err, NULL, NULL pass_file_line);
}

pointer_t attr_fastcall convert_real_to_mpint(frame_s *fp, frame_t src_slot, const struct type *src_type)
{
	unsigned char attr_unused *src_ptr;
	ajla_error_t err;
	struct data *d;

	d = data_alloc_longint_mayfail(0, &err pass_file_line);
	if (unlikely(!d))
		goto fail;
	mpint_free(&da(d,longint)->mp);

#define re(n, rtype, ntype, pack, unpack)				\
	case TYPE_TAG_real + n:	{					\
		if (unlikely(!cat(mpint_init_from_,rtype)(&da(d,longint)->mp, cast_ptr(rtype *, src_ptr), &err))) {\
			data_free_r1(d);				\
			goto fail;					\
		}							\
		break;							\
	}

	barrier_aliasing();
	src_ptr = frame_var(fp, src_slot);
	switch (src_type->tag) {
		for_all_real(re, for_all_empty)
		default:
			internal(file_line, "convert_real_to_mpint: invalid type %u", src_type->tag);
	}
	barrier_aliasing();
	return pointer_data(d);

#undef re

fail:
	barrier_aliasing();
	return pointer_error(err, NULL, NULL pass_file_line);
}

static attr_noinline void convert_mpint_to_real(frame_s *fp, frame_t dest_slot, const struct type *dest_type, const mpint_t attr_unused *mp)
{
	unsigned char attr_unused *dest_ptr;

#define re(n, rtype, ntype, pack, unpack)				\
	case TYPE_TAG_real + n:						\
		cat(mpint_export_to_,rtype)(mp, cast_ptr(rtype *, dest_ptr));\
		break;

	barrier_aliasing();
	dest_ptr = frame_var(fp, dest_slot);
	switch (dest_type->tag) {
		for_all_real(re, for_all_empty)
		default:
			internal(file_line, "convert_mpint_to_real: invalid type %u", dest_type->tag);
	}
	barrier_aliasing();

#undef re
}

void * attr_hot_fastcall thunk_convert(frame_s *fp, const code_t *ip, frame_t src_slot, frame_t dest_slot, unsigned strict_flag)
{
	int converted;
	const struct type *src_type;
	const struct type *dest_type;
	ajla_error_t err;
	struct data *d;

	if (unlikely(src_slot == dest_slot))
		return POINTER_FOLLOW_THUNK_GO;

	src_type = frame_get_type_of_local(fp, src_slot);
	dest_type = frame_get_type_of_local(fp, dest_slot);

	converted = ipret_unbox_value(fp, src_type, src_slot);
	if (unlikely(converted == UNBOX_THUNK)) {
		return ipret_op_build_thunk(fp, ip, src_slot, NO_FRAME_T, dest_slot, strict_flag);
	}
	if (converted == UNBOX_DID_SOMETHING) {
		return POINTER_FOLLOW_THUNK_RETRY;
	}

	if (type_is_equal(dest_type, type_get_int(INT_DEFAULT_N))) {
		if (likely(TYPE_TAG_IS_INT(src_type->tag))) {
			if (likely(converted == UNBOX_LONGINT)) {
				goto convert_longint;
			}
		}
	} else {
		if (unlikely(!type_is_equal(src_type, type_get_int(INT_DEFAULT_N))))
			goto int_err;
		if (TYPE_TAG_IS_FIXED(dest_type->tag)) {
			if (likely(converted == UNBOX_LONGINT)) {
				bool res;
				if (!TYPE_TAG_FIXED_IS_UNSIGNED(dest_type->tag))
					res = mpint_export(&da(pointer_get_data(*frame_pointer(fp, src_slot)), longint)->mp, frame_var(fp, dest_slot), TYPE_TAG_IDX_FIXED(dest_type->tag) >> 1, &err);
				else
					res = mpint_export_unsigned(&da(pointer_get_data(*frame_pointer(fp, src_slot)), longint)->mp, frame_var(fp, dest_slot), TYPE_TAG_IDX_FIXED(dest_type->tag) >> 1, &err);
				if (unlikely(!res))
					frame_set_pointer(fp, dest_slot, pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT), fp, ip pass_file_line));
				return POINTER_FOLLOW_THUNK_GO;
			}
		} else if (TYPE_TAG_IS_INT(dest_type->tag)) {
			if (likely(converted == UNBOX_LONGINT)) {
				goto convert_longint;
			}
		} else if (likely(TYPE_TAG_IS_REAL(dest_type->tag))) {
			if (likely(converted == UNBOX_LONGINT)) {
				convert_mpint_to_real(fp, dest_slot, dest_type, &da(pointer_get_data(*frame_pointer(fp, src_slot)), longint)->mp);
				return POINTER_FOLLOW_THUNK_GO;
			}
		}
	}
	goto int_err;

convert_longint:
	d = pointer_get_data(*frame_pointer(fp, src_slot));
	if (mpint_export(&da(d,longint)->mp, frame_var(fp, dest_slot), TYPE_TAG_IDX_INT(dest_type->tag), &err)) {
		return POINTER_FOLLOW_THUNK_GO;
	}
	pointer_copy_owned(fp, src_slot, dest_slot);
	return POINTER_FOLLOW_THUNK_GO;

int_err:
	internal(file_line, "thunk_convert: invalid conversion %u->%u (%d)", src_type->tag, dest_type->tag, converted);
	return POINTER_FOLLOW_THUNK_RETRY;
}


static bool attr_hot_fastcall ipret_unbox_bool(frame_s *fp, frame_t slot)
{
	if (frame_test_flag(fp, slot)) {
		pointer_t ptr = *frame_pointer(fp, slot);
		if (pointer_is_thunk(ptr))
			return true;
		barrier_aliasing();
		*frame_slot(fp, slot, ajla_flat_option_t) = (ajla_flat_option_t)da(pointer_get_data(ptr),option)->option;
		barrier_aliasing();
		frame_clear_flag(fp, slot);
		pointer_dereference(ptr);
	}
	return false;
}

void * attr_hot_fastcall thunk_bool_operator(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_2, frame_t slot_r, unsigned strict_flag)
{
	code_t code;
	ajla_flat_option_t val1, val2, result;

	code = *ip;
	code %= OPCODE_MODE_MULT;
	code = (code - OPCODE_BOOL_OP) / OPCODE_BOOL_OP_MULT;

	val1 = val2 = 2;
	if (!ipret_unbox_bool(fp, slot_1)) {
		barrier_aliasing();
		val1 = *frame_slot(fp, slot_1, ajla_flat_option_t);
		barrier_aliasing();
		switch (code) {
			case OPCODE_BOOL_OP_less:
				if (val1) {
					result = 0;
					goto have_result;
				}
				break;
			case OPCODE_BOOL_OP_less_equal:
				if (!val1) {
					result = 1;
					goto have_result;
				}
				break;
			case OPCODE_BOOL_OP_and:
			case OPCODE_BOOL_OP_greater:
				if (!val1) {
					result = 0;
					goto have_result;
				}
				break;
			case OPCODE_BOOL_OP_or:
			case OPCODE_BOOL_OP_greater_equal:
				if (val1) {
					result = 1;
					goto have_result;
				}
				break;
			case OPCODE_BOOL_OP_not:
				result = val1 ^ 1;
				goto have_result;
		}
	}
	if (slot_2 != NO_FRAME_T && !ipret_unbox_bool(fp, slot_2)) {
		barrier_aliasing();
		val2 = *frame_slot(fp, slot_2, ajla_flat_option_t);
		barrier_aliasing();
		switch (code) {
			case OPCODE_BOOL_OP_less:
			case OPCODE_BOOL_OP_and:
				if (!val2) {
					result = 0;
					goto have_result;
				}
				break;
			case OPCODE_BOOL_OP_less_equal:
			case OPCODE_BOOL_OP_or:
				if (val2) {
					result = 1;
					goto have_result;
				}
				break;
			case OPCODE_BOOL_OP_greater:
				if (val2) {
					result = 0;
					goto have_result;
				}
				break;
			case OPCODE_BOOL_OP_greater_equal:
				if (!val2) {
					result = 1;
					goto have_result;
				}
				break;
		}
	}
	if (!((val1 | val2) & 2)) {
		return POINTER_FOLLOW_THUNK_RETRY;
	}
	if (val1 & val2 & 2) {
		switch (code) {
			case OPCODE_BOOL_OP_and:
			case OPCODE_BOOL_OP_or:
			case OPCODE_BOOL_OP_less:
			case OPCODE_BOOL_OP_less_equal:
			case OPCODE_BOOL_OP_greater:
			case OPCODE_BOOL_OP_greater_equal:
				strict_flag |= FLAG_NEED_BOTH_EXCEPTIONS_TO_FAIL;
		}
	}

	return ipret_op_build_thunk(fp, ip, slot_1, slot_2, slot_r, strict_flag);

have_result:
	frame_free(fp, slot_r);
	barrier_aliasing();
	*frame_slot(fp, slot_r, ajla_flat_option_t) = result;
	barrier_aliasing();
	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall thunk_bool_jump(frame_s *fp, const code_t *ip, frame_t slot)
{
	pointer_t *thunk = frame_pointer(fp, slot);
	struct data *data;

	pointer_follow(thunk, true, data, PF_WAIT, fp, ip,
		return ex_,
		return POINTER_FOLLOW_THUNK_EXCEPTION
	);

	barrier_aliasing();
	*frame_slot(fp, slot, ajla_flat_option_t) = (ajla_flat_option_t)da(data,option)->option;
	barrier_aliasing();
	frame_clear_flag(fp, slot);
	data_dereference(data);
	return POINTER_FOLLOW_THUNK_RETRY;
}


void attr_fastcall ipret_copy_variable(frame_s *src_fp, frame_t src_slot, frame_s *dst_fp, frame_t dst_slot, bool deref)
{
	pointer_t ptr;
	const struct type *src_type;
	src_type = frame_get_type_of_local(src_fp, src_slot);
	if (!frame_variable_is_flat(src_fp, src_slot)) {
		ptr = frame_get_pointer_reference(src_fp, src_slot, deref);
	} else {
		const struct type *dst_type = frame_get_type_of_local(dst_fp, dst_slot);
		if (likely(TYPE_IS_FLAT(dst_type))) {
			ajla_assert(!frame_test_flag(dst_fp, dst_slot), (file_line, "ipret_copy_variable: flag already set for destination slot %"PRIuMAX"", (uintmax_t)dst_slot));
			ajla_assert(type_is_equal(src_type, dst_type), (file_line, "ipret_copy_variable: copying between different types (%u,%u,%u) -> (%u,%u,%u)", src_type->tag, src_type->size, src_type->align, dst_type->tag, dst_type->size, dst_type->align));
			memcpy_fast(frame_var(dst_fp, dst_slot), frame_var(src_fp, src_slot), dst_type->size);
			return;
		} else {
			ptr = flat_to_data(src_type, frame_var(src_fp, src_slot));
		}
	}
	ajla_assert(!frame_test_flag(dst_fp, dst_slot), (file_line, "ipret_copy_variable: flag already set for destination slot %"PRIuMAX"", (uintmax_t)dst_slot));
	frame_set_pointer(dst_fp, dst_slot, ptr);
}

pointer_t ipret_copy_variable_to_pointer(frame_s *src_fp, frame_t src_slot, bool deref)
{
	const struct type *src_type = frame_get_type_of_local(src_fp, src_slot);
	if (!frame_variable_is_flat(src_fp, src_slot)) {
		return frame_get_pointer_reference(src_fp, src_slot, deref);
	} else {
		return flat_to_data(src_type, frame_var(src_fp, src_slot));
	}
}


struct data_compare_context {
	struct ipret_call_cache_arg *arguments;
	arg_t n_arguments;
	arg_t n_return_values;
	ajla_error_t err;
};

static int saved_cache_compare(struct data *saved_cache, size_t idx, struct data_compare_context *ctx)
{
	size_t ptr_idx = idx * ((size_t)ctx->n_arguments + (size_t)ctx->n_return_values);
	arg_t ai;
	for (ai = 0; ai < ctx->n_arguments; ai++) {
		int c;
		c = data_compare(da(saved_cache,saved_cache)->pointers[ptr_idx + ai], ctx->arguments[ai].ptr, &ctx->err);
		if (c)
			return c;
	}
	return 0;
}

static pointer_t *saved_cache_find(struct data *function, struct data_compare_context *ctx)
{
	struct data *saved_cache = da(function,function)->loaded_cache;
	size_t n_entries = da(saved_cache,saved_cache)->n_entries;
	size_t result;
	int cmp;
	/*debug("searching: %s, %zu", da(function,function)->function_name, n_entries);*/
	binary_search(size_t, n_entries, result, !(cmp = saved_cache_compare(saved_cache, result, ctx)), cmp < 0, return NULL);
	/*debug("found it: %s, %zu", da(function,function)->function_name, result);*/
	return &da(saved_cache,saved_cache)->pointers[result * ((size_t)ctx->n_arguments + (size_t)ctx->n_return_values) + (size_t)ctx->n_arguments];
}

static int cache_entry_compare(const struct tree_entry *e1, uintptr_t e2)
{
	struct cache_entry *c1 = get_struct(e1, struct cache_entry, entry);
	struct data_compare_context *ctx = cast_ptr(struct data_compare_context *, num_to_ptr(e2));
	arg_t ai;
	for (ai = 0; ai < ctx->n_arguments; ai++) {
		int c;
		c = data_compare(c1->arguments[ai], ctx->arguments[ai].ptr, MEM_DONT_TRY_TO_FREE);
		if (c == -1 || c == 1)
			return c;
		if (c == DATA_COMPARE_OOM) {
			ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY);
			return 0;
		}
		if (unlikely(c))
			internal(file_line, "cache_entry_compare: data_compare returned %d", c);
	}
	return 0;
}

static void cache_evaluated(void *cookie, pointer_t ptr)
{
	struct cache_entry_return *ret = cookie;
	struct cache_entry *c;
	pointer_reference_owned(ptr);
	ret->ptr = ptr;
	c = ret->ce;
	address_lock(c, DEPTH_THUNK);
	/*debug("cache evaluated: %p, pending %u", c, c->n_pending);*/
	if (likely(!--c->n_pending)) {
		wake_up_wait_list(&c->wait_list, address_get_mutex(c, DEPTH_THUNK), TASK_SUBMIT_MAY_SPAWN);
	} else {
		address_unlock(c, DEPTH_THUNK);
	}
}

void * attr_fastcall ipret_call_cache(frame_s *fp, const code_t *ip, pointer_t *direct_function, struct ipret_call_cache_arg *arguments, frame_t *return_values, frame_t free_fn_slot)
{
	struct thunk *thunk = NULL;
	struct data_compare_context ctx;
	struct tree_insert_position ins;
	struct tree_entry *e;
	struct cache_entry *c = NULL;	/* avoid warning */
	void *ex;
	arg_t ai;
	bool wr_lock;
	struct thunk **results;
	struct data *function_reference;
	struct data *function = pointer_get_data(*direct_function);
	arg_t n_arguments = da(function,function)->n_arguments;
	arg_t n_return_values = da(function,function)->n_return_values;
	bool save = *ip % OPCODE_MODE_MULT == OPCODE_CALL_SAVE || *ip % OPCODE_MODE_MULT == OPCODE_CALL_INDIRECT_SAVE;

	ctx.err.error_class = EC_NONE;

	for (ai = 0; ai < n_arguments; ai++)
		arguments[ai].need_free_ptr = false;
	for (ai = 0; ai < n_arguments; ai++) {
		struct function_argument *f_arg = arguments[ai].f_arg;
		if (unlikely(f_arg != NULL)) {
			if (f_arg->tag == TYPE_TAG_unknown) {
				ex = pointer_deep_eval(&f_arg->u.ptr, fp, ip, &thunk);
				arguments[ai].ptr = pointer_reference(&f_arg->u.ptr);
				arguments[ai].need_free_ptr = true;
			} else {
				arguments[ai].ptr = flat_to_data(type_get_from_tag(f_arg->tag), f_arg->u.slot);
				ex = pointer_deep_eval(&arguments[ai].ptr, fp, ip, &thunk);
				arguments[ai].need_free_ptr = true;
			}
		} else {
			frame_t slot = arguments[ai].slot;
			if (!frame_variable_is_flat(fp, slot)) {
				ex = frame_pointer_deep_eval(fp, ip, slot, &thunk);
				arguments[ai].ptr = *frame_pointer(fp, slot);
			} else {
				arguments[ai].ptr = flat_to_data(frame_get_type_of_local(fp, slot), frame_var(fp, slot));
				ex = pointer_deep_eval(&arguments[ai].ptr, fp, ip, &thunk);
				arguments[ai].need_free_ptr = true;
			}
		}
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION) {
			if (!rwmutex_supported) {
				wr_lock = true;
				address_write_lock(function);
			} else {
				wr_lock = false;
				address_read_lock(function);
			}
			goto ret_c;
		}
		if (ex != POINTER_FOLLOW_THUNK_GO)
			goto ret1;
	}

	ctx.arguments = arguments;
	ctx.n_arguments = n_arguments;
	ctx.n_return_values = n_return_values;

	if (da(function,function)->loaded_cache) {
		pointer_t *results;
		/*debug("loaded cache: %s", da(function,function)->function_name);*/
		ctx.err.error_class = EC_NONE;
		results = saved_cache_find(function, &ctx);
		if (results || unlikely(ctx.err.error_class != EC_NONE)) {
			for (ai = 0; ai < n_arguments; ai++) {
				if (arguments[ai].deref) {
					frame_t slot = arguments[ai].slot;
					if (frame_test_and_clear_flag(fp, slot))
						pointer_dereference(*frame_pointer(fp, slot));
					*frame_pointer(fp, slot) = pointer_empty();
				}
			}
			if (unlikely(free_fn_slot != NO_FRAME_T)) {
				frame_free_and_clear(fp, free_fn_slot);
			}
			if (unlikely(ctx.err.error_class != EC_NONE)) {
				for (ai = 0; ai < n_return_values; ai++) {
					frame_set_pointer(fp, return_values[ai], pointer_error(ctx.err, NULL, NULL pass_file_line));
				}
			} else {
				for (ai = 0; ai < n_return_values; ai++) {
					pointer_t ptr = pointer_reference(&results[ai]);
					frame_set_pointer(fp, return_values[ai], ptr);
				}
			}
			ex = POINTER_FOLLOW_THUNK_GO;
			goto ret1;
		}
	}

	if (!rwmutex_supported) {
		wr_lock = true;
		address_write_lock(function);
	} else {
		wr_lock = false;
		address_read_lock(function);
	}

again:
	ctx.err.error_class = EC_NONE;
	e = tree_find_for_insert(&da(function,function)->cache, cache_entry_compare, ptr_to_num(&ctx), &ins);
	if (e) {
		if (unlikely(ctx.err.error_class != EC_NONE)) {
			if (!wr_lock)
				address_read_unlock(function);
			else
				address_write_unlock(function);
			if (ctx.err.error_type == AJLA_ERROR_OUT_OF_MEMORY && mem_trim_cache()) {
				if (!wr_lock)
					address_read_lock(function);
				else
					address_write_lock(function);
				goto again;
			}
			wr_lock = false;
			address_read_lock(function);
			goto ret_c;
		}
		c = get_struct(e, struct cache_entry, entry);
		address_lock(c, DEPTH_THUNK);
		goto have_c;
	}
	if (!wr_lock) {
		address_read_unlock(function);
		wr_lock = true;
		address_write_lock(function);
		goto again;
	}

	c = struct_alloc_array_mayfail(mem_alloc_mayfail, struct cache_entry, arguments, n_arguments, MEM_DONT_TRY_TO_FREE);
	if (unlikely(!c))
		goto oom1;
	c->save = save;
	c->returns = mem_alloc_array_mayfail(mem_alloc_mayfail, struct cache_entry_return *, 0, 0, n_return_values, sizeof(struct cache_entry_return), MEM_DONT_TRY_TO_FREE);
	if (unlikely(!c->returns))
		goto oom2;
	for (ai = 0; ai < n_return_values; ai++) {
		c->returns[ai].ex = NULL;
	}
	for (ai = 0; ai < n_return_values; ai++) {
		c->returns[ai].ex = function_evaluate_prepare(MEM_DONT_TRY_TO_FREE);
		if (unlikely(!c->returns[ai].ex))
			goto oom3;
	}
	for (ai = 0; ai < n_arguments; ai++) {
		pointer_reference_owned(arguments[ai].ptr);
		c->arguments[ai] = arguments[ai].ptr;
	}
	results = mem_alloc_array_mayfail(mem_alloc_mayfail, struct thunk **, 0, 0, n_return_values, sizeof(struct thunk *), MEM_DONT_TRY_TO_FREE);
	if (unlikely(!results))
		goto oom3;
	if (!(function_reference = data_alloc_function_reference_mayfail(n_arguments, MEM_DONT_TRY_TO_FREE pass_file_line)))
		goto oom4;
	da(function_reference,function_reference)->is_indirect = false;
	da(function_reference,function_reference)->u.direct = direct_function;
	if (unlikely(!thunk_alloc_function_call(pointer_data(function_reference), n_return_values, results, MEM_DONT_TRY_TO_FREE))) {
		data_free_r1(function_reference);
oom4:
		mem_free(results);
oom3:
		for (ai = 0; ai < n_return_values; ai++) {
			if (c->returns[ai].ex)
				execution_control_free(c->returns[ai].ex);
		}
		mem_free(c->returns);
oom2:
		mem_free(c);
oom1:
		address_write_unlock(function);
		if (mem_trim_cache()) {
			address_write_lock(function);
			goto again;
		}
		address_write_lock(function);
		ctx.err = error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY);
		goto ret_c;
	}
	for (ai = 0; ai < n_arguments; ai++) {
		pointer_reference_owned(c->arguments[ai]);
		data_fill_function_reference(function_reference, ai, c->arguments[ai]);
	}
	address_lock(c, DEPTH_THUNK);
	/*debug("evaluaring: %p", c);*/
	c->n_pending = n_return_values;
	list_init(&c->wait_list);
	for (ai = 0; ai < n_return_values; ai++) {
		c->returns[ai].ce = c;
		function_evaluate_submit(c->returns[ai].ex, pointer_thunk(results[ai]), cache_evaluated, &c->returns[ai]);
	}
	mem_free(results);

	tree_insert_after_find(&c->entry, &ins);

have_c:
	if (!c->save && unlikely(save))
		c->save = true;
	if (c->n_pending) {
		struct execution_control *exx;
		/*debug("waiting on %p, pending %u", c, c->n_pending);*/
		exx = frame_execution_control(fp);
		exx->wait[0].mutex_to_lock = address_get_mutex(c, DEPTH_THUNK);
		list_add(&c->wait_list, &exx->wait[0].wait_entry);
		address_unlock(c, DEPTH_THUNK);
		pointer_follow_wait(fp, ip);
		ex = POINTER_FOLLOW_THUNK_EXIT;
		goto ret2;
	}
	address_unlock(c, DEPTH_THUNK);

ret_c:
	for (ai = 0; ai < n_arguments; ai++) {
		if (arguments[ai].deref) {
			frame_t slot = arguments[ai].slot;
			if (frame_test_and_clear_flag(fp, slot))
				pointer_dereference(*frame_pointer(fp, slot));
			*frame_pointer(fp, slot) = pointer_empty();
		}
	}
	if (unlikely(free_fn_slot != NO_FRAME_T)) {
		frame_free_and_clear(fp, free_fn_slot);
	}
	if (likely(!thunk) && unlikely(ctx.err.error_class != EC_NONE))
		thunk = thunk_alloc_exception_error(ctx.err, NULL, NULL, NULL pass_file_line);
	for (ai = 0; ai < n_return_values; ai++) {
		pointer_t ptr;
		if (likely(!thunk)) {
			ptr = pointer_reference(&c->returns[ai].ptr);
		} else {
			if (ai)
				thunk_reference(thunk);
			ptr = pointer_thunk(thunk);
		}
		frame_set_pointer(fp, return_values[ai], ptr);
	}
	ex = POINTER_FOLLOW_THUNK_GO;

ret2:
	if (likely(!wr_lock))
		address_read_unlock(function);
	else
		address_write_unlock(function);

ret1:
	for (ai = 0; ai < n_arguments; ai++) {
		if (arguments[ai].need_free_ptr) {
			pointer_dereference(arguments[ai].ptr);
		}
	}
	mem_free(arguments);
	mem_free(return_values);
	return ex;
}


static attr_noinline void * ipret_get_index_complicated(frame_s *fp, const code_t *ip, frame_s *fp_slot, frame_t slot, bool *is_negative, array_index_t *idx, pointer_t *thunk argument_position)
{
again:
	if (likely(!frame_test_flag(fp_slot, slot))) {
		int_default_t in;
		barrier_aliasing();
		in = *frame_slot(fp_slot, slot, int_default_t);
		barrier_aliasing();
		if (unlikely(in < 0)) {
negative:
			if (!is_negative) {
				*thunk = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX), fp, ip pass_position);
				return POINTER_FOLLOW_THUNK_EXCEPTION;
			}
			*is_negative = true;
			return POINTER_FOLLOW_THUNK_GO;
		}
		index_from_int_(idx, in pass_position);
	} else {
		pointer_t *ptr = frame_pointer(fp_slot, slot);
		struct data *d;

		pointer_follow(ptr, true, d, PF_WAIT, fp, ip,
			return ex_,
			thunk_reference(thunk_);
			*thunk = pointer_thunk(thunk_);
			return POINTER_FOLLOW_THUNK_EXCEPTION;
		);
		if (da_tag(d) == DATA_TAG_flat) {
			ipret_unbox_value(fp_slot, type_get_int(INT_DEFAULT_N), slot);
			goto again;
		}
		if (unlikely(mpint_negative(&da(d,longint)->mp))) {
			goto negative;
		}
		index_from_mp_(idx, &da(d,longint)->mp pass_position);
	}
	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall ipret_get_index(frame_s *fp, const code_t *ip, frame_s *fp_slot, frame_t slot, bool *is_negative, array_index_t *idx, pointer_t *thunk argument_position)
{
	if (likely(fp == fp_slot))
		ajla_assert(frame_get_type_of_local(fp_slot, slot)->tag == type_get_int(INT_DEFAULT_N)->tag, (file_line, "ipret_get_index: invalid type %u", (unsigned)frame_get_type_of_local(fp_slot, slot)->tag));
	if (likely(!frame_test_flag(fp_slot, slot))) {
		int_default_t in;
		barrier_aliasing();
		in = *frame_slot(fp_slot, slot, int_default_t);
		barrier_aliasing();
		if (unlikely(in < 0))
			goto complicated;
		index_from_int_(idx, in pass_position);
	} else {
complicated:
		return ipret_get_index_complicated(fp, ip, fp_slot, slot, is_negative, idx, thunk pass_position);
	}
	return POINTER_FOLLOW_THUNK_GO;
}


void * attr_hot_fastcall ipret_record_load_create_thunk(frame_s *fp, const code_t *ip, frame_t record, frame_t record_slot, frame_t result_slot)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	ex = pcode_find_record_option_load_function(PCODE_FUNCTION_RECORD_LOAD, record_slot, fp, ip, &fn_ptr);

	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 1, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, record, false);

	frame_set_pointer(fp, result_slot, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall ipret_option_load_create_thunk(frame_s *fp, const code_t *ip, frame_t option, frame_t option_idx, frame_t result_slot)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	ex = pcode_find_record_option_load_function(PCODE_FUNCTION_OPTION_LOAD, option_idx, fp, ip, &fn_ptr);

	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 1, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, option, false);

	frame_set_pointer(fp, result_slot, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall thunk_option_test(frame_s *fp, const code_t *ip, frame_t slot_1, ajla_option_t option, frame_t slot_r)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	pointer_follow_thunk_noeval(frame_pointer(fp, slot_1),
		return POINTER_FOLLOW_THUNK_RETRY,
		pointer_copy_owned(fp, slot_1, slot_r);
		return POINTER_FOLLOW_THUNK_GO,
		break
	);

	ex = pcode_find_record_option_load_function(PCODE_FUNCTION_OPTION_TEST, option, fp, ip, &fn_ptr);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 1, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, slot_1, false);

	frame_set_pointer(fp, slot_r, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall thunk_option_ord(frame_s *fp, const code_t *ip, frame_t slot_1, frame_t slot_r)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	pointer_follow_thunk_noeval(frame_pointer(fp, slot_1),
		return POINTER_FOLLOW_THUNK_RETRY,
		pointer_copy_owned(fp, slot_1, slot_r);
		return POINTER_FOLLOW_THUNK_GO,
		break
	);

	ex = pcode_find_option_ord_function(fp, ip, &fn_ptr);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 1, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, slot_1, false);

	frame_set_pointer(fp, slot_r, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}


void * attr_hot_fastcall ipret_array_load_create_thunk(frame_s *fp, const code_t *ip, frame_t array, frame_t index, frame_t result_slot)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	ex = pcode_find_array_load_function(fp, ip, &fn_ptr);

	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 2, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, array, false);
	ipret_fill_function_reference_from_slot(function_reference, 1, fp, index, false);

	frame_set_pointer(fp, result_slot, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

static attr_noinline void *array_len_create_thunk(frame_s *fp, const code_t *ip, frame_t array_slot, frame_t result_slot, bool finite)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	ex = pcode_find_array_len_function(finite, fp, ip, &fn_ptr);

	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 1, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, array_slot, false);

	frame_set_pointer(fp, result_slot, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

static attr_noinline void *array_len_greater_than_create_thunk(frame_s *fp, const code_t *ip, frame_t array_slot, frame_t length_slot, frame_t result_slot)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	ex = pcode_find_array_len_greater_than_function(fp, ip, &fn_ptr);

	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 2, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, array_slot, false);
	ipret_fill_function_reference_from_slot(function_reference, 1, fp, length_slot, false);

	frame_set_pointer(fp, result_slot, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

static attr_noinline void *array_sub_create_thunk(frame_s *fp, const code_t *ip, frame_t array_slot, frame_t start_slot, frame_t end_slot, frame_t result_slot, unsigned flags)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	ex = pcode_find_array_sub_function(fp, ip, &fn_ptr);

	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 3, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, array_slot, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);
	ipret_fill_function_reference_from_slot(function_reference, 1, fp, start_slot, false);
	ipret_fill_function_reference_from_slot(function_reference, 2, fp, end_slot, false);

	frame_set_pointer(fp, result_slot, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

static attr_noinline void *array_skip_create_thunk(frame_s *fp, const code_t *ip, frame_t array_slot, frame_t start_slot, frame_t result_slot, unsigned flags)
{
	pointer_t *fn_ptr;
	void *ex;
	struct data *function_reference;
	struct thunk *result;

	ex = pcode_find_array_skip_function(fp, ip, &fn_ptr);

	if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		return ex;

	result = build_thunk(fn_ptr, 2, &function_reference);
	ipret_fill_function_reference_from_slot(function_reference, 0, fp, array_slot, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);
	ipret_fill_function_reference_from_slot(function_reference, 1, fp, start_slot, false);

	frame_set_pointer(fp, result_slot, pointer_thunk(result));

	return POINTER_FOLLOW_THUNK_GO;
}

static bool array_resolve_thunk(frame_s *fp, frame_t slot)
{
	pointer_t *ptr;
	if (unlikely(frame_variable_is_flat(fp, slot)))
		return false;
retry:
	ptr = frame_pointer(fp, slot);
	if (likely(frame_test_flag(fp, slot))) {
		if (unlikely(pointer_is_thunk(*ptr))) {
			if (thunk_is_finished(pointer_get_thunk(*ptr))) {
				pointer_follow_thunk_(ptr, POINTER_FOLLOW_THUNK_NOEVAL);
				goto retry;
			}
			return true;
		}
	}
	if (da_tag(pointer_get_data(*ptr)) == DATA_TAG_array_incomplete) {
		if (unlikely(!frame_test_and_set_flag(fp, slot)))
			data_reference(pointer_get_data(*ptr));
		array_incomplete_collapse(ptr);
		return true;
	}
	return false;
}

static void *array_walk(frame_s *fp, const code_t *ip, pointer_t *ptr, array_index_t *idx, unsigned flags, pointer_t *result, pointer_t **can_modify)
{
	struct data *a;
	array_index_t this_len;

	*can_modify = ptr;

again:
	pointer_follow(ptr, false, a, flags & OPCODE_OP_FLAG_STRICT ? PF_WAIT : PF_NOEVAL, fp, ip,
		return ex_,
		thunk_reference(thunk_);
		*result = pointer_thunk(thunk_);
		return POINTER_FOLLOW_THUNK_EXCEPTION
	);

	if (unlikely(index_eq_int(*idx, 0))) {
		*result = *ptr;
		return POINTER_FOLLOW_THUNK_GO;
	}

	if (unlikely(da_tag(a) == DATA_TAG_array_incomplete)) {
		if (!data_is_writable(a))
			*can_modify = NULL;
		this_len = array_len(pointer_get_data(da(a,array_incomplete)->first));
		if (!index_ge_index(this_len, *idx)) {
			index_sub(idx, this_len);
			index_free(&this_len);
			ptr = &da(a,array_incomplete)->next;
			if (*can_modify)
				*can_modify = ptr;
			goto again;
		}
		index_free(&this_len);
		*result = pointer_data(a);
	} else {
		this_len = array_len(a);
		if (unlikely(!index_ge_index(this_len, *idx))) {
			index_free(&this_len);
			return POINTER_FOLLOW_THUNK_RETRY;	/* this means index out of range, not a retry */
		}
		index_free(&this_len);
		*result = pointer_data(a);
	}
	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall ipret_array_len(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, unsigned flags)
{
	const struct type *type;
	pointer_t *ptr;
	array_index_t idx_len;
	ajla_error_t err;

	ajla_assert(type_is_equal(frame_get_type_of_local(fp, slot_r), type_get_int(INT_DEFAULT_N)), (file_line, "ipret_array_len: invalid index type %u", frame_get_type_of_local(fp, slot_r)->tag));
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "ipret_array_len: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));

	type = frame_get_type_of_local(fp, slot_a);
	if (unlikely(TYPE_IS_FLAT(type))) {
		const struct flat_array_definition *flat_def = type_def(type,flat_array);
		barrier_aliasing();
		*frame_slot(fp, slot_r, int_default_t) = flat_def->n_elements;
		barrier_aliasing();
		return POINTER_FOLLOW_THUNK_GO;
	}

	index_from_int(&idx_len, 0);
	ptr = frame_pointer(fp, slot_a);

	if (flags & OPCODE_OP_FLAG_STRICT) {
		array_resolve_thunk(fp, slot_a);
	}

	while (1) {
		struct data *array_data;
		struct data *this_ptr;
		array_index_t this_len;

		pointer_follow(ptr, false, array_data, flags & OPCODE_OP_FLAG_STRICT ? PF_WAIT : PF_NOEVAL, fp, ip,
			if (!(flags & OPCODE_OP_FLAG_STRICT)) {
				if (unlikely((flags & OPCODE_FLAG_LEN_FINITE) != 0) && likely(!index_eq_int(idx_len, 0)))
					goto brk;
				ex_ = array_len_create_thunk(fp, ip, slot_a, slot_r, !!(flags & OPCODE_FLAG_LEN_FINITE));
			}
			index_free(&idx_len);
			return ex_,
			index_free(&idx_len);
			thunk_reference(thunk_);
			frame_set_pointer(fp, slot_r, pointer_thunk(thunk_));
			return POINTER_FOLLOW_THUNK_GO
		);

		if (da_tag(array_data) == DATA_TAG_array_incomplete)
			this_ptr = pointer_get_data(da(array_data,array_incomplete)->first);
		else
			this_ptr = array_data;

		this_len = array_len(this_ptr);

		if (unlikely(!index_add_(&idx_len, this_len, &err pass_file_line))) {
			index_free(&this_len);
			goto array_len_error;
		}
		index_free(&this_len);

		if (unlikely((flags & (OPCODE_OP_FLAG_STRICT | OPCODE_FLAG_LEN_FINITE)) == (OPCODE_OP_FLAG_STRICT | OPCODE_FLAG_LEN_FINITE)) && likely(!index_eq_int(idx_len, 0))) {
			flags &= ~OPCODE_OP_FLAG_STRICT;
		}

		if (da_tag(array_data) == DATA_TAG_array_incomplete) {
			ptr = &da(array_data,array_incomplete)->next;
			continue;
		}

		break;
	}
brk:

	if (likely(!index_is_mp(idx_len))) {
		int_default_t len = index_to_int(idx_len);
		index_free(&idx_len);
		barrier_aliasing();
		*frame_slot(fp, slot_r, int_default_t) = len;
		barrier_aliasing();
	} else {
		struct data *d;
		d = data_alloc_longint_mayfail(0, &err pass_file_line);
		if (unlikely(!d)) {
			index_free(&idx_len);
array_len_error:
			frame_set_pointer(fp, slot_r, pointer_error(err, fp, ip pass_file_line));
		} else {
			mpint_free(&da(d,longint)->mp);
			index_free_get_mp(&idx_len, &da(d,longint)->mp);
			frame_set_pointer(fp, slot_r, pointer_data(d));
		}
	}

	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall ipret_array_len_greater_than(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, frame_t slot_l, unsigned flags)
{
	const struct type *type;
	bool neg = false;
	int result = 1;
	pointer_t *ptr;
	void *ex;
	array_index_t remaining_length;
	pointer_t res_ptr;
	pointer_t *can_modify;

	ajla_assert(type_is_equal(frame_get_type_of_local(fp, slot_r), type_get_flat_option()), (file_line, "ipret_array_len_greater_than: invalid index type %u", frame_get_type_of_local(fp, slot_r)->tag));
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "ipret_array_len_greater_than: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));

	ex = ipret_get_index(fp, ip, fp, slot_l, &neg, &remaining_length, &res_ptr pass_file_line);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION)
			goto err;
		return ex;
	}
	if (unlikely(neg)) {
		result = 1;
		goto ret_result_nofree;
	}

	type = frame_get_type_of_local(fp, slot_a);
	if (unlikely(TYPE_IS_FLAT(type))) {
		const struct flat_array_definition *flat_def = type_def(type,flat_array);
		if (index_ge_int(remaining_length, flat_def->n_elements))
			result = 0;
		goto ret_result;
	}

	ptr = frame_pointer(fp, slot_a);

	if (flags & OPCODE_OP_FLAG_STRICT) {
		array_resolve_thunk(fp, slot_a);
	}

	index_add_int(&remaining_length, 1);
	ex = array_walk(fp, ip, ptr, &remaining_length, flags, &res_ptr, &can_modify);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (likely(ex == POINTER_FOLLOW_THUNK_RETRY)) {
			result = 0;
			goto ret_result;
		}
		if (unlikely(ex == POINTER_FOLLOW_THUNK_EXCEPTION))
			goto err_free;
		if (!(flags & OPCODE_OP_FLAG_STRICT))
			ex = array_len_greater_than_create_thunk(fp, ip, slot_a, slot_l, slot_r);
		index_free(&remaining_length);
		return ex;
	}

ret_result:
	index_free(&remaining_length);
ret_result_nofree:
	barrier_aliasing();
	*frame_slot(fp, slot_r, ajla_flat_option_t) = result;
	barrier_aliasing();
	return POINTER_FOLLOW_THUNK_GO;

err_free:
	index_free(&remaining_length);
err:
	frame_set_pointer(fp, slot_r, res_ptr);
	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall ipret_array_sub(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, frame_t slot_start, frame_t slot_end, unsigned flags)
{
	array_index_t start, end, end_tmp;
	pointer_t res_ptr;
	pointer_t *can_modify;
	void *ex;
	pointer_t *ptr;
	struct data *acc = NULL;

	ajla_assert(flags & OPCODE_FLAG_FREE_ARGUMENT || !frame_test_flag(fp, slot_r), (file_line, "ipret_array_sub: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));

	ex = ipret_get_index(fp, ip, fp, slot_start, NULL, &start, &res_ptr pass_file_line);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION)
			goto except;
		return ex;
	}
	ex = ipret_get_index(fp, ip, fp, slot_end, NULL, &end, &res_ptr pass_file_line);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION)
			goto except_start;
		index_free(&start);
		return ex;
	}
	if (!index_ge_index(end, start)) {
		res_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), fp, ip pass_file_line);
		goto except_end;
	}

	if (frame_variable_is_flat(fp, slot_a)) {
		struct data *d;
		ajla_error_t err;
		int_default_t st, len;
		const struct type *type = frame_get_type_of_local(fp, slot_a);
		const struct flat_array_definition *flat_def = type_def(type,flat_array);
		if (index_ge_int(end, flat_def->n_elements + 1)) {
			res_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), fp, ip pass_file_line);
			goto except_end;
		}
		st = index_to_int(start);
		len = index_to_int(end) - st;
		d = data_alloc_array_flat_mayfail(flat_def->base, len, len, false, &err pass_file_line);
		if (unlikely(!d)) {
			res_ptr = pointer_error(err, fp, ip pass_file_line);
			goto except_end;
		}
		memcpy(da_array_flat(d), frame_var(fp, slot_a) + st * flat_def->base->size, len * flat_def->base->size);
		res_ptr = pointer_data(d);
		goto except_end;
	}

	ptr = frame_pointer(fp, slot_a);

	if (flags & OPCODE_OP_FLAG_STRICT) {
		array_resolve_thunk(fp, slot_a);
	}

	index_copy(&end_tmp, end);
	ex = array_walk(fp, ip, ptr, &end_tmp, flags, &res_ptr, &can_modify);
	index_free(&end_tmp);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (likely(ex == POINTER_FOLLOW_THUNK_RETRY)) {
			res_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), fp, ip pass_file_line);
			goto except_end;
		}
		if (unlikely(ex == POINTER_FOLLOW_THUNK_EXCEPTION))
			goto except_end;
		if (!(flags & OPCODE_OP_FLAG_STRICT))
			ex = array_sub_create_thunk(fp, ip, slot_a, slot_start, slot_end, slot_r, flags);
		index_free(&start);
		index_free(&end);
		return ex;
	}

	if (!(flags & OPCODE_FLAG_FREE_ARGUMENT) || !frame_test_flag(fp, slot_a))
		can_modify = NULL;

	while (1) {
		struct data *array_data;
		struct data *this_ptr;
		array_index_t this_len;

#if 0
		if (pointer_is_thunk(*ptr)) {
			struct stack_trace st;
			stack_trace_init(&st);
			stack_trace_capture(&st, fp, ip, 20);
			stack_trace_print(&st);
			stack_trace_free(&st);
		}
#endif
		array_data = pointer_get_data(*ptr);

		if (da_tag(array_data) == DATA_TAG_array_incomplete)
			this_ptr = pointer_get_data(da(array_data,array_incomplete)->first);
		else
			this_ptr = array_data;

		this_len = array_len(this_ptr);

		if (!index_ge_index(this_len, start)) {
			index_sub(&start, this_len);
			index_sub(&end, this_len);
			index_free(&this_len);
		} else {
			bool done = false;
			array_index_t this_step;
			ajla_error_t err;
			struct data *t;

			if (can_modify) {
				if (da_tag(array_data) == DATA_TAG_array_incomplete)
					da(array_data,array_incomplete)->first = pointer_empty();
				else
					*ptr = pointer_empty();
			}

			if (!index_ge_index(this_len, end)) {
				index_sub3(&this_step, this_len, start);
			} else {
				index_sub3(&this_step, end, start);
				done = true;
			}
			/*debug("start %lu, end %lu, this_len %lu, this_step %lu", start, end, this_len, this_step);*/
			index_free(&this_len);
			index_sub(&end, this_step);
			index_sub(&end, start);
			t = array_sub(this_ptr, start, this_step, can_modify != NULL, &err);
			index_from_int(&start, 0);

			if (unlikely(!t)) {
				res_ptr = pointer_error(err, fp, ip pass_file_line);
				goto except_end;
			}

			if (!acc) {
				acc = t;
			} else {
				acc = array_join(acc, t, &err);
				if (unlikely(!acc)) {
					res_ptr = pointer_error(err, fp, ip pass_file_line);
					goto except_end;
				}
			}

			if (done) {
				res_ptr = pointer_data(acc);
				acc = NULL;
				break;
			}
		}

		if (unlikely(da_tag(array_data) != DATA_TAG_array_incomplete)) {
			res_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), fp, ip pass_file_line);
			break;
		}
		ptr = &da(array_data,array_incomplete)->next;
	}

except_end:
	index_free(&end);
except_start:
	index_free(&start);
except:
	if (acc)
		data_dereference(acc);
	if (flags & OPCODE_FLAG_FREE_ARGUMENT) {
		if (pointer_is_empty(*frame_pointer(fp, slot_a)))
			frame_clear_flag(fp, slot_a);
		else
			frame_free_and_clear(fp, slot_a);
	}
	frame_set_pointer(fp, slot_r, res_ptr);
	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall ipret_array_skip(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_a, frame_t slot_start, unsigned flags)
{
	array_index_t start, len;
	pointer_t res_ptr;
	pointer_t *can_modify;
	void *ex;
	pointer_t *ptr;
	struct data *a, *ta, *ts;
	ajla_error_t err;
	bool deref;

	ajla_assert(flags & OPCODE_FLAG_FREE_ARGUMENT || !frame_test_flag(fp, slot_r), (file_line, "ipret_array_skip: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));

	ex = ipret_get_index(fp, ip, fp, slot_start, NULL, &start, &res_ptr pass_file_line);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION)
			goto ret;
		return ex;
	}

	if (frame_variable_is_flat(fp, slot_a)) {
		struct data *d;
		ajla_error_t err;
		int_default_t st, len;
		const struct type *type = frame_get_type_of_local(fp, slot_a);
		const struct flat_array_definition *flat_def = type_def(type,flat_array);
		if (index_ge_int(start, flat_def->n_elements + 1)) {
			res_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), fp, ip pass_file_line);
			goto ret_free_start;
		}
		st = index_to_int(start);
		len = flat_def->n_elements - st;
		d = data_alloc_array_flat_mayfail(flat_def->base, len, len, false, &err pass_file_line);
		if (unlikely(!d)) {
			res_ptr = pointer_error(err, fp, ip pass_file_line);
			goto ret_free_start;
		}
		memcpy(da_flat(d), frame_var(fp, slot_a) + st * flat_def->base->size, len * flat_def->base->size);
		res_ptr = pointer_data(d);
		goto ret_free_start;
	}

	ptr = frame_pointer(fp, slot_a);

	if (flags & OPCODE_OP_FLAG_STRICT) {
		array_resolve_thunk(fp, slot_a);
	}

	ex = array_walk(fp, ip, ptr, &start, flags, &res_ptr, &can_modify);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (likely(ex == POINTER_FOLLOW_THUNK_RETRY)) {
			res_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), fp, ip pass_file_line);
			goto ret_free_start;
		}
		if (unlikely(ex == POINTER_FOLLOW_THUNK_EXCEPTION))
			goto ret_free_start;
		if (!(flags & OPCODE_OP_FLAG_STRICT))
			ex = array_skip_create_thunk(fp, ip, slot_a, slot_start, slot_r, flags);
		index_free(&start);
		return ex;
	}

	if (unlikely(index_eq_int(start, 0))) {
		pointer_reference_owned(res_ptr);
		goto ret_free_start;
	}

	if (!(flags & OPCODE_FLAG_FREE_ARGUMENT) || !frame_test_flag(fp, slot_a))
		can_modify = NULL;

	a = pointer_get_data(res_ptr);
	if (da_tag(a) == DATA_TAG_array_incomplete) {
		ta = pointer_get_data(da(a,array_incomplete)->first);
	} else {
		ta = a;
	}

	len = array_len(ta);
	index_sub(&len, start);
	if (unlikely(index_eq_int(len, 0)) && da_tag(a) == DATA_TAG_array_incomplete) {
		res_ptr = pointer_reference(&da(a,array_incomplete)->next);
		index_free(&len);
		goto ret_free_start;
	}
	deref = false;
	if (can_modify) {
		*can_modify = pointer_empty();
		deref = true;
	}
	ts = array_sub(ta, start, len, deref, &err);
	if (unlikely(!ts)) {
		res_ptr = pointer_error(err, fp, ip pass_file_line);
		goto ret;
	}

	if (a != ta) {
		if (deref) {
			da(a,array_incomplete)->first = pointer_data(ts);
			res_ptr = pointer_data(a);
		} else {
			struct data *inc;
			pointer_t next = pointer_reference(&da(a,array_incomplete)->next);
			inc = data_alloc_array_incomplete(ts, next, &err pass_file_line);
			if (unlikely(!inc)) {
				data_dereference(ts);
				pointer_dereference(next);
				res_ptr = pointer_error(err, fp, ip pass_file_line);
				goto ret;
			}
			res_ptr = pointer_data(inc);
		}
	} else {
		res_ptr = pointer_data(ts);
	}
	goto ret;

ret_free_start:
	index_free(&start);
ret:
	if (flags & OPCODE_FLAG_FREE_ARGUMENT) {
		if (pointer_is_empty(*frame_pointer(fp, slot_a)))
			frame_clear_flag(fp, slot_a);
		else
			frame_free_and_clear(fp, slot_a);
	}
	frame_set_pointer(fp, slot_r, res_ptr);
	return POINTER_FOLLOW_THUNK_GO;
}

static void attr_hot ipret_array_append_pointers(frame_s *fp, const code_t *ip, pointer_t *ptr_r, pointer_t ptr_1, pointer_t ptr_2, pointer_t *fn_ptr)
{
	ajla_error_t err;
	struct data *d;

	if (unlikely(fn_ptr != NULL)) {
		if (unlikely(pointer_is_thunk(ptr_1))) {
			struct thunk *result;
			struct data *function_reference;

			if (pointer_is_thunk(ptr_1) && thunk_tag_volatile(pointer_get_thunk(ptr_1)) == THUNK_TAG_EXCEPTION) {
				*ptr_r = ptr_1;
				pointer_dereference(ptr_2);
				return;
			}

			result = build_thunk(fn_ptr, 2, &function_reference);
			data_fill_function_reference(function_reference, 0, ptr_1);
			data_fill_function_reference(function_reference, 1, ptr_2);
			*ptr_r = pointer_thunk(result);
			return;
		} else if (likely(da_tag(pointer_get_data(ptr_1)) == DATA_TAG_array_incomplete)) {
			struct data *first;
			pointer_t last;
			struct thunk *thunk;
			struct data *function_reference, *result;

			array_incomplete_decompose(pointer_get_data(ptr_1), &first, &last);

			thunk = build_thunk(fn_ptr, 2, &function_reference);
			data_fill_function_reference(function_reference, 0, last);
			data_fill_function_reference(function_reference, 1, ptr_2);

			result = data_alloc_array_incomplete(first, pointer_thunk(thunk), &err pass_file_line);
			if (unlikely(!result)) {
				data_dereference(first);
				pointer_dereference(pointer_thunk(thunk));
				*ptr_r = pointer_error(err, fp, ip pass_file_line);
			} else {
				*ptr_r = pointer_data(result);
			}
			return;
		}
	}

	if (unlikely(array_is_empty(pointer_get_data(ptr_1)))) {
		*ptr_r = ptr_2;
		pointer_dereference(ptr_1);
		return;
	}

	if (unlikely(pointer_is_thunk(ptr_2)) || unlikely(da_tag(pointer_get_data(ptr_2)) == DATA_TAG_array_incomplete)) {
		struct data *result;
		result = data_alloc_array_incomplete(pointer_get_data(ptr_1), ptr_2, &err pass_file_line);
		if (unlikely(!result)) {
			pointer_dereference(ptr_1);
			pointer_dereference(ptr_2);
			*ptr_r = pointer_error(err, fp, ip pass_file_line);
		} else {
			*ptr_r = pointer_data(result);
			if (!pointer_is_thunk(ptr_2))
				array_incomplete_collapse(ptr_r);
		}
		return;
	}

	d = array_join(pointer_get_data(ptr_1), pointer_get_data(ptr_2), &err);
	if (!d)
		*ptr_r = pointer_error(err, fp, ip pass_file_line);
	else
		*ptr_r = pointer_data(d);
}

void * attr_hot_fastcall ipret_array_append(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, frame_t slot_2, unsigned flags)
{
	pointer_t *fn_ptr = NULL;
	pointer_t ptr_1, ptr_2, *ptr_r;

	if (unlikely(array_resolve_thunk(fp, slot_1))) {
		void *ex = pcode_find_array_append_function(fp, ip, &fn_ptr);
		if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
			return ex;
	}
	array_resolve_thunk(fp, slot_2);

	ptr_1 = ipret_copy_variable_to_pointer(fp, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);
	ptr_2 = ipret_copy_variable_to_pointer(fp, slot_2, (flags & OPCODE_FLAG_FREE_ARGUMENT_2) != 0);

	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "ipret_array_append: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));

	frame_set_flag(fp, slot_r);
	ptr_r = frame_pointer(fp, slot_r);

	ipret_array_append_pointers(fp, ip, ptr_r, ptr_1, ptr_2, fn_ptr);

	return POINTER_FOLLOW_THUNK_GO;
}

void * attr_hot_fastcall ipret_array_append_one_flat(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, frame_t slot_2, unsigned flags)
{
	const int minimum_size = 16;
	ajla_error_t sink;
	pointer_t ptr;
	struct data *data;
	const struct type *type;
	if (unlikely(!(flags & OPCODE_FLAG_FREE_ARGUMENT)))
		goto fallback;
	if (unlikely(!frame_variable_is_flat(fp, slot_2)))
		goto fallback;
	if (unlikely(!frame_test_flag(fp, slot_1)))
		goto fallback;
	ptr = *frame_pointer(fp, slot_1);
	if (unlikely(pointer_is_thunk(ptr)))
		goto fallback;
	data = pointer_get_data(ptr);
	if (unlikely(da_tag(data) != DATA_TAG_array_flat)) {
		if (likely(da_tag(data) == DATA_TAG_array_pointers) && likely(!da(data,array_pointers)->n_used_entries)) {
			type = frame_get_type_of_local(fp, slot_2);
			data = data_alloc_array_flat_mayfail(type, minimum_size, 0, false, &sink pass_file_line);
			if (unlikely(!data))
				goto fallback;
			pointer_dereference(ptr);
			goto do_copy;
		}
		goto fallback;
	}
	if (unlikely(!data_is_writable(data)))
		goto fallback;
	if (unlikely(da(data,array_flat)->n_used_entries == da(data,array_flat)->n_allocated_entries)) {
		struct data *new_data;
		int_default_t new_size = (uint_default_t)da(data,array_flat)->n_used_entries * 2;
		new_size = maximum(new_size, minimum_size);
		if (unlikely(new_size < 0) ||
		    unlikely(new_size <= da(data,array_flat)->n_used_entries))
			goto fallback;
		type = da(data,array_flat)->type;
		new_data = data_alloc_array_flat_mayfail(type, new_size, da(data,array_flat)->n_used_entries, false, &sink pass_file_line);
		if (unlikely(!new_data))
			goto fallback;
		memcpy(da_array_flat(new_data), da_array_flat(data), da(data,array_flat)->n_used_entries * type->size);
		data_free_r1(data);
		data = new_data;
		goto do_copy;
	}
do_copy:
	type = da(data,array_flat)->type;
	memcpy_fast(da_array_flat(data) + (size_t)da(data,array_flat)->n_used_entries * type->size, frame_var(fp, slot_2), type->size);
	da(data,array_flat)->n_used_entries++;

	frame_clear_flag(fp, slot_1);
	*frame_pointer(fp, slot_1) = pointer_empty();
	frame_set_flag(fp, slot_r);
	*frame_pointer(fp, slot_r) = pointer_data(data);

	return POINTER_FOLLOW_THUNK_GO;
fallback:
	return ipret_array_append_one(fp, ip, slot_r, slot_1, slot_2, flags);
}

void * attr_hot_fastcall ipret_array_append_one(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, frame_t slot_2, unsigned flags)
{
	ajla_error_t err;
	pointer_t *fn_ptr = NULL;
	pointer_t ptr_1, ptr_2, ptr_e, *ptr_r;
	struct data *data;

	if (unlikely(array_resolve_thunk(fp, slot_1))) {
		void *ex = pcode_find_array_append_function(fp, ip, &fn_ptr);
		if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
			return ex;
	}

	ptr_1 = ipret_copy_variable_to_pointer(fp, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);

	if (frame_variable_is_flat(fp, slot_2)) {
		const struct type *type = frame_get_type_of_local(fp, slot_2);
		data = data_alloc_array_flat_mayfail(type, 1, 1, false, &err pass_file_line);
		if (unlikely(!data))
			goto no_flat;
		memcpy_fast(da_array_flat(data), frame_var(fp, slot_2), type->size);
		ptr_2 = pointer_data(data);
		goto have_data;
	}

no_flat:
	ptr_e = ipret_copy_variable_to_pointer(fp, slot_2, (flags & OPCODE_FLAG_FREE_ARGUMENT_2) != 0);

	if (unlikely(pointer_is_thunk(ptr_1)))
		goto fallback;
	data = pointer_get_data(ptr_1);
	if (unlikely(da_tag(data) != DATA_TAG_array_pointers))
		goto fallback;
	if (unlikely(!data_is_writable(data)))
		goto fallback;
	if (unlikely(da(data,array_pointers)->n_used_entries == da(data,array_pointers)->n_allocated_entries)) {
		struct data *new_data;
		size_t new_size = (size_t)da(data,array_pointers)->n_used_entries * 2;
		new_size = maximum(new_size, 16);
		if (unlikely(new_size <= (size_t)da(data,array_pointers)->n_used_entries))
			goto fallback;
		new_data = data_alloc_array_pointers_mayfail(new_size, da(data,array_pointers)->n_used_entries, &err pass_file_line);
		if (unlikely(!new_data))
			goto fallback;
		memcpy(da(new_data,array_pointers)->pointer, da(data,array_pointers)->pointer, da(data,array_pointers)->n_used_entries * sizeof(pointer_t));
		data_free_r1(data);
		data = new_data;
	}
	da(data,array_pointers)->pointer[da(data,array_pointers)->n_used_entries++] = ptr_e;

	frame_set_flag(fp, slot_r);
	*frame_pointer(fp, slot_r) = pointer_data(data);

	return POINTER_FOLLOW_THUNK_GO;

fallback:
	data = data_alloc_array_pointers_mayfail(1, 1, &err pass_file_line);
	if (likely(data != NULL)) {
		da(data,array_pointers)->pointer[0] = ptr_e;
		ptr_2 = pointer_data(data);
	} else {
		pointer_dereference(ptr_e);
		ptr_2 = pointer_error(err, fp, ip pass_file_line);
	}

have_data:
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "ipret_array_append_one: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));
	frame_set_flag(fp, slot_r);
	ptr_r = frame_pointer(fp, slot_r);

	ipret_array_append_pointers(fp, ip, ptr_r, ptr_1, ptr_2, fn_ptr);

	return POINTER_FOLLOW_THUNK_GO;
}

static int_default_t get_array_pointers(unsigned char *flat, const struct type attr_unused *type, int_default_t attr_unused n_elements, pointer_t *ptr, void *context)
{
	struct data *na = context;
	if (unlikely(flat != NULL))
		return 0;
	ajla_assert(da(na,array_pointers)->n_used_entries < da(na,array_pointers)->n_allocated_entries, (file_line, "get_array_pointers: array overrun"));
	da(na,array_pointers)->pointer[da(na,array_pointers)->n_used_entries++] = pointer_reference(ptr);
	return 1;
}

static int_default_t get_array_flat(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t attr_unused *ptr, void *context)
{
	size_t size, i;
	struct data *na = context;
	unsigned char *dest;
	if (unlikely(!flat))
		return 0;
	ajla_assert(da(na,array_flat)->n_used_entries + n_elements <= da(na,array_flat)->n_allocated_entries, (file_line, "get_array_flat: array overrun"));
	size = (size_t)n_elements * type->size;
	dest = da_array_flat(na) + type->size * (size_t)da(na,array_flat)->n_used_entries;
	for (i = 0; i < size; i++, flat++, dest++) {
		if (*flat != 0)
			*dest = *flat;
	}
	da(na,array_flat)->n_used_entries += n_elements;
	return n_elements;
}

static int_default_t get_array_type(unsigned char *flat, const struct type *type, int_default_t attr_unused n_elements, pointer_t attr_unused *ptr, void *context)
{
	if (flat)
		*cast_ptr(const struct type **, context) = type;
	return 0;
}

void * attr_fastcall ipret_array_flatten(frame_s *fp, const code_t *ip, frame_t slot_r, frame_t slot_1, unsigned flags)
{
	ajla_error_t sink;
	pointer_t *ptr;
	struct data *data, *na;
	array_index_t len_long;
	int_default_t len;
	bool success;
	const struct type *flat_type;
	const struct type *array_type = frame_get_type_of_local(fp, slot_r);

	if (frame_variable_is_flat(fp, slot_1))
		goto do_nothing;

	ptr = frame_pointer(fp, slot_1);
next_ptr:
	pointer_follow(ptr, false, data, PF_WAIT, fp, ip,
		return ex_,
		goto do_nothing
	);
	if (unlikely(da_tag(data) == DATA_TAG_array_incomplete)) {
		ptr = &da(data,array_incomplete)->next;
		goto next_ptr;
	}

	array_resolve_thunk(fp, slot_1);

	data = pointer_get_data(*frame_pointer(fp, slot_1));
	if (da_tag(data) == DATA_TAG_array_flat && da(data,array_flat)->n_used_entries == da(data,array_flat)->n_allocated_entries) {
		if (array_type->tag == TYPE_TAG_flat_array) {
			pointer_t p = frame_get_pointer_reference(fp, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);
			na = pointer_get_data(p);
			goto try_to_flatten;
		}
		goto do_nothing;
	}
	if (da_tag(data) == DATA_TAG_array_pointers && da(data,array_pointers)->n_used_entries == da(data,array_pointers)->n_allocated_entries && da(data,array_pointers)->pointer == da(data,array_pointers)->pointer_array) {
		goto do_nothing;
	}

	len_long = array_len(data);
	if (unlikely(!index_is_int(len_long))) {
		index_free(&len_long);
		goto do_nothing;
	}
	len = index_to_int(len_long);
	index_free(&len_long);

	flat_type = NULL;
	index_from_int(&len_long, 0);
	array_onstack_iterate(fp, slot_1, &len_long, get_array_type, &flat_type);
	index_free(&len_long);

	if (!flat_type) {
		na = data_alloc_array_pointers_mayfail(len, 0, &sink pass_file_line);
		if (unlikely(!na))
			goto do_nothing;
		index_from_int(&len_long, 0);
		success = array_onstack_iterate(fp, slot_1, &len_long, get_array_pointers, na);
		index_free(&len_long);
		if (unlikely(!success)) {
			pointer_dereference(pointer_data(na));
			goto do_nothing;
		}
	} else {
		na = data_alloc_array_flat_mayfail(flat_type, len, 0, true, &sink pass_file_line);
		if (unlikely(!na))
			goto do_nothing;
		index_from_int(&len_long, 0);
		success = array_onstack_iterate(fp, slot_1, &len_long, get_array_flat, na);
		index_free(&len_long);
		if (unlikely(!success)) {
			data_free_r1(na);
			goto do_nothing;
		}
	}

	if (flags & OPCODE_FLAG_FREE_ARGUMENT)
		frame_free_and_clear(fp, slot_1);

try_to_flatten:
	if (array_type->tag == TYPE_TAG_flat_array && da_tag(na) == DATA_TAG_array_flat) {
		struct flat_array_definition *fa = type_def(array_type,flat_array);
		if (fa->n_elements == da(na,array_flat)->n_used_entries) {
			memcpy(frame_var(fp, slot_r), da_array_flat(na), array_type->size);
			pointer_dereference(pointer_data(na));
			return POINTER_FOLLOW_THUNK_GO;
		}
	}

	frame_set_pointer(fp, slot_r, pointer_data(na));

	return POINTER_FOLLOW_THUNK_GO;

do_nothing:
	ipret_copy_variable(fp, slot_1, fp, slot_r, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);
	return POINTER_FOLLOW_THUNK_GO;
}

void attr_fastcall ipret_prefetch_functions(struct data *function)
{
	frame_t x;
	for (x = 0; x < da(function,function)->local_directory_size; x++) {
		ajla_error_t sink;
		pointer_t *lfnp, lfn;
		lfnp = da(function,function)->local_directory[x];
		if (pointer_is_thunk(pointer_locked_read(lfnp))) {
			struct execution_control *ex;
			lfn = pointer_reference(lfnp);
			if (unlikely(!pointer_is_thunk(lfn)) || thunk_tag(pointer_get_thunk(lfn)) != THUNK_TAG_FUNCTION_CALL) {
				pointer_dereference(lfn);
				continue;
			}
			ex = function_evaluate_prepare(&sink);
			if (likely(ex != NULL))
				function_evaluate_submit(ex, lfn, NULL, NULL);
			else
				pointer_dereference(lfn);
		}
	}
}


static attr_noinline frame_s *ipret_break(frame_s *top_fp, frame_s *high, frame_s *low)
{
	frame_s *fp;
	struct execution_control *high_ex, *low_ex;
	struct data *high_function, *low_function;
	ajla_error_t sink;
	struct thunk *t;
	struct thunk **result;
	const code_t *ip;
	arg_t ia;

	fp = top_fp;
	do {
		struct data *function = get_frame(fp)->function;
		const struct local_arg *la = da(function,function)->args;
		for (ia = 0; ia < da(function,function)->n_arguments; ia++, la++) {
			frame_t slot;
			pointer_t ptr;
			if (!la->may_be_borrowed)
				continue;
			slot = la->slot;
			ptr = *frame_pointer(fp, slot);
			if (!pointer_is_empty(ptr) && !frame_test_and_set_flag(fp, slot)) {
				ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "ipret_break: thunk doesn't have flag set: %s, %u", da(function,function)->function_name, (unsigned)ia));
				pointer_reference_owned(ptr);
			}
		}
	} while ((fp = frame_up(fp)) != low);

	high_ex = frame_execution_control(high);

	top_fp = stack_split(top_fp, low, &high, &sink);
	if (unlikely(!top_fp))
		goto err0;

	low_ex = execution_control_alloc(&sink);
	if (unlikely(!low_ex))
		goto err1;

	low_ex->stack = frame_stack_bottom(low);
	low_ex->stack->ex = low_ex;
	low_ex->callback = high_ex->callback;

	t = high_ex->thunk;
	low_ex->thunk = t;
	if (t) {
		address_lock(t, DEPTH_THUNK);
		t->u.function_call.u.execution_control = low_ex;
		list_take(&low_ex->wait_list, &high_ex->wait_list);
		address_unlock(t, DEPTH_THUNK);
	}

	high_ex->stack = frame_stack_bottom(high);
	high_ex->stack->ex = high_ex;

	high_function = get_frame(high)->function;
	result = mem_alloc_array_mayfail(mem_alloc_mayfail, struct thunk **, 0, 0, da(high_function,function)->n_return_values, sizeof(struct thunk *), &sink);
	if (unlikely(!result))
		goto err2;

	if (unlikely(!thunk_alloc_blackhole(high_ex, da(get_frame(high)->function,function)->n_return_values, result, &sink)))
		goto err3;

	low_function = get_frame(low)->function;
	ip = da(low_function,function)->code + get_frame(high)->previous_ip;
	low_ex->current_frame = low;

	ia = 0;
	do {
		frame_t dst_slot;

		dst_slot = get_max_param(ip, 0);
		frame_set_pointer(low, dst_slot, pointer_thunk(result[ia]));

		ip += max_param_size(1) + 1;
	} while (++ia < da(high_function,function)->n_return_values);

	low_ex->current_ip = frame_ip(low, ip);

	mem_free(result);

	/*get_frame(low)->timestamp++;*/

	return top_fp;

err3:
	mem_free(result);
err2:
	mem_free(high_ex);
err1:
	stack_free(frame_stack_bottom(top_fp));
err0:
	return NULL;
}

static void * attr_hot_fastcall ipret_break_the_chain(frame_s *fp, const code_t *ip, int waiting, bool *something_breakable)
{
	frame_s *top_fp = fp;
	frame_s *prev_fp;
	struct execution_control *ex;
	timestamp_t t = get_frame(fp)->timestamp++;

	if (!waiting) {
		struct data *top_fn = get_frame(fp)->function;
		if (unlikely(profiling)) {
			profile_counter_t profiling_counter;
			profiling_counter = load_relaxed(&da(top_fn,function)->profiling_counter);
			profiling_counter += profile_sample();
			store_relaxed(&da(top_fn,function)->profiling_counter, profiling_counter);
		}
	}

	*something_breakable = false;

	if (unlikely(frame_execution_control(fp)->atomic != 0))
		goto no_break;

	while (1) {
		uchar_efficient_t mode;
		prev_fp = frame_up(fp);
		if (frame_is_top(prev_fp))
			break;
		mode = get_frame(fp)->mode;
		if (mode == CALL_MODE_STRICT)
			goto skip_this;
		if (mode == CALL_MODE_SPARK || mode == CALL_MODE_WEAKSPARK || (timestamp_t)(t - get_frame(prev_fp)->timestamp) > break_ticks) {
			struct execution_control *low_ex, *high_ex;
			frame_s *new_fp;
			/*debug("break: %s - %s (%u - %u - %u)", da(get_frame(prev_fp)->function,function)->function_name, da(get_frame(fp)->function,function)->function_name, t, get_frame(prev_fp)->timestamp, get_frame(fp)->timestamp);*/
			/*debug("break %"PRIuMAX"", (uintmax_t)++break_count);*/
			new_fp = ipret_break(top_fp, fp, prev_fp);
			if (unlikely(!new_fp))
				break;
			low_ex = frame_execution_control(prev_fp);
			if (waiting > 0) {
				high_ex = frame_execution_control(new_fp);
				high_ex->current_frame = new_fp;
#if 0
				task_submit(low_ex, mode == CALL_MODE_SPARK ? TASK_SUBMIT_MUST_SPAWN : TASK_SUBMIT_MAY_SPAWN);
				return NULL;
#else
				waiting = -1;
				goto cont_with_low_ex;
#endif
			}
#if 0
			task_submit(low_ex, mode == CALL_MODE_SPARK ? TASK_SUBMIT_MUST_SPAWN : TASK_SUBMIT_MAY_SPAWN);
			top_fp = new_fp;
			break;
#else
			high_ex = frame_execution_control(new_fp);
			high_ex->current_frame = new_fp;
			high_ex->current_ip = frame_ip(new_fp, ip);
			task_submit(high_ex, mode == CALL_MODE_SPARK ? TASK_SUBMIT_MUST_SPAWN : TASK_SUBMIT_MAY_SPAWN);
cont_with_low_ex:
			prev_fp = top_fp = low_ex->current_frame;
			ip = da(get_frame(top_fp)->function,function)->code + low_ex->current_ip;
			/*t = get_frame(top_fp)->timestamp;*/
#endif
		} else {
			*something_breakable = true;
		}
skip_this:
		fp = prev_fp;
	}

no_break:
	if (waiting > 0)
		return NULL;
	ex = frame_execution_control(top_fp);
	ex->current_frame = top_fp;
	ex->current_ip = frame_ip(top_fp, ip);
	return ex;
}

bool attr_fastcall ipret_break_waiting_chain(frame_s *fp, ip_t ip)
{
	bool something_breakable;
	struct execution_control *ex;

	ex = ipret_break_the_chain(fp, da(get_frame(fp)->function,function)->code + ip, 1, &something_breakable);
	if (ex)
		task_submit(ex, TASK_SUBMIT_MAY_SPAWN);

	return something_breakable;
}

void * attr_hot_fastcall ipret_tick(frame_s *fp, const code_t *ip)
{
	bool sink;
	struct execution_control *ex;

	waiting_list_break();

	ex = ipret_break_the_chain(fp, ip, 0, &sink);

	return task_schedule(ex);
}

#endif
