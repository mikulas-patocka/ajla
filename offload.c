/*
 * Copyright (C) 2025 Mikulas Patocka
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

#include "ipunalg.h"
#include "data.h"
#include "array.h"
#include "ipfn.h"
#include "ipio.h"
#include "arindex.h"

#include "offload.h"

static void copy_results(frame_s *fp, const code_t *ip, uint32_t n_dims, uint32_t n_args, uint32_t n_results)
{
	ip_t offset = 13 + 4 * n_dims + 2 * n_args;
	uint32_t i;
	debug("n_results: %x", n_results);
	for (i = 0; i < n_results; i++) {
		uint32_t result_in = get_unaligned_32(ip + offset);
		bool deref = !!(get_unaligned_32(ip + offset + 2) & OPCODE_FLAG_FREE_ARGUMENT);
		uint32_t result_out = get_unaligned_32(ip + offset + 4);
		offset += 6;
		debug("result: %x - %x", result_in, result_out);
		ipret_copy_variable(fp, result_in, fp, result_out, deref);
	}
}

static struct data *type_to_mpint(const struct type *type, const unsigned char *flat, ajla_error_t *err)
{
	bool ret;
	struct data *d;
	if (TYPE_TAG_IS_REAL(type->tag)) {
		d = io_ffi_encode_real(type, flat, err);
		if (unlikely(!d))
			return NULL;
		return d;
	}
	d = data_alloc_longint_mayfail((size_t)type->size * 8, err pass_file_line);
	if (unlikely(!d))
		return NULL;
	switch (type->tag) {
#define fx(n, s, u, sz, bits)						\
		case TYPE_TAG_integer + n:				\
		case TYPE_TAG_fixed + 2 * n + TYPE_TAG_fixed_signed: {	\
			s val = *cast_ptr(s *, flat);			\
			ret = cat(mpint_set_from_,s)(&da(d,longint)->mp, val, false, err);\
			break;						\
		}							\
		case TYPE_TAG_fixed + 2 * n + TYPE_TAG_fixed_unsigned: {\
			s val = *cast_ptr(s *, flat);			\
			ret = cat(mpint_set_from_,s)(&da(d,longint)->mp, val, true, err);\
			break;						\
		}
		for_all_fixed(fx);
		default:
			internal(file_line, "type_to_mpint: invalid type tag %u", type->tag);
#undef fx
	}
	if (unlikely(!ret)) {
		pointer_dereference(pointer_data(d));
		return NULL;
	}
	return d;
}

void *ipret_offload(frame_s *fp, const code_t *ip)
{
	void *ex;
	ajla_error_t err;
	frame_t result_slot;
	size_t record_idx;
	pointer_t *record_ptr;
	struct data *record_fn;
	const struct record_definition *record_definition;
	struct data *record = NULL;
	struct data *shape;
	struct data *args;
	struct data *arg_types;
	struct data *arg_lengths;
	pointer_t result_ptr;
	uint32_t n_dims, n_args, n_results;
	ip_t offset;
	size_t i;

	result_slot = get_unaligned_32(ip + 1);
	record_idx = get_unaligned_32(ip + 3);
	n_dims = get_unaligned_32(ip + 7);
	n_args = get_unaligned_32(ip + 9);
	n_results = get_unaligned_32(ip + 11);

	record_ptr = da(get_frame(fp)->function,function)->local_directory[record_idx];
	pointer_follow(record_ptr, false, record_fn, PF_WAIT, fp, ip,
		ex = ex_;
		goto return_ex,
		thunk_reference(thunk_);
		result_ptr = pointer_thunk(thunk_);
		goto set_result;
	);
	record_definition = type_def(da(record_fn,function)->record_definition,record);
	record = data_alloc_record_mayfail(record_definition, &err pass_file_line);
	if (unlikely(!record))
		goto set_err;
	memset(da_record_frame(record), 0, bitmap_slots(record_definition->n_slots) * slot_size);

	debug("OFFLOADING: %x %x %x", n_dims, n_args, n_results);

	shape = data_alloc_array_flat_mayfail(type_get_int(INT_DEFAULT_N), n_dims, n_dims, false, &err pass_file_line);
	if (unlikely(!shape))
		goto set_err;
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[0], pointer_data(shape));

	args = data_alloc_array_pointers_mayfail(n_args, n_args, &err pass_file_line);
	if (unlikely(!args))
		goto set_err;
	for (i = 0; i < n_args; i++)
		da(args,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[1], pointer_data(args));

	arg_types = data_alloc_array_flat_mayfail(type_get_flat_option(), n_args, n_args, false, &err pass_file_line);
	if (unlikely(!arg_types))
		goto set_err;
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[2], pointer_data(arg_types));

	arg_lengths = data_alloc_array_pointers_mayfail(n_args, n_args, &err pass_file_line);
	if (unlikely(!arg_lengths))
		goto set_err;
	for (i = 0; i < n_args; i++)
		da(arg_lengths,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[3], pointer_data(arg_lengths));

	offset = 13;
	for (i = 0; i < n_dims; i++) {
		int_default_t len;
		array_index_t idx;
		pointer_t *ptr;
		struct data *array_data;
		uint32_t dim_mode = get_unaligned_32(ip + offset);
		uint32_t dim_size = get_unaligned_32(ip + offset + 2);
		offset += 4;
		switch (dim_mode) {
			case 1:
				ex = ipret_get_index(fp, ip, fp, dim_size, NULL, &idx, &result_ptr pass_file_line);
				if (unlikely(ex == POINTER_FOLLOW_THUNK_EXCEPTION)) {
					goto set_result;
				}
				if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
					goto return_ex;
				}
process_idx:
				if (index_is_int(idx)) {
					len = index_to_int(idx);
					index_free(&idx);
				} else {
					index_free(&idx);
					err = error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW);
					goto set_err;
				}
				break;
			case 2:
				len = (int32_t)dim_size;
				break;
			case 3:
				ptr = frame_pointer(fp, dim_size);
				pointer_follow(ptr, true, array_data, PF_WAIT, fp, ip,
					ex = ex_;
					goto return_ex,
					thunk_reference(thunk_);
					result_ptr = pointer_thunk(thunk_);
					goto set_result;
				);
				if (unlikely(da_tag(array_data) == DATA_TAG_array_incomplete))
					goto set_unsupp;
				idx = array_len(array_data);
				goto process_idx;
			default:
				internal(file_line, "ipret_offload: invalid dim mode %lu", (unsigned long)dim_mode);
		}
		if (unlikely(len < 0)) {
			err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
			goto set_err;
		}
		cast_ptr(int_default_t *, da_array_flat(shape))[i] = len;
		debug("dim %u, len %lx", (int)i, (long)len);
	}

	for (i = 0; i < n_args; i++) {
		const struct type *type;
		struct data *d;
		uint32_t slot = get_unaligned_32(ip + offset);
		offset += 2;

		type = frame_get_type_of_local(fp, slot);

		if (TYPE_TAG_IS_BUILTIN(type->tag)) {
			unsigned char *flat;
			int ffi_type;
			size_t len = type->size;
			if (frame_test_flag(fp, slot)) {
				pointer_t *ptr = frame_pointer(fp, slot);
				pointer_follow(ptr, true, d, PF_WAIT, fp, ip,
					ex = ex_;
					goto return_ex,
					thunk_reference(thunk_);
					result_ptr = pointer_thunk(thunk_);
					goto set_result;
				);
				if (da_tag(d) == DATA_TAG_longint) {
					pointer_reference_owned(pointer_data(d));
					goto set_ptr;
				}
				flat = da_flat(d);
			} else {
				flat = frame_var(fp, slot);
			}
			d = type_to_mpint(type, flat, &err);
			if (unlikely(!d))
				goto set_err;
set_ptr:
			da(args,array_pointers)->pointer[i] = pointer_data(d);

			ffi_type = io_ffi_get_ffi_type(type);
			if (unlikely(ffi_type == -1))
				goto set_unsupp;
			cast_ptr(ajla_flat_option_t *, da_array_flat(arg_types))[i] = ffi_type;

			d = type_to_mpint(type_get_fixed(log_2(sizeof(size_t)), true), cast_ptr(const unsigned char *, &len), &err);
			if (unlikely(!d))
				goto set_err;
			da(arg_lengths,array_pointers)->pointer[i] = pointer_data(d);
		} else {
			pointer_t *ptr;
			uintptr_t flat;
			size_t len;
			struct data *d;
			if (TYPE_IS_FLAT(type) && !frame_test_flag(fp, slot))
				goto set_unsupp;
			ptr = frame_pointer(fp, slot);
			pointer_follow(ptr, true, d, PF_WAIT, fp, ip,
				ex = ex_;
				goto return_ex,
				thunk_reference(thunk_);
				result_ptr = pointer_thunk(thunk_);
				goto set_result;
			);
			if (da_tag(d) == DATA_TAG_array_flat) {
				flat = ptr_to_num(da_array_flat(d));
				len = (size_t)da(d,array_flat)->n_used_entries * da(d,array_flat)->type->size;
			} else if (da_tag(d) == DATA_TAG_array_slice) {
				flat = ptr_to_num(da(d,array_slice)->flat_data_minus_data_array_offset + data_array_offset);
				len = (size_t)da(d,array_slice)->n_entries * da(d,array_slice)->type->size;
			} else {
				goto set_unsupp;
			}

			d = type_to_mpint(type_get_fixed(log_2(sizeof(uintptr_t)), true), cast_ptr(const unsigned char *, &flat), &err);
			if (unlikely(!d))
				goto set_err;
			da(args,array_pointers)->pointer[i] = pointer_data(d);

			cast_ptr(ajla_flat_option_t *, da_array_flat(arg_types))[i] = 0;

			d = type_to_mpint(type_get_fixed(log_2(sizeof(size_t)), true), cast_ptr(const unsigned char *, &len), &err);
			if (unlikely(!d))
				goto set_err;
			da(arg_lengths,array_pointers)->pointer[i] = pointer_data(d);
		}
	}

	frame_set_pointer(fp, result_slot, pointer_data(record));
	copy_results(fp, ip, n_dims, n_args, n_results);
	return POINTER_FOLLOW_THUNK_GO;

set_result:
	if (record)
		pointer_dereference(pointer_data(record));
	frame_set_pointer(fp, result_slot, result_ptr);
	copy_results(fp, ip, n_dims, n_args, n_results);
	return POINTER_FOLLOW_THUNK_GO;

set_unsupp:
	err = error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED);
set_err:
	if (record)
		pointer_dereference(pointer_data(record));
	frame_set_pointer(fp, result_slot, pointer_error(err, fp, ip pass_file_line));
	copy_results(fp, ip, n_dims, n_args, n_results);
	return POINTER_FOLLOW_THUNK_GO;

return_ex:
	if (record)
		pointer_dereference(pointer_data(record));
	return ex;
}

#endif
