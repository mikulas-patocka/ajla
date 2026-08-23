/*
 * Copyright (C) 2025, 2026 Mikulas Patocka
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
#include "md.h"

#include "offload.h"

static void copy_results(frame_s *fp, const code_t *ip, uint32_t n_dims, uint32_t n_args, uint32_t n_results)
{
	ajla_error_t err;
	pointer_t *buffer;
	pointer_t ptr;
	uint32_t i;
	ip_t offset;
	buffer = mem_alloc_array_mayfail(mem_alloc_mayfail, pointer_t *, 0, 0, n_results, sizeof(pointer_t), &err);
	offset = 13 + 4 * n_dims + 2 * n_args;
	for (i = 0; i < n_results; i++) {
		uint32_t result_in = get_unaligned_32(ip + offset);
		bool deref = !!(get_unaligned_32(ip + offset + 2) & OPCODE_FLAG_FREE_ARGUMENT);
		offset += 6;
		ptr = ipret_copy_variable_to_pointer(fp, result_in, deref);
		if (likely(buffer != NULL)) {
			buffer[i] = ptr;
		} else {
			pointer_dereference(ptr);
		}
	}
	offset = 13 + 4 * n_dims + 2 * n_args;
	for (i = 0; i < n_results; i++) {
		uint32_t result_out = get_unaligned_32(ip + offset + 4);
		offset += 6;
		if (likely(buffer != NULL)) {
			frame_set_pointer(fp, result_out, buffer[i]);
		} else {
			struct thunk *t = thunk_alloc_exception_error(err, NULL, NULL, NULL pass_file_line);
			frame_set_pointer(fp, result_out, pointer_thunk(t));
		}
	}
	if (likely(buffer != NULL))
		mem_free(buffer);
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
	struct data *function_name;
	struct data *shape;
	struct data *args;
	struct data *arg_types;
	struct data *arg_lengths;
	struct data *arg_n_entries;
	struct data *results_in;
	struct data *results_out;
	struct data *results_lengths;
	struct data *blob;
	struct data *results = NULL;
	pointer_t result_ptr;
	uint32_t n_dims, n_args, n_results, blob_len;
	const char *name;
	size_t name_len;
	ip_t offset;
	size_t i;
	uint32_t q;

	result_slot = get_unaligned_32(ip + 1);
	record_idx = get_unaligned_32(ip + 3);
	n_dims = get_unaligned_32(ip + 7);
	n_args = get_unaligned_32(ip + 9);
	n_results = get_unaligned_32(ip + 11);

	record_ptr = &da(get_frame(fp)->function,function)->function_pointers[record_idx]->ptr;
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

	name = da(get_frame(fp)->function,function)->function_name;
	/*debug("OFFLOADING: %s: %x %x %x", name, n_dims, n_args, n_results);*/
	name_len = strlen(name);
	function_name = data_alloc_array_flat_mayfail(type_get_fixed(0, true), name_len, name_len, false, &err pass_file_line);
	if (unlikely(!function_name))
		goto set_err;
	memcpy(da_array_flat(function_name), name, name_len);
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[0], pointer_data(function_name));

	shape = data_alloc_array_flat_mayfail(type_get_int(INT_DEFAULT_N), n_dims, n_dims, false, &err pass_file_line);
	if (unlikely(!shape))
		goto set_err;
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[1], pointer_data(shape));

	args = data_alloc_array_pointers_mayfail(n_args, n_args, &err pass_file_line);
	if (unlikely(!args))
		goto set_err;
	for (i = 0; i < n_args; i++)
		da(args,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[2], pointer_data(args));

	arg_types = data_alloc_array_flat_mayfail(type_get_bool(), n_args, n_args, false, &err pass_file_line);
	if (unlikely(!arg_types))
		goto set_err;
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[3], pointer_data(arg_types));

	arg_lengths = data_alloc_array_pointers_mayfail(n_args, n_args, &err pass_file_line);
	if (unlikely(!arg_lengths))
		goto set_err;
	for (i = 0; i < n_args; i++)
		da(arg_lengths,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[4], pointer_data(arg_lengths));

	arg_n_entries = data_alloc_array_pointers_mayfail(n_args, n_args, &err pass_file_line);
	if (unlikely(!arg_n_entries))
		goto set_err;
	for (i = 0; i < n_args; i++)
		da(arg_n_entries,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[5], pointer_data(arg_n_entries));

	results_in = data_alloc_array_pointers_mayfail(n_results, n_results, &err pass_file_line);
	if (unlikely(!results_in))
		goto set_err;
	for (i = 0; i < n_results; i++)
		da(results_in,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[6], pointer_data(results_in));

	results_out = data_alloc_array_pointers_mayfail(n_results, n_results, &err pass_file_line);
	if (unlikely(!results_out))
		goto set_err;
	for (i = 0; i < n_results; i++)
		da(results_out,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[7], pointer_data(results_out));

	results_lengths = data_alloc_array_pointers_mayfail(n_results, n_results, &err pass_file_line);
	if (unlikely(!results_lengths))
		goto set_err;
	for (i = 0; i < n_results; i++)
		da(results_lengths,array_pointers)->pointer[i] = pointer_empty();
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[8], pointer_data(results_lengths));

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
				if (unlikely(da_tag(array_data) == DATA_TAG_array_incomplete)) {
					if (ipret_warnings)
						warning("%s: incomplete array", name);
					goto set_unsupp;
				}
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
	}

	for (i = 0; i < n_args; i++) {
		const struct type *type;
		struct data *d;
		uint32_t slot = get_unaligned_32(ip + offset);
		offset += 2;

		type = frame_get_type_of_local(fp, slot);

		if (TYPE_TAG_IS_BUILTIN(type->tag)) {
			float flt;
			ajla_flat_option_t fo;
			unsigned char *flat;
			int ffi_type;
			size_t len;
			if (frame_test_flag(fp, slot)) {
				pointer_t *ptr = frame_pointer(fp, slot);
				pointer_follow(ptr, true, d, PF_WAIT, fp, ip,
					ex = ex_;
					goto return_ex,
					thunk_reference(thunk_);
					result_ptr = pointer_thunk(thunk_);
					goto set_result;
				);
				if (da_tag(d) == DATA_TAG_option) {
					fo = da(d,option)->option;
					if (unlikely(fo != da(d,option)->option))
						goto set_unsupp;
					flat = cast_ptr(unsigned char *, &fo);
				} else if (da_tag(d) == DATA_TAG_longint) {
					goto set_unsupp;
				} else {
					flat = da_flat(d);
				}
			} else {
				flat = frame_var(fp, slot);
			}
			if (TYPE_TAG_IS_REAL(type->tag) && !TYPE_TAG_IDX_REAL(type->tag)) {
				type = type_get_real(1);
				flt = half_to_float(*cast_ptr(uint16_t *, flat));
				flat = cast_ptr(unsigned char *, &flt);
			}
			if (type->tag == TYPE_TAG_bool || type->tag == TYPE_TAG_flat_opt) {
				type = type_get_fixed(log_2(sizeof(ajla_flat_option_t)), true);
			}
			d = type_to_mpint(type, flat, &err);
			if (unlikely(!d))
				goto set_err;
			da(args,array_pointers)->pointer[i] = pointer_data(d);

			ffi_type = io_ffi_get_ffi_type(type);
			if (unlikely(ffi_type == -1)) {
				if (ipret_warnings)
					warning("%s: unknown type", name);
				goto set_unsupp;
			}
			cast_ptr(ajla_flat_option_t *, da_array_flat(arg_types))[i] = ffi_type;

			len = type->size;
			d = type_to_mpint(type_get_fixed(log_2(sizeof(size_t)), true), cast_ptr(const unsigned char *, &len), &err);
			if (unlikely(!d))
				goto set_err;
			da(arg_lengths,array_pointers)->pointer[i] = pointer_data(d);

			len = 1;
			d = type_to_mpint(type_get_fixed(log_2(sizeof(size_t)), true), cast_ptr(const unsigned char *, &len), &err);
			if (unlikely(!d))
				goto set_err;
			da(arg_n_entries,array_pointers)->pointer[i] = pointer_data(d);
		} else {
			pointer_t *ptr;
			uintptr_t flat;
			size_t len;
			int_default_t n_entries;
			struct data *d;
			if (unlikely(frame_variable_is_flat(fp, slot))) {
				pointer_t non_flat_ptr;
				type = frame_get_type_of_local(fp, slot);
				non_flat_ptr = flat_to_data(type, frame_var(fp, slot));
				frame_set_pointer(fp, slot, non_flat_ptr);
			}

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
				n_entries = da(d,array_flat)->n_used_entries;
			} else if (da_tag(d) == DATA_TAG_array_slice) {
				flat = ptr_to_num(da(d,array_slice)->flat_data_minus_data_array_offset + data_array_offset);
				len = (size_t)da(d,array_slice)->n_entries * da(d,array_slice)->type->size;
				n_entries = da(d,array_slice)->n_entries;
			} else {
				if (ipret_warnings)
					warning("%s: array is not flat", name);
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

			d = type_to_mpint(type_get_fixed(log_2(sizeof(int_default_t)), false), cast_ptr(const unsigned char *, &n_entries), &err);
			if (unlikely(!d))
				goto set_err;
			da(arg_n_entries,array_pointers)->pointer[i] = pointer_data(d);
		}
	}

	results = data_alloc_array_pointers_mayfail(n_results, n_results, &err pass_file_line);
	if (unlikely(!results))
		goto set_err;
	for (i = 0; i < n_results; i++)
		da(results,array_pointers)->pointer[i] = pointer_empty();

	for (i = 0; i < n_results; i++) {
		pointer_t *ptr;
		struct data *in_d, *out_d;
		uintptr_t out_flat;
		size_t len;
		const struct type *type;
		struct data *d;
		size_t new_size;
		uint32_t in_slot = get_unaligned_32(ip + offset);
		offset += 6;

		if (unlikely(frame_variable_is_flat(fp, in_slot))) {
			pointer_t non_flat_ptr;
			type = frame_get_type_of_local(fp, in_slot);
			non_flat_ptr = flat_to_data(type, frame_var(fp, in_slot));
			frame_set_pointer(fp, in_slot, non_flat_ptr);
		}

		ptr = frame_pointer(fp, in_slot);
		pointer_follow(ptr, true, in_d, PF_WAIT, fp, ip,
			ex = ex_;
			goto return_ex,
			thunk_reference(thunk_);
			result_ptr = pointer_thunk(thunk_);
			goto set_result;
		);

		if (likely(da_tag(in_d) == DATA_TAG_array_flat)) {
			type = da(in_d,array_flat)->type;
			len = (size_t)da(in_d,array_flat)->n_used_entries;
		} else {
			if (ipret_warnings)
				warning("%s: output array is not flat", name);
			goto set_unsupp;
		}

		out_d = data_alloc_array_flat_mayfail(type, len, len, false, &err pass_file_line);
		if (unlikely(!out_d))
			goto set_err;
		da(results,array_pointers)->pointer[i] = pointer_data(out_d);
		out_flat = ptr_to_num(da_array_flat(out_d));

		d = data_alloc_array_slice_mayfail(in_d, da_array_flat(in_d), 0, len, &err pass_file_line);
		if (unlikely(!d))
			goto set_err;
		new_size = (size_t)da(d,array_slice)->n_entries * type->size;
		if (unlikely((int_default_t)new_size < 0) || unlikely((size_t)(int_default_t)new_size != new_size)) {
			if (ipret_warnings)
				warning("%s: array size overflow", name);
			goto set_unsupp;
		}
		da(d,array_slice)->type = type_get_fixed(0, true);
		da(d,array_slice)->n_entries = new_size;
		da(results_in,array_pointers)->pointer[i] = pointer_data(d);

		d = type_to_mpint(type_get_fixed(log_2(sizeof(uintptr_t)), true), cast_ptr(const unsigned char *, &out_flat), &err);
		if (unlikely(!d))
			goto set_err;
		da(results_out,array_pointers)->pointer[i] = pointer_data(d);

		len *= type->size;
		d = type_to_mpint(type_get_fixed(log_2(sizeof(size_t)), true), cast_ptr(const unsigned char *, &len), &err);
		if (unlikely(!d))
			goto set_err;
		da(results_lengths,array_pointers)->pointer[i] = pointer_data(d);
	}

	offset = 13 + 4 * n_dims + 2 * n_args + 6 * n_results;
	blob_len = get_unaligned_32(ip + offset);
	offset += 2;
	blob = data_alloc_array_flat_mayfail(type_get_fixed(0, true), blob_len, blob_len, false, &err pass_file_line);
	if (unlikely(!blob))
		goto set_err;
	frame_set_pointer(da_record_frame(record), record_definition->idx_to_frame[9], pointer_data(blob));
	q = 0;
	for (i = 0; i < blob_len; i++) {
		uint8_t val;
		if (!(i & 3)) {
			q = get_unaligned_32(ip + offset);
			offset += 2;
		}
		val = q;
		q >>= 8;
		da_array_flat(blob)[i] = val;
	}

	offset = 13 + 4 * n_dims + 2 * n_args;
	for (i = 0; i < n_results; i++) {
		uint32_t result_in = get_unaligned_32(ip + offset);
		bool deref = !!(get_unaligned_32(ip + offset + 2) & OPCODE_FLAG_FREE_ARGUMENT);
		offset += 6;
		if (deref)
			frame_free(fp, result_in);
	}
	offset = 13 + 4 * n_dims + 2 * n_args;
	for (i = 0; i < n_results; i++) {
		uint32_t result_out = get_unaligned_32(ip + offset + 4);
		offset += 6;
		frame_set_pointer(fp, result_out, da(results,array_pointers)->pointer[i]);
	}
	data_free_r1(results);
	frame_set_pointer(fp, result_slot, pointer_data(record));
	return POINTER_FOLLOW_THUNK_GO;

set_result:
	if (record)
		pointer_dereference(pointer_data(record));
	if (results)
		pointer_dereference(pointer_data(results));
	frame_set_pointer(fp, result_slot, result_ptr);
	copy_results(fp, ip, n_dims, n_args, n_results);
	return POINTER_FOLLOW_THUNK_GO;

set_unsupp:
	err = error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED);
set_err:
	if (record)
		pointer_dereference(pointer_data(record));
	if (results)
		pointer_dereference(pointer_data(results));
	frame_set_pointer(fp, result_slot, pointer_error(err, fp, ip pass_file_line));
	copy_results(fp, ip, n_dims, n_args, n_results);
	return POINTER_FOLLOW_THUNK_GO;

return_ex:
	if (record)
		pointer_dereference(pointer_data(record));
	if (results)
		pointer_dereference(pointer_data(results));
	return ex;
}

#endif
