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
					err = error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED);
					goto set_err;
				}
				idx = array_len(array_data);
				goto process_idx;
				break;
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

	frame_set_pointer(fp, result_slot, pointer_data(record));
	copy_results(fp, ip, n_dims, n_args, n_results);
	return POINTER_FOLLOW_THUNK_GO;

set_result:
	if (record)
		pointer_dereference(pointer_data(record));
	frame_set_pointer(fp, result_slot, result_ptr);
	copy_results(fp, ip, n_dims, n_args, n_results);
	return POINTER_FOLLOW_THUNK_GO;

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
