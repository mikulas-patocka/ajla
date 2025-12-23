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

#include "offload.h"

void *ipret_offload(frame_s *fp, const code_t *ip)
{
	ajla_error_t err;
	frame_t result_slot;
	size_t record_idx;
	pointer_t *record_ptr;
	struct data *record_fn;
	const struct record_definition *record_definition;
	struct data *record;
	pointer_t result_ptr;

	result_slot = get_unaligned_32(ip + 1);
	record_idx = get_unaligned_32(ip + 3);
	record_ptr = da(get_frame(fp)->function,function)->local_directory[record_idx];
	pointer_follow(record_ptr, false, record_fn, PF_WAIT, fp, ip,
		return ex_,
		thunk_reference(thunk_);
		result_ptr = pointer_thunk(thunk_);
		goto set_result;
	);
	record_definition = type_def(da(record_fn,function)->record_definition,record);
	record = data_alloc_record_mayfail(record_definition, &err pass_file_line);
	if (unlikely(!record))
		goto set_err;

	result_ptr = pointer_data(record);

set_result:
	frame_set_pointer(fp, result_slot, result_ptr);
	return POINTER_FOLLOW_THUNK_GO;

set_err:
	frame_set_pointer(fp, result_slot, pointer_error(err, fp, ip pass_file_line));
	return POINTER_FOLLOW_THUNK_GO;
}

#endif
