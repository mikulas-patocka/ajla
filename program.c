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

#include "module.h"
#include "funct.h"
#include "task.h"
#include "module.h"
#include "builtin.h"

static void program_callback(void attr_unused *callback_cookie, pointer_t ptr)
{
	if (likely(!pointer_is_empty(ptr))) {
		if (unlikely(pointer_is_thunk(ptr))) {
			struct thunk *t = pointer_get_thunk(ptr);
			struct thunk_exception *te = &t->u.exception;
			if (te->err.error_class == EC_EXIT && te->err.error_type == AJLA_ERROR_EXIT) {
				if (unlikely(te->err.error_aux < 0) || unlikely(te->err.error_aux >= 256))
					retval = EXCEPTION_RETVAL;
				else
					retval = te->err.error_aux;
				if (te->msg)
					stderr_msg("%s", te->msg);
			} else {
				thunk_exception_print(t);
				retval = EXCEPTION_RETVAL;
			}
		} else {
			tag_t attr_unused tag = da_tag(pointer_get_data(ptr));
			ajla_assert_lo(tag == DATA_TAG_option, (file_line, "program_callback: data tag %02x", tag));
		}
	}
	task_program_exited();
}

void name(program_run)(void)
{
	struct data *function_reference;
	struct thunk *thunk;

	function_reference = data_alloc_function_reference_mayfail(0, NULL pass_file_line);
	da(function_reference,function_reference)->is_indirect = false;
	da(function_reference,function_reference)->u.direct = start_fn;

	thunk_alloc_function_call(pointer_data(function_reference), 1, &thunk, NULL);

	task_program_started();
	function_evaluate_submit(function_evaluate_prepare(NULL), pointer_thunk(thunk), program_callback, NULL);
}

#endif
