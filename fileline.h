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

#ifndef AJLA_FILELINE_H
#define AJLA_FILELINE_H

#ifdef DEBUG_TRACK_FILE_LINE
#define argument_position	, const char attr_unused *position_arg
#define pass_position		, position_arg
#define pass_file_line		, file_line
typedef const char *		position_t;
#define position_string(x)	(x)
#define position_string_alloc(x) (x)
#define position_string_free(x)	do { } while (0)
#define caller_file_line	position_string(position_arg)
#define caller_file_line_x	caller_file_line
#else
#define argument_position
#define pass_position
#define pass_file_line
typedef void *			position_t;
const char *position_string(void *);
const char *position_string_alloc(void *);
#define position_string_free(x)	mem_free(x)
#ifdef return_address
#define position_arg		return_address
#define caller_file_line	position_string(position_arg)
#else
#define position_arg		NULL
#define caller_file_line	file_line
#endif
#define caller_file_line_x	file_line
#endif

#endif
