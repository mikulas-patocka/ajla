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

#ifndef AJLA_ERROR_H
#define AJLA_ERROR_H

#ifdef EINTR
#define EINTR_LOOP_VAL(ret_, err_, call_)				\
do {									\
	(ret_) = (call_);						\
} while (unlikely((ret_) == (err_)) && unlikely(errno == EINTR))
#else
#define EINTR_LOOP_VAL(ret_, err_, call_)				\
do {									\
	(ret_) = (call_);						\
} while (0)
#endif

#define EINTR_LOOP(ret_, call_)		EINTR_LOOP_VAL(ret_, -1, call_)


typedef struct {
	short error_class;
	short error_type;
	int error_aux;
#if defined(DEBUG_ERROR) && defined(DEBUG_TRACK_FILE_LINE)
	char position[20];
#endif
} ajla_error_t;

const char *error_decode(ajla_error_t);
void trace_v(const char *, va_list);
void trace(const char *, ...) attr_printf(1, 2);
void stderr_msg_v(const char *m, va_list l);
void stderr_msg(const char *, ...) attr_printf(1, 2);
void debug_v(const char *, va_list);
void debug(const char *, ...) attr_printf(1, 2);
void warning_v(const char *, va_list);
void warning(const char *, ...) attr_printf(1, 2);
attr_noreturn fatal_v(const char *, va_list);
attr_noreturn attr_printf(1, 2) fatal(const char *, ...);
attr_noreturn internal_v(const char *, const char *, va_list);
attr_noreturn attr_printf(2, 3) internal(const char *, const char *, ...);

#define MEM_DONT_TRY_TO_FREE		((ajla_error_t *)SPECIAL_POINTER_1)

void fatal_mayfail(ajla_error_t, ajla_error_t *, const char *, ...) attr_printf(3, 4);
void fatal_warning_mayfail(ajla_error_t, ajla_error_t *, const char *, ...) attr_printf(3, 4);

static inline ajla_error_t error_ajla_aux_(int ec, int type, int aux argument_position)
{
	ajla_error_t e;
	if (unlikely(type < AJLA_ERROR_BASE) ||
	    unlikely(type >= AJLA_ERROR_N))
		internal(file_line, "invalid ajla error type %d", type);
	e.error_class = ec;
	e.error_type = type;
	e.error_aux = aux;
#if defined(DEBUG_ERROR) && defined(DEBUG_TRACK_FILE_LINE)
	strncpy(e.position, position_arg, sizeof e.position - 1);
	e.position[sizeof e.position - 1] = 0;
#endif
	return e;
}

#define error_ajla_aux(ec, type, aux)	error_ajla_aux_(ec, type, aux pass_file_line)

#define error_ajla_system(ec, aux)	error_ajla_aux_(ec, AJLA_ERROR_SYSTEM, aux pass_file_line)

#define error_ajla(ec, type)		error_ajla_aux_(ec, type, 0 pass_file_line)

ajla_error_t error_from_errno(int ec, int errn);

void error_init_multithreaded(void);
void error_done_multithreaded(void);
void error_init(void);
void error_done(void);

#endif
