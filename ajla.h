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

#include "config-m.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdarg.h>
#include <stddef.h>
#include <float.h>
#include <math.h>
#ifdef HAVE_QUADMATH_H
#include <quadmath.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>

#include "debug.h"
#include "cfg.h"
#include "compiler.h"
#include "fn_impl.h"
#include "pcode-op.h"
#include "fileline.h"
#include "error.h"
#include "options.h"
#include "common.h"

extern extern_const bool dll;
extern int retval;
#define EXCEPTION_RETVAL	64


#if defined(FILE_COMPRESSION) && !defined(POINTER_COMPRESSION_POSSIBLE)
#define FILE_OMIT
#endif

#define u_name(n)	cat(u_,n)
#define c_name(n)	cat(c_,n)

#ifdef POINTER_COMPRESSION_POSSIBLE
extern uchar_efficient_t pointer_compression_enabled;
#define call(n)		(pointer_compression_enabled ? c_name(n) : u_name(n))
#else
#define pointer_compression_enabled	false
#define call(n)		u_name(n)
#endif


#if !defined(FILE_COMPRESSION)
#define shared_var
#define shared_init(v)	= v
#else
#define shared_var	extern
#define shared_init(v)
#endif


#define switch_call(fn)				\
void u_name(fn)(void);				\
void c_name(fn)(void);				\
static inline void fn(void) { call(fn)(); }

switch_call(data_init)
switch_call(data_done)
switch_call(array_index_init)
switch_call(array_index_done)
switch_call(function_init)
switch_call(function_done)
switch_call(pcode_init)
switch_call(pcode_done)
switch_call(save_init)
switch_call(save_done)
switch_call(module_init)
switch_call(module_done)
switch_call(ipio_init)
switch_call(ipio_done)
switch_call(ipret_init)
switch_call(ipret_done)
switch_call(task_init)
switch_call(task_done)
switch_call(task_run)
switch_call(program_run)
switch_call(bist)
