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

#ifndef AJLA_STR_H
#define AJLA_STR_H

#include "mem_al.h"

void * attr_fastcall array_realloc_mayfail(void *p, size_t element_size, size_t old_length, size_t new_length, void **err_ptr, ajla_error_t *mayfail);
void * attr_fastcall array_finish_realloc(void *p, size_t length);

#define array_init_mayfail(type, ptr, len, mayfail)			\
(									\
	*(len) = 0,							\
	*(ptr) = mem_alloc_mayfail(type *, 0, mayfail),			\
	(!((is_constant(mayfail) && !return_ptr(mayfail))) && !*(ptr) ? false : true)\
)

#define array_init(type, ptr, len)					\
	(void)array_init_mayfail(type, ptr, len, NULL)

#define array_add_mayfail(type, ptr, len, var, err_ptr, mayfail)	\
(									\
	(*(len))++,							\
	*(ptr) = cast_ptr(type *, array_realloc_mayfail(*(ptr), sizeof(type), (*(len) - 1), *(len), err_ptr, mayfail)),\
	(!((is_constant(mayfail) && !return_ptr(mayfail))) && !*(ptr) ? (*(len))--, false : ((*(ptr))[*(len) - 1] = (var), true))\
)

#define array_add(type, ptr, len, var)					\
	(void)array_add_mayfail(type, ptr, len, var, NULL, NULL)

#define array_add_multiple_mayfail(type, ptr, len, var, varlen, err_ptr, mayfail)\
(									\
	(*(len)) += (varlen),						\
	*(ptr) = cast_ptr(type *, array_realloc_mayfail(*(ptr), sizeof(type), (*(len) - (varlen)), *(len), err_ptr, mayfail)),\
	(!((is_constant(mayfail) && !return_ptr(mayfail))) && !*(ptr) ? (*(len)) -= (varlen), false : (memcpy(&(*(ptr))[*(len) - (varlen)], (var), (varlen) * sizeof(type)), true))\
)

#define array_add_multiple(type, ptr, len, var, varlen)			\
	(void)array_add_multiple_mayfail(type, ptr, len, var, varlen, NULL, NULL)

#define array_finish(type, ptr, len)					\
	(*(ptr) = (type *)array_finish_realloc(*(ptr), *(len) * sizeof(type)))


#define str_init(ptr, len)				\
do {							\
	array_init(char, (ptr), (len));			\
} while (0)

#define str_finish(ptr, len)				\
do {							\
	str_add_char((ptr), (len), 0);			\
	array_finish(char, (ptr), (len));		\
} while (0)

void attr_fastcall str_add_bytes(char **, size_t *, const char *, size_t);
void attr_fastcall str_add_string(char **, size_t *, const char *);
void attr_fastcall str_add_char(char **, size_t *, char);
void attr_fastcall str_add_unsigned(char **, size_t *, uintbig_t, int);
void attr_fastcall str_add_signed(char **, size_t *, intbig_t, int);
void attr_fastcall str_add_hex(char **s, size_t *l, const char *hex);

char *str_dup(const char *str, size_t max_len, ajla_error_t *err);

static inline char *str_from_unsigned(uintbig_t i, int base)
{
	size_t str_l;
	char *str;
	str_init(&str, &str_l);
	str_add_unsigned(&str, &str_l, i, base);
	str_finish(&str, &str_l);
	return str;
}

static inline char *str_from_signed(uintbig_t i, int base)
{
	size_t str_l;
	char *str;
	str_init(&str, &str_l);
	str_add_signed(&str, &str_l, i, base);
	str_finish(&str, &str_l);
	return str;
}

#endif
