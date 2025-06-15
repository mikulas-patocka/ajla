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

#include "mem_al.h"

#include "str.h"

#ifndef DEBUG_TRACK_FILE_LINE
const char *position_string(void *ptr)
{
#if 1
	static char buffer[sizeof(uintptr_t) * 2 + 1];
	char *b = buffer;
	str_add_unsigned(&b, NULL, ptr_to_num(ptr), 16);
	return buffer;
#else
	return str_from_unsigned(ptr_to_num(ptr), 16);
#endif
}
const char *position_string_alloc(void *ptr)
{
	return str_from_unsigned(ptr_to_num(ptr), 16);
}
#endif

static size_t next_power_of_2(size_t len)
{
#if defined(HAVE_STDBIT_H) && defined(HAVE_FAST_CLZ)
	if (sizeof(size_t) == sizeof(unsigned long)) {
		if (unlikely(!(len + 1)))
			return 0;
		return stdc_bit_ceil_ul(len + 1);
	}
#ifdef HAVE_LONG_LONG
	if (sizeof(size_t) == sizeof(unsigned long long)) {
		if (unlikely(!(len + 1)))
			return 0;
		return stdc_bit_ceil_ull(len + 1);
	}
#endif
#endif
#if defined(HAVE_BUILTIN_CLZ) && defined(HAVE_FAST_CLZ)
	if (is_power_of_2(sizeof(size_t)) && sizeof(size_t) == sizeof(unsigned long)) {
		if (!len)
			return 1;
		return (size_t)2 << ((unsigned)(sizeof(size_t) * 8 - 1) CLZ_BSR_OP __builtin_clzl(len));
	}
#endif
	len |= len >> 1;
	len |= len >> 2;
	len |= len >> 4;
	len |= len >> 8;
	len |= len >> 15 >> 1;
	len |= len >> 15 >> 15 >> 2;
	len++;
	return len;
}

void * attr_fastcall array_realloc_mayfail(void *p, size_t element_size, size_t old_length, size_t new_length, void **err_ptr, ajla_error_t *mayfail)
{
	void *pp;
	if (unlikely(new_length <= old_length)) {
		if (unlikely(new_length == old_length))
			return p;
array_overflow:
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "array allocation size overflow");
		mem_free(p);
		return NULL;
	}
	new_length--;
#ifdef HAVE_BUILTIN_ADD_SUB_OVERFLOW
	if (unlikely(__builtin_sub_overflow(old_length, 1, &old_length)))
		goto do_realloc;
#else
	if (unlikely(!old_length))
		goto do_realloc;
	old_length--;
#endif
	if (unlikely((old_length ^ new_length) >= old_length)) {
		size_t total_size;
do_realloc:
		new_length = next_power_of_2(new_length);
		if (unlikely(!new_length))
			goto array_overflow;
#ifdef HAVE_BUILTIN_MUL_OVERFLOW
		if (unlikely(__builtin_mul_overflow(new_length, element_size, &total_size)))
			goto array_overflow;
#else
		total_size = new_length * element_size;
		if (unlikely(total_size / new_length != element_size))
			goto array_overflow;
#endif
		pp = mem_realloc_mayfail(void *, p, total_size, mayfail);
		if (unlikely(!pp)) {
			if (err_ptr)
				*err_ptr = p;
			else
				mem_free(p);
		}
		p = pp;
	}
	return p;
}

void * attr_fastcall array_finish_realloc(void *p, size_t length)
{
	void *n;
	ajla_error_t sink;
	if (unlikely(!(n = mem_realloc_mayfail(void *, p, length, &sink))))
		return p;
	return n;
}


void attr_fastcall str_add_bytes(char **s, size_t *l, const char *a, size_t ll)
{
	array_add_multiple(char, s, l, a, ll);
}

void attr_fastcall str_add_string(char **s, size_t *l, const char *a)
{
	str_add_bytes(s, l, a, strlen(a));
}

void attr_fastcall str_add_char(char **s, size_t *l, char c)
{
	array_add(char, s, l, c);
}

void attr_fastcall str_add_unsigned(char **s, size_t *l, uintbig_t i, int base)
{
	uintbig_t n = 1;
	uintbig_t limit = i / base;
	while (n <= limit)
		n *= base;
	do {
		char p = (char)(i / n);
		i %= n;
		p += '0' + (((p < 10) - 1) & ('a' - '9' - 1));
		if (likely(l != NULL))		/* see position_string */
			str_add_char(s, l, p);
		else
			*(*s)++ = p;
		n /= base;
	} while (n);
	if (unlikely(!l))
		**s = 0;
}

void attr_fastcall str_add_signed(char **s, size_t *l, intbig_t i, int base)
{
#if defined(__IBMC__)
	/* compiler bug - causes internal error */
	volatile
#endif
	uintbig_t ui = (uintbig_t)i;
	/*debug("number: %llx %llx", (unsigned long long)(ui >> 64), (unsigned long long)ui);*/
	if (unlikely(i < 0)) {
		str_add_char(s, l, '-');
		ui = -ui;
	}
	str_add_unsigned(s, l, ui, base);
}

void attr_fastcall str_add_hex(char **s, size_t *l, const char *hex)
{
	while (*hex) {
		char c = 0;
		if (hex[0] >= '0' && hex[0] <= '9')
			c += (hex[0] - '0') << 4;
		else if (hex[0] >= 'a' && hex[0] <= 'f')
			c += (hex[0] - 'a' + 10) << 4;
		else
			internal(file_line, "str_add_hex: invalid string: %s", hex);
		hex++;
		if (hex[0] >= '0' && hex[0] <= '9')
			c += hex[0] - '0';
		else if (hex[0] >= 'a' && hex[0] <= 'f')
			c += hex[0] - 'a' + 10;
		else
			internal(file_line, "str_add_hex: invalid string: %s", hex);
		hex++;
		str_add_char(s, l, c);
	}
}

char *str_dup(const char *str, size_t max_len, ajla_error_t *err)
{
	size_t l;
	char *c;
	l = strnlen(str, max_len);
	c = mem_alloc_mayfail(char *, l + 1, err);
	if (unlikely(!c))
		return NULL;
	c[l] = 0;
	return memcpy(c, str, l);
}
