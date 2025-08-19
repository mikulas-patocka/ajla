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

#include "md.h"

struct module_designator *module_designator_alloc(unsigned path_idx, const uint8_t *path, size_t path_len, bool program, ajla_error_t *mayfail)
{
	struct module_designator *md = struct_alloc_array_mayfail(mem_alloc_mayfail, struct module_designator, path, path_len, mayfail);
	if (unlikely(!md))
		return NULL;
	md->path_idx = path_idx;
	md->path_len = path_len;
	md->program = program;
	memcpy(md->path, path, path_len);
	return md;
}

void module_designator_free(struct module_designator *md)
{
	mem_free(md);
}

size_t module_designator_length(const struct module_designator *md)
{
	return offsetof(struct module_designator, path[md->path_len]);
}

int module_designator_compare(const struct module_designator *md1, const struct module_designator *md2)
{
	if (md1->path_idx < md2->path_idx)
		return -1;
	if (md1->path_idx > md2->path_idx)
		return 1;
	if (md1->program != md2->program)
		return md1->program - md2->program;
	if (md1->path_len < md2->path_len)
		return -1;
	if (md1->path_len > md2->path_len)
		return 1;
	return memcmp(md1->path, md2->path, md1->path_len);
}

struct function_designator *function_designator_alloc(const pcode_t *p, ajla_error_t *mayfail)
{
	size_t i;
	size_t n_entries, n_spec_data;
	struct function_designator *fd;
	ajla_assert_lo(p[0] > 0, (file_line, "function_designator_alloc: invalid length %ld", (long)p[0]));
	n_entries = *p++;
	ajla_assert_lo(p[n_entries] >= 0, (file_line, "function_designator_alloc: invalid spec length %ld", (long)p[n_entries]));
	n_spec_data = p[n_entries];
	if (unlikely(n_entries + n_spec_data < n_entries)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), mayfail, "function designator overflow");
		return NULL;
	}
	fd = struct_alloc_array_mayfail(mem_alloc_mayfail, struct function_designator, entries, n_entries + n_spec_data, mayfail);
	if (unlikely(!fd))
		return NULL;
	fd->n_entries = n_entries;
	fd->n_spec_data = n_spec_data;
	for (i = 0; i < n_entries; i++)
		fd->entries[i] = *p++;
	p++;
	for (i = 0; i < n_spec_data; i++)
		fd->entries[n_entries + i] = *p++;
	return fd;
}

struct function_designator *function_designator_alloc_single(pcode_t idx, ajla_error_t *mayfail)
{
	pcode_t p[3];
	p[0] = 1;
	p[1] = idx;
	p[2] = 0;
	return function_designator_alloc(p, mayfail);
}

void function_designator_free(struct function_designator *fd)
{
	mem_free(fd);
}

size_t function_designator_length(const struct function_designator *fd)
{
	return offsetof(struct function_designator, entries[fd->n_entries + fd->n_spec_data]);
}

struct function_designator *function_designator_copy(const struct function_designator *fd, ajla_error_t *mayfail)
{
	size_t len = function_designator_length(fd);
	struct function_designator *new_fd = mem_alloc_mayfail(struct function_designator *, len, mayfail);
	if (unlikely(!new_fd))
		return NULL;
	memcpy(new_fd, fd, len);
	return new_fd;
}

int function_designator_compare(const struct function_designator *fd1, const struct function_designator *fd2)
{
	size_t i;
	if (fd1->n_entries < fd2->n_entries)
		return -1;
	if (fd1->n_entries > fd2->n_entries)
		return 1;
	if (fd1->n_spec_data < fd2->n_spec_data)
		return -1;
	if (fd1->n_spec_data > fd2->n_spec_data)
		return 1;
	for (i = 0; i < fd1->n_entries + fd1->n_spec_data; i++) {
		if (fd1->entries[i] < fd2->entries[i])
			return -1;
		if (fd1->entries[i] > fd2->entries[i])
			return 1;
	}
	return 0;
}

bool pcode_load_blob(const pcode_t **pc, uint8_t **blob, size_t *l, ajla_error_t *err)
{
	pcode_t n, i, q;

	if (blob) {
		if (unlikely(!array_init_mayfail(uint8_t, blob, l, err)))
			return false;
	}

	q = 0;		/* avoid warning */
	n = *(*pc)++;
	for (i = 0; i < n; i++) {
		uint8_t val;
		if (!(i & 3)) {
			q = *(*pc)++;
		}
		val = q;
		q >>= 8;
		if (blob) {
			if (unlikely(!array_add_mayfail(uint8_t, blob, l, (uint8_t)val, NULL, err)))
				return false;
		}
	}

	return true;
}

bool pcode_load_module_and_function_designator(const pcode_t **pc, struct module_designator **md, struct function_designator **fd, ajla_error_t *err)
{
	unsigned path_idx;
	bool program;
	pcode_t q;
	uint8_t *blob = NULL;
	size_t l;

	*md = NULL;
	*fd = NULL;

	q = *(*pc)++;
	path_idx = (unsigned)q;
	if (unlikely(q != (pcode_t)path_idx))
		goto exception_overflow;
	program = path_idx & 1;
	path_idx >>= 1;
	if (unlikely(!pcode_load_blob(pc, &blob, &l, err)))
		goto exception;

	*md = module_designator_alloc(path_idx, blob, l, program, err);
	if (unlikely(!*md))
		goto exception;

	mem_free(blob), blob = NULL;

	*fd = function_designator_alloc(*pc, err);
	if (unlikely(!*fd))
		goto exception;
	*pc += (*fd)->n_entries + 1;
	*pc += (*fd)->n_spec_data + 1;

	return true;

exception_overflow:
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "pcode overflow");
exception:
	if (blob)
		mem_free(blob);
	if (*md)
		module_designator_free(*md), *md = NULL;
	if (*fd)
		function_designator_free(*fd), *fd = NULL;
	return false;
}
