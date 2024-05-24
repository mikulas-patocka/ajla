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

#ifndef AJLA_ARRAY_H
#define AJLA_ARRAY_H

#include "data.h"
#include "arindex.h"

#define array_read			name(array_read)
#define array_clone			name(array_clone)
#define array_modify			name(array_modify)
#define array_len			name(array_len)
#define array_is_empty			name(array_is_empty)
#define array_join			name(array_join)
#define array_sub			name(array_sub)
#define array_create			name(array_create)
#define array_create_sparse		name(array_create_sparse)
#define array_string			name(array_string)
#define array_incomplete_decompose	name(array_incomplete_decompose)
#define array_incomplete_collapse	name(array_incomplete_collapse)
#define array_from_flat_mem		name(array_from_flat_mem)


#define BTREE_MAX_NODE_EXPAND	2
#define BTREE_MAX_NODE_COLLAPSE	2
#define BTREE_MIN_SIZE		((BTREE_MAX_SIZE - BTREE_MAX_NODE_EXPAND) / 2 - BTREE_MAX_NODE_COLLAPSE)
#define SCALAR_SPLIT_SIZE	minimum(BTREE_MAX_SIZE, signed_maximum(int_default_t))


bool attr_fastcall array_read(struct data *array, array_index_t idx, pointer_t **result_ptr, unsigned char **result_flat, const struct type **flat_type, int_default_t *run, ajla_error_t *err);

struct data *array_clone(pointer_t *ptr, ajla_error_t *err);

#define ARRAY_MODIFY_NEED_FLAT	1
#define ARRAY_MODIFY_NEED_PTR	2
bool attr_fastcall array_modify(pointer_t *root, array_index_t idx, unsigned flags, pointer_t **result_ptr, unsigned char **result_flat, const struct type **flat_type, frame_s *fp, const code_t *ip);

array_index_t attr_fastcall array_len(struct data *array);
bool attr_fastcall array_is_empty(struct data *array);

struct data * attr_fastcall array_join(struct data *array1, struct data *array2, ajla_error_t *err);
struct data * attr_fastcall array_sub(struct data *array, array_index_t start, array_index_t len, bool deref, ajla_error_t *err);

pointer_t array_create(array_index_t length, const struct type *flat_type, const unsigned char *flat, pointer_t ptr);
pointer_t array_create_sparse(array_index_t length, pointer_t ptr);
pointer_t attr_fastcall array_string(int_default_t length, const struct type *flat_type, const unsigned char *flat);

void attr_fastcall array_incomplete_decompose(struct data *array, struct data **first, pointer_t *last);
bool attr_fastcall array_incomplete_collapse(pointer_t *ptr);

struct data * attr_fastcall array_from_flat_mem(const struct type *type, const char *mem, size_t n_elements, ajla_error_t *mayfail);

#endif
