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

#ifndef AJLA_ARRAYU_H
#define AJLA_ARRAYU_H

#include "data.h"

#define array_btree_iterate	name(array_btree_iterate)
#define array_onstack_iterate	name(array_onstack_iterate)
#define array_to_bytes		name(array_to_bytes)
#define array_onstack_to_bytes	name(array_onstack_to_bytes)

bool attr_fastcall array_btree_iterate(pointer_t *array_ptr, array_index_t *idx, int_default_t (*callback)(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t *ptr, void *context), void *context);

bool attr_fastcall array_onstack_iterate(frame_s *fp, frame_t slot, array_index_t *idx, int_default_t (*callback)(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t *ptr, void *context), void *context);

void attr_fastcall array_to_bytes(pointer_t *array_ptr, char **str, size_t *str_l);
void attr_fastcall array_onstack_to_bytes(frame_s *fp, frame_t slot, char **str, size_t *str_l);

#endif
