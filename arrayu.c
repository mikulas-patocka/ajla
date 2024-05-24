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

#include "data.h"
#include "array.h"

#include "arrayu.h"

static int_default_t callback_pointer(pointer_t *p, int_default_t (*callback)(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t *ptr, void *context), void *context)
{
	pointer_t ptr = pointer_locked_read(p);
	if (!pointer_is_thunk(ptr) && da_tag(pointer_get_data(ptr)) == DATA_TAG_flat) {
		struct data *d = pointer_get_data(ptr);
		return callback(da_flat(d), type_get_from_tag(da(d,flat)->data_type), 1, NULL, context);
	} else {
		return callback(NULL, type_get_unknown(), 1, p, context);
	}
}

bool attr_fastcall array_btree_iterate(pointer_t *array_ptr, array_index_t *idx, int_default_t (*callback)(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t *ptr, void *context), void *context)
{
	struct data *array;

	if (pointer_is_thunk(*array_ptr)) {
		return callback(NULL, type_get_unknown(), 0, array_ptr, context) != 0;
	}
	array = pointer_get_data(*array_ptr);

	switch (da_tag(array)) {
		case DATA_TAG_array_flat: {
			unsigned char *flat = da_array_flat(array);
			int_default_t n_elements = da(array,array_flat)->n_used_entries;

			if (unlikely(index_ge_int(*idx, n_elements)))
				return true;

			n_elements -= index_to_int(*idx);
			flat += da(array,array_flat)->type->size * index_to_int(*idx);

			if (likely(n_elements != 0)) {
				int_default_t processed = callback(flat, da(array,array_flat)->type, n_elements, NULL, context);
				index_add_int(idx, processed);
				if (processed < n_elements)
					return false;
			}
			return true;
		}
		case DATA_TAG_array_slice: {
			unsigned char *flat = da(array,array_slice)->flat_data_minus_data_array_offset + data_array_offset;
			int_default_t n_elements = da(array,array_slice)->n_entries;

			if (unlikely(index_ge_int(*idx, n_elements)))
				return true;

			n_elements -= index_to_int(*idx);
			flat += da(array,array_slice)->type->size * index_to_int(*idx);

			if (likely(n_elements != 0)) {
				int_default_t processed = callback(flat, da(array,array_slice)->type, n_elements, NULL, context);
				index_add_int(idx, processed);
				if (processed < n_elements)
					return false;
			}
			return true;
		}
		case DATA_TAG_array_pointers: {
			pointer_t *ptr = da(array,array_pointers)->pointer;
			int_default_t n_elements = da(array,array_pointers)->n_used_entries;
			int_default_t i;

			if (unlikely(index_ge_int(*idx, n_elements)))
				return true;

			n_elements -= index_to_int(*idx);
			ptr += index_to_int(*idx);

			for (i = 0; i < n_elements; i++) {
				if (unlikely(!callback_pointer(&ptr[i], callback, context)))
					return false;
				index_add_int(idx, 1);
			}
			return true;
		}
		case DATA_TAG_array_same: {
			pointer_t *ptr;

			ptr = &da(array,array_same)->pointer;
			while (!index_ge_index(*idx, da(array,array_same)->n_entries)) {
				if (unlikely(!callback_pointer(ptr, callback, context))) {
					return false;
				}
				index_add_int(idx, 1);
			}
			return true;
		}
		case DATA_TAG_array_btree: {
			btree_entries_t bt_pos, bt_pos_end;

			binary_search(btree_entries_t, da(array,array_btree)->n_used_btree_entries, bt_pos, false, index_ge_index(*idx, da(array,array_btree)->btree[bt_pos].end_index), break);

			bt_pos_end = da(array,array_btree)->n_used_btree_entries;
			for (; bt_pos < bt_pos_end; bt_pos++) {
				struct btree_level *bt_level = &da(array,array_btree)->btree[bt_pos];
				bool result;
				pointer_t *node;
				node = &bt_level->node;

				da_array_assert_son(array, pointer_get_data(*node));

				if (bt_pos)
					index_sub(idx, bt_level[-1].end_index);
				result = array_btree_iterate(node, idx, callback, context);
				if (bt_pos)
					index_add(idx, bt_level[-1].end_index);

				if (!result)
					return false;
			}
			return true;
		}
		case DATA_TAG_array_incomplete: {
			array_index_t first_len, total_first_len;
			bool result;
			pointer_t ptr;
			struct data *new_array;

			index_from_int(&total_first_len, 0);

again:
			first_len = array_len(pointer_get_data(da(array,array_incomplete)->first));
			if (!index_ge_index(*idx, first_len)) {
				result = array_btree_iterate(&da(array,array_incomplete)->first, idx, callback, context);
				if (!result) {
					index_free(&first_len);
					index_add(idx, total_first_len);
					index_free(&total_first_len);
					return false;
				}
			}

			index_add(&total_first_len, first_len);
			index_sub(idx, first_len);
			index_free(&first_len);

			ptr = pointer_locked_read(&da(array,array_incomplete)->next);
			if (pointer_is_thunk(ptr)) {
				result = callback(NULL, type_get_unknown(), 0, &da(array,array_incomplete)->next, context) != 0;
				index_add(idx, total_first_len);
				index_free(&total_first_len);
				return result;
			}

			new_array = pointer_get_data(ptr);

			if (da_tag(new_array) != DATA_TAG_array_incomplete) {
				result = array_btree_iterate(&da(array,array_incomplete)->next, idx, callback, context);
				index_add(idx, total_first_len);
				index_free(&total_first_len);
				return result;
			} else {
				array = new_array;
				goto again;
			}
		}
	}
	internal(file_line, "array_btree_iterate: invalid array tag %u", da_tag(array));
	return false;
}

bool attr_fastcall array_onstack_iterate(frame_s *fp, frame_t slot, array_index_t *idx, int_default_t (*callback)(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t *ptr, void *context), void *context)
{
	pointer_t *array_ptr;

	if (frame_variable_is_flat(fp, slot)) {
		const struct type *type = frame_get_type_of_local(fp, slot);
		const struct flat_array_definition *fa = get_struct(type, const struct flat_array_definition, type);
		int_default_t n_elements = fa->n_elements;
		unsigned char *flat = frame_slot(fp, slot, unsigned char);

		if (unlikely(index_ge_int(*idx, n_elements)))
			return true;

		n_elements -= index_to_int(*idx);
		flat += fa->base->size * index_to_int(*idx);

		if (likely(n_elements != 0)) {
			int_default_t processed = callback(flat, fa->base, n_elements, NULL, context);
			index_add_int(idx, processed);
			if (processed < n_elements)
				return false;
		}

		return true;
	}

	array_ptr = frame_pointer(fp, slot);

	return array_btree_iterate(array_ptr, idx, callback, context);
}

struct array_to_bytes_context {
	char *str;
	size_t str_l;
};

static int_default_t array_to_bytes_callback(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t attr_unused *ptr, void *ctx_)
{
	struct array_to_bytes_context *ctx = cast_ptr(struct array_to_bytes_context *, ctx_);
	if (likely(flat != NULL)) {
		str_add_bytes(&ctx->str, &ctx->str_l, (char *)flat, n_elements * type->size);
		return n_elements;
	} else {
		if (pointer_is_thunk(*ptr))
			internal(file_line, "array_to_bytes_callback: thunk encountered, tag %d", thunk_tag(pointer_get_thunk(*ptr)));
		else
			internal(file_line, "array_to_bytes_callback: pointer encountered, tag: %d", da_tag(pointer_get_data(*ptr)));
		return 0;
	}
}

void attr_fastcall array_to_bytes(pointer_t *array_ptr, char **str, size_t *str_l)
{
	array_index_t idx;
	struct array_to_bytes_context ctx;

	index_from_int(&idx, 0);
	str_init(&ctx.str, &ctx.str_l);

	if (!array_btree_iterate(array_ptr, &idx, array_to_bytes_callback, &ctx))
		internal(file_line, "array_to_bytes: array_btree_iterate failed");

	index_free(&idx);
	str_finish(&ctx.str, &ctx.str_l);

	*str = ctx.str;
	*str_l = ctx.str_l;
}

void attr_fastcall array_onstack_to_bytes(frame_s *fp, frame_t slot, char **str, size_t *str_l)
{
	if (frame_variable_is_flat(fp, slot)) {
		const struct type *type = frame_get_type_of_local(fp, slot);
		const struct flat_array_definition *fa = get_struct(type, const struct flat_array_definition, type);
		int_default_t n_elements = fa->n_elements;
		unsigned char *flat = frame_slot(fp, slot, unsigned char);
		size_t size = fa->base->size * n_elements;
		unsigned char *p;

		p = mem_alloc(unsigned char *, size + 1);
		*cast_ptr(char *, mempcpy(p, flat, size)) = 0;

		*str = cast_ptr(char *, p);
		*str_l = size;

		return;
	}

	array_to_bytes(frame_pointer(fp, slot), str, str_l);
}

#endif
