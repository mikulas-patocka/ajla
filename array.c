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


bool index_export_to_int(const mpint_t *t, int_default_t *result)
{
	ajla_error_t sink;
	return cat(mpint_export_to_,int_default_t)(t, result, &sink);
}

static inline mpint_t *index_alloc_mp_(unsigned long bits argument_position)
{
	mpint_t *result;
	result = mem_alloc_compressed_mayfail(mpint_t *, sizeof(mpint_t), NULL);
	mpint_alloc_mayfail(result, bits, NULL);
	return result;
}

void index_free_mp_(array_index_t idx argument_position)
{
	mpint_t *mp = index_get_mp_(idx pass_position);
	mpint_free(mp);
	mem_free_compressed(mp);
}

attr_noinline array_index_t index_copy_mp_(array_index_t idx argument_position)
{
	mpint_t *mp;
	array_index_t result;
	mp = mem_alloc_compressed_mayfail(mpint_t *, sizeof(mpint_t), NULL);
	mpint_alloc_copy_mayfail(mp, index_get_mp_(idx pass_position), NULL);
	index_set_mp_(&result, mp pass_position);
	return result;
}

attr_noinline bool index_ge_index_mp_(array_index_t idx1, array_index_t idx2 argument_position)
{
	ajla_flat_option_t result;
	mpint_less_equal(index_get_mp_(idx2 pass_position), index_get_mp_(idx1 pass_position), &result, NULL);
	return result;
}

attr_noinline bool index_eq_index_mp_(array_index_t idx1, array_index_t idx2 argument_position)
{
	ajla_flat_option_t result;
	mpint_equal(index_get_mp_(idx2 pass_position), index_get_mp_(idx1 pass_position), &result, NULL);
	return result;
}

attr_noinline array_index_t index_op_mp_(array_index_t idx2, array_index_t idx3, unsigned flags, ajla_error_t *err argument_position)
{
	mpint_t mp2, mp3;
	mpint_t *mp2_p, *mp3_p;
	mpint_t *mp;
	bool succeeded;
	array_index_t result;
	if (!index_is_mp_(idx2 pass_position)) {
		if (flags & INDEX_OP_MP_ARG3_) {
			mp2_p = &mp2;
		} else {
			mp2_p = mem_alloc_compressed_mayfail(mpint_t *, sizeof(mpint_t), NULL);
		}
		index_init_from_int(mp2_p, index_to_int_(idx2 pass_position));
	} else {
		mp2_p = index_get_mp_(idx2 pass_position);
	}
	if (!index_is_mp_(idx3 pass_position)) {
		index_init_from_int(&mp3, index_to_int_(idx3 pass_position));
		mp3_p = &mp3;
	} else {
		mp3_p = index_get_mp_(idx3 pass_position);
	}
	if (flags & INDEX_OP_MP_ARG3_) {
		mp = index_alloc_mp_(maximum(mpint_estimate_bits(mp2_p), mpint_estimate_bits(mp3_p)) pass_position);
		if (!(flags & INDEX_OP_MP_SUB_))
			succeeded = mpint_add(mp2_p, mp3_p, mp, err);
		else
			succeeded = mpint_subtract(mp2_p, mp3_p, mp, err);
		index_set_mp_(&result, mp pass_position);
		index_alloc_leak_(&result pass_position);
	} else {
		if (!(flags & INDEX_OP_MP_SUB_))
			succeeded = mpint_add(mp2_p, mp3_p, mp2_p, err);
		else
			succeeded = mpint_subtract(mp2_p, mp3_p, mp2_p, err);
		index_set_mp_(&result, mp2_p pass_position);
		index_free_leak_(&idx2 pass_position);
		index_alloc_leak_(&result pass_position);
	}
	if (mp2_p == &mp2)
		mpint_free(&mp2);
	if (mp3_p == &mp3)
		mpint_free(&mp3);
	if (unlikely(!succeeded)) {
		index_free_(&result pass_file_line);
		return index_invalid();
	}
#ifndef UNUSUAL_MPINT_ARRAY_INDICES
	if (flags & INDEX_OP_MP_SUB_) {
		int_default_t id;
		if (index_export_to_int(index_get_mp_(result pass_position), &id)) {
			index_free_mp_(result pass_position);
			ajla_assert_lo(id >= 0, (caller_file_line, "index_op_mp_: the result is negative: %"PRIdMAX"", (intmax_t)id));
			index_set_value_(&result, (uint_default_t)id);
		}
	}
#endif
	return result;
}


static int_default_t array_align_alloc(int_default_t len)
{
#if defined(__IBMC__) && INT_DEFAULT_BITS > 32
	/* compiler bug - causes internal error */
	volatile
#endif
	uint_default_t val = (uint_default_t)len;
#if defined(HAVE_BUILTIN_CLZ)
	if (is_power_of_2(sizeof(int_default_t)) && sizeof(int_default_t) == sizeof(unsigned)) {
		val = (uint_default_t)1 << ((unsigned)(sizeof(uint_default_t) * 8 - 1) CLZ_BSR_OP __builtin_clz(val + val - 1));
		if (unlikely((int_default_t)val < 0))
			return likely(!len) ? 0 : val - 1;
		else
			return val;
	} else if (is_power_of_2(sizeof(int_default_t)) && sizeof(int_default_t) == sizeof(unsigned long long)) {
		val = (uint_default_t)1 << ((unsigned)(sizeof(uint_default_t) * 8 - 1) CLZ_BSR_OP __builtin_clzll(val + val - 1));
		if (unlikely((int_default_t)val < 0))
			return likely(!len) ? 0 : val - 1;
		else
			return val;
	} else
#endif
	{
		val--;
		val |= val >> 1;
		val |= val >> 2;
		val |= val >> 4;
		val |= val >> 8;
		val |= val >> 15 >> 1;
		val |= val >> 15 >> 15 >> 2;
		val |= val >> 15 >> 15 >> 15 >> 15 >> 4;
		val++;
		if (unlikely((int_default_t)val < 0))
			return val - 1;
		else
			return val;
	}
}


bool attr_fastcall array_read(struct data *array, array_index_t idx, pointer_t **result_ptr, unsigned char **result_flat, const struct type **flat_type, int_default_t *run, ajla_error_t *err)
{
go_down:
	switch (da_tag(array)) {
		case DATA_TAG_array_flat: {
			if (unlikely(index_ge_int(idx, da(array,array_flat)->n_used_entries)))
				goto invalid_index;
			if (run)
				*run = da(array,array_flat)->n_used_entries - index_to_int(idx);
			*result_ptr = NULL;
			*flat_type = da(array,array_flat)->type;
			*result_flat = da_array_flat(array) + index_to_int(idx) * (size_t)(*flat_type)->size;
			break;
		}
		case DATA_TAG_array_slice: {
			if (unlikely(index_ge_int(idx, da(array,array_slice)->n_entries)))
				goto invalid_index;
			if (run)
				*run = da(array,array_slice)->n_entries - index_to_int(idx);
			*result_ptr = NULL;
			*flat_type = da(array,array_slice)->type;
			*result_flat = da(array,array_slice)->flat_data_minus_data_array_offset + data_array_offset + index_to_int(idx) * (size_t)(*flat_type)->size;
			break;
		}
		case DATA_TAG_array_pointers: {
			if (unlikely(index_ge_int(idx, da(array,array_pointers)->n_used_entries)))
				goto invalid_index;
			if (run)
				*run = da(array,array_pointers)->n_used_entries - index_to_int(idx);
			*result_ptr = &da(array,array_pointers)->pointer[index_to_int(idx)];
			*result_flat = NULL;
			break;
		}
		case DATA_TAG_array_same: {
			if (unlikely(index_ge_index(idx, da(array,array_same)->n_entries)))
				goto invalid_index;
			if (run) {
				array_index_t idx_diff;
				index_sub3(&idx_diff, da(array,array_same)->n_entries, idx);
				if (likely(index_is_int(idx_diff))) {
					*run = -index_to_int(idx_diff);
				} else {
					*run = sign_bit(int_default_t);
				}
				index_free(&idx_diff);
			}
			*result_ptr = &da(array,array_same)->pointer;
			*result_flat = NULL;
			break;
		}
		case DATA_TAG_array_btree: {
			btree_entries_t bt_pos;
			pointer_t *new_array_ptr;
			struct data *new_array;
			binary_search(btree_entries_t, da(array,array_btree)->n_used_btree_entries, bt_pos, false, index_ge_index(idx, da(array,array_btree)->btree[bt_pos].end_index), break);
			if (unlikely(bt_pos == da(array,array_btree)->n_used_btree_entries))
				goto invalid_index;
			if (bt_pos != 0) {
				struct btree_level *bt_prev = &da(array,array_btree)->btree[bt_pos - 1];
				index_sub(&idx, bt_prev->end_index);
			}
			new_array_ptr = &da(array,array_btree)->btree[bt_pos].node;
			new_array = pointer_get_data(*new_array_ptr);
			da_array_assert_son(array, new_array);
			array = new_array;
			goto go_down;
		}
		default:
			internal(file_line, "array_read: invalid array tag %u", da_tag(array));
	}

	index_free(&idx);
	return true;

invalid_index:
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), err, "index out of range");
	index_free(&idx);
	return false;
}


struct walk_context {
	pointer_t *root;
	pointer_t *ptr;
	struct data *upper_level;
	btree_entries_t upper_level_pos;
	array_index_t idx;
};

static struct data *array_clone_flat(pointer_t *ptr, int_default_t n_allocated, ajla_error_t *err)
{
	struct data *orig, *clone;

	orig = pointer_get_data(*ptr);

	ajla_assert(n_allocated >= da(orig,array_flat)->n_used_entries, (file_line, "array_clone_flat: trimming btree from %"PRIdMAX" to %"PRIdMAX"", (intmax_t)da(orig,array_flat)->n_used_entries, (intmax_t)n_allocated));

	clone = data_alloc_array_flat_mayfail(da(orig,array_flat)->type, n_allocated, da(orig,array_flat)->n_used_entries, false, err pass_file_line);
	if (unlikely(!clone))
		return NULL;

	memcpy(da_array_flat(clone), da_array_flat(orig), da(orig,array_flat)->n_used_entries * da_array_flat_element_size(orig));

	pointer_dereference(*ptr);
	*ptr = pointer_data(clone);
	return clone;
}

static struct data *array_clone_pointers(pointer_t *ptr, int_default_t n_allocated, ajla_error_t *err)
{
	struct data *orig, *clone;
	int_default_t i, n_used;

	orig = pointer_get_data(*ptr);

	ajla_assert(n_allocated >= da(orig,array_pointers)->n_used_entries, (file_line, "array_clone_pointers: trimming btree from %"PRIdMAX" to %"PRIdMAX"", (intmax_t)da(orig,array_pointers)->n_used_entries, (intmax_t)n_allocated));

	clone = data_alloc_array_pointers_mayfail(n_allocated, da(orig,array_pointers)->n_used_entries, err pass_file_line);
	if (unlikely(!clone))
		return NULL;

	n_used = da(clone,array_pointers)->n_used_entries;
	for (i = 0; i < n_used; i++)
		da(clone,array_pointers)->pointer[i] = pointer_reference(&da(orig,array_pointers)->pointer[i]);

	pointer_dereference(*ptr);
	*ptr = pointer_data(clone);
	return clone;
}

static struct data *array_clone_btree(pointer_t *ptr, btree_entries_t n_allocated, ajla_error_t *err)
{
	struct data *orig, *clone;
	btree_entries_t i, n;

	orig = pointer_get_data(*ptr);

	ajla_assert(n_allocated >= da(orig,array_btree)->n_used_btree_entries, (file_line, "array_clone_btree: trimming btree from %"PRIuMAX" to %"PRIuMAX"", (uintmax_t)da(orig,array_btree)->n_used_btree_entries, (uintmax_t)n_allocated));

	clone = data_alloc_flexible(array_btree, btree, n_allocated, err);
	if (unlikely(!clone))
		return NULL;
	n = da(clone,array_btree)->n_used_btree_entries = da(orig,array_btree)->n_used_btree_entries;
	da(clone,array_btree)->n_allocated_btree_entries = n_allocated;
	da(clone,array_btree)->depth = da(orig,array_btree)->depth;
	for (i = 0; i < n; i++) {
		index_copy(&da(clone,array_btree)->btree[i].end_index, da(orig,array_btree)->btree[i].end_index);
		pointer_reference_owned(da(clone,array_btree)->btree[i].node = da(orig,array_btree)->btree[i].node);
	}

	pointer_dereference(*ptr);
	*ptr = pointer_data(clone);
	return clone;
}

struct data *array_clone(pointer_t *ptr, ajla_error_t *err)
{
	struct data *orig, *clone;

	orig = pointer_get_data(*ptr);
	switch (da_tag(orig)) {
		case DATA_TAG_array_flat: {
			return array_clone_flat(ptr, da(orig,array_flat)->n_allocated_entries, err);
		}
		case DATA_TAG_array_slice: {
			clone = data_alloc_array_flat_mayfail(da(orig,array_slice)->type, da(orig,array_slice)->n_entries, da(orig,array_slice)->n_entries, false, err pass_file_line);
			if (unlikely(!clone))
				return NULL;
			memcpy(da_array_flat(clone), da(orig,array_slice)->flat_data_minus_data_array_offset + data_array_offset, da(orig,array_slice)->n_entries * da_array_flat_element_size(clone));
			break;
		}
		case DATA_TAG_array_pointers: {
			return array_clone_pointers(ptr, da(orig,array_pointers)->n_allocated_entries, err);
		}
		case DATA_TAG_array_same: {
			clone = data_alloc(array_same, err);
			if (unlikely(!clone))
				return NULL;
			index_copy(&da(clone,array_same)->n_entries, da(orig,array_same)->n_entries);
			da(clone,array_same)->pointer = pointer_reference(&da(orig,array_same)->pointer);
			break;
		}
		case DATA_TAG_array_btree: {
			return array_clone_btree(ptr, da(orig,array_btree)->n_allocated_btree_entries, err);
		}
		default:
			internal(file_line, "array_clone: invalid array tag %u", da_tag(orig));
	}
	pointer_dereference(*ptr);
	*ptr = pointer_data(clone);
	return clone;
}

static struct data *get_writable(pointer_t *ptr, ajla_error_t *err)
{
	struct data *array = pointer_get_data(*ptr);
	if (unlikely(!data_is_writable(array)))
		return array_clone(ptr, err);
	else
		return array;
}

enum copy_t {
	copy,
	copy_add,
	copy_sub,
	move_sub
};

static void copy_btree_nodes_(struct btree_level *target, const struct btree_level *source, btree_entries_t n, enum copy_t cp, array_index_t idx_shift argument_position)
{
	btree_entries_t i;
	for (i = 0; i < n; i++) {
		switch (cp) {
			case copy:
				index_copy_(&target->end_index, source->end_index pass_position);
				break;
			case copy_add:
				index_add3_(&target->end_index, source->end_index, idx_shift, NULL pass_position);
				break;
			case copy_sub:
				index_sub3_(&target->end_index, source->end_index, idx_shift pass_position);
				break;
			case move_sub:
				target->end_index = source->end_index;
				index_sub(&target->end_index, idx_shift);
				break;
		}
		target->node = source->node;
		target++;
		source++;
	}
}
#define copy_btree_nodes(target, source, n, cp, idx_shift)	copy_btree_nodes_(target, source, n, cp, idx_shift pass_file_line)

static void free_indices_range(struct btree_level *l, btree_entries_t n)
{
	while (n--)
		index_free(&l++->end_index);
}

static void free_btree_indices(struct data *array)
{
	free_indices_range(da(array,array_btree)->btree, da(array,array_btree)->n_used_btree_entries);
}

static bool split_btree_node(struct data *array, struct data **left, array_index_t *left_idx, struct data **right, array_index_t *right_idx, ajla_error_t *err)
{
	struct data *r1, *r2;
	btree_entries_t boundary = (da(array,array_btree)->n_used_btree_entries + 1) >> 1;

	index_copy(left_idx, da(array,array_btree)->btree[boundary - 1].end_index);
	index_copy(right_idx, da(array,array_btree)->btree[da(array,array_btree)->n_used_btree_entries - 1].end_index);

	r1 = data_alloc_flexible(array_btree, btree, BTREE_MAX_SIZE, err);
	if (unlikely(!r1))
		goto fail3;
	da(r1,array_btree)->n_allocated_btree_entries = BTREE_MAX_SIZE;
	da(r1,array_btree)->n_used_btree_entries = boundary;
	da(r1,array_btree)->depth = da(array,array_btree)->depth;
	copy_btree_nodes(da(r1,array_btree)->btree, da(array,array_btree)->btree, boundary, copy, *left_idx);
	r2 = data_alloc_flexible(array_btree, btree, BTREE_MAX_SIZE, err);
	if (unlikely(!r2))
		goto fail5;
	da(r2,array_btree)->n_allocated_btree_entries = BTREE_MAX_SIZE;
	da(r2,array_btree)->n_used_btree_entries = da(array,array_btree)->n_used_btree_entries - boundary;
	da(r2,array_btree)->depth = da(array,array_btree)->depth;

	copy_btree_nodes(da(r2,array_btree)->btree, da(array,array_btree)->btree + boundary, da(r2,array_btree)->n_used_btree_entries, copy_sub, *left_idx);

	*left = r1;
	*right = r2;

	return true;

fail5:
	free_btree_indices(r1);
	data_free_r1(r1);
fail3:
	*left = array;		/* avoid warning */
	*right = array;		/* avoid warning */
	index_free(right_idx);
	index_free(left_idx);
	return false;
}

static struct btree_level *expand_parent(struct walk_context *w, btree_entries_t n, array_index_t *prev_idx, ajla_error_t *err)
{
	struct btree_level *ret;
	if (unlikely(!w->upper_level)) {
		struct data *root;
		index_from_int(prev_idx, 0);
		w->upper_level = root = data_alloc_flexible(array_btree, btree, n + BTREE_MAX_NODE_EXPAND, err);
		if (unlikely(!root)) {
			index_free(prev_idx);
			return NULL;
		}
		da(root,array_btree)->n_allocated_btree_entries = n + BTREE_MAX_NODE_EXPAND;
		da(root,array_btree)->n_used_btree_entries = n;
		da(root,array_btree)->depth = da_array_depth(pointer_get_data(*w->root)) + 1;
		*w->root = pointer_data(root);
		ret = da(root,array_btree)->btree;
	} else {
		ajla_assert_lo(da(w->upper_level,array_btree)->n_used_btree_entries + n - 1 <= da(w->upper_level,array_btree)->n_allocated_btree_entries, (file_line, "expand_parent: parent node too small: %"PRIuMAX", %"PRIuMAX", %"PRIuMAX"", (uintmax_t)da(w->upper_level,array_btree)->n_used_btree_entries, (uintmax_t)n, (uintmax_t)da(w->upper_level,array_btree)->n_allocated_btree_entries));
		if (!w->upper_level_pos) {
			index_from_int(prev_idx, 0);
		} else {
			index_copy(prev_idx, da(w->upper_level,array_btree)->btree[w->upper_level_pos - 1].end_index);
		}
		index_free(&da(w->upper_level,array_btree)->btree[w->upper_level_pos].end_index);
		memmove(da(w->upper_level,array_btree)->btree + w->upper_level_pos + n, da(w->upper_level,array_btree)->btree + w->upper_level_pos + 1, (da(w->upper_level,array_btree)->n_used_btree_entries - w->upper_level_pos - 1) * sizeof(struct btree_level));
		da(w->upper_level,array_btree)->n_used_btree_entries += n - 1;
		ret = da(w->upper_level,array_btree)->btree + w->upper_level_pos;
	}
#ifdef DEBUG
	(void)memset(ret, 0x01, n * sizeof(struct btree_level));
#endif
	return ret;
}

static attr_noinline struct data *expand_btree_node(struct walk_context *w, ajla_error_t *err)
{
	struct data *array = pointer_get_data(*w->ptr);
	btree_entries_t old_size = da(array,array_btree)->n_allocated_btree_entries;

	if (old_size <= BTREE_MAX_SIZE - BTREE_MAX_NODE_EXPAND) {
		size_t new_size = (size_t)old_size * 2;
		if (unlikely(new_size < da(array,array_btree)->n_used_btree_entries + (size_t)BTREE_MAX_NODE_EXPAND))
			new_size = da(array,array_btree)->n_used_btree_entries + (size_t)BTREE_MAX_NODE_EXPAND;
		if (unlikely(new_size > BTREE_MAX_SIZE))
			new_size = BTREE_MAX_SIZE;
		array = array_clone_btree(w->ptr, new_size, err);
		if (unlikely(!array))
			return NULL;
	} else {
		struct data *left, *right;
		array_index_t prev_idx, left_idx, right_idx;
		struct btree_level *split;

		if (unlikely(!split_btree_node(array, &left, &left_idx, &right, &right_idx, err)))
			return NULL;
		split = expand_parent(w, 2, &prev_idx, err);
		if (unlikely(!split)) {
			index_free(&left_idx);
			index_free(&right_idx);
			free_btree_indices(left);
			free_btree_indices(right);
			data_free_r1(left);
			data_free_r1(right);
			return NULL;
		}

		free_btree_indices(array);
		data_free_r1(array);

		split[0].node = pointer_data(left);
		index_add3(&split[0].end_index, prev_idx, left_idx);
		split[1].node = pointer_data(right);
		index_add3(&split[1].end_index, prev_idx, right_idx);
		if (!index_ge_index(w->idx, left_idx)) {
			array = left;
		} else {
			index_sub(&w->idx, left_idx);
			array = right;
		}
		index_free(&left_idx);
		index_free(&right_idx);
		index_free(&prev_idx);
	}

	return array;
}

static attr_noinline struct data *rebalance_btree_nodes(struct walk_context *w, ajla_error_t *err)
{
	struct data *left, *right;
	struct data *upper = w->upper_level;
	bool merge_previous = !!w->upper_level_pos;
	btree_entries_t pos = w->upper_level_pos - (int)merge_previous;

	left = get_writable(&da(upper,array_btree)->btree[pos].node, err);
	if (unlikely(!left))
		return NULL;
	right = get_writable(&da(upper,array_btree)->btree[pos + 1].node, err);
	if (unlikely(!right))
		return NULL;
	if (da(left,array_btree)->n_used_btree_entries + da(right,array_btree)->n_used_btree_entries <= BTREE_MAX_SIZE - BTREE_MAX_NODE_EXPAND) {
		btree_entries_t boundary;
		boundary = da(left,array_btree)->n_used_btree_entries;
		if (da(left,array_btree)->n_allocated_btree_entries < boundary + da(right,array_btree)->n_used_btree_entries + BTREE_MAX_NODE_EXPAND) {
			left = array_clone_btree(&da(upper,array_btree)->btree[pos].node, BTREE_MAX_SIZE, err);
			if (unlikely(!left))
				return NULL;
		}
		if (merge_previous) {
			index_add(&w->idx, da(left,array_btree)->btree[boundary - 1].end_index);
		}
		copy_btree_nodes(da(left,array_btree)->btree + boundary, da(right,array_btree)->btree, da(right,array_btree)->n_used_btree_entries, copy_add, da(left,array_btree)->btree[boundary - 1].end_index);
		da(left,array_btree)->n_used_btree_entries += da(right,array_btree)->n_used_btree_entries;
		free_btree_indices(right);
		data_free_r1(right);
		index_free(&da(upper,array_btree)->btree[pos].end_index);
		da(upper,array_btree)->btree[pos].end_index = da(upper,array_btree)->btree[pos + 1].end_index;
		memmove(da(upper,array_btree)->btree + pos + 1, da(upper,array_btree)->btree + pos + 2, (da(upper,array_btree)->n_used_btree_entries - pos - 2) * sizeof(struct btree_level));
		da(upper,array_btree)->n_used_btree_entries--;
		if (unlikely(da(upper,array_btree)->n_used_btree_entries == 1)) {
			*w->root = da(upper,array_btree)->btree[0].node;
			free_btree_indices(upper);
			data_free_r1(upper);
		}
		return left;
	} else {
		struct data *retn;
		array_index_t split_index;
		btree_entries_t half = (da(left,array_btree)->n_used_btree_entries + da(right,array_btree)->n_used_btree_entries + 1) >> 1;
		if (da(left,array_btree)->n_allocated_btree_entries < half + BTREE_MAX_NODE_EXPAND) {
			left = array_clone_btree(&da(upper,array_btree)->btree[pos].node, BTREE_MAX_SIZE, err);
			if (unlikely(!left))
				return NULL;
		}
		if (da(right,array_btree)->n_allocated_btree_entries < half + BTREE_MAX_NODE_EXPAND) {
			right = array_clone_btree(&da(upper,array_btree)->btree[pos + 1].node, BTREE_MAX_SIZE, err);
			if (unlikely(!right))
				return NULL;
		}
		if (da(left,array_btree)->n_used_btree_entries < half) {
			array_index_t sub_idx;
			btree_entries_t diff = half - da(left,array_btree)->n_used_btree_entries;
			if (!merge_previous) {
				retn = left;
			} else {
				if (!index_ge_index(w->idx, da(right,array_btree)->btree[diff - 1].end_index)) {
					index_add(&w->idx, da(left,array_btree)->btree[da(left,array_btree)->n_used_btree_entries - 1].end_index);
					retn = left;
				} else {
					index_sub(&w->idx, da(right,array_btree)->btree[diff - 1].end_index);
					retn = right;
				}
			}
			copy_btree_nodes(da(left,array_btree)->btree + da(left,array_btree)->n_used_btree_entries, da(right,array_btree)->btree, diff, copy_add, da(left,array_btree)->btree[da(left,array_btree)->n_used_btree_entries - 1].end_index);
			index_copy(&sub_idx, da(right,array_btree)->btree[diff - 1].end_index);
			free_indices_range(da(right,array_btree)->btree, diff);
			copy_btree_nodes(da(right,array_btree)->btree, da(right,array_btree)->btree + diff, da(right,array_btree)->n_used_btree_entries - diff, move_sub, sub_idx);
			index_free(&sub_idx);
			da(left,array_btree)->n_used_btree_entries = half;
			da(right,array_btree)->n_used_btree_entries -= diff;
		} else {
			btree_entries_t diff = da(left,array_btree)->n_used_btree_entries - half;
			array_index_t idx_diff;
			struct btree_level *l;

			l = mem_alloc_array_mayfail(mem_alloc_mayfail, struct btree_level *, 0, 0, da(right,array_btree)->n_used_btree_entries + diff, sizeof(struct btree_level), err);
			if (unlikely(!l))
				return NULL;

			index_sub3(&idx_diff, da(left,array_btree)->btree[da(left,array_btree)->n_used_btree_entries - 1].end_index, da(left,array_btree)->btree[half - 1].end_index);
			copy_btree_nodes(l, da(left,array_btree)->btree + half, diff, copy_sub, da(left,array_btree)->btree[half - 1].end_index);
			copy_btree_nodes(l + diff, da(right,array_btree)->btree, da(right,array_btree)->n_used_btree_entries, copy_add, idx_diff);
			free_btree_indices(right);
			memcpy(da(right,array_btree)->btree, l, (da(right,array_btree)->n_used_btree_entries + diff) * sizeof(struct btree_level));
			mem_free(l);
			index_free(&idx_diff);
			free_indices_range(da(left,array_btree)->btree + half, da(left,array_btree)->n_used_btree_entries - half);
			da(left,array_btree)->n_used_btree_entries = half;
			da(right,array_btree)->n_used_btree_entries += diff;
			if (!merge_previous) {
				if (!index_ge_index(w->idx, da(left,array_btree)->btree[half - 1].end_index)) {
					retn = left;
				} else {
					index_sub(&w->idx, da(left,array_btree)->btree[half - 1].end_index);
					retn = right;
				}
			} else {
				index_add(&w->idx, da(right,array_btree)->btree[diff - 1].end_index);
				retn = right;
			}
		}
		index_copy(&split_index, da(left,array_btree)->btree[half - 1].end_index);
		if (pos)
			index_add(&split_index, da(upper,array_btree)->btree[pos - 1].end_index);
		index_free(&da(upper,array_btree)->btree[pos].end_index);
		da(upper,array_btree)->btree[pos].end_index = split_index;
		return retn;
	}
}

static void walk_init_context(struct walk_context *w, pointer_t *root, array_index_t idx)
{
	w->root = root;
	w->ptr = root;
	w->upper_level = NULL;
	w->upper_level_pos = 0;
	w->idx = idx;
}

static void walk_free_context(struct walk_context *w)
{
	index_free(&w->idx);
}

static bool walk_for_write(struct walk_context *w, ajla_error_t *err)
{
	struct data *array;
	btree_entries_t bt_pos;

	array = pointer_get_data(*w->ptr);

	if (unlikely(da(array,array_btree)->n_allocated_btree_entries - da(array,array_btree)->n_used_btree_entries < BTREE_MAX_NODE_EXPAND)) {
		array = get_writable(w->ptr, err);
		if (unlikely(!array))
			return false;
		array = expand_btree_node(w, err);
		if (unlikely(!array))
			return false;
	}
	if (w->upper_level && unlikely(da(array,array_btree)->n_used_btree_entries < BTREE_MIN_SIZE + BTREE_MAX_NODE_COLLAPSE)) {
		array = get_writable(w->ptr, err);
		if (unlikely(!array))
			return false;
		array = rebalance_btree_nodes(w, err);
		if (unlikely(!array))
			return false;
	}

	binary_search(btree_entries_t, da(array,array_btree)->n_used_btree_entries, bt_pos, false, index_ge_index(w->idx, da(array,array_btree)->btree[bt_pos].end_index), break);
	if (unlikely(bt_pos == da(array,array_btree)->n_used_btree_entries))
		goto invalid_index;
	if (bt_pos != 0) {
		struct btree_level *bt_prev = &da(array,array_btree)->btree[bt_pos - 1];
		index_sub(&w->idx, bt_prev->end_index);
	}
	w->upper_level = array;
	w->upper_level_pos = bt_pos;
	w->ptr = &da(array,array_btree)->btree[bt_pos].node;
	da_array_assert_son(w->upper_level, pointer_get_data(*w->ptr));
	return true;

invalid_index:
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), err, "index out of range");
	return false;
}

static struct data *alloc_one_ptr(pointer_t target, ajla_error_t *err)
{
	struct data *pointer = data_alloc_array_pointers_mayfail(1, 1, err pass_file_line);
	if (unlikely(!pointer))
		return NULL;
	da(pointer,array_pointers)->pointer[0] = target;
	return pointer;
}

static bool leaf_prepend_ptr(struct walk_context *w, array_index_t existing_size, pointer_t ptr, pointer_t **result_ptr, ajla_error_t *err)
{
	struct btree_level *split;
	array_index_t prev_idx;
	pointer_t *sibling_pointer;
	struct data *sibling;
	pointer_t orig = *w->ptr;

	if (unlikely(!w->upper_level) || unlikely(!w->upper_level_pos))
		goto expand;

	sibling_pointer = &da(w->upper_level,array_btree)->btree[w->upper_level_pos - 1].node;
	sibling = pointer_get_data(*sibling_pointer);
	if (da_tag(sibling) == DATA_TAG_array_pointers) {
		if (da(sibling,array_pointers)->n_used_entries == da(sibling,array_pointers)->n_allocated_entries) {
			uint_default_t new_size;
			if (unlikely(da(sibling,array_pointers)->n_allocated_entries >= SCALAR_SPLIT_SIZE))
				goto expand;
			new_size = (uint_default_t)da(sibling,array_pointers)->n_allocated_entries * 2;
			if (new_size > SCALAR_SPLIT_SIZE)
				new_size = SCALAR_SPLIT_SIZE;
			sibling = array_clone_pointers(sibling_pointer, (int_default_t)new_size, err);
			if (unlikely(!sibling))
				return false;
		}
		sibling = get_writable(sibling_pointer, err);
		if (unlikely(!sibling))
			return false;
		da(sibling,array_pointers)->pointer[da(sibling,array_pointers)->n_used_entries] = ptr;
		*result_ptr = &da(sibling,array_pointers)->pointer[da(sibling,array_pointers)->n_used_entries];
		da(sibling,array_pointers)->n_used_entries++;
		index_add_int(&get_struct(sibling_pointer, struct btree_level, node)->end_index, 1);
		return true;
	}

expand:
	sibling = alloc_one_ptr(ptr, err);
	if (unlikely(!sibling))
		return false;
	*result_ptr = &da(sibling,array_pointers)->pointer[0];
	split = expand_parent(w, 2, &prev_idx, err);
	if (unlikely(!split)) {
		data_free_r1(sibling);
		return false;
	}
	index_copy(&split[0].end_index, prev_idx);
	index_add_int(&split[0].end_index, 1);
	split[0].node = pointer_data(sibling);
	split[1].end_index = prev_idx;
	index_add(&split[1].end_index, existing_size);
	split[1].node = orig;
	return true;
}

static bool leaf_append_ptr(struct walk_context *w, array_index_t existing_size, pointer_t ptr, pointer_t **result_ptr, ajla_error_t *err)
{
	struct btree_level *split;
	array_index_t prev_idx;
	pointer_t *sibling_pointer;
	struct data *sibling;
	pointer_t orig = *w->ptr;

	if (unlikely(!w->upper_level) || unlikely(w->upper_level_pos == da(w->upper_level,array_btree)->n_used_btree_entries - 1))
		goto expand;

	sibling_pointer = &da(w->upper_level,array_btree)->btree[w->upper_level_pos + 1].node;
	sibling = pointer_get_data(*sibling_pointer);
	if (da_tag(sibling) == DATA_TAG_array_pointers) {
		if (da(sibling,array_pointers)->n_used_entries == da(sibling,array_pointers)->n_allocated_entries) {
			uint_default_t new_size;
			if (unlikely(da(sibling,array_pointers)->n_allocated_entries >= SCALAR_SPLIT_SIZE))
				goto expand;
			new_size = (uint_default_t)da(sibling,array_pointers)->n_allocated_entries * 2;
			if (new_size > SCALAR_SPLIT_SIZE)
				new_size = SCALAR_SPLIT_SIZE;
			sibling = array_clone_pointers(sibling_pointer, (int_default_t)new_size, err);
			if (unlikely(!sibling))
				return false;
		}
		sibling = get_writable(sibling_pointer, err);
		if (unlikely(!sibling))
			return false;
		if (da(sibling,array_pointers)->pointer == da(sibling,array_pointers)->pointer_array) {
			memmove(da(sibling,array_pointers)->pointer + 1, da(sibling,array_pointers)->pointer, da(sibling,array_pointers)->n_used_entries * sizeof(pointer_t));
		} else {
			da(sibling,array_pointers)->pointer--;
			da(sibling,array_pointers)->n_allocated_entries++;
		}
		da(sibling,array_pointers)->pointer[0] = ptr;
		*result_ptr = &da(sibling,array_pointers)->pointer[0];
		da(sibling,array_pointers)->n_used_entries++;
		index_sub_int(&get_struct(sibling_pointer, struct btree_level, node)[-1].end_index, 1);
		return true;
	}

expand:
	sibling = alloc_one_ptr(ptr, err);
	if (unlikely(!sibling))
		return false;
	*result_ptr = &da(sibling,array_pointers)->pointer[0];
	split = expand_parent(w, 2, &prev_idx, err);
	if (unlikely(!split)) {
		data_free_r1(sibling);
		return false;
	}
	index_copy(&split[0].end_index, prev_idx);
	index_add(&split[0].end_index, existing_size);
	index_sub_int(&split[0].end_index, 1);
	split[0].node = orig;
	split[1].end_index = prev_idx;
	index_add(&split[1].end_index, existing_size);
	split[1].node = pointer_data(sibling);
	return true;
}

static struct data *try_join_ptr(struct data *left, struct data *right)
{
	int_default_t sum;
	bool quick_copy;

	sum = (int_default_t)((uint_default_t)da(left,array_pointers)->n_used_entries + (uint_default_t)da(right,array_pointers)->n_used_entries);
	/*debug("join: %lu, %lu, max %lu, ref %lu", (uint_default_t)da(left,array_pointers)->n_used_entries, (uint_default_t)da(right,array_pointers)->n_used_entries, da(left,array_pointers)->n_allocated_entries, refcount_get_nonatomic(&left->refcount));*/
	if (unlikely(sum < 0))
		return NULL;

	if (!data_is_writable(left)) {
		if (sum > BTREE_MAX_SIZE)
			return NULL;
		goto clon;
	}
	if (da(left,array_pointers)->n_allocated_entries < sum) {
		pointer_t ptr;
clon:
		ptr = pointer_data(left);
		left = array_clone_pointers(&ptr, array_align_alloc(sum), MEM_DONT_TRY_TO_FREE);
		if (unlikely(!left))
			return NULL;
	}

	quick_copy = data_is_writable(right);

	if (quick_copy) {
		memcpy(da(left,array_pointers)->pointer + da(left,array_pointers)->n_used_entries, da(right,array_pointers)->pointer, da(right,array_pointers)->n_used_entries * sizeof(pointer_t));
	} else {
		int_default_t i, offs, total;
		offs = da(left,array_pointers)->n_used_entries;
		total = da(right,array_pointers)->n_used_entries;
		for (i = 0; i < total; i++)
			da(left,array_pointers)->pointer[offs + i] = pointer_reference(&da(right,array_pointers)->pointer[i]);

	}
	da(left,array_pointers)->n_used_entries += da(right,array_pointers)->n_used_entries;

	if (quick_copy)
		data_free_r1(right);
	else
		data_dereference(right);

	return left;
}

static void try_join_siblings_ptr(struct walk_context *w, pointer_t **result_ptr, bool ptr_right)
{
	struct data *ul = w->upper_level;
	btree_entries_t ul_pos = w->upper_level_pos;
	struct data *left, *right;
	int_default_t ptr_pos;

	left = pointer_get_data(da(ul,array_btree)->btree[ul_pos].node);
	right = pointer_get_data(da(ul,array_btree)->btree[ul_pos + 1].node);

	if (da_tag(left) != DATA_TAG_array_pointers || da_tag(right) != DATA_TAG_array_pointers)
		return;

	if (!ptr_right) {
		ptr_pos = (int_default_t)(*result_ptr - da(left,array_pointers)->pointer);
		ajla_assert((uint_default_t)ptr_pos < (uint_default_t)da(left,array_pointers)->n_used_entries, (file_line, "try_join_siblings_ptr: ptr is outside left node"));
	} else {
		ptr_pos = (int_default_t)(*result_ptr - da(right,array_pointers)->pointer);
		ajla_assert((uint_default_t)ptr_pos < (uint_default_t)da(right,array_pointers)->n_used_entries, (file_line, "try_join_siblings_ptr: ptr is outside right node"));
		ptr_pos += da(left,array_pointers)->n_used_entries;
	}

	left = try_join_ptr(left, right);
	if (unlikely(!left))
		return;

	*result_ptr = &da(left,array_pointers)->pointer[ptr_pos];

	da(ul,array_btree)->btree[ul_pos].node = pointer_data(left);
	index_free(&da(ul,array_btree)->btree[ul_pos].end_index);
	da(ul,array_btree)->btree[ul_pos].end_index = da(ul,array_btree)->btree[ul_pos + 1].end_index;
	memmove(da(ul,array_btree)->btree + ul_pos + 1, da(ul,array_btree)->btree + ul_pos + 2, (da(ul,array_btree)->n_used_btree_entries - ul_pos - 2) * sizeof(struct btree_level));
	da(ul,array_btree)->n_used_btree_entries--;
	if (unlikely(da(ul,array_btree)->n_used_btree_entries == 1)) {
		free_btree_indices(ul);
		data_free_r1(ul);
		*w->root = pointer_data(left);
	}
}

static void try_join_both_siblings_ptr(struct walk_context *w, pointer_t **result_ptr)
{
	if (w->upper_level) {
		if (w->upper_level_pos < da(w->upper_level,array_btree)->n_used_btree_entries - 1) {
			try_join_siblings_ptr(w, result_ptr, false);
		}
		if (w->upper_level_pos) {
			w->upper_level_pos--;
			try_join_siblings_ptr(w, result_ptr, true);
		}
	}
}

static bool flat_to_ptr(struct walk_context *w, pointer_t **result_ptr, ajla_error_t *err)
{
	struct data *array, *right, *single;
	pointer_t ptr;

	array = pointer_get_data(*w->ptr);
	ptr = flat_to_data(da(array,array_flat)->type, da_array_flat(array) + index_to_int(w->idx) * da_array_flat_element_size(array));

	if (unlikely(da(array,array_flat)->n_used_entries == 1)) {
		single = alloc_one_ptr(ptr, err);
		if (unlikely(!single))
			goto ret_err;
		*result_ptr = &da(single,array_pointers)->pointer[0];
		data_dereference(array);
		*w->ptr = pointer_data(single);
		try_join_both_siblings_ptr(w, result_ptr);
		return true;
	} else if (!index_to_int(w->idx)) {
		array_index_t existing_size;
		bool ret;
		index_from_int(&existing_size, da(array,array_flat)->n_used_entries);
		ret = leaf_prepend_ptr(w, existing_size, ptr, result_ptr, err);
		index_free(&existing_size);
		if (unlikely(!ret))
			goto ret_err;
		memmove(da_array_flat(array), da_array_flat(array) + da_array_flat_element_size(array), (da(array,array_flat)->n_used_entries - 1) * da_array_flat_element_size(array));
		da(array,array_flat)->n_used_entries--;
		return true;
	} else if (index_to_int(w->idx) == da(array,array_flat)->n_used_entries - 1) {
		array_index_t existing_size;
		bool ret;
		index_from_int(&existing_size, da(array,array_flat)->n_used_entries);
		ret = leaf_append_ptr(w, existing_size, ptr, result_ptr, err);
		index_free(&existing_size);
		if (unlikely(!ret))
			goto ret_err;
		da(array,array_flat)->n_used_entries--;
		return true;
	} else {
		struct btree_level *split;
		array_index_t prev_idx;
		int_default_t n_allocated = da(array,array_flat)->n_used_entries - 1 - index_to_int(w->idx);

		right = data_alloc_array_flat_mayfail(da(array,array_flat)->type, n_allocated, da(array,array_flat)->n_used_entries - 1 - index_to_int(w->idx), false, err pass_file_line);
		if (unlikely(!right))
			goto ret_err;
		memcpy(da_array_flat(right), da_array_flat(array) + (index_to_int(w->idx) + 1) * da_array_flat_element_size(array), da(right,array_flat)->n_used_entries * da_array_flat_element_size(array));

		single = alloc_one_ptr(ptr, err);
		if (unlikely(!single))
			goto free_right_ret_err;
		*result_ptr = &da(single,array_pointers)->pointer[0];

		split = expand_parent(w, 3, &prev_idx, err);
		if (unlikely(!split))
			goto free_single_right_ret_err;

		split[0].node = pointer_data(array);
		index_add3(&split[0].end_index, prev_idx, w->idx);
		split[1].node = pointer_data(single);
		index_add3(&split[1].end_index, prev_idx, w->idx);
		index_add_int(&split[1].end_index, 1);
		split[2].node = pointer_data(right);
		split[2].end_index = prev_idx;
		index_add_int(&split[2].end_index, da(array,array_flat)->n_used_entries);

		da(array,array_flat)->n_used_entries = index_to_int(w->idx);

		return true;
	}

free_single_right_ret_err:
	data_free_r1(single);
free_right_ret_err:
	data_free_r1(right);
ret_err:
	pointer_dereference(ptr);
	return false;
}

static bool leaf_prepend_flat(struct walk_context *w, const struct type *type, array_index_t existing_size, unsigned char **result_flat, ajla_error_t *err)
{
	struct btree_level *split;
	array_index_t prev_idx;
	pointer_t *sibling_pointer;
	struct data *sibling;
	pointer_t orig = *w->ptr;

	if (unlikely(!w->upper_level) || unlikely(!w->upper_level_pos))
		goto expand;

	sibling_pointer = &da(w->upper_level,array_btree)->btree[w->upper_level_pos - 1].node;
	sibling = pointer_get_data(*sibling_pointer);
	if (da_tag(sibling) == DATA_TAG_array_flat) {
		if (da(sibling,array_flat)->n_used_entries == da(sibling,array_flat)->n_allocated_entries) {
			uint_default_t new_size;
			if (unlikely(da(sibling,array_flat)->n_allocated_entries >= SCALAR_SPLIT_SIZE))
				goto expand;
			new_size = (uint_default_t)da(sibling,array_flat)->n_allocated_entries * 2;
			if (new_size > SCALAR_SPLIT_SIZE)
				new_size = SCALAR_SPLIT_SIZE;
			sibling = array_clone_flat(sibling_pointer, (int_default_t)new_size, err);
			if (unlikely(!sibling))
				return false;
		}
		sibling = get_writable(sibling_pointer, err);
		if (unlikely(!sibling))
			return false;
		*result_flat = da_array_flat(sibling) + (size_t)type->size * da(sibling,array_flat)->n_used_entries;
		da(sibling,array_flat)->n_used_entries++;
		index_add_int(&get_struct(sibling_pointer, struct btree_level, node)->end_index, 1);
		return true;
	}

expand:
	sibling = data_alloc_array_flat_mayfail(type, 1, 1, false, err pass_file_line);
	if (unlikely(!sibling))
		return false;
	*result_flat = da_array_flat(sibling);
	split = expand_parent(w, 2, &prev_idx, err);
	if (unlikely(!split)) {
		data_free_r1(sibling);
		return false;
	}
	index_copy(&split[0].end_index, prev_idx);
	index_add_int(&split[0].end_index, 1);
	split[0].node = pointer_data(sibling);
	split[1].end_index = prev_idx;
	index_add(&split[1].end_index, existing_size);
	split[1].node = orig;
	return true;
}

static bool leaf_append_flat(struct walk_context *w, const struct type *type, array_index_t existing_size, unsigned char **result_flat, ajla_error_t *err)
{
	struct btree_level *split;
	array_index_t prev_idx;
	pointer_t *sibling_pointer;
	struct data *sibling;
	pointer_t orig = *w->ptr;

	if (unlikely(!w->upper_level) || unlikely(w->upper_level_pos == da(w->upper_level,array_btree)->n_used_btree_entries - 1))
		goto expand;

	sibling_pointer = &da(w->upper_level,array_btree)->btree[w->upper_level_pos + 1].node;
	sibling = pointer_get_data(*sibling_pointer);
	if (da_tag(sibling) == DATA_TAG_array_flat) {
		if (da(sibling,array_flat)->n_used_entries == da(sibling,array_flat)->n_allocated_entries) {
			uint_default_t new_size;
			if (unlikely(da(sibling,array_flat)->n_allocated_entries >= SCALAR_SPLIT_SIZE))
				goto expand;
			new_size = (uint_default_t)da(sibling,array_flat)->n_allocated_entries * 2;
			if (new_size > SCALAR_SPLIT_SIZE)
				new_size = SCALAR_SPLIT_SIZE;
			sibling = array_clone_flat(sibling_pointer, (int_default_t)new_size, err);
			if (unlikely(!sibling))
				return false;
		}
		sibling = get_writable(sibling_pointer, err);
		if (unlikely(!sibling))
			return false;
		memmove(da_array_flat(sibling) + type->size, da_array_flat(sibling), (size_t)type->size * da(sibling,array_flat)->n_used_entries);
		*result_flat = da_array_flat(sibling);
		da(sibling,array_flat)->n_used_entries++;
		index_sub_int(&get_struct(sibling_pointer, struct btree_level, node)[-1].end_index, 1);
		return true;
	}

expand:
	sibling = data_alloc_array_flat_mayfail(type, 1, 1, false, err pass_file_line);
	if (unlikely(!sibling))
		return false;
	*result_flat = da_array_flat(sibling);
	split = expand_parent(w, 2, &prev_idx, err);
	if (unlikely(!split)) {
		data_free_r1(sibling);
		return false;
	}
	index_copy(&split[0].end_index, prev_idx);
	index_add(&split[0].end_index, existing_size);
	index_sub_int(&split[0].end_index, 1);
	split[0].node = orig;
	split[1].end_index = prev_idx;
	index_add(&split[1].end_index, existing_size);
	split[1].node = pointer_data(sibling);
	return true;
}

static struct data *try_join_flat(struct data *left, struct data *right)
{
	int_default_t sum;
	size_t element_size;

	sum = (int_default_t)((uint_default_t)da(left,array_flat)->n_used_entries + (uint_default_t)da(right,array_flat)->n_used_entries);
	if (unlikely(sum < 0))
		return NULL;

	if (!data_is_writable(left) || da(left,array_flat)->n_allocated_entries < sum) {
		pointer_t ptr = pointer_data(left);
		left = array_clone_flat(&ptr, array_align_alloc(sum), MEM_DONT_TRY_TO_FREE);
		if (unlikely(!left))
			return NULL;
	}

	element_size = da_array_flat_element_size(left);
	memcpy(da_array_flat(left) + da(left,array_flat)->n_used_entries * element_size, da_array_flat(right), da(right,array_flat)->n_used_entries * element_size);
	da(left,array_flat)->n_used_entries += da(right,array_flat)->n_used_entries;

	data_dereference(right);

	return left;
}

static void try_join_siblings_flat(struct walk_context *w, unsigned char **result_flat, bool ptr_right)
{
	struct data *ul = w->upper_level;
	btree_entries_t ul_pos = w->upper_level_pos;
	struct data *left, *right;
	size_t ptr_pos;
	size_t element_size;

	left = pointer_get_data(da(ul,array_btree)->btree[ul_pos].node);
	right = pointer_get_data(da(ul,array_btree)->btree[ul_pos + 1].node);

	if (da_tag(left) != DATA_TAG_array_flat || da_tag(right) != DATA_TAG_array_flat)
		return;

	element_size = da_array_flat_element_size(left);
	if (!ptr_right) {
		ptr_pos = *result_flat - da_array_flat(left);
		ajla_assert((uint_default_t)ptr_pos < (uint_default_t)da(left,array_flat)->n_used_entries * element_size, (file_line, "try_join_siblings_flat: ptr is outside left node"));
	} else {
		ptr_pos = *result_flat - da_array_flat(right);
		ajla_assert((uint_default_t)ptr_pos < (uint_default_t)da(right,array_flat)->n_used_entries * element_size, (file_line, "try_join_siblings_flat: ptr is outside right node"));
		ptr_pos += da(left,array_flat)->n_used_entries * element_size;
	}

	left = try_join_flat(left, right);
	if (unlikely(!left))
		return;

	*result_flat = da_array_flat(left) + ptr_pos;

	da(ul,array_btree)->btree[ul_pos].node = pointer_data(left);
	index_free(&da(ul,array_btree)->btree[ul_pos].end_index);
	da(ul,array_btree)->btree[ul_pos].end_index = da(ul,array_btree)->btree[ul_pos + 1].end_index;
	memmove(da(ul,array_btree)->btree + ul_pos + 1, da(ul,array_btree)->btree + ul_pos + 2, (da(ul,array_btree)->n_used_btree_entries - ul_pos - 2) * sizeof(struct btree_level));
	da(ul,array_btree)->n_used_btree_entries--;
	if (unlikely(da(ul,array_btree)->n_used_btree_entries == 1)) {
		free_btree_indices(ul);
		data_free_r1(ul);
		*w->root = pointer_data(left);
	}
}

static void try_join_both_siblings_flat(struct walk_context *w, unsigned char **result_flat)
{
	if (w->upper_level) {
		if (w->upper_level_pos < da(w->upper_level,array_btree)->n_used_btree_entries - 1) {
			try_join_siblings_flat(w, result_flat, false);
		}
		if (w->upper_level_pos) {
			w->upper_level_pos--;
			try_join_siblings_flat(w, result_flat, true);
		}
	}
}

static bool ptr_to_flat(struct walk_context *w, const struct type *type, unsigned char **result_flat, ajla_error_t *err)
{
	struct data *array, *right, *single;

	array = pointer_get_data(*w->ptr);

	if (unlikely(da(array,array_pointers)->n_used_entries == 1)) {
		struct data *new_flat;
		new_flat = data_alloc_array_flat_mayfail(type, 1, 1, false, err pass_file_line);
		if (unlikely(!new_flat))
			goto ret_err;
		*result_flat = da_array_flat(new_flat);
		data_dereference(array);
		*w->ptr = pointer_data(new_flat);
		try_join_both_siblings_flat(w, result_flat);
		return true;
	} else if (!index_to_int(w->idx)) {
		array_index_t existing_size;
		bool ret;
		index_from_int(&existing_size, da(array,array_pointers)->n_used_entries);
		ret = leaf_prepend_flat(w, type, existing_size, result_flat, err);
		index_free(&existing_size);
		if (unlikely(!ret))
			goto ret_err;
		pointer_dereference(da(array,array_pointers)->pointer[0]);
		da(array,array_pointers)->n_used_entries--;
		da(array,array_pointers)->n_allocated_entries--;
		da(array,array_pointers)->pointer++;
		return true;
	} else if (index_to_int(w->idx) == da(array,array_pointers)->n_used_entries - 1) {
		array_index_t existing_size;
		bool ret;
		index_from_int(&existing_size, da(array,array_pointers)->n_used_entries);
		ret = leaf_append_flat(w, type, existing_size, result_flat, err);
		index_free(&existing_size);
		if (unlikely(!ret))
			goto ret_err;
		pointer_dereference(da(array,array_pointers)->pointer[da(array,array_pointers)->n_used_entries - 1]);
		da(array,array_pointers)->n_used_entries--;
		return true;
	} else {
		struct btree_level *split;
		array_index_t prev_idx;
		int_default_t n_allocated = da(array,array_pointers)->n_used_entries - 1 - index_to_int(w->idx);

		right = data_alloc_array_pointers_mayfail(n_allocated, da(array,array_pointers)->n_used_entries - 1 - index_to_int(w->idx), err pass_file_line);
		if (unlikely(!right))
			goto ret_err;
		memcpy(da(right,array_pointers)->pointer, da(array,array_pointers)->pointer + index_to_int(w->idx) + 1, da(right,array_pointers)->n_used_entries * sizeof(pointer_t));

		single = data_alloc_array_flat_mayfail(type, 1, 1, false, err pass_file_line);
		if (unlikely(!single))
			goto free_right_ret_err;

		*result_flat = da_array_flat(single);

		split = expand_parent(w, 3, &prev_idx, err);
		if (unlikely(!split))
			goto free_single_right_ret_err;

		split[0].node = pointer_data(array);
		index_add3(&split[0].end_index, prev_idx, w->idx);
		split[1].node = pointer_data(single);
		index_copy(&split[1].end_index, split[0].end_index);
		index_add_int(&split[1].end_index, 1);
		split[2].node = pointer_data(right);
		split[2].end_index = prev_idx;
		index_add_int(&split[2].end_index, da(array,array_pointers)->n_used_entries);

		da(array,array_pointers)->n_used_entries = index_to_int(w->idx);
		pointer_dereference(da(array,array_pointers)->pointer[index_to_int(w->idx)]);

		return true;
	}

free_single_right_ret_err:
	data_free_r1(single);
free_right_ret_err:
	data_free_r1(right);
ret_err:
	return false;
}

static bool same_to_ptr(struct walk_context *w, pointer_t **result_ptr, ajla_error_t *err)
{
	struct data *array, *right, *single;
	pointer_t ptr;
	array_index_t n_entries_1;

	array = pointer_get_data(*w->ptr);
	ptr = da(array,array_same)->pointer;

	if (unlikely(!index_ge_int(da(array,array_same)->n_entries, 2))) {
		single = alloc_one_ptr(ptr, err);
		if (unlikely(!single))
			goto ret_err;
		*result_ptr = &da(single,array_pointers)->pointer[0];
		index_free(&da(array,array_same)->n_entries);
		data_free_r1(array);
		*w->ptr = pointer_data(single);
		try_join_both_siblings_ptr(w, result_ptr);
		return true;
	} else if (!index_ge_int(w->idx, 1)) {
		bool ret;
		ret = leaf_prepend_ptr(w, da(array,array_same)->n_entries, ptr, result_ptr, err);
		if (unlikely(!ret))
			goto ret_err;
		index_sub_int(&da(array,array_same)->n_entries, 1);
		pointer_reference_owned(ptr);
		return true;
	} else if (index_copy(&n_entries_1, da(array,array_same)->n_entries), index_sub_int(&n_entries_1, 1), index_ge_index(w->idx, n_entries_1)) {
		bool ret;
		ret = leaf_append_ptr(w, da(array,array_same)->n_entries, ptr, result_ptr, err);
		if (unlikely(!ret)) {
			index_free(&n_entries_1);
			goto ret_err;
		}
		index_free(&da(array,array_same)->n_entries);
		da(array,array_same)->n_entries = n_entries_1;
		pointer_reference_owned(ptr);
		return true;
	} else {
		struct btree_level *split;
		array_index_t prev_idx;

		index_sub(&n_entries_1, w->idx);
		right = data_alloc_array_same_mayfail(n_entries_1, err pass_file_line);
		if (unlikely(!right))
			goto ret_err;
		da(right,array_same)->pointer = ptr;

		single = alloc_one_ptr(ptr, err);
		if (unlikely(!single))
			goto free_right_ret_err;
		*result_ptr = &da(single,array_pointers)->pointer[0];

		split = expand_parent(w, 3, &prev_idx, err);
		if (unlikely(!split))
			goto free_single_right_ret_err;

		split[0].node = pointer_data(array);
		index_add3(&split[0].end_index, prev_idx, w->idx);
		split[1].node = pointer_data(single);
		index_copy(&split[1].end_index, split[0].end_index);
		index_add_int(&split[1].end_index, 1);
		split[2].node = pointer_data(right);
		split[2].end_index = prev_idx;
		index_add(&split[2].end_index, da(array,array_same)->n_entries);

		index_free(&da(array,array_same)->n_entries);
		index_copy(&da(array,array_same)->n_entries, w->idx);

		pointer_reference_owned(ptr);
		pointer_reference_owned(ptr);

		return true;
	}

free_single_right_ret_err:
	data_free_r1(single);
free_right_ret_err:
	data_free_r1(right);
ret_err:
	return false;
}

static bool same_to_flat(struct walk_context *w, const struct type *type, unsigned char **result_flat, ajla_error_t *err)
{
	struct data *array, *right, *single;
	pointer_t ptr;
	array_index_t n_entries_1;

	array = pointer_get_data(*w->ptr);
	ptr = da(array,array_same)->pointer;

	if (unlikely(!index_ge_int(da(array,array_same)->n_entries, 2))) {
		struct data *new_flat;
		new_flat = data_alloc_array_flat_mayfail(type, 1, 1, false, err pass_file_line);
		if (unlikely(!new_flat))
			goto ret_err;
		*result_flat = da_array_flat(new_flat);
		data_dereference(array);
		*w->ptr = pointer_data(new_flat);
		try_join_both_siblings_flat(w, result_flat);
		return true;
	} else if (!index_ge_int(w->idx, 1)) {
		bool ret;
		ret = leaf_prepend_flat(w, type, da(array,array_same)->n_entries, result_flat, err);
		if (unlikely(!ret))
			goto ret_err;
		index_sub_int(&da(array,array_same)->n_entries, 1);
		return true;
	} else if (index_copy(&n_entries_1, da(array,array_same)->n_entries), index_sub_int(&n_entries_1, 1), index_ge_index(w->idx, n_entries_1)) {
		bool ret;
		ret = leaf_append_flat(w, type, da(array,array_same)->n_entries, result_flat, err);
		if (unlikely(!ret)) {
			index_free(&n_entries_1);
			goto ret_err;
		}
		index_free(&da(array,array_same)->n_entries);
		da(array,array_same)->n_entries = n_entries_1;
		return true;
	} else {
		struct btree_level *split;
		array_index_t prev_idx;

		index_sub(&n_entries_1, w->idx);
		right = data_alloc_array_same_mayfail(n_entries_1, err pass_file_line);
		if (unlikely(!right))
			goto ret_err;
		da(right,array_same)->pointer = ptr;

		single = data_alloc_array_flat_mayfail(type, 1, 1, false, err pass_file_line);
		if (unlikely(!single))
			goto free_right_ret_err;

		*result_flat = da_array_flat(single);

		split = expand_parent(w, 3, &prev_idx, err);
		if (unlikely(!split))
			goto free_single_right_ret_err;

		split[0].node = pointer_data(array);
		index_add3(&split[0].end_index, prev_idx, w->idx);
		split[1].node = pointer_data(single);
		index_copy(&split[1].end_index, split[0].end_index);
		index_add_int(&split[1].end_index, 1);
		split[2].node = pointer_data(right);
		split[2].end_index = prev_idx;
		index_add(&split[2].end_index, da(array,array_same)->n_entries);

		index_free(&da(array,array_same)->n_entries);
		index_copy(&da(array,array_same)->n_entries, w->idx);

		pointer_reference_owned(ptr);

		return true;
	}

free_single_right_ret_err:
	data_free_r1(single);
free_right_ret_err:
	data_free_r1(right);
ret_err:
	return false;
}

bool attr_fastcall array_modify(pointer_t *root, array_index_t idx, unsigned flags, pointer_t **result_ptr, unsigned char **result_flat, const struct type **flat_type, frame_s *fp, const code_t *ip)
{
	struct walk_context w;
	ajla_error_t err;
	struct data *array;

	*result_ptr = NULL;
	*result_flat = NULL;

	walk_init_context(&w, root, idx);

next_level:
	array = get_writable(w.ptr, &err);
	if (unlikely(!array))
		goto ret_err;
	switch (da_tag(array)) {
		case DATA_TAG_array_slice: {
			array = array_clone(w.ptr, &err);
			if (unlikely(!array))
				goto ret_err;
		}
			/*-fallthrough*/
		case DATA_TAG_array_flat: {
			if (unlikely(index_ge_int(w.idx, da(array,array_flat)->n_used_entries)))
				goto ret_err_out_of_range;

			if (unlikely(flags & ARRAY_MODIFY_NEED_PTR)) {
				if (unlikely(!flat_to_ptr(&w, result_ptr, &err)))
					goto ret_err;
				break;
			}

			*flat_type = da(array,array_flat)->type;
			*result_flat = da_array_flat(array) + index_to_int(w.idx) * da_array_flat_element_size(array);
			break;
		}
		case DATA_TAG_array_pointers: {
			if (unlikely(index_ge_int(w.idx, da(array,array_pointers)->n_used_entries)))
				goto ret_err_out_of_range;

			if (unlikely(flags & ARRAY_MODIFY_NEED_FLAT)) {
				if (unlikely(!ptr_to_flat(&w, *flat_type, result_flat, &err)))
					goto ret_err;
				break;
			}

			*result_ptr = &da(array,array_pointers)->pointer[index_to_int(w.idx)];
			break;
		}
		case DATA_TAG_array_same: {
			if (unlikely(index_ge_index(w.idx, da(array,array_same)->n_entries)))
				goto ret_err_out_of_range;
			if (!(flags & ARRAY_MODIFY_NEED_FLAT)) {
				if (unlikely(!same_to_ptr(&w, result_ptr, &err)))
					goto ret_err;
				break;
			} else {
				if (unlikely(!same_to_flat(&w, *flat_type, result_flat, &err)))
					goto ret_err;
				break;
			}
		}
		case DATA_TAG_array_btree: {
			if (unlikely(!walk_for_write(&w, &err)))
				goto ret_err;
			goto next_level;
		}
		default:
			internal(file_line, "array_modify: invalid array tag %u", da_tag(array));
	}

	walk_free_context(&w);

	return true;

ret_err_out_of_range:
	err = error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE);
ret_err:
	walk_free_context(&w);
	pointer_dereference(*root);
	*root = pointer_error(err, fp, ip pass_file_line);
	*result_ptr = root;
	return false;
}

array_index_t attr_fastcall array_len(struct data *array)
{
	array_index_t result, tmp;
	switch (da_tag(array)) {
		case DATA_TAG_array_flat:
			index_from_int(&result, da(array,array_flat)->n_used_entries);
			break;
		case DATA_TAG_array_slice:
			index_from_int(&result, da(array,array_slice)->n_entries);
			break;
		case DATA_TAG_array_pointers:
			index_from_int(&result, da(array,array_pointers)->n_used_entries);
			break;
		case DATA_TAG_array_same:
			index_copy(&result, da(array,array_same)->n_entries);
			break;
		case DATA_TAG_array_btree:
			index_copy(&result, da(array,array_btree)->btree[da(array,array_btree)->n_used_btree_entries - 1].end_index);
			break;
		case DATA_TAG_array_incomplete:
			index_from_int(&result, 0);
follow_incomplete_chain:
			tmp = array_len(pointer_get_data(da(array,array_incomplete)->first));
			ajla_assert_lo(index_ge_int(tmp, 1), (file_line, "array_len: the first part is empty"));
			index_add(&result, tmp);
			index_free(&tmp);

			ajla_assert_lo(!pointer_is_thunk(da(array,array_incomplete)->next), (file_line, "array_len: incomplete thunk is not evaluated"));
			array = pointer_get_data(da(array,array_incomplete)->next);
			if (da_tag(array) != DATA_TAG_array_incomplete) {
				tmp = array_len(array);
				index_add(&result, tmp);
				index_free(&tmp);
			} else {
				goto follow_incomplete_chain;
			}
			break;
		default:
			internal(file_line, "array_len: invalid array tag %u", da_tag(array));
	}
	return result;
}

bool attr_fastcall array_is_empty(struct data *array)
{
	switch (da_tag(array)) {
		case DATA_TAG_array_flat:
			return !da(array,array_flat)->n_used_entries;
		case DATA_TAG_array_pointers:
			return !da(array,array_pointers)->n_used_entries;
		case DATA_TAG_array_slice:
			return !da(array,array_slice)->n_entries;
	}
	return false;
}

static bool array_greater(struct data *array1, struct data *array2)
{
	/*
	 * Note: the code will try to run rebalance_btree_nodes on the shallower
	 * array. If both array have equal depth, we must debalance the one
	 * with less entries.
	 */
	if (da_array_depth(array1) > da_array_depth(array2))
		return true;
	if (da_array_depth(array1) < da_array_depth(array2))
		return false;
	if (da_tag(array1) == DATA_TAG_array_btree) {
		if (da(array1,array_btree)->n_used_btree_entries > da(array2,array_btree)->n_used_btree_entries)
			return true;
		if (da(array1,array_btree)->n_used_btree_entries < da(array2,array_btree)->n_used_btree_entries)
			return false;
	}
	return true;
}

struct data * attr_fastcall array_join(struct data *array1, struct data *array2, ajla_error_t *err)
{
	struct walk_context w;
	array_index_t len1, len2, total_len, new_len, len_array;
	struct data *array, *new_array;
	tag_t new_tag;
	bool append;
	struct btree_level *split;
	array_index_t prev_idx;
	struct data *fix_idx;
	pointer_t result;

#if 1
	tag_t tag1 = da_tag(array1);
	tag_t tag2 = da_tag(array2);
	if (tag1 == DATA_TAG_array_flat && tag2 == DATA_TAG_array_flat) {
		new_array = try_join_flat(array1, array2);
		if (likely(new_array != NULL)) {
			return new_array;
		}
	}
	if (tag1 == DATA_TAG_array_pointers && tag2 == DATA_TAG_array_pointers) {
		new_array = try_join_ptr(array1, array2);
		if (likely(new_array != NULL)) {
			return new_array;
		}
	}
#endif

	len1 = array_len(array1);
	if (unlikely(!index_ge_int(len1, 1))) {
		index_free(&len1);
		data_dereference(array1);
		return array2;
	}
	len2 = array_len(array2);
	if (unlikely(!index_ge_int(len2, 1))) {
		index_free(&len2);
		index_free(&len1);
		data_dereference(array2);
		return array1;
	}

	if (unlikely(!index_add3_(&total_len, len1, len2, err pass_file_line))) {
		index_free(&len1);
		index_free(&len2);
		data_dereference(array1);
		data_dereference(array2);
		return NULL;
	}
	index_free(&total_len);

	if (array_greater(array1, array2)) {
		array_index_t search_for;
		result = pointer_data(array1);
		new_array = array2;
		new_len = len2;
		search_for = len1;
		index_sub_int(&search_for, 1);
		walk_init_context(&w, &result, search_for);
		append = true;
	} else {
		array_index_t search_for;
		result = pointer_data(array2);
		new_array = array1;
		new_len = len1;
		index_free(&len2);
		index_from_int(&search_for, 0);
		walk_init_context(&w, &result, search_for);
		append = false;
	}

next_level:
	array = pointer_get_data(*w.ptr);

	if (da_array_depth(array) > da_array_depth(new_array)) {
		array = get_writable(w.ptr, err);
		if (unlikely(!array))
			goto ret_err;
		if (unlikely(!walk_for_write(&w, err)))
			goto ret_err;
		goto next_level;
	}

	split = expand_parent(&w, 2, &prev_idx, err);
	if (unlikely(!split))
		goto ret_err;

	len_array = array_len(array);
	if (!append) {
		split[0].node = pointer_data(new_array);
		split[0].end_index = prev_idx;	/* 0 */
		split[1].node = pointer_data(array);
		split[1].end_index = len_array;
	} else {
		split[0].node = pointer_data(array);
		split[0].end_index = prev_idx;
		index_add(&split[0].end_index, len_array);
		split[1].node = pointer_data(new_array);
		index_copy(&split[1].end_index, split[0].end_index);
		index_free(&len_array);
	}

	fix_idx = pointer_get_data(result);
	while (1) {
		btree_entries_t i, s;
		s = !append ? 0 : da(fix_idx,array_btree)->n_used_btree_entries - 1;
		for (i = s; i < da(fix_idx,array_btree)->n_used_btree_entries; i++)
			index_add(&da(fix_idx,array_btree)->btree[i].end_index, new_len);
		if (fix_idx == w.upper_level) {
			w.upper_level_pos = s;
			w.ptr = &da(fix_idx,array_btree)->btree[s].node;
			index_free(&w.idx);
			index_from_int(&w.idx, 0);
			break;
		}
		fix_idx = pointer_get_data(da(fix_idx,array_btree)->btree[s].node);
	}

	new_tag = da_tag(new_array);
	if (new_tag == DATA_TAG_array_btree) {
#if 0
		/* test it in get_writable instead of here */
		struct data *ac;
		ac = get_writable(w.ptr, err);
		if (unlikely(!ac))
			goto ret_err_balance;
#endif
		if (unlikely(!walk_for_write(&w, err))) {
			goto ret_err_balance;
		}
	} else if (new_tag == DATA_TAG_array_flat) {
		unsigned char *ptr = da_array_flat(new_array);
		if (append)
			w.upper_level_pos--;
		try_join_siblings_flat(&w, &ptr, append);
	} else if (new_tag == DATA_TAG_array_pointers) {
		pointer_t *ptr = &da(new_array,array_pointers)->pointer[0];
		if (append)
			w.upper_level_pos--;
		try_join_siblings_ptr(&w, &ptr, append);
	}

	index_free(&new_len);
	walk_free_context(&w);

	return pointer_get_data(result);

ret_err:
	data_dereference(new_array);
ret_err_balance:
	index_free(&new_len);
	walk_free_context(&w);
	pointer_dereference(result);
	return NULL;
}


struct data * attr_fastcall array_sub(struct data *array, array_index_t start, array_index_t len, bool deref, ajla_error_t *err)
{
	struct data *result;
	bool can_modify = deref;

go_down:
	if (!data_is_writable(array))
		can_modify = false;

	switch (da_tag(array)) {
		case DATA_TAG_array_flat: {
			if (unlikely(index_eq_int(len, da(array,array_flat)->n_used_entries)))
				goto ret_array;
			if (unlikely(index_eq_int(len, 0))) {
				result = data_alloc_array_flat_mayfail(da(array,array_flat)->type, 0, 0, false, err pass_file_line);
				goto ret_free_start_len;
			}
#if 1
			result = data_alloc_array_slice_mayfail(array, da_array_flat(array), index_to_int(start), index_to_int(len), err pass_file_line);
			goto ret_free_start_len;
#else
			result = data_alloc_array_flat_mayfail(da(array,array_flat)->type, index_to_int(len), index_to_int(len), false, err pass_file_line);
			if (!result)
				goto ret_free_start_len;
			memcpy(da_array_flat(result), da_array_flat(array) + index_to_int(start) * da(array,array_flat)->type->size, index_to_int(len) * da(array,array_flat)->type->size);
			goto ret_free_start_len;
#endif
		}
		case DATA_TAG_array_slice: {
			struct data *base;
			if (unlikely(index_eq_int(len, da(array,array_slice)->n_entries)))
				goto ret_array;
			if (unlikely(index_eq_int(len, 0))) {
				result = data_alloc_array_flat_mayfail(da(array,array_slice)->type, 0, 0, false, err pass_file_line);
				goto ret_free_start_len;
			}
			base = pointer_get_data(da(array,array_slice)->reference);
			result = data_alloc_array_slice_mayfail(base, da(array,array_slice)->flat_data_minus_data_array_offset + data_array_offset, index_to_int(start), index_to_int(len), err pass_file_line);
			goto ret_free_start_len;
		}
		case DATA_TAG_array_pointers: {
			int_default_t st, l, i;
			if (unlikely(index_eq_int(len, da(array,array_pointers)->n_used_entries)))
				goto ret_array;
			if (unlikely(index_eq_int(len, 0))) {
				result = data_alloc_array_pointers_mayfail(0, 0, err pass_file_line);
				goto ret_free_start_len;
			}
			st = index_to_int(start);
			l = index_to_int(len);
			if (can_modify) {
				int_default_t total = da(array,array_pointers)->pointer + da(array,array_pointers)->n_allocated_entries - da(array,array_pointers)->pointer_array;
				if (total / 2 > da(array,array_pointers)->n_used_entries)
					goto pointers_do_copy;
				for (i = 0; i < st; i++)
					pointer_dereference(da(array,array_pointers)->pointer[i]);
				for (i = st + l; i < da(array,array_pointers)->n_used_entries; i++)
					pointer_dereference(da(array,array_pointers)->pointer[i]);
				da(array,array_pointers)->pointer += st;
				da(array,array_pointers)->n_used_entries = l;
				da(array,array_pointers)->n_allocated_entries -= st;
				result = array;
				deref = false;
				goto ret_free_start_len;
			}
pointers_do_copy:
			result = data_alloc_array_pointers_mayfail(l, l, err pass_file_line);
			if (unlikely(!result))
				goto ret_free_start_len;
			for (i = 0; i < l; i++) {
				da(result,array_pointers)->pointer[i] = pointer_reference(&da(array,array_pointers)->pointer[st + i]);
			}
			goto ret_free_start_len;
		}
		case DATA_TAG_array_same: {
			if (unlikely(index_eq_index(len, da(array,array_same)->n_entries)))
				goto ret_array;
			if (unlikely(index_eq_int(len, 0))) {
				result = data_alloc_array_pointers_mayfail(0, 0, err pass_file_line);
				goto ret_free_start_len;
			}
			result = data_alloc_array_same_mayfail(len, err pass_file_line);
			if (likely(result != NULL)) {
				da(result,array_same)->pointer = pointer_reference(&da(array,array_same)->pointer);
			}
			index_free(&start);
			goto ret;
		}
		case DATA_TAG_array_btree: {
			array_index_t max_step;
			btree_entries_t bt_pos;
			struct btree_level *levels = da(array,array_btree)->btree;
			if (unlikely(index_eq_index(len, levels[da(array,array_btree)->n_used_btree_entries - 1].end_index)))
				goto ret_array;

			if (unlikely(index_eq_int(len, 0))) {
				result = data_alloc_array_pointers_mayfail(0, 0, err pass_file_line);
				goto ret_free_start_len;
			}

			binary_search(btree_entries_t, da(array,array_btree)->n_used_btree_entries, bt_pos, false, index_ge_index(start, levels[bt_pos].end_index), break);

			index_sub3(&max_step, levels[bt_pos].end_index, start);
			if (bt_pos != 0) {
				struct btree_level *bt_prev = &levels[bt_pos - 1];
				index_sub(&start, bt_prev->end_index);
			}
			if (index_ge_index(max_step, len)) {
				pointer_t down_ptr;
				index_free(&max_step);
				down_ptr = levels[bt_pos].node;
				if (deref) {
					pointer_reference_owned(down_ptr);
					data_dereference(array);
				}
				array = pointer_get_data(down_ptr);
				goto go_down;
			}
			index_sub(&len, max_step);
			result = array_sub(pointer_get_data(levels[bt_pos].node), start, max_step, false, err);
			if (unlikely(!result))
				goto ret;
			do {
				array_index_t zero0;
				struct data *xa;
				bt_pos++;
				index_sub3(&max_step, levels[bt_pos].end_index, levels[bt_pos - 1].end_index);
				if (!index_ge_index(len, max_step)) {
					index_free(&max_step);
					index_copy(&max_step, len);
				}
				index_sub(&len, max_step);
				index_from_int(&zero0, 0);
				xa = array_sub(pointer_get_data(levels[bt_pos].node), zero0, max_step, false, err);

				result = array_join(result, xa, err);
				if (unlikely(!result)) {
					index_free(&len);
					goto ret;
				}
			} while (index_ge_int(len, 1));
			index_free(&len);
			goto ret;
		}
		default:
			internal(file_line, "array_sub: invalid array tag %u", da_tag(array));
	}

ret_array:
	if (deref)
		deref = false;
	else
		data_reference(array);
	result = array;

ret_free_start_len:
	index_free(&start);
	index_free(&len);

ret:
	if (deref)
		data_dereference(array);
	return result;
}


static int_default_t estimate_length(array_index_t length)
{
	if (likely(index_is_int(length)))
		return index_to_int(length);
	return signed_maximum(int_default_t);
}

pointer_t array_create(array_index_t length, const struct type *flat_type, const unsigned char *flat, pointer_t ptr)
{
	pointer_t result = pointer_empty();
	int_default_t est, i;
	struct data *array;
	unsigned char *flat_ptr;
	ajla_error_t err, *err_ptr;

try_again:
	est = estimate_length(length);

	if (false) {
oom:
		est >>= 1;
		if (!est) {
			if (!pointer_is_empty(result))
				pointer_dereference(result);
			result = pointer_error(err, NULL, NULL pass_file_line);
			goto ret_result;
		}
	}
	err_ptr = &err;
	if (likely(est > 1))
		err_ptr = MEM_DONT_TRY_TO_FREE;
	if (flat_type) {
		flat_size_t element_size;
		bool cnst = data_element_is_const(flat, flat_type->size);
		bool clear = cnst && !flat[0];
		array = data_alloc_array_flat_mayfail(flat_type, est, est, clear, err_ptr pass_file_line);
		if (unlikely(!array))
			goto oom;
		if (!clear) {
			flat_ptr = da_array_flat(array);
			element_size = flat_type->size;
			if (cnst) {
				memset(flat_ptr, flat[0], element_size * est);
			} else {
				int_default_t first_est = minimum(est, 4096 / element_size);
				for (i = 0; i < first_est; i++) {
					flat_ptr = mempcpy(flat_ptr, flat, element_size);
				}
				while (i < est) {
					int_default_t this_step = minimum(est - i, first_est);
					flat_ptr = mempcpy(flat_ptr, da_array_flat(array), this_step * element_size);
					i += this_step;
				}
			}
		}
	} else {
		array = data_alloc_array_pointers_mayfail(est, est, err_ptr pass_file_line);
		if (unlikely(!array))
			goto oom;
		if (unlikely(!est))
			pointer_dereference(ptr);
		else
			pointer_reference_owned_multiple(ptr, est - 1);
		for (i = 0; i < est; i++) {
			da(array,array_pointers)->pointer[i] = ptr;
		}
		ptr = pointer_empty();
	}

	if (likely(pointer_is_empty(result))) {
		result = pointer_data(array);
	} else {
		struct data *jr;
		jr = array_join(pointer_get_data(result), array, &err);
		if (!jr) {
			result = pointer_error(err, NULL, NULL pass_file_line);
			goto ret_result;
		}
		result = pointer_data(jr);
	}

	index_sub_int(&length, est);
	if (unlikely(index_ge_int(length, 1)))
		goto try_again;

ret_result:
	if (!pointer_is_empty(ptr))
		pointer_dereference(ptr);
	index_free(&length);
	return result;
}

pointer_t array_create_sparse(array_index_t length, pointer_t ptr)
{
	struct data *array;
	ajla_error_t err;

	if (unlikely(!index_ge_int(length, 1))) {
		array_index_t z;
		index_free(&length);
		index_from_int(&z, 0);
		return array_create(z, NULL, NULL, ptr);
	}

	array = data_alloc_array_same_mayfail(length, &err pass_file_line);
	if (unlikely(!array)) {
		pointer_dereference(ptr);
		return pointer_error(err, NULL, NULL pass_file_line);
	}
	da(array,array_same)->pointer = ptr;

	return pointer_data(array);
}

pointer_t attr_fastcall array_string(int_default_t length, const struct type *flat_type, const unsigned char *flat)
{
	ajla_error_t err;
	struct data *array;

	array = data_alloc_array_flat_mayfail(flat_type, length, length, false, &err pass_file_line);
	if (unlikely(!array)) {
		return pointer_error(err, NULL, NULL pass_file_line);
	}

	memcpy(da_array_flat(array), flat, flat_type->size * length);

	return pointer_data(array);
}


void attr_fastcall array_incomplete_decompose(struct data *array, struct data **first, pointer_t *last)
{
	*first = pointer_get_data(da(array,array_incomplete)->first);
	ajla_assert_lo(!array_is_empty(*first), (file_line, "array_incomplete_decompose: the first part is empty"));
	if (data_is_writable(array)) {
		*last = da(array,array_incomplete)->next;
		data_free_r1(array);
	} else {
		data_reference(*first);
		*last = pointer_reference(&da(array,array_incomplete)->next);
		data_dereference(array);
	}
}

bool attr_fastcall array_incomplete_collapse(pointer_t *ptr)
{
	struct data *array, *first, *next, *next_first;
	tag_t next_tag;
	pointer_t next_next;
	ajla_error_t err;
	bool changed = false;

	array = pointer_get_data(*ptr);

try_to_join_again:
	pointer_follow(&da(array,array_incomplete)->next, false, next, PF_NOEVAL, NULL, NULL,
		return changed,
		return changed
	);

	changed = true;

	next_tag = da_tag(next);
	if (next_tag != DATA_TAG_array_incomplete) {
		struct data *d;
		ajla_assert_lo(DATA_TAG_is_array(next_tag), (file_line, "array_incomplete_collapse: invalid tag %u", next_tag));
		array_incomplete_decompose(array, &first, &next_next);
		d = array_join(first, next, &err);
		if (!d)
			*ptr = pointer_error(err, NULL, NULL pass_file_line);
		else
			*ptr = pointer_data(d);
		return changed;
	} else {
		struct data *joined;
		array_incomplete_decompose(array, &first, &next_next);
		array_incomplete_decompose(next, &next_first, &next_next);
		joined = array_join(first, next_first, &err);
		if (!joined) {
			pointer_dereference(next_next);
			*ptr = pointer_error(err, NULL, NULL pass_file_line);
			return changed;
		}
		array = data_alloc_array_incomplete(joined, next_next, &err pass_file_line);
		if (unlikely(!array)) {
			data_dereference(joined);
			pointer_dereference(next_next);
			*ptr = pointer_error(err, NULL, NULL pass_file_line);
			return changed;
		}
		*ptr = pointer_data(array);
		goto try_to_join_again;
	}
}

struct data * attr_fastcall array_from_flat_mem(const struct type *type, const char *mem, size_t n_elements, ajla_error_t *mayfail)
{
	struct data *b;
	struct data *r = NULL;
	int_default_t s;

again:
	if (unlikely(n_elements > signed_maximum(int_default_t)))
		s = signed_maximum(int_default_t);
	else
		s = (int_default_t)n_elements;
	b = data_alloc_array_flat_mayfail(type, s, s, false, mayfail pass_file_line);
	if (unlikely(!b))
		goto ret_null;
	memcpy(da_array_flat(b), mem, s * type->size);
	if (!r) {
		r = b;
	} else {
		r = array_join(r, b, mayfail);
		if (unlikely(!r))
			goto ret_null;
	}
	if ((size_t)s < n_elements) {
		mem += s * type->size;
		n_elements -= s;
		goto again;
	}
	return r;

ret_null:
	if (r)
		data_dereference(r);
	return NULL;
}



#ifdef ARRAY_INDEX_T_COUNT_INDICES

shared_var refcount_t n_indices;

void index_increment_count(void)
{
	refcount_inc(&n_indices);
}

void index_decrement_count(void)
{
	if (unlikely(refcount_dec(&n_indices)))
		internal(file_line, "index_decrement_count: index refcount underflowed");
}

#endif

void name(array_index_init)(void)
{
#ifdef ARRAY_INDEX_T_COUNT_INDICES
	refcount_init(&n_indices);
#endif
}

void name(array_index_done)(void)
{
#ifdef ARRAY_INDEX_T_COUNT_INDICES
	if (unlikely(!refcount_is_one(&n_indices)))
		internal(file_line, "array_index_done: leaked %"PRIuMAX" array indices", (uintmax_t)refcount_get_nonatomic(&n_indices) - 1);
#endif
}

#endif
