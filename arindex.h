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

#ifndef AJLA_ARINDEX_H
#define AJLA_ARINDEX_H

#include "data.h"

#define index_export_to_int	name(index_export_to_int)
#define index_free_mp_		name(index_free_mp_)
#define index_copy_mp_		name(index_copy_mp_)
#define index_ge_index_mp_	name(index_ge_index_mp_)
#define index_eq_index_mp_	name(index_eq_index_mp_)
#define index_op_mp_		name(index_op_mp_)


static inline void index_init_from_int(mpint_t *t, int_default_t val)
{
	cat(mpint_init_from_,int_default_t)(t, val, NULL);
}

bool index_export_to_int(const mpint_t *t, int_default_t *result);

#if !defined(DEBUG) || defined(DEBUG_ARRAY_INDICES) || defined(UNUSUAL_MPINT_ARRAY_INDICES)
#define index_increment_count()		do { } while (0)
#define index_decrement_count()		do { } while (0)
#else
#define ARRAY_INDEX_T_COUNT_INDICES
#define index_increment_count	name(index_increment_count)
#define index_decrement_count	name(index_decrement_count)
void index_increment_count(void);
void index_decrement_count(void);
#endif

static inline void index_alloc_leak_(array_index_t attr_unused *idx argument_position)
{
#ifdef DEBUG_ARRAY_INDICES
	idx->test_leak = mem_alloc_position(0, NULL pass_position);
#endif
	index_increment_count();
}

static inline void index_free_leak_(array_index_t attr_unused *idx argument_position)
{
	index_decrement_count();
#ifdef DEBUG_ARRAY_INDICES
	if (likely(idx->test_leak != BAD_POINTER_3))
		mem_free_position(idx->test_leak pass_position);
	idx->test_leak = BAD_POINTER_1;
#endif
}

static inline void index_detach_leak(array_index_t attr_unused *idx)
{
#ifdef DEBUG_ARRAY_INDICES
	if (idx->test_leak != BAD_POINTER_3)
		mem_free_position(idx->test_leak pass_file_line);
	idx->test_leak = BAD_POINTER_3;
#endif
}

static inline uint_default_t index_get_value_(array_index_t idx)
{
#ifndef SCALAR_ARRAY_INDEX_T
	return idx.val;
#else
	return idx;
#endif
}

static inline void index_set_value_(array_index_t *idx, uint_default_t val)
{
#ifndef SCALAR_ARRAY_INDEX_T
	idx->val = val;
	idx->mp = NULL;		/* against warning */
#else
	*idx = val;
#endif
}

#define index_get_mp(idx)		index_get_mp_(idx pass_file_line)
static inline mpint_t *index_get_mp_(array_index_t idx argument_position)
{
	ajla_assert((int_default_t)index_get_value_(idx) < 0, (caller_file_line, "index_get_mp_: invalid value %"PRIdMAX"", (intmax_t)index_get_value_(idx)));
#ifndef SCALAR_ARRAY_INDEX_T
	return idx.mp;
#else
	return pointer_decompress((uint_default_t)(idx << 1));
#endif
}

#define index_set_mp(idx, mp)		index_set_mp_(idx, mp pass_file_line)
static inline void index_set_mp_(array_index_t *idx, mpint_t *mp argument_position)
{
#ifndef SCALAR_ARRAY_INDEX_T
	idx->val = (uint_default_t)-1;
	idx->mp = mp;
#else
	pointer_compress_test(mp, false);
	*idx = (uint_default_t)(pointer_compress(mp) >> 1) | sign_bit(uint_default_t);
#endif
}

static inline void index_validate(array_index_t attr_unused idx argument_position)
{
#ifdef DEBUG_ARRAY_INDICES
	if (likely(idx.test_leak != BAD_POINTER_3))
		mem_verify_position(idx.test_leak pass_position);
#endif
}

#ifdef SCALAR_ARRAY_INDEX_T
#define index_invalid()			(sign_bit(uint_default_t))
#define index_is_invalid(idx)		((idx) == index_invalid())
#else
static inline array_index_t index_invalid(void)
{
	array_index_t idx;
	idx.val = (uint_default_t)-1;
	idx.mp = NULL;
#ifdef DEBUG_ARRAY_INDICES
	idx.test_leak = BAD_POINTER_2;
#endif
	return idx;
}
static inline bool index_is_invalid(array_index_t idx)
{
	return (int_default_t)idx.val < 0 && !idx.mp;
}
#endif

#define index_is_mp(idx)		index_is_mp_(idx pass_file_line)
static inline bool index_is_mp_(array_index_t idx argument_position)
{
	index_validate(idx pass_position);
	return (int_default_t)index_get_value_(idx) < 0;
}

#define index_from_int(idx, val)	index_from_int_(idx, val pass_file_line)
static inline void index_from_int_(array_index_t *idx, int_default_t val argument_position)
{
	ajla_assert(val >= 0, (caller_file_line, "index_from_int: negative value %"PRIdMAX"", (intmax_t)val));
	index_alloc_leak_(idx pass_position);
#ifndef UNUSUAL_MPINT_ARRAY_INDICES
	index_set_value_(idx, (uint_default_t)val);
#else
	{
		mpint_t *result;
		result = mem_alloc_compressed_mayfail(mpint_t *, sizeof(mpint_t), NULL);
		index_init_from_int(result, val);
		index_set_mp_(idx, result pass_file_line);
	}
#endif
}

#define index_from_mp(idx, mp)		index_from_mp_(idx, mp pass_file_line)
static inline void index_from_mp_(array_index_t *idx, const mpint_t *mp argument_position)
{
#ifndef UNUSUAL_MPINT_ARRAY_INDICES
	int_default_t id;
	if (index_export_to_int(mp, &id)) {
		ajla_assert_lo(id >= 0, (caller_file_line, "index_from_mp: the result is negative: %"PRIdMAX"", (intmax_t)id));
		index_set_value_(idx, (uint_default_t)id);
	} else
#endif
	{
		mpint_t *result;
		result = mem_alloc_compressed_mayfail(mpint_t *, sizeof(mpint_t), NULL);
		mpint_alloc_copy_mayfail(result, mp, NULL);
		index_set_mp_(idx, result pass_file_line);
	}
	index_alloc_leak_(idx pass_position);
}

void index_free_mp_(array_index_t idx argument_position);
#define index_free(idx)			index_free_(idx pass_file_line)
static inline void index_free_(array_index_t *idx argument_position)
{
	if (unlikely(index_is_mp_(*idx pass_position)))
		index_free_mp_(*idx pass_position);
#ifdef DEBUG
	/* poison the pointer */
#ifndef SCALAR_ARRAY_INDEX_T
	index_set_mp_(idx, (mpint_t *)BAD_POINTER_1 pass_position);
#else
	*idx = 1 | sign_bit(uint_default_t);
#endif
#endif
	index_free_leak_(idx pass_position);
}

#define index_free_get_mp(idx, mp)	index_free_get_mp_(idx, mp pass_file_line)
static inline void index_free_get_mp_(array_index_t *idx, mpint_t *mp argument_position)
{
	mpint_t *mp_ptr;
	ajla_assert(index_is_mp_(*idx pass_position), (caller_file_line, "index_free_get_mp: positive value %"PRIdMAX"", (intmax_t)index_get_value_(*idx)));
	mp_ptr = index_get_mp_(*idx pass_position);
	*mp = *mp_ptr;
	mem_free_compressed(mp_ptr);
	index_set_value_(idx, 0);
	index_free_(idx pass_position);
}

array_index_t index_copy_mp_(array_index_t idx argument_position);
#define index_copy(idx1, idx2)		index_copy_(idx1, idx2 pass_file_line)
static inline void index_copy_(array_index_t *idx1, array_index_t idx2 argument_position)
{
	if (unlikely(index_is_mp_(idx2 pass_position))) {
		*idx1 = index_copy_mp_(idx2 pass_position);
	} else {
		*idx1 = idx2;
	}
	index_alloc_leak_(idx1 pass_position);
}

bool index_ge_index_mp_(array_index_t idx1, array_index_t idx2 argument_position);
#define index_ge_index(idx1, idx2)	index_ge_index_(idx1, idx2 pass_file_line)
static inline bool index_ge_index_(array_index_t idx1, array_index_t idx2 argument_position)
{
	index_validate(idx1 pass_position);
	index_validate(idx2 pass_position);
	if (unlikely((int_default_t)(index_get_value_(idx1) & index_get_value_(idx2)) < 0)) {
		return index_ge_index_mp_(idx1, idx2 pass_position);
	}
	return index_get_value_(idx1) >= index_get_value_(idx2);
}

bool index_eq_index_mp_(array_index_t idx1, array_index_t idx2 argument_position);
#define index_eq_index(idx1, idx2)	index_eq_index_(idx1, idx2 pass_file_line)
static inline bool index_eq_index_(array_index_t idx1, array_index_t idx2 argument_position)
{
	index_validate(idx1 pass_position);
	index_validate(idx2 pass_position);
	if (unlikely((int_default_t)(index_get_value_(idx1) & index_get_value_(idx2)) < 0)) {
		return index_eq_index_mp_(idx1, idx2 pass_position);
	}
	return index_get_value_(idx1) == index_get_value_(idx2);
}

#define index_ge_int(idx, val)		index_ge_int_(idx, val pass_file_line)
static inline bool index_ge_int_(array_index_t idx, int_default_t val argument_position)
{
	index_validate(idx pass_position);
	ajla_assert(val >= 0, (caller_file_line, "index_ge_int: negative value %"PRIdMAX"", (intmax_t)val));
#ifndef UNUSUAL_MPINT_ARRAY_INDICES
	return index_get_value_(idx) >= (uint_default_t)val;
#else
	{
		array_index_t val_idx;
		bool ret;
		index_from_int_(&val_idx, val pass_position);
		ret = index_ge_index_(idx, val_idx pass_position);
		index_free_(&val_idx pass_position);
		return ret;
	}
#endif
}

#define index_eq_int(idx, val)		index_eq_int_(idx, val pass_file_line)
static inline bool index_eq_int_(array_index_t idx, int_default_t val argument_position)
{
	index_validate(idx pass_position);
	ajla_assert(val >= 0, (caller_file_line, "index_eq_int: negative value %"PRIdMAX"", (intmax_t)val));
#ifndef UNUSUAL_MPINT_ARRAY_INDICES
	return index_get_value_(idx) == (uint_default_t)val;
#else
	{
		array_index_t val_idx;
		bool ret;
		index_from_int_(&val_idx, val pass_position);
		ret = index_eq_index_(idx, val_idx pass_position);
		index_free_(&val_idx pass_position);
		return ret;
	}
#endif
}

#define INDEX_OP_MP_ARG3_		0x1
#define INDEX_OP_MP_SUB_		0x2
array_index_t index_op_mp_(array_index_t idx2, array_index_t idx3, unsigned flags, ajla_error_t *err argument_position);
#define index_add3(idx1, idx2, idx3)	index_add3_(idx1, idx2, idx3, NULL pass_file_line)
static inline bool index_add3_(array_index_t *idx1, array_index_t idx2, array_index_t idx3, ajla_error_t *err argument_position)
{
	index_validate(idx2 pass_position);
	index_validate(idx3 pass_position);
	index_set_value_(idx1, index_get_value_(idx2) + index_get_value_(idx3));
	if (unlikely((int_default_t)(index_get_value_(*idx1) | index_get_value_(idx2) | index_get_value_(idx3)) < 0)) {
		*idx1 = index_op_mp_(idx2, idx3, INDEX_OP_MP_ARG3_, err pass_position);
		return !index_is_invalid(*idx1);
	} else {
		index_alloc_leak_(idx1 pass_position);
		return true;
	}
}

#define index_sub3(idx1, idx2, idx3)	index_sub3_(idx1, idx2, idx3 pass_file_line)
static inline void index_sub3_(array_index_t *idx1, array_index_t idx2, array_index_t idx3 argument_position)
{
	index_validate(idx2 pass_position);
	index_validate(idx3 pass_position);
	ajla_assert(index_ge_index_(idx2, idx3 pass_position), (caller_file_line, "index_sub3: invalid parameters %"PRIdMAX", %"PRIdMAX"", (intmax_t)index_get_value_(idx2), (intmax_t)index_get_value_(idx3)));
	if (unlikely(index_is_mp_(idx2 pass_position))) {
		*idx1 = index_op_mp_(idx2, idx3, INDEX_OP_MP_ARG3_ | INDEX_OP_MP_SUB_, NULL pass_position);
	} else {
		index_set_value_(idx1, index_get_value_(idx2) - index_get_value_(idx3));
		index_alloc_leak_(idx1 pass_position);
	}
}

#define index_add(idx1, idx2)		index_add_(idx1, idx2, NULL pass_file_line)
static inline bool index_add_(array_index_t *idx1, array_index_t idx2, ajla_error_t *err argument_position)
{
	uint_default_t result;
	index_validate(*idx1 pass_position);
	index_validate(idx2 pass_position);
	result = index_get_value_(*idx1) + index_get_value_(idx2);
	if (unlikely((int_default_t)(result | index_get_value_(*idx1) | index_get_value_(idx2)) < 0)) {
		*idx1 = index_op_mp_(*idx1, idx2, 0, err pass_position);
		return !index_is_invalid(*idx1);
	} else {
		index_set_value_(idx1, result);
		return true;
	}
}

#define index_sub(idx1, idx2)		index_sub_(idx1, idx2 pass_file_line)
static inline void index_sub_(array_index_t *idx1, array_index_t idx2 argument_position)
{
	index_validate(*idx1 pass_position);
	index_validate(idx2 pass_position);
	ajla_assert(index_ge_index_(*idx1, idx2 pass_position), (caller_file_line, "index_sub: invalid parameters %"PRIdMAX", %"PRIdMAX"", (intmax_t)index_get_value_(*idx1), (intmax_t)index_get_value_(idx2)));
	if (unlikely(index_is_mp_(*idx1 pass_position))) {
		*idx1 = index_op_mp_(*idx1, idx2, INDEX_OP_MP_SUB_, NULL pass_position);
	} else {
		index_set_value_(idx1, index_get_value_(*idx1) - index_get_value_(idx2));
	}
}

#define index_add_int(idx1, val)	index_add_int_(idx1, val pass_file_line)
static inline void index_add_int_(array_index_t *idx1, int_default_t val argument_position)
{
	array_index_t idx2;
	index_from_int_(&idx2, val pass_position);
	index_add_(idx1, idx2, NULL pass_position);
#if defined(ARRAY_INDEX_T_COUNT_INDICES) || defined(DEBUG_ARRAY_INDICES) || defined(UNUSUAL_MPINT_ARRAY_INDICES)
	index_free_(&idx2 pass_position);
#endif
}

#define index_sub_int(idx1, val)	index_sub_int_(idx1, val pass_file_line)
static inline void index_sub_int_(array_index_t *idx1, int_default_t val argument_position)
{
	array_index_t idx2;
	index_from_int_(&idx2, val pass_position);
	index_sub_(idx1, idx2 pass_position);
#if defined(ARRAY_INDEX_T_COUNT_INDICES) || defined(DEBUG_ARRAY_INDICES) || defined(UNUSUAL_MPINT_ARRAY_INDICES)
	index_free_(&idx2 pass_position);
#endif
}

#define index_is_int(idx)		index_is_int_(idx pass_file_line)
static inline bool index_is_int_(array_index_t idx argument_position)
{
	if (likely(!index_is_mp_(idx pass_position))) {
		return true;
	} else {
#ifdef UNUSUAL_MPINT_ARRAY_INDICES
		int_default_t val;
		if (index_export_to_int(index_get_mp_(idx pass_position), &val))
			return true;
#endif
		return false;
	}
}

#define index_to_int(idx)		index_to_int_(idx pass_file_line)
static inline int_default_t index_to_int_(array_index_t idx argument_position)
{
	int_default_t val;
	index_validate(idx pass_position);
#ifndef UNUSUAL_MPINT_ARRAY_INDICES
	val = (int_default_t)index_get_value_(idx);
#if !(defined(__IBMC__) && INT_DEFAULT_BITS > 32)
	/* compiler bug - causes internal error */
	ajla_assert(val >= 0, (caller_file_line, "index_to_int: negative number %"PRIdMAX"", (intmax_t)val));
#endif
#else
	val = 0;	/* against warning */
	if (unlikely(!index_export_to_int(index_get_mp_(idx pass_position), &val)))
		internal(caller_file_line, ("index_to_int: index_export_to_int failed"));
#endif
	return val;
}

#define index_to_mpint(idx, mp)		index_to_mpint_(idx, mp pass_file_line)
static inline void index_to_mpint_(array_index_t idx, mpint_t *mp argument_position)
{
	if (!index_is_mp_(idx pass_position)) {
		index_init_from_int(mp, (int_default_t)index_get_value_(idx));
	} else {
		mpint_alloc_copy_mayfail(mp, index_get_mp_(idx pass_position), NULL);
	}
}

#endif
