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

#include "mem_al.h"
#include "str.h"

#include "layout.h"

#define MAX_LOG2_ALIGN		5
#define MAX_SIZE		65

struct layout_entry {
	frame_t slots;
	unsigned char log2_align;
	frame_t position;
};

struct layout {
	uchar_efficient_t slot_bits;
	char_efficient_t flags_per_slot_bits;
	frame_t alignment;
	frame_t alignment_offset;
	struct layout_entry *entries;
	size_t n_entries;
	frame_t n_slots;
	frame_t max_align;
	frame_t min_idx[MAX_SIZE][MAX_LOG2_ALIGN];
};

static frame_t bitmap_slots(struct layout *l, frame_t n_vars)
{
	return (n_vars + (1 << l->flags_per_slot_bits) - 1) >> l->flags_per_slot_bits;
}

static frame_t bitmap_slots_estimate(struct layout *l, frame_t n_vars)
{
	return (n_vars - 1) / ((1 << l->flags_per_slot_bits) - 1) + 1;
}

struct layout *layout_start(uchar_efficient_t slot_bits, char_efficient_t flags_per_slot_bits, frame_t alignment, frame_t alignment_offset, ajla_error_t *mayfail)
{
	struct layout *l;

	l = mem_alloc_mayfail(struct layout *, sizeof(struct layout), mayfail);
	if (unlikely(!l))
		goto err0;
	l->slot_bits = slot_bits;
	l->flags_per_slot_bits = flags_per_slot_bits;
	ajla_assert_lo(is_power_of_2(alignment) && !((alignment | alignment_offset) & ((1U << l->slot_bits) - 1)), (file_line, "layout_start: invalid alignment %"PRIuMAX", %"PRIuMAX"", (uintmax_t)alignment, (uintmax_t)alignment_offset));
	l->alignment = alignment >> l->slot_bits;
	l->alignment_offset = alignment_offset >> l->slot_bits;
	if (unlikely(!array_init_mayfail(struct layout_entry, &l->entries, &l->n_entries, mayfail)))
		goto err1;
	l->max_align = 1U << l->slot_bits;

	return l;

err1:
	mem_free(l);
err0:
	return NULL;
}

bool layout_add(struct layout *l, frame_t size, frame_t align, ajla_error_t *mayfail)
{
	struct layout_entry le;

	ajla_assert(is_power_of_2(align), (file_line, "layout_add: invalid align %"PRIuMAX"", (uintmax_t)align));

	if (unlikely(align < 1U << l->slot_bits))
		align = 1U << l->slot_bits;
	if (unlikely(align > l->max_align))
		l->max_align = align;
	size = round_up(size, 1U << l->slot_bits);

	le.slots = size >> l->slot_bits;
	le.log2_align = (unsigned char)log_2(align >> l->slot_bits);
	le.position = NO_FRAME_T;	/* avoid warning */
	if (!array_add_mayfail(struct layout_entry, &l->entries, &l->n_entries, le, NULL, mayfail))
		return false;
	return true;
}

bool layout_compute(struct layout *l, bool linear, ajla_error_t *mayfail)
{
	frame_t i, j;
	frame_t n_slots;
	frame_t flag_slots;

	uchar_efficient_t *bitmap = NULL;
	size_t bitmap_size;

#define align_slots							\
	do {								\
		frame_t a = n_slots;					\
		a += -(a + l->alignment_offset) & (l->alignment - 1);	\
		if (unlikely(a < n_slots))				\
			goto overflow;					\
		n_slots = a;						\
	} while (0)

	n_slots = 0;
	if (unlikely(!l->n_entries))
		goto ret_true;

	flag_slots = 0;
	if (l->flags_per_slot_bits >= 0) {
		for (i = 0; i < l->n_entries; i++) {
			frame_t a = n_slots + l->entries[i].slots;
			if (unlikely(a < n_slots))
				goto overflow;
			n_slots = a;
		}

		align_slots;
		flag_slots = bitmap_slots_estimate(l, n_slots);
		n_slots += flag_slots;
		if (unlikely(n_slots < flag_slots))
			goto overflow;
		align_slots;
		flag_slots = bitmap_slots(l, n_slots);
	}

again:
	for (i = 0; i < MAX_SIZE; i++)
		for (j = 0; j < MAX_LOG2_ALIGN; j++)
			l->min_idx[i][j] = flag_slots;

	if (unlikely(!array_init_mayfail(uchar_efficient_t, &bitmap, &bitmap_size, mayfail)))
		goto ret_false;

	for (i = 0; i < l->n_entries; i++) {
		frame_t *ptr, start;
		struct layout_entry *le = &l->entries[i];
		if (linear) {
			ptr = &l->min_idx[0][0];
			start = *ptr;
		} else if (likely(le->slots < MAX_SIZE) && likely(le->log2_align < MAX_LOG2_ALIGN)) {
			ptr = &l->min_idx[le->slots][le->log2_align];
			start = *ptr;
		} else {
			ptr = NULL;
			start = flag_slots;
		}

		while (1) {
			frame_t a;
			frame_t more = -(start + l->alignment_offset) & ((1U << le->log2_align) - 1);
			if (unlikely(more != 0))
				goto search_further;

			a = start + le->slots;
			if (unlikely(a < start))
				goto overflow;
			for (j = le->slots - 1; j != (frame_t)-1; j--) {
				if ((frame_t)(start + j) < bitmap_size && bitmap[start + j]) {
					more = j + 1;
					goto search_further;
				}
			}

			while (bitmap_size < (frame_t)(start + le->slots)) {
				if (unlikely(!array_add_mayfail(uchar_efficient_t, &bitmap, &bitmap_size, 0, NULL, mayfail)))
					goto ret_false;
				if (unlikely(bitmap_size != (frame_t)bitmap_size))
					goto overflow;
			}
			for (j = 0; j < le->slots; j++)
				bitmap[start + j] = 1;
			break;

search_further:
			if (unlikely(start + more < start))
				goto overflow;
			start += more;
		}
		le->position = start;
		if (likely(ptr != NULL))
			*ptr = start + le->slots;
	}

	n_slots = (frame_t)bitmap_size;
	align_slots;

	mem_free(bitmap);
	bitmap = NULL;

	if (l->flags_per_slot_bits >= 0) {
		frame_t new_flag_slots = bitmap_slots(l, n_slots);
		if (unlikely(!new_flag_slots))
			goto overflow;
		if (unlikely(new_flag_slots > flag_slots)) {
			flag_slots = new_flag_slots;
			goto again;
		}
	}

ret_true:
	if (unlikely(n_slots >= sign_bit(frame_t)))
		goto overflow;

	l->n_slots = n_slots;

	return true;

#undef add_slots

overflow:
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "layout size overflow");
ret_false:
	if (bitmap)
		mem_free(bitmap);
	return false;
}

frame_t layout_get(struct layout *l, frame_t idx)
{
	ajla_assert_lo(idx < l->n_entries, (file_line, "layout_get: invalid index: %"PRIuMAX" >= %"PRIuMAX"", (uintmax_t)idx, (uintmax_t)l->n_entries));
	return l->entries[idx].position;
}

frame_t layout_size(const struct layout *l)
{
	return l->n_slots;
}

frame_t layout_alignment(const struct layout *l)
{
	return l->max_align;
}

void layout_free(struct layout *l)
{
	if (likely(l->entries != NULL))
		mem_free(l->entries);
	mem_free(l);
}
