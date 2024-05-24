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

#ifndef AJLA_TYPE_H
#define AJLA_TYPE_H

#include "list.h"

typedef unsigned char flat_size_t;
typedef uchar_efficient_t type_tag_t;


#define TYPE_TAG_fixed			0
#define TYPE_TAG_integer		(TYPE_TAG_fixed + 2 * TYPE_FIXED_N)
#define TYPE_TAG_real			(TYPE_TAG_integer + TYPE_INT_N)
#define TYPE_TAG_val			(TYPE_TAG_real + TYPE_REAL_N)

#define TYPE_TAG_flat_option		(TYPE_TAG_val + 0)
#define TYPE_TAG_builtin_N		(TYPE_TAG_val + 1)
#define TYPE_TAG_unknown		(TYPE_TAG_val + 1)
#define TYPE_TAG_record			(TYPE_TAG_val + 2)
#define TYPE_TAG_flat_record		(TYPE_TAG_val + 3)
#define TYPE_TAG_flat_array		(TYPE_TAG_val + 4)
#define TYPE_TAG_N			(TYPE_TAG_val + 5)

#define TYPE_TAG_VALIDATE(x)		ajla_assert((unsigned)(x) < TYPE_TAG_N, (file_line, "invalid type"))

#define TYPE_TAG_fixed_signed		0
#define TYPE_TAG_fixed_unsigned		1

#define TYPE_TAG_IS_FIXED(x)		(TYPE_TAG_VALIDATE(x), /*(x) >= TYPE_TAG_fixed &&*/ (x) < TYPE_TAG_fixed + 2 * TYPE_FIXED_N)
#define TYPE_TAG_IS_INT(x)		(TYPE_TAG_VALIDATE(x), (x) >= TYPE_TAG_integer && (x) < TYPE_TAG_integer + TYPE_INT_N)
#define TYPE_TAG_IS_REAL(x)		(TYPE_TAG_VALIDATE(x), (x) >= TYPE_TAG_real && (x) < TYPE_TAG_real + TYPE_REAL_N)
#define TYPE_TAG_FIXED_IS_UNSIGNED(x)	((((x) - TYPE_TAG_fixed) & 1) == TYPE_TAG_fixed_unsigned)
#define TYPE_TAG_IDX_FIXED(x)		((x) - TYPE_TAG_fixed)
#define TYPE_TAG_IDX_INT(x)		((x) - TYPE_TAG_integer)
#define TYPE_TAG_IDX_REAL(x)		((x) - TYPE_TAG_real)
#define TYPE_TAG_IS_BUILTIN(x)		(TYPE_TAG_IS_FIXED(x) || TYPE_TAG_IS_REAL(x) || TYPE_TAG_IS_INT(x) || (x) == TYPE_TAG_flat_option)
#define TYPE_TAG_IS_FLAT(x)		(TYPE_TAG_IS_BUILTIN(x) || (x) == TYPE_TAG_flat_record || (x) == TYPE_TAG_flat_array)
#define TYPE_IS_FLAT(t)			(TYPE_TAG_IS_FLAT((t)->tag))

/* this limits recursion depth in flat_to_data */
#define TYPE_MAX_DEPTH			7

struct type {
	type_tag_t tag;
	unsigned char depth;
	bool extra_compare;
	flat_size_t size;
	flat_size_t align;
};

static inline bool type_is_equal(const struct type *t1, const struct type *t2)
{
	return t1 == t2 || (
		t1->tag == t2->tag &&
		t1->size == t2->size &&
		t1->align == t2->align);
}

#define type_def(t, def)	(ajla_assert_lo((t)->tag == cat(TYPE_TAG_,def), (file_line, "type_def: invalid type tag %u, expected %u", (t)->tag, cat(TYPE_TAG_,def))), get_struct(t, struct cat(def,_definition), type))

const struct type *type_get_fixed(unsigned bits, bool uns);
const struct type *type_get_int(unsigned idx);
const struct type *type_get_real(unsigned idx);
const struct type *type_get_flat_option(void);
const struct type *type_get_unknown(void);
const struct type *type_get_from_tag(type_tag_t tag);


struct record_definition {
	struct type type;
	frame_t n_slots;
	frame_t alignment;
	arg_t n_entries;
	struct list entry;
	const frame_t *idx_to_frame;			/* indexed by idx */
	const struct type *types[FLEXIBLE_ARRAY];	/* indexed by slot */
};

struct record_definition *type_alloc_record_definition(frame_t size, ajla_error_t *mayfail);

static inline bool record_definition_is_elided(const struct record_definition *def, arg_t idx)
{
	ajla_assert(idx < def->n_entries, (file_line, "record_definition_is_elided: too high index: %"PRIuMAX" >= %"PRIuMAX"", (uintmax_t)idx, (uintmax_t)def->n_entries));
	return def->idx_to_frame[idx] == NO_FRAME_T;
}

static inline frame_t record_definition_slot(const struct record_definition *def, arg_t idx)
{
	frame_t slot;
	ajla_assert(idx < def->n_entries, (file_line, "record_definition_slot: too high index: %"PRIuMAX" >= %"PRIuMAX"", (uintmax_t)idx, (uintmax_t)def->n_entries));
	slot = def->idx_to_frame[idx];
	ajla_assert(slot < def->n_slots, (file_line, "record_definition_slot: too high slot: %"PRIuMAX" >= %"PRIuMAX"", (uintmax_t)slot, (uintmax_t)def->n_slots));
	return slot;
}


struct flat_record_definition_entry {
	flat_size_t flat_offset;
	const struct type *subtype;
};

struct flat_type_head {
	struct type type;		/* must be first */
};

struct flat_record_definition {
	struct type type;		/* must be first */
	const struct type *base;
	struct flat_record_definition_entry entries[FLEXIBLE_ARRAY];	/* indexed by slot of the original record */
};

#define flat_record_n_entries(def)	(type_def((def)->base,record)->n_entries)
#define flat_record_n_slots(def)	(type_def((def)->base,record)->n_slots)


struct flat_array_definition {
	struct type type;		/* must be first */
	const struct type *base;
	flat_size_t n_elements;
};


struct type_entry;
struct type_entry *type_prepare_flat_record(const struct type *base, ajla_error_t *mayfail);
void type_set_flat_record_entry(struct type_entry *def, arg_t idx, const struct type *subtype);
const struct type *type_get_flat_record(struct type_entry *def, ajla_error_t *mayfail);
void type_free_flat_record(struct type_entry *def);

const struct type *type_get_flat_array(const struct type *base, pcode_t n_elements, ajla_error_t *mayfail);


int type_memcmp(const unsigned char *flat1, const unsigned char *flat2, const struct type *type, size_t n);


void type_init(void);
void type_done(void);

#endif
