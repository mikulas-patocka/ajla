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
#include "tree.h"
#include "rwlock.h"
#include "layout.h"

#include "type.h"

static const struct type builtin_types[TYPE_TAG_unknown + 1] = {
#define f(n, s, u, sz, bits)	\
	{ TYPE_TAG_fixed + 2 * n,	0,	0,	sizeof(s),			align_of(s)	},\
	{ TYPE_TAG_fixed + 2 * n + 1,	0,	0,	sizeof(u),			align_of(u)	},
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits)	\
	{ TYPE_TAG_integer + n,		0,	0,	sizeof(s),			align_of(s),	},
#define fn(n, s)		\
	{ TYPE_TAG_N,			0,	0,	0,				0,		},
	for_all_int(f, fn)
#undef f
#undef fn
#define f(n, t, nt, pack, unpack)\
	{ TYPE_TAG_real + n,		0,	n == 3,	sizeof(t),			align_of(t)	},
#define fn(n, t)		\
	{ TYPE_TAG_N,			0,	0,	0,				0,		},
	for_all_real(f, fn)
#undef f
#undef fn
	{ TYPE_TAG_flat_option,		0,	0,	sizeof(ajla_flat_option_t),	align_of(ajla_flat_option_t)	},
	{ TYPE_TAG_unknown,		0,	0,	0,				1		},
};

const struct type *type_get_fixed(unsigned idx, bool uns)
{
	if (unlikely(idx >= TYPE_FIXED_N + uzero))
		return NULL;
	return &builtin_types[TYPE_TAG_fixed + 2 * idx + (uns ? TYPE_TAG_fixed_unsigned : TYPE_TAG_fixed_signed)];
}

const struct type *type_get_int(unsigned idx)
{
	if (unlikely(!(INT_MASK & (1U << idx)))) {
		int i;
		for (i = (int)idx + 1; i < TYPE_INT_N; i++) {
			if (INT_MASK & (1U << i)) {
				idx = (unsigned)i;
				goto ret_type;
			}
		}
		for (i = (int)idx - 1; i >= 0; i--) {
			if (INT_MASK & (1U << i)) {
				idx = (unsigned)i;
				goto ret_type;
			}
		}
		internal(file_line, "type_get_int: can't select integer type %u", idx);
	}
ret_type:
	return &builtin_types[TYPE_TAG_integer + idx];
}

const struct type *type_get_real(unsigned idx)
{
	if (unlikely(!(REAL_MASK & (1U << idx)))) {
		int i;
		for (i = (int)idx + 1; i < TYPE_REAL_N; i++) {
			if (REAL_MASK & (1U << i)) {
				idx = (unsigned)i;
				goto ret_type;
			}
		}
		return NULL;
	}
ret_type:
	return &builtin_types[TYPE_TAG_real + idx];
}

const struct type *type_get_flat_option(void)
{
	return &builtin_types[TYPE_TAG_flat_option];
}

const struct type *type_get_unknown(void)
{
	return &builtin_types[TYPE_TAG_unknown];
}

const struct type *type_get_from_tag(type_tag_t tag)
{
	ajla_assert_lo(tag < n_array_elements(builtin_types), (file_line, "type_get_from_tag: invalid tag %u", tag));
	return &builtin_types[tag];
}


shared_var struct list record_list;
shared_var mutex_t record_list_mutex;

struct record_definition *type_alloc_record_definition(frame_t size, ajla_error_t *mayfail)
{
	struct record_definition *def;
	def = struct_alloc_array_mayfail(mem_calloc_mayfail, struct record_definition, types, size, mayfail);
	if (unlikely(!def))
		return NULL;
	def->type = *type_get_unknown();
	def->type.tag = TYPE_TAG_record;
	mutex_lock(&record_list_mutex);
	list_add(&record_list, &def->entry);
	mutex_unlock(&record_list_mutex);
	return def;
}


shared_var struct tree type_tree;
rwlock_decl(type_tree_mutex);

struct type_entry {
	struct tree_entry entry;
	union {
		struct flat_type_head head;
		struct flat_record_definition flat_record_definition;
		struct flat_array_definition flat_array_definition;
	} u;
};

static int type_entry_compare(const struct tree_entry *e1, uintptr_t e2)
{
	const struct type_entry *t1 = get_struct(e1, struct type_entry, entry);
	const struct type_entry *t2 = cast_ptr(const struct type_entry *, num_to_ptr(e2));

	ajla_assert((t1->u.head.type.tag == TYPE_TAG_flat_record || t1->u.head.type.tag == TYPE_TAG_flat_array) &&
		    (t2->u.head.type.tag == TYPE_TAG_flat_record || t2->u.head.type.tag == TYPE_TAG_flat_array),
		    (file_line, "type_entry_compare: invalid type tags: %d, %d",
		    t1->u.head.type.tag == TYPE_TAG_flat_record,
		    t2->u.head.type.tag == TYPE_TAG_flat_record));

	if (unlikely(t1->u.head.type.tag != t2->u.head.type.tag))
		return (int)t1->u.head.type.tag - (int)t2->u.head.type.tag;

	if (t1->u.head.type.tag == TYPE_TAG_flat_record) {
		frame_t n_slots, i;
		ajla_assert(t1->u.flat_record_definition.base->tag == TYPE_TAG_record &&
			    t2->u.flat_record_definition.base->tag == TYPE_TAG_record,
			    (file_line, "type_entry_compare: invalid record bases: %d, %d",
			    t1->u.flat_record_definition.base->tag,
			    t2->u.flat_record_definition.base->tag));
		if (ptr_to_num(t1->u.flat_record_definition.base) < ptr_to_num(t2->u.flat_record_definition.base))
			return -1;
		if (ptr_to_num(t1->u.flat_record_definition.base) > ptr_to_num(t2->u.flat_record_definition.base))
			return 1;
		n_slots = flat_record_n_slots(&t1->u.flat_record_definition);
		for (i = 0; i < n_slots; i++) {
			if (ptr_to_num(t1->u.flat_record_definition.entries[i].subtype) < ptr_to_num(t2->u.flat_record_definition.entries[i].subtype))
				return -1;
			if (ptr_to_num(t1->u.flat_record_definition.entries[i].subtype) > ptr_to_num(t2->u.flat_record_definition.entries[i].subtype))
				return 1;
		}
		return 0;
	} else {
		if (ptr_to_num(t1->u.flat_array_definition.base) < ptr_to_num(t2->u.flat_array_definition.base))
			return -1;
		if (ptr_to_num(t1->u.flat_array_definition.base) > ptr_to_num(t2->u.flat_array_definition.base))
			return 1;
		return (int)t1->u.flat_array_definition.n_elements - (int)t2->u.flat_array_definition.n_elements;
	}
}

struct type_entry *type_prepare_flat_record(const struct type *base, ajla_error_t *mayfail)
{
	frame_t n_slots;
	struct type_entry *def;

	if (unlikely(base->depth >= TYPE_MAX_DEPTH))
		goto err_overflow;

	n_slots = type_def(base,record)->n_slots;
	def = struct_alloc_array_mayfail(mem_alloc_mayfail, struct type_entry, u.flat_record_definition.entries, n_slots, mayfail);
	if (unlikely(!def))
		return NULL;

	def->u.flat_record_definition.type.tag = TYPE_TAG_flat_record;
	def->u.flat_record_definition.type.extra_compare = 0;
	def->u.flat_record_definition.base = base;
	(void)memset(def->u.flat_record_definition.entries, 0, n_slots * sizeof(struct flat_record_definition_entry));

	return def;

err_overflow:
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "flat record too deep");
	return NULL;
}

static frame_t flat_record_slot(struct type_entry *def, arg_t idx)
{
	return record_definition_slot(type_def(def->u.flat_record_definition.base,record), idx);
}

void type_set_flat_record_entry(struct type_entry *def, arg_t idx, const struct type *subtype)
{
	frame_t slot = flat_record_slot(def, idx);
	ajla_assert_lo(!def->u.flat_record_definition.entries[slot].subtype, (file_line, "type_set_flat_record_entry: entry for index %"PRIuMAX" slot %"PRIuMAX" defined twice", (uintmax_t)idx, (uintmax_t)slot));
	def->u.flat_record_definition.entries[slot].subtype = subtype;
	if (subtype->extra_compare)
		def->u.flat_record_definition.type.extra_compare = 1;
}

static bool type_flat_record_allocate(struct type_entry *def, ajla_error_t *mayfail)
{
	arg_t i;
	struct layout *l;
	frame_t size, alignment;
	unsigned char *usemap;
	size_t u;

	l = layout_start(0, -1, 1, 0, mayfail);
	if (unlikely(!l))
		goto err;

	for (i = 0; i < flat_record_n_entries(&def->u.flat_record_definition); i++) {
		frame_t slot = flat_record_slot(def, i);
		const struct type *subtype = def->u.flat_record_definition.entries[slot].subtype;
		ajla_assert_lo(subtype != NULL, (file_line, "type_flat_record_allocate: subtype for entry %"PRIuMAX" not set", (uintmax_t)i));
		if (unlikely(!layout_add(l, subtype->size, subtype->align, mayfail)))
			goto err_free_layout;
	}

	if (unlikely(!layout_compute(l, true, mayfail)))
		goto err_free_layout;

	size = layout_size(l);
	alignment = layout_alignment(l);
	if (unlikely(size != (flat_size_t)size) ||
	    unlikely(alignment != (flat_size_t)alignment))
		goto err_overflow;

	def->u.flat_record_definition.type.depth = def->u.flat_record_definition.base->depth + 1;
	def->u.flat_record_definition.type.align = (flat_size_t)alignment;
	size = round_up(size, alignment);
	if (unlikely(!(flat_size_t)size))
		goto err_overflow;
	def->u.flat_record_definition.type.size = (flat_size_t)size;

	usemap = mem_calloc_mayfail(unsigned char *, size * sizeof(unsigned char), mayfail);
	if (unlikely(!usemap))
		goto err_free_layout;

	for (i = 0; i < flat_record_n_entries(&def->u.flat_record_definition); i++) {
		frame_t slot = flat_record_slot(def, i);
		const struct type *subtype = def->u.flat_record_definition.entries[slot].subtype;
		flat_size_t offset = (flat_size_t)layout_get(l, i);
		def->u.flat_record_definition.entries[slot].flat_offset = offset;
		memset(usemap + offset, 1, subtype->size);
	}

	for (u = 0; u < size; u++) {
		if (!usemap[u]) {
			def->u.flat_record_definition.type.extra_compare = 1;
			break;
		}
	}

	mem_free(usemap);

	layout_free(l);
	return true;

err_overflow:
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "flat record too large");
err_free_layout:
	layout_free(l);
err:
	return false;
}

const struct type *type_get_flat_record(struct type_entry *def, ajla_error_t *mayfail)
{
	struct tree_entry *e;
	struct tree_insert_position ins;

	rwlock_lock_read(&type_tree_mutex);
	e = tree_find(&type_tree, type_entry_compare, ptr_to_num(def));
	if (likely(e != NULL)) {
		rwlock_unlock_read(&type_tree_mutex);
		type_free_flat_record(def);
		return &get_struct(e, struct type_entry, entry)->u.flat_record_definition.type;
	}
	rwlock_unlock_read(&type_tree_mutex);

	if (unlikely(!type_flat_record_allocate(def, mayfail))) {
		type_free_flat_record(def);
		return NULL;
	}

	rwlock_lock_write(&type_tree_mutex);
	e = tree_find_for_insert(&type_tree, type_entry_compare, ptr_to_num(def), &ins);
	if (unlikely(e != NULL)) {
		rwlock_unlock_write(&type_tree_mutex);
		type_free_flat_record(def);
		return &get_struct(e, struct type_entry, entry)->u.flat_record_definition.type;
	}
	tree_insert_after_find(&def->entry, &ins);
	rwlock_unlock_write(&type_tree_mutex);

	return &def->u.flat_record_definition.type;
}

void type_free_flat_record(struct type_entry *def)
{
	mem_free(def);
}

const struct type *type_get_flat_array(const struct type *base, pcode_t n_elements, ajla_error_t *mayfail)
{
	struct type_entry ae;
	struct type_entry *ap;
	struct tree_entry *e;
	struct tree_insert_position ins;
	flat_size_t size;

	if (unlikely(n_elements != (pcode_t)(flat_size_t)n_elements))
		goto err_overflow;

	memset(&ae, 0, sizeof ae);	/* avoid warning */
	ae.u.flat_array_definition.type.tag = TYPE_TAG_flat_array;
	ae.u.flat_array_definition.base = base;
	ae.u.flat_array_definition.n_elements = (flat_size_t)n_elements;

	rwlock_lock_read(&type_tree_mutex);
	e = tree_find(&type_tree, type_entry_compare, ptr_to_num(&ae));
	if (likely(e != NULL)) {
		rwlock_unlock_read(&type_tree_mutex);
		return &get_struct(e, struct type_entry, entry)->u.flat_array_definition.type;
	}
	rwlock_unlock_read(&type_tree_mutex);

	if (unlikely(base->depth >= TYPE_MAX_DEPTH))
		goto err_overflow;

	size = (flat_size_t)((uintmax_t)base->size * (uintmax_t)n_elements);
	if (n_elements && unlikely(size / n_elements != base->size))
		goto err_overflow;

	ap = mem_alloc_mayfail(struct type_entry *, partial_sizeof(struct type_entry, u.flat_array_definition), mayfail);
	ap->u.flat_array_definition.type.tag = TYPE_TAG_flat_array;
	ap->u.flat_array_definition.type.depth = base->depth + 1;
	ap->u.flat_array_definition.type.extra_compare = base->extra_compare;
	ap->u.flat_array_definition.type.size = size;
	ap->u.flat_array_definition.type.align = base->align;	/* !!! TODO: use higher align for SIMD */
	ap->u.flat_array_definition.base = base;
	ap->u.flat_array_definition.n_elements = (flat_size_t)n_elements;

	rwlock_lock_write(&type_tree_mutex);
	e = tree_find_for_insert(&type_tree, type_entry_compare, ptr_to_num(&ae), &ins);
	if (unlikely(e != NULL)) {
		rwlock_unlock_write(&type_tree_mutex);
		mem_free(ap);
		return &get_struct(e, struct type_entry, entry)->u.flat_array_definition.type;
	}
	tree_insert_after_find(&ap->entry, &ins);
	rwlock_unlock_write(&type_tree_mutex);

	return &ap->u.flat_array_definition.type;

err_overflow:
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "flat array too large");
	return NULL;
}


int type_memcmp(const unsigned char *flat1, const unsigned char *flat2, const struct type *type, size_t n)
{
	size_t i;
	if (likely(!type->extra_compare))
		return memcmp(flat1, flat2, type->size * n);
	for (i = 0; i < n; i++, flat1 += type->size, flat2 += type->size) {
		int c;
		if (TYPE_TAG_IS_REAL(type->tag) && TYPE_TAG_IDX_REAL(type->tag) == 3) {
			c = memcmp(flat1, flat2, 10);
			if (c)
				return c;
		} else if (type->tag == TYPE_TAG_flat_record) {
			struct flat_record_definition *fd = type_def(type,flat_record);
			struct record_definition *rec = type_def(fd->base,record);
			arg_t i;
			for (i = 0; i < rec->n_entries; i++) {
				frame_t f = rec->idx_to_frame[i];
				struct flat_record_definition_entry *fde = &fd->entries[f];
				c = type_memcmp(flat1 + fde->flat_offset, flat2 + fde->flat_offset, fde->subtype, 1);
				if (c)
					return c;
			}
		} else if (type->tag == TYPE_TAG_flat_array) {
			struct flat_array_definition *fd = type_def(type,flat_array);
			c = type_memcmp(flat1, flat2, fd->base, fd->n_elements);
			if (c)
				return c;
		} else {
			internal(file_line, "type_memcmp: invalid type tag %u", type->tag);
		}
	}
	return 0;
}


void type_init(void)
{
	list_init(&record_list);
	mutex_init(&record_list_mutex);
	tree_init(&type_tree);
	rwlock_init(&type_tree_mutex);
}

void type_done(void)
{
	while (!tree_is_empty(&type_tree)) {
		struct type_entry *t = get_struct(tree_any(&type_tree), struct type_entry, entry);
		tree_delete(&t->entry);
		mem_free(t);
	}
	rwlock_done(&type_tree_mutex);
	while (!list_is_empty(&record_list)) {
		struct record_definition *def = get_struct(record_list.prev, struct record_definition, entry);
		list_del(&def->entry);
		if (def->idx_to_frame)
			mem_free(def->idx_to_frame);
		mem_free(def);
	}
	mutex_done(&record_list_mutex);
}
