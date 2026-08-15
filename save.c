/*
 * Copyright (C) 2024 - 2026 Mikulas Patocka
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

#include "str.h"
#include "tree.h"
#include "arindex.h"
#include "module.h"
#include "os.h"
#include "os_util.h"
#include "amalloc.h"
#include "thread.h"
#include "ipfn.h"
#include "ipio.h"
#include "builtin.h"

#include "save.h"

#include <fcntl.h>
#include <stdio.h>

#if defined(OS_HAS_MMAP) && defined(USE_AMALLOC) && !((defined(OS_CYGWIN) || defined(OS_WIN32)) && defined(POINTER_COMPRESSION))
#define USE_MMAP
#endif

static const char id[] = "AJLA" " " __DATE__ " " __TIME__;

static bool compsave;

static bool save_ok;
static char *save_data;
static size_t save_len;
static size_t writable_boundary;

static size_t last_md;

struct position_map {
	struct tree_entry entry;
	uintptr_t old_position;
	uintptr_t new_position;
	uintptr_t new_wrap_position;
	size_t size;
	bool is_function_pointer;
	bool need_duplicate;
	uintptr_t duplicate_position;
	size_t duplicate_size;
};

static struct tree position_tree;

static pointer_t *pointers;
static size_t pointers_len;

static struct function_descriptor *fn_descs;
static size_t fn_descs_len;

static struct cache_descriptor *cache_descs;
static size_t cache_descs_len;

static size_t *function_pointers;
static size_t function_pointers_len;

struct duplicate_record {
	size_t old_position;
	size_t fp_ptr;
	struct position_map *subpm;
};

static struct duplicate_record *duplicate_records;
static size_t duplicate_records_len;

struct file_descriptor {
	struct function_descriptor *fn_descs;
	size_t fn_descs_len;
	struct cache_descriptor *cache_descs;
	size_t cache_descs_len;
	char *dependencies;
	size_t dependencies_l;
	size_t writable_boundary;
	size_t *function_pointers;
	size_t function_pointers_len;
	void *base;
	int page_size;
	cpu_feature_mask_t cpu_feature_flags;
	unsigned char optimize_int;
	unsigned char privileged;
	unsigned char profiling;
	unsigned char strict_calls;
	unsigned char verifying;
	unsigned char noinline;
	unsigned char noautofma;
	chicken_mask_t chicken;
	char ajla_id[sizeof(id)];
};

static struct {
	char *loaded_data;
	size_t loaded_data_len;
#ifdef USE_MMAP
	bool loaded_data_mapped;
	bool loaded_data_amalloc;
#endif
} ld[2];

#define loaded_file_descriptor(n)	cast_ptr(struct file_descriptor *, ld[n].loaded_data + ld[n].loaded_data_len - sizeof(struct file_descriptor))


static size_t loaded_cache_idx;
static size_t loaded_fn_idx;
static size_t loaded_fn_cache;


struct dependence {
	struct tree_entry entry;
	char *fingerprint;
	size_t fingerprint_l;
	bool comp;
	char path_name[FLEXIBLE_ARRAY];
};

static struct tree dependencies;
static uchar_efficient_t dependencies_failed;
static mutex_t dependencies_mutex;


static int function_compare(const struct module_designator *md1, const struct function_designator *fd1, struct function_descriptor *fd2);
static int cache_compare(const struct module_designator *md1, const struct function_designator *fd1, struct cache_descriptor *fd2);
static void save_one_cache_entry(arg_t n_arguments, arg_t n_return_values, pointer_t *arguments, pointer_t *returns);
static void save_function_descriptor(
	const struct module_designator *md,
	const struct function_designator *fd,
	code_t *code,
	ip_t code_size,
	const struct local_variable_flags *local_variables_flags,
	frame_t n_slots,
	struct data *types,
	uint8_t *real_data,
	size_t real_size,
	struct line_position *lp,
	size_t lp_size,
	void *unoptimized_code_base,
	size_t unoptimized_code_entry_offset,
	size_t unoptimized_code_size,
	size_t *entries,
	size_t n_entries,
	struct trap_record *trap_records,
	size_t trap_records_size);
static void save_cache_descriptor(
	const struct module_designator *md,
	const struct function_designator *fd,
	arg_t n_arguments,
	arg_t n_return_values);
static bool dep_get_stream(char **result, size_t *result_l);


static bool align_output(size_t align)
{
	ajla_error_t sink;
	while (unlikely(save_len & (align - 1)) != 0) {
		if (unlikely(!array_add_mayfail(char, &save_data, &save_len, 0, NULL, &sink))) {
			save_ok = false;
			return false;
		}
	}
	return true;
}

static pointer_t offset_to_ptr(size_t offset)
{
	tag_t tag = da_thunk_tag(save_data + offset);
	if (unlikely(!tag_is_thunk(tag))) {
		return pointer_data(data_pointer_tag(num_to_ptr(offset), tag));
	} else {
		return pointer_thunk(thunk_pointer_tag(num_to_ptr(offset)));
	}
}

static int position_tree_compare(const struct tree_entry *t1, uintptr_t p2)
{
	struct position_map *pm = get_struct(t1, struct position_map, entry);
	if (pm->old_position + pm->size <= p2)
		return -1;
	if (pm->old_position > p2)
		return 1;
	return 0;
}

static void free_position_tree(struct tree *t)
{
	while (!tree_is_empty(t)) {
		struct position_map *pm = get_struct(tree_any(t), struct position_map, entry);
		tree_delete(&pm->entry);
		mem_free(pm);
	}
}

static size_t save_range(const void *ptr, size_t align, size_t size, struct stack_entry *subptrs, size_t subptrs_l, size_t *doff)
{
	ajla_error_t sink;
	size_t data_offset, payload_offset, i;
	struct data *d;
	if (unlikely(!align_output(SAVED_DATA_ALIGN)))
		return (size_t)-1;
	data_offset = save_len;
	if (doff)
		*doff = data_offset;
	d = data_alloc_flexible(saved, offsets, subptrs_l, &sink);
	if (unlikely(!d)) {
		save_ok = false;
		return (size_t)-1;
	}
	refcount_set_read_only(&d->refcount_);
	da(d,saved)->n_offsets = subptrs_l;

	if (unlikely(!array_add_multiple_mayfail(char, &save_data, &save_len, d, offsetof(struct data, u_.saved.offsets[subptrs_l]), NULL, &sink))) {
		save_ok = false;
		data_free(d);
		return (size_t)-1;
	}
	data_free(d);

	if (unlikely(!align_output(align)))
		return (size_t)-1;
	payload_offset = save_len;

	if (size && unlikely(!array_add_multiple_mayfail(char, &save_data, &save_len, ptr, size, NULL, &sink))) {
		save_ok = false;
		return (size_t)-1;
	}

	d = cast_ptr(struct data *, save_data + data_offset);
	d = data_pointer_tag(d, DATA_TAG_saved);
	da(d,saved)->total_size = save_len - data_offset;
	for (i = 0; i < subptrs_l; i++) {
		da(d,saved)->offsets[i] = payload_offset - data_offset + (cast_ptr(const char *, subptrs[i].ptr) - cast_ptr(const char *, ptr));
		/*debug("offsets: %zx - %zx (%zx %zx %p %p)", i, da(d,saved)->offsets[i], payload_offset, data_offset, subptrs[i].ptr, ptr);*/
	}

	return payload_offset;
}

struct subptr_state {
	uint64_t offset;
	bool need_duplicate;
	struct position_map *pm;
};

static size_t save_pointer(pointer_t *xptr, bool verify_only)
{
	ajla_error_t sink;
	struct stack_entry *subptrs;
	size_t subptrs_len;
	struct stack_entry *stk;
	size_t stk_l;
	struct subptr_state *sps;
	size_t ret = (size_t)-1;		/* avoid warning */

	struct tree processed;
	tree_init(&processed);

	if (unlikely(!data_save_init_stack(xptr, &stk, &stk_l))) {
		save_ok = false;
		goto err;
	}

cont:
	do {
		size_t align, size, i, data_pos, doff;
		bool need_duplicate;
		struct stack_entry ste;
		const char *p1;
		uintptr_t p1_num;
		struct tree_entry *e;
		struct tree_insert_position ins;
		bool need_sub;
		struct position_map *pm;

		ste = stk[stk_l - 1];
		p1 = ste.t->get_ptr(&ste);
		p1_num = ptr_to_num(p1);
		e = tree_find_for_insert(&position_tree, position_tree_compare, p1_num, &ins);

		if (verify_only && !e) {
			e = tree_find_for_insert(&processed, position_tree_compare, p1_num, &ins);
		}
		if (e) {
			pm = get_struct(e, struct position_map, entry);
			ret = p1_num - pm->old_position + pm->new_position;
			goto pop_stk;
		}

		if (unlikely(!ste.t->get_properties(&ste, &align, &size, &subptrs, &subptrs_len, &need_duplicate)))
			goto err;

		ajla_assert_lo(size != 0, (file_line, "save_pointer: size == 0"));

		sps = mem_alloc_array_mayfail(mem_calloc_mayfail, struct subptr_state *, 0, 0, subptrs_len, sizeof(struct subptr_state), &sink);
		if (unlikely(!sps)) {
			save_ok = false;
			goto err_free_subptrs;
		}

		need_sub = false;
		for (i = 0; i < subptrs_len; i++) {
			struct stack_entry *subptr;
			const char *p2;
			uintptr_t p2_num;
			struct tree_entry *e2;

			subptr = &subptrs[i];
			if (!subptr->t->get_ptr) {
				sps[i] = sps[i - 1];
				continue;
			}
			p2 = subptr->t->get_ptr(subptr);
			p2_num = ptr_to_num(p2);
			e2 = tree_find(&position_tree, position_tree_compare, p2_num);
			if (verify_only && !e2) {
				e2 = tree_find(&processed, position_tree_compare, p2_num);
			}
			if (!e2) {
				if (unlikely(!array_add_mayfail(struct stack_entry, &stk, &stk_l, *subptr, NULL, &sink))) {
					save_ok = false;
					goto err_free_sps;
				}
				need_sub = true;
			} else {
				struct position_map *subpm = get_struct(e2, struct position_map, entry);
				sps[i].offset = subpm->new_position - subpm->old_position;
				sps[i].need_duplicate = subpm->need_duplicate;
				sps[i].pm = subpm;
			}
		}
		if (need_sub) {
			if (subptrs)
				mem_free(subptrs);
			mem_free(sps);
			goto cont;
		}

		if (!verify_only) {
			if (!ste.t->wrap_on_save) {
				if (unlikely(!align_output(align)))
					goto err_free_sps;
				data_pos = save_len;
				doff = save_len;
				if (unlikely(!array_add_multiple_mayfail(char, &save_data, &save_len, p1, size, NULL, &sink))) {
					save_ok = false;
					goto err_free_sps;
				}
			} else {
				data_pos = save_range(p1, align, size, subptrs, subptrs_len, &doff);
				if (unlikely(data_pos == (size_t)-1)) {
					goto err_free_sps;
				}
			}
			ste.t->fixup_after_copy(save_data + data_pos);

			for (i = 0; i < subptrs_len; i++) {
				size_t offset = cast_ptr(char *, subptrs[i].ptr) - p1;
				if (subptrs[i].t->duplicate_parents && subptrs[i].t->duplicate_parents(save_data + data_pos + offset))
					need_duplicate = true;
			}

			for (i = 0; i < subptrs_len; i++) {
				size_t offset = cast_ptr(char *, subptrs[i].ptr) - p1;
				subptrs[i].t->fixup_sub_ptr(save_data + data_pos + offset, sps[i].offset);
				if (sps[i].need_duplicate) {
					struct duplicate_record dr;
					dr.old_position = p1_num;
					dr.fp_ptr = data_pos + offset;
					dr.subpm = sps[i].pm;
					if (unlikely(!array_add_mayfail(struct duplicate_record, &duplicate_records, &duplicate_records_len, dr, NULL, &sink))) {
						save_ok = false;
						goto err_free_sps;
					}
				}
			}
		} else {
			data_pos = 0;
		}
		if (subptrs)
			mem_free(subptrs);
		mem_free(sps);

		pm = mem_alloc_mayfail(struct position_map *, sizeof(struct position_map), &sink);
		if (unlikely(!pm)) {
			save_ok = false;
			goto err;
		}
		pm->old_position = p1_num;
		pm->new_position = data_pos;
		pm->new_wrap_position = doff;
		pm->size = size;
		pm->is_function_pointer = ste.t->is_function_pointer;
		pm->need_duplicate = need_duplicate;
		tree_insert_after_find(&pm->entry, &ins);
		ret = data_pos;

pop_stk:;
	} while (--stk_l);

	mem_free(stk);
	free_position_tree(&processed);
	return ret;

err_free_sps:
	mem_free(sps);
err_free_subptrs:
	if (subptrs)
		mem_free(subptrs);
err:
	if (stk)
		mem_free(stk);
	free_position_tree(&processed);
	return (size_t)-1;
}

static void save_prepare(void)
{
	ajla_error_t sink;
	save_data = NULL;
	save_ok = !save_disable && !dependencies_failed;
	last_md = (size_t)-1;
	tree_init(&position_tree);
	pointers = NULL;
	pointers_len = 0;
	function_pointers = NULL;
	loaded_cache_idx = 0;
	loaded_fn_idx = 0;
	loaded_fn_cache = (size_t)-1;
	if (unlikely(!array_init_mayfail(char, &save_data, &save_len, &sink))) {
		save_ok = false;
		return;
	}
	if (unlikely(!array_init_mayfail(struct function_descriptor, &fn_descs, &fn_descs_len, &sink))) {
		save_ok = false;
		return;
	}
	if (unlikely(!array_init_mayfail(struct cache_descriptor, &cache_descs, &cache_descs_len, &sink))) {
		save_ok = false;
		return;
	}
	if (unlikely(!array_init_mayfail(struct duplicate_record, &duplicate_records, &duplicate_records_len, &sink))) {
		save_ok = false;
		return;
	}
}

static int compare_arguments(arg_t n_arguments, pointer_t *ptr1, pointer_t *ptr2)
{
	ajla_error_t sink;
	arg_t ai;
	for (ai = 0; ai < n_arguments; ai++) {
		int c = data_compare(ptr1[ai], ptr2[ai], &sink);
		if (c)
			return c;
	}
	return 0;
}

static void save_cache_entries_until(pointer_t *arguments)
{
	struct cache_descriptor *cache_desc;
	struct data *dsc;
	if (unlikely(!save_ok))
		return;
	if (loaded_fn_cache == (size_t)-1)
		return;
	cache_desc = &loaded_file_descriptor(compsave)->cache_descs[loaded_cache_idx];
	dsc = cache_desc->data_saved_cache;
	while (loaded_fn_cache < da(dsc,saved_cache)->n_entries) {
		pointer_t *dsc_arguments = da(dsc,saved_cache)->pointers + loaded_fn_cache * ((size_t)da(dsc,saved_cache)->n_arguments + (size_t)da(dsc,saved_cache)->n_return_values);
		if (arguments) {
			int c = compare_arguments(da(dsc,saved_cache)->n_arguments, arguments, dsc_arguments);
			if (unlikely(c == DATA_COMPARE_OOM)) {
				save_ok = false;
				return;
			}
			if (unlikely(!c))
				internal(file_line, "save_cache_entries_until: data already present in loaded cache");
			if (c < 0)
				return;
		}
		save_one_cache_entry(da(dsc,saved_cache)->n_arguments, da(dsc,saved_cache)->n_return_values, dsc_arguments, dsc_arguments + da(dsc,saved_cache)->n_arguments);
		if (!save_ok)
			return;
		loaded_fn_cache++;
	}
}

static void save_loaded_function(struct function_descriptor *fn_desc)
{
	save_function_descriptor(fn_desc->md,
				fn_desc->fd,
				fn_desc->code,
				fn_desc->code_size,
				fn_desc->local_variables_flags,
				fn_desc->n_slots,
				fn_desc->types,
				fn_desc->real_data,
				fn_desc->real_size,
				fn_desc->lp,
				fn_desc->lp_size,
				fn_desc->unoptimized_code_base,
				fn_desc->unoptimized_code_entry_offset,
				fn_desc->unoptimized_code_size,
				fn_desc->entries,
				fn_desc->n_entries,
				fn_desc->trap_records,
				fn_desc->trap_records_size);
}

static void save_functions_until(struct data *d)
{
	if (unlikely(!save_ok))
		return;
	if (!ld[compsave].loaded_data)
		return;
	/*debug("save_functions_until: %lu, %lu", loaded_fn_idx, loaded_file_descriptor->function_descs_len);*/
	while (loaded_fn_idx < loaded_file_descriptor(compsave)->fn_descs_len) {
		struct function_descriptor *function_desc = &loaded_file_descriptor(compsave)->fn_descs[loaded_fn_idx];
		/*debug("test loaded: %lu", loaded_fn_idx);*/
		if (d) {
			int c = function_compare(da(d,function)->module_designator, da(d,function)->function_designator, function_desc);
			if (c <= 0 && c != DATA_COMPARE_OOM) {
				if (!c)
					loaded_fn_idx++;
				return;
			}
		}
		save_loaded_function(function_desc);
		if (!save_ok)
			return;
		loaded_fn_idx++;
	}
}

static void save_loaded_cache(struct cache_descriptor *cache_desc)
{
	struct data *dsc;
	ajla_error_t sink;
	size_t i, k;
	if (unlikely(!array_init_mayfail(pointer_t, &pointers, &pointers_len, &sink))) {
		save_ok = false;
		return;
	}
	dsc = cache_desc->data_saved_cache;
	k = (size_t)da(dsc,saved_cache)->n_arguments + (size_t)da(dsc,saved_cache)->n_return_values;
	for (i = 0; i < da(dsc,saved_cache)->n_entries; i++) {
		pointer_t *base = da(dsc,saved_cache)->pointers + k * i;
		save_one_cache_entry(da(dsc,saved_cache)->n_arguments, da(dsc,saved_cache)->n_return_values, base, base + da(dsc,saved_cache)->n_arguments);
		if (unlikely(!save_ok))
			return;
	}
	save_cache_descriptor(cache_desc->md,
				cache_desc->fd,
				da(dsc,saved_cache)->n_arguments,
				da(dsc,saved_cache)->n_return_values);
}

static void save_caches_until(struct data *d)
{
	loaded_fn_cache = (size_t)-1;
	if (unlikely(!save_ok))
		return;
	if (!ld[compsave].loaded_data)
		return;
	/*debug("save_caches_until: %lu, %lu", loaded_cache_idx, loaded_file_descriptor->cache_descs_len);*/
	while (loaded_cache_idx < loaded_file_descriptor(compsave)->cache_descs_len) {
		struct cache_descriptor *cache_desc = &loaded_file_descriptor(compsave)->cache_descs[loaded_cache_idx];
		/*debug("test loaded: %lu", loaded_cache_idx);*/
		if (d) {
			int c = cache_compare(da(d,function)->module_designator, da(d,function)->function_designator, cache_desc);
			if (c <= 0 && c != DATA_COMPARE_OOM) {
				if (!c) {
					loaded_fn_cache = 0;
				}
				return;
			}
		}
		save_loaded_cache(cache_desc);
		if (!save_ok)
			return;
		loaded_cache_idx++;
	}
}

static void save_one_cache_entry(arg_t n_arguments, arg_t n_return_values, pointer_t *arguments, pointer_t *returns)
{
	ajla_error_t sink;
	arg_t i;
	for (i = 0; i < n_arguments; i++) {
		pointer_t ptr;
		size_t st = save_pointer(&arguments[i], false);
		if (unlikely(st == (size_t)-1)) {
			save_ok = false;
			return;
		}
		ptr = offset_to_ptr(st);
		if (unlikely(!array_add_mayfail(pointer_t, &pointers, &pointers_len, ptr, NULL, &sink))) {
			save_ok = false;
			return;
		}
	}
	for (i = 0; i < n_return_values; i++) {
		pointer_t ptr;
		size_t st = save_pointer(&returns[i], false);
		if (unlikely(st == (size_t)-1)) {
			save_ok = false;
			return;
		}
		ptr = offset_to_ptr(st);
		if (unlikely(!array_add_mayfail(pointer_t, &pointers, &pointers_len, ptr, NULL, &sink))) {
			save_ok = false;
			return;
		}
	}
}

void save_start_cache(struct data *d, bool new_cache)
{
	ajla_error_t sink;
	if (!da(d,function)->n_return_values || !new_cache)
		return;
	/*const struct module_designator *md = da(d,function)->module_designator;
	const struct function_designator *fd = da(d,function)->function_designator;
	debug("save_start_function: %u:%.*s:%u (%lu) - %s", md->path_idx, (int)md->path_len, md->path, fd->entries[0], fd->n_entries, da(d,function)->function_name);*/
	/*debug("saving: %zu, %s", save_len, da(d,function)->function_name);*/
	save_caches_until(d);
	if (unlikely(!save_ok))
		return;
	if (unlikely(!array_init_mayfail(pointer_t, &pointers, &pointers_len, &sink))) {
		save_ok = false;
		return;
	}
}

void save_cache_entry(struct data *d, struct cache_entry *ce)
{
	arg_t i;
	pointer_t *returns;
	ajla_error_t sink;

	ajla_assert_lo(!ce->n_pending, (file_line, "save_cache_entry: evaluation is in progress: %lu", (unsigned long)ce->n_pending));
	if (unlikely(!save_ok))
		return;

	/*debug("save cache entry: %s (%d)", da(d,function)->function_name, compsave);*/
	for (i = 0; i < da(d,function)->n_arguments; i++) {
		if (unlikely(save_pointer(&ce->arguments[i], true) == (size_t)-1)) {
			/*debug("failed arg %d", i);*/
			return;
		}
	}
	for (i = 0; i < da(d,function)->n_return_values; i++) {
		if (unlikely(save_pointer(&ce->returns[i].ptr, true) == (size_t)-1)) {
			/*debug("failed return %d", i);*/
			return;
		}
	}
	save_cache_entries_until(ce->arguments);
	if (!save_ok)
		return;
	returns = mem_alloc_array_mayfail(mem_alloc_mayfail, pointer_t *, 0, 0, da(d,function)->n_return_values, sizeof(pointer_t), &sink);
	if (unlikely(!returns)) {
		save_ok = false;
		return;
	}
	for (i = 0; i < da(d,function)->n_return_values; i++) {
		returns[i] = ce->returns[i].ptr;
	}
	save_one_cache_entry(da(d,function)->n_arguments, da(d,function)->n_return_values, ce->arguments, returns);
	mem_free(returns);
}

void save_finish_cache(struct data *d)
{
	if (loaded_fn_cache != (size_t)-1) {
		save_cache_entries_until(NULL);
		if (unlikely(!save_ok))
			return;
		loaded_cache_idx++;
		loaded_fn_cache = (size_t)-1;
	}
	save_cache_descriptor(da(d,function)->module_designator,
				da(d,function)->function_designator,
				da(d,function)->n_arguments,
				da(d,function)->n_return_values);
}

static void save_function_descriptor(
	const struct module_designator *md,
	const struct function_designator *fd,
	code_t *code,
	ip_t code_size,
	const struct local_variable_flags *local_variables_flags,
	frame_t n_slots,
	struct data *types,
	uint8_t *real_data,
	size_t real_size,
	struct line_position *lp,
	size_t lp_size,
	void *unoptimized_code_base,
	size_t unoptimized_code_entry_offset,
	size_t unoptimized_code_size,
	size_t *entries,
	size_t n_entries,
	struct trap_record *trap_records,
	size_t trap_records_size)
{
	ajla_error_t sink;
	struct function_descriptor fn_desc;
	size_t code_off, lvf_off, real_data_off, lp_off, uc_off, en_off, tr_off;
	size_t last_fd;
	pointer_t types_ptr = pointer_data(types);
	size_t saved_types;
	/*debug("save_function_descriptor: %u:%.*s:%u (%lu)", md->path_idx, (int)md->path_len, md->path, fd->entries[0], fd->n_entries);*/
	if (unlikely(!align_output(SAVED_DATA_ALIGN)))
		return;

	code_off = save_range(code, align_of(code_t), (size_t)code_size * sizeof(code_t), NULL, 0, NULL);
	if (unlikely(code_off == (size_t)-1))
		return;

	lvf_off = save_range(local_variables_flags, align_of(struct local_variable_flags), (size_t)n_slots * sizeof(struct local_variable_flags), NULL, 0, NULL);
	if (unlikely(lvf_off == (size_t)-1))
		return;

	saved_types = save_pointer(&types_ptr, false);
	if (unlikely(saved_types == (size_t)-1)) {
		save_ok = false;
		return;
	}

	real_data_off = save_range(real_data, CODE_ALIGNMENT, real_size, NULL, 0, NULL);
	if (unlikely(code_off == (size_t)-1))
		return;

	lp_off = save_range(lp, align_of(struct line_position), (size_t)lp_size * sizeof(struct line_position), NULL, 0, NULL);
	if (unlikely(lp_off == (size_t)-1))
		return;

	uc_off = save_range(unoptimized_code_base, CODE_ALIGNMENT, unoptimized_code_size, NULL, 0, NULL);
	if (unlikely(uc_off == (size_t)-1))
		return;

	en_off = save_range(entries, align_of(size_t), n_entries * sizeof(size_t), NULL, 0, NULL);
	if (unlikely(en_off == (size_t)-1))
		return;

#ifdef HAVE_CODEGEN_TRAPS
	tr_off = save_range(trap_records, align_of(struct trap_record), trap_records_size * sizeof(struct trap_record), NULL, 0, NULL);
#else
	tr_off = save_range(trap_records, 1, 0, NULL, 0, NULL);
#endif
	if (unlikely(tr_off == (size_t)-1))
		return;

	if (!(last_md != (size_t)-1 && !module_designator_compare(cast_ptr(struct module_designator *, save_data + last_md), md))) {
		last_md = save_range(md, align_of(struct module_designator), module_designator_length(md), NULL, 0, NULL);
		if (unlikely(last_md == (size_t)-1))
			return;
	}

	last_fd = save_range(fd, align_of(struct function_designator), function_designator_length(fd), NULL, 0, NULL);
	if (unlikely(last_fd == (size_t)-1))
		return;

	fn_desc.code = num_to_ptr(code_off);
	fn_desc.code_size = code_size;
	fn_desc.local_variables_flags = num_to_ptr(lvf_off);
	fn_desc.n_slots = n_slots;
	fn_desc.types = num_to_ptr(saved_types);
	fn_desc.types = data_pointer_tag(fn_desc.types, DATA_TAG_function_types);
	fn_desc.real_data = num_to_ptr(real_data_off);
	fn_desc.real_size = real_size;
	fn_desc.lp = num_to_ptr(lp_off);
	fn_desc.lp_size = lp_size;
	fn_desc.unoptimized_code_base = num_to_ptr(uc_off);
	fn_desc.unoptimized_code_entry_offset = unoptimized_code_entry_offset;
	fn_desc.unoptimized_code_size = unoptimized_code_size;
	fn_desc.entries = num_to_ptr(en_off);
	fn_desc.n_entries = n_entries;
	fn_desc.trap_records = num_to_ptr(tr_off);
	fn_desc.trap_records_size = trap_records_size;
	fn_desc.md = num_to_ptr(last_md);
	fn_desc.fd = num_to_ptr(last_fd);
	if (!unlikely(array_add_mayfail(struct function_descriptor, &fn_descs, &fn_descs_len, fn_desc, NULL, &sink))) {
		save_ok = false;
		return;
	}
}

static void save_cache_descriptor(
	const struct module_designator *md,
	const struct function_designator *fd,
	arg_t n_arguments,
	arg_t n_return_values)
{
	ajla_error_t sink;
	size_t saved_pos;
	struct cache_descriptor cache_desc;
	struct data *dsc;
	size_t last_fd;

	if (!n_return_values)
		goto free_it;
	if (!pointers_len)
		goto free_it;

	dsc = data_alloc_flexible(saved_cache, pointers, pointers_len, &sink);
	if (unlikely(!dsc)) {
		save_ok = false;
		goto free_it;
	}
	refcount_set_read_only(&dsc->refcount_);
	da(dsc,saved_cache)->n_entries = pointers_len / ((size_t)n_arguments + (size_t)n_return_values);
	da(dsc,saved_cache)->n_arguments = n_arguments;
	da(dsc,saved_cache)->n_return_values = n_return_values;
	memcpy(da(dsc,saved_cache)->pointers, pointers, pointers_len * sizeof(pointer_t));

	if (unlikely(!align_output(SAVED_DATA_ALIGN)))
		goto free_it_2;

	saved_pos = save_len;
	if (unlikely(!array_add_multiple_mayfail(char, &save_data, &save_len, dsc, offsetof(struct data, u_.saved_cache.pointers[pointers_len]), NULL, &sink))) {
		save_ok = false;
		goto free_it_2;
	}

	if (!(last_md != (size_t)-1 && !module_designator_compare(cast_ptr(struct module_designator *, save_data + last_md), md))) {
		last_md = save_range(md, align_of(struct module_designator), module_designator_length(md), NULL, 0, NULL);
		if (unlikely(last_md == (size_t)-1))
			goto free_it_2;
	}

	last_fd = save_range(fd, align_of(struct function_designator), function_designator_length(fd), NULL, 0, NULL);
	if (unlikely(last_fd == (size_t)-1))
		goto free_it_2;

	cache_desc.data_saved_cache = num_to_ptr(saved_pos);
	cache_desc.data_saved_cache = data_pointer_tag(cache_desc.data_saved_cache, DATA_TAG_saved_cache);
	cache_desc.md = num_to_ptr(last_md);
	cache_desc.fd = num_to_ptr(last_fd);
	if (!unlikely(array_add_mayfail(struct cache_descriptor, &cache_descs, &cache_descs_len, cache_desc, NULL, &sink))) {
		save_ok = false;
		goto free_it_2;
	}

free_it_2:
	data_free(dsc);
free_it:
	if (pointers)
		mem_free(pointers);
	pointers = NULL;
	pointers_len = 0;
}

void save_function(struct data *d, bool new_cache)
{
	void *unoptimized_code_base = NULL;
	size_t unoptimized_code_entry_offset = 0;
	size_t unoptimized_code_size = 0;
	size_t *entries = NULL;
	size_t n_entries = 0;
	struct trap_record *trap_records = NULL;
	size_t trap_records_size = 0;
	if (!da(d,function)->n_return_values || !new_cache)
		return;
	save_functions_until(d);
#ifdef HAVE_CODEGEN
	if (!pointer_is_thunk(da(d,function)->codegen)) {
		ajla_error_t sink;
		size_t i;
		struct data *codegen;
		codegen = pointer_get_data(da(d,function)->codegen);
		entries = da(codegen,codegen)->offsets = mem_alloc_array_mayfail(mem_alloc_mayfail, size_t *, 0, 0, da(codegen,codegen)->n_entries, sizeof(size_t), &sink);
		if (unlikely(!entries)) {
			save_ok = false;
			return;
		}
		n_entries = da(codegen,codegen)->n_entries;
		for (i = 0; i < n_entries; i++)
			entries[i] = da(codegen,codegen)->unoptimized_code[i] - cast_ptr(char *, da(codegen,codegen)->unoptimized_code_base);
		unoptimized_code_base = da(codegen,codegen)->unoptimized_code_base;
		unoptimized_code_entry_offset = cast_ptr(char *, da(codegen,codegen)->unoptimized_code_entry) - cast_ptr(char *, da(codegen,codegen)->unoptimized_code_base);
		unoptimized_code_size = da(codegen,codegen)->unoptimized_code_size;
#ifdef HAVE_CODEGEN_TRAPS
		trap_records = da(codegen,codegen)->trap_records;
		trap_records_size = da(codegen,codegen)->trap_records_size;
#endif
	}
#endif
	save_function_descriptor(da(d,function)->module_designator,
				da(d,function)->function_designator,
				da(d,function)->code, da(d,function)->code_size,
				da(d,function)->local_variables_flags,
				function_n_variables(d),
				pointer_get_data(da(d,function)->types_ptr),
				cast_ptr(uint8_t *, d) + function_real_pool_offset(d),
				da(d,function)->real_size,
				da(d,function)->lp,
				da(d,function)->lp_size,
				unoptimized_code_base,
				unoptimized_code_entry_offset,
				unoptimized_code_size,
				entries,
				n_entries,
				trap_records,
				trap_records_size);

	if (entries) {
		struct data *codegen = pointer_get_data(da(d,function)->codegen);
		da(codegen,codegen)->offsets = NULL;
		mem_free(entries);
	}
}

static void duplicate_writeable_entries(void)
{
	ajla_error_t sink;
	struct tree_entry *e;
	struct position_map *pm, *pm2;
	size_t i, j;
	struct stack_entry *subptrs;
	size_t align, size, subptrs_l;
	bool duplicate;

	if (unlikely(!align_output(os_getpagesize())))
		return;

	writable_boundary = save_len;

	function_pointers_len = 0;
	for (e = tree_first(&position_tree); e; e = tree_next(e)) {
		pm = get_struct(e, struct position_map, entry);
		if (pm->need_duplicate) {
			char *cpy;
			if (unlikely(!data_save(save_data + pm->new_wrap_position, ptr_to_num(save_data), &align, &size, &subptrs, &subptrs_l, &duplicate)))
				return;
			if (subptrs)
				mem_free(subptrs);
			pm->duplicate_size = size;
			if (unlikely(!align_output(align)))
				return;
			pm->duplicate_position = save_len;
			cpy = mem_alloc_mayfail(char *, size, &sink);
			if (unlikely(!cpy)) {
				save_ok = false;
				return;
			}
			memcpy(cpy, save_data + pm->new_wrap_position, size);
			if (unlikely(!array_add_multiple_mayfail(char, &save_data, &save_len, cpy, size, NULL, &sink))) {
				mem_free(cpy);
				save_ok = false;
				return;
			}
			mem_free(cpy);
		}
		function_pointers_len += pm->is_function_pointer;
	}

	for (i = 0; i < duplicate_records_len; i++) {
		struct duplicate_record *dr = &duplicate_records[i];
		size_t old_position = dr->old_position;
		e = tree_find(&position_tree, position_tree_compare, old_position);
		if (!e)
			internal(file_line, "duplicate_writeable_entries: entry not found in position tree");
		pm = get_struct(e, struct position_map, entry);
		if (unlikely(!data_save(save_data + pm->new_wrap_position, ptr_to_num(save_data), &align, &size, &subptrs, &subptrs_l, &duplicate))) {
			return;
		}
		for (j = 0; j < subptrs_l; j++) {
			size_t offset = cast_ptr(char *, subptrs[j].ptr) - save_data;
			if (offset == dr->fp_ptr)
				goto found;
		}
		internal(file_line, "duplicate_writeable_entries: modification offset not found");
found:
		pm2 = dr->subpm;
		subptrs[j].t->fixup_sub_ptr(save_data + dr->fp_ptr, pm2->duplicate_position - pm2->new_wrap_position);
		mem_free(subptrs);
	}

	function_pointers = mem_alloc_array_mayfail(mem_alloc_mayfail, size_t *, 0, 0, function_pointers_len, sizeof(size_t), &sink);
	if (unlikely(!function_pointers)) {
		save_ok = false;
		return;
	}

	i = 0;
	for (e = tree_first(&position_tree); e; e = tree_next(e)) {
		struct position_map *pm = get_struct(e, struct position_map, entry);
		if (pm->need_duplicate) {
			memcpy(save_data + pm->duplicate_position, save_data + pm->new_wrap_position, pm->duplicate_size);
			if (unlikely(!data_save(save_data + pm->duplicate_position, ptr_to_num(save_data), &align, &size, &subptrs, &subptrs_l, &duplicate)))
				return;
			mem_free(subptrs);
		}
		if (pm->is_function_pointer) {
			function_pointers[i] = pm->duplicate_position + (pm->new_position - pm->new_wrap_position);
			i++;
		}
	}
}

static void save_finish_file(void)
{
	const int fn_desc_ptrs = 10;
	const int cache_desc_ptrs = 3;
	ajla_error_t sink;
	struct stack_entry *subptrs;
	char *deps;
	size_t i, deps_l;
	size_t fn_descs_offset, cache_descs_offset, deps_offset, fpptrs_offset, file_desc_offset;
	struct file_descriptor file_desc;

	if (!fn_descs_len && !cache_descs_len) {
		save_ok = false;
		return;
	}

	save_functions_until(NULL);
	save_caches_until(NULL);

	duplicate_writeable_entries();
	if (unlikely(!save_ok))
		return;

	subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, fn_descs_len, sizeof(struct stack_entry) * fn_desc_ptrs, &sink);
	if (unlikely(!subptrs)) {
		save_ok = false;
		return;
	}
	for (i = 0; i < fn_descs_len; i++) {
		subptrs[i * fn_desc_ptrs + 0].ptr = &fn_descs[i].code;
		subptrs[i * fn_desc_ptrs + 1].ptr = &fn_descs[i].local_variables_flags;
		subptrs[i * fn_desc_ptrs + 2].ptr = &fn_descs[i].types;
		subptrs[i * fn_desc_ptrs + 3].ptr = &fn_descs[i].real_data;
		subptrs[i * fn_desc_ptrs + 4].ptr = &fn_descs[i].lp;
		subptrs[i * fn_desc_ptrs + 5].ptr = &fn_descs[i].md;
		subptrs[i * fn_desc_ptrs + 6].ptr = &fn_descs[i].fd;
		subptrs[i * fn_desc_ptrs + 7].ptr = &fn_descs[i].unoptimized_code_base;
		subptrs[i * fn_desc_ptrs + 8].ptr = &fn_descs[i].entries;
		subptrs[i * fn_desc_ptrs + 9].ptr = &fn_descs[i].trap_records;
		/*debug("%p %p %zx", fn_descs[i].data_saved_cache, fn_descs[i].md, fn_descs[i].idx);*/
	}
	fn_descs_offset = save_range(fn_descs, align_of(struct function_descriptor), fn_descs_len * sizeof(struct function_descriptor), subptrs, fn_descs_len * fn_desc_ptrs, NULL);
	mem_free(subptrs);
	if (unlikely(fn_descs_offset == (size_t)-1))
		return;

	file_desc.fn_descs = num_to_ptr(fn_descs_offset);
	file_desc.fn_descs_len = fn_descs_len;

	subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, cache_descs_len, sizeof(struct stack_entry) * cache_desc_ptrs, &sink);
	if (unlikely(!subptrs)) {
		save_ok = false;
		return;
	}
	for (i = 0; i < cache_descs_len; i++) {
		/*debug("saving: %p, %p, %p", cache_descs[i].data_saved_cache, cache_descs[i].md, cache_descs[i].fd);*/
		subptrs[i * cache_desc_ptrs + 0].ptr = &cache_descs[i].data_saved_cache;
		subptrs[i * cache_desc_ptrs + 1].ptr = &cache_descs[i].md;
		subptrs[i * cache_desc_ptrs + 2].ptr = &cache_descs[i].fd;
	}
	cache_descs_offset = save_range(cache_descs, align_of(struct cache_descriptor), cache_descs_len * sizeof(struct cache_descriptor), subptrs, cache_descs_len * cache_desc_ptrs, NULL);
	mem_free(subptrs);
	if (unlikely(cache_descs_offset == (size_t)-1))
		return;

	file_desc.cache_descs = num_to_ptr(cache_descs_offset);
	file_desc.cache_descs_len = cache_descs_len;

	if (unlikely(!dep_get_stream(&deps, &deps_l))) {
		save_ok = false;
		return;
	}
	deps_offset = save_range(deps, 1, deps_l, NULL, 0, NULL);
	mem_free(deps);
	if (unlikely(deps_offset == (size_t)-1))
		return;

	fpptrs_offset = save_range(function_pointers, align_of(uintptr_t), function_pointers_len * sizeof(uintptr_t), NULL, 0, NULL);
	if (unlikely(fn_descs_offset == (size_t)-1))
		return;

	file_desc.dependencies = num_to_ptr(deps_offset);
	file_desc.dependencies_l = deps_l;
	file_desc.writable_boundary = writable_boundary;
	file_desc.function_pointers = num_to_ptr(fpptrs_offset);
	file_desc.function_pointers_len = function_pointers_len;
	file_desc.base = num_to_ptr(0);
	file_desc.page_size = os_getpagesize();
	file_desc.cpu_feature_flags = cpu_feature_flags;
	file_desc.optimize_int = optimize_int;
	file_desc.privileged = ipret_is_privileged;
	file_desc.profiling = profiling;
	file_desc.strict_calls = ipret_strict_calls;
	file_desc.verifying = verify != NULL;
	file_desc.noinline = ipret_noinline;
	file_desc.noautofma = noautofma;
	file_desc.chicken = chicken;
	memcpy(file_desc.ajla_id, id, sizeof(id));

	subptrs = mem_alloc_mayfail(struct stack_entry *, sizeof(struct stack_entry) * 5, &sink);
	if (unlikely(!subptrs)) {
		save_ok = false;
		return;
	}
	subptrs[0].ptr = &file_desc.fn_descs;
	subptrs[1].ptr = &file_desc.cache_descs;
	subptrs[2].ptr = &file_desc.dependencies;
	subptrs[3].ptr = &file_desc.function_pointers;
	subptrs[4].ptr = &file_desc.base;
	file_desc_offset = save_range(&file_desc, align_of(struct file_descriptor), sizeof(struct file_descriptor), subptrs, 5, NULL);
	mem_free(subptrs);
	if (unlikely(file_desc_offset == (size_t)-1))
		return;
}

static bool adjust_pointers(char *data, size_t len, uintptr_t offset)
{
	size_t pos = 0;
	while (pos < len) {
		refcount_t *ref;
		struct stack_entry *subptrs;
		size_t align, size, subptrs_l, i;
		bool duplicate;
		if (unlikely((pos & (SAVED_DATA_ALIGN - 1)) != 0)) {
			pos++;
			continue;
		}
		ref = cast_ptr(refcount_t *, data + pos + offsetof(struct data, refcount_));
		if (refcount_is_one(ref)) {
			pos += SAVED_DATA_ALIGN;
			continue;
		}
		if (unlikely(!refcount_is_read_only(ref)))
			internal(file_line, "adjust_pointers: invalid refcount at position %"PRIxMAX"", (uintmax_t)pos);
		if (unlikely(!data_save(data + pos, offset, &align, &size, &subptrs, &subptrs_l, &duplicate)))
			return false;
		for (i = 0; i < subptrs_l; i++) {
			subptrs[i].t->fixup_sub_ptr(subptrs[i].ptr, offset);
		}
		if (subptrs)
			mem_free(subptrs);
		pos += size;
	}
	return true;
}

static void bind_function_pointers(void)
{
	size_t i;

	for (i = 0; i < loaded_file_descriptor(compsave)->function_pointers_len; i++) {
		size_t off = loaded_file_descriptor(compsave)->function_pointers[i];
		struct function_pointer *fp = cast_ptr(struct function_pointer *, cast_ptr(char *, ld[compsave].loaded_data) + off);
		struct function_pointer *new_fp = module_load_function(fp->md, fp->fd, NULL);
		pointer_t ptr = pointer_reference(&new_fp->ptr);
		fp->ptr = ptr;
		fp->md = new_fp->md;
		fp->fd = new_fp->fd;
	}
}

void save_unbind_function_pointers(bool cs)
{
	size_t i, pos;
	/*ajla_time_t a1 = os_time_monotonic();*/
	if (!ld[cs].loaded_data)
		return;
	for (i = 0; i < loaded_file_descriptor(cs)->function_pointers_len; i++) {
		size_t off = loaded_file_descriptor(cs)->function_pointers[i];
		struct function_pointer *fp = cast_ptr(struct function_pointer *, cast_ptr(char *, ld[cs].loaded_data) + off);
		pointer_dereference(fp->ptr);
	}
	/*debug("save_unbind_function_pointers_1: %lu", os_time_monotonic() - a1);
	a1 = os_time_monotonic();*/
	pos = loaded_file_descriptor(cs)->writable_boundary;
	while (pos = round_up(pos, SAVED_DATA_ALIGN), pos < ld[cs].loaded_data_len) {
		char *p;
		refcount_t *ref;
		struct stack_entry *subptrs;
		size_t align, size, subptrs_l, i;
		bool duplicate;
		p = ld[cs].loaded_data + pos;
		ref = cast_ptr(refcount_t *, p + offsetof(struct data, refcount_));
		if (refcount_is_one(ref)) {
			pos += SAVED_DATA_ALIGN;
			continue;
		}
		if (unlikely(!refcount_is_read_only(ref)))
			internal(file_line, "unbind_function_pointers: invalid refcount at position %"PRIxMAX"", (uintmax_t)pos);
		if (unlikely(!data_save(p, 0, &align, &size, &subptrs, &subptrs_l, &duplicate))) {
			fatal("unable to allocate memory during shutdown");
			return;
		}
		for (i = 0; i < subptrs_l; i++) {
			if (subptrs[i].t->dereference_ptr) {
				pointer_t *ptr = subptrs[i].ptr;
				char *rawptr = pointer_get_value_strip_tag_(*ptr);
				if (likely(rawptr >= ld[cs].loaded_data) && likely(rawptr < ld[cs].loaded_data + ld[cs].loaded_data_len))
					continue;
				pointer_dereference(*ptr);
			}
		}
		if (subptrs)
			mem_free(subptrs);
		pos += size;
	}
	/*debug("save_unbind_function_pointers: %lu", os_time_monotonic() - a1);*/
}

static int function_compare(const struct module_designator *md1, const struct function_designator *fd1, struct function_descriptor *fd2)
{
	int x = module_designator_compare(md1, fd2->md);
	if (x)
		return x;
	return function_designator_compare(fd1, fd2->fd);
}

struct function_descriptor *save_find_function_descriptor(const struct module_designator *md, const struct function_designator *fd)
{
	size_t cs;
	for (cs = 0; cs < 2; cs++) {
		struct function_descriptor *fn_descs;
		size_t fn_descs_len;
		size_t result;
		int cmp;
		if (!ld[cs].loaded_data)
			continue;
		fn_descs = loaded_file_descriptor(cs)->fn_descs;
		fn_descs_len = loaded_file_descriptor(cs)->fn_descs_len;
		binary_search(size_t, fn_descs_len, result, !(cmp = function_compare(md, fd, &fn_descs[result])), cmp >= 0, goto cont);
		return &fn_descs[result];
cont:;
	}
	return NULL;
}

static int cache_compare(const struct module_designator *md1, const struct function_designator *fd1, struct cache_descriptor *fd2)
{
	int x = module_designator_compare(md1, fd2->md);
	if (x)
		return x;
	return function_designator_compare(fd1, fd2->fd);
}

struct cache_descriptor *save_find_cache_descriptor(const struct module_designator *md, const struct function_designator *fd)
{
	size_t cs;
	for (cs = 0; cs < 2; cs++) {
		struct cache_descriptor *cache_descs;
		size_t cache_descs_len;
		size_t result;
		int cmp;
		if (!ld[cs].loaded_data)
			continue;
		cache_descs = loaded_file_descriptor(cs)->cache_descs;
		cache_descs_len = loaded_file_descriptor(cs)->cache_descs_len;
		binary_search(size_t, cache_descs_len, result, !(cmp = cache_compare(md, fd, &cache_descs[result])), cmp >= 0, goto cont);
		return &cache_descs[result];
cont:;
	}
	return NULL;
}

static int dep_compare(const struct tree_entry *e1, uintptr_t e2)
{
	struct dependence *d1 = get_struct(e1, struct dependence, entry);
	const char *n2 = num_to_ptr(e2);
	return strcmp(d1->path_name, n2);
}

static bool dep_fingerprint(const char *path_name, char **result, size_t *result_l)
{
	ajla_error_t err;
	os_stat_t st;
	if (unlikely(!array_init_mayfail(char, result, result_l, &err)))
		return false;
	if (unlikely(!os_stat(dir_none, path_name, false, &st, &err))) {
		if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &err.error_class), sizeof err.error_class, NULL, &err)))
			return false;
		if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &err.error_type), sizeof err.error_type, NULL, &err)))
			return false;
		if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &err.error_aux), sizeof err.error_aux, NULL, &err)))
			return false;
		return true;
	}
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_mode), sizeof st.st_mode, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_dev), sizeof st.st_dev, NULL, &err)))
		return false;
#if !defined(OS_DOS)
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_ino), sizeof st.st_ino, NULL, &err)))
		return false;
#endif
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_size), sizeof st.st_size, NULL, &err)))
		return false;
#if defined(HAVE_STRUCT_STAT_ST_ATIM)
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_ctim.tv_sec), sizeof st.st_ctim.tv_sec, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_ctim.tv_nsec), sizeof st.st_ctim.tv_nsec, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_mtim.tv_sec), sizeof st.st_mtim.tv_sec, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_mtim.tv_nsec), sizeof st.st_mtim.tv_nsec, NULL, &err)))
		return false;
#elif defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_ctimespec.tv_sec), sizeof st.st_ctimespec.tv_sec, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_ctimespec.tv_nsec), sizeof st.st_ctimespec.tv_nsec, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_mtimespec.tv_sec), sizeof st.st_mtimespec.tv_sec, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_mtimespec.tv_nsec), sizeof st.st_mtimespec.tv_nsec, NULL, &err)))
		return false;
#else
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_ctime), sizeof st.st_ctime, NULL, &err)))
		return false;
	if (unlikely(!array_add_multiple_mayfail(char, result, result_l, cast_ptr(char *, &st.st_mtime), sizeof st.st_mtime, NULL, &err)))
		return false;
#endif
	return true;
}

void save_register_dependence(const char *path_name, bool comp)
{
	struct tree_insert_position ins;
	ajla_error_t sink;
	size_t path_name_len;
	struct dependence *dep;

	mutex_lock(&dependencies_mutex);
	/*debug("registering dependence: '%s'", path_name);*/
	if (unlikely(tree_find_for_insert(&dependencies, dep_compare, ptr_to_num(path_name), &ins) != NULL))
		goto unlock_ret;

	path_name_len = strlen(path_name) + 1;
	dep = struct_alloc_array_mayfail(mem_alloc_mayfail, struct dependence, path_name, path_name_len, &sink);
	if (unlikely(!dep)) {
		dependencies_failed = true;
		goto unlock_ret;
	}
	dep->comp = comp;
	memcpy(dep->path_name, path_name, path_name_len);
	if (unlikely(!dep_fingerprint(dep->path_name, &dep->fingerprint, &dep->fingerprint_l))) {
		mem_free(dep);
		dependencies_failed = true;
		goto unlock_ret;
	}

	tree_insert_after_find(&dep->entry, &ins);

unlock_ret:
	mutex_unlock(&dependencies_mutex);
}

static bool dep_get_stream(char **result, size_t *result_l)
{
	ajla_error_t sink;
	struct tree_entry *e;
	if (unlikely(!array_init_mayfail(char, result, result_l, &sink)))
		return false;
	for (e = tree_first(&dependencies); e; e = tree_next(e)) {
		struct dependence *dep = get_struct(e, struct dependence, entry);
		size_t path_name_len = strlen(dep->path_name) + 1;
		if (compsave && !dep->comp)
			continue;
		if (unlikely(!array_add_multiple_mayfail(char, result, result_l, dep->path_name, path_name_len, NULL, &sink)))
			return false;
		if (unlikely(!array_add_mayfail(char, result, result_l, (char)dep->fingerprint_l, NULL, &sink)))
			return false;
		if (unlikely(!array_add_multiple_mayfail(char, result, result_l, dep->fingerprint, dep->fingerprint_l, NULL, &sink)))
			return false;
	}
	return true;
}

static bool dep_verify(void)
{
	const char *ptr, *end;
	ptr = loaded_file_descriptor(compsave)->dependencies;
	end = ptr + loaded_file_descriptor(compsave)->dependencies_l;
	while (ptr < end) {
		char *fp;
		size_t fp_l, l;
		if (unlikely(!dep_fingerprint(ptr, &fp, &fp_l)))
			return false;
		ptr += strlen(ptr) + 1;
		l = (unsigned char)*ptr;
		ptr++;
		if (unlikely(l != fp_l) || unlikely(memcmp(ptr, fp, fp_l))) {
			mem_free(fp);
			return false;
		}
		mem_free(fp);
		ptr += fp_l;
	}
	ptr = loaded_file_descriptor(compsave)->dependencies;
	end = ptr + loaded_file_descriptor(compsave)->dependencies_l;
	while (ptr < end) {
		struct tree_insert_position ins;
		ajla_error_t sink;
		struct dependence *dep;

		const char *path_name, *fingerprint;
		size_t path_name_len, fingerprint_len;
		path_name = ptr;
		path_name_len = strlen(ptr) + 1;
		ptr += path_name_len;
		fingerprint = ptr + 1;
		fingerprint_len = (unsigned char)*ptr;
		ptr += 1 + fingerprint_len;

		if (unlikely(tree_find_for_insert(&dependencies, dep_compare, ptr_to_num(path_name), &ins) != NULL))
			continue;

		dep = struct_alloc_array_mayfail(mem_alloc_mayfail, struct dependence, path_name, path_name_len, &sink);
		if (unlikely(!dep)) {
			return false;
		}
		memcpy(dep->path_name, path_name, path_name_len);
		dep->fingerprint_l = fingerprint_len;
		dep->fingerprint = mem_alloc_mayfail(char *, fingerprint_len, &sink);
		if (unlikely(!dep->fingerprint)) {
			mem_free(dep);
			return false;
		}
		memcpy(dep->fingerprint, fingerprint, fingerprint_len);
		tree_insert_after_find(&dep->entry, &ins);
	}
	ajla_assert_lo(ptr == end, (file_line, "dep_verify: end mismatch: %p != %p", ptr, end));
	return true;
}

void save_unmap_data(bool cs)
{
	if (!ld[cs].loaded_data)
		return;
#ifdef USE_MMAP
	if (likely(ld[cs].loaded_data_mapped)) {
		os_munmap(ld[cs].loaded_data, ld[cs].loaded_data_len, true);
	} else if (ld[cs].loaded_data_amalloc) {
		amalloc_run_free(ld[cs].loaded_data, ld[cs].loaded_data_len);
	} else
#endif
	{
		mem_free(ld[cs].loaded_data);
	}
	ld[cs].loaded_data = NULL;
}

static char *save_get_file(void)
{
	ajla_error_t sink;
	char *pn, *fn;
	unsigned ext_index;
	char ext[5];
	size_t pn_l, fn_l;

	pn = str_dup(compsave ? "compiler" : *program_name ? program_name : "ajla", -1, &sink);
	if (unlikely(!pn))
		return NULL;
	pn_l = strlen(pn);
	if (pn_l > 5 && !strcasecmp(pn + pn_l - 5, ".ajla"))
		pn[pn_l -= 5] = 0;
	ext_index = 0;
#ifdef POINTER_COMPRESSION
	ext_index |= 0x01;
#endif
	if (optimize_int)
		ext_index |= 0x02;
	if (ipret_strict_calls)
		ext_index |= 0x04;
	if (verify != NULL)
		ext_index |= 0x08;
	if (ipret_noinline)
		ext_index |= 0x10;
	if (noautofma)
		ext_index |= 0x20;
	sprintf(ext, ".%c%02x", compsave ? 'c' : 's', ext_index);
	if (unlikely(!array_init_mayfail(char, &fn, &fn_l, &sink)))
		goto free_ret;
	if (unlikely(!array_add_multiple_mayfail(char, &fn, &fn_l, pn, pn_l, NULL, &sink)))
		goto free_ret;
	if (unlikely(!array_add_multiple_mayfail(char, &fn, &fn_l, ext, strlen(ext), NULL, &sink)))
		goto free_ret;
	if (unlikely(!array_add_mayfail(char, &fn, &fn_l, 0, NULL, &sink)))
		goto free_ret;
free_ret:
	mem_free(pn);
	return fn;
}

static void save_load_cache(void)
{
	ajla_error_t sink;
	char *path, *file;
	dir_handle_t dir;
	handle_t h;
	os_stat_t st;
	struct file_descriptor file_desc;

	if (unlikely(save_disable))
		return;

	path = os_get_directory_cache(&sink);
	if (unlikely(!path))
		return;
	dir = os_dir_open(os_cwd, path, 0, &sink);
	mem_free(path);
	if (unlikely(!dir_handle_is_valid(dir)))
		return;

	file = save_get_file();
	if (unlikely(!file)) {
		os_dir_close(dir);
		return;
	}
	h = os_open(dir, file, O_RDONLY, 0, &sink);
	mem_free(file);
	os_dir_close(dir);
	if (unlikely(!handle_is_valid(h)))
		return;

	if (unlikely(!os_fstat(h, &st, &sink))) {
		os_close(h);
		return;
	}
	if (unlikely(!S_ISREG(st.st_mode))) {
		os_close(h);
		return;
	}
	ld[compsave].loaded_data_len = (size_t)st.st_size;
	if (unlikely((uintmax_t)st.st_size != ld[compsave].loaded_data_len)) {
		os_close(h);
		return;
	}
	if (unlikely(ld[compsave].loaded_data_len < sizeof(struct file_descriptor))) {
		warning("too short cache file");
		os_close(h);
		return;
	}
	if (unlikely(!os_pread_all(h, cast_ptr(char *, &file_desc), sizeof(struct file_descriptor), st.st_size - sizeof(struct file_descriptor), &sink))) {
		os_close(h);
		return;
	}
	if (unlikely(file_desc.page_size != os_getpagesize()) ||
	    unlikely(file_desc.cpu_feature_flags != cpu_feature_flags) ||
	    unlikely(file_desc.optimize_int != optimize_int) ||
	    unlikely(file_desc.privileged != ipret_is_privileged) ||
	    unlikely(file_desc.profiling != profiling) ||
	    unlikely(file_desc.strict_calls != ipret_strict_calls) ||
	    unlikely(file_desc.verifying != (verify != NULL)) ||
	    unlikely(file_desc.noinline != ipret_noinline) ||
	    unlikely(file_desc.noautofma != noautofma) ||
	    unlikely(file_desc.chicken != chicken) ||
	    unlikely(memcmp(file_desc.ajla_id, id, sizeof(id)))) {
		os_close(h);
		return;
	}
#ifdef USE_MMAP
	{
		int prot_flags = PROT_READ | PROT_WRITE;
		void *ptr;
#ifndef POINTER_COMPRESSION
		ptr = os_mmap(file_desc.base, ld[compsave].loaded_data_len, prot_flags, MAP_PRIVATE, h, 0, &sink);
		/*debug("mapped: %p, %lx -> %p", file_desc.base, ld[compsave].loaded_data_len, ptr);*/
		if (unlikely(ptr == MAP_FAILED))
			goto skip_mmap;
		if (unlikely(ptr != file_desc.base)) {
			/*debug("address mismatch");*/
			os_munmap(ptr, ld[compsave].loaded_data_len, true);
			goto skip_mmap;
		}
		ld[compsave].loaded_data = ptr;
		ld[compsave].loaded_data_mapped = true;
#else
		if (unlikely(!amalloc_ptrcomp_try_reserve_range(file_desc.base, ld[compsave].loaded_data_len))) {
			/*debug("amalloc_ptrcomp_try_reserve_range failed");*/
			goto skip_mmap;
		}
		ptr = os_mmap(file_desc.base, ld[compsave].loaded_data_len, prot_flags, MAP_PRIVATE | MAP_FIXED, h, 0, &sink);
		if (unlikely(ptr == MAP_FAILED)) {
			amalloc_run_free(file_desc.base, ld[compsave].loaded_data_len);
			goto skip_mmap;
		}
		if (unlikely(ptr != file_desc.base))
			internal(file_line, "save_load_cache: os_mmap(MAP_FIXED) returned different pointer: %p != %p", ptr, file_desc.base);
		ld[compsave].loaded_data = ptr;
		ld[compsave].loaded_data_amalloc = true;
#endif
#if defined(HAVE_CODEGEN) && defined(HAVE_MPROTECT)
		os_mprotect(ptr, loaded_file_descriptor(compsave)->writable_boundary, PROT_READ | PROT_EXEC, NULL);
#endif
		bind_function_pointers();
		os_close(h);
		goto verify_ret;
	}
skip_mmap:
#endif
	ld[compsave].loaded_data = mem_alloc_mayfail(char *, st.st_size, &sink);
	if (unlikely(!ld[compsave].loaded_data)) {
		os_close(h);
		return;
	}
	if (unlikely(!os_pread_all(h, ld[compsave].loaded_data, st.st_size, 0, &sink))) {
		os_close(h);
		mem_free(ld[compsave].loaded_data);
		ld[compsave].loaded_data = NULL;
		return;
	}
	os_close(h);
#ifdef HAVE_CODEGEN
#if defined(CODEGEN_USE_HEAP) || !defined(USE_MMAP)
	/*debug("adjusting pointers: %p, %p", loaded_data, loaded_data + loaded_data_len);*/
	adjust_pointers(ld[compsave].loaded_data, ld[compsave].loaded_data_len, ptr_to_num(ld[compsave].loaded_data) - ptr_to_num(loaded_file_descriptor(compsave)->base));
	bind_function_pointers();
	os_code_invalidate_cache(cast_ptr(uint8_t *, ld[compsave].loaded_data), ld[compsave].loaded_data_len, true);
#else
	{
		void *new_ptr;
		new_ptr = amalloc_run_alloc(CODE_ALIGNMENT, ld[compsave].loaded_data_len, false, 0);
		if (unlikely(!new_ptr)) {
			save_unmap_data(compsave);
			return;
		}
		memcpy(new_ptr, ld[compsave].loaded_data, ld[compsave].loaded_data_len);
		mem_free(ld[compsave].loaded_data);
		ld[compsave].loaded_data = new_ptr;
		/*debug("adjusting pointers: %p, %p", ld[compsave].loaded_data, ld[compsave].loaded_data + ld[compsave].loaded_data_len);*/
		adjust_pointers(ld[compsave].loaded_data, ld[compsave].loaded_data_len, ptr_to_num(ld[compsave].loaded_data) - ptr_to_num(loaded_file_descriptor(compsave)->base));
		os_code_invalidate_cache(cast_ptr(uint8_t *, ld[compsave].loaded_data), ld[compsave].loaded_data_len, true);
		ld[compsave].loaded_data_amalloc = true;
	}
#endif
#else
	adjust_pointers(ld[compsave].loaded_data, ld[compsave].loaded_data_len, ptr_to_num(ld[compsave].loaded_data) - ptr_to_num(loaded_file_descriptor->base));
#endif
	goto verify_ret;
verify_ret:
	if (unlikely(!dep_verify())) {
		save_unbind_function_pointers(compsave);
		save_unmap_data(compsave);
		return;
	}
#ifdef DEBUG
	{
		size_t i;
		for (i = 0; i < loaded_file_descriptor(compsave)->cache_descs_len; i++) {
			struct cache_descriptor *cache_desc = &loaded_file_descriptor(compsave)->cache_descs[i];
			struct data *dsc = cache_desc->data_saved_cache;
			size_t j, k;
			/*const struct module_designator *md = cache_desc->md;
			debug("content: %u:%.*s:%lu:%lu", md->path_idx, (int)md->path_len, md->path, cache_desc->fd->n_entries, (long)cache_desc->fd->entries[0]);*/
			if (i > 0) {
				int c = cache_compare(loaded_file_descriptor(compsave)->cache_descs[i - 1].md, loaded_file_descriptor(compsave)->cache_descs[i - 1].fd, &loaded_file_descriptor(compsave)->cache_descs[i]);
				if (unlikely(c >= 0))
					internal(file_line, "save_load_cache: misordered cache descriptors: %d (%"PRIuMAX" / %"PRIuMAX")", c, (uintmax_t)i, (uintmax_t)loaded_file_descriptor(compsave)->cache_descs_len);
			}
			k = (size_t)da(dsc,saved_cache)->n_arguments + (size_t)da(dsc,saved_cache)->n_return_values;
			if (da(dsc,saved_cache)->n_entries) {
				for (j = 0; j < da(dsc,saved_cache)->n_entries - 1; j++) {
					pointer_t *p1 = &da(dsc,saved_cache)->pointers[j * k];
					pointer_t *p2 = &da(dsc,saved_cache)->pointers[(j + 1) * k];
					int c = compare_arguments(da(dsc,saved_cache)->n_arguments, p1, p2);
					if (unlikely(c >= 0) && c != DATA_COMPARE_OOM)
						internal(file_line, "save_load_cache: misordered cache entries: %d", c);
				}
			}
		}
		for (i = 0; i < loaded_file_descriptor(compsave)->fn_descs_len; i++) {
			struct function_descriptor *fn_desc = &loaded_file_descriptor(compsave)->fn_descs[i];
			if (i > 0) {
				int c = function_compare(loaded_file_descriptor(compsave)->fn_descs[i - 1].md, loaded_file_descriptor(compsave)->fn_descs[i - 1].fd, fn_desc);
				if (unlikely(c >= 0))
					internal(file_line, "save_load_cache: misordered function descriptors: %d (%"PRIuMAX" / %"PRIuMAX")", c, (uintmax_t)i, (uintmax_t)loaded_file_descriptor(compsave)->fn_descs_len);
			}
		}
	}
#endif
}

void name(save_init)(void)
{
	size_t cs;
	if (verify && verify[0])
		save_disable = true;
	for (cs = 0; cs < 2; cs++) {
		ld[cs].loaded_data = NULL;
#ifdef USE_MMAP
		ld[cs].loaded_data_mapped = false;
		ld[cs].loaded_data_amalloc = false;
#endif
	}
	tree_init(&dependencies);
	dependencies_failed = false;
	mutex_init(&dependencies_mutex);
	compsave = true;
	save_load_cache();
	compsave = false;
	save_load_cache();
	save_register_dependence(builtin_path, true);
}

#ifdef USE_MMAP
static char *save_data_mapped[2];
static size_t save_data_len[2];
#endif

static void save_stream(void)
{
	ajla_error_t sink;
	char *file, *path;
	path = os_get_directory_cache(&sink);
	if (unlikely(!path))
		return;
	file = save_get_file();
	if (!file) {
		mem_free(path);
		return;
	}
	/*debug("writing file: '%s'", file);*/
#ifdef USE_MMAP
	save_data_mapped[compsave] = amalloc_run_alloc(1, save_len, false, compsave + 1);
	/*debug("save_stream: %p, %llx", save_data_mapped, save_len);*/
	if (save_data_mapped[compsave]) {
		save_data_len[compsave] = save_len;
		memcpy(save_data_mapped[compsave], save_data, save_len);
		/*debug("adjusting pointers when saving");*/
		adjust_pointers(save_data_mapped[compsave], save_len, ptr_to_num(save_data_mapped[compsave]));
		os_write_atomic(path, file, save_data_mapped[compsave], save_len, &sink);
	} else
#endif
	{
		os_write_atomic(path, file, save_data, save_len, &sink);
	}
	mem_free(path);
	mem_free(file);
}

static void free_streams(void)
{
#ifdef USE_MMAP
	size_t cs;
	for (cs = 0; cs < 2; cs++) {
		if (save_data_len[cs] != 0)
			amalloc_run_free(save_data_mapped[cs], save_data_len[cs]);
	}
#endif
}

static void save_file(void)
{
	save_prepare();
	module_finish_functions(compsave);
	if (save_ok) {
		save_finish_file();
	}
	free_position_tree(&position_tree);
	if (save_data) {
		if (save_ok) {
			save_stream();
		}
		mem_free(save_data);
	}
	if (fn_descs) {
		mem_free(fn_descs);
	}
	if (cache_descs) {
		mem_free(cache_descs);
	}
	if (duplicate_records) {
		mem_free(duplicate_records);
	}
	if (function_pointers) {
		mem_free(function_pointers);
	}
}

void name(save_done)(void)
{
	compsave = true;
	save_file();

	compsave = false;
	save_file();

	free_streams();

	while (!tree_is_empty(&dependencies)) {
		struct dependence *dep = get_struct(tree_any(&dependencies), struct dependence, entry);
		tree_delete(&dep->entry);
		mem_free(dep->fingerprint);
		mem_free(dep);
	}
	mutex_done(&dependencies_mutex);
}

#endif
