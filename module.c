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

#include "args.h"
#include "mem_al.h"
#include "str.h"
#include "tree.h"
#include "rwlock.h"
#include "builtin.h"
#include "funct.h"
#include "pcode.h"
#include "array.h"
#include "profile.h"
#include "save.h"

#include "module.h"

pointer_t *start_fn;
shared_var pointer_t *optimizer_fn;
shared_var pointer_t *parser_fn;

static struct tree modules;
rwlock_decl(modules_mutex);

struct module_function {
	struct tree_entry entry;
	pointer_t function;
	pointer_t optimizer;
	pointer_t parser;
	struct function_designator fd;
};

struct module {
	struct tree_entry entry;
	struct tree functions;
	struct module_designator md;
};

static pointer_t module_create_optimizer_reference(struct module *m, struct function_designator *fd, bool optimizer)
{
	size_t i;
	ajla_flat_option_t program;
	int_default_t path_idx;
	struct data *filename;
	int_default_t *np;
	struct data *nesting_path;
	struct data *fn_ref;
	struct thunk *result;
	ajla_error_t err;

	program = m->md.program;

	path_idx = m->md.path_idx;
	if (path_idx < 0 || (uint_default_t)path_idx != m->md.path_idx) {
		return pointer_error(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), NULL, NULL pass_file_line);
	}

	filename = array_from_flat_mem(type_get_fixed(0, true), cast_ptr(const char *, m->md.path), m->md.path_len, &err);
	if (unlikely(!filename)) {
		return pointer_error(err, NULL, NULL pass_file_line);
	}

	np = mem_alloc_array_mayfail(mem_alloc_mayfail, int_default_t *, 0, 0, fd->n_entries, sizeof(int_default_t), &err);
	if (unlikely(!np)) {
		data_dereference(filename);
		return pointer_error(err, NULL, NULL pass_file_line);
	}
	for (i = 0; i < fd->n_entries; i++) {
		int_default_t e = (int_default_t)fd->entries[i];
		if (unlikely(e < 0) || unlikely(e != fd->entries[i])) {
			data_dereference(filename);
			mem_free(np);
			return pointer_error(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), NULL, NULL pass_file_line);
		}
		np[i] = e;
	}
	nesting_path = array_from_flat_mem(type_get_int(INT_DEFAULT_N), cast_ptr(const char *, np), fd->n_entries, &err);
	mem_free(np);
	if (unlikely(!nesting_path)) {
		data_dereference(filename);
		return pointer_error(err, NULL, NULL pass_file_line);
	}

	fn_ref = data_alloc_function_reference_mayfail(4, &err pass_file_line);
	if (unlikely(!fn_ref)) {
		data_dereference(filename);
		data_dereference(nesting_path);
		return pointer_error(err, NULL, NULL pass_file_line);
	}
	da(fn_ref,function_reference)->is_indirect = false;
	da(fn_ref,function_reference)->u.direct = optimizer ? optimizer_fn : parser_fn;

	data_fill_function_reference_flat(fn_ref, 0, type_get_int(INT_DEFAULT_N), cast_ptr(unsigned char *, &path_idx));
	data_fill_function_reference(fn_ref, 1, pointer_data(filename));
	data_fill_function_reference_flat(fn_ref, 2, type_get_flat_option(), cast_ptr(unsigned char *, &program));
	data_fill_function_reference(fn_ref, 3, pointer_data(nesting_path));

	if (unlikely(!thunk_alloc_function_call(pointer_data(fn_ref), 1, &result, &err))) {
		data_dereference(fn_ref);
		return pointer_error(err, NULL, NULL pass_file_line);
	}

	return pointer_thunk(result);
}

static bool module_function_init(struct module *m, struct module_function *mf, ajla_error_t attr_unused *mayfail)
{
	pointer_t ptr, optr, pptr;
	union internal_arg ia[3];
	if (m->md.path_idx > 0) {
		optr = module_create_optimizer_reference(m, &mf->fd, true);
		pptr = module_create_optimizer_reference(m, &mf->fd, false);
		ia[0].ptr = &mf->optimizer;
		ia[1].ptr = &m->md;
		ia[2].ptr = &mf->fd;
		ptr = function_build_internal_thunk(pcode_build_function_from_array, 3, ia);
	} else {
		ia[0].ptr = &m->md;
		ia[1].ptr = &mf->fd;
		optr = function_build_internal_thunk(pcode_array_from_builtin, 2, ia);
		pointer_reference_owned(optr);
		pptr = optr;
		ptr = function_build_internal_thunk(pcode_build_function_from_builtin, 2, ia);
	}
	mf->function = ptr;
	mf->optimizer = optr;
	mf->parser = pptr;
	return true;
}

static int function_test(const struct tree_entry *e, uintptr_t id)
{
	const struct function_designator *fd = cast_cpp(const struct function_designator *, num_to_ptr(id));
	const struct module_function *mf = get_struct(e, struct module_function, entry);
	return function_designator_compare(&mf->fd, fd);
}

static struct module_function *module_find_function(struct module *m, const struct function_designator *fd, bool create, ajla_error_t *mayfail)
{
	struct tree_insert_position ins;
	struct tree_entry *e;
	struct module_function *mf;

	e = tree_find_for_insert(&m->functions, function_test, ptr_to_num(fd), &ins);
	if (e)
		return get_struct(e, struct module_function, entry);

	if (!create)
		return NULL;

	mf = struct_alloc_array_mayfail(mem_alloc_mayfail, struct module_function, fd.entries, fd->n_entries, mayfail);
	if (unlikely(!mf))
		return NULL;

	mf->fd.n_entries = fd->n_entries;
	memcpy(mf->fd.entries, fd->entries, fd->n_entries * sizeof(fd->entries[0]));

	if (unlikely(!module_function_init(m, mf, mayfail))) {
		mem_free(mf);
		return NULL;
	}

	tree_insert_after_find(&mf->entry, &ins);

	return mf;
}

static int module_test(const struct tree_entry *e, uintptr_t id)
{
	const struct module_designator *md = cast_cpp(const struct module_designator *, num_to_ptr(id));
	const struct module *m = get_struct(e, struct module, entry);
	return module_designator_compare(&m->md, md);
}

static struct module *module_find(const struct module_designator *md, bool create, ajla_error_t *mayfail)
{
	struct tree_insert_position ins;
	struct tree_entry *e;
	struct module *m;

	e = tree_find_for_insert(&modules, module_test, ptr_to_num(md), &ins);
	if (likely(e != NULL))
		return get_struct(e, struct module, entry);

	if (!create)
		return NULL;

	m = struct_alloc_array_mayfail(mem_alloc_mayfail, struct module, md.path, md->path_len, mayfail);
	if (unlikely(!m))
		return NULL;

	m->md.path_len = md->path_len;
	m->md.path_idx = md->path_idx;
	m->md.program = md->program;
	memcpy(m->md.path, md->path, md->path_len);

	tree_init(&m->functions);

	tree_insert_after_find(&m->entry, &ins);

	return m;
}

pointer_t *module_load_function(const struct module_designator *md, const struct function_designator *fd, bool get_fn, bool optimizer, ajla_error_t *mayfail)
{
	struct module *m;
	struct module_function *mf;
	bool create = false;

	rwlock_lock_read(&modules_mutex);
retry:
	m = module_find(md, create, mayfail);
	if (!m)
		goto lock_for_write;

	mf = module_find_function(m, fd, create, mayfail);
	if (!mf)
		goto lock_for_write;

	if (!create)
		rwlock_unlock_read(&modules_mutex);
	else
		rwlock_unlock_write(&modules_mutex);

	if (get_fn)
		return &mf->function;
	else if (optimizer)
		return &mf->optimizer;
	else
		return &mf->parser;

lock_for_write:
	if (unlikely(create)) {
		rwlock_unlock_write(&modules_mutex);
		return NULL;
	}
	create = true;
	rwlock_unlock_read(&modules_mutex);
	rwlock_lock_write(&modules_mutex);
	goto retry;
}


static void module_finish_function(struct module_function *mf)
{
	if (!pointer_is_thunk(mf->function)) {
		struct data *d = pointer_get_data(mf->function);
		struct tree_entry *e;
		bool new_cache;
		if (profiling) {
			profile_collect(da(d,function)->function_name, load_relaxed(&da(d,function)->profiling_counter), load_relaxed(&da(d,function)->call_counter));
		}
		if (profiling_escapes) {
			ip_t ip_rel;
			for (ip_rel = 0; ip_rel < da(d,function)->code_size; ip_rel++) {
				struct stack_trace_entry ste;
				profile_counter_t profiling_counter = load_relaxed(&da(d,function)->escape_data[ip_rel].counter);
				if (likely(!profiling_counter))
					continue;
				if (unlikely(!stack_trace_get_location(d, ip_rel, &ste)))
					continue;
				profile_escape_collect(ste.function_name, profiling_counter, ste.line, da(d,function)->code[ip_rel], load_relaxed(&da(d,function)->escape_data[ip_rel].line));
			}
		}
		new_cache = false;
#ifdef HAVE_CODEGEN
		if (likely(!pointer_is_thunk(da(d,function)->codegen))) {
			struct data *codegen = pointer_get_data(da(d,function)->codegen);
			if (unlikely(!da(codegen,codegen)->is_saved))
				new_cache = true;
		}
#endif
		for (e = tree_first(&da(d,function)->cache); e && !new_cache; e = tree_next(e)) {
			struct cache_entry *ce = get_struct(e, struct cache_entry, entry);
			if (ce->save && da(d,function)->module_designator) {
				new_cache = true;
				break;
			}
		}
		save_start_function(d, new_cache);
		while ((e = tree_first(&da(d,function)->cache))) {
			struct cache_entry *ce = get_struct(e, struct cache_entry, entry);
			tree_delete(&ce->entry);
			if (ce->save && da(d,function)->module_designator) {
				/*debug("saving: %s", da(d,function)->function_name);*/
				save_cache_entry(d, ce);
			}
			free_cache_entry(d, ce);
		}
		save_finish_function(d);
	}
}

static void module_free_function(struct module_function *mf)
{
	pointer_dereference(mf->function);
	pointer_dereference(mf->optimizer);
	pointer_dereference(mf->parser);
}


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
	size_t n_entries = p[0];
	struct function_designator *fd;
	ajla_assert_lo(p[0] > 0, (file_line, "function_designator_alloc: invalid lenfth %ld", (long)p[0]));
	fd = struct_alloc_array_mayfail(mem_alloc_mayfail, struct function_designator, entries, n_entries, mayfail);
	if (unlikely(!fd))
		return NULL;
	fd->n_entries = n_entries;
	for (i = 0; i < n_entries; i++)
		fd->entries[i] = p[1 + i];
	return fd;
}

struct function_designator *function_designator_alloc_single(pcode_t idx, ajla_error_t *mayfail)
{
	pcode_t p[2];
	p[0] = 1;
	p[1] = idx;
	return function_designator_alloc(p, mayfail);
}

void function_designator_free(struct function_designator *fd)
{
	mem_free(fd);
}

size_t function_designator_length(const struct function_designator *fd)
{
	return offsetof(struct function_designator, entries[fd->n_entries]);
}

int function_designator_compare(const struct function_designator *fd1, const struct function_designator *fd2)
{
	if (fd1->n_entries < fd2->n_entries)
		return -1;
	if (fd1->n_entries > fd2->n_entries)
		return 1;
	/*return memcmp(fd1->entries, fd2->entries, fd1->n_entries * sizeof(fd1->entries[0]));*/
	{
		size_t i;
		for (i = 0; i < fd1->n_entries; i++) {
			if (fd1->entries[i] < fd2->entries[i])
				return -1;
			if (fd1->entries[i] > fd2->entries[i])
				return 1;
		}
		return 0;
	}
}


void name(module_init)(void)
{
	const char *n;
	struct module_designator *md;
	struct function_designator *fd;

	tree_init(&modules);
	rwlock_init(&modules_mutex);


	n = "start";
	md = module_designator_alloc(0, cast_ptr(const uint8_t *, n), strlen(n), false, NULL);
	fd = function_designator_alloc_single(0, NULL);
	start_fn = module_load_function(md, fd, true, true, NULL);
	function_designator_free(fd);
	module_designator_free(md);

	n = "compiler/compiler";
	md = module_designator_alloc(0, cast_ptr(const uint8_t *, n), strlen(n), false, NULL);
	fd = function_designator_alloc_single(0, NULL);
	optimizer_fn = module_load_function(md, fd, true, true, NULL);
	function_designator_free(fd);
	fd = function_designator_alloc_single(1, NULL);
	parser_fn = module_load_function(md, fd, true, true, NULL);
	function_designator_free(fd);
	module_designator_free(md);
}

void name(module_done)(void)
{
	struct tree_entry *e1, *e2;
	save_prepare();
	for (e1 = tree_first(&modules); e1; e1 = tree_next(e1)) {
		struct module *m = get_struct(e1, struct module, entry);
		/*debug("saving: %.*s", (int)m->md.path_len, m->md.path);*/
		for (e2 = tree_first(&m->functions); e2; e2 = tree_next(e2)) {
			struct module_function *mf = get_struct(e2, struct module_function, entry);
			module_finish_function(mf);
		}
	}
	while (!tree_is_empty(&modules)) {
		struct module *m = get_struct(tree_any(&modules), struct module, entry);
		tree_delete(&m->entry);
		while (!tree_is_empty(&m->functions)) {
			struct module_function *mf = get_struct(tree_any(&m->functions), struct module_function, entry);
			module_free_function(mf);
			tree_delete(&mf->entry);
			mem_free(mf);
		}
		mem_free(m);
	}
	rwlock_done(&modules_mutex);
}

#endif
