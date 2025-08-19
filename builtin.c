/*
 * Copyright (C) 2024, 2025 Mikulas Patocka
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
#include "os.h"
#include "os_util.h"

#include "builtin.h"

#ifndef wake_up_wait_list
void u_name(save_register_dependence)(const char *path_name);
void c_name(save_register_dependence)(const char *path_name);
#endif

#include <fcntl.h>

const char *builtin_lib_path;

static char *builtin_ptr;
static size_t builtin_size;
#ifdef OS_HAS_MMAP
static bool builtin_mapped;
#endif

struct builtin_file_info {
	uint32_t module_info;
	uint32_t n_modules;
	uint32_t spec_info;
	uint32_t n_specs;
	uint32_t signature;
};

struct builtin_module_info {
	uint32_t function_info;
	uint32_t n_functions;
};

struct builtin_function_info {
	uint32_t pcode;
	uint32_t n_pcode;
};

struct builtin_module_name {
	uint32_t len;
	uint32_t name[FLEXIBLE_ARRAY];
};

#define builtin_file	cast_ptr(const struct builtin_file_info *, builtin_ptr + builtin_size - sizeof(struct builtin_file_info))

static int builtin_compare(size_t idx, const uint8_t *path, size_t path_len)
{
	const struct builtin_module_info *mod;
	const struct builtin_function_info *fi;
	const struct builtin_module_name *name;
	size_t min_len, i;

	mod = cast_ptr(const struct builtin_module_info *, builtin_ptr + builtin_file->module_info);
	mod += idx;
	fi = cast_ptr(const struct builtin_function_info *, builtin_ptr + mod->function_info);
	fi += mod->n_functions;
	name = cast_ptr(const struct builtin_module_name *, fi);

	min_len = minimum(name->len, path_len);
	for (i = 0; i < min_len; i++) {
		if (name->name[i] < path[i])
			return -1;
		if (name->name[i] > path[i])
			return 1;
	}

	if (unlikely(name->len > path_len))
		return 1;
	if (unlikely(name->len < path_len))
		return -1;
	return 0;
}

static const struct builtin_module_info *builtin_find_module(const uint8_t *path, size_t path_len)
{
	const struct builtin_module_info *mod;
	size_t s;
	int c;
	binary_search(size_t, builtin_file->n_modules, s, !(c = builtin_compare(s, path, path_len)), c < 0, goto not_found);
	mod = cast_ptr(const struct builtin_module_info *, builtin_ptr + builtin_file->module_info);
	mod += s;
	return mod;
not_found:
	internal(file_line, "builtin_find_module: builtin module %.*s not found", (int)path_len, path);
	return NULL;
}

static void builtin_walk_nested(const pcode_t **start, size_t *size, size_t n_entries, const pcode_t *entries)
{
	while (--n_entries) {
		pcode_t entry = *++entries;
		const pcode_t *ptr;
		ajla_assert_lo(entry < (*start)[2], (file_line, "builtin_walk_nested: invalid nested function: %"PRIuMAX", %"PRIuMAX"", (uintmax_t)entry, (uintmax_t)(*start)[2]));
		ptr = (*start) + 9;
		ptr += 1 + ((*ptr + 3) >> 2);
		while (entry--) {
			ptr += *ptr + 1;
		}
		*start = ptr + 1;
		*size = *ptr;
	}
}

void builtin_find_function(const uint8_t *path, size_t path_len, size_t n_entries, const pcode_t *entries, const pcode_t **start, size_t *size)
{
	const struct builtin_function_info *f;
	const struct builtin_module_info *m = builtin_find_module(path, path_len);
	ajla_assert_lo((size_t)entries[0] < m->n_functions, (file_line, "builtin_find_function: invalid index"));
	f = cast_ptr(const struct builtin_function_info *, builtin_ptr + m->function_info);
	f += entries[0];
	*start = cast_ptr(const pcode_t *, builtin_ptr + f->pcode);
	*size = f->n_pcode;
	builtin_walk_nested(start, size, n_entries, entries);
}

void builtin_init(void)
{
	ajla_error_t sink;
	handle_t h;
	os_stat_t st;
	const char *pte, *builtin_path;

	pte = os_get_path_to_exe();
	builtin_lib_path = pte;
	builtin_path = os_join_paths(pte, "builtin.pcd", true, NULL);
	h = os_open(os_cwd, builtin_path, O_RDONLY, 0, &sink);
	if (unlikely(handle_is_valid(h)))
		goto found_builtin;
	mem_free(builtin_path);

#ifdef AJLA_LIB
	builtin_lib_path = AJLA_LIB;
	builtin_path = os_join_paths(AJLA_LIB, "builtin.pcd", true, NULL);
	h = os_open(os_cwd, builtin_path, O_RDONLY, 0, &sink);
	if (unlikely(handle_is_valid(h)))
		goto found_builtin;
	mem_free(builtin_path);
#endif

	fatal("unable to find builtin.pcd");

found_builtin:
	os_fstat(h, &st, NULL);
	if (unlikely(!S_ISREG(st.st_mode)))
		fatal("builtin file is not a regular file");
	builtin_size = (size_t)st.st_size;
	if (unlikely(st.st_size != (os_off_t)builtin_size) || unlikely(builtin_size < sizeof(struct builtin_file_info)) || unlikely((builtin_size & 3) != 0))
		fatal("builtin file has invalid size");

#ifdef OS_HAS_MMAP
	{
		struct builtin_file_info fi;
		os_pread_all(h, cast_ptr(char *, &fi), sizeof(struct builtin_file_info), builtin_size - sizeof(struct builtin_file_info), NULL);
		if (likely(fi.signature == 0x616C6A41)) {
			void *ptr = os_mmap(NULL, builtin_size, PROT_READ, MAP_PRIVATE, h, 0, &sink);
			if (likely(ptr != MAP_FAILED)) {
				builtin_ptr = ptr;
				builtin_mapped = true;
				os_close(h);
				goto finalize;
			}
		} else if (unlikely(fi.signature != 0x416A6C61))
			goto bad_sig;
	}
	builtin_mapped = false;
#endif
	builtin_ptr = mem_alloc(char *, builtin_size);
	os_pread_all(h, builtin_ptr, builtin_size, 0, NULL);
	os_close(h);

	if (unlikely(builtin_file->signature != 0x616C6A41)) {
		size_t i;
		if (unlikely(builtin_file->signature != 0x416A6C61))
#ifdef OS_HAS_MMAP
bad_sig:
#endif
			fatal("builtin file doesn't have a signature");
		for (i = 0; i < builtin_size; i += 4) {
			char *p = &builtin_ptr[i];
			char a[4];
			a[0] = p[0];
			a[1] = p[1];
			a[2] = p[2];
			a[3] = p[3];
			p[0] = a[3];
			p[1] = a[2];
			p[2] = a[1];
			p[3] = a[0];
		}
	}
	goto finalize;	/* avoid warning */
finalize:
	call(save_register_dependence)(builtin_path);
	mem_free(builtin_path);
}

void builtin_done(void)
{
#ifdef OS_HAS_MMAP
	if (likely(builtin_mapped))
		os_munmap(builtin_ptr, builtin_size, true);
	else
#endif
	{
		mem_free(builtin_ptr);
	}
}
