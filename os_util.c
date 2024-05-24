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

#include "str.h"
#include "os.h"
#include "obj_reg.h"

#include <fcntl.h>

#include "os_util.h"

bool os_read_file(const char *path, char **file, size_t *len, ajla_error_t *err)
{
	handle_t h;
	char buffer[192];
	if (unlikely(!array_init_mayfail(char, file, len, err)))
		return false;
	h = os_open(dir_none, path, O_RDONLY, 0, err);
	if (unlikely(!handle_is_valid(h)))
		goto ret_false;
	while (1) {
		ssize_t rd = os_read(h, buffer, sizeof buffer, err);
		if (unlikely(rd == OS_RW_ERROR))
			goto ret_false;
		if (unlikely(rd == OS_RW_WOULDBLOCK)) {
			fatal_warning_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SYSTEM_RETURNED_INVALID_DATA), err, "the read syscall tries to block");
			goto ret_false;
		}
		if (unlikely(!rd))
			break;
		if (unlikely(!array_add_multiple_mayfail(char, file, len, buffer, rd, NULL, err)))
			return false;
	}
	os_close(h);
	return true;

ret_false:
	mem_free(*file);
	return false;
}

bool os_pread_all(handle_t h, char *ptr, size_t len, os_off_t offset, ajla_error_t *err)
{
	while (len) {
		size_t this_step = len;
		ssize_t rd;
		if (unlikely(this_step > (size_t)signed_maximum(int) + zero))
			this_step = signed_maximum(int);
		rd = os_pread(h, ptr, this_step, offset, err);
		if (unlikely(rd == OS_RW_ERROR))
			return false;
		if (unlikely(rd == OS_RW_WOULDBLOCK)) {
			fatal_warning_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SYSTEM_RETURNED_INVALID_DATA), err, "the pread syscall tries to block");
			return false;
		}
		if (unlikely(!rd)) {
			fatal_warning_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SYSTEM_RETURNED_INVALID_DATA), err, "zero-sized read");
			return false;
		}
		ptr += rd;
		len -= rd;
		offset += rd;
	}
	return true;
}

bool os_write_all(handle_t h, const char *data, size_t len, ajla_error_t *err)
{
	obj_registry_verify(OBJ_TYPE_HANDLE, (uintptr_t)h, file_line);
	while (len) {
		ssize_t wr;
		size_t this_step = len;
		if (unlikely(this_step > signed_maximum(int)))
			this_step = signed_maximum(int);
		wr = os_write(h, data, this_step, err);
		if (unlikely(wr == OS_RW_ERROR))
			return false;
		if (unlikely(wr == OS_RW_WOULDBLOCK)) {
			fatal_warning_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SYSTEM_RETURNED_INVALID_DATA), err, "the write syscall tries to block");
			return false;
		}
		data += wr;
		len -= wr;
	}
	return true;
}

bool os_test_absolute_path(dir_handle_t dir, bool abs_path, ajla_error_t *err)
{
	if (!dir_handle_is_valid(dir) && !abs_path) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NON_ABSOLUTE_PATH), err, "non-absolute path");
		return false;
	}
	return true;
}

#if defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32)

bool os_path_is_absolute(const char *path)
{
	if ((path[0] == '/' || path[0] == '\\') && (path[1] == '/' || path[1] == '\\'))
		return true;
	if ((path[0] & 0xDF) >= 'A' && (path[0] & 0xDF) <= 'Z' && path[1] == ':' && (path[2] == '/' || path[2] == '\\'))
		return true;
	return false;
}

char *os_join_paths(const char *dir, const char *path, bool trim_last_slash, ajla_error_t *err)
{
	char *ptr;
	size_t len;
	bool is_abs = os_path_is_absolute(path);

	if (unlikely(!os_test_absolute_path(cast_ptr(char *, dir), is_abs, err)))
		return NULL;

	if (unlikely(!array_init_mayfail(char, &ptr, &len, err)))
		return NULL;

	if (is_abs) {
		if (unlikely(!array_add_multiple_mayfail(char, &ptr, &len, path, strlen(path), NULL, err)))
			return NULL;
		goto ret;
	}

	if (path[0] == '/' || path[0] == '\\') {
		if (unlikely(!array_add_multiple_mayfail(char, &ptr, &len, dir, 2, NULL, err)))
			return NULL;
	} else {
		if (unlikely(!array_add_multiple_mayfail(char, &ptr, &len, dir, strlen(dir), NULL, err)))
			return NULL;
		if (len && ptr[len - 1] != '/' && ptr[len - 1] != '\\')
			if (unlikely(!array_add_mayfail(char, &ptr, &len, '/', NULL, err)))
				return NULL;
	}
	if (unlikely(!array_add_multiple_mayfail(char, &ptr, &len, path, strlen(path), NULL, err)))
		return NULL;

ret:
	if (trim_last_slash) {
		if (len > 3 && (ptr[len - 1] == '/' || ptr[len - 1] == '\\'))
			len--;
	}

	if (unlikely(!array_add_mayfail(char, &ptr, &len, 0, NULL, err)))
		return NULL;

	array_finish(char, &ptr, &len);

	return ptr;
}

#else

bool os_path_is_absolute(const char *path)
{
#if defined(OS_CYGWIN)
	if ((path[0] & 0xdf) >= 'A' && (path[0] & 0xdf) <= 'Z' &&
	     path[1] == ':' &&
	    (path[2] == '/' || path[2] == '\\'))
		return true;
#endif
	return path[0] == '/';
}

char *os_join_paths(const char *base, const char *path, bool trim_last_slash, ajla_error_t *err)
{
	char *res;
	size_t res_l, base_l, path_l;
	if (unlikely(!array_init_mayfail(char, &res, &res_l, err)))
		return NULL;
	if (!os_path_is_absolute(path)) {
		base_l = strlen(base);
		if (unlikely(!array_add_multiple_mayfail(char, &res, &res_l, base, base_l, NULL, err)))
			return NULL;
		if (res_l && !os_is_path_separator(res[res_l - 1])) {
			if (unlikely(!array_add_mayfail(char, &res, &res_l, os_path_separator(), NULL, err)))
				return NULL;
		}
	}
	path_l = strlen(path);
	if (unlikely(!array_add_multiple_mayfail(char, &res, &res_l, path, path_l, NULL, err)))
		return NULL;
	if (trim_last_slash) {
		if (res_l > 1 && os_is_path_separator(res[res_l - 1]))
			res_l--;
	}
	if (unlikely(!array_add_mayfail(char, &res, &res_l, 0, NULL, err)))
		return NULL;
	array_finish(char, &res, &res_l);
	return res;
}

#endif

static char *os_get_directory(const char *env, const char *home, ajla_error_t *err)
{
	const char *e;
	char *cache_dir, *cache_dir_ajla;
	if ((e = getenv(env)) && *e) {
		cache_dir = str_dup(e, -1, err);
		if (unlikely(!cache_dir))
			return NULL;
	} else {
		const char *h = getenv("HOME");
		if (unlikely(!h)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "no home directory");
			return NULL;
		}

		cache_dir = os_join_paths(h, home, true, err);
		if (unlikely(!cache_dir))
			return NULL;
	}
	cache_dir_ajla = os_join_paths(cache_dir, "ajla", true, err);
	if (unlikely(!cache_dir_ajla)) {
		mem_free(cache_dir);
		return NULL;
	}
	mem_free(cache_dir);
	return cache_dir_ajla;
}

char *os_get_directory_cache(ajla_error_t *err)
{
#if defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32)
	return os_get_directory("TEMP", "cache", err);
#else
	return os_get_directory("XDG_CACHE_HOME", ".cache", err);
#endif
}

static bool os_test_make_dir(const char *path, size_t path_len, ajla_error_t *err)
{
	ajla_error_t mkdir_err;
	char *path_cpy;
	path_cpy = str_dup(path, path_len, err);
	if (unlikely(!path_cpy))
		return false;
	if (unlikely(!os_dir_action(os_cwd, path_cpy, IO_Action_Mk_Dir, 0700, 0, 0, NULL, &mkdir_err))) {
		if (likely(mkdir_err.error_type == AJLA_ERROR_SYSTEM) && likely(mkdir_err.error_aux == SYSTEM_ERROR_EEXIST)) {
			mem_free(path_cpy);
			return true;
		}
		fatal_mayfail(mkdir_err, err, "unable to make directory '%s'", path_cpy);
		mem_free(path_cpy);
		return false;
	}
	mem_free(path_cpy);
	return true;
}

bool os_create_directory_parents(const char *path, ajla_error_t *err)
{
	ajla_error_t sink;
	size_t i;
	if (os_test_make_dir(path, strlen(path), &sink))
		return true;
	i = 0;
	while (os_is_path_separator(path[i]))
		i++;
	if (!i && os_path_is_absolute(path)) {
		while (path[i] && !os_is_path_separator(path[i]))
			i++;
		while (os_is_path_separator(path[i]))
			i++;
	}
	while (path[i]) {
		while (path[i] && !os_is_path_separator(path[i]))
			i++;
		while (os_is_path_separator(path[i]))
			i++;
		if (unlikely(!os_test_make_dir(path, i, err)))
			return false;
	}
	return true;
}

bool os_write_atomic(const char *path, const char *filename, const char *data, size_t data_len, ajla_error_t *err)
{
	ajla_error_t open_err;
	uint32_t count = 0;
	char tmp_file[10 + 4 + 1];
	char *tmp_ptr;
	dir_handle_t dir;
	handle_t h;
	sig_state_t set;

	dir = os_dir_open(os_cwd, path, 0, &open_err);
	if (unlikely(!dir_handle_is_valid(dir))) {
		if (unlikely(!os_create_directory_parents(path, err)))
			return false;
		dir = os_dir_open(os_cwd, path, 0, err);
		if (unlikely(!dir_handle_is_valid(dir)))
			return false;
	}

try_next_file:
	tmp_ptr = tmp_file;
	str_add_unsigned(&tmp_ptr, NULL, count, 10);
	strcpy(tmp_ptr, ".tmp");

	os_block_signals(&set);

	h = os_open(dir, tmp_file, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600, &open_err);
	if (unlikely(!handle_is_valid(h))) {
		os_unblock_signals(&set);
		if (likely(open_err.error_type == AJLA_ERROR_SYSTEM) && likely(open_err.error_aux == SYSTEM_ERROR_EEXIST)) {
			if (++count)
				goto try_next_file;
		}
		fatal_mayfail(open_err, err, "unable to create file '%s'", tmp_file);
		os_dir_close(dir);
		return false;
	}

	if (unlikely(!os_write_all(h, data, data_len, err))) {
		os_close(h);
		os_dir_action(dir, tmp_file, IO_Action_Rm, 0, 0, 0, NULL, &open_err);
		os_unblock_signals(&set);
		os_dir_close(dir);
		return false;
	}

	os_close(h);

	if (unlikely(!os_dir2_action(dir, filename, IO_Action_Rename, dir, tmp_file, &open_err))) {
		os_dir_action(dir, tmp_file, IO_Action_Rm, 0, 0, 0, NULL, &open_err);
		os_unblock_signals(&set);
		os_dir_close(dir);
		return false;
	}

	os_unblock_signals(&set);
	os_dir_close(dir);

	return true;
}
