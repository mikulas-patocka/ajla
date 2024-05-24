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

#ifndef AJLA_OS_UTIL_H
#define AJLA_OS_UTIL_H

#include "os.h"

bool os_read_file(const char *path, char **file, size_t *len, ajla_error_t *err);
bool os_pread_all(handle_t h, char *ptr, size_t len, os_off_t offset, ajla_error_t *err);
bool os_write_all(handle_t h, const char *data, size_t len, ajla_error_t *err);

bool os_test_absolute_path(dir_handle_t dir, bool abs_path ,ajla_error_t *err);
bool os_path_is_absolute(const char *path);
char *os_join_paths(const char *base, const char *path, bool trim_last_slash, ajla_error_t *err);
char *os_get_directory_cache(ajla_error_t *err);
bool os_create_directory_parents(const char *path, ajla_error_t *err);
bool os_write_atomic(const char *path, const char *filename, const char *data, size_t data_len, ajla_error_t *err);

#endif
