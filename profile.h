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

#ifndef AJLA_PROFILE_H
#define AJLA_PROFILE_H

#include "code-op.h"

extern uchar_efficient_t profiling;
extern uchar_efficient_t profiling_escapes;

typedef uint_efficient_t profile_counter_t;

void profile_unblock(void);
profile_counter_t profile_sample(void);
void profile_collect(const char *function_name, profile_counter_t profiling_counter, profile_counter_t call_counter);
void profile_escape_collect(const char *function_name, profile_counter_t profiling_counter, ip_t ip, unsigned line, code_t code);

bool function_enable_profile(const char *option, size_t l);

void profile_init(void);
void profile_done(void);

#endif
