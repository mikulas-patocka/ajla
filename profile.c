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
#include "thread.h"
#include "util.h"
#include "os.h"

#include "profile.h"

uchar_efficient_t profiling = 0;
uchar_efficient_t profiling_escapes = 0;

struct profile_data {
	const char *function_name;
	profile_counter_t profiling_counter;
	profile_counter_t call_counter;
};

static struct profile_data *pd;
static size_t pd_len;

tls_decl(ajla_time_t, profiler_time);

void profile_unblock(void)
{
	ajla_time_t now = os_time_monotonic();
	tls_set(ajla_time_t, profiler_time, now);
}

profile_counter_t profile_sample(void)
{
	profile_counter_t retval;
	ajla_time_t now = os_time_monotonic();
	ajla_time_t us = tls_get(ajla_time_t, profiler_time);
	retval = ((now - us) + 500) / 1000;
	tls_set(ajla_time_t, profiler_time, now);
	return retval;
}

void profile_collect(const char *function_name, profile_counter_t profiling_counter, profile_counter_t call_counter)
{
	struct profile_data p;
	p.function_name = str_dup(function_name, -1, NULL);
	p.profiling_counter = profiling_counter;
	p.call_counter = call_counter;
	array_add(struct profile_data, &pd, &pd_len, p);
}

static int profile_cmp(const void *p1, const void *p2)
{
	const struct profile_data *q1 = p1;
	const struct profile_data *q2 = p2;
	if (q1->profiling_counter < q2->profiling_counter) return -1;
	if (q1->profiling_counter > q2->profiling_counter) return 1;
	if (q1->call_counter < q2->call_counter) return -1;
	if (q1->call_counter > q2->call_counter) return 1;
	return strcmp(q1->function_name, q2->function_name);
}

static void profile_print(void)
{
	size_t i;
	qsort(pd, pd_len, sizeof(struct profile_data), profile_cmp);
	for (i = 0; i < pd_len; i++) {
		debug("%-30s %"PRIuMAX" %"PRIuMAX"", pd[i].function_name, (uintmax_t)pd[i].profiling_counter, (uintmax_t)pd[i].call_counter);
		mem_free(pd[i].function_name);
	}
	mem_free(pd);
}


struct profile_escape_data {
	const char *function_name;
	profile_counter_t profiling_counter;
	ip_t ip;
	unsigned line;
	code_t code;
};

static struct profile_escape_data *ped;
static size_t ped_len;

void profile_escape_collect(const char *function_name, profile_counter_t profiling_counter, ip_t ip, unsigned line, code_t code)
{
	struct profile_escape_data pe;
	if ((code % OPCODE_MODE_MULT) == OPCODE_CHECKPOINT)
		return;
	pe.function_name = str_dup(function_name, -1, NULL);
	pe.profiling_counter = profiling_counter;
	pe.ip = ip;
	pe.line = line;
	pe.code = code;
	array_add(struct profile_escape_data, &ped, &ped_len, pe);
}

static int profile_escape_cmp(const void *p1, const void *p2)
{
	int r;
	const struct profile_escape_data *q1 = p1;
	const struct profile_escape_data *q2 = p2;
	if (q1->profiling_counter < q2->profiling_counter) return -1;
	if (q1->profiling_counter > q2->profiling_counter) return 1;
	r = strcmp(q1->function_name, q2->function_name);
	if (r)
		return r;
	if (q1->line < q2->line) return -1;
	if (q1->line > q2->line) return 1;
	if (q1->code < q2->code) return -1;
	if (q1->code > q2->code) return 1;
	return 0;
}

static void profile_escape_print(void)
{
	size_t i;
	qsort(ped, ped_len, sizeof(struct profile_escape_data), profile_escape_cmp);
	for (i = 0; i < ped_len; i++) {
		debug("%30s:%-6u %-10"PRIuMAX" %s,%lx", ped[i].function_name, ped[i].line, (uintmax_t)ped[i].profiling_counter, decode_opcode(ped[i].code, false), (unsigned long)ped[i].ip);
		mem_free(ped[i].function_name);
	}
	mem_free(ped);
}


bool function_enable_profile(const char *option, size_t l)
{
	if (!option)
		profiling = profiling_escapes = 1;
	else if (l == 8 && !strncmp(option, "function", l))
		profiling = 1;
	else if (l == 6 && !strncmp(option, "escape", l))
		profiling_escapes = 1;
	else
		return false;
	return true;
}

void profile_init(void)
{
	if (profiling) {
		tls_init(ajla_time_t, profiler_time);
		array_init(struct profile_data, &pd, &pd_len);
	}
	if (profiling_escapes) {
		array_init(struct profile_escape_data, &ped, &ped_len);
	}
}

void profile_done(void)
{
	if (profiling) {
		profile_print();
		tls_done(ajla_time_t, profiler_time);
	}
	if (profiling_escapes) {
		profile_escape_print();
	}
}
