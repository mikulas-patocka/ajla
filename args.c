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
#include "obj_reg.h"
#include "thread.h"
#include "profile.h"
#include "funct.h"
#include "tick.h"
#include "task.h"
#include "os.h"
#include "ipfn.h"
#include "save.h"
#include "codegen.h"
#include "ipio.h"

#include "args.h"

const char * const * args_left;
int n_args_left;
const char *program_name;
const char *arg0;

static void debug_all(const char attr_unused *str)
{
	mem_enable_debugging_option(NULL, 0);
	obj_registry_enable_debugging_option(NULL, 0);
	thread_enable_debugging_option(NULL, 0);
}

static void debug_select(const char *str)
{
	size_t l;
next_param:
	l = strcspn(str, ",");
	if ((unsigned)!mem_enable_debugging_option(str, l) &
	    (unsigned)!obj_registry_enable_debugging_option(str, l) &
	    (unsigned)!thread_enable_debugging_option(str, l))
		warning("invalid debugging option %.*s", (int)l, str);
	if (str[l] == ',') {
		str += l + 1;
		goto next_param;
	}
}

static void profile_all(const char attr_unused *str)
{
	function_enable_profile(NULL, 0);
	mem_al_enable_profile(NULL, 0);
}

static void profile_select(const char *str)
{
	size_t l;
next_param:
	l = strcspn(str, ",");
	if ((unsigned)!function_enable_profile(str, l) &
	    (unsigned)!mem_al_enable_profile(str, l))
		warning("invalid profiling option %.*s", (int)l, str);
	if (str[l] == ',') {
		str += l + 1;
		goto next_param;
	}
}

static void dump_select(const char *str)
{
	size_t l;
	const char *fn;
	l = strcspn(str, "=");
	fn = &str[l];
	if (fn[0])
		fn++;
	if (l == 4 && !strncmp(str, "code", l))
		dump_code = fn;
	else if (l == 5 && !strncmp(str, "pcode", l))
		dump_pcode = fn;
	else if (l == 2 && !strncmp(str, "z3", l))
		dump_z3 = fn;
	else
		warning("invalid dump option %.*s", (int)l, str);
}

static void ipret_set_strict_calls(const char attr_unused *str)
{
	ipret_strict_calls = true;
}

static void ipret_set_privileged(const char attr_unused *str)
{
	ipret_is_privileged = true;
}

static void ipret_set_compile(const char attr_unused *str)
{
	ipret_compile = true;
}

static void ipret_set_verify(const char attr_unused *str)
{
	ipret_verify = true;
}

static void set_noinline(const char attr_unused *str)
{
	ipret_noinline = true;
}

static void set_nosave(const char attr_unused *str)
{
	save_disable = true;
}

#define ARG_SWITCH	0
#define ARG_STRING	1
#define ARG_NUMBER	2

struct arg {
	const char *str;
	uchar_efficient_t mode;
	void (*handler)(const char *str);
	uint32_t *val;
	uint32_t min;
	uint32_t max;
};

static const struct arg args[] = {
	{ "--compile",			ARG_SWITCH,	ipret_set_compile,		NULL,			0, 0 },
	{ "--debug",			ARG_SWITCH,	debug_all,			NULL,			0, 0 },
	{ "--debug=",			ARG_STRING,	debug_select,			NULL,			0, 0 },
	{ "--dump-",			ARG_STRING,	dump_select,			NULL,			0, 0 },
	{ "--noinline",			ARG_SWITCH,	set_noinline,			NULL,			0, 0 },
	{ "--nosave",			ARG_SWITCH,	set_nosave,			NULL,			0, 0 },
	{ "--privileged",		ARG_SWITCH,	ipret_set_privileged,		NULL,			0, 0 },
	{ "--profile",			ARG_SWITCH,	profile_all,			NULL,			0, 0 },
	{ "--profile=",			ARG_STRING,	profile_select,			NULL,			0, 0 },
	{ "--ptrcomp",			ARG_SWITCH,	mem_al_set_ptrcomp,		NULL,			0, 0 },
	{ "--strict-calls",		ARG_SWITCH,	ipret_set_strict_calls,		NULL,			0, 0 },
	{ "--system-malloc",		ARG_SWITCH,	mem_al_set_system_malloc,	NULL,			0, 0 },
	{ "--thread-tick",		ARG_SWITCH,	NULL,				&thread_tick,		0, 0 },
	{ "--threads=",			ARG_NUMBER,	NULL,				&nr_cpus_override,	1, (unsigned)-1 },
	{ "--tick=", 			ARG_NUMBER,	NULL,				&tick_us,		1, (uint32_t)-1 },
	{ "--verify",			ARG_SWITCH,	ipret_set_verify,		NULL,			0, 0 },
};

static void process_arg(const char *arg)
{
	const struct arg *a;
	for (a = args; a < args + n_array_elements(args); a++) {
		size_t sl = strlen(a->str);
		switch (a->mode) {
			case ARG_SWITCH:
				if (!strcmp(arg, a->str)) {
					if (a->handler)
						a->handler(NULL);
					else
						*a->val = 1;
					return;
				}
				break;
			case ARG_STRING:
				if (!strncmp(arg, a->str, sl)) {
					const char *val = arg + sl;
					a->handler(val);
					return;
				}
				break;
			case ARG_NUMBER:
				if (!strncmp(arg, a->str, sl)) {
					unsigned long num;
					char *endptr;
					const char *val = arg + sl;
					if (!*val)
						goto inv;
					num = strtoul(val, &endptr, 10);
					if (*endptr)
						goto inv;
					if ((uint32_t)num != num || num < a->min || num > a->max)
						goto inv;
					*a->val = num;
					return;
				}
				break;
			default:
				internal(file_line, "process_arg: unknown mode %u", a->mode);
		}
	}
inv:
	fatal("invalid argument '%s'", arg);
}

void args_init(int argc, const char * const argv[])
{
	int i;
	const char *env;
	if (unlikely(!argc))
		fatal("the argument 0 is not present");
	arg0 = argv[0];
	if ((env = getenv("AJLA_OPTIONS"))) {
		while (1) {
			size_t len = strcspn(env, " 	");
			if (len) {
				char *a = malloc(len + 1);
				if (unlikely(!a))
					fatal("malloc failed");
				*(char *)mempcpy(a, env, len) = 0;
				process_arg(a);
				free(a);
			}
			env += len;
			if (!*env)
				break;
			env++;
		}
	}
	for (i = 1; i < argc; i++) {
		if (likely(argv[i][0] != '-'))
			break;
		if (argv[i][0] == '-' && argv[i][1] == '-' && !argv[i][2]) {
			i++;
			break;
		}
		process_arg(argv[i]);
	}
	args_left = argv + i;
	n_args_left = argc - i;
	if (!n_args_left) {
		program_name = "";
	} else {
		const char *p;
		program_name = args_left[0];
		for (p = program_name; *p; p++) {
			if (unlikely(os_is_path_separator(*p)))
				program_name = p + 1;
		}
	}
}

void args_done(void)
{
}
