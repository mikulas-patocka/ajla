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

#include "mem_al.h"
#include "profile.h"
#include "os.h"

#include "args.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

chicken_mask_t chicken = 0;

const char *dump_code = NULL;
const char *dump_opencl = NULL;
const char *dump_pcode = NULL;
const char *dump_z3 = NULL;
const char *verify = NULL;

bool help = false;
bool ipret_strict_calls = false;
bool ipret_is_privileged = false;
bool ipret_sandbox = false;
bool ipret_compile = false;
bool ipret_compile_run = false;
bool ipret_noinline = false;
bool ipret_verify_light = false;
uint32_t ipret_verify_timeout = 0;
bool ipret_warnings = false;
uint32_t ipret_opencl_device = 0;

bool optimize_int = false;

bool save_disable = false;
bool thread_tick = false;
uint32_t tick_us = DEFAULT_TICK_US;

uint32_t nr_cpus_override = 0;
uint32_t nr_nodes_override = 0;

const char * const * args_left;
int n_args_left;
const char *program_name;
const char *arg0;

static void chicken_select(const char *str)
{
	size_t l;
next_param:
	l = strcspn(str, ",");
	if (l == 2 && !strncmp(str, "cg", l))
		chicken |= CHICKEN_CG;
	else if (l == 13 && !strncmp(str, "cg-flag-cache", l))
		chicken |= CHICKEN_CG_FLAG_CACHE;
	else if (l == 15 && !strncmp(str, "cg-must-be-flat", l))
		chicken |= CHICKEN_CG_MUST_BE_FLAT;
	else if (l == 15 && !strncmp(str, "cg-must-be-data", l))
		chicken |= CHICKEN_CG_MUST_BE_DATA;
	else if (l == 5 && !strncmp(str, "cg-ra", l))
		chicken |= CHICKEN_CG_RA;
	else if (l == 11 && !strncmp(str, "cg-optimize", l))
		chicken |= CHICKEN_CG_OPTIMIZE;
	else if (l == 8 && !strncmp(str, "cg-traps", l))
		chicken |= CHICKEN_CG_TRAPS;
	else
		warning("invalid chicken option %.*s", (int)l, str);
	if (str[l] == ',') {
		str += l + 1;
		goto next_param;
	}
}

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
	else if (l == 6 && !strncmp(str, "opencl", l))
		dump_opencl = fn;
	else if (l == 5 && !strncmp(str, "pcode", l))
		dump_pcode = fn;
	else if (l == 2 && !strncmp(str, "z3", l))
		dump_z3 = fn;
	else
		warning("invalid dump option %.*s", (int)l, str);
}

static void verify_all(const char attr_unused *str)
{
	verify = "";
}

static void verify_select(const char *str)
{
	verify = str;
}

#define ARG_SWITCH	0
#define ARG_SWITCH_OFF	1
#define ARG_STRING	2
#define ARG_NUMBER	3

struct arg {
	const char *str;
	uchar_efficient_t mode;
	void (*handler)(const char *str);
	void *val;
	uint32_t min;
	uint32_t max;
};

static const struct arg args[] = {
	{ "--chicken=",			ARG_STRING,	chicken_select,			NULL,			0, 0 },
	{ "--compile",			ARG_SWITCH,	NULL,				&ipret_compile,		0, 0 },
	{ "--compile-run",		ARG_SWITCH,	NULL,				&ipret_compile_run,	0, 0 },
	{ "--debug",			ARG_SWITCH,	debug_all,			NULL,			0, 0 },
	{ "--debug=",			ARG_STRING,	debug_select,			NULL,			0, 0 },
	{ "--dump-",			ARG_STRING,	dump_select,			NULL,			0, 0 },
	{ "--help",			ARG_SWITCH,	NULL,				&help,			0, 0 },
	{ "--noinline",			ARG_SWITCH,	NULL,				&ipret_noinline,	0, 0 },
	{ "--nosave",			ARG_SWITCH,	NULL,				&save_disable,		0, 0 },
	{ "--numa-nodes=",		ARG_NUMBER,	NULL,				&nr_nodes_override,	1, (unsigned)-1 },
	{ "--opencl-device=",		ARG_NUMBER,	NULL,				&ipret_opencl_device,	0, signed_maximum(uint32_t) },
	{ "--optimize-fp",		ARG_SWITCH_OFF,	NULL,				&optimize_int,		0, 0 },
	{ "--optimize-int",		ARG_SWITCH,	NULL,				&optimize_int,		0, 0 },
	{ "--privileged",		ARG_SWITCH,	NULL,				&ipret_is_privileged,	0, 0 },
	{ "--profile",			ARG_SWITCH,	profile_all,			NULL,			0, 0 },
	{ "--profile=",			ARG_STRING,	profile_select,			NULL,			0, 0 },
	{ "--ptrcomp",			ARG_SWITCH,	mem_al_set_ptrcomp,		NULL,			0, 0 },
	{ "--sandbox",			ARG_SWITCH,	NULL,				&ipret_sandbox,		0, 0 },
	{ "--strict-calls",		ARG_SWITCH,	NULL,				&ipret_strict_calls,	0, 0 },
	{ "--system-malloc",		ARG_SWITCH,	mem_al_set_system_malloc,	NULL,			0, 0 },
	{ "--thread-tick",		ARG_SWITCH,	NULL,				&thread_tick,		0, 0 },
	{ "--threads=",			ARG_NUMBER,	NULL,				&nr_cpus_override,	1, (unsigned)-1 },
	{ "--tick=", 			ARG_NUMBER,	NULL,				&tick_us,		1, (uint32_t)-1 },
	{ "--verify",			ARG_SWITCH,	verify_all,			NULL,			0, 0 },
	{ "--verify=",			ARG_STRING,	verify_select,			NULL,			0, 0 },
	{ "--verify-light",		ARG_SWITCH,	NULL,				&ipret_verify_light,	0, 0 },
	{ "--verify-timeout=",		ARG_NUMBER,	NULL,				&ipret_verify_timeout,	0, signed_maximum(int32_t) },
	{ "--warnings",			ARG_SWITCH,	NULL,				&ipret_warnings,	0, 0 },
};

static const char *help_strings[] = {
"Ajla "AJLA_VERSION"",
"","\
--chicken=features	disable the specified comma-separated features","\
	cg		disable the code generator and only use the interpreter","\
	cg-flag-cache	disable the flag cache","\
	cg-must-be-flat	disable the optimization for flat variables","\
	cg-must-be-data	disable the optimization for data variables","\
	cg-ra		disable the register allocator","\
	cg-optimize	disable the machine code optimizer","\
	cg-traps	disable traps on architectures that use them","\
--compile		compile the whole program and don't run it","\
--compile-run		compile the whole program and run it","\
--debug			enable all debugging options","\
--debug=features	enable specific comma-separated debugging features","\
	magic		put magic number before all allocations","\
	redzone		put magic number after all allocations","\
	fill		fill memory block on allocation and freeing","\
	leak		identify memory leaks","\
	memory		enable magic, redzone, fill, leak","\
	mutex		enable mutex debugging","\
	mutex-errorcheck use the errorcheck attribute on mutexes","\
	cond		enable condition variable debugging","\
	thread		enable thread debugging","\
	handles		enable handle debugging","\
	objects		enable mutex, mutex-errorcheck, cond, thread, handles","\
--dump-code		write the generated machine code to \"dump.s\"","\
--dump-opencl		write the generated OpenCL code to stderr","\
--dump-pcode		write the generated pcode code to stderr","\
--dump-z3		write the generated z3 assertions to stderr","\
--help			display help","\
--noinline		disable automatic inlining","\
--nosave		do not save and load the compiled program","\
--numa_node=x		override the number of numa nodes to \"x\"","\
--opencl-device=x	use the OpenCL device with index \"x\"","\
--optimize-fp		optimize for floating point calculations (default)","\
--optimize-int		optimize for integer calculations","\
--profile		enable all profilng options","\
--profile=features	enable specified comma-separated profiling features","\
	function	print functions that consumed most CPUs","\
	escape		print positions where the code escaped from interpreter","\
	memory		print places where most memory was allocated","\
--ptrcomp		enable pointer compression","\
--sandbox		do not allow opening files or other unsafe operations","\
--strict-calls		disable automatic parallelization","\
--system-malloc		use the system malloc instead of Ajla malloc","\
--thread-tick		use a thread instead of a signal for timer ticks","\
--threads=x		override the number of CPUs to \"x\"","\
--tick=x		tick interval in microseconds (default 10000)","\
--verify		verify the program using z3","\
--verify-timeout=x	a timeout to verify a function in microseconds","\
--warnings		enable warnings in the OpenCL code" };

static void process_arg(const char *arg)
{
	const struct arg *a;
	for (a = args; a < args + n_array_elements(args); a++) {
		size_t sl = strlen(a->str);
		switch (a->mode) {
			case ARG_SWITCH:
			case ARG_SWITCH_OFF:
				if (!strcmp(arg, a->str)) {
					if (a->handler)
						a->handler(NULL);
					else
						*cast_ptr(bool *, a->val) = a->mode == ARG_SWITCH;
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
					*cast_ptr(uint32_t *, a->val) = num;
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

static void process_line_args(const char *line)
{
	while (1) {
		size_t len = strcspn(line, " 	");
		if (len) {
			char *a = malloc(len + 1);
			if (unlikely(!a))
				fatal("malloc failed");
			*(char *)mempcpy(a, line, len) = 0;
			process_arg(a);
			free(a);
		}
		line += len;
		if (!*line)
			break;
		line++;
	}
}

static void process_file_args(const char *file)
{
	int h;
	size_t position, size;
	ssize_t r;
	char *buffer, *nl;
	EINTR_LOOP(h, open(file, O_RDONLY));
	if (unlikely(h == -1))
		return;

	position = 0;
	size = 128;

	buffer = malloc(size);
	if (unlikely(!buffer))
		fatal("malloc failed");

again:
	EINTR_LOOP(r, read(h, buffer + position, size - position));
	if (unlikely(r < 0))
		goto close_ret;

	position += r;
new_line:
	nl = memchr(buffer, '\n', position);
	if (!nl) {
		if (unlikely(!r))
			goto close_ret;
		if (position == size) {
			size *= 2;
			if (unlikely(!size))
				fatal("size wrap around");
			buffer = realloc(buffer, size);
			if (unlikely(!buffer))
				fatal("realloc failed");
		}
		goto again;
	}
	*nl = 0;
	if (buffer[0] == '#') {
		memmove(buffer, nl + 1, position - (nl + 1 - buffer));
		position -= nl + 1 - buffer;
		goto new_line;
	}
	if (!strncmp(buffer, "// flags: ", 10)) {
		/*debug("\"%s\"", buffer + 10);*/
		process_line_args(buffer + 10);
	}

close_ret:
	free(buffer);
	close(h);
}

void args_init(int argc, const char * const argv[])
{
	int i;
	const char *env;
	if (unlikely(!argc))
		fatal("the argument 0 is not present");
	arg0 = argv[0];
	if ((env = getenv("AJLA_OPTIONS"))) {
		process_line_args(env);
	}
	for (i = 1; i < argc; i++) {
		if (likely(argv[i][0] != '-'))
			break;
		if (argv[i][0] == '-' && argv[i][1] == '-' && !argv[i][2]) {
			i++;
			break;
		}
	}
	if (i < argc) {
		process_file_args(argv[i]);
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
	if (unlikely(help)) {
		for (i = 0; i < (int)n_array_elements(help_strings); i++)
			puts(help_strings[i]);
		exit(0);
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
	if (unlikely(ipret_is_privileged) && unlikely(ipret_sandbox))
		fatal("the flags '--privileged' and '--sandbox' contradict each other");
}

void args_done(void)
{
}
