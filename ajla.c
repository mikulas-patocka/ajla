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

#include "args.h"
#include "amalloc.h"
#include "mem_al.h"
#include "obj_reg.h"
#include "os.h"
#include "asm.h"
#include "mpint.h"
#include "thread.h"
#include "addrlock.h"
#include "type.h"
#include "data.h"
#include "arindex.h"
#include "funct.h"
#include "pcode.h"
#include "profile.h"
#include "builtin.h"
#include "save.h"
#include "module.h"
#include "tick.h"
#include "timer.h"
#include "iomux.h"
#include "resolver.h"
#include "task.h"

extern_const bool dll = false;
int retval = 0;

int main(int argc, const char * const argv[])
{
	error_init();
	args_init(argc, argv);
	amalloc_init();
	mem_init();
	obj_registry_init();
	os_init();
	asm_init();
	mpint_init();
	thread_init();
	error_init_multithreaded();
	mem_init_multithreaded();
	obj_registry_init_multithreaded();
	address_lock_init();
	os_init_multithreaded();
	amalloc_init_multithreaded();
	type_init();
	data_init();
	array_index_init();
	function_init();
	pcode_init();
	profile_init();
	builtin_init();
	ipio_init();
	save_init();
	module_init();
	ipret_init();
	tick_init();
	timer_init();
	iomux_init();
	resolver_init();
	task_init();

	bist();

	program_run();

	task_run();

	task_done();
	resolver_done();
	iomux_done();
	timer_done();
	tick_done();
	ipret_done();
	module_done();
	save_done();
	ipio_done();
	builtin_done();
	profile_done();
	pcode_done();
	function_done();
	array_index_done();
	data_done();
	type_done();
	amalloc_done_multithreaded();
	os_done_multithreaded();
	address_lock_done();
	obj_registry_done_multithreaded();
	mem_done_multithreaded();
	error_done_multithreaded();
	thread_done();
	mpint_done();
	asm_done();
	os_done();
	obj_registry_done();
	mem_done();
	amalloc_done();
	args_done();
	error_done();

	return retval;
}
