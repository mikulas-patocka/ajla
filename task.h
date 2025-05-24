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

#ifndef AJLA_TASK_H
#define AJLA_TASK_H

#include "data.h"

#define task_submit		name(task_submit)
#define task_schedule		name(task_schedule)
#define task_ex_control_started	name(task_ex_control_started)
#define task_ex_control_exited	name(task_ex_control_exited)
#define task_program_started	name(task_program_started)
#define task_program_exited	name(task_program_exited)
#define waiting_list_add	name(waiting_list_add)
#define waiting_list_remove	name(waiting_list_remove)
#define waiting_list_break	name(waiting_list_break)

extern uint32_t nr_cpus_override;
extern uint32_t nr_nodes_override;

void attr_fastcall task_submit(struct execution_control *ex, unsigned spawn_mode);

void * attr_fastcall task_schedule(struct execution_control *ex);

void waiting_list_add(struct execution_control *ex);
void waiting_list_remove(struct execution_control *ex);
bool waiting_list_break(void);

#define SUBMIT_EX(ex)						\
do {								\
	if ((ex) != POINTER_FOLLOW_THUNK_EXIT) {		\
		task_submit(ex, TASK_SUBMIT_MAY_SPAWN);		\
	}							\
} while (0)

void task_ex_control_started(void);
void task_ex_control_exited(void);
void task_program_started(void);
void task_program_exited(void);

#endif
