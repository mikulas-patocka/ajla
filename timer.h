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

#ifndef AJLA_TIMER_H
#define AJLA_TIMER_H

#include "thread.h"

#if defined(OS_OS2) || defined(OS_WIN32)
#define TIMER_THREAD
#endif

bool timer_register_wait(ajla_time_t mt, mutex_t **mutex_to_lock, struct list *list_entry, ajla_error_t *err);
#ifndef TIMER_THREAD
uint32_t timer_wait_now(void);
void timer_check_all(void);
#endif

void timer_init(void);
void timer_done(void);

#endif
