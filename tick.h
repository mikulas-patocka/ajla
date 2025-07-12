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

#ifndef AJLA_TICK_H
#define AJLA_TICK_H

#if defined(HAVE_TIMER_CREATE) && defined(HAVE_STRUCT_SIGEVENT)
#define USE_TIMER_CREATE
#endif

/* Cygwin has bugs in signal-vs-thread interactions */
#if defined(HAVE_SIGNAL_H) && defined(HAVE_SETITIMER) && defined(HAVE_SIGACTION) && defined(HAVE_SIGSET_T) && !defined(__CYGWIN__)
#define USEABLE_SIGNAL
#endif

/*
 * If we don't have timer_create, we use setitimer. Unfortunatelly, there is no
 * way to stop setitimer (because it is sometimes implemented incorrectly
 * per-thread, not per-process).
 *
 * So we'd better fallback to a timer thread (that is stoppable), to reduce CPU
 * consumption when we are idle.
 */
#if defined(USEABLE_SIGNAL) && !defined(THREAD_NONE) && !defined(USE_TIMER_CREATE)
#undef USEABLE_SIGNAL
#endif

extern uint32_t tick_us;
extern bool thread_tick;

typedef unsigned tick_stamp_t;
extern atomic_type tick_stamp_t *tick_stamp_ptr;
#define tick_start(state)	(*(state) = load_relaxed(&tick_stamp))
#define tick_elapsed(state)	(unlikely(*(state) != load_relaxed(&tick_stamp)))

void tick_suspend(void);
void tick_resume(void);

void tick_init(void);
void tick_done(void);

#endif
