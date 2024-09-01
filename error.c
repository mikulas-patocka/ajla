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

#include "thread.h"
#include "os.h"

#include <stdio.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define ERROR_MSG_LENGTH	256

#ifdef NEED_EXPLICIT_ALIASING_BARRIER
volatile char alias_val;
volatile char * volatile alias_ptr = &alias_val;
#endif

#include "error.inc"

#ifdef DEBUG_TRACE
static FILE *trace_file = NULL;
#endif

struct error_tls {
	char msg[ERROR_MSG_LENGTH];
	tls_destructor_t destructor;
};
static struct error_tls thread1;
static tls_decl(struct error_tls *, error_tls);
bool error_threads_initialized;

static void error_per_thread_destructor(tls_destructor_t *destr)
{
	struct error_tls *t = get_struct(destr, struct error_tls, destructor);
	free(t);
}

static char *get_error_tls(void)
{
	static struct error_tls *t;
	if (unlikely(!error_threads_initialized))
		return thread1.msg;
	t = tls_get(struct error_tls *, error_tls);
	if (likely(t != NULL))
		return t->msg;
	t = malloc(sizeof(struct error_tls));
	if (unlikely(!t))
		return thread1.msg;
	tls_set(struct error_tls *, error_tls, t);
	tls_destructor(&t->destructor, error_per_thread_destructor);
	return t->msg;
}

const char attr_cold *error_decode(ajla_error_t error)
{
	const char *e;
	char *msg;
	const char *const_msg;
	const_msg = os_decode_error(error, get_error_tls);
	if (unlikely(const_msg != NULL))
		return const_msg;
	switch (error.error_type) {
		case AJLA_ERROR_SYSTEM: {
			if (unlikely(error.error_aux < SYSTEM_ERROR_BASE) ||
			    unlikely(error.error_aux >= SYSTEM_ERROR_N))
				break;
			return system_error_codes[error.error_aux - SYSTEM_ERROR_BASE];
		}
		case AJLA_ERROR_ERRNO: {
#ifdef HAVE_STRERROR_R
			uintptr_t r;
			msg = get_error_tls();
			r = (uintptr_t)strerror_r(error.error_aux, msg, ERROR_MSG_LENGTH);
			if (r >= 4096) {
				return num_to_ptr(r);
			} else {
				if (likely(!r))
					return msg;
				goto def;
			}
#else
			e = strerror(error.error_aux);
			if (unlikely(!e))
				e = "Unknown error";
			return e;
#endif
		}
		case AJLA_ERROR_SUBPROCESS: {
			msg = get_error_tls();
			if (error.error_aux < 0x100)
				sprintf(msg, "Subprocess returned an error: %d", error.error_aux);
			else
				sprintf(msg, "Subprocess terminated by a signal: %d", error.error_aux - 0x200);
			return msg;
		}
#ifdef HAVE_STRERROR_R
		def:
#endif
		default: {
			e = error_ajla_decode(error.error_type);
			if (unlikely(!e))
				break;
			if (!error.error_aux) {
				return e;
			} else {
				msg = get_error_tls();
				sprintf(msg, "%s: %d", e, error.error_aux);
				return msg;
			}
		}
	}
	msg = get_error_tls();
	sprintf(msg, "invalid error code: %d, %d, %d", error.error_class, error.error_type, error.error_aux);
	return msg;
}

static char * attr_cold highlight(bool attr_unused on)
{
#if !(defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32))
#ifdef HAVE_ISATTY
	if (isatty(2))
		return on ? "\033[1m" : "\033[0m";
#endif
#endif
	return "";
}

static attr_noreturn attr_cold force_dump(void)
{
	(void)fprintf(stderr, "\n%sForcing core dump%s\n", highlight(true), highlight(false));
	(void)fflush(stdout);
	(void)fflush(stderr);
#ifdef DEBUG_TRACE
	if (trace_file)
		fflush(trace_file);
#endif
#if defined(HAVE_SIGNAL_H) && defined(HAVE_RAISE) && !defined(__EMX__)
	(void)raise(SIGSEGV);
#else
	*(int *)BAD_POINTER_1 = 0;
	*(int *)num_to_ptr((uintptr_t)-1) = 0;
#endif
	exit(127);
}

static void attr_cold print_msg(FILE *f, const char *m, va_list l, const char *pfx, ...)
{
	va_list pfx_l;
	char attr_unused buffer[4096];
#ifdef OS_OS2
	if (f == stderr) {
		size_t i, j;
		ULONG wrt;
		va_start(pfx_l, pfx);
		vsnprintf(buffer, sizeof buffer, pfx, pfx_l);
		va_end(pfx_l);
		DosWrite(2, buffer, strlen(buffer), &wrt);
		vsnprintf(buffer, sizeof buffer, m, l);
		for (i = 0; buffer[i]; i++) {
			for (j = i; buffer[j] && buffer[j] != '\n'; j++);
			DosWrite(2, buffer + i, j - i, &wrt);
			DosWrite(2, "\r\n", 2, &wrt);
			i = j;
			if (!buffer[i])
				break;
		}
		return;
	}
#endif
#ifdef HAVE_VSNPRINTF
	va_start(pfx_l, pfx);
	vsnprintf(buffer, sizeof buffer, pfx, pfx_l);
	va_end(pfx_l);
	if (strlen(buffer) + strlen(m) + 2 <= sizeof(buffer)) {
		strcat(buffer, m);
		strcat(buffer, "\n");
		(void)vfprintf(f, buffer, l);
		return;
	}
#endif
	va_start(pfx_l, pfx);
	(void)vfprintf(f, pfx, pfx_l);
	va_end(pfx_l);
	(void)vfprintf(f, m, l);
	(void)fprintf(f, "\n");
}

#ifdef DEBUG_TRACE
void attr_cold trace_v(const char *m, va_list l)
{
	if (!trace_file)
		return;
	print_msg(trace_file, m, l, "TRACE(%d): ", thread_get_id());
	fflush(trace_file);
}
#endif

void attr_cold stderr_msg_v(const char *m, va_list l)
{
	print_msg(stderr, m, l, "");
}

void attr_cold debug_v(const char *m, va_list l)
{
	print_msg(stderr, m, l, "DEBUG MESSAGE: ");
}

void attr_cold warning_v(const char *m, va_list l)
{
	print_msg(stderr, m, l, "WARNING: ");
}

attr_noreturn attr_cold fatal_v(const char *m, va_list l)
{
	print_msg(stderr, m, l, "%sFATAL ERROR%s: ", highlight(true), highlight(false));
	exit(127);
}

attr_noreturn attr_cold internal_v(const char *position, const char *m, va_list l)
{
	print_msg(stderr, m, l, "%sINTERNAL ERROR%s at %s: ", highlight(true), highlight(false), position);
	force_dump();
}


void error_init_multithreaded(void)
{
	tls_init(struct error_tls *, error_tls);
	tls_set(struct error_tls *, error_tls, &thread1);
	error_threads_initialized = true;
}

void error_done_multithreaded(void)
{
	error_threads_initialized = false;
	tls_done(struct error_tls *, error_tls);
}


void error_init(void)
{
#ifdef SIGPIPE
	{
		void (*ret)(int);
		EINTR_LOOP_VAL(ret, SIG_ERR, signal(SIGPIPE, SIG_IGN));
		if (ret == SIG_ERR) {
			int er = errno;
			warning("signal(SIGPIPE, SIG_IGN) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	}
#endif
#ifdef SIGXFSZ
	{
		void (*ret)(int);
		EINTR_LOOP_VAL(ret, SIG_ERR, signal(SIGXFSZ, SIG_IGN));
		if (ret == SIG_ERR) {
			int er = errno;
			warning("signal(SIGXFSZ, SIG_IGN) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	}
#endif
	if (unlikely(AJLA_ERROR_N - AJLA_ERROR_BASE != (int)n_array_elements(error_codes)))
		internal(file_line, "error_init: error definitions do not match: %d != %d", AJLA_ERROR_N - AJLA_ERROR_BASE, (int)n_array_elements(error_codes));
	if (unlikely(SYSTEM_ERROR_N - SYSTEM_ERROR_BASE != (int)n_array_elements(system_error_codes)))
		internal(file_line, "error_init: system error definitions do not match: %d != %d", SYSTEM_ERROR_N - SYSTEM_ERROR_BASE, (int)n_array_elements(system_error_codes));
#if defined(HAVE_SETVBUF) && defined(__MINGW32__)
	/*
	 * When we spawn mingw binary from cygwin ssh session, stderr is
	 * bufferred even if it shouldn't be. We need to disable bufferring
	 * explicitly.
	 */
	setvbuf(stderr, NULL, _IONBF, 0);
#endif
#if 0
	ULONG resp;
	HAB os2_hab;
	HMQ os2_hmq;
	os2_hab = WinInitialize(0);
	os2_hmq = WinCreateMsgQueue(os2_hab, 0);
	resp = WinMessageBox(HWND_DESKTOP, HWND_DESKTOP, "text", "caption", 0, MB_OK | MB_ERROR | MB_APPLMODAL | MB_MOVEABLE);
	debug("response: %lu", resp);
#endif
#ifdef DEBUG_TRACE
	if (!getenv("AJLA_NO_TRACE"))
		trace_file = fopen("ajla.tr", "w");
#if defined(HAVE_SETVBUF)
	if (0 && trace_file)
		setvbuf(trace_file, NULL, _IONBF, 0);
#endif
#endif
}

void error_done(void)
{
#ifdef DEBUG_TRACE
	if (trace_file)
		fclose(trace_file);
#endif
}
