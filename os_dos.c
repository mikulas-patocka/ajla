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

#ifdef OS_DOS

#include "mem_al.h"
#include "str.h"

#include "os.h"

#include <unistd.h>
#include <conio.h>
#include <bios.h>
#include <dpmi.h>
#include <process.h>
#include <dir.h>
/*#include <sys/farptr.h>*/

#ifndef wake_up_wait_list
void u_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, unsigned spawn_mode);
void c_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, unsigned spawn_mode);
#endif

static bool have_ntvdm;
static int dos_charset;
static struct console_read_packet pkt;
static bool have_pkt;
static struct list packet_wait_list;
static mutex_t packet_mutex;

static int8_t dos_mouse_initialized;
static uint8_t dos_mouse_n_buttons;
static unsigned short dos_mouse_last_x;
static unsigned short dos_mouse_last_y;
static unsigned short dos_mouse_last_buttons;

static struct console_read_packet *mouse_events;
size_t n_mouse_events;

static bool dos_mouse_init(void)
{
	__dpmi_regs r;

	if (dos_mouse_initialized)
		return dos_mouse_initialized == 1;

	memset(&r, 0, sizeof(__dpmi_regs));
	__dpmi_int(0x33, &r);
	if (r.x.ax != 0xffff) {
		dos_mouse_initialized = -1;
		return false;
	}
	dos_mouse_n_buttons = r.x.bx == 3 ? 3 : 2;
	dos_mouse_initialized = 1;

	memset(&r, 0, sizeof(__dpmi_regs));
	r.x.ax = 7;
	r.x.cx = 0;
	r.x.dx = ScreenCols() * 8 - 1;
	__dpmi_int(0x33, &r);

	memset(&r, 0, sizeof(__dpmi_regs));
	r.x.ax = 8;
	r.x.cx = 0;
	r.x.dx = ScreenRows() * 8 - 1;
	__dpmi_int(0x33, &r);

	r.x.ax = 3;
	__dpmi_int(0x33, &r);
	dos_mouse_last_x = r.x.cx / 8;
	dos_mouse_last_y = r.x.dx / 8;
	dos_mouse_last_buttons = r.x.bx;

	return true;
}

static void dos_enqueue_mouse_packet(unsigned short x, unsigned short y, unsigned short buttons)
{
	ajla_error_t sink;
	struct console_read_packet mouse_packet;
	void *errp;

	memset(&mouse_packet, 0, sizeof(struct console_read_packet));
	mouse_packet.type = 2;
	mouse_packet.u.m.x = x;
	mouse_packet.u.m.y = y;
	mouse_packet.u.m.prev_buttons = dos_mouse_last_buttons;
	mouse_packet.u.m.buttons = buttons;

	if (n_mouse_events) {
		struct console_read_packet *last = &mouse_events[n_mouse_events - 1];
		if (last->u.m.buttons == last->u.m.prev_buttons)
			n_mouse_events--;
	}

	if (unlikely(!array_add_mayfail(struct console_read_packet, &mouse_events, &n_mouse_events, mouse_packet, &errp, &sink))) {
		mouse_events = errp;
		return;
	}

	dos_mouse_last_x = x;
	dos_mouse_last_y = y;
	dos_mouse_last_buttons = buttons;
}

static void dos_mouse_poll(void)
{
	size_t i;
	unsigned short x, y;
	__dpmi_regs r;

	for (i = 0; i < dos_mouse_n_buttons; i++) {
		memset(&r, 0, sizeof(__dpmi_regs));
		r.x.ax = !(dos_mouse_last_buttons & (1 << i)) ? 5 : 6;
		r.x.bx = i;
		__dpmi_int(0x33, &r);
		if (r.x.bx)
			dos_enqueue_mouse_packet(r.x.cx / 8, r.x.dx / 8, dos_mouse_last_buttons ^ (1 << i));
	}

	memset(&r, 0, sizeof(__dpmi_regs));
	r.x.ax = 3;
	__dpmi_int(0x33, &r);
	x = r.x.cx / 8;
	y = r.x.dx / 8;

	if (x != dos_mouse_last_x || y != dos_mouse_last_y)
		dos_enqueue_mouse_packet(x, y, dos_mouse_last_buttons);
}

static void dos_mouse_set_visibility(bool visible)
{
	if (dos_mouse_initialized == 1) {
		__dpmi_regs r;
		memset(&r, 0, sizeof(__dpmi_regs));
		r.x.ax = visible ? 1 : 2;
		__dpmi_int(0x33, &r);
	}
}

bool dos_poll_devices(void)
{
	if (dos_mouse_initialized == 1) {
		dos_mouse_poll();
	}

	if (!list_is_empty(&packet_wait_list) && !have_pkt) {
		int k;

		if (dos_mouse_init() && n_mouse_events) {
			mutex_lock(&packet_mutex);
			memcpy(&pkt, mouse_events, sizeof(struct console_read_packet));
			have_pkt = true;
			memmove(mouse_events, mouse_events + 1, (n_mouse_events - 1) * sizeof(struct console_read_packet));
			n_mouse_events--;
			call(wake_up_wait_list)(&packet_wait_list, &packet_mutex, TASK_SUBMIT_MAY_SPAWN);
			return true;
		}

		if (!bioskey(0x11)) {
			/*
			 * This is very strange. It fixes some lockups in NTVDM
			 * if we are holding a key for a few minutes
			 */
			if (have_ntvdm) {
				mutex_lock(&packet_mutex);
				call(wake_up_wait_list)(&packet_wait_list, &packet_mutex, TASK_SUBMIT_MAY_SPAWN);
			}
			return false;
		}
		k = bioskey(0x10);
		/*uint16_t head, tail;
		__asm__("cli");
		head = _farpeekw(0x40, 0x1a);
		tail = _farpeekw(0x40, 0x1c);
		if (head == tail) {
			__asm__("sti");
			mutex_lock(&packet_mutex);
			call(wake_up_wait_list)(&packet_wait_list, &packet_mutex, TASK_SUBMIT_MAY_SPAWN);
			return false;
		}
		k = _farpeekw(0x40, head);
		head += 2;
		if (head == _farpeekw(0x40, 0x82))
			head = _farpeekw(0x40, 0x80);
		_farpokew(0x40, 0x1a, head);
		__asm__("sti");*/
		/*k = 0x50e0;*/
		/*debug("bioskey: %04x", k);*/
		mutex_lock(&packet_mutex);
		memset(&pkt, 0, sizeof(struct console_read_packet));
		pkt.type = 1;
		pkt.u.k.vkey = (k >> 8) & 0xff;
		pkt.u.k.key = k & 0xff;
		pkt.u.k.cp = dos_charset;
		have_pkt = true;
		call(wake_up_wait_list)(&packet_wait_list, &packet_mutex, TASK_SUBMIT_MAY_SPAWN);
		return true;
	}
	return false;
}

void dos_yield(void)
{
	__dpmi_yield();
}

int os_charset(void)
{
	return dos_charset;
}

void dos_wait_on_packet(mutex_t **mutex_to_lock, struct list *list_entry)
{
	*mutex_to_lock = &packet_mutex;
	mutex_lock(&packet_mutex);
	list_add(&packet_wait_list, list_entry);
	if (unlikely(have_pkt)) {
		goto wake_up;
	}
	mutex_unlock(&packet_mutex);
	return;

wake_up:
	call(wake_up_wait_list)(&packet_wait_list, &packet_mutex, TASK_SUBMIT_MAY_SPAWN);
}

ssize_t os_read_console_packet(handle_t attr_unused h, struct console_read_packet *result, ajla_error_t attr_unused *err)
{
	if (have_pkt) {
		memcpy(result, &pkt, sizeof(struct console_read_packet));
		have_pkt = 0;
		return 1;
	}
	return OS_RW_WOULDBLOCK;
}

bool os_write_console_packet(handle_t attr_unused h, struct console_write_packet attr_unused *packet, ajla_error_t *err)
{
	bool mouse_hidden = false;
	uint8_t *buffer = NULL;
	size_t buffer_chars = 0;
	if (unlikely(!isatty(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to use packet console on non-console");
		goto fail;
	}

next:
	switch (packet->type) {
		case 1: {
			break;
		}
		case 2: {
			int x, y;
			unsigned n_chars, i;
			if (!mouse_hidden) {
				dos_mouse_set_visibility(false);
				mouse_hidden = true;
			}
			x = packet->u.c.x;
			y = packet->u.c.y;
			n_chars = packet->u.c.n_chars;
			if (!buffer || n_chars > buffer_chars) {
				if (unlikely(buffer != NULL))
					mem_free(buffer);
				buffer_chars = maximum(maximum(n_chars, buffer_chars * 2), 80);
				buffer = mem_alloc_mayfail(uint8_t *, buffer_chars * 2, err);
				if (unlikely(!buffer))
					goto fail;
			}
			for (i = 0; i < n_chars; i++) {
				buffer[i * 2] = packet->u.c.data[i * 2];
				buffer[i * 2 + 1] = packet->u.c.data[i * 2 + 1];
			}
			if (n_chars) {
				if (unlikely(!puttext(x + 1, y + 1, x + n_chars, y + 1, buffer))) {
					fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "puttext failed");
					goto fail;
				}
			}
			packet = cast_ptr(struct console_write_packet *, &packet->u.c.data[packet->u.c.n_chars * 2]);
			goto next;
		}
		case 3: {
			gotoxy(packet->u.p.x + 1, packet->u.p.y + 1);
			packet = cast_ptr(struct console_write_packet *, &packet->u.p.end);
			goto next;
		}
		case 4: {
			_setcursortype(packet->u.v.v ? _NORMALCURSOR : _NOCURSOR);
			packet = cast_ptr(struct console_write_packet *, &packet->u.v.end);
			goto next;
		}
		default: {
			internal(file_line, "os_write_console_packet: invalid type %d", (int)packet->type);
			break;
		}
	}
	if (mouse_hidden)
		dos_mouse_set_visibility(true);
	if (unlikely(buffer != NULL))
		mem_free(buffer);
	return true;

fail:
	if (mouse_hidden)
		dos_mouse_set_visibility(true);
	if (unlikely(buffer != NULL))
		mem_free(buffer);
	return false;
}

bool os_drives(char **drives, size_t *drives_l, ajla_error_t *err)
{
	unsigned cd, n_drvs, i, j;
	if (unlikely(!array_init_mayfail(char, drives, drives_l, err)))
		return false;
	_dos_getdrive(&cd);
	for (i = 0; i < 26; i++) {
		char str[4] = " :\\";
		str[0] = 'A' + i;
		_dos_setdrive(i + 1, &n_drvs);
		_dos_getdrive(&j);
		j--;
		if (likely(j != i))
			continue;
		if (unlikely(!array_add_multiple_mayfail(char, drives, drives_l, str, 4, NULL, err))) {
			_dos_setdrive(cd, &n_drvs);
			return false;
		}
	}
	_dos_setdrive(cd, &n_drvs);
	return true;
}

struct proc_handle {
	int status;
};

static void dos_revert_handles(int old_std_handles[3])
{
	int i;
	for (i = 0; i < 3; i++) {
		if (old_std_handles[i] >= 0) {
			int r;
			if (unlikely(old_std_handles[i] == i))
				continue;
			EINTR_LOOP(r, dup2(old_std_handles[i], i));
			if (r == -1) {
				int er = errno;
				fatal("can't copy file descriptor %d to %d: %s", old_std_handles[i], i, error_decode(error_from_errno(EC_SYSCALL, er)));
			}
			EINTR_LOOP(r, close(old_std_handles[i]));
		}
	}
}

struct proc_handle *os_proc_spawn(dir_handle_t wd, const char *path, size_t n_handles, handle_t *src, int *target, char * const args[], char *envc, ajla_error_t *err)
{
	int r;
	struct proc_handle *ph;
	char **env;
	size_t env_l;
	int er;
	int old_std_handles[3];
	unsigned i;

	if (unlikely(!array_init_mayfail(char *, &env, &env_l, err)))
		return NULL;
	while (*envc) {
		if (unlikely(!array_add_mayfail(char *, &env, &env_l, envc, NULL, err)))
			return NULL;
		envc = strchr(envc, 0) + 1;
	}
	if (unlikely(!array_add_mayfail(char *, &env, &env_l, NULL, NULL, err)))
		return NULL;

	ph = mem_alloc_mayfail(struct proc_handle *, sizeof(struct proc_handle), err);
	if (unlikely(!ph)) {
		mem_free(env);
		return NULL;
	}

	if (unlikely(!os_set_cwd(wd, err))) {
		mem_free(env);
		mem_free(ph);
		return NULL;
	}

	old_std_handles[0] = old_std_handles[1] = old_std_handles[2] = -1;
	for (i = 0; i < n_handles; i++) {
		handle_t s = src[i];
		int t = target[i];
		int saved_t;
		if (unlikely(t >= 3)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "only the first three handles can be redirected");
			goto redir_error;
		}
		if (old_std_handles[t] != -1) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "redirecting a handle multiple times");
			goto redir_error;
		}
		if (likely(s == t)) {
			old_std_handles[t] = s;
			continue;
		}
		EINTR_LOOP(saved_t, dup(t));
		if (unlikely(saved_t == -1)) {
			ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
			fatal_mayfail(e, err, "can't save handle %d: %s", t, error_decode(e));
			goto redir_error;
		}
		old_std_handles[t] = saved_t;
		if (s < 3 && unlikely(old_std_handles[s] >= 0))
			s = old_std_handles[s];
		EINTR_LOOP(r, dup2(s, t));
		if (unlikely(r == -1)) {
			ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
			fatal_mayfail(e, err, "can't copy handle %d to %d: %s", s, t, error_decode(e));
redir_error:
			os_set_original_cwd();
			dos_revert_handles(old_std_handles);
			mem_free(env);
			mem_free(ph);
			return NULL;
		}
	}

	EINTR_LOOP(r, spawnve(P_WAIT, path, args, env));
	er = errno;
	ph->status = r;

	os_set_original_cwd();
	dos_revert_handles(old_std_handles);
	mem_free(env);

	if (r == -1) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, er);
		fatal_mayfail(e, err, "can't spawn process '%s': %s", path, error_decode(e));
		mem_free(ph);
		return NULL;
	}

	return ph;
}

void os_proc_free_handle(struct proc_handle *ph)
{
	mem_free(ph);
}

bool os_proc_register_wait(struct proc_handle *ph, mutex_t attr_unused **mutex_to_lock, struct list attr_unused *list_entry, int *status)
{
	*status = ph->status;
	return true;
}

void os_proc_check_all(void)
{
}

dir_handle_t os_dir_root(ajla_error_t *err)
{
	char *d = str_dup(" :\\", -1, err);
	if (unlikely(!d))
		return NULL;
	d[0] = getdisk() + 'A';
	return d;
}

void dos_init(void)
{
	__dpmi_regs r;

	dos_mouse_initialized = 0;
	array_init(struct console_read_packet, &mouse_events, &n_mouse_events);

	memset(&r, 0, sizeof(__dpmi_regs));
	r.x.ax = 0x3306;
	__dpmi_int(0x21, &r);
	have_ntvdm = r.h.bl == 0x5 && r.h.bh == 0x32;

	memset(&r, 0, sizeof(__dpmi_regs));
	r.x.ax = 0x6601;
	__dpmi_int(0x21, &r);
	if (!(r.x.flags & 1)) {
		dos_charset = r.x.bx;
	} else {
		dos_charset = 437;
	}

	have_pkt = false;
	list_init(&packet_wait_list);
	mutex_init(&packet_mutex);
}

void dos_done(void)
{
	ajla_assert_lo(list_is_empty(&packet_wait_list), (file_line, "dos_done: packet_wait_list is not empty"));
	mutex_done(&packet_mutex);
	mem_free(mouse_events);
}

#endif
