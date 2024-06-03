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

#ifdef OS_OS2

#include "str.h"
#include "list.h"
#include "tree.h"
#include "thread.h"
#include "addrlock.h"
#include "obj_reg.h"
#include "os_util.h"

#include "os.h"
#include "iomux.h"

#define TCPIPV4
#define MAXSOCKETS			2048

#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/so_ioctl.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>

#define OS2_PIPE_SIZE			4096
#define OS2_BUFFER_SIZE			4096
#define OS2_PACKET_BUFFER_SIZE		4096
#define OS2_IO_THREAD_STACK_SIZE	65536
#define OS2_MAX_HANDLE			32768

#ifndef wake_up_wait_list
void u_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory);
void c_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory);
#endif

struct os2_io_thread {
	TID thread;
	HEV event;
	char *buffer;
	size_t buffer_pos;
	size_t buffer_len;
	APIRET err;
	bool eof;
	bool should_close;
	bool packet_mode;
	bool packet_is_queued;
	unsigned char last_buttons;
	bool fullscreen;
	HMOU mh;
	struct console_read_packet pkt;
	struct list wait_list;
	struct list socket_entry;
	handle_t h;
};

struct os2_handle {
	HFILE h;
	bool packet_mode;
	unsigned char t;
	char disk;
	int flags;

	struct os2_io_thread rd;
	struct os2_io_thread ms;
	struct os2_io_thread wr;

	struct list deferred_entry;
};

#define HANDTYPE_SOCKET		0xff

#define SOCKADDR_MAX_LEN	512
#define SOCKADDR_ALIGN		16

#include "os_os2_e.inc"
#include "os_com.inc"

#define A_DECL(type, var) type var##1, var##2, *var = _THUNK_PTR_STRUCT_OK(&var##1) ? &var##1 : &var##2

static bool os_threads_initialized;

static unsigned n_std_handles;
static handle_t *os2_std_handles;

dir_handle_t os_cwd;

static struct list deferred_write_list;
static struct list deferred_closed_list;
static mutex_t deferred_mutex;

static struct list socket_list[2];
static mutex_t socket_list_mutex;

static long double freq_period_usec;
static APIRET (*proc_DosTmrQueryFreq)(PULONG) = NULL;
static APIRET (*proc_DosTmrQueryTime)(PQWORD) = NULL;
static APIRET (*proc_DosOpenL)(PSZ, PHFILE, PULONG, long long, ULONG, ULONG, ULONG, PEAOP2) = NULL;
static APIRET (*proc_DosSetFilePtrL)(HFILE, long long, ULONG, long long *);
static APIRET (*proc_DosSetFileSizeL)(HFILE, long long);

static bool tcpip_loaded = false;

static int (*proc_accept)(int, struct sockaddr *, int *);
static int (*proc_bind)(int, struct sockaddr *, int);
static int (*proc_connect)(int, struct sockaddr *, int);
static void *(*proc_gethostbyname)(const char *);
static int (*proc_gethostname)(char *, int);
static int (*proc_getpeername)(int, struct sockaddr *, int *);
static int (*proc_getsockname)(int, struct sockaddr *, int *);
static int (*proc_getsockopt)(int, int, int, void *, int *);
static int (*proc_ioctl)(int, int, void *, int);
static int (*proc_listen)(int, int);
static int (*proc_recv)(int, void *, int, int);
static int (*proc_recvfrom)(int, void *, int, int, struct sockaddr *, int *);
static int (*proc_select)(int *, int, int, int, long);
static int (*proc_send)(int, const void *, int, int);
static int (*proc_sendto)(int, const void *, int, int, const struct sockaddr *, int);
static int (*proc_setsockopt)(int, int, int, const void *, int);
static int (*proc_shutdown)(int, int);
static int (*proc_socket)(int domain, int type, int protocol);
static int (*proc_sock_errno)(void);
static int (*proc_sock_init)(void);
static int (*proc_soclose)(int handle);
static int *proc_h_errno;


struct system_error_table_entry {
	unsigned short errn;
	unsigned short sys_error;
};

static const struct system_error_table_entry os2_error_to_system_error[] = {
	{ ERROR_FILE_NOT_FOUND,		SYSTEM_ERROR_ENOENT },
	{ ERROR_PATH_NOT_FOUND,		SYSTEM_ERROR_ENOENT },
	{ ERROR_TOO_MANY_OPEN_FILES,	SYSTEM_ERROR_EMFILE },
	{ ERROR_ACCESS_DENIED,		SYSTEM_ERROR_EACCES },
	{ ERROR_INVALID_HANDLE,		SYSTEM_ERROR_EBADF },
	{ ERROR_NOT_ENOUGH_MEMORY,	SYSTEM_ERROR_ENOMEM },
	{ ERROR_INVALID_DRIVE,		SYSTEM_ERROR_ENOENT },
	{ ERROR_CURRENT_DIRECTORY,	SYSTEM_ERROR_EBUSY },
	{ ERROR_NOT_SAME_DEVICE,	SYSTEM_ERROR_EXDEV },
	{ ERROR_WRITE_PROTECT,		SYSTEM_ERROR_EROFS },
	{ ERROR_CRC,			SYSTEM_ERROR_EIO },
	{ ERROR_SEEK,			SYSTEM_ERROR_EIO },
	{ ERROR_NOT_DOS_DISK,		SYSTEM_ERROR_EMEDIUMTYPE },
	{ ERROR_SECTOR_NOT_FOUND,	SYSTEM_ERROR_EIO },
	{ ERROR_WRITE_FAULT,		SYSTEM_ERROR_EIO },
	{ ERROR_READ_FAULT,		SYSTEM_ERROR_EIO },
	{ ERROR_GEN_FAILURE,		SYSTEM_ERROR_EIO },
	{ ERROR_SHARING_VIOLATION,	SYSTEM_ERROR_EBUSY },
	{ ERROR_WRONG_DISK,		SYSTEM_ERROR_EMEDIUMTYPE },
	{ ERROR_HANDLE_DISK_FULL,	SYSTEM_ERROR_ENOSPC },
	{ ERROR_SBCS_ATT_WRITE_PROT,	SYSTEM_ERROR_EROFS },
	{ ERROR_FILE_EXISTS,		SYSTEM_ERROR_EEXIST },
	{ ERROR_CANNOT_MAKE,		SYSTEM_ERROR_ENOENT },
	{ ERROR_INTERRUPT,		SYSTEM_ERROR_EINTR },
	{ ERROR_DEVICE_IN_USE,		SYSTEM_ERROR_EBUSY },
	{ ERROR_DRIVE_LOCKED,		SYSTEM_ERROR_EBUSY },
	{ ERROR_BROKEN_PIPE,		SYSTEM_ERROR_EPIPE },
	{ ERROR_OPEN_FAILED,		SYSTEM_ERROR_ENOENT },
	{ ERROR_DISK_FULL,		SYSTEM_ERROR_ENOSPC },
	{ ERROR_NO_MORE_SEARCH_HANDLES,	SYSTEM_ERROR_ENFILE },
	{ ERROR_INVALID_NAME,		SYSTEM_ERROR_ENOENT },
	{ ERROR_SEEK_ON_DEVICE,		SYSTEM_ERROR_ESPIPE },
	{ ERROR_BAD_PATHNAME,		SYSTEM_ERROR_ENOENT },
	{ ERROR_FILENAME_EXCED_RANGE,	SYSTEM_ERROR_ENAMETOOLONG },
	{ ERROR_PIPE_BUSY,		SYSTEM_ERROR_EBUSY },
	{ ERROR_NO_DATA,		SYSTEM_ERROR_EAGAIN },
	{ ERROR_PIPE_NOT_CONNECTED,	SYSTEM_ERROR_ENOTCONN },
	{ ERROR_CIRCULARITY_REQUESTED,	SYSTEM_ERROR_EINVAL },
	{ ERROR_DIRECTORY_IN_CDS,	SYSTEM_ERROR_EBUSY },
	{ ERROR_INVALID_PATH,		SYSTEM_ERROR_ENOENT },
	{ ERROR_TOO_MANY_OPENS,		SYSTEM_ERROR_EMFILE },
};

static ajla_error_t error_from_os2(int ec, APIRET rc)
{
	size_t r;
	binary_search(size_t, n_array_elements(os2_error_to_system_error), r, os2_error_to_system_error[r].errn == rc, os2_error_to_system_error[r].errn < rc, return error_ajla_aux(ec, AJLA_ERROR_OS2, rc));
	return error_ajla_aux(ec, AJLA_ERROR_SYSTEM, os2_error_to_system_error[r].sys_error);
}

static const struct system_error_table_entry socket_error_to_system_error[] = {
	{ SOCEPERM,			SYSTEM_ERROR_EPERM },
	{ SOCENOENT,			SYSTEM_ERROR_ENOENT },
	{ SOCESRCH,			SYSTEM_ERROR_ESRCH },
	{ SOCEINTR,			SYSTEM_ERROR_EINTR },
	{ SOCEIO,			SYSTEM_ERROR_EIO },
	{ SOCENXIO,			SYSTEM_ERROR_ENXIO },
	{ SOCE2BIG,			SYSTEM_ERROR_E2BIG },
	{ SOCENOEXEC,			SYSTEM_ERROR_ENOEXEC },
	{ SOCEBADF,			SYSTEM_ERROR_EBADF },
	{ SOCECHILD,			SYSTEM_ERROR_ECHILD },
	{ SOCEDEADLK,			SYSTEM_ERROR_EDEADLK },
	{ SOCENOMEM,			SYSTEM_ERROR_ENOMEM },
	{ SOCEACCES,			SYSTEM_ERROR_EACCES },
	{ SOCEFAULT,			SYSTEM_ERROR_EFAULT },
	{ SOCENOTBLK,			SYSTEM_ERROR_ENOTBLK },
	{ SOCEBUSY,			SYSTEM_ERROR_EBUSY },
	{ SOCEEXIST,			SYSTEM_ERROR_EEXIST },
	{ SOCEXDEV,			SYSTEM_ERROR_EXDEV },
	{ SOCENODEV,			SYSTEM_ERROR_ENODEV },
	{ SOCENOTDIR,			SYSTEM_ERROR_ENOTDIR },
	{ SOCEISDIR,			SYSTEM_ERROR_EISDIR },
	{ SOCEINVAL,			SYSTEM_ERROR_EINVAL },
	{ SOCENFILE,			SYSTEM_ERROR_ENFILE },
	{ SOCEMFILE,			SYSTEM_ERROR_EMFILE },
	{ SOCENOTTY,			SYSTEM_ERROR_ENOTTY },
	{ SOCETXTBSY,			SYSTEM_ERROR_ETXTBSY },
	{ SOCEFBIG,			SYSTEM_ERROR_EFBIG },
	{ SOCENOSPC,			SYSTEM_ERROR_ENOSPC },
	{ SOCESPIPE,			SYSTEM_ERROR_ESPIPE },
	{ SOCEROFS,			SYSTEM_ERROR_EROFS },
	{ SOCEMLINK,			SYSTEM_ERROR_EMLINK },
	{ SOCEPIPE,			SYSTEM_ERROR_EPIPE },
	{ SOCEDOM,			SYSTEM_ERROR_EDOM },
	{ SOCERANGE,			SYSTEM_ERROR_ERANGE },
	{ SOCEAGAIN,			SYSTEM_ERROR_EAGAIN },
	{ SOCEINPROGRESS,		SYSTEM_ERROR_EINPROGRESS },
	{ SOCEALREADY,			SYSTEM_ERROR_EALREADY },
	{ SOCENOTSOCK,			SYSTEM_ERROR_ENOTSOCK },
	{ SOCEDESTADDRREQ,		SYSTEM_ERROR_EDESTADDRREQ },
	{ SOCEMSGSIZE,			SYSTEM_ERROR_EMSGSIZE },
	{ SOCEPROTOTYPE,		SYSTEM_ERROR_EPROTOTYPE },
	{ SOCENOPROTOOPT,		SYSTEM_ERROR_ENOPROTOOPT },
	{ SOCEPROTONOSUPPORT,		SYSTEM_ERROR_EPROTONOSUPPORT },
	{ SOCESOCKTNOSUPPORT,		SYSTEM_ERROR_ESOCKTNOSUPPORT },
	{ SOCEOPNOTSUPP,		SYSTEM_ERROR_EOPNOTSUPP },
	{ SOCEPFNOSUPPORT,		SYSTEM_ERROR_EPFNOSUPPORT },
	{ SOCEAFNOSUPPORT,		SYSTEM_ERROR_EAFNOSUPPORT },
	{ SOCEADDRINUSE,		SYSTEM_ERROR_EADDRINUSE },
	{ SOCEADDRNOTAVAIL,		SYSTEM_ERROR_EADDRNOTAVAIL },
	{ SOCENETDOWN,			SYSTEM_ERROR_ENETDOWN },
	{ SOCENETUNREACH,		SYSTEM_ERROR_ENETUNREACH },
	{ SOCENETRESET,			SYSTEM_ERROR_ENETRESET },
	{ SOCECONNABORTED,		SYSTEM_ERROR_ECONNABORTED },
	{ SOCECONNRESET,		SYSTEM_ERROR_ECONNRESET },
	{ SOCENOBUFS,			SYSTEM_ERROR_ENOBUFS },
	{ SOCEISCONN,			SYSTEM_ERROR_EISCONN },
	{ SOCENOTCONN,			SYSTEM_ERROR_ENOTCONN },
	{ SOCESHUTDOWN,			SYSTEM_ERROR_ESHUTDOWN },
	{ SOCETOOMANYREFS,		SYSTEM_ERROR_ETOOMANYREFS },
	{ SOCETIMEDOUT,			SYSTEM_ERROR_ETIMEDOUT },
	{ SOCECONNREFUSED,		SYSTEM_ERROR_ECONNREFUSED },
	{ SOCELOOP,			SYSTEM_ERROR_ELOOP },
	{ SOCENAMETOOLONG,		SYSTEM_ERROR_ENAMETOOLONG },
	{ SOCEHOSTDOWN,			SYSTEM_ERROR_EHOSTDOWN },
	{ SOCEHOSTUNREACH,		SYSTEM_ERROR_EHOSTUNREACH },
	{ SOCENOTEMPTY,			SYSTEM_ERROR_ENOTEMPTY },
/*	{ SOCEPROCLIM,			SYSTEM_ERROR_EPROCLIM },	*/
	{ SOCEUSERS,			SYSTEM_ERROR_EUSERS },
	{ SOCEDQUOT,			SYSTEM_ERROR_EDQUOT },
	{ SOCESTALE,			SYSTEM_ERROR_ESTALE },
	{ SOCEREMOTE,			SYSTEM_ERROR_EREMOTE },
/*	{ SOCEBADRPC,			SYSTEM_ERROR_EBADRPC },		*/
/*	{ SOCERPCMISMATCH,		SYSTEM_ERROR_ERPCMISMATCH },	*/
/*	{ SOCEPROGUNAVAIL,		SYSTEM_ERROR_EPROGUNAVAIL },	*/
/*	{ SOCEPROGMISMATCH,		SYSTEM_ERROR_EPROGMISMATCH },	*/
/*	{ SOCEPROCUNAVAIL,		SYSTEM_ERROR_EPROCUNAVAIL },	*/
	{ SOCENOLCK,			SYSTEM_ERROR_ENOLCK },
	{ SOCENOSYS,			SYSTEM_ERROR_ENOSYS },
/*	{ SOCEFTYPE,			SYSTEM_ERROR_EFTYPE },		*/
/*	{ SOCEAUTH,			SYSTEM_ERROR_EAUTH },		*/
/*	{ SOCENEEDAUTH,			SYSTEM_ERROR_ENEEDAUTH },	*/
/*	{ SOCEOS2ERR,			SYSTEM_ERROR_EOS2ERR },		*/
};

static ajla_error_t error_from_os2_socket(void)
{
	size_t r;
	int rc;
	if (unlikely(!tcpip_loaded)) {
		return error_ajla(EC_SYSCALL, AJLA_ERROR_NOT_SUPPORTED);
	}
	rc = proc_sock_errno();
	binary_search(size_t, n_array_elements(socket_error_to_system_error), r, socket_error_to_system_error[r].errn == rc, socket_error_to_system_error[r].errn < rc, return error_ajla_aux(EC_SYSCALL, AJLA_ERROR_OS2_SOCKET, rc));
	return error_ajla_aux(EC_SYSCALL, AJLA_ERROR_SYSTEM, socket_error_to_system_error[r].sys_error);
}

uint32_t os_get_last_error(void)
{
	return 0;
}

uint32_t os_get_last_socket_error(void)
{
	if (unlikely(!tcpip_loaded)) {
		return 0;
	}
	return proc_sock_errno();
}


void os_block_signals(sig_state_t attr_unused *set)
{
	ULONG n;
	APIRET rc = DosEnterMustComplete(&n);
	if (unlikely(rc != 0))
		fatal("DosEnterMustComplete failed: %lu", rc);
}

void os_unblock_signals(const sig_state_t attr_unused *set)
{
	ULONG n;
	APIRET rc = DosExitMustComplete(&n);
	if (unlikely(rc != 0))
		fatal("DosExitMustComplete failed: %lu", rc);
}

void attr_cold os_stop(void)
{
	warning("stop not supported on OS/2");
}

static void os2_enter_critical_section(void)
{
	APIRET rc = DosEnterCritSec();
	if (unlikely(rc != 0))
		internal(file_line, "DosEnterCritSec returned an error: %lu", rc);
}

static void os2_exit_critical_section(void)
{
	APIRET rc = DosExitCritSec();
	if (unlikely(rc != 0))
		internal(file_line, "DosExitCritSec returned an error: %lu", rc);
}

static void os2_close_handle(HFILE hfile)
{
	APIRET rc = DosClose(hfile);
	if (unlikely(rc != 0))
		internal(file_line, "DosClose(%lu) returned an error: %lu", hfile, rc);
}

static void os2_close_socket(int sock)
{
	proc_soclose(sock);
}

static void *os2_alloc_buffer(size_t size)
{
	APIRET rc;
	void *addr;
again:
	rc = DosAllocMem(&addr, size, PAG_READ | PAG_WRITE | PAG_COMMIT);
	if (unlikely(rc != 0)) {
		if (rc == ERROR_INTERRUPT)
			goto again;
		return NULL;
	}
	return addr;
}

static void os2_free_buffer(void *addr)
{
	APIRET rc;
again:
	rc = DosFreeMem(addr);
	if (unlikely(rc)) {
		if (rc == ERROR_INTERRUPT)
			goto again;
		internal(file_line, "os2_free_buffer: DosFreeMem(%p) returned error: %lu", addr, rc);
	}
}

static bool os2_increase_open_files(void)
{
	APIRET rc;
	rc = DosSetMaxFH(OS2_MAX_HANDLE);
	return !rc;
}

static void os2_set_inherit(HFILE hfile, bool inherit)
{
	APIRET rc;
	ULONG state;

	rc = DosQueryFHState(hfile, &state);
	if (unlikely(rc != 0))
		internal(file_line, "DosQueryFHState returned an error: %lu", rc);

	state &= 0x8 | OPEN_FLAGS_NO_CACHE | OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_WRITE_THROUGH;
	if (!inherit)
		state |= OPEN_FLAGS_NOINHERIT;

	rc = DosSetFHState(hfile, state);
	if (unlikely(rc != 0))
		internal(file_line, "DosSetFHState (%lu) returned an error: %lu", state, rc);
}

static bool os2_handle_is_valid(HFILE hfile)
{
	APIRET rc;
	ULONG state;
	rc = DosQueryFHState(hfile, &state);
	return !rc;
}

static bool os2_handle_dup1(HFILE hfile, HFILE *n, ajla_error_t *err)
{
	APIRET rc;
	bool increased = false;
retry:
	*n = 0xffffffffUL;
	rc = DosDupHandle(hfile, n);
	if (unlikely(rc != 0)) {
		ajla_error_t e;
		if (!increased && rc == ERROR_TOO_MANY_OPEN_FILES) {
			if (os2_increase_open_files()) {
				increased = true;
				goto retry;
			}
		}
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't duplicate handle: %s", error_decode(e));
		return false;
	}
	return true;
}

static bool os2_handle_dup2(HFILE hfile, HFILE n, ajla_error_t *err)
{
	ULONG nn;
	APIRET rc;
	bool increased = false;
retry:
	nn = n;
	rc = DosDupHandle(hfile, &nn);
	if (unlikely(rc != 0)) {
		ajla_error_t e;
		if (!increased && (rc == ERROR_TOO_MANY_OPEN_FILES || rc == ERROR_INVALID_TARGET_HANDLE)) {
			if (os2_increase_open_files()) {
				increased = true;
				goto retry;
			}
		}
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't duplicate handle: %s", error_decode(e));
		return false;
	}
	return true;
}

static bool os2_handle_placeholder(HFILE h, ajla_error_t *err)
{
	HFILE hfile;
	ULONG action;
	APIRET rc;
	bool increased = false;
retry:
	rc = DosOpen("con", &hfile, &action, 0, 0, OPEN_ACTION_OPEN_IF_EXISTS | OPEN_ACTION_FAIL_IF_NEW, OPEN_ACCESS_READWRITE | OPEN_SHARE_DENYNONE | OPEN_FLAGS_NOINHERIT, NULL);
	if (unlikely(rc != 0)) {
		ajla_error_t e;
		if (!increased && rc == ERROR_TOO_MANY_OPEN_FILES) {
			if (os2_increase_open_files()) {
				increased = true;
				goto retry;
			}
		}
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't open device 'con': %s", error_decode(e));
		return false;
	}
	if (hfile == h)
		return true;
	if (unlikely(!os2_handle_dup2(hfile, h, err))) {
		os2_close_handle(hfile);
		return false;
	}
	os2_close_handle(hfile);
	return true;
}

static handle_t os2_hfile_to_handle(HFILE hfile, int flags, char disk, ajla_error_t *err)
{
	ULONG htype, hattr;
	APIRET rc;
	handle_t h;

	rc = DosQueryHType(hfile, &htype, &hattr);
	if (unlikely(rc != 0))
		internal(file_line, "DosQueryHType returned an error: %lu", rc);

	h = mem_calloc_mayfail(handle_t, sizeof(struct os2_handle), err);
	if (unlikely(!h)) {
		os2_close_handle(hfile);
		return NULL;
	}

	h->h = hfile;
	h->t = htype & 0xff;
	h->disk = disk;
	if (h->t == HANDTYPE_FILE)
		flags &= ~O_NONBLOCK;
	h->flags = flags;
	list_init(&h->rd.wait_list);
	list_init(&h->wr.wait_list);
	h->rd.h = h;
	h->ms.h = h;
	h->wr.h = h;

	obj_registry_insert(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);

	return h;
}

static handle_t os2_socket_to_handle(int sock, ajla_error_t *err)
{
	handle_t h;
	int one = 1;

	if (unlikely(proc_ioctl(sock, FIONBIO, &one, sizeof one) == -1)) {
		fatal_mayfail(error_from_os2_socket(), err, "could not set socket non-blocking");
		os2_close_socket(sock);
		return NULL;
	}

	h = mem_calloc_mayfail(handle_t, sizeof(struct os2_handle), err);
	if (unlikely(!h)) {
		os2_close_socket(sock);
		return NULL;
	}

	h->h = sock;
	h->t = HANDTYPE_SOCKET;
	h->flags = O_RDWR | O_NONBLOCK;
	list_init(&h->rd.wait_list);
	list_init(&h->wr.wait_list);
	h->rd.h = h;
	h->wr.h = h;

	obj_registry_insert(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);

	return h;
}

uintptr_t os_handle_to_number(handle_t h)
{
	return h->h;
}

handle_t os_number_to_handle(uintptr_t n, bool sckt, ajla_error_t *err)
{
	if (!sckt) {
		return os2_hfile_to_handle(n, O_RDWR, 0, err);
	} else {
		if (unlikely(!tcpip_loaded)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "TCP/IP is not installed");
			return NULL;
		}
		return os2_socket_to_handle(n, err);
	}
}

static void os2_clean_up_handles(void);

handle_t os_open(dir_handle_t dir, const char *path, int flags, int mode, ajla_error_t *err)
{
	char *joined;
	ULONG open_flag, attrs, action;
	HFILE hfile;
	APIRET rc;
	bool increased;
	handle_t h;

	os2_clean_up_handles();

	joined = os_join_paths(dir, path, false, err);
	if (unlikely(!joined))
		return NULL;

	open_flag = 0;
	if (flags & O_CREAT) {
		open_flag |= OPEN_ACTION_CREATE_IF_NEW;
	} else {
		open_flag |= OPEN_ACTION_FAIL_IF_NEW;
	}
	if (flags & O_EXCL) {
		open_flag |= OPEN_ACTION_FAIL_IF_EXISTS;
	} else if (flags & O_TRUNC) {
		open_flag |= OPEN_ACTION_REPLACE_IF_EXISTS;
	} else {
		open_flag |= OPEN_ACTION_OPEN_IF_EXISTS;
	}

	attrs = 0;
	if (!(mode & 0222))
		attrs |= FILE_READONLY;

	increased = false;
retry:
	if (likely(proc_DosOpenL != NULL)) {
		/* * DosOpenL crashes if the address is in high memory */
		size_t l_joined = strlen(joined) + 1;
		unsigned char *fn;
		if (l_joined >= 512) {
			fn = os2_alloc_buffer(l_joined);
			if (unlikely(!fn)) {
				fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), err, "out of memory for file name buffer (%"PRIuMAX" bytes)", (uintmax_t)l_joined);
				mem_free(joined);
				return NULL;
			}
		} else {
			fn = alloca(l_joined);
		}
		memcpy(fn, joined, l_joined);
		rc = proc_DosOpenL(fn, &hfile, &action, 0, attrs, open_flag, (flags & 0x3) | OPEN_SHARE_DENYNONE | OPEN_FLAGS_NOINHERIT, NULL);
		if (l_joined >= 512) {
			os2_free_buffer(fn);
		}
	} else {
		rc = DosOpen(joined, &hfile, &action, 0, attrs, open_flag, (flags & 0x3) | OPEN_SHARE_DENYNONE | OPEN_FLAGS_NOINHERIT, NULL);
	}

	if (unlikely(rc != 0)) {
		ajla_error_t e;
		if (!increased && rc == ERROR_TOO_MANY_OPEN_FILES) {
			if (os2_increase_open_files()) {
				increased = true;
				goto retry;
			}
		}
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't open file '%s': %s", joined, error_decode(e));
		mem_free(joined);
		return NULL;
	}

	h = os2_hfile_to_handle(hfile, flags, joined[0], err);
	mem_free(joined);
	return h;
}

bool os_pipe(handle_t result[2], int nonblock_flags, ajla_error_t *err)
{
	HFILE h1, h2;
	APIRET rc;
	bool increased;

	os2_clean_up_handles();

	increased = false;
retry:
	os2_enter_critical_section();

	rc = DosCreatePipe(&h1, &h2, OS2_PIPE_SIZE);
	if (unlikely(rc != 0)) {
		ajla_error_t e;
		os2_exit_critical_section();
		if (!increased && rc == ERROR_TOO_MANY_OPEN_FILES) {
			if (os2_increase_open_files()) {
				increased = true;
				goto retry;
			}
		}
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't create pipe: %s", error_decode(e));
		return false;
	}

	os2_set_inherit(h1, false);
	os2_set_inherit(h2, false);

	os2_exit_critical_section();

	result[0] = os2_hfile_to_handle(h1, O_RDONLY | (nonblock_flags & 1 ? O_NONBLOCK : 0), 0, err);
	if (unlikely(!result[0])) {
		os2_close_handle(h2);
		return false;
	}
	result[1] = os2_hfile_to_handle(h2, O_WRONLY | (nonblock_flags & 2 ? O_NONBLOCK : 0), 0, err);
	if (unlikely(!result[1])) {
		os_close(result[0]);
		return false;
	}

	return true;
}


static void os2_terminate_io_thread(struct os2_io_thread *thr);

static void os_free_handle(handle_t h, bool should_close)
{
	ajla_assert_lo(list_is_empty(&h->rd.wait_list), (file_line, "os_free_handle: freeing handle when there are processes waiting for read"));
	ajla_assert_lo(list_is_empty(&h->wr.wait_list), (file_line, "os_free_handle: freeing handle when there are processes waiting for write"));
	obj_registry_remove(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (h->rd.thread) {
		os2_terminate_io_thread(&h->rd);
	}
	if (h->ms.thread) {
		os2_terminate_io_thread(&h->ms);
	}
	if (h->wr.thread) {
		address_lock(h, DEPTH_THUNK);
		if (h->wr.buffer_len != 0 && !h->wr.err) {
			h->wr.eof = true;
			h->wr.should_close = should_close;
			mutex_lock(&deferred_mutex);
			list_add(&deferred_write_list, &h->deferred_entry);
			mutex_unlock(&deferred_mutex);
			address_unlock(h, DEPTH_THUNK);
			return;
		}
		address_unlock(h, DEPTH_THUNK);
		os2_terminate_io_thread(&h->wr);
	}
	if (likely(should_close)) {
		if (h->t == HANDTYPE_SOCKET) {
			mutex_lock(&socket_list_mutex);
			if (h->rd.socket_entry.next != NULL)
				list_del(&h->rd.socket_entry);
			if (h->wr.socket_entry.next != NULL)
				list_del(&h->wr.socket_entry);
			mutex_unlock(&socket_list_mutex);
			os2_close_socket(h->h);
		} else {
			os2_close_handle(h->h);
		}
	}
	mem_free(h);
}

void os_close(handle_t h)
{
	os_free_handle(h, true);
}

unsigned os_n_std_handles(void)
{
	return n_std_handles;
}

handle_t os_get_std_handle(unsigned p)
{
	return os2_std_handles[p];
}

static void os2_clean_up_handles(void)
{
	if (!list_is_empty(&deferred_closed_list)) {
		mutex_lock(&deferred_mutex);
		while (!list_is_empty(&deferred_closed_list)) {
			handle_t h = get_struct(deferred_closed_list.prev, struct os2_handle, deferred_entry);
			list_del(&h->deferred_entry);
			obj_registry_insert(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
			os_free_handle(h, false);
		}
		mutex_unlock(&deferred_mutex);
	}
}


static APIRET os2_read_keyboard_packet(struct os2_io_thread *rd)
{
	APIRET rc;
	USHORT cp;
	A_DECL(KBDKEYINFO, kbki);
	sig_state_t s;
again:
	/*
	 * If we kill the thread while it's inside KbdCharIn,
	 * the keyboard deadlocks. So, we must use polling :-(
	 */
	memset(kbki, 0, sizeof(KBDKEYINFO));
	os_block_signals(&s);
	rc = KbdCharIn(kbki, IO_NOWAIT, 0);
	os_unblock_signals(&s);
	if (unlikely(rc != 0))
		return rc;
	if (!kbki->chChar && !kbki->chScan) {
		DosSleep(5);
		goto again;
	}
	/*debug("key: %u, vkey: %u, fsstate: %x", kbki->chChar, kbki->chScan, kbki->fsState);*/
	memset(&rd->pkt, 0, sizeof(struct console_read_packet));
	rd->pkt.type = 1;
	rd->pkt.u.k.key = kbki->chChar;
	rd->pkt.u.k.vkey = kbki->chScan;
	rd->pkt.u.k.ctrl = kbki->fsState;
	os_block_signals(&s);
	rc = KbdGetCp(0, &cp, 0);
	os_unblock_signals(&s);
	if (unlikely(rc != 0))
		return rc;
	rd->pkt.u.k.cp = cp;
	return 0;
}

static APIRET os2_read_mouse_packet(struct os2_io_thread *rd)
{
	APIRET rc;
	USHORT w = MOU_WAIT;
	A_DECL(MOUEVENTINFO, mei);
	rc = MouReadEventQue(mei, &w, rd->mh);
	if (unlikely(rc != 0))
		return rc;
	memset(&rd->pkt, 0, sizeof(struct console_read_packet));
	rd->pkt.type = 2;
	rd->pkt.u.m.x = mei->col;
	rd->pkt.u.m.y = mei->row;
	rd->pkt.u.m.prev_buttons = rd->last_buttons;
	rd->last_buttons = 0;
	if (mei->fs & (MOUSE_MOTION_WITH_BN1_DOWN | MOUSE_BN1_DOWN))
		rd->last_buttons |= 1;
	if (mei->fs & (MOUSE_MOTION_WITH_BN2_DOWN | MOUSE_BN2_DOWN))
		rd->last_buttons |= 2;
	if (mei->fs & (MOUSE_MOTION_WITH_BN3_DOWN | MOUSE_BN3_DOWN))
		rd->last_buttons |= 4;
	rd->pkt.u.m.buttons = rd->last_buttons;
	rd->pkt.u.m.wx = rd->pkt.u.m.wy = 0;
	rd->pkt.u.m.soft_cursor = rd->fullscreen;
	return 0;
}

static void os2_read_thread(ULONG rd_)
{
	struct os2_io_thread *rd = num_to_ptr(rd_);
	handle_t h = rd->h;
	sig_state_t s;
	APIRET rc;
	while (1) {
		os_block_signals(&s);
		address_lock(h, DEPTH_THUNK);
		if (unlikely(rd->err) || unlikely(rd->eof)) {
			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);
			while (1)
				DosSleep(-1);
		} else if (rd->packet_mode) {
			if (rd->packet_is_queued)
				goto wait_for_space;

			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);

			if (rd == &h->rd)
				rc = os2_read_keyboard_packet(rd);
			else if (rd == &h->ms)
				rc = os2_read_mouse_packet(rd);
			else
				internal(file_line, "os2_read_thread: invalid pointer %p, %p", rd, h);

			os_block_signals(&s);
			address_lock(h, DEPTH_THUNK);

			if (!rc)
				rd->packet_is_queued = true;
			else
				rd->err = rc;
			call(wake_up_wait_list)(&h->rd.wait_list, address_get_mutex(h, DEPTH_THUNK), false);
			os_unblock_signals(&s);
		} else if (rd->buffer_len < OS2_BUFFER_SIZE) {
			size_t ptr = (rd->buffer_pos + rd->buffer_len) % OS2_BUFFER_SIZE;
			size_t len = rd->buffer_pos <= ptr ? OS2_BUFFER_SIZE - ptr : rd->buffer_pos - ptr;
			ULONG rd_num;
			APIRET rc;
			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);

			rc = DosRead(h->h, rd->buffer + ptr, len, &rd_num);

			os_block_signals(&s);
			address_lock(h, DEPTH_THUNK);
			if (unlikely(rc != 0)) {
				rd->err = rc;
			}
			if (unlikely(!rd_num)) {
				rd->eof = true;
			}
			rd->buffer_len += rd_num;
			call(wake_up_wait_list)(&h->rd.wait_list, address_get_mutex(h, DEPTH_THUNK), false);
			os_unblock_signals(&s);
		} else {
			ULONG count;
wait_for_space:
			rc = DosResetEventSem(rd->event, &count);
			if (rc && unlikely(rc != ERROR_ALREADY_RESET))
				internal(file_line, "DosResetEventSem returned an error: %lu", rc);
			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);
wait_again:
			rc = DosWaitEventSem(rd->event, SEM_INDEFINITE_WAIT);
			if (unlikely(rc != 0)) {
				if (rc == ERROR_INTERRUPT || rc == ERROR_TIMEOUT)
					goto wait_again;
				internal(file_line, "DosWaitEventSem returned an error: %lu", rc);
			}
		}
	}
}

static void os2_write_thread(ULONG wr_)
{
	struct os2_io_thread *wr = num_to_ptr(wr_);
	handle_t h = wr->h;
	sig_state_t s;
	APIRET rc;
	while (1) {
		os_block_signals(&s);
		address_lock(h, DEPTH_THUNK);
		if (unlikely(wr->err)) {
			if (wr->eof)
				goto eof;
			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);
			while (1)
				DosSleep(-1);
		} else if (wr->buffer_len) {
			APIRET rc;
			ULONG wr_num;
			size_t len = minimum(wr->buffer_len, OS2_BUFFER_SIZE - wr->buffer_pos);
			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);

			/*DosSleep(2000);*/
			rc = DosWrite(h->h, wr->buffer + wr->buffer_pos, len, &wr_num);

			os_block_signals(&s);
			address_lock(h, DEPTH_THUNK);
			if (unlikely(rc != 0)) {
				wr->err = rc;
			}

			wr->buffer_pos = (wr->buffer_pos + wr_num) % OS2_BUFFER_SIZE;
			wr->buffer_len -= wr_num;

			call(wake_up_wait_list)(&h->wr.wait_list, address_get_mutex(h, DEPTH_THUNK), false);
			os_unblock_signals(&s);
		} else if (unlikely(wr->eof)) {
eof:
			wr->buffer_len = 0;
			if (wr->should_close)
				os2_close_handle(h->h);

			mutex_lock(&deferred_mutex);
			list_del(&h->deferred_entry);
			list_add(&deferred_closed_list, &h->deferred_entry);
			mutex_unlock(&deferred_mutex);

			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);
			while (1)
				DosSleep(-1);
		} else {
			ULONG count;
			rc = DosResetEventSem(wr->event, &count);
			if (rc && unlikely(rc != ERROR_ALREADY_RESET))
				internal(file_line, "DosResetEventSem returned an error: %lu", rc);
			address_unlock(h, DEPTH_THUNK);
			os_unblock_signals(&s);
wait_again:
			rc = DosWaitEventSem(wr->event, SEM_INDEFINITE_WAIT);
			if (unlikely(rc != 0)) {
				if (rc == ERROR_INTERRUPT || rc == ERROR_TIMEOUT)
					goto wait_again;
				internal(file_line, "DosWaitEventSem returned an error: %lu", rc);
			}
		}
	}
}

static void os2_clear_thread_buffer(struct os2_io_thread *thr)
{
	thr->eof = false;
	thr->err = 0;
	thr->buffer_pos = thr->buffer_len = 0;
	thr->packet_is_queued = false;
	thr->last_buttons = 0;
}

static bool os2_create_io_thread(handle_t h, struct os2_io_thread *thr, PFNTHREAD addr, ajla_error_t *err)
{
	APIRET rc;
	os2_clear_thread_buffer(thr);
	thr->packet_mode = h->packet_mode;
	if (!thr->packet_mode) {
		thr->buffer = os2_alloc_buffer(OS2_BUFFER_SIZE);
		if (unlikely(!thr->buffer)) {
			fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), err, "out of memory for i/o buffer (%"PRIuMAX" bytes)", (uintmax_t)OS2_BUFFER_SIZE);
			goto ret1;
		}
	} else {
		thr->buffer = NULL;
	}
	rc = DosCreateEventSem(NULL, &thr->event, 0, FALSE);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "DosCreateEventSem failed: %s", error_decode(e));
		goto ret2;
	}
	if (thr == &h->ms) {
		HMOU mh;
		USHORT evmask;
		PTIB tib;
		PPIB pib;
		rc = DosGetInfoBlocks(&tib, &pib);
		if (unlikely(rc != 0)) {
			ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
			fatal("DosGetInfoBlocks returned an error: %s", error_decode(e));
		}
		thr->fullscreen = pib->pib_ultype == 0;
		rc = MouOpen(NULL, &mh);
		if (unlikely(rc)) {
			ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
			fatal_mayfail(e, err, "MouOpen returned an error: %s", error_decode(e));
			goto ret3;
		}
		thr->mh = mh;
		evmask = 0x7f;
		rc = MouSetEventMask(&evmask, mh);
		if (unlikely(rc)) {
			ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
			fatal_mayfail(e, err, "MouSetEventMask returned an error: %s", error_decode(e));
			goto ret4;
		}
	}
	mutex_lock(&thread_spawn_mutex);
	rc = DosCreateThread(&thr->thread, addr, ptr_to_num(thr), 0x2, OS2_IO_THREAD_STACK_SIZE);
	mutex_unlock(&thread_spawn_mutex);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't spawn i/o thread: %s", error_decode(e));
		goto ret4;
	}
	return true;

ret4:
	if (thr->mh) {
		MouClose(thr->mh);
		thr->mh = 0;
	}
ret3:
	rc = DosCloseEventSem(thr->event);
	if (unlikely(rc != 0))
		internal(file_line, "DosCloseEventSem returned an error: %lu", rc);
ret2:
	if (thr->buffer) {
		os2_free_buffer(thr->buffer);
		thr->buffer = NULL;
	}
ret1:
	return false;
}

static void os2_terminate_thread(TID t, bool accept_invalid)
{
	APIRET rc;
	mutex_lock(&thread_spawn_mutex);
	os2_enter_critical_section();	/* avoid hang in DosRead from pipe */
	rc = DosKillThread(t);
	os2_exit_critical_section();
	if (unlikely(rc != 0)) {
		if (accept_invalid && unlikely(rc == ERROR_INVALID_THREADID))
			goto ok;
		internal(file_line, "DosKillThread (%u) returned an error: %lu", (unsigned)t, rc);
	}
	rc = DosWaitThread(&t, DCWW_WAIT);
	if (likely(rc != 0) && unlikely(rc != ERROR_INVALID_THREADID))
		internal(file_line, "DosWaitThread returned an error: %lu", rc);
ok:
	mutex_unlock(&thread_spawn_mutex);
}

static void os2_terminate_io_thread(struct os2_io_thread *thr)
{
	APIRET rc;

	os2_terminate_thread(thr->thread, false);

	thr->thread = 0;

	if (thr->buffer) {
		os2_free_buffer(thr->buffer);
		thr->buffer = NULL;
	}

	rc = DosCloseEventSem(thr->event);
	if (unlikely(rc != 0))
		internal(file_line, "DosCloseEventSem returned an error: %lu", rc);

	if (thr->mh != 0) {
		MouClose(thr->mh);
		thr->mh = 0;
	}
}

static bool os2_create_read_thread(handle_t h, ajla_error_t *err)
{
	if (unlikely(!h->rd.thread))
		return os2_create_io_thread(h, &h->rd, os2_read_thread, err);
	return true;
}

static bool os2_create_mouse_thread(handle_t h, ajla_error_t *err)
{
	if (unlikely(!h->ms.thread)) {
		return os2_create_io_thread(h, &h->ms, os2_read_thread, err);
	}
	return true;
}

static bool os2_create_write_thread(handle_t h, ajla_error_t *err)
{
	if (unlikely(!h->wr.thread))
		return os2_create_io_thread(h, &h->wr, os2_write_thread, err);
	return true;
}

static void os2_terminate_read_threads(handle_t h)
{
	if (h->rd.thread)
		os2_terminate_io_thread(&h->rd);
	if (h->ms.thread)
		os2_terminate_io_thread(&h->ms);
	os2_clear_thread_buffer(&h->rd);
	os2_clear_thread_buffer(&h->ms);
	call(wake_up_wait_list)(&h->rd.wait_list, address_get_mutex(h, DEPTH_THUNK), true);
}

static ssize_t os_read_nonblock(handle_t h, char *buffer, int size, ajla_error_t *err)
{
	ssize_t this_len;
again:
	address_lock(h, DEPTH_THUNK);
	if (unlikely(h->packet_mode)) {
		h->packet_mode = false;
		os2_terminate_read_threads(h);
		goto again;
	}
	if (unlikely(!os2_create_read_thread(h, err))) {
		address_unlock(h, DEPTH_THUNK);
		return OS_RW_ERROR;
	}
	if (h->rd.buffer_len) {
		bool was_full = h->rd.buffer_len == OS2_BUFFER_SIZE;
		this_len = minimum(h->rd.buffer_len, OS2_BUFFER_SIZE - h->rd.buffer_pos);
		this_len = minimum(this_len, size);
		memcpy(buffer, h->rd.buffer + h->rd.buffer_pos, this_len);
		h->rd.buffer_pos = (h->rd.buffer_pos + this_len) % OS2_BUFFER_SIZE;
		h->rd.buffer_len -= this_len;
		if (was_full) {
			APIRET rc = DosPostEventSem(h->rd.event);
			if (unlikely(rc != 0) && unlikely(rc != ERROR_ALREADY_POSTED) && rc != ERROR_TOO_MANY_POSTS)
				internal(file_line, "DosPostEventSem returned an error: %lu", rc);
		}
	} else {
		if (unlikely(h->rd.err != 0)) {
			ajla_error_t e = error_from_os2(EC_SYSCALL, h->rd.err);
			fatal_mayfail(e, err, "can't read handle: %s", error_decode(e));
			this_len = OS_RW_ERROR;
			goto unlock_ret;
		}
		if (unlikely(h->rd.eof)) {
			this_len = 0;
			goto unlock_ret;
		}
		this_len = OS_RW_WOULDBLOCK;
	}
unlock_ret:
	address_unlock(h, DEPTH_THUNK);
	return this_len;
}

static ssize_t os_write_nonblock(handle_t h, const char *buffer, int size, ajla_error_t *err)
{
	size_t ptr;
	ssize_t this_len;
	address_lock(h, DEPTH_THUNK);
	if (unlikely(!os2_create_write_thread(h, err))) {
		address_unlock(h, DEPTH_THUNK);
		return OS_RW_ERROR;
	}
	if (unlikely(h->wr.err)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, h->wr.err);
		fatal_mayfail(e, err, "can't write handle: %s", error_decode(e));
		this_len = OS_RW_ERROR;
		goto unlock_ret;
	}
	if (h->wr.buffer_len < OS2_BUFFER_SIZE) {
		bool was_empty = !h->wr.buffer_len;
		ptr = (h->wr.buffer_pos + h->wr.buffer_len) % OS2_BUFFER_SIZE;
		this_len = h->wr.buffer_pos <= ptr ? OS2_BUFFER_SIZE - ptr : h->wr.buffer_pos - ptr;
		this_len = minimum(this_len, size);
		memcpy(h->wr.buffer + ptr, buffer, this_len);
		h->wr.buffer_len += this_len;
		if (was_empty) {
			APIRET rc = DosPostEventSem(h->wr.event);
			if (unlikely(rc != 0) && unlikely(rc != ERROR_ALREADY_POSTED) && rc != ERROR_TOO_MANY_POSTS)
				internal(file_line, "DosPostEventSem returned an error: %lu", rc);
		}
	} else {
		this_len = OS_RW_WOULDBLOCK;
	}
unlock_ret:
	address_unlock(h, DEPTH_THUNK);
	return this_len;
}

static bool os2_setfilesize(handle_t h, os_off_t size, ajla_error_t *err)
{
	APIRET rc;
	if (unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "set file size on socket is not supported");
		return false;
	}
	if (likely(proc_DosSetFileSizeL != NULL)) {
		rc = proc_DosSetFileSizeL(h->h, size);
	} else {
		if (unlikely(size != (LONG)size)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "file size overflow");
			return false;
		}
		rc = DosSetFileSize(h->h, size);
	}
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't set handle position: %s", error_decode(e));
		return false;
	}
	return true;
}

static bool os2_setfileptr(handle_t h, os_off_t off, ULONG rel, os_off_t *result, ajla_error_t *err)
{
	APIRET rc;
	ULONG ul;
	if (unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "seek on socket is not supported");
		return false;
	}
	if (likely(proc_DosSetFilePtrL != NULL)) {
		rc = proc_DosSetFilePtrL(h->h, off, rel, result);
	} else {
		if (unlikely(off != (LONG)off)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "file size overflow");
			return false;
		}
		rc = DosSetFilePtr(h->h, off, rel, &ul);
		*result = ul;
	}
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't set handle position: %s", error_decode(e));
		return false;
	}
	return true;
}

ssize_t os_do_rw(handle_t h, char *buffer, int size, bool wr, ajla_error_t *err)
{
	ULONG result;
	APIRET rc;
	char *bb = NULL;	/* avoid warning */
	bool bounce = h->t == HANDTYPE_DEVICE && ptr_to_num(buffer) + size >= 0x20000000UL;
	if (unlikely(bounce)) {
		bb = os2_alloc_buffer(size);
		if (unlikely(!buffer)) {
			fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), err, "out of memory for bounce buffer (%"PRIuMAX" bytes)", (uintmax_t)size);
			return OS_RW_ERROR;
		}
		if (wr)
			memcpy(bb, buffer, size);
	}
	if (!wr)
		rc = DosRead(h->h, bounce ? bb : buffer, size, &result);
	else
		rc = DosWrite(h->h, bounce ? bb : buffer, size, &result);
	if (unlikely(bounce)) {
		if (!wr && likely(!rc))
			memcpy(buffer, bb, result);
		os2_free_buffer(bb);
	}
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't %s handle: %s", !wr ? "read from" : "write to", error_decode(e));
		return OS_RW_ERROR;
	}
	return result;
}

static ssize_t os_read_socket(handle_t h, char *buffer, int size, ajla_error_t *err)
{
	int r;
again:
	r = proc_recv(h->h, buffer, size, 0);
	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		if (er == SOCEINTR)
			goto again;
		if (er == SOCEAGAIN)
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_os2_socket(), err, "error reading socket");
		return OS_RW_ERROR;
	}
	return r;
}

static ssize_t os_write_socket(handle_t h, const char *buffer, int size, ajla_error_t *err)
{
	int r;
again:
	r = proc_send(h->h, buffer, size, 0);
	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		if (er == SOCEINTR)
			goto again;
		if (er == SOCEAGAIN)
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_os2_socket(), err, "error writing socket");
		return OS_RW_ERROR;
	}
	return r;
}

ssize_t os_read(handle_t h, char *buffer, int size, ajla_error_t *err)
{
	ssize_t res;
	if (unlikely((h->flags & 3) == O_WRONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to read from write-only handle");
		return false;
	}
	if (h->t == HANDTYPE_SOCKET)
		return os_read_socket(h, buffer, size, err);
	if (h->flags & O_NONBLOCK)
		return os_read_nonblock(h, buffer, size, err);
	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);
	res = os_do_rw(h, buffer, size, false, err);
	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);
	return res;
}

ssize_t os_write(handle_t h, const char *buffer, int size, ajla_error_t *err)
{
	ssize_t res;
	if (unlikely((h->flags & 3) == O_RDONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to write to read-only handle");
		return false;
	}
	if (h->t == HANDTYPE_SOCKET)
		return os_write_socket(h, buffer, size, err);
	if (h->flags & O_NONBLOCK && h->t != HANDTYPE_DEVICE)
		return os_write_nonblock(h, buffer, size, err);
	if (likely(os_threads_initialized) && h->flags & O_APPEND && h->t == HANDTYPE_FILE)
		address_lock(h, DEPTH_THUNK);
	if (h->flags & O_APPEND && h->t == HANDTYPE_FILE) {
		os_off_t sink;
		if (unlikely(!os2_setfileptr(h, 0, FILE_END, &sink, err))) {
			res = OS_RW_ERROR;
			goto unlock_ret;
		}
	}
	res = os_do_rw(h, cast_ptr(char *, buffer), size, true, err);
unlock_ret:
	if (likely(os_threads_initialized) && h->flags & O_APPEND && h->t == HANDTYPE_FILE)
		address_unlock(h, DEPTH_THUNK);
	return res;
}

ssize_t os_pread(handle_t h, char *buffer, int size, os_off_t off, ajla_error_t *err)
{
	ssize_t res;
	os_off_t sink;
	if (unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "seek operation on socket");
		return OS_RW_ERROR;
	}
	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);
	if (unlikely(!os2_setfileptr(h, off, FILE_BEGIN, &sink, err))) {
		res = OS_RW_ERROR;
		goto unlock_ret;
	}
	res = os_do_rw(h, buffer, size, false, err);
unlock_ret:
	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);
	return res;
}

ssize_t os_pwrite(handle_t h, const char *buffer, int size, os_off_t off, ajla_error_t *err)
{
	ssize_t res;
	os_off_t sink;
	if (unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "seek operation on socket");
		return OS_RW_ERROR;
	}
	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);
	if (unlikely(!os2_setfileptr(h, off, FILE_BEGIN, &sink, err))) {
		res = OS_RW_ERROR;
		goto unlock_ret;
	}
	res = os_do_rw(h, cast_ptr(char *, buffer), size, true, err);
unlock_ret:
	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);
	return res;
}

bool os_lseek(handle_t h, unsigned mode, os_off_t off, os_off_t *result, ajla_error_t *err)
{
	bool ret;
	ULONG rel;
	os_off_t len;

	if (unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "seek operation on socket");
		return false;
	}

	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);

	switch (mode) {
		case 0:	rel = FILE_BEGIN; break;
		case 1: rel = FILE_CURRENT; break;
		case 2: rel = FILE_END; break;
		case 3: ret = os2_setfileptr(h, 0, FILE_END, &len, err);
			if (unlikely(!ret))
				goto ret_ret;
			if (unlikely(off > len))
				off = len;
			*result = off;
			ret = true;
			goto ret_ret;
		case 4:	rel = FILE_END; off = 0; break;
		default:internal(file_line, "os_lseek: unsupported mode %u", mode);
			rel = (ULONG)-1; break;
	}

	ret = os2_setfileptr(h, off, rel, result, err);

ret_ret:
	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);

	return ret;
}

bool os_ftruncate(handle_t h, os_off_t size, ajla_error_t *err)
{
	bool ret;
	os_off_t current_size;

	if (unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "ftruncate operation on socket");
		return false;
	}

	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);

	ret = os2_setfileptr(h, 0, FILE_END, &current_size, err);

	if (size < current_size) {
		ret = os2_setfilesize(h, size, err);
	} else if (size > current_size) {
		os_off_t sink;
		ret = os2_setfileptr(h, size - 1, FILE_BEGIN, &sink, err);
		if (likely(ret)) {
			ULONG written;
			APIRET rc;
			rc = DosWrite(h->h, "", 1, &written);
			if (unlikely(rc != 0)) {
				ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
				fatal_mayfail(e, err, "extern file: %s", error_decode(e));
				ret = false;
			}
		}
	} else {
		ret = true;
	}

	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);

	return ret;
}

bool os_fallocate(handle_t h, os_off_t position, os_off_t size, ajla_error_t *err)
{
	bool ret;
	os_off_t current_size;

	if (unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "fallocate operation on socket");
		return false;
	}

	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);

	ret = os2_setfileptr(h, 0, FILE_END, &current_size, err);
	if (unlikely(!ret))
		goto unlock_ret;

	if (position <= current_size && position + size > current_size) {
		ret = os2_setfilesize(h, position + size, err);
	} else {
		ret = true;
	}

unlock_ret:
	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);

	return ret;
}

bool os_clone_range(handle_t attr_unused src_h, os_off_t attr_unused src_pos, handle_t attr_unused dst_h, os_off_t attr_unused dst_pos, os_off_t attr_unused len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "clone not supported");
	return false;
}

bool os_fsync(handle_t h, unsigned mode, ajla_error_t *err)
{
	APIRET rc;
	ULONG version[2];

	if (handle_is_valid(h) && unlikely(h->t == HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "fsync operation on socket");
		return false;
	}

	/* There is fsync bug in OS/2 before OS/2 3.0 XR_W005 */
	if (!DosQuerySysInfo(QSV_VERSION_MAJOR, QSV_VERSION_MINOR, version, sizeof version)) {
		if (version[0] == 20 && version[1] < 40)
			return true;
	}

	if (mode == 0 || mode == 1)
		rc = DosResetBuffer(h->h);
	else
		rc = DosResetBuffer(0xffffffffUL);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't flush buffers: %s", error_decode(e));
		return false;
	}
	return true;
}


int os_charset(void)
{
	APIRET rc;
	USHORT cp;
	rc = VioGetCp(0, &cp, 0);
	if (unlikely(rc != 0))
		return 437;
	return cp;
}

ssize_t os_read_console_packet(handle_t h, struct console_read_packet *result, ajla_error_t *err)
{
	APIRET rc;
	ssize_t retval;
again:
	address_lock(h, DEPTH_THUNK);
	if (unlikely((h->flags & 3) == O_WRONLY) ||
	    unlikely(h->t != HANDTYPE_DEVICE)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to use packet console on non-console");
		retval = OS_RW_ERROR;
		goto unlock_ret;
	}
	if (unlikely(!h->packet_mode)) {
		h->packet_mode = true;
		os2_terminate_read_threads(h);
		goto again;
	}
	if (unlikely(!os2_create_read_thread(h, err))) {
		retval = OS_RW_ERROR;
		goto unlock_ret;
	}
	os2_create_mouse_thread(h, err);
	if (h->rd.packet_is_queued) {
		memcpy(result, &h->rd.pkt, sizeof(struct console_read_packet));
		h->rd.packet_is_queued = false;
		rc = DosPostEventSem(h->rd.event);
		if (unlikely(rc != 0) && unlikely(rc != ERROR_ALREADY_POSTED) && rc != ERROR_TOO_MANY_POSTS)
			internal(file_line, "DosPostEventSem returned an error: %lu", rc);
		retval = 1;
		goto unlock_ret;
	}
	if (h->ms.packet_is_queued) {
		memcpy(result, &h->ms.pkt, sizeof(struct console_read_packet));
		h->ms.packet_is_queued = false;
		rc = DosPostEventSem(h->ms.event);
		if (unlikely(rc != 0) && unlikely(rc != ERROR_ALREADY_POSTED) && rc != ERROR_TOO_MANY_POSTS)
			internal(file_line, "DosPostEventSem returned an error: %lu", rc);
		retval = 1;
		goto unlock_ret;
	}
	if (unlikely(h->rd.err != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, h->rd.err);
		fatal_mayfail(e, err, "can't read keyboard packet: %s", error_decode(e));
		retval = OS_RW_ERROR;
		goto unlock_ret;
	}
	if (unlikely(h->ms.err != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, h->ms.err);
		fatal_mayfail(e, err, "can't read mouse packet: %s", error_decode(e));
		retval = OS_RW_ERROR;
		goto unlock_ret;
	}
	retval = OS_RW_WOULDBLOCK;
unlock_ret:
	address_unlock(h, DEPTH_THUNK);
	return retval;
}

bool os_write_console_packet(handle_t h, struct console_write_packet *packet, ajla_error_t *err)
{
	PCH pch;
	APIRET rc;
	if (unlikely((h->flags & 3) == O_RDONLY) ||
	    unlikely(h->t != HANDTYPE_DEVICE)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to use packet console on non-console");
		goto err0;
	}
	pch = os2_alloc_buffer(OS2_PACKET_BUFFER_SIZE);
	if (unlikely(!pch)) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), err, "out of memory for write console buffer");
		goto err0;
	}
next:
	switch (packet->type) {
		case 1: {
			break;
		}
		case 2: {
			int x, y;
			unsigned n_chars;
			int32_t *ptr;
			x = packet->u.c.x;
			y = packet->u.c.y;
			n_chars = packet->u.c.n_chars;
			ptr = packet->u.c.data;
			while (n_chars) {
				BYTE attr[3];
				unsigned n, i;
				for (n = 1; n < n_chars && n < OS2_PACKET_BUFFER_SIZE; n++) {
					if (ptr[n * 2 + 1] != ptr[1])
						break;
				}
				for (i = 0; i < n; i++) {
					pch[i] = ptr[i * 2];
				}
				rc = VioWrtCharStr(pch, n, y, x, 0);
				if (unlikely(rc != 0)) {
					ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
					fatal_mayfail(e, err, "VioWrtCharStr failed: %s", error_decode(e));
					goto err1;
				}
				attr[0] = ptr[1];
				attr[1] = 0;
				attr[2] = 0;
				rc = VioWrtNAttr(attr, n, y, x, 0);
				if (unlikely(rc != 0)) {
					ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
					fatal_mayfail(e, err, "VioWrtNAttr failed: %s", error_decode(e));
					goto err1;
				}

				x += n;
				ptr += n * 2;
				n_chars -= n;
			}
			packet = cast_ptr(struct console_write_packet *, &packet->u.c.data[packet->u.c.n_chars * 2]);
			goto next;
		}
		case 3: {
			rc = VioSetCurPos(packet->u.p.y, packet->u.p.x, 0);
			if (unlikely(rc != 0)) {
				ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
				fatal_mayfail(e, err, "VioSetCurPos failed: %s", error_decode(e));
				goto err1;
			}
			packet = cast_ptr(struct console_write_packet *, &packet->u.p.end);
			goto next;
		}
		case 4: {
			A_DECL(VIOCURSORINFO, vci);
			rc = VioGetCurType(vci, 0);
			if (unlikely(rc != 0)) {
				ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
				fatal_mayfail(e, err, "VioGetCurType failed: %s", error_decode(e));
				goto err1;
			}
			vci->attr = packet->u.v.v ? 0 : -1;
			rc = VioSetCurType(vci, 0);
			if (unlikely(rc != 0)) {
				ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
				fatal_mayfail(e, err, "VioSetCurType failed: %s", error_decode(e));
				goto err1;
			}
			packet = cast_ptr(struct console_write_packet *, &packet->u.v.end);
			goto next;
		}
		default: {
			internal(file_line, "os_write_console_packet: invalid type %d", (int)packet->type);
			break;
		}
	}
	os2_free_buffer(pch);
	return true;

err1:
	os2_free_buffer(pch);
err0:
	return false;
}


dir_handle_t os_dir_root(ajla_error_t *err)
{
	unsigned bit;
	APIRET rc;
	ULONG current, drv;
	char *d = str_dup(" :\\", -1, err);
	if (unlikely(!d))
		return NULL;
	rc = DosQueryCurrentDisk(&current, &drv);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "DosQueryCurrentDisk failed: %s", error_decode(e));
		mem_free(d);
		return NULL;
	}
	if (unlikely(!drv))
		drv = 4;
	if (drv & ~3U)
		drv &= ~3U;
	bit = low_bit(drv);
	d[0] = 'A' + bit;
	return d;
}

dir_handle_t os_dir_cwd(ajla_error_t *err)
{
	ULONG disk, logical;
	APIRET rc;
	char *ptr, *p;
	size_t len;

	char *buffer;
	ULONG buffer_len;

	if (unlikely(!array_init_mayfail(char, &ptr, &len, err)))
		return dir_none;

	rc = DosQueryCurrentDisk(&disk, &logical);
	if (unlikely(rc)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "DosQueryCurrentDisk failed: %s", error_decode(e));
		mem_free(ptr);
		return dir_none;
	}

	if (unlikely(!array_add_mayfail(char, &ptr, &len, disk + 'A' - 1, NULL, err)))
		return dir_none;
	if (unlikely(!array_add_multiple_mayfail(char, &ptr, &len, ":\\", 2, NULL, err)))
		return dir_none;

	buffer_len = 1;
alloc_again:
	buffer = mem_alloc_mayfail(char *, buffer_len, err);
	if (unlikely(!buffer)) {
		mem_free(ptr);
		return dir_none;
	}
	rc = DosQueryCurrentDir(disk, buffer, &buffer_len);
	if (rc == ERROR_BUFFER_OVERFLOW) {
		mem_free(buffer);
		goto alloc_again;
	}
	if (unlikely(rc)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "DosQueryCurrentDir failed: %s", error_decode(e));
		mem_free(ptr);
		mem_free(buffer);
		return dir_none;
	}
	if (unlikely(!array_add_multiple_mayfail(char, &ptr, &len, buffer, strlen(buffer) + 1, NULL, err))) {
		mem_free(buffer);
		return dir_none;
	}
	mem_free(buffer);
	array_finish(char, &ptr, &len);
	p = ptr;
	while ((p = strchr(p, '\\')))
		*p++ = '/';
	return ptr;
}

static bool os2_dir_set(dir_handle_t dir, ajla_error_t *err)
{
	APIRET rc;
	if ((dir[0] & 0xdf) >= 'A' && (dir[0] & 0xdf) <= 'Z' && dir[1] == ':') {
		rc = DosSetDefaultDisk((dir[0] & 0xdf) - 'A' + 1);
		if (unlikely(rc != 0)) {
			ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
			fatal_mayfail(e, err, "can't set current disk '%c:': %s", dir[0] & 0xdf, error_decode(e));
			return false;
		}
		dir += 2;
	}
	rc = DosSetCurrentDir(dir);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't set current directory '%s': %s", dir, error_decode(e));
		return false;
	}
	return true;
}

dir_handle_t os_dir_open(dir_handle_t dir, const char *path, int attr_unused flags, ajla_error_t *err)
{
	char *result;
	FILESTATUS3 fs;
	APIRET rc;
	result = os_join_paths(dir, path, true, err);
	if (unlikely(!result))
		return dir_none;
	rc = DosQueryPathInfo(result, FIL_STANDARD, &fs, sizeof fs);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't open directory '%s': %s", result, error_decode(e));
		mem_free(result);
		return dir_none;
	}
	if (unlikely(!(fs.attrFile & FILE_DIRECTORY))) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, ERROR_PATH_NOT_FOUND);
		fatal_mayfail(e, err, "can't open directory '%s': %s", result, error_decode(e));
		mem_free(result);
		return dir_none;
	}
	return result;
}

void os_dir_close(dir_handle_t h)
{
	mem_free(h);
}

char *os_dir_path(dir_handle_t h, ajla_error_t *err)
{
	return str_dup(h, -1, err);
}

#define FIND_BUFFER_SIZE	65535

static void os_close_dir(HDIR hdir)
{
	APIRET rc = DosFindClose(hdir);
	if (unlikely(rc != 0))
		internal(file_line, "DosFindClose returned an error: %lu", rc);
}

static bool process_find_buffer(char *buffer, size_t n_entries, char ***files, size_t *n_files, ajla_error_t *err)
{
	while (n_entries--) {
		void *err_ptr;
		FILEFINDBUF3 *ffb = cast_ptr(FILEFINDBUF3 *, buffer);
		char *name = ffb->achName;
		buffer += ffb->oNextEntryOffset;
		if (unlikely(!strcmp(name, ".")) || unlikely(!strcmp(name, "..")))
			continue;
		name = str_dup(name, -1, err);
		if (unlikely(!name))
			return false;
		if (unlikely(!array_add_mayfail(char *, files, n_files, name, &err_ptr, err))) {
			*files = err_ptr;
			return false;
		}
	}
	return true;
}

bool os_dir_read(dir_handle_t h, char ***files, size_t *n_files, ajla_error_t *err)
{
	HDIR hdir = HDIR_CREATE;
	char find_buffer[FIND_BUFFER_SIZE];
	char *fn;
	ULONG n_entries;
	APIRET rc;

	if (unlikely(!array_init_mayfail(char *, files, n_files, err)))
		return false;

	fn = os_join_paths(h, "*", false, err);
	if (unlikely(!fn))
		goto ret_false;

	n_entries = FIND_BUFFER_SIZE;
	rc = DosFindFirst(fn, &hdir, FILE_READONLY | FILE_HIDDEN | FILE_SYSTEM | FILE_DIRECTORY | FILE_ARCHIVED, find_buffer, FIND_BUFFER_SIZE, &n_entries, FIL_STANDARD);
	mem_free(fn);
	if (unlikely(rc != 0)) {
		ajla_error_t e;
		if (likely(rc == ERROR_NO_MORE_FILES))
			goto ret_array;
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "error reading directory '%s': %s", h, error_decode(e));
		goto ret_false;
	}
proc_buffer:
	if (unlikely(!process_find_buffer(find_buffer, n_entries, files, n_files, err))) {
		os_close_dir(hdir);
		goto ret_false;
	}
	n_entries = FIND_BUFFER_SIZE;
	rc = DosFindNext(hdir, find_buffer, FIND_BUFFER_SIZE, &n_entries);
	if (likely(rc != 0)) {
		ajla_error_t e;
		os_close_dir(hdir);
		if (likely(rc == ERROR_NO_MORE_FILES))
			goto ret_array;
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "error reading directory '%s': %s", h, error_decode(e));
		goto ret_false;
	}
	goto proc_buffer;

ret_array:
	return true;

ret_false:
	os_dir_free(*files, *n_files);
	return false;
}

void os_dir_free(char **files, size_t n_files)
{
	size_t i;
	for (i = 0; i < n_files; i++)
		mem_free(files[i]);
	mem_free(files);
}


unsigned os_dev_t_major(dev_t attr_unused dev)
{
	return 0;
}

unsigned os_dev_t_minor(dev_t attr_unused dev)
{
	return 0;
}

static os_time_t time_to_os_time(int year, int month, int day, int hour, int min, int sec)
{
	os_time_t x;

	/*debug("y=%d, m=%d, d=%d, h=%d, m=%d, s=%d", year, month, day, hour, min, sec);*/

	x = (os_time_t)year * 365 + day + (month - 1) * 31;
	if (month <= 2)
		year--;
	else
		x -= (month * 4 + 23) / 10;
	x += year / 4 - ((year / 100 + 1) * 3) / 4;

	x = (x - 719528) * 24 * 3600;

	x += hour * 3600 + min * 60 + sec;

	return x;
}

static void os_time_to_time(os_time_t t, int *year, int *month, int *day, int *hour, int *min, int *sec)
{
	time_t tim = t;
	struct tm *tm;
	if (os_threads_initialized)
		address_lock(NULL, DEPTH_THUNK);
	tm = gmtime(&tim);
	if (unlikely(!tm)) {
		*year = *month = *day = *hour = *min = *sec = 0;
	} else {
		*year = tm->tm_year + 1900;
		*month = tm->tm_mon;
		*day = tm->tm_mday;
		*hour = tm->tm_hour;
		*min = tm->tm_min;
		*sec = tm->tm_sec;
	}
	if (os_threads_initialized)
		address_unlock(NULL, DEPTH_THUNK);
}

#if 0
time_t _mktime(struct tm *);
static os_time_t file_time_to_os_time(FDATE *fd, FTIME *ft)
{
	struct tm tm;
	tm.tm_year = fd->year + 80;
	tm.tm_mon = fd->month - 1;
	tm.tm_mday = fd->day;
	tm.tm_hour = ft->hours;
	tm.tm_min = ft->minutes;
	tm.tm_sec = ft->twosecs * 2;
	return _mktime(&tm);
}
#else
static os_time_t file_time_to_os_time(FDATE *fd, FTIME *ft)
{
	int year, month, day, hour, min, sec;

	year = fd->year + 1980;
	month = fd->month;
	day = fd->day;
	hour = ft->hours;
	min = ft->minutes;
	sec = ft->twosecs * 2;

	return time_to_os_time(year, month, day, hour, min, sec) + timezone;
}

static void os_time_to_file_time(os_time_t t, FDATE *fd, FTIME *ft)
{
	int year, month, day, hour, min, sec;
	t -= timezone;
	os_time_to_time(t, &year, &month, &day, &hour, &min, &sec);
	fd->year = year - 1980;
	fd->month = month;
	fd->day = day;
	ft->hours = hour;
	ft->minutes = min;
	ft->twosecs = sec / 2;
}
#endif

ajla_time_t os_time_t_to_ajla_time(os_time_t sec)
{
	return (ajla_time_t)sec * 1000000;
}

static os_time_t ajla_time_to_os_time(ajla_time_t usec)
{
	return usec / 1000000;
}

bool os_fstat(handle_t h, os_stat_t *st, ajla_error_t *err)
{
	FILESTATUS3 info;
	ULONG state;
	APIRET rc;

	memset(st, 0, sizeof(os_stat_t));
	st->st_nlink = 1;

	switch (h->t) {
		case HANDTYPE_SOCKET:
			st->st_mode = S_IFSOCK | 0600;
			break;
		case HANDTYPE_DEVICE:
			st->st_mode = S_IFCHR;
			goto qfhstate;
		case HANDTYPE_PIPE:
			st->st_mode = S_IFIFO;
		qfhstate:
			rc = DosQueryFHState(h->h, &state);
			if (unlikely(rc != 0))
				internal(file_line, "DosQueryFHState returned an error: %lu", rc);
			if ((state & 7) == OPEN_ACCESS_READONLY)
				st->st_mode |= 0444;
			else
				st->st_mode |= 0666;
			break;
		default:
			st->st_mode = S_IFREG;
			rc = DosQueryFileInfo(h->h, FIL_STANDARD, &info, sizeof(info));
			if (unlikely(rc != 0)) {
				ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
				fatal_mayfail(e, err, "DosQueryFileInfo returned an error: %s", error_decode(e));
				return false;
			}
			st->st_ctime = file_time_to_os_time(&info.fdateCreation, &info.ftimeCreation);
			st->st_atime = file_time_to_os_time(&info.fdateLastAccess, &info.ftimeLastAccess);
			st->st_mtime = file_time_to_os_time(&info.fdateLastWrite, &info.ftimeLastWrite);
			if (unlikely((info.attrFile & 0x01) != 0))
				st->st_mode |= 0444;
			else
				st->st_mode |= 0666;
			st->st_size = info.cbFile;
			st->st_blocks = round_up(st->st_size, 512) / 512;
			st->st_blksize = 512;
			break;
	}

	return true;
}

bool os_stat(dir_handle_t dir, const char *path, bool attr_unused lnk, os_stat_t *st, ajla_error_t *err)
{
	ajla_error_t sink;
	dir_handle_t dh;
	FILESTATUS3 info;
	APIRET rc;

	memset(st, 0, sizeof(os_stat_t));
	st->st_nlink = 1;

	dh = os_dir_open(dir, path, 0, &sink);
	if (dir_handle_is_valid(dh)) {
		st->st_mode = S_IFDIR | 0777;
	} else {
		st->st_mode = S_IFREG | 0666;
		dh = os_join_paths(dir, path, false, err);
		if (unlikely(!dh))
			return false;
	}
	rc = DosQueryPathInfo(dh, FIL_STANDARD, &info, sizeof info);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't access path '%s': %s", dh, error_decode(e));
		os_dir_close(dh);
		return false;
	}
	st->st_ctime = file_time_to_os_time(&info.fdateCreation, &info.ftimeCreation);
	st->st_atime = file_time_to_os_time(&info.fdateLastAccess, &info.ftimeLastAccess);
	st->st_mtime = file_time_to_os_time(&info.fdateLastWrite, &info.ftimeLastWrite);
	if (unlikely((info.attrFile & 1) != 0))
		st->st_mode &= ~0222;
	st->st_size = info.cbFile;
	st->st_blocks = round_up(st->st_size, 512) / 512;
	st->st_blksize = 512;
	os_dir_close(dh);
	return true;
}

static bool os_stat_disk(char disk, os_statvfs_t *st, ajla_error_t *err)
{
	FSALLOCATE fsal;
	APIRET rc;

	disk &= 0xdf;
	if (unlikely(disk < 'A') || unlikely(disk > 'Z')) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "statvfs not supported");
		return false;
	}
	rc = DosQueryFSInfo(disk - 'A' + 1, FSIL_ALLOC, &fsal, sizeof(FSALLOCATE));
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't get disk '%c' free space: %s", disk - 1 + 'A', error_decode(e));
		return false;
	}
	memset(st, 0, sizeof(os_statvfs_t));
	st->f_bsize = st->f_frsize = fsal.cSectorUnit * fsal.cbSector;
	st->f_blocks = fsal.cUnit;
	st->f_bfree = st->f_bavail = fsal.cUnitAvail;
	st->f_fsid = fsal.idFileSystem;
	st->f_namemax = 255;
	return true;
}

bool os_fstatvfs(handle_t h, os_statvfs_t *st, ajla_error_t *err)
{
	return os_stat_disk(h->disk, st, err);
}

bool os_dstatvfs(dir_handle_t dir, os_statvfs_t *st, ajla_error_t *err)
{
	return os_stat_disk(dir[0], st, err);
}

char *os_readlink(dir_handle_t attr_unused dir, const char attr_unused *path, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "readlink not supported");
	return NULL;
}

bool os_dir_action(dir_handle_t dir, const char *path, int action, int attr_unused mode, ajla_time_t attr_unused dev_major, ajla_time_t attr_unused dev_minor, const char attr_unused *syml, ajla_error_t *err)
{
	APIRET rc;
	FILESTATUS3 fs;
	char *joined;
	bool allow_trailing_slash = action == IO_Action_Rm_Dir || action == IO_Action_Mk_Dir;

	joined = os_join_paths(dir, path, allow_trailing_slash, err);
	if (unlikely(!joined))
		return false;

	switch (action) {
		case IO_Action_Rm:
			rc = DosDelete(joined);
			break;
		case IO_Action_Rm_Dir:
			rc = DosDeleteDir(joined);
			break;
		case IO_Action_Mk_Dir:
			rc = DosCreateDir(joined, NULL);
			if (rc == ERROR_ACCESS_DENIED) {
				APIRET rc2;
				rc2 = DosQueryPathInfo(joined, FIL_STANDARD, &fs, sizeof fs);
				if (!rc2)
					rc = ERROR_FILE_EXISTS;
			}
			break;
		case IO_Action_Mk_Pipe:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkpipe not supported");
			goto ret_false;
		case IO_Action_Mk_Socket:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mksocket not supported");
			goto ret_false;
		case IO_Action_Mk_CharDev:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkchardev not supported");
			goto ret_false;
		case IO_Action_Mk_BlockDev:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkblockdev not supported");
			goto ret_false;
		case IO_Action_Mk_SymLink:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mksymlink not supported");
			goto ret_false;
		case IO_Action_ChMod:
		case IO_Action_ChOwn:
		case IO_Action_LChOwn:
			rc = DosQueryPathInfo(joined, FIL_STANDARD, &fs, sizeof fs);
			break;
		case IO_Action_UTime:
		case IO_Action_LUTime: {
			rc = DosQueryPathInfo(joined, FIL_STANDARD, &fs, sizeof fs);
			if (unlikely(rc))
				break;
			os_time_to_file_time(ajla_time_to_os_time(dev_major), &fs.fdateLastWrite, &fs.ftimeLastWrite);
			os_time_to_file_time(ajla_time_to_os_time(dev_minor), &fs.fdateLastAccess, &fs.ftimeLastAccess);
			rc = DosSetPathInfo(joined, FIL_STANDARD, &fs, sizeof(fs), 0);
			break;
		}
		default:
			internal(file_line, "os_dir_action: invalid action %d", action);
	}
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't perform action %d on '%s': %s", action, joined, error_decode(e));
		goto ret_false;
	}
	mem_free(joined);
	return true;

ret_false:
	mem_free(joined);
	return false;
}

bool os_dir2_action(dir_handle_t dest_dir, const char *dest_path, int action, dir_handle_t src_dir, const char *src_path, ajla_error_t *err)
{
	APIRET rc;
	FILESTATUS3 fs;
	char *dest_joined = NULL;
	char *src_joined = NULL;

	dest_joined = os_join_paths(dest_dir, dest_path, false, err);
	if (unlikely(!dest_joined))
		goto ret_false;
	src_joined = os_join_paths(src_dir, src_path, false, err);
	if (unlikely(!src_joined))
		goto ret_false;

	switch (action) {
		case IO_Action_Mk_Link:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mklink not supported");
			goto ret_false;
		case IO_Action_Rename:
			rc = DosQueryPathInfo(src_joined, FIL_STANDARD, &fs, sizeof fs);
			if (likely(!rc)) {
				DosDelete(dest_joined);
				rc = DosMove(src_joined, dest_joined);
			}
			break;
		default:
			internal(file_line, "os_dir2_action: invalid action %d", action);
	}

	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't perform action %d on '%s' and '%s': %s", action, src_joined, dest_joined, error_decode(e));
		goto ret_false;
	}

	mem_free(dest_joined);
	mem_free(src_joined);
	return true;

ret_false:
	if (dest_joined)
		mem_free(dest_joined);
	if (src_joined)
		mem_free(src_joined);
	return false;
}

static unsigned char os_path_to_exe[270];

const char *os_get_path_to_exe(void)
{
	return os_path_to_exe;
}

static void os_init_path_to_exe(void)
{
	APIRET rc;
	PTIB tib;
	PPIB pib;
	size_t i, j;
	rc = DosGetInfoBlocks(&tib, &pib);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal("DosGetInfoBlocks returned an error: %s", error_decode(e));
	}
	rc = DosQueryModuleName(pib->pib_hmte, sizeof os_path_to_exe, os_path_to_exe);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal("DosQueryModuleName returned an error: %s", error_decode(e));
	}
	j = 0;
	for (i = 0; os_path_to_exe[i]; i++)
		if (os_is_path_separator(os_path_to_exe[i]))
			j = i + 1;
	os_path_to_exe[j] = 0;
}


bool os_tcgetattr(handle_t attr_unused h, os_termios_t *t, ajla_error_t *err)
{
	APIRET rc;
	A_DECL(KBDINFO, kbi);
	rc = KbdGetStatus(kbi, 0);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "KbdGetStatus returned an error: %s", error_decode(e));
		return false;
	}
	t->tc_flags = 0;
	if (kbi->fsMask & 2)
		t->tc_flags |= IO_Stty_Flag_Noecho;
	return true;
}

bool os_tcsetattr(handle_t attr_unused h, const os_termios_t *t, ajla_error_t *err)
{
	APIRET rc;
	A_DECL(KBDINFO, kbi);
	rc = KbdGetStatus(kbi, 0);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "KbdGetStatus returned an error: %s", error_decode(e));
		return false;
	}
	kbi->fsMask &= ~3;
	if (t->tc_flags & IO_Stty_Flag_Noecho)
		kbi->fsMask |= 2;
	else
		kbi->fsMask |= 1;
	rc = KbdSetStatus(kbi, 0);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "KbdSetStatus returned an error: %s", error_decode(e));
		return false;
	}
	return true;
}

void os_tcflags(os_termios_t *t, int flags)
{
	t->tc_flags = flags;
}

int os_tty_size(handle_t attr_unused h, int x, int y, int *nx, int *ny, mutex_t **mutex_to_lock, struct list *list_entry, ajla_error_t *err)
{
	A_DECL(VIOMODEINFO, vmi);
	APIRET rc;
	vmi->cb = sizeof(VIOMODEINFO);
	rc = VioGetMode(vmi, 0);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't get tty size: %s", error_decode(e));
		return 0;
	}

	*nx = vmi->col;
	*ny = vmi->row;

	if (*nx == x && *ny == y) {
		iomux_never(mutex_to_lock, list_entry);
		return 2;
	}

	return 1;
}


const char *os_get_flavor(void)
{
	return "OS/2";
}

void os_get_uname(os_utsname_t *un)
{
	ULONG version[2];

	memset(un, 0, sizeof(os_utsname_t));

	strcpy(un->sysname, "OS/2");

	if (!DosQuerySysInfo(QSV_VERSION_MAJOR, QSV_VERSION_MINOR, version, sizeof version)) {
		if (version[0] == 20) {
			version[0] = 2;
			if (version[1] == 10) {
				version[1] = 1;
			} else if (version[1] >= 30) {
				version[0] = version[1] / 10;
				version[1] %= 10;
			}
		}
		sprintf(un->release, "%d.%d", (int)version[0], (int)version[1]);
	}

#ifdef ARCH_NAME
	strcpy(un->machine, ARCH_NAME);
#endif
}

char *os_get_host_name(ajla_error_t *err)
{
	char *e;
	if (tcpip_loaded) {
		char nodename[256] = "";
		proc_gethostname(nodename, sizeof nodename - 1);
		if (nodename[0])
			return str_dup(nodename, -1, err);
	}
	e = getenv("HOSTNAME");
	if (!e)
		e = "";
	return str_dup(e, -1, err);
}


#if 0
static ajla_time_t os_timeval_to_ajla_time(const struct timeval *tv)
{
	return os_time_t_to_ajla_time(tv->tv_sec) + tv->tv_usec;
}
ajla_time_t os_time_real(void)
{
	int r;
	struct timeval tv;
	EINTR_LOOP(r, gettimeofday(&tv, NULL));
	if (unlikely(r == -1)) {
		int e = errno;
		fatal("gettimeofday failed: %d, %s", e, error_decode(error_from_errno(EC_SYSCALL, e)));
	}
	return os_timeval_to_ajla_time(&tv);
}
#else
ajla_time_t os_time_real(void)
{
	APIRET rc;
	DATETIME dt;
	int year, month, day, hour, min, sec;
	os_time_t ost;
	rc = DosGetDateTime(&dt);
	if (unlikely(rc != 0)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal("DosGetDateTime returned an error: %s", error_decode(e));
	}
	year = dt.year;
	month = dt.month;
	day = dt.day;
	hour = dt.hours;
	min = dt.minutes;
	sec = dt.seconds;
	ost = time_to_os_time(year, month, day, hour, min, sec) + timezone;
	return os_time_t_to_ajla_time(ost) + dt.hundredths * 10000;
}
#endif

static mutex_t tick_mutex;
static ULONG tick_last;
static ULONG tick_high;

ajla_time_t os_time_monotonic(void)
{
	APIRET rc;
	ULONG t;
	ajla_time_t ret;

	if (likely(proc_DosTmrQueryTime != NULL)) {
		union {
			QWORD qw;
			long long ll;
		} q;
		rc = proc_DosTmrQueryTime(&q.qw);
		if (unlikely(rc != 0)) {
			ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
			fatal("DosTmrQueryTime returned an error: %s", error_decode(e));
		}
		return (ajla_time_t)(q.ll * freq_period_usec);
	}

	if (likely(os_threads_initialized))
		mutex_lock(&tick_mutex);
	rc = DosQuerySysInfo(QSV_MS_COUNT, QSV_MS_COUNT, &t, sizeof t);
	if (unlikely(rc)) {
		ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
		fatal("DosQuerySysInfo(%u) returned an error: %s", QSV_MS_COUNT, error_decode(e));
	}
	if (unlikely(t < tick_last))
		tick_high++;
	tick_last = t;
	ret = ((ajla_time_t)tick_high * (1 << 31) * 2) + t;
	if (likely(os_threads_initialized))
		mutex_unlock(&tick_mutex);
	return ret * 1000;
}


void iomux_never(mutex_t **mutex_to_lock, struct list *list_entry)
{
	*mutex_to_lock = address_get_mutex(NULL, DEPTH_THUNK);
	list_init(list_entry);
}

static void os2_notify(void);

void iomux_register_wait(handle_t h, bool wr, mutex_t **mutex_to_lock, struct list *list_entry)
{
	struct os2_io_thread *thr;
	thr = !wr ? &h->rd : &h->wr;
	address_lock(h, DEPTH_THUNK);
	*mutex_to_lock = address_get_mutex(h, DEPTH_THUNK);
	list_add(&thr->wait_list, list_entry);
	if (h->t == HANDTYPE_SOCKET) {
		address_unlock(h, DEPTH_THUNK);
		mutex_lock(&socket_list_mutex);
		if (thr->socket_entry.next == NULL)
			list_add(&socket_list[(int)wr], &thr->socket_entry);
		mutex_unlock(&socket_list_mutex);
		os2_notify();
		return;
	}
	if (!wr) {
		if (unlikely(h->rd.buffer_len != 0) || unlikely(h->rd.packet_is_queued) || unlikely(h->rd.err != 0) || unlikely(h->rd.eof))
			goto wake_up;
		if (unlikely(h->ms.buffer_len != 0) || unlikely(h->ms.packet_is_queued) || unlikely(h->ms.err != 0) || unlikely(h->ms.eof))
			goto wake_up;
	} else {
		if (unlikely(h->wr.buffer_len != OS2_BUFFER_SIZE) || unlikely(h->wr.err != 0))
			goto wake_up;
	}
	address_unlock(h, DEPTH_THUNK);
	return;

wake_up:
	call(wake_up_wait_list)(&thr->wait_list, address_get_mutex(h, DEPTH_THUNK), true);
}

bool iomux_test_handle(handle_t h, bool wr)
{
	if (h->t == HANDTYPE_SOCKET) {
		int sel[1];
		int r;
again:
		sel[0] = h->h;
		r = proc_select(sel, !wr, wr, 0, 0);
		if (unlikely(r == -1)) {
			int er = proc_sock_errno();
			if (er == SOCEINTR)
				goto again;
			internal(file_line, "select returned an error: %d", er);
		}
		return !!r;
	}
	/*
	 * os_read/os_write is non-blocking even for standard handles,
	 * so we don't need this function
	 */
	return true;
}


struct proc_handle {
	struct tree_entry entry;
	PID pid;
	bool fired;
	bool detached;
	RESULTCODES codes;
	struct list wait_list;
};

static struct tree proc_tree;
static mutex_t proc_tree_mutex;
static TID proc_wait_thread;

static inline void proc_lock(void)
{
	mutex_lock(&proc_tree_mutex);
}

static inline void proc_unlock(void)
{
	mutex_unlock(&proc_tree_mutex);
}

static int proc_handle_compare(const struct tree_entry *e, uintptr_t pid)
{
	const struct proc_handle *ph = get_struct(e, struct proc_handle, entry);
	if (unlikely(ph->pid == (PID)pid)) return 0;
	if (ph->pid > (PID)pid) return 1;
	return -1;
}

static bool proc_addstr(char **ptr, size_t *len, const char *str, bool cvt_slashes, ajla_error_t *err)
{
	size_t i, j, bs;
	bool quote = false;
	if (*len) {
		if ((*ptr)[*len - 1]) {
			if (unlikely(!array_add_mayfail(char, ptr, len, ' ', NULL, err)))
				return false;
		}
		if (!str[0] || str[strcspn(str, " \t")])
			quote = true;
	}
	if (quote) {
		if (unlikely(!array_add_mayfail(char, ptr, len, '"', NULL, err)))
			return false;
	}
	bs = 0;
	for (i = 0; str[i]; i++) {
		char c = str[i];
		if (cvt_slashes && c == '/')
			c = '\\';
		if (c == '\\') {
			bs++;
		} else if (c == '"') {
			for (j = 0; j <= bs; j++)
				if (unlikely(!array_add_mayfail(char, ptr, len, '\\', NULL, err)))
					return false;
			bs = 0;
		} else {
			bs = 0;
		}
		if (unlikely(!array_add_mayfail(char, ptr, len, c, NULL, err)))
			return false;
	}
	if (quote) {
		for (j = 0; j < bs; j++)
			if (unlikely(!array_add_mayfail(char, ptr, len, '\\', NULL, err)))
					return false;
		if (unlikely(!array_add_mayfail(char, ptr, len, '"', NULL, err)))
			return false;
	}
	return true;
}

static void os2_wait_thread(ULONG attr_unused x)
{
	sig_state_t s;

	os_block_signals(&s);
lock_loop:
	proc_lock();

	while (!tree_is_empty(&proc_tree)) {
		RESULTCODES codes;
		PID pid;
		APIRET rc;
		struct tree_entry *e;
		struct proc_handle *ph;

		proc_unlock();
		os_unblock_signals(&s);

		rc = DosWaitChild(DCWA_PROCESS, DCWW_WAIT, &codes, &pid, 0);
		if (unlikely(rc))
			internal(file_line, "DosWaitChild returned an error: %lu", rc);

		os_block_signals(&s);
		proc_lock();

		e = tree_find(&proc_tree, proc_handle_compare, pid);
		if (!e) {
			continue;
		}

		ph = get_struct(e, struct proc_handle, entry);
		ph->fired = true;
		ph->codes = codes;
		tree_delete(&ph->entry);

		if (!ph->detached) {
			call(wake_up_wait_list)(&ph->wait_list, &proc_tree_mutex, false);
			goto lock_loop;
		} else {
			os2_free_buffer(ph);
		}
	}
	proc_wait_thread = 0;

	proc_unlock();
	os_unblock_signals(&s);
}

struct proc_handle *os_proc_spawn(dir_handle_t wd, const char *path, size_t n_handles, handle_t *source, int *target, char * const args[], char *envc, ajla_error_t *err)
{
	char * const *a;
	char *ptr, *copy_of_ptr, *copy_of_env;
	size_t len, env_len;
	char obj_name_buf[260];
	RESULTCODES codes;
	APIRET rc;
	HFILE i;
	ajla_error_t err_x, err_xx;
	struct proc_handle *ph;
	struct tree_entry *en;
	struct tree_insert_position ins;
	unsigned char *cwd;
	short mapping_table[OS2_MAX_HANDLE];

	if (!*args) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "empty arguments in spawn");
		return NULL;
	}

	if (unlikely(!array_init_mayfail(char, &ptr, &len, err)))
		return NULL;

	for (a = args; *a; a++) {
		if (!proc_addstr(&ptr, &len, *a, a == args, err))
			return NULL;
		if (a == args)
			if (unlikely(!array_add_mayfail(char, &ptr, &len, 0, NULL, err)))
				return NULL;
	}

	if (unlikely(!array_add_mayfail(char, &ptr, &len, 0, NULL, err)))
		return NULL;
	if (unlikely(!array_add_mayfail(char, &ptr, &len, 0, NULL, err)))
		return NULL;

	if (unlikely(len >= 65536)) {
		mem_free(ptr);
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "arguments size overflow");
		return NULL;
	}

	/*
	 * The EMX source code says that the argument buffer must not cross
	 * 64k boundary.
	 */
	copy_of_ptr = os2_alloc_buffer(len);
	if (unlikely(!copy_of_ptr)) {
		mem_free(ptr);
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), err, "out of memory for arg buffer (%"PRIuMAX" bytes)", (uintmax_t)len);
		return NULL;
	}
	memcpy(copy_of_ptr, ptr, len);
	mem_free(ptr);

	for (env_len = 0; envc[env_len];)
		env_len += strlen(envc + env_len) + 1;
	env_len++;
	copy_of_env = os2_alloc_buffer(env_len);
	if (unlikely(!copy_of_env)) {
		os2_free_buffer(copy_of_ptr);
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), err, "out of memory for env buffer (%"PRIuMAX" bytes)", (uintmax_t)env_len);
		return NULL;
	}
	memcpy(copy_of_env, envc, env_len);

	ph = os2_alloc_buffer(sizeof(struct proc_handle));
	if (unlikely(!ph)) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), err, "out of memory for process handle (%"PRIuMAX" bytes)", (uintmax_t)sizeof(struct proc_handle));
		os2_free_buffer(copy_of_ptr);
		os2_free_buffer(copy_of_env);
		return NULL;
	}
	ph->fired = false;
	ph->detached = false;
	list_init(&ph->wait_list);

	cwd = os_dir_cwd(err);
	if (unlikely(!cwd)) {
		os2_free_buffer(copy_of_ptr);
		os2_free_buffer(copy_of_env);
		return NULL;
	}

	proc_lock();

	if (!proc_wait_thread) {
		mutex_lock(&thread_spawn_mutex);
		rc = DosCreateThread(&proc_wait_thread, os2_wait_thread, 0, 0x2, OS2_IO_THREAD_STACK_SIZE);
		mutex_unlock(&thread_spawn_mutex);
		if (unlikely(rc != 0)) {
			ajla_error_t e = error_from_os2(EC_SYSCALL, rc);
			fatal_mayfail(e, err, "can't spawn wait thread: %s", error_decode(e));
			proc_unlock();
			mem_free(cwd);
			os2_free_buffer(copy_of_ptr);
			os2_free_buffer(copy_of_env);
			return NULL;
		}
	}

	for (i = 0; i < OS2_MAX_HANDLE; i++)
		mapping_table[i] = -1;

	os2_enter_critical_section();

	for (i = 0; i < n_handles; i++) {
		handle_t s = source[i];
		HFILE tgt;
		if (unlikely(s->t == HANDTYPE_SOCKET)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), &err_x, "socket can't be inherited by subprocesses on OS/2");
			goto handle_error;
		}
		address_lock(s, DEPTH_THUNK);
		if (s->rd.thread) {
			os2_terminate_io_thread(&s->rd);
		}
		if (s->ms.thread) {
			os2_terminate_io_thread(&s->ms);
		}
		address_unlock(s, DEPTH_THUNK);
		tgt = target[i];
		if (tgt >= OS2_MAX_HANDLE) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW), &err_x, "destination handle too large");
			goto handle_error;
		}
		if (!os2_handle_is_valid(tgt)) {
			/*debug("placeholder");*/
			if (unlikely(!os2_handle_placeholder(tgt, &err_x)))
				goto handle_error;
			mapping_table[tgt] = -2;
		}
	}
	for (i = 0; i < n_handles; i++) {
		HFILE tgt = target[i];
		if (mapping_table[tgt] == -1) {
			HFILE n;
			if (unlikely(!os2_handle_dup1(tgt, &n, &err_x)))
				goto handle_error;
			mapping_table[tgt] = n;
			/*debug("duplicating %lu -> %lu", tgt, n);*/
		}
	}
	for (i = 0; i < n_handles; i++) {
		HFILE src = source[i]->h;
		HFILE tgt = target[i];
		if (mapping_table[src] >= 0)
			src = mapping_table[src];
		/*debug("dup2: %lu -> %u", src, tgt);*/
		if (unlikely(!os2_handle_dup2(src, tgt, &err_x)))
			goto handle_error;
		os2_set_inherit(tgt, true);
	}

	if (unlikely(!os2_dir_set(wd, err))) {
		os2_exit_critical_section();
		proc_unlock();
		mem_free(cwd);
		os2_free_buffer(copy_of_ptr);
		os2_free_buffer(copy_of_env);
		return NULL;
	}

	rc = DosExecPgm(obj_name_buf, sizeof obj_name_buf, EXEC_ASYNCRESULT, copy_of_ptr, copy_of_env, &codes, path);

	if (0) {
handle_error:
		rc = (APIRET)-1;
	}

	for (i = 0; i < n_handles; i++) {
		if (mapping_table[i] == -2)
			os2_close_handle(target[i]);
	}
	for (i = 0; i < OS2_MAX_HANDLE; i++) {
		if (mapping_table[i] >= 0) {
			os2_handle_dup2(mapping_table[i], i, NULL);
			os2_close_handle(mapping_table[i]);
		}
	}
	/*for (i = 0; i < OS2_MAX_HANDLE; i++) {
		if (mapping_table[i] >= 0) {
			debug("restored: %u -> %u", mapping_table[i], i);
		}
	}*/

	os2_dir_set(cwd, &err_xx);

	os2_exit_critical_section();

	mem_free(cwd);
	os2_free_buffer(copy_of_ptr);
	os2_free_buffer(copy_of_env);

	if (unlikely(rc != 0)) {
		ajla_error_t e;
		proc_unlock();
		if (rc != (APIRET)-1) {
			e = error_from_os2(EC_SYSCALL, rc);
			fatal_mayfail(e, err, "DosExecPgm returned(%s) an error: %s", path, error_decode(e));
		} else {
			e = err_x;
			fatal_mayfail(e, err, "error preparing handles for spawn: %s", error_decode(e));
		}
		return NULL;
	}

	ph->pid = codes.codeTerminate;

	en = tree_find_for_insert(&proc_tree, proc_handle_compare, ph->pid, &ins);
	if (unlikely(en != NULL)) {
		fatal("pid %ld is already present in the tree", (long)ph->pid);
	}

	tree_insert_after_find(&ph->entry, &ins);

	proc_unlock();

	return ph;
}

void os_proc_free_handle(struct proc_handle *ph)
{
	proc_lock();
	ajla_assert_lo(list_is_empty(&ph->wait_list), (file_line, "os_proc_free_handle: freeing handle when there are processes waiting for it"));
	if (ph->fired) {
		proc_unlock();
		os2_free_buffer(ph);
	} else {
		ph->detached = true;
		proc_unlock();
	}
}

bool os_proc_register_wait(struct proc_handle *ph, mutex_t **mutex_to_lock, struct list *list_entry, int *status)
{
	proc_lock();
	if (ph->fired) {
		/*debug("exit: %lu, %lu", ph->codes.codeTerminate, ph->codes.codeResult);*/
		*status = ph->codes.codeResult;
		proc_unlock();
		return true;
	} else {
		*mutex_to_lock = &proc_tree_mutex;
		list_add(&ph->wait_list, list_entry);
		proc_unlock();
		return false;
	}
}


static int os2_notify_socket[2];

static bool os2_socketpair_af_unix(int result[2])
{
	int lst;
	struct sockaddr_un sun;
	socklen_t len;
	int r;
	int one;

	lst = -1;
	result[0] = result[1] = -1;

	lst = proc_socket(PF_UNIX, SOCK_STREAM, 0);
	if (unlikely(lst == -1))
		goto fail;

	memset(&sun, 0, sizeof sun);
	sun.sun_family = AF_UNIX;
	r = proc_bind(lst, (struct sockaddr *)&sun, sizeof sun);
	if (unlikely(r == -1))
		goto fail;

	len = sizeof sun;
	r = proc_getsockname(lst, (struct sockaddr *)&sun, &len);
	if (unlikely(r == -1))
		goto fail;

	r = proc_listen(lst, 1);
	if (unlikely(r == -1))
		goto fail;

	result[0] = proc_socket(PF_UNIX, SOCK_STREAM, 0);
	if (unlikely(result[0] == -1))
		goto fail;

	r = proc_connect(result[0], (struct sockaddr *)&sun, sizeof sun);
	if (unlikely(r == -1))
		goto fail;

	len = sizeof sun;
	result[1] = proc_accept(lst, (struct sockaddr *)&sun, &len);
	if (unlikely(result[1] == -1))
		goto fail;

	one = 1;
	r = proc_ioctl(result[0], FIONBIO, &one, sizeof one);
	if (unlikely(r == -1))
		goto fail;
	r = proc_ioctl(result[1], FIONBIO, &one, sizeof one);
	if (unlikely(r == -1))
		goto fail;

	proc_soclose(lst);

	return true;

fail:
	if (lst != -1)
		proc_soclose(lst);
	if (result[0] != -1)
		proc_soclose(result[0]);
	if (result[1] != -1)
		proc_soclose(result[1]);
	return false;
}

static bool os2_socketpair(int result[2])
{
	int lst;
	struct sockaddr_in sin;
	socklen_t len;
	int r;
	int one;

	if (os2_socketpair_af_unix(result))
		return true;

	lst = -1;
	result[0] = result[1] = -1;

	lst = proc_socket(PF_INET, SOCK_STREAM, 0);
	if (unlikely(lst == -1))
		goto fail;

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	r = proc_bind(lst, (struct sockaddr *)&sin, sizeof sin);
	if (unlikely(r == -1))
		goto fail;

	len = sizeof sin;
	r = proc_getsockname(lst, (struct sockaddr *)&sin, &len);
	if (unlikely(r == -1))
		goto fail;

	r = proc_listen(lst, 1);
	if (unlikely(r == -1))
		goto fail;

	result[0] = proc_socket(PF_INET, SOCK_STREAM, 0);
	if (unlikely(result[0] == -1))
		goto fail;

	r = proc_connect(result[0], (struct sockaddr *)&sin, sizeof sin);
	if (unlikely(r == -1))
		goto fail;

	len = sizeof sin;
	result[1] = proc_accept(lst, (struct sockaddr *)&sin, &len);
	if (unlikely(result[1] == -1))
		goto fail;

	one = 1;
	r = proc_ioctl(result[0], FIONBIO, &one, sizeof one);
	if (unlikely(r == -1))
		goto fail;
	r = proc_ioctl(result[1], FIONBIO, &one, sizeof one);
	if (unlikely(r == -1))
		goto fail;

	proc_soclose(lst);

	return true;

fail:
	if (lst != -1)
		proc_soclose(lst);
	if (result[0] != -1)
		proc_soclose(result[0]);
	if (result[1] != -1)
		proc_soclose(result[1]);
	return false;
}

static void os2_notify(void)
{
	int r;
	char c = 0;
	r = proc_send(os2_notify_socket[1], &c, 1, 0);
	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		if (er != SOCEAGAIN)
			fatal("error writing to the notify socket: %d", er);
	}
}

static bool os2_drain_notify_pipe(void)
{
	static char buffer[1024];
	int r;
	r = proc_recv(os2_notify_socket[0], buffer, sizeof buffer, 0);
	if (likely(r == -1)) {
		int er = proc_sock_errno();
		if (likely(er == SOCEAGAIN))
			return false;
		fatal("error reading the notify socket: %d", er);
	}
	return !r;
}

static void os2_shutdown_notify_pipe(void)
{
	int r;
	r = proc_shutdown(os2_notify_socket[0], 2);
	if (likely(r == -1)) {
		int er = errno;
		fatal("error shutting down the notify socket: %d", er);
	}
#ifdef DEBUG
	os2_notify();
#endif
}


handle_t os_socket(int domain, int type, int protocol, ajla_error_t *err)
{
	int sock;
	if (unlikely(!tcpip_loaded)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "TCP/IP is not installed");
		return NULL;
	}
	domain = os_socket_pf(domain, err);
	if (unlikely(domain == -1))
		return NULL;
	type = os_socket_type(type, err);
	if (unlikely(type == -1))
		return NULL;
	sock = proc_socket(domain, type, protocol);
	if (unlikely(sock == -1)) {
		fatal_mayfail(error_from_os2_socket(), err, "socket failed");
		return NULL;
	}
	return os2_socket_to_handle(sock, err);
}

bool os_bind_connect(bool bnd, handle_t h, unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	int r;
	int er;
	struct sockaddr *sa;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}
again:
	sa = os_get_sock_addr(addr, &addr_len, err);
	if (unlikely(!sa))
		return false;
	r = (likely(!bnd) ? proc_connect : proc_bind)(h->h, sa, addr_len);
	mem_free_aligned(sa);
	if (unlikely(!r))
		return true;
	er = proc_sock_errno();
	if (er == SOCEINTR)
		goto again;
	if (likely(!bnd) && likely(er == SOCEINPROGRESS))
		return true;
	fatal_mayfail(error_from_os2_socket(), err, "can't %s socket: %d", !bnd ? "connect" : "bind", er);
	return false;
}

bool os_connect_completed(handle_t h, ajla_error_t *err)
{
	int r;
	int er;
	socklen_t er_l = sizeof er;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	r = proc_getsockopt(h->h, SOL_SOCKET, SO_ERROR, &er, &er_l);
	if (unlikely(r == -1)) {
		fatal_mayfail(error_from_os2_socket(), err, "getsockopt returned an error: %d", proc_sock_errno());
		return false;
	}
	if (unlikely(er)) {
		ajla_error_t e = error_ajla_aux(EC_SYSCALL, AJLA_ERROR_OS2_SOCKET, er);
		fatal_mayfail(e, err, "can't connect socket: %d", er);
		return false;
	}
	return true;
}

bool os_listen(handle_t h, ajla_error_t *err)
{
	int r;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	r = proc_listen(h->h, signed_maximum(int));
	if (unlikely(r == -1)) {
		fatal_mayfail(error_from_os2_socket(), err, "listen returned an error: %d", proc_sock_errno());
		return false;
	}
	return true;
}

int os_accept(handle_t h, handle_t *result, ajla_error_t *err)
{
	int r;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return OS_RW_ERROR;
	}

again:
	r = proc_accept(h->h, NULL, 0);
	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		if (er == SOCEINTR)
			goto again;
		if (er == SOCEAGAIN)
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_os2_socket(), err, "accept returned an error: %d", er);
		return OS_RW_ERROR;
	}

	*result = os2_socket_to_handle(r, err);

	return unlikely(*result == NULL) ? OS_RW_ERROR : 0;
}

bool os_getsockpeername(bool peer, handle_t h, unsigned char **addr, size_t *addr_len, ajla_error_t *err)
{
	int r;
	struct sockaddr *sa;
	socklen_t addrlen;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	sa = mem_align_mayfail(struct sockaddr *, SOCKADDR_MAX_LEN, SOCKADDR_ALIGN, err);
	if (unlikely(!sa))
		return false;
	addrlen = SOCKADDR_MAX_LEN;

	r = (!peer ? proc_getsockname : proc_getpeername)(h->h, sa, &addrlen);
	if (r == -1) {
		int er = proc_sock_errno();
		fatal_mayfail(error_from_os2_socket(), err, "%s returned an error: %d", !peer ? "getsockname" : "getpeername", er);
		goto free_ret_false;
	}

	*addr = os_get_ajla_addr(sa, &addrlen, err);
	if (unlikely(!*addr))
		goto free_ret_false;

	*addr_len = addrlen;

	mem_free_aligned(sa);
	return true;

free_ret_false:
	mem_free_aligned(sa);
	return false;
}

ssize_t os_recvfrom(handle_t h, char *buffer, size_t len, int flags, unsigned char **addr, size_t *addr_len, ajla_error_t *err)
{
	int r, f;
	struct sockaddr *sa;
	socklen_t addrlen;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return OS_RW_ERROR;
	}

	f = translate_flags(os_socket_msg, flags, err);
	if (unlikely(f < 0))
		return OS_RW_ERROR;

	sa = mem_align_mayfail(struct sockaddr *, SOCKADDR_MAX_LEN, SOCKADDR_ALIGN, err);
	if (unlikely(!sa))
		return OS_RW_ERROR;
again:
	addrlen = SOCKADDR_MAX_LEN;
	r = proc_recvfrom(h->h, buffer, len, f, sa, &addrlen);
	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		if (er == SOCEINTR)
			goto again;
		if (er == SOCEAGAIN) {
			mem_free_aligned(sa);
			return OS_RW_WOULDBLOCK;
		}
		fatal_mayfail(error_from_os2_socket(), err, "recvfrom returned an error: %d", er);
		goto free_ret_error;
	}
	if (unlikely(addrlen > SOCKADDR_MAX_LEN)) {
		fatal_mayfail(error_ajla(EC_SYSCALL, AJLA_ERROR_SIZE_OVERFLOW), err, "the system returned too long address");
		goto free_ret_error;
	}

	if (!addrlen) {
		if (unlikely(!array_init_mayfail(unsigned char, addr, addr_len, err))) {
			goto free_ret_error;
		}
	} else {
		*addr = os_get_ajla_addr(sa, &addrlen, err);
		if (unlikely(!*addr))
			goto free_ret_error;
		*addr_len = addrlen;
	}

	mem_free_aligned(sa);
	return r;

free_ret_error:
	mem_free_aligned(sa);
	return OS_RW_ERROR;
}

ssize_t os_sendto(handle_t h, const char *buffer, size_t len, int flags, unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	int r, f;
	struct sockaddr *sa;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return OS_RW_ERROR;
	}

	f = translate_flags(os_socket_msg, flags, err);
	if (unlikely(f < 0))
		return OS_RW_ERROR;

again:
	if (addr_len != 0) {
		size_t al = addr_len;
		sa = os_get_sock_addr(addr, &al, err);
		if (unlikely(!sa))
			return OS_RW_ERROR;
		r = proc_sendto(h->h, buffer, len, f, sa, al);
		mem_free_aligned(sa);
	} else {
		r = proc_send(h->h, buffer, len, f);
	}

	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		if (er == SOCEINTR)
			goto again;
		if (er == SOCEAGAIN)
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_os2_socket(), err, "send%s returned an error: %d", addr_len ? "to" : "", er);
		return OS_RW_ERROR;
	}

	return r;
}

bool os_getsockopt(handle_t h, int level, int option, char **buffer, size_t *buffer_len, ajla_error_t *err)
{
	int r;
	socklen_t opt_len;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	level = os_socket_level(level, err);
	if (unlikely(level < 0))
		return false;

	option = os_socket_option(option, err);
	if (unlikely(level < 0))
		return false;

	opt_len = 4096;

	*buffer = mem_alloc_mayfail(char *, opt_len, err);
	if (unlikely(!*buffer))
		return false;

	r = proc_getsockopt(h->h, level, option, *buffer, &opt_len);

	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		fatal_mayfail(error_from_os2_socket(), err, "getsockopt returned an error: %d", er);
		mem_free(*buffer);
		return false;
	}

	*buffer_len = opt_len;
	return true;
}

bool os_setsockopt(handle_t h, int level, int option, const char *buffer, size_t buffer_len, ajla_error_t *err)
{
	int r;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(h->t != HANDTYPE_SOCKET)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	level = os_socket_level(level, err);
	if (unlikely(level < 0))
		return false;

	option = os_socket_option(option, err);
	if (unlikely(level < 0))
		return false;

	r = proc_setsockopt(h->h, level, option, buffer, buffer_len);

	if (unlikely(r == -1)) {
		int er = proc_sock_errno();
		fatal_mayfail(error_from_os2_socket(), err, "setsockopt returned an error: %d", er);
		return false;
	}

	return true;
}

bool os_getaddrinfo(const char *host, int port, struct address **result, size_t *result_l, ajla_error_t *err)
{
	struct hostent *he;
	size_t i;
	void *xresult;
	char *a;

	if (unlikely(!tcpip_loaded)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "TCP/IP is not installed");
		return false;
	}

	if (unlikely(!array_init_mayfail(struct address, result, result_l, err)))
		return false;

	he = proc_gethostbyname(host);

	if (unlikely(!he)) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_H_ERRNO, *proc_h_errno), err, "host not found");
		goto fail;
	}

	if (he->h_addrtype != AF_INET || he->h_length != 4 || !he->h_addr) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_H_ERRNO, NO_DATA), err, "host not found");
		goto fail;
	}

	for (i = 0; (a = he->h_addr_list[i]); i++) {
		struct sockaddr_in sin;
		struct sockaddr sa;
		struct address addr;
		ajla_error_t e;
		socklen_t addrlen = sizeof sin;

		sin.sin_family = AF_INET;
		sin.sin_port = (port << 8) | (port >> 8);
		memcpy(&sin.sin_addr, a, 4);

		memcpy(&sa, &sin, sizeof sin);

		addr.address = os_get_ajla_addr(&sa, &addrlen, &e);
		if (unlikely(!addr.address))
			continue;
		addr.address_length = addrlen;

		if (unlikely(!array_add_mayfail(struct address, result, result_l, addr, &xresult, err))) {
			*result = xresult;
			goto fail;
		}
	}

	if (unlikely(!*result_l)) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_H_ERRNO, NO_DATA), err, "host not found");
		goto fail;
	}

	return true;

fail:
	for (i = 0; i < *result_l; i++)
		mem_free((*result)[i].address);
	mem_free(*result);
	return false;
}

char *os_getnameinfo(unsigned char attr_unused *addr, size_t attr_unused addr_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "getnameinfo not supported");
	return NULL;
}

const char *os_decode_error(ajla_error_t attr_unused error, char attr_unused *(*tls_buffer)(void))
{
	return NULL;
}


static struct dl_handle_t *hdoscalls = NULL;
static struct dl_handle_t *hso32dll = NULL;
static struct dl_handle_t *htcp32dll = NULL;

struct dl_handle_t *os_dlopen(const char *filename, ajla_error_t *err, char **err_msg)
{
	char mod[9];
	HMODULE h;
	APIRET rc;
again:
	memset(mod, 0, sizeof mod);
	rc = DosLoadModule(mod, sizeof mod, filename, &h);
	_control87(CW_DEFAULT, 0xffff);
	if (unlikely(rc != 0)) {
		ajla_error_t e;
		if (rc == ERROR_INTERRUPT)
			goto again;
		if (err_msg)
			*err_msg = NULL;
		e = error_from_os2(EC_SYSCALL, rc);
		fatal_mayfail(e, err, "can't load library '%s': %s (%s)", filename, error_decode(e), mod);
		return NULL;

	}
	if (unlikely(!h))
		fatal("DosLoadModule returned zero");
	/*debug("loaded: %s -> %lu", filename, h);*/
	return num_to_ptr(h);
}

void os_dlclose(struct dl_handle_t *dlh)
{
	APIRET rc;
again:
	rc = DosFreeModule(ptr_to_num(dlh));
	_control87(CW_DEFAULT, 0xffff);
	if (unlikely(rc != 0)) {
		if (rc == ERROR_INTERRUPT)
			goto again;
		internal(file_line, "DosFreeModule returned an error: %lu", rc);
	}
}

static const struct {
	const char *name;
	unsigned ordinal;
} ordinals[] = {
#include "os_os2_s.inc"
};

bool os_dlsym(struct dl_handle_t *dlh, const char *symbol, void **result)
{
	APIRET rc;
	if (dlh == hdoscalls) {
		size_t r;
		binary_search(size_t, n_array_elements(ordinals), r, !strcmp(ordinals[r].name, symbol), strcmp(ordinals[r].name, symbol) < 0, return false);
		rc = DosQueryProcAddr(ptr_to_num(dlh), ordinals[r].ordinal, NULL, (PPFN)result);
		/*debug("symbol %s, ordinal %u, result %lu", symbol, ordinals[r].ordinal, rc);*/
	} else {
		rc = DosQueryProcAddr(ptr_to_num(dlh), 0, symbol, (PPFN)result);
		/*debug("symbol %s, result %lu", symbol, rc);*/
	}
	if (unlikely(rc != 0)) {
		*result = NULL;
		return false;
	}
	return true;
}


void os_code_invalidate_cache(uint8_t attr_unused *code_ptr, size_t attr_unused code_size, bool attr_unused set_exec)
{
}

void *os_code_map(uint8_t *code, size_t attr_unused code_size, ajla_error_t attr_unused *err)
{
	return code;
}

void os_code_unmap(void *mapped_code, size_t attr_unused code_size)
{
	mem_free(mapped_code);
}


static int compare_int(const void *x1, const void *x2)
{
	return *cast_ptr(const int *, x1) - *cast_ptr(const int *, x2);
}

static thread_t iomux_thread;

thread_function_decl(iomux_poll_thread,
	thread_set_id(-1);
	while (likely(!os2_drain_notify_pipe())) {
		int *select_arg;
		size_t select_arg_n;
		size_t select_arg_read = 0;
		int wr;
		int r;

		array_init(int, &select_arg, &select_arg_n);
		array_add(int, &select_arg, &select_arg_n, os2_notify_socket[0]);
		mutex_lock(&socket_list_mutex);
		for (wr = 0; wr < 2; wr++) {
			struct list *l;
			list_for_each(l, &socket_list[wr]) {
				struct os2_io_thread *thr = get_struct(l, struct os2_io_thread, socket_entry);
				handle_t h = thr->h;
				address_lock(h, DEPTH_THUNK);
				if (!list_is_empty(&thr->wait_list)) {
					array_add(int, &select_arg, &select_arg_n, h->h);
				} else {
					l = l->prev;
					list_del(&thr->socket_entry);
					thr->socket_entry.next = NULL;
				}
				address_unlock(h, DEPTH_THUNK);
			}
			if (!wr)
				select_arg_read = select_arg_n;
		}
		mutex_unlock(&socket_list_mutex);

		r = proc_select(select_arg, select_arg_read, select_arg_n - select_arg_read, 0, -1);

		if (unlikely(r == -1)) {
			int er = proc_sock_errno();
			if (er == SOCEINTR) {
				mem_free(select_arg);
				continue;
			}
			internal(file_line, "select returned an error: %d", er);
		}

		qsort(select_arg, select_arg_read, sizeof(int), compare_int);
		qsort(select_arg + select_arg_read, select_arg_n - select_arg_read, sizeof(int), compare_int);

		mutex_lock(&socket_list_mutex);
		for (wr = 0; wr < 2; wr++) {
			struct list *l;
			list_for_each(l, &socket_list[wr]) {
				struct os2_io_thread *thr = get_struct(l, struct os2_io_thread, socket_entry);
				handle_t h = thr->h;
				int hndl = h->h;
				void *p;
				if (!wr)
					p = bsearch(&hndl, select_arg, select_arg_read, sizeof(int), compare_int);
				else
					p = bsearch(&hndl, select_arg + select_arg_read, select_arg_n - select_arg_read, sizeof(int), compare_int);
				if (p) {
					address_lock(h, DEPTH_THUNK);
					call(wake_up_wait_list)(&thr->wait_list, address_get_mutex(h, DEPTH_THUNK), true);
				}
			}
		}
		mutex_unlock(&socket_list_mutex);
		mem_free(select_arg);
	}
)


void iomux_init(void)
{
}

void iomux_done(void)
{
}


static void os2_init_tcpip(void)
{
	ajla_error_t sink;
	if (tcpip_loaded)
		return;

	hso32dll = os_dlopen("SO32DLL", &sink, NULL);
	if (!hso32dll)
		return;
	htcp32dll = os_dlopen("TCP32DLL", &sink, NULL);
	if (!htcp32dll)
		return;
	if (!os_dlsym(hso32dll, "ACCEPT", (void **)&proc_accept) ||
	    !os_dlsym(hso32dll, "BIND", (void **)&proc_bind) ||
	    !os_dlsym(hso32dll, "CONNECT", (void **)&proc_connect) ||
	    !os_dlsym(htcp32dll, "GETHOSTBYNAME", (void **)&proc_gethostbyname) ||
	    !os_dlsym(htcp32dll, "GETHOSTNAME", (void **)&proc_gethostname) ||
	    !os_dlsym(hso32dll, "GETPEERNAME", (void **)&proc_getpeername) ||
	    !os_dlsym(hso32dll, "GETSOCKNAME", (void **)&proc_getsockname) ||
	    !os_dlsym(hso32dll, "GETSOCKOPT", (void **)&proc_getsockopt) ||
	    !os_dlsym(hso32dll, "IOCTL", (void **)&proc_ioctl) ||
	    !os_dlsym(hso32dll, "LISTEN", (void **)&proc_listen) ||
	    !os_dlsym(hso32dll, "RECV", (void **)&proc_recv) ||
	    !os_dlsym(hso32dll, "RECVFROM", (void **)&proc_recvfrom) ||
	    !os_dlsym(hso32dll, "SELECT", (void **)&proc_select) ||
	    !os_dlsym(hso32dll, "SEND", (void **)&proc_send) ||
	    !os_dlsym(hso32dll, "SENDTO", (void **)&proc_sendto) ||
	    !os_dlsym(hso32dll, "SETSOCKOPT", (void **)&proc_setsockopt) ||
	    !os_dlsym(hso32dll, "SHUTDOWN", (void **)&proc_shutdown) ||
	    !os_dlsym(hso32dll, "SOCKET", (void **)&proc_socket) ||
	    !os_dlsym(hso32dll, "SOCK_ERRNO", (void **)&proc_sock_errno) ||
	    !os_dlsym(hso32dll, "SOCK_INIT", (void **)&proc_sock_init) ||
	    !os_dlsym(hso32dll, "SOCLOSE", (void **)&proc_soclose) ||
	    !os_dlsym(htcp32dll, "H_ERRNO", (void **)&proc_h_errno) ||
	     proc_sock_init()) {
		return;
	}
	if (!os2_socketpair(os2_notify_socket))
		return;

	tcpip_loaded = true;
}

bool os2_test_for_32bit_tcpip(const char *mem)
{
	int r;

	os2_init_tcpip();

	if (unlikely(!tcpip_loaded))
		return true;

	r = proc_send(os2_notify_socket[1], mem, 1, 0);

	return r >= 0;
}


void os_init(void)
{
	APIRET rc;
#ifdef DEBUG
	unsigned i;
	for (i = 0; i < n_array_elements(os2_error_to_system_error) - 1; i++)
		if (unlikely(os2_error_to_system_error[i].errn >= os2_error_to_system_error[i + 1].errn))
			internal(file_line, "os_init: os2_error_to_system_error is not monotonic at %u", i);
	for (i = 0; i < n_array_elements(socket_error_to_system_error) - 1; i++)
		if (unlikely(socket_error_to_system_error[i].errn >= socket_error_to_system_error[i + 1].errn))
			internal(file_line, "os_init: socket_error_to_system_error is not monotonic at %u", i);
#endif
	os_threads_initialized = false;

	os_init_path_to_exe();

	n_std_handles = 0;
	while (1) {
		ULONG htype, hattr;
		rc = DosQueryHType(n_std_handles, &htype, &hattr);
		if (rc)
			break;
		n_std_handles++;

	}
	if (unlikely(n_std_handles < 3))
		exit(127);

	tick_high = 0;
	tick_last = 0;

	tzset();

	hdoscalls = os_dlopen("DOSCALLS", NULL, NULL);

	os_dlsym(hdoscalls, "DosTmrQueryFreq", (void **)&proc_DosTmrQueryFreq);
	os_dlsym(hdoscalls, "DosTmrQueryTime", (void **)&proc_DosTmrQueryTime);
	if (proc_DosTmrQueryFreq) {
		ULONG tmr_freq;
		QWORD qw;
		rc = proc_DosTmrQueryFreq(&tmr_freq);
		if (unlikely(rc != 0))
			goto no_dos_tmr_q;
		freq_period_usec = (long double)1000000 / tmr_freq;
		rc = proc_DosTmrQueryTime(&qw);
		if (unlikely(rc != 0))
			goto no_dos_tmr_q;
	} else {
no_dos_tmr_q:
		proc_DosTmrQueryFreq = NULL;
		proc_DosTmrQueryTime = NULL;
	}
	os_dlsym(hdoscalls, "DosOpenL", (void **)&proc_DosOpenL);
	os_dlsym(hdoscalls, "DosSetFilePtrL", (void **)&proc_DosSetFilePtrL);
	os_dlsym(hdoscalls, "DosSetFileSizeL", (void **)&proc_DosSetFileSizeL);
	/*debug("%p %p %p", proc_DosOpenL, proc_DosSetFilePtrL, proc_DosSetFileSizeL);*/

	os2_init_tcpip();

	os_cwd = os_dir_cwd(NULL);
}

void os_done(void)
{
	os_dir_close(os_cwd);

	if (tcpip_loaded) {
		os2_close_socket(os2_notify_socket[0]);
		os2_close_socket(os2_notify_socket[1]);
		tcpip_loaded = false;
	}
}

void os_init_multithreaded(void)
{
	unsigned u;

	os_init_calendar_lock();

	mutex_init(&tick_mutex);
	list_init(&deferred_write_list);
	list_init(&deferred_closed_list);
	mutex_init(&deferred_mutex);
	os_threads_initialized = true;

	tree_init(&proc_tree);
	mutex_init(&proc_tree_mutex);
	proc_wait_thread = 0;

	os2_std_handles = mem_alloc_array_mayfail(mem_alloc_mayfail, handle_t *, 0, 0, n_std_handles, sizeof(handle_t), NULL);
	for (u = 0; u < n_std_handles; u++) {
		os2_set_inherit(u, false);
		os2_std_handles[u] = os2_hfile_to_handle(u, (!u ? O_RDONLY : O_WRONLY) | O_NONBLOCK, 0, NULL);
	}

#if 0
	{
		int i = 0;
		while (1) {
			debug("X1: %d", i++);
			os2_create_read_thread(os2_std_handles[0], NULL);
			/*os2_terminate_io_thread(&os2_std_handles[0]->rd);*/
			os_free_handle(os2_std_handles[0], false);
			os2_std_handles[0] = os2_hfile_to_handle(0, O_RDONLY | O_NONBLOCK, 0, NULL);
		}
	}
#endif
#if 0
	{
		int i = 0;
		while (1) {
			ssize_t r;
			char c;
			handle_t p[2];
			debug("X2: %d", i++);
			os_pipe(p, 3, NULL);
			r = os_read(p[0], &c, 1, NULL);
			r = r;
			r = rand() & 0xffff;
			while (r--)
				__asm__ volatile("nop":::"memory");
			os_close(p[0]);
			os_close(p[1]);
		}
	}
#endif

	if (tcpip_loaded) {
		mutex_init(&socket_list_mutex);
		list_init(&socket_list[0]);
		list_init(&socket_list[1]);
		thread_spawn(&iomux_thread, iomux_poll_thread, NULL, PRIORITY_IO, NULL);
	}
}

void os_done_multithreaded(void)
{
	unsigned u;
	TID pwt;

	if (tcpip_loaded) {
		os2_shutdown_notify_pipe();
		thread_join(&iomux_thread);
		ajla_assert_lo(list_is_empty(&socket_list[0]), (file_line, "os_done_multithreaded: read socket list is not empty"));
		ajla_assert_lo(list_is_empty(&socket_list[1]), (file_line, "os_done_multithreaded: write socket list is not empty"));
		mutex_done(&socket_list_mutex);
	}

	for (u = 0; u < n_std_handles; u++) {
		os_free_handle(os2_std_handles[u], false);
		os2_set_inherit(u, true);
	}
	mem_free(os2_std_handles);
	os2_std_handles = NULL;

	mutex_lock(&deferred_mutex);
	while (!list_is_empty(&deferred_write_list)) {
		mutex_unlock(&deferred_mutex);
		DosSleep(1);
		mutex_lock(&deferred_mutex);
	}
	mutex_unlock(&deferred_mutex);
	os2_clean_up_handles();

	proc_lock();
	if (unlikely(!tree_is_empty(&proc_tree))) {
		struct proc_handle *ph = get_struct(tree_any(&proc_tree), struct proc_handle, entry);
		tree_delete(&ph->entry);
		os2_free_buffer(ph);
	}
	pwt = proc_wait_thread;
	proc_unlock();
	if (pwt)
		os2_terminate_thread(pwt, true);

	mutex_done(&proc_tree_mutex);
	mutex_done(&deferred_mutex);
	mutex_done(&tick_mutex);

	os_done_calendar_lock();

	os_threads_initialized = false;
}

#endif
