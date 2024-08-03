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

#ifdef OS_WIN32

#include "str.h"
#include "obj_reg.h"
#include "addrlock.h"
#include "thread.h"
#include "timer.h"
#include "os_util.h"

#include "os.h"
#include "iomux.h"

#include <stdio.h>
#include <time.h>


#define WIN32_BUFFER_SIZE		4096
#define WIN32_LINE_BUFFER_SIZE		4096
#define WIN32_IO_THREAD_STACK_SIZE	4096

#define SOCKADDR_MAX_LEN		512
#define SOCKADDR_ALIGN			16

#define CONNECT_TIMEOUT			500000

struct win32_io_thread {
	handle_t h;
	HANDLE thread;
	char *buffer;
	unsigned buffer_pos;
	unsigned buffer_len;
	char *line_buffer;
	unsigned line_buffer_pos;
	unsigned line_buffer_size;
	DWORD err;
	bool line_buffer_eof;
	bool eof;
	bool should_close;
	bool need_terminate;
	HANDLE data_event;
	HANDLE startup_event;
	HANDLE terminate_mutex;
	HANDLE terminate_event;
	atomic_type uchar_efficient_t is_packet_console;
	bool packet_is_queued;
	struct console_read_packet packet;
	unsigned last_buttons;
};

struct win32_handle {
	HANDLE h;
	SOCKET s;
	DWORD type;
	int flags;
	bool is_console;
	bool is_overlapped;

	int tc_flags;

	char utf8_buffer[5];
	uint8_t utf8_buffer_size;

	struct list wait_list[2];

	struct win32_io_thread *rd;
	struct win32_io_thread *wr;

	bool connect_in_progress;
	struct list socket_entry[2];

	struct list deferred_entry;

	char file_name[FLEXIBLE_ARRAY];
};

struct fdx_set {
	u_int fd_count;
	SOCKET fd_array[1];
};


#include "os_com.inc"


static HMODULE handle_iphlpa;

static LPCSTR (WINAPI *fn_GetEnvironmentStrings)(void);
static LPCSTR (WINAPI *fn_GetEnvironmentStringsA)(void);
static LPCWSTR (WINAPI *fn_GetEnvironmentStringsW)(void);
static BOOL (WINAPI *fn_FreeEnvironmentStringsA)(LPCSTR env);
static BOOL (WINAPI *fn_FreeEnvironmentStringsW)(LPCWSTR env);
static LONG (NTAPI *fn_RtlGetVersion)(POSVERSIONINFOW lpVersionInformation);
static VOID (NTAPI *fn_RtlFreeUserThreadStack)(HANDLE ProcessHandle, HANDLE ThreadHandle);
static BOOL (WINAPI *fn_GetDiskFreeSpaceExA)(LPCSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);
static BOOL (WINAPI *fn_GetDiskFreeSpaceExW)(LPWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);
static BOOL (WINAPI *fn_CancelIo)(HANDLE hFile);
static BOOL (WINAPI *fn_CancelIoEx)(HANDLE hFile, LPOVERLAPPED lpOverlapped);
static BOOL (WINAPI *fn_MoveFileExA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags);
static BOOL (WINAPI *fn_MoveFileExW)(LPWSTR lpExistingFileName, LPWSTR lpNewFileName, DWORD dwFlags);
static BOOL (WINAPI *fn_FlushInstructionCache)(HANDLE hProcess, LPCVOID *lpBaseAddress, SIZE_T dwSize);
static DWORD (WINAPI *fn_GetNetworkParams)(char *, PULONG pOutBufLen);
static uint64_t (WINAPI *fn_GetTickCount64)(void);

/* QPC is broken, it sometimes jumps backwards, so don't use it by default */
#ifdef USER_QPC
static BOOL (WINAPI *fn_QueryPerformanceFrequency)(LARGE_INTEGER *lpPerformanceCount);
static BOOL (WINAPI *fn_QueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount);
static long double perf_multiplier;
#endif

typedef struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	size_t ai_addrlen;
	char *ai_canonname;
	struct sockaddr *ai_addr;
	struct addrinfo *ai_next;
} ADDRINFOA, *PADDRINFOA;

typedef ADDRINFOA ADDRINFO, *LPADDRINFO;

#define EAI_NONAME	WSAHOST_NOT_FOUND

static int (WINAPI *fn_getaddrinfo)(const char *nodename, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
static void (WINAPI *fn_freeaddrinfo)(LPADDRINFO pAddrInfo);
static int (WINAPI *fn_getnameinfo)(const struct sockaddr *sockaddr, socklen_t sockaddr_len, char *node, DWORD node_size, char *service, DWORD service_size, int flags);


static bool os_threads_initialized;

static handle_t win32_std_handles[3];

dir_handle_t os_cwd;

static struct list deferred_write_list;
static struct list deferred_closed_list;
static mutex_t deferred_mutex;

static bool winsock_supported;
static struct list socket_list[2];
static mutex_t socket_list_mutex;


struct system_error_table_entry {
	unsigned short errn;
	unsigned short sys_error;
};

static const struct system_error_table_entry win32_error_to_system_error[] = {
	{ ERROR_INVALID_FUNCTION,		SYSTEM_ERROR_EINVAL },
	{ ERROR_FILE_NOT_FOUND,			SYSTEM_ERROR_ENOENT },
	{ ERROR_PATH_NOT_FOUND,			SYSTEM_ERROR_ENOENT },
	{ ERROR_TOO_MANY_OPEN_FILES,		SYSTEM_ERROR_EMFILE },
	{ ERROR_ACCESS_DENIED,			SYSTEM_ERROR_EACCES },
	{ ERROR_INVALID_HANDLE,			SYSTEM_ERROR_EBADF },
	{ ERROR_NOT_ENOUGH_MEMORY,		SYSTEM_ERROR_ENOMEM },
	{ ERROR_OUTOFMEMORY,			SYSTEM_ERROR_ENOMEM },
	{ ERROR_INVALID_DRIVE,			SYSTEM_ERROR_ENOENT },
	{ ERROR_NOT_SAME_DEVICE,		SYSTEM_ERROR_EXDEV },
	{ ERROR_WRITE_PROTECT,			SYSTEM_ERROR_EROFS },
	{ ERROR_NOT_READY,			SYSTEM_ERROR_ENOMEDIUM },
	{ ERROR_CRC,				SYSTEM_ERROR_EIO },
	{ ERROR_SECTOR_NOT_FOUND,		SYSTEM_ERROR_EIO },
	{ ERROR_SHARING_VIOLATION,		SYSTEM_ERROR_EBUSY },
	{ ERROR_HANDLE_DISK_FULL,		SYSTEM_ERROR_ENOSPC },
	{ ERROR_NOT_SUPPORTED,			SYSTEM_ERROR_EOPNOTSUPP },
	{ ERROR_DEV_NOT_EXIST,			SYSTEM_ERROR_ENXIO },
	{ ERROR_NETWORK_ACCESS_DENIED,		SYSTEM_ERROR_EACCES },
	{ ERROR_FILE_EXISTS,			SYSTEM_ERROR_EEXIST },
	{ ERROR_DRIVE_LOCKED,			SYSTEM_ERROR_EBUSY },
	{ ERROR_BROKEN_PIPE,			SYSTEM_ERROR_EPIPE },
	{ ERROR_OPEN_FAILED,			SYSTEM_ERROR_ENOENT },
	{ ERROR_BUFFER_OVERFLOW,		SYSTEM_ERROR_ENAMETOOLONG },
	{ ERROR_DISK_FULL,			SYSTEM_ERROR_ENOSPC },
	{ ERROR_INVALID_NAME,			SYSTEM_ERROR_EINVAL },
	{ ERROR_NEGATIVE_SEEK,			SYSTEM_ERROR_EINVAL },
	{ ERROR_SEEK_ON_DEVICE,			SYSTEM_ERROR_ESPIPE },
	{ ERROR_DIR_NOT_EMPTY,			SYSTEM_ERROR_ENOTEMPTY },
	{ ERROR_BUSY,				SYSTEM_ERROR_EBUSY },
	{ ERROR_ALREADY_EXISTS,			SYSTEM_ERROR_EEXIST },
	{ ERROR_FILENAME_EXCED_RANGE,		SYSTEM_ERROR_ENAMETOOLONG },
	{ /*ERROR_FILE_TOO_LARGE*/ 223,		SYSTEM_ERROR_EOVERFLOW },
	{ ERROR_NO_DATA,			SYSTEM_ERROR_EPIPE },
	{ ERROR_DIRECTORY,			SYSTEM_ERROR_ENOTDIR },
	{ 567,					SYSTEM_ERROR_ENOMEM },
	{ WSAEINTR,				SYSTEM_ERROR_EINTR },
	{ WSAEBADF,				SYSTEM_ERROR_EBADF },
	{ WSAEACCES,				SYSTEM_ERROR_EACCES },
	{ WSAEFAULT,				SYSTEM_ERROR_EFAULT },
	{ WSAEINVAL,				SYSTEM_ERROR_EINVAL },
	{ WSAEMFILE,				SYSTEM_ERROR_EMFILE },
	{ WSAEWOULDBLOCK,			SYSTEM_ERROR_EAGAIN },
	{ WSAEINPROGRESS,			SYSTEM_ERROR_EINPROGRESS },
	{ WSAEALREADY,				SYSTEM_ERROR_EALREADY },
	{ WSAENOTSOCK,				SYSTEM_ERROR_ENOTSOCK },
	{ WSAEDESTADDRREQ,			SYSTEM_ERROR_EDESTADDRREQ },
	{ WSAEMSGSIZE,				SYSTEM_ERROR_EMSGSIZE },
	{ WSAEPROTOTYPE,			SYSTEM_ERROR_EPROTOTYPE },
	{ WSAENOPROTOOPT,			SYSTEM_ERROR_ENOPROTOOPT },
	{ WSAEPROTONOSUPPORT,			SYSTEM_ERROR_EPROTONOSUPPORT },
	{ WSAESOCKTNOSUPPORT,			SYSTEM_ERROR_ESOCKTNOSUPPORT },
	{ WSAEOPNOTSUPP,			SYSTEM_ERROR_EOPNOTSUPP },
	{ WSAEPFNOSUPPORT,			SYSTEM_ERROR_EPFNOSUPPORT },
	{ WSAEAFNOSUPPORT,			SYSTEM_ERROR_EAFNOSUPPORT },
	{ WSAEADDRINUSE,			SYSTEM_ERROR_EADDRINUSE },
	{ WSAEADDRNOTAVAIL,			SYSTEM_ERROR_EADDRNOTAVAIL },
	{ WSAENETDOWN,				SYSTEM_ERROR_ENETDOWN },
	{ WSAENETUNREACH,			SYSTEM_ERROR_ENETUNREACH },
	{ WSAENETRESET,				SYSTEM_ERROR_ENETRESET },
	{ WSAECONNABORTED,			SYSTEM_ERROR_ECONNABORTED },
	{ WSAECONNRESET,			SYSTEM_ERROR_ECONNRESET },
	{ WSAENOBUFS,				SYSTEM_ERROR_ENOBUFS },
	{ WSAEISCONN,				SYSTEM_ERROR_EISCONN },
	{ WSAENOTCONN,				SYSTEM_ERROR_ENOTCONN },
	{ WSAESHUTDOWN,				SYSTEM_ERROR_ESHUTDOWN },
	{ WSAETOOMANYREFS,			SYSTEM_ERROR_ETOOMANYREFS },
	{ WSAETIMEDOUT,				SYSTEM_ERROR_ETIMEDOUT },
	{ WSAECONNREFUSED,			SYSTEM_ERROR_ECONNREFUSED },
	{ WSAELOOP,				SYSTEM_ERROR_ELOOP },
	{ WSAENAMETOOLONG,			SYSTEM_ERROR_ENAMETOOLONG },
	{ WSAEHOSTDOWN,				SYSTEM_ERROR_EHOSTDOWN },
	{ WSAEHOSTUNREACH,			SYSTEM_ERROR_EHOSTUNREACH },
	{ WSAENOTEMPTY,				SYSTEM_ERROR_ENOTEMPTY },
	{ WSAEUSERS,				SYSTEM_ERROR_EUSERS },
	{ WSAEDQUOT,				SYSTEM_ERROR_EDQUOT },
	{ WSAESTALE,				SYSTEM_ERROR_ESTALE },
	{ WSAEREMOTE,				SYSTEM_ERROR_EREMOTE },
	{ WSAEDISCON,				SYSTEM_ERROR_EPIPE },
};

#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES		((DWORD)-1)
#endif

#ifndef FILE_READ_ONLY
#define FILE_READ_ONLY			8
#endif

static ajla_error_t error_from_win32(int ec, DWORD rc)
{
	size_t r;
	binary_search(size_t, n_array_elements(win32_error_to_system_error), r, win32_error_to_system_error[r].errn == rc, win32_error_to_system_error[r].errn < rc, return error_ajla_aux(ec, AJLA_ERROR_WIN32, rc));
	return error_ajla_aux(ec, AJLA_ERROR_SYSTEM, win32_error_to_system_error[r].sys_error);
}

static ajla_error_t error_from_win32_socket(int errn)
{
	if (unlikely(!winsock_supported)) {
		return error_ajla(EC_SYSCALL, AJLA_ERROR_NOT_SUPPORTED);
	}
	return error_from_win32(EC_SYSCALL, errn);
}

uint32_t os_get_last_error(void)
{
	return GetLastError();
}

uint32_t os_get_last_socket_error(void)
{
	return WSAGetLastError();
}

#ifdef BIT64

#define is_winnt()	true

#else

static bool is_winnt(void)
{
	return (GetVersion() & 0x80000000U) == 0;
}

#endif

static WCHAR *utf8_to_wchar(const char *str, ajla_error_t *err)
{
	WCHAR *r;
	size_t l;
	ajla_error_t e;

	if (unlikely(!array_init_mayfail(WCHAR, &r, &l, err)))
		return NULL;

	while (*str) {
		unsigned char c = *str++;
		unsigned char d, e, f;
		uint32_t u;
		if (likely(c < 0x80)) {
			u = c;
		} else if (unlikely(c < 0xc0)) {
			goto invalid;
		} else if (likely(c < 0xe0)) {
			d = *str++;
			if (unlikely(d < 0x80) || unlikely(d >= 0xc0))
				goto invalid;
			u = ((uint32_t)(c & 0x1f) << 6) | (d & 0x3f);
			if (unlikely(u < 0x80))
				goto invalid;
		} else if (likely(c < 0xf0)) {
			d = *str++;
			if (unlikely(d < 0x80) || unlikely(d >= 0xc0))
				goto invalid;
			e = *str++;
			if (unlikely(e < 0x80) || unlikely(e >= 0xc0))
				goto invalid;
			u = ((uint32_t)(c & 0xf) << 12) | ((uint32_t)(d & 0x3f) << 6) | (e & 0x3f);
			if (unlikely(u < 0x800))
				goto invalid;
		} else if (likely(c < 0xf8)) {
			d = *str++;
			if (unlikely(d < 0x80) || unlikely(d >= 0xc0))
				goto invalid;
			e = *str++;
			if (unlikely(e < 0x80) || unlikely(e >= 0xc0))
				goto invalid;
			f = *str++;
			if (unlikely(f < 0x80) || unlikely(f >= 0xc0))
				goto invalid;
			u = ((uint32_t)(c & 0x7) << 18) | ((uint32_t)(d & 0x3f) << 12) | ((uint32_t)(e & 0x3f) << 6) | (f & 0x3f);
			if (unlikely(u < 0x10000) || unlikely(u >= 0x110000))
				goto invalid;
		} else {
			goto invalid;
		}
		if (u < 0x10000) {
			if (unlikely(u >= 0xd800) && unlikely(u < 0xe000))
				goto invalid;
			if (unlikely(!array_add_mayfail(WCHAR, &r, &l, u, NULL, err)))
				return NULL;
		} else {
			uint16_t u1, u2;
			u -= 0x10000;
			u1 = (u >> 10) | 0xd800;
			u2 = (u & 0x3ff) | 0xdc00;
			if (unlikely(!array_add_mayfail(WCHAR, &r, &l, u1, NULL, err)))
				return NULL;
			if (unlikely(!array_add_mayfail(WCHAR, &r, &l, u2, NULL, err)))
				return NULL;
		}
	}

	if (unlikely(!array_add_mayfail(WCHAR, &r, &l, 0, NULL, err)))
		return false;

	return r;

invalid:
	mem_free(r);
	e = error_from_win32(EC_SYSCALL, AJLA_ERROR_INVALID_OPERATION);
	fatal_mayfail(e, err, "invalid utf-8");
	return NULL;
}

static char *wchar_to_utf8(char *result, const WCHAR *str, ajla_error_t *err)
{
	char *r;
	size_t l;
	ajla_error_t e;

	if (likely(!result)) {
		if (unlikely(!array_init_mayfail(char, &r, &l, err)))
			return NULL;
	} else {
		r = result;
		l = 0;
	}

#define emit_char(ch)							\
do {									\
	if (likely(!result)) {						\
		if (unlikely(!array_add_mayfail(char, &r, &l, ch, NULL, err)))\
			return NULL;					\
	} else {							\
		result[l++] = (ch);					\
	}								\
} while (0)

	while (*str) {
		uint32_t w = (uint16_t)*str++;
		if (unlikely((w & 0xfc00) == 0xd800)) {
			uint32_t hi = (w & 0x3ff) << 10;
			uint32_t lo = (uint16_t)*str++;
			if (unlikely((lo & 0xfc00) != 0xdc00))
				goto invalid;
			lo &= 0x3ff;
			w = hi + lo + 0x10000;
		}
		if (likely(w < 0x80)) {
			emit_char(w);
		} else if (likely(w < 0x800)) {
			emit_char(0xc0 | (w >> 6));
			emit_char(0x80 | (w & 0x3f));
		} else if (likely(w < 0x10000)) {
			emit_char(0xe0 | (w >> 12));
			emit_char(0x80 | ((w >> 6) & 0x3f));
			emit_char(0x80 | (w & 0x3f));
		} else if (likely(w < 0x110000)) {
			emit_char(0xf0 | (w >> 18));
			emit_char(0x80 | ((w >> 12) & 0x3f));
			emit_char(0x80 | ((w >> 6) & 0x3f));
			emit_char(0x80 | (w & 0x3f));
		} else {
			goto invalid;
		}
	}

	emit_char(0);

#undef emit_char

	if (likely(!result)) {
		array_finish(char, &r, &l);
	}

	return r;

invalid:
	if (likely(!result))
		mem_free(r);
	e = error_from_win32(EC_SYSCALL, AJLA_ERROR_INVALID_OPERATION);
	fatal_mayfail(e, err, "invalid utf-16");
	return NULL;
}


void os_block_signals(sig_state_t attr_unused *set)
{
}

void os_unblock_signals(const sig_state_t attr_unused *set)
{
}

void os_stop(void)
{
	warning("stop not supported on Windows");
}


static void win32_close_handle(HANDLE h)
{
	if (unlikely(!CloseHandle(h)))
		internal(file_line, "CloseHandle failed: %u", GetLastError());
}

static void win32_close_change_notification_handle(HANDLE h)
{
	if (unlikely(!FindCloseChangeNotification(h)))
		internal(file_line, "FindCloseChangeNotification failed: %u", GetLastError());
}

static void win32_close_socket(SOCKET s)
{
	if (unlikely(closesocket(s) == SOCKET_ERROR))
		warning("closesocket returned an error: %u", WSAGetLastError());
}

static void win32_set_event(HANDLE h)
{
	if (unlikely(!SetEvent(h)))
		internal(file_line, "SetEvent failed: %u", GetLastError());
}


static handle_t win32_hfile_to_handle(HANDLE hfile, int flags, bool overlapped, char *file_name, ajla_error_t *err)
{
	size_t file_name_len;
	handle_t h;
	DWORD type, gle, cmode;

	SetLastError(0);
	type = GetFileType(hfile);
	if (unlikely(type == FILE_TYPE_UNKNOWN) && (gle = GetLastError())) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't get file type: %s", error_decode(e));
		win32_close_handle(hfile);
		return NULL;
	}
	type &= ~FILE_TYPE_REMOTE;

	file_name_len = strlen(file_name);

	h = struct_alloc_array_mayfail(mem_calloc_mayfail, struct win32_handle, file_name, file_name_len + 1, err);
	if (unlikely(!h)) {
		win32_close_handle(hfile);
		return NULL;
	}

	memcpy(h->file_name, file_name, file_name_len + 1);

	if (GetConsoleMode(hfile, &cmode)) {
		h->is_console = true;
	}

	h->is_overlapped = overlapped;

	h->h = hfile;
	h->s = INVALID_SOCKET;
	h->type = type;
	if (type == FILE_TYPE_DISK)
		flags &= ~O_NONBLOCK;
	h->flags = flags;

	list_init(&h->wait_list[0]);
	list_init(&h->wait_list[1]);

	obj_registry_insert(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);

	return h;
}

static handle_t win32_socket_to_handle(SOCKET sock, ajla_error_t *err)
{
	handle_t h;
	u_long one = 1;

	if (unlikely(ioctlsocket(sock, FIONBIO, &one) == SOCKET_ERROR)) {
		fatal_mayfail(error_from_win32_socket(WSAGetLastError()), err, "could not set socket non-blocking");
		win32_close_socket(sock);
		return NULL;
	}

	h = struct_alloc_array_mayfail(mem_calloc_mayfail, struct win32_handle, file_name, 1, err);
	if (unlikely(!h)) {
		win32_close_socket(sock);
		return NULL;
	}

	h->h = INVALID_HANDLE_VALUE;
	h->s = sock;
	h->flags = O_RDWR | O_NONBLOCK;

	list_init(&h->wait_list[0]);
	list_init(&h->wait_list[1]);

	obj_registry_insert(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);

	return h;
}

static inline bool handle_is_socket(handle_t h)
{
	return h->s != INVALID_SOCKET;
}

uintptr_t os_handle_to_number(handle_t h)
{
	if (handle_is_socket(h))
		return h->s;
	else
		return ptr_to_num(h->h);
}

handle_t os_number_to_handle(uintptr_t n, bool sckt, ajla_error_t *err)
{
	if (!sckt) {
		return win32_hfile_to_handle(num_to_ptr(n), O_RDWR, false, "", err);
	} else {
		if (unlikely(!winsock_supported)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "TCP/IP is not configured");
			return NULL;
		}
		return win32_socket_to_handle(n, err);
	}
}

static void win32_clean_up_handles(void);

handle_t os_open(dir_handle_t dir, const char *path, int flags, int mode, ajla_error_t *err)
{
	char *joined;
	DWORD access, disposition, attrs, share_mode;
	HANDLE hfile;
	DWORD gle;
	handle_t h;

	win32_clean_up_handles();

	joined = os_join_paths(dir, path, false, err);
	if (unlikely(!joined))
		return NULL;

	switch (flags & 3) {
		case O_RDONLY:	access = GENERIC_READ; break;
		case O_WRONLY:	access = GENERIC_WRITE; break;
		case O_RDWR:	access = GENERIC_READ | GENERIC_WRITE; break;
		default: internal(file_line, "os_open: invalid flags %x", flags); return NULL;
	}

	switch (flags & (O_CREAT | O_EXCL | O_TRUNC)) {
		case 0:					disposition = OPEN_EXISTING; break;
		case O_CREAT:				disposition = OPEN_ALWAYS; break;
		case O_CREAT | O_EXCL:			disposition = CREATE_NEW; break;
		case O_TRUNC:				disposition = TRUNCATE_EXISTING; break;
		case O_TRUNC | O_CREAT:			disposition = CREATE_ALWAYS; break;
		case O_TRUNC | O_CREAT | O_EXCL:	disposition = CREATE_NEW; break;
		default: internal(file_line, "os_open: invalid flags %x", flags); return NULL;
	}

	attrs = 0;
	if (!(mode & 0222))
		attrs |= FILE_READ_ONLY;

	share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
retry:
	if (is_winnt()) {
		WCHAR *w = utf8_to_wchar(joined, err);
		if (unlikely(!w)) {
			mem_free(joined);
			return NULL;
		}
		hfile = CreateFileW(w, access, share_mode, NULL, disposition, attrs, NULL);
		gle = GetLastError();
		mem_free(w);
	} else {
		hfile = CreateFileA(joined, access, share_mode, NULL, disposition, attrs, NULL);
		gle = GetLastError();
	}
	if (unlikely(hfile == INVALID_HANDLE_VALUE)) {
		ajla_error_t e;
		if (gle == ERROR_INVALID_PARAMETER && share_mode & FILE_SHARE_DELETE) {
			share_mode &= ~FILE_SHARE_DELETE;
			goto retry;
		}
		e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't open file '%s': %s", joined, error_decode(e));
		mem_free(joined);
		return NULL;
	}
	h = win32_hfile_to_handle(hfile, flags, false, joined, err);
	mem_free(joined);
	return h;
}

static mutex_t pipe_count_mutex;
static uint64_t pipe_count;

bool os_pipe(handle_t result[2], int nonblock_flags, ajla_error_t *err)
{
	HANDLE h1, h2;
	bool overlapped = false;

	win32_clean_up_handles();

	if (unlikely(!fn_CancelIoEx) && likely(fn_CancelIo != NULL)) {
		char name[256];
		uint64_t pc;
retry:
		if (likely(os_threads_initialized))
			mutex_lock(&pipe_count_mutex);
		pc = pipe_count++;
		if (likely(os_threads_initialized))
			mutex_unlock(&pipe_count_mutex);
		sprintf(name, "\\\\.\\pipe\\ajla-%x-%08x%08x", (unsigned)GetCurrentProcessId(), (unsigned)(pc >> 32), (unsigned)pc);
		h1 = CreateNamedPipeA(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 0, 0, 0, NULL);
		if (unlikely(h1 == INVALID_HANDLE_VALUE)) {
			ajla_error_t e;
			DWORD gle = GetLastError();
			if (gle == ERROR_CALL_NOT_IMPLEMENTED)
				goto unnamed_pipe;
			if (gle == ERROR_PIPE_BUSY)
				goto retry;
			e = error_from_win32(EC_SYSCALL, gle);
			fatal_mayfail(e, err, "can't create named pipe: %s", error_decode(e));
			return false;
		}
		h2 = CreateFileA(name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
		if (unlikely(h2 == INVALID_HANDLE_VALUE)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't connect to create named pipe: %s", error_decode(e));
			win32_close_handle(h1);
			return false;
		}
		overlapped = true;
	} else {
unnamed_pipe:
		if (unlikely(!CreatePipe(&h1, &h2, NULL, 0))) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't create pipe: %s", error_decode(e));
			return false;
		}
	}

	result[0] = win32_hfile_to_handle(h1, O_RDONLY | (nonblock_flags & 1 ? O_NONBLOCK : 0), overlapped, "", err);
	if (unlikely(!result[0])) {
		win32_close_handle(h1);
		return false;
	}
	result[1] = win32_hfile_to_handle(h2, O_WRONLY | (nonblock_flags & 2 ? O_NONBLOCK : 0), overlapped, "", err);
	if (unlikely(!result[1])) {
		os_close(result[0]);
		return false;
	}

	return true;
}

static void win32_terminate_io_thread(struct win32_io_thread *thr);

static void os_free_handle(handle_t h, bool should_close)
{
	ajla_assert_lo(list_is_empty(&h->wait_list[0]), (file_line, "os_free_handle: freeing handle when there are processes waiting for read"));
	ajla_assert_lo(list_is_empty(&h->wait_list[1]), (file_line, "os_free_handle: freeing handle when there are processes waiting for write"));
	obj_registry_remove(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (h->rd) {
		win32_terminate_io_thread(h->rd);
	}
	if (h->wr) {
		address_lock(h, DEPTH_THUNK);
		if (h->wr->buffer_len != 0 && !h->wr->err) {
			h->wr->eof = true;
			h->wr->should_close = should_close;
			mutex_lock(&deferred_mutex);
			list_add(&deferred_write_list, &h->deferred_entry);
			mutex_unlock(&deferred_mutex);
			address_unlock(h, DEPTH_THUNK);
			return;
		}
		address_unlock(h, DEPTH_THUNK);
		win32_terminate_io_thread(h->wr);
	}
	if (likely(should_close)) {
		if (handle_is_socket(h)) {
			mutex_lock(&socket_list_mutex);
			if (h->socket_entry[0].next != NULL)
				list_del(&h->socket_entry[0]);
			if (h->socket_entry[1].next != NULL)
				list_del(&h->socket_entry[1]);
			mutex_unlock(&socket_list_mutex);
			win32_close_socket(h->s);
		} else {
			win32_close_handle(h->h);
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
	return 3;
}

handle_t os_get_std_handle(unsigned h)
{
	return win32_std_handles[h];
}

static HANDLE get_std_handle(unsigned u)
{
	DWORD s;
	HANDLE h;
	switch (u) {
		case 0:	s = STD_INPUT_HANDLE; break;
		case 1:	s = STD_OUTPUT_HANDLE; break;
		case 2:	s = STD_ERROR_HANDLE; break;
		default: internal(file_line, "get_std_handle: invalid handle %u", u);
	}
	h = GetStdHandle(s);
	if (unlikely(h == INVALID_HANDLE_VALUE)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal("can't get standard handle %u: %s", u, error_decode(e));
	}
	return h;
}

static void win32_clean_up_handles(void)
{
	if (!list_is_empty(&deferred_closed_list)) {
		mutex_lock(&deferred_mutex);
		while (!list_is_empty(&deferred_closed_list)) {
			handle_t h = get_struct(deferred_closed_list.prev, struct win32_handle, deferred_entry);
			list_del(&h->deferred_entry);
			obj_registry_insert(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
			os_free_handle(h, false);
		}
		mutex_unlock(&deferred_mutex);
	}
}


static void wait_for_event(HANDLE event)
{
	DWORD r = WaitForSingleObject(event, INFINITE);
	if (likely(r == WAIT_OBJECT_0))
		return;
	if (r == WAIT_FAILED)
		internal(file_line, "WaitForSingleObject failed: %u", GetLastError());
	internal(file_line, "WaitForSingleObject returned: %x", r);
}

static bool wait_for_event_timeout(HANDLE event)
{
	DWORD r = WaitForSingleObject(event, 1);
	if (likely(r == WAIT_OBJECT_0))
		return true;
	if (likely(r == WAIT_TIMEOUT))
		return false;
	if (r == WAIT_FAILED)
		internal(file_line, "WaitForSingleObject failed: %u", GetLastError());
	internal(file_line, "WaitForSingleObject returned: %x", r);
	return false;
}

static unsigned wait_for_2_events(HANDLE event1, HANDLE event2)
{
	DWORD r;
	HANDLE a[2];
	a[0] = event1;
	a[1] = event2;
	r = WaitForMultipleObjects(2, a, FALSE, INFINITE);
	if (likely(r >= WAIT_OBJECT_0 + zero) && likely(r < WAIT_OBJECT_0 + 2))
		return r - WAIT_OBJECT_0;
	if (unlikely(r == WAIT_FAILED))
		internal(file_line, "WaitForMultipleObjects failed: %u", GetLastError());
	internal(file_line, "WaitForMultipleObjects returned: %x", r);
	return 0;
}

static void unlock_mutex(HANDLE mutex)
{
	if (unlikely(!ReleaseMutex(mutex)))
		internal(file_line, "ReleaseMutex failed: %u", GetLastError());
}

static bool use_terminate_thread(struct win32_io_thread *thr)
{
	return unlikely(!fn_CancelIoEx) && !thr->h->is_console && !thr->h->is_overlapped;
}

static void lock_io_thread(struct win32_io_thread *thr)
{
	if (unlikely(use_terminate_thread(thr)))
		wait_for_event(thr->terminate_mutex);
	address_lock(thr->h, DEPTH_THUNK);
}

static void unlock_io_thread(struct win32_io_thread *thr)
{
	address_unlock(thr->h, DEPTH_THUNK);
	if (unlikely(use_terminate_thread(thr)))
		unlock_mutex(thr->terminate_mutex);
}

static int read_console_packet(struct win32_io_thread *thr, struct console_read_packet *p)
{
	unsigned w;
	INPUT_RECORD ev;
	DWORD nr;
	bool wnt = is_winnt();
again:
	w = wait_for_2_events(thr->terminate_event, thr->h->h);
	if (unlikely(!w))
		return 0;
	if (unlikely(!load_relaxed(&thr->is_packet_console)))
		return 0;
	if (wnt) {
		if (unlikely(!ReadConsoleInputW(thr->h->h, &ev, 1, &nr)))
			return -1;
	} else {
		if (unlikely(!ReadConsoleInputA(thr->h->h, &ev, 1, &nr)))
			return -1;
	}
	memset(p, 0, sizeof(struct console_read_packet));
	if (ev.EventType == KEY_EVENT && ev.Event.KeyEvent.bKeyDown) {
		/*debug("%x - %x - %x", ev.Event.KeyEvent.uChar.AsciiChar, ev.Event.KeyEvent.wVirtualKeyCode, ev.Event.KeyEvent.dwControlKeyState);*/
		p->type = 1;
		p->u.k.vkey = ev.Event.KeyEvent.wVirtualKeyCode;
		p->u.k.ctrl = ev.Event.KeyEvent.dwControlKeyState;
		if (wnt) {
			p->u.k.key = ev.Event.KeyEvent.uChar.UnicodeChar;
		} else {
			p->u.k.key = (unsigned char)ev.Event.KeyEvent.uChar.AsciiChar;
			p->u.k.cp = GetConsoleCP();
		}
		return 1;
	}
	if (ev.EventType == MOUSE_EVENT) {
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		HANDLE g;
		unsigned i;
		for (i = 2; i >= 1; i--) {
			g = get_std_handle(i);
			if (likely(GetConsoleScreenBufferInfo(g, &csbi)))
				goto have_csbi;
		}
		goto again;
have_csbi:
		p->type = 2;
		p->u.m.x = ev.Event.MouseEvent.dwMousePosition.X - csbi.srWindow.Left;
		p->u.m.y = ev.Event.MouseEvent.dwMousePosition.Y - csbi.srWindow.Top;
		p->u.m.prev_buttons = thr->last_buttons;
		p->u.m.buttons = thr->last_buttons = ev.Event.MouseEvent.dwButtonState & 0x1f;
		if (ev.Event.MouseEvent.dwEventFlags & 4)
			p->u.m.wy = ev.Event.MouseEvent.dwButtonState & 0x80000000U ? 1 : -1;
		if (ev.Event.MouseEvent.dwEventFlags & 8)
			p->u.m.wx = ev.Event.MouseEvent.dwButtonState & 0x80000000U ? 1 : -1;
		return 1;
		/*debug("%u %u %x %x", ev.Event.MouseEvent.dwMousePosition.X, ev.Event.MouseEvent.dwMousePosition.Y, ev.Event.MouseEvent.dwButtonState, ev.Event.MouseEvent.dwEventFlags);*/
	}
	goto again;
}

static void echo(struct win32_io_thread *thr, WCHAR ch)
{
	DWORD cmode;
	HANDLE g;
	unsigned i;
	if (thr->h->tc_flags & IO_Stty_Flag_Noecho)
		return;
	for (i = 2; i >= 1; i--) {
		g = get_std_handle(i);
		if (GetConsoleMode(g, &cmode)) {
			DWORD wr;
			if (is_winnt()) {
				WriteConsoleW(g, &ch, 1, &wr, NULL);
			} else {
				char cha = ch;
				WriteConsoleA(g, &cha, 1, &wr, NULL);
			}
			return;
		}
	}
}

static BOOL read_console(struct win32_io_thread *thr, char *buffer, unsigned len, DWORD *rd)
{
	unsigned w;
	INPUT_RECORD ev;
	DWORD nr;
	WCHAR ch;
	*rd = 0;
again:
	if (thr->line_buffer_pos) {
		unsigned tx = min(len, thr->line_buffer_pos);
		unsigned rem = thr->line_buffer_size - thr->line_buffer_pos;
		memcpy(buffer, thr->line_buffer, tx);
		memmove(thr->line_buffer, thr->line_buffer + tx, rem);
		thr->line_buffer_pos -= tx;
		thr->line_buffer_size -= tx;
		*rd = tx;
		return TRUE;
	}
	if (unlikely(thr->line_buffer_eof) && !thr->line_buffer_size)
		return TRUE;
	w = wait_for_2_events(thr->terminate_event, thr->h->h);
	if (unlikely(!w))
		return TRUE;
	if (unlikely(load_relaxed(&thr->is_packet_console)))
		return TRUE;
	if (is_winnt()) {
		if (unlikely(!ReadConsoleInputW(thr->h->h, &ev, 1, &nr)))
			return FALSE;
		ch = ev.Event.KeyEvent.uChar.UnicodeChar;
	} else {
		if (unlikely(!ReadConsoleInputA(thr->h->h, &ev, 1, &nr)))
			return FALSE;
		ch = ev.Event.KeyEvent.uChar.AsciiChar;
	}
	if (ev.EventType == KEY_EVENT && ev.Event.KeyEvent.bKeyDown && ch && !thr->line_buffer_eof) {
		if (ch == 26 && !(thr->h->tc_flags & IO_Stty_Flag_Raw)) {
			thr->line_buffer_eof = true;
			thr->line_buffer_pos = thr->line_buffer_size;
		} else if (ch == 8 && !(thr->h->tc_flags & IO_Stty_Flag_Raw)) {
			if (thr->line_buffer_size > thr->line_buffer_pos) {
				echo(thr, 8);
				echo(thr, ' ');
				echo(thr, 8);
				thr->line_buffer_size--;
			}
		} else if ((ch == 10 || ch == 13) && !(thr->h->tc_flags & IO_Stty_Flag_Raw)) {
			if (thr->line_buffer_size <= WIN32_LINE_BUFFER_SIZE - 2) {
				thr->line_buffer[thr->line_buffer_size++] = 13;
				thr->line_buffer[thr->line_buffer_size++] = 10;
				thr->line_buffer_pos = thr->line_buffer_size;
			}
			echo(thr, 13);
			echo(thr, 10);
		} else {
			char ch_buffer[5];
			size_t ch_len;
			if (is_winnt()) {
				WCHAR wchstr[2];
				wchstr[0] = ch;
				wchstr[1] = 0;
				if (unlikely(!wchar_to_utf8(ch_buffer, wchstr, NULL)))
					goto skip_invalid_char;
			} else {
				ch_buffer[0] = ch;
				ch_buffer[1] = 0;
			}
			ch_len = strlen(ch_buffer);
			if (thr->line_buffer_size <= WIN32_LINE_BUFFER_SIZE - 2 - ch_len) {
				memcpy(&thr->line_buffer[thr->line_buffer_size], ch_buffer, ch_len);
				thr->line_buffer_size += ch_len;
				if (thr->h->tc_flags & IO_Stty_Flag_Raw)
					thr->line_buffer_pos = thr->line_buffer_size;
			}
skip_invalid_char:
			echo(thr, ch);
		}
	}
	goto again;
}

static BOOL read_overlapped(struct win32_io_thread *thr, char *buffer, unsigned len, DWORD *rd)
{
	unsigned w;
	OVERLAPPED ovl;
	memset(&ovl, 0, sizeof ovl);
	if (unlikely(!ReadFile(thr->h->h, buffer, len, rd, &ovl))) {
		DWORD gle = GetLastError();
		if (gle != ERROR_IO_PENDING)
			return FALSE;
	}
	w = wait_for_2_events(thr->terminate_event, thr->h->h);
	if (unlikely(!w)) {
		if (unlikely(!fn_CancelIo(thr->h->h)))
			internal(file_line, "CancelIo failed: %u", GetLastError());
	}
	return GetOverlappedResult(thr->h->h, &ovl, rd, TRUE);
}

static DWORD WINAPI win32_read_thread(LPVOID thr_)
{
	struct win32_io_thread *thr = thr_;
	if (unlikely(use_terminate_thread(thr)))
		win32_set_event(thr->startup_event);
	while (1) {
		lock_io_thread(thr);
		if (unlikely(thr->err) || unlikely(thr->eof) || unlikely(thr->need_terminate)) {
			unlock_io_thread(thr);
			break;
		} else if (load_relaxed(&thr->is_packet_console)) {
			int b;
			DWORD gle;
			if (thr->packet_is_queued)
				goto wait_for_space;
			unlock_io_thread(thr);
			b = read_console_packet(thr, &thr->packet);
			gle = GetLastError();
			lock_io_thread(thr);
			if (unlikely(b < 0)) {
				if (unlikely(gle == ERROR_OPERATION_ABORTED)) {
				} if (likely(gle == ERROR_BROKEN_PIPE)) {
					thr->eof = true;
				} else {
					thr->err = gle;
				}
			} else if (b > 0) {
				if (likely(load_relaxed(&thr->is_packet_console)))
					thr->packet_is_queued = true;
			}
			call(wake_up_wait_list)(&thr->h->wait_list[0], address_get_mutex(thr->h, DEPTH_THUNK), false);
			if (unlikely(use_terminate_thread(thr)))
				unlock_mutex(thr->terminate_mutex);
		} else if (thr->buffer_len < WIN32_BUFFER_SIZE) {
			BOOL b;
			DWORD gle;
			DWORD rd = 0;
			size_t ptr = (thr->buffer_pos + thr->buffer_len) % WIN32_BUFFER_SIZE;
			size_t len = thr->buffer_pos <= ptr ? WIN32_BUFFER_SIZE - ptr : thr->buffer_pos - ptr;
			unlock_io_thread(thr);
			if (thr->h->is_console)
				b = read_console(thr, thr->buffer + ptr, len, &rd);
			else if (thr->h->is_overlapped)
				b = read_overlapped(thr, thr->buffer + ptr, len, &rd);
			else
				b = ReadFile(thr->h->h, thr->buffer + ptr, len, &rd, NULL);
			gle = GetLastError();
			lock_io_thread(thr);
			thr->buffer_len += rd;
			if (unlikely(!b)) {
				if (unlikely(gle == ERROR_OPERATION_ABORTED)) {
				} if (likely(gle == ERROR_BROKEN_PIPE)) {
					thr->eof = true;
				} else {
					thr->err = gle;
				}
			} else if (!rd) {
				if (!load_relaxed(&thr->is_packet_console))
					thr->eof = true;
			}
			call(wake_up_wait_list)(&thr->h->wait_list[0], address_get_mutex(thr->h, DEPTH_THUNK), false);
			if (unlikely(use_terminate_thread(thr)))
				unlock_mutex(thr->terminate_mutex);
		} else {
wait_for_space:
			if (unlikely(!ResetEvent(thr->data_event)))
				internal(file_line, "ResetEvent failed: %u", GetLastError());
			unlock_io_thread(thr);
			wait_for_event(thr->data_event);
		}
	}
	return 0;
}

static BOOL write_overlapped(struct win32_io_thread *thr, char *buffer, unsigned len, DWORD *wr)
{
	unsigned w;
	OVERLAPPED ovl;
	memset(&ovl, 0, sizeof ovl);
	if (unlikely(!WriteFile(thr->h->h, buffer, len, wr, &ovl))) {
		DWORD gle = GetLastError();
		if (gle != ERROR_IO_PENDING)
			return FALSE;
	}
	w = wait_for_2_events(thr->terminate_event, thr->h->h);
	if (unlikely(!w)) {
		if (unlikely(!fn_CancelIo(thr->h->h)))
			internal(file_line, "CancelIo failed: %u", GetLastError());
	}
	return GetOverlappedResult(thr->h->h, &ovl, wr, TRUE);
}

static DWORD WINAPI win32_write_thread(LPVOID thr_)
{
	struct win32_io_thread *thr = thr_;
	if (unlikely(use_terminate_thread(thr)))
		win32_set_event(thr->startup_event);
	while (1) {
		lock_io_thread(thr);
		if (unlikely(thr->err) || unlikely(thr->need_terminate)) {
			if (thr->eof && !thr->need_terminate)
				goto eof;
			unlock_io_thread(thr);
			break;
		} else if (thr->buffer_len) {
			BOOL b;
			DWORD gle;
			DWORD wr = 0;
			size_t len = minimum(thr->buffer_len, WIN32_BUFFER_SIZE - thr->buffer_pos);
			unlock_io_thread(thr);
			if (thr->h->is_overlapped)
				b = write_overlapped(thr, thr->buffer + thr->buffer_pos, len, &wr);
			else
				b = WriteFile(thr->h->h, thr->buffer + thr->buffer_pos, len, &wr, NULL);
			gle = GetLastError();
			lock_io_thread(thr);
			thr->buffer_pos = (thr->buffer_pos + wr) % WIN32_BUFFER_SIZE;
			thr->buffer_len -= wr;
			if (unlikely(!b)) {
				if (gle != ERROR_OPERATION_ABORTED)
					thr->err = gle;
			}
			call(wake_up_wait_list)(&thr->h->wait_list[1], address_get_mutex(thr->h, DEPTH_THUNK), false);
			if (unlikely(use_terminate_thread(thr)))
				unlock_mutex(thr->terminate_mutex);
		} else if (unlikely(thr->eof)) {
eof:
			thr->buffer_len = 0;
			if (thr->should_close)
				win32_close_handle(thr->h->h);
			mutex_lock(&deferred_mutex);
			list_del(&thr->h->deferred_entry);
			list_add(&deferred_closed_list, &thr->h->deferred_entry);
			mutex_unlock(&deferred_mutex);
			unlock_io_thread(thr);
			break;
		} else {
			if (unlikely(!ResetEvent(thr->data_event)))
				internal(file_line, "ResetEvent failed: %u", GetLastError());
			unlock_io_thread(thr);
			wait_for_event(thr->data_event);
		}
	}
	return 0;
}

static bool win32_create_io_thread(handle_t h, struct win32_io_thread **pthr, LPTHREAD_START_ROUTINE win32_thread_function, ajla_error_t *err)
{
	struct win32_io_thread *thr;
	DWORD threadid;
	thr = mem_calloc_mayfail(struct win32_io_thread *, sizeof(struct win32_io_thread), err);
	if (unlikely(!thr))
		goto err;
	*pthr = thr;

	thr->h = h;
	thr->eof = false;
	thr->buffer_pos = thr->buffer_len = 0;

	thr->buffer = mem_alloc_mayfail(char *, WIN32_BUFFER_SIZE, err);
	if (unlikely(!thr->buffer))
		goto err0;
	thr->data_event = CreateEventA(NULL, TRUE, FALSE, NULL);
	if (unlikely(!thr->data_event)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal_mayfail(e, err, "can't create event: %s", error_decode(e));
		goto err1;
	}
	if (unlikely(use_terminate_thread(thr))) {
		thr->startup_event = CreateEventA(NULL, TRUE, FALSE, NULL);
		if (unlikely(!thr->startup_event)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't create event: %s", error_decode(e));
			goto err2;
		}
		thr->terminate_mutex = CreateMutexA(NULL, FALSE, NULL);
		if (unlikely(!thr->terminate_mutex)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't create mutex: %s", error_decode(e));
			goto err3;
		}
	}
	if (h->is_console || h->is_overlapped) {
		thr->terminate_event = CreateEventA(NULL, TRUE, FALSE, NULL);
		if (unlikely(!thr->terminate_event)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't create event: %s", error_decode(e));
			goto err4;
		}
	}
	if (h->is_console) {
		thr->line_buffer = mem_alloc_mayfail(char *, WIN32_LINE_BUFFER_SIZE, err);
		if (unlikely(!thr->line_buffer))
			goto err5;
	}

	thr->thread = CreateThread(NULL, WIN32_IO_THREAD_STACK_SIZE, win32_thread_function, thr, 0, &threadid);
	if (unlikely(!thr->thread)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal_mayfail(e, err, "can't create thread: %s", error_decode(e));
		goto err6;
	}

	if (unlikely(use_terminate_thread(thr))) {
		wait_for_event(thr->startup_event);
		win32_close_handle(thr->startup_event);
	}

	return true;

err6:
	if (h->is_console)
		mem_free(thr->line_buffer);
err5:
	if (h->is_console || h->is_overlapped)
		win32_close_handle(thr->terminate_event);
err4:
	if (unlikely(use_terminate_thread(thr)))
		win32_close_handle(thr->terminate_mutex);
err3:
	if (unlikely(use_terminate_thread(thr)))
		win32_close_handle(thr->startup_event);
err2:
	win32_close_handle(thr->data_event);
err1:
	mem_free(thr->buffer);
err0:
	mem_free(thr);
err:
	return false;
}

static void win32_terminate_io_thread(struct win32_io_thread *thr)
{
	DWORD gle;
	if (unlikely(use_terminate_thread(thr))) {
		wait_for_event(thr->terminate_mutex);
		if (likely(fn_RtlFreeUserThreadStack != NULL)) {
			CONTEXT context;
			if (unlikely(SuspendThread(thr->thread) == (DWORD)-1)) {
				gle = GetLastError();
				if (likely(gle == 5))
					goto already_terminating;
				internal(file_line, "SuspendThread failed: %u", gle);
			}
			context.ContextFlags = CONTEXT_CONTROL;
			if (unlikely(!GetThreadContext(thr->thread, &context))) {
				gle = GetLastError();
				if (likely(gle == 5))
					goto already_terminating;
				internal(file_line, "GetThreadContext failed: %u", gle);
			}
			fn_RtlFreeUserThreadStack(GetCurrentProcess(), thr->thread);
		}
already_terminating:
		if (unlikely(!TerminateThread(thr->thread, 0))) {
			gle = GetLastError();
			if (unlikely(gle != 87))
				internal(file_line, "TerminateThread failed: %u", gle);
		}
		unlock_mutex(thr->terminate_mutex);
		wait_for_event(thr->thread);
		win32_close_handle(thr->terminate_mutex);
	} else if (thr->h->is_console || thr->h->is_overlapped) {
		address_lock(thr->h, DEPTH_THUNK);
		thr->need_terminate = true;
		win32_set_event(thr->data_event);
		win32_set_event(thr->terminate_event);
		address_unlock(thr->h, DEPTH_THUNK);
		wait_for_event(thr->thread);
		win32_close_handle(thr->terminate_event);
		if (thr->h->is_console)
			mem_free(thr->line_buffer);
	} else {
		/*Sleep(1000);*/
csi_again:
		address_lock(thr->h, DEPTH_THUNK);
		thr->need_terminate = true;
		win32_set_event(thr->data_event);
		if (unlikely(!fn_CancelIoEx(thr->h->h, NULL))) {
			DWORD gle = GetLastError();
			if (unlikely(gle != 6) && unlikely(gle != 1168))
				internal(file_line, "CancelIoEx failed: %u", gle);
		}
		address_unlock(thr->h, DEPTH_THUNK);
		if (unlikely(!wait_for_event_timeout(thr->thread))) {
			goto csi_again;
		}
	}
	win32_close_handle(thr->thread);
	thr->thread = NULL;
	win32_close_handle(thr->data_event);
	mem_free(thr->buffer);
	mem_free(thr);
}

static bool win32_create_read_thread(handle_t h, ajla_error_t *err)
{
	if (unlikely(!h->rd))
		return win32_create_io_thread(h, &h->rd, win32_read_thread, err);
	return true;
}

static bool win32_create_write_thread(handle_t h, ajla_error_t *err)
{
	if (unlikely(!h->wr))
		return win32_create_io_thread(h, &h->wr, win32_write_thread, err);
	return true;
}

static void win32_close_read_thread(handle_t h)
{
	struct win32_io_thread *thr;
	address_lock(h, DEPTH_THUNK);
	if (!h->rd) {
		address_unlock(h, DEPTH_THUNK);
		return;
	}
	thr = h->rd;
	h->rd = NULL;
	call(wake_up_wait_list)(&h->wait_list[0], address_get_mutex(h, DEPTH_THUNK), true);
	win32_terminate_io_thread(thr);
}

static ssize_t os_read_nonblock(handle_t h, char *buffer, int size, ajla_error_t *err)
{
	ssize_t this_len;
	address_lock(h, DEPTH_THUNK);
	if (unlikely(!win32_create_read_thread(h, err))) {
		address_unlock(h, DEPTH_THUNK);
		return OS_RW_ERROR;
	}
	if (load_relaxed(&h->rd->is_packet_console)) {
		store_relaxed(&h->rd->is_packet_console, false);
		h->rd->packet_is_queued = false;
		win32_set_event(h->rd->data_event);
	}
	if (h->rd->buffer_len) {
		bool was_full = h->rd->buffer_len == WIN32_BUFFER_SIZE;
		this_len = minimum(h->rd->buffer_len, WIN32_BUFFER_SIZE - h->rd->buffer_pos);
		this_len = minimum(this_len, size);
		memcpy(buffer, h->rd->buffer + h->rd->buffer_pos, this_len);
		h->rd->buffer_pos = (h->rd->buffer_pos + this_len) % WIN32_BUFFER_SIZE;
		h->rd->buffer_len -= this_len;
		if (was_full) {
			win32_set_event(h->rd->data_event);
		}
	} else {
		if (unlikely(h->rd->err != 0)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, h->rd->err);
			fatal_mayfail(e, err, "can't read handle: %s", error_decode(e));
			this_len = OS_RW_ERROR;
			goto unlock_ret;
		}
		if (unlikely(h->rd->eof)) {
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
	if (unlikely(!win32_create_write_thread(h, err))) {
		address_unlock(h, DEPTH_THUNK);
		return OS_RW_ERROR;
	}
	if (unlikely(h->wr->err)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, h->wr->err);
		fatal_mayfail(e, err, "can't write handle: %s", error_decode(e));
		this_len = OS_RW_ERROR;
		goto unlock_ret;
	}
	if (h->wr->buffer_len < WIN32_BUFFER_SIZE) {
		bool was_empty = !h->wr->buffer_len;
		ptr = (h->wr->buffer_pos + h->wr->buffer_len) % WIN32_BUFFER_SIZE;
		this_len = h->wr->buffer_pos <= ptr ? WIN32_BUFFER_SIZE - ptr : h->wr->buffer_pos - ptr;
		this_len = minimum(this_len, size);
		memcpy(h->wr->buffer + ptr, buffer, this_len);
		h->wr->buffer_len += this_len;
		if (was_empty) {
			win32_set_event(h->wr->data_event);
		}
	} else {
		this_len = OS_RW_WOULDBLOCK;
	}
unlock_ret:
	address_unlock(h, DEPTH_THUNK);
	return this_len;
}

static bool win32_setfileptr(handle_t h, os_off_t off, DWORD rel, os_off_t *result, ajla_error_t *err)
{
	DWORD gle;
	LONG high;
	DWORD low_ret;
	if (unlikely(h->type != FILE_TYPE_DISK)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to seek on non-disk handle");
		return false;
	}
	high = off >> 31 >> 1;
	SetLastError(0);
	low_ret = SetFilePointer(h->h, off, &high, rel);
	gle = GetLastError();
	if (unlikely(gle != 0)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't set handle position: %s", error_decode(e));
		return false;
	}
	if (result) {
		*result = low_ret + ((uint64_t)(uint32_t)high << 32);
	}
	return true;
}

static ssize_t os_do_rw(handle_t h, char *buffer, int size, bool wr, os_off_t *off, ajla_error_t *err)
{
	BOOL b;
	DWORD result;
	bool need_lock = os_threads_initialized && (off || (h->flags & O_APPEND && likely(h->type == FILE_TYPE_DISK)));

	if (likely(need_lock))
		address_lock(h, DEPTH_THUNK);

	if (off) {
		if (unlikely(!win32_setfileptr(h, *off, FILE_BEGIN, NULL, err)))
			goto unlock_ret_error;
	} else if (h->flags & O_APPEND && likely(h->type == FILE_TYPE_DISK)) {
		if (unlikely(!win32_setfileptr(h, 0, FILE_END, NULL, err)))
			goto unlock_ret_error;
	}

do_io_again:
	if (!wr)
		b = ReadFile(h->h, buffer, size, &result, NULL);
	else
		b = WriteFile(h->h, buffer, size, &result, NULL);

	if (!b) {
		ajla_error_t e;
		DWORD gle = GetLastError();
		if (gle == ERROR_OPERATION_ABORTED) {
			if (!result)
				goto do_io_again;
			else
				goto ok;
		}
		e = error_from_win32(EC_SYSCALL, gle);

		if (likely(need_lock))
			address_unlock(h, DEPTH_THUNK);
		fatal_mayfail(e, err, "can't %s handle: %s", !wr ? "read from" : "write to", error_decode(e));
		return OS_RW_ERROR;
	}

ok:
	if (likely(need_lock))
		address_unlock(h, DEPTH_THUNK);

	return result;

unlock_ret_error:
	if (likely(need_lock))
		address_unlock(h, DEPTH_THUNK);

	return OS_RW_ERROR;
}

static ssize_t os_write_console(handle_t h, const char *buffer, int size, ajla_error_t *err)
{
	ssize_t ret = size;
	WCHAR *r;
	size_t l;
	if (unlikely(!array_init_mayfail(WCHAR, &r, &l, err)))
		return OS_RW_ERROR;
	while (size--) {
		ajla_error_t sink;
		WCHAR *wc;
		unsigned char c = *buffer++;
		if (c < 0x80) {
			h->utf8_buffer_size = 0;
			if (unlikely(!array_add_mayfail(WCHAR, &r, &l, c, NULL, err)))
				return OS_RW_ERROR;
			continue;
		} else if (c < 0xc0) {
			if (unlikely(!h->utf8_buffer_size) || unlikely((size_t)h->utf8_buffer_size + 1 >= sizeof(h->utf8_buffer)))
				continue;
			h->utf8_buffer[h->utf8_buffer_size++] = c;
		} else if (c < 0xf8) {
			h->utf8_buffer[0] = c;
			h->utf8_buffer_size = 1;
		} else {
			h->utf8_buffer_size = 0;
			continue;
		}
		h->utf8_buffer[h->utf8_buffer_size] = 0;
		wc = utf8_to_wchar(h->utf8_buffer, &sink);
		if (wc) {
			size_t wl;
			h->utf8_buffer_size = 0;
			for (wl = 0; wc[wl]; wl++) ;
			if (unlikely(!array_add_multiple_mayfail(WCHAR, &r, &l, wc, wl, NULL, err))) {
				mem_free(wc);
				return OS_RW_ERROR;
			}
			mem_free(wc);
		} else {
			if (unlikely(sink.error_class == EC_ASYNC)) {
				if (!err)
					fatal("can't allocate console buffer: %s", error_decode(sink));
				*err = sink;
				mem_free(r);
				return OS_RW_ERROR;
			}
		}
	}
	if (l) {
		DWORD written;
		BOOL b = WriteConsoleW(h->h, r, l, &written, NULL);
		if (unlikely(!b)) {
			ajla_error_t e;
			DWORD gle = GetLastError();
			mem_free(r);
			e = error_from_win32(EC_SYSCALL, gle);
			fatal_mayfail(e, err, "can't write to console: %s", error_decode(e));
			return OS_RW_ERROR;
		}
	}
	mem_free(r);
	return ret;
}

static ssize_t os_read_socket(handle_t h, char *buffer, int size, ajla_error_t *err)
{
	int r;

	r = recv(h->s, buffer, size, 0);
	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		if (likely(er == WSAEWOULDBLOCK))
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_win32_socket(er), err, "error reading socket");
		return OS_RW_ERROR;
	}
	return r;
}

static ssize_t os_write_socket(handle_t h, const char *buffer, int size, ajla_error_t *err)
{
	int r;

	r = send(h->s, buffer, size, 0);
	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		if (likely(er == WSAEWOULDBLOCK))
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_win32_socket(er), err, "error writing socket");
		return OS_RW_ERROR;
	}
	return r;
}

ssize_t os_read(handle_t h, char *buffer, int size, ajla_error_t *err)
{
	if (unlikely((h->flags & 3) == O_WRONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to read from write-only handle");
		return OS_RW_ERROR;
	}

	if (handle_is_socket(h))
		return os_read_socket(h, buffer, size, err);
	if (h->flags & O_NONBLOCK)
		return os_read_nonblock(h, buffer, size, err);
	return os_do_rw(h, buffer, size, false, NULL, err);
}

ssize_t os_write(handle_t h, const char *buffer, int size, ajla_error_t *err)
{
	if (unlikely((h->flags & 3) == O_RDONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to write to read-only handle");
		return OS_RW_ERROR;
	}

	if (handle_is_socket(h))
		return os_write_socket(h, buffer, size, err);
	if (h->flags & O_NONBLOCK && !h->is_console)
		return os_write_nonblock(h, buffer, size, err);
	if (h->is_console && is_winnt())
		return os_write_console(h, buffer, size, err);
	return os_do_rw(h, cast_ptr(char *, buffer), size, true, NULL, err);
}

ssize_t os_pread(handle_t h, char *buffer, int size, os_off_t off, ajla_error_t *err)
{
	if (unlikely((h->flags & 3) == O_WRONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to read from write-only handle");
		return OS_RW_ERROR;
	}

	if (unlikely(handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "seek operation on socket");
		return OS_RW_ERROR;
	}
	return os_do_rw(h, buffer, size, false, &off, err);
}

ssize_t os_pwrite(handle_t h, const char *buffer, int size, os_off_t off, ajla_error_t *err)
{
	if (unlikely((h->flags & 3) == O_RDONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to write to read-only handle");
		return OS_RW_ERROR;
	}

	if (unlikely(handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "seek operation on socket");
		return OS_RW_ERROR;
	}
	return os_do_rw(h, cast_ptr(char *, buffer), size, true, &off, err);
}

bool os_lseek(handle_t h, unsigned mode, os_off_t off, os_off_t *result, ajla_error_t *err)
{
	bool ret;
	ULONG rel;
	os_off_t len;

	if (unlikely(handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "seek operation on socket");
		return false;
	}

	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);

	switch (mode) {
		case 0:	rel = FILE_BEGIN; break;
		case 1: rel = FILE_CURRENT; break;
		case 2: rel = FILE_END; break;
		case 3: ret = win32_setfileptr(h, 0, FILE_END, &len, err);
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

	ret = win32_setfileptr(h, off, rel, result, err);

ret_ret:
	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);

	return ret;
}

bool os_ftruncate(handle_t h, os_off_t size, ajla_error_t *err)
{
	bool ret;
	BOOL b;

	if (unlikely(handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "ftruncate operation on socket");
		return false;
	}

	if (likely(os_threads_initialized))
		address_lock(h, DEPTH_THUNK);

	ret = win32_setfileptr(h, size, FILE_BEGIN, NULL, err);
	if (unlikely(!ret))
		goto ret_ret;

	b = SetEndOfFile(h->h);
	if (unlikely(!b)) {
		DWORD gle = GetLastError();
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't set file size: %s", error_decode(e));
		ret = false;
		goto ret_ret;
	}

	ret = true;

ret_ret:
	if (likely(os_threads_initialized))
		address_unlock(h, DEPTH_THUNK);

	return ret;
}

bool os_fallocate(handle_t attr_unused h, os_off_t attr_unused position, os_off_t attr_unused size, ajla_error_t attr_unused *err)
{
	return true;
}

bool os_clone_range(handle_t attr_unused src_h, os_off_t attr_unused src_pos, handle_t attr_unused dst_h, os_off_t attr_unused dst_pos, os_off_t attr_unused len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "clone not supported");
	return false;
}

bool os_fsync(handle_t h, unsigned attr_unused mode, ajla_error_t *err)
{
	BOOL b;

	if (unlikely(!handle_is_valid(h)) || unlikely(h->is_console))
		return true;

	if (unlikely(handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "fsync operation on socket");
		return false;
	}

	b = FlushFileBuffers(h->h);
	if (unlikely(!b)) {
		DWORD gle = GetLastError();
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't flush file: %s", error_decode(e));
		return false;
	}

	return true;
}


int os_charset(void)
{
	if (is_winnt())
		return 0;
	else
		return GetACP();
}

int os_charset_console(void)
{
	if (is_winnt())
		return 0;
	else
		return GetConsoleOutputCP();
}

ssize_t os_read_console_packet(handle_t h, struct console_read_packet *result, ajla_error_t *err)
{
	ssize_t retval;
	DWORD cmode;
	address_lock(h, DEPTH_THUNK);
	if (unlikely(!h->is_console) || unlikely((h->flags & 3) == O_WRONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to use packet console on non-console");
		retval = OS_RW_ERROR;
		goto unlock_ret;
	}
	if (GetConsoleMode(h->h, &cmode)) {
		if (unlikely(!(cmode & ENABLE_MOUSE_INPUT))) {
			cmode |= ENABLE_MOUSE_INPUT;
			SetConsoleMode(h->h, cmode);
		}
	}
	if (unlikely(!win32_create_read_thread(h, err))) {
		address_unlock(h, DEPTH_THUNK);
		retval = OS_RW_ERROR;
		goto unlock_ret;
	}
	if (!load_relaxed(&h->rd->is_packet_console)) {
		store_relaxed(&h->rd->is_packet_console, true);
		h->rd->last_buttons = 0;
		h->rd->buffer_len = 0;
		win32_set_event(h->rd->data_event);
	}
	if (h->rd->packet_is_queued) {
		memcpy(result, &h->rd->packet, sizeof(struct console_read_packet));
		h->rd->packet_is_queued = false;
		win32_set_event(h->rd->data_event);
		retval = 1;
	} else {
		if (unlikely(h->rd->err != 0)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, h->rd->err);
			fatal_mayfail(e, err, "can't read console packet: %s", error_decode(e));
			retval = OS_RW_ERROR;
		} else {
			retval = OS_RW_WOULDBLOCK;
		}
	}
unlock_ret:
	address_unlock(h, DEPTH_THUNK);
	return retval;
}

static atomic_type unsigned window_offset_x;
static atomic_type unsigned window_offset_y;

bool os_write_console_packet(handle_t h, struct console_write_packet *packet, ajla_error_t *err)
{
	BOOL ret;
	unsigned offset_x = load_relaxed(&window_offset_x);
	unsigned offset_y = load_relaxed(&window_offset_y);
	bool wnt = is_winnt();
	if (unlikely(!h->is_console) || unlikely((h->flags & 3) == O_RDONLY)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "attempting to use packet console on non-console");
		return false;
	}

	if (h->is_console && (h->flags & 3) == O_RDONLY) {
		handle_t h1;
		h1 = os_get_std_handle(1);
		if (h1->is_console) {
			h = h1;
			goto have_h;
		}
		h1 = os_get_std_handle(2);
		if (h1->is_console) {
			h = h1;
			goto have_h;
		}
	}

have_h:

next:
	switch (packet->type) {
		case 1: {
			break;
		}
		case 2: {
			int i;
			CHAR_INFO *chr;
			COORD dwBufferSize;
			COORD dwBufferCoord;
			SMALL_RECT lpWriteRegion;

			chr = mem_alloc_array_mayfail(mem_alloc_mayfail, CHAR_INFO *, 0, 0, packet->u.c.n_chars, sizeof(CHAR_INFO), err);
			if (unlikely(!chr))
				return false;
			for (i = 0; i < packet->u.c.n_chars; i++) {
				if (wnt)
					chr[i].Char.UnicodeChar = packet->u.c.data[i * 2];
				else
					chr[i].Char.AsciiChar = packet->u.c.data[i * 2];
				chr[i].Attributes = packet->u.c.data[i * 2 + 1];
			}
			dwBufferSize.X = packet->u.c.n_chars;
			dwBufferSize.Y = 1;
			dwBufferCoord.X = 0;
			dwBufferCoord.Y = 0;
			lpWriteRegion.Left = packet->u.c.x + offset_x;
			lpWriteRegion.Top = packet->u.c.y + offset_y;
			lpWriteRegion.Right = packet->u.c.x + packet->u.c.n_chars - 1 + offset_x;
			lpWriteRegion.Bottom = packet->u.c.y + offset_y;
			if (wnt)
				ret = WriteConsoleOutputW(h->h, chr, dwBufferSize, dwBufferCoord, &lpWriteRegion);
			else
				ret = WriteConsoleOutputA(h->h, chr, dwBufferSize, dwBufferCoord, &lpWriteRegion);
			if (unlikely(!ret)) {
				ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
				fatal_mayfail(e, err, "can't write to console buffer");
				mem_free(chr);
				return false;
			}
			mem_free(chr);
			packet = cast_ptr(struct console_write_packet *, &packet->u.c.data[packet->u.c.n_chars * 2]);
			goto next;
		}
		case 3: {
			COORD dwCursorPosition;
			dwCursorPosition.X = packet->u.p.x + offset_x;
			dwCursorPosition.Y = packet->u.p.y + offset_y;
			ret = SetConsoleCursorPosition(h->h, dwCursorPosition);
			/*if (unlikely(!ret)) {
				ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
				fatal_mayfail(e, err, "can't set cursor position");
				return false;
			}*/
			packet = cast_ptr(struct console_write_packet *, &packet->u.p.end);
			goto next;
		}
		case 4: {
			CONSOLE_CURSOR_INFO cci;
			ret = GetConsoleCursorInfo(h->h, &cci);
			if (unlikely(!ret)) {
				ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
				fatal_mayfail(e, err, "can't get cursor info");
				return false;
			}
			cci.bVisible = packet->u.v.v;
			ret = SetConsoleCursorInfo(h->h, &cci);
			if (unlikely(!ret)) {
				ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
				fatal_mayfail(e, err, "can't set cursor info");
				return false;
			}
			packet = cast_ptr(struct console_write_packet *, &packet->u.v.end);
			goto next;
		}
		default: {
			internal(file_line, "os_write_console_packet: invalid type %d", (int)packet->type);
			break;
		}
	}
	return true;
}


dir_handle_t os_dir_root(ajla_error_t *err)
{
	unsigned bit;
	DWORD drv;
	char *d = str_dup(" :\\", -1, err);
	if (unlikely(!d))
		return NULL;
	drv = GetLogicalDrives();
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
	DWORD buf_size, data_size;
	char *buf = NULL;	/* avoid warning */
	WCHAR *wbuf = NULL;	/* avoid warning */

	if (is_winnt()) {
		buf_size = GetCurrentDirectoryW(0, NULL);
	} else {
		buf_size = GetCurrentDirectoryA(0, NULL);
	}
	if (unlikely(!buf_size)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal_mayfail(e, err, "can't get current directory");
		return dir_none;
	}

again:
	if (is_winnt()) {
		wbuf = mem_alloc_mayfail(WCHAR *, buf_size * sizeof(WCHAR), err);
		if (unlikely(!wbuf))
			return dir_none;
		data_size = GetCurrentDirectoryW(buf_size, wbuf);
	} else {
		buf = mem_alloc_mayfail(char *, buf_size, err);
		if (unlikely(!buf))
			return dir_none;
		data_size = GetCurrentDirectoryA(buf_size, buf);
	}
	if (unlikely(!data_size)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		mem_free(is_winnt() ? cast_ptr(void *, wbuf) : cast_ptr(void *, buf));
		fatal_mayfail(e, err, "can't get current directory");
		return dir_none;
	}
	if (unlikely(data_size > buf_size)) {
		mem_free(is_winnt() ? cast_ptr(void *, wbuf) : cast_ptr(void *, buf));
		buf_size = data_size;
		goto again;
	}
	if (is_winnt()) {
		buf = wchar_to_utf8(NULL, wbuf, err);
		mem_free(wbuf);
	}
	return buf;
}

dir_handle_t os_dir_open(dir_handle_t dir, const char *path, int attr_unused flags, ajla_error_t *err)
{
	char *joined;
	DWORD gle;
	DWORD attr;
	joined = os_join_paths(dir, path, true, err);
	if (unlikely(!joined))
		return dir_none;
	if (is_winnt()) {
		WCHAR *w = utf8_to_wchar(joined, err);
		if (unlikely(!w)) {
			mem_free(joined);
			return NULL;
		}
		attr = GetFileAttributesW(w);
		gle = GetLastError();
		mem_free(w);
	} else {
		attr = GetFileAttributesA(joined);
		gle = GetLastError();
	}
	if (unlikely(attr == INVALID_FILE_ATTRIBUTES)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		mem_free(joined);
		fatal_mayfail(e, err, "can't open directory");
		return dir_none;
	}
	if (unlikely(!(attr & FILE_ATTRIBUTE_DIRECTORY))) {
		ajla_error_t e = error_ajla_system(EC_SYSCALL, SYSTEM_ERROR_ENOTDIR);
		mem_free(joined);
		fatal_mayfail(e, err, "can't open directory");
		return dir_none;
	}
	return joined;
}

void os_dir_close(dir_handle_t h)
{
	mem_free(h);
}

char *os_dir_path(dir_handle_t h, ajla_error_t *err)
{
	return str_dup(h, -1, err);
}

static bool add_file_name(char *a, char ***files, size_t *n_files, ajla_error_t *err)
{
	void *err_ptr;
	if (unlikely(!strcmp(a, ".")) ||
	    unlikely(!strcmp(a, ".."))) {
		mem_free(a);
		return true;
	}
	if (unlikely(!array_add_mayfail(char *, files, n_files, a, &err_ptr, err))) {
		*files = err_ptr;
		mem_free(a);
		return false;
	}
	return true;
}

bool os_dir_read(dir_handle_t h, char ***files, size_t *n_files, ajla_error_t *err)
{
	HANDLE hdir;
	BOOL b;
	DWORD gle;
	char *fn;
	union {
		WIN32_FIND_DATAA find_data_a;
		WIN32_FIND_DATAW find_data_w;
	} u;

	if (unlikely(!array_init_mayfail(char *, files, n_files, err)))
		return false;

	fn = os_join_paths(h, "*", false, err);
	if (unlikely(!fn))
		goto ret_false;

	if (is_winnt()) {
		WCHAR *w = utf8_to_wchar(fn, err);
		if (unlikely(!w)) {
			mem_free(fn);
			goto ret_false;
		}
		mem_free(fn);
		hdir = FindFirstFileW(w, &u.find_data_w);
		gle = GetLastError();
		mem_free(w);
	} else {
		hdir = FindFirstFileA(fn, &u.find_data_a);
		gle = GetLastError();
		mem_free(fn);
	}

	if (unlikely(hdir == INVALID_HANDLE_VALUE)) {
		ajla_error_t e;
		if (/*likely(gle == ERROR_FILE_NOT_FOUND) ||*/ likely(gle == ERROR_NO_MORE_FILES))
			return true;
		e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't read directory");
		goto ret_false;
	}

loop:
	if (is_winnt()) {
		char *a = wchar_to_utf8(NULL, u.find_data_w.cFileName, err);
		if (unlikely(!a))
			goto close_h_ret_false;
		if (unlikely(!add_file_name(a, files, n_files, err)))
			goto close_h_ret_false;
	} else {
		char *a = str_dup(u.find_data_a.cFileName, -1, err);
		if (unlikely(!a))
			goto close_h_ret_false;
		if (unlikely(!add_file_name(a, files, n_files, err)))
			goto close_h_ret_false;
	}

	if (is_winnt())
		b = FindNextFileW(hdir, &u.find_data_w);
	else
		b = FindNextFileA(hdir, &u.find_data_a);
	if (unlikely(!b)) {
		ajla_error_t e;
		DWORD gle = GetLastError();
		if (/*likely(gle == ERROR_FILE_NOT_FOUND) ||*/ likely(gle == ERROR_NO_MORE_FILES)) {
			if (unlikely(!FindClose(hdir)))
				internal(file_line, "FindClose failed: %u", GetLastError());
			return true;
		}
		e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't read directory");
		goto close_h_ret_false;
	}
	goto loop;


close_h_ret_false:
	if (unlikely(!FindClose(hdir)))
		internal(file_line, "FindClose failed: %u", GetLastError());
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

ajla_time_t os_time_t_to_ajla_time(os_time_t tick)
{
	return tick / 10 - (int64_t)116444736 * (int64_t)100000000;
}

static os_time_t ajla_time_to_os_time(ajla_time_t a)
{
	return 10 * a + (int64_t)10 * (int64_t)116444736 * (int64_t)100000000;
}

static uint64_t get_win32_time(const FILETIME *ft)
{
	/*debug("get_win32_time: %llx", ((uint64_t)ft->dwHighDateTime << 32) | ft->dwLowDateTime);*/
	return ((uint64_t)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

static void make_win32_filetime(uint64_t t, FILETIME *ft)
{
	ft->dwLowDateTime = t;
	ft->dwHighDateTime = t >> 32;
}

bool os_fstat(handle_t h, os_stat_t *st, ajla_error_t *err)
{
	BY_HANDLE_FILE_INFORMATION info;

	memset(st, 0, sizeof(*st));

	switch (h->type) {
		case FILE_TYPE_DISK:	st->st_mode = S_IFREG; break;
		case FILE_TYPE_CHAR:	st->st_mode = S_IFCHR; break;
		case FILE_TYPE_PIPE:	st->st_mode = S_IFIFO; break;
		default:		st->st_mode = S_IFCHR; break;
	}

	if (unlikely(!GetFileInformationByHandle(h->h, &info))) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal_mayfail(e, err, "GetFileInformationByHandle returned an error: %s", error_decode(e));
		return false;
	}

	st->st_dev = info.dwVolumeSerialNumber;
	st->st_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
	st->st_size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
	st->st_blocks = round_up(st->st_size, 4096) / 512;
	st->st_blksize = 4096;
	st->st_nlink = info.nNumberOfLinks;
	st->st_ctime = get_win32_time(&info.ftCreationTime);
	st->st_atime = get_win32_time(&info.ftLastAccessTime);
	st->st_mtime = get_win32_time(&info.ftLastWriteTime);

	if (unlikely(info.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
		st->st_mode |= 0444;
	else
		st->st_mode |= 0666;

	return true;
}

bool os_stat(dir_handle_t dir, const char *path, bool attr_unused lnk, os_stat_t *st, ajla_error_t *err)
{
	HANDLE hdir;
	DWORD gle;
	union {
		WIN32_FIND_DATAA find_data_a;
		WIN32_FIND_DATAW find_data_w;
	} u;

	ajla_error_t sink;
	dir_handle_t dh;

	memset(st, 0, sizeof(*st));

	dh = os_dir_open(dir, path, 0, &sink);
	if (dir_handle_is_valid(dh)) {
		st->st_mode = S_IFDIR | 0777;
	} else {
		handle_t fh = os_open(dir, path, O_RDONLY, 0, err);
		if (handle_is_valid(fh)) {
			bool succ = os_fstat(fh, st, err);
			os_close(fh);
			return succ;
		}
		st->st_mode = S_IFREG | 0666;
		dh = os_join_paths(dir, path, false, err);
		if (unlikely(!dh))
			return false;
	}

	if (unlikely(strchr(dh, '*') != NULL) || unlikely(strchr(dh, '?') != NULL)) {
		ajla_error_t e = error_ajla_system(EC_SYSCALL, SYSTEM_ERROR_ENOENT);
		fatal_mayfail(e, err, "can't open file '%s': %s", dh, error_decode(e));
		os_dir_close(dh);
		return false;
	}

	if (is_winnt()) {
		WCHAR *w = utf8_to_wchar(dh, err);
		if (unlikely(!w)) {
			os_dir_close(dh);
			return false;
		}
		hdir = FindFirstFileW(w, &u.find_data_w);
		gle = GetLastError();
		mem_free(w);
	} else {
		hdir = FindFirstFileA(dh, &u.find_data_a);
		gle = GetLastError();
	}
	if (unlikely(hdir == INVALID_HANDLE_VALUE)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't open file '%s': %s", dh, error_decode(e));
		os_dir_close(dh);
		return false;
	}

	st->st_nlink = 1;

	if (is_winnt()) {
		st->st_size = ((uint64_t)u.find_data_w.nFileSizeHigh << 32) | u.find_data_a.nFileSizeLow;
		st->st_ctime = get_win32_time(&u.find_data_w.ftCreationTime);
		st->st_atime = get_win32_time(&u.find_data_w.ftLastAccessTime);
		st->st_mtime = get_win32_time(&u.find_data_w.ftLastWriteTime);
		if (unlikely(u.find_data_w.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
			st->st_mode &= ~0222;
	} else {
		st->st_size = ((uint64_t)u.find_data_a.nFileSizeHigh << 32) | u.find_data_a.nFileSizeLow;
		st->st_ctime = get_win32_time(&u.find_data_a.ftCreationTime);
		st->st_atime = get_win32_time(&u.find_data_a.ftLastAccessTime);
		st->st_mtime = get_win32_time(&u.find_data_a.ftLastWriteTime);
		if (unlikely(u.find_data_a.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
			st->st_mode &= ~0222;
	}
	st->st_blocks = round_up(st->st_size, 4096) / 512;
	st->st_blksize = 4096;

	if (unlikely(!FindClose(hdir)))
		internal(file_line, "FindClose failed: %u", GetLastError());

	os_dir_close(dh);
	return true;
}

bool os_fstatvfs(handle_t h, os_statvfs_t *st, ajla_error_t *err)
{
	if (unlikely(!h->file_name[0])) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "statvfs not supported");
		return false;
	}
	return os_dstatvfs(h->file_name, st, err);
}

bool os_dstatvfs(dir_handle_t dir, os_statvfs_t *st, ajla_error_t *err)
{
	size_t len;
	char *disk;
	BOOL b;
	BOOL b2;
	DWORD spc, bps, freecl, totalcl;
	DWORD gle;
	ULARGE_INTEGER availb, totalb, freeb;
	availb.QuadPart = 0;	/* avoid warning */
	totalb.QuadPart = 0;	/* avoid warning */
	freeb.QuadPart = 0;	/* avoid warning */
	if ((dir[0] == '/' || dir[0] == '\\') && (dir[1] == '/' || dir[1] == '\\')) {
		len = 2;
		len += strcspn(dir + 2, "/\\");
		if (dir[len]) {
			len++;
			len += strcspn(dir + len, "/\\");
			if (dir[len])
				len++;
		}
	} else if ((dir[0] & 0xDF) >= 'A' && (dir[0] & 0xDF) <= 'Z' && dir[1] == ':' && (dir[2] == '/' || dir[2] == '\\')) {
		len = 3;
	} else {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "statvfs not on this directory");
		return false;
	}
	disk = str_dup(dir, len, err);
	if (unlikely(!disk))
		return false;
	if (is_winnt()) {
		WCHAR *w = utf8_to_wchar(disk, err);
		if (unlikely(!w)) {
			mem_free(disk);
			return false;
		}
		b2 = FALSE;
		if (fn_GetDiskFreeSpaceExW)
			b2 = fn_GetDiskFreeSpaceExW(w, &availb, &totalb, &freeb);
		b = GetDiskFreeSpaceW(w, &spc, &bps, &freecl, &totalcl);
		gle = GetLastError();
		mem_free(w);
	} else {
		b2 = FALSE;
		if (fn_GetDiskFreeSpaceExA)
			b2 = fn_GetDiskFreeSpaceExA(disk, &availb, &totalb, &freeb);
		b = GetDiskFreeSpaceA(disk, &spc, &bps, &freecl, &totalcl);
		gle = GetLastError();
	}
	if (unlikely(!b)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't get disk '%s' free space: %s", disk, error_decode(e));
		mem_free(disk);
		return false;
	}
	memset(st, 0, sizeof(os_statvfs_t));
	st->f_bsize = bps * spc;
	st->f_frsize = bps;
	st->f_blocks = (uint64_t)totalcl * spc;
	st->f_bfree = st->f_bavail = (uint64_t)freecl * spc;
	st->f_fsid = disk[0];
	st->f_namemax = 255;
	if (b2) {
		st->f_blocks = totalb.QuadPart / st->f_frsize;
		st->f_bfree = freeb.QuadPart / st->f_frsize;
		st->f_bavail = availb.QuadPart / st->f_frsize;
	}
	mem_free(disk);
	return true;
}

char *os_readlink(dir_handle_t attr_unused dir, const char attr_unused *path, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "readlink not supported");
	return NULL;
}

bool os_dir_action(dir_handle_t dir, const char *path, int action, int attr_unused mode, ajla_time_t dev_major, ajla_time_t dev_minor, const char attr_unused *syml, ajla_error_t *err)
{
	bool ret = false;
	BOOL b;
	DWORD gle;
	char *joined;
	WCHAR *joined_w = NULL;
	bool allow_trailing_slash = action == IO_Action_Rm_Dir || action == IO_Action_Mk_Dir;

	joined = os_join_paths(dir, path, allow_trailing_slash, err);
	if (unlikely(!joined))
		return false;

	if (is_winnt()) {
		joined_w = utf8_to_wchar(joined, err);
		if (unlikely(!joined_w)) {
			mem_free(joined);
			goto free_ret;
		}
	}

	switch (action) {
		case IO_Action_Rm:
			if (joined_w)
				b = DeleteFileW(joined_w);
			else
				b = DeleteFileA(joined);
			gle = GetLastError();
			break;
		case IO_Action_Rm_Dir:
			if (joined_w)
				b = RemoveDirectoryW(joined_w);
			else
				b = RemoveDirectoryA(joined);
			gle = GetLastError();
			break;
		case IO_Action_Mk_Dir:
			if (joined_w)
				b = CreateDirectoryW(joined_w, NULL);
			else
				b = CreateDirectoryA(joined, NULL);
			gle = GetLastError();
			if (gle == ERROR_ACCESS_DENIED) {
				if ((joined[0] & 0xdf) >= 'A' && (joined[0] & 0xdf) <= 'Z' && joined[1] == ':' && joined[2] && !joined[2 + strspn(joined + 2, "\\/")])
					gle = ERROR_ALREADY_EXISTS;
			}
			break;
		case IO_Action_Mk_Pipe:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkpipe not supported");
			goto free_ret;
		case IO_Action_Mk_Socket:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mksocket not supported");
			goto free_ret;
		case IO_Action_Mk_CharDev:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkchardev not supported");
			goto free_ret;
		case IO_Action_Mk_BlockDev:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkblockdev not supported");
			goto free_ret;
		case IO_Action_Mk_SymLink:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mksymlink not supported");
			goto free_ret;
		case IO_Action_ChMod:
		case IO_Action_ChOwn:
		case IO_Action_LChOwn:
			if (joined_w)
				b = GetFileAttributesW(joined_w) != INVALID_FILE_ATTRIBUTES;
			else
				b = GetFileAttributesA(joined) != INVALID_FILE_ATTRIBUTES;
			gle = GetLastError();
			break;
		case IO_Action_UTime:
		case IO_Action_LUTime: {
			HANDLE hfile;
			FILETIME modft, accft;
			make_win32_filetime(ajla_time_to_os_time(dev_major), &modft);
			make_win32_filetime(ajla_time_to_os_time(dev_minor), &accft);
			if (joined_w)
				hfile = CreateFileW(joined_w, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
			else
				hfile = CreateFileA(joined, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
			if (unlikely(hfile == INVALID_HANDLE_VALUE)) {
				gle = GetLastError();
				goto return_error;
			}
			b = SetFileTime(hfile, NULL, &accft, &modft);
			gle = GetLastError();
			win32_close_handle(hfile);
			break;
		}
		default:
			internal(file_line, "os_dir_action: invalid action %d", action);
	}

	if (unlikely(!b)) {
		ajla_error_t e;
return_error:
		e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't perform action %d on '%s': %s", action, joined, error_decode(e));
		goto free_ret;
	}

	ret = true;

free_ret:
	if (joined_w)
		mem_free(joined_w);
	mem_free(joined);
	return ret;
}

bool os_dir2_action(dir_handle_t dest_dir, const char *dest_path, int action, dir_handle_t src_dir, const char *src_path, ajla_error_t *err)
{
	bool ret = false;
	BOOL b;
	DWORD gle;
	char *dest_joined = NULL, *src_joined = NULL;
	WCHAR *dest_joined_w = NULL, *src_joined_w = NULL;

	dest_joined = os_join_paths(dest_dir, dest_path, false, err);
	if (unlikely(!dest_joined))
		goto free_ret;

	src_joined = os_join_paths(src_dir, src_path, false, err);
	if (unlikely(!src_joined))
		goto free_ret;
	if (is_winnt()) {
		dest_joined_w = utf8_to_wchar(dest_joined, err);
		if (unlikely(!dest_joined_w)) {
			mem_free(dest_joined);
			goto free_ret;
		}
		src_joined_w = utf8_to_wchar(src_joined, err);
		if (unlikely(!src_joined_w)) {
			mem_free(src_joined);
			goto free_ret;
		}
	}

	switch (action) {
		case IO_Action_Mk_Link:
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mklink not supported");
			goto free_ret;
		case IO_Action_Rename:
			if (dest_joined_w) {
				if (unlikely(!fn_MoveFileExW)) {
move_file_w:
					if (unlikely(GetFileAttributesW(src_joined_w) == INVALID_FILE_ATTRIBUTES)) {
						gle = GetLastError();
						b = FALSE;
						goto return_error;
					}
					DeleteFileW(dest_joined_w);
					b = MoveFileW(src_joined_w, dest_joined_w);
					gle = GetLastError();
				} else {
					b = fn_MoveFileExW(src_joined_w, dest_joined_w, MOVEFILE_REPLACE_EXISTING);
					gle = GetLastError();
					if (unlikely(!b) && gle == ERROR_CALL_NOT_IMPLEMENTED)
						goto move_file_w;
				}
			} else {
				if (unlikely(!fn_MoveFileExA)) {
move_file:
					if (unlikely(GetFileAttributesA(src_joined) == INVALID_FILE_ATTRIBUTES)) {
						gle = GetLastError();
						b = FALSE;
						goto return_error;
					}
					DeleteFileA(dest_joined);
					b = MoveFileA(src_joined, dest_joined);
					gle = GetLastError();
				} else {
					b = fn_MoveFileExA(src_joined, dest_joined, MOVEFILE_REPLACE_EXISTING);
					gle = GetLastError();
					if (unlikely(!b) && gle == ERROR_CALL_NOT_IMPLEMENTED)
						goto move_file;
				}
			}
			break;
		default:
			internal(file_line, "os_dir2_action: invalid action %d", action);
	}
	if (unlikely(!b)) {
		ajla_error_t e;
return_error:
		e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't perform action %d on '%s' and '%s': %s", action, src_joined, dest_joined, error_decode(e));
		goto free_ret;
	}

	ret = true;

free_ret:
	if (dest_joined)
		mem_free(dest_joined);
	if (dest_joined_w)
		mem_free(dest_joined_w);
	if (src_joined)
		mem_free(src_joined);
	if (src_joined_w)
		mem_free(src_joined_w);
	return ret;
}

uint32_t os_drives(void)
{
	return GetLogicalDrives();
}


bool os_tcgetattr(handle_t h, os_termios_t *t, ajla_error_t attr_unused *err)
{
	t->tc_flags = h->tc_flags;
	return true;
}

bool os_tcsetattr(handle_t h, const os_termios_t *t, ajla_error_t attr_unused *err)
{
	h->tc_flags = t->tc_flags;
	if (h->is_console) {
		if (t->tc_flags & IO_Stty_Flag_Nosignal)
			SetConsoleCtrlHandler(NULL, TRUE);
		else
			SetConsoleCtrlHandler(NULL, FALSE);
	}
	return true;
}

void os_tcflags(os_termios_t *t, int flags)
{
	t->tc_flags = flags;
}

bool os_tty_size(handle_t h, int *nx, int *ny, ajla_error_t *err)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if (h->is_console && (h->flags & 3) == O_RDONLY) {
		handle_t h1;
		h1 = os_get_std_handle(1);
		if (h1->is_console) {
			h = h1;
			goto have_h;
		}
		h1 = os_get_std_handle(2);
		if (h1->is_console) {
			h = h1;
			goto have_h;
		}
	}

have_h:
	if (!GetConsoleScreenBufferInfo(h->h, &csbi)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal_mayfail(e, err, "GetConsoleScreenBufefrInfo failed: %s", error_decode(e));
		return false;
	}

	*nx = csbi.srWindow.Right - csbi.srWindow.Left + 1;
	*ny = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;

	store_relaxed(&window_offset_x, csbi.srWindow.Left);
	store_relaxed(&window_offset_y, csbi.srWindow.Top);

	return true;
}


const char *os_get_flavor(void)
{
	return "Windows";
}

void os_get_uname(os_utsname_t *un)
{
	OSVERSIONINFOA osva;
	OSVERSIONINFOW osvw;
	unsigned platform, major, minor, build;

	memset(un, 0, sizeof(os_utsname_t));
	strcpy(un->sysname, "Windows");

	if (fn_RtlGetVersion) {
		memset(&osvw, 0, sizeof osvw);
		osvw.dwOSVersionInfoSize = sizeof osvw;
		if (unlikely(fn_RtlGetVersion(&osvw)))
			fatal("RtlGetVersion failed");

		platform = osvw.dwPlatformId;
		major = osvw.dwMajorVersion;
		minor = osvw.dwMinorVersion;
		build = osvw.dwBuildNumber;
	} else {
		memset(&osva, 0, sizeof osva);
		osva.dwOSVersionInfoSize = sizeof osva;
		if (unlikely(!GetVersionExA(&osva)))
			fatal("GetVersionExA failed: %u", GetLastError());

		platform = osva.dwPlatformId;
		major = osva.dwMajorVersion;
		minor = osva.dwMinorVersion;
		build = osva.dwBuildNumber;
	}

	switch (platform) {
		case VER_PLATFORM_WIN32s:
			sprintf(un->release, "%u.%u", major, minor);
			break;
		case VER_PLATFORM_WIN32_WINDOWS:
			if (minor < 10) {
				if (build < 1111)
					strcpy(un->release, "95");
				else
					strcpy(un->release, "95 OSR2");
			} else if (minor == 10) {
				if (build < 2222)
					strcpy(un->release, "98");
				else
					strcpy(un->release, "98 SE");
			} else if (minor == 90) {
				strcpy(un->release, "ME");
			} else {
				sprintf(un->release, "%u.%u", major, minor);
			}
			break;
		case VER_PLATFORM_WIN32_NT:
			if (major == 5 && minor == 0) {
				strcpy(un->release, "2000");
			} else if (major == 5 && minor == 1) {
				strcpy(un->release, "XP");
			} else if (major == 5 && minor == 2) {
				strcpy(un->release, "Server 2003");
			} else if (major == 6 && minor == 0) {
				strcpy(un->release, "Vista");
			} else if (major == 6 && minor == 1) {
				strcpy(un->release, "7");
			} else if (major == 6 && minor == 2) {
				strcpy(un->release, "8");
			} else if (major == 6 && minor == 3) {
				strcpy(un->release, "8.1");
			} else if (major == 10 && minor == 0) {
				if (build < 22000)
					strcpy(un->release, "10");
				else
					strcpy(un->release, "11");
			} else {
				sprintf(un->release, "NT %u.%u", major, minor);
			}
			break;
	}

	if (fn_RtlGetVersion) {
		ajla_error_t sink;
		char *u = wchar_to_utf8(NULL, osvw.szCSDVersion, &sink);
		if (u) {
			strncpy(un->version, u, sizeof un->version - 1);
			mem_free(u);
		}
	} else {
		strncpy(un->version, osva.szCSDVersion, sizeof un->version - 1);
	}

#ifdef ARCH_NAME
	strcpy(un->machine, ARCH_NAME);
#endif
}

char *os_get_host_name(ajla_error_t *err)
{
	if (fn_GetNetworkParams) {
		ULONG buf_len;
		DWORD dw;
		dw = fn_GetNetworkParams(NULL, &buf_len);
		if (dw == ERROR_BUFFER_OVERFLOW) {
			char *buffer;
retry:
			buffer = mem_alloc_mayfail(char *, buf_len, err);
			if (unlikely(!buffer))
				return NULL;
			dw = fn_GetNetworkParams(buffer, &buf_len);
			if (likely(dw == ERROR_SUCCESS))
				return buffer;
			mem_free(buffer);
			if (dw == ERROR_BUFFER_OVERFLOW)
				goto retry;
		}
	}
	return str_dup("", -1, err);
}


static char *os_path_to_exe;

static void os_init_path_to_exe(void)
{
	DWORD r;
	DWORD s = 16;
	size_t i, j;
again:
	if (is_winnt()) {
		WCHAR *w = mem_alloc(WCHAR *, s * sizeof(WCHAR));
		r = GetModuleFileNameW(NULL, w, s);
		if (unlikely(!r)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal("GetModuleFileNameW returned an error: %s", error_decode(e));
		}
		if (r >= s - 1) {
			mem_free(w);
			s *= 2;
			if (unlikely(!s))
				fatal("GetModuleFileNameW overflow");
			goto again;
		}
		os_path_to_exe = wchar_to_utf8(NULL, w, NULL);
		mem_free(w);
	} else {
		os_path_to_exe = mem_alloc(char *, s);
		r = GetModuleFileNameA(NULL, os_path_to_exe, s);
		if (unlikely(!r)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal("GetModuleFileNameA returned an error: %s", error_decode(e));
		}
		if (r >= s - 1) {
			mem_free(os_path_to_exe);
			s *= 2;
			if (unlikely(!s))
				fatal("GetModuleFileNameA overflow");
			goto again;
		}
	}

	j = 0;
	for (i = 0; os_path_to_exe[i]; i++)
		if (os_is_path_separator(os_path_to_exe[i]))
			j = i + 1;
	os_path_to_exe[j] = 0;
}

const char *os_get_path_to_exe(void)
{
	return os_path_to_exe;
}


ajla_time_t os_time_real(void)
{
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	return os_time_t_to_ajla_time(get_win32_time(&ft));
}

static mutex_t tick_mutex;
static DWORD tick_last;
static DWORD tick_high;

ajla_time_t os_time_monotonic(void)
{
	DWORD t;
	int64_t ret;

#ifdef USER_QPC
	if (likely(fn_QueryPerformanceCounter != NULL)) {
		LARGE_INTEGER li;
		if (likely(fn_QueryPerformanceCounter(&li))) {
			int64_t c = li.LowPart + ((uint64_t)li.HighPart << 32);
			c = (long double)c * perf_multiplier;
			return c;
		}
	}
#endif

	if (likely(fn_GetTickCount64 != NULL)) {
		ret = fn_GetTickCount64();
	} else {
		if (likely(os_threads_initialized))
			mutex_lock(&tick_mutex);
		t = GetTickCount();
		if (unlikely(t < tick_last))
			tick_high++;
		tick_last = t;
		ret = ((uint64_t)tick_high << 32) | t;
		if (likely(os_threads_initialized))
			mutex_unlock(&tick_mutex);
	}
	return ret * 1000;
}


static int get_socket_error(handle_t h)
{
	int r;
	int e;
	socklen_t e_l = sizeof(int);

	r = getsockopt(h->s, SOL_SOCKET, SO_ERROR, cast_ptr(char *, &e), &e_l);
	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		internal(file_line, "getsockopt returned an error: %d", er);
	}

	return e;
}

void iomux_never(mutex_t **mutex_to_lock, struct list *list_entry)
{
	*mutex_to_lock = address_get_mutex(NULL, DEPTH_THUNK);
	list_init(list_entry);
}

static void win32_notify(void);

void iomux_register_wait(handle_t h, bool wr, mutex_t **mutex_to_lock, struct list *list_entry)
{
	struct win32_io_thread *thr;
	address_lock(h, DEPTH_THUNK);
	*mutex_to_lock = address_get_mutex(h, DEPTH_THUNK);
	list_add(&h->wait_list[wr], list_entry);
	if (handle_is_socket(h)) {
		struct list *socket_entry = &h->socket_entry[wr];
		address_unlock(h, DEPTH_THUNK);
		mutex_lock(&socket_list_mutex);
		if (socket_entry->next == NULL)
			list_add(&socket_list[(int)wr], socket_entry);
		mutex_unlock(&socket_list_mutex);
		win32_notify();
		return;
	}
	thr = !wr ? h->rd : h->wr;
	if (!wr) {
		if (unlikely(thr->buffer_len != 0) || unlikely(thr->packet_is_queued) || unlikely(thr->err != 0) || unlikely(thr->eof))
			goto wake_up;
	} else {
		if (unlikely(thr->buffer_len != WIN32_BUFFER_SIZE) || unlikely(thr->err != 0)) {
			goto wake_up;
		}
	}
	address_unlock(h, DEPTH_THUNK);
	return;

wake_up:
	call(wake_up_wait_list)(&h->wait_list[wr], address_get_mutex(h, DEPTH_THUNK), true);
}

bool iomux_test_handle(handle_t h, bool wr)
{
	if (handle_is_socket(h)) {
		int r;
		struct fdx_set fd;
		struct timeval tv;
		if (h->connect_in_progress && likely(wr)) {
			int e = get_socket_error(h);
			if (e)
				return true;
		}
		fd.fd_count = 1;
		fd.fd_array[0] = h->s;
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		if (!wr)
			r = select(FD_SETSIZE, cast_ptr(fd_set *, &fd), NULL, NULL, &tv);
		else
			r = select(FD_SETSIZE, NULL, cast_ptr(fd_set *, &fd), NULL, &tv);
		if (unlikely(r == SOCKET_ERROR))
			internal(file_line, "select returned an error: %d", WSAGetLastError());
		return !!r;
	}
	/*
	 * os_read/os_write is non-blocking even for standard handles,
	 * so we don't need this function
	 */
	return true;
}


#define HANDLES_PER_THREAD	(MAXIMUM_WAIT_OBJECTS - 1)

struct monitor_handle {
	HANDLE h;
	void (*wake_up)(void *cookie);
	void (*cls)(HANDLE h);
	void *cookie;
	bool needs_close;
};

struct monitor_thread {
	struct list entry;
	thread_t thread;
	HANDLE wake_up;
	bool terminate;
	int n_handles;
	struct monitor_handle handles[HANDLES_PER_THREAD];
};

static mutex_t monitor_mutex;
static struct list monotor_threads;

static inline void monitor_lock(void)
{
	mutex_lock(&monitor_mutex);
}

static inline void monitor_unlock(void)
{
	mutex_unlock(&monitor_mutex);
}

thread_function_decl(monitor_thread,
	struct monitor_thread *mt = arg;
	HANDLE handles[HANDLES_PER_THREAD + 1];

	monitor_lock();
	while (1) {
		DWORD r;
		int i;
		int j;
		int n_handles = mt->n_handles;
		for (i = j = 0; i < n_handles; i++, j++) {
			if (mt->handles[i].needs_close) {
				mt->handles[i].cls(mt->handles[i].h);
				j--;
				mt->n_handles--;
				continue;
			}
			mt->handles[j] = mt->handles[i];
			handles[j] = mt->handles[j].h;
		}
		handles[j] = mt->wake_up;
		if (mt->terminate)
			break;
		monitor_unlock();
		r = WaitForMultipleObjects(j + 1, handles, FALSE, INFINITE);
		if (unlikely(r == WAIT_FAILED))
			internal(file_line, "WaitForMultipleObjects failed: %u", GetLastError());
		monitor_lock();
		if (r >= WAIT_OBJECT_0 + zero && likely(r < WAIT_OBJECT_0 + j)) {
			i = r - WAIT_OBJECT_0;
			if (i < mt->n_handles && !mt->handles[i].needs_close) {
				void (*wake_up)(void *cookie) = mt->handles[i].wake_up;
				void *cookie = mt->handles[i].cookie;
				memmove(&mt->handles[i], &mt->handles[i + 1], (mt->n_handles - (i + 1)) * sizeof(struct monitor_handle));
				mt->n_handles--;
				wake_up(cookie);
				monitor_lock();
			}
		}
	}
	monitor_unlock();
)

static bool monitor_handle(HANDLE h, void (*wake_up)(void *cookie), void (*cls)(HANDLE h), void *cookie, ajla_error_t *err)
{
	struct list *l;
	struct monitor_thread *mt;
	int n;

	monitor_lock();

	list_for_each(l, &monotor_threads) {
		mt = get_struct(l, struct monitor_thread, entry);
		n = mt->n_handles;
		if (likely(n < HANDLES_PER_THREAD)) {
			if (unlikely(l != monotor_threads.next)) {
				list_del(&mt->entry);
				list_add(&monotor_threads, &mt->entry);
			}
			goto setup_handle;
		}
	}

	mt = mem_calloc_mayfail(struct monitor_thread *, sizeof(struct monitor_thread), err);
	if (unlikely(!mt))
		goto fail;
	mt->wake_up = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (!mt->wake_up) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal_mayfail(e, err, "can't create event: %s", error_decode(e));
		goto fail;
	}
	if (unlikely(!thread_spawn(&mt->thread, monitor_thread, mt, PRIORITY_IO, err))) {
		goto fail;
	}
	n = 0;
	list_add(&monotor_threads, &mt->entry);

setup_handle:
	mt->handles[n].h = h;
	mt->handles[n].wake_up = wake_up;
	mt->handles[n].cls = cls;
	mt->handles[n].cookie = cookie;
	mt->handles[n].needs_close = false;
	mt->n_handles = n + 1;
	win32_set_event(mt->wake_up);

	monitor_unlock();

	return true;

fail:
	if (mt) {
		if (mt->wake_up)
			win32_close_handle(mt->wake_up);
		mem_free(mt);
	}
	return false;
}

static void monitor_close(HANDLE h)
{
	struct list *l;
	struct monitor_thread *mt;
	int n;

	list_for_each(l, &monotor_threads) {
		mt = get_struct(l, struct monitor_thread, entry);
		for (n = 0; n < mt->n_handles; n++) {
			if (h == mt->handles[n].h)
				goto found;
		}
	}
	return;

found:
	mt->handles[n].needs_close = true;

	win32_set_event(mt->wake_up);
}

static void monitor_init(void)
{
	list_init(&monotor_threads);
	mutex_init(&monitor_mutex);
}

static void monitor_done(void)
{
	monitor_lock();
	while (!list_is_empty(&monotor_threads)) {
		struct monitor_thread *mt = get_struct(monotor_threads.next, struct monitor_thread, entry);
		mt->terminate = true;
		win32_set_event(mt->wake_up);
		monitor_unlock();
		thread_join(&mt->thread);
		monitor_lock();
		if (unlikely(mt->n_handles))
			internal(file_line, "monitor_done: %d handles were leaked", mt->n_handles);
		list_del(&mt->entry);
		win32_close_handle(mt->wake_up);
		mem_free(mt);
	}
	monitor_unlock();
	mutex_done(&monitor_mutex);
}


struct proc_handle {
	HANDLE process_handle;
	DWORD exit_code;
	bool fired;
	struct list wait_list;
};

static void proc_wait_end(void *ph_)
{
	struct proc_handle *ph = ph_;

	ph->fired = true;
	if (unlikely(!GetExitCodeProcess(ph->process_handle, &ph->exit_code)))
		internal(file_line, "GetExitCodeProcess failed: %u", GetLastError());
	win32_close_handle(ph->process_handle);
	call(wake_up_wait_list)(&ph->wait_list, &monitor_mutex, true);
}

static bool proc_addstr(char **ptr, size_t *len, const char *str, bool cvt_slashes, ajla_error_t *err)
{
	size_t i, j, bs;
	bool quote;
	if (*len)
		if (unlikely(!array_add_mayfail(char, ptr, len, ' ', NULL, err)))
			return false;
	quote = !str[0] || str[strcspn(str, " \t")];
	if (unlikely(quote)) {
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
	if (unlikely(quote)) {
		for (j = 0; j < bs; j++)
			if (unlikely(!array_add_mayfail(char, ptr, len, '\\', NULL, err)))
					return false;
		if (unlikely(!array_add_mayfail(char, ptr, len, '"', NULL, err)))
			return false;
	}
	return true;
}

struct proc_handle *os_proc_spawn(dir_handle_t wd, const char *path, size_t n_handles, handle_t *source, int *target, char * const args[], char *envc, ajla_error_t *err)
{
	char *path_cpy;
	struct proc_handle *ph;
	union {
		STARTUPINFOA sti_a;
		STARTUPINFOW sti_w;
	} u;
	DWORD dwCreationFlags = 0;
	PROCESS_INFORMATION pi;
	BOOL b;
	DWORD gle;
	char * const *a;
	char *ptr;
	size_t len;
	size_t i;

	path_cpy = str_dup(path, -1, err);
	if (unlikely(!path_cpy))
		return NULL;
	for (i = 0; path_cpy[i]; i++)
		if (path_cpy[i] == '/')
			path_cpy[i] = '\\';

	ph = mem_calloc_mayfail(struct proc_handle *, sizeof(struct proc_handle), err);
	if (unlikely(!ph))
		goto err0;

	list_init(&ph->wait_list);

	if (!*args) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "empty arguments in spawn");
		goto err3;
	}
	if (unlikely(!array_init_mayfail(char, &ptr, &len, err)))
		goto err3;
	for (a = args; *a; a++) {
		if (!proc_addstr(&ptr, &len, *a, a == args, err))
			goto err3;
	}
	if (unlikely(!array_add_mayfail(char, &ptr, &len, 0, NULL, err)))
		goto err3;

	if (is_winnt()) {
		memset(&u.sti_w, 0, sizeof u.sti_w);
		u.sti_w.cb = sizeof u.sti_w;
		u.sti_w.dwFlags = STARTF_USESTDHANDLES;
		if (fn_GetEnvironmentStringsW && fn_FreeEnvironmentStringsW) {
			dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
	} else {
		memset(&u.sti_a, 0, sizeof u.sti_a);
		u.sti_a.cb = sizeof u.sti_a;
		u.sti_a.dwFlags = STARTF_USESTDHANDLES;
	}
	for (i = 0; i < n_handles; i++) {
		HANDLE *t;
		if (target[i] == 0) {
			t = is_winnt() ? &u.sti_w.hStdInput : &u.sti_a.hStdInput;
		} else if (target[i] == 1) {
			t = is_winnt() ? &u.sti_w.hStdOutput : &u.sti_a.hStdOutput;
		} else if (likely(target[i] == 2)) {
			t = is_winnt() ? &u.sti_w.hStdError : &u.sti_a.hStdError;
		} else {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "only the first three handles can be redirected");
			goto err4;
		}
		if (unlikely(handle_is_socket(source[i]))) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "socket can't be inherited by subprocesses on Windows");
			goto err4;
		}
		if (unlikely(*t != NULL)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "redirecting a handle multiple times");
			goto err4;
		}
		win32_close_read_thread(source[i]);
		if (unlikely(!DuplicateHandle(GetCurrentProcess(), source[i]->h, GetCurrentProcess(), t, 0, TRUE, DUPLICATE_SAME_ACCESS))) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't duplicate handle: %s", error_decode(e));
			goto err4;
		}
	}
	if (is_winnt()) {
		WCHAR *path_cpy_w, *ptr_w, *wd_w;
		path_cpy_w = utf8_to_wchar(path_cpy, err);
		if (unlikely(!path_cpy_w)) {
			goto err4;
		}
		ptr_w = utf8_to_wchar(ptr, err);
		if (unlikely(!ptr_w)) {
			mem_free(path_cpy_w);
			goto err4;
		}
		wd_w = utf8_to_wchar(wd, err);
		if (unlikely(!wd_w)) {
			mem_free(path_cpy_w);
			mem_free(ptr_w);
			goto err4;
		}
		if (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) {
			char *e;
			WCHAR *uni_env;
			size_t uni_env_l;
			if (unlikely(!array_init_mayfail(WCHAR, &uni_env, &uni_env_l, err))) {
				mem_free(path_cpy_w);
				mem_free(ptr_w);
				mem_free(wd_w);
				goto err4;
			}
			e = envc;
			while (*e) {
				ajla_error_t sink;
				size_t i;
				WCHAR *wc = utf8_to_wchar(e, &sink);
				e += strlen(e) + 1;
				if (unlikely(!wc)) {
					if (sink.error_class == EC_ASYNC) {
						if (!err)
							fatal("can't allocate environment memory: %s", error_decode(sink));
						*err = sink;
						mem_free(uni_env);
						mem_free(path_cpy_w);
						mem_free(ptr_w);
						mem_free(wd_w);
						goto err4;
					}
					continue;
				}
				for (i = 0; wc[i]; i++) ;
				if (unlikely(!array_add_multiple_mayfail(WCHAR, &uni_env, &uni_env_l, wc, i + 1, NULL, err))) {
					mem_free(wc);
					mem_free(path_cpy_w);
					mem_free(ptr_w);
					mem_free(wd_w);
					goto err4;
				}
				mem_free(wc);
			}
			if (unlikely(!array_add_mayfail(WCHAR, &uni_env, &uni_env_l, 0, NULL, err))) {
				mem_free(path_cpy_w);
				mem_free(ptr_w);
				mem_free(wd_w);
				goto err4;
			}
			b = CreateProcessW(path_cpy_w, ptr_w, NULL, NULL, TRUE, dwCreationFlags, uni_env, wd_w, &u.sti_w, &pi);
			gle = GetLastError();
			mem_free(uni_env);
		} else {
			b = CreateProcessW(path_cpy_w, ptr_w, NULL, NULL, TRUE, dwCreationFlags, envc, wd_w, &u.sti_w, &pi);
			gle = GetLastError();
		}
		mem_free(path_cpy_w);
		mem_free(ptr_w);
		mem_free(wd_w);
	} else {
		b = CreateProcessA(path_cpy, ptr, NULL, NULL, TRUE, dwCreationFlags, envc, wd, &u.sti_a, &pi);
		gle = GetLastError();
	}
	if (unlikely(!b)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't create process(%s): %s", path, error_decode(e));
		goto err4;
	}
	ph->process_handle = pi.hProcess;
	win32_close_handle(pi.hThread);

	if (unlikely(!monitor_handle(ph->process_handle, proc_wait_end, win32_close_handle, ph, err))) {
		goto err4;
	}

	for (i = 0; i < 3; i++) {
		HANDLE *t;
		if (!i)
			t = is_winnt() ? &u.sti_w.hStdInput : &u.sti_a.hStdInput;
		else if (i == 1)
			t = is_winnt() ? &u.sti_w.hStdOutput : &u.sti_a.hStdOutput;
		else
			t = is_winnt() ? &u.sti_w.hStdError : &u.sti_a.hStdError;
		if (*t)
			win32_close_handle(*t);
	}
	mem_free(ptr);
	mem_free(path_cpy);
	return ph;

err4:
	for (i = 0; i < 3; i++) {
		HANDLE *t;
		if (!i)
			t = is_winnt() ? &u.sti_w.hStdInput : &u.sti_a.hStdInput;
		else if (i == 1)
			t = is_winnt() ? &u.sti_w.hStdOutput : &u.sti_a.hStdOutput;
		else
			t = is_winnt() ? &u.sti_w.hStdError : &u.sti_a.hStdError;
		if (*t)
			win32_close_handle(*t);
	}
	mem_free(ptr);
err3:
	mem_free(ph);
err0:
	mem_free(path_cpy);
	return NULL;
}

void os_proc_free_handle(struct proc_handle *ph)
{
	ajla_assert_lo(list_is_empty(&ph->wait_list), (file_line, "os_proc_free_handle: freeing handle when there are processes waiting for it"));
	monitor_lock();
	if (!ph->fired)
		monitor_close(ph->process_handle);
	monitor_unlock();
	mem_free(ph);
}

bool os_proc_register_wait(struct proc_handle *ph, mutex_t **mutex_to_lock, struct list *list_entry, int *status)
{
	monitor_lock();
	if (ph->fired) {
		*status = ph->exit_code;
		monitor_unlock();
		return true;
	} else {
		*mutex_to_lock = &monitor_mutex;
		list_add(&ph->wait_list, list_entry);
		monitor_unlock();
		return false;
	}
}


int os_signal_handle(const char attr_unused *str, signal_seq_t attr_unused *seq, ajla_error_t attr_unused *err)
{
	*seq = 0;
	return 0;
}

void os_signal_unhandle(int attr_unused sig)
{
}

signal_seq_t os_signal_seq(int attr_unused sig)
{
	return 0;
}

bool os_signal_wait(int attr_unused sig, signal_seq_t attr_unused seq, mutex_t **mutex_to_lock, struct list *list_entry)
{
	iomux_never(mutex_to_lock, list_entry);
	return true;
}


struct win32_notify_handle {
	HANDLE h;
	struct list wait_list;
	bool fired;
};

static void iomux_directory_handle_wake_up(void *nh_)
{
	struct win32_notify_handle *nh = nh_;
	nh->fired = true;
	win32_close_change_notification_handle(nh->h);
	call(wake_up_wait_list)(&nh->wait_list, &monitor_mutex, true);
}

bool iomux_directory_handle_alloc(dir_handle_t handle, notify_handle_t *h, uint64_t attr_unused *seq, ajla_error_t *err)
{
	struct win32_notify_handle *nh;
	DWORD gle;
	nh = mem_alloc_mayfail(struct win32_notify_handle *, sizeof(struct win32_notify_handle), err);
	if (unlikely(!nh))
		return false;
	list_init(&nh->wait_list);
	nh->fired = false;
	if (is_winnt()) {
		WCHAR *w = utf8_to_wchar(handle, err);
		if (unlikely(!w)) {
			mem_free(nh);
			return false;
		}
		nh->h = FindFirstChangeNotificationW(w, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY);
		gle = GetLastError();
		mem_free(w);
	} else {
		nh->h = FindFirstChangeNotificationA(handle, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY);
		gle = GetLastError();
	}
	if (unlikely(nh->h == INVALID_HANDLE_VALUE)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't wait on change of '%s': %s", handle, error_decode(e));
		mem_free(nh);
		return false;
	}
	if (unlikely(!monitor_handle(nh->h, iomux_directory_handle_wake_up, win32_close_change_notification_handle, nh, err))) {
		win32_close_change_notification_handle(nh->h);
		mem_free(nh);
		return false;
	}
	*h = nh;
	return true;
}

bool iomux_directory_handle_wait(notify_handle_t h, uint64_t attr_unused seq, mutex_t **mutex_to_lock, struct list *list_entry)
{
	struct win32_notify_handle *nh = h;
	monitor_lock();
	if (nh->fired) {
		monitor_unlock();
		return true;
	} else {
		*mutex_to_lock = &monitor_mutex;
		list_add(&nh->wait_list, list_entry);
		monitor_unlock();
		return false;
	}
}

void iomux_directory_handle_free(notify_handle_t h)
{
	struct win32_notify_handle *nh = h;
	ajla_assert_lo(list_is_empty(&nh->wait_list), (file_line, "iomux_directory_handle_free: freeing handle when there are processes waiting for it"));
	monitor_lock();
	if (!nh->fired)
		monitor_close(nh->h);
	monitor_unlock();
	mem_free(nh);
}


static SOCKET win32_notify_socket[2];

static bool win32_socketpair(SOCKET result[2])
{
	SOCKET lst;
	struct sockaddr_in sin;
	socklen_t len;
	int r;
	u_long one;

	lst = INVALID_SOCKET;
	result[0] = result[1] = INVALID_SOCKET;

	lst = socket(PF_INET, SOCK_STREAM, 0);
	if (unlikely(lst == INVALID_SOCKET))
		goto fail;

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	r = bind(lst, (struct sockaddr *)&sin, sizeof sin);
	if (unlikely(r == SOCKET_ERROR))
		goto fail;

	len = sizeof sin;
	r = getsockname(lst, (struct sockaddr *)&sin, &len);
	if (unlikely(r == SOCKET_ERROR))
		goto fail;

	r = listen(lst, 1);
	if (unlikely(r == SOCKET_ERROR))
		goto fail;

	result[0] = socket(PF_INET, SOCK_STREAM, 0);
	if (unlikely(result[0] == INVALID_SOCKET))
		goto fail;

	r = connect(result[0], (struct sockaddr *)&sin, sizeof sin);
	if (unlikely(r == SOCKET_ERROR))
		goto fail;

	len = sizeof sin;
	result[1] = accept(lst, (struct sockaddr *)&sin, &len);
	if (unlikely(result[1] == INVALID_SOCKET))
		goto fail;

	one = 1;
	r = ioctlsocket(result[0], FIONBIO, &one);
	if (unlikely(r == SOCKET_ERROR))
		goto fail;
	r = ioctlsocket(result[1], FIONBIO, &one);
	if (unlikely(r == SOCKET_ERROR))
		goto fail;

	win32_close_socket(lst);

	return true;

fail:
	if (lst != INVALID_SOCKET)
		win32_close_socket(lst);
	if (result[0] != INVALID_SOCKET)
		win32_close_socket(result[0]);
	if (result[1] != INVALID_SOCKET)
		win32_close_socket(result[1]);
	return false;
}

static void win32_notify(void)
{
	int r;
	char c = 0;
	r = send(win32_notify_socket[1], &c, 1, 0);
	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		if (unlikely(er != WSAEWOULDBLOCK))
			fatal("error writing to the notify socket: %d", er);
	}
}

static void win32_shutdown_notify_pipe(void)
{
	int r;
	char c = 1;
retry:
	r = send(win32_notify_socket[1], &c, 1, 0);
	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		if (er == WSAEWOULDBLOCK) {
			Sleep(1);
			goto retry;
		}
		fatal("error writing to the notify socket: %d", er);
	}
}

static bool win32_drain_notify_pipe(void)
{
	char buffer[1024];
	int r;
	r = recv(win32_notify_socket[0], buffer, sizeof buffer, 0);
	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		if (likely(er == WSAEWOULDBLOCK))
			return false;
		fatal("error reading the notify socket: %d", er);
	}
	return !!memchr(buffer, 1, r);
}


handle_t os_socket(int domain, int type, int protocol, ajla_error_t *err)
{
	SOCKET sock;
	if (unlikely(!winsock_supported)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "TCP/IP is not configured");
		return NULL;
	}
	domain = os_socket_pf(domain, err);
	if (unlikely(domain == -1))
		return NULL;
	type = os_socket_type(type, err);
	if (unlikely(type == -1))
		return NULL;
	sock = socket(domain, type, protocol);
	if (unlikely(sock == INVALID_SOCKET)) {
		fatal_mayfail(error_from_win32_socket(WSAGetLastError()), err, "socket failed");
		return NULL;
	}
	return win32_socket_to_handle(sock, err);
}

bool os_bind_connect(bool bnd, handle_t h, unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	int r;
	int er;
	struct sockaddr *sa;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}
	sa = os_get_sock_addr(addr, &addr_len, err);
	if (unlikely(!sa))
		return false;
	r = (likely(!bnd) ? connect : bind)(h->s, sa, addr_len);
	er = WSAGetLastError();
	mem_free_aligned(sa);
	if (unlikely(r != SOCKET_ERROR))
		return true;
	if (likely(!bnd) && (likely(er == WSAEWOULDBLOCK) || likely(!er))) {
		/*debug("connect would block");
		while (1) {
			int t1 = iomux_test_handle(h, false);
			int t2 = iomux_test_handle(h, true);
			Sleep(1000);
			debug("test handle: %d", t1, t2);
			if (t2)
				break;
			{
				int er;
				socklen_t er_l = sizeof(er);
				r = getsockopt(h->s, SOL_SOCKET, SO_ERROR, cast_ptr(char *, &er), &er_l);
				if (unlikely(r == SOCKET_ERROR)) {
					er = WSAGetLastError();
					fatal_mayfail(error_from_win32_socket(er), err, "getsockopt returned an error: %d", er);
					return false;
				}
				debug("socket status: %d", er);
			}
		}*/
		h->connect_in_progress = true;
		return true;
	}
	fatal_mayfail(error_from_win32_socket(er), err, "can't %s socket: %d", !bnd ? "connect" : "bind", er);
	return false;
}

bool os_connect_completed(handle_t h, ajla_error_t *err)
{
	int e;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	e = get_socket_error(h);
	if (unlikely(e)) {
		fatal_mayfail(error_from_win32_socket(e), err, "can't connect socket: %d", e);
		return false;
	}
	h->connect_in_progress = false;
	return true;
}

bool os_listen(handle_t h, ajla_error_t *err)
{
	int r;
	int er;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	r = listen(h->s, signed_maximum(int));
	if (unlikely(r == SOCKET_ERROR)) {
		er = WSAGetLastError();
		fatal_mayfail(error_from_win32_socket(er), err, "listen returned an error: %d", er);
		return false;
	}
	return true;
}

int os_accept(handle_t h, handle_t *result, ajla_error_t *err)
{
	SOCKET sock;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return OS_RW_ERROR;
	}

	sock = accept(h->s, NULL, 0);
	if (unlikely(sock == INVALID_SOCKET)) {
		int er = WSAGetLastError();
		if (likely(er == WSAEWOULDBLOCK))
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_win32_socket(er), err, "accept returned an error: %d", er);
		return OS_RW_ERROR;
	}

	*result = win32_socket_to_handle(sock, err);

	return unlikely(*result == NULL) ? OS_RW_ERROR : 0;
}

bool os_getsockpeername(bool peer, handle_t h, unsigned char **addr, size_t *addr_len, ajla_error_t *err)
{
	int r;
	struct sockaddr *sa;
	socklen_t addrlen;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return OS_RW_ERROR;
	}

	sa = mem_align_mayfail(struct sockaddr *, SOCKADDR_MAX_LEN, SOCKADDR_ALIGN, err);
	if (unlikely(!sa))
		return false;
	addrlen = SOCKADDR_MAX_LEN;
	r = (!peer ? getsockname : getpeername)(h->s, sa, &addrlen);
	if (r == SOCKET_ERROR) {
		int er = WSAGetLastError();
		fatal_mayfail(error_from_win32_socket(er), err, "%s returned an error: %d", !peer ? "getsockname" : "getpeername", er);
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
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return OS_RW_ERROR;
	}

	f = translate_flags(os_socket_msg, flags, err);
	if (unlikely(f < 0))
		return OS_RW_ERROR;

	sa = mem_align_mayfail(struct sockaddr *, SOCKADDR_MAX_LEN, SOCKADDR_ALIGN, err);
	if (unlikely(!sa))
		return OS_RW_ERROR;
	addrlen = SOCKADDR_MAX_LEN;
	r = recvfrom(h->s, buffer, len, f, sa, &addrlen);
	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		if (likely(er == WSAEWOULDBLOCK))
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_win32_socket(er), err, "recvfrom returned an error: %d", er);
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
	int er;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return OS_RW_ERROR;
	}

	f = translate_flags(os_socket_msg, flags, err);
	if (unlikely(f < 0))
		return OS_RW_ERROR;

	if (addr_len != 0) {
		size_t al = addr_len;
		sa = os_get_sock_addr(addr, &al, err);
		if (unlikely(!sa))
			return OS_RW_ERROR;
		r = sendto(h->s, buffer, len, f, sa, al);
		er = WSAGetLastError();
		mem_free_aligned(sa);
	} else {
		r = send(h->s, buffer, len, f);
		er = WSAGetLastError();
	}

	if (unlikely(r == SOCKET_ERROR)) {
		if (likely(er == WSAEWOULDBLOCK))
			return OS_RW_WOULDBLOCK;
		fatal_mayfail(error_from_win32_socket(er), err, "send%s returned an error: %d", addr_len ? "to" : "", er);
		return OS_RW_ERROR;
	}

	return r;
}

bool os_getsockopt(handle_t h, int level, int option, char **buffer, size_t *buffer_len, ajla_error_t *err)
{
	int r;
	socklen_t opt_len;

	obj_registry_verify(OBJ_TYPE_HANDLE, ptr_to_num(h), file_line);
	if (unlikely(!handle_is_socket(h))) {
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

	r = getsockopt(h->s, level, option, *buffer, &opt_len);

	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		fatal_mayfail(error_from_win32_socket(er), err, "getsockopt returned an error: %d", er);
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
	if (unlikely(!handle_is_socket(h))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "socket operation on non-socket");
		return false;
	}

	level = os_socket_level(level, err);
	if (unlikely(level < 0))
		return false;

	option = os_socket_option(option, err);
	if (unlikely(level < 0))
		return false;

	r = setsockopt(h->s, level, option, buffer, buffer_len);

	if (unlikely(r == SOCKET_ERROR)) {
		int er = WSAGetLastError();
		fatal_mayfail(error_from_win32_socket(er), err, "setsockopt returned an error: %d", er);
		return false;
	}

	return true;
}

static bool os_use_getaddrinfo(const char *host, int port, struct address **result, size_t *result_l, ajla_error_t *err)
{
	char port_str[6];
	ssize_t r;
	size_t i;
	struct addrinfo *res = NULL, *rs;

	if (unlikely(!array_init_mayfail(struct address, result, result_l, err)))
		return false;

	sprintf(port_str, "%d", port);
	r = fn_getaddrinfo(host, port_str, NULL, &res);
	if (unlikely(r)) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_GAI, abs((int)r)), err, "host not found");
		goto fail;
	}

	for (rs = res; rs; rs = rs->ai_next) {
		void *xresult;
		struct address addr;
		ajla_error_t e;
		socklen_t addrlen = rs->ai_addrlen;

		addr.address = os_get_ajla_addr(rs->ai_addr, &addrlen, &e);
		if (unlikely(!addr.address))
			continue;
		addr.address_length = addrlen;

		if (unlikely(!array_add_mayfail(struct address, result, result_l, addr, &xresult, err))) {
			*result = xresult;
			goto fail;
		}
	}

	if (unlikely(!*result_l)) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_GAI, abs(EAI_NONAME)), err, "host not found");
		goto fail;
	}

	fn_freeaddrinfo(res);
	return true;

fail:
	if (res)
		fn_freeaddrinfo(res);
	for (i = 0; i < *result_l; i++)
		mem_free((*result)[i].address);
	mem_free(*result);
	return false;
}

bool os_getaddrinfo(const char *host, int port, struct address **result, size_t *result_l, ajla_error_t *err)
{
	struct hostent *he;
	size_t i;
	void *xresult;
	char *a;

	if (unlikely(!winsock_supported)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "TCP/IP is not configured");
		return false;
	}

	if (likely(fn_getaddrinfo != NULL)) {
		return os_use_getaddrinfo(host, port, result, result_l, err);
	}

	if (unlikely(!array_init_mayfail(struct address, result, result_l, err)))
		return false;

	he = gethostbyname(host);

	if (unlikely(!he)) {
		int er = WSAGetLastError();
		fatal_mayfail(error_from_win32_socket(er), err, "host not found");
		goto fail;
	}

	if (he->h_addrtype != AF_INET || he->h_length != 4 || !he->h_addr) {
		int er = WSANO_DATA;
		fatal_mayfail(error_from_win32_socket(er), err, "host not found");
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
		int er = WSANO_DATA;
		fatal_mayfail(error_from_win32_socket(er), err, "host not found");
		goto fail;
	}

	return true;

fail:
	for (i = 0; i < *result_l; i++)
		mem_free((*result)[i].address);
	mem_free(*result);
	return false;
}

static char *os_use_getnameinfo(unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	struct sockaddr *sa;
	int r;
	char *h;
	size_t h_len;
	sa = os_get_sock_addr(addr, &addr_len, err);
	if (unlikely(!sa))
		return NULL;
	h_len = 64;
alloc_buffer_again:
	h = mem_alloc_mayfail(char *, h_len, err);
	if (unlikely(!h)) {
		mem_free_aligned(sa);
		return NULL;
	}
	r = fn_getnameinfo(sa, addr_len, h, h_len, NULL, 0, 0);
	if (unlikely(r)) {
		if (unlikely(r == 122)) {
			mem_free(h);
			h_len *= 2;
			if (unlikely(!h_len)) {
				fatal_mayfail(error_ajla(EC_SYSCALL, AJLA_ERROR_SIZE_OVERFLOW), err, "name buffer overflow");
				mem_free_aligned(sa);
				return NULL;
			}
			goto alloc_buffer_again;
		}
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_GAI, abs((int)r)), err, "host not found");
		mem_free(h);
		mem_free_aligned(sa);
		return NULL;
	}
	mem_free_aligned(sa);
	return h;
}

char *os_getnameinfo(unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	struct sockaddr *sa;
	struct hostent *he;
	char *name;
	size_t le;

	if (unlikely(!winsock_supported)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "TCP/IP is not configured");
		return false;
	}

	if (likely(fn_getnameinfo != NULL)) {
		return os_use_getnameinfo(addr, addr_len, err);
	}

	sa = os_get_sock_addr(addr, &addr_len, err);
	if (unlikely(!sa))
		return NULL;
	switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin;
			if (unlikely(addr_len < offsetof(struct sockaddr_in, sin_addr) + 4)) {
				fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "too short address");
				mem_free_aligned(sa);
				return NULL;
			}
			sin = cast_ptr(struct sockaddr_in *, sa);
			he = gethostbyaddr(cast_ptr(char *, &sin->sin_addr.s_addr), 4, sa->sa_family);
			break;
		}
#ifdef AF_INET6
		case AF_INET6: {
			struct sockaddr_in6 *sin6;
			if (unlikely(addr_len < offsetof(struct sockaddr_in6, sin6_addr) + 16)) {
				fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "too short address");
				mem_free_aligned(sa);
				return NULL;
			}
			sin6 = cast_ptr(struct sockaddr_in6 *, sa);
			he = gethostbyaddr(&sin6->sin6_addr.s6_addr, 16, sa->sa_family);
			break;
		}
#endif
		default: {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "address family %d not supported", sa->sa_family);
			mem_free_aligned(sa);
			return NULL;
		}
	}
	mem_free_aligned(sa);
	if (unlikely(!he) || !he->h_name) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_H_ERRNO, h_errno), err, "host not found");
		return NULL;
	}
	le = strlen(he->h_name);
	name = mem_alloc_mayfail(char *, le + 1, err);
	if (unlikely(!name))
		return NULL;
	return memcpy(name, he->h_name, le + 1);
}

bool os_getaddrinfo_is_thread_safe(void)
{
	return winsock_supported && fn_getaddrinfo != NULL && fn_getnameinfo != NULL;
}

const char *os_decode_error(ajla_error_t attr_unused error, char attr_unused *(*tls_buffer)(void))
{
	return NULL;
}


struct dl_handle_t *os_dlopen(const char *filename, ajla_error_t *err, char **err_msg)
{
	size_t i;
	DWORD gle;
	HMODULE h;
	*err_msg = NULL;
	if (is_winnt()) {
		WCHAR *w = utf8_to_wchar(filename, err);
		if (unlikely(!w))
			return NULL;
		for (i = 0; w[i]; i++)
			if (w[i] == '/')
				w[i] = '\\';
		h = LoadLibraryW(w);
		gle = GetLastError();
		mem_free(w);
	} else {
		char *a = str_dup(filename, -1, err);
		if (unlikely(!a))
			return NULL;
		for (i = 0; a[i]; i++)
			if (a[i] == '/')
				a[i] = '\\';
		h = LoadLibraryA(a);
		gle = GetLastError();
		mem_free(a);
	}
	if (unlikely(!h)) {
		ajla_error_t e = error_from_win32(EC_SYSCALL, gle);
		fatal_mayfail(e, err, "can't load library %s: %s", filename, error_decode(e));
		return NULL;
	}
	return cast_ptr(struct dl_handle_t *, h);
}

void os_dlclose(struct dl_handle_t *dlh)
{
	if (unlikely(!FreeLibrary(cast_ptr(HMODULE, dlh))))
		internal(file_line, "FreeLibrary failed: %u", GetLastError());
}

bool os_dlsym(struct dl_handle_t *dlh, const char *symbol, void **result)
{
	void *r = GetProcAddress(cast_ptr(HMODULE, dlh), symbol);
	if (unlikely(!r))
		return false;
	*result = r;
	return true;
}


static thread_t iomux_thread;

static int compare_socket(const void *x1, const void *x2)
{
	SOCKET s1 = *cast_ptr(const SOCKET *, x1);
	SOCKET s2 = *cast_ptr(const SOCKET *, x2);
	if (s1 < s2)
		return -1;
	if (s1 > s2)
		return 1;
	return 0;
}

thread_function_decl(iomux_poll_thread,
	u_int fdx_size;
	struct fdx_set *fdx[2];

	thread_set_id(-1);

	fdx_size = 1;
	fdx[0] = mem_alloc(struct fdx_set *, sizeof(struct fdx_set));
	fdx[1] = mem_alloc(struct fdx_set *, sizeof(struct fdx_set));

	while (likely(!win32_drain_notify_pipe())) {
		int wr;
		int r;
		bool need_timeout = false;
		struct timeval timeout;
		timeout.tv_sec = CONNECT_TIMEOUT / 1000000;
		timeout.tv_usec = CONNECT_TIMEOUT % 1000000;

		fdx[0]->fd_count = 1;
		fdx[0]->fd_array[0] = win32_notify_socket[0];
		fdx[1]->fd_count = 0;

		mutex_lock(&socket_list_mutex);
		for (wr = 0; wr < 2; wr++) {
			struct list *l;
			list_for_each(l, &socket_list[wr]) {
				handle_t h = get_struct(l, struct win32_handle, socket_entry[wr]);
				address_lock(h, DEPTH_THUNK);
				if (!list_is_empty(&h->wait_list[wr])) {
					if (unlikely(fdx[wr]->fd_count == fdx_size)) {
						fdx_size *= 2;
						if (unlikely(!fdx_size))
							fatal("too many sockets");
						mem_check_overflow(offsetof(struct fdx_set, fd_array), fdx_size, sizeof(SOCKET), NULL);
						fdx[0] = mem_realloc(struct fdx_set *, fdx[0], offsetof(struct fdx_set, fd_array[fdx_size]));
						fdx[1] = mem_realloc(struct fdx_set *, fdx[1], offsetof(struct fdx_set, fd_array[fdx_size]));
					}
					fdx[wr]->fd_array[fdx[wr]->fd_count++] = h->s;
					if (unlikely(h->connect_in_progress))
						need_timeout = true;
				} else {
					l = l->prev;
					list_del(&h->socket_entry[wr]);
					h->socket_entry[wr].next = NULL;
				}
				address_unlock(h, DEPTH_THUNK);
			}
		}
		mutex_unlock(&socket_list_mutex);

		r = select(FD_SETSIZE, cast_ptr(fd_set *, fdx[0]), cast_ptr(fd_set *, fdx[1]), NULL, need_timeout ? &timeout : NULL);
		if (unlikely(r == SOCKET_ERROR)) {
			int er = WSAGetLastError();
			internal(file_line, "select returned an error: %d", er);
		}

		qsort(fdx[0]->fd_array, fdx[0]->fd_count, sizeof(SOCKET), compare_socket);
		qsort(fdx[1]->fd_array, fdx[1]->fd_count, sizeof(SOCKET), compare_socket);

		mutex_lock(&socket_list_mutex);
		for (wr = 0; wr < 2; wr++) {
			struct list *l;
			list_for_each(l, &socket_list[wr]) {
				handle_t h = get_struct(l, struct win32_handle, socket_entry[wr]);
				SOCKET hndl = h->s;
				void *p;
				p = bsearch(&hndl, fdx[wr]->fd_array, fdx[wr]->fd_count, sizeof(SOCKET), compare_socket);
				if (p) {
wake_up:
					address_lock(h, DEPTH_THUNK);
					call(wake_up_wait_list)(&h->wait_list[wr], address_get_mutex(h, DEPTH_THUNK), true);
				} else {
					if (unlikely(h->connect_in_progress)) {
						int e = get_socket_error(h);
						if (e)
							goto wake_up;
					}
				}
			}
		}
		mutex_unlock(&socket_list_mutex);
	}

	mem_free(fdx[0]);
	mem_free(fdx[1]);
)


int os_getpagesize(void)
{
	SYSTEM_INFO si;
	static int ps = 0;
	if (likely(ps))
		return ps;
	GetSystemInfo(&si);
	ps = si.dwAllocationGranularity;
	return ps;
}

static DWORD prot_to_protect(int prot)
{
	if (prot == PROT_NONE)
		return PAGE_NOACCESS;
	if (prot == PROT_READ)
		return PAGE_READONLY;
	if (prot == (PROT_READ | PROT_WRITE))
		return PAGE_READWRITE;
	return PAGE_EXECUTE_READWRITE;
}

void *os_mmap(void *ptr, size_t size, int prot, int flags, handle_t h, os_off_t off, ajla_error_t *err)
{
	size_t align;
	DWORD allocation_type, protect;
	void *res;
	ajla_error_t e;

	align = (size_t)1 << MAP_ALIGNED_BITS(flags);
	allocation_type = MEM_RESERVE | (prot == PROT_NONE ? 0 : MEM_COMMIT);
	protect = prot_to_protect(prot);

	if (unlikely((flags & (MAP_EXCL | MAP_FIXED)) == MAP_FIXED)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "fixed mappings not supported");
		return MAP_FAILED;
	}
	if (unlikely(handle_is_valid(h))) {
		HANDLE hmap;
		DWORD map_access = !prot || prot == PROT_READ ? FILE_MAP_READ : FILE_MAP_WRITE;
		if (unlikely(handle_is_socket(h))) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mmap of socket not supported");
			return MAP_FAILED;
		}
		hmap = CreateFileMappingA(h->h, NULL, protect, 0, 0, NULL);
		if (unlikely(!hmap)) {
			e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't create mapping object: %s", error_decode(e));
			return MAP_FAILED;
		}
repeat_filemap:
		res = MapViewOfFileEx(hmap, map_access, off >> 31 >> 1, off, size, ptr);
		if (unlikely(!res)) {
			if (ptr && !(flags & MAP_FIXED)) {
				ptr = NULL;
				goto repeat_filemap;
			}
			e = error_from_win32(EC_SYSCALL, GetLastError());
			win32_close_handle(hmap);
			fatal_mayfail(e, err, "can't map file: %s", error_decode(e));
			return MAP_FAILED;
		}
		if (ptr && unlikely(res != ptr))
			internal(file_line, "MapViewOfFileEx allocated different memory: %p != %p", res, ptr);
		win32_close_handle(hmap);
		return res;
	}
repeat:
	res = VirtualAlloc(ptr, size + align - 1, allocation_type, protect);
	if (unlikely(!res)) {
		if (ptr && !(flags & MAP_FIXED)) {
			ptr = NULL;
			goto repeat;
		}
		e = error_from_win32(EC_SYSCALL, GetLastError());
		fatal_mayfail(e, err, "can't allocate memory: %s", error_decode(e));
		return MAP_FAILED;
	}
	if (ptr && unlikely(res != ptr))
		internal(file_line, "VirtualAlloc allocated different memory: %p != %p", res, ptr);
	if (align != 1) {
		void *aptr = num_to_ptr(round_up(ptr_to_num(res), align));
		if (unlikely(!VirtualFree(res, 0, MEM_RELEASE)))
			internal(file_line, "VirtualFree failed: %u", GetLastError());
		res = VirtualAlloc(aptr, size, allocation_type, protect);
		if (unlikely(!res))
			goto repeat;
		if (unlikely(res != aptr)) {
			internal(file_line, "VirtualAlloc allocated different memory: %p != %p", res, aptr);
		}
		return aptr;
	}
	return res;
}

void os_munmap(void *ptr, size_t attr_unused size, bool file)
{
	if (!file) {
		if (unlikely(!VirtualFree(ptr, 0, MEM_RELEASE)))
			internal(file_line, "VirtualFree failed: %u", GetLastError());
	} else {
		if (unlikely(!UnmapViewOfFile(ptr)))
			internal(file_line, "UnmapViewOfFile failed: %u", GetLastError());
	}
}

bool os_mprotect(void *ptr, size_t size, int prot, ajla_error_t *err)
{
	if (prot == PROT_NONE) {
		if (unlikely(!VirtualFree(ptr, size, MEM_DECOMMIT)))
			internal(file_line, "VirtualFree failed: %u", GetLastError());
	} else {
		DWORD allocation_type, protect;
		allocation_type = MEM_COMMIT;
		protect = prot_to_protect(prot);
		if (unlikely(!VirtualAlloc(ptr, size, allocation_type, protect))) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal_mayfail(e, err, "can't commit memory: %s", error_decode(e));
			return false;
		}
	}
	return true;
}

void os_code_invalidate_cache(uint8_t *code, size_t code_size, bool set_exec)
{
	DWORD old;
	if (fn_FlushInstructionCache) {
		if (unlikely(!fn_FlushInstructionCache(GetCurrentProcess(), cast_ptr(void *, code), code_size))) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal("failed to flush instruction cache: FlushInstructionCache(%p, %"PRIxMAX") returned error: %s", code, (uintmax_t)code_size, error_decode(e));
		}
	}
	if (set_exec) {
		if (unlikely(!VirtualProtect(code, code_size, PAGE_EXECUTE_READWRITE, &old))) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal("failed to set memory range read+write+exec: VirtualProtect(%p, %"PRIxMAX") returned error: %s", code, (uintmax_t)code_size, error_decode(e));
		}
	}
}

void *os_code_map(uint8_t *code, size_t attr_unused code_size, ajla_error_t attr_unused *err)
{
	/*debug("making executable: %p, %lx", code, code_size);*/
	os_code_invalidate_cache(code, code_size, true);
	return code;
}

void os_code_unmap(void *mapped_code, size_t attr_unused code_size)
{
	mem_free(mapped_code);
}


void os_get_environment(char **str, size_t *l)
{
	array_init(char, str, l);
	if (!is_winnt() || !fn_GetEnvironmentStringsW || !fn_FreeEnvironmentStringsW) {
		const char *e, *a;
		if (fn_GetEnvironmentStringsA)
			e = fn_GetEnvironmentStringsA();
		else
			e = fn_GetEnvironmentStrings();
		a = e;
		if (unlikely(!e)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal("GetEnvironmentStringsA failed: %s", error_decode(e));
		}
		while (*a) {
			bool upcase = true;
			if (*a == '=') {
				a += strlen(a) + 1;
				continue;
			}
			while (*a) {
				char c = *a++;
				if (upcase) {
					if (c >= 'a' && c <= 'z')
						c -= 0x20;
					if (c == '=')
						upcase = false;
				}
				array_add(char, str, l, c);
			}
			array_add(char, str, l, 0);
			a++;
		}
		if (fn_GetEnvironmentStringsA && fn_FreeEnvironmentStringsA) {
			if (unlikely(!fn_FreeEnvironmentStringsA(e))) {
				ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
				fatal("FreeEnvironmentStringsA failed: %s", error_decode(e));
			}
		}
	} else {
		const WCHAR *e, *a;
		e = fn_GetEnvironmentStringsW();
		a = e;
		if (unlikely(!e)) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal("GetEnvironmentStringsW failed: %s", error_decode(e));
		}
		while (*a) {
			ajla_error_t err;
			size_t utf8_len, i;
			char *utf8_str;
			if (*a == '=')
				goto skip;
			utf8_str = wchar_to_utf8(NULL, a, &err);
			if (unlikely(!utf8_str)) {
				if (err.error_class == EC_ASYNC) {
					ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
					fatal("can't allocate environment memory: %s", error_decode(e));
				}
				goto skip;
			}
			utf8_len = strlen(utf8_str);
			for (i = 0; i < utf8_len; i++) {
				if (utf8_str[i] == '=')
					break;
				if (utf8_str[i] >= 'a' && utf8_str[i] <= 'z')
					utf8_str[i] -= 0x20;
			}
			array_add_multiple(char, str, l, utf8_str, utf8_len + 1);
			mem_free(utf8_str);
skip:
			while (*a)
				a++;
			a++;
		}
		if (unlikely(!fn_FreeEnvironmentStringsW(e))) {
			ajla_error_t e = error_from_win32(EC_SYSCALL, GetLastError());
			fatal("FreeEnvironmentStringsW failed: %s", error_decode(e));
		}
	}
}


void iomux_init(void)
{
}

void iomux_done(void)
{
}

void os_init(void)
{
#ifdef DEBUG
	unsigned i;
	for (i = 0; i < n_array_elements(win32_error_to_system_error) - 1; i++)
		if (unlikely(win32_error_to_system_error[i].errn >= win32_error_to_system_error[i + 1].errn))
			internal(file_line, "os_init: win32_error_to_system_error is not monotonic at %u", i);
#endif
	os_threads_initialized = false;

	tick_high = 0;
	tick_last = 0;
	store_relaxed(&window_offset_x, 0);
	store_relaxed(&window_offset_y, 0);

	os_cwd = os_dir_cwd(NULL);
	os_init_path_to_exe();

	fn_GetEnvironmentStrings = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetEnvironmentStrings");
	fn_GetEnvironmentStringsA = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetEnvironmentStringsA");
	fn_GetEnvironmentStringsW = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetEnvironmentStringsW");
	fn_FreeEnvironmentStringsA = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeEnvironmentStringsA");
	fn_FreeEnvironmentStringsW = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeEnvironmentStringsW");
	if (!fn_GetEnvironmentStrings)
		fatal("Could not get GetEnvironmentStrings");
	fn_RtlGetVersion = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
	fn_RtlFreeUserThreadStack = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFreeUserThreadStack");
	fn_GetDiskFreeSpaceExA = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetDiskFreeSpaceExA");
	fn_GetDiskFreeSpaceExW = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetDiskFreeSpaceExW");
	fn_CancelIo = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CancelIo");
	fn_CancelIoEx = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CancelIoEx");
	fn_MoveFileExA = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "MoveFileExA");
	fn_MoveFileExW = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "MoveFileExW");
	fn_FlushInstructionCache = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FlushInstructionCache");
	handle_iphlpa = LoadLibraryA("iphlpapi.dll");
	if (handle_iphlpa)
		fn_GetNetworkParams = (void *)GetProcAddress(handle_iphlpa, "GetNetworkParams");

	fn_GetTickCount64 = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount64");

#ifdef USER_QPC
	fn_QueryPerformanceFrequency = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "QueryPerformanceFrequency");
	if (likely(fn_QueryPerformanceFrequency != NULL)) {
		LARGE_INTEGER li;
		int64_t perf_frequency;
		if (likely(fn_QueryPerformanceFrequency(&li))) {
			perf_frequency = li.LowPart + ((uint64_t)li.HighPart << 32);
			perf_multiplier = (long double)1000000 / (long double)perf_frequency;
			fn_QueryPerformanceCounter = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "QueryPerformanceCounter");
		}
	}
#endif

	fn_getaddrinfo = (void *)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "getaddrinfo");
	fn_freeaddrinfo = (void *)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "freeaddrinfo");
	if (unlikely(!fn_getaddrinfo) || unlikely(!fn_freeaddrinfo)) {
		fn_getaddrinfo = NULL;
		fn_freeaddrinfo = NULL;
	}
	fn_getnameinfo = (void *)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "getnameinfo");
}

void os_init_multithreaded(void)
{
	unsigned u;
	WSADATA wsadata;
	int wsaret;

	os_init_calendar_lock();

	monitor_init();

	if (!fn_CancelIoEx) {
		pipe_count = 0;
		mutex_init(&pipe_count_mutex);
	}
	mutex_init(&tick_mutex);
	list_init(&deferred_write_list);
	list_init(&deferred_closed_list);
	mutex_init(&deferred_mutex);
	os_threads_initialized = true;
	for (u = 0; u < 3; u++)
		win32_std_handles[u] = win32_hfile_to_handle(get_std_handle(u), (!u ? O_RDONLY : O_WRONLY) | O_NONBLOCK, false, "", NULL);

#if 0
	{
		int i = 0;
		while (1) {
			debug("X1: %d", i++);
			win32_create_read_thread(win32_std_handles[0], NULL);
			/*win32_terminate_io_thread(&win32_std_handles[0]->rd);*/
			os_free_handle(win32_std_handles[0], false);
			win32_std_handles[0] = win32_hfile_to_handle(get_std_handle(0), O_RDONLY | O_NONBLOCK, false, "", NULL);
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
			os_close(p[0]);
			os_close(p[1]);
		}
	}
#endif

	wsaret = WSAStartup(MAKEWORD(1, 1), &wsadata);
	winsock_supported = !wsaret;
	if (winsock_supported) {
		if (unlikely(!win32_socketpair(win32_notify_socket))) {
			if (WSACleanup())
				warning("WSACleanup returned an error: %u", WSAGetLastError());
			winsock_supported = false;
		}
	}
	if (winsock_supported) {
		mutex_init(&socket_list_mutex);
		list_init(&socket_list[0]);
		list_init(&socket_list[1]);
		thread_spawn(&iomux_thread, iomux_poll_thread, NULL, PRIORITY_IO, NULL);
	}
}

void os_done_multithreaded(void)
{
	unsigned u;

	if (winsock_supported) {
		win32_shutdown_notify_pipe();
		thread_join(&iomux_thread);
		win32_close_socket(win32_notify_socket[0]);
		win32_close_socket(win32_notify_socket[1]);
		ajla_assert_lo(list_is_empty(&socket_list[0]), (file_line, "os_done_multithreaded: read socket list is not empty"));
		ajla_assert_lo(list_is_empty(&socket_list[1]), (file_line, "os_done_multithreaded: write socket list is not empty"));
		mutex_done(&socket_list_mutex);
		if (WSACleanup())
			warning("WSACleanup returned an error: %u", WSAGetLastError());
		winsock_supported = false;
	}

	for (u = 0; u < 3; u++)
		os_free_handle(win32_std_handles[u], false);

	mutex_lock(&deferred_mutex);
	while (!list_is_empty(&deferred_write_list)) {
		mutex_unlock(&deferred_mutex);
		Sleep(1);
		mutex_lock(&deferred_mutex);
	}
	mutex_unlock(&deferred_mutex);
	win32_clean_up_handles();

	mutex_done(&tick_mutex);
	if (!fn_CancelIoEx)
		mutex_done(&pipe_count_mutex);

	monitor_done();

	os_done_calendar_lock();

	os_threads_initialized = false;
}

void os_done(void)
{
	mem_free(os_path_to_exe);
	os_dir_close(os_cwd);
}

#endif
