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

#ifndef AJLA_OS_H
#define AJLA_OS_H

#include "list.h"
#include "tree.h"
#include "thread.h"

#if defined(OS_OS2)

#include "thread.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>

#define NO_DIR_HANDLES

typedef long long os_off_t;
typedef int64_t os_time_t;
typedef struct {
	uint32_t st_mode;
	uint32_t st_dev;
	uint8_t st_ino;
	uint8_t st_nlink;
	os_off_t st_size;
	os_off_t st_blocks;
	uint32_t st_blksize;
	os_time_t st_atime;
	os_time_t st_ctime;
	os_time_t st_mtime;
	uint8_t st_uid;
	uint8_t st_gid;
	uint8_t st_rdev;
} os_stat_t;

typedef struct {
	unsigned f_bsize;
	unsigned f_frsize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	uint64_t f_favail;
	unsigned long f_fsid;
	unsigned f_flag;
	unsigned f_namemax;
} os_statvfs_t;

typedef struct {
	int tc_flags;
} os_termios_t;

typedef struct {
	char sysname[65];
	char release[65];
	char version[65];
	char machine[65];
} os_utsname_t;

typedef struct os2_handle *handle_t;
#define handle_is_valid(h)	((h) != NULL)
#define handle_none		NULL
uintptr_t os_handle_to_number(handle_t h);
handle_t os_number_to_handle(uintptr_t n, bool sckt, ajla_error_t *err);

typedef char *dir_handle_t;
#define dir_handle_is_valid(h)	((h) != NULL)
#define dir_none		NULL

typedef unsigned char sig_state_t;

#define OS_HAS_DLOPEN
struct dl_handle_t;
struct dl_handle_t *os_dlopen(const char *filename, ajla_error_t *err, char **err_msg);
void os_dlclose(struct dl_handle_t *dlh);
bool os_dlsym(struct dl_handle_t *dlh, const char *symbol, void **result);

#define os_getaddrinfo_is_thread_safe()		false

#elif defined(OS_WIN32)

#include <sys/stat.h>
/*#include <sys/time.h>*/
#include <fcntl.h>

#define NO_DIR_HANDLES

typedef int64_t os_off_t;
typedef int64_t os_time_t;

typedef struct {
	uint32_t st_mode;
	uint32_t st_dev;
	uint64_t st_ino;
	uint32_t st_nlink;
	os_off_t st_size;
	os_off_t st_blocks;
	uint32_t st_blksize;
	os_time_t st_atime;
	os_time_t st_ctime;
	os_time_t st_mtime;
	uint8_t st_uid;
	uint8_t st_gid;
	uint8_t st_rdev;
} os_stat_t;

typedef struct {
	unsigned f_bsize;
	unsigned f_frsize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	uint64_t f_favail;
	unsigned long f_fsid;
	unsigned f_flag;
	unsigned f_namemax;
} os_statvfs_t;

typedef struct {
	int tc_flags;
} os_termios_t;

typedef struct {
	char sysname[65];
	char release[65];
	char version[129];
	char machine[65];
} os_utsname_t;

typedef struct win32_handle *handle_t;
#define handle_is_valid(h)	((h) != NULL)
#define handle_none		NULL
uintptr_t os_handle_to_number(handle_t h);
handle_t os_number_to_handle(uintptr_t n, bool sckt, ajla_error_t *err);

typedef char *dir_handle_t;
#define dir_handle_is_valid(h)	((h) != NULL)
#define dir_none		NULL

typedef unsigned char sig_state_t;

#ifndef O_NONBLOCK
#define O_NONBLOCK		0x40000000
#endif

#ifdef _MSC_VER
#undef S_IFIFO
#undef S_IFCHR
#undef S_IFDIR
#undef S_IFBLK
#undef S_IFREG
#undef S_IFLNK
#undef S_IFSOCK
#undef S_IFMT
#define S_IFIFO			0010000
#define S_IFCHR			0020000
#define S_IFDIR			0040000
#define S_IFBLK			0060000
#define S_IFREG			0100000
#define S_IFLNK			0120000
#define S_IFSOCK		0140000
#define S_IFMT			0170000
#define S_ISFIFO(x)		(((x) & S_IFMT) == S_IFIFO)
#define S_ISCHR(x)		(((x) & S_IFMT) == S_IFCHR)
#define S_ISDIR(x)		(((x) & S_IFMT) == S_IFDIR)
#define S_ISBLK(x)		(((x) & S_IFMT) == S_IFBLK)
#define S_ISREG(x)		(((x) & S_IFMT) == S_IFREG)
#define S_ISLNK(x)		(((x) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(x)		(((x) & S_IFMT) == S_IFSOCK)
#endif

#define OS_HAS_MMAP
int os_getpagesize(void);
void *os_mmap(void *ptr, size_t size, int prot, int flags, handle_t h, os_off_t off, ajla_error_t *err);
void os_munmap(void *ptr, size_t size, bool file);
bool os_mprotect(void *ptr, size_t size, int prot, ajla_error_t *err);
#define MAP_FAILED		((void *)-1)
#define PROT_NONE		0
#define PROT_READ		1
#define PROT_WRITE		2
#define PROT_EXEC		4
#define MAP_ANONYMOUS		1
#define MAP_PRIVATE		2
#define MAP_FIXED		4
#define MAP_EXCL		8
#define MAP_NORESERVE		16
#define MAP_ALIGNED(x)		(32 * (x))
#define MAP_ALIGNED_BITS(m)	((m) >> 5)

#define OS_HAS_DLOPEN
struct dl_handle_t;
struct dl_handle_t *os_dlopen(const char *filename, ajla_error_t *err, char **err_msg);
void os_dlclose(struct dl_handle_t *dlh);
bool os_dlsym(struct dl_handle_t *dlh, const char *symbol, void **result);

bool os_getaddrinfo_is_thread_safe(void);

void os_get_environment(char **str, size_t *l);

#else

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_UCONTEXT_H
#include <ucontext.h>
#endif
#if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
#include <sys/utsname.h>
#endif
#include <sys/stat.h>
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#elif defined(HAVE_SYS_VFS_H)
#include <sys/vfs.h>
#endif
#include <termios.h>

#if !defined(HAVE_FCHDIR) || defined(OS_DOS) || defined(UNUSUAL_NO_DIR_HANDLES)
#define NO_DIR_HANDLES
#endif

#if defined(__hpux) && !defined(__LP64__)
#if defined(HAVE_FSTAT64) && defined(HAVE_FSTATVFS64) && defined(HAVE_FTRUNCATE64) && defined(HAVE_LSEEK64) && defined(HAVE_LSTAT64) && defined(HAVE_MMAP64) && defined(HAVE_OPEN64) && defined(HAVE_PREAD64) && defined(HAVE_PWRITE64) && defined(HAVE_STAT64) && defined(HAVE_STATVFS64) && defined(HAVE_TRUNCATE64)
#define OS_USE_LARGEFILE64_SOURCE
#endif
#endif

#ifdef OS_USE_LARGEFILE64_SOURCE
typedef off64_t os_off_t;
typedef struct stat64 os_stat_t;
typedef struct statvfs64 os_statvfs_t;
#else
typedef off_t os_off_t;
typedef struct stat os_stat_t;
#if defined(HAVE_STATVFS) || defined(HAVE_FSTATVFS)
typedef struct statvfs os_statvfs_t;
#endif
#endif

#if !defined(OS_USE_LARGEFILE64_SOURCE) && !defined(HAVE_STATVFS) && !defined(HAVE_FSTATVFS)
typedef struct {
	unsigned f_bsize;
	unsigned f_frsize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	uint64_t f_favail;
	unsigned long f_fsid;
	unsigned f_flag;
	unsigned f_namemax;
} os_statvfs_t;
#endif

typedef time_t os_time_t;
typedef struct termios os_termios_t;

#if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
typedef struct utsname os_utsname_t;
#else
typedef struct {
	char sysname[65];
	char release[65];
	char version[65];
	char machine[65];
} os_utsname_t;
#endif

typedef int handle_t;
#define handle_is_valid(h)	((h) >= 0)
#define handle_none		-1
#define os_handle_to_number(h)	((uintptr_t)(h))
handle_t os_number_to_handle(uintptr_t n, bool sckt, ajla_error_t *err);

#ifndef NO_DIR_HANDLES
typedef int dir_handle_t;
#define dir_handle_is_valid(h)	((h) >= 0)
#define dir_none		(-1)
#else
typedef char *dir_handle_t;
#define dir_handle_is_valid(h)	((h) != NULL)
#define dir_none		NULL
#endif

#if defined(HAVE_SYS_MMAN_H) && defined(HAVE_MMAP)
#include <sys/mman.h>
#define OS_HAS_MMAP
int os_getpagesize(void);
void *os_mmap(void *ptr, size_t size, int prot, int flags, handle_t h, os_off_t off, ajla_error_t *err);
void os_munmap(void *ptr, size_t size, bool file);
bool os_mprotect(void *ptr, size_t size, int prot, ajla_error_t *err);
#ifndef MAP_FAILED
#define MAP_FAILED	((void *)-1)
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS	MAP_ANON
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE	0
#endif
#if defined(__linux__) && defined(HAVE_MREMAP)
#define OS_HAS_MREMAP
void *os_mremap(void *old_ptr, size_t old_size, size_t new_size, int flags, void *new_ptr, ajla_error_t *err);
#endif
#endif

#if defined(HAVE_SIGPROCMASK) && defined(HAVE_SIGSET_T) && defined(HAVE_SIGFILLSET)
typedef sigset_t sig_state_t;
#define USE_SIGPROCMASK
#else
typedef int sig_state_t;
#endif
#ifdef HAVE_SIGACTION
#define OS_HAS_SIGNALS
#endif

#if defined(OS_HAS_SIGNALS) && defined(SA_SIGINFO) && defined(HAVE_UCONTEXT_H)
#define OS_SUPPORTS_TRAPS			(!dll)
#else
#define OS_SUPPORTS_TRAPS			0
#endif

#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
#define OS_HAS_DLOPEN
struct dl_handle_t;
struct dl_handle_t *os_dlopen(const char *filename, ajla_error_t *err, char **err_msg);
void os_dlclose(struct dl_handle_t *dlh);
bool os_dlsym(struct dl_handle_t *dlh, const char *symbol, void **result);
#endif

#if defined(HAVE_GETADDRINFO) && (defined(HAVE_HAVE_GETNAMEINFO) || !defined(HAVE_GETHOSTBYADDR))
#define os_getaddrinfo_is_thread_safe()		true
#else
#define os_getaddrinfo_is_thread_safe()		false
#endif

#endif


uint32_t os_get_last_error(void);
uint32_t os_get_last_socket_error(void);


void os_code_invalidate_cache(uint8_t *code, size_t code_size, bool set_exec);
void *os_code_map(uint8_t *code, size_t code_size, ajla_error_t *err);
void os_code_unmap(void *mapped_code, size_t code_size);


static inline char os_path_separator(void)
{
#if defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32)
	return '\\';
#else
	return '/';
#endif
}

static inline bool os_is_path_separator(char c)
{
#if defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32) || defined(OS_CYGWIN)
	if (c == '\\' || c == ':')
		return true;
#endif
	return c == '/';
}

static inline bool os_is_env_separator(char c)
{
#if defined(OS_DOS) || defined(OS_OS2) || defined(OS_WIN32)
	return c == ';';
#endif
	return c == ':';
}

bool os_path_is_absolute(const char *path);


extern dir_handle_t os_cwd;
bool os_set_cwd(dir_handle_t h, ajla_error_t *err);
void os_set_original_cwd(void);


void os_block_signals(sig_state_t *set);
void os_unblock_signals(const sig_state_t *set);
void os_stop(void);

void os_set_cloexec(handle_t h);
handle_t os_open(dir_handle_t dir, const char *path, int flags, int mode, ajla_error_t *err);
bool os_pipe(handle_t result[2], int nonblock_flags, ajla_error_t *err);
void os_close(handle_t h);
unsigned os_n_std_handles(void);
handle_t os_get_std_handle(unsigned p);
#define OS_RW_ERROR		-1
#define OS_RW_WOULDBLOCK	-2
ssize_t os_read(handle_t h, char *buffer, int size, ajla_error_t *err);
ssize_t os_write(handle_t h, const char *buffer, int size, ajla_error_t *err);
ssize_t os_pread(handle_t h, char *buffer, int size, os_off_t off, ajla_error_t *err);
ssize_t os_pwrite(handle_t h, const char *buffer, int size, os_off_t off, ajla_error_t *err);
bool os_lseek(handle_t, unsigned mode, os_off_t off, os_off_t *result, ajla_error_t *err);
bool os_ftruncate(handle_t h, os_off_t size, ajla_error_t *err);
bool os_fallocate(handle_t h, os_off_t position, os_off_t size, ajla_error_t *err);
bool os_clone_range(handle_t src_h, os_off_t src_pos, handle_t dst_h, os_off_t dst_pos, os_off_t len, ajla_error_t *err);
bool os_fsync(handle_t h, unsigned mode, ajla_error_t *err);
int os_charset(void);
int os_charset_console(void);
struct console_read_packet {
	int32_t type;
	union {
		struct {
			int32_t vkey;
			int32_t key;
			int32_t ctrl;
			int32_t cp;
		} k;
		struct {
			int32_t x, y;
			int32_t prev_buttons, buttons;
			int32_t wx, wy;
			int32_t soft_cursor;
		} m;
	} u;
};
#define CONSOLE_PACKET_ENTRIES	(sizeof(struct console_read_packet) / sizeof(int32_t))
ssize_t os_read_console_packet(handle_t h, struct console_read_packet *result, ajla_error_t *err);
struct console_write_packet {
	int32_t type;
	union {
		struct {
			int32_t x, y;
			int32_t n_chars;
			int32_t data[FLEXIBLE_ARRAY_GCC];
		} c;
		struct {
			int32_t x, y;
			int32_t end;
		} p;
		struct {
			int32_t v;
			int32_t end;
		} v;
	} u;
};
bool os_write_console_packet(handle_t h, struct console_write_packet *packet, ajla_error_t *err);

dir_handle_t os_dir_root(ajla_error_t *err);
dir_handle_t os_dir_cwd(ajla_error_t *err);
dir_handle_t os_dir_open(dir_handle_t dir, const char *path, int flags, ajla_error_t *err);
void os_dir_close(dir_handle_t h);
char *os_dir_path(dir_handle_t h, ajla_error_t *err);

bool os_dir_read(dir_handle_t h, char ***files, size_t *n_files, ajla_error_t *err);
void os_dir_free(char **files, size_t n_files);

unsigned os_dev_t_major(dev_t dev);
unsigned os_dev_t_minor(dev_t dev);
bool os_fstat(handle_t h, os_stat_t *st, ajla_error_t *err);
bool os_stat(dir_handle_t dir, const char *path, bool lnk, os_stat_t *st, ajla_error_t *err);
char *os_readlink(dir_handle_t dir, const char *path, ajla_error_t *err);
bool os_fstatvfs(handle_t h, os_statvfs_t *st, ajla_error_t *err);
bool os_dstatvfs(dir_handle_t dir, os_statvfs_t *st, ajla_error_t *err);
bool os_dir_action(dir_handle_t dir, const char *path, int action, int mode, ajla_time_t major, ajla_time_t minor, const char *syml, ajla_error_t *err);
bool os_dir2_action(dir_handle_t dir, const char *path, int action, dir_handle_t src_dir, const char *src_path, ajla_error_t *err);
bool os_tcgetattr(handle_t h, os_termios_t *t, ajla_error_t *err);
bool os_tcsetattr(handle_t h, const os_termios_t *t, ajla_error_t *err);
void os_tcflags(os_termios_t *t, int flags);
int os_tty_size(handle_t h, int x, int y, int *nx, int *ny, mutex_t **mutex_to_lock, struct list *list_entry, ajla_error_t *err);
const char *os_get_path_to_exe(void);

ajla_time_t os_time_t_to_ajla_time(os_time_t sec);
#ifdef HAVE_STRUCT_TIMESPEC
ajla_time_t os_timespec_to_ajla_time(const struct timespec *ts);
#endif
ajla_time_t os_time_real(void);
ajla_time_t os_time_monotonic(void);
bool os_time_to_calendar(ajla_time_t t, bool local, int *year, int *month, int *day, int *hour, int *min, int *sec, int *usec, int *yday, int *wday, int *is_dst, ajla_error_t *err);
bool os_calendar_to_time(bool local, int year, int month, int day, int hour, int min, int sec, int usec, int is_dst, ajla_time_t *t, ajla_error_t *err);

const char *os_get_flavor(void);
void os_get_uname(os_utsname_t *un);
bool os_kernel_version(const char *sys, const char *vers);
char *os_get_host_name(ajla_error_t *err);

struct proc_handle;

struct proc_handle *os_proc_spawn(dir_handle_t wd, const char *path, size_t n_handles, handle_t *src, int *target, char * const args[], char *envc, ajla_error_t *err);
void os_proc_free_handle(struct proc_handle *ph);
bool os_proc_register_wait(struct proc_handle *ph, mutex_t **mutex_to_lock, struct list *list_entry, int *status);
void os_proc_check_all(void);

#ifdef OS_HAS_SIGNALS
bool os_signal_prepare(unsigned sig, sig_atomic_t *seq, ajla_error_t *err);
bool os_signal_wait(int sig, sig_atomic_t seq, mutex_t **mutex_to_lock, struct list *list_entry);
void os_signal_check_all(void);
#ifdef SA_SIGINFO
void os_signal_trap(unsigned sig, void (*handler)(int, siginfo_t *, void *));
#endif
void os_signal_restore(unsigned sig);
#else
static inline void os_signal_check_all(void) { }
#endif

handle_t os_socket(int domain, int type, int protocol, ajla_error_t *err);
bool os_bind_connect(bool bnd, handle_t h, unsigned char *addr, size_t addr_len, ajla_error_t *err);
bool os_connect_completed(handle_t h, ajla_error_t *err);
bool os_listen(handle_t h, ajla_error_t *err);
int os_accept(handle_t h, handle_t *result, ajla_error_t *err);
bool os_getsockpeername(bool peer, handle_t h, unsigned char **addr, size_t *addr_len, ajla_error_t *err);
struct address {
	unsigned char *address;
	size_t address_length;
	struct tree_entry entry;
};
ssize_t os_recvfrom(handle_t h, char *buffer, size_t len, int flags, unsigned char **addr, size_t *addr_len, ajla_error_t *err);
ssize_t os_sendto(handle_t h, const char *buffer, size_t len, int flags, unsigned char *addr, size_t addr_len, ajla_error_t *err);
bool os_getsockopt(handle_t h, int level, int option, char **buffer, size_t *buffer_len, ajla_error_t *err);
bool os_setsockopt(handle_t h, int level, int option, const char *buffer, size_t buffer_len, ajla_error_t *err);
bool os_getaddrinfo(const char *host, int port, struct address **result, size_t *result_l, ajla_error_t *err);
char *os_getnameinfo(unsigned char *addr, size_t addr_len, ajla_error_t *err);

const char *os_decode_error(ajla_error_t error, char *(*tls_buffer)(void));

#if !defined(OS_DOS)
#define OS_HAVE_NOTIFY_PIPE
extern handle_t os_notify_pipe[2];
void os_notify(void);
bool os_drain_notify_pipe(void);
void os_shutdown_notify_pipe(void);
#else
static inline void os_notify(void) { }
static inline void os_shutdown_notify_pipe(void) { }
#endif

#if defined(OS_DOS)
bool dos_poll_devices(void);
void dos_yield(void);
void dos_wait_on_packet(mutex_t **mutex_to_lock, struct list *list_entry);
void dos_init(void);
void dos_done(void);
#endif

void os_init(void);
void os_init_multithreaded(void);
void os_done_multithreaded(void);
void os_done(void);

#endif
