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

#if !defined(OS_OS2) && !defined(OS_WIN32)

#include "str.h"
#include "tree.h"
#include "rwlock.h"
#include "args.h"
#include "obj_reg.h"
#include "addrlock.h"
#include "iomux.h"
#include "timer.h"
#include "os_util.h"

#include "os.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif
#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_NETWORK
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#ifdef OS_HAS_DLOPEN
#include <dlfcn.h>
#endif
#include <signal.h>
#include <sys/ioctl.h>
#if defined(HAVE_SYS_PARAM_H)
#include <sys/param.h>
#endif
#if defined(HAVE_SYS_UCRED_H)
#include <sys/ucred.h>
#endif
#if defined(HAVE_SYS_MOUNT_H)
#include <sys/mount.h>
#endif
#if defined(HAVE_LINUX_FS_H)
#include <linux/fs.h>
#endif

#define SOCKADDR_MAX_LEN	65535
#define SOCKADDR_ALIGN		16

#ifndef wake_up_wait_list
void u_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory);
void c_name(wake_up_wait_list)(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory);
#endif

#if !defined(THREAD_NONE) && defined(USE_SIGPROCMASK) && defined(HAVE_PTHREAD) && defined(HAVE_PTHREAD_SIGMASK)
#include <pthread.h>
#define USE_PTHREAD_SIGMASK
#endif

#ifdef OS_USE_LARGEFILE64_SOURCE
#define fstat		fstat64
#define fstatvfs	fstatvfs64
#define ftruncate	ftruncate64
#define lseek		lseek64
#define lstat		lstat64
#define mmap		mmap64
#define open		open64
#define pread		pread64
#define pwrite		pwrite64
#define stat		stat64
#define statvfs		statvfs64
#define truncate	truncate64
#endif

static rwmutex_t fork_lock;
static bool os_threads_initialized = false;

#if !defined(NO_DIR_HANDLES) && !defined(OS_USE_LARGEFILE64_SOURCE) && defined(O_CLOEXEC) && defined(HAVE_OPENAT) && defined(HAVE_FSTATAT) && defined(HAVE_READLINKAT) && defined(HAVE_UNLINKAT) && defined(HAVE_MKDIRAT) && defined(HAVE_MKNODAT) && defined(HAVE_SYMLINKAT) && defined(HAVE_LINKAT) && defined(HAVE_RENAMEAT) && defined(HAVE_FCHMODAT) && defined(HAVE_FCHOWNAT) && defined(HAVE_UTIMENSAT)
static bool have_O_CLOEXEC_openat = false;
#define HAVE_AT_FUNCTIONS
#endif

dir_handle_t os_cwd;


#include "os_com.inc"


static void os_lock_fork(bool for_write)
{
	if (os_threads_initialized) {
		if (!for_write)
			rwmutex_lock_read(&fork_lock);
		else
			rwmutex_lock_write(&fork_lock);
	}
}

static void os_unlock_fork(bool for_write)
{
	if (os_threads_initialized) {
		if (!for_write)
			rwmutex_unlock_read(&fork_lock);
		else
			rwmutex_unlock_write(&fork_lock);
	}
}

uint32_t os_get_last_error(void)
{
	return 0;
}

uint32_t os_get_last_socket_error(void)
{
	return 0;
}

#ifdef OS_HAS_MMAP

int os_getpagesize(void)
{
#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	{
		long ps;
		EINTR_LOOP(ps, sysconf(_SC_PAGESIZE));
		if (unlikely(ps == -1)) {
			int er = errno;
			warning("sysconf(_SC_PAGESIZE) returned error: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		} else {
			return ps;
		}
	}
#elif defined(HAVE_GETPAGESIZE)
	{
		int ps;
		EINTR_LOOP(ps, getpagesize());
		if (unlikely(ps == -1)) {
			int er = errno;
			warning("getpagesize() returned error: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		} else {
			return ps;
		}
	}
#endif
	return 512;
}

void *os_mmap(void *ptr, size_t size, int prot, int flags, int h, os_off_t off, ajla_error_t *err)
{
	void *p;
#ifdef PROT_MPROTECT
	prot |= PROT_MPROTECT(PROT_EXEC);
#endif
#ifndef HAVE_MPROTECT
	prot |= PROT_EXEC;
#endif
	EINTR_LOOP_VAL(p, MAP_FAILED, mmap(ptr, size, prot, flags, h, off));
	if (unlikely(p == MAP_FAILED)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't map memory: %s", error_decode(e));
		return MAP_FAILED;
	}
	return p;
}

void os_munmap(void *ptr, size_t size, bool attr_unused file)
{
	int r;
	EINTR_LOOP(r, munmap(ptr, size));
	if (unlikely(r == -1)) {
		int er = errno;
		internal(file_line, "os_munmap: munmap(%p, %"PRIxMAX") returned error: %d, %s", ptr, (uintmax_t)size, er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
}

bool os_mprotect(void attr_unused *ptr, size_t attr_unused size, int attr_unused prot, ajla_error_t *err)
{
#ifdef HAVE_MPROTECT
	int r;
	EINTR_LOOP(r, mprotect(ptr, size, prot));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't protect memory: %s", error_decode(e));
		return false;
	}
	return true;
#else
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "the system doesn't support mprotect");
	return false;
#endif
}

#ifdef OS_HAS_MREMAP
void *os_mremap(void *old_ptr, size_t old_size, size_t new_size, int flags, void attr_unused *new_ptr, ajla_error_t *err)
{
	void *p;
#ifdef MREMAP_FIXED
	EINTR_LOOP_VAL(p, MAP_FAILED, mremap(old_ptr, old_size, new_size, flags, new_ptr));
#else
	EINTR_LOOP_VAL(p, MAP_FAILED, mremap(old_ptr, old_size, new_size, flags));
#endif
	if (unlikely(p == MAP_FAILED)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't remap memory: %s", error_decode(e));
		return MAP_FAILED;
	}
	return p;
}
#endif

#endif


void os_code_invalidate_cache(uint8_t attr_unused *code, size_t attr_unused code_size, bool attr_unused set_exec)
{
#if defined(ARCH_PARISC) && defined(HAVE_GCC_ASSEMBLER)
	size_t i;
	size_t cl_size = cpu_test_feature(CPU_FEATURE_pa20) ? 64 : 16;
	size_t align = ptr_to_num(code) & (cl_size - 1);
	code -= align;
	code_size += align;
	__asm__ volatile ("sync" : : : "memory");
	for (i = 0; i < code_size; i += cl_size) {
		__asm__ volatile ("fdc %%r0(%0)" : : "r"(code + i) : "memory");
	}
	__asm__ volatile ("sync");
#if defined(ARCH_PARISC32)
	if (PA_SPACES) {
		unsigned long reg;
		__asm__ volatile("ldsid (%1), %0\n mtsp %0, %%sr0" : "=r"(reg) : "r"(code) : "memory");
	}
#endif
	for (i = 0; i < code_size; i += cl_size) {
#if defined(ARCH_PARISC32)
		if (PA_SPACES) {
			__asm__ volatile ("fic %%r0(%%sr0, %0)" : : "r"(code + i) : "memory");
		} else {
			__asm__ volatile ("fic %%r0(%%sr4, %0)" : : "r"(code + i) : "memory");
		}
#else
		__asm__ volatile ("fic %%r0(%0)" : : "r"(code + i) : "memory");
#endif
	}
	__asm__ volatile ("sync" : : : "memory");
#elif defined(ARCH_ALPHA)
	/* imb doesn't work on SMP systems */
#elif defined(ARCH_SPARC64) && defined(HAVE_GCC_ASSEMBLER)
	size_t i;
	__asm__ volatile ("membar #StoreStore" : : : "memory");
	for (i = 0; i < code_size; i += 8) {
		__asm__ volatile ("flush %0" : : "r"(code + i) : "memory");
	}
#elif defined(HAVE___BUILTIN___CLEAR_CACHE)
	__builtin___clear_cache(cast_ptr(void *, code), cast_ptr(char *, code) + code_size);
#endif
#if defined(OS_HAS_MMAP) && defined(HAVE_MPROTECT)
	if (set_exec) {
		int prot_flags = PROT_READ | PROT_EXEC
#ifdef CODEGEN_USE_HEAP
			| PROT_WRITE
#endif
			;
		int page_size = os_getpagesize();
		int front_pad = ptr_to_num(code) & (page_size - 1);
		uint8_t *mem_region = code - front_pad;
		size_t mem_length = code_size + front_pad;
		mem_length = round_up(mem_length, page_size);
		os_mprotect(mem_region, mem_length, prot_flags, NULL);
	}
#endif
}

void *os_code_map(uint8_t *code, size_t code_size, ajla_error_t attr_unused *err)
{
#ifdef CODEGEN_USE_HEAP
	os_code_invalidate_cache(code, code_size, !amalloc_enabled);
	return code;
#else
	size_t rounded_size = round_up(code_size, os_getpagesize());
	void *ptr = os_mmap(NULL, rounded_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, handle_none, 0, err);
	if (unlikely(ptr == MAP_FAILED)) {
		mem_free(code);
		return NULL;
	}
	memcpy(ptr, code, code_size);
	os_code_invalidate_cache(ptr, code_size, true);
	mem_free(code);
	return ptr;
#endif
}

void os_code_unmap(void *mapped_code, size_t attr_unused code_size)
{
#ifdef CODEGEN_USE_HEAP
	mem_free(mapped_code);
#else
	size_t rounded_size = round_up(code_size, os_getpagesize());
	os_munmap(mapped_code, rounded_size, false);
#endif
}


void os_block_signals(sig_state_t attr_unused *set)
{
#ifdef USE_SIGPROCMASK
	int er;
	sig_state_t block;
	sigfillset(&block);
	sigdelset(&block, SIGFPE);
	sigdelset(&block, SIGTRAP);
#ifdef USE_PTHREAD_SIGMASK
	er = pthread_sigmask(SIG_BLOCK, &block, set);
	if (unlikely(er))
		fatal("pthread_sigmask failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
#else
	if (unlikely(sigprocmask(SIG_BLOCK, &block, set))) {
		er = errno;
		fatal("sigprocmask failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
#endif
#elif defined(HAVE_SIGBLOCK) && defined(HAVE_SIGSETMASK)
	sig_state_t s = sigblock(~(sigmask(SIGFPE) | sigmask(SIGTRAP)));
	if (set)
		*set = s;
#endif
}

void os_unblock_signals(const sig_state_t attr_unused *set)
{
#ifdef USE_SIGPROCMASK
	int er;
#ifdef USE_PTHREAD_SIGMASK
	er = pthread_sigmask(SIG_SETMASK, set, NULL);
	if (unlikely(er))
		fatal("pthread_sigmask failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
#else
	if (unlikely(sigprocmask(SIG_SETMASK, set, NULL))) {
		er = errno;
		fatal("sigprocmask failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
#endif
#elif defined(HAVE_SIGBLOCK) && defined(HAVE_SIGSETMASK)
	sigsetmask(*set);
#endif
}

#if !defined(OS_DOS)
static void os_unblock_all_signals(void)
{
	sig_state_t unblock;
#ifdef USE_SIGPROCMASK
	sigemptyset(&unblock);
#elif defined(HAVE_SIGBLOCK) && defined(HAVE_SIGSETMASK)
	unblock = 0;
#endif
	os_unblock_signals(&unblock);
}
#endif


void attr_cold os_stop(void)
{
#ifdef SIGSTOP
	kill(getpid(), SIGSTOP);
#else
	warning("stop not supported");
#endif
}

static void u_sleep(unsigned us)
{
	struct timeval tv;
	tv.tv_sec = us / 1000000;
	tv.tv_usec = us % 1000000;
	select(0, NULL, NULL, NULL, &tv);
}

void os_background(void)
{
#ifndef OS_DOS
	int r;
	pid_t pa, p;
#ifdef __linux__
	sig_state_t set;
#endif
	pa = getpid();
	os_lock_fork(true);
#ifdef __linux__
	os_block_signals(&set);
#endif
	EINTR_LOOP(p, fork());
#ifdef __linux__
	os_unblock_signals(&set);
#endif
	if (!p) {
		while (1) {
			/*
			 * Note that this is racy. If we send SIGCONT too
			 * quickly, the ajla process will not be put to
			 * background.
			 */
			u_sleep(100000);
			kill(pa, SIGCONT);
		}
	}
	os_unlock_fork(true);
	if (p == -1)
		return;
	kill(pa, SIGSTOP);
	/*
	 * Another race - we must not send SIGKILL too quickly
	 */
	u_sleep(100000);
	kill(p, SIGKILL);
	EINTR_LOOP(r, waitpid(p, NULL, 0));
#endif
}

bool os_foreground(void)
{
	int sigttin, sigttou;
	signal_seq_t seq;
	os_termios_t tc;
	int r;

	sigttin = os_signal_handle("SIGTTIN", &seq, NULL);
	sigttou = os_signal_handle("SIGTTOU", &seq, NULL);
	r = tcgetattr(0, &tc);
	if (!r)
		r = tcsetattr(0, TCSANOW, &tc);
	os_signal_unhandle(sigttin);
	os_signal_unhandle(sigttou);
	return !r;
}


void os_set_cloexec(handle_t h)
{
	int r;
	EINTR_LOOP(r, fcntl(h, F_SETFD, FD_CLOEXEC));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("fcntl(F_SETFD, FD_CLOEXEC) failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
}

static char *os_call_getcwd(ajla_error_t *err)
{
	char *h, *r;
	ajla_error_t e;
	size_t buf_size = 32;

again:
	h = mem_alloc_mayfail(char *, buf_size, err);
	if (unlikely(!h))
		return NULL;
	EINTR_LOOP_VAL(r, NULL, getcwd(h, buf_size));
	if (unlikely(!r)) {
		if (errno == ERANGE) {
			mem_free(h);
			buf_size *= 2;
			if (unlikely(!buf_size)) {
				fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "overflow when allocating directory buffer");
				return NULL;
			}
			goto again;
		}
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't get working directory: %s", error_decode(e));
		mem_free(h);
		return NULL;
	}
#ifdef __GLIBC__
	if (unlikely(h[0] != '/')) {
		e = error_from_errno(EC_SYSCALL, ENOENT);
		fatal_mayfail(e, err, "can't get working directory: %s", error_decode(e));
		mem_free(h);
		return NULL;
	}
#endif

	return h;
}

static dir_handle_t os_get_cwd(ajla_error_t *err)
{
#ifndef NO_DIR_HANDLES
	dir_handle_t h;
#ifdef HAVE_AT_FUNCTIONS
	if (likely(have_O_CLOEXEC_openat)) {
		EINTR_LOOP(h, open(".", O_RDONLY | O_CLOEXEC, 0));
		if (unlikely(h == -1)) {
			ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
			fatal_mayfail(e, err, "can't open the current directory: %s", error_decode(e));
		} else {
			obj_registry_insert(OBJ_TYPE_HANDLE, h, file_line);
		}
		return h;
	}
#endif
	EINTR_LOOP(h, open(".", O_RDONLY, 0));
	if (unlikely(h == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "cam't open the current directory: %s", error_decode(e));
	} else {
		obj_registry_insert(OBJ_TYPE_HANDLE, h, file_line);
		os_set_cloexec(h);
	}

	return h;
#else
	return os_call_getcwd(err);
#endif
}

bool os_set_cwd(dir_handle_t h, ajla_error_t *err)
{
#ifndef NO_DIR_HANDLES
	int r;
	EINTR_LOOP(r, fchdir(h));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't set directory: %s", error_decode(e));
		return false;
	}
#else
	int r;
	EINTR_LOOP(r, chdir(h));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't set directory '%s': %s", h, error_decode(e));
		return false;
	}
#endif
	return true;
}

void os_set_original_cwd(void)
{
	int r;
	ajla_error_t sink;
	if (likely(os_set_cwd(os_cwd, &sink)))
		return;
	EINTR_LOOP(r, chdir("/"));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("unable to select root directory: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
}

static handle_t os_open_internal(dir_handle_t dir, const char *path, int flags, int mode, bool want_dir, ajla_error_t *err)
{
	int h;
	bool abs_path = os_path_is_absolute(path);

	if (unlikely(!os_test_absolute_path(dir, abs_path, err)))
		return -1;

#ifdef O_DIRECTORY
	if (want_dir)
		flags |= O_DIRECTORY;
#endif

#ifdef HAVE_AT_FUNCTIONS
	if (likely(have_O_CLOEXEC_openat)) {
		if (!dir_handle_is_valid(dir)) {
			EINTR_LOOP(h, open(path, flags | O_CLOEXEC, mode));
		} else {
			EINTR_LOOP(h, openat(dir, path, flags | O_CLOEXEC, mode));
		}
		if (h == -1) {
			ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
#ifdef O_PATH
			if (errno == EACCES && want_dir) {
				EINTR_LOOP(h, openat(dir, path, flags | O_CLOEXEC | O_PATH, mode));
				if (h != -1)
					goto have_it;
			}
#endif
			fatal_mayfail(e, err, "can't open file '%s': %s", path, error_decode(e));
		} else {
			goto have_it;
have_it:
			obj_registry_insert(OBJ_TYPE_HANDLE, h, file_line);
		}
		goto test_dir_ret_h;
	}
#endif
	os_lock_fork(!abs_path);

	if (!abs_path) {
		if (unlikely(!os_set_cwd(dir, err))) {
			h = -1;
			goto restore_dir_ret;
		}
	}

	EINTR_LOOP(h, open(path, flags, mode));
	if (unlikely(h == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't open file '%s': %s", path, error_decode(e));
		goto restore_dir_ret;
	}
	obj_registry_insert(OBJ_TYPE_HANDLE, h, file_line);

	os_set_cloexec(h);

restore_dir_ret:
	if (!abs_path) {
		os_set_original_cwd();
	}

	os_unlock_fork(!abs_path);

#ifdef HAVE_AT_FUNCTIONS
test_dir_ret_h:
#endif
	if (likely(h != -1)) {
		os_stat_t st;
		if (!want_dir) {
			if (!(flags & (O_WRONLY | O_RDWR))) {
				if (unlikely(!os_fstat(h, &st, err))) {
					ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
					fatal_mayfail(e, err, "fstat on file '%s' failed", path);
					os_close(h);
					h = -1;
				} else if (unlikely(S_ISDIR(st.st_mode))) {
					ajla_error_t e = error_from_errno(EC_SYSCALL, EISDIR);
					fatal_mayfail(e, err, "file '%s' is a directory", path);
					os_close(h);
					h = -1;
				}
			}
		} else {
#ifndef O_DIRECTORY
			if (unlikely(!os_fstat(h, &st, err))) {
				ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
				fatal_mayfail(e, err, "fstat on file '%s' failed", path);
				os_close(h);
				h = -1;
			} else if (unlikely(!S_ISDIR(st.st_mode))) {
				ajla_error_t e = error_from_errno(EC_SYSCALL, ENOTDIR);
				fatal_mayfail(e, err, "file '%s' is not a directory", path);
				os_close(h);
				h = -1;
			}
#endif
		}
	}
	return h;
}

handle_t os_open(dir_handle_t dir, const char *path, int flags, int mode, ajla_error_t *err)
{
#ifdef OS_DOS
	flags |= O_BINARY;
#endif
	return os_open_internal(dir, path, flags, mode, false, err);
}

bool os_pipe(handle_t result[2], int nonblock_flags, ajla_error_t *err)
{
	int r, i;
#ifdef HAVE_PIPE2
	EINTR_LOOP(r, pipe2(result, O_CLOEXEC | (nonblock_flags == 3 ? O_NONBLOCK : 0)));
	if (likely(r != -1)) {
		if (nonblock_flags == 3) {
			obj_registry_insert(OBJ_TYPE_HANDLE, result[0], file_line);
			obj_registry_insert(OBJ_TYPE_HANDLE, result[1], file_line);
			return true;
		}
		goto set_nonblock;
	}
	if (errno != ENOSYS) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't create pipe: %s", error_decode(e));
		return false;
	}
#endif

	os_lock_fork(false);
	EINTR_LOOP(r, pipe(result));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		os_unlock_fork(false);
		fatal_mayfail(e, err, "can't create pipe: %s", error_decode(e));
		return false;
	}
	for (i = 0; i < 2; i++)
		os_set_cloexec(result[i]);
	os_unlock_fork(false);

#ifdef HAVE_PIPE2
set_nonblock:
#endif
	for (i = 0; i < 2; i++) {
		obj_registry_insert(OBJ_TYPE_HANDLE, result[i], file_line);
		if (nonblock_flags & (1 << i)) {
			EINTR_LOOP(r, fcntl(result[i], F_SETFL, O_NONBLOCK));
			if (unlikely(r == -1)) {
				int er = errno;
				fatal("fcntl(F_SETFL, O_NONBLOCK) on a pipe failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
			}
		}
	}
	return true;
}

void os_close_handle(handle_t h)
{
	int r;
	if (unlikely(h < 0))
		internal(file_line, "os_close: attempting to close invalid handle %d", h);
	EINTR_LOOP(r, close(h));
	if (unlikely(r == -1) && errno == EBADF)
		internal(file_line, "os_close: closing invalid handle %d", h);
}

void os_close(handle_t h)
{
	obj_registry_remove(OBJ_TYPE_HANDLE, h, file_line);
	os_close_handle(h);
}

static unsigned n_std_handles;

unsigned os_n_std_handles(void)
{
	return n_std_handles;
}

handle_t os_get_std_handle(unsigned h)
{
	return (handle_t)h;
}

handle_t os_number_to_handle(uintptr_t n, bool attr_unused sckt, ajla_error_t *err)
{
	if (unlikely(n != (uintptr_t)(int)n) || unlikely((int)n < 0)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "invalid handle");
		return handle_none;
	}
	obj_registry_insert(OBJ_TYPE_HANDLE, (int)n, file_line);
	return (int)n;
}


static ssize_t os_rdwr_return(int r, const char *msg, ajla_error_t *err)
{
	if (unlikely(r == -1)) {
		ajla_error_t e;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return OS_RW_WOULDBLOCK;
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "error %s data: %s", msg, error_decode(e));
		return OS_RW_ERROR;
	}
	return r;
}

ssize_t os_read(handle_t h, char *buffer, int size, ajla_error_t *err)
{
	ssize_t r;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
	EINTR_LOOP(r, read(h, buffer, size));
	return os_rdwr_return(r, "reading", err);
}

ssize_t os_write(handle_t h, const char *buffer, int size, ajla_error_t *err)
{
	ssize_t r;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
	EINTR_LOOP(r, write(h, buffer, size));
	/*
	 * https://stackoverflow.com/questions/5656628/what-should-i-do-when-writefd-buf-count-returns-0
	 * Long, long ago, pre-POSIX, some systems returned 0 instead of EAGAIN.
	 */
	if (unlikely(!r) && size)
		return OS_RW_WOULDBLOCK;
	return os_rdwr_return(r, "writing", err);
}

ssize_t os_pread(handle_t h, char *buffer, int size, os_off_t off, ajla_error_t *err)
{
	ssize_t r;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
#ifndef DO_LOCK_HANDLES
	EINTR_LOOP(r, pread(h, buffer, size, off));
#else
	address_lock(num_to_ptr(h), DEPTH_HANDLE);
	EINTR_LOOP(off, lseek(h, off, SEEK_SET));
	if (unlikely(off == -1)) {
		r = -1;
		goto ret;
	}
	EINTR_LOOP(r, read(h, buffer, size));
ret:
	address_unlock(num_to_ptr(h), DEPTH_HANDLE);
#endif
	return os_rdwr_return(r, "preading", err);
}

ssize_t os_pwrite(handle_t h, const char *buffer, int size, os_off_t off, ajla_error_t *err)
{
	ssize_t r;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
#ifndef DO_LOCK_HANDLES
	EINTR_LOOP(r, pwrite(h, buffer, size, off));
#else
	address_lock(num_to_ptr(h), DEPTH_HANDLE);
	EINTR_LOOP(off, lseek(h, off, SEEK_SET));
	if (unlikely(off == -1)) {
		r = -1;
		goto ret;
	}
	EINTR_LOOP(r, write(h, buffer, size));
ret:
	address_unlock(num_to_ptr(h), DEPTH_HANDLE);
#endif
	return os_rdwr_return(r, "pwriting", err);
}

bool os_lseek(handle_t h, unsigned mode, os_off_t off, os_off_t *result, ajla_error_t *err)
{
	int whence;
	os_off_t res;
#ifdef DO_LOCK_HANDLES
	address_lock(num_to_ptr(h), DEPTH_HANDLE);
#endif
restart:
	switch (mode) {
		case 0:
			whence = SEEK_SET;
			break;
		case 1:
			whence = SEEK_CUR;
			break;
		case 2:
			whence = SEEK_END;
			break;
		case 3:
#ifdef SEEK_DATA
			whence = SEEK_DATA;
#else
			EINTR_LOOP(res, lseek(h, 0, SEEK_END));
			if (unlikely(res == -1))
				goto ret_error;
			if (unlikely(off > res))
				off = res;
			*result = off;
			goto ret_true;
#endif
			break;
		case 4:
#ifdef SEEK_HOLE
			whence = SEEK_HOLE;
#else
			off = 0;
			whence = SEEK_END;
#endif
			break;
		default:internal(file_line, "os_lseek: unsupported mode %u", mode);
			goto ret_false;
	}
	EINTR_LOOP(res, lseek(h, off, whence));
	if (unlikely(res == -1)) {
		ajla_error_t e;
		if (errno == EINVAL) {
			if (mode == 3) {
				*result = off;
				goto ret_true;
			}
			if (mode == 4) {
				off = 0;
				mode = 2;
				goto restart;
			}
		}
		if (errno == ENXIO && mode >= 3) {
			off = 0;
			mode = 2;
			goto restart;
		}
		goto ret_error;
ret_error:
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't lseek: %s", error_decode(e));
		goto ret_false;
	}
	*result = res;
ret_true:
#ifdef DO_LOCK_HANDLES
	address_unlock(num_to_ptr(h), DEPTH_HANDLE);
#endif
	return true;
ret_false:
#ifdef DO_LOCK_HANDLES
	address_unlock(num_to_ptr(h), DEPTH_HANDLE);
#endif
	return false;
}

bool os_ftruncate(handle_t h, os_off_t size, ajla_error_t *err)
{
	int r;
	EINTR_LOOP(r, ftruncate(h, size));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "ftruncate returned an error: %s", error_decode(e));
		return false;
	}
	return true;
}

bool os_fallocate(handle_t attr_unused h, os_off_t attr_unused position, os_off_t attr_unused size, ajla_error_t attr_unused *err)
{
#ifdef HAVE_FALLOCATE
	int r;
	if (unlikely(!size))
		return true;
	/* EINTR may cause infinite loop */
#if 1
	{
		sig_state_t set;
		os_block_signals(&set);
		EINTR_LOOP(r, fallocate(h, FALLOC_FL_KEEP_SIZE, position, size));
		os_unblock_signals(&set);
	}
#else
	r = fallocate(h, FALLOC_FL_KEEP_SIZE, position, size);
	if (unlikely(r == -1) && errno == EINTR)
		r = fallocate(h, FALLOC_FL_KEEP_SIZE, position, size);
#endif
	if (unlikely(r == -1) && errno != EINTR && errno != ENOSYS && errno != EOPNOTSUPP) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "fallocate returned an error: %s", error_decode(e));
		return false;
	}
#endif
	return true;
}

bool os_clone_range(handle_t attr_unused src_h, os_off_t attr_unused src_pos, handle_t attr_unused dst_h, os_off_t attr_unused dst_pos, os_off_t attr_unused len, ajla_error_t *err)
{
#ifdef FICLONERANGE
	int r;
	struct file_clone_range c;
	c.src_fd = src_h;
	c.src_offset = src_pos;
	c.src_length = len;;
	c.dest_offset = dst_pos;
	EINTR_LOOP(r, ioctl(dst_h, FICLONERANGE, &c));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "clone range returned an error: %s", error_decode(e));
		return false;
	}
	return true;
#endif
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "clone not supported");
	return false;
}
bool os_fsync(handle_t h, unsigned mode, ajla_error_t *err)
{
	int r;
#ifdef __APPLE__
	if (mode == 0 || mode == 1) {
		EINTR_LOOP(r, fcntl(h, F_FULLFSYNC));
		if (likely(r != -1))
			goto ret;
	}
#endif
#if defined(HAVE_FDATASYNC) && !defined(__APPLE__)
	if (mode == 0) {
		EINTR_LOOP(r, fdatasync(h));
		goto ret;
	}
#endif
	if (mode == 0 || mode == 1) {
		EINTR_LOOP(r, fsync(h));
		goto ret;
	}
#ifdef HAVE_SYNCFS
	if (mode == 2) {
		EINTR_LOOP(r, syncfs(h));
		goto ret;
	}
#endif
	if (mode == 2 || mode == 3) {
		sync();
		return true;
	}
	internal(file_line, "os_fsync: invalid mode %u", mode);
ret:
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "ftruncate returned an error: %s", error_decode(e));
		return false;
	}
	return true;
}

#if !defined(OS_DOS)
ssize_t os_read_console_packet(handle_t attr_unused h, struct console_read_packet attr_unused *result, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "console packets not supported");
	return OS_RW_ERROR;
}

bool os_write_console_packet(handle_t attr_unused h, struct console_write_packet attr_unused *packet, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "console packets not supported");
	return false;
}

dir_handle_t os_dir_root(ajla_error_t *err)
{
	const char *root = "/";
#ifndef NO_DIR_HANDLES
	return os_dir_open(dir_none, root, 0, err);
#else
	return str_dup(root, -1, err);
#endif
}
#endif

dir_handle_t os_dir_cwd(ajla_error_t *err)
{
	return os_dir_open(os_cwd, ".", 0, err);
}

dir_handle_t os_dir_open(dir_handle_t dir, const char *path, int attr_unused flags, ajla_error_t *err)
{
#ifndef NO_DIR_HANDLES
	return os_open_internal(dir, path, O_RDONLY | flags, 0, true, err);
#else
	dir_handle_t ret;

	if (unlikely(!os_test_absolute_path(dir, os_path_is_absolute(path), err)))
		return dir_none;

	os_lock_fork(true);

	if (dir_handle_is_valid(dir)) {
		if (unlikely(!os_set_cwd(dir, err))) {
			ret = dir_none;
			goto restore_ret;
		}
	}

	if (unlikely(!os_set_cwd((dir_handle_t)path, err))) {
		ret = dir_none;
		goto restore_ret;
	}

	ret = os_get_cwd(err);

restore_ret:
	os_set_original_cwd();

	os_unlock_fork(true);
	return ret;
#endif
}

void os_dir_close(dir_handle_t h)
{
#ifndef NO_DIR_HANDLES
	os_close(h);
#else
	mem_free(h);
#endif
}

char *os_dir_path(dir_handle_t h, ajla_error_t *err)
{
#ifndef NO_DIR_HANDLES
	char *path;
#ifdef __linux__
	ajla_error_t sink;
	char lnk[25];
	snprintf(lnk, sizeof(lnk), "/proc/self/fd/%u", h);
	path = os_readlink(dir_none, lnk, &sink);
	if (likely(path != NULL)) {
		size_t sl, dl;
		char *deleted = " (deleted)";
		if (unlikely(path[0] != '/')) {
			mem_free(path);
			goto skip_optimization;
		}
		sl = strlen(path);
		dl = strlen(deleted);
		if (sl >= dl && unlikely(!memcmp(path + sl - dl, deleted, dl))) {
			mem_free(path);
			goto skip_optimization;
		}
		return path;
	}
skip_optimization:
#endif
	os_lock_fork(true);
	if (unlikely(!os_set_cwd(h, err))) {
		path = NULL;
		goto unlock_ret;
	}
	path = os_call_getcwd(err);
	os_set_original_cwd();
unlock_ret:
	os_unlock_fork(true);
	return path;
#else
	return str_dup(h, -1, err);
#endif
}

static void os_close_DIR(DIR *d)
{
	int r;
	EINTR_LOOP(r, closedir(d));
	if (unlikely(r))
		internal(file_line, "os_close_DIR: closing invalid directory handle: %s", error_decode(error_from_errno(EC_SYSCALL, errno)));
}

bool os_dir_read(dir_handle_t h, char ***files, size_t *n_files, ajla_error_t *err)
{
	ajla_error_t e;
	DIR *d;
#if !defined(NO_DIR_HANDLES)
	int er;
	os_lock_fork(true);
	if (unlikely(!os_set_cwd(h, err))) {
		os_set_original_cwd();
		os_unlock_fork(true);
		return false;
	}
	EINTR_LOOP_VAL(d, NULL, opendir("."));
	er = errno;
	os_set_original_cwd();
	os_unlock_fork(true);
	errno = er;
#else
	EINTR_LOOP_VAL(d, NULL, opendir(h));
#endif
	if (unlikely(!d)) {
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't open directory: %s", error_decode(e));
		return false;
	}
	if (unlikely(!array_init_mayfail(char *, files, n_files, err))) {
		os_close_DIR(d);
		return false;
	}

	while (1) {
		struct dirent *de;
		char *fn;
		errno = 0;
		de = readdir(d);
		if (unlikely(!de)) {
			if (likely(!errno))
				break;
			e = error_from_errno(EC_SYSCALL, errno);
			fatal_mayfail(e, err, "error reading directory directory: %s", error_decode(e));
			os_dir_free(*files, *n_files);
			os_close_DIR(d);
			return false;
		}
		if (unlikely(!strcmp(de->d_name, ".")) ||
		    unlikely(!strcmp(de->d_name, "..")))
			continue;
		fn = mem_alloc_mayfail(char *, strlen(de->d_name) + 1, err);
		if (unlikely(!fn)) {
			os_dir_free(*files, *n_files);
			os_close_DIR(d);
			return false;
		}
		strcpy(fn, de->d_name);
		array_add(char *, files, n_files, fn);
	}
	os_close_DIR(d);
	return true;
}

void os_dir_free(char **files, size_t n_files)
{
	size_t i;
	for (i = 0; i < n_files; i++)
		mem_free(files[i]);
	mem_free(files);
}


unsigned os_dev_t_major(dev_t dev)
{
#if defined(HAVE_SYS_SYSMACROS_H) || defined(major)
	return major(dev);
#else
	return (dev >> 8) & 0xff;
#endif
}

unsigned os_dev_t_minor(dev_t dev)
{
#if defined(HAVE_SYS_SYSMACROS_H) || defined(minor)
	return minor(dev);
#else
	return dev & 0xff;
#endif
}

bool os_fstat(handle_t h, os_stat_t *st, ajla_error_t *err)
{
	int r;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
	EINTR_LOOP(r, fstat(h, st));
	if (unlikely(r == -1)) {
		ajla_error_t e;
		if (unlikely(errno == EBADF))
			internal(file_line, "os_fstat: invalid handle %d", h);
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't stat file handle: %s", error_decode(e));
		return false;
	}
	return true;
}

bool os_stat(dir_handle_t dir, const char *path, bool attr_unused lnk, os_stat_t *st, ajla_error_t *err)
{
	int r;
	bool abs_path = os_path_is_absolute(path);

	if (unlikely(!os_test_absolute_path(dir, abs_path, err)))
		return false;

#ifdef HAVE_AT_FUNCTIONS
	if (likely(have_O_CLOEXEC_openat)) {
		EINTR_LOOP(r, fstatat(dir, path, st, lnk ? AT_SYMLINK_NOFOLLOW : 0));
		if (unlikely(r == -1)) {
			ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
			fatal_mayfail(e, err, "can't open file '%s': %s", path, error_decode(e));
		}
		return r != -1;
	}
#endif
	if (!abs_path) {
		os_lock_fork(true);
		if (unlikely(!os_set_cwd(dir, err))) {
			r = -1;
			goto unlock_ret_r;
		}
	}

#ifdef HAVE_LSTAT
	EINTR_LOOP(r, (!lnk ? stat : lstat)(path, st));
#else
	EINTR_LOOP(r, stat(path, st));
#endif
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't open file '%s': %s", path, error_decode(e));
	}

unlock_ret_r:
	if (!abs_path) {
		os_set_original_cwd();
		os_unlock_fork(true);
	}

	return r != -1;
}

#if (defined(HAVE_FSTATFS) && !defined(HAVE_FSTATVFS)) || (defined(HAVE_STATFS) && !defined(HAVE_STATVFS))
static inline void attr_unused statfs_2_statvfs(struct statfs *stfs, os_statvfs_t *st)
{
	memset(st, 0, sizeof(os_statvfs_t));
#if defined(__linux__)
	st->f_bsize = stfs->f_bsize;
	st->f_frsize = stfs->f_bsize;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	st->f_bsize = stfs->f_iosize;
	st->f_frsize = stfs->f_bsize;
#else
	st->f_bsize = stfs->f_bsize;
	st->f_frsize = stfs->f_bsize;
#endif
	st->f_blocks = stfs->f_blocks;
	st->f_bfree = stfs->f_bfree;
	st->f_bavail = stfs->f_bavail;
	st->f_files = stfs->f_files;
	st->f_ffree = stfs->f_ffree;
	st->f_favail = stfs->f_ffree;
	memcpy(&st->f_fsid, &stfs->f_fsid, minimum(sizeof(st->f_fsid), sizeof(stfs->f_fsid)));
#if defined(__linux__)
	st->f_namemax = stfs->f_namelen;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	st->f_namemax = stfs->f_namemax;
#else
	st->f_namemax = 255;
#endif
}
#endif

bool os_fstatvfs(handle_t h, os_statvfs_t *st, ajla_error_t *err)
{
	ajla_error_t e;
	int r;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
#if defined(HAVE_FSTATVFS)
	EINTR_LOOP(r, fstatvfs(h, st));
	if (unlikely(r == -1))
		goto err;
	return true;
#elif defined(HAVE_FSTATFS)
	{
		struct statfs stfs;
		EINTR_LOOP(r, fstatfs(h, &stfs));
		if (unlikely(r == -1))
			goto err;
		statfs_2_statvfs(&stfs, st);
		return true;
	}
#endif
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "the system doesn't support mprotect");
	return false;

	goto err;
err:
	if (unlikely(errno == EBADF))
		internal(file_line, "os_fstatvfs: invalid handle %d", h);
	e = error_from_errno(EC_SYSCALL, errno);
	fatal_mayfail(e, err, "can't fstatvfs file handle: %s", error_decode(e));
	return false;
}

bool os_dstatvfs(dir_handle_t dir, os_statvfs_t *st, ajla_error_t *err)
{
	ajla_error_t attr_unused e;
	int attr_unused r;
#ifndef NO_DIR_HANDLES
	return os_fstatvfs(dir, st, err);
#elif defined(HAVE_STATVFS)
	EINTR_LOOP(r, statvfs(dir, st));
	if (unlikely(r == -1))
		goto err;
	return true;
#elif defined(HAVE_STATFS)
	{
		struct statfs stfs;
		EINTR_LOOP(r, statfs(dir, &stfs));
		if (unlikely(r == -1))
			goto err;
		statfs_2_statvfs(&stfs, st);
		return true;
	}
#endif
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "the system doesn't support mprotect");
	return false;

	goto err;
err:
	e = error_from_errno(EC_SYSCALL, errno);
	fatal_mayfail(e, err, "can't statvfs directory: %s", error_decode(e));
	return false;
}

char *os_readlink(dir_handle_t attr_unused dir, const char attr_unused *path, ajla_error_t *err)
{
#ifdef HAVE_READLINK
	size_t buf_size = 32;
	ssize_t r;
	char *buf;
	bool abs_path = os_path_is_absolute(path);

	if (unlikely(!os_test_absolute_path(dir, abs_path, err)))
		return NULL;

alloc_larger:
	buf = mem_alloc_mayfail(char *, buf_size, err);
	if (unlikely(!buf))
		return NULL;

#ifdef HAVE_AT_FUNCTIONS
	if (likely(have_O_CLOEXEC_openat)) {
		EINTR_LOOP(r, readlinkat(dir, path, buf, buf_size));
		goto proc_r;
	}
#endif
	if (!abs_path) {
		os_lock_fork(true);
		if (unlikely(!os_set_cwd(dir, err))) {
			os_unlock_fork(true);
			mem_free(buf);
			return NULL;
		}
	}

	EINTR_LOOP(r, readlink(path, buf, buf_size));

	if (!abs_path) {
		int e = errno;
		os_set_original_cwd();
		os_unlock_fork(true);
		errno = e;
	}

#ifdef HAVE_AT_FUNCTIONS
proc_r:
#endif
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't read link '%s': %s", path, error_decode(e));
		mem_free(buf);
		return NULL;
	}
	if (unlikely((size_t)r == buf_size)) {
		mem_free(buf);
		buf_size *= 2;
		if (unlikely((buf_size * 2) == 0)) {
			fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "overflow when allocating readlink buffer");
			return NULL;
		}
		goto alloc_larger;
	}

	buf[r] = 0;

	return buf;
#else
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "readlink not supported");
	return NULL;
#endif
}

bool os_dir_action(dir_handle_t dir, const char *path, int action, int mode, ajla_time_t attr_unused dev_major, ajla_time_t attr_unused dev_minor, const char *syml, ajla_error_t *err)
{
	int r;
	bool abs_path = os_path_is_absolute(path);

	if (unlikely((mode & ~07777) != 0)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "invalid mode: %d", mode);
		return false;
	}

	if (unlikely(!os_test_absolute_path(dir, abs_path, err)))
		return false;

#ifdef HAVE_AT_FUNCTIONS
	if (likely(have_O_CLOEXEC_openat)) {
		if (!dir_handle_is_valid(dir))
			dir = AT_FDCWD;
		switch (action) {
			case IO_Action_Rm:
				EINTR_LOOP(r, unlinkat(dir, path, 0));
				break;
			case IO_Action_Rm_Dir:
				EINTR_LOOP(r, unlinkat(dir, path, AT_REMOVEDIR));
				break;
			case IO_Action_Mk_Dir:
				EINTR_LOOP(r, mkdirat(dir, path, mode));
				break;
			case IO_Action_Mk_Pipe:
				EINTR_LOOP(r, mknodat(dir, path, mode | S_IFIFO, 0));
				break;
			case IO_Action_Mk_Socket:
				EINTR_LOOP(r, mknodat(dir, path, mode | S_IFSOCK, 0));
				break;
			case IO_Action_Mk_CharDev:
#if defined(HAVE_SYS_SYSMACROS_H) || defined(makedev)
				EINTR_LOOP(r, mknodat(dir, path, mode | S_IFCHR, makedev(dev_major, dev_minor)));
#else
				fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkchardev not supported");
				return false;
#endif
				break;
			case IO_Action_Mk_BlockDev:
#if defined(HAVE_SYS_SYSMACROS_H) || defined(makedev)
				EINTR_LOOP(r, mknodat(dir, path, mode | S_IFBLK, makedev(dev_major, dev_minor)));
#else
				fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkblockdev not supported");
				return false;
#endif
				break;
			case IO_Action_Mk_SymLink:
				EINTR_LOOP(r, symlinkat(syml, dir, path));
				break;
			case IO_Action_ChMod:
				EINTR_LOOP(r, fchmodat(dir, path, mode, 0));
				break;
			case IO_Action_ChOwn:
				EINTR_LOOP(r, fchownat(dir, path, dev_major, dev_minor, 0));
				break;
			case IO_Action_LChOwn:
				EINTR_LOOP(r, fchownat(dir, path, dev_major, dev_minor, AT_SYMLINK_NOFOLLOW));
				break;
			case IO_Action_UTime:
			case IO_Action_LUTime: {
				struct timespec ts[2];
				ts[0].tv_sec = dev_minor / 1000000;
				ts[0].tv_nsec = dev_minor % 1000000 * 1000;
				ts[1].tv_sec = dev_major / 1000000;
				ts[1].tv_nsec = dev_major % 1000000 * 1000;
				EINTR_LOOP(r, utimensat(dir, path, ts, action == IO_Action_UTime ? 0 : AT_SYMLINK_NOFOLLOW));
				break;
			}
			default:
				internal(file_line, "os_dir_action: invalid action %d", action);
		}
		goto proc_r;
	}
#endif

	if (!abs_path) {
		os_lock_fork(true);
		if (unlikely(!os_set_cwd(dir, err))) {
			os_unlock_fork(true);
			return false;
		}
	}

	switch (action) {
		case IO_Action_Rm:
			EINTR_LOOP(r, unlink(path));
			break;
		case IO_Action_Rm_Dir:
			EINTR_LOOP(r, rmdir(path));
			break;
		case IO_Action_Mk_Dir:
			EINTR_LOOP(r, mkdir(path, mode));
#ifdef __minix__
			/*
			 * Minix 3 returns EACCES when attempting to make the
			 * home directory. So we test if the directory exists
			 * and return EEXIST if it does.
			 */
			if (r == -1 && errno == EACCES) {
				struct stat st;
				int rr;
				EINTR_LOOP(rr, stat(path, &st));
				if (!rr)
					errno = EEXIST;
				else
					errno = EACCES;
			}
#endif
			break;
		case IO_Action_Mk_Pipe:
#ifdef HAVE_MKNOD
			EINTR_LOOP(r, mknod(path, mode | S_IFIFO, 0));
#else
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkpipe not supported");
			goto ret_false;
#endif
			break;
		case IO_Action_Mk_Socket:
#if defined(HAVE_MKNOD) && defined(S_IFSOCK)
			EINTR_LOOP(r, mknod(path, mode | S_IFSOCK, 0));
#else
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mksocket not supported");
			goto ret_false;
#endif
			break;
		case IO_Action_Mk_CharDev:
#if defined(HAVE_MKNOD) && (defined(HAVE_SYS_SYSMACROS_H) || defined(makedev))
			EINTR_LOOP(r, mknod(path, mode | S_IFCHR, makedev(dev_major, dev_minor)));
#else
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkchardev not supported");
			goto ret_false;
#endif
			break;
		case IO_Action_Mk_BlockDev:
#if defined(HAVE_MKNOD) && (defined(HAVE_SYS_SYSMACROS_H) || defined(makedev))
			EINTR_LOOP(r, mknod(path, mode | S_IFBLK, makedev(dev_major, dev_minor)));
#else
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "mkblockdev not supported");
			goto ret_false;
#endif
			break;
		case IO_Action_Mk_SymLink:
#ifdef HAVE_SYMLINK
			EINTR_LOOP(r, symlink(syml, path));
#else
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "symlink not supported");
			goto ret_false;
#endif
			break;
		case IO_Action_ChMod:
			EINTR_LOOP(r, chmod(path, mode));
			break;
		case IO_Action_LChOwn: {
#ifdef HAVE_LCHOWN
			EINTR_LOOP(r, lchown(path, dev_major, dev_minor));
			break;
#else
			struct stat st;
			EINTR_LOOP(r, lstat(path, &st));
			if (unlikely(r))
				break;
			if (S_ISLNK(st.st_mode))
				break;
#endif
		}
			/*-fallthrough*/
		case IO_Action_ChOwn:
#ifdef HAVE_CHOWN
			EINTR_LOOP(r, chown(path, dev_major, dev_minor));
#else
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "chown not supported");
			goto ret_false;
#endif
			break;
		case IO_Action_LUTime: {
			struct stat st;
			EINTR_LOOP(r, lstat(path, &st));
			if (unlikely(r))
				break;
			if (S_ISLNK(st.st_mode)) {
				r = -1;
				errno = -ELOOP;
				break;
			}
		}
			/*-fallthrough*/
		case IO_Action_UTime: {
#if defined(HAVE_UTIMES)
			struct timeval ts[2];
			ts[0].tv_sec = dev_minor / 1000000;
			ts[0].tv_usec = dev_minor % 1000000;
			ts[1].tv_sec = dev_major / 1000000;
			ts[1].tv_usec = dev_major % 1000000;
			EINTR_LOOP(r, utimes(cast_ptr(char *, path), ts));
			break;
#elif defined(HAVE_UTIME)
			struct utimbuf tm;
			tm.actime = dev_minor / 1000000;
			tm.modtime = dev_major / 1000000;
			EINTR_LOOP(r, times(path, &tm));
			break;
#endif
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "utime not supported");
			goto ret_false;
		}
		default:
			internal(file_line, "os_dir_action: invalid action %d", action);
	}

	if (!abs_path) {
		int e = errno;
		os_set_original_cwd();
		os_unlock_fork(true);
		errno = e;
	}

#ifdef HAVE_AT_FUNCTIONS
proc_r:
#endif
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't perform action %d on '%s': %s", action, path, error_decode(e));
		return false;
	}
	return true;

ret_false:
	if (!abs_path) {
		int e = errno;
		os_set_original_cwd();
		os_unlock_fork(true);
		errno = e;
	}
	return false;
}

bool os_dir2_action(dir_handle_t dest_dir, const char *dest_path, int action, dir_handle_t src_dir, const char *src_path, ajla_error_t *err)
{
	bool ret;
	int r;
	char *dest_final_path = NULL;
	char *src_final_path = NULL;
	bool abs_dest_path = os_path_is_absolute(dest_path);
	bool abs_src_path = os_path_is_absolute(src_path);

	if (unlikely(!os_test_absolute_path(dest_dir, abs_dest_path, err)))
		return false;
	if (unlikely(!os_test_absolute_path(src_dir, abs_src_path, err)))
		return false;

#ifdef HAVE_AT_FUNCTIONS
	if (likely(have_O_CLOEXEC_openat)) {
		if (!dir_handle_is_valid(dest_dir))
			dest_dir = AT_FDCWD;
		if (!dir_handle_is_valid(src_dir))
			src_dir = AT_FDCWD;
		switch (action) {
			case IO_Action_Mk_Link:
				EINTR_LOOP(r, linkat(src_dir, src_path, dest_dir, dest_path, 0));
				break;
			case IO_Action_Rename:
				EINTR_LOOP(r, renameat(src_dir, src_path, dest_dir, dest_path));
				break;
			default:
				internal(file_line, "os_dir2_action: invalid action %d", action);

		}
		goto proc_r;
	}
#endif
	if (abs_dest_path) {
		dest_final_path = str_dup(dest_path, -1, err);
		if (unlikely(!dest_final_path)) {
			ret = false;
			goto free_ret;
		}
	} else {
		char *dest_dir_path = os_dir_path(dest_dir, err);
		if (unlikely(!dest_dir_path)) {
			ret = false;
			goto free_ret;
		}
		dest_final_path = os_join_paths(dest_dir_path, dest_path, true, err);
		if (unlikely(!dest_final_path)) {
			mem_free(dest_dir_path);
			ret = false;
			goto free_ret;
		}
		mem_free(dest_dir_path);
		dest_dir_path = NULL;
	}
	if (abs_src_path) {
		src_final_path = str_dup(src_path, -1, err);
		if (unlikely(!src_final_path)) {
			ret = false;
			goto free_ret;
		}
	} else {
		char *src_dir_path = os_dir_path(src_dir, err);
		if (unlikely(!src_dir_path)) {
			ret = false;
			goto free_ret;
		}
		src_final_path = os_join_paths(src_dir_path, src_path, true, err);
		if (unlikely(!src_final_path)) {
			mem_free(src_dir_path);
			ret = false;
			goto free_ret;
		}
		mem_free(src_dir_path);
		src_dir_path = NULL;
	}

	switch (action) {
		case IO_Action_Mk_Link:
#ifdef HAVE_LINK
			EINTR_LOOP(r, link(src_final_path, dest_final_path));
#else
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "link not supported");
			ret = false;
			goto free_ret;
#endif
			break;
		case IO_Action_Rename:
			EINTR_LOOP(r, rename(src_final_path, dest_final_path));
			break;
		default:
			internal(file_line, "os_dir2_action: invalid action %d", action);

	}

#ifdef HAVE_AT_FUNCTIONS
proc_r:
#endif
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't perform action %d on '%s' and '%s': %s", action, src_path, dest_path, error_decode(e));
		ret = false;
		goto free_ret;
	}
	ret = true;

free_ret:
	if (dest_final_path)
		mem_free(dest_final_path);
	if (src_final_path)
		mem_free(src_final_path);
	return ret;
}

#if !defined(OS_DOS)

bool os_drives(char **drives, size_t *drives_l, ajla_error_t *err)
{
#if defined(OS_CYGWIN)
	uint32_t mask = GetLogicalDrives();
	return os_drives_bitmap(mask, drives, drives_l, err);
#elif defined(HAVE_GETFSSTAT)
	int r, i;
	int n_entries;
	struct statfs *buf;

	n_entries = 2;
again:
	buf = mem_alloc_array_mayfail(mem_alloc_mayfail, struct statfs *, 0, 0, n_entries, sizeof(struct statfs), err);
	if (unlikely(!buf))
		return false;
	EINTR_LOOP(r, getfsstat(buf, sizeof(struct statfs) * n_entries, MNT_NOWAIT));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "getfsstat failed: %s", error_decode(e));
		mem_free(buf);
		return false;
	}
	if (r >= n_entries) {
		mem_free(buf);
		n_entries *= 2U;
		if (unlikely(n_entries < 0)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "getfsstat buffer overflow");
			return false;
		}
		goto again;
	}

	if (unlikely(!array_init_mayfail(char, drives, drives_l, err))) {
		mem_free(buf);
		return false;
	}

	for (i = 0; i < r; i++) {
		char *str;
		size_t str_l;
		if (buf[i].f_blocks <= 2)
			continue;
		str = buf[i].f_mntonname;
		str_l = strlen(str) + 1;
		if (unlikely(!array_add_multiple_mayfail(char, drives, drives_l, str, str_l, NULL, err))) {
			mem_free(buf);
			return false;
		}
	}

	mem_free(buf);
	return true;
#else
	if (unlikely(!array_init_mayfail(char, drives, drives_l, err)))
		return false;
	return true;
#endif
}

#endif


bool os_tcgetattr(handle_t h, os_termios_t *t, ajla_error_t *err)
{
	int r;
	EINTR_LOOP(r, tcgetattr(h, t));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "tcgetattr failed: %s", error_decode(e));
		return false;
	}
	return true;
}

bool os_tcsetattr(handle_t h, const os_termios_t *t, ajla_error_t *err)
{
	int r;
	EINTR_LOOP(r, tcsetattr(h, TCSANOW, cast_ptr(os_termios_t *, t)));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "tcsetattr failed: %s", error_decode(e));
		return false;
	}
	return true;
}

void os_tcflags(os_termios_t *t, int flags)
{
	if (flags & IO_Stty_Flag_Raw) {
#ifdef HAVE_CFMAKERAW
		cfmakeraw(t);
		t->c_cc[VMIN] = 1;
#else
		t->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
		t->c_oflag &= ~OPOST;
		t->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
		t->c_cflag &= ~(CSIZE|PARENB);
		t->c_cflag |= CS8;
		t->c_cc[VMIN] = 1;
		t->c_cc[VTIME] = 0;
#endif
	}
	if (flags & IO_Stty_Flag_Noecho)
		t->c_lflag &= ~ECHO;
	else
		t->c_lflag |= ECHO;
	if (flags & IO_Stty_Flag_Nosignal)
		t->c_lflag &= ~ISIG;
	else
		t->c_lflag |= ISIG;
	if (flags & IO_Stty_Flag_NoCRLF)
		t->c_oflag &= ~OPOST;
	else
		t->c_oflag |= OPOST;
}

bool os_tty_size(handle_t h, int *nx, int *ny, int *ox, int *oy, ajla_error_t *err)
{
	int r;
	struct winsize ws;
	signal_seq_t attr_unused seq;

	EINTR_LOOP(r, ioctl(h, TIOCGWINSZ, &ws));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "ioctl(TIOCGWINSZ) failed: %s", error_decode(e));
		return false;
	}

	*nx = ws.ws_col;
	*ny = ws.ws_row;
	*ox = 0;
	*oy = 0;

	return true;
}


static char *os_path_to_exe;

static void os_init_path_to_exe(void)
{
	size_t i, sep;
	char *path, *component, *test_path;
	ajla_error_t sink;
	os_stat_t st;
	dir_handle_t dh;
#ifdef __linux__
	char *ptexe = os_readlink(dir_none, "/proc/self/exe", &sink);
	if (likely(ptexe != NULL)) {
		if (likely(ptexe[0] == '/')) {
			sep = 0;
			for (i = 0; ptexe[i]; i++)
				if (unlikely(os_is_path_separator(ptexe[i])))
					sep = i + !i;
			ptexe[sep] = 0;
			os_path_to_exe = ptexe;
			return;
		}
		mem_free(ptexe);
	}
#endif
	sep = 0;
	for (i = 0; arg0[i]; i++)
		if (unlikely(os_is_path_separator(arg0[i])))
			sep = i + 1;
	if (sep) {
		component = str_dup(arg0, sep, NULL);
		goto get_abs_path;
	}

	path = getenv("PATH");
	if (!path) {
		component = str_dup(".", -1, NULL);
		goto get_abs_path;
	}
next_component:
	i = 0;
	while (path[i] && !os_is_env_separator(path[i]))
		i++;
	component = str_dup(path, i, NULL);
	test_path = os_join_paths(component, arg0, true, NULL);
	if (os_stat(os_cwd, test_path, false, &st, &sink)) {
		mem_free(test_path);
		goto get_abs_path;
	}
	mem_free(test_path);
	mem_free(component);
	if (path[i]) {
		path += i + 1;
		goto next_component;
	}
	warning("could not find executable in path");
	component = str_dup(".", -1, NULL);
get_abs_path:
	if (os_path_is_absolute(component)) {
		os_path_to_exe = component;
		return;
	}
	dh = os_dir_open(os_cwd, component, 0, NULL);
	os_path_to_exe = os_dir_path(dh, NULL);
	os_dir_close(dh);
	mem_free(component);
}

const char *os_get_path_to_exe(void)
{
	return os_path_to_exe;
}


ajla_time_t os_time_t_to_ajla_time(time_t sec)
{
	return (ajla_time_t)sec * 1000000;
}

static ajla_time_t os_timeval_to_ajla_time(const struct timeval *tv)
{
	return os_time_t_to_ajla_time(tv->tv_sec) + tv->tv_usec;
}

#ifdef HAVE_STRUCT_TIMESPEC
ajla_time_t os_timespec_to_ajla_time(const struct timespec *ts)
{
	return os_time_t_to_ajla_time(ts->tv_sec) + ts->tv_nsec / 1000;
}
#endif

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

ajla_time_t os_time_monotonic(void)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(HAVE_CLOCK_MONOTONIC)
	int r;
	struct timespec ts;
	EINTR_LOOP(r, clock_gettime(CLOCK_MONOTONIC, &ts));
	if (unlikely(r == -1)) {
		int e = errno;
		fatal("clock_gettime(%d) failed: %d, %s", (int)CLOCK_MONOTONIC, e, error_decode(error_from_errno(EC_SYSCALL, e)));
	}
	return os_timespec_to_ajla_time(&ts);
#else
	return os_time_real();
#endif
}


#if !defined(OS_DOS)

static bool spawn_process_handles(unsigned n_handles, handle_t *src, int *target)
{
	int r;
	unsigned i;
	handle_t max_handle = 3;
	for (i = 0; i < n_handles; i++) {
		if (unlikely(src[i] >= signed_maximum(int) / 2) ||
		    unlikely(target[i] >= signed_maximum(int) / 2))
			return false;
		if (src[i] >= max_handle) max_handle = src[i] + 1;
		if (target[i] >= max_handle) max_handle = target[i] + 1;
	}
	for (i = 0; i < n_handles; i++) {
		EINTR_LOOP(r, dup2(src[i], max_handle + i));
		if (unlikely(r == -1))
			return false;
		/*os_close_handle(src[i]);*/
	}
	for (i = 0; i < n_handles; i++) {
		EINTR_LOOP(r, close(src[i]));
	}
	EINTR_LOOP(r, close(0));
	EINTR_LOOP(r, close(1));
	EINTR_LOOP(r, close(2));
	for (i = 0; i < n_handles; i++) {
		EINTR_LOOP(r, dup2(max_handle + i, target[i]));
		if (unlikely(r == -1))
			return false;
		os_close_handle(max_handle + i);
	}
	for (i = 0; i < n_handles; i++) {
		EINTR_LOOP(r, fcntl(target[i], F_GETFL));
		if (likely(r >= 0) && r & O_NONBLOCK) {
			int ir;
			r &= ~O_NONBLOCK;
			EINTR_LOOP(ir, fcntl(target[i], F_SETFL, r));
		}
	}
	return true;
}

static bool os_fork(dir_handle_t wd, const char *path, unsigned n_handles, handle_t *src, int *target, char * const args[], char * const env[], pid_t *pid, ajla_error_t *err)
{
#ifdef __linux__
	sig_state_t set;
#endif
	pid_t p;
	int r;
	os_lock_fork(true);
#ifdef __linux__
	os_block_signals(&set);
#endif
	EINTR_LOOP(p, fork());
#ifdef __linux__
	os_unblock_signals(&set);
#endif
	if (!p) {
		ajla_error_t sink;
		if (unlikely(!os_set_cwd(wd, &sink)))
			_exit(127);
		if (unlikely(!spawn_process_handles(n_handles, src, target)))
			_exit(127);
		os_unblock_all_signals();
		EINTR_LOOP(r, execve(path, args, env));
		_exit(127);
	}
	os_unlock_fork(true);
	if (p == -1) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't spawn process '%s': %s", path, error_decode(e));
		return false;
	}
	*pid = p;
	return true;
}

struct proc_handle {
	struct tree_entry entry;
	pid_t pid;
	bool fired;
	bool detached;
	int status;
	int sigchld;
	struct list wait_list;
};

static struct tree proc_tree;
static mutex_t proc_tree_mutex;

static inline void proc_lock(void)
{
	mutex_lock(&proc_tree_mutex);
}

static inline void proc_unlock(void)
{
	mutex_unlock(&proc_tree_mutex);
}

static void proc_handle_free(struct proc_handle *ph)
{
	os_signal_unhandle(ph->sigchld);
	mem_free(ph);
}

static int proc_handle_compare(const struct tree_entry *e, uintptr_t pid)
{
	const struct proc_handle *ph = get_struct(e, struct proc_handle, entry);
	if (unlikely(ph->pid == (pid_t)pid)) return 0;
	if (ph->pid > (pid_t)pid) return 1;
	return -1;
}

struct proc_handle *os_proc_spawn(dir_handle_t wd, const char *path, size_t n_handles, handle_t *src, int *target, char * const args[], char *envc, ajla_error_t *err)
{
	struct proc_handle *ph;
	signal_seq_t seq;
	struct tree_insert_position ins;
	struct tree_entry *e;

	char **env;
	size_t env_l;

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
	ph->fired = false;
	ph->detached = false;
	list_init(&ph->wait_list);
	ph->sigchld = os_signal_handle("SIGCHLD", &seq, err);
	if (unlikely(ph->sigchld < 0)) {
		mem_free(env);
		mem_free(ph);
		return NULL;
	}
	if (unlikely(!ph->sigchld))
		iomux_enable_poll();

	proc_lock();

	if (unlikely(!os_fork(wd, path, n_handles, src, target, args, env, &ph->pid, err))) {
		proc_unlock();
		mem_free(env);
		proc_handle_free(ph);
		return NULL;
	}

	e = tree_find_for_insert(&proc_tree, proc_handle_compare, ph->pid, &ins);
	if (unlikely(e != NULL)) {
		fatal("pid %ld is already present in the tree", (long)ph->pid);
	}

	tree_insert_after_find(&ph->entry, &ins);

	proc_unlock();

	mem_free(env);

	return ph;
}

void os_proc_free_handle(struct proc_handle *ph)
{
	proc_lock();
	ajla_assert_lo(list_is_empty(&ph->wait_list), (file_line, "os_proc_free_handle: freeing handle when there are processes waiting for it"));
	if (ph->fired) {
		proc_unlock();
		proc_handle_free(ph);
	} else {
		ph->detached = true;
		proc_unlock();
	}
}

bool os_proc_register_wait(struct proc_handle *ph, mutex_t **mutex_to_lock, struct list *list_entry, int *status)
{
	proc_lock();
	if (ph->fired) {
		*status = ph->status;
		proc_unlock();
		return true;
	} else {
		*mutex_to_lock = &proc_tree_mutex;
		list_add(&ph->wait_list, list_entry);
		proc_unlock();
		return false;
	}
}

static void process_pid_and_status(pid_t pid, int status)
{
	struct tree_entry *e;
	struct proc_handle *ph;

	proc_lock();

	e = tree_find(&proc_tree, proc_handle_compare, pid);
	if (!e) {
		proc_unlock();
		return;
	}

	ph = get_struct(e, struct proc_handle, entry);
	ph->fired = true;

	if (WIFEXITED(status)) {
		ph->status = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		ph->status = -WTERMSIG(status);
	} else {
		proc_unlock();
		return;
	}

	tree_delete(&ph->entry);

	if (!ph->detached) {
		call(wake_up_wait_list)(&ph->wait_list, &proc_tree_mutex, true);
	} else {
		proc_handle_free(ph);
		proc_unlock();
	}
}

static attr_noinline void proc_check_owned(void)
{
	struct tree_entry *e;
	struct proc_handle *ph;
	pid_t pid = 0;
	pid_t r;
	int status;

next:
	proc_lock();
	e = tree_find_next(&proc_tree, proc_handle_compare, pid);
	if (likely(!e)) {
		proc_unlock();
		return;
	}
	ph = get_struct(e, struct proc_handle, entry);
	pid = ph->pid;
	proc_unlock();

	EINTR_LOOP(r, waitpid(pid, &status, WNOHANG));
	if (r <= 0)
		goto next;

	process_pid_and_status(pid, status);
	goto next;
}

void os_proc_check_all(void)
{
	pid_t pid;
	int status;

	proc_lock();
	if (likely(tree_is_empty(&proc_tree))) {
		proc_unlock();
		return;
	}
	proc_unlock();

	if (!dll) {
test_another:
		EINTR_LOOP(pid, waitpid(-1, &status, WNOHANG));
		if (unlikely(pid > 0)) {
			process_pid_and_status(pid, status);
			goto test_another;
		}
	} else {
		proc_check_owned();
	}
}

#endif


#ifdef OS_HAS_SIGNALS

#if defined(SIGRTMAX)
#define N_SIGNALS	(int)(SIGRTMAX + 1)
#elif defined(NSIG)
#define N_SIGNALS	(int)NSIG
#else
#define N_SIGNALS	32
#endif

struct signal_state {
	thread_volatile signal_seq_t sig_sequence;
	signal_seq_t last_sig_sequence;
	bool trapped;
	uintptr_t refcount;
	struct list wait_list;
	struct sigaction prev_sa;
};

static struct signal_state *signal_states;
static mutex_t signal_state_mutex;

static void signal_handler(int sig)
{
	signal_states[sig].sig_sequence += 1UL;
	os_notify();
}

static int os_signal_number(const char *str)
{
#ifdef SIGABRT
	if (!strcmp(str, "SIGABRT")) return SIGABRT;
#endif
#ifdef SIGALRM
	if (!strcmp(str, "SIGALRM")) return SIGALRM;
#endif
#ifdef SIGBUS
	if (!strcmp(str, "SIGBUS")) return SIGBUS;
#endif
#ifdef SIGCHLD
	if (!strcmp(str, "SIGCHLD")) return SIGCHLD;
#endif
#ifdef SIGCLD
	if (!strcmp(str, "SIGCLD")) return SIGCLD;
#endif
#ifdef SIGCONT
	if (!strcmp(str, "SIGCONT")) return SIGCONT;
#endif
#ifdef SIGEMT
	if (!strcmp(str, "SIGEMT")) return SIGEMT;
#endif
#ifdef SIGFPE
	if (!strcmp(str, "SIGFPE")) return SIGFPE;
#endif
#ifdef SIGHUP
	if (!strcmp(str, "SIGHUP")) return SIGHUP;
#endif
#ifdef SIGILL
	if (!strcmp(str, "SIGILL")) return SIGILL;
#endif
#ifdef SIGINFO
	if (!strcmp(str, "SIGINFO")) return SIGINFO;
#endif
#ifdef SIGINT
	if (!strcmp(str, "SIGINT")) return SIGINT;
#endif
#ifdef SIGIO
	if (!strcmp(str, "SIGIO")) return SIGIO;
#endif
#ifdef SIGIOT
	if (!strcmp(str, "SIGIOT")) return SIGIOT;
#endif
#ifdef SIGKILL
	if (!strcmp(str, "SIGKILL")) return SIGKILL;
#endif
#ifdef SIGLOST
	if (!strcmp(str, "SIGLOST")) return SIGLOST;
#endif
#ifdef SIGPIPE
	if (!strcmp(str, "SIGPIPE")) return SIGPIPE;
#endif
#ifdef SIGPOLL
	if (!strcmp(str, "SIGPOLL")) return SIGPOLL;
#endif
#ifdef SIGPROF
	if (!strcmp(str, "SIGPROF")) return SIGPROF;
#endif
#ifdef SIGPWR
	if (!strcmp(str, "SIGPWR")) return SIGPWR;
#endif
#ifdef SIGQUIT
	if (!strcmp(str, "SIGQUIT")) return SIGQUIT;
#endif
#ifdef SIGSEGV
	if (!strcmp(str, "SIGSEGV")) return SIGSEGV;
#endif
#ifdef SIGSTKFLT
	if (!strcmp(str, "SIGSTKFLT")) return SIGSTKFLT;
#endif
#ifdef SIGSTOP
	if (!strcmp(str, "SIGSTOP")) return SIGSTOP;
#endif
#ifdef SIGTSTP
	if (!strcmp(str, "SIGTSTP")) return SIGTSTP;
#endif
#ifdef SIGSYS
	if (!strcmp(str, "SIGSYS")) return SIGSYS;
#endif
#ifdef SIGTERM
	if (!strcmp(str, "SIGTERM")) return SIGTERM;
#endif
#ifdef SIGTRAP
	if (!strcmp(str, "SIGTRAP")) return SIGTRAP;
#endif
#ifdef SIGTTIN
	if (!strcmp(str, "SIGTTIN")) return SIGTTIN;
#endif
#ifdef SIGTTOU
	if (!strcmp(str, "SIGTTOU")) return SIGTTOU;
#endif
#ifdef SIGUNUSED
	if (!strcmp(str, "SIGUNUSED")) return SIGUNUSED;
#endif
#ifdef SIGURG
	if (!strcmp(str, "SIGURG")) return SIGURG;
#endif
#ifdef SIGUSR1
	if (!strcmp(str, "SIGUSR1")) return SIGUSR1;
#endif
#ifdef SIGUSR2
	if (!strcmp(str, "SIGUSR2")) return SIGUSR2;
#endif
#ifdef SIGVTALRM
	if (!strcmp(str, "SIGVTALRM")) return SIGVTALRM;
#endif
#ifdef SIGWINCH
	if (!strcmp(str, "SIGWINCH")) return SIGWINCH;
#endif
#ifdef SIGXCPU
	if (!strcmp(str, "SIGXCPU")) return SIGXCPU;
#endif
#ifdef SIGXFSZ
	if (!strcmp(str, "SIGXFSZ")) return SIGXFSZ;
#endif
#if defined(SIGRTMIN) && defined(SIGRTMAX)
	if (!strncmp(str, "SIGRT", 5) && str[5]) {
		char *endptr;
		unsigned long num = strtoul(str + 5, &endptr, 10);
		if (unlikely(*endptr))
			return 0;
		num += SIGRTMIN;
		if (unlikely(num < (unsigned long)SIGRTMIN) || unlikely(num > (unsigned long)SIGRTMAX))
			return 0;
		return num;
	}
#endif
	return 0;
}

int os_signal_handle(const char *str, signal_seq_t *seq, ajla_error_t *err)
{
	struct signal_state *s;
	int sig = os_signal_number(str);
	if (unlikely(!sig)) {
		*seq = 0;
		return 0;
	}
	mutex_lock(&signal_state_mutex);
	s = &signal_states[sig];
	if (unlikely(s->trapped)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "signal %s already handled", str);
		goto unlock_err;
	}
	if (likely(!s->refcount)) {
		struct sigaction sa;
		int r;

		s->sig_sequence = 0;
		s->last_sig_sequence = 0;

		(void)memset(&sa, 0, sizeof sa);
		sa.sa_handler = signal_handler;
		sigemptyset(&sa.sa_mask);
#ifdef SA_RESTART
		if (sig != SIGTTIN && sig != SIGTTOU)
			sa.sa_flags |= SA_RESTART;
#endif
		EINTR_LOOP(r, sigaction(sig, &sa, &s->prev_sa));
		if (unlikely(r == -1)) {
			ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
			fatal_mayfail(e, err, "sigaction(%d) failed: %s", sig, error_decode(e));
			goto unlock_err;
		}
	}
	s->refcount++;
	*seq = s->last_sig_sequence;
	mutex_unlock(&signal_state_mutex);
	return sig;

unlock_err:
	mutex_unlock(&signal_state_mutex);
	return -1;
}

static void os_signal_restore(struct signal_state *s, int sig)
{
	int r;
	EINTR_LOOP(r, sigaction(sig, &s->prev_sa, NULL));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal("sigaction(%d) failed: %s", sig, error_decode(e));
	}
}

void os_signal_unhandle(int sig)
{
	struct signal_state *s;
	if (unlikely(!sig))
		return;
	mutex_lock(&signal_state_mutex);
	s = &signal_states[sig];
	if (!s->refcount)
		internal(file_line, "os_signal_unhandle: refcount underflow");
	s->refcount--;
	if (!s->refcount)
		os_signal_restore(s, sig);
	mutex_unlock(&signal_state_mutex);
}

signal_seq_t os_signal_seq(int sig)
{
	struct signal_state *s;
	signal_seq_t seq;
	if (unlikely(!sig))
		return 0;
	mutex_lock(&signal_state_mutex);
	s = &signal_states[sig];
	if (unlikely(!s))
		internal(file_line, "os_signal_unhandle: unhandled signal");
	seq = s->last_sig_sequence;
	mutex_unlock(&signal_state_mutex);
	return seq;
}

bool os_signal_wait(int sig, signal_seq_t seq, mutex_t **mutex_to_lock, struct list *list_entry)
{
	struct signal_state *s;

	if (unlikely(!sig)) {
		iomux_never(mutex_to_lock, list_entry);
		return true;
	}

	mutex_lock(&signal_state_mutex);
	s = &signal_states[sig];
	if (unlikely(seq != s->last_sig_sequence)) {
		mutex_unlock(&signal_state_mutex);
		return false;
	}
	*mutex_to_lock = &signal_state_mutex;
	list_add(&s->wait_list, list_entry);
	mutex_unlock(&signal_state_mutex);

	return true;
}

void os_signal_check_all(void)
{
	int sig = 0;
again:
	mutex_lock(&signal_state_mutex);
	for (; sig < N_SIGNALS; sig++) {
		struct signal_state *s = &signal_states[sig];
		signal_seq_t seq = s->sig_sequence;
		if (unlikely(seq != s->last_sig_sequence)) {
			s->last_sig_sequence = seq;
			call(wake_up_wait_list)(&s->wait_list, &signal_state_mutex, true);
			sig++;
			goto again;
		}
	}
	mutex_unlock(&signal_state_mutex);
}

#ifdef HAVE_CODEGEN_TRAPS

void *u_data_trap_lookup(void *ptr);
void *c_data_trap_lookup(void *ptr);

static void sigfpe_handler(int attr_unused sig, siginfo_t *siginfo, void *ucontext)
{
	ucontext_t *uc = ucontext;
#if defined(ARCH_ALPHA)
	if (unlikely(siginfo->si_code != FPE_FLTINV))
		fatal("unexpected SIGFPE received: %d", siginfo->si_code);
	uc->uc_mcontext.sc_pc = ptr_to_num(call(data_trap_lookup)(num_to_ptr(uc->uc_mcontext.sc_pc)));
#endif
#if defined(ARCH_MIPS)
	if (unlikely(siginfo->si_code != FPE_INTOVF))
		fatal("unexpected SIGFPE received: %d", siginfo->si_code);
	uc->uc_mcontext.pc = ptr_to_num(call(data_trap_lookup)(num_to_ptr(uc->uc_mcontext.pc)));
#endif
}

#endif

#ifdef SA_SIGINFO
void os_signal_trap(int sig, void (*handler)(int, siginfo_t *, void *))
{
	if (OS_SUPPORTS_TRAPS) {
		struct signal_state *s = &signal_states[sig];
		struct sigaction sa;
		int r;

		s->trapped = true;

		(void)memset(&sa, 0, sizeof sa);
		sa.sa_sigaction = handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags |= SA_SIGINFO;
		EINTR_LOOP(r, sigaction(sig, &sa, &s->prev_sa));
		if (unlikely(r == -1)) {
			ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
			fatal("sigaction(%d) failed: %s", sig, error_decode(e));
		}
	}
}
void os_signal_untrap(int sig)
{
	if (OS_SUPPORTS_TRAPS) {
		struct signal_state *s = &signal_states[sig];
		ajla_assert_lo(s->trapped, (file_line, "os_signal_untrap: signal %d not trapped", sig));
		os_signal_restore(s, sig);
		s->trapped = false;
	}
}
#endif

#else

int os_signal_handle(const char attr_unused *str, signal_seq_t attr_unused *seq, ajla_error_t attr_unused *err)
{
	*seq = NULL;
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

void os_signal_check_all(void)
{
}

#endif


#ifdef HAVE_NETWORK

handle_t os_socket(int domain, int type, int protocol, ajla_error_t *err)
{
	int r, h;
	domain = os_socket_pf(domain, err);
	if (unlikely(domain == -1))
		return -1;
	type = os_socket_type(type, err);
	if (unlikely(type == -1))
		return -1;
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
	EINTR_LOOP(h, socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol));
	if (likely(h != -1)) {
		obj_registry_insert(OBJ_TYPE_HANDLE, h, file_line);
		return h;
	}
	if (errno != EINVAL) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't create socket (%d, %d, %d): %s", domain, type, protocol, error_decode(e));
		return -1;
	}
#endif
	os_lock_fork(false);
	EINTR_LOOP(h, socket(domain, type, protocol));
	if (unlikely(h == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		os_unlock_fork(false);
		fatal_mayfail(e, err, "can't create socket (%d, %d, %d): %s", domain, type, protocol, error_decode(e));
		return -1;
	}
	os_set_cloexec(h);
	os_unlock_fork(false);
	obj_registry_insert(OBJ_TYPE_HANDLE, h, file_line);
	EINTR_LOOP(r, fcntl(h, F_SETFL, O_NONBLOCK));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("fcntl(F_SETFL, O_NONBLOCK) on a socket failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	return h;
}

bool os_bind_connect(bool bnd, handle_t h, unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	int r;
	struct sockaddr *sa;
	ajla_error_t e;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
	sa = os_get_sock_addr(addr, &addr_len, err);
	if (unlikely(!sa))
		return false;
	if (likely(!bnd))
		EINTR_LOOP(r, connect(h, sa, addr_len));
	else
		EINTR_LOOP(r, bind(h, sa, addr_len));
	mem_free_aligned(sa);
	if (unlikely(!r))
		return true;
	if (likely(!bnd) && likely(errno == EINPROGRESS))
		return true;
	e = error_from_errno(EC_SYSCALL, errno);
	fatal_mayfail(e, err, "can't %s socket: %s", !bnd ? "connect" : "bind", error_decode(e));
	return false;
}

bool os_connect_completed(handle_t h, ajla_error_t *err)
{
	ajla_error_t e;
	int r;
	int er;
	socklen_t er_l;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
	er_l = sizeof er;
	EINTR_LOOP(r, getsockopt(h, SOL_SOCKET, SO_ERROR, &er, &er_l));
	if (unlikely(r == -1)) {
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "getsockopt returned an error: %s", error_decode(e));
		return false;
	}
	if (unlikely(er)) {
		e = error_from_errno(EC_SYSCALL, er);
		fatal_mayfail(e, err, "can't connect socket: %s", error_decode(e));
		return false;
	}
	return true;
}

bool os_listen(handle_t h, ajla_error_t *err)
{
	int r;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
	EINTR_LOOP(r, listen(h, signed_maximum(int)));
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "listen returned an error: %s", error_decode(e));
		return false;
	}
	return true;
}

int os_accept(handle_t h, handle_t *result, ajla_error_t *err)
{
	int r;
	ajla_error_t e;
	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);
#ifdef HAVE_ACCEPT4
	EINTR_LOOP(r, accept4(h, NULL, 0, SOCK_NONBLOCK | SOCK_CLOEXEC));
	if (likely(r != -1)) {
		*result = r;
		obj_registry_insert(OBJ_TYPE_HANDLE, r, file_line);
		return 0;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return OS_RW_WOULDBLOCK;
	if (errno != ENOSYS) {
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "accept returned an error: %s", error_decode(e));
		return OS_RW_ERROR;
	}
#endif
	os_lock_fork(false);
	EINTR_LOOP(r, accept(h, NULL, 0));
	if (unlikely(r == -1)) {
		os_unlock_fork(false);
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return OS_RW_WOULDBLOCK;
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "accept returned an error: %s", error_decode(e));
		return OS_RW_ERROR;
	}
	os_set_cloexec(r);
	os_unlock_fork(false);
	*result = r;
	obj_registry_insert(OBJ_TYPE_HANDLE, r, file_line);
	EINTR_LOOP(r, fcntl(r, F_SETFL, O_NONBLOCK));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("fcntl(F_SETFL, O_NONBLOCK) on a socket failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	return 0;
}

bool os_getsockpeername(bool peer, handle_t h, unsigned char **addr, size_t *addr_len, ajla_error_t *err)
{
	int r;
	struct sockaddr *sa;
	socklen_t addrlen;

	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);

	sa = mem_align_mayfail(struct sockaddr *, SOCKADDR_MAX_LEN, SOCKADDR_ALIGN, err);
	if (unlikely(!sa))
		return false;
	addrlen = SOCKADDR_MAX_LEN;

	if (!peer) {
		EINTR_LOOP(r, getsockname(h, sa, &addrlen));
	} else {
#ifdef HAVE_GETPEERNAME
		EINTR_LOOP(r, getpeername(h, sa, &addrlen));
#else
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "getpeername not supported");
		goto free_ret_false;
#endif
	}
	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "%s returned an error: %s", !peer ? "getsockname" : "getpeername", error_decode(e));
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
	struct sockaddr *sa;
	socklen_t addrlen;
	ssize_t r;
	int f;

	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);

	f = translate_flags(os_socket_msg, flags, err);
	if (unlikely(f < 0))
		return OS_RW_ERROR;

	sa = mem_align_mayfail(struct sockaddr *, SOCKADDR_MAX_LEN, SOCKADDR_ALIGN, err);
	if (unlikely(!sa))
		return OS_RW_ERROR;
	addrlen = SOCKADDR_MAX_LEN;

	EINTR_LOOP(r, recvfrom(h, buffer, len, f, sa, &addrlen));

	if (r >= 0) {
		if (unlikely(addrlen > SOCKADDR_MAX_LEN)) {
			fatal_mayfail(error_ajla(EC_SYSCALL, AJLA_ERROR_SIZE_OVERFLOW), err, "the system returned too long address");
			mem_free_aligned(sa);
			return OS_RW_ERROR;
		}
		if (!addrlen) {
			if (unlikely(!array_init_mayfail(unsigned char, addr, addr_len, err))) {
				mem_free_aligned(sa);
				return OS_RW_ERROR;
			}
		} else {
			*addr = os_get_ajla_addr(sa, &addrlen, err);
			if (unlikely(!*addr)) {
				mem_free_aligned(sa);
				return OS_RW_ERROR;
			}
			*addr_len = addrlen;
		}
	}
	mem_free_aligned(sa);
	return os_rdwr_return(r, "receiving", err);
}

ssize_t os_sendto(handle_t h, const char *buffer, size_t len, int flags, unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	struct sockaddr *sa;
	ssize_t r;
	int f;

	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);

	f = translate_flags(os_socket_msg, flags, err);
	if (unlikely(f < 0))
		return OS_RW_ERROR;

	if (addr_len != 0) {
		sa = os_get_sock_addr(addr, &addr_len, err);
		if (unlikely(!sa))
			return OS_RW_ERROR;
		EINTR_LOOP(r, sendto(h, buffer, len, f, sa, addr_len));
		mem_free_aligned(sa);
	} else {
		EINTR_LOOP(r, send(h, buffer, len, f));
	}

	return os_rdwr_return(r, "sending", err);
}

bool os_getsockopt(handle_t h, int level, int option, char **buffer, size_t *buffer_len, ajla_error_t *err)
{
	int r;
	socklen_t opt_len;

	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);

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

	EINTR_LOOP(r, getsockopt(h, level, option, *buffer, &opt_len));

	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "getsockopt returned an error: %s", error_decode(e));
		mem_free(*buffer);
		return false;
	}

	*buffer_len = opt_len;
	return true;
}

bool os_setsockopt(handle_t h, int level, int option, const char *buffer, size_t buffer_len, ajla_error_t *err)
{
	int r;

	obj_registry_verify(OBJ_TYPE_HANDLE, h, file_line);

	level = os_socket_level(level, err);
	if (unlikely(level < 0))
		return false;

	option = os_socket_option(option, err);
	if (unlikely(level < 0))
		return false;

	EINTR_LOOP(r, setsockopt(h, level, option, buffer, buffer_len));

	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "setsockopt returned an error: %s", error_decode(e));
		return false;
	}

	return true;
}

#ifdef HAVE_GETADDRINFO
bool os_getaddrinfo(const char *host, int port, struct address **result, size_t *result_l, ajla_error_t *err)
{
	char port_str[6];
	int r;
	size_t i;
	struct addrinfo *res = NULL, *rs;

	if (unlikely(!array_init_mayfail(struct address, result, result_l, err)))
		return false;

	snprintf(port_str, sizeof port_str, "%d", port);
	r = getaddrinfo(host, port_str, NULL, &res);
	if (unlikely(r)) {
		if (unlikely(r == EAI_SYSTEM))
			fatal_mayfail(error_from_errno(EC_SYSCALL, errno), err, "host not found");
		else
			fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_GAI, abs((int)r)), err, "host not found");
		goto fail;
	}

	for (rs = res; rs; rs = rs->ai_next) {
		void *xresult;
		struct address addr;
		ajla_error_t e;
		socklen_t addrlen = rs->ai_addrlen;

		memset(&addr.entry, 0, sizeof addr.entry);		/* avoid warning */

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

	freeaddrinfo(res);
	return true;

fail:
	if (res)
		freeaddrinfo(res);
	for (i = 0; i < *result_l; i++)
		mem_free((*result)[i].address);
	mem_free(*result);
	return false;
}
#else
#ifndef NO_DATA
#define NO_DATA		1
#endif
#ifndef HAVE_H_ERRNO
#define h_errno		1
#endif
bool os_getaddrinfo(const char *host, int port, struct address **result, size_t *result_l, ajla_error_t *err)
{
	struct hostent *he;
	size_t i;
	void *xresult;
	char *a;

	if (unlikely(!array_init_mayfail(struct address, result, result_l, err)))
		return false;

	he = gethostbyname(host);

	if (unlikely(!he)) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_H_ERRNO, h_errno), err, "host not found");
		goto fail;
	}

	if (he->h_addrtype != AF_INET || he->h_length != 4 || !he->h_addr) {
		fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_H_ERRNO, NO_DATA), err, "host not found");
		goto fail;
	}

#ifdef h_addr
	for (i = 0; (a = he->h_addr_list[i]); i++)
#else
	a = he->h_addr;
#endif
	{
		struct sockaddr_in sin;
		struct sockaddr sa;
		struct address addr;
		ajla_error_t e;
		socklen_t addrlen = sizeof sin;

		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
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
#endif

#ifdef HAVE_GETNAMEINFO
char *os_getnameinfo(unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	struct sockaddr *sa;
	int r;
	char *h;
	size_t h_len;
	sa = os_get_sock_addr(addr, &addr_len, err);
	if (unlikely(!sa))
		return NULL;
#ifdef EAI_OVERFLOW
	h_len = 64;
alloc_buffer_again:
#else
	h_len = NI_MAXHOST;
#endif
	h = mem_alloc_mayfail(char *, h_len, err);
	if (unlikely(!h)) {
		mem_free_aligned(sa);
		return NULL;
	}
	r = getnameinfo(sa, addr_len, h, h_len, NULL, 0, 0);
	if (unlikely(r)) {
#ifdef EAI_OVERFLOW
		if (unlikely(r == EAI_OVERFLOW)) {
			mem_free(h);
			h_len *= 2;
			if (unlikely(!h_len)) {
				fatal_mayfail(error_ajla(EC_SYSCALL, AJLA_ERROR_SIZE_OVERFLOW), err, "name buffer overflow");
				mem_free_aligned(sa);
				return NULL;
			}
			goto alloc_buffer_again;
		}
#endif
		if (unlikely(r == EAI_SYSTEM)) {
			fatal_mayfail(error_from_errno(EC_SYSCALL, errno), err, "host not found");
		} else {
			fatal_mayfail(error_ajla_aux(EC_SYSCALL, AJLA_ERROR_GAI, abs((int)r)), err, "host not found");
		}
		mem_free(h);
		mem_free_aligned(sa);
		return NULL;
	}
	mem_free_aligned(sa);
	return h;
}
#elif defined(HAVE_GETHOSTBYADDR)
char *os_getnameinfo(unsigned char *addr, size_t addr_len, ajla_error_t *err)
{
	struct sockaddr *sa;
	struct hostent *he;
	char *name;
	size_t le;
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
			he = gethostbyaddr(cast_ptr(void *, &sin->sin_addr.s_addr), 4, sa->sa_family);
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
#else
char *os_getnameinfo(unsigned char attr_unused *addr, size_t attr_unused addr_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "getnameinfo not supported");
	return NULL;
}
#endif

#else

handle_t os_socket(int attr_unused domain, int attr_unused type, int attr_unused protocol, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return -1;
}

bool os_bind_connect(bool attr_unused bnd, handle_t attr_unused h, unsigned char attr_unused *addr, size_t attr_unused addr_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

bool os_connect_completed(handle_t attr_unused h, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

bool os_listen(handle_t attr_unused h, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

int os_accept(handle_t attr_unused h, handle_t attr_unused *result, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return OS_RW_ERROR;
}

bool os_getsockpeername(bool attr_unused peer, handle_t attr_unused h, unsigned char attr_unused **addr, size_t attr_unused *addr_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

ssize_t os_recvfrom(handle_t attr_unused h, char attr_unused *buffer, size_t attr_unused len, int attr_unused flags, unsigned char attr_unused **addr, size_t attr_unused *addr_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return OS_RW_ERROR;
}

ssize_t os_sendto(handle_t attr_unused h, const char attr_unused *buffer, size_t attr_unused len, int attr_unused flags, unsigned char attr_unused *addr, size_t attr_unused addr_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

bool os_getsockopt(handle_t attr_unused h, int attr_unused level, int attr_unused option, char attr_unused **buffer, size_t attr_unused *buffer_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

bool os_setsockopt(handle_t attr_unused h, int attr_unused level, int attr_unused option, const char attr_unused *buffer, size_t attr_unused buffer_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

bool os_getaddrinfo(const char attr_unused *host, int attr_unused port, struct address attr_unused **result, size_t attr_unused *result_l, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return false;
}

char *os_getnameinfo(unsigned char attr_unused *addr, size_t attr_unused addr_len, ajla_error_t *err)
{
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), err, "sockets not supported");
	return NULL;
}

#endif


const char *os_decode_error(ajla_error_t error, char attr_unused *(*tls_buffer)(void))
{
	switch (error.error_type) {
#if defined(HAVE_NETWORK) && defined(HAVE_GETADDRINFO)
		case AJLA_ERROR_GAI: {
			return gai_strerror(error.error_aux * (EAI_NONAME < 0 ? -1 : 1));
		}
#else
		case AJLA_ERROR_H_ERRNO: {
#if defined(HAVE_NETWORK) && defined(HAVE_HSTRERROR)
			return hstrerror(error.error_aux);
#else
			return "Unknown host";
#endif
		}
#endif
	}
	return NULL;
}


#ifdef OS_HAS_DLOPEN
struct dl_handle_t *os_dlopen(const char *filename, ajla_error_t *err, char **err_msg)
{
	struct dl_handle_t *dlh;
	dlh = dlopen(filename, RTLD_LAZY);
	if (unlikely(!dlh)) {
		ajla_error_t e;
		*err_msg = dlerror();
		e = error_ajla(EC_SYNC, AJLA_ERROR_LIBRARY_NOT_FOUND);
		fatal_mayfail(e, err, "can't open dynamic library '%s': %s", filename, *err_msg);
		return NULL;
	}
	return dlh;
}

void os_dlclose(struct dl_handle_t *dlh)
{
	int r = dlclose(dlh);
#if defined(OS_CYGWIN)
	/* dlclose fails if we attempt to unload non-cygwin dll */
	if (unlikely(r == -1) && errno == ENOENT)
		return;
#endif
	if (unlikely(r))
		internal(file_line, "dlclose failed: %s", dlerror());
}

bool os_dlsym(struct dl_handle_t *dlh, const char *symbol, void **result)
{
	void *r;
	r = dlsym(dlh, symbol);
	if (unlikely(!r))
		return false;
	*result = r;
	return true;
}
#endif


#ifdef OS_HAVE_NOTIFY_PIPE
handle_t os_notify_pipe[2];

void os_notify(void)
{
	int r;
	char c = 0;
	EINTR_LOOP(r, write(os_notify_pipe[1], &c, 1));
	if (unlikely(r == -1)) {
		int er = errno;
		if (unlikely(er != EAGAIN) && unlikely(er != EWOULDBLOCK) && unlikely(er != EBADF)) {
			fatal("error writing to the notify pipe: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	}
}

bool os_drain_notify_pipe(void)
{
	static char buffer[1024];
	int r;
	EINTR_LOOP(r, read(os_notify_pipe[0], buffer, sizeof(buffer)));
	if (likely(r == -1)) {
		int er = errno;
		if (unlikely(er != EAGAIN) && unlikely(er != EWOULDBLOCK)) {
			fatal("error reading the notify pipe: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	}
	return !r;
}

void os_shutdown_notify_pipe(void)
{
	int r;
	EINTR_LOOP(r, dup2(os_notify_pipe[0], os_notify_pipe[1]));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("error shutting down the notify pipe: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
#ifdef DEBUG
	os_notify();
#endif
}
#endif


#if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)

const char *os_get_flavor(void)
{
#if defined(OS_DOS)
	return "DOS";
#elif defined(OS_CYGWIN)
	return "Cygwin";
#else
	return "Unix";
#endif
}

void os_get_uname(os_utsname_t *un)
{
	int r;
	EINTR_LOOP(r, uname(un));
	if (unlikely(r == -1)) {
		int er = errno;
		fatal("uname returned error: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
	}
	if (sizeof un->sysname >= 10 && likely(!strcmp(un->sysname, "Linux")))
		strcpy(un->sysname, "GNU/Linux");	/* make RMS happy */
}

bool os_kernel_version(const char *sys, const char *vers)
{
	static os_utsname_t un;
	static bool have_un = false;
	const char *last_comp, *ptr_sys, *ptr_wanted;
	if (!have_un) {
		os_get_uname(&un);
		have_un = true;
	}
	if (unlikely(strcmp(sys, un.sysname)))
		return false;
	last_comp = strrchr(vers, '.');
	if (last_comp)
		last_comp++;
	else
		last_comp = vers;
	if (strncmp(un.release, vers, last_comp - vers))
		return false;
	ptr_sys = un.release + (last_comp - vers);
	ptr_wanted = vers + (last_comp - vers);
	if (!*ptr_wanted)
		return true;
	if (likely(*ptr_sys >= '0') && likely(*ptr_sys <= '9')) {
		if (atoi(ptr_sys) >= atoi(ptr_wanted)) {
			return true;
		}
	}
	return false;
}

#else

void os_get_uname(os_utsname_t *un)
{
	memset(un, 0, sizeof(os_utsname_t));
	strcpy(un->sysname, "Posix");
#ifdef ARCH_NAME
	strcpy(un->machine, ARCH_NAME);
#endif
}

bool os_kernel_version(const char attr_unused *sys, const char attr_unused *vers)
{
	return false;
}

#endif

char *os_get_host_name(ajla_error_t *err)
{
#ifdef HAVE_GETHOSTNAME
	size_t s = 128;
	char *hn;
	int r;

try_more:
	s *= 2;
	if (unlikely(!s)) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "overflow when allocating host name");
		return NULL;
	}
	hn = mem_alloc_mayfail(char *, s, err);
	if (unlikely(!hn))
		return NULL;

	EINTR_LOOP(r, gethostname(hn, s));

	if (unlikely(r == -1)) {
		ajla_error_t e = error_from_errno(EC_SYSCALL, errno);
		mem_free(hn);
		if (errno == EINVAL || errno == ENAMETOOLONG)
			goto try_more;
		fatal_mayfail(e, err, "can't get hostname: %s", error_decode(e));
		return NULL;
	}

	if (unlikely(strnlen(hn, s) >= s - 1)) {
		mem_free(hn);
		goto try_more;
	}

	return hn;
#else
	char *e = getenv("HOSTNAME");
	if (!e)
		e = "";
	return str_dup(e, -1, err);
#endif
}

void os_init(void)
{
	ajla_error_t sink;
	int r, i;

#if defined(OS_DOS)
	EINTR_LOOP(r, close(3));
	EINTR_LOOP(r, close(4));
#endif

	n_std_handles = 0;
	while (1) {
		struct stat st;
		EINTR_LOOP(r, fstat(n_std_handles, &st));
		if (r)
			break;
		n_std_handles++;
	}
	if (unlikely(n_std_handles < 3))
		exit(127);

#ifdef HAVE_AT_FUNCTIONS
	if (os_kernel_version("GNU/Linux", "3") ||
	    os_kernel_version("GNU/Linux", "2.6.23")) {
		have_O_CLOEXEC_openat = true;
	} else {
		int h, r;
		int flags;
		os_stat_t st;
		EINTR_LOOP(r, fstatat(AT_FDCWD, "/", &st, AT_SYMLINK_NOFOLLOW));
		if (unlikely(r == -1))
			goto skip_test;

		EINTR_LOOP(h, openat(AT_FDCWD, "/dev/null", O_RDONLY | O_CLOEXEC));
		if (unlikely(h == -1))
			goto skip_test;

		EINTR_LOOP(flags, fcntl(h, F_GETFD));
		if (likely(flags >= 0) && likely(flags & FD_CLOEXEC))
			have_O_CLOEXEC_openat = true;
		os_close_handle(h);
skip_test:;
	}
#endif

	os_cwd = os_get_cwd(&sink);
	if (unlikely(dir_handle_is_valid(os_cwd))) {
		os_set_original_cwd();
	} else {
		os_cwd = os_get_cwd(NULL);
	}

	os_init_path_to_exe();

#ifdef OS_HAVE_NOTIFY_PIPE
	os_pipe(os_notify_pipe, 3, NULL);
#endif

#ifdef OS_HAS_SIGNALS
	signal_states = mem_alloc_array_mayfail(mem_calloc_mayfail, struct signal_state *, 0, 0, N_SIGNALS, sizeof(struct signal_state), NULL);
	for (i = 0; i < N_SIGNALS; i++)
		list_init(&signal_states[i].wait_list);
	if (!dll) {
#ifdef HAVE_CODEGEN_TRAPS
		os_signal_trap(SIGFPE, sigfpe_handler);
#if defined(ARCH_MIPS)
		os_signal_trap(SIGTRAP, sigfpe_handler);
#endif
#endif
	}
#endif
}

void os_done(void)
{
#ifdef OS_HAS_SIGNALS
	int sig;
	if (!dll) {
#ifdef HAVE_CODEGEN_TRAPS
		os_signal_untrap(SIGFPE);
#if defined(ARCH_MIPS)
		os_signal_untrap(SIGTRAP);
#endif
#endif
	}
	for (sig = 0; sig < N_SIGNALS; sig++) {
		if (unlikely(signal_states[sig].trapped) || unlikely(signal_states[sig].refcount != 0))
			internal(file_line, "signal %d leaked", sig);
	}
	mem_free(signal_states);
	signal_states = NULL;
#endif

#ifdef OS_HAVE_NOTIFY_PIPE
	os_close(os_notify_pipe[0]);
	os_close(os_notify_pipe[1]);
#endif

	os_dir_close(os_cwd);

	mem_free(os_path_to_exe);
}

void os_init_multithreaded(void)
{
	unsigned u;

	os_init_calendar_lock();

	rwmutex_init(&fork_lock);
	os_threads_initialized = true;

#if !defined(OS_DOS)
	tree_init(&proc_tree);
	mutex_init(&proc_tree_mutex);
#endif

#ifdef OS_HAS_SIGNALS
	mutex_init(&signal_state_mutex);
#endif

	for (u = 0; u < n_std_handles; u++)
		obj_registry_insert(OBJ_TYPE_HANDLE, u, file_line);
#ifdef OS_DOS
	dos_init();
#endif
}

void os_done_multithreaded(void)
{
	unsigned u;
#ifdef OS_DOS
	dos_done();
#endif

	for (u = 0; u < n_std_handles; u++)
		obj_registry_remove(OBJ_TYPE_HANDLE, u, file_line);

#ifdef OS_HAS_SIGNALS
	mutex_done(&signal_state_mutex);
#endif

#if !defined(OS_DOS)
	if (unlikely(!tree_is_empty(&proc_tree))) {
		struct proc_handle *ph = get_struct(tree_any(&proc_tree), struct proc_handle, entry);
		tree_delete(&ph->entry);
		proc_handle_free(ph);
	}
	mutex_done(&proc_tree_mutex);
#endif

	os_threads_initialized = false;
	rwmutex_done(&fork_lock);

	os_done_calendar_lock();
}

#endif
