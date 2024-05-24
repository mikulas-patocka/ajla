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

static const char * const error_codes[] = {
	"Unknown error",
	"Out of memory",
	"Allocation size overflow",
	"Integer is too large",
	"Number doesn't fit",
	"Invalid operation",
	"Operation not supported",
	"Negative index",
	"Index out of range",
	"Option doesn't match",
	"Record field not initialized",
	"Array entry not initialized",
	"Not found",
	"Non-absolute path",
	"Abort",
	"Floating-point NaN",
	"Floating-point infinity",
	"System returned invalid data",
	"Compiler error",
	"Optimizer error",
	"System error",
	"Syscall error",
	"OS/2 error",
	"OS/2 socket error",
	"Win32 error",
	"Gethostbyname error",
	"Getaddrinfo error",
	"Subprocess error",
	"Library not found",
	"Symbol not found",
	"Exit",
	"User error",
	"User error 2",
	"User error 3",
};

static const char * const system_error_codes[] = {
	"Operation not permitted",
	"No such file or directory",
	"No such process",
	"Interrupted system call",
	"I/O error",
	"No such device or address",
	"Argument list too long",
	"Exec format error",
	"Bad file number",
	"No child processes",
	"Try again",
	"Out of memory",
	"Permission denied",
	"Bad address",
	"Block device required",
	"Device or resource busy",
	"File exists",
	"Cross-device link",
	"No such device",
	"Not a directory",
	"Is a directory",
	"Invalid argument",
	"File table overflow",
	"Too many open files",
	"Not a typewriter",
	"Text file busy",
	"File too large",
	"No space left on device",
	"Illegal seek",
	"Read-only file system",
	"Too many links",
	"Broken pipe",
	"Math argument out of domain of func",
	"Math result not representable",
	"Resource deadlock would occur",
	"File name too long",
	"No record locks available",
	"Invalid system call number",
	"Directory not empty",
	"Too many symbolic links encountered",
	"No message of desired type",
	"Identifier removed",
	"Channel number out of range",
	"Level 2 not synchronized",
	"Level 3 halted",
	"Level 3 reset",
	"Link number out of range",
	"Protocol driver not attached",
	"No CSI structure available",
	"Level 2 halted",
	"Invalid exchange",
	"Invalid request descriptor",
	"Exchange full",
	"No anode",
	"Invalid request code",
	"Invalid slot",
	"Bad font file format",
	"Device not a stream",
	"No data available",
	"Timer expired",
	"Out of streams resources",
	"Machine is not on the network",
	"Package not installed",
	"Object is remote",
	"Link has been severed",
	"Advertise error",
	"Srmount error",
	"Communication error on send",
	"Protocol error",
	"Multihop attempted",
	"RFS specific error",
	"Not a data message",
	"Value too large for defined data type",
	"Name not unique on network",
	"File descriptor in bad state",
	"Remote address changed",
	"Can not access a needed shared library",
	"Accessing a corrupted shared library",
	".lib section in a.out corrupted",
	"Attempting to link in too many shared libraries",
	"Cannot exec a shared library directly",
	"Illegal byte sequence",
	"Interrupted system call should be restarted",
	"Streams pipe error",
	"Too many users",
	"Socket operation on non-socket",
	"Destination address required",
	"Message too long",
	"Protocol wrong type for socket",
	"Protocol not available",
	"Protocol not supported",
	"Socket type not supported",
	"Operation not supported on transport endpoint",
	"Protocol family not supported",
	"Address family not supported by protocol",
	"Address already in use",
	"Cannot assign requested address",
	"Network is down",
	"Network is unreachable",
	"Network dropped connection because of reset",
	"Software caused connection abort",
	"Connection reset by peer",
	"No buffer space available",
	"Transport endpoint is already connected",
	"Transport endpoint is not connected",
	"Cannot send after transport endpoint shutdown",
	"Too many references: cannot splice",
	"Connection timed out",
	"Connection refused",
	"Host is down",
	"No route to host",
	"Operation already in progress",
	"Operation now in progress",
	"Stale file handle",
	"Structure needs cleaning",
	"Not a XENIX named type file",
	"No XENIX semaphores available",
	"Is a named type file",
	"Remote I/O error",
	"Quota exceeded",
	"No medium found",
	"Wrong medium type",
	"Operation Canceled",
	"Required key not available",
	"Key has expired",
	"Key has been revoked",
	"Key was rejected by service",
	"Owner died",
	"State not recoverable",
	"Operation not possible due to RF-kill",
	"Memory page has hardware error",
};

static const char attr_cold *error_ajla_decode(int error)
{
	if (likely(error >= AJLA_ERROR_BASE) && likely(error < AJLA_ERROR_N))
		return error_codes[error - AJLA_ERROR_BASE];
	return NULL;
}

void attr_cold trace(const char attr_unused *m, ...)
{
#ifdef DEBUG_TRACE
	va_list l;
	va_start(l, m);
	trace_v(m, l);
	va_end(l);
#endif
}

void attr_cold stderr_msg(const char *m, ...)
{
	va_list l;
	va_start(l, m);
	stderr_msg_v(m, l);
	va_end(l);
}

void attr_cold debug(const char *m, ...)
{
	va_list l;
	va_start(l, m);
	debug_v(m, l);
	va_end(l);
}

void attr_cold warning(const char *m, ...)
{
	va_list l;
	va_start(l, m);
	warning_v(m, l);
	va_end(l);
}

attr_noreturn attr_cold fatal(const char *m, ...)
{
	va_list l;
	va_start(l, m);
	fatal_v(m, l);
	va_end(l);
}

attr_noreturn attr_cold internal(const char *position, const char *m, ...)
{
	va_list l;
	va_start(l, m);
	internal_v(position, m, l);
	va_end(l);
}

void attr_cold attr_printf(3,4) fatal_mayfail(ajla_error_t e, ajla_error_t *mayfail, const char *m, ...)
{
	if (mayfail == MEM_DONT_TRY_TO_FREE)
		return;
	if (unlikely(!mayfail)) {
		va_list l;
		va_start(l, m);
		fatal_v(m, l);
		va_end(l);
		return;
	}
	*mayfail = e;
}

void attr_cold attr_printf(3,4) fatal_warning_mayfail(ajla_error_t e, ajla_error_t *mayfail, const char *m, ...)
{
	if (unlikely(!mayfail)) {
		va_list l;
		va_start(l, m);
		fatal_v(m, l);
		va_end(l);
		return;
	} else {
		va_list l;
		va_start(l, m);
		warning_v(m, l);
		va_end(l);
		if (mayfail != MEM_DONT_TRY_TO_FREE)
			*mayfail = e;
	}
}

struct system_error_table_entry {
	int errn;
	int sys_error;
};

static const struct system_error_table_entry errno_to_system_error[] = {
#ifdef EPERM
	{ EPERM,		SYSTEM_ERROR_EPERM },
#endif
#ifdef ENOENT
	{ ENOENT,		SYSTEM_ERROR_ENOENT },
#endif
#ifdef ESRCH
	{ ESRCH,		SYSTEM_ERROR_ESRCH },
#endif
#ifdef EINTR
	{ EINTR,		SYSTEM_ERROR_EINTR },
#endif
#ifdef EIO
	{ EIO,			SYSTEM_ERROR_EIO },
#endif
#ifdef ENXIO
	{ ENXIO,		SYSTEM_ERROR_ENXIO },
#endif
#ifdef E2BIG
	{ E2BIG,		SYSTEM_ERROR_E2BIG },
#endif
#ifdef ENOEXEC
	{ ENOEXEC,		SYSTEM_ERROR_ENOEXEC },
#endif
#ifdef EBADF
	{ EBADF,		SYSTEM_ERROR_EBADF },
#endif
#ifdef ECHILD
	{ ECHILD,		SYSTEM_ERROR_ECHILD },
#endif
#ifdef EAGAIN
	{ EAGAIN,		SYSTEM_ERROR_EAGAIN },
#endif
#ifdef ENOMEM
	{ ENOMEM,		SYSTEM_ERROR_ENOMEM },
#endif
#ifdef EACCES
	{ EACCES,		SYSTEM_ERROR_EACCES },
#endif
#ifdef EFAULT
	{ EFAULT,		SYSTEM_ERROR_EFAULT },
#endif
#ifdef ENOTBLK
	{ ENOTBLK,		SYSTEM_ERROR_ENOTBLK },
#endif
#ifdef EBUSY
	{ EBUSY,		SYSTEM_ERROR_EBUSY },
#endif
#ifdef EEXIST
	{ EEXIST,		SYSTEM_ERROR_EEXIST },
#endif
#ifdef EXDEV
	{ EXDEV,		SYSTEM_ERROR_EXDEV },
#endif
#ifdef ENODEV
	{ ENODEV,		SYSTEM_ERROR_ENODEV },
#endif
#ifdef ENOTDIR
	{ ENOTDIR,		SYSTEM_ERROR_ENOTDIR },
#endif
#ifdef EISDIR
	{ EISDIR,		SYSTEM_ERROR_EISDIR },
#endif
#ifdef EINVAL
	{ EINVAL,		SYSTEM_ERROR_EINVAL },
#endif
#ifdef ENFILE
	{ ENFILE,		SYSTEM_ERROR_ENFILE },
#endif
#ifdef EMFILE
	{ EMFILE,		SYSTEM_ERROR_EMFILE },
#endif
#ifdef ENOTTY
	{ ENOTTY,		SYSTEM_ERROR_ENOTTY },
#endif
#ifdef ETXTBSY
	{ ETXTBSY,		SYSTEM_ERROR_ETXTBSY },
#endif
#ifdef EFBIG
	{ EFBIG,		SYSTEM_ERROR_EFBIG },
#endif
#ifdef ENOSPC
	{ ENOSPC,		SYSTEM_ERROR_ENOSPC },
#endif
#ifdef ESPIPE
	{ ESPIPE,		SYSTEM_ERROR_ESPIPE },
#endif
#ifdef EROFS
	{ EROFS,		SYSTEM_ERROR_EROFS },
#endif
#ifdef EMLINK
	{ EMLINK,		SYSTEM_ERROR_EMLINK },
#endif
#ifdef EPIPE
	{ EPIPE,		SYSTEM_ERROR_EPIPE },
#endif
#ifdef EDOM
	{ EDOM,			SYSTEM_ERROR_EDOM },
#endif
#ifdef ERANGE
	{ ERANGE,		SYSTEM_ERROR_ERANGE },
#endif
#ifdef EDEADLK
	{ EDEADLK,		SYSTEM_ERROR_EDEADLK },
#endif
#ifdef ENAMETOOLONG
	{ ENAMETOOLONG,		SYSTEM_ERROR_ENAMETOOLONG },
#endif
#ifdef ENOLCK
	{ ENOLCK,		SYSTEM_ERROR_ENOLCK },
#endif
#ifdef ENOSYS
	{ ENOSYS,		SYSTEM_ERROR_ENOSYS },
#endif
#ifdef ENOTEMPTY
	{ ENOTEMPTY,		SYSTEM_ERROR_ENOTEMPTY },
#endif
#ifdef ELOOP
	{ ELOOP,		SYSTEM_ERROR_ELOOP },
#endif
#ifdef EWOULDBLOCK
	{ EWOULDBLOCK,		SYSTEM_ERROR_EAGAIN },
#endif
#ifdef ENOMSG
	{ ENOMSG,		SYSTEM_ERROR_ENOMSG },
#endif
#ifdef EIDRM
	{ EIDRM,		SYSTEM_ERROR_EIDRM },
#endif
#ifdef ECHRNG
	{ ECHRNG,		SYSTEM_ERROR_ECHRNG },
#endif
#ifdef EL2NSYNC
	{ EL2NSYNC,		SYSTEM_ERROR_EL2NSYNC },
#endif
#ifdef EL3HLT
	{ EL3HLT,		SYSTEM_ERROR_EL3HLT },
#endif
#ifdef EL3RST
	{ EL3RST,		SYSTEM_ERROR_EL3RST },
#endif
#ifdef ELNRNG
	{ ELNRNG,		SYSTEM_ERROR_ELNRNG },
#endif
#ifdef EUNATCH
	{ EUNATCH,		SYSTEM_ERROR_EUNATCH },
#endif
#ifdef ENOCSI
	{ ENOCSI,		SYSTEM_ERROR_ENOCSI },
#endif
#ifdef EL2HLT
	{ EL2HLT,		SYSTEM_ERROR_EL2HLT },
#endif
#ifdef EBADE
	{ EBADE,		SYSTEM_ERROR_EBADE },
#endif
#ifdef EBADR
	{ EBADR,		SYSTEM_ERROR_EBADR },
#endif
#ifdef EXFULL
	{ EXFULL,		SYSTEM_ERROR_EXFULL },
#endif
#ifdef ENOANO
	{ ENOANO,		SYSTEM_ERROR_ENOANO },
#endif
#ifdef EBADRQC
	{ EBADRQC,		SYSTEM_ERROR_EBADRQC },
#endif
#ifdef EBADSLT
	{ EBADSLT,		SYSTEM_ERROR_EBADSLT },
#endif
#ifdef EDEADLOCK
	{ EDEADLOCK,		SYSTEM_ERROR_EDEADLK },
#endif
#ifdef EBFONT
	{ EBFONT,		SYSTEM_ERROR_EBFONT },
#endif
#ifdef ENOSTR
	{ ENOSTR,		SYSTEM_ERROR_ENOSTR },
#endif
#ifdef ENODATA
	{ ENODATA,		SYSTEM_ERROR_ENODATA },
#endif
#ifdef ETIME
	{ ETIME,		SYSTEM_ERROR_ETIME },
#endif
#ifdef ENOSR
	{ ENOSR,		SYSTEM_ERROR_ENOSR },
#endif
#ifdef ENONET
	{ ENONET,		SYSTEM_ERROR_ENONET },
#endif
#ifdef ENOPKG
	{ ENOPKG,		SYSTEM_ERROR_ENOPKG },
#endif
#ifdef EREMOTE
	{ EREMOTE,		SYSTEM_ERROR_EREMOTE },
#endif
#ifdef ENOLINK
	{ ENOLINK,		SYSTEM_ERROR_ENOLINK },
#endif
#ifdef EADV
	{ EADV,			SYSTEM_ERROR_EADV },
#endif
#ifdef ESRMNT
	{ ESRMNT,		SYSTEM_ERROR_ESRMNT },
#endif
#ifdef ECOMM
	{ ECOMM,		SYSTEM_ERROR_ECOMM },
#endif
#ifdef EPROTO
	{ EPROTO,		SYSTEM_ERROR_EPROTO },
#endif
#ifdef EMULTIHOP
	{ EMULTIHOP,		SYSTEM_ERROR_EMULTIHOP },
#endif
#ifdef EDOTDOT
	{ EDOTDOT,		SYSTEM_ERROR_EDOTDOT },
#endif
#ifdef EBADMSG
	{ EBADMSG,		SYSTEM_ERROR_EBADMSG },
#endif
#ifdef EOVERFLOW
	{ EOVERFLOW,		SYSTEM_ERROR_EOVERFLOW },
#endif
#ifdef ENOTUNIQ
	{ ENOTUNIQ,		SYSTEM_ERROR_ENOTUNIQ },
#endif
#ifdef EBADFD
	{ EBADFD,		SYSTEM_ERROR_EBADFD },
#endif
#ifdef EREMCHG
	{ EREMCHG,		SYSTEM_ERROR_EREMCHG },
#endif
#ifdef ELIBACC
	{ ELIBACC,		SYSTEM_ERROR_ELIBACC },
#endif
#ifdef ELIBBAD
	{ ELIBBAD,		SYSTEM_ERROR_ELIBBAD },
#endif
#ifdef ELIBSCN
	{ ELIBSCN,		SYSTEM_ERROR_ELIBSCN },
#endif
#ifdef ELIBMAX
	{ ELIBMAX,		SYSTEM_ERROR_ELIBMAX },
#endif
#ifdef ELIBEXEC
	{ ELIBEXEC,		SYSTEM_ERROR_ELIBEXEC },
#endif
#ifdef EILSEQ
	{ EILSEQ,		SYSTEM_ERROR_EILSEQ },
#endif
#ifdef ERESTART
	{ ERESTART,		SYSTEM_ERROR_ERESTART },
#endif
#ifdef ESTRPIPE
	{ ESTRPIPE,		SYSTEM_ERROR_ESTRPIPE },
#endif
#ifdef EUSERS
	{ EUSERS,		SYSTEM_ERROR_EUSERS },
#endif
#ifdef ENOTSOCK
	{ ENOTSOCK,		SYSTEM_ERROR_ENOTSOCK },
#endif
#ifdef EDESTADDRREQ
	{ EDESTADDRREQ,		SYSTEM_ERROR_EDESTADDRREQ },
#endif
#ifdef EMSGSIZE
	{ EMSGSIZE,		SYSTEM_ERROR_EMSGSIZE },
#endif
#ifdef EPROTOTYPE
	{ EPROTOTYPE,		SYSTEM_ERROR_EPROTOTYPE },
#endif
#ifdef ENOPROTOOPT
	{ ENOPROTOOPT,		SYSTEM_ERROR_ENOPROTOOPT },
#endif
#ifdef EPROTONOSUPPORT
	{ EPROTONOSUPPORT,	SYSTEM_ERROR_EPROTONOSUPPORT },
#endif
#ifdef ESOCKTNOSUPPORT
	{ ESOCKTNOSUPPORT,	SYSTEM_ERROR_ESOCKTNOSUPPORT },
#endif
#ifdef EOPNOTSUPP
	{ EOPNOTSUPP,		SYSTEM_ERROR_EOPNOTSUPP },
#endif
#ifdef EPFNOSUPPORT
	{ EPFNOSUPPORT,		SYSTEM_ERROR_EPFNOSUPPORT },
#endif
#ifdef EAFNOSUPPORT
	{ EAFNOSUPPORT,		SYSTEM_ERROR_EAFNOSUPPORT },
#endif
#ifdef EADDRINUSE
	{ EADDRINUSE,		SYSTEM_ERROR_EADDRINUSE },
#endif
#ifdef EADDRNOTAVAIL
	{ EADDRNOTAVAIL,	SYSTEM_ERROR_EADDRNOTAVAIL },
#endif
#ifdef ENETDOWN
	{ ENETDOWN,		SYSTEM_ERROR_ENETDOWN },
#endif
#ifdef ENETUNREACH
	{ ENETUNREACH,		SYSTEM_ERROR_ENETUNREACH },
#endif
#ifdef ENETRESET
	{ ENETRESET,		SYSTEM_ERROR_ENETRESET },
#endif
#ifdef ECONNABORTED
	{ ECONNABORTED,		SYSTEM_ERROR_ECONNABORTED },
#endif
#ifdef ECONNRESET
	{ ECONNRESET,		SYSTEM_ERROR_ECONNRESET },
#endif
#ifdef ENOBUFS
	{ ENOBUFS,		SYSTEM_ERROR_ENOBUFS },
#endif
#ifdef EISCONN
	{ EISCONN,		SYSTEM_ERROR_EISCONN },
#endif
#ifdef ENOTCONN
	{ ENOTCONN,		SYSTEM_ERROR_ENOTCONN },
#endif
#ifdef ESHUTDOWN
	{ ESHUTDOWN,		SYSTEM_ERROR_ESHUTDOWN },
#endif
#ifdef ETOOMANYREFS
	{ ETOOMANYREFS,		SYSTEM_ERROR_ETOOMANYREFS },
#endif
#ifdef ETIMEDOUT
	{ ETIMEDOUT,		SYSTEM_ERROR_ETIMEDOUT },
#endif
#ifdef ECONNREFUSED
	{ ECONNREFUSED,		SYSTEM_ERROR_ECONNREFUSED },
#endif
#ifdef EHOSTDOWN
	{ EHOSTDOWN,		SYSTEM_ERROR_EHOSTDOWN },
#endif
#ifdef EHOSTUNREACH
	{ EHOSTUNREACH,		SYSTEM_ERROR_EHOSTUNREACH },
#endif
#ifdef EALREADY
	{ EALREADY,		SYSTEM_ERROR_EALREADY },
#endif
#ifdef EINPROGRESS
	{ EINPROGRESS,		SYSTEM_ERROR_EINPROGRESS },
#endif
#ifdef ESTALE
	{ ESTALE,		SYSTEM_ERROR_ESTALE },
#endif
#ifdef EUCLEAN
	{ EUCLEAN,		SYSTEM_ERROR_EUCLEAN },
#endif
#ifdef ENOTNAM
	{ ENOTNAM,		SYSTEM_ERROR_ENOTNAM },
#endif
#ifdef ENAVAIL
	{ ENAVAIL,		SYSTEM_ERROR_ENAVAIL },
#endif
#ifdef EISNAM
	{ EISNAM,		SYSTEM_ERROR_EISNAM },
#endif
#ifdef EREMOTEIO
	{ EREMOTEIO,		SYSTEM_ERROR_EREMOTEIO },
#endif
#ifdef EDQUOT
	{ EDQUOT,		SYSTEM_ERROR_EDQUOT },
#endif
#ifdef ENOMEDIUM
	{ ENOMEDIUM,		SYSTEM_ERROR_ENOMEDIUM },
#endif
#ifdef EMEDIUMTYPE
	{ EMEDIUMTYPE,		SYSTEM_ERROR_EMEDIUMTYPE },
#endif
#ifdef ECANCELED
	{ ECANCELED,		SYSTEM_ERROR_ECANCELED },
#endif
#ifdef ENOKEY
	{ ENOKEY,		SYSTEM_ERROR_ENOKEY },
#endif
#ifdef EKEYEXPIRED
	{ EKEYEXPIRED,		SYSTEM_ERROR_EKEYEXPIRED },
#endif
#ifdef EKEYREVOKED
	{ EKEYREVOKED,		SYSTEM_ERROR_EKEYREVOKED },
#endif
#ifdef EKEYREJECTED
	{ EKEYREJECTED,		SYSTEM_ERROR_EKEYREJECTED },
#endif
#ifdef EOWNERDEAD
	{ EOWNERDEAD,		SYSTEM_ERROR_EOWNERDEAD },
#endif
#ifdef ENOTRECOVERABLE
	{ ENOTRECOVERABLE,	SYSTEM_ERROR_ENOTRECOVERABLE },
#endif
#ifdef ERFKILL
	{ ERFKILL,		SYSTEM_ERROR_ERFKILL },
#endif
#ifdef EHWPOISON
	{ EHWPOISON,		SYSTEM_ERROR_EHWPOISON },
#endif
};

ajla_error_t error_from_errno(int ec, int errn)
{
	size_t i;
	for (i = 0; i < n_array_elements(errno_to_system_error); i++) {
		if (unlikely(errn == errno_to_system_error[i].errn))
			return error_ajla_aux(ec, AJLA_ERROR_SYSTEM, errno_to_system_error[i].sys_error);
	}
	return error_ajla_aux(ec, AJLA_ERROR_ERRNO, errn);
}
