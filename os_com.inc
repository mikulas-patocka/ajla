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

#if defined(HAVE_NETWORK) || defined(OS_OS2) || defined(OS_WIN32)
#include "os_pos_s.inc"
#endif


static inline bool os_drives_bitmap(uint32_t mask, char **drives, size_t *drives_l, ajla_error_t *err)
{
	if (unlikely(!array_init_mayfail(char, drives, drives_l, err)))
		return false;
	while (mask) {
		char str[4] = " :\\";
		unsigned bit = low_bit(mask);
		mask &= ~(1U << bit);
		str[0] = bit + 'A';
		if (unlikely(str[0] > 'Z'))
			break;
		if (unlikely(!array_add_multiple_mayfail(char, drives, drives_l, str, 4, NULL, err)))
			return false;
	}
	return true;
}


#if defined(HAVE_NETWORK) || defined(OS_OS2) || defined(OS_WIN32)

static int translate_flags(int (*x)(int idx, ajla_error_t *err), int flags, ajla_error_t *err)
{
	int result = 0;
	while (flags > 0) {
		unsigned lb = 1U << low_bit(flags);
		int v = x(lb, err);
		if (unlikely(v < 0))
			return v;
		result |= v;
		flags &= ~lb;
	}
	return result;
}

static struct sockaddr *os_get_sock_addr(unsigned char *addr, size_t *addr_len, ajla_error_t *err)
{
	struct sockaddr *sa;
	size_t padded_len;
	int domain;
	if (unlikely(*addr_len < 2)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "too short address");
		return NULL;
	}
	if (unlikely(*addr_len >= SOCKADDR_MAX_LEN)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "too long address");
		return NULL;
	}
	domain = os_socket_af(addr[0] | (addr[1] << 8), err);
	if (unlikely(domain == -1))
		return NULL;
	padded_len = maximum(*addr_len, sizeof(struct sockaddr));
	sa = mem_align_mayfail(struct sockaddr *, padded_len, SOCKADDR_ALIGN, err);
	if (unlikely(!sa))
		return NULL;
	memset(sa, 0, padded_len);
	sa->sa_family = domain;
	memcpy(sa->sa_data, addr + 2, *addr_len - 2);
	*addr_len = padded_len;
	return sa;
}

static unsigned char *os_get_ajla_addr(struct sockaddr *sa, socklen_t *addr_len, ajla_error_t *err)
{
	unsigned char *addr;
	int domain;
	if (unlikely(*addr_len < 2)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SYSTEM_RETURNED_INVALID_DATA), err, "too short address");
		return NULL;
	}
	if (sa->sa_family == AF_INET)
		*addr_len = minimum(*addr_len, 8);
	domain = os_af_socket(sa->sa_family, err);
	if (unlikely(domain == -1))
		return NULL;
	addr = mem_alloc_mayfail(unsigned char *, *addr_len, err);
	if (unlikely(!addr))
		return NULL;
	addr[0] = domain;
	addr[1] = domain >> 8;
	memcpy(addr + 2, sa->sa_data, *addr_len - 2);
	return addr;

}

#endif


static const uint8_t month_days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static bool is_leap_year(int year)
{
	return !(year % 4) - !(year % 100) + !(year % 400);
}

#ifndef HAVE_TIMEGM
#define add(x) do { t2 = (uintmax_t)t + (x); if (unlikely(t2 < t)) goto ovf; t = t2; } while (0)
#define sub(x) do { t2 = (uintmax_t)t - (x); if (unlikely(t2 > t)) goto ovf; t = t2; } while (0)
static time_t my_timegm(struct tm *tm)
{
	int i;
	time_t t2;
	time_t t = 946684800;
	int year = (unsigned)tm->tm_year - 100;
	if (unlikely(year > tm->tm_year))
		goto ovf;
	if (year >= 0) {
		time_t y400 = year / 400;
		year %= 400;
		if (unlikely(y400 > signed_maximum(time_t) / 126227808 / 100))
			goto ovf;
		add(y400 * 126227808 * 100);
		for (i = 0; i < year; i++)
			add((365 + is_leap_year(i)) * 24 * 3600);
	}
	for (i = 0; i < tm->tm_mon; i++) {
		add((month_days[i] + (i == 1 && is_leap_year(year))) * 24 * 3600);
	}
	add((tm->tm_mday - 1) * 24 * 3600);
	add(tm->tm_hour * 3600);
	add(tm->tm_min * 60);
	add(tm->tm_sec);
	if (year < 0) {
		time_t y400 = (-(unsigned)year / 400);
		year = -(-(unsigned)year % 400);
		if (unlikely(y400 > signed_maximum(time_t) / 126227808 / 100))
			goto ovf;
		sub(y400 * 126227808 * 100);
		for (i = -1; i >= year; i--)
			sub((365 + is_leap_year(400 - i)) * 24 * 3600);
	}
	return t;

ovf:
#ifdef EOVERFLOW
	errno = EOVERFLOW;
#else
	errno = EINVAL;
#endif
	return (time_t)-1;
}
#undef add
#undef sub
#else
#define my_timegm	timegm
#endif

#if (!defined(HAVE_GMTIME_R) && !defined(HAVE_LOCALTIME_R)) || defined(THREAD_NONE)
#define HAVE_CALENDAR_LOCK
static mutex_t calendar_lock;
#endif

bool os_time_to_calendar(ajla_time_t t, bool local, int *year, int *month, int *day, int *hour, int *min, int *sec, int *usec, int *yday, int *wday, int *is_dst, ajla_error_t *err)
{
	ajla_error_t e;
	struct tm attr_unused xtm;
	struct tm *tm;
	ajla_time_t at;
	time_t tim;
	if (t >= 0) {
		at = t / 1000000;
	} else {
		at = -(-(ajla_utime_t)t / 1000000);
		if (t % 1000000)
			at--;
	}
	tim = at;
	if (unlikely(tim != at))
		goto ovf;
#ifdef HAVE_CALENDAR_LOCK
	mutex_lock(&calendar_lock);
	tm = local ? localtime(&tim) : gmtime(&tim);
#else
	tm = local ? localtime_r(&tim, &xtm) : gmtime_r(&tim, &xtm);
#endif
	if (unlikely(!tm)) {
#ifdef EOVERFLOW
		if (errno == EOVERFLOW)
			goto ovf;
#endif
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't convert time: %s", error_decode(e));
#ifdef HAVE_CALENDAR_LOCK
		mutex_unlock(&calendar_lock);
#endif
		return false;
	}
	*year = tm->tm_year + 1900;
	*month = tm->tm_mon;
	*day = tm->tm_mday - 1;
	*hour = tm->tm_hour;
	*min = tm->tm_min;
	*sec = tm->tm_sec;
	*usec = (ajla_utime_t)t - (at * 1000000);
	*yday = tm->tm_yday;
	*wday = tm->tm_wday;
	*is_dst = tm->tm_isdst;
#ifdef HAVE_CALENDAR_LOCK
	mutex_unlock(&calendar_lock);
#endif
	return true;

ovf:
	e = error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE);
	fatal_mayfail(e, err, "can't convert time: %s", error_decode(e));
	return false;
}

bool os_calendar_to_time(bool local, int year, int month, int day, int hour, int min, int sec, int usec, int is_dst, ajla_time_t *t, ajla_error_t *err)
{
	ajla_error_t e;
	unsigned days;
	struct tm tm;
	time_t s;
	ajla_utime_t at;
	if (unlikely((int)((unsigned)year - 1900) > year) ||
	    unlikely((unsigned)month >= 12))
		goto ovf;
	days = month_days[month];
	if (month == 1 && is_leap_year(year))
		days++;
	if (unlikely((unsigned)day >= days) ||
	    unlikely((unsigned)hour >= 24) ||
	    unlikely((unsigned)min >= 60) ||
	    unlikely((unsigned)sec >= 60) ||
	    unlikely((unsigned)usec >= 1000000))
		goto ovf;
	memset(&tm, 0, sizeof(struct tm));
	tm.tm_year = year - 1900;
	tm.tm_mon = month;
	tm.tm_mday = day + 1;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;
	tm.tm_isdst = is_dst;
	errno = 0;
	s = local ? mktime(&tm) : my_timegm(&tm);
	if (unlikely(errno)) {
#ifdef EOVERFLOW
		if (errno == EOVERFLOW)
			goto ovf;
#endif
		e = error_from_errno(EC_SYSCALL, errno);
		fatal_mayfail(e, err, "can't convert time: %s", error_decode(e));
		return false;
	}
	at = (ajla_utime_t)s * 1000000U;
	if (unlikely((ajla_time_t)at / 1000000 != (ajla_time_t)s) ||
	    unlikely(at + usec < at)) {
		goto ovf;
	}
	at += usec;
	*t = at;
	return true;

ovf:
	e = error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE);
	fatal_mayfail(e, err, "can't convert time: %s", error_decode(e));
	return false;
}

static void os_init_calendar_lock(void)
{
#ifdef HAVE_CALENDAR_LOCK
	mutex_init(&calendar_lock);
#endif
}

static void os_done_calendar_lock(void)
{
#ifdef HAVE_CALENDAR_LOCK
	mutex_done(&calendar_lock);
#endif
}
