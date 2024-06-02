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

#ifndef AJLA_REFCOUNT_H
#define AJLA_REFCOUNT_H

#include "addrlock.h"
#include "thread.h"
#include "asm.h"
#include "ptrcomp.h"

#if defined(REFCOUNT_WIN32)

#if !defined(_WIN64)
typedef ULONG refcount_int_t;
#define REFCOUNT_STEP		1
#define RefcountDec(x)		((LONG)InterlockedDecrement((/*volatile*/ LONG *)(x)) < 0)
#define RefcountAdd(x, v)						\
do {									\
	LONG v_ = (v);							\
	while (v_ > 0)							\
		InterlockedIncrement((/*volatile*/ LONG *)(x)), v_--;	\
	while (v_ < 0)							\
		InterlockedDecrement((/*volatile*/ LONG *)(x)), v_++;	\
} while (0)
#define RefcountXchg(x, v)	InterlockedExchange((/*volatile*/ LONG *)(x), v)
#else
typedef ULONGLONG refcount_int_t;
#define REFCOUNT_STEP		256
#define RefcountDec(x)		((ULONGLONG)InterlockedExchangeAdd64((/*volatile*/ LONGLONG *)(x), -REFCOUNT_STEP) < REFCOUNT_STEP)
#define RefcountAdd(x, v)	InterlockedAdd64((/*volatile*/ LONGLONG *)(x), v)
#define RefcountXchg(x, v)	InterlockedExchange64((/*volatile*/ LONGLONG *)(x), v)
#endif

#else

#if defined(SIZEOF_VOID_P) && SIZEOF_VOID_P >= 8 && !defined(DEBUG)
#define REFCOUNT_STEP		256
#else
#define REFCOUNT_STEP		1
#endif

typedef uintptr_t refcount_int_t;

#endif


#if REFCOUNT_STEP >= 32
#define REFCOUNT_TAG
#endif


#if defined(REFCOUNT_ASM_X86) || defined(REFCOUNT_ASM_X86_LABELS)
#if !defined(INLINE_ASM_GCC_X86_64)
#define REFCOUNT_ASM_X86_SUFFIX		"l"
#else
#define REFCOUNT_ASM_X86_SUFFIX		"q"
#endif
#endif

typedef struct {
#if !defined(REFCOUNT_ATOMIC) || defined(HAVE_REAL_GNUC)
	refcount_int_t refcount;
#define refcount_const	const
#else
/* we don't really want this because on parisc it causes unwanted locking during initialization */
	atomic_uintptr_t refcount;
#define refcount_const
#endif
#ifdef DEBUG_REFCOUNTS
	char position[20];
#endif
} refcount_t;


#if !defined(REFCOUNT_ATOMIC)
#define MEMORY_ORDER_DEC		0
#define MEMORY_ORDER_TEST_1		0
#define memory_order_relaxed		0
#elif defined(THREAD_SANITIZER)
#define MEMORY_ORDER_DEC		memory_order_acq_rel
#define MEMORY_ORDER_TEST_1		memory_order_acquire
#else
#define MEMORY_ORDER_DEC		memory_order_release
#define MEMORY_ORDER_TEST_1		memory_order_relaxed
#endif


#ifdef REFCOUNTS_ARE_ATOMIC
#ifdef REFCOUNT_ATOMIC
#define REFCOUNT_VOLATILE(r, order)	(atomic_load_explicit(&(r)->refcount, order))
#else
#define REFCOUNT_VOLATILE(r, order)	(*cast_ptr(volatile refcount_const refcount_int_t *, &(r)->refcount))
#endif
#endif

#if defined(SIZEOF_VOID_P) && defined(POINTER_IGNORE_BITS)
#define REFCOUNT_LIMIT (((uintptr_t)1 << (SIZEOF_VOID_P * 8 - 1 - POINTER_IGNORE_BITS)) / (SIZEOF_VOID_P / 2))
#elif defined(SIZEOF_VOID_P)
#define REFCOUNT_LIMIT (((uintptr_t)1 << (SIZEOF_VOID_P * 8 - 1)) / (SIZEOF_VOID_P / 2))
#else
#define REFCOUNT_LIMIT ((refcount_int_t)-(2 * REFCOUNT_STEP))
#endif

static attr_always_inline void refcount_set_position(refcount_t attr_unused *r, const char attr_unused *position)
{
#ifdef DEBUG_REFCOUNTS
	size_t l = strlen(position);
	if (likely(l < sizeof(r->position)))
		strcpy(r->position, position);
	else
		strcpy(r->position, position + (l - sizeof(r->position)) + 1);
#endif
}

static attr_always_inline void refcount_init_raw_(refcount_t *r, refcount_int_t val, const char *position)
{
#if !defined(REFCOUNT_ATOMIC) || defined(HAVE_REAL_GNUC)
	r->refcount = val;
#else
	atomic_init(&r->refcount, val);
#endif
	refcount_set_position(r, position);
}

static attr_always_inline void refcount_init_(refcount_t *r, const char *position)
{
	refcount_init_raw_(r, 0, position);
}

#ifdef REFCOUNT_TAG
static attr_always_inline void refcount_init_tag_(refcount_t *r, unsigned char tag, const char *position)
{
#ifdef DEBUG_REFCOUNTS
	unsigned t = tag;
	if (unlikely(t >= REFCOUNT_STEP))
		internal(file_line, "refcount_init_tag: invalid tag %u", tag);
#endif
	refcount_init_raw_(r, tag, position);
}
#endif

static attr_always_inline void refcount_init_val_(refcount_t *r, refcount_int_t val, const char *position)
{
	refcount_init_raw_(r, (val - 1) * REFCOUNT_STEP, position);
}

#if defined(REFCOUNTS_ARE_ATOMIC) && !defined(THREAD_NONE)
#define refcount_get_(r, order)		REFCOUNT_VOLATILE(r, order)
#elif defined(REFCOUNT_SYNC)
static attr_always_inline refcount_int_t refcount_get_(refcount_const refcount_t *r, int attr_unused order)
{
	return __sync_add_and_fetch(cast_ptr(refcount_int_t *, &r->refcount), 0);
}
#else
static attr_always_inline refcount_int_t refcount_get_(refcount_const refcount_t *r, int attr_unused order)
{
	refcount_int_t result;
	address_lock(r, DEPTH_REFCOUNT);
	result = r->refcount;
	address_unlock(r, DEPTH_REFCOUNT);
	return result;
}
#endif

static attr_always_inline bool refcount_is_read_only(refcount_const refcount_t *r)
{
	refcount_int_t v = refcount_get_(r, memory_order_relaxed);
#ifdef DEBUG_REFCOUNTS
	return v >= (refcount_int_t)-(REFCOUNT_STEP * 2) && v < (refcount_int_t)-REFCOUNT_STEP;
#else
	return v >= (refcount_int_t)-REFCOUNT_STEP;
#endif
}

static attr_always_inline void refcount_set_read_only(refcount_t *r)
{
#ifdef DEBUG_REFCOUNTS
	refcount_int_t val = (refcount_int_t)-(REFCOUNT_STEP * 2);
#else
	refcount_int_t val = (refcount_int_t)-REFCOUNT_STEP;
#endif
#ifdef REFCOUNT_TAG
	val |= refcount_get_(r, memory_order_relaxed) & (REFCOUNT_STEP - 1);
#endif
	refcount_init_raw_(r, val, file_line);
}

static attr_always_inline bool refcount_is_invalid(refcount_const refcount_t attr_unused *r)
{
	return !refcount_is_read_only(r) && refcount_get_(r, memory_order_relaxed) >= REFCOUNT_LIMIT;
}

static attr_always_inline void refcount_validate(refcount_const refcount_t attr_unused *r, const char attr_unused *msg, const char attr_unused *position)
{
#ifdef DEBUG_REFCOUNTS
	if (unlikely(!r))
		internal(position, "%s: refcount is NULL", msg);
	if (unlikely(refcount_is_invalid(r))) {
		internal(position, "%s: refcount %p is invalid: %"PRIxMAX" (%s)", msg, r, (uintmax_t)refcount_get_(r, memory_order_relaxed), r->position);
	}
#endif
}

static attr_always_inline bool refcount_is_one_(refcount_const refcount_t *r, const char *position)
{
	refcount_validate(r, "refcount_is_one", position);
	return refcount_get_(r, MEMORY_ORDER_TEST_1) < REFCOUNT_STEP;
}

#ifdef REFCOUNT_TAG
static attr_always_inline unsigned char refcount_tag_get(refcount_const refcount_t *r)
{
#if defined(C_LITTLE_ENDIAN) && !defined(__alpha__) && !defined(THREAD_SANITIZER)
	return ((volatile unsigned char *)&r->refcount)[0] & (REFCOUNT_STEP - 1);
#elif defined(C_BIG_ENDIAN) && !defined(THREAD_SANITIZER)
	return ((volatile unsigned char *)&r->refcount)[sizeof(refcount_int_t) - 1] & (REFCOUNT_STEP - 1);
#else
	return refcount_get_(r, memory_order_relaxed) & (REFCOUNT_STEP - 1);
#endif
}
#endif

static attr_always_inline void refcount_add_raw_(refcount_t *r, refcount_int_t add, const char *position)
{
	refcount_int_t attr_unused value;
	if (position)
		refcount_validate(r, "refcount_add_raw", position);
#if defined(REFCOUNT_ASM_X86) || defined(REFCOUNT_ASM_X86_LABELS)
	if (is_constant(add) && add == 1)
		__asm__ volatile ("lock; inc"REFCOUNT_ASM_X86_SUFFIX" %0"::"m"(r->refcount):"cc","memory");
	else if (is_constant(add) && add == (refcount_int_t)-1)
		__asm__ volatile ("lock; dec"REFCOUNT_ASM_X86_SUFFIX" %0"::"m"(r->refcount):"cc","memory");
	else
		__asm__ volatile ("lock; add"REFCOUNT_ASM_X86_SUFFIX" %1, %0"::"m"(r->refcount),"ir"(add):"cc","memory");
#if defined(DEBUG_REFCOUNTS) && defined(REFCOUNTS_ARE_ATOMIC)
	value = REFCOUNT_VOLATILE(r, memory_order_relaxed);
#else
	value = REFCOUNT_STEP;
#endif
#elif defined(REFCOUNT_ATOMIC)
	value = atomic_fetch_add_explicit(&r->refcount, add, memory_order_relaxed);
	value += add;
#elif defined(REFCOUNT_SYNC)
	value = __sync_add_and_fetch(&r->refcount, add);
#elif defined(REFCOUNT_WIN32)
	RefcountAdd(&r->refcount, add);
#if defined(DEBUG_REFCOUNTS) && defined(REFCOUNTS_ARE_ATOMIC)
	value = REFCOUNT_VOLATILE(r, memory_order_relaxed);
#else
	value = REFCOUNT_STEP;
#endif
#elif defined(REFCOUNT_LOCK)
	address_lock(r, DEPTH_REFCOUNT);
	value = r->refcount += add;
	address_unlock(r, DEPTH_REFCOUNT);
#else
	error - no refcount method
#endif
#ifdef DEBUG_REFCOUNTS
	if (position) {
		refcount_t test;
		test.refcount = value;
		if (unlikely(refcount_is_invalid(&test)) || (unlikely(refcount_is_one_(&test, position)) && unlikely(add >= REFCOUNT_STEP) && likely(add < sign_bit(refcount_int_t))))
			internal(position, "refcount_add_raw_: refcount overflow: %"PRIuMAX" (adding %"PRIuMAX")", (uintmax_t)value, (uintmax_t)add);
	}
#endif
}

#ifdef REFCOUNT_TAG
static attr_always_inline void refcount_tag_set_(refcount_t *r, unsigned char old_tag, unsigned char new_tag, const char attr_unused *position)
{
#ifdef DEBUG_REFCOUNTS
	if (unlikely(refcount_tag_get(r) != old_tag))
		internal(position, "refcount_tag_set: tag does not match: %u != %u; new tag %u", refcount_tag_get(r), old_tag, new_tag);
#endif
	refcount_add_raw_(r, (refcount_int_t)new_tag - (refcount_int_t)old_tag, NULL);
}
#endif

static attr_always_inline void refcount_poison_(refcount_t attr_unused *r, const char attr_unused *position)
{
#ifdef DEBUG_REFCOUNTS
#ifndef REFCOUNT_TAG
	refcount_init_raw_(r, -1, position);
#else
	refcount_int_t add = (refcount_int_t)-REFCOUNT_STEP - (refcount_int_t)((refcount_int_t)refcount_get_(r, memory_order_relaxed) & (refcount_int_t)-REFCOUNT_STEP);
	refcount_add_raw_(r, add, NULL);
#endif
#endif
}

static attr_always_inline void refcount_poison_tag_(refcount_t attr_unused *r, const char attr_unused *position)
{
#ifdef DEBUG_REFCOUNTS
	refcount_init_raw_(r, -1, position);
#endif
}

#if !defined(THREAD_NONE) && defined(REFCOUNTS_ARE_ATOMIC) && !defined(UNUSUAL_ARITHMETICS)
#define refcount_one_fastpath				\
do {							\
	if (likely(REFCOUNT_VOLATILE(r, MEMORY_ORDER_TEST_1) < REFCOUNT_STEP)) {\
		refcount_poison_(r, position);		\
		return true;				\
	}						\
} while (0)
#else
#define refcount_one_fastpath	do { } while (0)
#endif

static attr_always_inline bool refcount_dec_(refcount_t *r, const char *position)
{
	bool result;
	refcount_validate(r, "refcount_dec", position);
	refcount_set_position(r, position);
#if defined(REFCOUNT_ASM_X86_LABELS)
	refcount_one_fastpath;
	__asm__ goto ("lock; sub"REFCOUNT_ASM_X86_SUFFIX" %1, %0; jc %l[x86_ret_true]"::"m"(r->refcount),"i"(REFCOUNT_STEP):"cc","memory":x86_ret_true);
	return false;
x86_ret_true:
	refcount_poison_(r, position);
	return true;
#elif defined(REFCOUNT_ASM_X86)
	refcount_one_fastpath;
	if (sizeof(bool) == 1) {
		__asm__ volatile ("lock; sub"REFCOUNT_ASM_X86_SUFFIX" %2, %1; setc %0":"=q"(result):"m"(r->refcount),"i"(REFCOUNT_STEP):"cc","memory");
	} else {
		unsigned char res;
		__asm__ volatile ("lock; sub"REFCOUNT_ASM_X86_SUFFIX" %2, %1; setc %0":"=q"(res):"m"(r->refcount),"i"(REFCOUNT_STEP):"cc","memory");
		result = res;
	}
	return result;
#elif defined(REFCOUNT_ATOMIC)
	refcount_one_fastpath;
	result = atomic_fetch_sub_explicit(&r->refcount, REFCOUNT_STEP, MEMORY_ORDER_DEC) < REFCOUNT_STEP;
#elif defined(REFCOUNT_SYNC)
	refcount_one_fastpath;
	result = (refcount_int_t)(__sync_sub_and_fetch(&r->refcount, REFCOUNT_STEP) + REFCOUNT_STEP) < REFCOUNT_STEP;
#elif defined(REFCOUNT_WIN32)
	refcount_one_fastpath;
	result = RefcountDec(&r->refcount);
#elif defined(REFCOUNT_LOCK)
	refcount_one_fastpath;
	address_lock(r, DEPTH_REFCOUNT);
	result = (refcount_int_t)(r->refcount -= REFCOUNT_STEP) >= (refcount_int_t)-REFCOUNT_STEP;
	address_unlock(r, DEPTH_REFCOUNT);
#else
	error - no refcount method
#endif
	if (result)
		refcount_poison_(r, position);
	return result;
}

#undef refcount_one_fastpath

static attr_always_inline bool refcount_xchgcmp(refcount_t *r, refcount_int_t val, refcount_int_t cmp)
{
	refcount_int_t result;
	val = (val - 1) * REFCOUNT_STEP;
#if defined(REFCOUNT_ASM_X86) || defined(REFCOUNT_ASM_X86_LABELS)
	__asm__ ("xchg"REFCOUNT_ASM_X86_SUFFIX" %1, %0":"=r"(result):"m"(r->refcount),"0"(val):"memory");
#elif defined(REFCOUNT_ATOMIC)
	result = atomic_exchange_explicit(&r->refcount, val, memory_order_acquire);
#elif defined(REFCOUNT_SYNC)
	do {
		result = refcount_get_(r, memory_order_relaxed);
	} while (unlikely(!__sync_bool_compare_and_swap(&r->refcount, result, val)));
#elif defined(REFCOUNT_WIN32)
	result = RefcountXchg(&r->refcount, val);
#elif defined(REFCOUNT_LOCK)
	address_lock(r, DEPTH_REFCOUNT);
	result = r->refcount;
	refcount_init_raw_(r, val, file_line);
	address_unlock(r, DEPTH_REFCOUNT);
#else
	error - no refcount method
#endif
	return result == (cmp - 1) * REFCOUNT_STEP;
}

static attr_always_inline void refcount_set(refcount_t *r, refcount_int_t val)
{
	val = (val - 1) * REFCOUNT_STEP;
#if defined(REFCOUNT_ASM_X86) || defined(REFCOUNT_ASM_X86_LABELS)
	__asm__ ("mov"REFCOUNT_ASM_X86_SUFFIX" %1, %0":"=m"(r->refcount):"ri"(val));
#elif defined(REFCOUNT_ATOMIC)
	atomic_store_explicit(&r->refcount, val, memory_order_relaxed);
#elif defined(REFCOUNT_SYNC)
	{
		refcount_int_t result;
		do {
			result = refcount_get_(r, memory_order_relaxed);
		} while (unlikely(!__sync_bool_compare_and_swap(&r->refcount, result, val)));
	}
#elif defined(REFCOUNT_WIN32)
	*(volatile refcount_int_t *)&r->refcount = val;
#elif defined(REFCOUNT_LOCK)
	address_lock(r, DEPTH_REFCOUNT);
	refcount_init_raw_(r, val, file_line);
	address_unlock(r, DEPTH_REFCOUNT);
#else
	error - no refcount method
#endif
}

static attr_always_inline bool refcount_is_one_nonatomic_(refcount_const refcount_t *r, const char *position)
{
	refcount_validate(r, "refcount_is_one_nonatomic", position);
	return r->refcount < REFCOUNT_STEP;
}

static attr_always_inline void refcount_inc_nonatomic_(refcount_t *r, const char *position)
{
	refcount_validate(r, "refcount_inc_nonatomic", position);
	r->refcount += REFCOUNT_STEP;
#ifdef DEBUG_REFCOUNTS
	if (unlikely(refcount_is_invalid(r)) || unlikely(refcount_is_one_(r, position)))
		internal(position, "refcount_inc_nonatomic: refcount overflow: %"PRIuMAX"", (uintmax_t)r->refcount);
#endif
}

static attr_always_inline bool refcount_dec_nonatomic_(refcount_t *r, const char *position)
{
	bool result;
	refcount_validate(r, "refcount_dec_nonatomic", position);
	refcount_init_raw_(r, r->refcount - REFCOUNT_STEP, position);
	result = (refcount_int_t)r->refcount >= (refcount_int_t)-REFCOUNT_STEP;
	if (result)
		refcount_poison_(r, position);
	return result;
}

static attr_always_inline refcount_int_t refcount_get_nonatomic_(refcount_t *r, const char *position)
{
	refcount_validate(r, "refcount_get_nonatomic", position);
	return (r->refcount / REFCOUNT_STEP) + 1;
}

#define refcount_init(r)		refcount_init_(r, file_line)
#define refcount_init_tag(r, tag)	refcount_init_tag_(r, tag, file_line)
#define refcount_init_val(r, val)	refcount_init_val_(r, val, file_line)
#define refcount_is_one(r)		refcount_is_one_(r, file_line)
#define refcount_inc(r)			refcount_add_raw_(r, REFCOUNT_STEP, file_line)
#define refcount_inc_(r, position)	refcount_add_raw_(r, REFCOUNT_STEP, position)
#define refcount_add(r, val)		refcount_add_raw_(r, (refcount_int_t)(val) * REFCOUNT_STEP, file_line)
#define refcount_add_(r, val, position)	refcount_add_raw_(r, (refcount_int_t)(val) * REFCOUNT_STEP, position)
#define refcount_poison(r)		refcount_poison_(r, file_line);
#define refcount_poison_tag(r)		refcount_poison_tag_(r, file_line);
#define refcount_dec(r)			refcount_dec_(r, file_line)
#define refcount_is_one_nonatomic(r)	refcount_is_one_nonatomic_(r, file_line)
#define refcount_inc_nonatomic(r)	refcount_inc_nonatomic_(r, file_line)
#define refcount_dec_nonatomic(r)	refcount_dec_nonatomic_(r, file_line)
#define refcount_get_nonatomic(r)	refcount_get_nonatomic_(r, file_line)

#ifdef REFCOUNT_TAG
#define refcount_tag_set(r, old_tag, new_tag)	refcount_tag_set_(r, old_tag, new_tag, file_line)
#endif

#endif
