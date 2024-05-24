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

#ifndef FILE_OMIT

#include "mem_al.h"
#include "str.h"
#include "data.h"
#include "refcount.h"
#include "tree.h"
#include "array.h"
#include "ipret.h"
#include "code-op.h"
#include "arithm-i.h"
#include "thread.h"
#include "rwlock.h"
#include "os.h"

#include <stdio.h>
#include <fcntl.h>

static attr_always_inline void verify_size(const char *str, size_t s1, size_t s2, size_t s3)
{
	/*debug("verify_size: %s - %d", str, (int)s1);*/
	if (s1 != s3 ||
	    s2 != s3)
		internal(file_line, "bad type %s: %"PRIuMAX", %"PRIuMAX", %"PRIuMAX"",
			str, (uintmax_t)s1, (uintmax_t)s2, (uintmax_t)s3);
}

static attr_noinline void bist_constants(void)
{
#define f(n, s, u, sz, bits)	verify_size("int_" stringify(s), sizeof(s), sizeof(u), sz);
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits)	verify_size(stringify(s), sizeof(s), sizeof(u), sz);
	for_all_fixed(f)
#undef f
	verify_size("ip_t", sizeof(ip_t), sizeof(ip_t), SIZEOF_IP_T);
}


#ifdef DEBUG_BIST


static attr_noinline void bist_memory(void)
{
	int i;
	char *p, *q, *r;
	p = mem_alloc(char *, 11);
	(void)strcpy(p, "1234567890");
	q = mem_alloc(char *, 21);
	(void)strcpy(q, "1234567890abcdefghij");
	p = mem_realloc(char *, p, 101);
	for (i = 0; i < 9; i++)
		(void)strcat(p, "abcdefghij");
	r = cast_cpp(char *, mempcpy(q + 4, q, 4));
	if (unlikely(r != q + 8))
		internal("bist_memory: mempcpy result mismatch: %p != %p", r, q + 8);
	if (unlikely(strcmp(q, "1234123490abcdefghij")))
		internal(file_line, "bist_memory: mempcpy string mismatch: %s", q);
	mem_free(p);
	mem_free(q);

	p = mem_alloc(char *, 0);
	if (unlikely(!p))
		internal(file_line, "mem_alloc(0) returns NULL");
	p = mem_realloc(char *, p, 0);
	if (unlikely(!p))
		internal(file_line, "mem_realloc(0) returns NULL");
	mem_free(p);
	p = mem_calloc(char *, 0);
	if (unlikely(!p))
		internal(file_line, "mem_calloc(0) returns NULL");
	p = mem_realloc(char *, p, 0);
	if (unlikely(!p))
		internal(file_line, "mem_realloc(0) returns NULL");
	mem_free(p);
	p = mem_align(char *, 0, 1);
	if (unlikely(!p))
		internal(file_line, "mem_align(0, 1) returns NULL");
	mem_free_aligned(p);
}


static attr_noinline void bist_string(void)
{
	char *str;
	size_t str_l;
	char c;
#ifndef DEBUG_TRACK_FILE_LINE
	str = position_string(bist_string);
#endif
	str_init(&str, &str_l);
	str_add_string(&str, &str_l, "");
	for (c = 0; c < 127; c++)
		str_add_bytes(&str, &str_l, &c, 1);
	for (c = 0; c < 127; c++)
		if (unlikely(str[(int)c] != c))
			internal(file_line, "bist_string: str[%d] == %d", c, str[(int)c]);
	str_finish(&str, &str_l);
	if (unlikely(str[127] != 0))
		internal(file_line, "bist_string: bad string end: %d", str[127]);
	mem_free(str);
}

static attr_noinline void bist_memarray(void)
{
	int *array;
	size_t array_l;
	int i = 3;
	array_init(int, &array, &array_l);
	array_add_multiple(int, &array, &array_l, &i, 1);
	for (i = 0; i < 100; i++)
		array_add(int, &array, &array_l, i * 2);
	for (i = 0; i < 100; i++)
		if (unlikely(array[i + 1] != i * 2))
			internal(file_line, "bist_memarray: array[%d] == %d", i, array[i]);
	mem_free(array);
}


static attr_noinline void bist_pointer(void)
{
	pointer_t p;
	struct thunk *th;
	struct data *dat, *res_d;
	th = thunk_alloc_exception_error(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), NULL, NULL, NULL pass_file_line);
	dat = data_alloc(flat, NULL);
	p = pointer_thunk(th);
	if (unlikely(pointer_get_thunk(p) != th))
		internal(file_line, "bist_pointer: bad thunk pointer %p != %p", (const void *)pointer_get_thunk(p), (const void *)th);
	p = pointer_data(dat);
	if (unlikely(pointer_get_data(p) != dat))
bad_data:
		internal(file_line, "bist_pointer: bad data pointer %p != %p", (const void *)pointer_get_data(p), (const void *)dat);
	pointer_follow(&p, false, res_d, PF_NOEVAL, NULL, NULL,
		internal(file_line, "bist_pointer: thunk, execution control %p", (const void *)ex_),
		internal(file_line, "bist_pointer: exception: %p", (const void *)thunk_)
	);
	if (unlikely(res_d != dat))
		goto bad_data;
	thunk_free(th);
	data_free_r1(dat);
}


#define bist_refcount_is_one		name(bist_refcount_is_one)
attr_noinline bool bist_refcount_is_one(refcount_t *ref);
attr_noinline bool bist_refcount_is_one(refcount_t *ref)
{
	return refcount_is_one(ref);
}

#define bist_refcount_inc		name(bist_refcount_inc)
attr_noinline void bist_refcount_inc(refcount_t *ref);
attr_noinline void bist_refcount_inc(refcount_t *ref)
{
	refcount_inc(ref);
}

#define bist_refcount_dec_false		name(bist_refcount_dec_false)
attr_noinline void bist_refcount_dec_false(refcount_t *ref, const char *position);
attr_noinline void bist_refcount_dec_false(refcount_t *ref, const char *position)
{
	if (unlikely(refcount_dec(ref)))
		internal(position, "bist_refcount_dec_false: refcount_dec returned true");
}

#define bist_refcount_dec_true		name(bist_refcount_dec_true)
attr_noinline void bist_refcount_dec_true(refcount_t *ref, const char *position);
attr_noinline void bist_refcount_dec_true(refcount_t *ref, const char *position)
{
	if (unlikely(!refcount_dec(ref)))
		internal(position, "bist_refcount_dec_true: refcount_dec returned false");
}

#define bist_refcount_xchgcmp_false	name(bist_refcount_xchgcmp_false)
attr_noinline void bist_refcount_xchgcmp_false(refcount_t *ref, refcount_int_t val, refcount_int_t cmp, const char *position);
attr_noinline void bist_refcount_xchgcmp_false(refcount_t *ref, refcount_int_t val, refcount_int_t cmp, const char *position)
{
	if (unlikely(refcount_xchgcmp(ref, val, cmp)))
		internal(position, "bist_refcount_xchgcmp_false: refcount_xchgcmp returned true");
}

#define bist_refcount_xchgcmp_true	name(bist_refcount_xchgcmp_true)
attr_noinline void bist_refcount_xchgcmp_true(refcount_t *ref, refcount_int_t val, refcount_int_t cmp, const char *position);
attr_noinline void bist_refcount_xchgcmp_true(refcount_t *ref, refcount_int_t val, refcount_int_t cmp, const char *position)
{
	if (unlikely(!refcount_xchgcmp(ref, val, cmp)))
		internal(position, "bist_refcount_xchgcmp_true: refcount_xchgcmp returned false");
}

static attr_noinline void bist_refcount(void)
{
	refcount_t ref;

#ifndef REFCOUNT_TAG
	refcount_init(&ref);
#else
	refcount_init_tag(&ref, 5);
#endif
	bist_refcount_inc(&ref);
	bist_refcount_inc(&ref);
#ifdef REFCOUNT_TAG
	if (unlikely(refcount_tag_get(&ref) != 5)) internal(file_line, "bist_refcount: refcount tag is not 5");
#endif
	if (unlikely(refcount_get_nonatomic(&ref) != 3) || unlikely(bist_refcount_is_one(&ref))) internal(file_line, "bist_refcount: refcount is not 3");
	bist_refcount_dec_false(&ref, file_line);
	if (unlikely(refcount_get_nonatomic(&ref) != 2) || unlikely(bist_refcount_is_one(&ref))) internal(file_line, "bist_refcount: refcount is not 2");
	bist_refcount_dec_false(&ref, file_line);
	if (unlikely(refcount_get_nonatomic(&ref) != 1) || unlikely(!bist_refcount_is_one(&ref))) internal(file_line, "bist_refcount: refcount is not 1");
	bist_refcount_dec_true(&ref, file_line);

	refcount_init_val(&ref, 4);
	refcount_inc_nonatomic(&ref);
	if (unlikely(refcount_get_nonatomic(&ref) != 5) || unlikely(refcount_is_one_nonatomic(&ref))) internal(file_line, "bist_refcount: nonatomic refcount is not 5");
	bist_refcount_xchgcmp_true(&ref, 3, 5, file_line);
	if (unlikely(refcount_get_nonatomic(&ref) != 3) || unlikely(refcount_is_one_nonatomic(&ref))) internal(file_line, "bist_refcount: nonatomic refcount is not 3");
	bist_refcount_xchgcmp_false(&ref, 2, 1, file_line);
	if (unlikely(refcount_get_nonatomic(&ref) != 2) || unlikely(refcount_is_one_nonatomic(&ref))) internal(file_line, "bist_refcount: nonatomic refcount is not 2");
	if (unlikely(refcount_dec_nonatomic(&ref))) internal(file_line, "bist_refcount: nonatomic refcount should not be zero");
	if (unlikely(refcount_get_nonatomic(&ref) != 1) || unlikely(!refcount_is_one_nonatomic(&ref))) internal(file_line, "bist_refcount: nonatomic refcount is not 1");
	if (unlikely(!refcount_dec_nonatomic(&ref))) internal(file_line, "bist_refcount: nonatomic refcount should be zero");
}


static attr_noinline void bist_arithm(void)
{
#define f(n, s, u, sz, bits)						\
	{								\
		s op1 = 10;						\
		s op2 = 20;						\
		s res;							\
		s * volatile resp = &res; /* avoid failure with icc */	\
		*resp = 25;						\
		res = 25;						\
		if (!cat(INT_binary_add_,s)(&op1, &op2, &res))		\
			internal(file_line, "bist_arithm: %s failed", stringify(cat(INT_binary_add_,s)));\
		if (res != 30)						\
			internal(file_line, "bist_arithm: %s: bad result %s", stringify(cat(INT_binary_add_,s)), str_from_signed(res, 16));\
	}
	for_all_int(f, for_all_empty)
#undef f
}

#define bist_cat_(a, b)	a##b
#define bist_cat(a, b)	bist_cat_(a, b)
#define bist_popcnt(type, utype)					\
{									\
	type val, res1, res2 = 0;	/* avoid warning */		\
	val = (type)0x12345678UL;					\
	if (sizeof(type) >= sizeof(unsigned long)) {			\
		val = (type)((utype)val | ((utype)val << 31));		\
		val = (type)((utype)val | ((utype)val << 31 << 31));	\
	}								\
	if (unlikely(!bist_cat(INT_unary_popcnt_,type)(&val, &res1)))	\
		internal(file_line, "bist_popcnt(%s) INT_unary_popcnt failed", stringify(type));\
	if ((cpu_feature_flags & FIXED_POPCNT_ALT1_FEATURES) == FIXED_POPCNT_ALT1_FEATURES) {\
		if (unlikely(!bist_cat(INT_unary_popcnt_alt1_,type)(&val, &res2)))\
			internal(file_line, "bist_popcnt(%s) INT_unary_popcnt_alt1 failed", stringify(type));\
	} else {							\
		res2 = 0;						\
		while (val)						\
			val &= val - 1, res2++;				\
	}								\
	if (unlikely(res1 != res2))					\
		internal(file_line, "bist_popcnt(%s) mismatch: %"PRIdMAX" != %"PRIdMAX"", stringify(type), (intmax_t)res, (intmax_t)res1);\
}

#if defined(INT_POPCNT_ALT1_TYPES) && INT_POPCNT_ALT1_TYPES & 1
#define bist_popcnt_int8_t	bist_popcnt(int8_t, uint8_t)
#else
#define bist_popcnt_int8_t
#endif
#if defined(INT_POPCNT_ALT1_TYPES) && INT_POPCNT_ALT1_TYPES & 2
#define bist_popcnt_int16_t	bist_popcnt(int16_t, uint16_t)
#else
#define bist_popcnt_int16_t
#endif
#if defined(INT_POPCNT_ALT1_TYPES) && INT_POPCNT_ALT1_TYPES & 4
#define bist_popcnt_int32_t	bist_popcnt(int32_t, uint32_t)
#else
#define bist_popcnt_int32_t
#endif
#if defined(INT_POPCNT_ALT1_TYPES) && INT_POPCNT_ALT1_TYPES & 8
#define bist_popcnt_int64_t	bist_popcnt(int64_t, uint64_t)
#else
#define bist_popcnt_int64_t
#endif
#if defined(INT_POPCNT_ALT1_TYPES) && INT_POPCNT_ALT1_TYPES & 16
#define bist_popcnt_int128_t	bist_popcnt(int128_t, uint128_t)
#else
#define bist_popcnt_int128_t
#endif

#define generate_bist_arithm(n, type, utype, sz, bits)			\
static attr_noinline void cat(bist_binary_,type)(			\
	bool (*fn)(const type *, const type *, type *),			\
	const char *fn_name,						\
	type op1, type op2, bool succeed, type result)			\
{									\
	type res;							\
	type * volatile resp = &res; /* avoid failure with icc */	\
	*resp = -1;							\
	res = -1;							\
	if (unlikely(fn(&op1, &op2, &res) != succeed))			\
		internal(file_line, "bist_binary_%s: %s(%s, %s) %s",	\
			stringify(type), fn_name,			\
			str_from_signed(op1, 16), str_from_signed(op2, 16),\
			succeed ? "failed" : "succeeded");		\
	if (!succeed && unlikely(res != -1))				\
		internal(file_line, "bist_binary_%s: %s(%s, %s) modified result: %s",\
			stringify(type), fn_name,			\
			str_from_signed(op1, 16), str_from_signed(op2, 16), str_from_signed(res, 16));\
	if (succeed && unlikely(res != result))				\
		internal(file_line, "bist_binary_%s: %s(%s, %s) returned wrong result: %s != %s",\
			stringify(type), fn_name,			\
			str_from_signed(op1, 16), str_from_signed(op2, 16), str_from_signed(res, 16),\
			str_from_signed(result, 16));			\
}									\
									\
static attr_noinline void cat(bist_unary_,type)(			\
	bool (*fn)(const type *, type *),				\
	const char *fn_name,						\
	type op1, bool succeed, type result)				\
{									\
	type res;							\
	type * volatile resp = &res; /* avoid failure with icc */	\
	*resp = -1;							\
	res = -1;							\
	if (unlikely(fn(&op1, &res) != succeed))			\
		internal(file_line, "bist_binary_%s: %s(%s) %s",	\
			stringify(type), fn_name,			\
			str_from_signed(op1, 16),			\
			succeed ? "failed" : "succeeded");		\
	if (!succeed && unlikely(res != -1))				\
		internal(file_line, "bist_binary_%s: %s(%s) modified result: %s",\
			stringify(type), fn_name,			\
			str_from_signed(op1, 16), str_from_signed(res, 16));\
	if (succeed && unlikely(res != result))				\
		internal(file_line, "bist_binary_%s: %s(%s) returned wrong result: %s != %s",\
			stringify(type), fn_name,			\
			str_from_signed(op1, 16), str_from_signed(res, 16),\
			str_from_signed(result, 16));			\
}									\
									\
static attr_noinline void cat(bist_arithm_,type)(void)			\
{									\
	type op1 = 10;							\
	type op2 = 20;							\
	type res;							\
	type * volatile resp = &res; /* avoid failure with icc */	\
	*resp = 25;							\
	res = 25;							\
	if (!cat(INT_binary_add_,type)(&op1, &op2, &res))		\
		internal(file_line, "bist_arithm_%s: %s failed",	\
			stringify(type),				\
			stringify(cat(add_,type)));			\
	if (res != 30)							\
		internal(file_line, "bist_arithm_%s: %s: bad result %"PRIdMAX,\
			stringify(type),				\
			stringify(cat(add_,type)), (intmax_t)res);	\
									\
	cat(bist_binary_,type)(cat(INT_binary_add_,type), stringify(cat(INT_binary_add_,type)), 10, 20, true, 30);\
	cat(bist_binary_,type)(cat(INT_binary_add_,type), stringify(cat(INT_binary_add_,type)), sign_bit(utype) / 2, sign_bit(utype) / 2, false, 0);\
	cat(bist_binary_,type)(cat(INT_binary_add_,type), stringify(cat(INT_binary_add_,type)), sign_bit(utype) / 2, sign_bit(utype) / 2 - 1, true, sign_bit(utype) - 1);\
	cat(bist_binary_,type)(cat(INT_binary_add_,type), stringify(cat(INT_binary_add_,type)), -(sign_bit(utype) / 2), -(sign_bit(utype) / 2) - 1, false, 0);\
	cat(bist_binary_,type)(cat(INT_binary_add_,type), stringify(cat(INT_binary_add_,type)), -(sign_bit(utype) / 2), -(sign_bit(utype) / 2), true, sign_bit(utype));\
									\
	cat(bist_binary_,type)(cat(INT_binary_subtract_,type), stringify(cat(INT_binary_subtract_,type)), 20, 30, true, -10);\
	cat(bist_binary_,type)(cat(INT_binary_subtract_,type), stringify(cat(INT_binary_subtract_,type)), sign_bit(utype) / 2, -(sign_bit(utype) / 2), false, 0);\
	cat(bist_binary_,type)(cat(INT_binary_subtract_,type), stringify(cat(INT_binary_subtract_,type)), sign_bit(utype) / 2, -(sign_bit(utype) / 2 - 1), true, sign_bit(utype) - 1);\
	cat(bist_binary_,type)(cat(INT_binary_subtract_,type), stringify(cat(INT_binary_subtract_,type)), -(sign_bit(utype) / 2), sign_bit(utype) / 2 + 1, false, 0);\
	cat(bist_binary_,type)(cat(INT_binary_subtract_,type), stringify(cat(INT_binary_subtract_,type)), -(sign_bit(utype) / 2), sign_bit(utype) / 2, true, sign_bit(utype));\
									\
	cat(bist_unary_,type)(cat(INT_unary_not_,type), stringify(cat(INT_unary_not_,type)), 0, true, -1);\
	cat(bist_unary_,type)(cat(INT_unary_not_,type), stringify(cat(INT_unary_not_,type)), 10, true, -11);\
	cat(bist_unary_,type)(cat(INT_unary_not_,type), stringify(cat(INT_unary_not_,type)), sign_bit(utype), true, sign_bit(utype) - 1);\
	cat(bist_unary_,type)(cat(INT_unary_not_,type), stringify(cat(INT_unary_not_,type)), sign_bit(utype) - 1, true, sign_bit(utype));\
	cat(bist_unary_,type)(cat(INT_unary_neg_,type), stringify(cat(INT_unary_neg_,type)), 0, true, 0);\
	cat(bist_unary_,type)(cat(INT_unary_neg_,type), stringify(cat(INT_unary_neg_,type)), 10, true, -10);\
	cat(bist_unary_,type)(cat(INT_unary_neg_,type), stringify(cat(INT_unary_neg_,type)), sign_bit(utype), false, 0);\
	cat(bist_unary_,type)(cat(INT_unary_neg_,type), stringify(cat(INT_unary_neg_,type)), sign_bit(utype) - 1, true, sign_bit(type) + 1);\
									\
	cat(bist_binary_,type)(cat(INT_binary_multiply_,type), stringify(cat(INT_binary_multiply_,type)), 10, 11, true, 110);\
	cat(bist_binary_,type)(cat(INT_binary_multiply_,type), stringify(cat(INT_binary_multiply_,type)), (type)1 << (sizeof(type) * 4 - 1), (type)1 << (sizeof(type) * 4), false, 0);\
	cat(bist_binary_,type)(cat(INT_binary_multiply_,type), stringify(cat(INT_binary_multiply_,type)), ((type)1 << (sizeof(type) * 4 - 1)) - 1, (type)1 << (sizeof(type) * 4), true, (((type)1 << (sizeof(type) * 4 - 1)) - 1) * ((type)1 << (sizeof(type) * 4)));\
	cat(bist_binary_,type)(cat(INT_binary_multiply_,type), stringify(cat(INT_binary_multiply_,type)), -((type)1 << (sizeof(type) * 4 - 1)), (type)1 << (sizeof(type) * 4), true, sign_bit(utype));\
	cat(bist_binary_,type)(cat(INT_binary_multiply_,type), stringify(cat(INT_binary_multiply_,type)), -((type)1 << (sizeof(type) * 4 - 1)), ((type)1 << (sizeof(type) * 4)) + 1, false, 0);\
									\
	cat(bist_binary_,type)(cat(INT_binary_divide_,type), stringify(cat(INT_binary_divide_,type)), 10, 0, false, 0);\
	cat(bist_binary_,type)(cat(INT_binary_divide_,type), stringify(cat(INT_binary_divide_,type)), 121, 11, true, 11);\
	cat(bist_binary_,type)(cat(INT_binary_divide_,type), stringify(cat(INT_binary_divide_,type)), 119, 11, true, 10);\
	cat(bist_binary_,type)(cat(INT_binary_divide_,type), stringify(cat(INT_binary_divide_,type)), -119, 11, true, -10);\
	cat(bist_binary_,type)(cat(INT_binary_divide_,type), stringify(cat(INT_binary_divide_,type)), 119, -11, true, -10);\
	cat(bist_binary_,type)(cat(INT_binary_divide_,type), stringify(cat(INT_binary_divide_,type)), -119, -11, true, 10);\
									\
	cat(bist_binary_,type)(cat(INT_binary_modulo_,type), stringify(cat(INT_binary_modulo_,type)), 10, 0, false, 0);\
	cat(bist_binary_,type)(cat(INT_binary_modulo_,type), stringify(cat(INT_binary_modulo_,type)), 121, 11, true, 0);\
	cat(bist_binary_,type)(cat(INT_binary_modulo_,type), stringify(cat(INT_binary_modulo_,type)), 119, 11, true, 9);\
	cat(bist_binary_,type)(cat(INT_binary_modulo_,type), stringify(cat(INT_binary_modulo_,type)), -119, 11, true, -9);\
	cat(bist_binary_,type)(cat(INT_binary_modulo_,type), stringify(cat(INT_binary_modulo_,type)), 119, -11, true, 9);\
	cat(bist_binary_,type)(cat(INT_binary_modulo_,type), stringify(cat(INT_binary_modulo_,type)), -119, -11, true, -9);\
									\
	cat(bist_popcnt_,type);						\
}
for_all_int(generate_bist_arithm, for_all_empty)
#undef generate_bist_arithm


#ifdef HAVE___FP16
#define fp16	__fp16
#else
#define fp16	_Float16
#endif

static attr_noinline void bist_conv_float_half(float f1, float f3, bool eq)
{
	uint16_t n;
	float f2;
#ifdef TEST_HALF_FLOAT_CONVERSION
	union {
		uint16_t i;
		fp16 fp;
	} u;
#endif
	/*debug("f2h: %.9e", f1);*/
	n = float_to_half(f1);
#ifdef TEST_HALF_FLOAT_CONVERSION
	u.fp = (fp16)f1;
	if (!((n & 0x7fff) > 0x7c00 && (u.i & 0x7fff) > 0x7c00))
		if (unlikely(n != u.i))
			internal(file_line, "bist_conv_float_half: test failed for %.9e: %u != %u", f1, (unsigned)n, (unsigned)u.i);
#endif
	/*debug("h2f: %04x", n);*/
	f2 = half_to_float(n);
	/*debug("done: %.9e", f2);*/
	if (eq && memcmp(&f2, &f3, sizeof(float)))
		internal(file_line, "bist_conv_float_half: test failed for %.9e -> %04x -> %.9e (should be %.9e)", f1, (unsigned)n, f2, f3);
}

static attr_noinline void bist_conv(unsigned attr_unused flags)
{
	uint32_t i;
	for (i = 0; i < 65536; i++) {
		float f1;
		uint16_t n;
#ifdef TEST_HALF_FLOAT_CONVERSION
		float f2;
		union {
			uint16_t i;
			fp16 fp;
		} u;
		u.i = i;
#endif
		f1 = half_to_float(i);
#ifdef TEST_HALF_FLOAT_CONVERSION
		f2 = (float)u.fp;
		if (unlikely(isnan_real32_t(f1) != isnan_real32_t(f2)))
			internal(file_line, "bist_conv: nan test failed for %lx: %.9e != %.9e", (unsigned long)i, f1, f2);
		if (likely(!isnan_real32_t(f1)) && memcmp(&f1, &f2, sizeof(float)))
			internal(file_line, "bist_conv: test failed for %lx: %.9e != %.9e", (unsigned long)i, f1, f2);
#endif
		n = float_to_half(f1);
		if (!((n & 0x7fff) > 0x7c00 && (i & 0x7fff) > 0x7c00))
			if (unlikely(n != i))
				internal(file_line, "bist_conv: test failed for %lx -> %.9e -> %04x", (unsigned long)i, f1, (unsigned)n);

	}
	for (i = 0; i < 131072; i++) {
		uint32_t ri = i;
		if (i >= 2048) {
			uint32_t l, tr;
			uint32_t ii;
			for (ii = i, l = -1; ii; ii >>= 1) l++;
			l -= 11;
			tr = ri & ((2UL << l) - 1);
			ri &= -(2UL << l);
			if (tr >= (1UL << l) + !(ri & (2UL << l)))
				ri += 2UL << l;
		}
#ifdef HUGE_VAL
		bist_conv_float_half((float)i, ri >= 0x10000 ? HUGE_VAL : (float)ri, true);
#endif
		bist_conv_float_half(-(float)(i * 2) + 1, -(float)(i * 2) + 1, i < 1024);
		bist_conv_float_half((float)i / 0x400, (float)i / 0x400, i <= 2048);
		bist_conv_float_half((float)i / 0x4000000, (float)i / 0x4000000, !(i & 0x003f));
		bist_conv_float_half((float)(1. / (i + 1)), (float)(1. / (i + 1)), is_power_of_2(i + 1));
	}
	bist_conv_float_half(-0., -0., true);
#ifdef HUGE_VAL
	bist_conv_float_half(HUGE_VAL, HUGE_VAL, true);
	bist_conv_float_half(-HUGE_VAL, -HUGE_VAL, true);
#endif
#ifdef NAN
	bist_conv_float_half(NAN, NAN, false);
#endif
}

#undef fp16


#define left		children[0]
#define right		children[1]
#define rb_is_black(n)	((n)->color == RB_BLACK)

struct rb_test {
	int value;
	struct tree_entry entry;
};

#define TREE_SIZE	1024
#define TREE_STEPS	10240

shared_var int rbtree_content[TREE_SIZE];
shared_var int rbtree_content_n;
shared_var struct tree rbtree;
shared_var int rbtree_node_count;

shared_var int rbtree_verify_node_count;

static int bist_rbtree_verify_node(struct tree_entry *e, int from, int to)
{
	struct rb_test *t;
	int depth_left, depth_right, depth_me;
	if (!e)
		return 1;
	rbtree_verify_node_count++;
	t = get_struct(e, struct rb_test, entry);
	tree_verify_node(&t->entry);
	if (unlikely(t->value < from) || unlikely(t->value > to))
		internal(file_line, "bist_rbtree_verify_node: value %d out of range %d,%d", t->value, from, to);
	if (!rb_is_black(e)) {
		if (e->left && unlikely(!rb_is_black(e->left)))
			internal(file_line, "bist_rbtree_verify_node: left node is not black");
		if (e->right && unlikely(!rb_is_black(e->right)))
			internal(file_line, "bist_rbtree_verify_node: right node is not black");
		depth_me = 0;
	} else {
		depth_me = 1;
	}
	depth_left = bist_rbtree_verify_node(e->left, from, (unsigned)t->value - 1);
	depth_right = bist_rbtree_verify_node(e->right, (unsigned)t->value + 1, to);
	if (unlikely(depth_left != depth_right))
		internal(file_line, "bist_rbtree_verify_node: imbalanced node: %d != %d", depth_left, depth_right);
	return depth_left + depth_me;
}

static void bist_rbtree_verify(struct tree *root)
{
	rbtree_verify_node_count = 0;
	(void)bist_rbtree_verify_node(root->root, 0, signed_maximum(int));
	if (unlikely(rbtree_verify_node_count != rbtree_node_count))
		internal(file_line, "bist_rbtree_verify: node count mismatch: %d != %d", rbtree_verify_node_count, rbtree_node_count);
}

static int bist_rb_test(const struct tree_entry *e, uintptr_t i)
{
	const struct rb_test *t = get_struct(e, struct rb_test, entry);
	if (t->value == (int)i) return 0;
	if (t->value > (int)i) return 1;
	return -1;
}

static bool bist_rbtree_insert(int n)
{
	struct tree_entry *found;
	struct rb_test *t;
	struct tree_insert_position ins;
	found = tree_find_for_insert(&rbtree, bist_rb_test, n, &ins);
	if (found)
		return false;
	t = mem_alloc(struct rb_test *, sizeof(struct rb_test));
	/*debug("inserting %p:%d", t, n);*/
	t->value = n;
	tree_insert_after_find(&t->entry, &ins);
	rbtree_node_count++;
	bist_rbtree_verify(&rbtree);
	found = tree_find(&rbtree, bist_rb_test, n);
	if (found != &t->entry)
		internal(file_line, "bist_rbtree_insert: number %d not found in tree: %p, %p", n, found, &t->entry);
	found = tree_find_next(&rbtree, bist_rb_test, n - 1);
	if (found != &t->entry)
		internal(file_line, "bist_rbtree_insert: number %d not found in tree: %p, %p", n, found, &t->entry);
	return true;
}

static void bist_rbtree_insert_into_content(int n)
{
	rbtree_content[rbtree_content_n++] = n;
	(void)bist_rbtree_insert(n);
}

static void bist_rbtree_delete(int n)
{
	struct tree_entry *f;
	struct rb_test *t;
	f = tree_find(&rbtree, bist_rb_test, n);
	if (unlikely(!f))
		internal(file_line, "bist_rbtree_delete: item %d not found", n);
	t = get_struct(f, struct rb_test, entry);
	tree_delete(&t->entry);
	rbtree_node_count--;
	bist_rbtree_verify(&rbtree);
	mem_free(t);
}

static int rbtree_content_compare(const void *p1, const void *p2)
{
	int i1 = *(int *)p1;
	int i2 = *(int *)p2;
	if (i1 < i2) return -1;
	if (likely(i1 > i2)) return 1;
	return 0;
}

static attr_noinline void bist_rbtree(unsigned attr_unused flags)
{
	int n, m, e;
	rbtree_content_n = 0;
	tree_init(&rbtree);
	rbtree_node_count = 0;
	for (n = 0; n < TREE_SIZE; n += 4) {
		bist_rbtree_insert_into_content(n);
		bist_rbtree_insert_into_content(rand());
		bist_rbtree_insert_into_content(TREE_SIZE * 3 / 2 - n);
		bist_rbtree_insert_into_content(rand() & 0xfff);
	}
	qsort(rbtree_content, rbtree_content_n, sizeof(rbtree_content[0]), rbtree_content_compare);
	for (e = 0, m = 0, n = 0; n < rbtree_content_n; n++) {
		if (n + 1 < rbtree_content_n && rbtree_content[n] == rbtree_content[n + 1]) {
			e++;
			continue;
		}
		rbtree_content[m++] = rbtree_content[n];
		/*printf("entry[%d]: %d\n", m - 1, rbtree_content[m - 1]);*/
	}
	rbtree_content_n = m;
	/*printf("used entries = %d\n", m);*/
	if (unlikely(rbtree_content_n != rbtree_node_count))
		internal(file_line, "bist_rbtree: bad node count: %d != %d", rbtree_content_n, rbtree_node_count);
	while (1) {
		int x;
		struct tree_entry *q;
		if (tree_is_empty(&rbtree)) break;
		bist_rbtree_delete(get_struct(tree_first(&rbtree), struct rb_test, entry)->value);
		if (tree_is_empty(&rbtree)) break;
		bist_rbtree_delete(get_struct(tree_any(&rbtree), struct rb_test, entry)->value);
		if (tree_is_empty(&rbtree)) break;
		x = rand() % rbtree_content_n;
		q = tree_find(&rbtree, bist_rb_test, rbtree_content[x]);
		if (q) {
			bist_rbtree_delete(get_struct(q, struct rb_test, entry)->value);
		}
	}

	if (unlikely(rbtree_node_count))
		internal(file_line, "bist_rbtree: %d nodes leaked in test 1", rbtree_node_count);

	/* 2nd test */
	tree_init(&rbtree);
	(void)memset(&rbtree_content, 0, sizeof rbtree_content);
	for (n = 0; n < TREE_STEPS; n++) {
		int x = rand() % TREE_SIZE;
		if (rbtree_content[x]) {
			bist_rbtree_delete(x);
			rbtree_content[x] = 0;
		} else {
			if (!bist_rbtree_insert(x))
				internal(file_line, "bist_rbtree: %d already present", x);
			rbtree_content[x] = 1;
		}
	}

	while (!tree_is_empty(&rbtree)) {
		int x = rand() % TREE_SIZE;
		if (rbtree_content[x]) {
			bist_rbtree_delete(x);
			rbtree_content[x] = 0;
		}
	}

	if (unlikely(rbtree_node_count))
		internal(file_line, "bist_rbtree: %d nodes leaked in test 2", rbtree_node_count);
}


#if INT_MASK & (1 << 2)
#define int_bist_t	int32_t
#define int_bist_type	type_get_fixed(2, false)
#elif INT_MASK & (1 << 3)
#define int_bist_t	int64_t
#define int_bist_type	type_get_fixed(3, false)
#elif INT_MASK & (1 << 4)
#define int_bist_t	int128_t
#define int_bist_type	type_get_fixed(4, false)
#elif INT_MASK & (1 << 1)
#define int_bist_t	int16_t
#define int_bist_type	type_get_fixed(1, false)
#else
#define int_bist_t	int8_t
#define int_bist_type	type_get_fixed(0, false)
#endif

#define N_ARRAY_ENTRIES		minimum(192, signed_maximum(int_default_t))
#define N_ARRAY_OPERATIONS	2048
#define FLAT_ARRAY_LENGTH	3
#define SAME_ARRAY_LENGTH	127
#define ARRAY_STRIDE		3
#define SAME_MAGIC		-123

#if 0
static void bist_dump_array(const char *name, struct data *a)
{
	if (name)
		debug("%s", name);
	if (refcount_is_invalid(&a->refcount))
		internal(file_line, "bist_light_array_check: invalid refcount");
	switch (da_tag(a)) {
		case DATA_TAG_array_flat:
			debug("           FLAT");
			break;
		case DATA_TAG_array_slice:
			debug("           SLICE");
			break;
		case DATA_TAG_array_pointers:
			debug("           POINTERS");
			break;
		case DATA_TAG_array_same:
			debug("           SAME");
			break;
		case DATA_TAG_array_btree: {
			btree_entries_t bt_pos;
			debug("%.*sBTREE(%d)", 10 - da(a,array_btree)->depth, "          ", (int)da(a,array_btree)->n_used_btree_entries);
			for (bt_pos = 0; bt_pos < da(a,array_btree)->n_used_btree_entries; bt_pos++) {
				struct btree_level *levels = da(a,array_btree)->btree;
				bist_dump_array(NULL, pointer_get_data(levels[bt_pos].node));
			}
			break;
		}

		default:
			internal(file_line, "bist_dump_array: invalid array tag %u", da_tag(a));
	}
}
#else
#define bist_dump_array(name, a)	do { } while (0)
#endif

struct bist_array_state {
	int8_t array_flag[N_ARRAY_ENTRIES];
	pointer_t array_ptr;
	int_bist_t array_n_same;
	struct data *array_same_pointer;
};

static void bist_array_verify_node(struct bist_array_state *st, struct data *d, const array_index_t *size, int_bist_t abs_idx)
{
	int_default_t i;
	btree_entries_t bi;
	int_bist_t n;
	struct data *s;
	switch (da_tag(d)) {
		case DATA_TAG_array_flat:
			if (unlikely(da(d,array_flat)->n_used_entries > da(d,array_flat)->n_allocated_entries))
				internal(file_line, "bist_array_verify_node: flat entries overflow");

			if (size && unlikely(index_to_int(*size) != da(d,array_flat)->n_used_entries))
				internal(file_line, "bist_array_verify_node: flat invalid size %"PRIdMAX" != %"PRIdMAX"", (intmax_t)index_to_int(*size), (intmax_t)da(d,array_flat)->n_used_entries);

			for (i = 0; i < da(d,array_flat)->n_used_entries; i++) {
				n = cast_ptr(int_bist_t *, da_array_flat(d))[i];
				if (unlikely(n != abs_idx + i))
					internal(file_line, "bist_array_verify_node: invalid flat value %"PRIdMAX" + %"PRIdMAX" != %"PRIdMAX"", (intmax_t)abs_idx, (intmax_t)i, (intmax_t)n);
			}

			break;
		case DATA_TAG_array_slice:
			if (size && unlikely(index_to_int(*size) != da(d,array_slice)->n_entries))
				internal(file_line, "bist_array_verify_node: slice invalid size %"PRIdMAX" != %"PRIdMAX"", (intmax_t)index_to_int(*size), (intmax_t)da(d,array_slice)->n_entries);
			break;
		case DATA_TAG_array_pointers:
			if (unlikely(da(d,array_pointers)->n_used_entries > da(d,array_pointers)->n_allocated_entries))
				internal(file_line, "bist_array_verify_node: pointers entries overflow");

			if (size && unlikely(index_to_int(*size) != da(d,array_pointers)->n_used_entries))
				internal(file_line, "bist_array_verify_node: pointers invalid size %"PRIdMAX" != %"PRIdMAX"", (intmax_t)index_to_int(*size), (intmax_t)da(d,array_pointers)->n_used_entries);

			for (i = 0; i < da(d,array_pointers)->n_used_entries; i++) {
				struct data *p = pointer_get_data(da(d,array_pointers)->pointer[i]);
				n = *cast_ptr(int_bist_t *, da_flat(p));
				if (unlikely(n != abs_idx + i))
					internal(file_line, "bist_array_verify_node: invalid pointer value %"PRIdMAX" + %"PRIdMAX" != %"PRIdMAX"", (intmax_t)abs_idx, (intmax_t)i, (intmax_t)n);
			}

			break;
		case DATA_TAG_array_same:
			if (size && (unlikely(!index_ge_index(*size, da(d,array_same)->n_entries)) ||
				     unlikely(!index_ge_index(da(d,array_same)->n_entries, *size))))
				internal(file_line, "bist_array_verify_node: same invalid size %"PRIdMAX" != %"PRIdMAX"", (intmax_t)index_to_int(*size), (intmax_t)index_to_int(da(d,array_same)->n_entries));
			s = pointer_get_data(da(d,array_same)->pointer);
			n = *cast_ptr(int_bist_t *, da_flat(s));
			if (unlikely(n != SAME_MAGIC))
				internal(file_line, "bist_array_verify_node: invalid same value %ld", (long)n);
			if (unlikely(!st->array_n_same))
				st->array_same_pointer = s;
			else if (unlikely(st->array_same_pointer != s))
				internal(file_line, "bist_array_verify_node: same unexpectedly split");
			st->array_n_same++;
			break;
		case DATA_TAG_array_btree:
			if (unlikely(da(d,array_btree)->n_used_btree_entries > da(d,array_btree)->n_allocated_btree_entries))
				internal(file_line, "bist_array_verify_node: btree entries overflow");

			if (unlikely(da(d,array_btree)->n_used_btree_entries < (!size ? 2 : BTREE_MIN_SIZE)) ||
			    unlikely(da(d,array_btree)->n_used_btree_entries > BTREE_MAX_SIZE))
				internal(file_line, "bist_array_verify_node: btree entries not in range (%"PRIuMAX",%"PRIuMAX"): %"PRIuMAX"", (uintmax_t)(!size ? 2 : BTREE_MIN_SIZE), (uintmax_t)BTREE_MAX_SIZE, (uintmax_t)da(d,array_btree)->n_used_btree_entries);

			if (size && (unlikely(!index_ge_index(*size, da(d,array_btree)->btree[da(d,array_btree)->n_used_btree_entries - 1].end_index)) ||
				     unlikely(!index_ge_index(da(d,array_btree)->btree[da(d,array_btree)->n_used_btree_entries - 1].end_index, *size))))
				internal(file_line, "bist_array_verify_node: btree invalid size: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)index_to_int(*size), (intmax_t)index_to_int(da(d,array_btree)->btree[da(d,array_btree)->n_used_btree_entries - 1].end_index));

			for (bi = 0; bi < da(d,array_btree)->n_used_btree_entries; bi++) {
				struct data *sub;
				array_index_t sub_size;
				int_bist_t ab = abs_idx;
				index_copy(&sub_size, da(d,array_btree)->btree[bi].end_index);
				if (bi) {
					array_index_t *ei = &da(d,array_btree)->btree[bi - 1].end_index;
					if (unlikely(index_is_mp(*ei))) {
						mpint_t mp;
						int_bist_t mpi = (int_bist_t)-0x7fffffffL;	/* avoid warning */
						index_to_mpint(*ei, &mp);
						cat(mpint_export_to_,int_bist_t)(&mp, &mpi, NULL);
						mpint_free(&mp);
						ab += mpi;
					} else {
						ab += (int_bist_t)index_to_int(*ei);
					}
					index_sub(&sub_size, *ei);
				}

				sub = pointer_get_data(da(d,array_btree)->btree[bi].node);
				da_array_assert_son(d, sub);
				bist_array_verify_node(st, sub, &sub_size, ab);
				index_free(&sub_size);
			}
			break;
		default:
			internal(file_line, "bist_array_verify_node: invalid array tag %u", da_tag(d));
	}
}

static void bist_array_verify(struct bist_array_state *st, bool test_same)
{
	struct data *d = pointer_get_data(st->array_ptr);
	st->array_n_same = 0;
	bist_array_verify_node(st, d, NULL, 0);
#if 1
	if (test_same && st->array_n_same && unlikely(st->array_n_same != (int_bist_t)refcount_get_nonatomic(&st->array_same_pointer->refcount_)))
		internal(file_line, "bist_array_verify: same refcount mismatch: %ld != %ld", (long)st->array_n_same, (long)refcount_get_nonatomic(&st->array_same_pointer->refcount_));
#endif
}

static void bist_array_test_ptr(pointer_t ptr, int_bist_t want)
{
	int_bist_t n = *cast_ptr(int_bist_t *, da_flat(pointer_get_data(ptr)));
	if (unlikely(n != want))
		internal(file_line, "bist_array_test_ptr: invalid pointer value: %ld != %ld", (long)n, (long)want);
}

static array_index_t int32_to_idx(int_bist_t i)
{
	array_index_t idx;
	if (INT_DEFAULT_BITS >= sizeof(int_bist_t) * 8
#ifdef MPINT_GMP
	    && rand() & 1
#endif
	    ) {
		index_from_int(&idx, (int_default_t)i);
	} else {
		mpint_t mp;
		cat(mpint_init_from_,int_bist_t)(&mp, i, NULL);
		index_from_mp(&idx, &mp);
		mpint_free(&mp);
	}
	return idx;
}

static void bist_array_toggle(struct bist_array_state *st, int_bist_t i)
{
	pointer_t *result_ptr;
	unsigned char *result_flat;
	const struct type *flat_type;
	struct data *d;

	array_read(pointer_get_data(st->array_ptr), int32_to_idx(i), &result_ptr, &result_flat, &flat_type, NULL, NULL);

	if (!st->array_flag[i]) {
		if (unlikely(!result_flat))
			internal(file_line, "bist_array_toggle: result_flat should be set at index %ld", (long)i);
		if (unlikely(result_ptr != NULL))
			internal(file_line, "bist_array_toggle: result_ptr should not be set at index %ld", (long)i);
		if (unlikely(!type_is_equal(flat_type, int_bist_type)))
			internal(file_line, "bist_array_toggle: invalid type at index %ld", (long)i);
		if (unlikely(*cast_ptr(int_bist_t *, result_flat) != i))
			internal(file_line, "bist_array_toggle: invalid flat value at index %ld: %ld", (long)i, (long)*cast_ptr(int_bist_t *, result_flat));
		if (unlikely(!array_modify(&st->array_ptr, int32_to_idx(i), ARRAY_MODIFY_NEED_PTR, &result_ptr, &result_flat, &flat_type, NULL, NULL)))
			fatal("bist_array_toggle: array_modify need ptr failed");
			/*internal(file_line, "bist_array_toggle: array_modify failed");*/
		bist_array_test_ptr(*result_ptr, i);
		st->array_flag[i] = 1;
	} else {
		int_bist_t should_be;
		if (unlikely(result_flat != NULL))
			internal(file_line, "bist_array_toggle: result_flat should not be set at index %ld", (long)i);
		if (unlikely(!result_ptr))
			internal(file_line, "bist_array_toggle: result_ptr should be set at index %ld", (long)i);
		d = pointer_get_data(*result_ptr);
		if (st->array_flag[i] == -1)
			should_be = SAME_MAGIC;
		else
			should_be = i;
		if (unlikely(*cast_ptr(int_bist_t *, da_flat(d)) != should_be))
			internal(file_line, "bist_array_toggle: invalid pointed value at index %ld: %ld != %ld", (long)i, (long)*cast_ptr(int_bist_t *, da_flat(d)), (long)should_be);
		flat_type = int_bist_type;
		if (st->array_flag[i] == -1 && rand() & 1) {
			struct data *flat;
			int_bist_t di;
			if (unlikely(!array_modify(&st->array_ptr, int32_to_idx(i), ARRAY_MODIFY_NEED_PTR, &result_ptr, &result_flat, &flat_type, NULL, NULL)))
				fatal("bist_array_toggle: array_modify from same need ptr failed");
				/*internal(file_line, "bist_array_toggle: array_modify failed");*/
			bist_array_test_ptr(*result_ptr, SAME_MAGIC);
			di = i;
			flat = data_alloc_flat_mayfail(TYPE_TAG_N, cast_ptr(unsigned char *, &di), sizeof(int_bist_t), NULL pass_file_line);
			pointer_dereference(*result_ptr);
			*result_ptr = pointer_data(flat);
			st->array_flag[i] = 1;
		} else {
			if (unlikely(!array_modify(&st->array_ptr, int32_to_idx(i), ARRAY_MODIFY_NEED_FLAT, &result_ptr, &result_flat, &flat_type, NULL, NULL)))
				fatal("bist_array_toggle: array_modify need ptr failed");
				/*internal(file_line, "bist_array_toggle: array_modify failed");*/
			*cast_ptr(int_bist_t *, result_flat) = i;
			st->array_flag[i] = 0;
		}
	}
	bist_array_verify(st, true);
}

static attr_noinline void bist_array_st(struct bist_array_state *st, unsigned flags)
{
	unsigned rep;
	int_bist_t i, j, half, l;
	int_bist_t di;
	struct data *array, *flat;
	pointer_t array_ptr_2;

	if (!(flags & 0x80)) {
		array = data_alloc_array_flat_mayfail(int_bist_type, 0, 0, false, NULL pass_file_line);
		st->array_ptr = pointer_data(array);
		array_ptr_2 = pointer_data(array);
		pointer_reference_owned(array_ptr_2);

		half = N_ARRAY_ENTRIES / 2;
		half -= half % FLAT_ARRAY_LENGTH;
		for (j = half; j < N_ARRAY_ENTRIES; j += l) {
			l = minimum(N_ARRAY_ENTRIES - j, (int_bist_t)FLAT_ARRAY_LENGTH);
			if (!(flags & 0x01)) {
				array = data_alloc_array_flat_mayfail(int_bist_type, l, l, false, NULL pass_file_line);
				for (i = 0; i < l; i++) {
					cast_ptr(int_bist_t *, da_array_flat(array))[i] = j + i;
					st->array_flag[j + i] = 0;
				}
			} else {
				array = data_alloc_array_pointers_mayfail(l, l, NULL pass_file_line);
				for (i = 0; i < l; i++) {
					di = j + i;
					flat = data_alloc_flat_mayfail(TYPE_TAG_N, cast_ptr(unsigned char *, &di), sizeof(int_bist_t), NULL pass_file_line);
					da(array,array_pointers)->pointer[i] = pointer_data(flat);
					st->array_flag[j + i] = 1;
				}
			}
			st->array_ptr = pointer_data(array_join(pointer_get_data(st->array_ptr), array, NULL));
		}
		for (j = half - FLAT_ARRAY_LENGTH; j >= 0; j -= FLAT_ARRAY_LENGTH) {
			l = FLAT_ARRAY_LENGTH;
			if (!(flags & 0x01)) {
				array = data_alloc_array_flat_mayfail(int_bist_type, l, l, false, NULL pass_file_line);
				for (i = 0; i < l; i++) {
					cast_ptr(int_bist_t *, da_array_flat(array))[i] = j + i;
					st->array_flag[j + i] = 0;
				}
			} else {
				array = data_alloc_array_pointers_mayfail(l, l, NULL pass_file_line);
				for (i = 0; i < l; i++) {
					di = j + i;
					flat = data_alloc_flat_mayfail(TYPE_TAG_N, cast_ptr(unsigned char *, &di), sizeof(int_bist_t), NULL pass_file_line);
					da(array,array_pointers)->pointer[i] = pointer_data(flat);
					st->array_flag[j + i] = 1;
				}
			}
			array_ptr_2 = pointer_data(array_join(array, pointer_get_data(array_ptr_2), NULL));
		}
		st->array_ptr = pointer_data(array_join(pointer_get_data(array_ptr_2), pointer_get_data(st->array_ptr), NULL));
	} else {
		array = data_alloc_array_flat_mayfail(int_bist_type, N_ARRAY_ENTRIES, N_ARRAY_ENTRIES, false, NULL pass_file_line);
		for (i = 0; i < N_ARRAY_ENTRIES; i++) {
			st->array_flag[i] = 0;
			cast_ptr(int_bist_t *, da_array_flat(array))[i] = i;
		}
		st->array_ptr = pointer_data(array);
	}
	/*debug("depth: %d", da_array_depth(pointer_get_data(st->array_ptr)));*/
	for (rep = 0; rep < N_ARRAY_OPERATIONS; rep++) {
		i = rand() % N_ARRAY_ENTRIES;
		bist_array_toggle(st, i);
	}
	/*debug("depth: %d", da_array_depth(pointer_get_data(st->array_ptr)));*/
	for (j = 0; j < ARRAY_STRIDE; j++)
		for (i = j; i <= N_ARRAY_ENTRIES - ARRAY_STRIDE; i += ARRAY_STRIDE) {
			if (!st->array_flag[i])
				bist_array_toggle(st, i);
		}
	/*debug("depth: %d", da_array_depth(pointer_get_data(st->array_ptr)));*/
	for (rep = 0; rep < N_ARRAY_OPERATIONS; rep++) {
		i = rand() % N_ARRAY_ENTRIES;
		bist_array_toggle(st, i);
	}
	/*debug("depth: %d", da_array_depth(pointer_get_data(st->array_ptr)));*/
	for (j = 0; j < ARRAY_STRIDE; j++)
		for (i = j; i <= N_ARRAY_ENTRIES - ARRAY_STRIDE; i += ARRAY_STRIDE) {
			if (st->array_flag[i])
				bist_array_toggle(st, i);
		}
	/*debug("depth: %d", da_array_depth(pointer_get_data(st->array_ptr)));*/
	bist_array_verify(st, true);
	pointer_dereference(st->array_ptr);
}

#if 0
struct bist_array_state *global_st;
void bist_g_verify(void)
{
	bist_array_verify(global_st, false);
}
#endif

static attr_noinline void bist_array_2_st(struct bist_array_state *st)
{
	unsigned rep;
	int_bist_t i, j, l;
	int_bist_t di;
	struct data *array, *flat;
	pointer_t flat_ptr;

	di = SAME_MAGIC;
	flat = data_alloc_flat_mayfail(TYPE_TAG_N, cast_ptr(unsigned char *, &di), sizeof(int_bist_t), NULL pass_file_line);
	flat_ptr = pointer_data(flat);
	array = data_alloc_array_pointers_mayfail(0, 0, NULL pass_file_line);
	st->array_ptr = pointer_data(array);
	for (j = 0; j < N_ARRAY_ENTRIES; j += l) {
		array_index_t ll;
		l = minimum(N_ARRAY_ENTRIES - j, (int_bist_t)SAME_ARRAY_LENGTH);
		if (j) pointer_reference_owned(flat_ptr);
		index_from_int(&ll, l);
		array = data_alloc_array_same_mayfail(ll, NULL pass_file_line);
		da(array,array_same)->pointer = flat_ptr;
		for (i = 0; i < l; i++) {
			st->array_flag[j + i] = -1;
		}
		st->array_ptr = pointer_data(array_join(pointer_get_data(st->array_ptr), array, NULL));
	}
	for (rep = 0; rep < N_ARRAY_OPERATIONS; rep++) {
		struct data *a1, *a2;
		array_index_t z0, zi, zn;
		i = rand() % (N_ARRAY_ENTRIES + 1);
		/*debug("%d: %d/%d", rep, i, (int)N_ARRAY_ENTRIES);*/
		bist_array_verify(st, true);
		index_from_int(&z0, 0);
		index_from_int(&zi, i);
		a1 = array_sub(pointer_get_data(st->array_ptr), z0, zi, false, NULL);
		bist_dump_array("a1", a1);
		bist_array_verify(st, false);
		index_from_int(&zi, i);
		index_from_int(&zn, N_ARRAY_ENTRIES - i);
		a2 = array_sub(pointer_get_data(st->array_ptr), zi, zn, false, NULL);
		bist_dump_array("a2", a2);
#if 0
		data_dereference(a1);
		data_dereference(a2);
#else
		bist_array_verify(st, false);
		pointer_dereference(st->array_ptr);
		bist_dump_array("a1", a1);
		bist_dump_array("a2", a2);
		st->array_ptr = pointer_data(array_join(a1, a2, NULL));
		bist_dump_array("array_ptr", pointer_get_data(st->array_ptr));
#endif
	}
	bist_array_verify(st, true);
	for (rep = 0; rep < N_ARRAY_OPERATIONS; rep++) {
		i = rand() % N_ARRAY_ENTRIES;
		bist_array_toggle(st, i);
	}
	/*debug("depth: %d", da_array_depth(pointer_get_data(st->array_ptr)));*/
	pointer_dereference(st->array_ptr);
}

static attr_noinline void bist_array(unsigned flags)
{
	struct bist_array_state *st = mem_alloc(struct bist_array_state *, sizeof(struct bist_array_state));
	if (!(flags & 0x100))
		bist_array_st(st, flags);
	else
		bist_array_2_st(st);
	mem_free(st);
}


#define BIST_THREADS	10
static tls_decl(int, bist_tls);
shared_var mutex_t bist_mutex;
rwlock_decl(bist_rwlock);
shared_var cond_t bist_cond_0;
shared_var cond_t bist_cond_1;
shared_var cond_t bist_cond_2;
shared_var int bist_state;
shared_var int bist_counter;
shared_var int bist_terminating;
shared_var int bist_rwlock_test;

#ifndef THREAD_NONE
shared_var thread_t bist_threads[BIST_THREADS];
#define bist_check_missing_stack_probe	name(bist_check_missing_stack_probe)
attr_noinline void bist_check_missing_stack_probe(void);
attr_noinline void bist_check_missing_stack_probe(void)
{
	volatile char attr_unused array[8192];
	array[0] = 0;
}
thread_function_decl(bist_thread_fn,
	int tl;
	int myid = (int)(cast_ptr(thread_t *, arg) - bist_threads);

	bist_check_missing_stack_probe();

	tls_set(int, bist_tls, myid);

	cond_lock(&bist_cond_0);
	cond_unlock_signal(&bist_cond_0);

	cond_lock(&bist_cond_1);
	mutex_lock(&bist_mutex);
	bist_counter++;
	mutex_unlock(&bist_mutex);
	if (bist_counter == BIST_THREADS) cond_unlock_signal(&bist_cond_1);
	else cond_unlock(&bist_cond_1);

	cond_lock(&bist_cond_2);
	while (1) {
		if (bist_state == 1 && bist_counter == myid)
			break;
		cond_wait(&bist_cond_2);
	}
	cond_unlock(&bist_cond_2);

	cond_lock(&bist_cond_1);
	bist_terminating = myid;
	cond_unlock_broadcast(&bist_cond_1);

	rwlock_lock_read(&bist_rwlock);
	if (unlikely(bist_rwlock_test != myid))
		internal(file_line, "bist_thread_fn: invalid rwlock value %d != %d", bist_rwlock_test, myid);
	rwlock_unlock_read(&bist_rwlock);

	tl = tls_get(int, bist_tls);
	if (unlikely(tl != myid))
		internal(file_line, "bist_thread_fn: invalid tls value %d != %d", tl, myid);
)
#endif

static attr_noinline void bist_thread(unsigned attr_unused flags)
{
	int i;
	int tl;
	const char *thread_str;
	tls_init(int, bist_tls);
	tls_set(int, bist_tls, -1);
	mutex_init(&bist_mutex);
	rwlock_init(&bist_rwlock);
	cond_init(&bist_cond_0);
	cond_init(&bist_cond_1);
	cond_init(&bist_cond_2);

	thread_str = getenv("AJLA_THREADS");
	if (thread_str && !strcmp(thread_str, "1"))
		goto skip_bist_thread;

	bist_state = 0;
	bist_counter = 0;
	bist_terminating = -1;
	bist_rwlock_test = -1;
	mutex_lock(&bist_mutex);
	for (i = 0; i < BIST_THREADS; i++) {
		cond_lock(&bist_cond_0);
#ifndef THREAD_NONE
		thread_spawn(&bist_threads[i], bist_thread_fn, &bist_threads[i], PRIORITY_TIMER, NULL);
		cond_wait(&bist_cond_0);
#endif
		cond_unlock(&bist_cond_0);
	}
	if (unlikely(bist_counter != 0))
		internal(file_line, "bist_thread: mutex doesn't work, counter %d", bist_counter);
	mutex_unlock(&bist_mutex);
	cond_lock(&bist_cond_1);
#ifdef THREAD_NONE
	bist_counter = BIST_THREADS;
#endif
	while (1) {
		if (bist_counter == BIST_THREADS)
			break;
		cond_wait(&bist_cond_1);
	}
	cond_unlock(&bist_cond_1);
	cond_lock(&bist_cond_2);
	bist_state = 1;
	while (bist_counter) {
		bist_counter--;
		rwlock_lock_write(&bist_rwlock);
		cond_unlock_broadcast(&bist_cond_2);
		cond_lock(&bist_cond_1);
#ifndef THREAD_NONE
		while (bist_terminating != bist_counter)
			cond_wait(&bist_cond_1);
#endif
		cond_unlock(&bist_cond_1);
		bist_rwlock_test = bist_counter;
		rwlock_unlock_write(&bist_rwlock);
#ifndef THREAD_NONE
		thread_join(&bist_threads[bist_counter]);
#endif
		cond_lock(&bist_cond_2);
	}
	cond_unlock(&bist_cond_2);

skip_bist_thread:
	mutex_done(&bist_mutex);
	rwlock_done(&bist_rwlock);
	cond_done(&bist_cond_0);
	cond_done(&bist_cond_1);
	cond_done(&bist_cond_2);
	tl = tls_get(int, bist_tls);
	if (unlikely(tl != -1))
		internal(file_line, "bist_thread: invalid tls value %d != -1", tl);
	tls_done(int, bist_tls);
}


#ifndef THREAD_NONE

struct bist_background_function {
	void (*fn)(unsigned);
	unsigned flags;
};

shared_var thread_t *bist_background_threads shared_init(NULL);
shared_var size_t bist_background_threads_n;

thread_function_decl(bist_background_thread,
	struct bist_background_function *bbf = arg;
	bbf->fn(bbf->flags);
	mem_free(bbf);
)

#endif

static void bist_background(void (*fn)(unsigned), unsigned flags)
{
#ifndef THREAD_NONE
	if (!getenv("AJLA_BIST_ST")) {
		struct bist_background_function *bbf;
		thread_t thr;
		if (!bist_background_threads) {
			array_init(thread_t, &bist_background_threads, &bist_background_threads_n);
		}
		bbf = mem_alloc(struct bist_background_function *, sizeof(struct bist_background_function));
		bbf->fn = fn;
		bbf->flags = flags;
		thread_spawn(&thr, bist_background_thread, bbf, PRIORITY_COMPUTE, NULL);
		array_add(thread_t, &bist_background_threads, &bist_background_threads_n, thr);
	} else
#endif
		fn(flags);
}

static void bist_background_done(void)
{
#ifndef THREAD_NONE
	if (bist_background_threads) {
		size_t i;
		for (i = 0; i < bist_background_threads_n; i++) {
			thread_join(&bist_background_threads[i]);
		}
		mem_free(bist_background_threads);
		bist_background_threads = NULL;
	}
#endif
}


#endif


void name(bist)(void)
{
#ifdef DEBUG_INFO
#if defined(C_LITTLE_ENDIAN)
	const char *endian = "little endian";
#elif defined(C_BIG_ENDIAN)
	const char *endian = "big endian";
#else
	const char *endian = "unknown endian";
#endif
	debug("sizeof(int) = %d, sizeof(long) = %d, sizeof(size_t) = %d, sizeof(void *) = %d, sizeof(int_default_t) = %d", (int)sizeof(int), (int)sizeof(long), (int)sizeof(size_t), (int)sizeof(void *), (int)sizeof(int_default_t));
	debug("align_of(int) = %d, align_of(long) = %d, align_of(size_t) = %d, align_of(void *) = %d, align_of(int_default_t) = %d", (int)align_of(int), (int)align_of(long), (int)align_of(size_t), (int)align_of(void *), (int)align_of(int_default_t));
#if defined(HAVE_NATIVE_FP16) || !(REAL_MASK & 1)
#define em	""
#else
#define em	" (fp16 emulated)"
#endif
	debug("fixed_mask = 0x%x, int_mask = 0x%x, real_mask = 0x%x%s", (1 << TYPE_FIXED_N) - 1, INT_MASK, REAL_MASK, em);
#undef em
	debug("scalar_align = %d, frame_align = %d, max_frame_align = %d, slot_size = %d, %s", (int)scalar_align, (int)frame_align, (int)max_frame_align, (int)slot_size, endian);
#endif
	bist_constants();
#ifdef DEBUG_BIST
	if (!getenv("AJLA_NO_BIST")) {
		bist_memory();
		bist_string();
		bist_memarray();
		bist_pointer();
		bist_refcount();
		bist_arithm();
#define f(n, s, u, sz, bits)	cat(bist_arithm_,s)();
		for_all_int(f, for_all_empty)
#undef f
		bist_background(bist_conv, 0);
		bist_background(bist_rbtree, 0);
		bist_background(bist_array, 0x00);
		bist_background(bist_array, 0x01);
		bist_background(bist_array, 0x80);
		bist_background(bist_array, 0x100);
		bist_background(bist_thread, 0);
		bist_background_done();
		debug("bist passed");
	}
#endif
	/*{
		size_t len, i;
		char **files;
		dir_handle_t c = os_dir_cwd();
		os_dir_read(c, &files, &len, NULL);
		for (i = 0; i < len; i++) {
			debug("%s", files[i]);
		}
		os_dir_free(files, len);
		os_dir_close(c);
	}*/
}

#endif
