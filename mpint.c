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

#include "mem_al.h"

#include "mpint.h"

#define MPINT_MAX_BITS		0x80000000UL


#if defined(MPINT_GMP) && __GNU_MP_VERSION+0 < 5
typedef unsigned long mp_bitcnt_t;
#endif

#ifndef mpz_limbs_read
#define mpz_limbs_read(t)		((t)->_mp_d)
#endif

#ifndef mpz_limbs_write
#define mpz_limbs_write(t, idx)		(((size_t)(t)->_mp_alloc < (idx) ? internal(file_line, "mpz_limbs_write: not enough entries: %"PRIuMAX" < %"PRIuMAX"", (uintmax_t)(t)->_mp_alloc, (uintmax_t)(idx)), 0 : 0), (t)->_mp_d)
#endif

#ifndef mpz_limbs_finish
#define mpz_limbs_finish(t, idx)	((t)->_mp_size = idx)
#endif

static attr_noinline bool attr_fastcall attr_cold mpint_size_ok_slow(const mpint_t *t, ajla_error_t *err)
{
	size_t sz = mpz_sizeinbase(t, 2);
	if (sz >= MPINT_MAX_BITS) {
		if (sz == MPINT_MAX_BITS && mpz_sgn(t) < 0 &&
		    mpz_scan1(t, 0) == MPINT_MAX_BITS - 1)
			return true;
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), err, "integer too large");
		return false;
	}
	return true;
}

static inline bool mpint_size_ok(const mpint_t attr_unused *t, ajla_error_t *err)
{
	size_t size = mpz_size(t);
	if (likely(size <= (MPINT_MAX_BITS - 1) / GMP_NUMB_BITS))
		return true;
	return mpint_size_ok_slow(t, err);
}

bool attr_fastcall mpint_add(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	mpz_add(r, s1, s2);
	if (unlikely(!mpint_size_ok(r, err))) {
		return false;
	}
	return true;
}

bool attr_fastcall mpint_subtract(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	mpz_sub(r, s1, s2);
	if (unlikely(!mpint_size_ok(r, err))) {
		return false;
	}
	return true;
}

static inline bool mpint_multiply_early_check(size_t size1, size_t size2, ajla_error_t *err)
{
	if (unlikely(size1 + size2 > 1 + (MPINT_MAX_BITS + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), err, "integer too large");
		return false;
	}
	return true;
}

bool attr_fastcall mpint_multiply(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	if (unlikely(!mpint_multiply_early_check(mpz_size(s1), mpz_size(s2), err))) {
		return false;
	}
	mpz_mul(r, s1, s2);
	if (unlikely(!mpint_size_ok(r, err)))
		return false;
	return true;
}

bool attr_fastcall mpint_divide(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	if (unlikely(!mpz_sgn(s2))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "divide by zero");
		return false;
	}
	mpz_tdiv_q(r, s1, s2);
	if (unlikely(!mpint_size_ok(r, err))) {
		return false;
	}
	return true;
}

bool attr_fastcall mpint_modulo(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	if (unlikely(!mpz_sgn(s2))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "modulo by zero");
		return false;
	}
	mpz_tdiv_r(r, s1, s2);
	return true;
}

bool attr_fastcall mpint_power(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	mpint_t x1, x2;
	mpz_init_set(&x1, s1);
	mpz_init_set(&x2, s2);
	if (unlikely(mpz_sgn(&x2) < 0)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "power by negative number");
ret_err:
		mpz_clear(&x1);
		mpz_clear(&x2);
		return false;
	}
	mpz_set_ui(r, 1);
	while (1) {
		if (mpz_tstbit(&x2, 0)) {
			if (unlikely(!mpint_multiply(r, &x1, r, err)))
				goto ret_err;
		}
		if (!mpz_sgn(&x2))
			break;
		mpz_tdiv_q_2exp(&x2, &x2, 1);
		if (unlikely(!mpint_multiply(&x1, &x1, &x1, err)))
			goto ret_err;
	}
	mpz_clear(&x1);
	mpz_clear(&x2);
	return true;
}

bool attr_fastcall mpint_and(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t attr_unused *err)
{
	mpz_and(r, s1, s2);
	return true;
}

bool attr_fastcall mpint_or(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t attr_unused *err)
{
	mpz_ior(r, s1, s2);
	return true;
}

bool attr_fastcall mpint_xor(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t attr_unused *err)
{
	mpz_xor(r, s1, s2);
	return true;
}

bool attr_fastcall mpint_shl(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	unsigned long sh;
	size_t size1, size2;
	if (unlikely(!mpz_fits_ulong_p(s2))) {
overflow:
		if (unlikely((mpz_sgn(s2) < 0))) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "shift left with negative count");
			return false;
		} else {
			if (!mpz_sgn(s1)) {
				mpz_set_ui(r, 0);
				return true;
			} else {
				fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), err, "integer too large");
				return false;
			}
		}
	}
	sh = mpz_get_ui(s2);
	if (unlikely((mp_bitcnt_t)sh != sh))
		goto overflow;
	size1 = mpz_size(s1);
	size2 = 1 + sh / GMP_NUMB_BITS;
	if (unlikely(!mpint_multiply_early_check(size1, size2, err)))
		return false;
	mpz_mul_2exp(r, s1, sh);
	if (unlikely(!mpint_size_ok(r, err)))
		return false;
	return true;
}

bool attr_fastcall mpint_shr(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	unsigned long sh;
	if (unlikely(!mpz_fits_ulong_p(s2))) {
overflow:
		if (unlikely((mpz_sgn(s2) < 0))) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "shift right with negative count");
			return false;
		} else {
			if (mpz_sgn(s1) >= 0) {
				mpz_set_ui(r, 0);
				return true;
			} else {
				mpz_set_si(r, -1);
				return true;
			}
		}
	}
	sh = mpz_get_ui(s2);
	if (unlikely((mp_bitcnt_t)sh != sh))
		goto overflow;
	mpz_fdiv_q_2exp(r, s1, sh);
	return true;
}

static inline bool attr_fastcall mpint_btx_(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err, void (*fn_bit)(mpint_t *, mp_bitcnt_t), int mode)
{
	unsigned long sh;
	if (unlikely(!mpz_fits_ulong_p(s2))) {
		if (unlikely(mpz_sgn(s2) < 0)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "bit %s with negative position", mode == 0 ? "set" : mode == 1 ? "reset" : "complement");
			return false;
		}
overflow:
		if (mode == 0 && mpz_sgn(s1) < 0) {
			mpz_set(r, s1);
			return true;
		}
		if (mode == 1 && mpz_sgn(s1) >= 0) {
			mpz_set(r, s1);
			return true;
		}
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), err, "integer too large");
		return false;
	}
	sh = mpz_get_ui(s2);
	if (unlikely(sh != (unsigned long)(mp_bitcnt_t)sh))
		goto overflow;
	mpz_set(r, s1);
	fn_bit(r, sh);
	return true;
}

bool attr_fastcall mpint_bts(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	return mpint_btx_(s1, s2, r, err, mpz_setbit, 0);
}

bool attr_fastcall mpint_btr(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
	return mpint_btx_(s1, s2, r, err, mpz_clrbit, 1);
}

bool attr_fastcall mpint_btc(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err)
{
#if !defined(mpz_combit) || defined(UNUSUAL_ARITHMETICS)
	ajla_flat_option_t o;
	if (unlikely(!mpint_bt(s1, s2, &o, err)))
		return false;
	if (!o)
		return mpint_bts(s1, s2, r, err);
	else
		return mpint_btr(s1, s2, r, err);
#else
	return mpint_btx_(s1, s2, r, err, mpz_combit, 2);
#endif
}

bool attr_fastcall mpint_equal(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t attr_unused *err)
{
	*r = !mpz_cmp(s1, s2);
	return true;
}

bool attr_fastcall mpint_not_equal(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t attr_unused *err)
{
	*r = !!mpz_cmp(s1, s2);
	return true;
}

bool attr_fastcall mpint_less(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t attr_unused *err)
{
	*r = mpz_cmp(s1, s2) < 0;
	return true;
}

bool attr_fastcall mpint_less_equal(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t attr_unused *err)
{
	*r = mpz_cmp(s2, s1) >= 0;
	return true;
}

bool attr_fastcall mpint_bt(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err)
{
	unsigned long sh;
	if (unlikely(!mpz_fits_ulong_p(s2))) {
		if (unlikely(mpz_sgn(s2) < 0)) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "bit test with negative position");
			return false;
		}
overflow:
		*r = mpz_sgn(s1) < 0;
		return true;
	}
	sh = mpz_get_ui(s2);
	if (unlikely(sh != (unsigned long)(mp_bitcnt_t)sh))
		goto overflow;
	*r = mpz_tstbit(s1, sh);
	return true;
}

bool attr_fastcall mpint_not(const mpint_t *s, mpint_t *r, ajla_error_t attr_unused *err)
{
	mpz_com(r, s);
	return true;
}

bool attr_fastcall mpint_neg(const mpint_t *s, mpint_t *r, ajla_error_t *err)
{
	mpz_neg(r, s);
	if (unlikely(!mpint_size_ok(r, err))) {
		return false;
	}
	return true;
}

bool attr_fastcall mpint_inc(const mpint_t *s, mpint_t *r, ajla_error_t *err)
{
	mpz_add_ui(r, s, 1);
	if (unlikely(!mpint_size_ok(r, err))) {
		return false;
	}
	return true;
}

bool attr_fastcall mpint_dec(const mpint_t *s, mpint_t *r, ajla_error_t *err)
{
	mpz_sub_ui(r, s, 1);
	if (unlikely(!mpint_size_ok(r, err))) {
		return false;
	}
	return true;
}

bool attr_fastcall mpint_bsf(const mpint_t *s, mpint_t *r, ajla_error_t *err)
{
	mp_bitcnt_t b;
	if (unlikely(!mpz_sgn(s))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "bit scan forward with zero argument");
		return false;
	}
	b = mpz_scan1(s, 0);
#ifndef UNUSUAL_ARITHMETICS
	if (likely(b == (unsigned long)b))
		mpz_set_ui(r, b);
	else
#endif
		mpz_import(r, 1, 1, sizeof(b), 0, 0, &b);
	return true;
}

bool attr_fastcall mpint_bsr(const mpint_t *s, mpint_t *r, ajla_error_t *err)
{
	size_t sz;
	if (unlikely(mpz_sgn(s) <= 0)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "bit scan reverse with non-positive argument");
		return false;
	}
	sz = mpz_sizeinbase(s, 2) - 1;
#ifndef UNUSUAL_ARITHMETICS
	if (likely(sz == (unsigned long)sz))
		mpz_set_ui(r, sz);
	else
#endif
		mpz_import(r, 1, 1, sizeof(sz), 0, 0, &sz);
	return true;
}

bool attr_fastcall mpint_popcnt(const mpint_t *s, mpint_t *r, ajla_error_t *err)
{
	mp_bitcnt_t b;
	if (unlikely(mpz_sgn(s) < 0)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "population count with negative argument");
		return false;
	}
	b = mpz_popcount(s);
#ifndef UNUSUAL_ARITHMETICS
	if (likely(b == (unsigned long)b))
		mpz_set_ui(r, b);
	else
#endif
		mpz_import(r, 1, 1, sizeof(b), 0, 0, &b);
	return true;
}

static inline bool mpint_raw_test_bit(const mp_limb_t *ptr, size_t bit)
{
	return (ptr[bit / GMP_NUMB_BITS] >> (bit % GMP_NUMB_BITS)) & 1;
}

#define mpint_conv_real(n, type, ntype, pack, unpack)			\
bool attr_fastcall cat(mpint_init_from_,type)(mpint_t *t, type *valp, ajla_error_t *err)\
{									\
	ntype norm, mult, val = unpack(*valp);				\
	int ex, shift;							\
	size_t limbs, idx;						\
	mp_limb_t *ptr;							\
	bool neg = unlikely(val < (ntype)0);				\
	val = cat(mathfunc_,ntype)(fabs)(val);				\
	if (unlikely(!cat(isfinite_, ntype)(val))) {			\
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INFINITY), err, "attempting to convert infinity to integer");\
		return false;						\
	}								\
	norm = cat(mathfunc_,ntype)(frexp)(val, &ex);			\
	if (unlikely(!mpint_alloc_mayfail(t, likely(ex >= 0) ? ex : 0, err)))\
		return false;						\
	if (unlikely(ex <= 0))						\
		goto skip;						\
	idx = (unsigned)(ex - 1) / GMP_NUMB_BITS;			\
	limbs = idx + 1;						\
	ptr = mpz_limbs_write(t, limbs);				\
	shift = ((unsigned)(ex - 1) % GMP_NUMB_BITS) + 1;		\
	mult = (ntype)((mp_limb_t)1 << (shift - 1));			\
	mult += mult;							\
	norm *= mult;							\
	while (1) {							\
		mp_limb_t limb = (mp_limb_t)norm;			\
		norm -= (ntype)limb;					\
		ptr[idx] = limb;					\
		if (!idx)						\
			break;						\
		if (!norm) {						\
			memset(ptr, 0, idx * sizeof(mp_limb_t));	\
			break;						\
		}							\
		idx--;							\
		norm = norm * ((ntype)((mp_limb_t)1 << (GMP_NUMB_BITS - 1)) * 2.);\
	}								\
	mpz_limbs_finish(t, limbs);					\
	if (unlikely(neg)) {						\
		if (unlikely(!mpint_neg(t, t, err)))			\
			goto fail_free;					\
	}								\
skip:									\
	return true;							\
fail_free:								\
	mpint_free(t);							\
	return false;							\
}									\
void attr_fastcall cat(mpint_export_to_,type)(const mpint_t *s, type *result)\
{									\
	size_t sz, last_bit, idx, base_pos;				\
	const mp_limb_t *limbs;						\
	ntype mult, r = 0;						\
									\
	if (unlikely(!mpz_sgn(s)))					\
		goto skip;						\
									\
	limbs = mpz_limbs_read(s);					\
									\
	sz = mpz_sizeinbase(s, 2);					\
	last_bit = sz < cat(bits_,ntype) ? 0 : sz - cat(bits_,ntype);	\
									\
	idx = (sz - 1) / GMP_NUMB_BITS;					\
	base_pos = idx * GMP_NUMB_BITS;					\
	mult = cat(mathfunc_,ntype)(ldexp)(1., base_pos);		\
									\
	while (1) {							\
		ntype l;						\
		mp_limb_t limb = limbs[idx];				\
		mp_limb_t mask = (mp_limb_t)-1;				\
									\
		mask <<= base_pos <= last_bit ? last_bit - base_pos : 0;\
									\
		l = (ntype)(limb & mask);				\
									\
		if (l)							\
			r += mult * l;					\
									\
		if (base_pos <= last_bit)				\
			break;						\
									\
		sz = base_pos;						\
		idx = (sz - 1) / GMP_NUMB_BITS;				\
		base_pos = idx * GMP_NUMB_BITS;				\
									\
		mult = mult * (ntype)(1. / ((ntype)((mp_limb_t)1 << (GMP_NUMB_BITS - 1)) * 2.));\
	}								\
									\
	if (last_bit >= 1 && mpint_raw_test_bit(limbs, last_bit - 1)) {	\
		if (mpint_raw_test_bit(limbs, last_bit) || mpn_scan1(limbs, 0) != last_bit - 1) {\
			r += cat(mathfunc_,ntype)(ldexp)(1., last_bit);	\
		}							\
	}								\
									\
	if (unlikely(mpz_sgn(s) < 0))					\
		r = -r;							\
									\
skip:									\
	*result = pack(r);						\
}
for_all_real(mpint_conv_real, for_all_empty)
#undef mpint_conv_real


bool mpint_export_to_blob(const mpint_t *s, uint8_t **blob, size_t *blob_size, ajla_error_t *err)
{
	uint8_t *ptr;
	size_t sz = (mpz_sizeinbase(s, 2) + 7) / 8 + 1;
	size_t count;

	ptr = mem_alloc_mayfail(uint8_t *, sz, err);
	if (unlikely(!ptr))
		return false;

	mpz_export(ptr, &count, -1, 1, 0, 0, s);
	if (count > sz)
		internal(file_line, "mpint_export_to_blob: mpz_export ran over the end of allocated memory: %"PRIuMAX" > %"PRIuMAX"", (uintmax_t)count, (uintmax_t)sz);
	while (count < sz) {
		ptr[count++] = 0;
	}

	if (unlikely(mpz_sgn(s) < 0)) {
		size_t i;
		bool do_not = false;
		for (i = 0; i < sz; i++) {
			if (!do_not) {
				if (ptr[i] != 0) {
					ptr[i] = -ptr[i];
					do_not = true;
				}
			} else {
				ptr[i] = ~ptr[i];
			}
		}
		while (sz >= 2) {
			if (ptr[sz - 1] == 0xff && ptr[sz - 2] >= 0x80)
				sz--;
			else
				break;
		}
	} else {
		while (sz >= 2) {
			if (ptr[sz - 1] == 0x00 && ptr[sz - 2] < 0x80)
				sz--;
			else
				break;
		}
		if (sz == 1 && !ptr[0])
			sz = 0;
	}

	*blob = ptr;
	*blob_size = sz;

	return true;
}


static void *gmp_alloc(size_t size)
{
	return mem_alloc(void *, size);
}

static void *gmp_realloc(void *ptr, size_t attr_unused old_size, size_t new_size)
{
	return mem_realloc(void *, ptr, new_size);
}

static void gmp_free(void *ptr, size_t attr_unused size)
{
	mem_free(ptr);
}


void mpint_init(void)
{
	if (!dll)
		mp_set_memory_functions(gmp_alloc, gmp_realloc, gmp_free);
}

void mpint_done(void)
{
}
