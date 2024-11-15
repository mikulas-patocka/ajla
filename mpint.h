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

#ifndef AJLA_MPINT_H
#define AJLA_MPINT_H

#include "str.h"
#include "code-op.h"


#if !defined(MPINT_GMP)
#include "mini-gmp.h"
#elif defined(HAVE_GMP_H)
#include <gmp.h>
#elif defined(HAVE_GMP_GMP_H)
#include <gmp/gmp.h>
#endif

typedef MP_INT mpint_t;

#define mp_direct	long
#define mp_udirect	unsigned long

static inline unsigned long mpint_estimate_bits(const mpint_t *t)
{
	return (unsigned long)mpz_size(t) * GMP_NUMB_BITS;
}

static inline bool mpint_alloc_mayfail(mpint_t *t, unsigned long bits, ajla_error_t attr_unused *err)
{
	mpz_init2(t, bits);
	return true;
}

static inline bool mpint_alloc_copy_mayfail(mpint_t *t, const mpint_t *src, ajla_error_t attr_unused *err)
{
	mpz_init_set(t, src);
	return true;
}

static inline void mpint_free(mpint_t *t)
{
	mpz_clear(t);
}

static inline bool mpint_negative(const mpint_t *t)
{
	return mpz_sgn(t) < 0;
}

#define mpint_conv_int(n, type, utype, sz, bits)			\
static inline bool cat(mpint_set_from_,type)(mpint_t *t, type val, bool uns, ajla_error_t attr_unused *err)\
{									\
	if (sizeof(type) <= sizeof(mp_direct)) {			\
		if (!uns)						\
			mpz_set_si(t, (mp_direct)val);			\
		else							\
			mpz_set_ui(t, (mp_udirect)(cat(u,type))val);	\
	} else {							\
		bool sign = val < 0 && !uns;				\
		if (unlikely(sign))					\
			val = -(utype)val;				\
									\
		mpz_import(t, 1, 1, sizeof(type), 0, 0, &val);		\
		if (unlikely(sign))					\
			mpz_neg(t, t);					\
	}								\
	return true;							\
}									\
									\
static inline bool cat(mpint_init_from_,type)(mpint_t *t, type val, ajla_error_t *err)\
{									\
	if (sizeof(type) <= sizeof(mp_direct)) {			\
		mpz_init_set_si(t, (mp_direct)val);			\
	} else {							\
		if (unlikely(!mpint_alloc_mayfail(t, sizeof(type) * 8, err)))\
			return false;					\
		if (unlikely(!cat(mpint_set_from_,type)(t, val, false, err))) {\
			mpz_clear(t);					\
			return false;					\
		}							\
	}								\
	return true;							\
}									\
									\
static attr_always_inline bool cat(mpint_export_to_,type)(const mpint_t *t, type *result, ajla_error_t *err)\
{									\
	if (mpz_fits_slong_p(t)) {					\
		long l;							\
		l = mpz_get_si(t);					\
		if (unlikely(l != (type)l))				\
			goto doesnt_fit;				\
		*result = (type)l;					\
		return true;						\
	} else if (sizeof(type) > sizeof(long)) {			\
		utype ui;						\
		size_t bit = mpz_sizeinbase(t, 2);			\
		if (bit > 8 * sizeof(type))				\
			goto doesnt_fit;				\
		(void)mpz_export(&ui, NULL, 1, sizeof(utype), 0, 0, t);	\
		if (mpz_sgn(t) >= 0) {					\
			if ((type)ui < 0)				\
				goto doesnt_fit;			\
		} else {						\
			ui = -ui;					\
			if ((type)ui >= 0)				\
				goto doesnt_fit;			\
		}							\
		*result = (type)ui;					\
		return true;						\
	}								\
									\
doesnt_fit:								\
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT), err, "integer too large for the target type");\
	return false;							\
}									\
									\
static attr_always_inline bool cat(mpint_export_to_,utype)(const mpint_t *t, utype *result, ajla_error_t *err)\
{									\
	if (mpz_fits_ulong_p(t)) {					\
		unsigned long l;					\
		l = mpz_get_ui(t);					\
		if (unlikely(l != (utype)l))				\
			goto doesnt_fit;				\
		*result = (utype)l;					\
		return true;						\
	} else if (sizeof(utype) > sizeof(unsigned long)) {		\
		size_t bit;						\
		if (unlikely(mpz_sgn(t) < 0))				\
			goto doesnt_fit;				\
		bit = mpz_sizeinbase(t, 2);				\
		if (bit > 8 * sizeof(utype))				\
			goto doesnt_fit;				\
		(void)mpz_export(result, NULL, 1, sizeof(utype), 0, 0, t);\
		return true;						\
	}								\
									\
doesnt_fit:								\
	fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT), err, "integer too large for the target type");\
	return false;							\
}
for_all_int(mpint_conv_int, for_all_empty)
#undef mpint_conv_int


static inline bool mpint_import_from_code(mpint_t *m, const code_t *code, ip_t n_words, ajla_error_t *err)
{
	if (unlikely(n_words >= size_t_limit + uzero)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), err, "integer too large");
		return false;
	}
	if (likely(n_words != 0) && unlikely((code[!CODE_ENDIAN ? n_words - 1 : 0] & sign_bit(code_t)) != 0)) {
		size_t i;
		code_t *copy = mem_alloc_array_mayfail(mem_alloc_mayfail, code_t *, 0, 0, n_words, sizeof(code_t), err);
		if (unlikely(!copy))
			return false;
		for (i = 0; i < n_words; i++)
			copy[i] = ~code[i];
		mpz_import(m, n_words, !CODE_ENDIAN ? -1 : 1, sizeof(code_t), 0, 0, copy);
		mem_free(copy);
		mpz_com(m, m);
	} else {
		mpz_import(m, n_words, !CODE_ENDIAN ? -1 : 1, sizeof(code_t), 0, 0, code);
	}
	return true;
}

#define mpint_import_from_variable(m, type, var)			\
do {									\
	if (!is_unsigned(type) && unlikely((var) < (type)zero)) {	\
		type var2 = -(var);					\
		mpz_import((m), 1, 1, sizeof(var), 0, 0, &var2);	\
		mpz_neg((m), (m));					\
	} else {							\
		mpz_import((m), 1, 1, sizeof(var), 0, 0, &(var));	\
	}								\
} while (0)

#define mpint_export_to_variable(m, type, var, success)			\
do {									\
	size_t bit;							\
	success = true;							\
	(var) = 0;							\
	bit = mpz_sizeinbase(m, 2);					\
	if (unlikely(bit > 8 * sizeof(type))) {				\
		success = false;					\
		break;							\
	}								\
	mpz_export(&(var), NULL, 1, sizeof(type), 0, 0, (m));		\
	if (likely(mpz_sgn(m) >= 0)) {					\
		if (unlikely((var) < (type)zero))			\
			success = false;				\
	} else {							\
		if (is_unsigned(type))					\
			success = false;				\
		if (likely((var) != sign_bit(type)))			\
			(var) = -(var);					\
		if (unlikely((var) >= (type)zero))			\
			success = false;				\
	}								\
} while (0)


bool attr_fastcall mpint_add(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_subtract(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_multiply(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_divide(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_modulo(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_power(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_and(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_or(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_xor(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_shl(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_shr(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_bts(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_btr(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_btc(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);

bool attr_fastcall mpint_equal(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);
bool attr_fastcall mpint_not_equal(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);
bool attr_fastcall mpint_less(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);
bool attr_fastcall mpint_less_equal(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);
bool attr_fastcall mpint_greater(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);
bool attr_fastcall mpint_greater_equal(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);
bool attr_fastcall mpint_bt(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);

bool attr_fastcall mpint_not(const mpint_t *s, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_neg(const mpint_t *s, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_inc(const mpint_t *s, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_dec(const mpint_t *s, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_bsf(const mpint_t *s, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_bsr(const mpint_t *s, mpint_t *r, ajla_error_t *err);
bool attr_fastcall mpint_popcnt(const mpint_t *s, mpint_t *r, ajla_error_t *err);

#define mpint_divide_alt1	mpint_divide
#define mpint_modulo_alt1	mpint_modulo
#define mpint_popcnt_alt1	mpint_popcnt

#define mpint_conv_real(n, type, ntype, pack, unpack)			\
bool attr_fastcall cat(mpint_init_from_,type)(mpint_t *t, type *valp, ajla_error_t *err);\
void attr_fastcall cat(mpint_export_to_,type)(const mpint_t *t, type *result);
for_all_real(mpint_conv_real, for_all_empty)
#undef mpint_conv_real

bool mpint_export_to_blob(const mpint_t *s, uint8_t **blob, size_t *blob_size, ajla_error_t *err);

static inline void str_add_mpint(char **s, size_t *l, const mpint_t *mp, uint16_t base_n)
{
	mpint_t mod, base, num;
	int8_t digit;
	int16_t base_m = (int16_t)base_n;
	ajla_flat_option_t neg, bo;
	size_t pos, i;

	pos = *l;

	mpint_init_from_int8_t(&mod, 0, NULL);
	mpint_init_from_int16_t(&base, base_m, NULL);
	mpint_alloc_mayfail(&num, 0, NULL);
	mpint_add(mp, &mod, &num, NULL);
	mpint_less(&num, &mod, &neg, NULL);
	if (neg) {
		mpint_neg(&num, &num, NULL);
	}

	do {
		mpint_modulo(&num, &base, &mod, NULL);
		digit = 0;	/* avoid warning */
		mpint_export_to_int8_t(&mod, &digit, NULL);
		str_add_char(s, l, digit <= 9 ? '0' + (char)digit : 'a' - 10 + (char)digit);
		mpint_less(&num, &base, &bo, NULL);
		if (!bo) mpint_divide(&num, &base, &num, NULL);
	} while (!bo);

	if (neg)
		str_add_char(s, l, '-');

	mpint_free(&mod);
	mpint_free(&base);
	mpint_free(&num);

	for (i = 0; i < (*l - pos) / 2; i++) {
		char c = (*s)[pos + i];
		(*s)[pos + i] = (*s)[*l - 1 - i];
		(*s)[*l - 1 - i] = c;
	}
}


void mpint_init(void);
void mpint_done(void);

#endif
