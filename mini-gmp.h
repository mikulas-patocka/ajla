/* mini-gmp, a minimalistic implementation of a GNU GMP subset.

Copyright 2011-2015, 2017, 2019-2020 Free Software Foundation, Inc.

This file is part of the GNU MP Library.

The GNU MP Library is free software; you can redistribute it and/or modify
it under the terms of either:

  * the GNU Lesser General Public License as published by the Free
    Software Foundation; either version 3 of the License, or (at your
    option) any later version.

or

  * the GNU General Public License as published by the Free Software
    Foundation; either version 2 of the License, or (at your option) any
    later version.

or both in parallel, as here.

The GNU MP Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received copies of the GNU General Public License and the
GNU Lesser General Public License along with the GNU MP Library.  If not,
see https://www.gnu.org/licenses/.  */

/* Modified by Mikulas Patocka to fit in Ajla */

/* About mini-gmp: This is a minimal implementation of a subset of the
   GMP interface. It is intended for inclusion into applications which
   have modest bignums needs, as a fallback when the real GMP library
   is not installed.

   This file defines the public interface. */

#ifndef AJLA_MINI_GMP_H
#define AJLA_MINI_GMP_H

#ifndef MPINT_GMP

void mp_set_memory_functions (void *(*) (size_t),
			      void *(*) (void *, size_t, size_t),
			      void (*) (void *, size_t));

#ifndef MINI_GMP_LIMB_TYPE
#define MINI_GMP_LIMB_TYPE long
#endif

typedef unsigned MINI_GMP_LIMB_TYPE mp_limb_t;
typedef long mp_size_t;
typedef unsigned long mp_bitcnt_t;

typedef mp_limb_t *mp_ptr;
typedef const mp_limb_t *mp_srcptr;

#define GMP_NUMB_BITS		(sizeof(mp_limb_t) * 8)

typedef struct
{
  int _mp_alloc;		/* Number of *limbs* allocated and pointed
				   to by the _mp_d field.  */
  int _mp_size;			/* abs(_mp_size) is the number of limbs the
				   last field points to.  If _mp_size is
				   negative this is a negative number.  */
  mp_limb_t *_mp_d;		/* Pointer to the limbs.  */
} __mpz_struct;

typedef __mpz_struct MP_INT;

typedef __mpz_struct mpz_t[1];

typedef __mpz_struct *mpz_ptr;
typedef const __mpz_struct *mpz_srcptr;

extern const int mp_bits_per_limb;

mp_bitcnt_t mpn_scan1 (mp_srcptr, mp_bitcnt_t);

#define mpn_invert_limb(x) mpn_invert_3by2 ((x), 0)

void mpz_init (mpz_t);
void mpz_init2 (mpz_t, mp_bitcnt_t);
void mpz_clear (mpz_t);

#define mpz_odd_p(z)   (((z)->_mp_size != 0) & (int) (z)->_mp_d[0])
#define mpz_even_p(z)  (! mpz_odd_p (z))

int mpz_sgn (const mpz_t);
int mpz_cmp (const mpz_t, const mpz_t);

void mpz_neg (mpz_t, const mpz_t);

void mpz_add_ui (mpz_t, const mpz_t, unsigned long);
void mpz_add (mpz_t, const mpz_t, const mpz_t);
void mpz_sub_ui (mpz_t, const mpz_t, unsigned long);
void mpz_sub (mpz_t, const mpz_t, const mpz_t);

void mpz_mul (mpz_t, const mpz_t, const mpz_t);
void mpz_mul_2exp (mpz_t, const mpz_t, mp_bitcnt_t);

void mpz_tdiv_q (mpz_t, const mpz_t, const mpz_t);
void mpz_tdiv_r (mpz_t, const mpz_t, const mpz_t);

void mpz_fdiv_q_2exp (mpz_t, const mpz_t, mp_bitcnt_t);
void mpz_tdiv_q_2exp (mpz_t, const mpz_t, mp_bitcnt_t);

int mpz_tstbit (const mpz_t, mp_bitcnt_t);
void mpz_setbit (mpz_t, mp_bitcnt_t);
void mpz_clrbit (mpz_t, mp_bitcnt_t);

void mpz_com (mpz_t, const mpz_t);
void mpz_and (mpz_t, const mpz_t, const mpz_t);
void mpz_ior (mpz_t, const mpz_t, const mpz_t);
void mpz_xor (mpz_t, const mpz_t, const mpz_t);

mp_bitcnt_t mpz_popcount (const mpz_t);
mp_bitcnt_t mpz_scan1 (const mpz_t, mp_bitcnt_t);

int mpz_fits_slong_p (const mpz_t);
int mpz_fits_ulong_p (const mpz_t);
long int mpz_get_si (const mpz_t);
unsigned long int mpz_get_ui (const mpz_t);
size_t mpz_size (const mpz_t);

#define MPZ_ROINIT_N(xp, xs) {{0, (xs),(xp) }}

void mpz_set_si (mpz_t, signed long int);
void mpz_set_ui (mpz_t, unsigned long int);
void mpz_set (mpz_t, const mpz_t);

void mpz_init_set_si (mpz_t, signed long int);
void mpz_init_set (mpz_t, const mpz_t);

size_t mpz_sizeinbase (const mpz_t, int);

void mpz_import (mpz_t, size_t, int, size_t, int, size_t, const void *);
void *mpz_export (void *, size_t *, int, size_t, int, size_t, const mpz_t);

#endif

#endif /* AJLA_MINI_GMP_H */
