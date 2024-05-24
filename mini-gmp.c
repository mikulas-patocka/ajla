/* mini-gmp, a minimalistic implementation of a GNU GMP subset.

   Contributed to the GNU project by Niels Möller

Copyright 1991-1997, 1999-2019 Free Software Foundation, Inc.

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

/* NOTE: All functions in this file which are not declared in
   mini-gmp.h are internal, and are not intended to be compatible
   with GMP or with future versions of mini-gmp. */

/* Much of the material copied from GMP files, including: gmp-impl.h,
   longlong.h, mpn/generic/add_n.c, mpn/generic/addmul_1.c,
   mpn/generic/lshift.c, mpn/generic/mul_1.c,
   mpn/generic/mul_basecase.c, mpn/generic/rshift.c,
   mpn/generic/sbpi1_div_qr.c, mpn/generic/sub_n.c,
   mpn/generic/submul_1.c. */

#include "ajla.h"

#ifndef MPINT_GMP

#include <limits.h>

#ifdef __BORLANDC__
#define const
#endif

#include "mini-gmp.h"

#define assert(x)	ajla_assert(x, (file_line, "gmp assertion failed"))

/* Macros */
#define GMP_LIMB_BITS ((int)sizeof(mp_limb_t) * CHAR_BIT)

#define GMP_LIMB_MAX ((mp_limb_t) ~ (mp_limb_t) 0)
#define GMP_LIMB_HIGHBIT ((mp_limb_t) 1 << (GMP_LIMB_BITS - 1))

#define GMP_HLIMB_BIT ((mp_limb_t) 1 << (GMP_LIMB_BITS / 2))
#define GMP_LLIMB_MASK (GMP_HLIMB_BIT - 1)

#define GMP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)
#define GMP_ULONG_HIGHBIT ((unsigned long) 1 << (GMP_ULONG_BITS - 1))

#define GMP_ABS(x) ((x) >= 0 ? (x) : -(x))
#define GMP_NEG_CAST(T,x) (-((T)((x) + 1) - 1))

#define GMP_MIN(a, b) ((a) < (b) ? (a) : (b))
#define GMP_MAX(a, b) ((a) > (b) ? (a) : (b))

#define GMP_CMP(a,b) (((a) > (b)) - ((a) < (b)))

#if defined(DBL_MANT_DIG) && FLT_RADIX == 2
#define GMP_DBL_MANT_BITS DBL_MANT_DIG
#else
#define GMP_DBL_MANT_BITS (53)
#endif

/* Return non-zero if xp,xsize and yp,ysize overlap.
   If xp+xsize<=yp there's no overlap, or if yp+ysize<=xp there's no
   overlap.  If both these are false, there's an overlap. */
#define GMP_MPN_OVERLAP_P(xp, xsize, yp, ysize)				\
  ((xp) + (xsize) > (yp) && (yp) + (ysize) > (xp))

#define gmp_assert_nocarry(x) do { \
    mp_limb_t attr_unused __cy = (x);	   \
    assert (__cy == 0);		   \
  } while (0)

#define gmp_clz(count, x) do {						\
    mp_limb_t __clz_x = (x);						\
    unsigned __clz_c = 0;						\
    int LOCAL_SHIFT_BITS = 8;						\
    if (GMP_LIMB_BITS > LOCAL_SHIFT_BITS)				\
      for (;								\
	   (__clz_x & ((mp_limb_t) 0xff << (GMP_LIMB_BITS - 8))) == 0;	\
	   __clz_c += 8)						\
	{ __clz_x <<= LOCAL_SHIFT_BITS;	}				\
    for (; (__clz_x & GMP_LIMB_HIGHBIT) == 0; __clz_c++)		\
      __clz_x <<= 1;							\
    (count) = __clz_c;							\
  } while (0)

#define gmp_ctz(count, x) do {						\
    mp_limb_t __ctz_x = (x);						\
    unsigned __ctz_c = 0;						\
    gmp_clz (__ctz_c, __ctz_x & - __ctz_x);				\
    (count) = GMP_LIMB_BITS - 1 - __ctz_c;				\
  } while (0)

#define gmp_add_ssaaaa(sh, sl, ah, al, bh, bl) \
  do {									\
    mp_limb_t __x;							\
    __x = (al) + (bl);							\
    (sh) = (ah) + (bh) + (__x < (al));					\
    (sl) = __x;								\
  } while (0)

#define gmp_sub_ddmmss(sh, sl, ah, al, bh, bl) \
  do {									\
    mp_limb_t __x;							\
    __x = (al) - (bl);							\
    (sh) = (ah) - (bh) - ((al) < (bl));					\
    (sl) = __x;								\
  } while (0)

#define gmp_umul_ppmm(w1, w0, u, v)					\
  do {									\
    int LOCAL_GMP_LIMB_BITS = GMP_LIMB_BITS;				\
    if (sizeof(unsigned int) * CHAR_BIT >= 2 * GMP_LIMB_BITS)		\
      {									\
	unsigned int __ww = (unsigned int) (u) * (v);			\
	w0 = (mp_limb_t) __ww;						\
	w1 = (mp_limb_t) (__ww >> LOCAL_GMP_LIMB_BITS);			\
      }									\
    else if (GMP_ULONG_BITS >= 2 * GMP_LIMB_BITS)			\
      {									\
	unsigned long int __ww = (unsigned long int) (u) * (v);		\
	w0 = (mp_limb_t) __ww;						\
	w1 = (mp_limb_t) (__ww >> LOCAL_GMP_LIMB_BITS);			\
      }									\
    else {								\
      mp_limb_t __x0, __x1, __x2, __x3;					\
      unsigned __ul, __vl, __uh, __vh;					\
      mp_limb_t __u = (u), __v = (v);					\
									\
      __ul = __u & GMP_LLIMB_MASK;					\
      __uh = __u >> (GMP_LIMB_BITS / 2);				\
      __vl = __v & GMP_LLIMB_MASK;					\
      __vh = __v >> (GMP_LIMB_BITS / 2);				\
									\
      __x0 = (mp_limb_t) __ul * __vl;					\
      __x1 = (mp_limb_t) __ul * __vh;					\
      __x2 = (mp_limb_t) __uh * __vl;					\
      __x3 = (mp_limb_t) __uh * __vh;					\
									\
      __x1 += __x0 >> (GMP_LIMB_BITS / 2);/* this can't give carry */	\
      __x1 += __x2;		/* but this indeed can */		\
      if (__x1 < __x2)		/* did we get it? */			\
	__x3 += GMP_HLIMB_BIT;	/* yes, add it in the proper pos. */	\
									\
      (w1) = __x3 + (__x1 >> (GMP_LIMB_BITS / 2));			\
      (w0) = (__x1 << (GMP_LIMB_BITS / 2)) + (__x0 & GMP_LLIMB_MASK);	\
    }									\
  } while (0)

#define gmp_udiv_qrnnd_preinv(q, r, nh, nl, d, di)			\
  do {									\
    mp_limb_t _qh, _ql, _r, _mask;					\
    gmp_umul_ppmm (_qh, _ql, (nh), (di));				\
    gmp_add_ssaaaa (_qh, _ql, _qh, _ql, (nh) + 1, (nl));		\
    _r = (nl) - _qh * (d);						\
    _mask = -(mp_limb_t) (_r > _ql); /* both > and >= are OK */		\
    _qh += _mask;							\
    _r += _mask & (d);							\
    if (_r >= (d))							\
      {									\
	_r -= (d);							\
	_qh++;								\
      }									\
									\
    (r) = _r;								\
    (q) = _qh;								\
  } while (0)

#define gmp_udiv_qr_3by2(q, r1, r0, n2, n1, n0, d1, d0, dinv)		\
  do {									\
    mp_limb_t _q0, _t1, _t0, _mask;					\
    gmp_umul_ppmm ((q), _q0, (n2), (dinv));				\
    gmp_add_ssaaaa ((q), _q0, (q), _q0, (n2), (n1));			\
									\
    /* Compute the two most significant limbs of n - q'd */		\
    (r1) = (n1) - (d1) * (q);						\
    gmp_sub_ddmmss ((r1), (r0), (r1), (n0), (d1), (d0));		\
    gmp_umul_ppmm (_t1, _t0, (d0), (q));				\
    gmp_sub_ddmmss ((r1), (r0), (r1), (r0), _t1, _t0);			\
    (q)++;								\
									\
    /* Conditionally adjust q and the remainders */			\
    _mask = - (mp_limb_t) ((r1) >= _q0);				\
    (q) += _mask;							\
    gmp_add_ssaaaa ((r1), (r0), (r1), (r0), _mask & (d1), _mask & (d0)); \
    if ((r1) >= (d1))							\
      {									\
	if ((r1) > (d1) || (r0) >= (d0))				\
	  {								\
	    (q)++;							\
	    gmp_sub_ddmmss ((r1), (r0), (r1), (r0), (d1), (d0));	\
	  }								\
      }									\
  } while (0)

/* Swap macros. */
#define MP_LIMB_T_SWAP(x, y)						\
  do {									\
    mp_limb_t __mp_limb_t_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mp_limb_t_swap__tmp;					\
  } while (0)
#define MP_SIZE_T_SWAP(x, y)						\
  do {									\
    mp_size_t __mp_size_t_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mp_size_t_swap__tmp;					\
  } while (0)
#define MP_BITCNT_T_SWAP(x,y)			\
  do {						\
    mp_bitcnt_t __mp_bitcnt_t_swap__tmp = (x);	\
    (x) = (y);					\
    (y) = __mp_bitcnt_t_swap__tmp;		\
  } while (0)
#define MP_PTR_SWAP(x, y)						\
  do {									\
    mp_ptr __mp_ptr_swap__tmp = (x);					\
    (x) = (y);								\
    (y) = __mp_ptr_swap__tmp;						\
  } while (0)
#define MP_SRCPTR_SWAP(x, y)						\
  do {									\
    mp_srcptr __mp_srcptr_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mp_srcptr_swap__tmp;					\
  } while (0)

#define MPN_PTR_SWAP(xp,xs, yp,ys)					\
  do {									\
    MP_PTR_SWAP (xp, yp);						\
    MP_SIZE_T_SWAP (xs, ys);						\
  } while(0)
#define MPN_SRCPTR_SWAP(xp,xs, yp,ys)					\
  do {									\
    MP_SRCPTR_SWAP (xp, yp);						\
    MP_SIZE_T_SWAP (xs, ys);						\
  } while(0)

#define MPZ_PTR_SWAP(x, y)						\
  do {									\
    mpz_ptr __mpz_ptr_swap__tmp = (x);					\
    (x) = (y);								\
    (y) = __mpz_ptr_swap__tmp;						\
  } while (0)
#define MPZ_SRCPTR_SWAP(x, y)						\
  do {									\
    mpz_srcptr __mpz_srcptr_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mpz_srcptr_swap__tmp;					\
  } while (0)

const int mp_bits_per_limb = GMP_LIMB_BITS;


/* Memory allocation and other helper functions. */
static attr_noreturn
gmp_die (const char *msg)
{
  internal(file_line, "%s", msg);
}

static void *
gmp_default_alloc (size_t size)
{
  void *p;

  assert (size > 0);

  p = malloc (size);
  if (!p)
    gmp_die("gmp_default_alloc: Virtual memory exhausted.");

  return p;
}

static void *
gmp_default_realloc (void *old, size_t attr_unused unused_old_size, size_t new_size)
{
  void * p;

  p = realloc (old, new_size);

  if (!p)
    gmp_die("gmp_default_realloc: Virtual memory exhausted.");

  return p;
}

static void
gmp_default_free (void *p, size_t attr_unused unused_size)
{
  free (p);
}

static void * (*gmp_allocate_func) (size_t) = gmp_default_alloc;
static void * (*gmp_reallocate_func) (void *, size_t, size_t) = gmp_default_realloc;
static void (*gmp_free_func) (void *, size_t) = gmp_default_free;

void
mp_set_memory_functions (void *(*alloc_func) (size_t),
			 void *(*realloc_func) (void *, size_t, size_t),
			 void (*free_func) (void *, size_t))
{
  if (!alloc_func)
    alloc_func = gmp_default_alloc;
  if (!realloc_func)
    realloc_func = gmp_default_realloc;
  if (!free_func)
    free_func = gmp_default_free;

  gmp_allocate_func = alloc_func;
  gmp_reallocate_func = realloc_func;
  gmp_free_func = free_func;
}

#define gmp_xalloc(size) ((*gmp_allocate_func)((size)))
#define gmp_free(p) ((*gmp_free_func) ((p), 0))

static mp_ptr
gmp_xalloc_limbs (mp_size_t size)
{
  return (mp_ptr) gmp_xalloc (size * sizeof (mp_limb_t));
}

static mp_ptr
gmp_xrealloc_limbs (mp_ptr old, mp_size_t size)
{
  assert (size > 0);
  return (mp_ptr) (*gmp_reallocate_func) (old, 0, size * sizeof (mp_limb_t));
}


/* MPN interface */

static void
mpn_copyi (mp_ptr d, mp_srcptr s, mp_size_t n)
{
  mp_size_t i;
  for (i = 0; i < n; i++)
    d[i] = s[i];
}

static void
mpn_copyd (mp_ptr d, mp_srcptr s, mp_size_t n)
{
  while (--n >= 0)
    d[n] = s[n];
}

static int
mpn_cmp (mp_srcptr ap, mp_srcptr bp, mp_size_t n)
{
  while (--n >= 0)
    {
      if (ap[n] != bp[n])
	return ap[n] > bp[n] ? 1 : -1;
    }
  return 0;
}

static int
mpn_cmp4 (mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn)
{
  if (an != bn)
    return an < bn ? -1 : 1;
  else
    return mpn_cmp (ap, bp, an);
}

static mp_size_t
mpn_normalized_size (mp_srcptr xp, mp_size_t n)
{
  while (n > 0 && xp[n-1] == 0)
    --n;
  return n;
}

static int
mpn_zero_p(mp_srcptr rp, mp_size_t n)
{
  return mpn_normalized_size (rp, n) == 0;
}

static void
mpn_zero (mp_ptr rp, mp_size_t n)
{
  while (--n >= 0)
    rp[n] = 0;
}

static mp_limb_t
mpn_add_1 (mp_ptr rp, mp_srcptr ap, mp_size_t n, mp_limb_t b)
{
  mp_size_t i;

  assert (n > 0);
  i = 0;
  do
    {
      mp_limb_t r = ap[i] + b;
      /* Carry out */
      b = (r < b);
      rp[i] = r;
    }
  while (++i < n);

  return b;
}

static mp_limb_t
mpn_add_n (mp_ptr rp, mp_srcptr ap, mp_srcptr bp, mp_size_t n)
{
  mp_size_t i;
  mp_limb_t cy;

  for (i = 0, cy = 0; i < n; i++)
    {
      mp_limb_t a, b, r;
      a = ap[i]; b = bp[i];
      r = a + cy;
      cy = (r < cy);
      r += b;
      cy += (r < b);
      rp[i] = r;
    }
  return cy;
}

static mp_limb_t
mpn_add (mp_ptr rp, mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn)
{
  mp_limb_t cy;

  assert (an >= bn);

  cy = mpn_add_n (rp, ap, bp, bn);
  if (an > bn)
    cy = mpn_add_1 (rp + bn, ap + bn, an - bn, cy);
  return cy;
}

static mp_limb_t
mpn_sub_1 (mp_ptr rp, mp_srcptr ap, mp_size_t n, mp_limb_t b)
{
  mp_size_t i;

  assert (n > 0);

  i = 0;
  do
    {
      mp_limb_t a = ap[i];
      /* Carry out */
      mp_limb_t cy = a < b;
      rp[i] = a - b;
      b = cy;
    }
  while (++i < n);

  return b;
}

static mp_limb_t
mpn_sub_n (mp_ptr rp, mp_srcptr ap, mp_srcptr bp, mp_size_t n)
{
  mp_size_t i;
  mp_limb_t cy;

  for (i = 0, cy = 0; i < n; i++)
    {
      mp_limb_t a, b;
      a = ap[i]; b = bp[i];
      b += cy;
      cy = (b < cy);
      cy += (a < b);
      rp[i] = a - b;
    }
  return cy;
}

static mp_limb_t
mpn_sub (mp_ptr rp, mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn)
{
  mp_limb_t cy;

  assert (an >= bn);

  cy = mpn_sub_n (rp, ap, bp, bn);
  if (an > bn)
    cy = mpn_sub_1 (rp + bn, ap + bn, an - bn, cy);
  return cy;
}

static mp_limb_t
mpn_mul_1 (mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl)
{
  mp_limb_t ul, cl, hpl, lpl;

  assert (n >= 1);

  cl = 0;
  do
    {
      ul = *up++;
      gmp_umul_ppmm (hpl, lpl, ul, vl);

      lpl += cl;
      cl = (lpl < cl) + hpl;

      *rp++ = lpl;
    }
  while (--n != 0);

  return cl;
}

static mp_limb_t
mpn_addmul_1 (mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl)
{
  mp_limb_t ul, cl, hpl, lpl, rl;

  assert (n >= 1);

  cl = 0;
  do
    {
      ul = *up++;
      gmp_umul_ppmm (hpl, lpl, ul, vl);

      lpl += cl;
      cl = (lpl < cl) + hpl;

      rl = *rp;
      lpl = rl + lpl;
      cl += lpl < rl;
      *rp++ = lpl;
    }
  while (--n != 0);

  return cl;
}

static mp_limb_t
mpn_submul_1 (mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl)
{
  mp_limb_t ul, cl, hpl, lpl, rl;

  assert (n >= 1);

  cl = 0;
  do
    {
      ul = *up++;
      gmp_umul_ppmm (hpl, lpl, ul, vl);

      lpl += cl;
      cl = (lpl < cl) + hpl;

      rl = *rp;
      lpl = rl - lpl;
      cl += lpl > rl;
      *rp++ = lpl;
    }
  while (--n != 0);

  return cl;
}

static mp_limb_t
mpn_mul (mp_ptr rp, mp_srcptr up, mp_size_t un, mp_srcptr vp, mp_size_t vn)
{
  assert (un >= vn);
  assert (vn >= 1);
  assert (!GMP_MPN_OVERLAP_P(rp, un + vn, up, un));
  assert (!GMP_MPN_OVERLAP_P(rp, un + vn, vp, vn));

  /* We first multiply by the low order limb. This result can be
     stored, not added, to rp. We also avoid a loop for zeroing this
     way. */

  rp[un] = mpn_mul_1 (rp, up, un, vp[0]);

  /* Now accumulate the product of up[] and the next higher limb from
     vp[]. */

  while (--vn >= 1)
    {
      rp += 1, vp += 1;
      rp[un] = mpn_addmul_1 (rp, up, un, vp[0]);
    }
  return rp[un];
}


static mp_limb_t
mpn_lshift (mp_ptr rp, mp_srcptr up, mp_size_t n, unsigned int cnt)
{
  mp_limb_t high_limb, low_limb;
  unsigned int tnc;
  mp_limb_t retval;

  assert (n >= 1);
  assert (cnt >= 1);
  assert (cnt < GMP_LIMB_BITS);

  up += n;
  rp += n;

  tnc = GMP_LIMB_BITS - cnt;
  low_limb = *--up;
  retval = low_limb >> tnc;
  high_limb = (low_limb << cnt);

  while (--n != 0)
    {
      low_limb = *--up;
      *--rp = high_limb | (low_limb >> tnc);
      high_limb = (low_limb << cnt);
    }
  *--rp = high_limb;

  return retval;
}

static mp_limb_t
mpn_rshift (mp_ptr rp, mp_srcptr up, mp_size_t n, unsigned int cnt)
{
  mp_limb_t high_limb, low_limb;
  unsigned int tnc;
  mp_limb_t retval;

  assert (n >= 1);
  assert (cnt >= 1);
  assert (cnt < GMP_LIMB_BITS);

  tnc = GMP_LIMB_BITS - cnt;
  high_limb = *up++;
  retval = (high_limb << tnc);
  low_limb = high_limb >> cnt;

  while (--n != 0)
    {
      high_limb = *up++;
      *rp++ = low_limb | (high_limb << tnc);
      low_limb = high_limb >> cnt;
    }
  *rp = low_limb;

  return retval;
}

static mp_bitcnt_t
mpn_common_scan (mp_limb_t limb, mp_size_t i, mp_srcptr up, mp_size_t un,
		 mp_limb_t ux)
{
  unsigned cnt;

  assert (ux == 0 || ux == GMP_LIMB_MAX);
  assert (0 <= i && i <= un );

  while (limb == 0)
    {
      i++;
      if (i == un)
	return (ux == 0 ? ~(mp_bitcnt_t) 0 : un * (mp_bitcnt_t)GMP_LIMB_BITS);
      limb = ux ^ up[i];
    }
  gmp_ctz (cnt, limb);
  return (mp_bitcnt_t) i * GMP_LIMB_BITS + cnt;
}

mp_bitcnt_t
mpn_scan1 (mp_srcptr ptr, mp_bitcnt_t bit)
{
  mp_size_t i;
  i = bit / GMP_LIMB_BITS;

  return mpn_common_scan ( ptr[i] & (GMP_LIMB_MAX << (bit % GMP_LIMB_BITS)),
			  i, ptr, i, 0);
}


/* MPN division interface. */

/* The 3/2 inverse is defined as

     m = floor( (B^3-1) / (B u1 + u0)) - B
*/
static mp_limb_t
mpn_invert_3by2 (mp_limb_t u1, mp_limb_t u0)
{
  mp_limb_t r, m;

  {
    mp_limb_t p, ql;
    unsigned ul, uh, qh;

    /* For notation, let b denote the half-limb base, so that B = b^2.
       Split u1 = b uh + ul. */
    ul = u1 & GMP_LLIMB_MASK;
    uh = u1 >> (GMP_LIMB_BITS / 2);

    /* Approximation of the high half of quotient. Differs from the 2/1
       inverse of the half limb uh, since we have already subtracted
       u0. */
    qh = (u1 ^ GMP_LIMB_MAX) / uh;

    /* Adjust to get a half-limb 3/2 inverse, i.e., we want

       qh' = floor( (b^3 - 1) / u) - b = floor ((b^3 - b u - 1) / u
	   = floor( (b (~u) + b-1) / u),

       and the remainder

       r = b (~u) + b-1 - qh (b uh + ul)
       = b (~u - qh uh) + b-1 - qh ul

       Subtraction of qh ul may underflow, which implies adjustments.
       But by normalization, 2 u >= B > qh ul, so we need to adjust by
       at most 2.
    */

    r = ((~u1 - (mp_limb_t) qh * uh) << (GMP_LIMB_BITS / 2)) | GMP_LLIMB_MASK;

    p = (mp_limb_t) qh * ul;
    /* Adjustment steps taken from udiv_qrnnd_c */
    if (r < p)
      {
	qh--;
	r += u1;
	if (r >= u1) /* i.e. we didn't get carry when adding to r */
	  if (r < p)
	    {
	      qh--;
	      r += u1;
	    }
      }
    r -= p;

    /* Low half of the quotient is

       ql = floor ( (b r + b-1) / u1).

       This is a 3/2 division (on half-limbs), for which qh is a
       suitable inverse. */

    p = (r >> (GMP_LIMB_BITS / 2)) * qh + r;
    /* Unlike full-limb 3/2, we can add 1 without overflow. For this to
       work, it is essential that ql is a full mp_limb_t. */
    ql = (p >> (GMP_LIMB_BITS / 2)) + 1;

    /* By the 3/2 trick, we don't need the high half limb. */
    r = (r << (GMP_LIMB_BITS / 2)) + GMP_LLIMB_MASK - ql * u1;

    if (r >= (GMP_LIMB_MAX & (p << (GMP_LIMB_BITS / 2))))
      {
	ql--;
	r += u1;
      }
    m = ((mp_limb_t) qh << (GMP_LIMB_BITS / 2)) + ql;
    if (r >= u1)
      {
	m++;
	r -= u1;
      }
  }

  /* Now m is the 2/1 inverse of u1. If u0 > 0, adjust it to become a
     3/2 inverse. */
  if (u0 > 0)
    {
      mp_limb_t th, tl;
      r = ~r;
      r += u0;
      if (r < u0)
	{
	  m--;
	  if (r >= u1)
	    {
	      m--;
	      r -= u1;
	    }
	  r -= u1;
	}
      gmp_umul_ppmm (th, tl, u0, m);
      r += th;
      if (r < th)
	{
	  m--;
	  m -= ((r > u1) | ((r == u1) & (tl > u0)));
	}
    }

  return m;
}

struct gmp_div_inverse
{
  /* Normalization shift count. */
  unsigned shift;
  /* Normalized divisor (d0 unused for mpn_div_qr_1) */
  mp_limb_t d1, d0;
  /* Inverse, for 2/1 or 3/2. */
  mp_limb_t di;
};

static void
mpn_div_qr_1_invert (struct gmp_div_inverse *inv, mp_limb_t d)
{
  unsigned shift;

  assert (d > 0);
  gmp_clz (shift, d);
  inv->shift = shift;
  inv->d1 = d << shift;
  inv->di = mpn_invert_limb (inv->d1);
}

static void
mpn_div_qr_2_invert (struct gmp_div_inverse *inv,
		     mp_limb_t d1, mp_limb_t d0)
{
  unsigned shift;

  assert (d1 > 0);
  gmp_clz (shift, d1);
  inv->shift = shift;
  if (shift > 0)
    {
      d1 = (d1 << shift) | (d0 >> (GMP_LIMB_BITS - shift));
      d0 <<= shift;
    }
  inv->d1 = d1;
  inv->d0 = d0;
  inv->di = mpn_invert_3by2 (d1, d0);
}

static void
mpn_div_qr_invert (struct gmp_div_inverse *inv,
		   mp_srcptr dp, mp_size_t dn)
{
  assert (dn > 0);

  if (dn == 1)
    mpn_div_qr_1_invert (inv, dp[0]);
  else if (dn == 2)
    mpn_div_qr_2_invert (inv, dp[1], dp[0]);
  else
    {
      unsigned shift;
      mp_limb_t d1, d0;

      d1 = dp[dn-1];
      d0 = dp[dn-2];
      assert (d1 > 0);
      gmp_clz (shift, d1);
      inv->shift = shift;
      if (shift > 0)
	{
	  d1 = (d1 << shift) | (d0 >> (GMP_LIMB_BITS - shift));
	  d0 = (d0 << shift) | (dp[dn-3] >> (GMP_LIMB_BITS - shift));
	}
      inv->d1 = d1;
      inv->d0 = d0;
      inv->di = mpn_invert_3by2 (d1, d0);
    }
}

/* Not matching current public gmp interface, rather corresponding to
   the sbpi1_div_* functions. */
static mp_limb_t
mpn_div_qr_1_preinv (mp_ptr qp, mp_srcptr np, mp_size_t nn,
		     const struct gmp_div_inverse *inv)
{
  mp_limb_t d, di;
  mp_limb_t r;
  mp_ptr tp = NULL;

  if (inv->shift > 0)
    {
      /* Shift, reusing qp area if possible. In-place shift if qp == np. */
      tp = qp ? qp : gmp_xalloc_limbs (nn);
      r = mpn_lshift (tp, np, nn, inv->shift);
      np = tp;
    }
  else
    r = 0;

  d = inv->d1;
  di = inv->di;
  while (--nn >= 0)
    {
      mp_limb_t q;

      gmp_udiv_qrnnd_preinv (q, r, r, np[nn], d, di);
      if (qp)
	qp[nn] = q;
    }
  if ((inv->shift > 0) && (tp != qp))
    gmp_free (tp);

  return r >> inv->shift;
}

static void
mpn_div_qr_2_preinv (mp_ptr qp, mp_ptr np, mp_size_t nn,
		     const struct gmp_div_inverse *inv)
{
  unsigned shift;
  mp_size_t i;
  mp_limb_t d1, d0, di, r1, r0;

  assert (nn >= 2);
  shift = inv->shift;
  d1 = inv->d1;
  d0 = inv->d0;
  di = inv->di;

  if (shift > 0)
    r1 = mpn_lshift (np, np, nn, shift);
  else
    r1 = 0;

  r0 = np[nn - 1];

  i = nn - 2;
  do
    {
      mp_limb_t n0, q;
      n0 = np[i];
      gmp_udiv_qr_3by2 (q, r1, r0, r1, r0, n0, d1, d0, di);

      if (qp)
	qp[i] = q;
    }
  while (--i >= 0);

  if (shift > 0)
    {
      assert ((r0 & (GMP_LIMB_MAX >> (GMP_LIMB_BITS - shift))) == 0);
      r0 = (r0 >> shift) | (r1 << (GMP_LIMB_BITS - shift));
      r1 >>= shift;
    }

  np[1] = r1;
  np[0] = r0;
}

static void
mpn_div_qr_pi1 (mp_ptr qp,
		mp_ptr np, mp_size_t nn, mp_limb_t n1,
		mp_srcptr dp, mp_size_t dn,
		mp_limb_t dinv)
{
  mp_size_t i;

  mp_limb_t d1, d0;
  mp_limb_t cy, cy1;
  mp_limb_t q;

  assert (dn > 2);
  assert (nn >= dn);

  d1 = dp[dn - 1];
  d0 = dp[dn - 2];

  assert ((d1 & GMP_LIMB_HIGHBIT) != 0);
  /* Iteration variable is the index of the q limb.
   *
   * We divide <n1, np[dn-1+i], np[dn-2+i], np[dn-3+i],..., np[i]>
   * by            <d1,          d0,        dp[dn-3],  ..., dp[0] >
   */

  i = nn - dn;
  do
    {
      mp_limb_t n0 = np[dn-1+i];

      if (n1 == d1 && n0 == d0)
	{
	  q = GMP_LIMB_MAX;
	  mpn_submul_1 (np+i, dp, dn, q);
	  n1 = np[dn-1+i];	/* update n1, last loop's value will now be invalid */
	}
      else
	{
	  gmp_udiv_qr_3by2 (q, n1, n0, n1, n0, np[dn-2+i], d1, d0, dinv);

	  cy = mpn_submul_1 (np + i, dp, dn-2, q);

	  cy1 = n0 < cy;
	  n0 = n0 - cy;
	  cy = n1 < cy1;
	  n1 = n1 - cy1;
	  np[dn-2+i] = n0;

	  if (cy != 0)
	    {
	      n1 += d1 + mpn_add_n (np + i, np + i, dp, dn - 1);
	      q--;
	    }
	}

      if (qp)
	qp[i] = q;
    }
  while (--i >= 0);

  np[dn - 1] = n1;
}

static void
mpn_div_qr_preinv (mp_ptr qp, mp_ptr np, mp_size_t nn,
		   mp_srcptr dp, mp_size_t dn,
		   const struct gmp_div_inverse *inv)
{
  assert (dn > 0);
  assert (nn >= dn);

  if (dn == 1)
    np[0] = mpn_div_qr_1_preinv (qp, np, nn, inv);
  else if (dn == 2)
    mpn_div_qr_2_preinv (qp, np, nn, inv);
  else
    {
      mp_limb_t nh;
      unsigned shift;

      assert (inv->d1 == dp[dn-1]);
      assert (inv->d0 == dp[dn-2]);
      assert ((inv->d1 & GMP_LIMB_HIGHBIT) != 0);

      shift = inv->shift;
      if (shift > 0)
	nh = mpn_lshift (np, np, nn, shift);
      else
	nh = 0;

      mpn_div_qr_pi1 (qp, np, nn, nh, dp, dn, inv->di);

      if (shift > 0)
	gmp_assert_nocarry (mpn_rshift (np, np, dn, shift));
    }
}

static void
mpn_div_qr (mp_ptr qp, mp_ptr np, mp_size_t nn, mp_srcptr dp, mp_size_t dn)
{
  struct gmp_div_inverse inv;
  mp_ptr tp = NULL;

  assert (dn > 0);
  assert (nn >= dn);

  mpn_div_qr_invert (&inv, dp, dn);
  if (dn > 2 && inv.shift > 0)
    {
      tp = gmp_xalloc_limbs (dn);
      gmp_assert_nocarry (mpn_lshift (tp, dp, dn, inv.shift));
      dp = tp;
    }
  mpn_div_qr_preinv (qp, np, nn, dp, dn, &inv);
  if (tp)
    gmp_free (tp);
}


static mp_bitcnt_t
mpn_limb_size_in_base_2 (mp_limb_t u)
{
  unsigned shift;

  assert (u > 0);
  gmp_clz (shift, u);
  return GMP_LIMB_BITS - shift;
}


/* MPZ interface */
void
mpz_init (mpz_t r)
{
  static const mp_limb_t dummy_limb = GMP_LIMB_MAX & 0xc1a0;

  r->_mp_alloc = 0;
  r->_mp_size = 0;
  r->_mp_d = (mp_ptr) &dummy_limb;
}

/* The utility of this function is a bit limited, since many functions
   assigns the result variable using mpz_swap. */
void
mpz_init2 (mpz_t r, mp_bitcnt_t bits)
{
  mp_size_t rn;

  bits -= (bits != 0);		/* Round down, except if 0 */
  rn = 1 + bits / GMP_LIMB_BITS;

  r->_mp_alloc = rn;
  r->_mp_size = 0;
  r->_mp_d = gmp_xalloc_limbs (rn);
}

void
mpz_clear (mpz_t r)
{
  if (r->_mp_alloc)
    gmp_free (r->_mp_d);
}

static mp_ptr
mpz_realloc (mpz_t r, mp_size_t size)
{
  size = GMP_MAX (size, 1);

  if (r->_mp_alloc)
    r->_mp_d = gmp_xrealloc_limbs (r->_mp_d, size);
  else
    r->_mp_d = gmp_xalloc_limbs (size);
  r->_mp_alloc = size;

  if (GMP_ABS (r->_mp_size) > size)
    r->_mp_size = 0;

  return r->_mp_d;
}

/* Realloc for an mpz_t WHAT if it has less than NEEDED limbs.  */
#define MPZ_REALLOC(z,n) ((n) > (z)->_mp_alloc			\
			  ? mpz_realloc(z,n)			\
			  : (z)->_mp_d)

/* MPZ assignment and basic conversions. */
void
mpz_set_si (mpz_t r, signed long int x)
{
  if (x >= 0)
    mpz_set_ui (r, x);
  else /* (x < 0) */
    if (GMP_LIMB_BITS < GMP_ULONG_BITS)
      {
	mpz_set_ui (r, GMP_NEG_CAST (unsigned long int, x));
	mpz_neg (r, r);
      }
  else
    {
      r->_mp_size = -1;
      MPZ_REALLOC (r, 1)[0] = GMP_NEG_CAST (unsigned long int, x);
    }
}

void
mpz_set_ui (mpz_t r, unsigned long int x)
{
  if (x > 0)
    {
      r->_mp_size = 1;
      MPZ_REALLOC (r, 1)[0] = x;
      if (GMP_LIMB_BITS < GMP_ULONG_BITS)
	{
	  int LOCAL_GMP_LIMB_BITS = GMP_LIMB_BITS;
	  while (x >>= LOCAL_GMP_LIMB_BITS)
	    {
	      ++ r->_mp_size;
	      MPZ_REALLOC (r, r->_mp_size)[r->_mp_size - 1] = x;
	    }
	}
    }
  else
    r->_mp_size = 0;
}

void
mpz_set (mpz_t r, const mpz_t x)
{
  /* Allow the NOP r == x */
  if (r != x)
    {
      mp_size_t n;
      mp_ptr rp;

      n = GMP_ABS (x->_mp_size);
      rp = MPZ_REALLOC (r, n);

      mpn_copyi (rp, x->_mp_d, n);
      r->_mp_size = x->_mp_size;
    }
}

void
mpz_init_set_si (mpz_t r, signed long int x)
{
  mpz_init (r);
  mpz_set_si (r, x);
}

static void
mpz_init_set_ui (mpz_t r, unsigned long int x)
{
  mpz_init (r);
  mpz_set_ui (r, x);
}

void
mpz_init_set (mpz_t r, const mpz_t x)
{
  mpz_init (r);
  mpz_set (r, x);
}

static int
mpz_cmp_ui (const mpz_t u, unsigned long v);
int
mpz_cmpabs_ui (const mpz_t u, unsigned long v);

int
mpz_fits_slong_p (const mpz_t u)
{
  return (LONG_MAX + LONG_MIN == 0 || mpz_cmp_ui (u, LONG_MAX) <= 0) &&
    mpz_cmpabs_ui (u, GMP_NEG_CAST (unsigned long int, LONG_MIN)) <= 0;
}

static int
mpn_absfits_ulong_p (mp_srcptr up, mp_size_t un)
{
  int ulongsize = GMP_ULONG_BITS / GMP_LIMB_BITS;
  mp_limb_t ulongrem = 0;

  if (GMP_ULONG_BITS % GMP_LIMB_BITS != 0)
    ulongrem = (mp_limb_t) (ULONG_MAX >> GMP_LIMB_BITS * ulongsize) + 1;

  return un <= ulongsize || (up[ulongsize] < ulongrem && un == ulongsize + 1);
}

int
mpz_fits_ulong_p (const mpz_t u)
{
  mp_size_t us = u->_mp_size;

  return us >= 0 && mpn_absfits_ulong_p (u->_mp_d, us);
}

long int
mpz_get_si (const mpz_t u)
{
  unsigned long r = mpz_get_ui (u);
  unsigned long c = -LONG_MAX - LONG_MIN;

  if (u->_mp_size < 0)
    /* This expression is necessary to properly handle -LONG_MIN */
    return -(long) c - (long) ((r - c) & LONG_MAX);
  else
    return (long) (r & LONG_MAX);
}

unsigned long int
mpz_get_ui (const mpz_t u)
{
  if (GMP_LIMB_BITS < GMP_ULONG_BITS)
    {
      int LOCAL_GMP_LIMB_BITS = GMP_LIMB_BITS;
      unsigned long r = 0;
      mp_size_t n = GMP_ABS (u->_mp_size);
      n = GMP_MIN (n, 1 + (mp_size_t) (GMP_ULONG_BITS - 1) / GMP_LIMB_BITS);
      while (--n >= 0)
	r = (r << LOCAL_GMP_LIMB_BITS) + u->_mp_d[n];
      return r;
    }

  return u->_mp_size == 0 ? 0 : u->_mp_d[0];
}

size_t
mpz_size (const mpz_t u)
{
  return GMP_ABS (u->_mp_size);
}


/* MPZ comparisons and the like. */
int
mpz_sgn (const mpz_t u)
{
  return GMP_CMP (u->_mp_size, 0);
}

static int
mpz_cmp_ui (const mpz_t u, unsigned long v)
{
  mp_size_t usize = u->_mp_size;

  if (usize < 0)
    return -1;
  else
    return mpz_cmpabs_ui (u, v);
}

int
mpz_cmp (const mpz_t a, const mpz_t b)
{
  mp_size_t asize = a->_mp_size;
  mp_size_t bsize = b->_mp_size;

  if (asize != bsize)
    return (asize < bsize) ? -1 : 1;
  else if (asize >= 0)
    return mpn_cmp (a->_mp_d, b->_mp_d, asize);
  else
    return mpn_cmp (b->_mp_d, a->_mp_d, -asize);
}

int
mpz_cmpabs_ui (const mpz_t u, unsigned long v)
{
  mp_size_t un = GMP_ABS (u->_mp_size);

  if (! mpn_absfits_ulong_p (u->_mp_d, un))
    return 1;
  else
    {
      unsigned long uu = mpz_get_ui (u);
      return GMP_CMP(uu, v);
    }
}

void
mpz_neg (mpz_t r, const mpz_t u)
{
  mpz_set (r, u);
  r->_mp_size = -r->_mp_size;
}

static void
mpz_swap (mpz_t u, mpz_t v)
{
  MP_SIZE_T_SWAP (u->_mp_size, v->_mp_size);
  MP_SIZE_T_SWAP (u->_mp_alloc, v->_mp_alloc);
  MP_PTR_SWAP (u->_mp_d, v->_mp_d);
}


/* MPZ addition and subtraction */


void
mpz_add_ui (mpz_t r, const mpz_t a, unsigned long b)
{
  mpz_t bb;
  mpz_init_set_ui (bb, b);
  mpz_add (r, a, bb);
  mpz_clear (bb);
}

static void
mpz_ui_sub (mpz_t r, unsigned long a, const mpz_t b);

void
mpz_sub_ui (mpz_t r, const mpz_t a, unsigned long b)
{
  mpz_ui_sub (r, b, a);
  mpz_neg (r, r);
}

static void
mpz_ui_sub (mpz_t r, unsigned long a, const mpz_t b)
{
  mpz_neg (r, b);
  mpz_add_ui (r, r, a);
}

static mp_size_t
mpz_abs_add (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t an = GMP_ABS (a->_mp_size);
  mp_size_t bn = GMP_ABS (b->_mp_size);
  mp_ptr rp;
  mp_limb_t cy;

  if (an < bn)
    {
      MPZ_SRCPTR_SWAP (a, b);
      MP_SIZE_T_SWAP (an, bn);
    }

  rp = MPZ_REALLOC (r, an + 1);
  cy = mpn_add (rp, a->_mp_d, an, b->_mp_d, bn);

  rp[an] = cy;

  return an + cy;
}

static mp_size_t
mpz_abs_sub (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t an = GMP_ABS (a->_mp_size);
  mp_size_t bn = GMP_ABS (b->_mp_size);
  int cmp;
  mp_ptr rp;

  cmp = mpn_cmp4 (a->_mp_d, an, b->_mp_d, bn);
  if (cmp > 0)
    {
      rp = MPZ_REALLOC (r, an);
      gmp_assert_nocarry (mpn_sub (rp, a->_mp_d, an, b->_mp_d, bn));
      return mpn_normalized_size (rp, an);
    }
  else if (cmp < 0)
    {
      rp = MPZ_REALLOC (r, bn);
      gmp_assert_nocarry (mpn_sub (rp, b->_mp_d, bn, a->_mp_d, an));
      return -mpn_normalized_size (rp, bn);
    }
  else
    return 0;
}

void
mpz_add (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t rn;

  if ( (a->_mp_size ^ b->_mp_size) >= 0)
    rn = mpz_abs_add (r, a, b);
  else
    rn = mpz_abs_sub (r, a, b);

  r->_mp_size = a->_mp_size >= 0 ? rn : - rn;
}

void
mpz_sub (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t rn;

  if ( (a->_mp_size ^ b->_mp_size) >= 0)
    rn = mpz_abs_sub (r, a, b);
  else
    rn = mpz_abs_add (r, a, b);

  r->_mp_size = a->_mp_size >= 0 ? rn : - rn;
}


void
mpz_mul (mpz_t r, const mpz_t u, const mpz_t v)
{
  int sign;
  mp_size_t un, vn, rn;
  mpz_t t;
  mp_ptr tp;

  un = u->_mp_size;
  vn = v->_mp_size;

  if (un == 0 || vn == 0)
    {
      r->_mp_size = 0;
      return;
    }

  sign = (un ^ vn) < 0;

  un = GMP_ABS (un);
  vn = GMP_ABS (vn);

  mpz_init2 (t, (un + vn) * GMP_LIMB_BITS);

  tp = t->_mp_d;
  if (un >= vn)
    mpn_mul (tp, u->_mp_d, un, v->_mp_d, vn);
  else
    mpn_mul (tp, v->_mp_d, vn, u->_mp_d, un);

  rn = un + vn;
  rn -= tp[rn-1] == 0;

  t->_mp_size = sign ? - rn : rn;
  mpz_swap (r, t);
  mpz_clear (t);
}

void
mpz_mul_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t bits)
{
  mp_size_t un, rn;
  mp_size_t limbs;
  unsigned shift;
  mp_ptr rp;

  un = GMP_ABS (u->_mp_size);
  if (un == 0)
    {
      r->_mp_size = 0;
      return;
    }

  limbs = bits / GMP_LIMB_BITS;
  shift = bits % GMP_LIMB_BITS;

  rn = un + limbs + (shift > 0);
  rp = MPZ_REALLOC (r, rn);
  if (shift > 0)
    {
      mp_limb_t cy = mpn_lshift (rp + limbs, u->_mp_d, un, shift);
      rp[rn-1] = cy;
      rn -= (cy == 0);
    }
  else
    mpn_copyd (rp + limbs, u->_mp_d, un);

  mpn_zero (rp, limbs);

  r->_mp_size = (u->_mp_size < 0) ? - rn : rn;
}


/* MPZ division */
enum mpz_div_round_mode { GMP_DIV_FLOOR, GMP_DIV_CEIL, GMP_DIV_TRUNC };

/* Allows q or r to be zero. Returns 1 iff remainder is non-zero. */
static int
mpz_div_qr (mpz_t q, mpz_t r,
	    const mpz_t n, const mpz_t d, enum mpz_div_round_mode mode)
{
  mp_size_t ns, ds, nn, dn, qs;
  ns = n->_mp_size;
  ds = d->_mp_size;

  if (ds == 0)
    gmp_die("mpz_div_qr: Divide by zero.");

  if (ns == 0)
    {
      if (q)
	q->_mp_size = 0;
      if (r)
	r->_mp_size = 0;
      return 0;
    }

  nn = GMP_ABS (ns);
  dn = GMP_ABS (ds);

  qs = ds ^ ns;

  if (nn < dn)
    {
      if (mode == GMP_DIV_CEIL && qs >= 0)
	{
	  /* q = 1, r = n - d */
	  if (r)
	    mpz_sub (r, n, d);
	  if (q)
	    mpz_set_ui (q, 1);
	}
      else if (mode == GMP_DIV_FLOOR && qs < 0)
	{
	  /* q = -1, r = n + d */
	  if (r)
	    mpz_add (r, n, d);
	  if (q)
	    mpz_set_si (q, -1);
	}
      else
	{
	  /* q = 0, r = d */
	  if (r)
	    mpz_set (r, n);
	  if (q)
	    q->_mp_size = 0;
	}
      return 1;
    }
  else
    {
      mp_ptr np, qp;
      mp_size_t qn, rn;
      mpz_t tq, tr;

      mpz_init_set (tr, n);
      np = tr->_mp_d;

      qn = nn - dn + 1;

      if (q)
	{
	  mpz_init2 (tq, qn * GMP_LIMB_BITS);
	  qp = tq->_mp_d;
	}
      else
	qp = NULL;

      mpn_div_qr (qp, np, nn, d->_mp_d, dn);

      if (qp)
	{
	  qn -= (qp[qn-1] == 0);

	  tq->_mp_size = qs < 0 ? -qn : qn;
	}
      rn = mpn_normalized_size (np, dn);
      tr->_mp_size = ns < 0 ? - rn : rn;

      if (mode == GMP_DIV_FLOOR && qs < 0 && rn != 0)
	{
	  if (q)
	    mpz_sub_ui (tq, tq, 1);
	  if (r)
	    mpz_add (tr, tr, d);
	}
      else if (mode == GMP_DIV_CEIL && qs >= 0 && rn != 0)
	{
	  if (q)
	    mpz_add_ui (tq, tq, 1);
	  if (r)
	    mpz_sub (tr, tr, d);
	}

      if (q)
	{
	  mpz_swap (tq, q);
	  mpz_clear (tq);
	}
      if (r)
	mpz_swap (tr, r);

      mpz_clear (tr);

      return rn != 0;
    }
}

void
mpz_tdiv_q (mpz_t q, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (q, NULL, n, d, GMP_DIV_TRUNC);
}

void
mpz_tdiv_r (mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (NULL, r, n, d, GMP_DIV_TRUNC);
}

static void
mpz_div_q_2exp (mpz_t q, const mpz_t u, mp_bitcnt_t bit_index,
		enum mpz_div_round_mode mode)
{
  mp_size_t un, qn;
  mp_size_t limb_cnt;
  mp_ptr qp;
  int adjust;

  un = u->_mp_size;
  if (un == 0)
    {
      q->_mp_size = 0;
      return;
    }
  limb_cnt = bit_index / GMP_LIMB_BITS;
  qn = GMP_ABS (un) - limb_cnt;
  bit_index %= GMP_LIMB_BITS;

  if (mode == ((un > 0) ? GMP_DIV_CEIL : GMP_DIV_FLOOR)) /* un != 0 here. */
    /* Note: Below, the final indexing at limb_cnt is valid because at
       that point we have qn > 0. */
    adjust = (qn <= 0
	      || !mpn_zero_p (u->_mp_d, limb_cnt)
	      || (u->_mp_d[limb_cnt]
		  & (((mp_limb_t) 1 << bit_index) - 1)));
  else
    adjust = 0;

  if (qn <= 0)
    qn = 0;
  else
    {
      qp = MPZ_REALLOC (q, qn);

      if (bit_index != 0)
	{
	  mpn_rshift (qp, u->_mp_d + limb_cnt, qn, bit_index);
	  qn -= qp[qn - 1] == 0;
	}
      else
	{
	  mpn_copyi (qp, u->_mp_d + limb_cnt, qn);
	}
    }

  q->_mp_size = qn;

  if (adjust)
    mpz_add_ui (q, q, 1);
  if (un < 0)
    mpz_neg (q, q);
}

void
mpz_fdiv_q_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_q_2exp (r, u, cnt, GMP_DIV_FLOOR);
}

void
mpz_tdiv_q_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_q_2exp (r, u, cnt, GMP_DIV_TRUNC);
}


/* Logical operations and bit manipulation. */

/* Numbers are treated as if represented in two's complement (and
   infinitely sign extended). For a negative values we get the two's
   complement from -x = ~x + 1, where ~ is bitwise complement.
   Negation transforms

     xxxx10...0

   into

     yyyy10...0

   where yyyy is the bitwise complement of xxxx. So least significant
   bits, up to and including the first one bit, are unchanged, and
   the more significant bits are all complemented.

   To change a bit from zero to one in a negative number, subtract the
   corresponding power of two from the absolute value. This can never
   underflow. To change a bit from one to zero, add the corresponding
   power of two, and this might overflow. E.g., if x = -001111, the
   two's complement is 110001. Clearing the least significant bit, we
   get two's complement 110000, and -010000. */

int
mpz_tstbit (const mpz_t d, mp_bitcnt_t bit_index)
{
  mp_size_t limb_index;
  unsigned shift;
  mp_size_t ds;
  mp_size_t dn;
  mp_limb_t w;
  int bit;

  ds = d->_mp_size;
  dn = GMP_ABS (ds);
  limb_index = bit_index / GMP_LIMB_BITS;
  if (limb_index >= dn)
    return ds < 0;

  shift = bit_index % GMP_LIMB_BITS;
  w = d->_mp_d[limb_index];
  bit = (w >> shift) & 1;

  if (ds < 0)
    {
      /* d < 0. Check if any of the bits below is set: If so, our bit
	 must be complemented. */
      if (shift > 0 && (mp_limb_t) (w << (GMP_LIMB_BITS - shift)) > 0)
	return bit ^ 1;
      while (--limb_index >= 0)
	if (d->_mp_d[limb_index] > 0)
	  return bit ^ 1;
    }
  return bit;
}

static void
mpz_abs_add_bit (mpz_t d, mp_bitcnt_t bit_index)
{
  mp_size_t dn, limb_index;
  mp_limb_t bit;
  mp_ptr dp;

  dn = GMP_ABS (d->_mp_size);

  limb_index = bit_index / GMP_LIMB_BITS;
  bit = (mp_limb_t) 1 << (bit_index % GMP_LIMB_BITS);

  if (limb_index >= dn)
    {
      mp_size_t i;
      /* The bit should be set outside of the end of the number.
	 We have to increase the size of the number. */
      dp = MPZ_REALLOC (d, limb_index + 1);

      dp[limb_index] = bit;
      for (i = dn; i < limb_index; i++)
	dp[i] = 0;
      dn = limb_index + 1;
    }
  else
    {
      mp_limb_t cy;

      dp = d->_mp_d;

      cy = mpn_add_1 (dp + limb_index, dp + limb_index, dn - limb_index, bit);
      if (cy > 0)
	{
	  dp = MPZ_REALLOC (d, dn + 1);
	  dp[dn++] = cy;
	}
    }

  d->_mp_size = (d->_mp_size < 0) ? - dn : dn;
}

static void
mpz_abs_sub_bit (mpz_t d, mp_bitcnt_t bit_index)
{
  mp_size_t dn, limb_index;
  mp_ptr dp;
  mp_limb_t bit;

  dn = GMP_ABS (d->_mp_size);
  dp = d->_mp_d;

  limb_index = bit_index / GMP_LIMB_BITS;
  bit = (mp_limb_t) 1 << (bit_index % GMP_LIMB_BITS);

  assert (limb_index < dn);

  gmp_assert_nocarry (mpn_sub_1 (dp + limb_index, dp + limb_index,
				 dn - limb_index, bit));
  dn = mpn_normalized_size (dp, dn);
  d->_mp_size = (d->_mp_size < 0) ? - dn : dn;
}

void
mpz_setbit (mpz_t d, mp_bitcnt_t bit_index)
{
  if (!mpz_tstbit (d, bit_index))
    {
      if (d->_mp_size >= 0)
	mpz_abs_add_bit (d, bit_index);
      else
	mpz_abs_sub_bit (d, bit_index);
    }
}

void
mpz_clrbit (mpz_t d, mp_bitcnt_t bit_index)
{
  if (mpz_tstbit (d, bit_index))
    {
      if (d->_mp_size >= 0)
	mpz_abs_sub_bit (d, bit_index);
      else
	mpz_abs_add_bit (d, bit_index);
    }
}

void
mpz_com (mpz_t r, const mpz_t u)
{
  mpz_add_ui (r, u, 1);
  mpz_neg (r, r);
}

void
mpz_and (mpz_t r, const mpz_t u, const mpz_t v)
{
  mp_size_t un, vn, rn, i;
  mp_ptr up, vp, rp;

  mp_limb_t ux, vx, rx;
  mp_limb_t uc, vc, rc;
  mp_limb_t ul, vl, rl;

  un = GMP_ABS (u->_mp_size);
  vn = GMP_ABS (v->_mp_size);
  if (un < vn)
    {
      MPZ_SRCPTR_SWAP (u, v);
      MP_SIZE_T_SWAP (un, vn);
    }
  if (vn == 0)
    {
      r->_mp_size = 0;
      return;
    }

  uc = u->_mp_size < 0;
  vc = v->_mp_size < 0;
  rc = uc & vc;

  ux = -uc;
  vx = -vc;
  rx = -rc;

  /* If the smaller input is positive, higher limbs don't matter. */
  rn = vx ? un : vn;

  rp = MPZ_REALLOC (r, rn + (mp_size_t) rc);

  up = u->_mp_d;
  vp = v->_mp_d;

  i = 0;
  do
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      vl = (vp[i] ^ vx) + vc;
      vc = vl < vc;

      rl = ( (ul & vl) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  while (++i < vn);
  assert (vc == 0);

  for (; i < rn; i++)
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      rl = ( (ul & vx) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  if (rc)
    rp[rn++] = rc;
  else
    rn = mpn_normalized_size (rp, rn);

  r->_mp_size = rx ? -rn : rn;
}

void
mpz_ior (mpz_t r, const mpz_t u, const mpz_t v)
{
  mp_size_t un, vn, rn, i;
  mp_ptr up, vp, rp;

  mp_limb_t ux, vx, rx;
  mp_limb_t uc, vc, rc;
  mp_limb_t ul, vl, rl;

  un = GMP_ABS (u->_mp_size);
  vn = GMP_ABS (v->_mp_size);
  if (un < vn)
    {
      MPZ_SRCPTR_SWAP (u, v);
      MP_SIZE_T_SWAP (un, vn);
    }
  if (vn == 0)
    {
      mpz_set (r, u);
      return;
    }

  uc = u->_mp_size < 0;
  vc = v->_mp_size < 0;
  rc = uc | vc;

  ux = -uc;
  vx = -vc;
  rx = -rc;

  /* If the smaller input is negative, by sign extension higher limbs
     don't matter. */
  rn = vx ? vn : un;

  rp = MPZ_REALLOC (r, rn + (mp_size_t) rc);

  up = u->_mp_d;
  vp = v->_mp_d;

  i = 0;
  do
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      vl = (vp[i] ^ vx) + vc;
      vc = vl < vc;

      rl = ( (ul | vl) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  while (++i < vn);
  assert (vc == 0);

  for (; i < rn; i++)
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      rl = ( (ul | vx) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  if (rc)
    rp[rn++] = rc;
  else
    rn = mpn_normalized_size (rp, rn);

  r->_mp_size = rx ? -rn : rn;
}

void
mpz_xor (mpz_t r, const mpz_t u, const mpz_t v)
{
  mp_size_t un, vn, i;
  mp_ptr up, vp, rp;

  mp_limb_t ux, vx, rx;
  mp_limb_t uc, vc, rc;
  mp_limb_t ul, vl, rl;

  un = GMP_ABS (u->_mp_size);
  vn = GMP_ABS (v->_mp_size);
  if (un < vn)
    {
      MPZ_SRCPTR_SWAP (u, v);
      MP_SIZE_T_SWAP (un, vn);
    }
  if (vn == 0)
    {
      mpz_set (r, u);
      return;
    }

  uc = u->_mp_size < 0;
  vc = v->_mp_size < 0;
  rc = uc ^ vc;

  ux = -uc;
  vx = -vc;
  rx = -rc;

  rp = MPZ_REALLOC (r, un + (mp_size_t) rc);

  up = u->_mp_d;
  vp = v->_mp_d;

  i = 0;
  do
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      vl = (vp[i] ^ vx) + vc;
      vc = vl < vc;

      rl = (ul ^ vl ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  while (++i < vn);
  assert (vc == 0);

  for (; i < un; i++)
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      rl = (ul ^ ux) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  if (rc)
    rp[un++] = rc;
  else
    un = mpn_normalized_size (rp, un);

  r->_mp_size = rx ? -un : un;
}

static unsigned
gmp_popcount_limb (mp_limb_t x)
{
  unsigned c;

  /* Do 16 bits at a time, to avoid limb-sized constants. */
  int LOCAL_SHIFT_BITS = 16;
  for (c = 0; x > 0;)
    {
      unsigned w = x - ((x >> 1) & 0x5555);
      w = ((w >> 2) & 0x3333) + (w & 0x3333);
      w =  (w >> 4) + w;
      w = ((w >> 8) & 0x000f) + (w & 0x000f);
      c += w;
      if (GMP_LIMB_BITS > LOCAL_SHIFT_BITS)
	x >>= LOCAL_SHIFT_BITS;
      else
	x = 0;
    }
  return c;
}

static mp_bitcnt_t
mpn_popcount (mp_srcptr p, mp_size_t n)
{
  mp_size_t i;
  mp_bitcnt_t c;

  for (c = 0, i = 0; i < n; i++)
    c += gmp_popcount_limb (p[i]);

  return c;
}

mp_bitcnt_t
mpz_popcount (const mpz_t u)
{
  mp_size_t un;

  un = u->_mp_size;

  if (un < 0)
    return ~(mp_bitcnt_t) 0;

  return mpn_popcount (u->_mp_d, un);
}


mp_bitcnt_t
mpz_scan1 (const mpz_t u, mp_bitcnt_t starting_bit)
{
  mp_ptr up;
  mp_size_t us, un, i;
  mp_limb_t limb, ux;

  us = u->_mp_size;
  un = GMP_ABS (us);
  i = starting_bit / GMP_LIMB_BITS;

  /* Past the end there's no 1 bits for u>=0, or an immediate 1 bit
     for u<0. Notice this test picks up any u==0 too. */
  if (i >= un)
    return (us >= 0 ? ~(mp_bitcnt_t) 0 : starting_bit);

  up = u->_mp_d;
  ux = 0;
  limb = up[i];

  if (starting_bit != 0)
    {
      if (us < 0)
	{
	  ux = mpn_zero_p (up, i);
	  limb = ~ limb + ux;
	  ux = - (mp_limb_t) (limb >= ux);
	}

      /* Mask to 0 all bits before starting_bit, thus ignoring them. */
      limb &= GMP_LIMB_MAX << (starting_bit % GMP_LIMB_BITS);
    }

  return mpn_common_scan (limb, i, up, un, ux);
}


/* MPZ base conversion. */

size_t
mpz_sizeinbase (const mpz_t u, int base)
{
  mp_size_t un;
  mp_srcptr up;
  mp_ptr tp;
  mp_bitcnt_t bits;
  struct gmp_div_inverse bi;
  size_t ndigits;

  assert (base >= 2);
  assert (base <= 62);

  un = GMP_ABS (u->_mp_size);
  if (un == 0)
    return 1;

  up = u->_mp_d;

  bits = (un - 1) * GMP_LIMB_BITS + mpn_limb_size_in_base_2 (up[un-1]);
  switch (base)
    {
    case 2:
      return bits;
    case 4:
      return (bits + 1) / 2;
    case 8:
      return (bits + 2) / 3;
    case 16:
      return (bits + 3) / 4;
    case 32:
      return (bits + 4) / 5;
      /* FIXME: Do something more clever for the common case of base
	 10. */
    }

  tp = gmp_xalloc_limbs (un);
  mpn_copyi (tp, up, un);
  mpn_div_qr_1_invert (&bi, base);

  ndigits = 0;
  do
    {
      ndigits++;
      mpn_div_qr_1_preinv (tp, tp, un, &bi);
      un -= (tp[un-1] == 0);
    }
  while (un > 0);

  gmp_free (tp);
  return ndigits;
}


static int
gmp_detect_endian (void)
{
  static const int i = 2;
  const unsigned char *p = (const unsigned char *) &i;
  return 1 - *p;
}

/* Import and export. Does not support nails. */
void
mpz_import (mpz_t r, size_t count, int order, size_t size, int endian,
	    size_t nails, const void *src)
{
  const unsigned char *p;
  ptrdiff_t word_step;
  mp_ptr rp;
  mp_size_t rn;

  /* The current (partial) limb. */
  mp_limb_t limb;
  /* The number of bytes already copied to this limb (starting from
     the low end). */
  size_t bytes;
  /* The index where the limb should be stored, when completed. */
  mp_size_t i;

  if (nails != 0)
    gmp_die ("mpz_import: Nails not supported.");

  assert (order == 1 || order == -1);
  assert (endian >= -1 && endian <= 1);

  if (endian == 0)
    endian = gmp_detect_endian ();

  p = (unsigned char *) src;

  word_step = (order != endian) ? 2 * size : 0;

  /* Process bytes from the least significant end, so point p at the
     least significant word. */
  if (order == 1)
    {
      p += size * (count - 1);
      word_step = - word_step;
    }

  /* And at least significant byte of that word. */
  if (endian == 1)
    p += (size - 1);

  rn = (size * count + sizeof(mp_limb_t) - 1) / sizeof(mp_limb_t);
  rp = MPZ_REALLOC (r, rn);

  for (limb = 0, bytes = 0, i = 0; count > 0; count--, p += word_step)
    {
      size_t j;
      for (j = 0; j < size; j++, p -= (ptrdiff_t) endian)
	{
	  limb |= (mp_limb_t) *p << (bytes++ * CHAR_BIT);
	  if (bytes == sizeof(mp_limb_t))
	    {
	      rp[i++] = limb;
	      bytes = 0;
	      limb = 0;
	    }
	}
    }
  assert (i + (bytes > 0) == rn);
  if (limb != 0)
    rp[i++] = limb;
  else
    i = mpn_normalized_size (rp, i);

  r->_mp_size = i;
}

void *
mpz_export (void *r, size_t *countp, int order, size_t size, int endian,
	    size_t nails, const mpz_t u)
{
  size_t count;
  mp_size_t un;

  if (nails != 0)
    gmp_die ("mpz_import: Nails not supported.");

  assert (order == 1 || order == -1);
  assert (endian >= -1 && endian <= 1);
  assert (size > 0 || u->_mp_size == 0);

  un = u->_mp_size;
  count = 0;
  if (un != 0)
    {
      size_t k;
      unsigned char *p;
      ptrdiff_t word_step;
      /* The current (partial) limb. */
      mp_limb_t limb;
      /* The number of bytes left to do in this limb. */
      size_t bytes;
      /* The index where the limb was read. */
      mp_size_t i;

      un = GMP_ABS (un);

      /* Count bytes in top limb. */
      limb = u->_mp_d[un-1];
      assert (limb != 0);

      k = (GMP_LIMB_BITS <= CHAR_BIT);
      if (!k)
	{
	  do {
	    int LOCAL_CHAR_BIT = CHAR_BIT;
	    k++; limb >>= LOCAL_CHAR_BIT;
	  } while (limb != 0);
	}
      /* else limb = 0; */

      count = (k + (un-1) * sizeof (mp_limb_t) + size - 1) / size;

      if (!r)
	r = gmp_xalloc (count * size);

      if (endian == 0)
	endian = gmp_detect_endian ();

      p = (unsigned char *) r;

      word_step = (order != endian) ? 2 * size : 0;

      /* Process bytes from the least significant end, so point p at the
	 least significant word. */
      if (order == 1)
	{
	  p += size * (count - 1);
	  word_step = - word_step;
	}

      /* And at least significant byte of that word. */
      if (endian == 1)
	p += (size - 1);

      for (bytes = 0, i = 0, k = 0; k < count; k++, p += word_step)
	{
	  size_t j;
	  for (j = 0; j < size; ++j, p -= (ptrdiff_t) endian)
	    {
	      if (sizeof (mp_limb_t) == 1)
		{
		  if (i < un)
		    *p = u->_mp_d[i++];
		  else
		    *p = 0;
		}
	      else
		{
		  int LOCAL_CHAR_BIT = CHAR_BIT;
		  if (bytes == 0)
		    {
		      if (i < un)
			limb = u->_mp_d[i++];
		      bytes = sizeof (mp_limb_t);
		    }
		  *p = limb;
		  limb >>= LOCAL_CHAR_BIT;
		  bytes--;
		}
	    }
	}
      assert (i == un);
      assert (k == count);
    }

  if (countp)
    *countp = count;

  return r;
}

#endif
