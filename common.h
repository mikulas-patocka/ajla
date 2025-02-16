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

#define cat_(a, b)		a##b
#define cat(a, b)		cat_(a, b)
#define cat3(a, b, c)		cat(a, cat(b, c))
#define cat4(a, b, c, d)	cat(a, cat(b, cat(c, d)))
#define cat5(a, b, c, d, e)	cat(a, cat(b, cat(c, cat(d, e))))
#define cat6(a, b, c, d, e, f)	cat(a, cat(b, cat(c, cat(d, cat(e, f)))))
#define cat7(a, b, c, d, e, f, g) cat(a, cat(b, cat(c, cat(d, cat(e, cat(f, g))))))

#define n_array_elements(a)	(sizeof(a) / sizeof(a[0]))

#ifndef __GNUC__
static const int zero = 0;
#else
static inline int zero_(void)
{
	return 0;
}
#define zero	(zero_())
#endif
#define uzero	((unsigned)zero)

#define round_down(x, y)	((x) & ~((y) - 1 + 0 * (x)))
#define round_up(x, y)		(((x) + (y) - 1) & ~((y) - 1 + 0 * (x)))

#define minimum(x, y)		((x) < (y) ? (x) : (y))
#define maximum(x, y)		((x) >= (y) ? (x) : (y))
#define maximum_maybe0(x, y)	((x) >= (y) + zero ? (x) : (y))

#define sign_bit(type)		((type)(-((type)1 << (8 * sizeof(type) - 2)) * 2))
#define signed_maximum(type)	(~sign_bit(type))
#define is_unsigned(type)	((type)-1 >= 1)

#define is_power_of_2(x)	((x) && !((x) & ((x) - 1)))

static const size_t attr_unused size_t_limit = (size_t)-1;	/* use const to avoid warning */

#ifndef DEBUG
#define ajla_assert(x, msg)	((void)zero)
#else
#define ajla_assert(x, msg)	(likely(x) ? (void)0 : internal msg)
#endif

#ifndef DEBUG_LOW_OVERHEAD
#define ajla_assert_lo(x, msg)	((void)zero)
#else
#define ajla_assert_lo(x, msg)	(likely(x) ? (void)0 : internal msg)
#endif

#define for_all_fixed0x_(macro)
#define for_all_fixed1x_(macro)	for_all_fixed0x_(macro) macro(0, int8_t, uint8_t, 1, 8)
#define for_all_fixed2x_(macro)	for_all_fixed1x_(macro) macro(1, int16_t, uint16_t, 2, 16)
#define for_all_fixed3x_(macro)	for_all_fixed2x_(macro) macro(2, int32_t, uint32_t, 4, 32)
#define for_all_fixed4x_(macro)	for_all_fixed3x_(macro) macro(3, int64_t, uint64_t, 8, 64)
#define for_all_fixed5x_(macro)	for_all_fixed4x_(macro) macro(4, int128_t, uint128_t, 16, 128)
#define for_all_fixed(macro)	cat3(for_all_fixed,TYPE_FIXED_N,x_)(macro)

#define for_all_empty(n, t)

#if INT_MASK & 0x1
#define for_all_int1x_(m, mn)	m(0, int8_t, uint8_t, 1, 8)
#else
#define for_all_int1x_(m, mn)	mn(0, int8_t)
#endif
#if INT_MASK & 0x2
#define for_all_int2x_(m, mn)	for_all_int1x_(m, mn) m(1, int16_t, uint16_t, 2, 16)
#else
#define for_all_int2x_(m, mn)	for_all_int1x_(m, mn) mn(1, int16_t)
#endif
#if INT_MASK & 0x4
#define for_all_int3x_(m, mn)	for_all_int2x_(m, mn) m(2, int32_t, uint32_t, 4, 32)
#else
#define for_all_int3x_(m, mn)	for_all_int2x_(m, mn) mn(2, int32_t)
#endif
#if INT_MASK & 0x8
#define for_all_int4x_(m, mn)	for_all_int3x_(m, mn) m(3, int64_t, uint64_t, 8, 64)
#else
#define for_all_int4x_(m, mn)	for_all_int3x_(m, mn) mn(3, int64_t)
#endif
#if INT_MASK & 0x10
#define for_all_int5x_(m, mn)	for_all_int4x_(m, mn) m(4, int128_t, uint128_t, 16, 128)
#else
#define for_all_int5x_(m, mn)	for_all_int4x_(m, mn) mn(4, int128_t)
#endif
#define for_all_int(m, mn)	cat3(for_all_int,TYPE_INT_N,x_)(m, mn)

#define for_all_real0x_(m, mn)
#if REAL_MASK & 0x1
#define for_all_real1x_(m, mn)		for_all_real0x_(m, mn)		m(0, real16_t, native_real16_t, pack_real16_t, unpack_real16_t)
#else
#define for_all_real1x_(m, mn)		for_all_real0x_(m, mn)		mn(0, real16_t)
#endif
#if REAL_MASK & 0x2
#define for_all_real2x_(m, mn)		for_all_real1x_(m, mn)		m(1, real32_t, native_real32_t, pack_real32_t, unpack_real32_t)
#else
#define for_all_real2x_(m, mn)		for_all_real1x_(m, mn)		mn(1, real32_t)
#endif
#if REAL_MASK & 0x4
#define for_all_real3x_(m, mn)		for_all_real2x_(m, mn)		m(2, real64_t, native_real64_t, pack_real64_t, unpack_real64_t)
#else
#define for_all_real3x_(m, mn)		for_all_real2x_(m, mn)		mn(2, real64_t)
#endif
#if REAL_MASK & 0x8
#define for_all_real4x_(m, mn)		for_all_real3x_(m, mn)		m(3, real80_t, native_real80_t, pack_real80_t, unpack_real80_t)
#else
#define for_all_real4x_(m, mn)		for_all_real3x_(m, mn)		mn(3, real80_t)
#endif
#if REAL_MASK & 0x10
#define for_all_real5x_(m, mn)		for_all_real4x_(m, mn)		m(4, real128_t, native_real128_t, pack_real128_t, unpack_real128_t)
#else
#define for_all_real5x_(m, mn)		for_all_real4x_(m, mn)		mn(4, real128_t)
#endif
#define for_all_real(m, mn)		cat3(for_all_real,TYPE_REAL_N,x_)(m, mn)


static inline unsigned low_bit(unsigned x)
{
#if defined(HAVE_STDBIT_H)
	return stdc_trailing_zeros_ui(x);
#elif defined(HAVE_BUILTIN_CTZ)
	return __builtin_ctz(x);
#elif defined(HAVE_FFS)
	return ffs(x) - 1;
#else
	unsigned ret = 0;
	while (1) {
		if (x & 1)
			break;
		x >>= 1;
		ret++;
	}
	return ret;
#endif
}

static inline unsigned high_bit(unsigned x)
{
#if defined(HAVE_STDBIT_H)
	return sizeof(unsigned) * 8 - 1 - stdc_leading_zeros_ui(x);
#elif defined(HAVE_BUILTIN_CLZ)
	return sizeof(unsigned) * 8 - 1 - __builtin_clz(x);
#elif defined(HAVE_FLS)
	return fls(x) - 1;
#else
	unsigned ret = (unsigned)-1;
	do {
		ret++;
		x >>= 1;
	} while (x);
	return ret;
#endif
}

static inline unsigned log_2(unsigned x)
{
	ajla_assert(is_power_of_2(x), (file_line, "log_2: value %u is not a power of 2", x));
	return low_bit(x);
}

static inline int pop_count(unsigned x)
{
#if defined(HAVE_STDBIT_H)
	return stdc_count_ones_ui(x);
#elif defined(HAVE_BUILTIN_POPCOUNT)
	return __builtin_popcount(x);
#else
	int ret = 0;
	while (x)
		x &= x - 1, ret++;
	return ret;
#endif
}

#if 1
#define assert_alignment(ptr, align)	\
	(ajla_assert(is_power_of_2(align), (file_line, "assert_alignment: value %" PRIuMAX " is not a power of 2", (uintmax_t)(align))),\
	 ajla_assert(!((uintptr_t)(ptr) & ((align) - 1)), (file_line, "assert_alignment: pointer %p is not aligned on %" PRIuMAX "", (void *)(ptr), (uintmax_t)(align))),\
	 __builtin_assume_aligned(ptr, align))
#else
#define assert_alignment(ptr, align)	(__builtin_assume_aligned(ptr, align))
#endif

#define get_struct_(ptr, str, entry)	(cast_ptr(str *, (cast_ptr(char *, (ptr)) - offsetof(str, entry))))
#define get_struct(ptr, str, entry)	((void)sizeof(&get_struct_(ptr, str, entry)->entry == (ptr)), get_struct_(ptr, str, entry))

static inline uintptr_t ptr_to_num(const void *ptr)
{
	return (uintptr_t)ptr;
}

static inline void *num_to_ptr(uintptr_t num)
{
	return (void *)num;
}

#define binary_search(t, n, result, equal, less, not_found)		\
do {									\
	t start_ = 0;							\
	t end_ = (n);							\
	while (1) {							\
		t diff_ = end_ - start_;				\
		if (unlikely(!diff_)) {					\
			(result) = start_;				\
			not_found;					\
			not_reached();					\
		}							\
		(result) = start_ + (diff_ >> 1);			\
		if (unlikely(equal)) {					\
			break;						\
		}							\
		if (less) {						\
			start_ = (result) + 1;				\
		} else {						\
			end_ = (result);				\
		}							\
	}								\
} while (0)
