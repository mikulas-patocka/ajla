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

#ifndef AJLA_IPRET_H
#define AJLA_IPRET_H

#include "data.h"

#define run			name(run)
#define cg_upcall_vector	name(cg_upcall_vector)

/*#define DEBUG_UPCALL*/

#ifdef POINTER_COMPRESSION
#define pointer_t_upcall	uintptr_t
#define int_default_t_upcall	intptr_t
#else
#define pointer_t_upcall	pointer_t
#define int_default_t_upcall	int_default_t
#endif

void attr_fastcall run(frame_s *, ip_t);

struct cg_upcall_vector_s {
	atomic_type tick_stamp_t ts;
#ifdef HAVE_CODEGEN
	void (*mem_copy)(void *dest, const void *src, size_t size);
	void (*mem_clear)(void *ptr, size_t size);
	void (*cg_upcall_pointer_dereference)(pointer_t_upcall ptr);
	void (*cg_upcall_pointer_reference_owned)(pointer_t_upcall ptr);
	pointer_t (*cg_upcall_flat_to_data)(frame_s *fp, uintptr_t slot, const unsigned char *flat);
	unsigned char *(*cg_upcall_data_alloc_function_reference_mayfail)(uintptr_t n_curried_arguments);
	unsigned char *(*cg_upcall_data_alloc_record_mayfail)(const struct record_definition *def);
	unsigned char *(*cg_upcall_data_alloc_option_mayfail)(void);
	unsigned char *(*cg_upcall_data_alloc_array_flat_mayfail)(const struct type *t, int_default_t_upcall n_allocated, int_default_t_upcall n_used, bool clear);
	unsigned char *(*cg_upcall_data_alloc_array_pointers_mayfail)(int_default_t_upcall n_allocated, int_default_t_upcall n_used);
	pointer_t (*cg_upcall_array_create)(int_default_t_upcall length, const struct type *flat_type, const unsigned char *flat, pointer_t_upcall ptr);
	pointer_t (*cg_upcall_array_create_sparse)(int_default_t_upcall length, pointer_t_upcall ptr);
	pointer_t (*cg_upcall_array_sub)(pointer_t_upcall array, int_default_t_upcall start, int_default_t_upcall end, bool deref);
	pointer_t (*cg_upcall_array_skip)(pointer_t_upcall array, int_default_t_upcall start, bool deref);
	pointer_t (*cg_upcall_array_join)(pointer_t_upcall ptr1, pointer_t_upcall ptr2);
	void *(*cg_upcall_ipret_io)(frame_s *fp, const code_t *ip, uintptr_t code_params);
	pointer_t (*cg_upcall_ipret_copy_variable_to_pointer)(frame_s *src_fp, uintptr_t src_slot, bool deref);
	int_default_t (*ipret_system_property)(int_default_t_upcall idx);
	bool (*cat(FIXED_binary_add_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_subtract_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_binary_multiply_,s))(const u *v1, const u *v2, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_binary_divide_,s))(const u *v1, const u *v2, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_binary_udivide_,s))(const u *v1, const u *v2, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_binary_modulo_,s))(const u *v1, const u *v2, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_binary_umodulo_,s))(const u *v1, const u *v2, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_binary_power_,s))(const u *v1, const u *v2, u *r);
	for_all_fixed(f)
#undef f
	bool (*cat(FIXED_binary_shl_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_shr_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_ushr_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_rol_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_ror_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_bts_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_btr_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_btc_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, uintbig_t *r);
	bool (*cat(FIXED_binary_less_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, ajla_flat_option_t *r);
	bool (*cat(FIXED_binary_less_equal_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, ajla_flat_option_t *r);
	bool (*cat(FIXED_binary_uless_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, ajla_flat_option_t *r);
	bool (*cat(FIXED_binary_uless_equal_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, ajla_flat_option_t *r);
	bool (*cat(FIXED_binary_bt_,TYPE_INT_MAX))(const uintbig_t *v1, const uintbig_t *v2, ajla_flat_option_t *r);
	void (*cat(FIXED_unary_neg_,TYPE_INT_MAX))(const uintbig_t *v1, uintbig_t *r);
	void (*cat(FIXED_unary_inc_,TYPE_INT_MAX))(const uintbig_t *v1, uintbig_t *r);
	void (*cat(FIXED_unary_dec_,TYPE_INT_MAX))(const uintbig_t *v1, uintbig_t *r);
#define f(n, s, u, sz, bits) \
	void (*cat(FIXED_unary_bswap_,s))(const u *v1, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	void (*cat(FIXED_unary_brev_,s))(const u *v1, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	void (*cat(FIXED_unary_bsf_,s))(const u *v1, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	void (*cat(FIXED_unary_bsr_,s))(const u *v1, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	void (*cat(FIXED_unary_popcnt_,s))(const u *v1, u *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_uto_int_,s))(const u *v1, int_default_t *r);
	for_all_fixed(f)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(FIXED_ufrom_int_,s))(const int_default_t *v1, u *r);
	for_all_fixed(f)
#undef f
	bool (*cat(INT_binary_add_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, intbig_t *r);
	bool (*cat(INT_binary_subtract_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, intbig_t *r);
#define f(n, s, u, sz, bits) \
	bool (*cat(INT_binary_multiply_,s))(const s *v1, const s *v2, s *r);
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(INT_binary_divide_,s))(const s *v1, const s *v2, s *r);
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(INT_binary_modulo_,s))(const s *v1, const s *v2, s *r);
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(INT_binary_power_,s))(const s *v1, const s *v2, s *r);
	for_all_int(f, for_all_empty)
#undef f
	bool (*cat(INT_binary_shl_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, intbig_t *r);
	bool (*cat(INT_binary_shr_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, intbig_t *r);
	bool (*cat(INT_binary_bts_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, intbig_t *r);
	bool (*cat(INT_binary_btr_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, intbig_t *r);
	bool (*cat(INT_binary_btc_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, intbig_t *r);
	bool (*cat(INT_binary_bt_,TYPE_INT_MAX))(const intbig_t *v1, const intbig_t *v2, ajla_flat_option_t *r);
	bool (*cat(INT_unary_neg_,TYPE_INT_MAX))(const intbig_t *v1, intbig_t *r);
	bool (*cat(INT_unary_inc_,TYPE_INT_MAX))(const intbig_t *v1, intbig_t *r);
	bool (*cat(INT_unary_dec_,TYPE_INT_MAX))(const intbig_t *v1, intbig_t *r);
#define f(n, s, u, sz, bits) \
	bool (*cat(INT_unary_bsf_,s))(const s *v1, s *r);
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(INT_unary_bsr_,s))(const s *v1, s *r);
	for_all_int(f, for_all_empty)
#undef f
#define f(n, s, u, sz, bits) \
	bool (*cat(INT_unary_popcnt_,s))(const s *v1, s *r);
	for_all_int(f, for_all_empty)
#undef f
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_add_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_add_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_subtract_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_subtract_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_multiply_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_multiply_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_divide_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_divide_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_modulo_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_modulo_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_power_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_power_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_ldexp_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_ldexp_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_atan2_,t))(const t *v1, const t *v2, t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_atan2_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_equal_,t))(const t *v1, const t *v2, ajla_flat_option_t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_equal_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_not_equal_,t))(const t *v1, const t *v2, ajla_flat_option_t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_not_equal_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_less_,t))(const t *v1, const t *v2, ajla_flat_option_t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_less_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_binary_less_equal_,t))(const t *v1, const t *v2, ajla_flat_option_t *r);
#define nf(n, t) \
	void (*cat(REAL_binary_less_equal_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_neg_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_neg_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_sqrt_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_sqrt_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_cbrt_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_cbrt_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_sin_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_sin_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_cos_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_cos_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_tan_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_tan_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_asin_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_asin_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_acos_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_acos_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_atan_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_atan_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_sinh_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_sinh_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_cosh_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_cosh_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_tanh_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_tanh_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_asinh_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_asinh_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_acosh_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_acosh_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_atanh_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_atanh_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_exp2_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_exp2_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_exp_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_exp_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_exp10_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_exp10_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_log2_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_log2_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_log_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_log_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_log10_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_log10_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_round_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_round_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_ceil_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_ceil_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_floor_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_floor_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_trunc_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_trunc_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_fract_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_fract_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_mantissa_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_mantissa_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_exponent_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_exponent_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_next_number_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_next_number_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_prev_number_,t))(const t *v1, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_prev_number_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	bool (*cat(REAL_unary_to_int_,t))(const t *val, int_default_t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_to_int_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_from_int_,t))(const int_default_t *val, t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_from_int_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#define f(n, t, nt, pack, unpack) \
	void (*cat(REAL_unary_is_exception_,t))(const t *v1, ajla_flat_option_t *r);
#define nf(n, t) \
	void (*cat(REAL_unary_is_exception_,t))(void);
	for_all_real(f, nf)
#undef f
#undef nf
#endif
#ifdef DEBUG_UPCALL
	void (*cg_upcall_debug)(unsigned long x1, unsigned long x2, unsigned long x3, unsigned long x4);
#endif
};

#undef nf

extern struct cg_upcall_vector_s cg_upcall_vector;

#define tick_stamp	(cg_upcall_vector.ts)

#endif
