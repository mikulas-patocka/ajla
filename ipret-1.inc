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

#if ARG_MODE == 0
#define get_param(ip, n)	(!((n) & 1) ? get_lo((ip) + (n) / 2) : get_hi((ip) + (n) / 2))
#define param_size(n)		(((n) + 1) / 2)
#elif ARG_MODE == 1
/* A cast to uintptr_t because of gcc optimizer inefficiency */
#define get_param(ip, n)	((uintptr_t)(ip)[n])
#define param_size(n)		(n)
#elif ARG_MODE == 2
#define get_param(ip, n)	get_unaligned_32(&(ip)[(n) * 2])
#define param_size(n)		((n) * 2)
#endif

#define get_i_param(n)		get_param(ip + 1, n)
#define ADVANCE_I_PARAM(n)	ADVANCE_IP(1 + param_size(n))


#ifdef EMIT_FUNCTIONS
static const code_t attr_cold *cat(free_parameters_,ARG_MODE)(frame_s *fp, const code_t *ip, frame_t n_entries)
{
	while (n_entries--) {
		if (get_param(ip, 1) & OPCODE_FLAG_FREE_ARGUMENT)
			frame_free_and_clear(fp, get_param(ip, 0));
		ADVANCE_IP(param_size(2));
	}
	return ip;
}
#endif


#define move_scalar(utype)						\
do {									\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "scalar move: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	barrier_aliasing();						\
	if (unlikely(frame_test_and_clear_flag(fp, slot_1))) {		\
		frame_set_pointer(fp, slot_r, *frame_pointer(fp, slot_1));\
		pointer_poison(frame_pointer(fp, slot_1));		\
	} else {							\
		*frame_slot(fp, slot_r, utype) =			\
		*frame_slot(fp, slot_1, utype);				\
	}								\
	barrier_aliasing();						\
	ADVANCE_I_PARAM(2);						\
} while (0)

#define copy_scalar(utype)						\
do {									\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "scalar copy: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	barrier_aliasing();						\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		pointer_t ptr = *frame_pointer(fp, slot_1);		\
		frame_set_pointer(fp, slot_r, ptr);			\
		pointer_reference_owned(ptr);				\
	} else {							\
		*frame_slot(fp, slot_r, utype) =			\
		*frame_slot(fp, slot_1, utype);				\
	}								\
	barrier_aliasing();						\
	ADVANCE_I_PARAM(2);						\
} while (0)


#define DEFINE_FIXED_REAL_BINARY_OPCODE(tc, type, op)			\
DEFINE_OPCODE(								\
		cat3(OPCODE_,tc,OP) +					\
		cat4(OPCODE_,tc,OP_,op) * cat3(OPCODE_,tc,OP_MULT) +	\
		cat4(OPCODE_,tc,TYPE_,type) * cat3(OPCODE_,tc,TYPE_MULT),\
		cat7(tc,binary_,op,_,type,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_2 = get_i_param(1);				\
	frame_t slot_r = get_i_param(2);				\
	ajla_assert(slot_r == slot_1 || slot_r == slot_2 || !frame_test_flag(fp, slot_r), (file_line, "fixed binary: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	if (unlikely(frame_test_2(fp, slot_1, slot_2))) {		\
		goto cat(escape_fixed_binary_thunk_,ARG_MODE);		\
	} else {							\
		const void *val1;					\
		const void *val2;					\
		void *result;						\
		val1 = frame_var(fp, slot_1);				\
		val2 = frame_var(fp, slot_2);				\
		result = frame_var(fp, slot_r);				\
		barrier_aliasing();					\
		if (unlikely(!cat5(tc,binary_,op,_,type)(val1, val2, result))) {\
			barrier_aliasing();				\
			goto cat(escape_fixed_binary_thunk_,ARG_MODE);	\
		}							\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(4);					\
	}								\
)

#define DEFINE_FIXED_REAL_UNARY_OPCODE(tc, type, op)			\
DEFINE_OPCODE(								\
		cat3(OPCODE_,tc,OP) +					\
		cat4(OPCODE_,tc,OP_,op) * cat3(OPCODE_,tc,OP_MULT) +	\
		cat4(OPCODE_,tc,TYPE_,type) * cat3(OPCODE_,tc,TYPE_MULT),\
		cat7(tc,unary_,op,_,type,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	ajla_assert(slot_r == slot_1 || !frame_test_flag(fp, slot_r), (file_line, "fixed unary: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_fixed_unary_thunk_,ARG_MODE);		\
	} else {							\
		const void *val1;					\
		void *result;						\
		val1 = frame_var(fp, slot_1);				\
		result = frame_var(fp, slot_r);				\
		barrier_aliasing();					\
		cat5(tc,unary_,op,_,type)(val1, result);		\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_FIXED_TO_INT(type, utype)				\
DEFINE_OPCODE(								\
		OPCODE_FIXED_OP +					\
		OPCODE_FIXED_OP_to_int * OPCODE_FIXED_OP_MULT +		\
		cat(OPCODE_FIXED_TYPE_,type) * OPCODE_FIXED_TYPE_MULT,	\
		cat4(FIXED_unary_to_int_,type,_,ARG_MODE),		\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		type val1;						\
		int_default_t r;					\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, type);			\
		r = (int_default_t)val1;				\
		if (unlikely(r != val1))				\
			frame_set_pointer(fp, slot_r, convert_fixed_to_mpint(val1, false));\
		else							\
			*frame_slot(fp, slot_r, int_default_t) = r;	\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_FIXED_UTO_INT(type, utype)				\
DEFINE_OPCODE(								\
		OPCODE_FIXED_OP +					\
		OPCODE_FIXED_OP_uto_int * OPCODE_FIXED_OP_MULT +	\
		cat(OPCODE_FIXED_TYPE_,type) * OPCODE_FIXED_TYPE_MULT,	\
		cat4(FIXED_unary_uto_int_,type,_,ARG_MODE),		\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		utype val1;						\
		int_default_t r;					\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, utype);			\
		r = (int_default_t)val1;				\
		if (unlikely((utype)r != val1) || unlikely(r < 0))	\
			frame_set_pointer(fp, slot_r, convert_fixed_to_mpint(val1, true));\
		else							\
			*frame_slot(fp, slot_r, int_default_t) = r;	\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_FIXED_FROM_INT(type, utype)				\
DEFINE_OPCODE(								\
		OPCODE_FIXED_OP +					\
		OPCODE_FIXED_OP_from_int * OPCODE_FIXED_OP_MULT +	\
		cat(OPCODE_FIXED_TYPE_,type) * OPCODE_FIXED_TYPE_MULT,	\
		cat4(FIXED_unary_from_int_,type,_,ARG_MODE),		\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		int_default_t val1;					\
		type r;							\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, int_default_t);		\
		r = (type)val1;						\
		if (unlikely(r != val1))				\
			frame_set_pointer(fp, slot_r, pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT), fp, ip pass_file_line));\
		else							\
			*frame_slot(fp, slot_r, type) = r;		\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_FIXED_UFROM_INT(type, utype)				\
DEFINE_OPCODE(								\
		OPCODE_FIXED_OP +					\
		OPCODE_FIXED_OP_ufrom_int * OPCODE_FIXED_OP_MULT +	\
		cat(OPCODE_FIXED_TYPE_,type) * OPCODE_FIXED_TYPE_MULT,	\
		cat4(FIXED_unary_ufrom_int_,type,_,ARG_MODE),		\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		int_default_t val1;					\
		utype r;						\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, int_default_t);		\
		r = (utype)val1;					\
		if (unlikely((int_default_t)r != val1) || unlikely(val1 < 0))\
			frame_set_pointer(fp, slot_r, pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT), fp, ip pass_file_line));\
		else							\
			*frame_slot(fp, slot_r, type) = r;		\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_SCALAR_MOVE_OPCODE(tc, type)				\
DEFINE_OPCODE(								\
		cat3(OPCODE_,tc,OP) +					\
		cat3(OPCODE_,tc,OP_move) * cat3(OPCODE_,tc,OP_MULT) +	\
		cat4(OPCODE_,tc,TYPE_,type) * cat3(OPCODE_,tc,TYPE_MULT),\
		cat5(tc,move_,type,_,ARG_MODE),				\
	move_scalar(type);						\
)

#define DEFINE_SCALAR_COPY_OPCODE(tc, type)				\
DEFINE_OPCODE(								\
		cat3(OPCODE_,tc,OP) +					\
		cat3(OPCODE_,tc,OP_copy) * cat3(OPCODE_,tc,OP_MULT) +	\
		cat4(OPCODE_,tc,TYPE_,type) * cat3(OPCODE_,tc,TYPE_MULT),\
		cat5(tc,copy_,type,_,ARG_MODE),				\
	copy_scalar(type);						\
)

#define DEFINE_FIXED_LDC_OPCODE(cls, type, utype, opc, shrt)		\
DEFINE_OPCODE(								\
		OPCODE_##cls##_OP +					\
		OPCODE_##cls##_OP_##opc * OPCODE_##cls##_OP_MULT +	\
		cat(OPCODE_##cls##_TYPE_,type) * OPCODE_##cls##_TYPE_MULT,\
		cat6(fixed_,opc,_,type,_,ARG_MODE),			\
	frame_t slot;							\
	utype *val;							\
	ip_t sz;							\
	slot = get_i_param(0);						\
	ajla_assert(!frame_test_flag(fp, slot), (file_line, "ldc fixed: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot));\
	val = frame_slot(fp, slot, utype);				\
	barrier_aliasing();						\
	sz = cat(fixed_ldc_,type)(val, ip + 1 + param_size(1), shrt);	\
	barrier_aliasing();						\
	ADVANCE_I_PARAM(1);						\
	ADVANCE_IP(sz);							\
)

#define DEFINE_FIXED_OPCODES(n, type, utype, sz, bits)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, add)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, subtract)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, multiply)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, divide)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, udivide)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, modulo)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, umodulo)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, power)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, and)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, or)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, xor)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, shl)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, shr)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, ushr)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, rol)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, ror)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, bts)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, btr)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, btc)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, equal)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, not_equal)\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, less)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, less_equal)\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, uless)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, uless_equal)\
DEFINE_FIXED_REAL_BINARY_OPCODE(FIXED_, type, bt)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, not)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, neg)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, inc)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, dec)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, bswap)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, brev)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, bsf)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, bsr)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(FIXED_, type, popcnt)	\
DEFINE_FIXED_TO_INT(type, utype)			\
DEFINE_FIXED_UTO_INT(type, utype)			\
DEFINE_FIXED_FROM_INT(type, utype)			\
DEFINE_FIXED_UFROM_INT(type, utype)			\
DEFINE_SCALAR_MOVE_OPCODE(FIXED_, type)			\
DEFINE_SCALAR_COPY_OPCODE(FIXED_, type)			\
DEFINE_FIXED_LDC_OPCODE(FIXED, type, utype, ldc, false)

for_all_fixed(DEFINE_FIXED_OPCODES)

#if TYPE_FIXED_N >= 3
DEFINE_FIXED_LDC_OPCODE(FIXED, int32_t, uint32_t, ldc16, true)
#if TYPE_FIXED_N >= 4
DEFINE_FIXED_LDC_OPCODE(FIXED, int64_t, uint64_t, ldc16, true)
#if TYPE_FIXED_N >= 5
DEFINE_FIXED_LDC_OPCODE(FIXED, int128_t, uint128_t, ldc16, true)
#endif
#endif
#endif


#define DEFINE_REAL_TO_INT(type, op)					\
DEFINE_OPCODE(								\
		OPCODE_REAL_OP +					\
		cat(OPCODE_REAL_OP_,op) * OPCODE_REAL_OP_MULT +		\
		cat(OPCODE_REAL_TYPE_,type) * OPCODE_REAL_TYPE_MULT,	\
		cat6(REAL_unary_,op,_,type,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		bool ret;						\
		barrier_aliasing();					\
		ret = cat4(REAL_unary_,op,_,type)(frame_slot(fp, slot_1, type), frame_slot(fp, slot_r, int_default_t));\
		barrier_aliasing();					\
		if (unlikely(!ret))					\
			frame_set_pointer(fp, slot_r, convert_real_to_mpint(fp, slot_1, frame_get_type_of_local(fp, slot_1)));\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_REAL_FROM_INT(type, op)					\
DEFINE_OPCODE(								\
		OPCODE_REAL_OP +					\
		cat(OPCODE_REAL_OP_,op) * OPCODE_REAL_OP_MULT +		\
		cat(OPCODE_REAL_TYPE_,type) * OPCODE_REAL_TYPE_MULT,	\
		cat6(REAL_unary_,op,_,type,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		barrier_aliasing();					\
		cat4(REAL_unary_,op,_,type)(frame_slot(fp, slot_1, int_default_t), frame_slot(fp, slot_r, type));\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)


#define DEFINE_REAL_OPCODES(n, type, ntype, pack, unpack)\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, add)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, subtract)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, multiply)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, divide)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, modulo)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, power)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, ldexp)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, atan2)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, equal)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, not_equal)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, less)	\
DEFINE_FIXED_REAL_BINARY_OPCODE(REAL_, type, less_equal)\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, neg)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, sqrt)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, cbrt)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, sin)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, cos)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, tan)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, asin)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, acos)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, atan)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, sinh)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, cosh)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, tanh)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, asinh)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, acosh)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, atanh)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, exp2)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, exp)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, exp10)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, log2)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, log)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, log10)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, round)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, ceil)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, floor)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, trunc)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, fract)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, mantissa)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, exponent)	\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, next_number)\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, prev_number)\
DEFINE_REAL_TO_INT(type, to_int)			\
DEFINE_REAL_FROM_INT(type, from_int)			\
DEFINE_FIXED_REAL_UNARY_OPCODE(REAL_, type, is_exception)\
DEFINE_SCALAR_MOVE_OPCODE(REAL_, type)			\
DEFINE_SCALAR_COPY_OPCODE(REAL_, type)			\
DEFINE_FIXED_LDC_OPCODE(REAL, type, type, ldc, false)

for_all_real(DEFINE_REAL_OPCODES, for_all_empty)


DEFINE_LABEL(cat(escape_fixed_binary_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_fixed_operator(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), get_i_param(3));
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(4);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
)


DEFINE_LABEL(cat(escape_fixed_unary_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_fixed_operator(fp, ip, get_i_param(0), NO_FRAME_T, get_i_param(1), get_i_param(2));
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
)


DEFINE_LABEL(cat(escape_convert_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_convert(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2));
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
)


START_BLOCK(
	bool (attr_fastcall *function_int_binary)(const mpint_t *s1, const mpint_t *s2, mpint_t *r, ajla_error_t *err);
	bool (attr_fastcall *function_int_binary_logical)(const mpint_t *s1, const mpint_t *s2, ajla_flat_option_t *r, ajla_error_t *err);
	bool (attr_fastcall *function_int_unary)(const mpint_t *s1, mpint_t *r, ajla_error_t *err);
)

#define DEFINE_INT_BINARY_OPCODE(type, op)				\
DEFINE_OPCODE(								\
		OPCODE_INT_OP +						\
		cat(OPCODE_INT_OP_,op) * OPCODE_INT_OP_MULT +		\
		cat(OPCODE_INT_TYPE_,type) * OPCODE_INT_TYPE_MULT,	\
		cat6(int_binary_,op,_,type,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_2 = get_i_param(1);				\
	frame_t slot_r = get_i_param(2);				\
	ajla_assert(slot_r == slot_1 || slot_r == slot_2 || !frame_test_flag(fp, slot_r), (file_line, "int binary: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	if (unlikely(frame_test_2(fp, slot_1, slot_2))) {		\
cat6(escape_int_binary_,op,_,type,_,ARG_MODE):				\
		function_int_binary = cat(mpint_,op);			\
		goto cat(escape_int_binary_thunk_,ARG_MODE);		\
	} else {							\
		const void *val1;					\
		const void *val2;					\
		void *result;						\
		val1 = frame_var(fp, slot_1);				\
		val2 = frame_var(fp, slot_2);				\
		result = frame_var(fp, slot_r);				\
		barrier_aliasing();					\
		if (unlikely(!cat4(INT_binary_,op,_,type)(val1, val2, result))) {\
			barrier_aliasing();				\
			goto cat6(escape_int_binary_,op,_,type,_,ARG_MODE);\
		}							\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(4);					\
	}								\
)

#define DEFINE_INT_BINARY_LOGICAL_OPCODE(type, op)			\
DEFINE_OPCODE(								\
		OPCODE_INT_OP +						\
		cat(OPCODE_INT_OP_,op) * OPCODE_INT_OP_MULT +		\
		cat(OPCODE_INT_TYPE_,type) * OPCODE_INT_TYPE_MULT,	\
		cat6(int_binary_,op,_,type,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_2 = get_i_param(1);				\
	frame_t slot_r = get_i_param(2);				\
	ajla_assert(slot_r == slot_1 || slot_r == slot_2 || !frame_test_flag(fp, slot_r), (file_line, "int logical: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	if (unlikely(frame_test_2(fp, slot_1, slot_2))) {		\
cat6(escape_int_binary_logical_,op,_,type,_,ARG_MODE):			\
		function_int_binary_logical = cat(mpint_,op);		\
		goto cat(escape_int_binary_logical_thunk_,ARG_MODE);	\
	} else {							\
		const void *val1;					\
		const void *val2;					\
		void *result;						\
		val1 = frame_var(fp, slot_1);				\
		val2 = frame_var(fp, slot_2);				\
		result = frame_var(fp, slot_r);				\
		barrier_aliasing();					\
		if (unlikely(!cat4(INT_binary_,op,_,type)(val1, val2, result))) {\
			barrier_aliasing();				\
			goto cat6(escape_int_binary_logical_,op,_,type,_,ARG_MODE);\
		}							\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(4);					\
	}								\
)

#define DEFINE_INT_UNARY_OPCODE(type, op)				\
DEFINE_OPCODE(								\
		OPCODE_INT_OP +						\
		cat(OPCODE_INT_OP_,op) * OPCODE_INT_OP_MULT +		\
		cat(OPCODE_INT_TYPE_,type) * OPCODE_INT_TYPE_MULT,	\
		cat6(int_binary_,op,_,type,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	ajla_assert(slot_r == slot_1 || !frame_test_flag(fp, slot_r), (file_line, "int unary: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
cat6(escape_int_unary_,op,_,type,_,ARG_MODE):				\
		function_int_unary = cat(mpint_,op);			\
		goto cat(escape_int_unary_thunk_,ARG_MODE);		\
	} else {							\
		const void *val1;					\
		void *result;						\
		val1 = frame_var(fp, slot_1);				\
		result = frame_var(fp, slot_r);				\
		barrier_aliasing();					\
		if (unlikely(!cat4(INT_unary_,op,_,type)(val1, result))) {\
			barrier_aliasing();				\
			goto cat6(escape_int_unary_,op,_,type,_,ARG_MODE);\
		}							\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_INT_TO_INT(type)						\
DEFINE_OPCODE(								\
		OPCODE_INT_OP +						\
		OPCODE_INT_OP_to_int * OPCODE_INT_OP_MULT +		\
		cat(OPCODE_INT_TYPE_,type) * OPCODE_INT_TYPE_MULT,	\
		cat4(INT_unary_to_int_,type,_,ARG_MODE),		\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		type val1;						\
		int_default_t r;					\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, type);			\
		r = (int_default_t)val1;				\
		if (unlikely(r != val1))				\
			frame_set_pointer(fp, slot_r, convert_fixed_to_mpint(val1, false));\
		else							\
			*frame_slot(fp, slot_r, int_default_t) = r;	\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_INT_FROM_INT(typeid, type)				\
DEFINE_OPCODE(								\
		OPCODE_INT_OP +						\
		OPCODE_INT_OP_from_int * OPCODE_INT_OP_MULT +		\
		cat(OPCODE_INT_TYPE_,type) * OPCODE_INT_TYPE_MULT,	\
		cat4(INT_unary_from_int_,type,_,ARG_MODE),		\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_convert_thunk_,ARG_MODE);		\
	} else {							\
		int_default_t val1;					\
		type r;							\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, int_default_t);		\
		r = (type)val1;						\
		if (unlikely(r != val1))				\
			frame_set_pointer(fp, slot_r, convert_fixed_to_mpint(val1, false));\
		else							\
			*frame_slot(fp, slot_r, type) = r;		\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

#define DEFINE_INT_LDC_OPCODE(type, opc, shrt)				\
DEFINE_OPCODE(								\
		OPCODE_INT_OP +						\
		OPCODE_INT_OP_##opc * OPCODE_INT_OP_MULT +		\
		cat(OPCODE_INT_TYPE_,type) * OPCODE_INT_TYPE_MULT,	\
		cat6(int_,opc,_,type,_,ARG_MODE),			\
	frame_t slot;							\
	type *val;							\
	ip_t sz;							\
	slot = get_i_param(0);						\
	ajla_assert(!frame_test_flag(fp, slot), (file_line, "ldc int: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot));\
	val = frame_slot(fp, slot, type);				\
	barrier_aliasing();						\
	sz = cat(int_ldc_,type)(val, ip + 1 + param_size(1), shrt);	\
	barrier_aliasing();						\
	ADVANCE_I_PARAM(1);						\
	ADVANCE_IP(sz);							\
)

#define DEFINE_INT_OPCODES(typeid, s, u, sz, bits)	\
DEFINE_INT_BINARY_OPCODE(s, add)			\
DEFINE_INT_BINARY_OPCODE(s, subtract)			\
DEFINE_INT_BINARY_OPCODE(s, multiply)			\
DEFINE_INT_BINARY_OPCODE(s, divide)			\
DEFINE_INT_BINARY_OPCODE(s, modulo)			\
DEFINE_INT_BINARY_OPCODE(s, power)			\
DEFINE_INT_BINARY_OPCODE(s, and)			\
DEFINE_INT_BINARY_OPCODE(s, or)				\
DEFINE_INT_BINARY_OPCODE(s, xor)			\
DEFINE_INT_BINARY_OPCODE(s, shl)			\
DEFINE_INT_BINARY_OPCODE(s, shr)			\
DEFINE_INT_BINARY_OPCODE(s, bts)			\
DEFINE_INT_BINARY_OPCODE(s, btr)			\
DEFINE_INT_BINARY_OPCODE(s, btc)			\
DEFINE_INT_BINARY_LOGICAL_OPCODE(s, equal)		\
DEFINE_INT_BINARY_LOGICAL_OPCODE(s, not_equal)		\
DEFINE_INT_BINARY_LOGICAL_OPCODE(s, less)		\
DEFINE_INT_BINARY_LOGICAL_OPCODE(s, less_equal)		\
DEFINE_INT_BINARY_LOGICAL_OPCODE(s, bt)			\
DEFINE_INT_UNARY_OPCODE(s, not)				\
DEFINE_INT_UNARY_OPCODE(s, neg)				\
DEFINE_INT_UNARY_OPCODE(s, inc)				\
DEFINE_INT_UNARY_OPCODE(s, dec)				\
DEFINE_INT_UNARY_OPCODE(s, bsf)				\
DEFINE_INT_UNARY_OPCODE(s, bsr)				\
DEFINE_INT_UNARY_OPCODE(s, popcnt)			\
DEFINE_INT_TO_INT(s)					\
DEFINE_INT_FROM_INT(typeid, s)				\
DEFINE_SCALAR_MOVE_OPCODE(INT_, s)			\
DEFINE_SCALAR_COPY_OPCODE(INT_, s)			\
DEFINE_INT_LDC_OPCODE(s, ldc, false)			\
DEFINE_INT_LDC_OPCODE(s, ldc16, true)

for_all_int(DEFINE_INT_OPCODES, for_all_empty)

DEFINE_LABEL(cat(escape_int_binary_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_int_binary_operator(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), get_i_param(3), function_int_binary);
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(4);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
)

DEFINE_LABEL(cat(escape_int_binary_logical_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_int_binary_logical_operator(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), get_i_param(3), function_int_binary_logical);
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(4);
	else if (ex != POINTER_FOLLOW_THUNK_RETRY)
		RELOAD_EX_POSITION(ex);
)

DEFINE_LABEL(cat(escape_int_unary_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_int_unary_operator(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), function_int_unary);
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
)

#define file_inc "ipret-a1.inc"
#include "for-fix.inc"

#define file_inc "ipret-a2.inc"
#include "for-int.inc"

#define file_inc "ipret-a3.inc"
#include "for-real.inc"

END_BLOCK()


#define DEFINE_BOOL_BINARY_OPCODE(op, operator)				\
DEFINE_OPCODE(								\
		OPCODE_BOOL_OP +					\
		cat(OPCODE_BOOL_OP_,op) * OPCODE_BOOL_OP_MULT,		\
		cat4(bool_binary_,op,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_2 = get_i_param(1);				\
	frame_t slot_r = get_i_param(2);				\
									\
	if (unlikely(frame_test_2(fp, slot_1, slot_2))) {		\
	ajla_assert(slot_r == slot_1 || slot_r == slot_2 || !frame_test_flag(fp, slot_r), (file_line, "bool binary: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
		goto cat(escape_bool_binary_thunk_,ARG_MODE);		\
	} else {							\
		ajla_flat_option_t val1;				\
		ajla_flat_option_t val2;				\
		ajla_flat_option_t result;				\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, ajla_flat_option_t);	\
		val2 = *frame_slot(fp, slot_2, ajla_flat_option_t);	\
		result = val1 operator val2;				\
		*frame_slot(fp, slot_r, ajla_flat_option_t) = result;	\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(4);					\
	}								\
)

#define DEFINE_BOOL_UNARY_OPCODE(op, operator)				\
DEFINE_OPCODE(								\
		OPCODE_BOOL_OP +					\
		cat(OPCODE_BOOL_OP_,op) * OPCODE_BOOL_OP_MULT,		\
		cat4(bool_unary_,op,_,ARG_MODE),			\
	frame_t slot_1 = get_i_param(0);				\
	frame_t slot_r = get_i_param(1);				\
									\
	ajla_assert(slot_r == slot_1 || !frame_test_flag(fp, slot_r), (file_line, "bool unary: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));\
	if (unlikely(frame_test_flag(fp, slot_1))) {			\
		goto cat(escape_bool_unary_thunk_,ARG_MODE);		\
	} else {							\
		ajla_flat_option_t val1;				\
		ajla_flat_option_t result;				\
		barrier_aliasing();					\
		val1 = *frame_slot(fp, slot_1, ajla_flat_option_t);	\
		result = val1 operator;					\
		*frame_slot(fp, slot_r, ajla_flat_option_t) = result;	\
		barrier_aliasing();					\
		ADVANCE_I_PARAM(3);					\
	}								\
)

DEFINE_BOOL_BINARY_OPCODE(and, &)
DEFINE_BOOL_BINARY_OPCODE(or, |)
DEFINE_BOOL_BINARY_OPCODE(equal, ==)
DEFINE_BOOL_BINARY_OPCODE(not_equal, ^)
DEFINE_BOOL_BINARY_OPCODE(less, <)
DEFINE_BOOL_BINARY_OPCODE(less_equal, <=)
DEFINE_BOOL_UNARY_OPCODE(not, ^ 1)

DEFINE_LABEL(cat(escape_bool_binary_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_bool_operator(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), get_i_param(3));
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(4);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
)

DEFINE_LABEL(cat(escape_bool_unary_thunk_,ARG_MODE),
	void *ex;
	ASM_PREVENT_CSE;
	ex = thunk_bool_operator(fp, ip, get_i_param(0), NO_FRAME_T, get_i_param(1), get_i_param(2));
	if (ex == POINTER_FOLLOW_THUNK_GO)
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
)


DEFINE_OPCODE_START_LBL(OPCODE_BOOL_OP + OPCODE_BOOL_OP_move, cat(bool_move_,ARG_MODE))
#ifdef EMIT_CODE
	move_scalar(ajla_flat_option_t);
#endif
DEFINE_OPCODE_END(OPCODE_BOOL_OP + OPCODE_BOOL_OP_move)

DEFINE_OPCODE_START_LBL(OPCODE_BOOL_OP + OPCODE_BOOL_OP_copy, cat(bool_copy_,ARG_MODE))
#ifdef EMIT_CODE
	copy_scalar(ajla_flat_option_t);
#endif
DEFINE_OPCODE_END(OPCODE_BOOL_OP + OPCODE_BOOL_OP_copy)


DEFINE_OPCODE_START(OPCODE_INT_LDC_LONG)
#ifdef EMIT_CODE
	frame_t slot;
	ip_t sz;
	slot = get_i_param(0);
	sz = ipret_int_ldc_long(fp, slot, ip + 1 + param_size(1));
	ADVANCE_I_PARAM(1);
	ADVANCE_IP(sz);
#endif
DEFINE_OPCODE_END(OPCODE_INT_LDC_LONG)


DEFINE_OPCODE_START(OPCODE_IS_EXCEPTION)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	ajla_assert(slot_r == slot_1 || !frame_test_flag(fp, slot_r), (file_line, "is exception: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));
	if (!frame_variable_is_flat(fp, slot_1)) {
		void *ex = is_thunk_operator(fp, ip, slot_1, slot_r, get_i_param(2));
		if (ex == POINTER_FOLLOW_THUNK_GO)
			ADVANCE_I_PARAM(3);
		else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
			RELOAD_EX_POSITION(ex);
	} else {
		barrier_aliasing();
		*frame_slot(fp, slot_r, ajla_flat_option_t) = 0;
		barrier_aliasing();
		ADVANCE_I_PARAM(3);
	}
#endif
DEFINE_OPCODE_END(OPCODE_IS_EXCEPTION)

DEFINE_OPCODE_START(OPCODE_EXCEPTION_CLASS)
#ifdef EMIT_CODE
	void *ex;
	ex = thunk_get_param(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), 0);
	if (likely(ex == POINTER_FOLLOW_THUNK_GO))
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
#endif
DEFINE_OPCODE_END(OPCODE_EXCEPTION_CLASS)

DEFINE_OPCODE_START(OPCODE_EXCEPTION_TYPE)
#ifdef EMIT_CODE
	void *ex;
	ex = thunk_get_param(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), 1);
	if (likely(ex == POINTER_FOLLOW_THUNK_GO))
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
#endif
DEFINE_OPCODE_END(OPCODE_EXCEPTION_TYPE)

DEFINE_OPCODE_START(OPCODE_EXCEPTION_AUX)
#ifdef EMIT_CODE
	void *ex;
	ex = thunk_get_param(fp, ip, get_i_param(0), get_i_param(1), get_i_param(2), 2);
	if (likely(ex == POINTER_FOLLOW_THUNK_GO))
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
#endif
DEFINE_OPCODE_END(OPCODE_EXCEPTION_AUX)

DEFINE_OPCODE_START(OPCODE_SYSTEM_PROPERTY)
#ifdef EMIT_CODE
	void *ex;
	ex = ipret_get_system_property(fp, ip, get_i_param(0), get_i_param(1));
	if (likely(ex == POINTER_FOLLOW_THUNK_GO))
		ADVANCE_I_PARAM(3);
	else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY))
		RELOAD_EX_POSITION(ex);
#endif
DEFINE_OPCODE_END(OPCODE_SYSTEM_PROPERTY)


DEFINE_OPCODE_START(OPCODE_FLAT_MOVE)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	if (likely(frame_variable_is_flat(fp, slot_1))) {
		memcpy(frame_var(fp, slot_r), frame_var(fp, slot_1), frame_get_type_of_local(fp, slot_1)->size);
	} else {
		pointer_t ptr = frame_get_pointer_reference(fp, slot_1, true);
		frame_set_pointer(fp, slot_r, ptr);
	}
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_FLAT_MOVE)

DEFINE_OPCODE_START(OPCODE_FLAT_COPY)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	if (likely(frame_variable_is_flat(fp, slot_1))) {
		memcpy(frame_var(fp, slot_r), frame_var(fp, slot_1), frame_get_type_of_local(fp, slot_1)->size);
	} else {
		pointer_t ptr = frame_get_pointer_reference(fp, slot_1, false);
		frame_set_pointer(fp, slot_r, ptr);
	}
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_FLAT_COPY)

DEFINE_OPCODE_START(OPCODE_REF_MOVE)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	pointer_t ptr = frame_get_pointer_reference(fp, slot_1, true);
	pointer_poison(frame_pointer(fp, slot_1));
	frame_set_pointer(fp, slot_r, ptr);
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_REF_MOVE)

DEFINE_OPCODE_START(OPCODE_REF_MOVE_CLEAR)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	pointer_t ptr = frame_get_pointer_reference(fp, slot_1, true);
	frame_set_pointer(fp, slot_r, ptr);
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_REF_MOVE_CLEAR)

DEFINE_OPCODE_START(OPCODE_REF_COPY)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	pointer_t ptr = frame_get_pointer_reference(fp, slot_1, false);
	frame_set_pointer(fp, slot_r, ptr);
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_REF_COPY)

DEFINE_OPCODE_START(OPCODE_BOX_MOVE_CLEAR)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	pointer_t ptr = ipret_copy_variable_to_pointer(fp, slot_1, true);
	*frame_pointer(fp, slot_1) = pointer_empty();
	frame_set_pointer(fp, slot_r, ptr);
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_BOX_MOVE_CLEAR)

DEFINE_OPCODE_START(OPCODE_BOX_COPY)
#ifdef EMIT_CODE
	frame_t slot_1 = get_i_param(0);
	frame_t slot_r = get_i_param(1);
	pointer_t ptr = ipret_copy_variable_to_pointer(fp, slot_1, false);
	frame_set_pointer(fp, slot_r, ptr);
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_BOX_COPY)

DEFINE_OPCODE_START(OPCODE_TAKE_BORROWED)
#ifdef EMIT_CODE
	frame_t slot = get_i_param(0);
	if (!frame_test_and_set_flag(fp, slot)) {
		pointer_t ptr = *frame_pointer(fp, slot);
		pointer_reference_owned(ptr);
	}
	ADVANCE_I_PARAM(1);
#endif
DEFINE_OPCODE_END(OPCODE_TAKE_BORROWED)


DEFINE_OPCODE_START(OPCODE_DEREFERENCE)
#ifdef EMIT_CODE
	frame_t slot = get_i_param(0);
#if 0
	{
		struct data *fn = get_frame(fp)->function;
		const struct type *type = frame_get_type_of_local(fp, slot);
		bool may_be_borrowed = da(fn,function)->local_variables[slot].may_be_borrowed;
		if (!frame_test_flag(fp, slot) && !may_be_borrowed && !TYPE_IS_FLAT(type))
			internal(file_line, "dereference: %s: the value is unexpectedly borrowed", da(fn,function)->function_name);
	}
#endif
	frame_free(fp, slot);
	pointer_poison(frame_pointer(fp, slot));
	ADVANCE_I_PARAM(1);
#endif
DEFINE_OPCODE_END(OPCODE_DEREFERENCE)

DEFINE_OPCODE_START(OPCODE_DEREFERENCE_CLEAR)
#ifdef EMIT_CODE
	frame_t slot = get_i_param(0);
#if 0
	{
		struct data *fn = get_frame(fp)->function;
		const struct type *type = frame_get_type_of_local(fp, slot);
		bool may_be_borrowed = da(fn,function)->local_variables[slot].may_be_borrowed;
		if (!frame_test_flag(fp, slot) && !may_be_borrowed && !TYPE_IS_FLAT(type))
			internal(file_line, "dereference clear: %s: the value is unexpectedly borrowed", da(fn,function)->function_name);
	}
#endif
	frame_free_and_clear(fp, slot);
	ADVANCE_I_PARAM(1);
#endif
DEFINE_OPCODE_END(OPCODE_DEREFERENCE_CLEAR)

DEFINE_OPCODE_START(OPCODE_EVAL)
#ifdef EMIT_CODE
	frame_t slot = get_i_param(0);
	if (frame_test_flag(fp, slot)) {
		pointer_t *ptr = frame_pointer(fp, slot);
		struct data attr_unused *result;
/*cat(eval_again_,ARG_MODE):*/
		pointer_follow(ptr, true, result, PF_WAIT, fp, ip,
			RELOAD_EX_POSITION(ex_),
			goto cat(eval_skip_,ARG_MODE));
/*
		if (unlikely(da_tag(result) == DATA_TAG_array_incomplete)) {
			ptr = &da(result,array_incomplete)->next;
			goto cat(eval_again_,ARG_MODE);
		}
*/
cat(eval_skip_,ARG_MODE):;
	}
	ADVANCE_I_PARAM(1);
#endif
DEFINE_OPCODE_END(OPCODE_EVAL)


DEFINE_OPCODE_START(OPCODE_CHECKPOINT)
#ifdef EMIT_CODE
#if defined(HAVE_CODEGEN)
	frame_t id = get_i_param(0);
	const code_t attr_unused *orig_ip = ip;
#endif
	ADVANCE_I_PARAM(1);

	if (unlikely(tick_elapsed(&ts)) && likely(frame_execution_control(fp) != NULL)) {
		ipret_checkpoint_forced;
	} else {
#ifdef HAVE_CODEGEN
		struct data *fn = get_frame(fp)->function;
		code_return_t r;
		void *new_fp;
		ip_t new_ip;
		struct data *codegen;
		if (unlikely(load_relaxed(&da(fn,function)->codegen_failed)))
			goto cat(checkpoint_exit_,ARG_MODE);
#if 1
		pointer_follow(&da(fn,function)->codegen, false, codegen, PF_WAIT, fp, orig_ip,
			RELOAD_EX_POSITION(ex_),
			store_relaxed(&da(fn,function)->codegen_failed, 1);
			goto cat(checkpoint_exit_,ARG_MODE);
		);
#else
		pointer_follow(&da(fn,function)->codegen, false, codegen, PF_SPARK, NULL, 0,
			/*debug("sparked: %s %p", da(fn,function)->function_name, ex_);*/
			SUBMIT_EX(ex_);
			goto cat(checkpoint_exit_,ARG_MODE),
			store_relaxed(&da(fn,function)->codegen_failed, 1);
			goto cat(checkpoint_exit_,ARG_MODE);
		);
#endif

		/*debug("running optimized code: %s, %p, %x, %p, %d, %p, %p, %u", da(fn,function)->function_name, da(codegen,codegen)->unoptimized_code_base, id, da(codegen,codegen)->unoptimized_code[id], da(codegen,codegen)->entry_offset, fp, &cg_upcall_vector, ts);*/
		/*debug("fp[0] = %lx", *(long *)((char *)fp + 0));
		debug("fp[8] = %lx", *(long *)((char *)fp + 8));
		debug("fp[16] = %lx", *(long *)((char *)fp + 16));
		debug("fp[24] = %lx", *(long *)((char *)fp + 24));
		debug("fp[32] = %lx", *(long *)((char *)fp + 32));
		debug("fp[40] = %lx", *(long *)((char *)fp + 40));*/
		/*{
			uintptr_t *stub = (void *)da(codegen,codegen)->unoptimized_code[id];
			debug("entry: %p, %lx %lx %lx %lx", stub, stub[0], stub[1], stub[2], stub[3]);
		}*/
		/*__asm__ volatile("nopr %r6");*/
		/*__asm__ volatile("xnop");*/
		/*__asm__ volatile("cover");*/
		/*debug("calling: %p, %u, %lx, %lx", da(codegen,codegen)->unoptimized_code[id], da(codegen,codegen)->entry_offset, ((long *)da(codegen,codegen)->unoptimized_code[id])[0], ((long *)da(codegen,codegen)->unoptimized_code[id])[1]);*/
		r = ((code_fn)(da(codegen,codegen)->unoptimized_code[id] - da(codegen,codegen)->entry_offset))(fp, &cg_upcall_vector, ts);
#if defined(ARCH_X86_32) || defined(ARCH_ARM32) || defined(ARCH_MIPS32) || defined(ARCH_POWER32) || defined(ARCH_SPARC32)
#if defined(C_LITTLE_ENDIAN) || defined(ARCH_MIPS_N32)
		new_fp = num_to_ptr(r & 0xffffffffU);
		new_ip = r >> 32;
#else
		new_fp = num_to_ptr(r >> 32);
		new_ip = r & 0xffffffffU;
#endif
#else
		new_fp = r.fp;
		new_ip = r.ip;
#endif
		/*debug("ran optimized code: %s, %p, %lx -> %p, %x", da(fn,function)->function_name, fp, (unsigned long)(ip - da(fn,function)->code), new_fp, new_ip);*/
		if (unlikely(new_ip == (ip_t)-1)) {
			/*debug("reload on optimized code: %p", new_fp);*/
			RELOAD_EX_POSITION(new_fp);
		} else {
			/*if (fp != new_fp) debug("switching function: %s -> %s", da(fn,function)->function_name, da(get_frame(new_fp)->function,function)->function_name);*/
			fp = new_fp;
			ip = da(get_frame(fp)->function,function)->code + new_ip;
			if (unlikely(profiling_escapes)) {
				profile_counter_t profiling_counter;
				fn = get_frame(fp)->function;
				profiling_counter = load_relaxed(&da(fn,function)->escape_data[new_ip].counter);
				profiling_counter++;
				store_relaxed(&da(fn,function)->escape_data[new_ip].counter, profiling_counter);
			}
		}
#endif
		goto cat(checkpoint_exit_,ARG_MODE);
cat(checkpoint_exit_,ARG_MODE):;
	}
#endif
DEFINE_OPCODE_END(OPCODE_CHECKPOINT)


#if ARG_MODE == 0
DEFINE_OPCODE_START(OPCODE_JMP)
#ifdef EMIT_CODE
	if (SIZEOF_IP_T == 2) {
		int16_t offset = ip[1];
		ADVANCE_IP(2);
		ip = cast_ptr(const code_t *, cast_ptr(const char *, ip) + offset);
	} else if (SIZEOF_IP_T == 4) {
		int32_t offset = get_unaligned_32(&ip[1]);
		ADVANCE_IP(3);
		ip = cast_ptr(const code_t *, cast_ptr(const char *, ip) + offset);
	} else {
		not_reached();
	}
#endif
DEFINE_OPCODE_END(OPCODE_JMP)
#endif

#if ARG_MODE == 0 && SIZEOF_IP_T > 2
DEFINE_OPCODE_START(OPCODE_JMP_BACK_16)
#ifdef EMIT_CODE
	uint16_t offset;

	offset = ip[1];
	ip = cast_ptr(const code_t *, cast_ptr(const char *, ip) - offset);
#endif
DEFINE_OPCODE_END(OPCODE_JMP_BACK_16)
#endif

DEFINE_OPCODE_START(OPCODE_JMP_FALSE)
#ifdef EMIT_CODE
	int32_t offset;
	frame_t slot;
	ajla_flat_option_t val1;

	slot = get_i_param(0);
	if (unlikely(frame_test_flag(fp, slot))) {
		void *ex = thunk_bool_jump(fp, ip, slot);
		if (ex != POINTER_FOLLOW_THUNK_RETRY) {
			if (likely(ex != POINTER_FOLLOW_THUNK_EXCEPTION)) {
				RELOAD_EX_POSITION(ex);
			} else {
				if (SIZEOF_IP_T == 2) {
					offset = ip[1 + param_size(1) + 1];
					ADVANCE_I_PARAM(1);
					ADVANCE_IP(2);
				} else if (SIZEOF_IP_T == 4) {
					offset = get_unaligned_32(&ip[1 + param_size(1) + 2]);
					ADVANCE_I_PARAM(1);
					ADVANCE_IP(4);
				} else {
					not_reached();
				}
				ip = cast_ptr(const code_t *, cast_ptr(const char *, ip) + offset);
				goto cat(jmp_false_exception_,ARG_MODE);
			}
		}
	}
	barrier_aliasing();
	val1 = *frame_slot(fp, slot, ajla_flat_option_t);
	barrier_aliasing();
	if (SIZEOF_IP_T == 2) {
		offset = ip[1 + param_size(1)];
		ADVANCE_I_PARAM(1);
		ADVANCE_IP(2);
	} else if (SIZEOF_IP_T == 4) {
		offset = get_unaligned_32(&ip[1 + param_size(1)]);
		ADVANCE_I_PARAM(1);
		ADVANCE_IP(4);
	} else {
		not_reached();
	}
	if (!val1)
		ip = cast_ptr(const code_t *, cast_ptr(const char *, ip) + offset);

cat(jmp_false_exception_,ARG_MODE):;
#endif
DEFINE_OPCODE_END(OPCODE_JMP_FALSE)

#if ARG_MODE == 0
DEFINE_OPCODE_START(OPCODE_LABEL)
#ifdef EMIT_CODE
	ADVANCE_IP(1);
#endif
DEFINE_OPCODE_END(OPCODE_LABEL)
#endif


START_BLOCK(
	pointer_t *direct_data;
	pointer_t indirect_data;
	arg_t n_arguments;
	frame_t result_slot;
	struct thunk *function_error;
)

DEFINE_OPCODE_START(OPCODE_LOAD_FN)
#ifdef EMIT_CODE
	struct data *new_reference;
	pointer_t result_ptr;

	n_arguments = get_i_param(0);
	result_slot = get_i_param(1);
	direct_data = da(get_frame(fp)->function,function)->local_directory[get_i_param(2)];
	indirect_data = pointer_empty();	/* avoid warning */

	ADVANCE_I_PARAM(3);

cat(fn_copy_arguments_,ARG_MODE):

	new_reference = data_alloc_function_reference_mayfail(n_arguments, &ajla_error pass_file_line);
	if (unlikely(!new_reference)) {
		function_error = thunk_alloc_exception_error(ajla_error, NULL, fp, ip pass_file_line);
		if (!direct_data)
			pointer_dereference(indirect_data);
/*cat(fn_set_error_,ARG_MODE):*/
		ip = cat(free_parameters_,ARG_MODE)(fp, ip, n_arguments);
		result_ptr = pointer_thunk(function_error);
	} else {
		arg_t i;
		if (direct_data) {
			da(new_reference,function_reference)->is_indirect = false;
			da(new_reference,function_reference)->u.direct = direct_data;
		} else {
			da(new_reference,function_reference)->is_indirect = true;
			da(new_reference,function_reference)->u.indirect = indirect_data;
		}
		for (i = 0; i < n_arguments; i++) {
			ipret_fill_function_reference_from_slot(new_reference, i, fp, get_param(ip, 0), (get_param(ip, 1) & OPCODE_FLAG_FREE_ARGUMENT) != 0);
			ADVANCE_IP(param_size(2));
		}
		result_ptr = pointer_data(new_reference);
	}

	frame_set_pointer(fp, result_slot, result_ptr);
#endif
DEFINE_OPCODE_END(OPCODE_LOAD_FN)

DEFINE_OPCODE_START(OPCODE_CURRY)
#ifdef EMIT_CODE
	frame_t fn_ref_slot;

	n_arguments = get_i_param(0);
	result_slot = get_i_param(1);

	fn_ref_slot = get_i_param(2);
	direct_data = NULL;
	indirect_data = frame_get_pointer_reference(fp, fn_ref_slot, (get_i_param(3) & OPCODE_FLAG_FREE_ARGUMENT) != 0);

	ADVANCE_I_PARAM(4);

	goto cat(fn_copy_arguments_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CURRY)

END_BLOCK()

START_BLOCK(
	arg_t n_arguments;
	arg_t n_return_values;
	struct thunk *function_error;
	struct data *function;
	const code_t *orig_ip;
	frame_s *new_fp;
	arg_t i;
	pointer_t *direct_function;
	pointer_t indirect_function;
	unsigned char mode;
)
DEFINE_OPCODE_START(OPCODE_CALL)
#ifdef EMIT_CODE
	pointer_t *function_ptr;

	mode = CALL_MODE_NORMAL;
cat(call_from_mode_,ARG_MODE):

	n_arguments = get_i_param(0);
	n_return_values = get_i_param(1);
	function_ptr = da(get_frame(fp)->function,function)->local_directory[get_i_param(2)];

	pointer_follow(function_ptr, false, function, PF_WAIT, fp, ip,
		RELOAD_EX_POSITION(ex_),
		function_error = thunk_;
		thunk_reference(function_error);
		ADVANCE_I_PARAM(3);
		goto cat(call_set_error_,ARG_MODE);
	);

	ajla_assert(da(function,function)->n_arguments == n_arguments && da(function,function)->n_return_values == n_return_values,
		(file_line, "call %s->%s: the number of arguments does not match: %lu != %lu || %lu != %lu",
			da(get_frame(fp)->function,function)->function_name, da(function,function)->function_name,
			(unsigned long)da(function,function)->n_arguments, (unsigned long)n_arguments,
			(unsigned long)da(function,function)->n_return_values, (unsigned long)n_return_values));

	ADVANCE_I_PARAM(3);

	new_fp = frame_build(fp, function, &ajla_error);
	if (unlikely(!new_fp)) {
cat(call_allocation_error_,ARG_MODE):
		function_error = thunk_alloc_exception_error(ajla_error, NULL, fp, ip pass_file_line);
cat(call_set_error_,ARG_MODE):
		ip = cat(free_parameters_,ARG_MODE)(fp, ip, n_arguments);
		pointer_reference_owned_multiple(pointer_thunk(function_error), n_return_values - 1);
		i = n_return_values;
		while (1) {
			frame_t slot_r = get_max_param(ip, 0);
			ADVANCE_IP(max_param_size(1) + 1);
			frame_set_pointer(fp, slot_r, pointer_thunk(function_error));
			if (!--i)
				break;
		}
	} else {
		fp = frame_up(new_fp);
		frame_init(new_fp, function, get_frame(fp)->timestamp, mode);

		i = 0;
cat(call_copy_arguments_,ARG_MODE):
		for (; i < da(function,function)->n_arguments; i++) {
			frame_t src_slot = get_param(ip, 0);
			frame_t dst_slot = da(function,function)->args[i].slot;
			unsigned char src_flag = (unsigned char)get_param(ip, 1);
			bool may_be_borrowed = da(function,function)->args[i].may_be_borrowed;
			if (may_be_borrowed && src_flag & OPCODE_CALL_MAY_LEND && !pointer_is_thunk(*frame_pointer(fp, src_slot))) {
				*frame_pointer(new_fp, dst_slot) = *frame_pointer(fp, src_slot);
			} else if (may_be_borrowed && src_flag & OPCODE_CALL_MAY_GIVE && !frame_test_flag(fp, src_slot) && !pointer_is_thunk(*frame_pointer(fp, src_slot))) {
				*frame_pointer(new_fp, dst_slot) = *frame_pointer(fp, src_slot);
				*frame_pointer(fp, src_slot) = pointer_empty();
			} else {
				ipret_copy_variable(fp, src_slot, new_fp, dst_slot, (src_flag & OPCODE_FLAG_FREE_ARGUMENT) != 0);
			}
			ADVANCE_IP(param_size(2));
		}
		get_frame(new_fp)->previous_ip = frame_ip(fp, ip);

		fp = new_fp;
		ip = &da(function,function)->code[0];

		if (unlikely(mode == CALL_MODE_SPARK)) {
			ipret_checkpoint_forced;
		}
	}
#endif
DEFINE_OPCODE_END(OPCODE_CALL)

DEFINE_OPCODE_START(OPCODE_CALL_STRICT)
#ifdef EMIT_CODE
	mode = CALL_MODE_STRICT;
	goto cat(call_from_mode_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_STRICT)

DEFINE_OPCODE_START(OPCODE_CALL_SPARK)
#ifdef EMIT_CODE
	mode = CALL_MODE_SPARK;
	goto cat(call_from_mode_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_SPARK)

DEFINE_OPCODE_START(OPCODE_CALL_INDIRECT)
#ifdef EMIT_CODE
	frame_t fn_ref_slot;
	bool deref;
	pointer_t *ptr;

	mode = CALL_MODE_NORMAL;
cat(call_indirect_from_mode_,ARG_MODE):

	orig_ip = ip;
	n_arguments = get_i_param(0);
	n_return_values = get_i_param(1);
	fn_ref_slot = get_i_param(2);
	deref = (get_i_param(3) & OPCODE_FLAG_FREE_ARGUMENT) != 0;
	ADVANCE_I_PARAM(4);

	ptr = frame_pointer(fp, fn_ref_slot);
	while (1) {
		pointer_follow(ptr, false, function, PF_WAIT, fp, orig_ip,
			RELOAD_EX_POSITION(ex_),
			function_error = thunk_;
			thunk_reference(function_error);
			if (deref)
				frame_free_and_clear(fp, fn_ref_slot);
			goto cat(call_set_error_,ARG_MODE)
		);
		if (!da(function,function_reference)->is_indirect)
			break;
		ptr = &da(function,function_reference)->u.indirect;
	}
	ptr = da(function,function_reference)->u.direct;
	pointer_follow(ptr, false, function, PF_WAIT, fp, orig_ip,
		RELOAD_EX_POSITION(ex_),
		function_error = thunk_;
		thunk_reference(function_error);
		if (deref)
			frame_free_and_clear(fp, fn_ref_slot);
		goto cat(call_set_error_,ARG_MODE)
	);

	new_fp = frame_build(fp, function, &ajla_error);
	if (unlikely(!new_fp)) {
		if (deref)
			frame_free_and_clear(fp, fn_ref_slot);
		goto cat(call_allocation_error_,ARG_MODE);
	} else {
		fp = frame_up(new_fp);
		frame_init(new_fp, function, get_frame(fp)->timestamp, mode);

		i = da(function,function)->n_arguments - n_arguments;

		copy_from_function_reference_to_frame(new_fp, pointer_get_data(*frame_pointer(fp, fn_ref_slot)), i, deref && frame_test_flag(fp, fn_ref_slot));
		if (deref)
			frame_free_and_clear(fp, fn_ref_slot);

		goto cat(call_copy_arguments_,ARG_MODE);
	}
#endif
DEFINE_OPCODE_END(OPCODE_CALL_INDIRECT)

DEFINE_OPCODE_START(OPCODE_CALL_INDIRECT_STRICT)
#ifdef EMIT_CODE
	mode = CALL_MODE_STRICT;
	goto cat(call_indirect_from_mode_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_INDIRECT_STRICT)

DEFINE_OPCODE_START(OPCODE_CALL_INDIRECT_SPARK)
#ifdef EMIT_CODE
	mode = CALL_MODE_SPARK;
	goto cat(call_indirect_from_mode_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_INDIRECT_SPARK)

DEFINE_OPCODE_START(OPCODE_CALL_LAZY)
#ifdef EMIT_CODE
	struct data *function_reference;
	struct thunk **results;

	n_arguments = get_i_param(0);
	n_return_values = get_i_param(1);
	direct_function = da(get_frame(fp)->function,function)->local_directory[get_i_param(2)];
	indirect_function = pointer_empty();	/* avoid warning */

	ADVANCE_I_PARAM(3);

cat(call_lazy_copy_arguments_,ARG_MODE):
	results = mem_alloc_array_mayfail(mem_alloc_mayfail, struct thunk **, 0, 0, n_return_values, sizeof(struct thunk *), &ajla_error);
	if (unlikely(!results)) {
		if (!direct_function)
			pointer_dereference(indirect_function);
		goto cat(call_allocation_error_,ARG_MODE);
	}

	if (!(function_reference = data_alloc_function_reference_mayfail(n_arguments, &ajla_error pass_file_line))) {
		if (!direct_function)
			pointer_dereference(indirect_function);
		mem_free(results);
		goto cat(call_allocation_error_,ARG_MODE);
	}
	if (direct_function) {
		da(function_reference,function_reference)->is_indirect = false;
		da(function_reference,function_reference)->u.direct = direct_function;
	} else {
		da(function_reference,function_reference)->is_indirect = true;
		da(function_reference,function_reference)->u.indirect = indirect_function;
	}

	if (!thunk_alloc_function_call(pointer_data(function_reference), n_return_values, results, &ajla_error)) {
		if (!direct_function)
			pointer_dereference(indirect_function);
		mem_free(results);
		data_free_r1(function_reference);
		goto cat(call_allocation_error_,ARG_MODE);
	}

	for (i = 0; i < n_arguments; i++) {
		frame_t src_slot = get_param(ip, 0);
		unsigned char src_flag = (unsigned char)get_param(ip, 1);
		ipret_fill_function_reference_from_slot(function_reference, i, fp, src_slot, (src_flag & OPCODE_FLAG_FREE_ARGUMENT) != 0);
		ADVANCE_IP(param_size(2));
	}

	for (i = 0; i < n_return_values; i++) {
		frame_t slot_r = get_max_param(ip, 0);
		frame_set_pointer(fp, slot_r, pointer_thunk(results[i]));
		ADVANCE_IP(max_param_size(1) + 1);
	}

	mem_free(results);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_LAZY)

DEFINE_OPCODE_START(OPCODE_CALL_INDIRECT_LAZY)
#ifdef EMIT_CODE
	frame_t fn_ref_slot;
	bool deref;

	n_arguments = get_i_param(0);
	n_return_values = get_i_param(1);
	fn_ref_slot = get_i_param(2);
	deref = (get_i_param(3) & OPCODE_FLAG_FREE_ARGUMENT) != 0;
	ADVANCE_I_PARAM(4);

	indirect_function = frame_get_pointer_reference(fp, fn_ref_slot, deref);
	direct_function = NULL;

	goto cat(call_lazy_copy_arguments_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_INDIRECT_LAZY)

DEFINE_OPCODE_START(OPCODE_CALL_CACHE)
#ifdef EMIT_CODE
	struct ipret_call_cache_arg *arguments;
	frame_t *return_values;
	void *ex;

cat(call_cache_,ARG_MODE):
	orig_ip = ip;
	n_arguments = get_i_param(0);
	n_return_values = get_i_param(1);
	direct_function = da(get_frame(fp)->function,function)->local_directory[get_i_param(2)];
	ADVANCE_I_PARAM(3);

	pointer_follow(direct_function, false, function, PF_WAIT, fp, orig_ip,
		RELOAD_EX_POSITION(ex_),
		function_error = thunk_;
		thunk_reference(function_error);
		goto cat(call_set_error_,ARG_MODE);
	);
	ajla_assert(da(function,function)->n_arguments == n_arguments && da(function,function)->n_return_values == n_return_values,
		(file_line, "call_cache: the number of arguments does not match: %lu != %lu || %lu != %lu",
			(unsigned long)da(function,function)->n_arguments, (unsigned long)n_arguments,
			(unsigned long)da(function,function)->n_return_values, (unsigned long)n_return_values));

	arguments = mem_alloc_array_mayfail(mem_alloc_mayfail, struct ipret_call_cache_arg *, 0, 0, n_arguments, sizeof(struct ipret_call_cache_arg), &ajla_error);
	if (!arguments) {
		goto cat(call_allocation_error_,ARG_MODE);
	}
	return_values = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, n_return_values, sizeof(frame_t), &ajla_error);
	if (!return_values) {
		mem_free(arguments);
		goto cat(call_allocation_error_,ARG_MODE);
	}

	for (i = 0; i < n_arguments; i++) {
		frame_t src_slot = get_param(ip, 0);
		unsigned char src_flag = (unsigned char)get_param(ip, 1);
		arguments[i].f_arg = NULL;
		arguments[i].slot = src_slot;
		arguments[i].deref = (src_flag & OPCODE_FLAG_FREE_ARGUMENT) != 0;
		ADVANCE_IP(param_size(2));
	}

	for (i = 0; i < n_return_values; i++) {
		frame_t slot_r = get_max_param(ip, 0);
		return_values[i] = slot_r;
		ADVANCE_IP(max_param_size(1) + 1);
	}

	ex = ipret_call_cache(fp, orig_ip, direct_function, arguments, return_values, NO_FRAME_T);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		RELOAD_EX_POSITION(ex);
	}
#endif
DEFINE_OPCODE_END(OPCODE_CALL_CACHE)

DEFINE_OPCODE_START(OPCODE_CALL_SAVE)
#ifdef EMIT_CODE
	goto cat(call_cache_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_SAVE)

DEFINE_OPCODE_START(OPCODE_CALL_INDIRECT_CACHE)
#ifdef EMIT_CODE
	struct ipret_call_cache_arg *arguments;
	frame_t *return_values;
	void *ex;

	frame_t fn_ref_slot;
	bool deref;
	pointer_t *ptr;
	arg_t n_curried_arguments;

cat(call_indirect_cache_,ARG_MODE):
	orig_ip = ip;
	n_arguments = get_i_param(0);
	n_return_values = get_i_param(1);
	fn_ref_slot = get_i_param(2);
	deref = (get_i_param(3) & OPCODE_FLAG_FREE_ARGUMENT) != 0;
	ADVANCE_I_PARAM(4);

	n_curried_arguments = 0;
	ptr = frame_pointer(fp, fn_ref_slot);
	while (1) {
		pointer_follow(ptr, false, function, PF_WAIT, fp, orig_ip,
			RELOAD_EX_POSITION(ex_),
			function_error = thunk_;
			thunk_reference(function_error);
			if (deref)
				frame_free_and_clear(fp, fn_ref_slot);
			goto cat(call_set_error_,ARG_MODE)
		);
		n_curried_arguments += da(function,function_reference)->n_curried_arguments;
		if (!da(function,function_reference)->is_indirect)
			break;
		ptr = &da(function,function_reference)->u.indirect;
	}
	ptr = da(function,function_reference)->u.direct;
	pointer_follow(ptr, false, function, PF_WAIT, fp, orig_ip,
		RELOAD_EX_POSITION(ex_),
		function_error = thunk_;
		thunk_reference(function_error);
		if (deref)
			frame_free_and_clear(fp, fn_ref_slot);
		goto cat(call_set_error_,ARG_MODE)
	);

	arguments = mem_alloc_array_mayfail(mem_alloc_mayfail, struct ipret_call_cache_arg *, 0, 0, n_curried_arguments + n_arguments, sizeof(struct ipret_call_cache_arg), &ajla_error);
	if (!arguments) {
		if (deref)
			frame_free_and_clear(fp, fn_ref_slot);
		goto cat(call_allocation_error_,ARG_MODE);
	}
	return_values = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, n_return_values, sizeof(frame_t), &ajla_error);
	if (!return_values) {
		mem_free(arguments);
		if (deref)
			frame_free_and_clear(fp, fn_ref_slot);
		goto cat(call_allocation_error_,ARG_MODE);
	}

	i = n_curried_arguments;
	function = pointer_get_data(*frame_pointer(fp, fn_ref_slot));
	while (1) {
		arg_t j;
		j = da(function,function_reference)->n_curried_arguments;
		while (j--) {
			i--;
			arguments[i].f_arg = &da(function,function_reference)->arguments[j];
			arguments[i].deref = false;
		}
		if (!da(function,function_reference)->is_indirect)
			break;
		function = pointer_get_data(da(function,function_reference)->u.indirect);
	}

	for (i = n_curried_arguments; i < n_curried_arguments + n_arguments; i++) {
		frame_t src_slot = get_param(ip, 0);
		unsigned char src_flag = (unsigned char)get_param(ip, 1);
		arguments[i].f_arg = NULL;
		arguments[i].slot = src_slot;
		arguments[i].deref = (src_flag & OPCODE_FLAG_FREE_ARGUMENT) != 0;
		ADVANCE_IP(param_size(2));
	}

	for (i = 0; i < n_return_values; i++) {
		frame_t slot_r = get_max_param(ip, 0);
		return_values[i] = slot_r;
		ADVANCE_IP(max_param_size(1) + 1);
	}

	ex = ipret_call_cache(fp, orig_ip, ptr, arguments, return_values, deref ? fn_ref_slot : NO_FRAME_T);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		RELOAD_EX_POSITION(ex);
	}
#endif
DEFINE_OPCODE_END(OPCODE_CALL_INDIRECT_CACHE)

DEFINE_OPCODE_START(OPCODE_CALL_INDIRECT_SAVE)
#ifdef EMIT_CODE
	goto cat(call_indirect_cache_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_CALL_INDIRECT_SAVE)

END_BLOCK()

DEFINE_OPCODE_START(OPCODE_RETURN)
#ifdef EMIT_CODE
	struct data *function;
	frame_s *previous_fp;
	const code_t *previous_ip;
	arg_t i, n;

	/*ADVANCE_I_PARAM(0);*/

	function = get_frame(fp)->function;
	previous_fp = frame_up(fp);
	if (unlikely(frame_is_top(previous_fp))) {
		struct execution_control *ex;
		void *exx;
		struct thunk *t;
		struct stack_bottom *sb = frame_stack_bottom(previous_fp);
		ex = sb->ex;
		if (!ex) {
			frame_t src_slot = get_i_param(0);
			sb->ret = ipret_copy_variable_to_pointer(fp, src_slot, true);
			goto exit_ipret;
		}
		t = ex->thunk;
		n = da(function,function)->n_return_values;
		i = 0;
		do {
			frame_t src_slot = get_i_param(i * 2);
			frame_t flags = get_i_param(i * 2 + 1);
			t->u.function_call.results[i].ptr = ipret_copy_variable_to_pointer(fp, src_slot, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);
		} while (++i < n);
		exx = thunk_terminate(t, n);
#if 0
		if (exx != POINTER_FOLLOW_THUNK_EXIT)
			task_submit(exx, true);
		goto exit_ipret;
#else
		RELOAD_EX_POSITION(exx);
#endif
	}

	get_frame(previous_fp)->timestamp = get_frame(fp)->timestamp;
	previous_ip = &da(get_frame(previous_fp)->function,function)->code[get_frame(fp)->previous_ip];

	n = da(function,function)->n_return_values;
	i = 0;
	do {
		frame_t src_slot, dst_slot, flags;
		src_slot = get_i_param(i * 2);
		flags = get_i_param(i * 2 + 1);
		dst_slot = (frame_t)get_max_param(previous_ip, 0);
		previous_ip += max_param_size(1) + 1;
		ipret_copy_variable(fp, src_slot, previous_fp, dst_slot, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0);
	} while (++i < n);

	fp = previous_fp;
	ip = previous_ip;
#endif
DEFINE_OPCODE_END(OPCODE_RETURN)


DEFINE_OPCODE_START(OPCODE_STRUCTURED)
#ifdef EMIT_CODE
	const code_t *orig_ip = ip;

	frame_t struc, elem;
	pointer_t *struc_ptr;
	unsigned char *struc_flat;
	const struct type *t;
	bool optimize_elem_is_flat;

	unsigned char type;
	frame_t arg;

	pointer_t thunk_ptr;

	elem = get_i_param(1);
	optimize_elem_is_flat = frame_variable_is_flat(fp, elem);

cat(structured_retry_,ARG_MODE):
	struc = get_i_param(0);
	ADVANCE_I_PARAM(2);

	t = frame_get_type_of_local(fp, struc);
	if (frame_variable_is_flat(fp, struc)) {
		if (!optimize_elem_is_flat) {
			frame_set_pointer(fp, struc, flat_to_data(frame_get_type_of_local(fp, struc), frame_var(fp, struc)));
			struc_flat = NULL;
			struc_ptr = frame_pointer(fp, struc);
		} else {
			struc_flat = frame_var(fp, struc);
			struc_ptr = NULL;	/* avoid warning */
		}
	} else {
		struc_flat = NULL;
		struc_ptr = frame_pointer(fp, struc);
	}

	do {
		array_index_t array_index = index_invalid(); /* avoid warning */
		struct data *data = NULL;		     /* avoid warning */

		type = (unsigned char)get_param(ip, 0);
		arg = get_param(ip, 1);
		ADVANCE_IP(param_size(3));

		if ((type & OPCODE_STRUCTURED_MASK) == OPCODE_STRUCTURED_ARRAY) {
			void *ex = ipret_get_index(fp, orig_ip, fp, arg, false, &array_index, &thunk_ptr pass_file_line);
			if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
				if (ex == POINTER_FOLLOW_THUNK_EXCEPTION)
					goto cat(structured_error_,ARG_MODE);
				RELOAD_EX_POSITION(ex);
			}
		}

		if (struc_flat) {
			switch (type & OPCODE_STRUCTURED_MASK) {
				case OPCODE_STRUCTURED_RECORD: {
					const struct flat_record_definition_entry *e;
					ajla_assert(arg < flat_record_n_slots(type_def(t,flat_record)), (file_line, "structured flat record: invalid index: %"PRIuMAX" >= %"PRIuMAX"", (uintmax_t)arg, (uintmax_t)flat_record_n_slots(type_def(t,flat_record))));
					e = &type_def(t,flat_record)->entries[arg];
					t = e->subtype;
					struc_flat += e->flat_offset;
					break;
				}
				case OPCODE_STRUCTURED_OPTION: {
					thunk_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_OPTION_DOESNT_MATCH), fp, ip pass_file_line);
					goto cat(structured_error_,ARG_MODE);
				}
				case OPCODE_STRUCTURED_ARRAY: {
					if (unlikely(index_ge_int(array_index, type_def(t,flat_array)->n_elements))) {
						index_free(&array_index);
						thunk_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), fp, ip pass_file_line);
						goto cat(structured_error_,ARG_MODE);
					}
					t = type_def(t,flat_array)->base;
					struc_flat += t->size * index_to_int(array_index);
					index_free(&array_index);
					break;
				}
				default:
					internal(file_line, "structured flat: invalid structure type %02x", type);
			}
		} else {
cat(structured_restart_pointer_follow_,ARG_MODE):
			pointer_follow(struc_ptr, false, data, PF_WAIT, fp, orig_ip,
				if ((type & OPCODE_STRUCTURED_MASK) == OPCODE_STRUCTURED_ARRAY)
					index_free(&array_index);
				RELOAD_EX_POSITION(ex_),
				if ((type & OPCODE_STRUCTURED_MASK) == OPCODE_STRUCTURED_ARRAY)
					index_free(&array_index);
				goto cat(structured_read_to_the_end_,ARG_MODE);
			);
			if (unlikely(!data_is_writable(data))) {
				struct_clone(struc_ptr);
				goto cat(structured_restart_pointer_follow_,ARG_MODE);
			}
			switch (type & OPCODE_STRUCTURED_MASK) {
				case OPCODE_STRUCTURED_RECORD: {
					const struct record_definition *def = type_def(da(data,record)->definition,record);
					ajla_assert(arg < def->n_slots, (file_line, "structured record: invalid index: %"PRIuMAX" >= %"PRIuMAX"", (uintmax_t)arg, (uintmax_t)def->n_slots));
					t = def->types[arg];
					struc_ptr = frame_pointer(da_record_frame(data), arg);

					if (type & OPCODE_STRUCTURED_FLAG_END) {
						if (frame_variable_is_flat(fp, elem)) {
							if (TYPE_IS_FLAT(t)) {
								frame_free(da_record_frame(data), arg);
								struc_flat = frame_var(da_record_frame(data), arg);
								goto cat(structured_write_flat_,ARG_MODE);
							}
						} else {
							if (!frame_test_and_set_flag(da_record_frame(data), arg))
								goto cat(structured_write_ptr_,ARG_MODE);
						}
					}

					if (!frame_test_flag(da_record_frame(data), arg)) {
						struc_flat = frame_var(da_record_frame(data), arg);
						if (unlikely(!optimize_elem_is_flat)) {
							frame_set_pointer(da_record_frame(data), arg, flat_to_data(t, struc_flat));
							struc_flat = NULL;
						}
					}
					break;
				}
				case OPCODE_STRUCTURED_OPTION: {
					if (unlikely(da(data,option)->option != arg)) {
						if (likely((type & OPCODE_STRUCTURED_FLAG_END) != 0)) {
							da(data,option)->option = arg;
						} else {
							thunk_ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_OPTION_DOESNT_MATCH), fp, ip pass_file_line);
cat(structured_error_,ARG_MODE):
							if (struc_flat) {
								pointer_dereference(thunk_ptr);
								optimize_elem_is_flat = false;
								ip = orig_ip;
								goto cat(structured_retry_,ARG_MODE);
							} else {
								pointer_dereference(*struc_ptr);
								*struc_ptr = thunk_ptr;
								goto cat(structured_read_to_the_end_,ARG_MODE);
							}
						}
					}
					struc_ptr = &da(data,option)->pointer;
					break;
				}
				case OPCODE_STRUCTURED_ARRAY: {
					unsigned array_flags;
					if (unlikely(da_tag(data) == DATA_TAG_array_incomplete)) {
						array_index_t len_first;

						if (array_incomplete_collapse(struc_ptr))
							goto cat(structured_restart_pointer_follow_,ARG_MODE);

						len_first = array_len(pointer_get_data(da(data,array_incomplete)->first));
						if (!index_ge_index(array_index, len_first)) {
							index_free(&len_first);
							struc_ptr = &da(data,array_incomplete)->first;
							goto cat(structured_restart_pointer_follow_,ARG_MODE);
						} else {
							index_sub(&array_index, len_first);
							index_free(&len_first);
							struc_ptr = &da(data,array_incomplete)->next;
							goto cat(structured_restart_pointer_follow_,ARG_MODE);
						}
					}
					if (!optimize_elem_is_flat) {
						array_flags = ARRAY_MODIFY_NEED_PTR;
					} else if (type & OPCODE_STRUCTURED_FLAG_END) {
						array_flags = ARRAY_MODIFY_NEED_FLAT;
						t = frame_get_type_of_local(fp, elem);
					} else {
						array_flags = 0;
					}
					if (unlikely(!array_modify(struc_ptr, array_index, array_flags, &struc_ptr, &struc_flat, &t, fp, ip))) {
						goto cat(structured_read_to_the_end_,ARG_MODE);
					}
					break;
				}
				default:
					internal(file_line, "structured: invalid structure type %02x", type);
			}
		}
	} while (!(type & OPCODE_STRUCTURED_FLAG_END));
	if (struc_flat) {
cat(structured_write_flat_,ARG_MODE):
		memcpy_fast(struc_flat, frame_var(fp, elem), frame_get_type_of_local(fp, elem)->size);
	} else {
		/* The pointer may be empty if we moved from an option without data to an option with data */
		if (likely(!pointer_is_empty(*struc_ptr)))
			pointer_dereference(*struc_ptr);
		if (frame_variable_is_flat(fp, elem)) {
			*struc_ptr = flat_to_data(frame_get_type_of_local(fp, elem), frame_var(fp, elem));
		} else {
cat(structured_write_ptr_,ARG_MODE):
			*struc_ptr = frame_get_pointer_reference(fp, elem, (type & OPCODE_STRUCTURED_FREE_VARIABLE) != 0);
		}
	}
	if (false) {
		do {
			type = (unsigned char)get_param(ip, 0);
			arg = get_param(ip, 1);
			ADVANCE_IP(param_size(3));
cat(structured_read_to_the_end_,ARG_MODE):;
		} while (!(type & OPCODE_STRUCTURED_FLAG_END));
		if (type & OPCODE_STRUCTURED_FREE_VARIABLE)
			frame_free(fp, elem);
	}
#endif
DEFINE_OPCODE_END(OPCODE_STRUCTURED)

DEFINE_OPCODE_START(OPCODE_RECORD_CREATE)
#ifdef EMIT_CODE
	frame_t result_slot;
	arg_t n_entries, i, ii;
	const struct type *t;
	const struct record_definition *def;

	result_slot = get_i_param(0);
	n_entries = get_i_param(1);
	ADVANCE_I_PARAM(2);

	t = frame_get_type_of_local(fp, result_slot);
	if (t->tag == TYPE_TAG_flat_record) {
		const code_t *backup_ip;
		def = type_def(type_def(t,flat_record)->base,record);
		backup_ip = ip;
		for (i = 0, ii = 0; i < n_entries; i++, ii++) {
			frame_t var_slot, record_slot;
			flat_size_t flat_offset;
			const struct type *flat_type;

			while (unlikely(record_definition_is_elided(def, ii)))
				ii++;

			var_slot = get_param(ip, 0);

			if (unlikely(!frame_variable_is_flat(fp, var_slot))) {
				ip = backup_ip;
				goto cat(create_record_no_flat_,ARG_MODE);
			}
			record_slot = record_definition_slot(def, ii);
			flat_offset = type_def(t,flat_record)->entries[record_slot].flat_offset;
			flat_type = type_def(t,flat_record)->entries[record_slot].subtype;
			ajla_assert(type_is_equal(frame_get_type_of_local(fp, var_slot), flat_type), (file_line, "record create (flat): copying between different types (%u,%u,%u) -> (%u,%u,%u)", frame_get_type_of_local(fp, var_slot)->tag, frame_get_type_of_local(fp, var_slot)->size, frame_get_type_of_local(fp, var_slot)->align, flat_type->tag, flat_type->size, flat_type->align));
			memcpy_fast(frame_var(fp, result_slot) + flat_offset, frame_var(fp, var_slot), flat_type->size);
			ADVANCE_IP(param_size(2));
		}
		ajla_assert(!frame_test_flag(fp, result_slot), (file_line, "record create (flat): flag already set for destination slot %"PRIuMAX"", (uintmax_t)result_slot));
	} else {
		struct data *result;
		def = type_def(t,record);
cat(create_record_no_flat_,ARG_MODE):
		result = data_alloc_record_mayfail(def, &ajla_error pass_file_line);
		if (unlikely(!result)) {
			ip = cat(free_parameters_,ARG_MODE)(fp, ip, n_entries);
			frame_set_pointer(fp, result_slot, pointer_error(ajla_error, fp, ip pass_file_line));
			break;
		}
		memset(da_record_frame(result), 0, bitmap_slots(def->n_slots) * slot_size);
		for (i = 0, ii = 0; i < n_entries; i++, ii++) {
			frame_t var_slot, record_slot;
			const struct type *rec_type, *var_type;

			while (unlikely(record_definition_is_elided(def, ii)))
				ii++;

			var_slot = get_param(ip, 0);
			record_slot = record_definition_slot(def, ii);
			rec_type = def->types[record_slot];
			var_type = frame_get_type_of_local(fp, var_slot);

			if (!frame_variable_is_flat(fp, var_slot)) {
				pointer_t ptr = frame_get_pointer_reference(fp, var_slot, (get_param(ip, 1) & OPCODE_FLAG_FREE_ARGUMENT) != 0);
				frame_set_pointer(da_record_frame(result), record_slot, ptr);
			} else if (TYPE_IS_FLAT(rec_type)) {
				ajla_assert(type_is_equal(var_type, rec_type), (file_line, "record create: copying between different types (%u,%u,%u) -> (%u,%u,%u)", var_type->tag, var_type->size, var_type->align, rec_type->tag, rec_type->size, rec_type->align));
				memcpy_fast(frame_var(da_record_frame(result), record_slot), frame_var(fp, var_slot), rec_type->size);
			} else {
				pointer_t ptr = flat_to_data(var_type, frame_var(fp, var_slot));
				frame_set_pointer(da_record_frame(result), record_slot, ptr);
			}

			ADVANCE_IP(param_size(2));
		}
		frame_set_pointer(fp, result_slot, pointer_data(result));
	}
#endif
DEFINE_OPCODE_END(OPCODE_RECORD_CREATE)

DEFINE_OPCODE_START(OPCODE_RECORD_LOAD)
#ifdef EMIT_CODE
	frame_t record, record_slot, result;
	unsigned flags;
	const struct type *t;
	record = get_i_param(0);
	record_slot = get_i_param(1);
	result = get_i_param(2);
	flags = get_i_param(3);

	t = frame_get_type_of_local(fp, record);
	if (t->tag == TYPE_TAG_flat_record && !frame_test_flag(fp, record)) {
		const struct flat_record_definition_entry *ft = &type_def(t,flat_record)->entries[record_slot];
		if (likely(TYPE_IS_FLAT(frame_get_type_of_local(fp, result)))) {
			memcpy_fast(frame_var(fp, result), frame_var(fp, record) + ft->flat_offset, ft->subtype->size);
		} else {
			pointer_t ptr = flat_to_data(ft->subtype, frame_var(fp, record) + ft->flat_offset);
			frame_set_pointer(fp, result, ptr);
		}
	} else {
		const struct type *rtype, *etype;
		struct data *data;
		frame_s *fr;
		pointer_follow(frame_pointer(fp, record), true, data, unlikely(flags & OPCODE_OP_FLAG_STRICT) ? PF_WAIT : PF_NOEVAL, fp, ip,
			if (!(flags & OPCODE_OP_FLAG_STRICT)) {
				ex_ = ipret_record_load_create_thunk(fp, ip, record, record_slot, result);
				if (ex_ == POINTER_FOLLOW_THUNK_GO)
					goto cat(record_load_end_,ARG_MODE);
			}
			RELOAD_EX_POSITION(ex_),
			thunk_reference(thunk_);
			frame_set_pointer(fp, result, pointer_thunk(thunk_));
			goto cat(record_load_end_,ARG_MODE);
		);
		rtype = da(data,record)->definition;
		etype = type_def(rtype,record)->types[record_slot];
		fr = da_record_frame(data);
		if (!frame_test_flag(fr, record_slot)) {
			 if (likely(TYPE_IS_FLAT(frame_get_type_of_local(fp, result)))) {
				memcpy_fast(frame_var(fp, result), frame_var(fr, record_slot), etype->size);
			 } else {
				pointer_t ptr = flat_to_data(etype, frame_var(fr, record_slot));
				frame_set_pointer(fp, result, ptr);
			 }
		} else {
			pointer_reference_maybe(fp, result, frame_pointer(fr, record_slot), flags);
		}
	}

cat(record_load_end_,ARG_MODE):
	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_RECORD_CREATE)

DEFINE_OPCODE_START(OPCODE_OPTION_CREATE_EMPTY_FLAT)
#ifdef EMIT_CODE
	frame_t slot_r = get_i_param(0);
	ajla_flat_option_t opt = (ajla_flat_option_t)get_i_param(1);
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "option create empty flat: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));
	barrier_aliasing();
	*frame_slot(fp, slot_r, ajla_flat_option_t) = opt;
	barrier_aliasing();
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_CREATE_EMPTY_FLAT)

DEFINE_OPCODE_START(OPCODE_OPTION_CREATE_EMPTY)
#ifdef EMIT_CODE
	struct data *d;
	frame_t slot_r;

	d = data_alloc(option, &ajla_error);
	slot_r = get_i_param(0);
	if (likely(d != NULL)) {
		da(d,option)->option = get_i_param(1);
		da(d,option)->pointer = pointer_empty();
		frame_set_pointer(fp, slot_r, pointer_data(d));
	} else {
		frame_set_pointer(fp, slot_r, pointer_error(ajla_error, fp, ip pass_file_line));
	}
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_CREATE_EMPTY)

DEFINE_OPCODE_START(OPCODE_OPTION_CREATE)
#ifdef EMIT_CODE
	struct data *d;
	frame_t slot_1, slot_r;
	pointer_t ptr;

	slot_1 = get_i_param(2);
	if (!frame_variable_is_flat(fp, slot_1)) {
		ptr = frame_get_pointer_reference(fp, slot_1, (get_i_param(3) & OPCODE_FLAG_FREE_ARGUMENT) != 0);
	} else {
		ptr = flat_to_data(frame_get_type_of_local(fp, slot_1), frame_var(fp, slot_1));
	}

	d = data_alloc(option, &ajla_error);
	slot_r = get_i_param(0);
	if (likely(d != NULL)) {
		da(d,option)->option = get_i_param(1);
		da(d,option)->pointer = ptr;
		frame_set_pointer(fp, slot_r, pointer_data(d));
	} else {
		pointer_dereference(ptr);
		frame_set_pointer(fp, slot_r, pointer_error(ajla_error, fp, ip pass_file_line));
	}
	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_CREATE)

DEFINE_OPCODE_START(OPCODE_OPTION_LOAD)
#ifdef EMIT_CODE
	frame_t option, option_idx, result;
	unsigned flags;
	struct data *data;
	pointer_t ptr;

	option = get_i_param(0);
	option_idx = get_i_param(1);
	result = get_i_param(2);
	flags = get_i_param(3);

	if (unlikely(frame_variable_is_flat(fp, option)))
		goto cat(option_load_mismatch,ARG_MODE);

	pointer_follow(frame_pointer(fp, option), true, data, unlikely(flags & OPCODE_OP_FLAG_STRICT) ? PF_WAIT : PF_NOEVAL, fp, ip,
		if (!(flags & OPCODE_OP_FLAG_STRICT)) {
			ex_ = ipret_option_load_create_thunk(fp, ip, option, option_idx, result);
			if (ex_ == POINTER_FOLLOW_THUNK_GO)
				goto cat(option_load_end_,ARG_MODE);
		}
		RELOAD_EX_POSITION(ex_),
		thunk_reference(thunk_);
		frame_set_pointer(fp, result, pointer_thunk(thunk_));
		goto cat(option_load_end_,ARG_MODE);
	);

	if (unlikely(da(data,option)->option != option_idx)) {
cat(option_load_mismatch,ARG_MODE):
		ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_OPTION_DOESNT_MATCH), fp, ip pass_file_line);
		frame_set_pointer(fp, result, ptr);
	} else {
		pointer_reference_maybe(fp, result, &da(data,option)->pointer, flags);
	}

cat(option_load_end_,ARG_MODE):
	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_LOAD)


START_BLOCK(
	frame_t slot_1;
	ajla_option_t option;
)

DEFINE_OPCODE_START(OPCODE_OPTION_TEST_FLAT)
#ifdef EMIT_CODE
	slot_1 = get_i_param(0);

	if (!frame_test_flag(fp, slot_1)) {
		barrier_aliasing();
		option = *frame_slot(fp, slot_1, ajla_flat_option_t);
		barrier_aliasing();
		goto cat(option_test_store_result_,ARG_MODE);
	}
	goto cat(option_test_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_TEST_FLAT)

DEFINE_OPCODE_START(OPCODE_OPTION_TEST)
#ifdef EMIT_CODE
	frame_t slot_r;
	pointer_t ptr;
	struct data *data;

	slot_1 = get_i_param(0);
cat(option_test_,ARG_MODE):
	ptr = *frame_pointer(fp, slot_1);
	if (unlikely(pointer_is_thunk(ptr))) {
		void *ex;
		ajla_assert(!frame_test_flag(fp, get_i_param(2)), (file_line, "option test: flag already set for destination slot %"PRIuMAX"", (uintmax_t)get_i_param(2)));
		ex = thunk_option_test(fp, ip, slot_1, get_i_param(1), get_i_param(2));
		if (ex == POINTER_FOLLOW_THUNK_GO) {
			ADVANCE_I_PARAM(3);
			break;
		} else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY)) {
			RELOAD_EX_POSITION(ex);
		}
		break;
	}
	data = pointer_get_data(ptr);
	option = da(data,option)->option;
cat(option_test_store_result_,ARG_MODE):
	slot_r = get_i_param(2);
	barrier_aliasing();
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "option test: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));
	*frame_slot(fp, slot_r, ajla_flat_option_t) = option == (ajla_option_t)get_i_param(1);
	barrier_aliasing();
	ADVANCE_I_PARAM(3);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_TEST)

DEFINE_OPCODE_START(OPCODE_OPTION_ORD_FLAT)
#ifdef EMIT_CODE
	slot_1 = get_i_param(0);

	if (!frame_test_flag(fp, slot_1)) {
		barrier_aliasing();
		option = *frame_slot(fp, slot_1, ajla_flat_option_t);
		barrier_aliasing();
		goto cat(option_ord_store_result_,ARG_MODE);
	}
	goto cat(option_ord_,ARG_MODE);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_ORD_FLAT)

DEFINE_OPCODE_START(OPCODE_OPTION_ORD)
#ifdef EMIT_CODE
	frame_t slot_r;
	pointer_t ptr;
	struct data *data;

	slot_1 = get_i_param(0);
cat(option_ord_,ARG_MODE):
	ptr = *frame_pointer(fp, slot_1);
	if (unlikely(pointer_is_thunk(ptr))) {
		void *ex;
		ajla_assert(!frame_test_flag(fp, get_i_param(1)), (file_line, "option ord: flag already set for destination slot %"PRIuMAX"", (uintmax_t)get_i_param(2)));
		ex = thunk_option_ord(fp, ip, slot_1, get_i_param(1));
		if (ex == POINTER_FOLLOW_THUNK_GO) {
			ADVANCE_I_PARAM(2);
			break;
		} else if (unlikely(ex != POINTER_FOLLOW_THUNK_RETRY)) {
			RELOAD_EX_POSITION(ex);
		}
		break;
	}
	data = pointer_get_data(ptr);
	option = da(data,option)->option;
cat(option_ord_store_result_,ARG_MODE):
	slot_r = get_i_param(1);
	barrier_aliasing();
	ajla_assert(!frame_test_flag(fp, slot_r), (file_line, "option ord: flag already set for destination slot %"PRIuMAX"", (uintmax_t)slot_r));
	*frame_slot(fp, slot_r, int_default_t) = option;
	barrier_aliasing();
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_OPTION_ORD)

END_BLOCK()


DEFINE_OPCODE_START(OPCODE_ARRAY_CREATE)
#ifdef EMIT_CODE
	frame_t result_slot;
	size_t n_entries;
	struct data *total;

	result_slot = get_i_param(0);
	n_entries = get_i_param(1);
	ADVANCE_I_PARAM(2);

	ajla_assert(n_entries != 0, (file_line, "array create: zero entries"));

	total = NULL;
	while (1) {
		size_t n, i;
		struct data *a;
		const struct type *type = frame_get_type_of_local(fp, get_param(ip, 0));
		bool flat = frame_variable_is_flat(fp, get_param(ip, 0));
		for (n = 1; n < n_entries; n++) {
			if (frame_variable_is_flat(fp, get_param(ip, n * 2)) != flat)
				break;
			if (unlikely((int_default_t)(n + 1) < zero))
				break;
		}
		do {
			if (flat)
				a = data_alloc_array_flat_mayfail(type, n, n, false, &ajla_error pass_file_line);
			else
				a = data_alloc_array_pointers_mayfail(n, n, &ajla_error pass_file_line);
		} while (unlikely(!a) && (n >>= 1));
		if (unlikely(!a)) {
			if (total)
				data_dereference(total);
			goto cat(array_create_error_,ARG_MODE);
		}
		n_entries -= n;
		if (flat) {
			unsigned char *flat_ptr = da_array_flat(a);
			for (i = 0; i < n; i++) {
				frame_t var_slot = get_param(ip, 0);
				memcpy_fast(flat_ptr, frame_var(fp, var_slot), type->size);
				flat_ptr += type->size;
				ADVANCE_IP(param_size(2));
			}
		} else {
			for (i = 0; i < n; i++) {
				frame_t var_slot = get_param(ip, 0);
				pointer_t ptr = frame_get_pointer_reference(fp, var_slot, (get_param(ip, 1) & OPCODE_FLAG_FREE_ARGUMENT) != 0);
				da(a,array_pointers)->pointer[i] = ptr;
				ADVANCE_IP(param_size(2));
			}
		}
		if (likely(!total)) {
			total = a;
		} else {
			total = array_join(total, a, &ajla_error);
			if (unlikely(!total)) {
cat(array_create_error_,ARG_MODE):
				ip = cat(free_parameters_,ARG_MODE)(fp, ip, n_entries);
				frame_set_pointer(fp, result_slot, pointer_error(ajla_error, fp, ip pass_file_line));
				break;
			}
		}
		if (likely(!n_entries)) {
			frame_set_pointer(fp, result_slot, pointer_data(total));
			break;
		}
	}
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_CREATE)

DEFINE_OPCODE_START(OPCODE_ARRAY_CREATE_EMPTY_FLAT)
#ifdef EMIT_CODE
	frame_t result_slot;
	struct data *a;
	const struct type *type = da(get_frame(fp)->function,function)->types[get_i_param(1)];
	TYPE_TAG_VALIDATE(type->tag);

	a = data_alloc_array_flat_mayfail(type, 0, 0, false, &ajla_error pass_file_line);
	result_slot = get_i_param(0);
	frame_set_pointer(fp, result_slot, likely(a != NULL) ? pointer_data(a) : pointer_error(ajla_error, fp, ip pass_file_line));
	ADVANCE_I_PARAM(2);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_CREATE_EMPTY_FLAT)

DEFINE_OPCODE_START(OPCODE_ARRAY_CREATE_EMPTY)
#ifdef EMIT_CODE
	frame_t result_slot;
	struct data *a;

	a = data_alloc_array_pointers_mayfail(0, 0, &ajla_error pass_file_line);
	result_slot = get_i_param(0);
	frame_set_pointer(fp, result_slot, likely(a != NULL) ? pointer_data(a) : pointer_error(ajla_error, fp, ip pass_file_line));
	ADVANCE_I_PARAM(1);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_CREATE_EMPTY)

DEFINE_OPCODE_START(OPCODE_ARRAY_FILL)
#ifdef EMIT_CODE
	frame_t content_slot, length_slot, result_slot;
	unsigned char content_flag;
	array_index_t length;
	pointer_t result_ptr;
	void *ex;

	content_slot = get_i_param(0);
	content_flag = get_i_param(1);
	length_slot = get_i_param(2);
	result_slot = get_i_param(3);

	ex = ipret_get_index(fp, ip, fp, length_slot, false, &length, &result_ptr pass_file_line);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION) {
			if (content_flag & OPCODE_FLAG_FREE_ARGUMENT)
				frame_free_and_clear(fp, content_slot);
			goto cat(array_fill_error_,ARG_MODE);
		}
		RELOAD_EX_POSITION(ex);
	}

	if (!frame_variable_is_flat(fp, content_slot)) {
		pointer_t ptr = frame_get_pointer_reference(fp, content_slot, (content_flag & OPCODE_FLAG_FREE_ARGUMENT) != 0);
		if (unlikely((content_flag & OPCODE_ARRAY_FILL_FLAG_SPARSE) != 0)) {
			result_ptr = array_create_sparse(length, ptr);
		} else {
			result_ptr = array_create(length, NULL, NULL, ptr);
		}
	} else {
		const struct type *type = frame_get_type_of_local(fp, content_slot);
		barrier_aliasing();
		if (unlikely((content_flag & OPCODE_ARRAY_FILL_FLAG_SPARSE) != 0) && likely(index_ge_int(length, 1))) {
			pointer_t ptr = flat_to_data(type, frame_var(fp, content_slot));
			result_ptr = array_create_sparse(length, ptr);
		} else {
			if (TYPE_IS_FLAT(frame_get_type_of_local(fp, result_slot))) {
				unsigned char *result = frame_var(fp, result_slot);
				int_default_t l = index_to_int(length);
				index_free(&length);
				while (l--) {
					result = mempcpy(result, frame_var(fp, content_slot), type->size);
				}
				goto cat(array_exit_,ARG_MODE);
			} else {
				result_ptr = array_create(length, type, frame_var(fp, content_slot), pointer_empty());
			}
		}
		barrier_aliasing();
	}

cat(array_fill_error_,ARG_MODE):
	frame_set_pointer(fp, result_slot, result_ptr);

cat(array_exit_,ARG_MODE):
	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_FILL)

DEFINE_OPCODE_START(OPCODE_ARRAY_STRING)
#ifdef EMIT_CODE
	frame_t result_slot, length;
	pointer_t result_ptr;

	result_slot = get_i_param(0);
	length = get_i_param(1);
	ADVANCE_I_PARAM(2);

	if (unlikely((int_default_t)length < (int_default_t)zero) ||
	    unlikely((frame_t)(int_default_t)length != length)) {
		result_ptr = pointer_error(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), fp, ip pass_file_line);
	} else {
		result_ptr = array_string(length, type_get_fixed(0, true), cast_ptr(unsigned char *, ip));
	}
	frame_set_pointer(fp, result_slot, result_ptr);

	ADVANCE_IP((length + 1) >> 1);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_STRING)

DEFINE_OPCODE_START(OPCODE_ARRAY_UNICODE)
#ifdef EMIT_CODE
	frame_t result_slot, length;
	pointer_t result_ptr;

	result_slot = get_i_param(0);
	length = get_i_param(1);
	ADVANCE_I_PARAM(2);

	if (unlikely((int_default_t)length < (int_default_t)zero) ||
	    unlikely((frame_t)(int_default_t)length != length)) {
		result_ptr = pointer_error(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), fp, ip pass_file_line);
	} else {
		result_ptr = array_string(length, type_get_int(2), cast_ptr(unsigned char *, ip));
	}
	frame_set_pointer(fp, result_slot, result_ptr);

	ADVANCE_IP(length * 2);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_STRING)

DEFINE_OPCODE_START(OPCODE_ARRAY_LOAD)
#ifdef EMIT_CODE
	frame_t array, idx, result;
	unsigned flags;
	const struct type *t, *t_elem;
	void *ex;
	array_index_t array_index;
	pointer_t ptr;
	unsigned char *flat;

	array = get_i_param(0);
	idx = get_i_param(1);
	result = get_i_param(2);
	flags = get_i_param(3);

	ex = ipret_get_index(fp, ip, fp, idx, false, &array_index, &ptr pass_file_line);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION)
			goto cat(array_load_set_ptr_,ARG_MODE);
		RELOAD_EX_POSITION(ex);
	}

	t = frame_get_type_of_local(fp, array);
	if (t->tag == TYPE_TAG_flat_array && !frame_test_flag(fp, array)) {
		const struct flat_array_definition *def = type_def(t,flat_array);
		if (unlikely(index_ge_int(array_index, def->n_elements))) {
			index_free(&array_index);
			ptr = pointer_error(error_ajla(EC_SYNC, AJLA_ERROR_INDEX_OUT_OF_RANGE), fp, ip pass_file_line);
			goto cat(array_load_set_ptr_,ARG_MODE);
		}
		t_elem = def->base;
		flat = frame_var(fp, array) + t_elem->size * index_to_int(array_index);
		index_free(&array_index);
		goto cat(array_load_set_flat_,ARG_MODE);
	} else {
		pointer_t *array_ptr = frame_pointer(fp, array);
		pointer_t *pptr;
		struct data *data;

cat(array_restart_pointer_follow_,ARG_MODE):
		pointer_follow(array_ptr, false, data, unlikely(flags & OPCODE_OP_FLAG_STRICT) ? PF_WAIT : PF_NOEVAL, fp, ip,
			index_free(&array_index);
			if (!(flags & OPCODE_OP_FLAG_STRICT)) {
				ex_ = ipret_array_load_create_thunk(fp, ip, array, idx, result);
				if (ex_ == POINTER_FOLLOW_THUNK_GO)
					goto cat(array_load_end_,ARG_MODE);
			}
			RELOAD_EX_POSITION(ex_),
			index_free(&array_index);
			thunk_reference(thunk_);
			ptr = pointer_thunk(thunk_);
			goto cat(array_load_set_ptr_,ARG_MODE);
		);

		if (unlikely(da_tag(data) == DATA_TAG_array_incomplete)) {
			array_index_t len_first;

			if (array_ptr == frame_pointer(fp, array)) {
				if (!frame_test_and_set_flag(fp, array))
					data_reference(data);
				if (array_incomplete_collapse(array_ptr))
					goto cat(array_restart_pointer_follow_,ARG_MODE);
			}

			len_first = array_len(pointer_get_data(da(data,array_incomplete)->first));
			if (!index_ge_index(array_index, len_first)) {
				index_free(&len_first);
				data = pointer_get_data(da(data,array_incomplete)->first);
			} else {
				index_sub(&array_index, len_first);
				index_free(&len_first);
				array_ptr = &da(data,array_incomplete)->next;
				goto cat(array_restart_pointer_follow_,ARG_MODE);
			}
		}

		if (unlikely(!array_read(data, array_index, &pptr, &flat, &t_elem, NULL, &ajla_error))) {
			ptr = pointer_error(ajla_error, fp, ip pass_file_line);
			goto cat(array_load_set_ptr_,ARG_MODE);
		}
		if (pptr) {
			pointer_reference_maybe(fp, result, pptr, flags);
			goto cat(array_load_end_,ARG_MODE);
		} else {
cat(array_load_set_flat_,ARG_MODE):
			 if (likely(TYPE_IS_FLAT(frame_get_type_of_local(fp, result)))) {
				memcpy_fast(frame_var(fp, result), flat, t_elem->size);
				goto cat(array_load_end_,ARG_MODE);
			 } else {
				ptr = flat_to_data(t_elem, flat);
			 }
		}
	}

cat(array_load_set_ptr_,ARG_MODE):
	frame_set_pointer(fp, result, ptr);

cat(array_load_end_,ARG_MODE):
	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_LOAD)

DEFINE_OPCODE_START(OPCODE_ARRAY_LEN)
#ifdef EMIT_CODE
	frame_t slot_a, slot_r;
	unsigned flags;
	void *ex;

	slot_a = get_i_param(0);
	slot_r = get_i_param(1);
	flags = get_i_param(2);

	ex = ipret_array_len(fp, ip, slot_r, slot_a, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(3);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_LEN)

DEFINE_OPCODE_START(OPCODE_ARRAY_LEN_ATLEAST)
#ifdef EMIT_CODE
	frame_t slot_a, slot_l, slot_r;
	unsigned flags;
	void *ex;

	slot_a = get_i_param(0);
	slot_l = get_i_param(1);
	slot_r = get_i_param(2);
	flags = get_i_param(3);

	ex = ipret_array_len_atleast(fp, ip, slot_r, slot_a, slot_l, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_LEN_ATLEAST)

DEFINE_OPCODE_START(OPCODE_ARRAY_SUB)
#ifdef EMIT_CODE
	frame_t slot_a, slot_start, slot_end, slot_r;
	unsigned flags;
	void *ex;

	slot_a = get_i_param(0);
	slot_start = get_i_param(1);
	slot_end = get_i_param(2);
	slot_r = get_i_param(3);
	flags = get_i_param(4);

	ex = ipret_array_sub(fp, ip, slot_r, slot_a, slot_start, slot_end, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(5);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_SUB)

DEFINE_OPCODE_START(OPCODE_ARRAY_SKIP)
#ifdef EMIT_CODE
	frame_t slot_a, slot_start, slot_r;
	unsigned flags;
	void *ex;

	slot_a = get_i_param(0);
	slot_start = get_i_param(1);
	slot_r = get_i_param(2);
	flags = get_i_param(3);

	ex = ipret_array_skip(fp, ip, slot_r, slot_a, slot_start, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_SKIP)

DEFINE_OPCODE_START(OPCODE_ARRAY_APPEND)
#ifdef EMIT_CODE
	frame_t slot_r, slot_1, slot_2;
	unsigned flags;
	void *ex;

	slot_r = get_i_param(0);
	flags = get_i_param(1);
	slot_1 = get_i_param(2);
	slot_2 = get_i_param(3);

	ex = ipret_array_append(fp, ip, slot_r, slot_1, slot_2, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_APPEND)

DEFINE_OPCODE_START(OPCODE_ARRAY_APPEND_ONE_FLAT)
#ifdef EMIT_CODE
	frame_t slot_r, slot_1, slot_2;
	unsigned flags;
	void *ex;

	slot_r = get_i_param(0);
	flags = get_i_param(1);
	slot_1 = get_i_param(2);
	slot_2 = get_i_param(3);

	ex = ipret_array_append_one_flat(fp, ip, slot_r, slot_1, slot_2, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_APPEND_ONE_FLAT)

DEFINE_OPCODE_START(OPCODE_ARRAY_APPEND_ONE)
#ifdef EMIT_CODE
	frame_t slot_r, slot_1, slot_2;
	unsigned flags;
	void *ex;

	slot_r = get_i_param(0);
	flags = get_i_param(1);
	slot_1 = get_i_param(2);
	slot_2 = get_i_param(3);

	ex = ipret_array_append_one(fp, ip, slot_r, slot_1, slot_2, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(4);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_APPEND_ONE)

DEFINE_OPCODE_START(OPCODE_ARRAY_FLATTEN)
#ifdef EMIT_CODE
	frame_t slot_r, slot_1;
	unsigned flags;
	void *ex;

	slot_r = get_i_param(0);
	flags = get_i_param(1);
	slot_1 = get_i_param(2);

	ex = ipret_array_flatten(fp, ip, slot_r, slot_1, flags);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO))
		RELOAD_EX_POSITION(ex);

	ADVANCE_I_PARAM(3);
#endif
DEFINE_OPCODE_END(OPCODE_ARRAY_FLATTEN)


#if ARG_MODE == 0
DEFINE_OPCODE_START(OPCODE_IO)
#ifdef EMIT_CODE
	unsigned char io_code, n_outputs, n_inputs, n_params;
	void *ex;

	io_code = get_i_param(0);
	n_outputs = get_i_param(1);
	n_inputs = get_i_param(2);
	n_params = get_i_param(3);

	ex = ipret_io(fp, ip, io_code, n_outputs, n_inputs, n_params);
	if (ex != POINTER_FOLLOW_THUNK_GO) {
		RELOAD_EX_POSITION(ex);
	} else {
		ADVANCE_IP(3 + 2 * (n_outputs + n_inputs + n_params));
	}
#endif
DEFINE_OPCODE_END(OPCODE_IO)
#endif

#if ARG_MODE == 0
DEFINE_OPCODE_START(OPCODE_INTERNAL_FUNCTION)
#ifdef EMIT_CODE
	void *ex = function_call_internal(fp, ip);
	if (ex != POINTER_FOLLOW_THUNK_RETRY) {
		RELOAD_EX_POSITION(ex);
	}
#endif
DEFINE_OPCODE_END(OPCODE_INTERNAL_FUNCTION)
#endif

#if ARG_MODE == 0
DEFINE_OPCODE_START(OPCODE_UNREACHABLE)
#ifdef EMIT_CODE
	internal(file_line, "unreachable code");
#endif
DEFINE_OPCODE_END(OPCODE_UNREACHABLE)
#endif

#if ARG_MODE == 0
DEFINE_OPCODE_START(OPCODE_EXIT_THREAD)
#ifdef EMIT_CODE
	struct execution_control *ex = frame_execution_control(fp);
	pointer_t *var_ptr = frame_pointer(fp, get_i_param(0));
	struct data attr_unused *data;

	pointer_follow(var_ptr, true, data, PF_WAIT, fp, ip,
		RELOAD_EX_POSITION(ex_),
		ajla_assert_lo(thunk_tag(thunk_) == THUNK_TAG_EXCEPTION, (file_line, "exit_thread: invalid thunk tag %u", thunk_tag(thunk_)));
		goto exit_ipret_thunk;
	);

exit_ipret_thunk:
	ajla_assert_lo(ex->thunk == NULL, (file_line, "exit_thread: non-NULL thunk %p", ex->thunk));
	ex->current_frame = fp;
	ex->current_ip = frame_ip(fp, ip);
	execution_control_terminate(ex, *var_ptr);
	goto exit_ipret;
#endif
DEFINE_OPCODE_END(OPCODE_EXIT_THREAD)
#endif


#undef move_scalar
#undef copy_scalar

#undef get_param
#undef param_size
#undef get_i_param
#undef ADVANCE_I_PARAM

#undef ARG_MODE
#undef DEFINE_OPCODE_START
