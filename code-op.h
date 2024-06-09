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

#ifndef AJLA_OPCODE_H
#define AJLA_OPCODE_H

typedef uint16_t code_t;

#define OPCODE_MASK		0xffff

#define OPCODE_OP_FLAG_STRICT			0x0001
#define OPCODE_FLAG_FREE_ARGUMENT		0x0002
#define OPCODE_FLAG_FREE_ARGUMENT_2		0x0004
#define OPCODE_CALL_MAY_LEND			0x0004	/* OPCODE_FLAG_FREE_ARGUMENT must not be set */
#define OPCODE_CALL_MAY_GIVE			0x0008	/* OPCODE_FLAG_FREE_ARGUMENT must be set */
#define OPCODE_ARRAY_FILL_FLAG_SPARSE		0x0004
#define OPCODE_STRUCT_MAY_BORROW		0x0008
#define FLAG_NEED_BOTH_EXCEPTIONS_TO_FAIL	0x0100	/* not used in code, used internally in ipret.c */
#define FLAG_FIRST_EXCEPTION			0x0200	/* not used in code, used internally in ipret.c */
#define FLAG_TESTING_FOR_EXCEPTION		0x0400	/* not used in code, used internally in ipret.c */
#define OPCODE_MAY_RETURN_FLAT			0x0001

#define OPCODE_FIXED_OP_MULT		1
#define OPCODE_FIXED_OP_add			0
#define OPCODE_FIXED_OP_subtract		1
#define OPCODE_FIXED_OP_multiply		2
#define OPCODE_FIXED_OP_divide			3
#define OPCODE_FIXED_OP_divide_alt1		4
#define OPCODE_FIXED_OP_udivide			5
#define OPCODE_FIXED_OP_udivide_alt1		6
#define OPCODE_FIXED_OP_modulo			7
#define OPCODE_FIXED_OP_modulo_alt1		8
#define OPCODE_FIXED_OP_umodulo			9
#define OPCODE_FIXED_OP_umodulo_alt1		10
#define OPCODE_FIXED_OP_power			11
#define OPCODE_FIXED_OP_and			12
#define OPCODE_FIXED_OP_or			13
#define OPCODE_FIXED_OP_xor			14
#define OPCODE_FIXED_OP_shl			15
#define OPCODE_FIXED_OP_shr			16
#define OPCODE_FIXED_OP_ushr			17
#define OPCODE_FIXED_OP_rol			18
#define OPCODE_FIXED_OP_ror			19
#define OPCODE_FIXED_OP_bts			20
#define OPCODE_FIXED_OP_btr			21
#define OPCODE_FIXED_OP_btc			22
#define OPCODE_FIXED_OP_equal			23
#define OPCODE_FIXED_OP_not_equal		24
#define OPCODE_FIXED_OP_less			25
#define OPCODE_FIXED_OP_less_equal		26
#define OPCODE_FIXED_OP_uless			27
#define OPCODE_FIXED_OP_uless_equal		28
#define OPCODE_FIXED_OP_bt			29
#define OPCODE_FIXED_OP_UNARY			 30
#define OPCODE_FIXED_OP_not			30
#define OPCODE_FIXED_OP_neg			31
#define OPCODE_FIXED_OP_inc			32
#define OPCODE_FIXED_OP_dec			33
#define OPCODE_FIXED_OP_bswap			34
#define OPCODE_FIXED_OP_bswap_alt1		35
#define OPCODE_FIXED_OP_brev			36
#define OPCODE_FIXED_OP_brev_alt1		37
#define OPCODE_FIXED_OP_bsf			38
#define OPCODE_FIXED_OP_bsf_alt1		39
#define OPCODE_FIXED_OP_bsr			40
#define OPCODE_FIXED_OP_bsr_alt1		41
#define OPCODE_FIXED_OP_popcnt			42
#define OPCODE_FIXED_OP_popcnt_alt1		43
#define OPCODE_FIXED_OP_to_int			44
#define OPCODE_FIXED_OP_uto_int			45
#define OPCODE_FIXED_OP_from_int		46
#define OPCODE_FIXED_OP_ufrom_int		47
#define OPCODE_FIXED_OP_N			 48
#define OPCODE_FIXED_OP_move			48
#define OPCODE_FIXED_OP_copy			49
#define OPCODE_FIXED_OP_ldc			50
#define OPCODE_FIXED_OP_ldc16			51

#define OPCODE_FIXED_TYPE_MULT		52
#define OPCODE_FIXED_TYPE_int8_t		0
#define OPCODE_FIXED_TYPE_int16_t		1
#define OPCODE_FIXED_TYPE_int32_t		2
#define OPCODE_FIXED_TYPE_int64_t		3
#define OPCODE_FIXED_TYPE_int128_t		4

#define OPCODE_INT_OP_MULT		1
#define OPCODE_INT_OP_add			0
#define OPCODE_INT_OP_subtract			1
#define OPCODE_INT_OP_multiply			2
#define OPCODE_INT_OP_divide			3
#define OPCODE_INT_OP_divide_alt1		4
#define OPCODE_INT_OP_modulo			5
#define OPCODE_INT_OP_modulo_alt1		6
#define OPCODE_INT_OP_power			7
#define OPCODE_INT_OP_and			8
#define OPCODE_INT_OP_or			9
#define OPCODE_INT_OP_xor			10
#define OPCODE_INT_OP_shl			11
#define OPCODE_INT_OP_shr			12
#define OPCODE_INT_OP_bts			13
#define OPCODE_INT_OP_btr			14
#define OPCODE_INT_OP_btc			15
#define OPCODE_INT_OP_equal			16
#define OPCODE_INT_OP_not_equal			17
#define OPCODE_INT_OP_less			18
#define OPCODE_INT_OP_less_equal		19
#define OPCODE_INT_OP_bt			20
#define OPCODE_INT_OP_UNARY			 21
#define OPCODE_INT_OP_not			21
#define OPCODE_INT_OP_neg			22
#define OPCODE_INT_OP_inc			23
#define OPCODE_INT_OP_dec			24
#define OPCODE_INT_OP_bsf			25
#define OPCODE_INT_OP_bsr			26
#define OPCODE_INT_OP_popcnt			27
#define OPCODE_INT_OP_popcnt_alt1		28
#define OPCODE_INT_OP_to_int			29
#define OPCODE_INT_OP_from_int			30
#define OPCODE_INT_OP_N				 31
#define OPCODE_INT_OP_move			31
#define OPCODE_INT_OP_copy			32
#define OPCODE_INT_OP_ldc			33
#define OPCODE_INT_OP_ldc16			34

#define OPCODE_INT_TYPE_MULT		35
#define OPCODE_INT_TYPE_int8_t			0
#define OPCODE_INT_TYPE_int16_t			1
#define OPCODE_INT_TYPE_int32_t			2
#define OPCODE_INT_TYPE_int64_t			3
#define OPCODE_INT_TYPE_int128_t		4

#define OPCODE_REAL_OP_MULT		1
#define OPCODE_REAL_OP_add			0
#define OPCODE_REAL_OP_add_alt1			1
#define OPCODE_REAL_OP_add_alt2			2
#define OPCODE_REAL_OP_subtract			3
#define OPCODE_REAL_OP_subtract_alt1		4
#define OPCODE_REAL_OP_subtract_alt2		5
#define OPCODE_REAL_OP_multiply			6
#define OPCODE_REAL_OP_multiply_alt1		7
#define OPCODE_REAL_OP_multiply_alt2		8
#define OPCODE_REAL_OP_divide			9
#define OPCODE_REAL_OP_divide_alt1		10
#define OPCODE_REAL_OP_divide_alt2		11
#define OPCODE_REAL_OP_modulo			12
#define OPCODE_REAL_OP_power			13
#define OPCODE_REAL_OP_ldexp			14
#define OPCODE_REAL_OP_atan2			15
#define OPCODE_REAL_OP_equal			16
#define OPCODE_REAL_OP_equal_alt1		17
#define OPCODE_REAL_OP_equal_alt2		18
#define OPCODE_REAL_OP_not_equal		19
#define OPCODE_REAL_OP_not_equal_alt1		20
#define OPCODE_REAL_OP_not_equal_alt2		21
#define OPCODE_REAL_OP_less			22
#define OPCODE_REAL_OP_less_alt1		23
#define OPCODE_REAL_OP_less_alt2		24
#define OPCODE_REAL_OP_less_equal		25
#define OPCODE_REAL_OP_less_equal_alt1		26
#define OPCODE_REAL_OP_less_equal_alt2		27
#define OPCODE_REAL_OP_UNARY			 28
#define OPCODE_REAL_OP_neg			28
#define OPCODE_REAL_OP_neg_alt1			29
#define OPCODE_REAL_OP_neg_alt2			30
#define OPCODE_REAL_OP_sqrt			31
#define OPCODE_REAL_OP_sqrt_alt1		32
#define OPCODE_REAL_OP_sqrt_alt2		33
#define OPCODE_REAL_OP_cbrt			35
#define OPCODE_REAL_OP_sin			36
#define OPCODE_REAL_OP_cos			37
#define OPCODE_REAL_OP_tan			38
#define OPCODE_REAL_OP_asin			39
#define OPCODE_REAL_OP_acos			40
#define OPCODE_REAL_OP_atan			41
#define OPCODE_REAL_OP_sinh			42
#define OPCODE_REAL_OP_cosh			43
#define OPCODE_REAL_OP_tanh			44
#define OPCODE_REAL_OP_asinh			45
#define OPCODE_REAL_OP_acosh			46
#define OPCODE_REAL_OP_atanh			47
#define OPCODE_REAL_OP_exp2			48
#define OPCODE_REAL_OP_exp			49
#define OPCODE_REAL_OP_exp10			50
#define OPCODE_REAL_OP_log2			51
#define OPCODE_REAL_OP_log			52
#define OPCODE_REAL_OP_log10			53
#define OPCODE_REAL_OP_round			54
#define OPCODE_REAL_OP_ceil			55
#define OPCODE_REAL_OP_floor			56
#define OPCODE_REAL_OP_trunc			57
#define OPCODE_REAL_OP_fract			58
#define OPCODE_REAL_OP_mantissa			59
#define OPCODE_REAL_OP_exponent			60
#define OPCODE_REAL_OP_next_number		61
#define OPCODE_REAL_OP_prev_number		62
#define OPCODE_REAL_OP_to_int			63
#define OPCODE_REAL_OP_to_int_alt1		64
#define OPCODE_REAL_OP_to_int_alt2		65
#define OPCODE_REAL_OP_from_int			66
#define OPCODE_REAL_OP_from_int_alt1		67
#define OPCODE_REAL_OP_from_int_alt2		68
#define OPCODE_REAL_OP_is_exception		69
#define OPCODE_REAL_OP_is_exception_alt1	70
#define OPCODE_REAL_OP_is_exception_alt2	71
#define OPCODE_REAL_OP_N			 72
#define OPCODE_REAL_OP_move			72
#define OPCODE_REAL_OP_copy			73
#define OPCODE_REAL_OP_ldc			74

#define OPCODE_REAL_TYPE_MULT		75
#define OPCODE_REAL_TYPE_real16_t		0
#define OPCODE_REAL_TYPE_real32_t		1
#define OPCODE_REAL_TYPE_real64_t		2
#define OPCODE_REAL_TYPE_real80_t		3
#define OPCODE_REAL_TYPE_real128_t		4

#define OPCODE_BOOL_OP_MULT		1
#define OPCODE_BOOL_OP_and			0
#define OPCODE_BOOL_OP_or			1
#define OPCODE_BOOL_OP_equal			2
#define OPCODE_BOOL_OP_not_equal		3
#define OPCODE_BOOL_OP_less			4
#define OPCODE_BOOL_OP_less_equal		5
#define OPCODE_BOOL_OP_UNARY			 6
#define OPCODE_BOOL_OP_not			6
#define OPCODE_BOOL_OP_N			 7
#define OPCODE_BOOL_OP_move			7
#define OPCODE_BOOL_OP_copy			8

#define OPCODE_BOOL_TYPE_MULT		9

#define OPCODE_FIXED_OP			0
#define OPCODE_INT_OP			(OPCODE_FIXED_OP + OPCODE_FIXED_TYPE_MULT * TYPE_FIXED_N)
#define OPCODE_REAL_OP			(OPCODE_INT_OP + OPCODE_INT_TYPE_MULT * TYPE_INT_N)
#define OPCODE_BOOL_OP			(OPCODE_REAL_OP + OPCODE_REAL_TYPE_MULT * TYPE_REAL_N)
#define OPCODE_EXTRA			(OPCODE_BOOL_OP + OPCODE_BOOL_TYPE_MULT)

enum {
	OPCODE_INT_LDC_LONG = OPCODE_EXTRA,
	OPCODE_IS_EXCEPTION,		/* src, dest, strict flag */
	OPCODE_EXCEPTION_CLASS,		/* src, dest, strict flag */
	OPCODE_EXCEPTION_TYPE,		/* src, dest, strict flag */
	OPCODE_EXCEPTION_AUX,		/* src, dest, strict flag */
	OPCODE_SYSTEM_PROPERTY,		/* src, dest, strict flag */
	OPCODE_FLAT_MOVE,
	OPCODE_FLAT_COPY,
	OPCODE_REF_MOVE,
	OPCODE_REF_MOVE_CLEAR,
	OPCODE_REF_COPY,
	OPCODE_BOX_MOVE_CLEAR,
	OPCODE_BOX_COPY,
	OPCODE_TAKE_BORROWED,
	OPCODE_DEREFERENCE,
	OPCODE_DEREFERENCE_CLEAR,
	OPCODE_EVAL,
	OPCODE_CHECKPOINT,
	OPCODE_JMP,
	OPCODE_JMP_BACK_16,
	OPCODE_JMP_FALSE,		/* var, false_offset*2, exception_offset*2 */
	OPCODE_LABEL,
	OPCODE_LOAD_FN,			/* n_arg, result, fn_idx,		[arg_var, arg_deref] */
	OPCODE_CURRY,			/* n_arg, result, fn_thunk, fn_deref,	[arg_var, arg_deref] */
	OPCODE_CALL,			/* n_arg, n_ret, fn_idx,		[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_STRICT,		/* n_arg, n_ret, fn_idx,		[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_SPARK,		/* n_arg, n_ret, fn_idx,		[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_LAZY,		/* n_arg, n_ret, fn_idx,		[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_CACHE,		/* n_arg, n_ret, fn_idx,		[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_SAVE,		/* n_arg, n_ret, fn_idx,		[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_INDIRECT,		/* n_arg, n_ret, fn_thunk, fn_deref,	[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_INDIRECT_STRICT,	/* n_arg, n_ret, fn_thunk, fn_deref,	[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_INDIRECT_SPARK,	/* n_arg, n_ret, fn_thunk, fn_deref,	[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_INDIRECT_LAZY,	/* n_arg, n_ret, fn_thunk, fn_deref,	[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_INDIRECT_CACHE,	/* n_arg, n_ret, fn_thunk, fn_deref,	[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_CALL_INDIRECT_SAVE,	/* n_arg, n_ret, fn_thunk, fn_deref,	[arg_var, arg_deref], [ret_var(32), ret_flag(16)] */
	OPCODE_RETURN,			/* val, arg_deref ... */
	OPCODE_STRUCTURED,		/* struct, element ... */
#define  OPCODE_STRUCTURED_RECORD		0x01	/* + element_slot, record_type */
#define  OPCODE_STRUCTURED_OPTION		0x02	/* + option,	   nothing */
#define  OPCODE_STRUCTURED_ARRAY		0x03	/* + index_slot,   nothing */
#define  OPCODE_STRUCTURED_MASK			0x0f
#define  OPCODE_STRUCTURED_FREE_VARIABLE	0x10
#define  OPCODE_STRUCTURED_FLAG_END		0x20
	OPCODE_RECORD_CREATE,		/* result, n_entries, [entry_var, arg_deref] */
	OPCODE_RECORD_LOAD,		/* record, slot, result, (strict_flag | borrow_flag) */
	OPCODE_OPTION_CREATE_EMPTY_FLAT,/* result, option */
	OPCODE_OPTION_CREATE_EMPTY,	/* result, option */
	OPCODE_OPTION_CREATE,		/* result, option, arg_var, arg_deref */
	OPCODE_OPTION_LOAD,		/* option, idx, result, (strict_flag | borrow_flag) */
	OPCODE_OPTION_TEST_FLAT,	/* var, option, result */
	OPCODE_OPTION_TEST,		/* var, option, result */
	OPCODE_OPTION_ORD_FLAT,		/* var, result */
	OPCODE_OPTION_ORD,		/* var, result */
	OPCODE_ARRAY_CREATE,		/* result, n_entries, [entry_var, arg_deref] */
	OPCODE_ARRAY_CREATE_EMPTY_FLAT,	/* result, local_type */
	OPCODE_ARRAY_CREATE_EMPTY,	/* result */
	OPCODE_ARRAY_FILL,		/* content_var, content_deref | flag_sparse, length_var, result */
	OPCODE_ARRAY_STRING,		/* result, length, [chars] */
	OPCODE_ARRAY_UNICODE,		/* result, length, [chars] */
	OPCODE_ARRAY_LOAD,		/* array, idx slot, result, (strict_flag | borrow_flag) */
	OPCODE_ARRAY_LEN,		/* array, result, strict_flag */
	OPCODE_ARRAY_LEN_GREATER_THAN,	/* array, size, result, strict_flag */
	OPCODE_ARRAY_SUB,		/* array, start, end, result, strict_flags | deref */
	OPCODE_ARRAY_SKIP,		/* array, start, result, strict_flags | deref */
	OPCODE_ARRAY_APPEND,		/* result, arg_deref1 | arg_deref2, arg1, arg2 */
	OPCODE_ARRAY_APPEND_ONE_FLAT,	/* result, arg_deref1 | arg_deref2, arg1, arg2 */
	OPCODE_ARRAY_APPEND_ONE,	/* result, arg_deref1 | arg_deref2, arg1, arg2 */
	OPCODE_ARRAY_FLATTEN,		/* result, arg_deref1, arg1 */
	OPCODE_IO,			/* (code, n_outputs, n_inputs, n_params), 32-bit: outputs, inputs, params */
	OPCODE_INTERNAL_FUNCTION,
	OPCODE_EXIT_THREAD,
	OPCODE_UNREACHABLE,
	OPCODE_N,
};

enum {
	OPCODE_MODE_MULT_0 = (OPCODE_N - 1),
	OPCODE_MODE_MULT_1 = (OPCODE_MODE_MULT_0 | (OPCODE_MODE_MULT_0 >> 1)),
	OPCODE_MODE_MULT_2 = (OPCODE_MODE_MULT_1 | (OPCODE_MODE_MULT_1 >> 2)),
	OPCODE_MODE_MULT_4 = (OPCODE_MODE_MULT_2 | (OPCODE_MODE_MULT_2 >> 4)),
	OPCODE_MODE_MULT_8 = (OPCODE_MODE_MULT_4 | (OPCODE_MODE_MULT_4 >> 8)),
	OPCODE_MODE_MULT = OPCODE_MODE_MULT_8 + 1,
};

#endif
