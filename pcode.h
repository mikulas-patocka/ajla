/*
 * Copyright (C) 2024 - 2026 Mikulas Patocka
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

#ifndef AJLA_PCODE_H
#define AJLA_PCODE_H

#include "data.h"

#define pcode_get_type				name(pcode_get_type)
#define pcode_generate_blob_from_value		name(pcode_generate_blob_from_value)
#define pcode_decode_real			name(pcode_decode_real)
#define pcode_build_function_from_builtin	name(pcode_build_function_from_builtin)
#define pcode_build_function_from_array		name(pcode_build_function_from_array)
#define pcode_array_from_builtin		name(pcode_array_from_builtin)
#define pcode_build_eval_function		name(pcode_build_eval_function)
#define pcode_find_op_function			name(pcode_find_op_function)
#define pcode_find_is_exception			name(pcode_find_is_exception)
#define pcode_find_get_exception		name(pcode_find_get_exception)
#define pcode_find_array_load_function		name(pcode_find_array_load_function)
#define pcode_find_array_len_function		name(pcode_find_array_len_function)
#define pcode_find_array_len_greater_than_function	name(pcode_find_array_len_greater_than_function)
#define pcode_find_array_sub_function		name(pcode_find_array_sub_function)
#define pcode_find_array_skip_function		name(pcode_find_array_skip_function)
#define pcode_find_array_append_function	name(pcode_find_array_append_function)
#define pcode_find_option_ord_function		name(pcode_find_option_ord_function)
#define pcode_find_record_option_load_function	name(pcode_find_record_option_load_function)
#define pcode_build_internal_functions		name(pcode_build_internal_functions)

#define Op_IsBool(op)			((op) == Bin_Equal || (op) == Bin_NotEqual || (op) == Bin_Less || (op) == Bin_LessEqual || (op) == Bin_Greater || (op) == Bin_GreaterEqual || (op) == Bin_Bt || (op) == Un_IsException)
#define Op_IsInt(op)			((op) == Un_ConvertToInt || (op) == Un_ExceptionClass || (op) == Un_ExceptionType || (op) == Un_ExceptionAux)
#define Op_IsReal(op)			((op) >= Un_ConvertToReal16 && (op) <= Un_ConvertToReal128)
#define Op_IsTernary(op)		((op) >= Tern_FMA && (op) <= Tern_FNMS)
#define Op_IsBinary(op)			((op) >= Bin_Add && (op) <= Bin_Bt)
#define Op_IsUnary(op)			((op) >= Un_Not && (op) <= Un_SystemProperty)

const struct type *pcode_get_type(pcode_t q);
bool pcode_generate_blob_from_value(pointer_t ptr, pcode_t pcode_type, pcode_t **res_blob, size_t *res_len, ajla_error_t *err);
bool pcode_decode_real(const struct type *type, const uint8_t *blob, size_t blob_l, uint8_t **result, ajla_error_t *err);
void *pcode_build_function_from_builtin(frame_s *f, const code_t *ip, union internal_arg arguments[]);
void *pcode_build_function_from_array(frame_s *fp, const code_t *ip, union internal_arg arguments[]);
void *pcode_array_from_builtin(frame_s *fp, const code_t *ip, union internal_arg arguments[]);
pointer_t pcode_build_eval_function(pcode_t src_type, pcode_t dest_type, pcode_t op, pcode_t *blob_1, size_t blob_1_len, pcode_t *blob_2, size_t blob_2_len, pcode_t *blob_3, size_t blob_3_len, ajla_error_t *err);

#define PCODE_FIND_OP_UNARY	0x1
#define PCODE_FIND_OP_BINARY	0x2
#define PCODE_FIND_OP_TERNARY	0x4
#define PCODE_CONVERT_FROM_INT	0x8
void attr_fastcall pcode_find_op_function(const struct type *type, const struct type *rtype, code_t code, unsigned flags, struct function_pointer **result);
void attr_fastcall pcode_find_is_exception(struct function_pointer **result);
void attr_fastcall pcode_find_get_exception(unsigned mode, struct function_pointer **result);

void attr_fastcall pcode_find_array_load_function(struct function_pointer **result);
void attr_fastcall pcode_find_array_len_function(bool finite, struct function_pointer **result);
void attr_fastcall pcode_find_array_len_greater_than_function(struct function_pointer **result);
void attr_fastcall pcode_find_array_sub_function(struct function_pointer **result);
void attr_fastcall pcode_find_array_skip_function(struct function_pointer **result);
void attr_fastcall pcode_find_array_append_function(struct function_pointer **result);
void attr_fastcall pcode_find_option_ord_function(struct function_pointer **result);

#define PCODE_FUNCTION_RECORD_LOAD	0
#define PCODE_FUNCTION_OPTION_LOAD	1
#define PCODE_FUNCTION_OPTION_TEST	2
void attr_fastcall pcode_find_record_option_load_function(unsigned char tag, frame_t slot, struct function_pointer **result);

extern void *(*pcode_build_internal_functions[])(frame_s *fp, const code_t *ip, union internal_arg a[]);

#endif
