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
#include "tree.h"
#include "tick.h"
#include "type.h"
#include "data.h"
#include "layout.h"
#include "funct.h"
#include "builtin.h"
#include "module.h"
#include "rwlock.h"
#include "arrayu.h"
#include "code-op.h"
#include "ipret.h"
#include "ipfn.h"
#include "save.h"
#include "codegen.h"

#include "pcode.h"

#define NO_OPCODE	((code_t)-1)

#define fx(n)	(OPCODE_FIXED_OP + (OPCODE_FIXED_OP_##n) * OPCODE_FIXED_OP_MULT)
#define in(n)	(OPCODE_INT_OP + (OPCODE_INT_OP_##n) * OPCODE_INT_OP_MULT)
#define re(n)	(OPCODE_REAL_OP + (OPCODE_REAL_OP_##n) * OPCODE_REAL_OP_MULT)
#define bo(n)	(OPCODE_BOOL_OP + (OPCODE_BOOL_OP_##n) * OPCODE_BOOL_OP_MULT)

#define Op_Mov	(Op_N + 0)
#define Op_Copy	(Op_N + 1)
#define Op_Ldc	(Op_N + 2)
#define Op_NN	(Op_N + 3)

shared_var const code_t pcode2code[Op_NN][5]
#ifndef FILE_COMPRESSION
= {
	{ fx(add),		fx(add),		in(add),		re(add),		NO_OPCODE,	},
	{ fx(subtract),		fx(subtract),		in(subtract),		re(subtract),		NO_OPCODE,	},
	{ fx(multiply),		fx(multiply),		in(multiply),		re(multiply),		NO_OPCODE,	},
	{ fx(divide),		fx(udivide),		in(divide),		NO_OPCODE,		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(divide),		NO_OPCODE,	},
	{ fx(modulo),		fx(umodulo),		in(modulo),		re(modulo),		NO_OPCODE,	},
	{ fx(power),		fx(power),		in(power),		re(power),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(atan2),		NO_OPCODE,	},
	{ fx(and),		fx(and),		in(and),		NO_OPCODE,		bo(and),	},
	{ fx(or),		fx(or),			in(or),			NO_OPCODE,		bo(or),		},
	{ fx(xor),		fx(xor),		in(xor),		NO_OPCODE,		bo(not_equal),	},
	{ fx(shl),		fx(shl),		in(shl),		re(ldexp),		NO_OPCODE,	},
	{ fx(shr),		fx(ushr),		in(shr),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(rol),		fx(rol),		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ fx(ror),		fx(ror),		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ fx(bts),		fx(bts),		in(bts),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(btr),		fx(btr),		in(btr),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(btc),		fx(btc),		in(btc),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(equal),		fx(equal),		in(equal),		re(equal),		bo(equal),	},
	{ fx(not_equal),	fx(not_equal),		in(not_equal),		re(not_equal),		bo(not_equal),	},
	{ fx(less),		fx(uless),		in(less),		re(less),		bo(less),	},
	{ fx(less_equal),	fx(uless_equal),	in(less_equal),		re(less_equal),		bo(less_equal),	},
	{ fx(bt),		fx(bt),			in(bt),			NO_OPCODE,		NO_OPCODE,	},
	{ fx(not),		fx(not),		in(not),		NO_OPCODE,		bo(not),	},
	{ fx(neg),		fx(neg),		in(neg),		re(neg),		NO_OPCODE,	},
	{ fx(inc),		fx(inc),		in(inc),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(dec),		fx(dec),		in(dec),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(bswap),		fx(bswap),		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ fx(brev),		fx(brev),		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ fx(bsf),		fx(bsf),		in(bsf),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(bsr),		fx(bsr),		in(bsr),		NO_OPCODE,		NO_OPCODE,	},
	{ fx(popcnt),		fx(popcnt),		in(popcnt),		NO_OPCODE,		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(sqrt),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(cbrt),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(sin),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(cos),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(tan),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(asin),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(acos),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(atan),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(sinh),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(cosh),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(tanh),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(asinh),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(acosh),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(atanh),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(exp2),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(exp),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(exp10),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(log2),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(log),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(log10),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(round),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(floor),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(ceil),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(trunc),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(fract),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(mantissa),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(exponent),		NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(next_number),	NO_OPCODE,	},
	{ NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		re(prev_number),	NO_OPCODE,	},
	{ fx(to_int),		fx(uto_int),		in(to_int),		re(to_int),		NO_OPCODE,	},
	{ fx(from_int),		fx(ufrom_int),		in(from_int),		re(from_int),		NO_OPCODE,	},
	{ OPCODE_IS_EXCEPTION,	NO_OPCODE,		NO_OPCODE,		re(is_exception),	NO_OPCODE,	},
	{ OPCODE_EXCEPTION_CLASS,NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ OPCODE_EXCEPTION_TYPE,NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ OPCODE_EXCEPTION_AUX,	NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ OPCODE_SYSTEM_PROPERTY,NO_OPCODE,		NO_OPCODE,		NO_OPCODE,		NO_OPCODE,	},
	{ fx(move),		fx(move),		in(move),		re(move),		bo(move),	},
	{ fx(copy),		fx(copy),		in(copy),		re(copy),		bo(copy),	},
	{ fx(ldc),		fx(ldc),		in(ldc),		re(ldc),		NO_OPCODE,	},
}
#endif
;

#undef fx
#undef in
#undef re
#undef bo

static void instruction_class(const struct type *t, unsigned *cls, code_t *typeq, pcode_t op)
{
	if ((op == Un_IsException && !TYPE_TAG_IS_REAL(t->tag)) || op == Un_ExceptionClass || op == Un_ExceptionType || op == Un_ExceptionAux || op == Un_SystemProperty) {
		*typeq = 0;
		*cls = 0;
	} else if (TYPE_TAG_IS_FIXED(t->tag)) {
		*typeq = (TYPE_TAG_IDX_FIXED(t->tag) >> 1) * OPCODE_FIXED_TYPE_MULT;
		*cls = TYPE_TAG_FIXED_IS_UNSIGNED(t->tag);
	} else if (TYPE_TAG_IS_INT(t->tag)) {
		*typeq = TYPE_TAG_IDX_INT(t->tag) * OPCODE_INT_TYPE_MULT;
		*cls = 2;
	} else if (TYPE_TAG_IS_REAL(t->tag)) {
		*typeq = TYPE_TAG_IDX_REAL(t->tag) * OPCODE_REAL_TYPE_MULT;
		*cls = 3;
	} else if (t->tag == TYPE_TAG_flat_option) {
		*typeq = 0;
		*cls = 4;
	} else {
		internal(file_line, "instruction_class: invalid type %u", t->tag);
	}
}

static code_t get_code(pcode_t op, const struct type *t)
{
	code_t code, typeq;
	unsigned cls;
	ajla_assert(op >= 0 && op < Op_NN, (file_line, "get_code: invalid operation %"PRIdMAX"", (intmax_t)op));
	instruction_class(t, &cls, &typeq, op);
	code = pcode2code[op][cls];
	ajla_assert(code != NO_OPCODE, (file_line, "get_code: invalid instruction and type: %"PRIdMAX", %u", (intmax_t)op, t->tag));
	code += typeq;
	return code_alt(code);
}

#define INIT_ARG_MODE	0
#define INIT_ARG_MODE_1	1
typedef unsigned char arg_mode_t;

static bool adjust_arg_mode(arg_mode_t *am, uintmax_t offs, ajla_error_t *mayfail)
{
	arg_mode_t my_am;
	if (offs + uzero <= 0xff) my_am = 0;
	else if (offs + uzero <= 0xffffU) my_am = 1;
	else if (offs + uzero <= 0xffffffffUL + uzero) my_am = 2;
	else my_am = 3;
	if (unlikely(my_am >= ARG_MODE_N)) {
		if (mayfail) {
			*mayfail = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
			return false;
		}
		internal(file_line, "adjust_arg_mode: too big arg mode: offset %"PRIuMAX", max mode %d", (uintmax_t)offs, ARG_MODE_N);
	}
	if (unlikely(my_am > *am))
		*am = my_am;
	return true;
}

#define get_arg_mode(am, val)						\
do {									\
	if (unlikely(!adjust_arg_mode(&(am), (val), ctx->err)))		\
		goto exception;						\
} while (0)

struct local_type {
	const struct type *type;
	pcode_t type_index;
};

struct pcode_type {
	const struct type *type;
	struct local_arg *argument;
	frame_t slot;
	pcode_t color;
	int8_t extra_type;
	bool is_dereferenced_in_call_argument;
	uint8_t varflags;
};

struct color {
	flat_size_t size;
	flat_size_t align;
	bool is_argument;
};

struct label_ref {
	size_t code_pos;
	pcode_t label;
};

struct ld_ref {
	struct tree_entry entry;
	size_t idx;
	pointer_t *ptr;
};

struct build_function_context {
	const pcode_t *pcode;
	const pcode_t *pcode_limit;
	const pcode_t *pcode_instr_end;

	ajla_error_t *err;
	pointer_t ret_val;

	pcode_t function_type;
	pcode_t n_local_types;
	pcode_t n_labels;
	frame_t n_local_variables;
	arg_t n_arguments;
	arg_t n_return_values;
	arg_t n_real_arguments;
	arg_t n_real_return_values;
	frame_t n_slots;

	uint8_t *function_name;

	struct local_type *local_types;
	struct pcode_type *pcode_types;		/* indexed by pcode idx */
	struct layout *layout;
	struct local_variable *local_variables;	/* indexed by slot */
	struct local_variable_flags *local_variables_flags;	/* indexed by slot */

	struct color *colors;
	size_t n_colors;

	size_t *labels;
	struct label_ref *label_ref;
	size_t label_ref_len;

	pointer_t **ld;
	size_t ld_len;
	struct tree ld_tree;

	struct local_arg *args;

	const struct type **types;
	size_t types_len;
	struct data *ft_free;

	code_t *code;
	size_t code_len;

	frame_t *record_entries;
	size_t record_entries_len;

	struct record_definition *record_definition;

	struct line_position *lp;
	size_t lp_size;

	struct escape_data *escape_data;

	unsigned checkpoint_num;

	bool is_eval;
	bool leaf;

	pcode_t builtin_type_indices[TYPE_TAG_N];
};

static const pcode_t no_type_index = -1;
static const pcode_t error_type_index = -2;
static const size_t no_label = (size_t)-1;

static void init_ctx(struct build_function_context *ctx)
{
	size_t i;
	ctx->n_real_arguments = 0;
	ctx->function_name = NULL;
	ctx->local_types = NULL;
	ctx->pcode_types = NULL;
	ctx->layout = NULL;
	ctx->local_variables = NULL;
	ctx->local_variables_flags = NULL;
	ctx->colors = NULL;
	ctx->labels = NULL;
	ctx->label_ref = NULL;
	ctx->ld = NULL;
	tree_init(&ctx->ld_tree);
	ctx->args = NULL;
	ctx->types = NULL;
	ctx->ft_free = NULL;
	ctx->types_len = 0;
	ctx->code = NULL;
	ctx->record_entries = NULL;
	ctx->record_definition = NULL;
	ctx->lp = NULL;
	ctx->lp_size = 0;
	ctx->escape_data = NULL;
	ctx->checkpoint_num = 0;
	ctx->leaf = true;
	for (i = 0; i < n_array_elements(ctx->builtin_type_indices); i++)
		ctx->builtin_type_indices[i] = no_type_index;
}

static void free_ld_tree(struct build_function_context *ctx)
{
	while (!tree_is_empty(&ctx->ld_tree)) {
		struct ld_ref *ld_ref = get_struct(tree_any(&ctx->ld_tree), struct ld_ref, entry);
		tree_delete(&ld_ref->entry);
		mem_free(ld_ref);
	}
}

static void done_ctx(struct build_function_context *ctx)
{
	if (ctx->function_name)
		mem_free(ctx->function_name);
	if (ctx->local_types)
		mem_free(ctx->local_types);
	if (ctx->pcode_types)
		mem_free(ctx->pcode_types);
	if (ctx->layout)
		layout_free(ctx->layout);
	if (ctx->local_variables)
		mem_free(ctx->local_variables);
	if (ctx->local_variables_flags)
		mem_free(ctx->local_variables_flags);
	if (ctx->colors)
		mem_free(ctx->colors);
	if (ctx->labels)
		mem_free(ctx->labels);
	if (ctx->label_ref)
		mem_free(ctx->label_ref);
	if (ctx->ld)
		mem_free(ctx->ld);
	free_ld_tree(ctx);
	if (ctx->args)
		mem_free(ctx->args);
	if (ctx->types)
		mem_free(ctx->types);
	if (ctx->ft_free)
		mem_free(ctx->ft_free);
	if (ctx->code)
		mem_free(ctx->code);
	if (ctx->record_entries)
		mem_free(ctx->record_entries);
	if (ctx->record_definition) {
		mem_free(ctx->record_definition->idx_to_frame);
		mem_free(ctx->record_definition);
	}
	if (ctx->lp)
		mem_free(ctx->lp);
	if (ctx->escape_data)
		mem_free(ctx->escape_data);
}

static char *function_name(const struct build_function_context *ctx)
{
	if (ctx->function_name)
		return cast_ptr(char *, ctx->function_name);
	return "";
}

static pcode_t pcode_get_fn(struct build_function_context *ctx argument_position)
{
	ajla_assert(ctx->pcode < ctx->pcode_limit, (caller_file_line, "pcode_get_fn(%s): no pcode left", function_name(ctx)));
	return *ctx->pcode++;
}
#define pcode_get()	pcode_get_fn(ctx pass_file_line)

static pcode_t u_pcode_get_fn(struct build_function_context *ctx argument_position)
{
	pcode_t p = pcode_get_fn(ctx pass_position);
	ajla_assert(p >= 0, (caller_file_line, "u_pcode_get_fn(%s): negative pcode %"PRIdMAX"", function_name(ctx), (intmax_t)p));
	return p;
}
#define u_pcode_get()	u_pcode_get_fn(ctx pass_file_line)

typedef const pcode_t *pcode_position_save_t;

static inline void pcode_position_save(struct build_function_context *ctx, pcode_position_save_t *save)
{
	*save = ctx->pcode;
}

static inline void pcode_position_restore(struct build_function_context *ctx, const pcode_position_save_t *save)
{
	ctx->pcode = *save;
}

typedef size_t code_position_save_t;

static inline void code_position_save(struct build_function_context *ctx, code_position_save_t *save)
{
	*save = ctx->code_len;
}

static inline void code_position_restore(struct build_function_context *ctx, const code_position_save_t *save)
{
	ajla_assert_lo(ctx->code_len >= *save, (file_line, "code_position_restore(%s): attempting to restore forward: %"PRIuMAX" < %"PRIuMAX"", function_name(ctx), (uintmax_t)ctx->code_len, (uintmax_t)*save));
	ctx->code_len = *save;
}

const struct type *pcode_get_type(pcode_t q)
{
	const struct type *t;
	switch (q) {
		case T_SInt8:
			t = type_get_fixed(0, false);
			break;
		case T_UInt8:
			t = type_get_fixed(0, true);
			break;
		case T_SInt16:
			t = type_get_fixed(1, false);
			break;
		case T_UInt16:
			t = type_get_fixed(1, true);
			break;
		case T_SInt32:
			t = type_get_fixed(2, false);
			break;
		case T_UInt32:
			t = type_get_fixed(2, true);
			break;
		case T_SInt64:
			t = type_get_fixed(3, false);
			break;
		case T_UInt64:
			t = type_get_fixed(3, true);
			break;
		case T_SInt128:
			t = type_get_fixed(4, false);
			break;
		case T_UInt128:
			t = type_get_fixed(4, true);
			break;

		case T_Integer:
			t = type_get_int(INT_DEFAULT_N);
			break;
		case T_Integer8:
			t = type_get_int(0);
			break;
		case T_Integer16:
			t = type_get_int(1);
			break;
		case T_Integer32:
			t = type_get_int(2);
			break;
		case T_Integer64:
			t = type_get_int(3);
			break;
		case T_Integer128:
			t = type_get_int(4);
			break;

		case T_Real16:
			t = type_get_real(0);
			break;
		case T_Real32:
			t = type_get_real(1);
			break;
		case T_Real64:
			t = type_get_real(2);
			break;
		case T_Real80:
			t = type_get_real(3);
			break;
		case T_Real128:
			t = type_get_real(4);
			break;

		case T_FlatOption:
			t = type_get_flat_option();
			break;

		case T_Undetermined:
			t = type_get_unknown();
			break;

		default:
			t = NULL;
			break;
	}
	return t;
}

static const struct type *pcode_to_type(const struct build_function_context *ctx, pcode_t q, ajla_error_t *mayfail)
{
	const struct type *t;
	if (q >= 0) {
		ajla_assert_lo(q < ctx->n_local_types, (file_line, "pcode_to_type(%s): invalid local type: %"PRIdMAX" >= %"PRIdMAX"", function_name(ctx), (intmax_t)q, (intmax_t)ctx->n_local_types));
		return ctx->local_types[q].type;
	}
	t = pcode_get_type(q);
	if (unlikely(!t)) {
		if (q == T_SInt64 || q == T_UInt64 || q == T_SInt128 || q == T_UInt128)
			return pcode_get_type(T_Integer128);
		if (q == T_Real16 || q == T_Real32 || q == T_Real64 || q == T_Real80 || q == T_Real128)
			return pcode_get_type(T_Integer128);
		if (unlikely(!mayfail))
			internal(file_line, "pcode_to_type(%s): invalid type %"PRIdMAX"", function_name(ctx), (intmax_t)q);
		*mayfail = error_ajla(EC_ASYNC, AJLA_ERROR_NOT_SUPPORTED);
	}
	return t;
}

static pcode_t type_to_pcode(const struct type *type)
{
	if (TYPE_TAG_IS_FIXED(type->tag))
		return (pcode_t)(T_SInt8 - TYPE_TAG_IDX_FIXED(type->tag));
	else if (TYPE_TAG_IS_INT(type->tag))
		return (pcode_t)(T_Integer8 - TYPE_TAG_IDX_INT(type->tag));
	else if (TYPE_TAG_IS_REAL(type->tag))
		return (pcode_t)(T_Real16 - TYPE_TAG_IDX_REAL(type->tag));
	else if (type->tag == TYPE_TAG_flat_option)
		return T_FlatOption;
	else
		internal(file_line, "type_to_pcode: invalid type %u", type->tag);
	return 0;
}

static pcode_t pcode_to_type_index(struct build_function_context *ctx, pcode_t q, bool non_flat)
{
	pcode_t *result;
	const struct type *type = pcode_to_type(ctx, q, NULL);
	if (!TYPE_IS_FLAT(type) && non_flat)
		return no_type_index;

	if (q >= 0) {
		result = &ctx->local_types[q].type_index;
	} else {
		unsigned tag = type->tag;
		ajla_assert_lo(tag < n_array_elements(ctx->builtin_type_indices), (file_line, "pcode_to_type_index(%s): invalid type tag %u", function_name(ctx), tag));
		result = &ctx->builtin_type_indices[tag];
	}
	if (*result != no_type_index)
		return *result;
	if (unlikely((pcode_t)ctx->types_len < 0)) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), ctx->err, "type array overflow");
		return error_type_index;
	}
	if (unlikely(!array_add_mayfail(const struct type *, &ctx->types, &ctx->types_len, type, NULL, ctx->err)))
		return error_type_index;
	return *result = (pcode_t)(ctx->types_len - 1);
}

#define pcode_get_var_deref(var, deref)					\
do {									\
	pcode_t r_ = u_pcode_get();					\
	ajla_assert_lo(!(r_ & ~(pcode_t)Flag_Free_Argument), (file_line, "pcode_get_ref(%s): invalid reference flag %"PRIdMAX"", function_name(ctx), (intmax_t)r_));\
	*(deref) = !!(r_ & Flag_Free_Argument);				\
	*(var) = pcode_get();						\
} while (0)

#define var_elided(idx)		(((idx) < zero) || ctx->pcode_types[idx].type == NULL)

static struct pcode_type *get_var_type(struct build_function_context *ctx, pcode_t v)
{
	ajla_assert_lo(!var_elided(v), (file_line, "get_var_type(%s): variable %"PRIdMAX" is elided", function_name(ctx), (intmax_t)v));
	ajla_assert_lo((frame_t)v < ctx->n_local_variables, (file_line, "get_var_type(%s): invalid local variable %"PRIdMAX", limit %"PRIuMAX"", function_name(ctx), (intmax_t)v, (uintmax_t)ctx->n_local_variables));
	return &ctx->pcode_types[v];
}

static bool pcode_load_blob(struct build_function_context *ctx, uint8_t **blob, size_t *l)
{
	pcode_t n, i, q;

	if (blob) {
		if (unlikely(!array_init_mayfail(uint8_t, blob, l, ctx->err)))
			return false;
	}

	q = 0;		/* avoid warning */
	n = u_pcode_get();
	for (i = 0; i < n; i++) {
		uint8_t val;
		if (!(i & 3)) {
			q = pcode_get();
		}
		val = q;
		q >>= 8;
		if (blob) {
			if (unlikely(!array_add_mayfail(uint8_t, blob, l, (uint8_t)val, NULL, ctx->err)))
				return false;
		}
	}

	return true;
}

static bool pcode_generate_blob(uint8_t *str, size_t str_len, pcode_t **res_blob, size_t *res_len, ajla_error_t *err)
{
	size_t i;
	if (unlikely(str_len > signed_maximum(pcode_t))) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "pcode overflow");
		return false;
	}
	if (unlikely(!array_init_mayfail(pcode_t, res_blob, res_len, err)))
		return false;
	if (unlikely(!array_add_mayfail(pcode_t, res_blob, res_len, 0, NULL, err)))
		return false;
	for (i = 0; i < str_len; i++) {
		uint8_t b = str[i];
		if (!(**res_blob % sizeof(pcode_t))) {
			if (unlikely(!array_add_mayfail(pcode_t, res_blob, res_len, b, NULL, err)))
				return false;
		} else {
			(*res_blob)[*res_len - 1] |= (upcode_t)((b) & 0xff) << (**res_blob % sizeof(pcode_t) * 8);
		}
		(**res_blob)++;
	}
	return true;
}

static pointer_t *pcode_module_load_function(struct build_function_context *ctx)
{
	unsigned path_idx;
	bool program;
	pointer_t *ptr;
	uint8_t *blob = NULL;
	size_t l;
	struct module_designator *md = NULL;
	struct function_designator *fd = NULL;
	pcode_t q;

	q = u_pcode_get();
	path_idx = (unsigned)q;
	if (unlikely(q != (pcode_t)path_idx))
		goto exception_overflow;
	program = path_idx & 1;
	path_idx >>= 1;
	if (unlikely(!pcode_load_blob(ctx, &blob, &l)))
		goto exception;

	md = module_designator_alloc(path_idx, blob, l, program, ctx->err);
	if (unlikely(!md))
		goto exception;

	mem_free(blob), blob = NULL;

	fd = function_designator_alloc(ctx->pcode, ctx->err);
	if (unlikely(!fd))
		goto exception;
	ctx->pcode += fd->n_entries + 1;

	ptr = module_load_function(md, fd, false, ctx->err);
	if (unlikely(!ptr))
		goto exception;

	module_designator_free(md), md = NULL;
	function_designator_free(fd), fd = NULL;

	return ptr;

exception_overflow:
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), ctx->err, "pcode overflow");
exception:
	if (blob)
		mem_free(blob);
	if (md)
		module_designator_free(md);
	if (fd)
		function_designator_free(fd);
	return NULL;
}

#define no_function_idx	((size_t)-1)

static int ld_tree_compare(const struct tree_entry *e, uintptr_t ptr)
{
	struct ld_ref *ld_ref = get_struct(e, struct ld_ref, entry);
	uintptr_t ld_ptr = ptr_to_num(ld_ref->ptr);
	if (ld_ptr < ptr)
		return -1;
	if (ld_ptr > ptr)
		return 1;
	return 0;
}

static size_t pcode_module_load_function_idx(struct build_function_context *ctx, pointer_t *ptr, bool must_exist)
{
	struct tree_entry *e;
	struct ld_ref *ld_ref;
	struct tree_insert_position ins;

	e = tree_find_for_insert(&ctx->ld_tree, ld_tree_compare, ptr_to_num(ptr), &ins);
	if (e) {
		ld_ref = get_struct(e, struct ld_ref, entry);
		return ld_ref->idx;
	}

	if (unlikely(must_exist))
		internal(file_line, "pcode_module_load_function_idx: local directory preload didn't work");

	ld_ref = mem_alloc_mayfail(struct ld_ref *, sizeof(struct ld_ref), ctx->err);
	if (unlikely(!ld_ref))
		return no_function_idx;
	ld_ref->ptr = ptr;
	ld_ref->idx = ctx->ld_len;

	tree_insert_after_find(&ld_ref->entry, &ins);

	if (unlikely(!array_add_mayfail(pointer_t *, &ctx->ld, &ctx->ld_len, ptr, NULL, ctx->err)))
		return no_function_idx;
	return ctx->ld_len - 1;
}

#define gen_code(n)							\
do {									\
	if (unlikely(!array_add_mayfail(code_t, &ctx->code, &ctx->code_len, n, NULL, ctx->err)))\
		goto exception;						\
} while (0)

#if !CODE_ENDIAN
#define gen_uint32(n)							\
do {									\
	gen_code((code_t)((n) & 0xffff));				\
	gen_code((code_t)((n) >> 15 >> 1));				\
} while (0)
#else
#define gen_uint32(n)							\
do {									\
	gen_code((code_t)((n) >> 15 >> 1));				\
	gen_code((code_t)((n) & 0xffff));				\
} while (0)
#endif

#define gen_am(am, m)							\
do {									\
	if (am <= 1) {							\
		gen_code((code_t)(m));					\
	} else if (am == 2) {						\
		gen_uint32((m));					\
	} else {							\
		internal(file_line, "gen_am(%s): arg mode %d", function_name(ctx), am);\
	}								\
} while (0)

#define gen_am_two(am, m, n)						\
do {									\
	if (!am) {							\
		gen_code((code_t)((m) + ((n) << 8)));			\
	} else if (am == 1) {						\
		gen_code((code_t)(m));					\
		gen_code((code_t)(n));					\
	} else if (am == 2) {						\
		gen_uint32((m));					\
		gen_uint32((n));					\
	} else {							\
		internal(file_line, "gen_am_two(%s): arg mode %d", function_name(ctx), am);\
	}								\
} while (0)

#define gen_relative_jump(lbl, diff)					\
do {									\
	uint32_t target;						\
	ajla_assert_lo((lbl) < ctx->n_labels, (file_line, "gen_relative_jump(%s): invalid label %"PRIdMAX"", function_name(ctx), (intmax_t)(lbl)));\
	target = -(((uint32_t)(diff) + 1) / (uint32_t)sizeof(code_t) * (uint32_t)sizeof(code_t));\
	if (ctx->labels[lbl] == no_label) {				\
		struct label_ref lr;					\
		lr.code_pos = ctx->code_len;				\
		lr.label = (lbl);					\
		if (unlikely(!array_add_mayfail(struct label_ref, &ctx->label_ref, &ctx->label_ref_len, lr, NULL, ctx->err)))\
			goto exception;					\
	} else {							\
		target += ((uint32_t)ctx->labels[lbl] - (uint32_t)ctx->code_len) * (uint32_t)sizeof(code_t);\
	}								\
	if (SIZEOF_IP_T == 2)						\
		gen_code((code_t)target);				\
	else if (SIZEOF_IP_T == 4)					\
		gen_uint32(target);					\
	else not_reached();						\
} while (0)

static bool gen_checkpoint(struct build_function_context *ctx, const pcode_t *params, pcode_t n_params, bool check_arguments)
{
	arg_mode_t am;
	code_t code;
	pcode_t i;
	pcode_t n_used_params;
	frame_t v;
	bool *processed_variables = NULL;

	if (unlikely(ctx->is_eval))
		return true;

	processed_variables = mem_alloc_array_mayfail(mem_calloc_mayfail, bool *, 0, 0, ctx->n_slots, sizeof(bool), ctx->err);
	if (unlikely(!processed_variables))
		goto exception;

	am = INIT_ARG_MODE_1;
	get_arg_mode(am, n_params);

	n_used_params = 0;
	for (i = 0; i < n_params; i++) {
		const struct pcode_type *tv;
		pcode_t var = params[i];
		if (var_elided(var))
			continue;
		tv = get_var_type(ctx, var);
		get_arg_mode(am, tv->slot);
		if (!processed_variables[tv->slot]) {
			processed_variables[tv->slot] = true;
			n_used_params++;
		}
	}

	if (check_arguments) {
		arg_t ia;
		for (ia = 0; ia < ctx->n_real_arguments; ia++) {
			const struct local_arg *la = &ctx->args[ia];
			if (ctx->local_variables_flags[la->slot].must_be_flat && ia < 4 && 0)
				goto x;
			if (!la->may_be_borrowed)
				continue;
x:
			get_arg_mode(am, la->slot);
			if (!processed_variables[la->slot]) {
				processed_variables[la->slot] = true;
				n_used_params++;
			}
		}
	}

	code = OPCODE_CHECKPOINT;
	code += am * OPCODE_MODE_MULT;
	gen_code(code);
	gen_am(ARG_MODE_N - 1, ctx->checkpoint_num);

	gen_am(am, n_used_params);

	for (v = 0; v < ctx->n_slots; v++) {
		if (unlikely(processed_variables[v])) {
			gen_am(am, v);
		}
	}

	mem_free(processed_variables);
	processed_variables = NULL;

	ctx->checkpoint_num++;
	if (unlikely(!ctx->checkpoint_num)) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), ctx->err, "checkpoint number overflow");
		goto exception;
	}

	return true;

exception:
	if (processed_variables)
		mem_free(processed_variables);
	return false;
}

static bool pcode_free(struct build_function_context *ctx, pcode_t res)
{
	arg_mode_t am;
	const struct pcode_type *tr;
	code_t code;
	const struct color *c;

	if (unlikely(var_elided(res)))
		return true;
	tr = get_var_type(ctx, res);
	am = INIT_ARG_MODE;
	get_arg_mode(am, tr->slot);
	c = &ctx->colors[tr->color];
	if (!TYPE_IS_FLAT(tr->type) && c->is_argument)
		code = OPCODE_DEREFERENCE_CLEAR;
	else
		code = OPCODE_DEREFERENCE;
	code += am * OPCODE_MODE_MULT;
	gen_code(code);
	gen_am(am, tr->slot);

	return true;

exception:
	return false;
}

static bool pcode_copy(struct build_function_context *ctx, bool type_cast, pcode_t res, pcode_t a1, bool a1_deref)
{
	const struct pcode_type *tr, *t1;
	arg_mode_t am;
	code_t code;

	tr = get_var_type(ctx, res);
	t1 = get_var_type(ctx, a1);

	if (t1->slot == tr->slot) {
		ajla_assert(a1_deref, (file_line, "pcode_copy(%s): dereference not set", function_name(ctx)));
		/*
		 * If we copy a value to itself, we must clear may_be_borrowed,
		 * otherwise we get failure in start03.ajla and start04.ajla.
		 *
		 * (note that pcode_copy is called from pcode_structured_write)
		 *
		 * The reason for the crash is that may_be_borrowed is per-variable,
		 * not per-slot flag - if we copy to a different variable occupying
		 * the same slot, we won't see may_be_borrowed anymore.
		 */

		if (t1->type->size == 0) {
			am = INIT_ARG_MODE;
			get_arg_mode(am, t1->slot);
			code = OPCODE_TAKE_BORROWED;
			code += am * OPCODE_MODE_MULT;
			gen_code(code);
			gen_am(am, t1->slot);
		}

		return true;
	}

	if ((t1->type->size == 0 && tr->type->size == 0) || type_cast) {
		const struct color *c = &ctx->colors[t1->color];
		am = INIT_ARG_MODE;
		get_arg_mode(am, t1->slot);
		get_arg_mode(am, tr->slot);
		if (type_cast) {
			code = a1_deref ? OPCODE_BOX_MOVE_CLEAR : OPCODE_BOX_COPY;
		} else {
			code = a1_deref ? (c->is_argument ? OPCODE_REF_MOVE_CLEAR : OPCODE_REF_MOVE) : OPCODE_REF_COPY;
		}
		code += am * OPCODE_MODE_MULT;
		gen_code(code);
		gen_am_two(am, t1->slot, tr->slot);
	} else if (t1->type->tag == TYPE_TAG_flat_record || t1->type->tag == TYPE_TAG_flat_array) {
		ajla_assert_lo(tr->type == t1->type, (file_line, "pcode_copy(%s): invalid types for flat copy instruction: %u, %u", function_name(ctx), t1->type->tag, tr->type->tag));
		am = INIT_ARG_MODE;
		get_arg_mode(am, t1->slot);
		get_arg_mode(am, tr->slot);
		code = a1_deref ? OPCODE_FLAT_MOVE : OPCODE_FLAT_COPY;
		code += am * OPCODE_MODE_MULT;
		gen_code(code);
		gen_am_two(am, t1->slot, tr->slot);
	} else {
		ajla_assert_lo(tr->type == t1->type, (file_line, "pcode_copy(%s): invalid types for copy instruction: %u, %u", function_name(ctx), t1->type->tag, tr->type->tag));
		am = INIT_ARG_MODE;
		get_arg_mode(am, t1->slot);
		get_arg_mode(am, tr->slot);
		code = get_code(a1_deref ? Op_Mov : Op_Copy, t1->type);
		code += am * OPCODE_MODE_MULT;
		gen_code(code);
		gen_am_two(am, t1->slot, tr->slot);
	}
	return true;

exception:
	return false;
}

static bool pcode_process_arguments(struct build_function_context *ctx, pcode_t n_arguments, pcode_t *n_real_arguments, arg_mode_t *am)
{
	pcode_t ai;
	if (n_real_arguments)
		*n_real_arguments = 0;
	for (ai = 0; ai < n_arguments; ai++) {
		pcode_t a1;
		struct pcode_type *t1;
		bool deref;
		pcode_get_var_deref(&a1, &deref);
		if (unlikely(var_elided(a1)))
			continue;
		t1 = get_var_type(ctx, a1);
		if (n_real_arguments) {
			get_arg_mode(*am, t1->slot);
			(*n_real_arguments)++;
			t1->is_dereferenced_in_call_argument = deref;
		} else {
			code_t flags = 0;
			if (deref) {
				flags |= OPCODE_FLAG_FREE_ARGUMENT;
				if (!TYPE_IS_FLAT(t1->type))
					flags |= OPCODE_CALL_MAY_GIVE;
			} else {
				if (!t1->is_dereferenced_in_call_argument && !TYPE_IS_FLAT(t1->type))
					flags |= OPCODE_CALL_MAY_LEND;
			}
			gen_am_two(*am, t1->slot, flags);
		}
	}
	if (n_real_arguments)
		get_arg_mode(*am, *n_real_arguments);
	return true;

exception:
	return false;
}

static bool pcode_dereference_arguments(struct build_function_context *ctx, pcode_t n_arguments)
{
	pcode_t ai;
	for (ai = 0; ai < n_arguments; ai++) {
		pcode_t a1;
		bool deref;
		pcode_get_var_deref(&a1, &deref);
		if (deref) {
			if (unlikely(!pcode_free(ctx, a1)))
				goto exception;
		}
	}
	return true;

exception:
	return false;
}

static bool pcode_finish_call(struct build_function_context *ctx, const struct pcode_type **rets, size_t rets_l, bool test_flat)
{
	size_t i;
	frame_t *vars = NULL;

	ctx->leaf = false;

	for (i = 0; i < rets_l; i++) {
		const struct pcode_type *tv = rets[i];
		if (ARG_MODE_N >= 3) {
			gen_uint32(tv->slot);
		} else {
			gen_code((code_t)tv->slot);
		}
		gen_code(TYPE_IS_FLAT(tv->type) ? OPCODE_MAY_RETURN_FLAT : 0);
	}

	if (unlikely(test_flat)) {
		arg_mode_t am;
		frame_t slot;
		size_t n_vars;

		if (unlikely(!gen_checkpoint(ctx, NULL, 0, false)))
			goto exception;

		vars = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, ctx->n_slots, sizeof(frame_t), ctx->err);
		if (unlikely(!vars))
			goto exception;

		am = INIT_ARG_MODE_1;
		n_vars = 0;
		for (slot = MIN_USEABLE_SLOT; slot < ctx->n_slots; slot++) {
			if (ctx->local_variables_flags[slot].must_be_flat || ctx->local_variables_flags[slot].must_be_data) {
				vars[n_vars++] = slot;
				get_arg_mode(am, slot);
			}
		}
		if (n_vars) {
			code_t code;
			get_arg_mode(am, n_vars);
			code = OPCODE_ESCAPE_NONFLAT;
			code += am * OPCODE_MODE_MULT;
			gen_code(code);
			gen_am(am, n_vars);
			for (i = 0; i < n_vars; i++)
				gen_am(am, vars[i]);
		}
		mem_free(vars);
		vars = NULL;
	}

	return true;

exception:
	if (vars)
		mem_free(vars);
	return false;
}

static bool pcode_call(struct build_function_context *ctx, pcode_t instr)
{
	bool elide = false;
	arg_mode_t am = INIT_ARG_MODE;
	pcode_t q;
	pcode_t res;
	const struct pcode_type *tr = NULL;	/* avoid warning */
	const struct pcode_type *ts = NULL;	/* avoid warning */
	pcode_t call_mode = 0;			/* avoid warning */
	pcode_t src_fn = 0;			/* avoid warning */
	bool src_deref = false;			/* avoid warning */
	code_t code;
	arg_t ai;
	pcode_t n_arguments, n_real_arguments;
	arg_t n_return_values, n_real_return_values;
	size_t fn_idx = 0;			/* avoid warning */
	pcode_position_save_t saved;
	const struct pcode_type **rets = NULL;
	size_t rets_l;

	if (instr == P_Load_Fn || instr == P_Curry) {
		res = u_pcode_get();
		if (unlikely(var_elided(res))) {
			elide = true;
		} else  {
			tr = get_var_type(ctx, res);
			get_arg_mode(am, tr->slot);
		}
		n_return_values = 0;	/* avoid warning */
	} else if (instr == P_Call || instr == P_Call_Indirect) {
		call_mode = u_pcode_get();
		q = u_pcode_get();
		n_return_values = (arg_t)q;
		if (unlikely(q != (pcode_t)n_return_values))
			goto exception_overflow;
	} else {
		internal(file_line, "pcode_call(%s): invalid instruction %"PRIdMAX"", function_name(ctx), (intmax_t)instr);
	}

	q = u_pcode_get();
	n_arguments = (arg_t)q;
	if (unlikely(q != (pcode_t)n_arguments))
		goto exception_overflow;
	if (instr == P_Load_Fn || instr == P_Call) {
		pointer_t *ptr;
		if (instr == P_Load_Fn)
			u_pcode_get();	/* call mode */
		ptr = pcode_module_load_function(ctx);
		if (unlikely(!ptr))
			goto exception;
		fn_idx = pcode_module_load_function_idx(ctx, ptr, true);
		if (unlikely(fn_idx == no_function_idx))
			goto exception;
		get_arg_mode(am, fn_idx);
		src_deref = false;	/* avoid warning */
		src_fn = ~sign_bit(pcode_t);		/* avoid warning */
	}
	if (instr == P_Curry || instr == P_Call_Indirect) {
		pcode_get_var_deref(&src_fn, &src_deref);
	}

	pcode_position_save(ctx, &saved);

	if (unlikely(!pcode_process_arguments(ctx, n_arguments, &n_real_arguments, &am)))
		goto exception;

	n_real_return_values = 0;
	if (instr == P_Call || instr == P_Call_Indirect) {
		for (ai = 0; ai < n_return_values; ai++) {
			q = u_pcode_get();
			if (unlikely(var_elided(q)))
				continue;
			n_real_return_values++;
		}
		if (!n_real_return_values)
			elide = true;
		get_arg_mode(am, n_return_values);
	}
	pcode_position_restore(ctx, &saved);

	if (unlikely(elide)) {
		/* TODO: remove the function from local directory if we just added it */
		if (src_deref) {
			if (unlikely(!pcode_free(ctx, src_fn)))
				goto exception;
		}
		pcode_dereference_arguments(ctx, n_arguments);

		goto skip_instr;
	}

	if (instr == P_Curry || instr == P_Call_Indirect) {
		ts = get_var_type(ctx, src_fn);
		ajla_assert_lo(ts->type->tag == TYPE_TAG_unknown, (file_line, "pcode_call(%s): expected function type, got %u", function_name(ctx), ts->type->tag));
		get_arg_mode(am, ts->slot);
		fn_idx = no_function_idx;	/* avoid warning */
	}

	code = 0;	/* avoid warning */
	switch (instr) {
		case P_Load_Fn:
			code = OPCODE_LOAD_FN;
			break;
		case P_Curry:
			code = OPCODE_CURRY;
			break;
		case P_Call:
			switch (call_mode) {
				case Call_Mode_Unspecified:
				case Call_Mode_Normal:
					code = OPCODE_CALL;
					break;
				case Call_Mode_Strict:
				case Call_Mode_Inline:
					code = OPCODE_CALL_STRICT;
					break;
				case Call_Mode_Spark:
					code = OPCODE_CALL_SPARK;
					break;
				case Call_Mode_Lazy:
					code = OPCODE_CALL_LAZY;
					break;
				case Call_Mode_Cache:
					code = OPCODE_CALL_CACHE;
					break;
				case Call_Mode_Save:
					code = OPCODE_CALL_SAVE;
					break;
				default:
					internal(file_line, "pcode_call(%s): invalid call mode %ld", function_name(ctx), (long)call_mode);
			}
			break;
		case P_Call_Indirect:
			switch (call_mode) {
				case Call_Mode_Unspecified:
				case Call_Mode_Normal:
					code = OPCODE_CALL_INDIRECT;
					break;
				case Call_Mode_Strict:
				case Call_Mode_Inline:
					code = OPCODE_CALL_INDIRECT_STRICT;
					break;
				case Call_Mode_Spark:
					code = OPCODE_CALL_INDIRECT_SPARK;
					break;
				case Call_Mode_Lazy:
					code = OPCODE_CALL_INDIRECT_LAZY;
					break;
				case Call_Mode_Cache:
					code = OPCODE_CALL_INDIRECT_CACHE;
					break;
				case Call_Mode_Save:
					code = OPCODE_CALL_INDIRECT_SAVE;
					break;
				default:
					internal(file_line, "pcode_call(%s): invalid call mode %ld", function_name(ctx), (long)call_mode);
			}
			break;
		default:
			internal(file_line, "pcode_call(%s): invalid instruction %"PRIdMAX"", function_name(ctx), (intmax_t)instr);
	}

	code += am * OPCODE_MODE_MULT;
	gen_code(code);
	if (instr == P_Load_Fn || instr == P_Curry)
		gen_am_two(am, n_real_arguments, tr->slot);
	else
		gen_am_two(am, n_real_arguments, n_real_return_values);
	if (instr == P_Load_Fn || instr == P_Call)
		gen_am(am, fn_idx);
	else
		gen_am_two(am, ts->slot, src_deref ? OPCODE_FLAG_FREE_ARGUMENT : 0);

	if (unlikely(!pcode_process_arguments(ctx, n_arguments, NULL, &am)))
		goto exception;

	if (instr == P_Call || instr == P_Call_Indirect) {
		if (unlikely(!array_init_mayfail(const struct pcode_type *, &rets, &rets_l, ctx->err)))
			goto exception;
		for (ai = 0; ai < n_return_values; ai++) {
			const struct pcode_type *tv;
			q = u_pcode_get();
			if (unlikely(var_elided(q)))
				continue;
			tv = get_var_type(ctx, q);
			if (unlikely(!array_add_mayfail(const struct pcode_type *, &rets, &rets_l, tv, NULL, ctx->err)))
				goto exception;
		}
		if (unlikely(!pcode_finish_call(ctx, rets, rets_l, false)))
			goto exception;
		mem_free(rets);
		rets = NULL;
	}

	return true;

exception_overflow:
	*ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
exception:
	if (rets)
		mem_free(rets);
	return false;

skip_instr:
	ctx->pcode = ctx->pcode_instr_end;
	return true;
}

static bool pcode_op_to_call(struct build_function_context *ctx, pcode_t op, const struct pcode_type *tr, const struct pcode_type *t1, pcode_t flags1, const struct pcode_type *t2, pcode_t flags2, bool preload)
{
	const char *module;
	struct module_designator *md = NULL;
	struct function_designator *fd = NULL;
	unsigned fn;
	pointer_t *ptr;
	size_t fn_idx;
	arg_mode_t am;
	code_t code;

	switch (t1->extra_type ? t1->extra_type : tr->extra_type) {
		case T_SInt128:	module = "private/long"; fn = 0 * Op_N; break;
		case T_UInt128:	module = "private/long"; fn = 1 * Op_N; break;
		case T_Real16:	module = "private/longreal"; fn = 0 * Op_N; break;
		case T_Real32:	module = "private/longreal"; fn = 1 * Op_N; break;
		case T_Real64:	module = "private/longreal"; fn = 2 * Op_N; break;
		case T_Real80:	module = "private/longreal"; fn = 3 * Op_N; break;
		case T_Real128:	module = "private/longreal"; fn = 4 * Op_N; break;
		default:
			internal(file_line, "pcode_op_to_call: type %d, %d", t1->extra_type, tr->extra_type);
	}
	fn += op;

	md = module_designator_alloc(0, cast_ptr(const uint8_t *, module), strlen(module), false, ctx->err);
	if (unlikely(!md))
		goto exception;
	fd = function_designator_alloc_single(fn, ctx->err);
	if (unlikely(!fd))
		goto exception;
	ptr = module_load_function(md, fd, false, ctx->err);
	if (unlikely(!ptr))
		goto exception;
	module_designator_free(md), md = NULL;
	function_designator_free(fd), fd = NULL;
	fn_idx = pcode_module_load_function_idx(ctx, ptr, !preload);
	if (unlikely(fn_idx == no_function_idx))
		goto exception;

	if (preload)
		return true;

	am = INIT_ARG_MODE;
	get_arg_mode(am, fn_idx);
	get_arg_mode(am, t1->slot);
	if (t2)
		get_arg_mode(am, t2->slot);

	code = OPCODE_CALL + am * OPCODE_MODE_MULT;
	gen_code(code);
	gen_am_two(am, t2 ? 2 : 1, 1);
	gen_am(am, fn_idx);
	gen_am_two(am, t1->slot, flags1 & Flag_Free_Argument ? OPCODE_FLAG_FREE_ARGUMENT : 0);
	if (t2)
		gen_am_two(am, t2->slot, flags2 & Flag_Free_Argument ? OPCODE_FLAG_FREE_ARGUMENT : 0);

	if (unlikely(!pcode_finish_call(ctx, &tr, 1, true)))
		goto exception;

	return true;

exception:
	if (md)
		module_designator_free(md);
	if (fd)
		function_designator_free(fd);
	return false;
}

#define sb0(pos)							\
do {									\
	while ((size_t)(pos) >= 8 * *blob_len)				\
		if (unlikely(!array_add_mayfail(uint8_t, blob, blob_len, 0, NULL, err)))\
			return false;					\
} while (0)

#define sb(pos)								\
do {									\
	sb0(pos);							\
	(*blob)[(pos) >> 3] |= 1U << ((pos) & 7);			\
} while (0)

#define re(n, rtype, ntype, pack, unpack)				\
static bool cat(pcode_generate_,rtype)(ntype val, uint8_t **blob, size_t *blob_len, ajla_error_t *err)\
{									\
	int ex_bits, sig_bits;						\
	int min_exp, max_exp, e;					\
	int pos;							\
	ntype norm;							\
	switch (n) {							\
		case 0:	ex_bits = 5; sig_bits = 11; break;		\
		case 1:	ex_bits = 8; sig_bits = 24; break;		\
		case 2:	ex_bits = 11; sig_bits = 53; break;		\
		case 3:	ex_bits = 15; sig_bits = 64; break;		\
		case 4:	ex_bits = 15; sig_bits = 113; break;		\
		default: internal(file_line, "invalid real type %d", n);\
	}								\
	min_exp = -(1 << (ex_bits - 1)) - sig_bits + 3;			\
	max_exp = (1 << (ex_bits - 1)) - sig_bits + 2;			\
	if (unlikely(cat(isnan_,ntype)(val))) {				\
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NAN), err, "NaN");\
		return false;						\
	}								\
	if (unlikely(val == 0)) {					\
		if (unlikely(1. / val < 0))				\
			sb(sig_bits);					\
		e = min_exp;						\
		goto set_e;						\
	}								\
	if (unlikely(val < 0)) {					\
		sb(sig_bits);						\
		val = -val;						\
	}								\
	if (unlikely(!cat(isfinite_,ntype)(val))) {			\
		sb(sig_bits - 1);					\
		e = max_exp;						\
		goto set_e;						\
	}								\
	norm = cat(mathfunc_,ntype)(frexp)(val, &e);			\
	e -= sig_bits;							\
	pos = sig_bits - 1;						\
	if (e < min_exp) {						\
		pos -= min_exp - e;					\
		e = min_exp;						\
	}								\
	while (pos >= 0) {						\
		int bit;						\
		norm *= 2;						\
		bit = norm;						\
		norm -= bit;						\
		if (bit)						\
			sb(pos);					\
		pos--;							\
	}								\
set_e:									\
	pos = sig_bits + 1;						\
	while (e && e != -1) {						\
		if (e & 1)						\
			sb(pos);					\
		pos++;							\
		if (e >= 0)						\
			e >>= 1;					\
		else							\
			e = ~(~e >> 1);					\
	}								\
	do {								\
		if (e & 1)						\
			sb(pos);					\
		else							\
			sb0(pos);					\
		pos++;							\
	} while (pos & 7);						\
	return true;							\
}
for_all_real(re, for_all_empty)
#undef re
#undef sb0
#undef sb

bool pcode_generate_blob_from_value(pointer_t ptr, pcode_t pcode_type, pcode_t **res_blob, size_t *res_len, ajla_error_t *err)
{
	uint8_t *blob;
	size_t blob_len;

	struct data *d;
	const struct type *type;

	type = pcode_to_type(NULL, pcode_type, err);
	if (unlikely(!type))
		return false;

	if (unlikely(!array_init_mayfail(uint8_t, &blob, &blob_len, err)))
		return false;
#define emit_byte(b)							\
do {									\
	if (unlikely(!array_add_mayfail(uint8_t, &blob, &blob_len, b, NULL, err)))\
		return false;						\
} while (0)

	d = pointer_get_data(ptr);
	if (likely(da_tag(d) == DATA_TAG_flat)) {
		bool negative;
		uintbig_t value;
		size_t size, i;
		switch (type->tag) {
#define fx(n, type, utype, sz, bits)					\
			case TYPE_TAG_integer + n:			\
			case TYPE_TAG_fixed + 2 * n + TYPE_TAG_fixed_signed:\
			case TYPE_TAG_fixed + 2 * n + TYPE_TAG_fixed_unsigned:\
				negative = *cast_ptr(type *, da_flat(d)) < 0;\
				value = *cast_ptr(type *, da_flat(d));	\
				size = sz;				\
				goto process_int;
#define re(n, rtype, ntype, pack, unpack)				\
			case TYPE_TAG_real + n:	{			\
				if (unlikely(!cat(pcode_generate_,rtype)(unpack(*cast_ptr(rtype *, da_flat(d))), &blob, &blob_len, err)))\
					return false;			\
				goto process_real;			\
			}
			for_all_fixed(fx);
			for_all_real(re, for_all_empty);
			default:
				internal(file_line, "pcode_generate_blob_from_value: invalid type tag %u", type->tag);
		}
#undef fx
#undef re
		if (0) {
			bool sign;
process_int:
			for (i = 0; i < size; i++) {
				emit_byte(value);
				value >>= 8;
			}
			sign = blob_len && blob[blob_len - 1] & 0x80;
			if (unlikely(sign != negative))
				emit_byte(negative ? 0xff : 0x00);

			while (blob_len >= 2 && blob[blob_len - 1] == (negative ? 0xff : 0x00) && (blob[blob_len - 2] & 0x80) == (negative ? 0x80 : 0x00))
				blob_len--;

			if (blob_len == 1 && !blob[0])
				blob_len = 0;
		}
	} else if (unlikely(da_tag(d) == DATA_TAG_longint)) {
		mem_free(blob);
		if (unlikely(!mpint_export_to_blob(&da(d,longint)->mp, &blob, &blob_len, err)))
			return false;
	} else if (likely(da_tag(d) == DATA_TAG_option)) {
		ajla_option_t opt;
		ajla_assert_lo(pointer_is_empty(da(d,option)->pointer), (file_line, "pcode_generate_blob_from_value: non-empty option"));
		opt = da(d,option)->option;
		do
			emit_byte(opt & 0xff);
		while ((opt >>= 8));
	} else {
		internal(file_line, "pcode_generate_blob_from_value: invalid data tag %u", da_tag(d));
	}

#if REAL_MASK
process_real:
#endif
	if (unlikely(!pcode_generate_blob(blob, blob_len, res_blob, res_len, err))) {
		mem_free(blob);
		return false;
	}

	mem_free(blob);

#undef emit_byte
	return true;
}


#define test(bit)	((size_t)(bit) < 8 * dl ? (d[(bit) >> 3] >> ((bit) & 7)) & 1 : dl ? d[dl - 1] >> 7 : 0)

#define re(n, rtype, ntype, pack, unpack)				\
static inline rtype cat(strto_,rtype)(const unsigned char *d, size_t dl)\
{									\
	int ex_bits, sig_bits;						\
	int ex;								\
	int i;								\
	bool b;								\
	ntype val;							\
	switch (n) {							\
		case 0:	ex_bits = 5; sig_bits = 11; break;		\
		case 1:	ex_bits = 8; sig_bits = 24; break;		\
		case 2:	ex_bits = 11; sig_bits = 53; break;		\
		case 3:	ex_bits = 15; sig_bits = 64; break;		\
		case 4:	ex_bits = 15; sig_bits = 113; break;		\
		default: internal(file_line, "invalid real type %d", n);\
	}								\
	ex = 0;								\
	b = false;							\
	for (i = 0; i < ex_bits + 1; i++) {				\
		b = test(sig_bits + 1 + i);				\
		ex |= (int)b << i;					\
	}								\
	if (b)								\
		ex |= -1U << i;						\
	val = 0;							\
	for (i = 0; i < sig_bits; i++) {				\
		if (test(i)) {						\
			val += cat(mathfunc_,ntype)(ldexp)(1, ex + i);	\
		}							\
	}								\
	if (test(sig_bits))						\
		val = -val;						\
	return pack(val);						\
}
for_all_real(re, for_all_empty)
#undef re

static bool pcode_decode_real(struct build_function_context *ctx, const struct type *type, const char attr_unused *blob, size_t attr_unused blob_l, code_t attr_unused **result, size_t attr_unused *result_len)
{
	switch (type->tag) {
#define re(n, rtype, ntype, pack, unpack)				\
		case TYPE_TAG_real + n: {				\
			rtype val = cat(strto_,rtype)((const unsigned char *)blob, blob_l);\
			*result_len = round_up(sizeof(rtype), sizeof(code_t)) / sizeof(code_t);\
			if (unlikely(!(*result = mem_alloc_array_mayfail(mem_calloc_mayfail, code_t *, 0, 0, *result_len, sizeof(code_t), ctx->err))))\
				goto err;				\
			memcpy(*result, &val, sizeof(rtype));		\
			break;						\
		}
		for_all_real(re, for_all_empty);
		default:
			internal(file_line, "pcode_decode_real(%s): invalid type tag %u", function_name(ctx), type->tag);
#undef re
	}
	return true;

	goto err;
err:
	return false;
}

static bool pcode_generate_constant_from_blob(struct build_function_context *ctx, pcode_t res, uint8_t *blob, size_t l)
{
	const struct pcode_type *pt;
	bool is_emulated_fixed_8, is_emulated_fixed_16;
	const struct type *type;
	size_t orig_l;
	code_t *raw_result = NULL;

	size_t requested_size;
	bool const_swap;
	code_t code;
	arg_mode_t am;

	size_t is;

	pt = get_var_type(ctx, res);
	type = pt->type;
	is_emulated_fixed_8 = pt->extra_type == T_SInt64 || pt->extra_type == T_UInt64;
	is_emulated_fixed_16 = pt->extra_type == T_SInt128 || pt->extra_type == T_UInt128;

	orig_l = l;

	if (TYPE_TAG_IS_FIXED(type->tag)) {
		if (TYPE_TAG_FIXED_IS_UNSIGNED(type->tag) && l == (size_t)type->size + 1 && blob[l - 1] == 0x00)
			l--;
		ajla_assert_lo(l <= type->size, (file_line, "pcode_generate_constant_from_blob(%s): too long constant for type %u", function_name(ctx), type->tag));
		if (l <= sizeof(code_t))
			requested_size = sizeof(code_t);
		else
			requested_size = round_up(type->size, sizeof(code_t));
	} else if (TYPE_TAG_IS_INT(type->tag)) {
		if (is_emulated_fixed_8 && l && blob[l - 1] & 0x80)
			requested_size = 8;
		else if (is_emulated_fixed_16 && l && blob[l - 1] & 0x80)
			requested_size = 16;
		else if (l <= sizeof(code_t))
			requested_size = sizeof(code_t);
		else if (l <= type->size)
			requested_size = round_up(type->size, sizeof(code_t));
		else
			requested_size = round_up(l, sizeof(code_t));
	} else if (TYPE_TAG_IS_REAL(type->tag)) {
		if (!unlikely(pcode_decode_real(ctx, type, cast_ptr(const char *, blob), l, &raw_result, &requested_size)))
			return false;
	} else {
		internal(file_line, "pcode_generate_constant_from_blob(%s): unknown type %u", function_name(ctx), type->tag);
	}

	if (likely(!raw_result)) {
		while (l < requested_size) {
			uint8_t c = !l ? 0 : !(blob[l - 1] & 0x80) ? 0 : 0xff;
			if (unlikely(!array_add_mayfail(uint8_t, &blob, &l, c, NULL, ctx->err)))
				goto exception;
		}
	}

	code = get_code(Op_Ldc, type);
	const_swap = !!CODE_ENDIAN;

	if (TYPE_TAG_IS_FIXED(type->tag)) {
		if (requested_size < type->size)
			code += (OPCODE_FIXED_OP_ldc16 - OPCODE_FIXED_OP_ldc) * OPCODE_FIXED_OP_MULT;
	} else if (TYPE_TAG_IS_INT(type->tag)) {
		if ((is_emulated_fixed_8 || is_emulated_fixed_16) && l && blob[l - 1] & 0x80) {
			if (unlikely(!array_add_mayfail(uint8_t, &blob, &l, 0, NULL, ctx->err)))
				goto exception;
			code = OPCODE_INT_LDC_LONG;
		} else if (requested_size < type->size) {
			code += (OPCODE_INT_OP_ldc16 - OPCODE_INT_OP_ldc) * OPCODE_INT_OP_MULT;
		} else if (requested_size > type->size && orig_l > type->size) {
			code = OPCODE_INT_LDC_LONG;
		}
	}

	am = INIT_ARG_MODE;
	get_arg_mode(am, pt->slot);

	gen_code(code + am * OPCODE_MODE_MULT);
	gen_am(am, pt->slot);
	if (unlikely(code == OPCODE_INT_LDC_LONG)) {
		gen_uint32(l / sizeof(code_t));
		/*debug("load long constant: %zu (%d)", l, type->tag);*/
	}
	if (unlikely(raw_result != NULL)) {
		size_t idx;
		for (idx = 0; idx < requested_size; idx++)
			gen_code(raw_result[idx]);
	} else for (is = 0; is < l; is += sizeof(code_t)) {
		size_t idx = !const_swap ? is : l - sizeof(code_t) - is;
		gen_code(blob[idx] + (blob[idx + 1] << 8));
	}

	mem_free(blob), blob = NULL;
	if (unlikely(raw_result != NULL))
		mem_free(raw_result);

	return true;

exception:
	if (blob)
		mem_free(blob);
	if (raw_result)
		mem_free(raw_result);
	return false;
}

static bool pcode_generate_constant(struct build_function_context *ctx, pcode_t res, int_default_t val)
{
	uint8_t *blob;
	size_t l;
	uint_default_t uval = (uint_default_t)val;

	if (unlikely(!array_init_mayfail(uint8_t, &blob, &l, ctx->err)))
		return false;

	while (uval) {
		if (unlikely(!array_add_mayfail(uint8_t, &blob, &l, (uint8_t)uval, NULL, ctx->err)))
			return false;
		uval >>= 8;
	}

	return pcode_generate_constant_from_blob(ctx, res, blob, l);
}

static bool pcode_generate_option_from_blob(struct build_function_context *ctx, const struct pcode_type *tr, uint8_t *blob, size_t l)
{
	arg_mode_t am;
	size_t i;
	ajla_option_t opt;
	code_t code;

	opt = 0;
	for (i = 0; i < l; i++) {
		ajla_option_t o = (ajla_option_t)blob[i];
		opt |= o << (i * 8);
		if (unlikely(opt >> (i * 8) != o))
			goto exception_overflow;
	}

	am = INIT_ARG_MODE;
	get_arg_mode(am, tr->slot);
	if (likely(opt == (ajla_option_t)(ajla_flat_option_t)opt) && tr->type->tag == TYPE_TAG_flat_option) {
		code = OPCODE_OPTION_CREATE_EMPTY_FLAT;
	} else {
		code = OPCODE_OPTION_CREATE_EMPTY;
	}
	code += am * OPCODE_MODE_MULT;
	gen_code(code);
	gen_am_two(am, tr->slot, opt);

	mem_free(blob);
	return true;

exception_overflow:
	*ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
exception:
	mem_free(blob);
	return false;
}

static bool pcode_load_constant(struct build_function_context *ctx)
{
	pcode_t res;
	uint8_t *blob;
	size_t l;
	const struct pcode_type *tr;

	res = u_pcode_get();
	if (unlikely(!pcode_load_blob(ctx, &blob, &l)))
		return false;

	if (var_elided(res)) {
		mem_free(blob);
		return true;
	}

	tr = get_var_type(ctx, res);

	if (tr->type->tag == TYPE_TAG_flat_option || tr->type->tag == TYPE_TAG_unknown) {
		return pcode_generate_option_from_blob(ctx, tr, blob, l);
	} else {
		return pcode_generate_constant_from_blob(ctx, res, blob, l);
	}
}

static bool pcode_structured_loop(struct build_function_context *ctx, pcode_t n_steps, code_t extra_flags, arg_mode_t *am, bool gen)
{
	pcode_t i = 0;
	do {
		pcode_t type;
		if (i == n_steps - 1)
			extra_flags |= OPCODE_STRUCTURED_FLAG_END;

		type = pcode_get();
		switch (type) {
			case Structured_Record: {
				arg_t idx;
				pcode_t rec_local, q, type_idx;
				const struct record_definition *def;
				frame_t slot;

				rec_local = u_pcode_get();
				q = u_pcode_get();

				idx = (arg_t)q;
				if (unlikely(q != (pcode_t)idx))
					goto exception_overflow;

				def = type_def(pcode_to_type(ctx, rec_local, NULL),record);

				if (record_definition_is_elided(def, idx)) {
					ajla_assert_lo(!gen, (file_line, "pcode_structured_loop(%s): elided record entry in the second pass", function_name(ctx)));
					continue;
				}

				type_idx = pcode_to_type_index(ctx, rec_local, false);
				if (unlikely(type_idx == error_type_index))
					goto exception;

				slot = record_definition_slot(def, idx);
				if (!gen) {
					get_arg_mode(*am, slot);
					get_arg_mode(*am, type_idx);
				} else {
					gen_am_two(*am, OPCODE_STRUCTURED_RECORD | extra_flags, slot);
					gen_am(*am, type_idx);
				}
				break;
			}
			case Structured_Option: {
				ajla_option_t opt;
				pcode_t q;

				q = u_pcode_get();
				opt = (ajla_option_t)q;
				if (unlikely(q != (pcode_t)opt))
					goto exception_overflow;

				if (!gen) {
					get_arg_mode(*am, opt);
				} else {
					gen_am_two(*am, OPCODE_STRUCTURED_OPTION | extra_flags, opt);
					gen_am(*am, 0);
				}
				break;
			}
			case Structured_Array: {
				pcode_t var, local_type, local_idx;
				const struct pcode_type *var_type;

				var = u_pcode_get();

				local_type = pcode_get();

				if (var_elided(var)) {
					ajla_assert_lo(!gen, (file_line, "pcode_structured_loop(%s): elided array index in the second pass", function_name(ctx)));
					continue;
				}

				var_type = get_var_type(ctx, var);
				ajla_assert_lo(type_is_equal(var_type->type, type_get_int(INT_DEFAULT_N)), (file_line, "pcode_structured_loop(%s): invalid index type %u", function_name(ctx), var_type->type->tag));

				local_idx = pcode_to_type_index(ctx, local_type, false);
				if (unlikely(local_idx == error_type_index))
					goto exception;

				if (!gen) {
					get_arg_mode(*am, var_type->slot);
					get_arg_mode(*am, local_idx);
				} else {
					gen_am_two(*am, OPCODE_STRUCTURED_ARRAY | extra_flags, var_type->slot);
					gen_am(*am, local_idx);
				}
				break;
			}
			default:
				internal(file_line, "pcode_structured_loop(%s): invalid type %"PRIdMAX"", function_name(ctx), (uintmax_t)type);
		}
	} while (++i < n_steps);

	return true;

exception_overflow:
	*ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
exception:
	return false;
}

static bool pcode_structured_write(struct build_function_context *ctx)
{
	pcode_t structured, scalar, n_steps;
	bool scalar_deref;
	pcode_t structured_source = 0;		/* avoid warning */
	bool structured_source_deref = false;	/* avoid warning */
	const struct pcode_type *structured_type, *scalar_type;
	code_t extra_flags = 0;
	arg_mode_t am = INIT_ARG_MODE;

	pcode_position_save_t saved;

	n_steps = u_pcode_get();
	ajla_assert_lo(n_steps != 0, (file_line, "pcode_structured_write(%s): zero n_steps", function_name(ctx)));
	structured = u_pcode_get();
	pcode_get_var_deref(&structured_source, &structured_source_deref);
	pcode_get_var_deref(&scalar, &scalar_deref);
	if (scalar_deref)
		extra_flags |= OPCODE_STRUCTURED_FREE_VARIABLE;

	pcode_position_save(ctx, &saved);

	if (!pcode_structured_loop(ctx, n_steps, extra_flags, &am, false))
		goto exception;

	if (unlikely(var_elided(structured)) || unlikely(var_elided(scalar)))
		return true;

	pcode_position_restore(ctx, &saved);

	if (!pcode_copy(ctx, false, structured, structured_source, structured_source_deref))
		goto exception;

	structured_type = get_var_type(ctx, structured);
	scalar_type = get_var_type(ctx, scalar);
	get_arg_mode(am, structured_type->slot);
	get_arg_mode(am, scalar_type->slot);

	gen_code(OPCODE_STRUCTURED + am * OPCODE_MODE_MULT);
	gen_am_two(am, structured_type->slot, scalar_type->slot);

	if (!pcode_structured_loop(ctx, n_steps, extra_flags, &am, true))
		goto exception;

	return true;

exception:
	return false;
}

static bool pcode_record_create(struct build_function_context *ctx)
{
	pcode_t result, q;
	pcode_position_save_t saved;
	pcode_t n_arguments, n_real_arguments;
	const struct pcode_type *tr;
	arg_mode_t am = INIT_ARG_MODE;

	result = u_pcode_get();
	q = u_pcode_get();
	n_arguments = (arg_t)q;
	if (unlikely(q != (pcode_t)n_arguments))
		goto exception_overflow;

	pcode_position_save(ctx, &saved);

	if (unlikely(!pcode_process_arguments(ctx, n_arguments, &n_real_arguments, &am)))
		goto exception;

	pcode_position_restore(ctx, &saved);

	if (unlikely(var_elided(result))) {
		pcode_dereference_arguments(ctx, n_arguments);
		return true;
	}

	tr = get_var_type(ctx, result);
	get_arg_mode(am, tr->slot);

	gen_code(OPCODE_RECORD_CREATE + am * OPCODE_MODE_MULT);
	gen_am_two(am, tr->slot, n_real_arguments);

	if (unlikely(!pcode_process_arguments(ctx, n_arguments, NULL, &am)))
		goto exception;

	return true;

exception_overflow:
	*ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
exception:
	return false;
}

static bool pcode_array_create(struct build_function_context *ctx)
{
	pcode_t result, local_type, length, n_real_arguments;
	pcode_position_save_t saved;
	const struct pcode_type *tr;
	arg_mode_t am = INIT_ARG_MODE;

	result = u_pcode_get();
	local_type = pcode_get();
	length = u_pcode_get();
	pcode_get();

	pcode_position_save(ctx, &saved);

	if (unlikely(!pcode_process_arguments(ctx, length, &n_real_arguments, &am)))
		goto exception;

	pcode_position_restore(ctx, &saved);

	if (unlikely(var_elided(result))) {
		pcode_dereference_arguments(ctx, length);
		return true;
	}

	ajla_assert_lo(length == n_real_arguments, (file_line, "pcode_array_create(%s): some elements are elided: %"PRIdMAX" != %"PRIdMAX"", function_name(ctx), (intmax_t)length, (intmax_t)n_real_arguments));

	tr = get_var_type(ctx, result);
	get_arg_mode(am, tr->slot);

	if (!length) {
		pcode_t type_idx = pcode_to_type_index(ctx, local_type, true);
		if (unlikely(type_idx == error_type_index))
			goto exception;
		if (type_idx == no_type_index) {
			gen_code(OPCODE_ARRAY_CREATE_EMPTY + am * OPCODE_MODE_MULT);
			gen_am(am, tr->slot);
		} else {
			get_arg_mode(am, type_idx);
			gen_code(OPCODE_ARRAY_CREATE_EMPTY_FLAT + am * OPCODE_MODE_MULT);
			gen_am_two(am, tr->slot, type_idx);
		}
	} else {
		get_arg_mode(am, length);
		gen_code(OPCODE_ARRAY_CREATE + am * OPCODE_MODE_MULT);
		gen_am_two(am, tr->slot, length);
		if (unlikely(!pcode_process_arguments(ctx, length, NULL, &am)))
			goto exception;
	}

	return true;

exception:
	return false;
}

static bool pcode_array_string(struct build_function_context *ctx)
{
	pcode_t result;
	uint8_t *blob;
	size_t blob_len, i;
	const struct pcode_type *tr;
	arg_mode_t am = INIT_ARG_MODE;

	result = u_pcode_get();

	if (!pcode_load_blob(ctx, &blob, &blob_len))
		goto exception;
	if (likely(var_elided(result))) {
		mem_free(blob);
		return true;
	}

	tr = get_var_type(ctx, result);
	get_arg_mode(am, tr->slot);
	get_arg_mode(am, blob_len);
	gen_code(OPCODE_ARRAY_STRING + am * OPCODE_MODE_MULT);
	gen_am_two(am, tr->slot, blob_len);
	for (i = 0; i < blob_len; i += 2) {
		union {
			code_t c;
			uint8_t b[2];
		} u;
		u.b[0] = blob[i];
		u.b[1] = i + 1 < blob_len ? blob[i + 1] : 0;
		gen_code(u.c);
	}
	mem_free(blob);
	return true;

exception:
	if (blob)
		mem_free(blob);
	return false;
}

static bool pcode_array_unicode(struct build_function_context *ctx)
{
	pcode_t result;
	pcode_t len, i;
	const struct pcode_type *tr;
	arg_mode_t am = INIT_ARG_MODE;

	result = u_pcode_get();

	len = ctx->pcode_instr_end - ctx->pcode;

	tr = get_var_type(ctx, result);
	get_arg_mode(am, tr->slot);
	get_arg_mode(am, len);
	gen_code(OPCODE_ARRAY_UNICODE + am * OPCODE_MODE_MULT);
	gen_am_two(am, tr->slot, len);
	for (i = 0; i < len; i++) {
		union {
			pcode_t p;
			code_t c[2];
		} u;
		u.p = pcode_get();
		gen_code(u.c[0]);
		gen_code(u.c[1]);
	}
	return true;

exception:
	return false;
}


static bool pcode_io(struct build_function_context *ctx)
{
	pcode_t io_type, n_outputs, n_inputs, n_params;
	unsigned pass;
	bool elided = false;
	code_position_save_t saved;

	code_position_save(ctx, &saved);

	io_type = u_pcode_get();
	n_outputs = u_pcode_get();
	n_inputs = u_pcode_get();
	n_params = u_pcode_get();

	ajla_assert_lo(!((io_type | n_outputs | n_inputs | n_params) & ~0xff), (file_line, "pcode_io(%s): data out of range %"PRIdMAX" %"PRIdMAX" %"PRIdMAX" %"PRIdMAX"", function_name(ctx), (intmax_t)io_type, (intmax_t)n_outputs, (intmax_t)n_inputs, (intmax_t)n_params));

	gen_code(OPCODE_IO);
	gen_code(io_type | (n_outputs << 8));
	gen_code(n_inputs | (n_params << 8));

	for (pass = 0; pass < 3; pass++) {
		unsigned val;
		if (!pass) val = n_outputs;
		else if (pass == 1) val = n_inputs;
		else val = n_params;

		while (val--) {
			pcode_t var = pcode_get();
			if (!pass && var_elided(var))
				elided = true;
			if (!elided) {
				if (pass < 2) {
					const struct pcode_type *t1;
					t1 = get_var_type(ctx, var);
					gen_uint32(t1->slot);
				} else {
					gen_uint32(var);
				}
			}
		}
	}

	if (elided)
		code_position_restore(ctx, &saved);

	return true;

exception:
	return false;
}


static bool pcode_args(struct build_function_context *ctx)
{
	const struct pcode_type *tr;
	arg_t i, vv;

	ajla_assert_lo(!ctx->args, (file_line, "pcode_args(%s): args already specified", function_name(ctx)));

	ctx->args = mem_alloc_array_mayfail(mem_alloc_mayfail, struct local_arg *, 0, 0, ctx->n_arguments, sizeof(struct local_arg), ctx->err);
	if (unlikely(!ctx->args))
		return false;

	for (i = 0, vv = 0; i < ctx->n_arguments; i++) {
		pcode_t res = pcode_get();
		if (unlikely(var_elided(res)))
			continue;
		tr = get_var_type(ctx, res);
		ctx->args[vv].slot = tr->slot;
		ctx->args[vv].may_be_borrowed = !TYPE_IS_FLAT(tr->type);
		ctx->args[vv].may_be_flat = TYPE_IS_FLAT(tr->type);
		ctx->pcode_types[res].argument = &ctx->args[vv];
		ctx->colors[tr->color].is_argument = true;
		if (!TYPE_IS_FLAT(tr->type))
			ctx->local_variables_flags[tr->slot].may_be_borrowed = true;
		vv++;
	}
	ctx->n_real_arguments = vv;

	return true;
}


struct pcode_return_struct {
	pcode_t flags;
	pcode_t res;
};

static bool pcode_return(struct build_function_context *ctx)
{
	arg_mode_t am = INIT_ARG_MODE;
	arg_t i, vv;
	struct pcode_return_struct *prs;

	prs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct pcode_return_struct *, 0, 0, ctx->n_return_values, sizeof(struct pcode_return_struct), ctx->err);
	if (unlikely(!prs))
		goto exception;

	for (i = 0, vv = 0; i < ctx->n_return_values; i++) {
		const struct pcode_type *tr;
		pcode_t flags = u_pcode_get();
		pcode_t res = pcode_get();
		prs[i].flags = flags;
		prs[i].res = res;
		if (unlikely((flags & Flag_Return_Elided) != 0))
			continue;
		tr = get_var_type(ctx, res);
		get_arg_mode(am, tr->slot);
		vv++;
	}

	ajla_assert_lo(ctx->n_real_return_values == vv, (file_line, "pcode_return(%s): return arguments mismatch: %u != %u", function_name(ctx), (unsigned)ctx->n_real_return_values, (unsigned)vv));

	for (i = 0; i < ctx->n_return_values; i++) {
		if (unlikely((prs[i].flags & (Flag_Free_Argument | Flag_Return_Elided)) == (Flag_Free_Argument | Flag_Return_Elided))) {
			arg_t j;
			arg_t q = (arg_t)-1;
			for (j = 0; j < i; j++)
				if (prs[j].res == prs[i].res && !(prs[j].flags & Flag_Return_Elided))
					q = j;
			if (q != (arg_t)-1) {
				prs[q].flags |= Flag_Free_Argument;
			} else {
				if (!pcode_free(ctx, prs[i].res))
					goto exception;
			}
			prs[i].flags &= ~Flag_Free_Argument;
		}
	}

	gen_code(OPCODE_RETURN + am * OPCODE_MODE_MULT);

	for (i = 0; i < ctx->n_return_values; i++) {
		unsigned code_flags;
		const struct pcode_type *tr;
		pcode_t flags = prs[i].flags;
		pcode_t res = prs[i].res;
		if (unlikely((flags & Flag_Return_Elided) != 0))
			continue;
		tr = get_var_type(ctx, res);
		code_flags = 0;
		if (flags & Flag_Free_Argument)
			code_flags |= OPCODE_FLAG_FREE_ARGUMENT;
		gen_am_two(am, tr->slot, code_flags);
	}

	mem_free(prs);
	return true;

exception:
	if (prs)
		mem_free(prs);
	return false;
}

static void pcode_get_instr(struct build_function_context *ctx, pcode_t *instr, pcode_t *instr_params)
{
	*instr = u_pcode_get();
	*instr_params = u_pcode_get();
	ajla_assert(ctx->pcode_limit - ctx->pcode >= *instr_params, (file_line, "pcode_get_instr(%s): instruction %"PRIdMAX" crosses pcode boundary: %"PRIdMAX" > %"PRIdMAX"", function_name(ctx), (intmax_t)*instr, (intmax_t)*instr_params, (intmax_t)(ctx->pcode_limit - ctx->pcode)));
	ctx->pcode_instr_end = ctx->pcode + *instr_params;

}

static bool pcode_preload_ld(struct build_function_context *ctx)
{
	pcode_position_save_t saved;

	pcode_position_save(ctx, &saved);
	while (ctx->pcode != ctx->pcode_limit) {
		pcode_t instr, instr_params;
		pcode_get_instr(ctx, &instr, &instr_params);
		switch (instr) {
			case P_Args:
				if (unlikely(!pcode_args(ctx)))
					goto exception;
				break;
#if NEED_OP_EMULATION
			case P_BinaryOp:
			case P_UnaryOp: {
				const struct pcode_type *tr, *t1;
				pcode_t op = u_pcode_get();
				pcode_t res = u_pcode_get();
				pcode_t flags1 = u_pcode_get();
				pcode_t a1 = pcode_get();
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				if (unlikely(t1->extra_type) || unlikely(tr->extra_type)) {
					if (unlikely(!pcode_op_to_call(ctx, op, tr, t1, flags1, NULL, 0, true)))
						goto exception;
				}
				break;
			}
#endif
			case P_Load_Fn:
			case P_Call: {
				pointer_t *ptr;
				size_t fn_idx;
				ctx->pcode += 3;
				ptr = pcode_module_load_function(ctx);
				if (unlikely(!ptr))
					goto exception;
				fn_idx = pcode_module_load_function_idx(ctx, ptr, false);
				if (unlikely(fn_idx == no_function_idx))
					goto exception;
				break;
			}
		}
		ctx->pcode = ctx->pcode_instr_end;
	}
	pcode_position_restore(ctx, &saved);

	return true;

exception:
	return false;
}

static bool pcode_check_args(struct build_function_context *ctx)
{
	size_t i;
	frame_t *vars = NULL;
	size_t n_vars;
	arg_mode_t am;

	vars = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, ctx->n_real_arguments, sizeof(frame_t), ctx->err);
	if (unlikely(!vars))
		goto exception;

	n_vars = 0;
	am = INIT_ARG_MODE_1;

	for (i = 0; i < ctx->n_real_arguments; i++) {
		frame_t slot = ctx->args[i].slot;
		if (ctx->local_variables_flags[slot].must_be_flat || ctx->local_variables_flags[slot].must_be_data) {
			vars[n_vars++] = slot;
			get_arg_mode(am, slot);
		}
	}

	if (n_vars) {
		code_t code;
		get_arg_mode(am, n_vars);
		code = OPCODE_ESCAPE_NONFLAT;
		code += am * OPCODE_MODE_MULT;
		gen_code(code);
		gen_am(am, n_vars);
		for (i = 0; i < n_vars; i++)
			gen_am(am, vars[i]);
	}

	mem_free(vars);
	vars = NULL;

	return true;

exception:
	if (vars)
		mem_free(vars);
	return false;
}

static bool pcode_generate_instructions(struct build_function_context *ctx)
{
	if (unlikely(!gen_checkpoint(ctx, NULL, 0, false)))
		goto exception;

	if (unlikely(!pcode_check_args(ctx)))
		goto exception;

	while (ctx->pcode != ctx->pcode_limit) {
		pcode_t instr, instr_params;
		pcode_get_instr(ctx, &instr, &instr_params);
		switch (instr) {
			pcode_t p, op, res, a1, a2, aa, flags, flags1, flags2, cnst;
			const struct pcode_type *tr, *t1, *t2, *ta;
			bool a1_deref, a2_deref;
			arg_mode_t am;
			code_t code;
			frame_t fflags;
			struct line_position lp;
			struct record_definition *def;

			case P_BinaryOp:
				op = u_pcode_get();
				ajla_assert_lo(op >= Op_N || Op_IsBinary(op), (file_line, "P_BinaryOp(%s): invalid binary op %"PRIdMAX"", function_name(ctx), (intmax_t)op));
				res = u_pcode_get();
				flags1 = u_pcode_get();
				a1 = pcode_get();
				flags2 = u_pcode_get();
				a2 = pcode_get();
				if (unlikely(var_elided(res))) {
					if (flags1 & Flag_Free_Argument)
						pcode_free(ctx, a1);
					if (flags2 & Flag_Free_Argument)
						pcode_free(ctx, a2);
					break;
				}
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				t2 = get_var_type(ctx, a2);
				ajla_assert_lo(op >= Op_N ||
					(type_is_equal(t1->type, t2->type) &&
					type_is_equal(tr->type, (Op_IsBool(op) ? type_get_flat_option()
					: Op_IsInt(op) ? type_get_int(INT_DEFAULT_N)
					: t1->type))), (file_line, "P_BinaryOp(%s): invalid types for binary operation %"PRIdMAX": %u, %u, %u", function_name(ctx), (intmax_t)op, t1->type->tag, t2->type->tag, tr->type->tag));
				if (NEED_OP_EMULATION && unlikely(t1->extra_type)) {
					if (unlikely(!pcode_op_to_call(ctx, op, tr, t1, flags1, t2, flags2, false)))
						goto exception;
					break;
				}
				fflags = 0;
				if (unlikely(flags1 & Flag_Op_Strict) != 0)
					fflags |= OPCODE_OP_FLAG_STRICT;
				if (flags1 & Flag_Fused_Bin_Jmp)
					fflags |= OPCODE_FLAG_FUSED;
				am = INIT_ARG_MODE;
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, t2->slot);
				get_arg_mode(am, tr->slot);
				code = (code_t)((likely(op < Op_N) ? get_code(op, t1->type) : (code_t)(op - Op_N)) + am * OPCODE_MODE_MULT);
				gen_code(code);
				gen_am_two(am, t1->slot, t2->slot);
				gen_am_two(am, tr->slot, fflags);
				if (flags1 & Flag_Free_Argument) {
					if (t1->slot != tr->slot)
						pcode_free(ctx, a1);
				}
				if (flags2 & Flag_Free_Argument) {
					if (t2->slot != tr->slot)
						pcode_free(ctx, a2);
				}
				break;
			case P_BinaryConstOp:
				op = u_pcode_get();
				ajla_assert_lo(Op_IsBinary(op), (file_line, "P_BinaryConstOp(%s): invalid binary op %"PRIdMAX"", function_name(ctx), (intmax_t)op));
				res = u_pcode_get();
				flags1 = u_pcode_get();
				a1 = pcode_get();
				cnst = pcode_get();
				if (unlikely(var_elided(res))) {
					if (flags1 & Flag_Free_Argument)
						pcode_free(ctx, a1);
					break;
				}
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				ajla_assert_lo(type_is_equal(tr->type, (Op_IsBool(op) ? type_get_flat_option() : t1->type)), (file_line, "P_BinaryConstOp(%s): invalid types for binary operation %"PRIdMAX": %u, %u", function_name(ctx), (intmax_t)op, t1->type->tag, tr->type->tag));
				fflags = 0;
				if (flags1 & Flag_Fused_Bin_Jmp)
					fflags |= OPCODE_FLAG_FUSED;
				am = INIT_ARG_MODE;
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, (frame_t)cnst);
				get_arg_mode(am, tr->slot);
				code = get_code(op, t1->type) + OPCODE_INT_OP_C + am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, t1->slot, (frame_t)cnst);
				gen_am_two(am, tr->slot, fflags);
				if (flags1 & Flag_Free_Argument) {
					if (t1->slot != tr->slot)
						pcode_free(ctx, a1);
				}
				break;
			case P_UnaryOp:
				op = u_pcode_get();
				ajla_assert_lo(op >= Op_N || Op_IsUnary(op), (file_line, "P_UnaryOp(%s): invalid unary op %"PRIdMAX"", function_name(ctx), (intmax_t)op));
				res = u_pcode_get();
				flags1 = u_pcode_get();
				a1 = pcode_get();
				if (unlikely(var_elided(res))) {
					if (flags1 & Flag_Free_Argument)
						pcode_free(ctx, a1);
					break;
				}
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				ajla_assert_lo(op >= Op_N || op == Un_ConvertFromInt ||
					type_is_equal(tr->type, (Op_IsBool(op) ? type_get_flat_option()
					: Op_IsInt(op) ? type_get_int(INT_DEFAULT_N)
					: t1->type)), (file_line, "P_UnaryOp(%s): invalid types for unary operation %"PRIdMAX": %u, %u", function_name(ctx), (intmax_t)op, t1->type->tag, tr->type->tag));
				if (NEED_OP_EMULATION && (unlikely(t1->extra_type) || unlikely(tr->extra_type))) {
					if (unlikely(!pcode_op_to_call(ctx, op, tr, t1, flags1, NULL, 0, false)))
						goto exception;
					break;
				}
				am = INIT_ARG_MODE;
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, tr->slot);
				code = (code_t)((likely(op < Op_N) ? get_code(op, op != Un_ConvertFromInt ? t1->type : tr->type) : (code_t)(op - Op_N)) + am * OPCODE_MODE_MULT);
				gen_code(code);
				gen_am_two(am, t1->slot, tr->slot);
				gen_am(am, flags1 & Flag_Op_Strict ? OPCODE_OP_FLAG_STRICT : 0);
				if (flags1 & Flag_Free_Argument) {
					if (t1->slot != tr->slot)
						pcode_free(ctx, a1);
				}
				break;
			case P_Copy:
			case P_Copy_Type_Cast:
				res = u_pcode_get();
				pcode_get_var_deref(&a1, &a1_deref);
				if (unlikely(var_elided(res))) {
					if (a1_deref) {
						if (unlikely(!pcode_free(ctx, a1)))
							goto exception;
					}
					break;
				}
				if (unlikely(!pcode_copy(ctx, instr != P_Copy, res, a1, a1_deref)))
					goto exception;
				break;
			case P_Free:
				res = u_pcode_get();
				if (unlikely(!pcode_free(ctx, res)))
					goto exception;
				break;
			case P_Eval:
				a1 = pcode_get();
				if (unlikely(var_elided(a1)))
					break;
				t1 = get_var_type(ctx, a1);
				am = INIT_ARG_MODE;
				get_arg_mode(am, t1->slot);
				code = OPCODE_EVAL;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am(am, t1->slot);
				break;
			case P_Keep:
				a1 = pcode_get();
				break;
			case P_Fn:
				res = u_pcode_get();
				ajla_assert_lo(var_elided(res), (file_line, "P_Fn(%s): Fn result is not elided", function_name(ctx)));
				a1 = u_pcode_get();
				a2 = u_pcode_get();
				for (p = 0; p < a1; p++)
					pcode_get();
				for (p = 0; p < a2; p++)
					pcode_get();
				break;
			case P_Load_Local_Type:
				res = u_pcode_get();
				ajla_assert_lo(var_elided(res), (file_line, "P_Load_Local_Type(%s): Load_Local_Type result is not elided", function_name(ctx)));
				pcode_get();
				u_pcode_get();
				break;
			case P_Load_Fn:
			case P_Curry:
			case P_Call_Indirect:
			case P_Call:
				if (unlikely(!pcode_call(ctx, instr)))
					goto exception;
#if 0
				if (instr == P_Call || instr == P_Call_Indirect) {
					pcode_t next, next_params;
					pcode_position_save_t s;
					pcode_position_save(ctx, &s);
next_one:
					pcode_get_instr(ctx, &next, &next_params);
					if (next == P_Line_Info) {
						ctx->pcode = ctx->pcode_instr_end;
						goto next_one;
					}
					pcode_position_restore(ctx, &s);
					//ajla_assert_lo(next == P_Checkpoint, (file_line, "%s: is followed by %"PRIdMAX"", instr == P_Call ? "P_Call" : "P_Call_Indirect", (intmax_t)next));
					debug("%d", next);
					ctx->pcode_instr_end = ctx->pcode;
				}
#endif
				break;
			case P_Load_Const:
				if (unlikely(!pcode_load_constant(ctx)))
					goto exception;
				break;
			case P_Structured_Write:
				if (unlikely(!pcode_structured_write(ctx)))
					goto exception;
				break;
			case P_Record_Type:
			case P_Option_Type:
				for (p = 0; p < instr_params; p++)
					pcode_get();
				break;
			case P_Record_Create:
				if (unlikely(!pcode_record_create(ctx)))
					goto exception;
				break;
			case P_Record_Load_Slot:
				res = u_pcode_get();
				a1 = u_pcode_get();
				op = u_pcode_get();
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, op);
				code = OPCODE_RECORD_LOAD;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, t1->slot, op);
				gen_am_two(am, tr->slot, OPCODE_OP_FLAG_STRICT);
				break;
			case P_Record_Load:
				res = u_pcode_get();
				flags = u_pcode_get();
				a1 = u_pcode_get();
				op = u_pcode_get();
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				if (TYPE_IS_FLAT(tr->type))
					flags &= ~Flag_Borrow;
				if (t1->type->tag == TYPE_TAG_flat_record) {
					def = type_def(type_def(t1->type,flat_record)->base,record);
				} else {
					def = type_def(t1->type,record);
				}
				ajla_assert_lo(!record_definition_is_elided(def, op), (file_line, "P_RecordLoad(%s): record entry %"PRIuMAX" is elided", function_name(ctx), (uintmax_t)op));
				op = record_definition_slot(def, op);
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, op);
				code = OPCODE_RECORD_LOAD;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, t1->slot, op);
				gen_am_two(am, tr->slot,
					(flags & Flag_Evaluate ? OPCODE_OP_FLAG_STRICT : 0) |
					(flags & Flag_Borrow ? OPCODE_STRUCT_MAY_BORROW : 0));
				if (flags & Flag_Borrow)
					ctx->local_variables_flags[tr->slot].may_be_borrowed = true;
				break;
			case P_Option_Load:
				res = u_pcode_get();
				flags = u_pcode_get();
				a1 = u_pcode_get();
				op = u_pcode_get();
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				if (TYPE_IS_FLAT(tr->type))
					flags &= ~Flag_Borrow;
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, op);
				code = OPCODE_OPTION_LOAD;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, t1->slot, op);
				gen_am_two(am, tr->slot,
					(flags & Flag_Evaluate ? OPCODE_OP_FLAG_STRICT : 0) |
					(flags & Flag_Borrow ? OPCODE_STRUCT_MAY_BORROW : 0));
				if (flags & Flag_Borrow)
					ctx->local_variables_flags[tr->slot].may_be_borrowed = true;
				break;
			case P_Option_Create:
				res = u_pcode_get();
				op = u_pcode_get();
				pcode_get_var_deref(&a1, &a1_deref);
				if (unlikely(var_elided(res))) {
					if (a1_deref) {
						if (unlikely(!pcode_free(ctx, a1)))
							goto exception;
					}
					break;
				}
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				ajla_assert_lo(tr->type->tag == TYPE_TAG_flat_option || tr->type->tag == TYPE_TAG_unknown, (file_line, "P_Option_Create(%s): invalid type %u", function_name(ctx), tr->type->tag));
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, op);
				if (unlikely(op != (pcode_t)(ajla_option_t)op))
					goto exception_overflow;
				code = OPCODE_OPTION_CREATE;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, tr->slot, op);
				gen_am_two(am, t1->slot, a1_deref ? OPCODE_FLAG_FREE_ARGUMENT : 0);
				break;
			case P_Option_Test:
				res = u_pcode_get();
				a1 = u_pcode_get();
				op = u_pcode_get();
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				ajla_assert_lo((t1->type->tag == TYPE_TAG_flat_option || t1->type->tag == TYPE_TAG_unknown) && tr->type->tag == TYPE_TAG_flat_option, (file_line, "P_Option_Test(%s): invalid types for option test %u, %u", function_name(ctx), t1->type->tag, tr->type->tag));
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, op);
				if (unlikely(op != (pcode_t)(ajla_option_t)op))
					goto exception_overflow;
				if (t1->type->tag == TYPE_TAG_flat_option)
					code = OPCODE_OPTION_TEST_FLAT;
				else
					code = OPCODE_OPTION_TEST;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, t1->slot, op);
				gen_am(am, tr->slot);
				break;
			case P_Option_Ord:
				res = u_pcode_get();
				a1 = u_pcode_get();
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				ajla_assert_lo((t1->type->tag == TYPE_TAG_flat_option || t1->type->tag == TYPE_TAG_unknown) && type_is_equal(tr->type, type_get_int(INT_DEFAULT_N)), (file_line, "P_Option_Ord(%s): invalid types for option test %u, %u", function_name(ctx), t1->type->tag, tr->type->tag));
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				if (t1->type->tag == TYPE_TAG_flat_option)
					code = OPCODE_OPTION_ORD_FLAT;
				else
					code = OPCODE_OPTION_ORD;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, t1->slot, tr->slot);
				break;
			case P_Array_Flexible:
			case P_Array_Fixed:
				res = u_pcode_get();
				ajla_assert_lo(var_elided(res), (file_line, "P_Array_Flexible(%s): P_Array_Flexible result is not elided", function_name(ctx)));
				a1 = pcode_get();
				ajla_assert_lo(var_elided(a1), (file_line, "P_Array_Flexible(%s): P_Array_Flexible argument is not elided", function_name(ctx)));
				if (instr == P_Array_Fixed)
					pcode_get();
				break;
			case P_Array_Create:
				if (unlikely(!pcode_array_create(ctx)))
					goto exception;
				break;
			case P_Array_Fill:
				res = u_pcode_get();
				pcode_get();	/* local type */
				op = u_pcode_get();
				ajla_assert_lo(!(op & ~(pcode_t)(Flag_Free_Argument | Flag_Array_Fill_Sparse)), (file_line, "P_Array_Fill(%s): invalid flags %"PRIdMAX"", function_name(ctx), (intmax_t)op));
				a1 = pcode_get();
				a2 = pcode_get();
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				t2 = get_var_type(ctx, a2);
				ajla_assert_lo(type_is_equal(t2->type, type_get_int(INT_DEFAULT_N)), (file_line, "P_Array_Fill(%s): invalid length type: %u", function_name(ctx), t2->type->tag));
				am = INIT_ARG_MODE;
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, t2->slot);
				get_arg_mode(am, tr->slot);
				gen_code(OPCODE_ARRAY_FILL + am * OPCODE_MODE_MULT);
				gen_am_two(am, t1->slot,
					((op & Flag_Free_Argument) ? OPCODE_FLAG_FREE_ARGUMENT : 0) |
					((op & Flag_Array_Fill_Sparse) ? OPCODE_ARRAY_FILL_FLAG_SPARSE : 0)
					);
				gen_am_two(am, t2->slot, tr->slot);
				break;
			case P_Array_String:
				if (unlikely(!pcode_array_string(ctx)))
					goto exception;
				break;
			case P_Array_Unicode:
				if (unlikely(!pcode_array_unicode(ctx)))
					goto exception;
				break;
			case P_Array_Load:
				res = u_pcode_get();
				flags = u_pcode_get();
				a1 = u_pcode_get();
				a2 = u_pcode_get();
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				t2 = get_var_type(ctx, a2);
				if (TYPE_IS_FLAT(tr->type))
					flags &= ~Flag_Borrow;
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, t2->slot);
				code = OPCODE_ARRAY_LOAD;
				code += am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am_two(am, t1->slot, t2->slot);
				gen_am_two(am, tr->slot,
					(flags & Flag_Evaluate ? OPCODE_OP_FLAG_STRICT : 0) |
					(flags & Flag_Borrow ? OPCODE_STRUCT_MAY_BORROW : 0) |
					(flags & Flag_Index_In_Range ? OPCODE_ARRAY_INDEX_IN_RANGE : 0));
				if (flags & Flag_Borrow)
					ctx->local_variables_flags[tr->slot].may_be_borrowed = true;
				break;
			case P_Array_Len:
				res = u_pcode_get();
				a1 = u_pcode_get();
				flags = u_pcode_get();
				ajla_assert_lo(!(flags & ~Flag_Evaluate), (file_line, "P_Array_Len(%s): invalid flags %"PRIuMAX"", function_name(ctx), (uintmax_t)flags));
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				ajla_assert_lo(type_is_equal(tr->type, type_get_int(INT_DEFAULT_N)), (file_line, "P_Array_Len(%s): invalid result type: %u", function_name(ctx), tr->type->tag));
				if (TYPE_IS_FLAT(t1->type)) {
					ajla_assert_lo(t1->type->tag == TYPE_TAG_flat_array, (file_line, "P_Array_Len(%s): invalid flat array type: %u", function_name(ctx), t1->type->tag));
					if (unlikely(!pcode_generate_constant(ctx, res, (int_default_t)type_def(t1->type,flat_array)->n_elements)))
						goto exception;
				} else {
					ajla_assert_lo(t1->type->tag == TYPE_TAG_unknown, (file_line, "P_Array_Len(%s): invalid array type: %u", function_name(ctx), t1->type->tag));
					am = INIT_ARG_MODE;
					get_arg_mode(am, t1->slot);
					get_arg_mode(am, tr->slot);
					gen_code(OPCODE_ARRAY_LEN + am * OPCODE_MODE_MULT);
					gen_am_two(am, t1->slot, tr->slot);
					gen_am(am, flags & Flag_Evaluate ? OPCODE_OP_FLAG_STRICT : 0);
				}
				break;
			case P_Array_Len_Greater_Than:
				res = u_pcode_get();
				a1 = u_pcode_get();
				a2 = u_pcode_get();
				flags = u_pcode_get();
				ajla_assert_lo(!(flags & ~(Flag_Evaluate | Flag_Fused_Bin_Jmp)), (file_line, "P_Array_Len_Greater_Than(%s): invalid flags %"PRIuMAX"", function_name(ctx), (uintmax_t)flags));
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				t2 = get_var_type(ctx, a2);
				ajla_assert_lo(type_is_equal(tr->type, type_get_flat_option()), (file_line, "P_Array_Len_Greater_Than(%s): invalid result type: %u", function_name(ctx), tr->type->tag));
				ajla_assert_lo(type_is_equal(t2->type, type_get_int(INT_DEFAULT_N)), (file_line, "P_Array_Len_Greater_Than(%s): invalid length type: %u", function_name(ctx), t2->type->tag));

				fflags = 0;
				if (unlikely(flags & Flag_Evaluate) != 0)
					fflags |= OPCODE_OP_FLAG_STRICT;
				if (flags & Flag_Fused_Bin_Jmp)
					fflags |= OPCODE_FLAG_FUSED;
				am = INIT_ARG_MODE;
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, t2->slot);
				get_arg_mode(am, tr->slot);
				gen_code(OPCODE_ARRAY_LEN_GREATER_THAN + am * OPCODE_MODE_MULT);
				gen_am_two(am, t1->slot, t2->slot);
				gen_am_two(am, tr->slot, fflags);
				break;
			case P_Array_Sub:
				res = u_pcode_get();
				flags = u_pcode_get();
				aa = u_pcode_get();
				a1 = u_pcode_get();
				a2 = u_pcode_get();
				ajla_assert_lo(!(flags & ~(Flag_Free_Argument | Flag_Evaluate)), (file_line, "P_Array_Sub(%s): invalid flags %"PRIuMAX"", function_name(ctx), (uintmax_t)flags));
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				ta = get_var_type(ctx, aa);
				t1 = get_var_type(ctx, a1);
				t2 = get_var_type(ctx, a2);
				ajla_assert_lo(type_is_equal(t1->type, type_get_int(INT_DEFAULT_N)), (file_line, "P_Array_Sub(%s): invalid length type: %u", function_name(ctx), t1->type->tag));
				ajla_assert_lo(type_is_equal(t2->type, type_get_int(INT_DEFAULT_N)), (file_line, "P_Array_Sub(%s): invalid length type: %u", function_name(ctx), t2->type->tag));

				am = INIT_ARG_MODE;
				get_arg_mode(am, ta->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, t2->slot);
				get_arg_mode(am, tr->slot);
				gen_code(OPCODE_ARRAY_SUB + am * OPCODE_MODE_MULT);
				gen_am_two(am, ta->slot, t1->slot);
				gen_am_two(am, t2->slot, tr->slot);
				gen_am(am,
					(flags & Flag_Free_Argument ? OPCODE_FLAG_FREE_ARGUMENT : 0) |
					(flags & Flag_Evaluate ? OPCODE_OP_FLAG_STRICT : 0)
					);
				break;
			case P_Array_Skip:
				res = u_pcode_get();
				flags = u_pcode_get();
				aa = u_pcode_get();
				a1 = u_pcode_get();
				ajla_assert_lo(!(flags & ~(Flag_Free_Argument | Flag_Evaluate)), (file_line, "P_Array_Skip(%s): invalid flags %"PRIuMAX"", function_name(ctx), (uintmax_t)flags));
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				ta = get_var_type(ctx, aa);
				t1 = get_var_type(ctx, a1);
				ajla_assert_lo(type_is_equal(t1->type, type_get_int(INT_DEFAULT_N)), (file_line, "P_Array_Skip(%s): invalid length type: %u", function_name(ctx), t1->type->tag));

				am = INIT_ARG_MODE;
				get_arg_mode(am, ta->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, tr->slot);
				gen_code(OPCODE_ARRAY_SKIP + am * OPCODE_MODE_MULT);
				gen_am_two(am, ta->slot, t1->slot);
				gen_am_two(am, tr->slot,
					(flags & Flag_Free_Argument ? OPCODE_FLAG_FREE_ARGUMENT : 0) |
					(flags & Flag_Evaluate ? OPCODE_OP_FLAG_STRICT : 0)
					);
				break;
			case P_Array_Append:
			case P_Array_Append_One:
				res = u_pcode_get();
				pcode_get_var_deref(&a1, &a1_deref);
				pcode_get_var_deref(&a2, &a2_deref);
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				t2 = get_var_type(ctx, a2);
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				get_arg_mode(am, t2->slot);
				if (instr == P_Array_Append) {
					gen_code(OPCODE_ARRAY_APPEND + am * OPCODE_MODE_MULT);
				} else {
					if (TYPE_IS_FLAT(t2->type)) {
						gen_code(OPCODE_ARRAY_APPEND_ONE_FLAT + am * OPCODE_MODE_MULT);
					} else {
						gen_code(OPCODE_ARRAY_APPEND_ONE + am * OPCODE_MODE_MULT);
					}
				}
				gen_am_two(am, tr->slot, (a1_deref ? OPCODE_FLAG_FREE_ARGUMENT : 0) | (a2_deref ? OPCODE_FLAG_FREE_ARGUMENT_2 : 0));
				gen_am_two(am, t1->slot, t2->slot);
				break;
			case P_Array_Flatten:
				res = u_pcode_get();
				pcode_get_var_deref(&a1, &a1_deref);
				if (unlikely(var_elided(res)))
					break;
				tr = get_var_type(ctx, res);
				t1 = get_var_type(ctx, a1);
				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				get_arg_mode(am, t1->slot);
				gen_code(OPCODE_ARRAY_FLATTEN + am * OPCODE_MODE_MULT);
				gen_am_two(am, tr->slot, (a1_deref ? OPCODE_FLAG_FREE_ARGUMENT : 0));
				gen_am(am, t1->slot);
				break;
			case P_Jmp:
				res = u_pcode_get();
				ajla_assert_lo(res < ctx->n_labels, (file_line, "P_Jmp(%s): invalid label %"PRIdMAX"", function_name(ctx), (intmax_t)res));
#if SIZEOF_IP_T > 2
				if (ctx->labels[res] != no_label) {
					uint32_t target;
					target = (uint32_t)((ctx->code_len - ctx->labels[res]) * sizeof(code_t));
					if (likely(target < 0x10000)) {
						gen_code(OPCODE_JMP_BACK_16);
						gen_code((code_t)target);
						break;
					}
				}
#endif
				gen_code(OPCODE_JMP);
				gen_relative_jump(res, SIZEOF_IP_T);
				break;
			case P_Jmp_False:
				res = pcode_get();
				tr = get_var_type(ctx, res);
				ajla_assert_lo(type_is_equal(tr->type, type_get_flat_option()), (file_line, "P_Jmp_False(%s): invalid type for conditional jump: %u", function_name(ctx), tr->type->tag));

				a1 = u_pcode_get();
				a2 = u_pcode_get();

				am = INIT_ARG_MODE;
				get_arg_mode(am, tr->slot);
				code = OPCODE_JMP_FALSE + am * OPCODE_MODE_MULT;
				gen_code(code);
				gen_am(am, tr->slot);
				gen_relative_jump(a1, SIZEOF_IP_T * 2);
				gen_relative_jump(a2, SIZEOF_IP_T);
				break;
			case P_Label:
				gen_code(OPCODE_LABEL);
				res = u_pcode_get();
				ajla_assert_lo(res < ctx->n_labels, (file_line, "P_Label(%s): invalid label %"PRIdMAX"", function_name(ctx), (intmax_t)res));
				ajla_assert_lo(ctx->labels[res] == no_label, (file_line, "P_Label(%s): label %"PRIdMAX" already defined", function_name(ctx), (intmax_t)res));
				ctx->labels[res] = ctx->code_len;
				break;
			case P_IO:
				if (unlikely(!pcode_io(ctx)))
					goto exception;
				break;
			case P_Args:
				ctx->pcode = ctx->pcode_instr_end;
				break;
			case P_Return_Vars:
				for (p = 0; p < instr_params; p++)
					pcode_get();
				break;
			case P_Return:
				if (unlikely(!pcode_return(ctx)))
					goto exception;
				break;
			case P_Checkpoint:
				if (unlikely(!gen_checkpoint(ctx, ctx->pcode, instr_params, true)))
					goto exception;
				for (p = 0; p < instr_params; p++)
					u_pcode_get();
				break;
			case P_Line_Info:
				lp.line = u_pcode_get();
				lp.ip = ctx->code_len;
				if (unlikely(!array_add_mayfail(struct line_position, &ctx->lp, &ctx->lp_size, lp, NULL, ctx->err)))
					goto exception;
				break;
			default:
				internal(file_line, "pcode_generate_instructions(%s): invalid pcode %"PRIdMAX"", function_name(ctx), (intmax_t)instr);
		}

		if (unlikely(ctx->pcode != ctx->pcode_instr_end)) {
			const pcode_t *pp;
			char *s;
			size_t l;
			str_init(&s, &l);
			for (pp = ctx->pcode_instr_end - instr_params - 2; pp < ctx->pcode; pp++) {
				str_add_char(&s, &l, ' ');
				str_add_signed(&s, &l, *pp, 10);
			}
			str_finish(&s, &l);
			internal(file_line, "pcode_generate_instructions(%s): mismatched instruction %"PRIdMAX" length: %"PRIdMAX" != %"PRIdMAX":%s", function_name(ctx), (intmax_t)instr, (intmax_t)(ctx->pcode - (ctx->pcode_instr_end - instr_params)), (intmax_t)instr_params, s);
		}
	}
	if (unlikely(ctx->code_len > sign_bit(ip_t) / sizeof(code_t) + uzero))
		goto exception_overflow;
	return true;

exception_overflow:
	*ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
exception:
	return false;
}

static bool pcode_generate_record(struct build_function_context *ctx)
{
	arg_t ai;
	frame_t layout_idx;
	struct record_definition *def;
	if (unlikely(!array_init_mayfail(frame_t, &ctx->record_entries, &ctx->record_entries_len, ctx->err)))
		goto exception;

	ctx->layout = layout_start(slot_bits, frame_flags_per_slot_bits, slot_size, data_record_offset, ctx->err);
	if (unlikely(!ctx->layout))
		goto exception;

	for (; ctx->pcode != ctx->pcode_limit; ctx->pcode = ctx->pcode_instr_end) {
		pcode_t instr, instr_params;
		pcode_get_instr(ctx, &instr, &instr_params);

		if (instr == P_Load_Local_Type) {
			pcode_t var, fn_var;
			pcode_t attr_unused idx;
			const struct pcode_type *p;
			const struct type *t;

			ajla_assert_lo(instr_params == 3, (file_line, "pcode_generate_record(%s): invalid number of parameters %"PRIdMAX"", function_name(ctx), (intmax_t)instr_params));

			var = u_pcode_get();
			fn_var = pcode_get();
			idx = u_pcode_get();
			if (unlikely(fn_var != -1))
				continue;
			if (unlikely(var != (pcode_t)(frame_t)var))
				goto exception_overflow;
			ajla_assert_lo((size_t)idx == ctx->record_entries_len, (file_line, "pcode_generate_record(%s): invalid index: %"PRIdMAX" != %"PRIuMAX"", function_name(ctx), (intmax_t)idx, (uintmax_t)ctx->record_entries_len));

			if (unlikely(!array_add_mayfail(frame_t, &ctx->record_entries, &ctx->record_entries_len, var, NULL, ctx->err)))
				goto exception;

			if (var_elided(var))
				continue;

			p = get_var_type(ctx, var);
			t = p->type;

			if (unlikely(!layout_add(ctx->layout, maximum(t->size, 1), t->align, ctx->err)))
				goto exception;
		}
	}

	array_finish(frame_t, &ctx->record_entries, &ctx->record_entries_len);

	if (unlikely(ctx->record_entries_len != (size_t)(arg_t)ctx->record_entries_len))
		goto exception_overflow;

	if (unlikely(!layout_compute(ctx->layout, false, ctx->err)))
		goto exception;


	def = type_alloc_record_definition(layout_size(ctx->layout), ctx->err);
	if (unlikely(!def))
		goto exception;
	def->n_slots = layout_size(ctx->layout);
	def->alignment = maximum(layout_alignment(ctx->layout), frame_align);
	def->n_entries = (arg_t)ctx->record_entries_len;

	layout_idx = 0;
	for (ai = 0; ai < ctx->record_entries_len; ai++) {
		frame_t var, slot;
		const struct pcode_type *te;
		var = ctx->record_entries[ai];
		if (var_elided((pcode_t)var)) {
			ctx->record_entries[ai] = NO_FRAME_T;
			continue;
		}
		slot = layout_get(ctx->layout, layout_idx++);
		ctx->record_entries[ai] = slot;
		te = get_var_type(ctx, (pcode_t)var);
		def->types[slot] = te->type;
	}

	def->idx_to_frame = ctx->record_entries, ctx->record_entries = NULL;
	ctx->record_definition = def;

	layout_free(ctx->layout), ctx->layout = NULL;

	return true;

exception_overflow:
	*ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
exception:
	return false;
}

/*
 * pointer_empty -> ret_ex
 * poitner_mark -> err
 * other -> thunk(error) or data(function)
 */
static pointer_t pcode_build_function_core(frame_s *fp, const code_t *ip, const pcode_t *pcode, size_t size, const struct module_designator *md, const struct function_designator *fd, void **ret_ex, ajla_error_t *err)
{
	frame_t v;
	pcode_t p, q, subfns;

	size_t is;

	struct data *ft, *fn;
	struct function_descriptor *sfd;
	bool is_saved;

#if defined(HAVE_CODEGEN)
	union internal_arg ia[1];
#endif

	struct build_function_context ctx_;
	struct build_function_context *ctx = &ctx_;

	init_ctx(ctx);
	ctx->err = err;
	ctx->pcode = pcode;
	ctx->pcode_limit = pcode + size;
	ctx->is_eval = !fp;

	q = u_pcode_get() & Fn_Mask;
	ajla_assert_lo(q == Fn_Function || q == Fn_Record || q == Fn_Option, (file_line, "pcode_build_function_core: invalid function type %"PRIdMAX"", (intmax_t)q));
	ctx->function_type = q;

	u_pcode_get();	/* call mode - used by the optimizer */

	subfns = u_pcode_get();

	ctx->n_local_types = u_pcode_get();

	q = u_pcode_get();
	ctx->n_local_variables = (frame_t)q;
	if (unlikely(q != (pcode_t)ctx->n_local_variables))
		goto exception_overflow;

	q = u_pcode_get();
	ctx->n_arguments = (arg_t)q;
	ajla_assert_lo(q == (pcode_t)ctx->n_arguments, (file_line, "pcode_build_function_core: overflow in n_arguments"));

	q = u_pcode_get();
	ctx->n_return_values = (arg_t)q;
	ajla_assert_lo(q == (pcode_t)ctx->n_return_values, (file_line, "pcode_build_function_core: overflow in n_return_values"));

	ajla_assert_lo((arg_t)ctx->n_arguments <= ctx->n_local_variables, (file_line, "pcode_build_function_core: invalid ctx->n_arguments or ctx->n_local_variables"));

	q = u_pcode_get();
	ctx->n_real_return_values = (arg_t)q;
	ajla_assert_lo(ctx->n_real_return_values <= ctx->n_return_values, (file_line, "pcode_build_function_core: invalid n_real_return_values"));

	ctx->n_labels = u_pcode_get();

	if (unlikely(!pcode_load_blob(ctx, &ctx->function_name, &is)))
		goto exception;
	if (unlikely(!array_add_mayfail(uint8_t, &ctx->function_name, &is, 0, NULL, ctx->err)))
		goto exception;
	array_finish(uint8_t, &ctx->function_name, &is);

	while (subfns--) {
		q = u_pcode_get();
		while (q--)
			pcode_get();
	}

	ctx->local_types = mem_alloc_array_mayfail(mem_alloc_mayfail, struct local_type *, 0, 0, ctx->n_local_types, sizeof(struct local_type), ctx->err);
	if (unlikely(!ctx->local_types))
		goto exception;

	for (p = 0; p < ctx->n_local_types; p++) {
		pointer_t *ptr;
		struct data *rec_fn;
		const struct record_definition *def;
		pcode_t base_idx, n_elements;
		struct type_entry *flat_rec;
		arg_t ai;
		const struct type *tt, *tp;

		q = pcode_get();
		switch (q) {
			case Local_Type_Record:
				ptr = pcode_module_load_function(ctx);
				if (unlikely(!ptr))
					goto exception;
				pointer_follow(ptr, false, rec_fn, PF_WAIT, fp, ip,
					*ret_ex = ex_;
					ctx->ret_val = pointer_empty();
					goto ret,
					thunk_reference(thunk_);
					ctx->ret_val = pointer_thunk(thunk_);
					goto ret;
				);
				ajla_assert_lo(da(rec_fn,function)->record_definition != NULL, (file_line, "pcode_build_function_core(%s): record has no definition", function_name(ctx)));
				def = type_def(da(rec_fn,function)->record_definition,record);
				tt = &def->type;
				break;
			case Local_Type_Flat_Record:
				base_idx = u_pcode_get();
				ajla_assert_lo(base_idx < p, (file_line, "pcode_build_function_core(%s): invalid base record index: %"PRIdMAX" >= %"PRIdMAX"", function_name(ctx), (intmax_t)base_idx, (intmax_t)p));
				n_elements = u_pcode_get();
				def = type_def(ctx->local_types[base_idx].type,record);
				ajla_assert_lo(n_elements == (pcode_t)def->n_entries, (file_line, "pcode_build_function_core(%s): the number of entries doesn't match: %"PRIdMAX" != %"PRIuMAX"", function_name(ctx), (intmax_t)n_elements, (uintmax_t)def->n_entries));
				flat_rec = type_prepare_flat_record(&def->type, ctx->err);
				if (unlikely(!flat_rec))
					goto record_not_flattened;
				for (ai = 0; ai < def->n_entries; ai++) {
					pcode_t typ = pcode_get();
					tp = pcode_to_type(ctx, typ, NULL);
					if (unlikely(!TYPE_IS_FLAT(tp))) {
						type_free_flat_record(flat_rec);
						goto record_not_flattened;
					}
					type_set_flat_record_entry(flat_rec, ai, tp);
				}
				tt = type_get_flat_record(flat_rec, ctx->err);
				if (unlikely(!tt))
					goto record_not_flattened;
				break;
			record_not_flattened:
				tt = &def->type;
				break;
			case Local_Type_Flat_Array:
				base_idx = pcode_get();
				n_elements = pcode_get();
				tp = pcode_to_type(ctx, base_idx, NULL);
				if (unlikely(!TYPE_IS_FLAT(tp)))
					goto array_not_flattened;
				if (unlikely(n_elements > signed_maximum(int_default_t) + zero))
					goto array_not_flattened;
				tt = type_get_flat_array(tp, n_elements, ctx->err);
				if (unlikely(!tt))
					goto array_not_flattened;
				break;
			array_not_flattened:
				tt = type_get_unknown();
				break;
			default:
				internal(file_line, "pcode_build_function_core(%s): invalid local type %"PRIdMAX"", function_name(ctx), (intmax_t)q);
		}
		ctx->local_types[p].type = tt;
		ctx->local_types[p].type_index = no_type_index;
	}

	ctx->layout = layout_start(slot_bits, frame_flags_per_slot_bits, frame_align, frame_offset, ctx->err);
	if (unlikely(!ctx->layout))
		goto exception;

	ctx->pcode_types = mem_alloc_array_mayfail(mem_alloc_mayfail, struct pcode_type *, 0, 0, ctx->n_local_variables, sizeof(struct pcode_type), ctx->err);
	if (unlikely(!ctx->pcode_types))
		goto exception;

	if (unlikely(!array_init_mayfail(struct color, &ctx->colors, &ctx->n_colors, ctx->err)))
		goto exception;
	is = 0;
	for (v = 0; v < ctx->n_local_variables; v++) {
		struct pcode_type *pt;
		pcode_t typ, color, varflags;

		pcode_get();
		typ = pcode_get();
		color = pcode_get();
		varflags = u_pcode_get();
		pcode_load_blob(ctx, NULL, NULL);
		pt = &ctx->pcode_types[v];
		pt->argument = NULL;
		pt->extra_type = 0;
		pt->varflags = varflags;

		if (color == -1) {
			pt->type = NULL;
		} else {
			const struct type *t = pcode_to_type(ctx, typ, NULL);
			struct color empty_color = { 0, 0, false };
			is++;

			pt->type = t;
			pt->color = color;
			if (typ < 0 && !pcode_get_type(typ))
				pt->extra_type = typ;
			while ((size_t)color >= ctx->n_colors)
				if (unlikely(!array_add_mayfail(struct color, &ctx->colors, &ctx->n_colors, empty_color, NULL, ctx->err)))
					goto exception;


			if (!ctx->colors[color].align) {
				ctx->colors[color].size = t->size;
				ctx->colors[color].align = t->align;
			} else {
				ajla_assert_lo(ctx->colors[color].size == t->size  &&
					       ctx->colors[color].align == t->align,
					       (file_line, "pcode_build_function_core(%s): mismatching variables are put into the same slot: %u != %u || %u != %u", function_name(ctx), ctx->colors[color].size, t->size, ctx->colors[color].align, t->align));
			}

		}
	}
	/*debug("n_local_variables: %s: %u * %zu = %zu (valid %zu, colors %zu, pcode %zu / %zu)", function_name(ctx), ctx->n_local_variables, sizeof(struct pcode_type), ctx->n_local_variables * sizeof(struct pcode_type), is, ctx->n_colors, ctx->pcode - pcode, ctx->pcode_limit - ctx->pcode);*/

	for (is = 0; is < ctx->n_colors; is++) {
		const struct color *c = &ctx->colors[is];
		if (c->align) {
			if (unlikely(!layout_add(ctx->layout, maximum(c->size, 1), c->align, ctx->err)))
				goto exception;
		} else {
			if (unlikely(!layout_add(ctx->layout, 0, 1, ctx->err)))
				goto exception;
		}
	}

	if (unlikely(!layout_compute(ctx->layout, false, ctx->err)))
		goto exception;

	ctx->n_slots = layout_size(ctx->layout);

	ctx->local_variables = mem_alloc_array_mayfail(mem_calloc_mayfail, struct local_variable *, 0, 0, ctx->n_slots, sizeof(struct local_variable), ctx->err);
	if (unlikely(!ctx->local_variables))
		goto exception;

	ctx->local_variables_flags = mem_alloc_array_mayfail(mem_calloc_mayfail, struct local_variable_flags *, 0, 0, ctx->n_slots, sizeof(struct local_variable_flags), ctx->err);
	if (unlikely(!ctx->local_variables_flags))
		goto exception;

	for (v = 0; v < ctx->n_local_variables; v++) {
		struct pcode_type *pt = &ctx->pcode_types[v];
		if (!pt->type) {
			pt->slot = NO_FRAME_T;
		} else {
			pt->slot = layout_get(ctx->layout, pt->color);
			ctx->local_variables[pt->slot].type = pt->type;
			/*ctx->local_variables_flags[pt->slot].may_be_borrowed = false;*/
			/*if (pt->type->tag == TYPE_TAG_flat_option && !(pt->varflags & VarFlag_Must_Be_Flat))
				debug("non-flat variable in %s", function_name(ctx));*/
			ctx->local_variables_flags[pt->slot].must_be_flat = !!(pt->varflags & VarFlag_Must_Be_Flat);
			ctx->local_variables_flags[pt->slot].must_be_data = !!(pt->varflags & VarFlag_Must_Be_Data);
		}
	}

	layout_free(ctx->layout), ctx->layout = NULL;

#if 0
	{
		unsigned n_elided = 0;
		for (v = 0; v < ctx->n_local_variables; v++) {
			struct pcode_type *pt = &ctx->pcode_types[v];
			if (!pt->type)
				n_elided++;
		}
		debug("function, elided %d/%d", n_elided, ctx->n_local_variables);
	}
#endif

	if (unlikely(!array_init_mayfail(pointer_t *, &ctx->ld, &ctx->ld_len, ctx->err)))
		goto exception;

	if (unlikely(!pcode_preload_ld(ctx)))
		goto exception;

	if (md) {
		sfd = save_find_function_descriptor(md, fd);
	} else {
		sfd = NULL;
	}

	is_saved = false;
	if (sfd) {
		ctx->code = sfd->code;
		ctx->code_len = sfd->code_size;
		ft = sfd->types;
		is_saved = true;
		goto skip_codegen;
	}

	ctx->labels = mem_alloc_array_mayfail(mem_alloc_mayfail, size_t *, 0, 0, ctx->n_labels, sizeof(size_t), ctx->err);
	if (unlikely(!ctx->labels))
		goto exception;
	for (p = 0; p < ctx->n_labels; p++)
		ctx->labels[p] = no_label;

	if (unlikely(!array_init_mayfail(struct label_ref, &ctx->label_ref, &ctx->label_ref_len, ctx->err)))
		goto exception;

	if (unlikely(!array_init_mayfail(const struct type *, &ctx->types, &ctx->types_len, ctx->err)))
		goto exception;

	if (unlikely(!array_init_mayfail(code_t, &ctx->code, &ctx->code_len, ctx->err)))
		goto exception;

	if (unlikely(!array_init_mayfail(struct line_position, &ctx->lp, &ctx->lp_size, ctx->err)))
		goto exception;

	if (unlikely(ctx->function_type == Fn_Record) || unlikely(ctx->function_type == Fn_Option)) {
		if (ctx->function_type == Fn_Record) {
			if (unlikely(!pcode_generate_record(ctx)))
				goto exception;
		}
		gen_code(OPCODE_UNREACHABLE);
	} else {
		if (unlikely(!pcode_generate_instructions(ctx)))
			goto exception;
	}

	array_finish(code_t, &ctx->code, &ctx->code_len);
	array_finish(struct line_position, &ctx->lp, &ctx->lp_size);

	for (is = 0; is < ctx->label_ref_len; is++) {
		uint32_t diff;
		struct label_ref *lr = &ctx->label_ref[is];
		ajla_assert_lo(lr->label < ctx->n_labels, (file_line, "pcode_build_function_core(%s): invalid label %"PRIdMAX"", function_name(ctx), (intmax_t)lr->label));
		ajla_assert_lo(ctx->labels[lr->label] != no_label, (file_line, "pcode_build_function_core(%s): label %"PRIdMAX" was not defined", function_name(ctx), (intmax_t)lr->label));
		diff = ((uint32_t)ctx->labels[lr->label] - (uint32_t)lr->code_pos) * sizeof(code_t);
		if (SIZEOF_IP_T == 2) {
			ctx->code[lr->code_pos] += (code_t)diff;
		} else if (SIZEOF_IP_T == 4 && !CODE_ENDIAN) {
			uint32_t val = ctx->code[lr->code_pos] | ((uint32_t)ctx->code[lr->code_pos + 1] << 16);
			val += diff;
			ctx->code[lr->code_pos] = val & 0xffff;
			ctx->code[lr->code_pos + 1] = val >> 16;
		} else if (SIZEOF_IP_T == 4 && CODE_ENDIAN) {
			uint32_t val = ((uint32_t)ctx->code[lr->code_pos] << 16) | ctx->code[lr->code_pos + 1];
			val += diff;
			ctx->code[lr->code_pos] = val >> 16;
			ctx->code[lr->code_pos + 1] = val & 0xffff;
		} else {
			not_reached();
		}
	}

	mem_free(ctx->labels), ctx->labels = NULL;
	mem_free(ctx->label_ref), ctx->label_ref = NULL;

	ft = data_alloc_flexible(function_types, types, ctx->types_len, ctx->err);
	if (unlikely(!ft))
		goto exception;
	da(ft,function_types)->n_types = ctx->types_len;
	memcpy(da(ft,function_types)->types, ctx->types, ctx->types_len * sizeof(const struct type *));
	mem_free(ctx->types);
	ctx->types = NULL;
	ctx->ft_free = ft;

skip_codegen:

	mem_free(ctx->colors), ctx->colors = NULL;
	mem_free(ctx->pcode_types), ctx->pcode_types = NULL;
	mem_free(ctx->local_types), ctx->local_types = NULL;
	free_ld_tree(ctx);
	array_finish(pointer_t *, &ctx->ld, &ctx->ld_len);

	if (profiling_escapes) {
		ctx->escape_data = mem_alloc_array_mayfail(mem_calloc_mayfail, struct escape_data *, 0, 0, ctx->code_len, sizeof(struct escape_data), ctx->err);
		if (unlikely(!ctx->escape_data))
			goto exception;
	}

	fn = data_alloc_flexible(function, local_directory, ctx->ld_len, ctx->err);
	if (unlikely(!fn))
		goto exception;

	da(fn,function)->frame_slots = frame_offset / slot_size + ctx->n_slots;
	da(fn,function)->n_bitmap_slots = bitmap_slots(ctx->n_slots);
	da(fn,function)->n_arguments = ctx->n_real_arguments;
	da(fn,function)->n_return_values = ctx->n_real_return_values;
	da(fn,function)->code = ctx->code;
	da(fn,function)->code_size = ctx->code_len;
	da(fn,function)->local_variables = ctx->local_variables;
	if (!is_saved) {
		da(fn,function)->local_variables_flags = ctx->local_variables_flags;
	} else {
		mem_free(ctx->local_variables_flags);
		da(fn,function)->local_variables_flags = sfd->local_variables_flags;
	}
	da(fn,function)->args = ctx->args;
	da(fn,function)->types_ptr = pointer_data(ft);
	da(fn,function)->record_definition = ctx->record_definition ? &ctx->record_definition->type : NULL;
	da(fn,function)->function_name = cast_ptr(char *, ctx->function_name);
	da(fn,function)->module_designator = md;
	da(fn,function)->function_designator = fd;
	if (!is_saved) {
		da(fn,function)->lp = ctx->lp;
		da(fn,function)->lp_size = ctx->lp_size;
	} else {
		da(fn,function)->lp = sfd->lp;
		da(fn,function)->lp_size = sfd->lp_size;
	}
	memcpy(da(fn,function)->local_directory, ctx->ld, ctx->ld_len * sizeof(pointer_t *));
	da(fn,function)->local_directory_size = ctx->ld_len;
	mem_free(ctx->ld);
#ifdef HAVE_CODEGEN
	ia[0].ptr = fn;
	da(fn,function)->codegen = function_build_internal_thunk(codegen_fn, 1, ia);
	store_relaxed(&da(fn,function)->codegen_failed, 0);
#endif
	function_init_common(fn);

	if (sfd) {
		/*if (memcmp(ctx->code, sfd->code, ctx->code_len * sizeof(code_t))) internal(file_line, "code mismatch");*/
		da(fn,function)->loaded_cache = sfd->data_saved_cache;
		/*if (da(fn,function)->loaded_cache) debug("loaded cache: %s", function_name(ctx));*/
	}

	da(fn,function)->escape_data = ctx->escape_data;
	da(fn,function)->leaf = ctx->leaf;
	da(fn,function)->is_saved = is_saved;

	ipret_prefetch_functions(fn);

	return pointer_data(fn);

exception_overflow:
	*ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
exception:
	ctx->ret_val = pointer_mark();
ret:
	done_ctx(ctx);
	return ctx->ret_val;
}

static void *pcode_build_function(frame_s *fp, const code_t *ip, const pcode_t *pcode, size_t size, const struct module_designator *md, const struct function_designator *fd)
{
	pointer_t ptr;
	void *ex;
	ajla_error_t err;
	ptr = pcode_build_function_core(fp, ip, pcode, size, md, fd, &ex, &err);
	if (unlikely(pointer_is_empty(ptr)))
		return ex;
	if (unlikely(pointer_is_mark(ptr)))
		return function_return(fp, pointer_error(err, NULL, NULL pass_file_line));
	return function_return(fp, ptr);
}

void *pcode_build_function_from_builtin(frame_s *fp, const code_t *ip, union internal_arg arguments[])
{
	const pcode_t *start;
	size_t size;
	struct module_designator *md = arguments[0].ptr;
	struct function_designator *fd = arguments[1].ptr;
	builtin_find_function(md->path, md->path_len, fd->n_entries, fd->entries, &start, &size);
	return pcode_build_function(fp, ip, start, size, md, arguments[1].ptr);
}

void *pcode_build_function_from_array(frame_s *fp, const code_t *ip, union internal_arg arguments[])
{
	pointer_t *ptr;
	void *ex;
	struct thunk *thunk;
	char *bytes;
	size_t bytes_l;
	const struct function_designator *fd;
	const pcode_t *start;
	size_t size;

	ptr = arguments[0].ptr;
	ex = pointer_deep_eval(ptr, fp, ip, &thunk);
	if (unlikely(ex != POINTER_FOLLOW_THUNK_GO)) {
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION) {
			return function_return(fp, pointer_thunk(thunk));
		}
		return ex;
	}

	array_to_bytes(ptr, &bytes, &bytes_l);
	bytes_l--;

	if (unlikely(bytes_l % sizeof(pcode_t) != 0))
		internal(file_line, "pcode_build_function_from_array: invalid length: %lu", (unsigned long)bytes_l);

	start = cast_ptr(const pcode_t *, bytes);
	size = bytes_l / sizeof(pcode_t);
	fd = arguments[2].ptr;

	/*builtin_walk_nested(&start, &size, fd->n_entries, fd->entries);*/

	ex = pcode_build_function(fp, ip, start, size, arguments[1].ptr, fd);

	mem_free(bytes);

	return ex;
}

void *pcode_array_from_builtin(frame_s *fp, const code_t attr_unused *ip, union internal_arg arguments[])
{
	const struct type *t;
	struct data *d;
	ajla_error_t err;
	const pcode_t *start;
	size_t size;
	struct module_designator *md = arguments[0].ptr;
	struct function_designator *fd = arguments[1].ptr;

	builtin_find_function(md->path, md->path_len, fd->n_entries, fd->entries, &start, &size);

	t = type_get_fixed(log_2(sizeof(pcode_t)), false);
	d = data_alloc_array_flat_mayfail(t, size, size, false, &err pass_file_line);
	if (unlikely(!d)) {
		return function_return(fp, pointer_thunk(thunk_alloc_exception_error(err, NULL, NULL, NULL pass_file_line)));
	}

	memcpy(da_array_flat(d), start, size * sizeof(pcode_t));

	return function_return(fp, pointer_data(d));
}


pointer_t pcode_build_eval_function(pcode_t src_type, pcode_t dest_type, pcode_t op, pcode_t *blob_1, size_t blob_1_len, pcode_t *blob_2, size_t blob_2_len, ajla_error_t *err)
{
	pcode_t *pc = NULL;
	size_t pc_l;
	unsigned n_local_variables;
	unsigned n_arguments;
	unsigned i;
	pointer_t ptr;

	if (unlikely(!array_init_mayfail(pcode_t, &pc, &pc_l, err)))
		goto ret_err;
#define add(x)								\
	do {								\
		if (unlikely(!array_add_mayfail(pcode_t, &pc, &pc_l, x, NULL, err)))\
			goto ret_err;					\
	} while (0)
#define addstr(x, l)							\
	do {								\
		if (unlikely(!array_add_multiple_mayfail(pcode_t, &pc, &pc_l, x, l, NULL, err)))\
			goto ret_err;					\
	} while (0)

	n_local_variables = Op_IsUnary(op) ? 2 : 3;
	n_arguments = n_local_variables - 1;

	add(Fn_Function);
	add(Call_Mode_Strict);
	add(0);
	add(0);
	add(n_local_variables);
	add(0);
	add(1);
	add(1);
	add(0);
	add(0);

	for (i = 0; i < n_local_variables; i++) {
		pcode_t t = i < n_arguments ? src_type : dest_type;
		add(t);
		add(t);
		add(i);
		add(0);
		add(0);
	}

	add(P_Args);
	add(0);

	add(P_Load_Const);
	add(1 + blob_1_len);
	add(0);
	addstr(blob_1, blob_1_len);
	if (n_arguments == 2) {
		add(P_Load_Const);
		add(1 + blob_2_len);
		add(1);
		addstr(blob_2, blob_2_len);
	}

	add(Op_IsUnary(op) ? P_UnaryOp : P_BinaryOp);
	add(Op_IsUnary(op) ? 4 : 6);
	add(op);
	add(n_arguments);
	add(Flag_Free_Argument | Flag_Op_Strict);
	add(0);
	if (n_arguments == 2) {
		add(Flag_Free_Argument);
		add(1);
	}

	add(P_Return);
	add(2);
	add(Flag_Free_Argument);
	add(n_arguments);

#undef add
#undef addstr

	ptr = pcode_build_function_core(NULL, NULL, pc, pc_l, NULL, NULL, NULL, err);

	mem_free(pc);

	return ptr;

ret_err:
	if (pc)
		mem_free(pc);
	return pointer_empty();
}


static void *pcode_alloc_op_function(pointer_t *ptr, frame_s *fp, const code_t *ip, void *(*build_fn)(frame_s *fp, const code_t *ip, union internal_arg ia[]), unsigned n_arguments, union internal_arg ia[], pointer_t **result)
{
	struct data *function;
	pointer_t fn_thunk;

#ifdef POINTER_FOLLOW_IS_LOCKLESS
	const addrlock_depth lock_depth = DEPTH_THUNK;
#else
	const addrlock_depth lock_depth = DEPTH_POINTER;
#endif

again:
	pointer_follow(ptr, false, function, PF_WAIT, fp, ip,
		return ex_,
		*result = ptr;
		return POINTER_FOLLOW_THUNK_RETRY);

	if (likely(function != NULL)) {
		*result = ptr;
		return POINTER_FOLLOW_THUNK_RETRY;
	}

	fn_thunk = function_build_internal_thunk(build_fn, n_arguments, ia);

	barrier_write_before_lock();
	address_lock(ptr, lock_depth);
	if (likely(pointer_is_empty(*pointer_volatile(ptr)))) {
		*pointer_volatile(ptr) = fn_thunk;
		address_unlock(ptr, lock_depth);
	} else {
		address_unlock(ptr, lock_depth);
		pointer_dereference(fn_thunk);
	}

	goto again;
}

static void *pcode_build_op_function(frame_s *fp, const code_t *ip, union internal_arg a[])
{
	pcode_t src_type = (pcode_t)a[0].i;
	pcode_t dest_type = (pcode_t)a[1].i;
	pcode_t op = (pcode_t)a[2].i;
	unsigned flags = (unsigned)a[3].i;
	unsigned i;
	unsigned n_local_variables;
	unsigned n_arguments;
	pcode_t pcode[41];
	pcode_t *pc = pcode;

	n_local_variables = flags & PCODE_FIND_OP_UNARY ? 2 : 3;
	n_arguments = n_local_variables - 1;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = (pcode_t)n_local_variables;
	*pc++ = (pcode_t)n_arguments;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	for (i = 0; i < n_local_variables; i++) {
		pcode_t t = i < n_arguments ? src_type : dest_type;
		*pc++ = t;
		*pc++ = t;
		*pc++ = i;
		*pc++ = 0;
		*pc++ = 0;
	}

	*pc++ = P_Args;
	*pc++ = n_arguments;
	for (i = 0; i < n_arguments; i++)
		*pc++ = i;

	*pc++ = (pcode_t)(flags & PCODE_FIND_OP_UNARY ? P_UnaryOp : P_BinaryOp);
	*pc++ = (pcode_t)(flags & PCODE_FIND_OP_UNARY ? 4 : 6);
	*pc++ = op;
	*pc++ = (pcode_t)n_arguments;
	*pc++ = Flag_Free_Argument | Flag_Op_Strict;
	*pc++ = 0;
	if (!(flags & PCODE_FIND_OP_UNARY)) {
		*pc++ = Flag_Free_Argument;
		*pc++ = 1;
	}

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = n_arguments;

	ajla_assert_lo((size_t)(pc - pcode) <= n_array_elements(pcode), (file_line, "pcode_build_op_function: array overflow: %"PRIdMAX" > %"PRIdMAX", src_type %"PRIdMAX", dest_type %"PRIdMAX", op %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode), (intmax_t)src_type, (intmax_t)dest_type, (intmax_t)op));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t fixed_op_thunk[TYPE_FIXED_N][OPCODE_FIXED_OP_N];
static pointer_t int_op_thunk[TYPE_INT_N][OPCODE_INT_OP_N];
static pointer_t real_op_thunk[TYPE_REAL_N][OPCODE_REAL_OP_N];
static pointer_t bool_op_thunk[OPCODE_BOOL_TYPE_MULT];

void * attr_fastcall pcode_find_op_function(const struct type *type, const struct type *rtype, code_t code, unsigned flags, frame_s *fp, const code_t *ip, pointer_t **result)
{
	union internal_arg ia[4];
	pointer_t *ptr;

	type_tag_t tag = likely(!(flags & PCODE_CONVERT_FROM_INT)) ? type->tag : rtype->tag;

	if (TYPE_TAG_IS_FIXED(tag)) {
		unsigned idx = (code - OPCODE_FIXED_OP - (TYPE_TAG_IDX_FIXED(tag) >> 1) * OPCODE_FIXED_TYPE_MULT) / OPCODE_FIXED_OP_MULT;
		ajla_assert(idx < OPCODE_FIXED_OP_N, (file_line, "pcode_find_op_function: invalid parameters, type %u, code %04x", tag, code));
		ptr = &fixed_op_thunk[TYPE_TAG_IDX_FIXED(tag) >> 1][idx];
	} else if (TYPE_TAG_IS_INT(tag)) {
		unsigned idx = (code - OPCODE_INT_OP - TYPE_TAG_IDX_INT(tag) * OPCODE_INT_TYPE_MULT) / OPCODE_INT_OP_MULT;
		if (idx >= OPCODE_INT_OP_C && idx < OPCODE_INT_OP_UNARY)
			idx -= OPCODE_INT_OP_C;
		ajla_assert(idx < OPCODE_INT_OP_N, (file_line, "pcode_find_op_function: invalid parameters, type %u, code %04x", tag, code));
		ptr = &int_op_thunk[TYPE_TAG_IDX_INT(tag)][idx];
		ajla_assert(is_power_of_2(type->size), (file_line, "pcode_find_op_function: invalid integer type size %"PRIuMAX"", (uintmax_t)type->size));
	} else if (TYPE_TAG_IS_REAL(tag)) {
		unsigned idx = (code - OPCODE_REAL_OP - TYPE_TAG_IDX_REAL(tag) * OPCODE_REAL_TYPE_MULT) / OPCODE_REAL_OP_MULT;
		ajla_assert(idx < OPCODE_REAL_OP_N, (file_line, "pcode_find_op_function: invalid parameters, type %u, code %04x", tag, code));
		ptr = &real_op_thunk[TYPE_TAG_IDX_REAL(tag)][idx];
	} else if (tag) {
		unsigned idx = (code - OPCODE_BOOL_OP) / OPCODE_BOOL_OP_MULT;
		ajla_assert(idx < OPCODE_BOOL_OP_N, (file_line, "pcode_find_op_function: invalid parameters, type %u, code %04x", tag, code));
		ptr = &bool_op_thunk[idx];
	} else {
		internal(file_line, "pcode_find_op_function: invalid type %u", tag);
	}

	ia[0].i = type_to_pcode(type);
	ia[1].i = type_to_pcode(rtype);
	ia[2].i = code + Op_N;
	ia[3].i = flags;

	return pcode_alloc_op_function(ptr, fp, ip, pcode_build_op_function, 4, ia, result);
}

static void *pcode_build_is_exception_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[36];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_FlatOption;
	*pc++ = T_FlatOption;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_UnaryOp;
	*pc++ = 4;
	*pc++ = Un_IsException;
	*pc++ = 1;
	*pc++ = Flag_Free_Argument | Flag_Op_Strict;
	*pc++ = 0;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 1;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_is_exception_function: array overflow: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t is_exception_thunk;

void * attr_fastcall pcode_find_is_exception(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&is_exception_thunk, fp, ip, pcode_build_is_exception_function, 0, NULL, result);
}

static void *pcode_build_get_exception_function(frame_s *fp, const code_t *ip, union internal_arg a[])
{
	pcode_t pcode[36];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_UnaryOp;
	*pc++ = 4;
	*pc++ = Un_ExceptionClass + a[0].i;
	*pc++ = 1;
	*pc++ = Flag_Free_Argument | Flag_Op_Strict;
	*pc++ = 0;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 1;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_get_exception_function: array overflow: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t get_exception_thunk[3];

void * attr_fastcall pcode_find_get_exception(unsigned mode, frame_s *fp, const code_t *ip, pointer_t **result)
{
	union internal_arg ia[1];
	ia[0].i = mode;
	return pcode_alloc_op_function(&get_exception_thunk[mode], fp, ip, pcode_build_get_exception_function, 1, ia, result);
}

static void *pcode_build_array_load_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[45];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 3;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 1;

	*pc++ = P_Array_Load;
	*pc++ = 4;
	*pc++ = 2;
	*pc++ = Flag_Evaluate;
	*pc++ = 0;
	*pc++ = 1;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 1;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 2;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_array_load_function: array mismatch: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t array_load_thunk;

void * attr_fastcall pcode_find_array_load_function(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&array_load_thunk, fp, ip, pcode_build_array_load_function, 0, NULL, result);
}

static void *pcode_build_array_len_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[35];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Array_Len;
	*pc++ = 3;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = Flag_Evaluate;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 1;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_array_len_function: array mismatch: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t array_len_thunk;

void * attr_fastcall pcode_find_array_len_function(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&array_len_thunk, fp, ip, pcode_build_array_len_function, 0, NULL, result);
}

static void *pcode_build_array_len_greater_than_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[45];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 3;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_FlatOption;
	*pc++ = T_FlatOption;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 1;

	*pc++ = P_Array_Len_Greater_Than;
	*pc++ = 4;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 1;
	*pc++ = Flag_Evaluate;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 1;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 2;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_array_len_function: array mismatch: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t array_len_greater_than_thunk;

void * attr_fastcall pcode_find_array_len_greater_than_function(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&array_len_greater_than_thunk, fp, ip, pcode_build_array_len_greater_than_function, 0, NULL, result);
}

static void *pcode_build_array_sub_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[55];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 4;
	*pc++ = 3;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 3;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 3;
	*pc++ = 0;
	*pc++ = 1;
	*pc++ = 2;

	*pc++ = P_Array_Sub;
	*pc++ = 5;
	*pc++ = 3;
	*pc++ = Flag_Evaluate;
	*pc++ = 0;
	*pc++ = 1;
	*pc++ = 2;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 1;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 2;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 3;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_array_len_function: array mismatch: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t array_sub_thunk;

void * attr_fastcall pcode_find_array_sub_function(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&array_sub_thunk, fp, ip, pcode_build_array_sub_function, 0, NULL, result);
}

static void *pcode_build_array_skip_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[45];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 3;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 1;

	*pc++ = P_Array_Skip;
	*pc++ = 4;
	*pc++ = 2;
	*pc++ = Flag_Evaluate;
	*pc++ = 0;
	*pc++ = 1;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 1;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 2;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_array_len_function: array mismatch: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t array_skip_thunk;

void * attr_fastcall pcode_find_array_skip_function(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&array_skip_thunk, fp, ip, pcode_build_array_skip_function, 0, NULL, result);
}

static void *pcode_build_array_append_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[43];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 3;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 2;
	*pc++ = 0;
	*pc++ = 1;

	*pc++ = P_Eval;
	*pc++ = 1;
	*pc++ = 0;

#if 0
	*pc++ = P_Eval;
	*pc++ = 1;
	*pc++ = 1;
#endif

	*pc++ = P_Array_Append;
	*pc++ = 5;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 0;
	*pc++ = Flag_Free_Argument;
	*pc++ = 1;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 2;
	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_array_append_function: array mismatch: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t array_append_thunk;

void * attr_fastcall pcode_find_array_append_function(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&array_append_thunk, fp, ip, pcode_build_array_append_function, 0, NULL, result);
}


static void *pcode_build_option_ord_function(frame_s *fp, const code_t *ip, union internal_arg attr_unused a[])
{
	pcode_t pcode[37];
	pcode_t *pc = pcode;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Integer;
	*pc++ = T_Integer;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Eval;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Option_Ord;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 1;

	ajla_assert_lo((size_t)(pc - pcode) == n_array_elements(pcode), (file_line, "pcode_build_option_ord_function: array mismatch: %"PRIdMAX" != %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

static pointer_t option_ord_thunk;

void * attr_fastcall pcode_find_option_ord_function(frame_s *fp, const code_t *ip, pointer_t **result)
{
	return pcode_alloc_op_function(&option_ord_thunk, fp, ip, pcode_build_option_ord_function, 0, NULL, result);
}


struct function_key {
	unsigned char tag;
	frame_t id;
};

static void *pcode_build_record_option_load_function(frame_s *fp, const code_t *ip, union internal_arg a[])
{
	pcode_t pcode[38];
	pcode_t *pc = pcode;
	pcode_t result_type = a[0].i == PCODE_FUNCTION_OPTION_TEST ? T_FlatOption : T_Undetermined;

	*pc++ = Fn_Function;
	*pc++ = Call_Mode_Strict;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 2;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = T_Undetermined;
	*pc++ = T_Undetermined;
	*pc++ = 0;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = result_type;
	*pc++ = result_type;
	*pc++ = 1;
	*pc++ = 0;
	*pc++ = 0;

	*pc++ = P_Args;
	*pc++ = 1;
	*pc++ = 0;

	switch (a[0].i) {
		case PCODE_FUNCTION_RECORD_LOAD:
			/* P_Record_Load_Slot already sets Flag_Evaluate */
			*pc++ = P_Record_Load_Slot;
			*pc++ = 3;
			*pc++ = 1;
			*pc++ = 0;
			*pc++ = (pcode_t)a[1].i;
			break;
		case PCODE_FUNCTION_OPTION_LOAD:
			*pc++ = P_Option_Load;
			*pc++ = 4;
			*pc++ = 1;
			*pc++ = Flag_Evaluate;
			*pc++ = 0;
			*pc++ = (pcode_t)a[1].i;
			break;
		case PCODE_FUNCTION_OPTION_TEST:
			*pc++ = P_Eval;
			*pc++ = 1;
			*pc++ = 0;
			*pc++ = P_Option_Test;
			*pc++ = 3;
			*pc++ = 1;
			*pc++ = 0;
			*pc++ = (pcode_t)a[1].i;
			break;
		default:
			internal(file_line, "pcode_build_record_option_load_function: invalid operation %"PRIuMAX"", (uintmax_t)a[0].i);
	}

	*pc++ = P_Free;
	*pc++ = 1;
	*pc++ = 0;

	*pc++ = P_Return;
	*pc++ = 2;
	*pc++ = Flag_Free_Argument;
	*pc++ = 1;

	ajla_assert_lo((size_t)(pc - pcode) <= n_array_elements(pcode), (file_line, "pcode_build_record_option_load_function: array overflow: %"PRIdMAX" > %"PRIdMAX"", (intmax_t)(pc - pcode), (intmax_t)n_array_elements(pcode)));

	return pcode_build_function(fp, ip, pcode, pc - pcode, NULL, NULL);
}

struct pcode_function {
	struct tree_entry entry;
	struct function_key key;
	pointer_t ptr;
};

shared_var struct tree pcode_functions;
rwlock_decl(pcode_functions_mutex);

static int record_option_load_compare(const struct tree_entry *e1, uintptr_t e2)
{
	struct pcode_function *rl = get_struct(e1, struct pcode_function, entry);
	struct function_key *key = cast_cpp(struct function_key *, num_to_ptr(e2));
	if (rl->key.tag != key->tag)
		return (int)rl->key.tag - key->tag;
	if (rl->key.id < key->id)
		return -1;
	if (rl->key.id > key->id)
		return -1;
	return 0;
}

static pointer_t *pcode_find_function_for_key(struct function_key *key)
{
	struct tree_entry *e;

	rwlock_lock_read(&pcode_functions_mutex);
	e = tree_find(&pcode_functions, record_option_load_compare, ptr_to_num(key));
	rwlock_unlock_read(&pcode_functions_mutex);
	if (unlikely(!e)) {
		struct tree_insert_position ins;
		rwlock_lock_write(&pcode_functions_mutex);
		e = tree_find_for_insert(&pcode_functions, record_option_load_compare, ptr_to_num(key), &ins);
		if (likely(!e)) {
			ajla_error_t sink;
			struct pcode_function *rl;
			rl = mem_alloc_mayfail(struct pcode_function *, sizeof(struct pcode_function), &sink);
			if (unlikely(!rl)) {
				rwlock_unlock_write(&pcode_functions_mutex);
				return NULL;
			}
			rl->key = *key;
			rl->ptr = pointer_empty();
			e = &rl->entry;
			tree_insert_after_find(e, &ins);
		}
		rwlock_unlock_write(&pcode_functions_mutex);
	}
	return &get_struct(e, struct pcode_function, entry)->ptr;
}

void * attr_fastcall pcode_find_record_option_load_function(unsigned char tag, frame_t slot, frame_s *fp, const code_t *ip, pointer_t **result)
{
	struct function_key key;
	pointer_t *ptr;
	union internal_arg ia[2];

	if (unlikely((uintmax_t)slot > (uintmax_t)signed_maximum(pcode_t) + zero)) {
		*result = out_of_memory_ptr;
		return POINTER_FOLLOW_THUNK_RETRY;
	}

	key.tag = tag;
	key.id = slot;

	ptr = pcode_find_function_for_key(&key);
	if (unlikely(!ptr)) {
		*result = out_of_memory_ptr;
		return POINTER_FOLLOW_THUNK_RETRY;
	}

	ia[0].i = tag;
	ia[1].i = slot;
	return pcode_alloc_op_function(ptr, fp, ip, pcode_build_record_option_load_function, 2, ia, result);
}

static void thunk_init_run(pointer_t *ptr, unsigned n)
{
	while (n--) {
		*ptr = pointer_empty();
		ptr++;
	}
}

static void thunk_free_run(pointer_t *ptr, unsigned n)
{
	while (n--) {
		if (!pointer_is_empty(*ptr))
			pointer_dereference(*ptr);
		ptr++;
	}
}

void name(pcode_init)(void)
{
	unsigned i;

	for (i = 0; i < TYPE_FIXED_N + uzero; i++) thunk_init_run(fixed_op_thunk[i], OPCODE_FIXED_OP_N);
	for (i = 0; i < TYPE_INT_N; i++) thunk_init_run(int_op_thunk[i], OPCODE_INT_OP_N);
	for (i = 0; i < TYPE_REAL_N + uzero; i++) thunk_init_run(real_op_thunk[i], OPCODE_REAL_OP_N);
	thunk_init_run(&is_exception_thunk, 1);
	thunk_init_run(get_exception_thunk, n_array_elements(get_exception_thunk));
	thunk_init_run(bool_op_thunk, OPCODE_BOOL_OP_N);
	thunk_init_run(&array_load_thunk, 1);
	thunk_init_run(&array_len_thunk, 1);
	thunk_init_run(&array_len_greater_than_thunk, 1);
	thunk_init_run(&array_sub_thunk, 1);
	thunk_init_run(&array_skip_thunk, 1);
	thunk_init_run(&array_append_thunk, 1);
	thunk_init_run(&option_ord_thunk, 1);
	tree_init(&pcode_functions);
	rwlock_init(&pcode_functions_mutex);
}

void name(pcode_done)(void)
{
	unsigned i;
	for (i = 0; i < TYPE_FIXED_N + uzero; i++) thunk_free_run(fixed_op_thunk[i], OPCODE_FIXED_OP_N);
	for (i = 0; i < TYPE_INT_N; i++) thunk_free_run(int_op_thunk[i], OPCODE_INT_OP_N);
	for (i = 0; i < TYPE_REAL_N + uzero; i++) thunk_free_run(real_op_thunk[i], OPCODE_REAL_OP_N);
	thunk_free_run(&is_exception_thunk, 1);
	thunk_free_run(get_exception_thunk, n_array_elements(get_exception_thunk));
	thunk_free_run(bool_op_thunk, OPCODE_BOOL_OP_N);
	thunk_free_run(&array_load_thunk, 1);
	thunk_free_run(&array_len_thunk, 1);
	thunk_free_run(&array_len_greater_than_thunk, 1);
	thunk_free_run(&array_sub_thunk, 1);
	thunk_free_run(&array_skip_thunk, 1);
	thunk_free_run(&array_append_thunk, 1);
	thunk_free_run(&option_ord_thunk, 1);
	while (!tree_is_empty(&pcode_functions)) {
		struct pcode_function *rl = get_struct(tree_any(&pcode_functions), struct pcode_function, entry);
		if (!pointer_is_empty(rl->ptr))
			pointer_dereference(rl->ptr);
		tree_delete(&rl->entry);
		mem_free(rl);
	}
	rwlock_done(&pcode_functions_mutex);
}

#endif
