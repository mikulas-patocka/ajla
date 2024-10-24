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

static const struct type *get_type_of_local(struct codegen_context *ctx, frame_t pos)
{
	const struct type *t;
	const struct data *function = ctx->fn;
	t = da(function,function)->local_variables[pos].type;
	if (t)
		TYPE_TAG_VALIDATE(t->tag);
	return t;
}

static unsigned real_type_to_op_size(unsigned real_type)
{
	switch (real_type) {
		case 0:	return OP_SIZE_2;
		case 1:	return OP_SIZE_4;
		case 2:	return OP_SIZE_8;
		case 3:	return OP_SIZE_10;
		case 4:	return OP_SIZE_16;
		default:
			internal(file_line, "real_type_to_op_size: invalid type %u", real_type);
			return 0;
	}
}

static unsigned spill_size(const struct type *t)
{
	if (TYPE_TAG_IS_REAL(t->tag)) {
		return real_type_to_op_size(TYPE_TAG_IDX_REAL(t->tag));
	} else {
		return log_2(t->size);
	}
}

static bool attr_w gen_frame_load_raw(struct codegen_context *ctx, unsigned size, enum extend ex, frame_t slot, int64_t offset, unsigned reg);
static bool attr_w gen_frame_store_raw(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg);

static bool attr_w spill(struct codegen_context *ctx, frame_t v)
{
	const struct type *t = get_type_of_local(ctx, v);
	g(gen_frame_store_raw(ctx, spill_size(t), v, 0, ctx->registers[v]));
	return true;
}

static bool attr_w unspill(struct codegen_context *ctx, frame_t v)
{
	const struct type *t = get_type_of_local(ctx, v);
	g(gen_frame_load_raw(ctx, spill_size(t), garbage, v, 0, ctx->registers[v]));
	return true;
}
