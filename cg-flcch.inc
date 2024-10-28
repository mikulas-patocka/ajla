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

static bool attr_w clear_flag_cache(struct codegen_context *ctx)
{
	memset(ctx->flag_cache, 0, function_n_variables(ctx->fn) * sizeof(int8_t));
	return true;
}

/*#define clear_flag_cache(ctx)	\
	(debug("clearing flag cache @ %d", __LINE__), memset((ctx)->flag_cache, 0, function_n_variables(ctx->fn) * sizeof(int8_t)), true)*/

static inline void flag_set(struct codegen_context *ctx, frame_t slot, bool val)
{
	unsigned c;
	if (val && !must_be_flat_chicken && da(ctx->fn,function)->local_variables_flags[slot].must_be_flat) {
		internal(file_line, "flag_set: %s: setting slot %lu as not flat", da(ctx->fn,function)->function_name, (unsigned long)slot);
	}
	c = ctx->flag_cache[slot] & ~(FLAG_CACHE_IS_FLAT | FLAG_CACHE_IS_NOT_FLAT);
	ctx->flag_cache[slot] = c | (!val ? FLAG_CACHE_IS_FLAT : FLAG_CACHE_IS_NOT_FLAT);
}

static inline void flag_set_unknown(struct codegen_context *ctx, frame_t slot)
{
	ctx->flag_cache[slot] = 0;
}

static inline bool flag_must_be_flat(struct codegen_context *ctx, frame_t slot)
{
	if (!must_be_flat_chicken && da(ctx->fn,function)->local_variables_flags[slot].must_be_flat) {
		if (unlikely((ctx->flag_cache[slot] & FLAG_CACHE_IS_NOT_FLAT) != 0))
			internal(file_line, "flag_must_be_flat: %s: must_be_flat slot %lu is not flat", da(ctx->fn,function)->function_name, (unsigned long)slot);
		return true;
	}
	return false;
}

static inline bool flag_is_clear(struct codegen_context *ctx, frame_t slot)
{
	if (!flag_cache_chicken && ctx->flag_cache[slot] & FLAG_CACHE_IS_FLAT)
		return true;
	if (flag_must_be_flat(ctx, slot))
		return true;
	return false;
}

static inline bool flag_is_set(struct codegen_context *ctx, frame_t slot)
{
	if (!flag_cache_chicken && ctx->flag_cache[slot] & FLAG_CACHE_IS_NOT_FLAT)
		return true;
	return false;
}

static bool attr_w gen_test_1_cached(struct codegen_context *ctx, frame_t slot_1, uint32_t label)
{
	if (flag_is_clear(ctx, slot_1))
		return true;
	return gen_test_1(ctx, R_FRAME, slot_1, 0, label, false, TEST);
}

static bool attr_w gen_test_2_cached(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, uint32_t label)
{
	if (flag_is_clear(ctx, slot_1))
		return gen_test_1_cached(ctx, slot_2, label);
	if (flag_is_clear(ctx, slot_2))
		return gen_test_1_cached(ctx, slot_1, label);
	return gen_test_2(ctx, slot_1, slot_2, label);
}

static bool attr_w gen_test_1_jz_cached(struct codegen_context *ctx, frame_t slot_1, uint32_t label)
{
	const struct type *type = get_type_of_local(ctx, slot_1);
	if (!TYPE_IS_FLAT(type) && !da(ctx->fn,function)->local_variables_flags[slot_1].may_be_borrowed)
		return true;
	if (flag_is_set(ctx, slot_1))
		return true;
	return gen_test_1(ctx, R_FRAME, slot_1, 0, label, true, TEST);
}
