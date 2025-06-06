/*
 * Copyright (C) 2024, 2025 Mikulas Patocka
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

#define frame_offs(x)	((ssize_t)offsetof(struct frame_struct, x) - (ssize_t)frame_offset)

#if defined(C_LITTLE_ENDIAN)
#define lo_word(size)		(0)
#define hi_word(size)		((size_t)1 << (size))
#elif defined(C_BIG_ENDIAN)
#define lo_word(size)		((size_t)1 << (size))
#define hi_word(size)		(0)
#else
endian not defined
#endif


static bool attr_w gen_frame_load_raw(struct codegen_context *ctx, unsigned size, enum extend ex, frame_t slot, int64_t offset, bool dual, unsigned reg);
static bool attr_w gen_frame_store_raw(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg);


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
	if (!TYPE_TAG_IS_BUILTIN(t->tag)) {
		return OP_SIZE_SLOT;
	} else if (TYPE_TAG_IS_REAL(t->tag)) {
		return real_type_to_op_size(TYPE_TAG_IDX_REAL(t->tag));
	} else {
		return log_2(t->size);
	}
}

static bool attr_w spill(struct codegen_context *ctx, frame_t v)
{
	const struct type *t = get_type_of_local(ctx, v);
	g(gen_frame_store_raw(ctx, spill_size(t), v, 0, ctx->registers[v]));
	return true;
}

static bool attr_w unspill(struct codegen_context *ctx, frame_t v)
{
	const struct type *t = get_type_of_local(ctx, v);
	enum extend ex = garbage;
	if (t->tag == TYPE_TAG_flat_option)
		ex = zero;
	else if (!TYPE_IS_FLAT(t))
		ex = native;
	g(gen_frame_load_raw(ctx, spill_size(t), ex, v, 0, false, ctx->registers[v]));
	return true;
}


static bool attr_w gen_frame_address(struct codegen_context *ctx, frame_t slot, int64_t offset, unsigned reg)
{
	offset += (size_t)slot * slot_size;
	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, reg, R_FRAME, offset, 0));
	return true;
}

static int64_t get_constant(unsigned size, enum extend ex, frame_t slot, int64_t offset, bool dual)
{
	if (ex == garbage)
		ex = sign_x;
	if (ex == native)
		ex = ARCH_PREFERS_SX(size) ? sign_x : zero_x;
	if (!dual) {
		int64_t c;
		if (unlikely(offset != 0))
			goto crash;
		c = frame_t_get_const(slot);
		if (ex == zero_x) {
			if (size == OP_SIZE_1) c &= 0xFFUL;
			if (size == OP_SIZE_2) c &= 0xFFFFUL;
			if (size == OP_SIZE_4) c &= 0xFFFFFFFFUL;
		}
		return c;
	}
	if (offset == (int64_t)lo_word(size))
		return frame_t_get_const(slot);
	if (offset == (int64_t)hi_word(size))
		return frame_t_get_const(slot) < 0 ? -1 : 0;
crash:
	internal(file_line, "get_constant: invalid offset %"PRIdMAX"", (intmax_t)offset);
	return 0;
}

static bool attr_w gen_frame_load_raw(struct codegen_context *ctx, unsigned size, enum extend ex, frame_t slot, int64_t offset, bool dual, unsigned reg)
{
	int64_t x_offset;
	if (frame_t_is_const(slot)) {
		g(gen_load_constant(ctx, reg, get_constant(size, ex, slot, offset, dual)));
		return true;
	}
	if (ex == garbage || ex == native) {
		if (!reg_is_fp(reg))
			ex = ARCH_PREFERS_SX(size) ? sign_x : zero_x;
		else
			ex = zero_x;
	}
	x_offset = offset + (size_t)slot * slot_size;
	if (!ARCH_HAS_BWX && size < OP_SIZE_4) {
		g(gen_address(ctx, R_FRAME, x_offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_4));
		gen_insn(INSN_MOVSX, OP_SIZE_4, 0, 0);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, ex, reg, reg));

		return true;
	}
#if defined(ARCH_ALPHA)
	if (size < OP_SIZE_4) {
		g(gen_address(ctx, R_FRAME, x_offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_one(reg);
		gen_address_offset();

		if (ex != zero_x)
			g(gen_extend(ctx, size, ex, reg, reg));

		return true;
	}
	if (size == OP_SIZE_4 && !reg_is_fp(reg) && ex == zero_x) {
		g(gen_frame_load_raw(ctx, size, sign_x, slot, offset, false, reg));
		g(gen_extend(ctx, size, ex, reg, reg));

		return true;
	}
#endif
#if defined(ARCH_MIPS)
	if (reg_is_fp(reg) && size == OP_SIZE_8 && !MIPS_HAS_LS_DOUBLE) {
#if defined(C_LITTLE_ENDIAN)
		g(gen_frame_load_raw(ctx, OP_SIZE_4, zero_x, slot, offset, true, reg));
		g(gen_frame_load_raw(ctx, OP_SIZE_4, zero_x, slot, offset + 4, true, reg + 1));
#else
		g(gen_frame_load_raw(ctx, OP_SIZE_4, zero_x, slot, offset, true, reg + 1));
		g(gen_frame_load_raw(ctx, OP_SIZE_4, zero_x, slot, offset + 4, true, reg));
#endif
		return true;
	}
#endif
#if defined(ARCH_IA64) || defined(ARCH_PARISC)
	if (ex == sign_x) {
		g(gen_address(ctx, R_FRAME, x_offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, ex, reg, reg));

		return true;
	}
#endif
#if defined(ARCH_POWER)
	if (size == OP_SIZE_1 && ex == sign_x) {
		g(gen_address(ctx, R_FRAME, x_offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, ex, reg, reg));

		return true;
	}
#endif
#if defined(ARCH_S390)
	if (size == OP_SIZE_1 && !cpu_test_feature(CPU_FEATURE_long_displacement)) {
		g(gen_address(ctx, R_FRAME, x_offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_0_8, 0);
		gen_one(reg);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, ex, reg, reg));

		return true;
	}
	if (size == OP_SIZE_16 && reg_is_fp(reg)) {
		g(gen_frame_load_raw(ctx, OP_SIZE_8, zero_x, 0, x_offset, true, reg));
		g(gen_frame_load_raw(ctx, OP_SIZE_8, zero_x, 0, x_offset + 8, true, reg + 2));

		return true;
	}
#endif
	g(gen_address(ctx, R_FRAME, x_offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : ex ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, size));
	gen_insn(unlikely(ex == sign_x) ? INSN_MOVSX : INSN_MOV, size, 0, 0);
	gen_one(reg);
	gen_address_offset();

	return true;
}

static bool attr_w gen_frame_load(struct codegen_context *ctx, unsigned size, enum extend ex, frame_t slot, int64_t offset, bool dual, unsigned reg)
{
	ajla_assert_lo((slot >= MIN_USEABLE_SLOT && slot < function_n_variables(ctx->fn)) || frame_t_is_const(slot), (file_line, "gen_frame_load: invalid slot: %lu >= %lu", (unsigned long)slot, (unsigned long)function_n_variables(ctx->fn)));
	if (slot_is_register(ctx, slot)) {
		if (unlikely(offset != 0))
			internal(file_line, "gen_frame_load: offset is non-zero: %"PRIdMAX"", (intmax_t)offset);
		if (ex != garbage && size < OP_SIZE_NATIVE && !reg_is_fp(reg)) {
			g(gen_extend(ctx, size, ex, reg, ctx->registers[slot]));
			return true;
		}
		g(gen_mov(ctx, !reg_is_fp(reg) ? OP_SIZE_NATIVE : size, reg, ctx->registers[slot]));
		goto ret;
	}

	g(gen_frame_load_raw(ctx, size, ex, slot, offset, dual, reg));
ret:
#ifdef DEBUG_GARBAGE
	if (size < OP_SIZE_NATIVE && ex == garbage) {
		uint64_t mask;
		g(gen_extend(ctx, size, zero_x, reg, reg));
		mask = (rand()) | ((uint64_t)rand() << 31) | ((uint64_t)rand() << 62);
		mask <<= 8ULL << size;
		g(gen_imm(ctx, mask, IMM_PURPOSE_OR, OP_SIZE_NATIVE));
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, ALU_OR, false, is_imm(), ctx->const_imm));
		gen_one(reg);
		gen_one(reg);
		gen_imm_offset();
	}
#endif
	return true;
}

static bool attr_w gen_frame_get(struct codegen_context *ctx, unsigned size, enum extend ex, frame_t slot, unsigned reg, unsigned *dest)
{
	const struct type *t;
	if (frame_t_is_const(slot)) {
#if defined(R_ZERO)
		if (!frame_t_get_const(slot)) {
			*dest = R_ZERO;
			return true;
		}
#endif
		g(gen_frame_load(ctx, size, ex, slot, 0, false, reg));
		*dest = reg;
		return true;
	}
	t = get_type_of_local(ctx, slot);
	ajla_assert_lo(slot >= MIN_USEABLE_SLOT && slot < function_n_variables(ctx->fn), (file_line, "gen_frame_get: invalid slot: %lu >= %lu", (unsigned long)slot, (unsigned long)function_n_variables(ctx->fn)));
	if (slot_is_register(ctx, slot)) {
		unsigned reg = ctx->registers[slot];
		if (ex != garbage && size < OP_SIZE_NATIVE && !reg_is_fp(reg)) {
			if (t->tag == TYPE_TAG_flat_option && size <= ARCH_BOOL_SIZE)
				goto skip_extend;
			g(gen_extend(ctx, size, ex, reg, reg));
		}
skip_extend:
		*dest = reg;
		goto ret;
	}
	*dest = reg;
	g(gen_frame_load(ctx, size, ex, slot, 0, false, reg));
ret:
#ifdef DEBUG_GARBAGE
	if (size < OP_SIZE_NATIVE && ex == garbage && t->tag != TYPE_TAG_flat_option) {
		uint64_t mask;
		g(gen_extend(ctx, size, zero_x, *dest, *dest));
		mask = (rand()) | ((uint64_t)rand() << 31) | ((uint64_t)rand() << 62);
		mask <<= 8ULL << size;
		g(gen_imm(ctx, mask, IMM_PURPOSE_OR, OP_SIZE_NATIVE));
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, ALU_OR, false, is_imm(), ctx->const_imm));
		gen_one(*dest);
		gen_one(*dest);
		gen_imm_offset();
	}
#endif
	return true;
}

#if defined(ARCH_X86)
static bool attr_w gen_frame_load_x87(struct codegen_context *ctx, unsigned insn, unsigned size, unsigned alu, frame_t slot)
{
	if (slot_is_register(ctx, slot))
		g(spill(ctx,slot));
	g(gen_address(ctx, R_FRAME, (size_t)slot * slot_size, IMM_PURPOSE_LDR_OFFSET, size));
	gen_insn(insn, size, alu, 0);
	gen_address_offset();
	return true;
}

static bool attr_w gen_frame_store_x87(struct codegen_context *ctx, unsigned insn, unsigned size, frame_t slot)
{
	g(gen_address(ctx, R_FRAME, (size_t)slot * slot_size, IMM_PURPOSE_STR_OFFSET, size));
	gen_insn(insn, size, 0, 0);
	gen_address_offset();
	if (slot_is_register(ctx, slot))
		g(unspill(ctx,slot));
	return true;
}
#endif

static bool attr_w gen_frame_load_op(struct codegen_context *ctx, unsigned size, enum extend ex, unsigned alu, unsigned writes_flags, frame_t slot, int64_t offset, bool dual, unsigned reg)
{
	ajla_assert_lo((slot >= MIN_USEABLE_SLOT && slot < function_n_variables(ctx->fn)) || frame_t_is_const(slot), (file_line, "gen_frame_load_op: invalid slot: %lu >= %lu", (unsigned long)slot, (unsigned long)function_n_variables(ctx->fn)));
	if (slot_is_register(ctx, slot)) {
		if (size != i_size(size) + (unsigned)zero && ex != garbage)
			goto fallback;
		g(gen_3address_alu(ctx, i_size(size), alu, reg, reg, ctx->registers[slot], writes_flags));
		return true;
	}
	if (frame_t_is_const(slot)) {
		int64_t cnst = get_constant(size, ex, slot, offset, dual);
		if (!cnst && !writes_flags && (ARCH_PARTIAL_ALU(size) || i_size(size) == OP_SIZE_NATIVE) && (alu == ALU_ADD || alu == ALU_OR || alu == ALU_SUB || alu == ALU_XOR || alu == ALU_ANDN))
			return true;
		g(gen_imm(ctx, cnst, alu_purpose(alu), i_size(size)));
		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), i_size(size), alu, ALU_WRITES_FLAGS(i_size(size), alu, false, is_imm(), ctx->const_imm) | writes_flags);
		gen_one(reg);
		gen_one(reg);
		gen_imm_offset();
		return true;
	}
#if defined(ARCH_X86) || defined(ARCH_S390)
#if defined(ARCH_S390)
	if (size >= OP_SIZE_4)
#endif
	{
		offset += (size_t)slot * slot_size;
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(size, alu, true, false, 0) | writes_flags);
		gen_one(reg);
		gen_one(reg);
		gen_address_offset();
		return true;
	}
#endif
fallback:
#if defined(R_SCRATCH_NA_1)
	g(gen_frame_load(ctx, size, ex, slot, offset, dual, R_SCRATCH_NA_1));
	g(gen_3address_alu(ctx, i_size(size), alu, reg, reg, R_SCRATCH_NA_1, writes_flags));
#endif
	return true;
}

static bool attr_w attr_unused gen_frame_load_op1(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags, frame_t slot, unsigned reg)
{
	ajla_assert_lo(slot >= MIN_USEABLE_SLOT && slot < function_n_variables(ctx->fn), (file_line, "gen_frame_load_op1: invalid slot: %lu >= %lu", (unsigned long)slot, (unsigned long)function_n_variables(ctx->fn)));
	if (slot_is_register(ctx, slot)) {
		g(gen_2address_alu1(ctx, size, alu, reg, ctx->registers[slot], writes_flags));
		return true;
	}
#if defined(ARCH_X86)
	{
		int64_t offset = (size_t)slot * slot_size;
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(size), size, alu, ALU1_WRITES_FLAGS(alu) | writes_flags);
		gen_one(reg);
		gen_address_offset();
		return true;
	}
#endif
#if !defined(ARCH_X86)
	g(gen_frame_load(ctx, size, garbage, slot, 0, false, reg));
	g(gen_2address_alu1(ctx, size, alu, reg, reg, writes_flags));
	return true;
#endif
}

#if ARCH_HAS_FLAGS
static bool attr_w gen_frame_load_cmp(struct codegen_context *ctx, unsigned size, bool logical, enum extend attr_unused ex, bool swap, frame_t slot, int64_t offset, bool dual, unsigned reg)
{
	if (slot_is_register(ctx, slot)) {
		if (size != i_size_cmp(size) + (unsigned)zero && ex != garbage)
			goto fallback;
		gen_insn(INSN_CMP, i_size_cmp(size), 0, 1 + logical);
		if (!swap) {
			gen_one(reg);
			gen_one(ctx->registers[slot]);
		} else {
			gen_one(ctx->registers[slot]);
			gen_one(reg);
		}
		return true;
	}
	if (frame_t_is_const(slot)) {
		if (!swap) {
			g(gen_imm(ctx, get_constant(size, ex, slot, offset, dual), !logical ? IMM_PURPOSE_CMP : IMM_PURPOSE_CMP_LOGICAL, size));
			gen_insn(INSN_CMP, i_size_cmp(size), 0, 1 + logical);
			gen_one(reg);
			gen_imm_offset();
		} else {
			g(gen_load_constant(ctx, R_SCRATCH_3, get_constant(size, ex, slot, offset, dual)));
			gen_insn(INSN_CMP, i_size_cmp(size), 0, 1 + logical);
			gen_one(R_SCRATCH_3);
			gen_one(reg);
		}
		return true;
	}
#if defined(ARCH_S390) || defined(ARCH_X86)
#if defined(ARCH_S390)
	if (size < OP_SIZE_4)
		goto fallback;
#endif
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
	gen_insn(INSN_CMP, size, 0, 1 + logical);
	if (!swap) {
		gen_one(reg);
		gen_address_offset();
	} else {
		gen_address_offset();
		gen_one(reg);
	}
	return true;
#endif
fallback:
#if defined(R_SCRATCH_NA_1)
	g(gen_frame_load(ctx, size, ex, slot, offset, false, R_SCRATCH_NA_1));
	gen_insn(INSN_CMP, i_size_cmp(size), 0, 1 + logical);
	if (!swap) {
		gen_one(reg);
		gen_one(R_SCRATCH_NA_1);
	} else {
		gen_one(R_SCRATCH_NA_1);
		gen_one(reg);
	}
#endif
	return true;
}

static bool attr_w gen_frame_load_cmp_imm(struct codegen_context *ctx, unsigned size, bool logical, enum extend attr_unused ex, frame_t slot, int64_t offset, int64_t value)
{
	if (slot_is_register(ctx, slot)) {
#if defined(ARCH_X86)
		g(gen_imm(ctx, value, logical ? IMM_PURPOSE_CMP_LOGICAL : IMM_PURPOSE_CMP, size));
		gen_insn(INSN_CMP, size, 0, 1 + logical);
		gen_one(ctx->registers[slot]);
		gen_imm_offset();
#else
		if (size != i_size(size) + (unsigned)zero && size < OP_SIZE_4 && ex != garbage)
			goto fallback;
		g(gen_imm(ctx, value, logical ? IMM_PURPOSE_CMP_LOGICAL : IMM_PURPOSE_CMP, size));
		gen_insn(INSN_CMP, i_size_cmp(size), 0, 1 + logical);
		gen_one(ctx->registers[slot]);
		gen_imm_offset();
#endif
		return true;
	}
#if defined(ARCH_X86)
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_MVI_CLI_OFFSET, size));
	g(gen_imm(ctx, value, logical ? IMM_PURPOSE_CMP_LOGICAL : IMM_PURPOSE_CMP, size));
	gen_insn(INSN_CMP, size, 0, 1 + logical);
	gen_address_offset();
	gen_imm_offset();
	return true;
#endif
#if defined(ARCH_S390)
	if (size != OP_SIZE_1 || !logical)
		goto fallback;
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_MVI_CLI_OFFSET, size));
	gen_insn(INSN_CMP, size, 0, 1 + logical);
	gen_address_offset();
	gen_one(ARG_IMM);
	gen_eight((int8_t)value);
	return true;
#endif
#if defined(R_SCRATCH_NA_1)
	goto fallback;
fallback:
	g(gen_frame_load(ctx, size, ex, slot, offset, false, R_SCRATCH_NA_1));
	g(gen_imm(ctx, value, logical ? IMM_PURPOSE_CMP_LOGICAL : IMM_PURPOSE_CMP, size));
	gen_insn(INSN_CMP, i_size(size), 0, 1 + logical);
	gen_one(R_SCRATCH_NA_1);
	gen_imm_offset();
	return true;
#endif
}
#endif

static bool attr_w gen_frame_load_2(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg1, unsigned reg2)
{
	if (frame_t_is_const(slot))
		goto skip_ldd;
#if defined(ARCH_ARM32)
	if (likely(!(reg1 & 1)) && likely(reg2 == reg1 + 1) && likely(cpu_test_feature(CPU_FEATURE_armv6)))
#elif defined(ARCH_ARM64)
	if (1)
#elif defined(ARCH_SPARC32)
	if (likely(!(reg2 & 1)) && likely(reg1 == reg2 + 1))
#elif defined(ARCH_S390)
	if (likely(reg1 == reg2 + 1))
#else
	if (0)
#endif
	{
		offset += (size_t)slot * slot_size;
		if (UNALIGNED_TRAP) {
			if (unlikely(((frame_offset + offset) & ((2U << size) - 1)) != 0)) {
				offset -= (size_t)slot * slot_size;
				goto skip_ldd;
			}
		}
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, size));
		gen_insn(INSN_LDP, size, 0, 0);
		gen_one(reg1);
		gen_one(reg2);
		gen_address_offset();
		return true;
	}
	goto skip_ldd;
skip_ldd:
	g(gen_frame_load(ctx, size, garbage, slot, offset + lo_word(size), true, reg1));
	g(gen_frame_load(ctx, size, garbage, slot, offset + hi_word(size), true, reg2));
	return true;
}

static bool attr_w gen_frame_store_raw(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg)
{
	offset += (size_t)slot * slot_size;
	if (!ARCH_HAS_BWX)
		size = maximum(OP_SIZE_4, size);
#if defined(ARCH_MIPS)
	if (reg_is_fp(reg) && size == OP_SIZE_8 && !MIPS_HAS_LS_DOUBLE) {
#if defined(C_LITTLE_ENDIAN)
		g(gen_frame_store_raw(ctx, OP_SIZE_4, 0, offset, reg));
		g(gen_frame_store_raw(ctx, OP_SIZE_4, 0, offset + 4, reg + 1));
#else
		g(gen_frame_store_raw(ctx, OP_SIZE_4, 0, offset, reg + 1));
		g(gen_frame_store_raw(ctx, OP_SIZE_4, 0, offset + 4, reg));
#endif
		return true;
	}
#endif
#if defined(ARCH_S390)
	if (size == OP_SIZE_16 && reg_is_fp(reg)) {
		g(gen_frame_store_raw(ctx, OP_SIZE_8, 0, offset, reg));
		g(gen_frame_store_raw(ctx, OP_SIZE_8, 0, offset + 8, reg + 2));
		return true;
	}
#endif
	g(gen_address(ctx, R_FRAME, offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_STR_OFFSET, size));
	gen_insn(INSN_MOV, size, 0, 0);
	gen_address_offset();
	gen_one(reg);
	return true;
}

static bool attr_w gen_frame_store(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg)
{
	ajla_assert_lo(slot >= MIN_USEABLE_SLOT && slot < function_n_variables(ctx->fn), (file_line, "gen_frame_store: invalid slot: %lu >= %lu", (unsigned long)slot, (unsigned long)function_n_variables(ctx->fn)));
	if (slot_is_register(ctx, slot)) {
		if (unlikely(offset != 0))
			internal(file_line, "gen_frame_store: offset is non-zero: %"PRIdMAX"", (intmax_t)offset);
		g(gen_mov(ctx, !reg_is_fp(reg) ? OP_SIZE_NATIVE : size, ctx->registers[slot], reg));
		return true;
	}
	return gen_frame_store_raw(ctx, size, slot, offset, reg);
}

static unsigned gen_frame_target(struct codegen_context *ctx, frame_t slot_r, frame_t slot_na_1, frame_t slot_na_2, unsigned reg)
{
	if (slot_is_register(ctx, slot_r)) {
		short d = ctx->registers[slot_r];
		if (slot_na_1 != NO_FRAME_T && slot_is_register(ctx, slot_na_1) && ctx->registers[slot_na_1] == d)
			return reg;
		if (slot_na_2 != NO_FRAME_T && slot_is_register(ctx, slot_na_2) && ctx->registers[slot_na_2] == d)
			return reg;
		return d;
	}
	return reg;
}

static bool attr_w gen_frame_store_2(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg1, unsigned reg2)
{
#if defined(ARCH_ARM32)
	if (likely(!(reg1 & 1)) && likely(reg2 == reg1 + 1) && likely(cpu_test_feature(CPU_FEATURE_armv6)))
#elif defined(ARCH_ARM64)
	if (1)
#elif defined(ARCH_SPARC32)
	if (likely(!(reg2 & 1)) && likely(reg1 == reg2 + 1))
#elif defined(ARCH_S390)
	if (likely(reg1 == reg2 + 1))
#else
	if (0)
#endif
	{
		offset += (size_t)slot * slot_size;
		if (UNALIGNED_TRAP) {
			if (unlikely(((frame_offset + offset) & ((2U << size) - 1)) != 0)) {
				offset -= (size_t)slot * slot_size;
				goto skip_ldd;
			}
		}
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, size));
		gen_insn(INSN_STP, size, 0, 0);
		gen_address_offset();
		gen_one(reg1);
		gen_one(reg2);
		return true;
	}
	goto skip_ldd;
skip_ldd:
	g(gen_frame_store(ctx, size, slot, offset + lo_word(size), reg1));
	g(gen_frame_store(ctx, size, slot, offset + hi_word(size), reg2));
	return true;
}

static bool attr_w gen_frame_store_imm_raw(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, int64_t imm)
{
	unsigned purpose = size == OP_SIZE_1 ? IMM_PURPOSE_MVI_CLI_OFFSET : IMM_PURPOSE_STR_OFFSET;
	offset += (size_t)slot * slot_size;
	if (!ARCH_HAS_BWX)
		size = maximum(OP_SIZE_4, size);
#if !defined(R_CONST_IMM)
	if (!is_direct_const(imm, purpose, size)) {
		g(gen_load_constant(ctx, R_SCRATCH_3, imm));
		g(gen_address(ctx, R_FRAME, offset, purpose, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_3);
		return true;
	}
#endif
	g(gen_address(ctx, R_FRAME, offset, purpose, size));
	g(gen_imm(ctx, imm, IMM_PURPOSE_STORE_VALUE, size));
	gen_insn(INSN_MOV, size, 0, 0);
	gen_address_offset();
	gen_imm_offset();
	return true;
}

static bool attr_w gen_frame_store_imm(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, int64_t imm)
{
	ajla_assert_lo(slot >= MIN_USEABLE_SLOT && slot < function_n_variables(ctx->fn), (file_line, "gen_frame_store_imm: invalid slot: %lu >= %lu", (unsigned long)slot, (unsigned long)function_n_variables(ctx->fn)));
	if (slot_is_register(ctx, slot)) {
		if (unlikely(offset != 0))
			internal(file_line, "gen_frame_store_imm: offset is non-zero: %"PRIdMAX"", (intmax_t)offset);
		if (size == OP_SIZE_1)
			imm = ARCH_PREFERS_SX(size) ? (int64_t)(int8_t)imm : (int64_t)(uint8_t)imm;
		if (size == OP_SIZE_2)
			imm = ARCH_PREFERS_SX(size) ? (int64_t)(int16_t)imm : (int64_t)(uint16_t)imm;
		if (size == OP_SIZE_4)
			imm = ARCH_PREFERS_SX(size) ? (int64_t)(int32_t)imm : (int64_t)(uint32_t)imm;
		g(gen_load_constant(ctx, ctx->registers[slot], imm));
		return true;
	}
	return gen_frame_store_imm_raw(ctx, size, slot, offset, imm);
}

static bool attr_w gen_frame_clear_raw(struct codegen_context *ctx, unsigned size, frame_t slot)
{
	g(gen_frame_store_imm_raw(ctx, size, slot, 0, 0));
	return true;
}

static bool attr_w gen_frame_clear(struct codegen_context *ctx, unsigned size, frame_t slot)
{
	g(gen_frame_store_imm(ctx, size, slot, 0, 0));
	if (slot_is_register(ctx, slot))
		g(spill(ctx, slot));
	return true;
}

#if defined(ARCH_X86)
static bool attr_w gen_frame_set_cond(struct codegen_context *ctx, unsigned attr_unused size, bool attr_unused logical, unsigned cond, frame_t slot)
{
	size_t offset;
	if (slot_is_register(ctx, slot)) {
		unsigned reg = ctx->registers[slot];
#if defined(ARCH_X86_32)
		if (reg >= 4) {
			gen_insn(INSN_SET_COND_PARTIAL, OP_SIZE_1, cond, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);

			g(gen_mov(ctx, OP_SIZE_1, reg, R_SCRATCH_1));
			return true;
		}
#endif
		if (cpu_test_feature(CPU_FEATURE_apx)) {
			gen_insn(INSN_SET_COND, OP_SIZE_8, cond, 0);
			gen_one(reg);
		} else {
			gen_insn(INSN_SET_COND_PARTIAL, OP_SIZE_1, cond, 0);
			gen_one(reg);
			gen_one(reg);
			if (sizeof(ajla_flat_option_t) > 1)
				g(gen_mov(ctx, OP_SIZE_1, reg, reg));
		}
		return true;
	}
	offset = (size_t)slot * slot_size;
	if (sizeof(ajla_flat_option_t) > 1) {
		gen_insn(INSN_SET_COND_PARTIAL, OP_SIZE_1, cond, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);

		g(gen_mov(ctx, OP_SIZE_1, R_SCRATCH_1, R_SCRATCH_1));

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot, 0, R_SCRATCH_1));
	} else {
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_SET_COND, OP_SIZE_1, cond, 0);
		gen_address_offset();
	}
	return true;
}
#elif defined(ARCH_ARM64)
static bool attr_w gen_frame_set_cond(struct codegen_context *ctx, unsigned attr_unused size, bool attr_unused logical, unsigned cond, frame_t slot)
{
	if (slot_is_register(ctx, slot)) {
		gen_insn(INSN_SET_COND, OP_SIZE_4, cond, 0);
		gen_one(ctx->registers[slot]);
	} else {
		gen_insn(INSN_SET_COND, OP_SIZE_4, cond, 0);
		gen_one(R_SCRATCH_1);
		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot, 0, R_SCRATCH_1));
	}
	return true;
}
#elif ARCH_HAS_FLAGS
static bool attr_w gen_frame_set_cond(struct codegen_context *ctx, unsigned size, bool logical, unsigned cond, frame_t slot)
{
	unsigned target = gen_frame_target(ctx, slot, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
#if defined(ARCH_POWER)
	if (!cpu_test_feature(CPU_FEATURE_v203))
#elif defined(ARCH_S390)
	if (!cpu_test_feature(CPU_FEATURE_misc_45))
#elif defined(ARCH_SPARC32)
	if (!SPARC_9)
#else
	if (0)
#endif
	{
		uint32_t label;
		g(gen_load_constant(ctx, target, 1));
		label = alloc_label(ctx);
		if (unlikely(!label))
			return false;
		gen_insn(!logical ? INSN_JMP_COND : INSN_JMP_COND_LOGICAL, i_size_cmp(size), cond, 0);
		gen_four(label);
		g(gen_load_constant(ctx, target, 0));
		gen_label(label);
		goto do_store;
	}
	g(gen_load_constant(ctx, target, 1));
	g(gen_imm(ctx, 0, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
	if (cond & COND_FP) {
		gen_insn(INSN_CMOV, OP_SIZE_NATIVE, cond ^ 1, 0);
	} else {
#if defined(ARCH_S390)
		gen_insn(logical ? INSN_CMOV_XCC : INSN_CMOV, OP_SIZE_NATIVE, cond ^ 1, 0);
#else
		gen_insn(size == OP_SIZE_8 ? INSN_CMOV_XCC : INSN_CMOV, OP_SIZE_NATIVE, cond ^ 1, 0);
#endif
	}
	gen_one(target);
	gen_one(target);
	gen_imm_offset();
do_store:
	g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot, 0, target));
	return true;
}
#endif

#if !ARCH_HAS_FLAGS
static bool attr_w gen_frame_cmp_imm_set_cond_reg(struct codegen_context *ctx, unsigned size, unsigned reg, int64_t imm, unsigned cond, frame_t slot_r)
{
	unsigned dest_reg;
	dest_reg = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_CMP_RESULT);
	g(gen_cmp_dest_reg(ctx, size, reg, (unsigned)-1, dest_reg, imm, cond));
	g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, dest_reg));

	return true;
}
#endif

static bool attr_w gen_frame_load_cmp_set_cond(struct codegen_context *ctx, unsigned size, enum extend ex, frame_t slot, unsigned reg, unsigned cond, frame_t slot_r)
{
#if ARCH_HAS_FLAGS
	bool logical = COND_IS_LOGICAL(cond);
	g(gen_frame_load_cmp(ctx, size, logical, ex, false, slot, 0, false, reg));
	g(gen_frame_set_cond(ctx, size, logical, cond, slot_r));
#else
	unsigned src_reg, dest_reg;
	g(gen_frame_get(ctx, size, ex, slot, R_SCRATCH_NA_1, &src_reg));
	dest_reg = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_NA_1);
	g(gen_cmp_dest_reg(ctx, size, reg, src_reg, dest_reg, 0, cond));
	g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, dest_reg));
#endif
	return true;
}

static bool attr_w gen_frame_load_cmp_imm_set_cond(struct codegen_context *ctx, unsigned size, enum extend ex, frame_t slot, int64_t value, unsigned cond, frame_t slot_r)
{
#if ARCH_HAS_FLAGS
	bool logical = COND_IS_LOGICAL(cond);
#if defined(ARCH_S390)
	if (cond == COND_E)
		logical = true;
#endif
	g(gen_frame_load_cmp_imm(ctx, size, logical, ex, slot, 0, value));
	g(gen_frame_set_cond(ctx, size, false, cond, slot_r));
#else
	unsigned src_reg;
	g(gen_frame_get(ctx, size, ex, slot, R_SCRATCH_NA_1, &src_reg));
	g(gen_frame_cmp_imm_set_cond_reg(ctx, size, src_reg, value, cond, slot_r));
#endif
	return true;
}

#if defined(ARCH_ARM) || defined(ARCH_S390) || defined(ARCH_SPARC)
static bool spill_can_pair(struct codegen_context *ctx, frame_t slot1, frame_t slot2, unsigned *s, int64_t *o, bool can_be_smaller)
{
	const struct type *t1 = get_type_of_local(ctx, slot1);
	const struct type *t2 = get_type_of_local(ctx, slot2);
	unsigned s1 = spill_size(t1);
	unsigned s2 = spill_size(t2);
#if !defined(C_LITTLE_ENDIAN)
	can_be_smaller = false;
#endif
	if (TYPE_TAG_IS_REAL(t1->tag) || TYPE_TAG_IS_REAL(t2->tag))
		return false;
	if (unlikely(s1 > OP_SIZE_NATIVE) || unlikely(s2 > OP_SIZE_NATIVE))
		return false;
	if (!can_be_smaller && (s1 < OP_SIZE_SLOT || s2 < OP_SIZE_SLOT))
		return false;
	s1 = maximum(s1, OP_SIZE_SLOT);
	s2 = maximum(s2, OP_SIZE_SLOT);
	if (unlikely(s1 != s2))
		return false;
	if (slot1 + 1 + (s1 > OP_SIZE_SLOT) != slot2)
		return false;
#if defined(ARCH_ARM32)
	if (unlikely(!cpu_test_feature(CPU_FEATURE_armv6)))
		return false;
#endif
#if defined(ARCH_ARM32) || defined(ARCH_SPARC)
	if (ctx->registers[slot1] & 1 ||
	    ctx->registers[slot2] != ctx->registers[slot1] + 1)
		return false;
#endif
#if defined(ARCH_S390)
	if (ctx->registers[slot2] != ctx->registers[slot1] + 1)
		return false;
#endif
#if defined(ARCH_SPARC)
	if (s1 != OP_SIZE_4)
		return false;
	if ((frame_offset + (slot1 * slot_size)) & 0x7)
		return false;
#endif
	*s = s1;
	*o = (size_t)slot1 * slot_size;
	return true;
}
#endif

static bool attr_w gen_spill_multiple(struct codegen_context *ctx, frame_t *v, size_t l, bool attr_unused can_be_smaller)
{
	size_t i;
	for (i = 0; i < l; i++) {
#if defined(ARCH_ARM) || defined(ARCH_S390) || defined(ARCH_SPARC)
		if (i + 1 < l) {
			unsigned s = 0;		/* avoid warning */
			int64_t offset = 0;	/* avoid warning */
			if (!spill_can_pair(ctx, v[i], v[i + 1], &s, &offset, can_be_smaller))
				goto skip_opt;
			g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, s));
			gen_insn(INSN_STP, s, 0, 0);
			gen_address_offset();
#if defined(ARCH_S390) || defined(ARCH_SPARC)
			gen_one(ctx->registers[v[i + 1]]);
			gen_one(ctx->registers[v[i]]);
#else
			gen_one(ctx->registers[v[i]]);
			gen_one(ctx->registers[v[i + 1]]);
#endif
			i++;
			continue;
		}
skip_opt:
#endif
		g(spill(ctx, v[i]));
	}
	return true;
}

static bool attr_w gen_unspill_multiple(struct codegen_context *ctx, frame_t *v, size_t l, bool attr_unused can_be_smaller)
{
	size_t i;
	for (i = 0; i < l; i++) {
#if defined(ARCH_ARM) || defined(ARCH_S390) || defined(ARCH_SPARC)
		if (i + 1 < l) {
			unsigned s = 0;		/* avoid warning */
			int64_t offset = 0;	/* avoid warning */
			if (!spill_can_pair(ctx, v[i], v[i + 1], &s, &offset, can_be_smaller))
				goto skip_opt;
			g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, s));
			gen_insn(INSN_LDP, s, 0, 0);
#if defined(ARCH_S390) || defined(ARCH_SPARC)
			gen_one(ctx->registers[v[i + 1]]);
			gen_one(ctx->registers[v[i]]);
#else
			gen_one(ctx->registers[v[i]]);
			gen_one(ctx->registers[v[i + 1]]);
#endif
			gen_address_offset();
			i++;
			continue;
		}
skip_opt:
#endif
		g(unspill(ctx, v[i]));
	}
	return true;
}

static bool attr_w gen_spill_all(struct codegen_context *ctx)
{
	frame_t v, n_vars, *vars;

	vars = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, function_n_variables(ctx->fn), sizeof(frame_t), &ctx->err);
	if (unlikely(!vars))
		return false;
	n_vars = 0;
	for (v = MIN_USEABLE_SLOT; v < function_n_variables(ctx->fn); v++)
		if (slot_is_register(ctx, v))
			vars[n_vars++] = v;
	if (unlikely(!gen_spill_multiple(ctx, vars, n_vars, false))) {
		mem_free(vars);
		return false;
	}
	mem_free(vars);
	return true;
}

static bool attr_w gen_upcall_start(struct codegen_context *ctx, unsigned offset, unsigned args, bool do_spill)
{
	unsigned idx;
	size_t attr_unused i;
	int attr_unused reg_to_push = -1;
	ajla_assert_lo(ctx->upcall_args == -1, (file_line, "gen_upcall_start: gen_upcall_end not called"));
	ajla_assert_lo(ctx->upcall_offset == -1, (file_line, "gen_upcall_start: gen_upcall_end not called"));
	ctx->upcall_args = (int)args;
	ctx->upcall_offset = (int)offset;
	idx = offset / sizeof(void *);
	ctx->upcall_hacked_abi = false;
	if (idx < 32 && (hacked_upcall_map >> idx) & 1)
		ctx->upcall_hacked_abi = true;

	if (do_spill) {
#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
		for (i = 0; i < ctx->need_spill_l; i++) {
			unsigned reg = ctx->registers[ctx->need_spill[i]];
			if (reg_is_fp(reg))
				g(spill(ctx, ctx->need_spill[i]));
		}
		ctx->n_pushes = 0;
		for (i = 0; i < ctx->need_spill_l; i++) {
			unsigned reg = ctx->registers[ctx->need_spill[i]];
			if (!reg_is_fp(reg)) {
				if (ctx->upcall_hacked_abi && !reg_is_saved(reg))
					continue;
				if (reg_to_push < 0) {
					reg_to_push = reg;
				} else {
					g(gen_x86_push2(ctx, reg_to_push, reg, true));
					reg_to_push = -1;
				}
				ctx->n_pushes++;
			}
		}
		if (ctx->n_pushes & 1) {
			g(gen_x86_push2(ctx, reg_to_push, R_CX, true));
		}
#else
		g(gen_spill_multiple(ctx, ctx->need_spill, ctx->need_spill_l, true));
#endif
	}
	return true;
}

static bool attr_w gen_upcall_end(struct codegen_context *ctx, unsigned attr_unused offset, unsigned attr_unused args, bool do_unspill)
{
	size_t attr_unused i;
	int attr_unused reg_to_pop = -1;
	ajla_assert_lo(ctx->upcall_args == (int)args, (file_line, "gen_upcall_end: gen_upcall_start args mismatch: %d != %d", ctx->upcall_args, (int)args));
	ajla_assert_lo(ctx->upcall_offset == (int)offset, (file_line, "gen_upcall_end: gen_upcall_start offset mismatch: %d != %d", ctx->upcall_offset, (int)offset));

	if (do_unspill) {
#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
		if (ctx->n_pushes & 1) {
			reg_to_pop = R_CX;
		}
		for (i = ctx->need_spill_l; i;) {
			unsigned reg;
			i--;
			reg = ctx->registers[ctx->need_spill[i]];
			if (!reg_is_fp(reg)) {
				if (ctx->upcall_hacked_abi && !reg_is_saved(reg))
					continue;
				if (reg_to_pop < 0) {
					reg_to_pop = reg;
				} else {
					g(gen_x86_pop2(ctx, reg_to_pop, reg, true));
					reg_to_pop = -1;
				}
			}
		}
		ajla_assert_lo(reg_to_pop == -1, (file_line, "gen_upcall_end: reg_to_pop mismatch"));
		for (i = 0; i < ctx->need_spill_l; i++) {
			unsigned reg = ctx->registers[ctx->need_spill[i]];
			if (reg_is_fp(reg))
				g(unspill(ctx, ctx->need_spill[i]));
		}
#else
		g(gen_unspill_multiple(ctx, ctx->need_spill, ctx->need_spill_l, true));
#endif
	}
	ctx->upcall_args = -1;
	ctx->upcall_offset = -1;
	ctx->upcall_hacked_abi = false;
	return true;
}

static bool attr_w gen_memcpy_raw(struct codegen_context *ctx, unsigned dest_base, int64_t dest_offset, unsigned src_base, int64_t src_offset, size_t size, size_t align)
{
	if (!size)
		return true;
	if (!ARCH_HAS_BWX) {
		if (align < 4 || (size & 3))
			goto call_memcpy;
	}
#if defined(ARCH_S390)
	if (size <= 0x10) {
		if (!(size & 3) || (cpu_test_feature(CPU_FEATURE_long_displacement) && cpu_test_feature(CPU_FEATURE_extended_imm)))
			goto do_explicit_copy;
	}
	if (size <= 0x100 && dest_offset >= 0 && dest_offset < 0x1000 && src_offset >= 0 && src_offset < 0x1000) {
		gen_insn(INSN_MEMCPY, 0, 0, 0);
		gen_one(ARG_ADDRESS_1);
		gen_one(dest_base);
		gen_eight(dest_offset);
		gen_one(ARG_ADDRESS_1);
		gen_one(src_base);
		gen_eight(src_offset);
		gen_one(ARG_IMM);
		gen_eight(size);
		return true;
	}
	goto call_memcpy;
do_explicit_copy:
#endif
	if (size <= INLINE_COPY_SIZE) {
		while (size) {
			unsigned reg;
			unsigned this_step;
			unsigned this_op_size;
#if defined(ARCH_ARM)
			if (size >= 2U << OP_SIZE_NATIVE
#if defined(ARCH_ARM32)
				&& align >= 1U << OP_SIZE_NATIVE
#endif
			) {
				g(gen_address(ctx, src_base, src_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_LDP, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_SCRATCH_NA_1);
				gen_one(R_SCRATCH_NA_2);
				gen_address_offset();

				g(gen_address(ctx, dest_base, dest_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_STP, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_NA_1);
				gen_one(R_SCRATCH_NA_2);

				size -= 2U << OP_SIZE_NATIVE;
				src_offset += 2U << OP_SIZE_NATIVE;
				dest_offset += 2U << OP_SIZE_NATIVE;

				continue;
			}
#endif
			reg = R_SCRATCH_1;
#if defined(ARCH_X86)
			if (size >= 16 && align >= 16 && cpu_test_feature(CPU_FEATURE_sse)) {
				this_step = 16;
				reg = FR_SCRATCH_1;
			} else
#endif
			if (size >= 8 && OP_SIZE_NATIVE >= OP_SIZE_8)
				this_step = 8;
			else if (size >= 4)
				this_step = 4;
			else if (size >= 2)
				this_step = 2;
			else
				this_step = 1;
			if (UNALIGNED_TRAP)
				this_step = minimum(this_step, align);
			this_op_size = log_2(this_step);

			g(gen_address(ctx, src_base, src_offset, ARCH_PREFERS_SX(this_op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, this_op_size));
			gen_insn(ARCH_PREFERS_SX(this_op_size) ? INSN_MOVSX : INSN_MOV, this_op_size, 0, 0);
			gen_one(reg);
			gen_address_offset();

			g(gen_address(ctx, dest_base, dest_offset, IMM_PURPOSE_STR_OFFSET, this_op_size));
			gen_insn(INSN_MOV, this_op_size, 0, 0);
			gen_address_offset();
			gen_one(reg);

			size -= this_step;
			src_offset += this_step;
			dest_offset += this_step;
		}
		return true;
	}

call_memcpy:
	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, mem_copy), 3, true));
	if (unlikely(R_ARG0 == src_base)) {
		if (unlikely(R_ARG1 == dest_base))
			internal(file_line, "gen_memcpy_raw: swapped registers: %u, %u", src_base, dest_base);
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG1, src_base, src_offset, 0));
		g(gen_upcall_argument(ctx, 1));
	}

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG0, dest_base, dest_offset, 0));
	g(gen_upcall_argument(ctx, 0));

	if (R_ARG0 != src_base) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG1, src_base, src_offset, 0));
		g(gen_upcall_argument(ctx, 1));
	}

#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
	if (cpu_test_feature(CPU_FEATURE_erms)) {
		g(gen_load_constant(ctx, R_CX, size));

		gen_insn(INSN_MEMCPY, 0, 0, 0);
		gen_one(ARG_ADDRESS_1_POST_I);
		gen_one(R_DI);
		gen_eight(0);
		gen_one(ARG_ADDRESS_1_POST_I);
		gen_one(R_SI);
		gen_eight(0);
		gen_one(R_CX);
		g(gen_upcall_end(ctx, offsetof(struct cg_upcall_vector_s, mem_copy), 3, true));
		return true;
	}
#endif

	g(gen_load_constant(ctx, R_ARG2, size));
	g(gen_upcall_argument(ctx, 2));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, mem_copy), 3, true));

	return true;
}

static bool attr_w gen_memcpy_to_slot(struct codegen_context *ctx, frame_t dest_slot, unsigned src_base, int64_t src_offset)
{
	const struct type *t = get_type_of_local(ctx, dest_slot);
	unsigned size = spill_size(t);
	short dest_reg = ctx->registers[dest_slot];
	if (dest_reg >= 0) {
		if (ARCH_PREFERS_SX(size) && !reg_is_fp(dest_reg)) {
#if defined(ARCH_S390)
			if (size == OP_SIZE_1 && !cpu_test_feature(CPU_FEATURE_long_displacement)) {
				g(gen_address(ctx, src_base, src_offset, IMM_PURPOSE_LDR_OFFSET, size));
				gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_0_8, 0);
				gen_one(dest_reg);
				gen_one(dest_reg);
				gen_address_offset();
				g(gen_extend(ctx, size, sign_x, dest_reg, dest_reg));
				return true;
			}
#endif
			g(gen_address(ctx, src_base, src_offset, IMM_PURPOSE_LDR_SX_OFFSET, size));
			gen_insn(INSN_MOVSX, size, 0, 0);
		} else {
			g(gen_address(ctx, src_base, src_offset, reg_is_fp(dest_reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_LDR_OFFSET, size));
			gen_insn(INSN_MOV, size, 0, 0);
		}
		gen_one(dest_reg);
		gen_address_offset();
		return true;
	}
	g(gen_memcpy_raw(ctx, R_FRAME, (size_t)dest_slot * slot_size, src_base, src_offset, t->size, t->align));
	return true;
}

static bool attr_w gen_memcpy_from_slot(struct codegen_context *ctx, unsigned dest_base, int64_t dest_offset, frame_t src_slot)
{
	const struct type *t = get_type_of_local(ctx, src_slot);
	short src_reg = ctx->registers[src_slot];
	if (src_reg >= 0) {
		unsigned size = spill_size(t);
		g(gen_address(ctx, dest_base, dest_offset, reg_is_fp(src_reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_STR_OFFSET, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_address_offset();
		gen_one(src_reg);
		return true;
	}
	g(gen_memcpy_raw(ctx, dest_base, dest_offset, R_FRAME, (size_t)src_slot * slot_size, t->size, t->align));
	return true;
}

static bool attr_w gen_memcpy_slots(struct codegen_context *ctx, frame_t dest_slot, frame_t src_slot)
{
	const struct type *t = get_type_of_local(ctx, src_slot);
	short dest_reg = ctx->registers[dest_slot];
	short src_reg = ctx->registers[src_slot];
	if (dest_reg >= 0 && src_reg >= 0) {
		unsigned size = spill_size(t);
		g(gen_mov(ctx, reg_is_fp(src_reg) ? size : OP_SIZE_NATIVE, dest_reg, src_reg));
		return true;
	}
	if (dest_reg >= 0) {
		unsigned size = spill_size(t);
		g(gen_frame_load(ctx, size, garbage, src_slot, 0, false, dest_reg));
		return true;
	}
	if (src_reg >= 0) {
		unsigned size = spill_size(t);
		g(gen_frame_store(ctx, size, dest_slot, 0, src_reg));
		return true;
	}
	g(gen_memcpy_raw(ctx, R_FRAME, (size_t)dest_slot * slot_size, R_FRAME, (size_t)src_slot * slot_size, t->size, maximum(slot_size, t->align)));
	return true;
}

static bool attr_w gen_clear_bitmap(struct codegen_context *ctx, unsigned additional_offset, unsigned dest_base, int64_t dest_offset, frame_t bitmap_slots)
{
	if (bitmap_slots <= INLINE_BITMAP_SLOTS) {
		bool attr_unused scratch_2_zeroed = false;
		size_t bitmap_length = (size_t)bitmap_slots * slot_size;
		size_t clear_offset = 0;
		additional_offset += (unsigned)dest_offset;
#if defined(ARCH_X86)
		g(gen_3address_alu(ctx, OP_SIZE_4, ALU_XOR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_1, 0));
#endif
#if defined(ARCH_ARM32) || defined(ARCH_S390)
		g(gen_load_constant(ctx, R_SCRATCH_1, 0));
#endif
		while (clear_offset < bitmap_length) {
			size_t len = bitmap_length - clear_offset;
			if (len > frame_align)
				len = frame_align;
			if (additional_offset)
				len = minimum(len, additional_offset & -additional_offset);
#if defined(ARCH_ARM32) || defined(ARCH_S390)
			len = minimum(len, 2U << OP_SIZE_NATIVE);
			if (len == 2U << OP_SIZE_NATIVE) {
				if (!scratch_2_zeroed) {
					g(gen_load_constant(ctx, R_SCRATCH_2, 0));
					scratch_2_zeroed = true;
				}
				g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_STP, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_2);
				goto next_loop;
			}
#elif defined(ARCH_ARM64)
			len = minimum(len, 1U << OP_SIZE_16);
			if (len == 1U << OP_SIZE_16) {
				g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_8));
				g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, OP_SIZE_8));
				gen_insn(INSN_STP, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_imm_offset();
				gen_imm_offset();
				goto next_loop;
			}
#elif defined(ARCH_X86)
			len = minimum(len, 1U << OP_SIZE_16);
			if (len == 1U << OP_SIZE_16 && cpu_test_feature(CPU_FEATURE_sse)) {
				if (!scratch_2_zeroed) {
					g(gen_3address_alu(ctx, OP_SIZE_16, ALU_XOR, FR_SCRATCH_1, FR_SCRATCH_1, FR_SCRATCH_1, 0));
					scratch_2_zeroed = true;
				}
				g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_VLDR_VSTR_OFFSET, OP_SIZE_16));
				gen_insn(INSN_MOV, OP_SIZE_16, 0, 0);
				gen_address_offset();
				gen_one(FR_SCRATCH_1);
				goto next_loop;
			}
#endif
			len = minimum(len, 1U << OP_SIZE_NATIVE);
			len = (size_t)1 << high_bit(len);
#if defined(ARCH_X86) || defined(ARCH_ARM32) || defined(ARCH_S390)
			g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_STR_OFFSET, log_2(len)));
			gen_insn(INSN_MOV, log_2(len), 0, 0);
			gen_address_offset();
			gen_one(R_SCRATCH_1);
#else
			g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_STR_OFFSET, log_2(len)));
			g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, log_2(len)));
			gen_insn(INSN_MOV, log_2(len), 0, 0);
			gen_address_offset();
			gen_imm_offset();
#endif
			goto next_loop;
next_loop:
			clear_offset += len;
			additional_offset += len;
		}
		return true;
	}
#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
	if (cpu_test_feature(CPU_FEATURE_erms)) {
		g(gen_x86_push(ctx, R_DI, true));

		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_DI, dest_base, dest_offset, 0));

		g(gen_load_constant(ctx, R_CX, (size_t)bitmap_slots * slot_size));

		g(gen_3address_alu(ctx, OP_SIZE_4, ALU_XOR, R_AX, R_AX, R_AX, 0));

		gen_insn(INSN_MEMSET, 0, 0, 0);
		gen_one(ARG_ADDRESS_1_POST_I);
		gen_one(R_DI);
		gen_eight(0);
		gen_one(R_CX);
		gen_one(R_AX);

		g(gen_x86_pop(ctx, R_DI, true));

		return true;
	}
#endif
	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, mem_clear), 2, true));

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG0, dest_base, dest_offset, 0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, (size_t)bitmap_slots * slot_size));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, mem_clear), 2, true));

	return true;
}

static bool attr_w load_function_offset(struct codegen_context *ctx, unsigned dest, size_t fn_offset)
{
	g(gen_frame_load_raw(ctx, OP_SIZE_ADDRESS, zero_x, 0, frame_offs(function), false, dest));

	g(gen_address(ctx, dest, fn_offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(dest);
	gen_address_offset();

	return true;
}
