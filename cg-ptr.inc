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

#if defined(POINTER_COMPRESSION)
#define POINTER_THUNK_BIT		0
#elif defined(POINTER_IGNORE_START)
#define POINTER_THUNK_BIT		POINTER_IGNORE_TOP_BIT
#elif defined(POINTER_TAG)
#define POINTER_THUNK_BIT		POINTER_TAG_BIT
#else
unsupported pointer mode
#endif

static bool attr_w gen_ptr_is_thunk(struct codegen_context *ctx, unsigned reg, frame_t slot, uint32_t label)
{
	if (slot != NO_FRAME_T) {
		if (ctx->flag_cache[slot] & FLAG_CACHE_IS_NOT_THUNK || da(ctx->fn,function)->local_variables_flags[slot].must_be_data)
			return true;
		ctx->flag_cache[slot] |= FLAG_CACHE_IS_NOT_THUNK;
	}
#if defined(ARCH_X86)
	if (POINTER_THUNK_BIT < 8
#if defined(ARCH_X86_32)
		&& reg < 4
#endif
		) {
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_1, reg, (uint64_t)1 << POINTER_THUNK_BIT, COND_NE, label));
	} else
#endif
	{
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_SLOT, reg, (uint64_t)1 << POINTER_THUNK_BIT, COND_NE, label));
	}
	return true;
}

static bool attr_w gen_test_multiple_thunks(struct codegen_context *ctx, frame_t *variables, size_t n_variables, uint32_t label)
{
	size_t n;
#if defined(ARCH_X86) || defined(ARCH_S390)
	if (n_variables >= 2) {
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, variables[0], 0, false, R_SCRATCH_1));
		for (n = 1; n < n_variables; n++) {
			g(gen_frame_load_op(ctx, OP_SIZE_SLOT, garbage, ALU_OR, 0, variables[n], 0, false, R_SCRATCH_1));
		}
		g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, NO_FRAME_T, label));
		return true;
	}
#endif
	for (n = 0; n < n_variables; n++) {
		unsigned reg;
		g(gen_frame_get(ctx, OP_SIZE_SLOT, garbage, variables[n], R_SCRATCH_1, &reg));
		g(gen_ptr_is_thunk(ctx, reg, NO_FRAME_T, label));
	}
	return true;
}

static bool attr_w gen_test_variables(struct codegen_context *ctx, frame_t *variables, size_t n_variables, uint32_t label)
{
	size_t i;
	frame_t *vars;

	for (i = 0; i < n_variables; i++) {
		frame_t v = variables[i];
		if (slot_is_register(ctx, v))
			g(unspill(ctx, v));
	}

	vars = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, n_variables, sizeof(frame_t), &ctx->err);
	if (unlikely(!vars))
		return false;

	for (i = 0; i < 2; i++) {
		size_t n_vars = 0;
		size_t n;
		for (n = 0; n < n_variables; n++) {
			frame_t v = variables[n];
			if (!i ? da(ctx->fn,function)->local_variables_flags[v].must_be_flat : da(ctx->fn,function)->local_variables_flags[v].must_be_data)
				vars[n_vars++] = v;
		}
		if (!i) {
			if (!gen_test_multiple(ctx, vars, n_vars, label)) {
				mem_free(vars);
				return false;
			}
		} else {
			if (!gen_test_multiple_thunks(ctx, vars, n_vars, label)) {
				mem_free(vars);
				return false;
			}
		}
	}

	mem_free(vars);
	return true;
}

static bool attr_w gen_barrier(struct codegen_context *ctx)
{
	if (ARCH_NEEDS_BARRIER)
		gen_insn(INSN_MB, 0, 0, 0);
	return true;
}

static bool attr_w gen_compare_refcount(struct codegen_context *ctx, unsigned ptr, unsigned val, unsigned cond, uint32_t label)
{
	unsigned op_size = log_2(sizeof(refcount_int_t));
#if defined(ARCH_X86)
	bool logical = COND_IS_LOGICAL(cond);
	g(gen_address(ctx, ptr, offsetof(struct data, refcount_), IMM_PURPOSE_LDR_OFFSET, op_size));
	g(gen_imm(ctx, val, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1 + logical);
	gen_address_offset();
	gen_imm_offset();

	gen_insn(!logical ? INSN_JMP_COND : INSN_JMP_COND_LOGICAL, op_size, cond, 0);
	gen_four(label);
#else
	g(gen_address(ctx, ptr, offsetof(struct data, refcount_), IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(INSN_MOV, op_size, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_2, val, cond, label));
#endif
	return true;
}

static bool attr_w gen_compare_ptr_tag(struct codegen_context *ctx, unsigned reg, unsigned tag, unsigned cond, uint32_t label, unsigned tmp_reg)
{
#if defined(ARCH_S390)
	switch (cond) {
		case COND_A:	cond = COND_G; break;
		case COND_AE:	cond = COND_GE; break;
		case COND_B:	cond = COND_L; break;
		case COND_BE:	cond = COND_LE; break;
	}
#endif
#if defined(DATA_TAG_AT_ALLOC)
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHR, tmp_reg, reg, POINTER_IGNORE_START, false));
#elif defined(REFCOUNT_TAG)
	size_t offset = offsetof(struct data, refcount_);
#if defined(C_BIG_ENDIAN)
	offset += sizeof(refcount_int_t) - 1;
#endif
#if defined(ARCH_X86) && REFCOUNT_STEP == 256
	g(gen_imm(ctx, tag, IMM_PURPOSE_CMP, OP_SIZE_4));
	gen_insn(INSN_CMP, OP_SIZE_1, 0, 1);
	gen_one(ARG_ADDRESS_1);
	gen_one(reg);
	gen_eight(offset);
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_1, cond, 0);
	gen_four(label);
	return true;
#endif
	if (ARCH_HAS_BWX && REFCOUNT_STEP == 256
#if defined(ARCH_S390)
		&& cpu_test_feature(CPU_FEATURE_extended_imm)
#endif
	    ) {
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(tmp_reg);
		gen_one(ARG_ADDRESS_1);
		gen_one(reg);
		gen_eight(offset);
	} else {
		gen_insn(INSN_MOV, log_2(sizeof(refcount_int_t)), 0, 0);
		gen_one(tmp_reg);
		gen_one(ARG_ADDRESS_1);
		gen_one(reg);
		gen_eight(offsetof(struct data, refcount_));

		g(gen_3address_alu_imm(ctx, log_2(sizeof(refcount_int_t)), ALU_AND, tmp_reg, tmp_reg, REFCOUNT_STEP - 1, 0));
	}
#else
#if defined(ARCH_S390)
	if (sizeof(tag_t) == 1 && !cpu_test_feature(CPU_FEATURE_extended_imm)) {
		g(gen_address(ctx, reg, offsetof(struct data, tag), IMM_PURPOSE_LDR_OFFSET, log_2(sizeof(tag_t))));
		gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_0_8, 0);
		gen_one(tmp_reg);
		gen_one(tmp_reg);
		gen_address_offset();

		g(gen_extend(ctx, log_2(sizeof(tag_t)), zero_x, tmp_reg, tmp_reg));
	} else
#endif
	{
		g(gen_address(ctx, reg, offsetof(struct data, tag), IMM_PURPOSE_LDR_OFFSET, log_2(sizeof(tag_t))));
		gen_insn(INSN_MOV, log_2(sizeof(tag_t)), 0, 0);
		gen_one(tmp_reg);
		gen_address_offset();
	}
#endif
	g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(OP_SIZE_4), tmp_reg, tag, cond, label));
	return true;
}

static bool attr_w gen_compare_da_tag(struct codegen_context *ctx, unsigned reg, unsigned tag, unsigned cond, uint32_t label, unsigned tmp_reg)
{
#if defined(ARCH_S390)
	switch (cond) {
		case COND_A:	cond = COND_G; break;
		case COND_AE:	cond = COND_GE; break;
		case COND_B:	cond = COND_L; break;
		case COND_BE:	cond = COND_LE; break;
	}
#endif
#if defined(POINTER_COMPRESSION)
#if defined(ARCH_X86) && POINTER_COMPRESSION <= 3 && defined(REFCOUNT_TAG) && REFCOUNT_STEP == 256 && defined(C_LITTLE_ENDIAN)
	g(gen_imm(ctx, tag, IMM_PURPOSE_CMP, log_2(sizeof(tag_t))));
	gen_insn(INSN_CMP, log_2(sizeof(tag_t)), 0, 0);
	gen_one(ARG_ADDRESS_1 + POINTER_COMPRESSION);
	gen_one(reg);
	gen_eight(offsetof(struct data, refcount_));
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_4, cond, 0);
	gen_four(label);

	return true;
#endif
	if (ARCH_PREFERS_SX(OP_SIZE_4)) {
		g(gen_extend(ctx, OP_SIZE_4, zero_x, tmp_reg, reg));

		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, tmp_reg, tmp_reg, POINTER_COMPRESSION, false));
	} else {
		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, tmp_reg, reg, POINTER_COMPRESSION, false));
	}
	g(gen_compare_ptr_tag(ctx, tmp_reg, tag, cond, label, tmp_reg));
	return true;
#endif
	g(gen_compare_ptr_tag(ctx, reg, tag, cond, label, tmp_reg));
	return true;
}

static bool attr_w gen_compare_tag_and_refcount(struct codegen_context *ctx, unsigned reg, unsigned tag, uint32_t label, unsigned attr_unused tmp_reg)
{
#if defined(REFCOUNT_TAG)
	g(gen_compare_refcount(ctx, reg, tag, COND_NE, label));
#else
	g(gen_compare_ptr_tag(ctx, reg, tag, COND_NE, label, tmp_reg));
	g(gen_compare_refcount(ctx, reg, REFCOUNT_STEP, COND_AE, label));
#endif
	return true;
}

static bool attr_w gen_decompress_pointer(struct codegen_context *ctx, bool attr_unused zx, unsigned dest, unsigned src, int64_t offset)
{
#ifdef POINTER_COMPRESSION
#if defined(ARCH_X86) && POINTER_COMPRESSION <= 3
	if (offset || dest != src) {
		g(gen_imm(ctx, offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, is_imm(), ctx->const_imm));
		gen_one(dest);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | POINTER_COMPRESSION);
		gen_one(src);
		gen_imm_offset();
		return true;
	}
#endif
	if (zx) {
		g(gen_extend(ctx, OP_SIZE_4, zero_x, dest, src));
		src = dest;
	}
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, dest, src, POINTER_COMPRESSION, false));
	src = dest;
#endif
	if (offset)
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, dest, src, offset, 0));
	return true;
}

static bool attr_w gen_compress_pointer(struct codegen_context attr_unused *ctx, unsigned dest, unsigned src)
{
#ifdef POINTER_COMPRESSION
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHR, dest, src, POINTER_COMPRESSION, false));
#else
	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), dest, src));
#endif
	return true;
}

static bool attr_w gen_frame_get_pointer(struct codegen_context *ctx, frame_t slot, bool deref, unsigned dest)
{
	if (!deref) {
		g(gen_upcall_start(ctx, 1));
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, dest));
	} else if (!da(ctx->fn,function)->local_variables_flags[slot].may_be_borrowed) {
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, dest));
		g(gen_set_1(ctx, R_FRAME, slot, 0, false));
		flag_set(ctx, slot, false);
	} else {
		uint32_t skip_label;
		skip_label = alloc_label(ctx);
		if (unlikely(!skip_label))
			return false;
		if (flag_is_set(ctx, slot)) {
			g(gen_set_1(ctx, R_FRAME, slot, 0, false));
			goto move_it;
		}
		if (flag_is_clear(ctx, slot))
			goto do_reference;
		g(gen_test_1(ctx, R_FRAME, slot, 0, skip_label, false, TEST_CLEAR));
do_reference:
		g(gen_upcall_start(ctx, 1));
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
move_it:
		gen_label(skip_label);
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, dest));
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot));
		flag_set(ctx, slot, false);
	}
	return true;
}

static bool attr_w gen_frame_set_pointer(struct codegen_context *ctx, frame_t slot, unsigned src, bool reference, bool not_thunk)
{
	bool escape_on_thunk = !not_thunk && da(ctx->fn,function)->local_variables_flags[slot].must_be_data;
	g(gen_set_1(ctx, R_FRAME, slot, 0, true));
	flag_set_unknown(ctx, slot);
	if (not_thunk)
		ctx->flag_cache[slot] |= FLAG_CACHE_IS_NOT_THUNK;
	flag_set(ctx, slot, true);
	g(gen_frame_store(ctx, OP_SIZE_SLOT, slot, 0, src));
	if (reference) {
		if (escape_on_thunk)
			g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, src));
		g(gen_upcall_start(ctx, 1));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, src));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
		if (escape_on_thunk)
			src = R_SAVED_1;
	}
	if (escape_on_thunk) {
		uint32_t nondata_label = alloc_escape_label_for_ip(ctx, ctx->current_position);
		if (unlikely(!nondata_label))
			return false;
		g(gen_ptr_is_thunk(ctx, src, NO_FRAME_T, nondata_label));
	}
	return true;
}

static bool attr_w gen_frame_set_pointer_2(struct codegen_context *ctx, frame_t slot_r, unsigned src, unsigned flags, uint32_t escape_label)
{
	g(gen_ptr_is_thunk(ctx, src, NO_FRAME_T, escape_label));
	g(gen_barrier(ctx));

	if (flags & OPCODE_STRUCT_MAY_BORROW) {
		g(gen_frame_store(ctx, OP_SIZE_SLOT, slot_r, 0, src));
		flag_set(ctx, slot_r, false);
	} else {
		g(gen_frame_set_pointer(ctx, slot_r, src, true, true));
	}
	return true;
}

static bool attr_w gen_frame_load_slot(struct codegen_context *ctx, frame_t slot, unsigned reg)
{
	g(gen_frame_load(ctx, OP_SIZE_SLOT, native, slot, 0, false, reg));
	return true;
}

static bool attr_w gen_frame_get_slot(struct codegen_context *ctx, frame_t slot, unsigned reg, unsigned *dest)
{
	if (slot_is_register(ctx, slot)) {
		*dest = ctx->registers[slot];
		return true;
	}
	*dest = reg;
	g(gen_frame_load_slot(ctx, slot, reg));
	return true;
}

static bool attr_w gen_frame_decompress_slot(struct codegen_context *ctx, frame_t slot, unsigned reg, unsigned *dest, uint32_t escape_label)
{
	if (slot_is_register(ctx, slot)) {
		unsigned creg = ctx->registers[slot];
		g(gen_ptr_is_thunk(ctx, creg, slot, escape_label));
#if !defined(POINTER_COMPRESSION)
		*dest = creg;
#else
		g(gen_decompress_pointer(ctx, ARCH_PREFERS_SX(OP_SIZE_SLOT), reg, creg, 0));
		*dest = reg;
#endif
		return true;
	}
	g(gen_frame_load(ctx, OP_SIZE_SLOT, native, slot, 0, false, reg));
	g(gen_ptr_is_thunk(ctx, reg, slot, escape_label));
	g(gen_decompress_pointer(ctx, ARCH_PREFERS_SX(OP_SIZE_SLOT), reg, reg, 0));
	*dest = reg;
	return true;
}
