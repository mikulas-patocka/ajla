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

#if defined(POINTER_COMPRESSION)
#define POINTER_THUNK_BIT		0
#elif defined(POINTER_IGNORE_START)
#define POINTER_THUNK_BIT		POINTER_IGNORE_TOP_BIT
#elif defined(POINTER_TAG)
#define POINTER_THUNK_BIT		POINTER_TAG_BIT
#else
unsupported pointer mode
#endif

static bool attr_w gen_compare_ptr_tag(struct codegen_context *ctx, unsigned reg, unsigned tag, unsigned cond, uint32_t label, unsigned tmp_reg, bool subtract, bool need_flags);
static bool attr_w gen_frame_decompress_slot(struct codegen_context *ctx, frame_t slot, unsigned reg, unsigned *dest, uint32_t escape_label);

static bool test_ptr_is_not_thunk(struct codegen_context *ctx, frame_t slot)
{
	if (ctx->flag_cache[slot] & FLAG_CACHE_IS_NOT_THUNK || da(ctx->fn,function)->local_variables_flags[slot].must_be_data)
		return true;
	return false;
}

static bool attr_w gen_ptr_is_thunk(struct codegen_context *ctx, unsigned reg, frame_t slot, uint32_t label)
{
	if (slot != NO_FRAME_T) {
		if (test_ptr_is_not_thunk(ctx, slot))
			return true;
		ctx->flag_cache[slot] |= FLAG_CACHE_IS_NOT_THUNK;
	}
#if defined(ARCH_X86)
	if (POINTER_THUNK_BIT < 8
#if defined(ARCH_X86_32)
		&& reg < 4
#endif
		) {
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_1, reg, (uint64_t)1 << POINTER_THUNK_BIT, COND_NE, label, -1));
	} else
#endif
	{
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_SLOT, reg, (uint64_t)1 << POINTER_THUNK_BIT, COND_NE, label, -1));
	}
	return true;
}

static bool attr_w gen_test_multiple_thunks(struct codegen_context *ctx, frame_t *variables, size_t n_variables, uint32_t label)
{
#if !defined(ARCH_M68K)
	if (n_variables >= 2 && slot_is_register(ctx, variables[0]) && slot_is_register(ctx, variables[1])) {
		g(gen_3address_alu(ctx, i_size(OP_SIZE_SLOT), ALU_OR, R_SCRATCH_1, ctx->registers[variables[0]], ctx->registers[variables[1]], 0));
		variables += 2;
		n_variables -= 2;
		while (n_variables && slot_is_register(ctx, variables[0])) {
			g(gen_3address_alu(ctx, i_size(OP_SIZE_SLOT), ALU_OR, R_SCRATCH_1, R_SCRATCH_1, ctx->registers[variables[0]], 0));
			variables++;
			n_variables--;
		}
#if defined(ARCH_X86) || defined(ARCH_S390)
		goto test_load_op;
#else
		g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, NO_FRAME_T, label));
#endif
	}
#endif
#if defined(ARCH_X86) || defined(ARCH_S390)
	if (n_variables >= 2) {
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, variables[0], 0, false, R_SCRATCH_1));
		variables++;
		n_variables--;
test_load_op:
		while (n_variables) {
			g(gen_frame_load_op(ctx, OP_SIZE_SLOT, garbage, ALU_OR, 0, variables[0], 0, false, R_SCRATCH_1));
			variables++;
			n_variables--;
		}
		g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, NO_FRAME_T, label));
		return true;
	}
#endif
	while (n_variables) {
		unsigned reg;
		g(gen_frame_get(ctx, OP_SIZE_SLOT, garbage, variables[0], R_SCRATCH_1, &reg));
		g(gen_ptr_is_thunk(ctx, reg, NO_FRAME_T, label));
		variables++;
		n_variables--;
	}
	return true;
}

static bool attr_w gen_unspill_variables(struct codegen_context *ctx, frame_t *variables, size_t n_variables)
{
	size_t i;
	size_t n_vars = 0;

	for (i = 0; i < n_variables; i++) {
		frame_t v = variables[i];
		if (slot_is_register(ctx, v) && !reg_is_x87(ctx->registers[v]))
			ctx->var_aux[n_vars++] = v;
	}

	g(gen_unspill_multiple(ctx, ctx->var_aux, n_vars, false));

	return true;
}

static bool attr_w gen_test_variable_tags(struct codegen_context *ctx, frame_t *variables, size_t n_variables, uint32_t label)
{
	size_t n_vars = 0;
	size_t n;
	for (n = 0; n < n_variables; n++) {
		frame_t v = variables[n];
		if (da(ctx->fn,function)->local_variables_flags[v].must_be_flat)
			ctx->var_aux[n_vars++] = v;
	}
	g(gen_test_multiple(ctx, ctx->var_aux, n_vars, label));
	return true;
}

static bool attr_w gen_test_variable_content(struct codegen_context *ctx, frame_t *variables, size_t n_variables, bool test_flag_on_thunks, uint32_t label)
{
	unsigned i;

	for (i = 0; i < 2; i++) {
		size_t n_vars = 0;
		size_t n;
		for (n = 0; n < n_variables; n++) {
			frame_t v = variables[n];
			if (i == 0 ? da(ctx->fn,function)->local_variables_flags[v].must_be_data :
			     da(ctx->fn,function)->local_variables_flags[v].must_be_data >= 2)
				ctx->var_aux[n_vars++] = v;
		}
		if (i == 0) {
			if (!test_flag_on_thunks) {
				g(gen_test_multiple_thunks(ctx, ctx->var_aux, n_vars, label));
			} else {
				size_t j;
				for (j = 0; j < n_vars; j++) {
					frame_t v = ctx->var_aux[j];
					unsigned reg;
					uint32_t skip_label;
					skip_label = alloc_label(ctx);
					if (unlikely(!skip_label))
						return false;
					g(gen_test_1(ctx, R_FRAME, v, 0, skip_label, true, TEST));
					g(gen_frame_get(ctx, OP_SIZE_SLOT, garbage, v, R_SCRATCH_1, &reg));
					g(gen_ptr_is_thunk(ctx, reg, NO_FRAME_T, label));
					gen_label(skip_label);
				}
			}
		} else {
			size_t j;
			for (j = 0; j < n_vars; j++) {
				frame_t v = ctx->var_aux[j];
				unsigned reg;
				uint32_t skip_label = 0;	/* avoid warning */
				bool is_arg = da(ctx->fn,function)->local_variables_flags[v].is_argument;
				if (is_arg) {
					skip_label = alloc_label(ctx);
					if (unlikely(!skip_label))
						return false;
				}
				g(gen_frame_decompress_slot(ctx, v, R_SCRATCH_1, &reg, 0));
				if (is_arg)
					g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_ADDRESS, reg, reg, COND_E, skip_label));
				g(gen_compare_ptr_tag(ctx, reg, DATA_TAG_array_flat, COND_NE, label, R_SCRATCH_2, false, false));
				if (is_arg)
					gen_label(skip_label);
			}
		}
	}

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
#if defined(ARCH_M68K) || defined(ARCH_X86)
	bool logical = COND_IS_LOGICAL(cond);
	g(gen_address(ctx, ptr, offsetof(struct data, refcount_), IMM_PURPOSE_LDR_OFFSET, op_size));
	g(gen_imm(ctx, val, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1 + logical);
	gen_address_offset();
	gen_imm_offset();

	gen_insn(!logical ? INSN_JMP_COND : INSN_JMP_COND_LOGICAL, op_size, cond, 0);
	gen_label_ref(label);
#else
	g(gen_address(ctx, ptr, offsetof(struct data, refcount_), IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(INSN_MOV, op_size, 0, MOV_WRITES_FLAGS(R_SCRATCH_NA_1, ARG_ADDRESS_1));
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	if (val == 0 && (cond == COND_E || cond == COND_NE)) {
		g(gen_jmp_on_zero(ctx, op_size, R_SCRATCH_NA_1, cond, label));
	} else if (val == 1 && cond == COND_AE) {
		g(gen_jmp_on_zero(ctx, op_size, R_SCRATCH_NA_1, COND_NE, label));
	} else {
		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_NA_1, val, cond, label, -1));
	}
#endif
	return true;
}

static bool attr_w gen_compare_ptr_tag(struct codegen_context *ctx, unsigned reg, unsigned tag, unsigned cond, uint32_t label, unsigned tmp_reg, bool subtract, bool need_flags)
{
	size_t attr_unused offset;
	unsigned attr_unused op_size = log_2(sizeof(tag_t));
	if (subtract
#if defined(ARCH_S390)
		|| 1
#endif
		)
		switch (cond) {
			case COND_A:	cond = COND_G; break;
			case COND_AE:	cond = COND_GE; break;
			case COND_B:	cond = COND_L; break;
			case COND_BE:	cond = COND_LE; break;
		}
#if defined(DATA_TAG_AT_ALLOC)
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHR, tmp_reg, reg, POINTER_IGNORE_START, 0));
#elif defined(REFCOUNT_TAG)
	offset = offsetof(struct data, refcount_);
#if defined(C_BIG_ENDIAN)
	offset += sizeof(refcount_int_t) - 1;
#endif
#if defined(ARCH_X86) && REFCOUNT_STEP == 256
	if (!subtract) {
		g(gen_imm(ctx, tag, IMM_PURPOSE_CMP, OP_SIZE_4));
		gen_insn(INSN_CMP, OP_SIZE_1, 0, 1);
		gen_one(ARG_ADDRESS_1);
		gen_one(reg);
		gen_eight(offset);
		gen_imm_offset();

		gen_insn(INSN_JMP_COND, OP_SIZE_1, cond, 0);
		gen_label_ref(label);
		return true;
	}
#endif
	if (ARCH_HAS_BWX && REFCOUNT_STEP == 256
#if defined(ARCH_S390)
		&& cpu_test_feature(CPU_FEATURE_extended_imm)
#endif
	    ) {
		g(gen_address(ctx, reg, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, MOV_WRITES_FLAGS(tmp_reg, ARG_ADDRESS_1));
		gen_one(tmp_reg);
		gen_address_offset();
	} else {
		g(gen_address(ctx, reg, offsetof(struct data, refcount_), IMM_PURPOSE_LDR_OFFSET, log_2(sizeof(refcount_int_t))));
		gen_insn(INSN_MOV, log_2(sizeof(refcount_int_t)), 0, MOV_WRITES_FLAGS(tmp_reg, ARG_ADDRESS_1));
		gen_one(tmp_reg);
		gen_address_offset();

		g(gen_3address_alu_imm(ctx, log_2(sizeof(refcount_int_t)), ALU_AND, tmp_reg, tmp_reg, REFCOUNT_STEP - 1, 0));
	}
#else
#if defined(ARCH_M68K) || defined(ARCH_X86)
	g(gen_address(ctx, reg, offsetof(struct data, tag), IMM_PURPOSE_MVI_CLI_OFFSET, op_size));
	g(gen_imm(ctx, tag, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1);
	gen_address_offset();
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, op_size, cond, 0);
	gen_label_ref(label);

	return true;
#endif
	g(gen_load_raw(ctx, op_size, i_size_cmp(op_size) == op_size ? garbage : native, reg, 0, offsetof(struct data, tag), false, tmp_reg));
#endif
	if (!subtract && !need_flags && !tag && (cond == COND_E || cond == COND_NE)) {
		g(gen_jmp_on_zero(ctx, i_size_cmp(op_size), tmp_reg, cond, label));
	} else if (!subtract) {
		g(gen_cmp_test_imm_jmp_q_flags(ctx, INSN_CMP, i_size_cmp(op_size), tmp_reg, tag, cond, label, -1, need_flags));
	} else {
		g(gen_3address_alu_imm(ctx, i_size_cmp(op_size), ALU_SUB, tmp_reg, tmp_reg, tag, 0));
		g(gen_jmp_on_zero(ctx, i_size_cmp(op_size), tmp_reg, cond, label));
	}
	return true;
}

static bool attr_w gen_compare_da_tag(struct codegen_context *ctx, unsigned reg, unsigned tag, unsigned cond, uint32_t label, unsigned tmp_reg)
{
#if defined(POINTER_COMPRESSION)
#if defined(ARCH_X86) && POINTER_COMPRESSION <= 3 && defined(REFCOUNT_TAG) && REFCOUNT_STEP == 256 && defined(C_LITTLE_ENDIAN)
	g(gen_imm(ctx, tag, IMM_PURPOSE_CMP, log_2(sizeof(tag_t))));
	gen_insn(INSN_CMP, log_2(sizeof(tag_t)), 0, 0);
	gen_one(ARG_ADDRESS_1 + POINTER_COMPRESSION);
	gen_one(reg);
	gen_eight(offsetof(struct data, refcount_));
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_4, cond, 0);
	gen_label_ref(label);

	return true;
#endif
	if (ARCH_PREFERS_SX(OP_SIZE_4)) {
		g(gen_extend(ctx, OP_SIZE_4, zero_x, tmp_reg, reg));

		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, tmp_reg, tmp_reg, POINTER_COMPRESSION, 0));
	} else {
		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, tmp_reg, reg, POINTER_COMPRESSION, 0));
	}
	g(gen_compare_ptr_tag(ctx, tmp_reg, tag, cond, label, tmp_reg, false, false));
	return true;
#endif
	g(gen_compare_ptr_tag(ctx, reg, tag, cond, label, tmp_reg, false, false));
	return true;
}

static bool attr_w gen_compare_tag_and_refcount(struct codegen_context *ctx, unsigned reg, unsigned tag, uint32_t label, unsigned attr_unused tmp_reg)
{
#if defined(REFCOUNT_TAG)
	g(gen_compare_refcount(ctx, reg, tag, COND_NE, label));
#else
	g(gen_compare_ptr_tag(ctx, reg, tag, COND_NE, label, tmp_reg, false, false));
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
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, dest, src, POINTER_COMPRESSION, 0));
	src = dest;
#endif
	if (offset) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, dest, src, offset, 0));
	} else {
		g(gen_mov(ctx, OP_SIZE_NATIVE, dest, src));
	}
	return true;
}

static bool attr_w gen_compress_pointer(struct codegen_context attr_unused *ctx, unsigned dest, unsigned src)
{
#ifdef POINTER_COMPRESSION
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHR, dest, src, POINTER_COMPRESSION, 0));
#else
	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), dest, src));
#endif
	return true;
}

static bool attr_w gen_frame_get_pointer(struct codegen_context *ctx, frame_t slot, bool deref, unsigned dest)
{
	if (!deref) {
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
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
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
move_it:
		gen_label(skip_label);
		g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot, 0, false, dest));
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot));
		flag_set(ctx, slot, false);
	}
	return true;
}

static bool attr_w gen_test_tag(struct codegen_context *ctx, frame_t slot, unsigned reg, uint32_t label)
{
	if (unlikely(reg == R_SCRATCH_3) || unlikely(reg == R_SCRATCH_4))
		internal(file_line, "gen_test_tag: conflicting register %u", reg);
	if (da(ctx->fn,function)->local_variables_flags[slot].must_be_data >= 2) {
		unsigned reg2;
#ifdef POINTER_COMPRESSION
		g(gen_decompress_pointer(ctx, ARCH_PREFERS_SX(OP_SIZE_SLOT), R_SCRATCH_3, reg, 0));
		reg2 = R_SCRATCH_3;
#else
		reg2 = reg;
#endif
		g(gen_compare_ptr_tag(ctx, reg2, DATA_TAG_array_flat, COND_NE, label, R_SCRATCH_4, false, false));
	}
	return true;
}

static bool attr_w gen_frame_set_pointer(struct codegen_context *ctx, frame_t slot, unsigned src, bool reference, bool not_thunk)
{
	bool escape_on_thunk = !not_thunk && da(ctx->fn,function)->local_variables_flags[slot].must_be_data;
	bool escape_on_tag = da(ctx->fn,function)->local_variables_flags[slot].must_be_data >= 2;
	g(gen_set_1(ctx, R_FRAME, slot, 0, true));
	flag_set_unknown(ctx, slot);
	if (not_thunk)
		ctx->flag_cache[slot] |= FLAG_CACHE_IS_NOT_THUNK;
	flag_set(ctx, slot, true);
	g(gen_frame_store(ctx, OP_SIZE_SLOT, slot, 0, src));
	if (reference) {
		if (escape_on_thunk || escape_on_tag)
			g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, src));
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, src));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		if (escape_on_thunk || escape_on_tag)
			src = R_SAVED_1;
	}
	if (escape_on_thunk || escape_on_tag) {
		uint32_t nondata_label = alloc_escape_label_for_ip(ctx, ctx->current_position, CG_EXIT_FLAG_NONFLAT);
		if (unlikely(!nondata_label))
			return false;
		if (escape_on_thunk)
			g(gen_ptr_is_thunk(ctx, src, NO_FRAME_T, nondata_label));
		if (escape_on_tag)
			g(gen_test_tag(ctx, slot, src, nondata_label));
	}
	return true;
}

static bool attr_w gen_frame_set_pointer_2(struct codegen_context *ctx, frame_t slot, unsigned src, unsigned flags, uint32_t escape_label)
{
	g(gen_ptr_is_thunk(ctx, src, NO_FRAME_T, escape_label));
	g(gen_barrier(ctx));
	if (flags & OPCODE_STRUCT_MAY_BORROW) {
		g(gen_test_tag(ctx, slot, src, escape_label));
		g(gen_frame_store(ctx, OP_SIZE_SLOT, slot, 0, src));
		flag_set(ctx, slot, false);
	} else {
		g(gen_frame_set_pointer(ctx, slot, src, true, true));
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
		if (escape_label)
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
	if (escape_label)
		g(gen_ptr_is_thunk(ctx, reg, slot, escape_label));
	g(gen_decompress_pointer(ctx, ARCH_PREFERS_SX(OP_SIZE_SLOT), reg, reg, 0));
	*dest = reg;
	return true;
}
