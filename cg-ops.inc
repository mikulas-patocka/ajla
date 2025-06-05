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

static bool attr_w gen_flat_move_copy(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_1, escape_label));

	g(gen_memcpy_slots(ctx, slot_r, slot_1));

	flag_set(ctx, slot_1, false);
	flag_set(ctx, slot_r, false);

	return false;
}

static bool attr_w gen_ref_move_copy(struct codegen_context *ctx, code_t code, frame_t slot_1, frame_t slot_r)
{
	unsigned reg;
	if (flag_must_be_flat(ctx, slot_r)) {
		uint32_t escape_label = alloc_escape_label(ctx);
		if (unlikely(!escape_label))
			return false;
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}
	g(gen_frame_get_slot(ctx, slot_1, R_SCRATCH_1, &reg));
	if (!da(ctx->fn,function)->local_variables_flags[slot_1].must_be_data &&
	     da(ctx->fn,function)->local_variables_flags[slot_r].must_be_data) {
		uint32_t escape_label = alloc_escape_label(ctx);
		if (unlikely(!escape_label))
			return false;
		g(gen_ptr_is_thunk(ctx, reg, slot_1, escape_label));
		ctx->flag_cache[slot_r] |= FLAG_CACHE_IS_NOT_THUNK;
	}
	g(gen_frame_store(ctx, OP_SIZE_SLOT, slot_r, 0, reg));
	g(gen_set_1(ctx, R_FRAME, slot_r, 0, true));
	flag_set(ctx, slot_r, true);
	if (code == OPCODE_REF_COPY) {
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, reg));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
	} else if (code == OPCODE_REF_MOVE && !da(ctx->fn,function)->local_variables_flags[slot_1].may_be_borrowed) {
		g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
		flag_set(ctx, slot_1, false);
	} else {
		uint32_t label_id;
		if (unlikely(!(label_id = alloc_label(ctx))))
			return false;
		if (flag_is_set(ctx, slot_1)) {
			g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
			goto move_it;
		}
		if (flag_is_clear(ctx, slot_1))
			goto do_reference;
		g(gen_test_1(ctx, R_FRAME, slot_1, 0, label_id, false, TEST_CLEAR));
do_reference:
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, reg));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
move_it:
		gen_label(label_id);
		if (code == OPCODE_REF_MOVE_CLEAR)
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
		flag_set(ctx, slot_1, false);
	}
	return true;
}

static bool attr_w gen_box_move_copy(struct codegen_context *ctx, code_t code, frame_t slot_1, frame_t slot_r)
{
	if (flag_must_be_flat(ctx, slot_r)) {
		uint32_t escape_label = alloc_escape_label(ctx);
		if (unlikely(!escape_label))
			return false;
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	if (slot_is_register(ctx, slot_1))
		g(spill(ctx, slot_1));

	if (code != OPCODE_BOX_MOVE_CLEAR) {
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_copy_variable_to_pointer_noderef), 2, true));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, slot_1));
		g(gen_upcall_argument(ctx, 1));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_copy_variable_to_pointer_noderef), 2, true));
	} else {
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_copy_variable_to_pointer_deref), 2, true));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, slot_1));
		g(gen_upcall_argument(ctx, 1));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_copy_variable_to_pointer_deref), 2, true));

		flag_set(ctx, slot_1, false);
	}

	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, false));

	return true;
}

static bool attr_w gen_eval(struct codegen_context *ctx, frame_t slot_1)
{
	uint32_t escape_label, skip_label;
	unsigned reg;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	skip_label = alloc_label(ctx);
	if (unlikely(!skip_label))
		return false;

	g(gen_test_1_jz_cached(ctx, slot_1, skip_label));

	g(gen_frame_get_slot(ctx, slot_1, R_SCRATCH_1, &reg));
	g(gen_ptr_is_thunk(ctx, reg, slot_1, escape_label));

	gen_label(skip_label);

	return true;
}

static bool attr_w gen_jump(struct codegen_context *ctx, int32_t jmp_offset, unsigned op_size, unsigned cond, unsigned reg1, unsigned reg2)
{
	ip_t ip = (ctx->current_position - da(ctx->fn,function)->code) + (jmp_offset / (int)sizeof(code_t));
	if (likely(!ctx->code_labels[ip])) {
		ctx->code_labels[ip] = alloc_label(ctx);
		if (unlikely(!ctx->code_labels[ip]))
			return false;
	}
	if (reg1 != -1U && reg2 != -1U) {
		g(gen_cmp_test_jmp(ctx, INSN_CMP, i_size_cmp(op_size), reg1, reg2, cond, ctx->code_labels[ip]));
#if defined(ARCH_IA64)
	} else if (reg_is_p(reg1)) {
		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond, 0);
		gen_one(reg1);
		gen_four(ctx->code_labels[ip]);
#endif
	} else if (reg1 != -1U) {
		g(gen_jmp_on_zero(ctx, op_size, reg1, cond, ctx->code_labels[ip]));
	} else if (cond == COND_ALWAYS) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(ctx->code_labels[ip]);
#if defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC)
	} else if (cond & COND_FP) {
		gen_insn(INSN_JMP_FP_TEST, 0, cond, 0);
		gen_four(ctx->code_labels[ip]);
#endif
	} else {
		gen_insn(COND_IS_LOGICAL(cond) ? INSN_JMP_COND_LOGICAL : INSN_JMP_COND, i_size_cmp(op_size), cond, 0);
		gen_four(ctx->code_labels[ip]);
	}
	return true;
}

static bool attr_w gen_cond_jump(struct codegen_context *ctx, frame_t slot, int32_t jmp_offset)
{
	unsigned size = log_2(sizeof(ajla_flat_option_t));
	size_t attr_unused offset;
	unsigned reg1;
	if (slot_is_register(ctx, slot)) {
		goto no_load_op;
	}
#if defined(ARCH_S390) || defined(ARCH_X86)
	offset = (size_t)slot * slot_size;
#if defined(ARCH_S390)
	if (size != OP_SIZE_1)
		goto no_load_op;
#endif
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_MVI_CLI_OFFSET, size));
	gen_insn(INSN_CMP, size, 0, 2);
	gen_address_offset();
	gen_one(ARG_IMM);
	gen_eight(0);

	g(gen_jump(ctx, jmp_offset, size, COND_E, -1U, -1U));
	return true;
#endif
	goto no_load_op;
no_load_op:
	g(gen_frame_get(ctx, size, i_size(size) == size ? garbage : native, slot, R_SCRATCH_1, &reg1));
	g(gen_jump(ctx, jmp_offset, size, COND_E, reg1, -1U));
	return true;
}

static bool attr_w gen_load_fn_or_curry(struct codegen_context *ctx, frame_t fn_idx, frame_t slot_fn, frame_t slot_r, unsigned flags)
{
	bool curry = fn_idx == NO_FRAME_T;
	uint32_t escape_label;
	arg_t i;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_function_reference_mayfail), 1, true));

	g(gen_load_constant(ctx, R_ARG0, ctx->args_l));
	g(gen_upcall_argument(ctx, 0));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_function_reference_mayfail), 1, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, R_RET0));

	if (!curry) {
		g(load_function_offset(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.local_directory[fn_idx])));

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.u.direct), IMM_PURPOSE_STR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_1);

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.is_indirect), IMM_PURPOSE_STR_OFFSET, log_2(sizeof(bool))));
		g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(uchar_efficient_t))));
		gen_insn(INSN_MOV, log_2(sizeof(uchar_efficient_t)), 0, 0);
		gen_address_offset();
		gen_imm_offset();
	} else {
		g(gen_frame_get_pointer(ctx, slot_fn, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_SCRATCH_1));

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.u.indirect), IMM_PURPOSE_STR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_1);

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.is_indirect), IMM_PURPOSE_STR_OFFSET, log_2(sizeof(bool))));
		g(gen_imm(ctx, 1, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(uchar_efficient_t))));
		gen_insn(INSN_MOV, log_2(sizeof(uchar_efficient_t)), 0, 0);
		gen_address_offset();
		gen_imm_offset();
	}

	for (i = 0; i < ctx->args_l; i++) {
		uintptr_t arg_offset_tag = offsetof(struct data, u_.function_reference.arguments[i].tag);
		uintptr_t arg_offset_ptr = offsetof(struct data, u_.function_reference.arguments[i].u.ptr);
		uintptr_t arg_offset_slot = offsetof(struct data, u_.function_reference.arguments[i].u.slot);
		frame_t arg_slot = ctx->args[i].slot;
		const struct type *t = get_type_of_local(ctx, arg_slot);
		uint32_t skip_flat_label, set_ptr_label, next_arg_label;
		skip_flat_label = alloc_label(ctx);
		if (unlikely(!skip_flat_label))
			return false;
		set_ptr_label = alloc_label(ctx);
		if (unlikely(!set_ptr_label))
			return false;
		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;
		if (TYPE_IS_FLAT(t)) {
			g(gen_test_1_cached(ctx, arg_slot, skip_flat_label));
			if (t->size <= slot_size && TYPE_TAG_IS_BUILTIN(t->tag)) {
				unsigned copy_size = OP_SIZE_SLOT;
				if (is_power_of_2(t->size))
					copy_size = log_2(t->size);
				if (!ARCH_HAS_BWX)
					copy_size = maximum(copy_size, OP_SIZE_4);
				g(gen_address(ctx, R_SAVED_1, arg_offset_tag, IMM_PURPOSE_STR_OFFSET, log_2(sizeof(type_tag_t))));
				g(gen_imm(ctx, t->tag, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(type_tag_t))));
				gen_insn(INSN_MOV, log_2(sizeof(type_tag_t)), 0, 0);
				gen_address_offset();
				gen_imm_offset();

				if (slot_is_register(ctx, arg_slot)) {
					g(gen_address(ctx, R_SAVED_1, arg_offset_slot, IMM_PURPOSE_STR_OFFSET, copy_size));
					gen_insn(INSN_MOV, spill_size(t), 0, 0);
					gen_address_offset();
					gen_one(ctx->registers[arg_slot]);
					goto copied;
				}
#if defined(ARCH_S390)
				if (copy_size == OP_SIZE_1 && !cpu_test_feature(CPU_FEATURE_long_displacement)) {
					g(gen_address(ctx, R_FRAME, (size_t)arg_slot * slot_size, IMM_PURPOSE_LDR_OFFSET, copy_size));
					gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_0_8, 0);
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_1);
					gen_address_offset();
				} else
#endif
				{
					g(gen_address(ctx, R_FRAME, (size_t)arg_slot * slot_size, ARCH_PREFERS_SX(copy_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, copy_size));
					gen_insn(ARCH_PREFERS_SX(copy_size) ? INSN_MOVSX : INSN_MOV, copy_size, 0, 0);
					gen_one(R_SCRATCH_1);
					gen_address_offset();
				}

				g(gen_address(ctx, R_SAVED_1, arg_offset_slot, IMM_PURPOSE_STR_OFFSET, copy_size));
				gen_insn(INSN_MOV, copy_size, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_1);
copied:
				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(next_arg_label);
			} else {
				if (slot_is_register(ctx, arg_slot))
					g(spill(ctx, arg_slot));

				g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

				g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
				g(gen_upcall_argument(ctx, 0));

				g(gen_load_constant(ctx, R_ARG1, arg_slot));
				g(gen_upcall_argument(ctx, 1));

				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(set_ptr_label);
			}
		}

		gen_label(skip_flat_label);
		g(gen_frame_get_pointer(ctx, arg_slot, (ctx->args[i].flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_RET0));

		gen_label(set_ptr_label);
		g(gen_address(ctx, R_SAVED_1, arg_offset_tag, IMM_PURPOSE_STR_OFFSET, log_2(sizeof(type_tag_t))));
		g(gen_imm(ctx, TYPE_TAG_unknown, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(type_tag_t))));
		gen_insn(INSN_MOV, log_2(sizeof(type_tag_t)), 0, 0);
		gen_address_offset();
		gen_imm_offset();

		g(gen_address(ctx, R_SAVED_1, arg_offset_ptr, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_address_offset();
		gen_one(R_RET0);

		gen_label(next_arg_label);
	}

	g(gen_compress_pointer(ctx, R_SAVED_1, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1, false, true));

	return true;
}

static bool attr_w gen_call(struct codegen_context *ctx, code_t code, frame_t fn_idx)
{
	struct data *new_fn = ctx->local_directory[fn_idx];
	frame_t required_slots = da(new_fn,function)->frame_slots;
	frame_t bitmap_slots = da(new_fn,function)->n_bitmap_slots;
	uint32_t escape_label;
	int64_t new_fp_offset;
	uchar_efficient_t call_mode;
	arg_t i;
	bool arch_use_flags = ARCH_HAS_FLAGS;
#if defined(ARCH_POWER)
	arch_use_flags = false;
#endif

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_spill_all(ctx));

	g(gen_frame_load_raw(ctx, log_2(sizeof(stack_size_t)), native, 0, frame_offs(available_slots), false, R_SCRATCH_1));
	g(gen_imm(ctx, required_slots, IMM_PURPOSE_SUB, i_size(log_2(sizeof(stack_size_t)))));
	gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(i_size(log_2(sizeof(stack_size_t)))), i_size(log_2(sizeof(stack_size_t))), ALU_SUB, arch_use_flags);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_1);
	gen_imm_offset();

	if (arch_use_flags) {
		gen_insn(COND_IS_LOGICAL(COND_B) ? INSN_JMP_COND_LOGICAL : INSN_JMP_COND, log_2(sizeof(stack_size_t)), COND_B, 0);
		gen_four(escape_label);
	} else {
		g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_1, COND_S, escape_label));
	}

	new_fp_offset = -(ssize_t)(required_slots * slot_size);

	g(gen_frame_store_raw(ctx, log_2(sizeof(stack_size_t)), 0, new_fp_offset + frame_offs(available_slots), R_SCRATCH_1));
	g(gen_frame_store_imm_raw(ctx, log_2(sizeof(ip_t)), 0, new_fp_offset + frame_offs(previous_ip), ctx->return_values - da(ctx->fn,function)->code));
	g(gen_frame_load_raw(ctx, log_2(sizeof(timestamp_t)), garbage, 0, frame_offs(timestamp), false, R_SCRATCH_1));
	g(gen_frame_store_raw(ctx, log_2(sizeof(timestamp_t)), 0, new_fp_offset + frame_offs(timestamp), R_SCRATCH_1));
	call_mode = code == OPCODE_CALL ? CALL_MODE_NORMAL : code == OPCODE_CALL_STRICT ? CALL_MODE_STRICT : CALL_MODE_SPARK;
	g(gen_frame_store_imm_raw(ctx, log_2(sizeof(uchar_efficient_t)), 0, new_fp_offset + frame_offs(mode), call_mode));

	g(gen_clear_bitmap(ctx, frame_offset, R_FRAME, new_fp_offset, bitmap_slots));

	for (i = 0; i < ctx->args_l; i++) {
		const struct code_arg *src_arg = &ctx->args[i];
		const struct local_arg *dest_arg = &da(new_fn,function)->args[i];
		const struct type *t = get_type_of_local(ctx, src_arg->slot);
		uint32_t non_flat_label, thunk_label, incr_ref_label, next_arg_label;
		unsigned reg;
		non_flat_label = alloc_label(ctx);
		if (unlikely(!non_flat_label))
			return false;
		thunk_label = alloc_label(ctx);
		if (unlikely(!thunk_label))
			return false;
		incr_ref_label = alloc_label(ctx);
		if (unlikely(!incr_ref_label))
			return false;
		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;
		if (TYPE_IS_FLAT(t)) {
			g(gen_test_1_cached(ctx, src_arg->slot, non_flat_label));
			if (dest_arg->may_be_flat) {
				const struct type *t = get_type_of_local(ctx, src_arg->slot);
				g(gen_memcpy_raw(ctx, R_FRAME, new_fp_offset + (size_t)dest_arg->slot * slot_size, R_FRAME, (size_t)src_arg->slot * slot_size, t->size, t->align));
			} else {
				g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, false));

				g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
				g(gen_upcall_argument(ctx, 0));

				g(gen_load_constant(ctx, R_ARG1, src_arg->slot));
				g(gen_upcall_argument(ctx, 1));

				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, false));

				g(gen_frame_store_raw(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, R_RET0));

				g(gen_set_1(ctx, R_FRAME, dest_arg->slot, new_fp_offset, true));
			}

			if (flag_is_clear(ctx, src_arg->slot))
				goto skip_ref_argument;

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		}
		gen_label(non_flat_label);

		if (dest_arg->may_be_borrowed && src_arg->flags & OPCODE_CALL_MAY_LEND) {
			bool bypass = test_ptr_is_not_thunk(ctx, src_arg->slot);
			if (slot_is_register(ctx, src_arg->slot) && reg_is_saved(ctx->registers[src_arg->slot])) {
				reg = ctx->registers[src_arg->slot];
			} else {
				g(gen_frame_load_raw(ctx, OP_SIZE_SLOT, native, src_arg->slot, 0, false, R_SCRATCH_1));
				reg = R_SCRATCH_1;
			}
			g(gen_ptr_is_thunk(ctx, reg, src_arg->slot, thunk_label));
			g(gen_frame_store_raw(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, reg));
			if (bypass) {
				goto skip_ref_argument;
			}
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		} else if (dest_arg->may_be_borrowed && src_arg->flags & OPCODE_CALL_MAY_GIVE) {
			bool bypass = flag_is_clear(ctx, src_arg->slot) && test_ptr_is_not_thunk(ctx, src_arg->slot);
			g(gen_test_1_cached(ctx, src_arg->slot, thunk_label));
			if (slot_is_register(ctx, src_arg->slot) && reg_is_saved(ctx->registers[src_arg->slot])) {
				reg = ctx->registers[src_arg->slot];
			} else {
				g(gen_frame_load_raw(ctx, OP_SIZE_SLOT, native, src_arg->slot, 0, false, R_SCRATCH_1));
				reg = R_SCRATCH_1;
			}
			g(gen_ptr_is_thunk(ctx, reg, src_arg->slot, thunk_label));
			g(gen_frame_store_raw(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, reg));
			g(gen_frame_clear_raw(ctx, OP_SIZE_SLOT, src_arg->slot));
			if (bypass) {
				goto skip_ref_argument;
			}
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		}

		gen_label(thunk_label);
		g(gen_set_1(ctx, R_FRAME, dest_arg->slot, new_fp_offset, true));
		if (slot_is_register(ctx, src_arg->slot) && reg_is_saved(ctx->registers[src_arg->slot])) {
			reg = ctx->registers[src_arg->slot];
		} else {
			g(gen_frame_load_raw(ctx, OP_SIZE_SLOT, native, src_arg->slot, 0, false, R_SCRATCH_1));
			reg = R_SCRATCH_1;
		}
		g(gen_frame_store_raw(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, reg));
		if (src_arg->flags & OPCODE_FLAG_FREE_ARGUMENT) {
			g(gen_frame_clear_raw(ctx, OP_SIZE_SLOT, src_arg->slot));
			if (flag_is_set(ctx, src_arg->slot)) {
				g(gen_set_1(ctx, R_FRAME, src_arg->slot, 0, false));
				flag_set(ctx, src_arg->slot, false);
				goto skip_ref_argument;
			}
			if (flag_is_clear(ctx, src_arg->slot))
				goto do_reference;
			g(gen_test_1(ctx, R_FRAME, src_arg->slot, 0, incr_ref_label, true, TEST_CLEAR));
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		}
do_reference:
		gen_label(incr_ref_label);

		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, false));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, reg));
		g(gen_upcall_argument(ctx, 0));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, false));

skip_ref_argument:
		gen_label(next_arg_label);
	}

	g(load_function_offset(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.local_directory[fn_idx])));

	g(gen_address(ctx, R_SCRATCH_1, 0, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_decompress_pointer(ctx, ARCH_PREFERS_SX(OP_SIZE_SLOT), R_SCRATCH_1, R_SCRATCH_1, 0));

	g(gen_frame_store_raw(ctx, OP_SIZE_ADDRESS, 0, frame_offs(function) + new_fp_offset, R_SCRATCH_1));

#if !defined(ARCH_X86) && !defined(ARCH_PARISC)
	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_SUB, R_FRAME, R_FRAME, -new_fp_offset, 0));
#else
	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_FRAME, R_FRAME, new_fp_offset, 0));
#endif

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.codegen), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, NO_FRAME_T, ctx->escape_nospill_label));
	g(gen_barrier(ctx));

	gen_pointer_compression(R_SCRATCH_1);
#if (defined(ARCH_X86) && !defined(ARCH_X86_X32)) || defined(ARCH_ARM32)
	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code_base), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_address_offset_compressed();
#else
	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code_base), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset_compressed();

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_SCRATCH_1);
#endif
	g(clear_flag_cache(ctx));

	return true;
}

static bool attr_w gen_return(struct codegen_context *ctx)
{
	int64_t new_fp_offset;
	uint32_t escape_label;
	arg_t i;
	int64_t retval_offset;
	unsigned attr_unused reg1;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	new_fp_offset = (size_t)da(ctx->fn,function)->frame_slots * slot_size;

	g(gen_frame_load_raw(ctx, OP_SIZE_ADDRESS, zero_x, 0, new_fp_offset + frame_offs(function), false, R_SCRATCH_2));

	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_SCRATCH_2, COND_E, escape_label));

	g(gen_address(ctx, R_SCRATCH_2, offsetof(struct data, u_.function.codegen), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, NO_FRAME_T, escape_label));
	g(gen_barrier(ctx));

	g(gen_frame_load_raw(ctx, log_2(sizeof(timestamp_t)), garbage, 0, frame_offs(timestamp), false, R_SCRATCH_1));
	g(gen_frame_store_raw(ctx, log_2(sizeof(timestamp_t)), 0, new_fp_offset + frame_offs(timestamp), R_SCRATCH_1));

	g(gen_frame_load_raw(ctx, log_2(sizeof(ip_t)), native, 0, frame_offs(previous_ip), false, R_SCRATCH_1));

	g(gen_address(ctx, R_SCRATCH_2, offsetof(struct data, u_.function.code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_lea3(ctx, R_SAVED_1, R_SCRATCH_2, R_SCRATCH_1, log_2(sizeof(code_t)), 0));

	retval_offset = 0;
	for (i = 0; i < ctx->args_l; i++) {
		const struct code_arg *src_arg = &ctx->args[i];
		const struct type *t = get_type_of_local(ctx, src_arg->slot);
		uint32_t copy_ptr_label, load_write_ptr_label, write_ptr_label, next_arg_label;

		copy_ptr_label = alloc_label(ctx);
		if (unlikely(!copy_ptr_label))
			return false;

		load_write_ptr_label = alloc_label(ctx);
		if (unlikely(!load_write_ptr_label))
			return false;

		write_ptr_label = alloc_label(ctx);
		if (unlikely(!write_ptr_label))
			return false;

		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;

		g(gen_load_code_32(ctx, R_SAVED_2, R_SAVED_1, retval_offset));

		if (TYPE_IS_FLAT(t)) {
			uint32_t flat_to_data_label;
			g(gen_test_1_cached(ctx, src_arg->slot, copy_ptr_label));

			flat_to_data_label = alloc_label(ctx);
			if (unlikely(!flat_to_data_label))
				return false;

#if defined(ARCH_X86)
			g(gen_address(ctx, R_SAVED_1, retval_offset + 2 + 2 * (ARG_MODE_N >= 3), IMM_PURPOSE_LDR_OFFSET, log_2(sizeof(code_t))));
			g(gen_imm(ctx, OPCODE_MAY_RETURN_FLAT, IMM_PURPOSE_TEST, log_2(sizeof(code_t))));
			gen_insn(INSN_TEST, log_2(sizeof(code_t)), 0, 1);
			gen_address_offset();
			gen_imm_offset();

			gen_insn(INSN_JMP_COND, log_2(sizeof(code_t)), COND_E, 0);
			gen_four(flat_to_data_label);
#else
			g(gen_load_two(ctx, R_SCRATCH_1, R_SAVED_1, retval_offset + 2 + 2 * (ARG_MODE_N >= 3)));

			g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, R_SCRATCH_1, OPCODE_MAY_RETURN_FLAT, COND_E, flat_to_data_label, -1));
#endif
#if defined(ARCH_X86)
			if (is_power_of_2(t->size) && t->size <= 2U << OP_SIZE_NATIVE) {
				if (t->size == 2U << OP_SIZE_NATIVE) {
					g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, src_arg->slot, 0, R_SCRATCH_1, R_SCRATCH_2));

					gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
					gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
					gen_one(R_FRAME);
					gen_one(R_SAVED_2);
					gen_eight(new_fp_offset + lo_word(OP_SIZE_NATIVE));
					gen_one(R_SCRATCH_1);

					gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
					gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
					gen_one(R_FRAME);
					gen_one(R_SAVED_2);
					gen_eight(new_fp_offset + hi_word(OP_SIZE_NATIVE));
					gen_one(R_SCRATCH_2);
				} else {
					g(gen_frame_get(ctx, log_2(t->size), garbage, src_arg->slot, R_SCRATCH_1, &reg1));

					gen_insn(INSN_MOV, log_2(t->size), 0, 0);
					gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
					gen_one(R_FRAME);
					gen_one(R_SAVED_2);
					gen_eight(new_fp_offset);
					gen_one(reg1);
				}
			} else
#endif
			{
				g(gen_lea3(ctx, R_SCRATCH_2, R_FRAME, R_SAVED_2, OP_SIZE_SLOT, new_fp_offset));

				g(gen_memcpy_from_slot(ctx, R_SCRATCH_2, 0, src_arg->slot));
			}

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);

			gen_label(flat_to_data_label);

			if (slot_is_register(ctx, src_arg->slot))
				g(spill(ctx, src_arg->slot));

			g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

			g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
			g(gen_upcall_argument(ctx, 0));

			g(gen_load_constant(ctx, R_ARG1, src_arg->slot));
			g(gen_upcall_argument(ctx, 1));

			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

			if (flag_is_clear(ctx, src_arg->slot))
				goto skip_ref_argument;

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(write_ptr_label);
		}

		gen_label(copy_ptr_label);

		if (unlikely(!(src_arg->flags & OPCODE_FLAG_FREE_ARGUMENT))) {
			g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
			g(gen_frame_load_slot(ctx, src_arg->slot, R_ARG0));
			g(gen_upcall_argument(ctx, 0));
			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		} else if (da(ctx->fn,function)->local_variables_flags[src_arg->slot].may_be_borrowed) {
			g(gen_test_1_cached(ctx, src_arg->slot, load_write_ptr_label));
			g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
			g(gen_frame_load_slot(ctx, src_arg->slot, R_ARG0));
			g(gen_upcall_argument(ctx, 0));
			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
		}

		gen_label(load_write_ptr_label);

		g(gen_frame_load_slot(ctx, src_arg->slot, R_RET0));

skip_ref_argument:
		gen_label(write_ptr_label);

#if defined(ARCH_X86)
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
		gen_one(R_FRAME);
		gen_one(R_SAVED_2);
		gen_eight(new_fp_offset);
		gen_one(R_RET0);
		goto scaled_store_done;
#endif
		if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_SLOT)) {
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, false, 0));
			gen_one(R_SCRATCH_3);
			gen_one(R_FRAME);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | OP_SIZE_SLOT);
			gen_one(R_SAVED_2);

			g(gen_address(ctx, R_SCRATCH_3, new_fp_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
			gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_address_offset();
			gen_one(R_RET0);
			goto scaled_store_done;
		}

		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_SCRATCH_3, R_SAVED_2, OP_SIZE_SLOT, false));

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, R_SCRATCH_3, R_SCRATCH_3, R_FRAME, 0));

		g(gen_address(ctx, R_SCRATCH_3, new_fp_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_address_offset();
		gen_one(R_RET0);

scaled_store_done:
		g(gen_set_1_variable(ctx, R_SAVED_2, new_fp_offset, true));

		gen_label(next_arg_label);

		retval_offset += 4 + 2 * (ARG_MODE_N >= 3);
	}

	g(gen_frame_load_raw(ctx, OP_SIZE_ADDRESS, zero_x, 0, new_fp_offset + frame_offs(function), false, R_SCRATCH_1));

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.codegen), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_decompress_pointer(ctx, ARCH_PREFERS_SX(OP_SIZE_SLOT), R_SCRATCH_1, R_SCRATCH_1, 0));

	g(gen_load_code_32(ctx, R_SCRATCH_2, R_SAVED_1, retval_offset + 2));

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_FRAME, R_FRAME, new_fp_offset, 0));

#if defined(ARCH_X86) && !defined(ARCH_X86_X32)
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(ARG_ADDRESS_2 + OP_SIZE_ADDRESS);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_2);
	gen_eight(offsetof(struct data, u_.codegen.unoptimized_code));

	goto scaled_jmp_done;
#endif
#if defined(ARCH_X86)
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_one(ARG_ADDRESS_2 + OP_SIZE_ADDRESS);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_2);
	gen_eight(offsetof(struct data, u_.codegen.unoptimized_code));

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_SCRATCH_1);

	goto scaled_jmp_done;
#endif
#if defined(ARCH_ARM32)
	gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, false, 0));
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_1);
	gen_one(ARG_SHIFTED_REGISTER);
	gen_one(ARG_SHIFT_LSL | OP_SIZE_ADDRESS);
	gen_one(R_SCRATCH_2);

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_address_offset();

	goto scaled_jmp_done;
#endif
	if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_ADDRESS)) {
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, false, 0));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | OP_SIZE_ADDRESS);
		gen_one(R_SCRATCH_2);

		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

		gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
		gen_one(R_SCRATCH_1);

		goto scaled_jmp_done;
	}

	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_SCRATCH_2, R_SCRATCH_2, OP_SIZE_ADDRESS, false));

	g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, 0));

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_SCRATCH_1);

	goto scaled_jmp_done;
scaled_jmp_done:
	return true;
}

static bool attr_w gen_scaled_array_address(struct codegen_context *ctx, size_t element_size, unsigned reg_dst, unsigned reg_src, unsigned reg_index, int64_t offset_src);
static bool attr_w gen_check_array_len(struct codegen_context *ctx, unsigned reg_array, bool allocated, unsigned reg_len, unsigned cond, uint32_t escape_label);

static bool attr_w gen_structured(struct codegen_context *ctx, frame_t slot_struct, frame_t slot_elem)
{
	uint32_t escape_label;
	const struct type *struct_type, *elem_type;
	size_t i;
	unsigned reg1, reg2;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	struct_type = get_type_of_local(ctx, slot_struct);
	elem_type = get_type_of_local(ctx, slot_elem);

	if (TYPE_IS_FLAT(struct_type) && struct_type->tag != TYPE_TAG_flat_option) {
		if (!TYPE_IS_FLAT(elem_type)) {
			goto struct_zero;
		} else {
			g(gen_test_1_cached(ctx, slot_struct, escape_label));
			flag_set(ctx, slot_struct, false);
		}
	} else {
struct_zero:
		g(gen_test_1_jz_cached(ctx, slot_struct, escape_label));
		struct_type = NULL;
	}

	if (slot_is_register(ctx, slot_struct))
		g(spill(ctx, slot_struct));
	g(gen_frame_address(ctx, slot_struct, 0, R_SAVED_1));

	for (i = 0; i < ctx->args_l; i++) {
		frame_t param_slot = ctx->args[i].slot;
		if (struct_type) {
			switch (ctx->args[i].flags & OPCODE_STRUCTURED_MASK) {
				case OPCODE_STRUCTURED_RECORD: {
					struct flat_record_definition_entry *e;
					ajla_assert_lo(struct_type->tag == TYPE_TAG_flat_record, (file_line, "gen_structured: invalid tag %u, expected %u", struct_type->tag, TYPE_TAG_flat_record));
					e = &type_def(struct_type,flat_record)->entries[param_slot];

					g(gen_imm(ctx, e->flat_offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
					gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, is_imm(), ctx->const_imm));
					gen_one(R_SAVED_1);
					gen_one(R_SAVED_1);
					gen_imm_offset();

					struct_type = e->subtype;
					break;
				}
				case OPCODE_STRUCTURED_ARRAY: {
					ajla_assert_lo(struct_type->tag == TYPE_TAG_flat_array, (file_line, "gen_structured: invalid tag %u, expected %u", struct_type->tag, TYPE_TAG_flat_array));
					g(gen_test_1_cached(ctx, param_slot, escape_label));
					flag_set(ctx, param_slot, false);
					g(gen_frame_get(ctx, OP_SIZE_INT, native, param_slot, R_SCRATCH_1, &reg1));

					g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, reg1, type_def(struct_type,flat_array)->n_elements, COND_AE, escape_label, -1));

					g(gen_scaled_array_address(ctx, type_def(struct_type,flat_array)->base->size, R_SAVED_1, R_SAVED_1, reg1, 0));

					struct_type = type_def(struct_type,flat_array)->base;
					break;
				}
				default:
					internal(file_line, "gen_structured: invalid structured flags %x", (unsigned)ctx->args[i].flags);
			}
		} else {
			gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SAVED_1);
			gen_eight(0);

			g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, NO_FRAME_T, escape_label));
			g(gen_barrier(ctx));

			g(gen_decompress_pointer(ctx, ARCH_PREFERS_SX(OP_SIZE_SLOT), R_SCRATCH_1, R_SCRATCH_1, 0));

			g(gen_compare_refcount(ctx, R_SCRATCH_1, REFCOUNT_STEP, COND_AE, escape_label));

			switch (ctx->args[i].flags & OPCODE_STRUCTURED_MASK) {
				case OPCODE_STRUCTURED_RECORD: {
					const struct type *rec_type, *e_type;
					rec_type = da_type(ctx->fn, ctx->args[i].type);
					TYPE_TAG_VALIDATE(rec_type->tag);
					if (unlikely(rec_type->tag == TYPE_TAG_flat_record))
						rec_type = type_def(rec_type,flat_record)->base;
					e_type = type_def(rec_type,record)->types[param_slot];
					if (!TYPE_IS_FLAT(e_type) || (e_type->tag == TYPE_TAG_flat_option && !(ctx->args[i].flags & OPCODE_STRUCTURED_FLAG_END))) {
						g(gen_test_1(ctx, R_SCRATCH_1, param_slot, data_record_offset, escape_label, true, TEST));
					} else {
						g(gen_test_1(ctx, R_SCRATCH_1, param_slot, data_record_offset, escape_label, false, TEST));
						struct_type = e_type;
					}
					g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SAVED_1, R_SCRATCH_1, data_record_offset + (size_t)param_slot * slot_size, 0));
					break;
				}
				case OPCODE_STRUCTURED_OPTION: {
					unsigned op_size = log_2(sizeof(ajla_option_t));
#if defined(ARCH_X86)
					g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.option.option), IMM_PURPOSE_LDR_OFFSET, op_size));
					g(gen_imm(ctx, param_slot, IMM_PURPOSE_CMP, op_size));
					gen_insn(INSN_CMP, op_size, 0, 1);
					gen_address_offset();
					gen_imm_offset();

					gen_insn(INSN_JMP_COND, op_size, COND_NE, 0);
					gen_four(escape_label);
#else
					g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
					gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
					gen_one(R_SCRATCH_2);
					gen_address_offset();

					g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_2, param_slot, COND_NE, escape_label, -1));
#endif
					g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SAVED_1, R_SCRATCH_1, offsetof(struct data, u_.option.pointer), 0));
					break;
				}
				case OPCODE_STRUCTURED_ARRAY: {
					const struct type *e_type = da_type(ctx->fn, ctx->args[i].type);

					g(gen_test_1_cached(ctx, param_slot, escape_label));
					flag_set(ctx, param_slot, false);

					g(gen_frame_get(ctx, OP_SIZE_INT, native, param_slot, R_SCRATCH_2, &reg2));

					g(gen_check_array_len(ctx, R_SCRATCH_1, false, reg2, COND_AE, escape_label));

					if (!TYPE_IS_FLAT(e_type) || (e_type->tag == TYPE_TAG_flat_option && !(ctx->args[i].flags & OPCODE_STRUCTURED_FLAG_END))) {
						g(gen_compare_ptr_tag(ctx, R_SCRATCH_1, DATA_TAG_array_pointers, COND_NE, escape_label, R_SCRATCH_3, false));

						g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
						gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
						gen_one(R_SCRATCH_1);
						gen_address_offset();

						g(gen_scaled_array_address(ctx, slot_size, R_SAVED_1, R_SCRATCH_1, reg2, 0));
					} else {
						g(gen_compare_ptr_tag(ctx, R_SCRATCH_1, DATA_TAG_array_flat, COND_NE, escape_label, R_SCRATCH_3, false));

						g(gen_scaled_array_address(ctx, e_type->size, R_SAVED_1, R_SCRATCH_1, reg2, data_array_offset));

						struct_type = e_type;
					}
					break;
				}
				default: {
					internal(file_line, "gen_structured: invalid structured flags %x", (unsigned)ctx->args[i].flags);
				}
			}
		}
	}

	if (struct_type) {
		g(gen_test_1_cached(ctx, slot_elem, escape_label));
		flag_set(ctx, slot_elem, false);
		g(gen_memcpy_from_slot(ctx, R_SAVED_1, 0, slot_elem));
	} else {
		uint32_t skip_deref_label;
		skip_deref_label = alloc_label(ctx);
		if (unlikely(!skip_deref_label))
			return false;

		if (TYPE_IS_FLAT(elem_type))
			g(gen_test_1_jz_cached(ctx, slot_elem, escape_label));

		gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SAVED_1);
		gen_eight(0);

		g(gen_jmp_on_zero(ctx, OP_SIZE_SLOT, R_SCRATCH_1, COND_E, skip_deref_label));

		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_dereference), 1, true));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_SCRATCH_1));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_dereference), 1, true));

		gen_label(skip_deref_label);

		g(gen_frame_get_pointer(ctx, slot_elem, (ctx->args[i - 1].flags & OPCODE_STRUCTURED_FREE_VARIABLE) != 0, R_SCRATCH_1));

		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SAVED_1);
		gen_eight(0);
		gen_one(R_SCRATCH_1);
	}

	return true;
}

static bool attr_w gen_record_create(struct codegen_context *ctx, frame_t slot_r)
{
	const struct type *t;
	const struct record_definition *def;
	uint32_t escape_label;
	arg_t i, ii;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	t = get_type_of_local(ctx, slot_r);
	if (t->tag == TYPE_TAG_flat_record) {
		const struct flat_record_definition *flat_def;
		const struct type *flat_type = t;
		t = type_def(t,flat_record)->base;
		def = type_def(t,record);
		flat_def = type_def(flat_type,flat_record);
		for (i = 0; i < ctx->args_l; i++) {
			frame_t var_slot = ctx->args[i].slot;
			g(gen_test_1_cached(ctx, var_slot, escape_label));
			flag_set(ctx, var_slot, false);
		}
		for (i = 0, ii = 0; i < ctx->args_l; i++, ii++) {
			frame_t var_slot, flat_offset, record_slot;
			while (unlikely(record_definition_is_elided(def, ii)))
				ii++;
			var_slot = ctx->args[i].slot;
			record_slot = record_definition_slot(def, ii);
			flat_offset = flat_def->entries[record_slot].flat_offset;
			g(gen_memcpy_from_slot(ctx, R_FRAME, (size_t)slot_r * slot_size + flat_offset, var_slot));
		}
		return true;
	}

	def = type_def(t,record);

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_record_mayfail), 2, true));

	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, slot_r));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_record_mayfail), 2, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, R_RET0));

	g(gen_clear_bitmap(ctx, 0, R_SAVED_1, data_record_offset, bitmap_slots(def->n_slots)));

	for (i = 0, ii = 0; i < ctx->args_l; i++, ii++) {
		frame_t var_slot, var_flags, record_slot;
		const struct type *var_type, *record_type;
		uint32_t skip_flat_label, set_ptr_label, next_arg_label;

		skip_flat_label = alloc_label(ctx);
		if (unlikely(!skip_flat_label))
			return false;
		set_ptr_label = alloc_label(ctx);
		if (unlikely(!set_ptr_label))
			return false;
		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;

		while (unlikely(record_definition_is_elided(def, ii)))
			ii++;
		var_slot = ctx->args[i].slot;
		var_type = get_type_of_local(ctx, var_slot);
		var_flags = ctx->args[i].flags;
		record_slot = record_definition_slot(def, ii);
		record_type = def->types[record_slot];
		if (TYPE_IS_FLAT(var_type)) {
			g(gen_test_1_cached(ctx, var_slot, skip_flat_label));
			if (TYPE_IS_FLAT(record_type)) {
				g(gen_memcpy_from_slot(ctx, R_SAVED_1, data_record_offset + (size_t)record_slot * slot_size, var_slot));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(next_arg_label);
			} else {
				if (slot_is_register(ctx, var_slot))
					g(spill(ctx, var_slot));

				g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

				g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
				g(gen_upcall_argument(ctx, 0));

				g(gen_load_constant(ctx, R_ARG1, var_slot));
				g(gen_upcall_argument(ctx, 1));

				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(set_ptr_label);
			}
		}

		gen_label(skip_flat_label);
		g(gen_frame_get_pointer(ctx, var_slot, (var_flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_RET0));

		gen_label(set_ptr_label);
		g(gen_address(ctx, R_SAVED_1, data_record_offset + (size_t)record_slot * slot_size, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_address_offset();
		gen_one(R_RET0);

		g(gen_set_1(ctx, R_SAVED_1, record_slot, data_record_offset, true));

		gen_label(next_arg_label);
	}

	g(gen_compress_pointer(ctx, R_SAVED_1, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1, false, true));

	return true;
}

static bool attr_w gen_record_load(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r, frame_t rec_slot, frame_t flags)
{
	const struct type *rec_type, *entry_type;
	uint32_t escape_label;
	unsigned reg;

	rec_type = get_type_of_local(ctx, slot_1);
	if (unlikely(rec_type->tag == TYPE_TAG_unknown)) {
		ajla_assert_lo(!*da(ctx->fn,function)->function_name, (file_line, "gen_record_load: function %s has record without definition", da(ctx->fn,function)->function_name));
		return false;
	}

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	/*debug("gen_record_load: %s: %u, %u", da(ctx->fn,function)->function_name, TYPE_TAG_unknown, rec_type->tag);*/
	if (TYPE_IS_FLAT(rec_type)) {
		const struct flat_record_definition_entry *ft = &type_def(rec_type,flat_record)->entries[rec_slot];
		g(gen_test_1_cached(ctx, slot_1, escape_label));
		g(gen_memcpy_to_slot(ctx, slot_r, R_FRAME, (size_t)slot_1 * slot_size + ft->flat_offset));
		flag_set(ctx, slot_1, false);
		flag_set(ctx, slot_r, false);
		return true;
	}
	entry_type = type_def(rec_type,record)->types[rec_slot];

	g(gen_frame_decompress_slot(ctx, slot_1, R_SCRATCH_2, &reg, escape_label));

	if (TYPE_IS_FLAT(entry_type)) {
		g(gen_test_1(ctx, reg, rec_slot, data_record_offset, escape_label, false, TEST));
		g(gen_memcpy_to_slot(ctx, slot_r, reg, (size_t)rec_slot * slot_size + data_record_offset));
		flag_set(ctx, slot_r, false);
		return true;
	}

	if (flag_must_be_flat(ctx, slot_r)) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	g(gen_test_1(ctx, reg, rec_slot, data_record_offset, escape_label, true, TEST));

	g(gen_address(ctx, reg, (size_t)rec_slot * slot_size + data_record_offset, ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_frame_set_pointer_2(ctx, slot_r, R_SCRATCH_1, flags, escape_label));

	return true;
}

static bool attr_w gen_option_create_empty_flat(struct codegen_context *ctx, ajla_flat_option_t opt, frame_t slot_r)
{
	g(gen_frame_store_imm(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, opt));
	flag_set(ctx, slot_r, false);
	return true;
}

static bool attr_w gen_option_create_empty(struct codegen_context *ctx, ajla_option_t opt, frame_t slot_r)
{
	unsigned option_size = log_2(sizeof(ajla_option_t));
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (flag_must_be_flat(ctx, slot_r)) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_option_mayfail), 0, true));
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_option_mayfail), 0, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_address(ctx, R_RET0, offsetof(struct data, u_.option.option), IMM_PURPOSE_STR_OFFSET, option_size));
	g(gen_imm(ctx, opt, IMM_PURPOSE_STORE_VALUE, option_size));
	gen_insn(INSN_MOV, option_size, 0, 0);
	gen_address_offset();
	gen_imm_offset();

	g(gen_address(ctx, R_RET0, offsetof(struct data, u_.option.pointer), IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
	g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, OP_SIZE_SLOT));
	gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_address_offset();
	gen_imm_offset();

	g(gen_compress_pointer(ctx, R_RET0, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, true));

	return true;
}

static bool attr_w gen_option_create(struct codegen_context *ctx, ajla_option_t opt, frame_t slot_1, frame_t slot_r, frame_t flags)
{
	unsigned option_size = log_2(sizeof(ajla_option_t));
	const struct type *type;
	uint32_t escape_label, get_pointer_label, got_pointer_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (flag_must_be_flat(ctx, slot_r)) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	get_pointer_label = alloc_label(ctx);
	if (unlikely(!get_pointer_label))
		return false;

	got_pointer_label = alloc_label(ctx);
	if (unlikely(!got_pointer_label))
		return false;

	type = get_type_of_local(ctx, slot_1);

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_option_mayfail), 0, true));
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_option_mayfail), 0, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, R_RET0));

	g(gen_address(ctx, R_RET0, offsetof(struct data, u_.option.option), IMM_PURPOSE_STR_OFFSET, option_size));
	g(gen_imm(ctx, opt, IMM_PURPOSE_STORE_VALUE, option_size));
	gen_insn(INSN_MOV, option_size, 0, 0);
	gen_address_offset();
	gen_imm_offset();

	if (TYPE_IS_FLAT(type)) {
		g(gen_test_1_cached(ctx, slot_1, get_pointer_label));

		if (slot_is_register(ctx, slot_1))
			g(spill(ctx, slot_1));

		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, slot_1));
		g(gen_upcall_argument(ctx, 1));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

		if (flag_is_clear(ctx, slot_1))
			goto skip_get_pointer_label;

		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(got_pointer_label);
	}

	gen_label(get_pointer_label);
	g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_RET0));

skip_get_pointer_label:
	gen_label(got_pointer_label);
	g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.option.pointer), IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
	gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_address_offset();
	gen_one(R_RET0);

	g(gen_compress_pointer(ctx, R_SAVED_1, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1, false, true));

	return true;
}

static bool attr_w gen_option_cmp(struct codegen_context *ctx, unsigned reg, frame_t opt, uint32_t label, frame_t slot_r)
{
	unsigned op_size = log_2(sizeof(ajla_option_t));
#if ARCH_HAS_FLAGS
#if defined(ARCH_X86)
	g(gen_address(ctx, reg, offsetof(struct data, u_.option.option), IMM_PURPOSE_LDR_OFFSET, op_size));
	g(gen_imm(ctx, opt, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1);
	gen_address_offset();
	gen_imm_offset();
#else
	g(gen_address(ctx, reg, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_imm(ctx, opt, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1);
	gen_one(R_SCRATCH_2);
	gen_imm_offset();
#endif
	if (label) {
		gen_insn(INSN_JMP_COND, op_size, COND_NE, 0);
		gen_four(label);
	} else {
		g(gen_frame_set_cond(ctx, op_size, false, COND_E, slot_r));
	}
	return true;
#else
	g(gen_address(ctx, reg, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_cmp_dest_reg(ctx, op_size, R_SCRATCH_2, (unsigned)-1, label ? R_CMP_RESULT : R_SCRATCH_2, opt, COND_E));

	if (label) {
		gen_insn(INSN_JMP_REG, i_size(op_size), COND_E, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);
	} else {
		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_2));
	}
	return true;
#endif
}

static bool attr_w gen_option_load(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r, ajla_option_t opt, frame_t flags)
{
	const struct type *type;
	uint32_t escape_label;
	unsigned reg;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (flag_must_be_flat(ctx, slot_r)) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	type = get_type_of_local(ctx, slot_1);
	if (TYPE_IS_FLAT(type)) {
		g(gen_test_1_jz_cached(ctx, slot_1, escape_label));
	}

	g(gen_frame_decompress_slot(ctx, slot_1, R_SCRATCH_1, &reg, escape_label));
	g(gen_option_cmp(ctx, reg, opt, escape_label, 0));

	g(gen_address(ctx, reg, offsetof(struct data, u_.option.pointer), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_frame_set_pointer_2(ctx, slot_r, R_SCRATCH_1, flags, escape_label));

	return true;
}

static bool attr_w gen_option_test_flat(struct codegen_context *ctx, frame_t slot_1, frame_t opt, frame_t slot_r)
{
	unsigned op_size = log_2(sizeof(ajla_flat_option_t));
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_1, escape_label));

	flag_set(ctx, slot_1, false);
	flag_set(ctx, slot_r, false);

	if (unlikely(opt != (ajla_flat_option_t)opt)) {
		g(gen_frame_clear(ctx, op_size, slot_r));
		return true;
	}

	g(gen_frame_load_cmp_imm_set_cond(ctx, op_size, zero_x, slot_1, opt, COND_E, slot_r));

	return true;
}

static bool attr_w gen_option_test(struct codegen_context *ctx, frame_t slot_1, frame_t opt, frame_t slot_r)
{
	uint32_t escape_label;
	unsigned reg;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_frame_decompress_slot(ctx, slot_1, R_SCRATCH_1, &reg, escape_label));

	flag_set(ctx, slot_r, false);

	if (unlikely(opt != (ajla_option_t)opt)) {
		g(gen_frame_clear(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r));
		return true;
	}

	g(gen_option_cmp(ctx, reg, opt, 0, slot_r));

	return true;
}

static bool attr_w gen_option_ord(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r, bool flat)
{
	unsigned op_size = log_2(sizeof(ajla_option_t));
	unsigned op_size_flat = log_2(sizeof(ajla_flat_option_t));
	uint32_t escape_label, ptr_label, store_label;
	unsigned reg, target;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	ptr_label = alloc_label(ctx);
	if (unlikely(!ptr_label))
		return false;

	store_label = alloc_label(ctx);
	if (unlikely(!store_label))
		return false;

	target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);

	if (flat) {
		g(gen_test_1_cached(ctx, slot_1, ptr_label));

		g(gen_frame_load(ctx, op_size_flat, zero_x, slot_1, 0, false, target));

		if (flag_is_clear(ctx, slot_1))
			goto skip_ptr_label;

		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(store_label);
	}

	gen_label(ptr_label);
	g(gen_frame_decompress_slot(ctx, slot_1, R_SCRATCH_1, &reg, escape_label));

	g(gen_address(ctx, reg, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(target);
	gen_address_offset();

skip_ptr_label:
	gen_label(store_label);
	g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, target));
	flag_set(ctx, slot_r, false);

	return true;
}

static bool attr_w gen_array_create(struct codegen_context *ctx, frame_t slot_r)
{
	size_t i;
	const struct type *type;
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	ajla_assert_lo(ctx->args_l != 0, (file_line, "gen_array_create: zero entries"));

	if (unlikely(ctx->args_l >= sign_bit(uint_default_t))) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	type = get_type_of_local(ctx, ctx->args[0].slot);
	for (i = 1; i < ctx->args_l; i++) {
		const struct type *t = get_type_of_local(ctx, ctx->args[i].slot);
		if (unlikely(t != type))
			internal(file_line, "gen_array_create: types do not match: %u != %u", type->tag, t->tag);
	}

	if (TYPE_IS_FLAT(type)) {
		int64_t offset;
		for (i = 0; i < ctx->args_l; i++) {
			g(gen_test_1_cached(ctx, ctx->args[i].slot, escape_label));
			flag_set(ctx, ctx->args[i].slot, false);
		}

		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_slot_mayfail), 3, true));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, ctx->args[0].slot));
		g(gen_upcall_argument(ctx, 1));

		g(gen_load_constant(ctx, R_ARG2, ctx->args_l));
		g(gen_upcall_argument(ctx, 2));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_slot_mayfail), 3, true));
		g(gen_sanitize_returned_pointer(ctx, R_RET0));
		g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, R_RET0));

		offset = data_array_offset;
		for (i = 0; i < ctx->args_l; i++) {
			g(gen_memcpy_from_slot(ctx, R_SAVED_1, offset, ctx->args[i].slot));
			offset += type->size;
		}
	} else {
		int64_t offset;
		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_pointers_mayfail), 2, true));

		g(gen_load_constant(ctx, R_ARG0, ctx->args_l));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, ctx->args_l));
		g(gen_upcall_argument(ctx, 1));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_pointers_mayfail), 2, true));
		g(gen_sanitize_returned_pointer(ctx, R_RET0));
		g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, R_RET0));

		g(gen_address(ctx, R_RET0, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SAVED_2);
		gen_address_offset();

		offset = 0;
		for (i = 0; i < ctx->args_l; i++) {
			g(gen_frame_get_pointer(ctx, ctx->args[i].slot, (ctx->args[i].flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_SCRATCH_1));
			g(gen_address(ctx, R_SAVED_2, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
			gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_address_offset();
			gen_one(R_SCRATCH_1);
			offset += sizeof(pointer_t);
		}
	}
	g(gen_compress_pointer(ctx, R_SAVED_1, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1, false, true));
	return true;
}

static bool attr_w gen_array_create_empty_flat(struct codegen_context *ctx, frame_t slot_r, frame_t local_type)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_types_ptr_mayfail), 4, true));

	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, local_type));
	g(gen_upcall_argument(ctx, 1));

	g(gen_load_constant(ctx, R_ARG2, ARRAY_PREALLOC_SIZE));
	g(gen_upcall_argument(ctx, 2));

	g(gen_load_constant(ctx, R_ARG3, 0));
	g(gen_upcall_argument(ctx, 3));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_types_ptr_mayfail), 4, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_compress_pointer(ctx, R_RET0, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, true));

	return true;
}

static bool attr_w gen_array_create_empty(struct codegen_context *ctx, frame_t slot_r)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_pointers_mayfail), 2, true));

	g(gen_load_constant(ctx, R_ARG0, ARRAY_PREALLOC_SIZE));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, 0));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_pointers_mayfail), 2, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_compress_pointer(ctx, R_RET0, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, true));

	return true;
}

static bool attr_w gen_array_fill(struct codegen_context *ctx, frame_t slot_1, frame_t flags, frame_t slot_2, frame_t slot_r)
{
	const struct type *content_type, *array_type;
	uint32_t escape_label;
	unsigned reg1, reg4;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_2, escape_label));

	content_type = get_type_of_local(ctx, slot_1);
	array_type = get_type_of_local(ctx, slot_r);

	if (TYPE_IS_FLAT(array_type)) {
		int64_t dest_offset;
		size_t i;
		const struct flat_array_definition *def = type_def(array_type,flat_array);

		ajla_assert_lo(TYPE_IS_FLAT(content_type), (file_line, "gen_array_fill: array is flat but content is not: %s", da(ctx->fn,function)->function_name));

		g(gen_test_1_cached(ctx, slot_1, escape_label));

		dest_offset = (size_t)slot_r * slot_size;
		for (i = 0; i < def->n_elements; i++) {
			g(gen_memcpy_from_slot(ctx, R_FRAME, dest_offset, slot_1));
			dest_offset += def->base->size;
		}
		flag_set(ctx, slot_1, false);
		flag_set(ctx, slot_r, false);

		return true;
	}

	if (slot_is_register(ctx, slot_1))
		g(spill(ctx, slot_1));

	if (unlikely((flags & OPCODE_ARRAY_FILL_FLAG_SPARSE) != 0)) {
		uint32_t get_ptr_label, got_ptr_label;

		get_ptr_label = alloc_label(ctx);
		if (unlikely(!get_ptr_label))
			return false;

		got_ptr_label = alloc_label(ctx);
		if (unlikely(!got_ptr_label))
			return false;

		if (TYPE_IS_FLAT(content_type)) {
			g(gen_test_1_cached(ctx, slot_1, get_ptr_label));

			g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

			g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
			g(gen_upcall_argument(ctx, 0));

			g(gen_load_constant(ctx, R_ARG1, slot_1));
			g(gen_upcall_argument(ctx, 1));

			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 2, true));

			g(gen_mov(ctx, i_size(OP_SIZE_SLOT), R_SCRATCH_4, R_RET0));

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(got_ptr_label);
		}

		gen_label(get_ptr_label);

		g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_SCRATCH_4));

		gen_label(got_ptr_label);

		g(gen_frame_get(ctx, OP_SIZE_INT, sign_x, slot_2, R_SCRATCH_1, &reg1));
		g(gen_jmp_if_negative(ctx, reg1, escape_label));

		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_sparse), 2, true));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, reg1));
		g(gen_upcall_argument(ctx, 0));

		g(gen_mov(ctx, i_size(OP_SIZE_SLOT), R_ARG1, R_SCRATCH_4));
		g(gen_upcall_argument(ctx, 1));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_sparse), 2, true));
	} else if (TYPE_IS_FLAT(content_type)) {
		g(gen_test_1_cached(ctx, slot_1, escape_label));
		flag_set(ctx, slot_1, false);

		g(gen_frame_get(ctx, OP_SIZE_INT, sign_x, slot_2, R_SCRATCH_4, &reg4));
		g(gen_jmp_if_negative(ctx, reg4, escape_label));

		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_flat), 3, true));
		g(gen_mov(ctx, i_size(OP_SIZE_INT), R_ARG1, reg4));
		g(gen_upcall_argument(ctx, 1));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG2, slot_1));
		g(gen_upcall_argument(ctx, 2));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_flat), 3, true));
	} else {
		if (slot_is_register(ctx, slot_2))
			g(spill(ctx, slot_2));

		g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_SCRATCH_1));

		g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_pointers), 4, true));

		g(gen_mov(ctx, i_size(OP_SIZE_SLOT), R_ARG3, R_SCRATCH_1));
		g(gen_upcall_argument(ctx, 3));

		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, ctx->instr_start - da(ctx->fn,function)->code));
		g(gen_upcall_argument(ctx, 1));

		g(gen_load_constant(ctx, R_ARG2, slot_2));
		g(gen_upcall_argument(ctx, 2));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_pointers), 4, true));
	}
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, false));

	return true;
}

static bool attr_w gen_array_string(struct codegen_context *ctx, type_tag_t tag, uint8_t *string, frame_t len, frame_t slot_r)
{
	uint32_t escape_label;
	int64_t offset;
	const struct type *type;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_tag_mayfail), 2, true));

	g(gen_load_constant(ctx, R_ARG0, tag));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, len));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_tag_mayfail), 2, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SAVED_1, R_RET0));

	g(gen_compress_pointer(ctx, R_RET0, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, true));

	g(load_function_offset(ctx, R_SCRATCH_3, offsetof(struct data, u_.function.code)));

	offset = string - cast_ptr(uint8_t *, da(ctx->fn,function)->code);
	type = type_get_from_tag(tag);
	g(gen_memcpy_raw(ctx, R_SAVED_1, data_array_offset, R_SCRATCH_3, offset, (size_t)len * type->size, minimum(type->align, align_of(code_t))));

	return true;
}

static bool attr_w gen_scaled_array_address(struct codegen_context *ctx, size_t element_size, unsigned reg_dst, unsigned reg_src, unsigned reg_index, int64_t offset_src)
{
	if (is_power_of_2(element_size)) {
		unsigned shift = log_2(element_size);
#if defined(ARCH_X86)
		if (shift <= 3 && imm_is_32bit(offset_src)) {
			gen_insn(INSN_LEA3, i_size(OP_SIZE_ADDRESS), shift, 0);
			gen_one(reg_dst);
			gen_one(reg_src);
			gen_one(reg_index);
			gen_one(ARG_IMM);
			gen_eight(offset_src);
			return true;
		}
#endif
		if (ARCH_HAS_SHIFTED_ADD(shift)) {
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, false, 0));
			gen_one(reg_dst);
			gen_one(reg_src);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | shift);
			gen_one(reg_index);

			goto add_offset;
		}

		if (shift) {
			g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, reg_dst, reg_index, shift, 0));
			reg_index = reg_dst;
		}
	} else {
		if (ARCH_HAS_MUL) {
			g(gen_imm(ctx, element_size, IMM_PURPOSE_MUL, i_size(OP_SIZE_ADDRESS)));
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_MUL, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_MUL, false, is_imm(), ctx->const_imm));
			gen_one(reg_dst);
			gen_one(reg_index);
			gen_imm_offset();
			reg_index = reg_dst;
		} else {
#if defined(R_CONST_IMM)
			size_t e_size = element_size;
			unsigned sh = 0;
			bool first_match = true;

			g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_CONST_IMM, reg_index));
			g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), reg_dst, reg_index));
			reg_index = reg_dst;

			if (!e_size)
				g(gen_load_constant(ctx, reg_index, 0));

			while (e_size) {
				if (e_size & 1) {
					if (first_match) {
						if (sh)
							g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, reg_index, reg_index, sh, false));
						first_match = false;
					} else if (ARCH_HAS_SHIFTED_ADD(sh)) {
						gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, false, 0));
						gen_one(reg_index);
						gen_one(reg_index);
						gen_one(ARG_SHIFTED_REGISTER);
						gen_one(ARG_SHIFT_LSL | sh);
						gen_one(R_CONST_IMM);
					} else {
						if (sh) {
							g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, R_CONST_IMM, R_CONST_IMM, sh, false));
							sh = 0;
						}
						g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, reg_index, reg_index, R_CONST_IMM, 0));
					}
				}
				sh += 1;
				e_size >>= 1;
			}
#else
			internal(file_line, "gen_scaled_array_address: R_CONST_IMM not defined");
#endif
		}
	}
#if defined(ARCH_S390)
	if (offset_src && s390_inline_address(offset_src)) {
		gen_insn(INSN_LEA3, i_size(OP_SIZE_ADDRESS), 0, 0);
		gen_one(reg_dst);
		gen_one(reg_index);
		gen_one(reg_src);
		gen_one(ARG_IMM);
		gen_eight(offset_src);
		return true;
	}
#endif
	g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, reg_dst, reg_index, reg_src, 0));
	goto add_offset;

add_offset:
	if (offset_src) {
		g(gen_imm(ctx, offset_src, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, is_imm(), ctx->const_imm));
		gen_one(reg_dst);
		gen_one(reg_dst);
		gen_imm_offset();
	}
	return true;
}

static bool attr_w gen_scaled_array_load(struct codegen_context *ctx, unsigned reg_src, unsigned reg_idx, int64_t offset_src, frame_t slot_r)
{
	const struct type *t = get_type_of_local(ctx, slot_r);
#if defined(ARCH_X86)
	if (is_power_of_2(t->size)) {
		unsigned shift = log_2(t->size);
		if (shift <= 3 && shift <= OP_SIZE_NATIVE && imm_is_32bit(offset_src)) {
			short reg = ctx->registers[slot_r];
			gen_insn(INSN_MOV, shift, 0, 0);
			gen_one(reg >= 0 ? reg : R_SCRATCH_2);
			gen_one(ARG_ADDRESS_2 + shift);
			gen_one(reg_src);
			gen_one(reg_idx);
			gen_eight(offset_src);

			if (reg < 0) {
				g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size, IMM_PURPOSE_STR_OFFSET, shift));
				gen_insn(INSN_MOV, shift, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_2);
			}

			return true;
		}
	}
#endif
#if defined(ARCH_S390)
	if (t->size == 1 && s390_inline_address(offset_src) && cpu_test_feature(CPU_FEATURE_long_displacement) && cpu_test_feature(CPU_FEATURE_extended_imm)) {
		short reg = ctx->registers[slot_r];
		gen_insn(INSN_MOVSX, OP_SIZE_1, 0, 0);
		gen_one(reg >= 0 ? reg : R_SCRATCH_2);
		gen_one(ARG_ADDRESS_2);
		gen_one(reg_src);
		gen_one(reg_idx);
		gen_eight(offset_src);

		if (reg < 0) {
			g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size, IMM_PURPOSE_STR_OFFSET, OP_SIZE_1));
			gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
			gen_address_offset();
			gen_one(R_SCRATCH_2);
		}

		return true;
	}
#endif
	g(gen_scaled_array_address(ctx, t->size, R_SCRATCH_2, reg_src, reg_idx, 0));

	g(gen_memcpy_to_slot(ctx, slot_r, R_SCRATCH_2, offset_src));

	return true;
}

static bool attr_w gen_scaled_array_store(struct codegen_context *ctx, unsigned reg_src, int64_t offset_src, frame_t slot_1)
{
	const struct type *t = get_type_of_local(ctx, slot_1);
#if defined(ARCH_X86)
	if (is_power_of_2(t->size)) {
		unsigned shift = log_2(t->size);
		if (shift <= 3 && shift <= OP_SIZE_NATIVE && imm_is_32bit(offset_src)) {
			short reg = ctx->registers[slot_1];
			if (reg < 0) {
				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size, IMM_PURPOSE_LDR_OFFSET, shift));
				gen_insn(INSN_MOV, shift, 0, 0);
				gen_one(R_SCRATCH_3);
				gen_address_offset();
				reg = R_SCRATCH_3;
			}

			gen_insn(INSN_MOV, shift, 0, 0);
			gen_one(ARG_ADDRESS_2 + shift);
			gen_one(reg_src);
			gen_one(R_SCRATCH_2);
			gen_eight(offset_src);
			gen_one(reg);

			return true;
		}
	}
#endif
#if defined(ARCH_S390)
	if (t->size == 1 && s390_inline_address(offset_src) && cpu_test_feature(CPU_FEATURE_long_displacement) && cpu_test_feature(CPU_FEATURE_extended_imm)) {
		short reg = ctx->registers[slot_1];
		if (reg < 0) {
			g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size, IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_1));
			gen_insn(INSN_MOVSX, OP_SIZE_1, 0, 0);
			gen_one(R_SCRATCH_3);
			gen_address_offset();
			reg = R_SCRATCH_3;
		}

		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(ARG_ADDRESS_2);
		gen_one(reg_src);
		gen_one(R_SCRATCH_2);
		gen_eight(offset_src);
		gen_one(reg);

		return true;
	}
#endif
	g(gen_scaled_array_address(ctx, t->size, R_SCRATCH_2, reg_src, R_SCRATCH_2, 0));

	g(gen_memcpy_from_slot(ctx, R_SCRATCH_2, offset_src, slot_1));

	return true;
}

static bool attr_w gen_check_array_len(struct codegen_context *ctx, unsigned reg_array, bool allocated, unsigned reg_len, unsigned cond, uint32_t escape_label)
{
	size_t offset = !allocated ? offsetof(struct data, u_.array_flat.n_used_entries) : offsetof(struct data, u_.array_flat.n_allocated_entries);
#if defined(ARCH_X86)
	g(gen_address(ctx, reg_array, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(INSN_CMP, OP_SIZE_INT, 0, 1);
	gen_one(reg_len);
	gen_address_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_INT, cond, 0);
	gen_four(escape_label);
#else
	g(gen_address(ctx, reg_array, offset, ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_one(R_SCRATCH_3);
	gen_address_offset();

	g(gen_cmp_test_jmp(ctx, INSN_CMP, i_size(OP_SIZE_INT), reg_len, R_SCRATCH_3, cond, escape_label));
#endif
	return true;
}

static bool attr_w gen_array_load(struct codegen_context *ctx, frame_t slot_1, frame_t slot_idx, frame_t slot_r, frame_t flags)
{
	const struct type *t = get_type_of_local(ctx, slot_1);
	const struct type *tr = get_type_of_local(ctx, slot_r);
	uint32_t escape_label;
	unsigned reg1, reg2;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(t->tag == TYPE_TAG_flat_array)) {
		const struct flat_array_definition *def = type_def(t,flat_array);

		g(gen_test_2_cached(ctx, slot_1, slot_idx, escape_label));

		flag_set(ctx, slot_1, false);
		flag_set(ctx, slot_idx, false);

		g(gen_frame_get(ctx, OP_SIZE_INT, native, slot_idx, R_SCRATCH_2, &reg2));

		if (!(flags & OPCODE_ARRAY_INDEX_IN_RANGE))
			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, reg2, def->n_elements, COND_AE, escape_label, -1));

		g(gen_scaled_array_load(ctx, R_FRAME, reg2, (size_t)slot_1 * slot_size, slot_r));
		return true;
	}

	g(gen_frame_decompress_slot(ctx, slot_1, R_SCRATCH_1, &reg1, escape_label));

	g(gen_test_1_cached(ctx, slot_idx, escape_label));
	flag_set(ctx, slot_idx, false);
	g(gen_frame_get(ctx, OP_SIZE_INT, native, slot_idx, R_SCRATCH_2, &reg2));

	if (!(flags & OPCODE_ARRAY_INDEX_IN_RANGE))
		g(gen_check_array_len(ctx, reg1, false, reg2, COND_AE, escape_label));

	if (TYPE_IS_FLAT(tr)) {
		uint32_t label;
		bool subtract = false;
#if !ARCH_HAS_FLAGS && !defined(ARCH_IA64) && !defined(ARCH_PARISC)
		subtract = true;
#endif
		g(gen_compare_ptr_tag(ctx, reg1, DATA_TAG_array_slice, COND_A, escape_label, R_SCRATCH_4, subtract));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SCRATCH_1, reg1));
#if defined(ARCH_ARM32) || defined(ARCH_S390) || defined(ARCH_X86)
#if defined(ARCH_X86)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_cmov)))
#elif defined(ARCH_S390)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_misc_45)))
#else
		if (0)
#endif
		{
			g(gen_address(ctx, reg1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
			gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
			gen_one(R_SCRATCH_3);
			gen_address_offset();
			goto no_cmov;
		}
		g(gen_address(ctx, reg1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_CMOV, OP_SIZE_ADDRESS, COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_address_offset();
#elif defined(ARCH_PARISC)
		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_CMP_CMOV, OP_SIZE_ADDRESS, COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_address_offset();
		gen_one(R_SCRATCH_4);
		gen_one(ARG_IMM);
		gen_eight(DATA_TAG_array_slice);
#elif defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_RISCV64)
		label = alloc_label(ctx);
		if (unlikely(!label))
			return false;

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_SCRATCH_4);
		gen_four(label);

		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

		gen_label(label);
#else
		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_3);
		gen_address_offset();
#if ARCH_HAS_FLAGS
#if defined(ARCH_POWER)
		if (!cpu_test_feature(CPU_FEATURE_v203))
			goto no_cmov;
#endif
#if defined(ARCH_SPARC)
		if (!SPARC_9)
			goto no_cmov;
#endif
		gen_insn(INSN_CMOV, i_size(OP_SIZE_ADDRESS), COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_3);
#else
		if (!subtract) {
			g(gen_imm(ctx, DATA_TAG_array_slice, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, COND_E, 0);
			gen_one(R_CMP_RESULT);
			gen_one(R_SCRATCH_4);
			gen_imm_offset();

			gen_insn(INSN_MOVR, OP_SIZE_NATIVE, COND_NE, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_CMP_RESULT);
			gen_one(R_SCRATCH_3);
		} else {
			gen_insn(INSN_MOVR, OP_SIZE_NATIVE, COND_E, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_3);
		}
#endif
#endif
		if (0) {
			goto no_cmov;
no_cmov:
			label = alloc_label(ctx);
			if (unlikely(!label))
				return false;
			gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
			gen_four(label);

			g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_SCRATCH_1, R_SCRATCH_3));

			gen_label(label);
		}
		g(gen_scaled_array_load(ctx, R_SCRATCH_1, reg2, data_array_offset, slot_r));
		flag_set(ctx, slot_r, false);
		return true;
	} else {
		if (flag_must_be_flat(ctx, slot_r)) {
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(escape_label);
			return true;
		}

		g(gen_compare_ptr_tag(ctx, reg1, DATA_TAG_array_pointers, COND_NE, escape_label, R_SCRATCH_3, false));

		g(gen_address(ctx, reg1, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

#if defined(ARCH_X86) || defined(ARCH_ARM)
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
		gen_one(R_SCRATCH_1);
		gen_one(reg2);
		gen_eight(0);

		goto scaled_load_done;
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_S390) || defined(ARCH_SPARC)
		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, R_SCRATCH_2, reg2, OP_SIZE_SLOT, false));

		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_ADDRESS_2);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
		gen_eight(0);

		goto scaled_load_done;
#endif
		if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_SLOT)) {
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, false, 0));
			gen_one(R_SCRATCH_2);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | OP_SIZE_SLOT);
			gen_one(reg2);
			gen_one(R_SCRATCH_1);

			gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SCRATCH_2);
			gen_eight(0);

			goto scaled_load_done;
		}

		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, R_SCRATCH_2, reg2, OP_SIZE_SLOT, false));

		g(gen_3address_alu(ctx, OP_SIZE_ADDRESS, ALU_ADD, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_1, 0));

		gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SCRATCH_2);
		gen_eight(0);
scaled_load_done:
		g(gen_frame_set_pointer_2(ctx, slot_r, R_SCRATCH_1, flags, escape_label));
		return true;
	}
}

static bool attr_w gen_array_len(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r, bool fused, int32_t offs_false)
{
	const struct type *t = get_type_of_local(ctx, slot_1);
	uint32_t escape_label;
	unsigned reg, target;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (slot_2 != NO_FRAME_T) {
		g(gen_test_1_cached(ctx, slot_2, escape_label));
		flag_set(ctx, slot_2, false);
	}

	if (unlikely(t->tag == TYPE_TAG_flat_array)) {
		if (fused) {
			target = R_SCRATCH_1;
			g(gen_load_constant(ctx, target, type_def(t,flat_array)->n_elements));
			goto do_fused;
		} else if (slot_2 == NO_FRAME_T) {
			g(gen_frame_store_imm(ctx, OP_SIZE_INT, slot_r, 0, (unsigned)type_def(t,flat_array)->n_elements));
		} else {
			g(gen_frame_load_cmp_imm_set_cond(ctx, OP_SIZE_INT, zero_x, slot_2, type_def(t,flat_array)->n_elements, COND_G, slot_r));
		}
		flag_set(ctx, slot_r, false);
	} else {
		g(gen_frame_decompress_slot(ctx, slot_1, R_SCRATCH_1, &reg, escape_label));

		if (offsetof(struct data, u_.array_flat.n_used_entries) != offsetof(struct data, u_.array_slice.n_entries) ||
		    offsetof(struct data, u_.array_flat.n_used_entries) != offsetof(struct data, u_.array_pointers.n_used_entries)) {
			not_reached();
			return false;
		}
		if (DATA_TAG_array_flat != DATA_TAG_array_slice - 1 ||
		    DATA_TAG_array_slice != DATA_TAG_array_pointers - 1 ||
		    DATA_TAG_array_same < DATA_TAG_array_flat ||
		    DATA_TAG_array_btree < DATA_TAG_array_flat ||
		    DATA_TAG_array_incomplete < DATA_TAG_array_flat) {
			not_reached();
			return false;
		}

		g(gen_compare_ptr_tag(ctx, reg, DATA_TAG_array_pointers, COND_A, escape_label, R_SCRATCH_2, false));

		if (slot_2 == NO_FRAME_T) {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
		} else {
			target = R_SCRATCH_1;
		}

#if defined(ARCH_X86) || defined(ARCH_S390)
		if (fused && slot_is_register(ctx, slot_2)) {
			g(gen_address(ctx, reg, offsetof(struct data, u_.array_flat.n_used_entries), ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
			gen_insn(INSN_CMP, OP_SIZE_INT, 0, 1 + COND_IS_LOGICAL(COND_GE));
			gen_one(ctx->registers[slot_2]);
			gen_address_offset();

			g(gen_jump(ctx, offs_false, i_size_cmp(OP_SIZE_INT), COND_GE, -1U, -1U));
			return true;
		}
#endif
		g(gen_address(ctx, reg, offsetof(struct data, u_.array_flat.n_used_entries), ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
		gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
		gen_one(target);
		gen_address_offset();

		if (fused)
do_fused:	{
			enum extend ex = OP_SIZE_INT == i_size_cmp(OP_SIZE_INT) + (unsigned)zero ? garbage : sign_x;
			unsigned reg2;
			if (ARCH_HAS_JMP_2REGS(COND_LE)) {
				g(gen_frame_get(ctx, OP_SIZE_INT, ex, slot_2, R_SCRATCH_2, &reg2));
				g(gen_jump(ctx, offs_false, i_size_cmp(OP_SIZE_INT), COND_LE, target, reg2));
				return true;
			}
#if ARCH_HAS_FLAGS
			g(gen_frame_load_cmp(ctx, OP_SIZE_INT, COND_IS_LOGICAL(COND_LE), ex, false, slot_2, 0, false, target));
			g(gen_jump(ctx, offs_false, i_size_cmp(OP_SIZE_INT), COND_LE, -1U, -1U));
#else
			g(gen_frame_get(ctx, OP_SIZE_INT, ex, slot_2, R_SCRATCH_2, &reg2));
			g(gen_cmp_dest_reg(ctx, i_size_cmp(OP_SIZE_INT), target, reg2, R_CMP_RESULT, 0, COND_G));
			g(gen_jump(ctx, offs_false, OP_SIZE_NATIVE, COND_E, R_CMP_RESULT, -1U));
#endif
		} else if (slot_2 == NO_FRAME_T) {
			g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, target));
		} else {
			g(gen_frame_load_cmp_set_cond(ctx, OP_SIZE_INT, zero_x, slot_2, R_SCRATCH_1, COND_G, slot_r));
		}
		flag_set(ctx, slot_r, false);
	}
	return true;
}

static bool attr_w gen_array_sub(struct codegen_context *ctx, frame_t slot_array, frame_t slot_from, frame_t slot_to, frame_t slot_r, frame_t flags)
{
	const struct type *t = get_type_of_local(ctx, slot_array);
	uint32_t escape_label, upcall_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	upcall_label = alloc_label(ctx);
	if (unlikely(!upcall_label))
		return false;

	if (unlikely(TYPE_IS_FLAT(t))) {
		g(gen_test_1_jz_cached(ctx, slot_array, escape_label));
	}

	g(gen_test_2_cached(ctx, slot_from, slot_to, escape_label));

	if (slot_is_register(ctx, slot_array))
		g(spill(ctx, slot_array));
	if (slot_is_register(ctx, slot_from))
		g(spill(ctx, slot_from));
	if (slot_is_register(ctx, slot_to))
		g(spill(ctx, slot_to));

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_sub), 4, true));

	g(gen_frame_load_raw(ctx, OP_SIZE_SLOT, garbage, slot_array, 0, false, R_ARG0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_frame_load_raw(ctx, OP_SIZE_INT, garbage, slot_from, 0, false, R_ARG1));
	g(gen_upcall_argument(ctx, 1));

	g(gen_frame_load_raw(ctx, OP_SIZE_INT, garbage, slot_to, 0, false, R_ARG2));
	g(gen_upcall_argument(ctx, 2));

	g(gen_load_constant(ctx, R_ARG3, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0));
	g(gen_upcall_argument(ctx, 3));

	if ((flags & OPCODE_FLAG_FREE_ARGUMENT) != 0) {
		g(gen_test_1_cached(ctx, slot_array, upcall_label));
		g(gen_load_constant(ctx, R_ARG3, 0));
		g(gen_upcall_argument(ctx, 3));
	}

	gen_label(upcall_label);
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_sub), 4, true));

	g(gen_jmp_on_zero(ctx, OP_SIZE_SLOT, R_RET0, COND_E, escape_label));

	if (slot_array != slot_r) {
		if (flags & OPCODE_FLAG_FREE_ARGUMENT) {
			g(gen_set_1(ctx, R_FRAME, slot_array, 0, false));
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_array));
			flag_set(ctx, slot_array, false);
		}
	}

	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, false));

	return true;
}

static bool attr_w gen_array_skip(struct codegen_context *ctx, frame_t slot_array, frame_t slot_from, frame_t slot_r, frame_t flags)
{
	const struct type *t = get_type_of_local(ctx, slot_array);
	uint32_t escape_label, upcall_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	upcall_label = alloc_label(ctx);
	if (unlikely(!upcall_label))
		return false;

	if (unlikely(TYPE_IS_FLAT(t))) {
		g(gen_test_1_jz_cached(ctx, slot_array, escape_label));
	}

	g(gen_test_1_cached(ctx, slot_from, escape_label));

	if (slot_is_register(ctx, slot_array))
		g(spill(ctx, slot_array));
	if (slot_is_register(ctx, slot_from))
		g(spill(ctx, slot_from));

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_skip), 3, true));

	g(gen_frame_load_raw(ctx, OP_SIZE_SLOT, garbage, slot_array, 0, false, R_ARG0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_frame_load_raw(ctx, OP_SIZE_INT, garbage, slot_from, 0, false, R_ARG1));
	g(gen_upcall_argument(ctx, 1));

	g(gen_load_constant(ctx, R_ARG2, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0));
	g(gen_upcall_argument(ctx, 2));

	if ((flags & OPCODE_FLAG_FREE_ARGUMENT) != 0) {
		g(gen_test_1_cached(ctx, slot_array, upcall_label));
		g(gen_load_constant(ctx, R_ARG2, 0));
		g(gen_upcall_argument(ctx, 2));
	}

	gen_label(upcall_label);
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_skip), 3, true));

	g(gen_jmp_on_zero(ctx, OP_SIZE_SLOT, R_RET0, COND_E, escape_label));

	if (slot_array != slot_r) {
		if (flags & OPCODE_FLAG_FREE_ARGUMENT) {
			g(gen_set_1(ctx, R_FRAME, slot_array, 0, false));
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_array));
			flag_set(ctx, slot_array, false);
		}
	}

	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, false));

	return true;
}

static bool attr_w gen_array_append(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r, frame_t flags)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(TYPE_IS_FLAT(get_type_of_local(ctx, slot_1))))
		g(gen_test_1_jz_cached(ctx, slot_1, escape_label));
	if (unlikely(TYPE_IS_FLAT(get_type_of_local(ctx, slot_2))))
		g(gen_test_1_jz_cached(ctx, slot_2, escape_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, zero_x, slot_1, 0, false, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, slot_1, escape_label));
	g(gen_frame_load(ctx, OP_SIZE_SLOT, zero_x, slot_2, 0, false, R_SCRATCH_2));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_2, slot_2, escape_label));

	g(gen_compare_da_tag(ctx, R_SCRATCH_1, DATA_TAG_array_incomplete, COND_E, escape_label, R_SCRATCH_1));
	g(gen_compare_da_tag(ctx, R_SCRATCH_2, DATA_TAG_array_incomplete, COND_E, escape_label, R_SCRATCH_2));

	g(gen_frame_get_pointer(ctx, slot_2, (flags & OPCODE_FLAG_FREE_ARGUMENT_2) != 0, R_SAVED_1));
	g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_SCRATCH_1));
	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_join), 2, true));
	g(gen_mov(ctx, i_size(OP_SIZE_SLOT), R_ARG0, R_SCRATCH_1));
	g(gen_upcall_argument(ctx, 0));
	g(gen_mov(ctx, i_size(OP_SIZE_SLOT), R_ARG1, R_SAVED_1));
	g(gen_upcall_argument(ctx, 1));
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_join), 2, true));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0, false, false));
	return true;
}

static bool attr_w gen_array_append_one_flat(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r, frame_t flags)
{
	uint32_t escape_label;
	unsigned reg;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(!(flags & OPCODE_FLAG_FREE_ARGUMENT))) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	g(gen_test_1_jz_cached(ctx, slot_1, escape_label));
	g(gen_test_1_cached(ctx, slot_2, escape_label));
	flag_set(ctx, slot_2, false);

	g(gen_frame_decompress_slot(ctx, slot_1, R_SAVED_1, &reg, escape_label));

	g(gen_compare_tag_and_refcount(ctx, reg, DATA_TAG_array_flat, escape_label, R_SCRATCH_1));

	g(gen_address(ctx, reg, offsetof(struct data, u_.array_flat.n_used_entries), ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_check_array_len(ctx, reg, true, R_SCRATCH_2, COND_E, escape_label));

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_INT), ALU_ADD, R_SCRATCH_1, R_SCRATCH_2, 1, 0));

	g(gen_address(ctx, reg, offsetof(struct data, u_.array_flat.n_used_entries), IMM_PURPOSE_STR_OFFSET, OP_SIZE_INT));
	gen_insn(INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_1);

	g(gen_scaled_array_store(ctx, reg, data_array_offset, slot_2));

	if (slot_1 != slot_r) {
#if !defined(POINTER_COMPRESSION)
		g(gen_frame_set_pointer(ctx, slot_r, reg, false, true));
#else
		unsigned target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SAVED_1);
		g(gen_compress_pointer(ctx, target, reg));
		g(gen_frame_set_pointer(ctx, slot_r, target, false, true));
#endif
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
		g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
		flag_set(ctx, slot_1, false);
	}

	return true;
}

static bool attr_w gen_array_append_one(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r, frame_t flags)
{
	uint32_t escape_label;
	unsigned reg;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(!(flags & OPCODE_FLAG_FREE_ARGUMENT))) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	g(gen_test_1_jz_cached(ctx, slot_1, escape_label));

	g(gen_frame_decompress_slot(ctx, slot_1, R_SAVED_1, &reg, escape_label));

	g(gen_compare_tag_and_refcount(ctx, reg, DATA_TAG_array_pointers, escape_label, R_SCRATCH_1));

	g(gen_address(ctx, reg, offsetof(struct data, u_.array_pointers.n_used_entries), ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_one(R_SAVED_2);
	gen_address_offset();

	g(gen_check_array_len(ctx, reg, true, R_SAVED_2, COND_E, escape_label));

	g(gen_frame_get_pointer(ctx, slot_2, (flags & OPCODE_FLAG_FREE_ARGUMENT_2) != 0, R_SCRATCH_2));

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_INT), ALU_ADD, R_SCRATCH_1, R_SAVED_2, 1, 0));

	g(gen_address(ctx, reg, offsetof(struct data, u_.array_pointers.n_used_entries), IMM_PURPOSE_STR_OFFSET, OP_SIZE_INT));
	gen_insn(INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_1);

	g(gen_address(ctx, reg, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_3);
	gen_address_offset();

	g(gen_scaled_array_address(ctx, slot_size, R_SAVED_2, R_SCRATCH_3, R_SAVED_2, 0));

	gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SAVED_2);
	gen_eight(0);
	gen_one(R_SCRATCH_2);

	if (slot_1 != slot_r) {
#if !defined(POINTER_COMPRESSION)
		g(gen_frame_set_pointer(ctx, slot_r, reg, false, true));
#else
		unsigned target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SAVED_1);
		g(gen_compress_pointer(ctx, target, reg));
		g(gen_frame_set_pointer(ctx, slot_r, target, false, true));
#endif
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
		g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
		flag_set(ctx, slot_1, false);
	}

	return true;
}

static bool attr_w gen_io(struct codegen_context *ctx, frame_t code, frame_t slot_1, frame_t slot_2, frame_t slot_3)
{
	uint32_t reload_label, escape_label;
	frame_t i;

	reload_label = alloc_reload_label(ctx);
	if (unlikely(!reload_label))
		return false;

	if (ctx->var_aux) {
		mem_free(ctx->var_aux);
		ctx->var_aux = NULL;
	}
	ctx->var_aux = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, slot_1 + slot_2, sizeof(frame_t), &ctx->err);
	if (unlikely(!ctx->var_aux))
		return false;

	for (i = 0; i < slot_1 + slot_2; i++)
		ctx->var_aux[i] = get_uint32(ctx);
	for (i = 0; i < slot_3; i++)
		get_uint32(ctx);

	for (i = 0; i < slot_2; i++) {
		frame_t input_slot = ctx->var_aux[slot_1 + i];
		if (slot_is_register(ctx, input_slot))
			g(spill(ctx, input_slot));
	}

	/*gen_insn(INSN_JMP, 0, 0, 0); gen_four(alloc_escape_label(ctx));*/

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_io), 3, true));
	g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_ARG0, R_FRAME));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, ctx->instr_start - da(ctx->fn,function)->code));
	g(gen_upcall_argument(ctx, 1));

	g(gen_load_constant(ctx, R_ARG2, ((uint32_t)code << 24) | ((uint32_t)slot_1 << 16) | ((uint32_t)slot_2 << 8) | slot_3));
	g(gen_upcall_argument(ctx, 2));
	/*debug("arg2: %08x", ((uint32_t)code << 24) | ((uint32_t)slot_1 << 16) | ((uint32_t)slot_2 << 8) | slot_3);*/

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_io), 3, true));
	g(gen_sanitize_returned_pointer(ctx, R_RET0));
	g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_ADDRESS, R_RET0, ptr_to_num(POINTER_FOLLOW_THUNK_GO), COND_NE, reload_label, -1));

	for (i = 0; i < slot_1; i++) {
		frame_t output_slot = ctx->var_aux[i];
		flag_set_unknown(ctx, output_slot);
	}

	escape_label = alloc_escape_label_for_ip(ctx, ctx->current_position);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_variables(ctx, ctx->var_aux, slot_1, escape_label));

	return true;
}
