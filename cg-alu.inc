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

static bool attr_w gen_jump(struct codegen_context *ctx, int32_t jmp_offset, unsigned op_size, unsigned cond, unsigned reg1, unsigned reg2);

static bool attr_w gen_alu_upcall(struct codegen_context *ctx, size_t upcall, unsigned op_size, frame_t slot_1, frame_t slot_2, frame_t slot_r, uint32_t label_ovf)
{
	if (slot_is_register(ctx, slot_1))
		g(spill(ctx, slot_1));
	if (slot_2 != NO_FRAME_T && slot_is_register(ctx, slot_2))
		g(spill(ctx, slot_2));
	if (frame_t_is_const(slot_2)) {
		size_t x_offs = offsetof(struct cg_upcall_vector_s, INT_binary_const_int8_t) + op_size * sizeof(void (*)(void));
		g(gen_upcall_start(ctx, x_offs, 4));
		g(gen_frame_address(ctx, slot_1, 0, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_load_constant(ctx, R_ARG1, frame_t_get_const(slot_2)));
		g(gen_upcall_argument(ctx, 1));
		g(gen_frame_address(ctx, slot_r, 0, R_ARG2));
		g(gen_upcall_argument(ctx, 2));
		g(gen_get_upcall_pointer(ctx, upcall, R_ARG3));
		g(gen_upcall_argument(ctx, 3));
		g(gen_upcall(ctx, x_offs, 4));
	} else if (slot_2 != NO_FRAME_T) {
		g(gen_upcall_start(ctx, upcall, 3));
		g(gen_frame_address(ctx, slot_1, 0, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_frame_address(ctx, slot_2, 0, R_ARG1));
		g(gen_upcall_argument(ctx, 1));
		g(gen_frame_address(ctx, slot_r, 0, R_ARG2));
		g(gen_upcall_argument(ctx, 2));
		g(gen_upcall(ctx, upcall, 3));
	} else {
		g(gen_upcall_start(ctx, upcall, 2));
		g(gen_frame_address(ctx, slot_1, 0, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_frame_address(ctx, slot_r, 0, R_ARG1));
		g(gen_upcall_argument(ctx, 1));
		g(gen_upcall(ctx, upcall, 2));
	}
	if (slot_is_register(ctx, slot_r))
		g(unspill(ctx, slot_r));
	if (label_ovf)
		g(gen_jmp_on_zero(ctx, OP_SIZE_1, R_RET0, COND_E, label_ovf));
	return true;
}

static bool attr_w gen_alu_typed_upcall(struct codegen_context *ctx, size_t upcall, unsigned op_size, frame_t slot_1, frame_t slot_2, frame_t slot_r, uint32_t label_ovf)
{
	upcall += op_size * sizeof(void (*)(void));
	return gen_alu_upcall(ctx, upcall, op_size, slot_1, slot_2, slot_r, label_ovf);
}

#define MODE_FIXED		0
#define MODE_INT		1
#define MODE_REAL		2
#define MODE_BOOL		3
#define MODE_ARRAY_LEN_GT	4

static bool attr_w gen_alu(struct codegen_context *ctx, unsigned mode, unsigned op_size, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_2, frame_t slot_r)
{
	unsigned alu;
	bool sgn, mod;
	unsigned reg1, reg2, reg3, target;
	switch (mode) {
		case MODE_FIXED: switch (op) {
			case OPCODE_FIXED_OP_add:		alu = ALU_ADD; goto do_alu;
			case OPCODE_FIXED_OP_subtract:		alu = ALU_SUB; goto do_alu;
			case OPCODE_FIXED_OP_multiply:		goto do_multiply;
			case OPCODE_FIXED_OP_divide:
			case OPCODE_FIXED_OP_divide_alt1:	sgn = true; mod = false; goto do_divide;
			case OPCODE_FIXED_OP_udivide:
			case OPCODE_FIXED_OP_udivide_alt1:	sgn = false; mod = false; goto do_divide;
			case OPCODE_FIXED_OP_modulo:
			case OPCODE_FIXED_OP_modulo_alt1:	sgn = true; mod = true; goto do_divide;
			case OPCODE_FIXED_OP_umodulo:
			case OPCODE_FIXED_OP_umodulo_alt1:	sgn = false; mod = true; goto do_divide;
			case OPCODE_FIXED_OP_power:		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_binary_power_int8_t), op_size, slot_1, slot_2, slot_r, 0);
			case OPCODE_FIXED_OP_and:		alu = ALU_AND; goto do_alu;
			case OPCODE_FIXED_OP_or:		alu = ALU_OR; goto do_alu;
			case OPCODE_FIXED_OP_xor:		alu = ALU_XOR; goto do_alu;
			case OPCODE_FIXED_OP_shl:		alu = ROT_SHL; goto do_shift;
			case OPCODE_FIXED_OP_shr:		alu = ROT_SAR; goto do_shift;
			case OPCODE_FIXED_OP_ushr:		alu = ROT_SHR; goto do_shift;
			case OPCODE_FIXED_OP_rol:		alu = ROT_ROL; goto do_shift;
			case OPCODE_FIXED_OP_ror:		alu = ROT_ROR; goto do_shift;
			case OPCODE_FIXED_OP_bts:		alu = BTX_BTS; goto do_bt;
			case OPCODE_FIXED_OP_btr:		alu = BTX_BTR; goto do_bt;
			case OPCODE_FIXED_OP_btc:		alu = BTX_BTC; goto do_bt;
			case OPCODE_FIXED_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_FIXED_OP_not_equal:		alu = COND_NE; goto do_compare;
			case OPCODE_FIXED_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_FIXED_OP_less_equal:	alu = COND_LE; goto do_compare;
			case OPCODE_FIXED_OP_greater:		alu = COND_G; goto do_compare;
			case OPCODE_FIXED_OP_greater_equal:	alu = COND_GE; goto do_compare;
			case OPCODE_FIXED_OP_uless:		alu = COND_B; goto do_compare;
			case OPCODE_FIXED_OP_uless_equal:	alu = COND_BE; goto do_compare;
			case OPCODE_FIXED_OP_ugreater:		alu = COND_A; goto do_compare;
			case OPCODE_FIXED_OP_ugreater_equal:	alu = COND_AE; goto do_compare;
			case OPCODE_FIXED_OP_bt:		alu = BTX_BT; goto do_bt;
			default:				internal(file_line, "gen_alu: unsupported fixed operation %u", op);
		}
		case MODE_INT: switch (op) {
			case OPCODE_INT_OP_add:			alu = ALU_ADD; goto do_alu;
			case OPCODE_INT_OP_subtract:		alu = ALU_SUB; goto do_alu;
			case OPCODE_INT_OP_multiply:		goto do_multiply;
			case OPCODE_INT_OP_divide:
			case OPCODE_INT_OP_divide_alt1:		sgn = true; mod = false; goto do_divide;
			case OPCODE_INT_OP_modulo:
			case OPCODE_INT_OP_modulo_alt1:		sgn = true; mod = true; goto do_divide;
			case OPCODE_INT_OP_power:		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_binary_power_int8_t), op_size, slot_1, slot_2, slot_r, label_ovf);
			case OPCODE_INT_OP_and:			alu = ALU_AND; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_or:			alu = ALU_OR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_xor:			alu = ALU_XOR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_shl:			alu = ROT_SHL; goto do_shift;
			case OPCODE_INT_OP_shr:			alu = ROT_SAR; goto do_shift;
			case OPCODE_INT_OP_bts:			alu = BTX_BTS; goto do_bt;
			case OPCODE_INT_OP_btr:			alu = BTX_BTR; goto do_bt;
			case OPCODE_INT_OP_btc:			alu = BTX_BTC; goto do_bt;
			case OPCODE_INT_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_INT_OP_not_equal:		alu = COND_NE; goto do_compare;
			case OPCODE_INT_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_INT_OP_less_equal:		alu = COND_LE; goto do_compare;
			case OPCODE_INT_OP_greater:		alu = COND_G; goto do_compare;
			case OPCODE_INT_OP_greater_equal:	alu = COND_GE; goto do_compare;
			case OPCODE_INT_OP_bt:			alu = BTX_BT; goto do_bt;
			default:				internal(file_line, "gen_alu: unsupported int operation %u", op);
		}
		case MODE_BOOL: switch (op) {
			case OPCODE_BOOL_OP_and:		alu = ALU_AND; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_or:			alu = ALU_OR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_BOOL_OP_not_equal:		alu = ALU_XOR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_BOOL_OP_less_equal:		alu = COND_LE; goto do_compare;
			case OPCODE_BOOL_OP_greater:		alu = COND_G; goto do_compare;
			case OPCODE_BOOL_OP_greater_equal:	alu = COND_GE; goto do_compare;
			default:				internal(file_line, "gen_alu: unsupported bool operation %u", op);
		}
	}
	internal(file_line, "gen_alu: unsupported mode %u", mode);

	/*******
	 * ALU *
	 *******/
do_alu: {
		size_t attr_unused offset;
		uint8_t attr_unused long_imm;
		unsigned first_flags;
		unsigned second_flags;
		unsigned second_alu;
		unsigned attr_unused op_size_flags;
		bool c;
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
#if !defined(ARCH_X86) && !defined(ARCH_ARM) && !defined(ARCH_PARISC) && !defined(ARCH_POWER) && !defined(ARCH_SPARC32)
			if (mode == MODE_FIXED) {
				if (alu == ALU_ADD) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_add_,TYPE_INT_MAX)), op_size, slot_1, slot_2, slot_r, 0));
					return true;
				} else if (alu == ALU_SUB) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_subtract_,TYPE_INT_MAX)), op_size, slot_1, slot_2, slot_r, 0));
					return true;
				}
			} else if (mode == MODE_INT) {
				if (alu == ALU_ADD) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_binary_add_,TYPE_INT_MAX)), op_size, slot_1, slot_2, slot_r, label_ovf));
					return true;
				} else if (alu == ALU_SUB) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_binary_subtract_,TYPE_INT_MAX)), op_size, slot_1, slot_2, slot_r, label_ovf));
					return true;
				}
			}
#endif
			first_flags = alu == ALU_ADD || alu == ALU_SUB ? 2 : 0;
			second_flags = mode == MODE_INT ? 1 : 0;
			second_alu = alu == ALU_ADD ? ALU_ADC : alu == ALU_SUB ? ALU_SBB : alu;
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
#if defined(ARCH_X86)
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, alu, first_flags, slot_2, lo_word(OP_SIZE_NATIVE), true, R_SCRATCH_1));
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, second_alu, second_flags, slot_2, hi_word(OP_SIZE_NATIVE), true, R_SCRATCH_2));
#else
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_2, 0, R_SCRATCH_3, R_SCRATCH_4));
			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, alu, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3, first_flags));
#if defined(ARCH_PARISC)
			if (mode == MODE_INT) {
				gen_insn(INSN_ALU_FLAGS_TRAP, OP_SIZE_NATIVE, second_alu, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, second_alu, false, false, 0));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_4);
				gen_four(label_ovf);
			} else
#endif
			{
				gen_insn(first_flags ? INSN_ALU_FLAGS : INSN_ALU, OP_SIZE_NATIVE, second_alu, second_flags | ALU_WRITES_FLAGS(OP_SIZE_NATIVE, second_alu, false, false, 0));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_4);
			}
#endif
#if !defined(ARCH_PARISC)
			if (mode == MODE_INT) {
				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_O, 0);
				gen_four(label_ovf);
			}
#endif
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
			return true;
		}

		if (((ARCH_HAS_FLAGS && i_size_cmp(op_size) == op_size + zero) || ARCH_SUPPORTS_TRAPS(op_size)) && slot_2 == slot_r && slot_1 != slot_2 && alu_is_commutative(alu)) {
			frame_t x = slot_1;
			slot_1 = slot_2;
			slot_2 = x;
		}
		if (((ARCH_HAS_FLAGS && i_size_cmp(op_size) == op_size + zero) || ARCH_SUPPORTS_TRAPS(op_size)) && slot_1 == slot_r && (slot_1 != slot_2 || mode != MODE_INT)
#if defined(ARCH_POWER)
			&& op_size == OP_SIZE_NATIVE
#endif
		    ) {
			struct cg_exit *ce;
			unsigned undo_alu = alu == ALU_ADD ? ALU_SUB : ALU_ADD;
			if (slot_is_register(ctx, slot_1)) {
				unsigned reg1 = ctx->registers[slot_1];
				if (slot_is_register(ctx, slot_2)
#if !defined(ARCH_POWER)
				    || frame_t_is_const(slot_2)
#endif
				    ) {
					unsigned reg2 = frame_t_is_const(slot_2) ? 0xff /* avoid warning */ : ctx->registers[slot_2];
					if (mode == MODE_INT && ARCH_SUPPORTS_TRAPS(op_size)) {
						if (frame_t_is_const(slot_2))
							g(gen_imm(ctx, frame_t_get_const(slot_2), alu_trap_purpose(alu) | (alu_purpose(undo_alu) << 8), i_size(op_size)));
						gen_insn(INSN_ALU_TRAP, op_size, alu, ALU_WRITES_FLAGS(op_size, alu, false, frame_t_is_const(slot_2) && is_imm(), ctx->const_imm));
						gen_one(reg1);
						gen_one(reg1);
						if (frame_t_is_const(slot_2))
							gen_imm_offset();
						else
							gen_one(reg2);
						if (ARCH_TRAP_BEFORE) {
							gen_four(label_ovf);
							return true;
						} else {
							ce = alloc_undo_label(ctx);
							if (unlikely(!ce))
								return false;
							gen_four(ce->undo_label);
							goto do_undo_opcode;
						}
					}
					if (frame_t_is_const(slot_2))
						g(gen_imm(ctx, frame_t_get_const(slot_2), alu_purpose(alu) | (alu_purpose(undo_alu) << 8), i_size(op_size)));
					gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(i_size(op_size)), i_size(op_size), alu, ALU_WRITES_FLAGS(i_size(op_size), alu, false, frame_t_is_const(slot_2) && is_imm(), ctx->const_imm) | (mode == MODE_INT));
					gen_one(reg1);
					gen_one(reg1);
					if (frame_t_is_const(slot_2))
						gen_imm_offset();
					else
						gen_one(reg2);
					if (mode == MODE_INT) {
						size_t m;
						ce = alloc_undo_label(ctx);
						if (unlikely(!ce))
							return false;
						gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
						gen_four(ce->undo_label);
do_undo_opcode:
						ce->undo_opcode = INSN_ALU + ARCH_PARTIAL_ALU(i_size(op_size));
						ce->undo_op_size = i_size(op_size);
						ce->undo_aux = undo_alu;
						ce->undo_writes_flags = ALU_WRITES_FLAGS(i_size(op_size), undo_alu, false, frame_t_is_const(slot_2) && is_imm(), ctx->const_imm);
						m = mark_params(ctx);
						gen_one(reg1);
						gen_one(reg1);
						if (frame_t_is_const(slot_2))
							gen_imm_offset();
						else
							gen_one(reg2);
						copy_params(ctx, ce, m);
					}
					return true;
				}
#if defined(ARCH_S390) || defined(ARCH_X86)
				else if (!frame_t_is_const(slot_2)) {
					size_t m;
					int64_t offset = (size_t)slot_2 * slot_size;
					g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, i_size(op_size)));
					gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(i_size(op_size)), i_size(op_size), alu, ALU_WRITES_FLAGS(i_size(op_size), alu, true, false, 0) | (mode == MODE_INT));
					gen_one(reg1);
					gen_one(reg1);
					gen_address_offset();
					if (mode == MODE_INT) {
						ce = alloc_undo_label(ctx);
						if (unlikely(!ce))
							return false;
						ce->undo_opcode = INSN_ALU + ARCH_PARTIAL_ALU(i_size(op_size));
						ce->undo_op_size = i_size(op_size);
						ce->undo_aux = undo_alu;
						ce->undo_writes_flags = ALU_WRITES_FLAGS(i_size(op_size), undo_alu, true, false, 0);
						m = mark_params(ctx);
						gen_one(reg1);
						gen_one(reg1);
						gen_address_offset();
						copy_params(ctx, ce, m);
						gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
						gen_four(ce->undo_label);
					}
					return true;
				}
#endif
			}
#if defined(ARCH_X86)
			else {
				unsigned reg2;
				size_t m;
				int64_t offset = (size_t)slot_1 * slot_size;
				if (!frame_t_is_const(slot_2))
					g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_1, &reg2));
				g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, i_size(op_size)));
				if (frame_t_is_const(slot_2))
					g(gen_imm(ctx, frame_t_get_const(slot_2), alu_purpose(alu) | (alu_purpose(undo_alu) << 8), i_size(op_size)));
				gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(op_size), i_size(op_size), alu, ALU_WRITES_FLAGS(i_size(op_size), undo_alu, true, frame_t_is_const(slot_2) && is_imm(), ctx->const_imm) | (mode == MODE_INT));
				gen_address_offset();
				gen_address_offset();
				if (frame_t_is_const(slot_2))
					gen_imm_offset();
				else
					gen_one(reg2);
				if (mode == MODE_INT) {
					ce = alloc_undo_label(ctx);
					if (unlikely(!ce))
						return false;
					ce->undo_opcode = INSN_ALU + ARCH_PARTIAL_ALU(op_size);
					ce->undo_op_size = i_size(op_size);
					ce->undo_aux = undo_alu;
					ce->undo_writes_flags = ALU_WRITES_FLAGS(i_size(op_size), undo_alu, true, frame_t_is_const(slot_2) && is_imm(), ctx->const_imm);
					m = mark_params(ctx);
					gen_address_offset();
					gen_address_offset();
					if (frame_t_is_const(slot_2))
						gen_imm_offset();
					else
						gen_one(reg2);
					copy_params(ctx, ce, m);
					gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
					gen_four(ce->undo_label);
				}
				return true;
			}
#endif
		}

#if defined(ARCH_X86)
		if (1)
#elif defined(ARCH_S390)
		if (op_size >= OP_SIZE_4)
#elif ARCH_HAS_FLAGS && !defined(ARCH_POWER)
		if (op_size == i_size(op_size) + (unsigned)zero && frame_t_is_const(slot_2))
#else
		if (mode != MODE_INT && op_size == i_size(op_size) + (unsigned)zero && frame_t_is_const(slot_2))
#endif
		{
			if (mode == MODE_INT) {
				target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			} else {
				target = gen_frame_target(ctx, slot_r, NO_FRAME_T, slot_2, R_SCRATCH_1);
			}
			g(gen_frame_load(ctx, op_size, garbage, slot_1, 0, false, target));
			g(gen_frame_load_op(ctx, op_size, garbage, alu, mode == MODE_INT, slot_2, 0, false, target));
			goto check_ovf_store;
		}
		op_size_flags = !ARCH_HAS_FLAGS && !ARCH_SUPPORTS_TRAPS(op_size) ? OP_SIZE_NATIVE : OP_SIZE_4;
#if defined(ARCH_POWER)
		op_size_flags = OP_SIZE_NATIVE;
#endif
		g(gen_frame_get(ctx, op_size, mode == MODE_INT && (op_size < op_size_flags || ARCH_SUPPORTS_TRAPS(op_size)) ? sign_x : garbage, slot_1, R_SCRATCH_1, &reg1));
		if (frame_t_is_const(slot_2)
#if defined(ARCH_POWER)
			&& 0
#endif
			) {
			reg2 = 0xff;
			c = true;
		} else {
			g(gen_frame_get(ctx, op_size, mode == MODE_INT && (op_size < op_size_flags || ARCH_SUPPORTS_TRAPS(op_size)) ? sign_x : garbage, slot_2, R_SCRATCH_2, &reg2));
			c = false;
		}
#if !ARCH_HAS_FLAGS
		if (mode == MODE_INT && op_size >= OP_SIZE_4) {
			if (ARCH_SUPPORTS_TRAPS(op_size)) {
				target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
				if (c)
					g(gen_imm(ctx, frame_t_get_const(slot_2), alu_trap_purpose(alu), op_size));
				gen_insn(INSN_ALU_TRAP, op_size, alu, ALU_WRITES_FLAGS(op_size, alu, false, c && is_imm(), ctx->const_imm));
				gen_one(target);
				gen_one(reg1);
				if (c)
					gen_imm_offset();
				else
					gen_one(reg2);
				gen_four(label_ovf);
				g(gen_frame_store(ctx, op_size, slot_r, 0, target));
				return true;
			}
			if (op_size >= OP_SIZE_NATIVE) {
				target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_3);
				if (c)
					g(gen_3address_alu_imm(ctx, i_size(op_size), alu, target, reg1, frame_t_get_const(slot_2), 0));
				else
					g(gen_3address_alu(ctx, i_size(op_size), alu, target, reg1, reg2, 0));
#if defined(ARCH_IA64)
				if (c) {
					g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_1, reg1, frame_t_get_const(slot_2), 0));
					g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_2, target, frame_t_get_const(slot_2), 0));
				} else {
					g(gen_3address_alu(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_1, reg1, reg2, 0));
					g(gen_3address_alu(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_2, target, reg2, 0));
				}
				if (alu == ALU_ADD) {
					g(gen_3address_alu(ctx, i_size(op_size), ALU_ANDN, R_SCRATCH_1, R_SCRATCH_2, R_SCRATCH_1, 0));
				} else {
					g(gen_3address_alu(ctx, i_size(op_size), ALU_ANDN, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, 0));
				}
				g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), R_SCRATCH_1, R_SCRATCH_1, COND_S, label_ovf));
#else
				if (c) {
					g(gen_cmp_test_jmp(ctx, INSN_CMP, i_size(op_size), reg1, target, (frame_t_get_const(slot_2) >= 0) ^ (alu != ALU_ADD) ? COND_G : COND_L, label_ovf));
				} else {
					gen_insn(INSN_CMP_DEST_REG, i_size(op_size), COND_L, 0);
					gen_one(R_SCRATCH_1);
					if (alu == ALU_ADD) {
						gen_one(target);
						gen_one(reg1);
					} else {
						gen_one(reg1);
						gen_one(target);
					}

					g(gen_imm(ctx, 0, IMM_PURPOSE_CMP, i_size(op_size)));
					gen_insn(INSN_CMP_DEST_REG, i_size(op_size), COND_L, 0);
					gen_one(R_SCRATCH_2);
					gen_one(reg2);
					gen_imm_offset();

					g(gen_cmp_test_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_1, R_SCRATCH_2, COND_NE, label_ovf));
				}
#endif
				g(gen_frame_store(ctx, op_size, slot_r, 0, target));
				return true;
			}
		}
#endif
		if (mode == MODE_INT) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
		} else if (!ARCH_IS_3ADDRESS(alu, mode == MODE_INT && op_size >= op_size_flags) && !alu_is_commutative(alu)) {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, slot_2, R_SCRATCH_1);
		} else {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
		}
		if (c) {
			g(gen_3address_alu_imm(ctx, i_size(op_size), alu, target, reg1, frame_t_get_const(slot_2), mode == MODE_INT && op_size >= op_size_flags));
		} else {
			g(gen_3address_alu(ctx, i_size(op_size), alu, target, reg1, reg2, mode == MODE_INT && op_size >= op_size_flags));
		}

		if (mode == MODE_INT && unlikely(op_size < op_size_flags)) {
			g(gen_cmp_extended(ctx, op_size_flags, op_size, target, R_SCRATCH_2, label_ovf));
		} else
check_ovf_store:
		if (mode == MODE_INT) {
			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}

	/************
	 * MULTIPLY *
	 ************/
do_multiply: {
		size_t attr_unused offset;
		uint8_t attr_unused long_imm;
		if (unlikely(op_size > OP_SIZE_NATIVE) || unlikely(!ARCH_HAS_MUL)) {
			if (mode == MODE_INT) {
				g(gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_binary_multiply_int8_t), op_size, slot_1, slot_2, slot_r, label_ovf));
				return true;
			}
#if defined(ARCH_X86)
			g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_1, hi_word(OP_SIZE_NATIVE), true, R_CX));
			g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_2, hi_word(OP_SIZE_NATIVE), true, R_AX));
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, ALU_MUL, true, slot_2, lo_word(OP_SIZE_NATIVE), true, R_CX));
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, ALU_MUL, true, slot_1, lo_word(OP_SIZE_NATIVE), true, R_AX));
			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, R_CX, R_CX, R_AX, 0));
			g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_2, lo_word(OP_SIZE_NATIVE), true, R_AX));

			offset = (size_t)slot_1 * slot_size + lo_word(OP_SIZE_NATIVE);
			g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
			gen_insn(INSN_MUL_L, OP_SIZE_NATIVE, 0, 1);
			gen_one(R_AX);
			gen_one(R_DX);
			gen_one(R_AX);
			gen_address_offset();

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, R_DX, R_DX, R_CX, 0));

			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_AX, R_DX));

			return true;
#elif defined(ARCH_ARM32)
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_2, 0, R_SCRATCH_3, R_SCRATCH_4));

			g(gen_mov(ctx, OP_SIZE_NATIVE, R_SCRATCH_NA_1, R_SCRATCH_1));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_MUL, R_SCRATCH_4, R_SCRATCH_1, R_SCRATCH_4, 0));

			gen_insn(INSN_MADD, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_4);

			gen_insn(INSN_MUL_L, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_3);

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_4, 0));

			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));

			return true;
#elif defined(ARCH_ARM64)
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_2, 0, R_SCRATCH_3, R_SCRATCH_4));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_UMULH, R_SCRATCH_NA_1, R_SCRATCH_1, R_SCRATCH_3, 0));

			gen_insn(INSN_MADD, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_NA_1);

			gen_insn(INSN_MADD, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_NA_1);

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_MUL, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3, 0));

			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));

			return true;
#else
			g(gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_binary_multiply_int8_t), op_size, slot_1, slot_2, slot_r, 0));
			return true;
#endif
		}

#if defined(ARCH_X86)
		if (mode == MODE_INT) {
			if (op_size != OP_SIZE_1 && slot_r == slot_1 && slot_is_register(ctx, slot_1)) {
				struct cg_exit *ce;
				target = ctx->registers[slot_1];
				g(gen_mov(ctx, op_size, R_SCRATCH_1, target));
				g(gen_frame_load_op(ctx, op_size, garbage, ALU_MUL, mode == MODE_INT, slot_2, 0, false, target));
				ce = alloc_undo_label(ctx);
				if (unlikely(!ce))
					return false;
				ce->undo_opcode = INSN_MOV;
				ce->undo_op_size = op_size;
				ce->undo_aux = 0;
				ce->undo_writes_flags = 0;
				ce->undo_parameters[0] = target;
				ce->undo_parameters[1] = R_SCRATCH_1;
				ce->undo_parameters_len = 2;
				gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
				gen_four(ce->undo_label);
				return true;
			}
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
		} else {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, slot_2, R_SCRATCH_1);
		}
		if (op_size == OP_SIZE_1)
			target = R_SCRATCH_1;
		g(gen_frame_load(ctx, op_size, garbage, slot_1, 0, false, target));
		if (op_size == OP_SIZE_1 && frame_t_is_const(slot_2)) {
			g(gen_load_constant(ctx, R_SCRATCH_3, frame_t_get_const(slot_2)));
			gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(op_size), op_size, ALU_MUL, 1);
			gen_one(target);
			gen_one(target);
			gen_one(R_SCRATCH_3);
		} else {
			g(gen_frame_load_op(ctx, op_size, garbage, ALU_MUL, mode == MODE_INT, slot_2, 0, false, target));
		}
		if (mode == MODE_INT) {
			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_ALPHA)
		if (mode == MODE_INT && ARCH_SUPPORTS_TRAPS(op_size)) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, garbage, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_2, &reg2));

			gen_insn(INSN_ALU_TRAP, op_size, ALU_MUL, ALU_WRITES_FLAGS(op_size, ALU_MUL, false, false, 0));
			gen_one(target);
			gen_one(reg1);
			gen_one(reg2);
			gen_four(label_ovf);
			g(gen_frame_store(ctx, op_size, slot_r, 0, target));

			return true;
		}
#endif
#if defined(ARCH_ARM32)
		if (mode == MODE_INT && op_size == OP_SIZE_4) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_3);
			g(gen_frame_get(ctx, op_size, garbage, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_2, &reg2));

			gen_insn(INSN_MUL_L, OP_SIZE_NATIVE, 0, 0);
			gen_one(target);
			gen_one(R_SCRATCH_4);
			gen_one(reg1);
			gen_one(reg2);

			gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
			gen_one(R_SCRATCH_4);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_ASR | 0x1f);
			gen_one(target);

			gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));

			return true;
		}
#endif
#if defined(ARCH_ARM64)
		if (mode == MODE_INT && op_size == OP_SIZE_4) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, op_size < OP_SIZE_4 ? sign_x : garbage, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, op_size < OP_SIZE_4 ? sign_x : garbage, slot_2, R_SCRATCH_2, &reg2));
			gen_insn(INSN_ALU, OP_SIZE_8, ALU_MUL, ALU_WRITES_FLAGS(OP_SIZE_8, ALU_MUL, false, false, 0));
			gen_one(target);
			gen_one(ARG_EXTENDED_REGISTER);
			gen_one(ARG_EXTEND_SXTW);
			gen_one(reg1);
			gen_one(ARG_EXTENDED_REGISTER);
			gen_one(ARG_EXTEND_SXTW);
			gen_one(reg2);

			gen_insn(INSN_CMP, OP_SIZE_8, 0, 1);
			gen_one(target);
			gen_one(ARG_EXTENDED_REGISTER);
			gen_one(ARG_EXTEND_SXTW);
			gen_one(target);

			gen_insn(INSN_JMP_COND, OP_SIZE_8, COND_NE, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));

			return true;
		}
		if (mode == MODE_INT && op_size == OP_SIZE_8) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, garbage, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_2, &reg2));
			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_SMULH, R_SCRATCH_3, reg1, reg2, 0));

			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_MUL, target, reg1, reg2, 0));

			gen_insn(INSN_CMP, OP_SIZE_8, 0, 1);
			gen_one(R_SCRATCH_3);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_ASR | 0x3f);
			gen_one(target);

			gen_insn(INSN_JMP_COND, OP_SIZE_8, COND_NE, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));

			return true;
		}
#endif
#if defined(ARCH_POWER)
		if (mode == MODE_INT && op_size >= OP_SIZE_4) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, garbage, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_2, &reg2));

			g(gen_3address_alu(ctx, op_size, ALU_MUL, target, reg1, reg2, 1));

			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));

			return true;
		}
#endif
#if defined(ARCH_LOONGARCH64) || (defined(ARCH_MIPS) && MIPS_R6) || defined(ARCH_RISCV64)
		if (mode == MODE_INT && op_size == OP_SIZE_NATIVE) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, garbage, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_2, &reg2));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_SMULH, R_SCRATCH_3, reg1, reg2, 0));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_MUL, target, reg1, reg2, 0));

			g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_4, target, (8U << OP_SIZE_NATIVE) - 1, 0));

			g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_3, R_SCRATCH_4, COND_NE, label_ovf));

			g(gen_frame_store(ctx, OP_SIZE_NATIVE, slot_r, 0, target));

			return true;
		}
#endif
#if defined(ARCH_S390)
		if (mode == MODE_INT && op_size >= OP_SIZE_4 && likely(cpu_test_feature(CPU_FEATURE_misc_insn_ext_2))) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			g(gen_frame_load(ctx, op_size, sign_x, slot_1, 0, false, target));
			g(gen_frame_load_op(ctx, op_size, sign_x, ALU_MUL, 1, slot_2, 0, false, target));

			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
#endif
#if (defined(ARCH_MIPS) && !MIPS_R6) || defined(ARCH_S390)
#if defined(ARCH_MIPS)
		if (mode == MODE_INT && op_size >= OP_SIZE_4)
#endif
#if defined(ARCH_S390)
		if (mode == MODE_INT && op_size == OP_SIZE_4)
#endif
		{
#if defined(ARCH_S390)
			target = R_SCRATCH_1;
			reg1 = R_SCRATCH_1;
			reg2 = R_SCRATCH_3;
			g(gen_frame_load(ctx, op_size, sign_x, slot_1, 0, false, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, sign_x, slot_2, 0, false, R_SCRATCH_3));
#else
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, sign_x, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, sign_x, slot_2, R_SCRATCH_3, &reg2));
#endif
			gen_insn(INSN_MUL_L, op_size, 0, 0);
			gen_one(target);
			gen_one(R_SCRATCH_2);
			gen_one(reg1);
			gen_one(reg2);

			g(gen_3address_rot_imm(ctx, op_size, ROT_SAR, R_SCRATCH_4, target, (8U << op_size) - 1, false));

			g(gen_cmp_test_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_2, R_SCRATCH_4, COND_NE, label_ovf));

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
#endif
		if (mode == MODE_INT && op_size == OP_SIZE_NATIVE) {
			g(gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_binary_multiply_int8_t), op_size, slot_1, slot_2, slot_r, label_ovf));
			return true;
		}

		target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
		if (op_size < OP_SIZE_NATIVE && mode == MODE_INT) {
			g(gen_frame_get(ctx, op_size, sign_x, slot_1, R_SCRATCH_1, &reg1));
			g(gen_frame_get(ctx, op_size, sign_x, slot_2, R_SCRATCH_2, &reg2));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_MUL, target, reg1, reg2, 0));
		} else {
			g(gen_frame_load(ctx, op_size, sign_x, slot_1, 0, false, target));
			g(gen_frame_load_op(ctx, op_size, sign_x, ALU_MUL, 0, slot_2, 0, false, target));
		}

		if (mode == MODE_INT) {
			g(gen_cmp_extended(ctx, OP_SIZE_NATIVE, op_size, target, R_SCRATCH_2, label_ovf));
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));

		return true;
	}

	/**********
	 * DIVIDE *
	 **********/
do_divide: {
		uint32_t attr_unused label_skip = 0;	/* avoid warning */
		uint32_t attr_unused label_skip2 = 0;	/* avoid warning */
		uint32_t attr_unused label_end = 0;	/* avoid warning */
		uint32_t attr_unused label_div_0 = 0;	/* avoid warning */
		unsigned attr_unused divide_alu = 0;	/* avoid warning */
		bool attr_unused have_mod = false;
		bool attr_unused force_sx = false;
		unsigned attr_unused div_op_size = i_size(op_size);
		if (unlikely(op_size > OP_SIZE_NATIVE) || unlikely(!ARCH_HAS_DIV)
#if defined(ARCH_S390)
			|| !(Z || (op_size <= OP_SIZE_4 && sgn))
#endif
		   ) {
			size_t upcall;
			if (mode == MODE_INT) {
				upcall = !mod ? offsetof(struct cg_upcall_vector_s, INT_binary_divide_int8_t) : offsetof(struct cg_upcall_vector_s, INT_binary_modulo_int8_t);
			} else if (sgn) {
				upcall = !mod ? offsetof(struct cg_upcall_vector_s, FIXED_binary_divide_int8_t) : offsetof(struct cg_upcall_vector_s, FIXED_binary_modulo_int8_t);
			} else {
				upcall = !mod ? offsetof(struct cg_upcall_vector_s, FIXED_binary_udivide_int8_t) : offsetof(struct cg_upcall_vector_s, FIXED_binary_umodulo_int8_t);
			}
			g(gen_alu_typed_upcall(ctx, upcall, op_size, slot_1, slot_2, slot_r, mode == MODE_INT ? label_ovf : 0));
			return true;
		}
#if defined(ARCH_X86) || defined(ARCH_S390)
		if (mode == MODE_FIXED) {
			label_skip = alloc_label(ctx);
			if (unlikely(!label_skip))
				return false;
			label_end = alloc_label(ctx);
			if (unlikely(!label_end))
				return false;
			if (sgn) {
				label_skip2 = alloc_label(ctx);
				if (unlikely(!label_skip2))
					return false;
			}
		}
#if defined(ARCH_X86)
		if (R_SCRATCH_1 != R_AX || R_SCRATCH_2 != R_DX || R_SCRATCH_3 != R_CX)
			internal(file_line, "gen_alu: bad scratch registers");
#endif
		g(gen_frame_load(ctx, op_size, sgn ? sign_x : zero_x, slot_1, 0, false, R_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, sgn ? sign_x : zero_x, slot_2, 0, false, R_SCRATCH_3));

		g(gen_jmp_on_zero(ctx, i_size(op_size), R_SCRATCH_3, COND_E, mode == MODE_INT ? label_ovf : label_skip));

		if (sgn) {
			uint64_t val;
			uint32_t label_not_minus_1;
			label_not_minus_1 = alloc_label(ctx);
			if (unlikely(!label_not_minus_1))
				return false;

			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_3, -1, COND_NE, label_not_minus_1));

			val = -(uint64_t)0x80 << (((1 << op_size) - 1) * 8);
			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_1, val, COND_E, mode == MODE_INT ? label_ovf : label_skip2));

			gen_label(label_not_minus_1);
		}

#if defined(ARCH_X86)
		if (op_size >= OP_SIZE_2) {
			if (sgn) {
				gen_insn(INSN_CWD + ARCH_PARTIAL_ALU(op_size), op_size, 0, 0);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_1);
				if (op_size == OP_SIZE_2)
					gen_one(R_SCRATCH_2);
			} else {
				g(gen_3address_alu(ctx, OP_SIZE_4, ALU_XOR, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_2, 0));
			}
		}
		gen_insn(INSN_DIV_L, op_size, sgn, 1);
		gen_one(R_SCRATCH_1);
		gen_one(i_size(op_size) == OP_SIZE_1 ? R_SCRATCH_1 : R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_one(i_size(op_size) == OP_SIZE_1 ? R_SCRATCH_1 : R_SCRATCH_2);
		gen_one(R_SCRATCH_3);
#else
		if (!sgn) {
			g(gen_load_constant(ctx, R_SCRATCH_2, 0));
		} else if (op_size <= OP_SIZE_4) {
			g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_2, R_SCRATCH_1, (1U << (OP_SIZE_NATIVE + 3)) - 1, false));
		}
		gen_insn(INSN_DIV_L, i_size(op_size), sgn, 1);
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_3);
#endif
		if (mod && i_size(op_size) == OP_SIZE_1) {
			g(gen_3address_rot_imm(ctx, OP_SIZE_2, ROT_SHR, R_SCRATCH_1, R_SCRATCH_1, 8, 0));
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		} else if (mod) {
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));
		} else {
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		}
		if (mode == MODE_FIXED) {
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(label_end);

			if (sgn) {
				gen_label(label_skip2);

				if (mod)
					g(gen_frame_clear(ctx, op_size, slot_r));
				else
					g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(label_end);
			}

			gen_label(label_skip);
			if (!mod)
				g(gen_frame_clear(ctx, op_size, slot_r));
			else
				g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			gen_label(label_end);
		}
		return true;
#else
#if defined(ARCH_MIPS)
		have_mod = true;
		div_op_size = maximum(op_size, OP_SIZE_4);
		if (op_size == OP_SIZE_4)
			force_sx = true;
#endif
#if defined(ARCH_POWER)
		have_mod = cpu_test_feature(CPU_FEATURE_v30);
		div_op_size = maximum(op_size, OP_SIZE_4);
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_RISCV64)
		have_mod = true;
		div_op_size = maximum(op_size, OP_SIZE_4);
#endif
		label_end = alloc_label(ctx);
		if (unlikely(!label_end))
			return false;

		g(gen_frame_get(ctx, op_size, (sgn && op_size < i_size(op_size)) || force_sx ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
		g(gen_frame_get(ctx, op_size, (sgn && op_size < i_size(op_size)) || force_sx ? sign_x : zero_x, slot_2, R_SCRATCH_2, &reg2));
		target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_3);

		if (ARCH_PREFERS_SX(op_size) && !sgn && op_size < i_size(op_size)) {
			g(gen_extend(ctx, op_size, zero_x, R_SCRATCH_1, reg1));
			reg1 = R_SCRATCH_1;
			g(gen_extend(ctx, op_size, zero_x, R_SCRATCH_2, reg2));
			reg2 = R_SCRATCH_2;
		}

		if (mode == MODE_INT) {
			g(gen_jmp_on_zero(ctx, i_size(op_size), reg2, COND_E, label_ovf));
			if (sgn) {
				uint64_t val;
				uint32_t label_not_minus_1;
				label_not_minus_1 = alloc_label(ctx);
				if (unlikely(!label_not_minus_1))
					return false;

				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), reg2, -1, COND_NE, label_not_minus_1));

				val = 0xFFFFFFFFFFFFFF80ULL << (((1 << op_size) - 1) * 8);
				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), reg1, val, COND_E, label_ovf));

				gen_label(label_not_minus_1);
			}
		} else {
#if !(defined(ARCH_ARM) && ARM_ASM_DIV_NO_TRAP)
			if (!mod) {
				g(gen_load_constant(ctx, target, 0));
			} else {
				g(gen_mov(ctx, OP_SIZE_NATIVE, target, reg1));
			}
			g(gen_jmp_on_zero(ctx, i_size(op_size), reg2, COND_E, label_end));
			if (sgn) {
				uint64_t val;
				uint32_t label_not_minus_1;
				label_not_minus_1 = alloc_label(ctx);
				if (unlikely(!label_not_minus_1))
					return false;

				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), reg2, -1, COND_NE, label_not_minus_1));

				if (!mod) {
					g(gen_mov(ctx, OP_SIZE_NATIVE, target, reg1));
				} else {
					g(gen_load_constant(ctx, target, 0));
				}

				val = 0xFFFFFFFFFFFFFF80ULL << (((1 << op_size) - 1) * 8);
				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), reg1, val, COND_E, label_end));

				gen_label(label_not_minus_1);
			}
#endif
		}
		if (mod && have_mod) {
			g(gen_3address_alu(ctx, div_op_size, sgn ? ALU_SREM : ALU_UREM, target, reg1, reg2, 0));
		} else {
			g(gen_3address_alu(ctx, div_op_size, sgn ? ALU_SDIV : ALU_UDIV, target, reg1, reg2, 0));
		}

		if (mod && !have_mod) {
#if defined(ARCH_ARM)
			gen_insn(INSN_MADD, i_size(op_size), 1, 0);
			gen_one(target);
			gen_one(target);
			gen_one(reg2);
			gen_one(reg1);
#else
			g(gen_3address_alu(ctx, i_size(op_size), ALU_MUL, R_SCRATCH_2, reg2, target, 0));
			g(gen_3address_alu(ctx, i_size(op_size), ALU_SUB, target, reg1, R_SCRATCH_2, 0));
#endif
		}

		gen_label(label_end);
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
	}
	/*********
	 * SHIFT *
	 *********/
do_shift: {
		bool sx;
		bool must_mask;
		unsigned op_s;
		int64_t cnst = 0;	/* avoid warning */
		bool c = frame_t_is_const(slot_2);
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
			size_t upcall;
			if (mode == MODE_FIXED) {
				switch (alu) {
					case ROT_SHL:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_shl_,TYPE_INT_MAX));
							break;
					case ROT_SAR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_shr_,TYPE_INT_MAX));
							break;
					case ROT_SHR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_ushr_,TYPE_INT_MAX));
							break;
					case ROT_ROL:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_rol_,TYPE_INT_MAX));
							break;
					case ROT_ROR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_ror_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid shift %u", alu);
				}
			} else {
				switch (alu) {
					case ROT_SHL:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_shl_,TYPE_INT_MAX));
							break;
					case ROT_SAR:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_shr_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid shift %u", alu);
				}
			}
			g(gen_alu_upcall(ctx, upcall, op_size, slot_1, slot_2, slot_r, mode == MODE_INT ? label_ovf : 0));
			return true;
		}
		op_s = i_size_rot(op_size);
#if defined(ARCH_X86)
		if (slot_1 == slot_r && !slot_is_register(ctx, slot_1) && !(mode == MODE_INT && alu == ROT_SHL)) {
			int64_t offset = (size_t)slot_1 * slot_size;
			if (c) {
				cnst = frame_t_get_const(slot_2);
				if (mode == MODE_INT) {
					if ((uint64_t)cnst > (8U << op_size) - 1) {
						gen_insn(INSN_JMP, 0, 0, 0);
						gen_four(label_ovf);
						return true;
					}
				} else {
					cnst &= (8U << op_size) - 1;
				}
				g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, op_size));
				gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(op_size), op_size, alu, 1);
				gen_address_offset();
				gen_address_offset();
				gen_one(ARG_IMM);
				gen_eight(cnst);
			} else {
				g(gen_frame_load(ctx, op_size, garbage, slot_2, 0, false, R_SCRATCH_3));
				if (mode == MODE_INT) {
					int64_t imm = (8U << op_size) - 1;
					g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_3, imm, COND_A, label_ovf));
				} else if ((alu != ROT_ROL && alu != ROT_ROR) && op_size < OP_SIZE_4) {
					g(gen_3address_alu_imm(ctx, OP_SIZE_1, ALU_AND, R_SCRATCH_3, R_SCRATCH_3, (8U << op_size) - 1, 0));
				}
				g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, op_size));
				gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(op_size), op_size, alu, 1);
				gen_address_offset();
				gen_address_offset();
				gen_one(R_SCRATCH_3);
			}
			return true;
		}
		if (mode == MODE_INT && alu == ROT_SHL && op_size < OP_SIZE_NATIVE)
			op_s = op_size + 1;
#endif
		must_mask = op_size < ARCH_SHIFT_SIZE;
		sx = (alu == ROT_SAR && op_size < op_s) || (alu == ROT_SHL && op_size < OP_SIZE_NATIVE && mode == MODE_INT);
#if defined(ARCH_MIPS)
		sx |= op_size == OP_SIZE_4;
#endif
		g(gen_frame_get(ctx, op_size, sx ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
		if (c) {
			reg3 = 0xff;	/* avoid warning */
			cnst = frame_t_get_const(slot_2);
		} else
#if defined(ARCH_X86)
		if (!ARCH_IS_3ADDRESS_ROT(alu, op_size)) {
			g(gen_frame_load(ctx, op_size, garbage, slot_2, 0, false, R_SCRATCH_3));
			reg3 = R_SCRATCH_3;
		} else
#endif
		g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_3, &reg3));

		if (ARCH_PREFERS_SX(op_size) && !sx && op_size < op_s) {
			g(gen_extend(ctx, op_size, zero_x, R_SCRATCH_1, reg1));
			reg1 = R_SCRATCH_1;
		}

		if (mode == MODE_INT) {
			int64_t imm = (8U << op_size) - 1;
			if (c) {
				if ((uint64_t)cnst > (uint64_t)imm) {
					gen_insn(INSN_JMP, 0, 0, 0);
					gen_four(label_ovf);
					return true;
				}
			} else {
				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size_cmp(op_size), reg3, imm, COND_A, label_ovf));
			}
		} else {
#if defined(ARCH_ARM)
			if (alu == ROT_ROL) {
				if (c) {
					cnst = -(uint64_t)cnst;
				} else {
					g(gen_2address_alu1(ctx, OP_SIZE_4, ALU1_NEG, R_SCRATCH_3, reg3, 0));
					reg3 = R_SCRATCH_3;
				}
				alu = ROT_ROR;
			}
#endif
#if defined(ARCH_LOONGARCH64)
			if (alu == ROT_ROL && op_size >= OP_SIZE_4) {
				if (c) {
					cnst = -(uint64_t)cnst;
				} else {
					g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NEG, R_SCRATCH_3, reg3, 0));
					reg3 = R_SCRATCH_3;
				}
				alu = ROT_ROR;
			}
#endif
#if defined(ARCH_MIPS)
			if (MIPS_HAS_ROT && alu == ROT_ROL && op_size >= OP_SIZE_4) {
				if (c) {
					cnst = -(uint64_t)cnst;
				} else {
					g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NEG, R_SCRATCH_3, reg3, 0));
					reg3 = R_SCRATCH_3;
				}
				alu = ROT_ROR;
			}
#endif
#if defined(ARCH_POWER)
			if (alu == ROT_ROR && op_size >= OP_SIZE_4) {
				if (c) {
					cnst = -(uint64_t)cnst;
				} else {
					g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NEG, R_SCRATCH_3, reg3, 0));
					reg3 = R_SCRATCH_3;
				}
				alu = ROT_ROL;
			}
#endif
#if defined(ARCH_S390)
			if (Z && alu == ROT_ROR && op_size >= OP_SIZE_4) {
				if (c) {
					cnst = -(uint64_t)cnst;
				} else {
					g(gen_2address_alu1(ctx, OP_SIZE_4, ALU1_NEG, R_SCRATCH_3, reg3, 0));
					reg3 = R_SCRATCH_3;
				}
				alu = ROT_ROL;
			}
#endif
			if (c) {
				cnst &= (8U << op_size) - 1;
			} else if (must_mask) {
				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_4), ALU_AND, R_SCRATCH_3, reg3, (8U << op_size) - 1, 0));
				reg3 = R_SCRATCH_3;
			}
		}

#if defined(ARCH_X86)
		if (mode == MODE_INT && alu == ROT_SHL) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_2);
		} else {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, slot_2, R_SCRATCH_2);
		}
		if (c) {
			g(gen_3address_rot_imm(ctx, op_s, alu, target, reg1, cnst, 0));
		} else  {
			g(gen_3address_rot(ctx, op_s, alu, target, reg1, reg3));
		}

		if (mode == MODE_INT && alu == ROT_SHL) {
			if (op_size < OP_SIZE_NATIVE) {
				gen_insn(INSN_MOVSX, op_size, 0, 0);
				gen_one(R_SCRATCH_4);
				gen_one(target);

				g(gen_cmp_test_jmp(ctx, INSN_CMP, op_s, target, R_SCRATCH_4, COND_NE, label_ovf));
			} else {
				if (c) {
					g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_4, target, cnst, 0));
				} else {
					g(gen_3address_rot(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_4, target, reg3));
				}

				g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, reg1, R_SCRATCH_4, COND_NE, label_ovf));
			}
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_ARM)
		if (op_size <= OP_SIZE_2 && alu == ROT_ROR) {
			gen_insn(INSN_ALU, OP_SIZE_4, ALU_OR, ALU_WRITES_FLAGS(OP_SIZE_4, ALU_OR, false, false, 0));
			gen_one(R_SCRATCH_1);
			gen_one(reg1);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | (8U << op_size));
			gen_one(reg1);
			if (op_size == OP_SIZE_1)
				alu = ROT_SHR;
			reg1 = R_SCRATCH_1;
		}
		goto do_generic_shift;
#endif
#if defined(ARCH_LOONGARCH64)
		if (alu == ROT_ROR && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
#if defined(ARCH_MIPS)
		if (MIPS_HAS_ROT && alu == ROT_ROR && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
#if defined(ARCH_POWER)
		if (alu == ROT_ROL && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
#if defined(ARCH_RISCV64)
		if ((alu == ROT_ROL || alu == ROT_ROR) && likely(cpu_test_feature(CPU_FEATURE_zbb))) {
			if (likely(op_size >= OP_SIZE_4)) {
				goto do_generic_shift;
			}
		}
#endif
#if defined(ARCH_S390)
		if (Z && alu == ROT_ROL && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
		if (alu == ROT_ROL || alu == ROT_ROR) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
			if (c) {
				g(gen_3address_rot_imm(ctx, op_s, alu == ROT_ROL ? ROT_SHL : ROT_SHR, R_SCRATCH_2, reg1, cnst, 0));
				g(gen_3address_rot_imm(ctx, op_s, alu == ROT_ROL ? ROT_SHR : ROT_SHL, target, reg1, -(uint64_t)cnst & ((8U << op_size) - 1), 0));
			} else {
				g(gen_3address_rot(ctx, op_s, alu == ROT_ROL ? ROT_SHL : ROT_SHR, R_SCRATCH_2, reg1, reg3));
				g(gen_2address_alu1(ctx, i_size(OP_SIZE_4), ALU1_NEG, R_SCRATCH_3, reg3, 0));
				if (must_mask) {
					g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_4), ALU_AND, R_SCRATCH_3, R_SCRATCH_3, (8U << op_size) - 1, 0));
				}
				g(gen_3address_rot(ctx, op_s, alu == ROT_ROL ? ROT_SHR : ROT_SHL, target, reg1, R_SCRATCH_3));
			}
			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, target, target, R_SCRATCH_2, 0));
			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}

		goto do_generic_shift;
do_generic_shift:
		if (mode == MODE_INT && alu == ROT_SHL) {
			target = gen_frame_target(ctx, slot_r, slot_1, slot_2, R_SCRATCH_1);
#if defined(ARCH_S390)
			if (op_size >= OP_SIZE_4) {
				if (c)
					g(gen_3address_rot_imm(ctx, op_size, ROT_SAL, target, reg1, cnst, 0));
				else
					g(gen_3address_rot(ctx, op_size, ROT_SAL, target, reg1, reg3));

				gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
				gen_four(label_ovf);
			} else
#endif
			if (op_size <= OP_SIZE_NATIVE - 1) {
				if (c)
					g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, alu, target, reg1, cnst, 0));
				else
					g(gen_3address_rot(ctx, OP_SIZE_NATIVE, alu, target, reg1, reg3));

				g(gen_cmp_extended(ctx, OP_SIZE_NATIVE, op_size, target, R_SCRATCH_2, label_ovf));
			} else {
				if (c) {
					g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, alu, R_SCRATCH_2, reg1, cnst, 0));
					g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_4, R_SCRATCH_2, cnst, 0));
				} else {
					g(gen_3address_rot(ctx, OP_SIZE_NATIVE, alu, R_SCRATCH_2, reg1, reg3));
					g(gen_3address_rot(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_4, R_SCRATCH_2, reg3));
				}

				g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, reg1, R_SCRATCH_4, COND_NE, label_ovf));

				g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));

				return true;
			}
		} else {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, slot_2, R_SCRATCH_1);
			if (c)
				g(gen_3address_rot_imm(ctx, op_s, alu, target, reg1, cnst, 0));
			else
				g(gen_3address_rot(ctx, op_s, alu, target, reg1, reg3));
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}
	/******
	 * BT *
	 ******/
do_bt: {
		unsigned attr_unused op_s;
		bool need_mask;
		bool c = frame_t_is_const(slot_2);
		int64_t cnst = !c ? 0 : frame_t_get_const(slot_2);
		int64_t max_imm = (8U << op_size) - 1;
		if (c) {
			if (mode == MODE_INT) {
				if (alu == BTX_BT ? (uint64_t)cnst > (uint64_t)max_imm : (uint64_t)cnst >= (uint64_t)max_imm) {
					gen_insn(INSN_JMP, 0, 0, 0);
					gen_four(label_ovf);
					return true;
				}
			}
			cnst &= max_imm;
		}
#if defined(ARCH_X86)
		if ((alu == BTX_BT || slot_1 == slot_r) && !slot_is_register(ctx, slot_1)) {
			int64_t offset;
			unsigned n_op_size = minimum(op_size, OP_SIZE_NATIVE);
			g(gen_frame_get(ctx, n_op_size, garbage, slot_2, R_SCRATCH_1, &reg2));
			if (mode == MODE_INT) {
				if (!c) {
					g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, n_op_size, reg2, max_imm, alu == BTX_BT ? COND_A : COND_AE, label_ovf));
					if (unlikely(op_size > OP_SIZE_NATIVE)) {
						g(gen_address(ctx, R_FRAME, (size_t)slot_2 * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
						gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
						gen_address_offset();
						gen_one(ARG_IMM);
						gen_eight(0);
						gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
						gen_four(label_ovf);
					}
				}
			} else {
				if (!c) {
					g(gen_3address_alu_imm(ctx, OP_SIZE_4, ALU_AND, R_SCRATCH_1, reg2, (8U << op_size) - 1, 0));
					reg2 = R_SCRATCH_1;
				}
			}
			offset = (size_t)slot_1 * slot_size;
			if (c && cnst >= 8U << OP_SIZE_NATIVE) {
				offset += 1U << OP_SIZE_NATIVE;
				cnst -= 8U << OP_SIZE_NATIVE;
			}
			g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_STR_OFFSET, maximum(n_op_size, OP_SIZE_2)));
			if (alu == BTX_BT) {
				gen_insn(INSN_BT, maximum(n_op_size, OP_SIZE_2), 0, 1);
				gen_address_offset();
				if (c) {
					gen_one(ARG_IMM);
					gen_eight(cnst);
				} else {
					gen_one(reg2);
				}
				g(gen_frame_set_cond(ctx, maximum(n_op_size, OP_SIZE_2), false, COND_B, slot_r));
			} else {
				gen_insn(INSN_BTX, maximum(n_op_size, OP_SIZE_2), alu, 1);
				gen_address_offset();
				gen_address_offset();
				if (c) {
					gen_one(ARG_IMM);
					gen_eight(cnst);
				} else {
					gen_one(reg2);
				}
			}
			return true;
		}
#endif
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
			size_t upcall;
			if (mode == MODE_FIXED) {
				switch (alu) {
					case BTX_BTS:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_bts_,TYPE_INT_MAX));
							break;
					case BTX_BTR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_btr_,TYPE_INT_MAX));
							break;
					case BTX_BTC:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_btc_,TYPE_INT_MAX));
							break;
					case BTX_BT:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_bt_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid bit test %u", alu);
				}
			} else {
				switch (alu) {
					case BTX_BTS:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_bts_,TYPE_INT_MAX));
							break;
					case BTX_BTR:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_btr_,TYPE_INT_MAX));
							break;
					case BTX_BTC:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_btc_,TYPE_INT_MAX));
							break;
					case BTX_BT:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_bt_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid bit test %u", alu);
				}
			}
			g(gen_alu_upcall(ctx, upcall, op_size, slot_1, slot_2, slot_r, label_ovf));
			return true;
		}
		op_s = minimum(OP_SIZE_NATIVE, ARCH_SHIFT_SIZE);
		op_s = maximum(op_s, op_size);
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, R_SCRATCH_1, &reg1));
		if (c) {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
			if (ARCH_HAS_BTX(alu == BTX_BT ? BTX_BTEXT : alu, OP_SIZE_NATIVE, true)) {
#ifdef ARCH_X86
				g(gen_mov(ctx, OP_SIZE_NATIVE, target, reg1));
				reg1 = target;
				gen_insn(INSN_BTX, OP_SIZE_NATIVE, alu == BTX_BT ? BTX_BTEXT : alu, 1);
#else
				gen_insn(INSN_BTX, OP_SIZE_NATIVE, alu == BTX_BT ? BTX_BTEXT : alu, 0);
#endif
				gen_one(target);
				gen_one(reg1);
				gen_one(ARG_IMM);
				gen_eight(cnst);
			} else switch (alu) {
				case BTX_BTS:
					g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_OR, target, reg1, (uint64_t)1 << cnst, 0));
					break;
				case BTX_BTR:
					g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_AND, target, reg1, ~((uint64_t)1 << cnst), 0));
					break;
				case BTX_BTC:
					g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, target, reg1, (uint64_t)1 << cnst, 0));
					break;
				case BTX_BT:
					if (cnst) {
						g(gen_3address_rot_imm(ctx, i_size(op_size), ROT_SHR, target, reg1, cnst, 0));
						g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_AND, target, target, 1, 0));
					} else {
						g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_AND, target, reg1, 1, 0));
					}
					break;
				default:
					internal(file_line, "do_alu: invalid bit test %u", alu);
			}
			if (alu == BTX_BT)
				g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));
			else
				g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
		g(gen_frame_get(ctx, op_size, garbage, slot_2, R_SCRATCH_2, &reg2));
		if (mode == MODE_INT) {
			if (!c)
				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size_cmp(op_size), reg2, max_imm, alu == BTX_BT ? COND_A : COND_AE, label_ovf));
		}
		if (alu != BTX_BT) {
			if (!ARCH_HAS_BTX(alu, OP_SIZE_NATIVE, false))
				goto do_generic_bt;
			need_mask = !ARCH_HAS_BTX(alu, op_size, false);
		} else {
#if defined(ARCH_X86)
			need_mask = op_size < OP_SIZE_2;
#else
			if (!ARCH_HAS_BTX(BTX_BTEXT, OP_SIZE_NATIVE, false))
				goto do_generic_bt;
			need_mask = !ARCH_HAS_BTX(BTX_BTEXT, op_size, false);
#endif
		}
		if (need_mask) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_4, ALU_AND, R_SCRATCH_2, reg2, (8U << op_size) - 1, 0));
			reg2 = R_SCRATCH_2;
		}
		if (alu == BTX_BT) {
#if defined(ARCH_X86)
			gen_insn(INSN_BT, maximum(op_size, OP_SIZE_2), 0, 1);
			gen_one(reg1);
			gen_one(reg2);

			g(gen_frame_set_cond(ctx, maximum(op_size, OP_SIZE_2), false, COND_B, slot_r));
#else
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
			gen_insn(INSN_BTX, need_mask ? OP_SIZE_NATIVE : op_size, BTX_BTEXT, 0);
			gen_one(target);
			gen_one(reg1);
			gen_one(reg2);

			g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));
#endif
		} else {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, slot_2, R_SCRATCH_1);
#if defined(ARCH_X86)
			if (target == reg2)
				target = R_SCRATCH_1;
			if (target != reg1) {
				g(gen_mov(ctx, op_size, target, reg1));
				reg1 = target;
			}
			gen_insn(INSN_BTX, maximum(op_size, OP_SIZE_2), alu, 1);
#else
			gen_insn(INSN_BTX, need_mask ? OP_SIZE_NATIVE : op_size, alu, 0);
#endif
			gen_one(target);
			gen_one(reg1);
			gen_one(reg2);

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		}
		return true;

		goto do_generic_bt;
do_generic_bt:
		if (mode == MODE_FIXED && op_size < ARCH_SHIFT_SIZE) {
			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_4), ALU_AND, R_SCRATCH_2, reg2, (8U << op_size) - 1, 0));
			reg2 = R_SCRATCH_2;
		}
		g(gen_load_constant(ctx, R_SCRATCH_3, 1));

		g(gen_3address_rot(ctx, op_s, ROT_SHL, R_SCRATCH_3, R_SCRATCH_3, reg2));

		switch (alu) {
			case BTX_BT:
#if ARCH_HAS_FLAGS
#if defined(ARCH_S390) || defined(ARCH_POWER)
				g(gen_3address_alu(ctx, i_size(op_size), ALU_AND, R_SCRATCH_1, reg1, R_SCRATCH_3, 1));
#else
				gen_insn(INSN_TEST, i_size(op_size), 0, 1);
				gen_one(reg1);
				gen_one(R_SCRATCH_3);
#endif
				g(gen_frame_set_cond(ctx, i_size_cmp(op_size), false, COND_NE, slot_r));
#else
				g(gen_3address_alu(ctx, i_size(op_size), ALU_AND, R_SCRATCH_1, reg1, R_SCRATCH_3, 0));
				g(gen_frame_cmp_imm_set_cond_reg(ctx, i_size(op_size), R_SCRATCH_1, 0, COND_NE, slot_r));
#endif
				return true;
			case BTX_BTS:
				target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
				g(gen_3address_alu(ctx, i_size(op_size), ALU_OR, target, reg1, R_SCRATCH_3, 0));
				break;
			case BTX_BTR:
				target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
				if (!ARCH_HAS_ANDN) {
					g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_3, R_SCRATCH_3, -1, 0));

					g(gen_3address_alu(ctx, i_size(op_size), ALU_AND, target, reg1, R_SCRATCH_3, 0));
					break;
				}
				g(gen_3address_alu(ctx, i_size(op_size), ALU_ANDN, target, reg1, R_SCRATCH_3, 0));
				break;
			case BTX_BTC:
				target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
				g(gen_3address_alu(ctx, i_size(op_size), ALU_XOR, target, reg1, R_SCRATCH_3, 0));
				break;
			default:
				internal(file_line, "gen_alu: unsupported bit test %u", alu);
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));

		return true;
	}
	/***********
	 * COMPARE *
	 ***********/
do_compare: {
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
			size_t attr_unused upcall;
			frame_t attr_unused swap;
			switch (alu) {
				case COND_E:
				case COND_NE:
					g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, ALU_XOR, 0, slot_2, lo_word(OP_SIZE_NATIVE), true, R_SCRATCH_1));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, ALU_XOR, 0, slot_2, hi_word(OP_SIZE_NATIVE), true, R_SCRATCH_2));
#if defined(ARCH_ARM64)
					g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, 0));

					gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
					gen_one(R_SCRATCH_1);
					gen_one(ARG_IMM);
					gen_eight(0);
#else
					g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, ARCH_HAS_FLAGS));
#endif
#if ARCH_HAS_FLAGS
					g(gen_frame_set_cond(ctx, OP_SIZE_NATIVE, false, alu, slot_r));
#else
					g(gen_frame_cmp_imm_set_cond_reg(ctx, OP_SIZE_NATIVE, R_SCRATCH_1, 0, alu, slot_r));
#endif
					return true;
#if defined(ARCH_X86_64) || defined(ARCH_X86_X32) || defined(ARCH_ARM)
				case COND_G:
				case COND_A:
					swap = slot_1; slot_1 = slot_2; slot_2 = swap;
					alu = alu == COND_G ? COND_L : COND_B;
					/*-fallthrough*/
				case COND_L:
				case COND_B:
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_2, lo_word(OP_SIZE_NATIVE), true, R_SCRATCH_2));
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_1, hi_word(OP_SIZE_NATIVE), true, R_SCRATCH_1));
					g(gen_frame_load_cmp(ctx, OP_SIZE_NATIVE, false, garbage, true, slot_1, lo_word(OP_SIZE_NATIVE), true, R_SCRATCH_2));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, ALU_SBB, 1, slot_2, hi_word(OP_SIZE_NATIVE), true, R_SCRATCH_1));
					g(gen_frame_set_cond(ctx, OP_SIZE_NATIVE, false, alu, slot_r));
					return true;
				case COND_GE:
				case COND_AE:
					swap = slot_1; slot_1 = slot_2; slot_2 = swap;
					alu = alu == COND_GE ? COND_LE : COND_BE;
					/*-fallthrough*/
				case COND_LE:
				case COND_BE:
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_1, lo_word(OP_SIZE_NATIVE), true, R_SCRATCH_2));
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_2, hi_word(OP_SIZE_NATIVE), true, R_SCRATCH_1));
					g(gen_frame_load_cmp(ctx, OP_SIZE_NATIVE, false, garbage, true, slot_2, lo_word(OP_SIZE_NATIVE), true, R_SCRATCH_2));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, garbage, ALU_SBB, 1, slot_1, hi_word(OP_SIZE_NATIVE), true, R_SCRATCH_1));
					g(gen_frame_set_cond(ctx, OP_SIZE_NATIVE, false, alu == COND_LE ? COND_GE : COND_AE, slot_r));
					return true;
#else
				case COND_L:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_less_,TYPE_INT_MAX)); goto do_upcall;
				case COND_LE:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_less_equal_,TYPE_INT_MAX)); goto do_upcall;
				case COND_G:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_greater_,TYPE_INT_MAX)); goto do_upcall;
				case COND_GE:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_greater_equal_,TYPE_INT_MAX)); goto do_upcall;
				case COND_B:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_uless_,TYPE_INT_MAX)); goto do_upcall;
				case COND_BE:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_uless_equal_,TYPE_INT_MAX)); goto do_upcall;
				case COND_A:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_ugreater_,TYPE_INT_MAX)); goto do_upcall;
				case COND_AE:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_ugreater_equal_,TYPE_INT_MAX)); goto do_upcall;
				do_upcall:	g(gen_alu_upcall(ctx, upcall, op_size, slot_1, slot_2, slot_r, 0));
						return true;
#endif
				default:
					internal(file_line, "gen_alu: unsupported condition %u", alu);
			}
			return false;
		}
#if defined(ARCH_X86)
		g(gen_frame_get(ctx, op_size, garbage, slot_1, R_SCRATCH_1, &reg1));
		g(gen_frame_load_cmp_set_cond(ctx, op_size, garbage, slot_2, reg1, alu, slot_r));
#else
		g(gen_frame_get(ctx, op_size, op_size == i_size_cmp(op_size) + (unsigned)zero ? garbage : alu == COND_L || alu == COND_LE || alu == COND_G || alu == COND_GE || ARCH_PREFERS_SX(op_size) ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
		g(gen_frame_load_cmp_set_cond(ctx, op_size, alu == COND_L || alu == COND_LE || alu == COND_G || alu == COND_GE || ARCH_PREFERS_SX(op_size) ? sign_x : zero_x, slot_2, reg1, alu, slot_r));
#endif
		return true;
	}
}

static bool attr_w gen_alu1(struct codegen_context *ctx, unsigned mode, unsigned op_size, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_r)
{
	unsigned alu;
	unsigned reg1, target;
	switch (mode) {
		case MODE_FIXED: switch (op) {
			case OPCODE_FIXED_OP_not:		alu = ALU1_NOT; goto do_alu;
			case OPCODE_FIXED_OP_neg:		alu = ALU1_NEG; goto do_alu;
			case OPCODE_FIXED_OP_bswap:
			case OPCODE_FIXED_OP_bswap_alt1:	alu = ALU1_BSWAP; goto do_bswap;
			case OPCODE_FIXED_OP_brev:
			case OPCODE_FIXED_OP_brev_alt1:		alu = ALU1_BREV; goto do_brev;
			case OPCODE_FIXED_OP_bsf:
			case OPCODE_FIXED_OP_bsf_alt1:		alu = ALU1_BSF; goto do_bsf_bsr_popcnt;
			case OPCODE_FIXED_OP_bsr:
			case OPCODE_FIXED_OP_bsr_alt1:		alu = ALU1_BSR; goto do_bsf_bsr_popcnt;
			case OPCODE_FIXED_OP_popcnt:
			case OPCODE_FIXED_OP_popcnt_alt1:	alu = ALU1_POPCNT; goto do_bsf_bsr_popcnt;
			case OPCODE_FIXED_OP_to_int:		goto do_fixed_conv;
			case OPCODE_FIXED_OP_from_int:		goto do_fixed_conv;
			case OPCODE_FIXED_OP_uto_int:		goto conv_uto_int;
			case OPCODE_FIXED_OP_ufrom_int:		goto conv_ufrom_int;
			default:				internal(file_line, "gen_alu1: unsupported fixed operation %u", op);
		}
		case MODE_INT: switch (op) {
			case OPCODE_INT_OP_not:			alu = ALU1_NOT; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_neg:			alu = ALU1_NEG; goto do_alu;
			case OPCODE_INT_OP_bsf:			alu = ALU1_BSF; goto do_bsf_bsr_popcnt;
			case OPCODE_INT_OP_bsr:			alu = ALU1_BSR; goto do_bsf_bsr_popcnt;
			case OPCODE_INT_OP_popcnt:
			case OPCODE_INT_OP_popcnt_alt1:		alu = ALU1_POPCNT; goto do_bsf_bsr_popcnt;
			case OPCODE_INT_OP_to_int:		goto do_conv;
			case OPCODE_INT_OP_from_int:		goto do_conv;
			default:				internal(file_line, "gen_alu1: unsupported int operation %u", op);
		}
		case MODE_BOOL: switch (op) {
			case OPCODE_BOOL_OP_not:		goto do_bool_not;
			default:				internal(file_line, "gen_alu1: unsupported bool operation %u", op);
		}
	}
	internal(file_line, "gen_alu1: unsupported mode %u", mode);

	/*******
	 * ALU *
	 *******/
do_alu: {
		bool arch_use_flags = ARCH_HAS_FLAGS;
		enum extend ex;
#if defined(ARCH_POWER)
		arch_use_flags = false;
#endif
		if (op_size > OP_SIZE_NATIVE) {
#if !defined(ARCH_X86) && !defined(ARCH_ARM) && !defined(ARCH_POWER)
			if (alu == ALU1_NEG) {
				if (mode == MODE_FIXED)
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_unary_neg_,TYPE_INT_MAX)), op_size, slot_1, NO_FRAME_T, slot_r, 0));
				else
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_unary_neg_,TYPE_INT_MAX)), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf));
				return true;
			}
#endif
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, alu, R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_NEG ? 2 : 0));
			if (alu == ALU1_NOT) {
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NOT, R_SCRATCH_2, R_SCRATCH_2, 0));
			} else {
#if defined(ARCH_X86)
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NOT, R_SCRATCH_2, R_SCRATCH_2, 0));

				g(gen_imm(ctx, -1, IMM_PURPOSE_SUB, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SBB, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, ALU_SBB, false, is_imm(), ctx->const_imm));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_imm_offset();
#else
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NGC, R_SCRATCH_2, R_SCRATCH_2, (mode == MODE_INT)));
#endif
			}
			if (mode == MODE_INT) {
				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_O, 0);
				gen_four(label_ovf);
			}
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
			return true;
		}
		if ((arch_use_flags || ARCH_SUPPORTS_TRAPS(op_size)) && slot_1 == slot_r && i_size_cmp(op_size) == op_size + zero) {
			struct cg_exit *ce;
			unsigned undo_alu = alu;
			if (slot_is_register(ctx, slot_1)) {
				unsigned reg = ctx->registers[slot_1];
				if (mode == MODE_INT && ARCH_SUPPORTS_TRAPS(op_size)) {
					gen_insn(INSN_ALU1_TRAP, op_size, alu, ALU1_WRITES_FLAGS(alu));
					gen_one(reg);
					gen_one(reg);
					if (ARCH_TRAP_BEFORE || alu == undo_alu) {
						gen_four(label_ovf);
						return true;
					} else {
						ce = alloc_undo_label(ctx);
						if (unlikely(!ce))
							return false;
						gen_four(ce->undo_label);
						goto do_undo_opcode;
					}
				}
				g(gen_2address_alu1(ctx, i_size(op_size), alu, reg, reg, mode == MODE_INT));
				if (mode == MODE_INT) {
					if (alu != undo_alu) {
						ce = alloc_undo_label(ctx);
						if (unlikely(!ce))
							return false;
						gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
						gen_four(ce->undo_label);
do_undo_opcode:
						ce->undo_opcode = INSN_ALU1 + ARCH_PARTIAL_ALU(op_size);
						ce->undo_op_size = i_size(op_size);
						ce->undo_aux = undo_alu;
						ce->undo_writes_flags = ALU1_WRITES_FLAGS(undo_alu);
						ce->undo_parameters[0] = reg;
						ce->undo_parameters[1] = reg;
						ce->undo_parameters_len = 2;
					} else {
						gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
						gen_four(label_ovf);
					}
				}
				return true;
			}
#if defined(ARCH_X86)
			else {
				size_t m;
				int64_t offset = (size_t)slot_1 * slot_size;
				g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, i_size(op_size)));
				gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(op_size), i_size(op_size), alu, ALU1_WRITES_FLAGS(alu) | (mode == MODE_INT));
				gen_address_offset();
				gen_address_offset();
				if (mode == MODE_INT) {
					if (alu != undo_alu) {
						ce = alloc_undo_label(ctx);
						if (unlikely(!ce))
							return false;
						ce->undo_opcode = INSN_ALU1 + ARCH_PARTIAL_ALU(op_size);
						ce->undo_op_size = i_size(op_size);
						ce->undo_aux = undo_alu;
						ce->undo_writes_flags = ALU1_WRITES_FLAGS(undo_alu);
						m = mark_params(ctx);
						gen_address_offset();
						gen_address_offset();
						copy_params(ctx, ce, m);
						gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
						gen_four(ce->undo_label);
					} else {
						gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
						gen_four(label_ovf);
					}
				}
				return true;
			}
#endif
		}
		target = gen_frame_target(ctx, slot_r, mode == MODE_INT ? slot_1 : NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
		if (mode == MODE_FIXED) {
			ex = garbage;
		} else {
			ex = ARCH_PREFERS_SX(op_size) ? sign_x : zero_x;
			if (ARCH_SUPPORTS_TRAPS(op_size))
				ex = garbage;
			if (op_size == i_size(op_size) + (unsigned)zero)
				ex = garbage;
		}
		g(gen_frame_get(ctx, op_size, ex, slot_1, mode == MODE_INT ? R_SCRATCH_2 : target, &reg1));
#if defined(ARCH_X86)
		g(gen_2address_alu1(ctx, op_size, alu, target, reg1, mode == MODE_INT));
#else
		if (mode == MODE_INT) {
#if defined(ARCH_POWER)
			if (op_size == OP_SIZE_NATIVE) {
				g(gen_2address_alu1(ctx, i_size(op_size), alu, target, reg1, 0));
				if (alu == ALU1_NEG) {
					g(gen_3address_alu(ctx, i_size(op_size), ALU_AND, R_CG_SCRATCH, target, reg1, 1));
				}
				gen_insn(INSN_JMP_COND, op_size, COND_L, 0);
				gen_four(label_ovf);

				g(gen_frame_store(ctx, op_size, slot_r, 0, target));

				return true;
			}
#endif
			if (!arch_use_flags && !ARCH_SUPPORTS_TRAPS(op_size) && ARCH_HAS_ANDN && op_size >= OP_SIZE_4) {
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, alu, target, reg1, 0));

				if (alu == ALU1_NEG) {
					g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_AND, R_SCRATCH_3, target, reg1, 0));
				}

				if (op_size < OP_SIZE_NATIVE)
					g(gen_extend(ctx, op_size, sign_x, R_SCRATCH_3, R_SCRATCH_3));

				g(gen_jmp_on_zero(ctx, OP_SIZE_NATIVE, R_SCRATCH_3, COND_S, label_ovf));

				g(gen_frame_store(ctx, op_size, slot_r, 0, target));

				return true;
			}
			if (op_size <= OP_SIZE_2 || (!arch_use_flags && !ARCH_SUPPORTS_TRAPS(op_size))) {
				int64_t imm = (ARCH_PREFERS_SX(op_size) ? -0x80ULL : 0x80ULL) << (((1 << op_size) - 1) * 8);

				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size_cmp(op_size), reg1, imm, COND_E, label_ovf));

				mode = MODE_FIXED;

				target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
			}
		}
#if !ARCH_HAS_FLAGS
		if (mode == MODE_INT) {
			gen_insn(INSN_ALU1_TRAP, op_size, alu, ALU1_WRITES_FLAGS(alu));
			gen_one(target);
			gen_one(reg1);
			gen_four(label_ovf);
			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
#endif
		g(gen_2address_alu1(ctx, i_size(op_size), alu, target, reg1, mode == MODE_INT));
#endif
		if (mode == MODE_INT) {
			gen_insn(INSN_JMP_COND, i_size_cmp(op_size), COND_O, 0);
			gen_four(label_ovf);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}

	/*******
	 * NOT *
	 *******/
do_bool_not: {
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
		g(gen_frame_get(ctx, op_size, garbage, slot_1, target, &reg1));

		g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, target, reg1, 1, 0));

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}

	/*********
	 * BSWAP *
	 *********/
do_bswap: {
		bool attr_unused sx = false;
#if defined(ARCH_X86) || defined(ARCH_ARM) || defined(ARCH_IA64) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_RISCV64) || defined(ARCH_S390)
#if defined(ARCH_ARM32)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_armv6)))
			goto do_generic_bswap;
#endif
#if defined(ARCH_MIPS)
		if (unlikely(!MIPS_HAS_ROT))
			goto do_generic_bswap;
		sx = op_size == OP_SIZE_4;
#endif
#if defined(ARCH_RISCV64)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_zbb)))
			goto do_generic_bswap;
#endif
#if defined(ARCH_S390)
		if (op_size == OP_SIZE_2)
			goto do_generic_bswap;
#endif
#if defined(ARCH_X86)
		if (op_size >= OP_SIZE_4 && !cpu_test_feature(CPU_FEATURE_bswap))
			goto do_generic_bswap;
#endif
		if (op_size > OP_SIZE_NATIVE) {
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
			reg1 = R_SCRATCH_1;
			target = R_SCRATCH_1;
		} else {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, sx ? sign_x : garbage, slot_1, target, &reg1));
		}

		if (op_size == OP_SIZE_1) {
#if defined(ARCH_IA64) || defined(ARCH_RISCV64)
		} else if (op_size == OP_SIZE_2 || op_size == OP_SIZE_4) {
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_BSWAP, target, reg1, 0));

			g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, target, target, op_size == OP_SIZE_2 ? 48 : 32, 0));
#endif
		} else if (op_size == OP_SIZE_2) {
#if defined(ARCH_X86)
			g(gen_3address_rot_imm(ctx, OP_SIZE_2, ROT_ROR, target, reg1, 8, 0));
#else
			g(gen_2address_alu1(ctx, OP_SIZE_4, ALU1_BSWAP16, target, reg1, 0));
#endif
		} else {
			g(gen_2address_alu1(ctx, minimum(op_size, OP_SIZE_NATIVE), ALU1_BSWAP, target, reg1, 0));
		}
		if (op_size > OP_SIZE_NATIVE) {
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_BSWAP, R_SCRATCH_2, R_SCRATCH_2, 0));
		}

		if (op_size > OP_SIZE_NATIVE)
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_2, R_SCRATCH_1));
		else
			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
		goto do_generic_bswap;
do_generic_bswap:
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_bswap_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
	}
	/********
	 * BREV *
	 ********/
do_brev: {
#if defined(ARCH_ARM) || defined(ARCH_LOONGARCH64) || (defined(ARCH_MIPS) && MIPS_R6)
#if defined(ARCH_ARM32)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_armv6t2)))
			goto do_generic_brev;
#endif
		if (op_size > OP_SIZE_NATIVE) {
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
			reg1 = R_SCRATCH_1;
			target = R_SCRATCH_1;
		} else {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, garbage, slot_1, target, &reg1));
		}

		g(gen_2address_alu1(ctx, minimum(maximum(OP_SIZE_4, op_size), OP_SIZE_NATIVE), ALU1_BREV, target, reg1, 0));
		if (op_size <= OP_SIZE_2) {
			g(gen_3address_rot_imm(ctx, OP_SIZE_4, ROT_SHR, target, target, op_size == OP_SIZE_1 ? 24 : 16, 0));
		}
		if (op_size > OP_SIZE_NATIVE) {
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_BREV, R_SCRATCH_2, R_SCRATCH_2, 0));
		}

		if (op_size > OP_SIZE_NATIVE)
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_2, R_SCRATCH_1));
		else
			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
		goto do_generic_brev;
do_generic_brev:
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_brev_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
	}
	/******************
	 * BSF/BSR/POPCNT *
	 ******************/
do_bsf_bsr_popcnt: {
		if (op_size > OP_SIZE_NATIVE) {
#if defined(ARCH_X86)
			uint32_t label_finish = 0;	/* avoid warning */
			if (alu == ALU1_POPCNT && unlikely(!cpu_test_feature(CPU_FEATURE_popcnt)))
				goto do_generic_bsf_bsr_popcnt;
			if (alu == ALU1_BSR || alu == ALU1_POPCNT) {
				if (mode == MODE_INT) {
					g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
					g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, OP_SIZE_NATIVE));
					gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
					gen_address_offset();
					gen_imm_offset();

					gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_S, 0);
					gen_four(label_ovf);
				}
			}
			if (alu == ALU1_BSF) {
				label_finish = alloc_label(ctx);
				if (unlikely(!label_finish))
					return false;

				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + lo_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_BSF, ALU1_WRITES_FLAGS(ALU1_BSF));
				gen_one(R_SCRATCH_1);
				gen_address_offset();

				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
				gen_four(label_finish);

				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_BSF, ALU1_WRITES_FLAGS(ALU1_BSF));
				gen_one(R_SCRATCH_1);
				gen_address_offset();

				g(gen_3address_alu_imm(ctx, OP_SIZE_4, ALU_ADD, R_SCRATCH_1, R_SCRATCH_1, 8U << OP_SIZE_NATIVE, 0));
			}
			if (alu == ALU1_BSR) {
				label_finish = alloc_label(ctx);
				if (unlikely(!label_finish))
					return false;

				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_BSR, ALU1_WRITES_FLAGS(ALU1_BSR));
				gen_one(R_SCRATCH_1);
				gen_address_offset();

				g(gen_3address_alu_imm(ctx, OP_SIZE_4, ALU_ADD, R_SCRATCH_1, R_SCRATCH_1, 8U << OP_SIZE_NATIVE, 0));

				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
				gen_four(label_finish);

				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + lo_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_BSR, ALU1_WRITES_FLAGS(ALU1_BSR));
				gen_one(R_SCRATCH_1);
				gen_address_offset();
			}
			if (alu == ALU1_BSF || alu == ALU1_BSR) {
				if (mode == MODE_INT) {
					gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_E, 0);
					gen_four(label_ovf);
				} else {
					gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
					gen_four(label_finish);

					g(gen_load_constant(ctx, R_SCRATCH_1, -1));
				}

				gen_label(label_finish);

				if (mode == MODE_INT)
					goto write_result;

				if (R_SCRATCH_1 != R_AX || R_SCRATCH_2 != R_DX)
					internal(file_line, "gen_alu1: bad scratch registers");
				gen_insn(INSN_CWD, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_DX);
				gen_one(R_AX);

				g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size + lo_word(OP_SIZE_NATIVE), IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_1);

				g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_2);

				return true;
			}
			if (alu == ALU1_POPCNT) {
				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + lo_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_POPCNT, ALU1_WRITES_FLAGS(ALU1_POPCNT));
				gen_one(R_SCRATCH_1);
				gen_address_offset();

				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_POPCNT, ALU1_WRITES_FLAGS(ALU1_POPCNT));
				gen_one(R_SCRATCH_2);
				gen_address_offset();

				g(gen_3address_alu(ctx, OP_SIZE_4, ALU_ADD, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, 1));
write_result:
				g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size + lo_word(OP_SIZE_NATIVE), IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_1);

				g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
				g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, OP_SIZE_NATIVE));
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_imm_offset();

				return true;
			}
#endif
			goto do_generic_bsf_bsr_popcnt;
		}
#if defined(ARCH_X86)
		if (alu == ALU1_POPCNT && unlikely(!cpu_test_feature(CPU_FEATURE_popcnt)))
			goto do_generic_bsf_bsr_popcnt;
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
		if (op_size == OP_SIZE_1 || ((alu == ALU1_BSR || alu == ALU1_POPCNT) && mode == MODE_INT)) {
			g(gen_frame_get(ctx, op_size, zero_x, slot_1, target, &reg1));
			if ((alu == ALU1_BSR || alu == ALU1_POPCNT) && mode == MODE_INT) {
				g(gen_cmp_test_jmp(ctx, INSN_TEST, op_size, reg1, reg1, alu == ALU1_BSR ? COND_LE : COND_S, label_ovf));
			}
			g(gen_2address_alu1(ctx, maximum(op_size, OP_SIZE_2), alu, target, reg1, 1));
			if ((alu == ALU1_BSR || alu == ALU1_POPCNT) && mode == MODE_INT)
				goto x86_bsf_bsr_popcnt_finish;
		} else {
			g(gen_frame_load_op1(ctx, op_size, alu, 1, slot_1, target));
		}
		if (alu == ALU1_POPCNT)
			goto x86_bsf_bsr_popcnt_finish;
		if (mode == MODE_FIXED) {
			uint32_t cmov_label;
			gen_insn(INSN_MOV, maximum(op_size, OP_SIZE_4), 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(ARG_IMM);
			gen_eight(-1);
			g(gen_cmov(ctx, maximum(op_size, OP_SIZE_4), COND_E, target, &cmov_label));
			gen_one(R_SCRATCH_2);
			if (cmov_label)
				gen_label(cmov_label);

		} else {
			gen_insn(INSN_JMP_COND, maximum(op_size, OP_SIZE_2), COND_E, 0);
			gen_four(label_ovf);
		}
x86_bsf_bsr_popcnt_finish:
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_ARM)
#if defined(ARCH_ARM32)
		if (alu == ALU1_BSR && unlikely(!cpu_test_feature(CPU_FEATURE_armv6)))
			goto do_generic_bsf_bsr_popcnt;
		if (alu == ALU1_BSF && unlikely(!cpu_test_feature(CPU_FEATURE_armv6t2)))
			goto do_generic_bsf_bsr_popcnt;
#endif
		if (alu == ALU1_POPCNT && unlikely(!cpu_test_feature(CPU_FEATURE_neon)))
			goto do_generic_bsf_bsr_popcnt;
		g(gen_frame_get(ctx, op_size, mode == MODE_INT ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), reg1, reg1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		}

		if (alu == ALU1_POPCNT) {
			g(gen_mov(ctx, OP_SIZE_NATIVE, FR_SCRATCH_1, reg1));
			gen_insn(INSN_FP_ALU1, OP_SIZE_NATIVE, FP_ALU1_VCNT8, 0);
			gen_one(FR_SCRATCH_1);
			gen_one(FR_SCRATCH_1);
#if defined(ARCH_ARM32)
			if (op_size > OP_SIZE_1) {
				gen_insn(INSN_FP_ALU1, OP_SIZE_1, FP_ALU1_VPADDL, 0);
				gen_one(FR_SCRATCH_1);
				gen_one(FR_SCRATCH_1);
			}
			if (op_size > OP_SIZE_2) {
				gen_insn(INSN_FP_ALU1, OP_SIZE_2, FP_ALU1_VPADDL, 0);
				gen_one(FR_SCRATCH_1);
				gen_one(FR_SCRATCH_1);
			}
#else
			if (op_size > OP_SIZE_1) {
				gen_insn(INSN_FP_ALU1, OP_SIZE_1, FP_ALU1_ADDV, 0);
				gen_one(FR_SCRATCH_1);
				gen_one(FR_SCRATCH_1);
			}
#endif
			g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
			if (slot_is_register(ctx, slot_r))
				g(unspill(ctx, slot_r));
			return true;
		}

		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
		if (mode == MODE_FIXED && alu == ALU1_BSF) {
			gen_insn(INSN_TEST, i_size(op_size), 0, 1);
			gen_one(target);
			gen_one(reg1);
			reg1 = target;
		}

		if (alu == ALU1_BSF) {
			g(gen_2address_alu1(ctx, i_size(op_size), ALU1_BREV, target, reg1, 0));
			reg1 = target;
		}

		g(gen_2address_alu1(ctx, i_size(op_size), ALU1_LZCNT, target, reg1, 0));

		if (alu == ALU1_BSR) {
			g(gen_load_constant(ctx, R_SCRATCH_2, op_size == OP_SIZE_8 ? 63 : 31));
			g(gen_3address_alu(ctx, i_size(op_size), ALU_SUB, target, R_SCRATCH_2, target, 0));
		}

		if (mode == MODE_FIXED && alu == ALU1_BSF) {
#if defined(ARCH_ARM32)
			g(gen_imm(ctx, -1, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
			gen_insn(INSN_CMOV, OP_SIZE_NATIVE, COND_E, 0);
			gen_one(target);
			gen_one(target);
			gen_imm_offset();
#else
			gen_insn(INSN_CSEL_INV, i_size(op_size), COND_NE, 0);
			gen_one(target);
			gen_one(ARG_IMM);
			gen_eight(0);
			gen_one(target);
#endif
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_ALPHA)
		if (likely(cpu_test_feature(CPU_FEATURE_cix))) {
			g(gen_frame_get(ctx, op_size, mode == MODE_INT ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
			target = gen_frame_target(ctx, slot_r, slot_1, NO_FRAME_T, R_SCRATCH_2);
			if (mode == MODE_INT) {
				g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, reg1, reg1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
			}
			if (alu == ALU1_POPCNT) {
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_POPCNT, target, reg1, 0));
			}
			if (alu == ALU1_BSF) {
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_BSF, target, reg1, 0));

				if (mode == MODE_FIXED) {
					g(gen_imm(ctx, -1, IMM_PURPOSE_MOVR, OP_SIZE_INT));
					gen_insn(INSN_MOVR, OP_SIZE_NATIVE, COND_E, 0);
					gen_one(target);
					gen_one(target);
					gen_one(reg1);
					gen_imm_offset();
				}
			}
			if (alu == ALU1_BSR) {
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_LZCNT, target, reg1, 0));

				g(gen_load_constant(ctx, R_SCRATCH_3, OP_SIZE_NATIVE == OP_SIZE_8 ? 63 : 31));

				g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_SUB, target, R_SCRATCH_3, target, 0));
			}
			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
#endif
#if defined(ARCH_MIPS)
		if (MIPS_HAS_CLZ && alu != ALU1_POPCNT) {
			g(gen_frame_get(ctx, op_size, mode == MODE_INT ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
			target = gen_frame_target(ctx, slot_r, slot_1, NO_FRAME_T, R_SCRATCH_2);
			if (mode == MODE_INT) {
				g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, reg1, reg1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
			}
			if (alu == ALU1_BSF) {
				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NEG, target, reg1, 0));

				g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_AND, R_SCRATCH_1, reg1, target, 0));
				reg1 = R_SCRATCH_1;
			}
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_LZCNT, target, reg1, 0));

			g(gen_load_constant(ctx, R_SCRATCH_3, OP_SIZE_NATIVE == OP_SIZE_8 ? 63 : 31));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_SUB, target, R_SCRATCH_3, target, 0));

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
#endif
#if defined(ARCH_POWER)
		if (alu == ALU1_BSF && (unlikely(!cpu_test_feature(CPU_FEATURE_v203)) || unlikely(!cpu_test_feature(CPU_FEATURE_v30))))
			goto do_generic_bsf_bsr_popcnt;
		if (alu == ALU1_POPCNT && unlikely(!cpu_test_feature(CPU_FEATURE_v206)))
			goto do_generic_bsf_bsr_popcnt;
		g(gen_frame_get(ctx, op_size, mode == MODE_INT ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, slot_1, NO_FRAME_T, R_SCRATCH_2);
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), reg1, reg1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		}
		if (alu == ALU1_POPCNT) {
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_POPCNT, target, reg1, 0));
		}
		if (alu == ALU1_BSF) {
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_BSF, target, reg1, 0));

			if (mode == MODE_FIXED) {
				g(gen_3address_alu(ctx, i_size(op_size), ALU_AND, R_SCRATCH_3, reg1, reg1, 1));

				g(gen_imm(ctx, -1, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
				gen_insn(INSN_CMOV, OP_SIZE_NATIVE, COND_E, 0);
				gen_one(target);
				gen_one(target);
				gen_imm_offset();
			}
		}
		if (alu == ALU1_BSR) {
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_LZCNT, target, reg1, 0));

			g(gen_load_constant(ctx, R_SCRATCH_3, OP_SIZE_NATIVE == OP_SIZE_8 ? 63 : 31));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_SUB, target, R_SCRATCH_3, target, 0));
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_RISCV64)
#if defined(ARCH_LOONGARCH64)
		if (alu == ALU1_POPCNT)
			goto do_generic_bsf_bsr_popcnt;
#endif
#if defined(ARCH_RISCV64)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_zbb)))
			goto do_generic_bsf_bsr_popcnt;
#endif
		g(gen_frame_get(ctx, op_size, mode == MODE_INT ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, slot_1, NO_FRAME_T, R_SCRATCH_2);
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, reg1, reg1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		}
		if (alu == ALU1_POPCNT) {
			g(gen_2address_alu1(ctx, maximum(OP_SIZE_4, op_size), ALU1_POPCNT, target, reg1, 0));
		}
		if (alu == ALU1_BSF) {
			g(gen_2address_alu1(ctx, maximum(OP_SIZE_4, op_size), ALU1_BSF, target, reg1, 0));

			if (mode == MODE_FIXED) {
				g(gen_imm(ctx, 1, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
				gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, COND_B, 0);
				gen_one(R_SCRATCH_3);
				gen_one(reg1);
				gen_imm_offset();

				g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_NEG, R_SCRATCH_3, R_SCRATCH_3, 0));

				g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, target, target, R_SCRATCH_3, 0));
			}
		}
		if (alu == ALU1_BSR) {
			g(gen_2address_alu1(ctx, maximum(OP_SIZE_4, op_size), ALU1_LZCNT, target, reg1, 0));

			g(gen_load_constant(ctx, R_SCRATCH_3, op_size <= OP_SIZE_4 ? 31 : 63));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_SUB, target, R_SCRATCH_3, target, 0));
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_IA64) || defined(ARCH_S390) || defined(ARCH_SPARC)
		if (alu == ALU1_BSF && !ARCH_HAS_ANDN)
			goto do_generic_bsf_bsr_popcnt;
#if defined(ARCH_S390)
		if (!cpu_test_feature(CPU_FEATURE_misc_45) || !cpu_test_feature(CPU_FEATURE_misc_insn_ext_3))
			goto do_generic_bsf_bsr_popcnt;
#endif
#if defined(ARCH_SPARC)
		if (!SPARC_9)
			goto do_generic_bsf_bsr_popcnt;
#endif
		g(gen_frame_get(ctx, op_size, mode == MODE_INT ? sign_x : zero_x, slot_1, R_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, slot_1, NO_FRAME_T, R_SCRATCH_2);
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, maximum(op_size, OP_SIZE_4), reg1, reg1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		} else {
			if (ARCH_PREFERS_SX(op_size) && alu == ALU1_POPCNT && op_size < OP_SIZE_NATIVE) {
				g(gen_extend(ctx, op_size, zero_x, R_SCRATCH_1, reg1));
				reg1 = R_SCRATCH_1;
			}
		}
		if (alu == ALU1_POPCNT) {
			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_POPCNT, R_SCRATCH_1, reg1, 0));
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}
		if (alu == ALU1_BSF) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_SUB, target, reg1, 1, 0));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ANDN, target, target, reg1, 0));

			g(gen_2address_alu1(ctx, OP_SIZE_NATIVE, ALU1_POPCNT, target, target, 0));

			if (mode == MODE_FIXED) {
				unsigned attr_unused test_reg = R_SCRATCH_1;
#if defined(ARCH_S390)
				g(gen_imm(ctx, 0, COND_IS_LOGICAL(COND_E) ? IMM_PURPOSE_CMP_LOGICAL : IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
				gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1 + COND_IS_LOGICAL(COND_E));
				gen_one(reg1);
				gen_imm_offset();

				g(gen_imm(ctx, -1, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
				gen_insn(INSN_CMOV, OP_SIZE_NATIVE, COND_E, 0);
				gen_one(target);
				gen_one(target);
				gen_imm_offset();
#else
#if defined(ARCH_IA64)
				g(gen_cmp_dest_reg(ctx, OP_SIZE_NATIVE, reg1, (unsigned)-1, R_CMP_RESULT, 0, COND_NE));
				test_reg = R_CMP_RESULT;
#endif
				g(gen_imm(ctx, -1, IMM_PURPOSE_MOVR, OP_SIZE_NATIVE));
				gen_insn(INSN_MOVR, OP_SIZE_NATIVE, COND_E, 0);
				gen_one(target);
				gen_one(target);
				gen_one(test_reg);
				gen_imm_offset();
#endif
			}

			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
#endif
do_generic_bsf_bsr_popcnt:
		if (alu == ALU1_BSF) {
			if (mode == MODE_FIXED)
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_bsf_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
			else
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_unary_bsf_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
		}
		if (alu == ALU1_BSR) {
			if (mode == MODE_FIXED)
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_bsr_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
			else
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_unary_bsr_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
		}
		if (alu == ALU1_POPCNT) {
			if (mode == MODE_FIXED)
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_popcnt_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
			else
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_unary_popcnt_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
		}
	}
	/**************
	 * CONVERSION *
	 **************/
do_fixed_conv:
do_conv: {
		unsigned src_op_size, dest_op_size;
		const struct type *src_type, *dest_type;
		src_type = get_type_of_local(ctx, slot_1);
		dest_type = get_type_of_local(ctx, slot_r);

		if (TYPE_TAG_IS_FIXED(src_type->tag)) {
			src_op_size = TYPE_TAG_IDX_FIXED(src_type->tag) >> 1;
		} else {
			src_op_size = TYPE_TAG_IDX_INT(src_type->tag);
		}

		if (TYPE_TAG_IS_FIXED(dest_type->tag)) {
			dest_op_size = TYPE_TAG_IDX_FIXED(dest_type->tag) >> 1;
		} else {
			dest_op_size = TYPE_TAG_IDX_INT(dest_type->tag);
		}

		if (src_op_size <= OP_SIZE_NATIVE) {
			g(gen_frame_get(ctx, src_op_size, sign_x, slot_1, R_SCRATCH_1, &reg1));
		} else {
#if defined(ARCH_X86)
			if (dest_op_size < src_op_size)
				g(gen_frame_load(ctx, OP_SIZE_NATIVE, garbage, slot_1, 0, false, R_SCRATCH_1));
			else
#endif
				g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_3));
			reg1 = R_SCRATCH_1;
		}

		if (dest_op_size >= src_op_size) {
			if (dest_op_size <= OP_SIZE_NATIVE) {
				g(gen_frame_store(ctx, dest_op_size, slot_r, 0, reg1));
			} else {
				if (src_op_size <= OP_SIZE_NATIVE) {
#if defined(ARCH_X86)
					if (R_SCRATCH_1 != R_AX || R_SCRATCH_2 != R_DX)
						internal(file_line, "gen_alu1: bad scratch registers");
					if (reg1 == R_SCRATCH_1) {
						gen_insn(INSN_CWD, OP_SIZE_NATIVE, 0, 0);
						gen_one(R_DX);
						gen_one(R_AX);
					} else
#endif
					g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_2, reg1, (1U << (OP_SIZE_NATIVE + 3)) - 1, false));
					g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, reg1, R_SCRATCH_2));
				} else {
					g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, reg1, R_SCRATCH_3));
				}
			}
			return true;
		} else {
			if (src_op_size > OP_SIZE_NATIVE) {
#if defined(ARCH_ARM)
				gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
				gen_one(R_SCRATCH_3);
				gen_one(ARG_SHIFTED_REGISTER);
				gen_one(ARG_SHIFT_ASR | ((1U << (OP_SIZE_NATIVE + 3)) - 1));
				gen_one(R_SCRATCH_1);

				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
				gen_four(label_ovf);
#elif defined(ARCH_X86)
				if (R_SCRATCH_1 != R_AX || R_SCRATCH_2 != R_DX)
					internal(file_line, "gen_alu1: bad scratch registers");
				gen_insn(INSN_CWD, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_DX);
				gen_one(R_AX);

				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size + hi_word(OP_SIZE_NATIVE), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
				gen_one(R_SCRATCH_2);
				gen_address_offset();

				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
				gen_four(label_ovf);
#else
				g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_2, R_SCRATCH_1, (1U << (OP_SIZE_NATIVE + 3)) - 1, 0));

				g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_3, R_SCRATCH_2, COND_NE, label_ovf));
#endif

				src_op_size = OP_SIZE_NATIVE;
			}
			if (src_op_size > dest_op_size) {
				g(gen_cmp_extended(ctx, OP_SIZE_NATIVE, dest_op_size, reg1, R_SCRATCH_2, label_ovf));
			}
			g(gen_frame_store(ctx, dest_op_size, slot_r, 0, reg1));
			return true;
		}
	}

conv_uto_int: {
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_uto_int_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
	}

conv_ufrom_int: {
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_ufrom_int_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
	}
}

static bool attr_w gen_constant(struct codegen_context *ctx, bool real, unsigned op_size, bool shrt, frame_t slot_r)
{
	uintbig_t c;
	if (shrt) {
		c = (int16_t)get_unaligned_16(ctx->current_position);
	} else switch (op_size) {
#define fx(n, type, utype, sz, bits)					\
		case n:							\
			c = (type)cat(get_unaligned_,bits)(ctx->current_position);\
			break;
		for_all_fixed(fx);
#undef fx
		default:
			internal(file_line, "gen_constant: invalid type %u", op_size);
	}
	if (op_size > OP_SIZE_NATIVE) {
		unsigned shift = (8U << OP_SIZE_NATIVE) - 1;
		g(gen_frame_store_imm_raw(ctx, OP_SIZE_NATIVE, slot_r, lo_word(OP_SIZE_NATIVE), c & (((uint64_t)2 << shift) - 1)));
		g(gen_frame_store_imm_raw(ctx, OP_SIZE_NATIVE, slot_r, hi_word(OP_SIZE_NATIVE), c >> 1 >> shift));
		if (real && slot_is_register(ctx, slot_r))
			g(unspill(ctx, slot_r));
		return true;
	} else if (real && slot_is_register(ctx, slot_r)) {
		if (ARCH_HAS_FP_GP_MOV) {
			g(gen_load_constant(ctx, R_SCRATCH_1, c));
			g(gen_mov(ctx, op_size, ctx->registers[slot_r], R_SCRATCH_1));
		} else {
			g(gen_frame_store_imm_raw(ctx, op_size, slot_r, 0, c));
			g(unspill(ctx, slot_r));
		}
	} else {
		g(gen_frame_store_imm(ctx, op_size, slot_r, 0, c));
	}
	return true;
}

static bool attr_w gen_real_constant(struct codegen_context *ctx, const struct type *t, frame_t slot_r)
{
	int64_t offset;
	if (is_power_of_2(t->size) && t->size <= sizeof(uintbig_t))
		return gen_constant(ctx, true, log_2(t->size), false, slot_r);

	g(load_function_offset(ctx, R_SCRATCH_3, offsetof(struct data, u_.function.code)));

	offset = (ctx->current_position - da(ctx->fn,function)->code) * sizeof(code_t);

	g(gen_memcpy_raw(ctx, R_FRAME, (size_t)slot_r * slot_size, R_SCRATCH_3, offset, t->size, minimum(t->align, sizeof(code_t))));
	if (slot_is_register(ctx, slot_r))
		g(unspill(ctx, slot_r));

	return true;
}

static bool attr_w gen_copy(struct codegen_context *ctx, unsigned op_size, frame_t slot_1, frame_t slot_r)
{
	unsigned reg1;
	if (unlikely(op_size > OP_SIZE_NATIVE)) {
		g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
		g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
		return true;
	} else {
		unsigned target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
		g(gen_frame_get(ctx, op_size, garbage, slot_1, target, &reg1));
		g(gen_frame_store(ctx, op_size, slot_r, 0, reg1));
		return true;
	}
}

static bool attr_w gen_fp_alu(struct codegen_context *ctx, unsigned real_type, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_2, frame_t slot_r)
{
	unsigned attr_unused fp_alu;
	size_t upc;
	unsigned attr_unused op_size = real_type_to_op_size(real_type);
	unsigned reg1, reg2, target;
	switch (op) {
		case OPCODE_REAL_OP_add:
		case OPCODE_REAL_OP_add_alt1:
		case OPCODE_REAL_OP_add_alt2: fp_alu = FP_ALU_ADD; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_add_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_subtract:
		case OPCODE_REAL_OP_subtract_alt1:
		case OPCODE_REAL_OP_subtract_alt2: fp_alu = FP_ALU_SUB; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_subtract_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_multiply:
		case OPCODE_REAL_OP_multiply_alt1:
		case OPCODE_REAL_OP_multiply_alt2: fp_alu = FP_ALU_MUL; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_multiply_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_divide:
		case OPCODE_REAL_OP_divide_alt1:
		case OPCODE_REAL_OP_divide_alt2: fp_alu = FP_ALU_DIV; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_divide_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_modulo:
		case OPCODE_REAL_OP_power:
		case OPCODE_REAL_OP_ldexp:
		case OPCODE_REAL_OP_atan2: upc = offsetof(struct cg_upcall_vector_s, REAL_binary_modulo_real16_t) + (op - OPCODE_REAL_OP_modulo) * TYPE_REAL_N * sizeof(void (*)(void)); goto do_upcall;
		case OPCODE_REAL_OP_equal:
		case OPCODE_REAL_OP_equal_alt1:
		case OPCODE_REAL_OP_equal_alt2: fp_alu = FP_COND_E; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_equal_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_not_equal:
		case OPCODE_REAL_OP_not_equal_alt1:
		case OPCODE_REAL_OP_not_equal_alt2: fp_alu = FP_COND_NE; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_not_equal_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_less:
		case OPCODE_REAL_OP_less_alt1:
		case OPCODE_REAL_OP_less_alt2: fp_alu = FP_COND_B; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_less_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_less_equal:
		case OPCODE_REAL_OP_less_equal_alt1:
		case OPCODE_REAL_OP_less_equal_alt2: fp_alu = FP_COND_BE; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_less_equal_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_greater:
		case OPCODE_REAL_OP_greater_alt1:
		case OPCODE_REAL_OP_greater_alt2: fp_alu = FP_COND_A; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_greater_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_greater_equal:
		case OPCODE_REAL_OP_greater_equal_alt1:
		case OPCODE_REAL_OP_greater_equal_alt2: fp_alu = FP_COND_AE; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_greater_equal_real16_t); goto do_cmp;
		default: internal(file_line, "gen_fp_alu: unsupported operation %u", op);
	}

do_alu:
	if ((SUPPORTED_FP >> real_type) & 1) {
#if defined(ARCH_IA64)
		if (unlikely(fp_alu == FP_ALU_DIV))
			goto do_upcall;
#endif
#if defined(ARCH_X86)
		if (1)
#elif defined(ARCH_S390)
		if ((op_size <= OP_SIZE_8 && (size_t)slot_2 * slot_size < 4096) || slot_is_register(ctx, slot_2))
#else
		if (slot_is_register(ctx, slot_2))
#endif
		{
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, slot_2, FR_SCRATCH_1);
			g(gen_frame_get(ctx, op_size, garbage, slot_1, FR_SCRATCH_1, &reg1));
			if (slot_is_register(ctx, slot_2)) {
				g(gen_3address_fp_alu(ctx, op_size, fp_alu, target, reg1, ctx->registers[slot_2]));
			} else {
				if (target != reg1 && !ARCH_IS_3ADDRESS_FP) {
					g(gen_mov(ctx, op_size, target, reg1));
					reg1 = target;
				}
				g(gen_address(ctx, R_FRAME, (size_t)slot_2 * slot_size, IMM_PURPOSE_VLDR_VSTR_OFFSET, op_size));
				gen_insn(INSN_FP_ALU, op_size, fp_alu, 0);
				gen_one(target);
				gen_one(reg1);
				gen_address_offset();
			}
			g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			return true;
		}
#if defined(ARCH_ALPHA)
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		g(gen_frame_get(ctx, op_size, zero_x, slot_2, FR_SCRATCH_2, &reg2));
		target = gen_frame_target(ctx, slot_r, slot_1, slot_2, FR_SCRATCH_3);
		g(gen_3address_fp_alu(ctx, op_size, fp_alu, target, reg1, reg2));
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
#else
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		g(gen_frame_get(ctx, op_size, zero_x, slot_2, FR_SCRATCH_2, &reg2));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_1);
		g(gen_3address_fp_alu(ctx, op_size, fp_alu, target, reg1, reg2));
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
#endif
		return true;
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		if (real_type != 3) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			g(gen_frame_load_x87(ctx, INSN_X87_ALU, op_size, fp_alu, slot_1));
		} else {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			gen_insn(INSN_X87_ALUP, op_size, fp_alu, 0);
			gen_one(R_ST1);
		}
		g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		g(gen_frame_get(ctx, op_size, zero_x, slot_2, FR_SCRATCH_2, &reg2));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_1);
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(reg2);
		gen_insn(INSN_FP_ALU, OP_SIZE_4, fp_alu, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
		gen_insn(INSN_FP_CVT, OP_SIZE_4, op_size, 0);
		gen_one(target);
		gen_one(FR_SCRATCH_1);
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}
#endif
	goto do_upcall;

do_cmp:
	if ((SUPPORTED_FP >> real_type) & 1
#if defined(ARCH_ALPHA)
		&& OS_SUPPORTS_TRAPS
#endif
	) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		g(gen_frame_get(ctx, op_size, zero_x, slot_2, FR_SCRATCH_2, &reg2));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
#if defined(ARCH_ALPHA)
		gen_insn(INSN_FP_CMP_DEST_REG_TRAP, op_size, fp_alu == FP_COND_NE ? FP_COND_E : fp_alu, 0);
		gen_one(FR_SCRATCH_3);
		gen_one(reg1);
		gen_one(reg2);
		gen_four(label_ovf);

		if (!ARCH_HAS_FP_GP_MOV) {
			g(gen_frame_store_raw(ctx, OP_SIZE_4, slot_r, 0, FR_SCRATCH_3));
			g(gen_frame_load_raw(ctx, OP_SIZE_4, sign_x, slot_r, 0, false, target));
		} else {
			g(gen_mov(ctx, OP_SIZE_4, target, FR_SCRATCH_3));
		}

		if (fp_alu == FP_COND_NE) {
			g(gen_imm(ctx, 0, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, COND_E, 0);
			gen_one(target);
			gen_one(target);
			gen_imm_offset();
		} else {
			g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHR, target, target, 30, 0));
		}

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));

		return true;
#elif defined(ARCH_IA64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_P, 0);
		gen_one(R_CMP_RESULT);
		gen_one(reg1);
		gen_one(reg2);

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label_ovf);

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, fp_alu, 0);
		gen_one(R_CMP_RESULT);
		gen_one(reg1);
		gen_one(reg2);

		g(gen_mov(ctx, OP_SIZE_NATIVE, target, R_CMP_RESULT));

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));

		return true;
#elif defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC)
		gen_insn(INSN_FP_CMP_COND, op_size, FP_COND_P, 1);
		gen_one(reg1);
		gen_one(reg2);

		gen_insn(INSN_JMP_FP_TEST, 0, FP_COND_P, 0);
		gen_four(label_ovf);

		gen_insn(INSN_FP_CMP_COND, op_size, fp_alu, 1);
		gen_one(reg1);
		gen_one(reg2);

		gen_insn(INSN_FP_TEST_REG, OP_SIZE_NATIVE, fp_alu, 0);
		gen_one(target);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));

		return true;
#elif defined(ARCH_RISCV64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(reg1);
		gen_one(reg1);

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(R_SCRATCH_2);
		gen_one(reg2);
		gen_one(reg2);

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_AND, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, 0));

		g(gen_jmp_on_zero(ctx, OP_SIZE_NATIVE, R_SCRATCH_1, COND_E, label_ovf));

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, fp_alu == FP_COND_NE ? FP_COND_E : fp_alu, 0);
		gen_one(target);
		gen_one(reg1);
		gen_one(reg2);

		if (fp_alu == FP_COND_NE) {
			g(gen_imm(ctx, 1, IMM_PURPOSE_XOR, OP_SIZE_NATIVE));
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_XOR, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, ALU_XOR, false, is_imm(), ctx->const_imm));
			gen_one(target);
			gen_one(target);
			gen_imm_offset();
		}

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));
		return true;
#else
		gen_insn(INSN_FP_CMP, op_size, 0, 1);
		gen_one(reg1);
		gen_one(reg2);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);
		g(gen_frame_set_cond(ctx, op_size, false, fp_alu, slot_r));
		return true;
#endif
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		if (likely(cpu_test_feature(CPU_FEATURE_cmov))) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FCOMIP, op_size, 0, 0);
			gen_one(R_ST1);
			gen_insn(INSN_X87_FSTP, op_size, 0, 0);
			gen_one(R_ST0);
			gen_insn(INSN_JMP_COND, op_size, COND_P, 0);
			gen_four(label_ovf);
			g(gen_frame_set_cond(ctx, op_size, false, fp_alu & 0xf, slot_r));
			return true;
		}

		if (real_type != 3) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			g(gen_frame_load_x87(ctx, INSN_X87_FCOMP, op_size, 0, slot_2));
		} else {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FCOMPP, op_size, 0, 0);
		}

		gen_insn(INSN_X87_FNSTSW, 0, 0, 0);
		gen_one(R_AX);
		gen_one(R_AX);

		gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
		gen_one(R_AX);
		gen_one(ARG_IMM);
		gen_eight(0x0400);

		gen_insn(INSN_JMP_COND, OP_SIZE_2, COND_NE, 0);
		gen_four(label_ovf);

		switch (fp_alu) {
			case FP_COND_E:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x4000);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_NE, slot_r));
				break;
			case FP_COND_NE:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x4000);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_E, slot_r));
				break;
			case FP_COND_B:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x0100);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_NE, slot_r));
				break;
			case FP_COND_BE:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x4100);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_NE, slot_r));
				break;
			case FP_COND_A:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x4100);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_E, slot_r));
				break;
			case FP_COND_AE:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x0100);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_E, slot_r));
				break;
			default:
				internal(file_line, "gen_fp_alu: invalid condition %u", fp_alu);
		}
		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		g(gen_frame_get(ctx, op_size, zero_x, slot_2, FR_SCRATCH_2, &reg2));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(reg2);
		gen_insn(INSN_FP_CMP, OP_SIZE_4, 0, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);
		g(gen_frame_set_cond(ctx, op_size, false, fp_alu, slot_r));
		return true;
	}
#endif

do_upcall:
	return gen_alu_typed_upcall(ctx, upc, real_type, slot_1, slot_2, slot_r, label_ovf);
}

#define OP_IS_ROUND(alu)	((alu) == FP_ALU1_ROUND || (alu) == FP_ALU1_FLOOR || (alu) == FP_ALU1_CEIL || (alu) == FP_ALU1_TRUNC)

static bool attr_w gen_fp_alu1(struct codegen_context *ctx, unsigned real_type, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_r)
{
	unsigned attr_unused fp_alu;
	size_t upc;
	unsigned attr_unused op_size = real_type_to_op_size(real_type);
	unsigned reg1, target;
	switch (op) {
		case OPCODE_REAL_OP_neg:
		case OPCODE_REAL_OP_neg_alt1:
		case OPCODE_REAL_OP_neg_alt2: fp_alu = FP_ALU1_NEG; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_neg_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_sqrt:
		case OPCODE_REAL_OP_sqrt_alt1:
		case OPCODE_REAL_OP_sqrt_alt2: fp_alu = FP_ALU1_SQRT; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_sqrt_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_round: fp_alu = FP_ALU1_ROUND; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_round_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_floor: fp_alu = FP_ALU1_FLOOR; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_floor_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_ceil: fp_alu = FP_ALU1_CEIL; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_ceil_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_trunc: fp_alu = FP_ALU1_TRUNC; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_trunc_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_to_int:
		case OPCODE_REAL_OP_to_int_alt1:
		case OPCODE_REAL_OP_to_int_alt2: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_to_int_real16_t); goto do_to_int;
		case OPCODE_REAL_OP_from_int:
		case OPCODE_REAL_OP_from_int_alt1:
		case OPCODE_REAL_OP_from_int_alt2: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_from_int_real16_t); label_ovf = 0; goto do_from_int;
		case OPCODE_REAL_OP_is_exception:
		case OPCODE_REAL_OP_is_exception_alt1:
		case OPCODE_REAL_OP_is_exception_alt2: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_is_exception_real16_t); label_ovf = 0; goto do_is_exception;
		default: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_cbrt_real16_t) + (op - OPCODE_REAL_OP_cbrt) * TYPE_REAL_N * sizeof(void (*)(void)); label_ovf = 0; goto do_upcall;
	}

do_alu:
	if ((SUPPORTED_FP >> real_type) & 1 && (
#if defined(ARCH_ALPHA)
		fp_alu == FP_ALU1_NEG ||
		(fp_alu == FP_ALU1_SQRT && cpu_test_feature(CPU_FEATURE_fix)) ||
#elif defined(ARCH_ARM32)
		fp_alu == FP_ALU1_NEG ||
		fp_alu == FP_ALU1_SQRT ||
#elif defined(ARCH_ARM64)
		true ||
#elif defined(ARCH_IA64)
		fp_alu == FP_ALU1_NEG ||
#elif defined(ARCH_LOONGARCH64)
		fp_alu == FP_ALU1_NEG ||
		fp_alu == FP_ALU1_SQRT ||
		fp_alu == FP_ALU1_ROUND ||
#elif defined(ARCH_MIPS)
		fp_alu == FP_ALU1_NEG ||
		(fp_alu == FP_ALU1_SQRT && MIPS_HAS_SQRT) ||
#elif defined(ARCH_PARISC)
		(fp_alu == FP_ALU1_NEG && PA_20) ||
		fp_alu == FP_ALU1_SQRT ||
#elif defined(ARCH_POWER)
		fp_alu == FP_ALU1_NEG ||
		(fp_alu == FP_ALU1_SQRT && cpu_test_feature(CPU_FEATURE_p2) && real_type != 4) ||
#elif defined(ARCH_S390)
		true ||
#elif defined(ARCH_SPARC)
		fp_alu == FP_ALU1_NEG ||
		fp_alu == FP_ALU1_SQRT ||
#elif defined(ARCH_RISCV64)
		fp_alu == FP_ALU1_NEG ||
		fp_alu == FP_ALU1_SQRT ||
#elif defined(ARCH_X86)
		fp_alu == FP_ALU1_SQRT ||
		(OP_IS_ROUND(fp_alu) && cpu_test_feature(CPU_FEATURE_sse41)) ||
#endif
		false)) {
#if defined(ARCH_S390)
		if (op_size <= OP_SIZE_8 && (size_t)slot_1 * slot_size < 4096 && fp_alu == FP_ALU1_SQRT) {
			target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_1);
			if (slot_is_register(ctx, slot_1)) {
				gen_insn(INSN_FP_ALU1, op_size, fp_alu, 0);
				gen_one(target);
				gen_one(ctx->registers[slot_1]);
				g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			} else {
				g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size, IMM_PURPOSE_VLDR_VSTR_OFFSET, op_size));
				gen_insn(INSN_FP_ALU1, op_size, fp_alu, 0);
				gen_one(target);
				gen_address_offset();
				g(gen_frame_store(ctx, op_size, slot_r, 0, target));
			}
			return true;
		}
#endif
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_2);
		gen_insn(INSN_FP_ALU1, op_size, fp_alu, 0);
		gen_one(target);
		gen_one(reg1);
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		if (fp_alu == FP_ALU1_NEG) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FCHS, op_size, 0, 0);
			g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
			return true;
		} else if (fp_alu == FP_ALU1_SQRT) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FSQRT, op_size, 0, 0);
			g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
			return true;
		} else if (fp_alu == FP_ALU1_ROUND) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FRNDINT, op_size, 0, 0);
			g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
			return true;
		}
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1 && (
#if defined(ARCH_ARM32)
		fp_alu == FP_ALU1_NEG ||
		fp_alu == FP_ALU1_SQRT ||
#elif defined(ARCH_ARM64)
		true ||
#elif defined(ARCH_X86)
		fp_alu == FP_ALU1_SQRT ||
		(OP_IS_ROUND(fp_alu) && cpu_test_feature(CPU_FEATURE_sse41)) ||
#endif
		false)) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_1);
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(target);
		gen_one(reg1);
		gen_insn(INSN_FP_ALU1, OP_SIZE_4, fp_alu, 0);
		gen_one(target);
		gen_one(target);
		gen_insn(INSN_FP_CVT, OP_SIZE_4, op_size, 0);
		gen_one(target);
		gen_one(target);
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}
#endif
	goto do_upcall;

do_to_int:
	if ((SUPPORTED_FP >> real_type) & 1
#if defined(ARCH_ALPHA)
		&& OS_SUPPORTS_TRAPS
#endif
#if defined(ARCH_MIPS)
		&& MIPS_HAS_TRUNC
#endif
	) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		goto do_cvt_to_int;
do_cvt_to_int:
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
#if defined(ARCH_X86)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(target);
		gen_one(reg1);

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, target, sign_bit(uint_default_t), COND_E, label_ovf));

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_ARM) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS)
#if defined(ARCH_ARM)
		gen_insn(INSN_FP_CMP, op_size, 0, 1);
		gen_one(reg1);
		gen_one(reg1);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);
#else
		gen_insn(INSN_FP_CMP_COND, op_size, FP_COND_P, 1);
		gen_one(reg1);
		gen_one(reg1);

		gen_insn(INSN_JMP_FP_TEST, 0, FP_COND_P, 0);
		gen_four(label_ovf);
#endif
#if defined(ARCH_ARM32) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);

		g(gen_mov(ctx, OP_SIZE_INT, target, FR_SCRATCH_1));
#else
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(target);
		gen_one(reg1);
#endif
		g(gen_imm(ctx, (int_default_t)(sign_bit(uint_default_t) + 1), IMM_PURPOSE_ADD, OP_SIZE_INT));
		gen_insn(INSN_ALU, OP_SIZE_INT, ALU_ADD, ALU_WRITES_FLAGS(OP_SIZE_INT, ALU_ADD, false, is_imm(), ctx->const_imm));
		gen_one(R_SCRATCH_2);
		gen_one(target);
		gen_imm_offset();

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_2, 1, COND_BE, label_ovf));

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_IA64)
		gen_insn(INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);

		g(gen_mov(ctx, OP_SIZE_NATIVE, target, FR_SCRATCH_1));

		if (OP_SIZE_INT == OP_SIZE_4) {
			g(gen_extend(ctx, OP_SIZE_4, sign_x, R_SCRATCH_2, target));
			g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, target, R_SCRATCH_2, COND_NE, label_ovf));
		} else {
			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, target, sign_bit(uint64_t), COND_E, label_ovf));
		}

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_SPARC)
#if defined(ARCH_POWER)
		if (!cpu_test_feature(CPU_FEATURE_ppc))
			goto do_upcall;
		if (OP_SIZE_INT == OP_SIZE_4)
			goto do_upcall;
#endif
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);

		g(gen_frame_store_raw(ctx, OP_SIZE_INT, slot_r, 0, FR_SCRATCH_1));
		if (slot_is_register(ctx, slot_r))
			g(unspill(ctx, slot_r));
		g(gen_frame_load(ctx, OP_SIZE_INT, garbage, slot_r, 0, false, target));

		g(gen_imm(ctx, sign_bit(uint_default_t) + 1, IMM_PURPOSE_ADD, OP_SIZE_INT));
		gen_insn(INSN_ALU, i_size(OP_SIZE_INT), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_INT), ALU_ADD, false, is_imm(), ctx->const_imm));
		gen_one(R_SCRATCH_2);
		gen_one(target);
		gen_imm_offset();

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_2, 1, COND_BE, label_ovf));

		return true;
#endif
#if defined(ARCH_ALPHA)
		gen_insn(INSN_FP_TO_INT64_TRAP, op_size, 0, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(reg1);
		gen_four(label_ovf);

		if (OP_SIZE_INT == OP_SIZE_4) {
			gen_insn(INSN_FP_INT64_TO_INT32_TRAP, 0, 0, 0);
			gen_one(FR_SCRATCH_3);
			gen_one(FR_SCRATCH_2);
			gen_four(label_ovf);
			g(gen_frame_store_raw(ctx, OP_SIZE_INT, slot_r, 0, FR_SCRATCH_3));
		} else {
			g(gen_frame_store_raw(ctx, OP_SIZE_INT, slot_r, 0, FR_SCRATCH_2));
		}
		if (slot_is_register(ctx, slot_r))
			g(unspill(ctx, slot_r));
		return true;
#endif
#if defined(ARCH_S390)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 1);
		gen_one(target);
		gen_one(reg1);

		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, target));
		return true;
#endif
#if defined(ARCH_RISCV64)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(target);
		gen_one(reg1);

		g(gen_load_constant(ctx, R_SCRATCH_2, sign_bit(int_default_t)));

		g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, target, R_SCRATCH_2, COND_E, label_ovf));

		g(gen_imm(ctx, -1, IMM_PURPOSE_XOR, i_size(size)));
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_XOR, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, ALU_XOR, false, is_imm(), ctx->const_imm));
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_2);
		gen_imm_offset();

		g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, target, R_SCRATCH_2, COND_E, label_ovf));

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, target));
		return true;
#endif
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));

		if (likely(cpu_test_feature(CPU_FEATURE_sse3))) {
			g(gen_frame_store_x87(ctx, INSN_X87_FISTTP, OP_SIZE_INT, slot_r));
		} else {
			gen_insn(INSN_PUSH, OP_SIZE_NATIVE, 0, 0);
			gen_one(ARG_IMM);
			gen_eight(0x0f7f);

			gen_insn(INSN_X87_FLDCW, 0, 0, 0);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SP);
			gen_eight(0);

			g(gen_frame_store_x87(ctx, INSN_X87_FISTP, OP_SIZE_INT, slot_r));

			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SP);
			gen_eight(0);
			gen_one(ARG_IMM);
			gen_eight(0x037f);

			gen_insn(INSN_X87_FLDCW, 0, 0, 0);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SP);
			gen_eight(0);

			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, 1);
			gen_one(R_SP);
			gen_one(R_SP);
			gen_one(ARG_IMM);
			gen_eight(1 << OP_SIZE_NATIVE);
		}
		if (slot_is_register(ctx, slot_r))
			g(unspill(ctx, slot_r));
		g(gen_frame_load(ctx, OP_SIZE_INT, garbage, slot_r, 0, false, R_SCRATCH_1));

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_1, sign_bit(int_default_t), COND_E, label_ovf));

		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);
		reg1 = FR_SCRATCH_1;
		real_type = 1;
		op_size = real_type_to_op_size(real_type);
		goto do_cvt_to_int;
	}
#endif
	goto do_upcall;

do_from_int:
	if ((SUPPORTED_FP >> real_type) & 1) {
#if defined(ARCH_ALPHA) || defined(ARCH_ARM32) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_SPARC)
		int int_op_size = OP_SIZE_INT;
#if defined(ARCH_POWER)
		if (int_op_size == OP_SIZE_4)
			goto do_upcall;
		if (op_size == OP_SIZE_4 && !cpu_test_feature(CPU_FEATURE_v206))
			goto do_upcall;
		if (op_size == OP_SIZE_8 && !cpu_test_feature(CPU_FEATURE_ppc))
			goto do_upcall;
#endif
		if (slot_is_register(ctx, slot_1))
			g(spill(ctx, slot_1));
		g(gen_frame_load_raw(ctx, int_op_size, zero_x, slot_1, 0, false, FR_SCRATCH_1));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_2);
#if defined(ARCH_ALPHA)
		if (OP_SIZE_INT == OP_SIZE_4) {
			gen_insn(INSN_MOVSX, OP_SIZE_4, 0, 0);
			gen_one(FR_SCRATCH_1);
			gen_one(FR_SCRATCH_1);

			int_op_size = OP_SIZE_8;
		}
#endif
		gen_insn(int_op_size == OP_SIZE_4 ? INSN_FP_FROM_INT32 : INSN_FP_FROM_INT64, op_size, 0, 0);
		gen_one(target);
		gen_one(FR_SCRATCH_1);

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#elif defined(ARCH_IA64)
		g(gen_frame_get(ctx, OP_SIZE_INT, sign_x, slot_1, R_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_1);

		g(gen_mov(ctx, OP_SIZE_NATIVE, target, reg1));

		gen_insn(INSN_FP_FROM_INT64, op_size, 0, 0);
		gen_one(target);
		gen_one(target);

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#else
		g(gen_frame_get(ctx, OP_SIZE_INT, garbage, slot_1, R_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_1);

		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_FROM_INT32 : INSN_FP_FROM_INT64, op_size, 0, 0);
		gen_one(target);
		gen_one(reg1);

		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
#endif
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		if (slot_is_register(ctx, slot_1))
			g(spill(ctx, slot_1));
		g(gen_frame_load_x87(ctx, INSN_X87_FILD, OP_SIZE_INT, 0, slot_1));
		g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, FR_SCRATCH_1);
#if defined(ARCH_ARM32)
		g(gen_frame_get(ctx, OP_SIZE_INT, zero_x, slot_1, FR_SCRATCH_1, &reg1));

		gen_insn(INSN_FP_FROM_INT32, OP_SIZE_4, 0, 0);
		gen_one(target);
		gen_one(reg1);
#else
		g(gen_frame_get(ctx, OP_SIZE_INT, garbage, slot_1, R_SCRATCH_1, &reg1));
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_FROM_INT32 : INSN_FP_FROM_INT64, OP_SIZE_4, 0, 0);
		gen_one(target);
		gen_one(reg1);
#endif
		gen_insn(INSN_FP_CVT, OP_SIZE_4, op_size, 0);
		gen_one(target);
		gen_one(target);
		g(gen_frame_store(ctx, op_size, slot_r, 0, target));
		return true;
	}
#endif
	goto do_upcall;

do_is_exception:
	if ((SUPPORTED_FP >> real_type) & 1) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		target = gen_frame_target(ctx, slot_r, NO_FRAME_T, NO_FRAME_T, R_SCRATCH_1);
#if defined(ARCH_ALPHA)
		gen_insn(INSN_FP_CMP_UNORDERED_DEST_REG, op_size, 0, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);

		if (!cpu_test_feature(CPU_FEATURE_fix)) {
			g(gen_frame_store_raw(ctx, OP_SIZE_4, slot_r, 0, FR_SCRATCH_2));
			g(gen_frame_load_raw(ctx, OP_SIZE_4, sign_x, slot_r, 0, false, target));
		} else {
			g(gen_mov(ctx, OP_SIZE_4, target, FR_SCRATCH_2));
		}

		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHR, target, target, 30, 0));

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));

		return true;
#elif defined(ARCH_IA64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_P, 0);
		gen_one(R_CMP_RESULT);
		gen_one(reg1);
		gen_one(reg1);

		g(gen_mov(ctx, OP_SIZE_NATIVE, target, R_CMP_RESULT));

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));
#elif defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC)
		gen_insn(INSN_FP_CMP_COND, op_size, FP_COND_P, 1);
		gen_one(reg1);
		gen_one(reg1);

		gen_insn(INSN_FP_TEST_REG, OP_SIZE_NATIVE, FP_COND_P, 0);
		gen_one(target);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));
#elif defined(ARCH_RISCV64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(target);
		gen_one(reg1);
		gen_one(reg1);

		g(gen_imm(ctx, 1, IMM_PURPOSE_XOR, OP_SIZE_NATIVE));
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_XOR, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, ALU_XOR, false, is_imm(), ctx->const_imm));
		gen_one(target);
		gen_one(target);
		gen_imm_offset();

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, target));
#else
		gen_insn(INSN_FP_CMP, op_size, 0, 1);
		gen_one(reg1);
		gen_one(reg1);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		g(gen_frame_set_cond(ctx, op_size, false, FP_COND_P, slot_r));
#endif
		return true;
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
		if (likely(cpu_test_feature(CPU_FEATURE_cmov))) {
			gen_insn(INSN_X87_FCOMIP, op_size, 0, 0);
			gen_one(R_ST0);

			g(gen_frame_set_cond(ctx, op_size, false, COND_P, slot_r));
			return true;
		}

		gen_insn(INSN_X87_FCOMP, op_size, 0, 0);
		gen_one(R_ST0);

		gen_insn(INSN_X87_FNSTSW, 0, 0, 0);
		gen_one(R_AX);
		gen_one(R_AX);

		gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
		gen_one(R_AX);
		gen_one(ARG_IMM);
		gen_eight(0x0400);

		g(gen_frame_set_cond(ctx, op_size, false, COND_NE, slot_r));

		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(reg1);
		gen_insn(INSN_FP_CMP, OP_SIZE_4, 0, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		g(gen_frame_set_cond(ctx, op_size, false, FP_COND_P, slot_r));
		return true;
	}
#endif

do_upcall:
	g(gen_alu_typed_upcall(ctx, upc, real_type, slot_1, NO_FRAME_T, slot_r, label_ovf));
	return true;
}

static bool attr_w gen_is_exception(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r)
{
	uint32_t no_ex_label, escape_label;
	const struct type *type = get_type_of_local(ctx, slot_1);

	no_ex_label = alloc_label(ctx);
	if (unlikely(!no_ex_label))
		return false;
	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (TYPE_IS_FLAT(type))
		g(gen_test_1_jz_cached(ctx, slot_1, no_ex_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, zero_x, slot_1, 0, false, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, slot_1, escape_label));

	if (!TYPE_IS_FLAT(type)) {
		g(gen_compare_da_tag(ctx, R_SCRATCH_1, DATA_TAG_flat, COND_E, escape_label, R_SCRATCH_1));
	}

	gen_label(no_ex_label);
	g(gen_frame_clear(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r));

	flag_set(ctx, slot_r, false);

	return true;
}

static bool attr_w gen_system_property(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_1, escape_label));

	g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_system_property), 1));

	g(gen_frame_load(ctx, OP_SIZE_INT, garbage, slot_1, 0, false, R_ARG0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_system_property), 1));

	g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_RET0));

	flag_set(ctx, slot_1, false);
	flag_set(ctx, slot_r, false);

	return true;
}

static bool attr_w gen_alu_jmp(struct codegen_context *ctx, unsigned mode, unsigned op_size, unsigned op, frame_t slot_1, frame_t slot_2, int32_t jmp_offset, bool *failed)
{
	unsigned alu;
	enum extend ex;
	unsigned reg1;
	unsigned attr_unused reg2;
#if 0
	*failed = true; return true;
#endif
	switch (mode) {
		case MODE_FIXED: switch (op) {
			case OPCODE_FIXED_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_FIXED_OP_not_equal:		alu = COND_NE; goto do_compare;
			case OPCODE_FIXED_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_FIXED_OP_less_equal:	alu = COND_LE; goto do_compare;
			case OPCODE_FIXED_OP_greater:		alu = COND_G; goto do_compare;
			case OPCODE_FIXED_OP_greater_equal:	alu = COND_GE; goto do_compare;
			case OPCODE_FIXED_OP_uless:		alu = COND_B; goto do_compare;
			case OPCODE_FIXED_OP_uless_equal:	alu = COND_BE; goto do_compare;
			case OPCODE_FIXED_OP_ugreater:		alu = COND_A; goto do_compare;
			case OPCODE_FIXED_OP_ugreater_equal:	alu = COND_AE; goto do_compare;
			case OPCODE_FIXED_OP_bt:		*failed = true; return true;
			default:				internal(file_line, "gen_alu_jmp: unsupported fixed operation %u", op);
		}
		case MODE_INT: switch (op) {
			case OPCODE_INT_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_INT_OP_not_equal:		alu = COND_NE; goto do_compare;
			case OPCODE_INT_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_INT_OP_less_equal:		alu = COND_LE; goto do_compare;
			case OPCODE_INT_OP_greater:		alu = COND_G; goto do_compare;
			case OPCODE_INT_OP_greater_equal:	alu = COND_GE; goto do_compare;
			case OPCODE_INT_OP_bt:			*failed = true; return true;
			default:				internal(file_line, "gen_alu_jmp: unsupported int operation %u", op);
		}
		case MODE_BOOL: switch (op) {
			case OPCODE_BOOL_OP_and:		alu = ALU_AND; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_or:			alu = ALU_OR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_equal:		alu = COND_E; mode = MODE_FIXED; goto do_compare;
			case OPCODE_BOOL_OP_not_equal:		alu = COND_NE; mode = MODE_FIXED; goto do_compare;
			case OPCODE_BOOL_OP_less:		alu = COND_L; mode = MODE_FIXED; goto do_compare;
			case OPCODE_BOOL_OP_less_equal:		alu = COND_LE; mode = MODE_FIXED; goto do_compare;
			case OPCODE_BOOL_OP_greater:		alu = COND_G; mode = MODE_FIXED; goto do_compare;
			case OPCODE_BOOL_OP_greater_equal:	alu = COND_GE; mode = MODE_FIXED; goto do_compare;
			default:				internal(file_line, "gen_alu_jmp: unsupported bool operation %u", op);
		}
	}
	internal(file_line, "gen_alu_jmp: unsupported mode %u", mode);
do_compare: {
		bool attr_unused logical;
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
			*failed = true;
			return true;
		}
		if (slot_is_register(ctx, slot_2) && !slot_is_register(ctx, slot_1)) {
			frame_t s = slot_1;
			slot_1 = slot_2;
			slot_2 = s;
			switch (alu) {
				case COND_L:	alu = COND_G; break;
				case COND_LE:	alu = COND_GE; break;
				case COND_G:	alu = COND_L; break;
				case COND_GE:	alu = COND_LE; break;
				case COND_B:	alu = COND_A; break;
				case COND_BE:	alu = COND_AE; break;
				case COND_A:	alu = COND_B; break;
				case COND_AE:	alu = COND_BE; break;
			}
		}
		ex = op_size == i_size_cmp(op_size) + (unsigned)zero ? garbage : alu == COND_L || alu == COND_LE || alu == COND_G || alu == COND_GE || ARCH_PREFERS_SX(op_size) ? sign_x : zero_x;
		g(gen_frame_get(ctx, op_size, ex, slot_1, R_SCRATCH_1, &reg1));
		if (ARCH_HAS_JMP_2REGS(alu)) {
			g(gen_frame_get(ctx, op_size, ex, slot_2, R_SCRATCH_2, &reg2));
			g(gen_jump(ctx, jmp_offset, i_size_cmp(op_size), alu ^ 1, reg1, reg2));
			return true;
		}
#if ARCH_HAS_FLAGS
		logical = COND_IS_LOGICAL(alu ^ 1);
		g(gen_frame_load_cmp(ctx, op_size, logical, ex, false, slot_2, 0, false, reg1));
		g(gen_jump(ctx, jmp_offset, op_size, alu ^ 1, -1U, -1U));
#else
		g(gen_frame_get(ctx, op_size, ex, slot_2, R_SCRATCH_2, &reg2));
		g(gen_cmp_dest_reg(ctx, op_size, reg1, reg2, R_CMP_RESULT, 0, alu));
		g(gen_jump(ctx, jmp_offset, OP_SIZE_NATIVE, COND_E, R_CMP_RESULT, -1U));
#endif
		return true;
	}
do_alu: {
		if (slot_is_register(ctx, slot_2) && !slot_is_register(ctx, slot_1)) {
			frame_t s = slot_1;
			slot_1 = slot_2;
			slot_2 = s;
		}
		ex = op_size == i_size(op_size) + (unsigned)zero ? garbage : ARCH_PREFERS_SX(op_size) ? sign_x : zero_x;
		g(gen_frame_get(ctx, op_size, ex, slot_1, R_SCRATCH_1, &reg1));
#if defined(ARCH_X86)
		if (alu == ALU_AND && !slot_is_register(ctx, slot_2)) {
			g(gen_address(ctx, R_FRAME, (size_t)slot_2 * slot_size, IMM_PURPOSE_LDR_OFFSET, op_size));
			gen_insn(INSN_TEST, i_size(op_size), 0, 1);
			gen_one(reg1);
			gen_address_offset();
			g(gen_jump(ctx, jmp_offset, op_size, COND_E, -1U, -1U));
			return true;
		}
#endif
		g(gen_frame_get(ctx, op_size, ex, slot_2, R_SCRATCH_2, &reg2));
#if ARCH_HAS_FLAGS && !defined(ARCH_S390)
		if (alu == ALU_AND) {
			gen_insn(INSN_TEST, i_size(op_size), 0, 1);
			gen_one(reg1);
			gen_one(reg2);
			g(gen_jump(ctx, jmp_offset, op_size, COND_E, -1U, -1U));
			return true;
		}
#endif
#if defined(ARCH_ARM64)
		if (alu == ALU_OR)
			goto skip_flags;
#endif
#if ARCH_HAS_FLAGS
		g(gen_3address_alu(ctx, i_size(op_size), alu, R_SCRATCH_1, reg1, reg2, 1));
		g(gen_jump(ctx, jmp_offset, i_size(op_size), COND_E, -1U, -1U));
		return true;
#endif
		goto skip_flags;
skip_flags:
		g(gen_3address_alu(ctx, i_size(op_size), alu, R_SCRATCH_1, reg1, reg2, 0));
		g(gen_jump(ctx, jmp_offset, i_size(op_size), COND_E, R_SCRATCH_1, -1U));
		return true;
	}
}

static bool attr_w gen_fp_alu_jmp(struct codegen_context *ctx, unsigned real_type, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_2, int32_t jmp_offset, bool *failed)
{
	unsigned attr_unused fp_alu;
	unsigned attr_unused op_size = real_type_to_op_size(real_type);
	unsigned reg1, reg2;
	unsigned attr_unused target;
	switch (op) {
		case OPCODE_REAL_OP_equal:
		case OPCODE_REAL_OP_equal_alt1:
		case OPCODE_REAL_OP_equal_alt2:	fp_alu = FP_COND_E; goto do_cmp;
		case OPCODE_REAL_OP_not_equal:
		case OPCODE_REAL_OP_not_equal_alt1:
		case OPCODE_REAL_OP_not_equal_alt2: fp_alu = FP_COND_NE; goto do_cmp;
		case OPCODE_REAL_OP_less:
		case OPCODE_REAL_OP_less_alt1:
		case OPCODE_REAL_OP_less_alt2: fp_alu = FP_COND_B; goto do_cmp;
		case OPCODE_REAL_OP_less_equal:
		case OPCODE_REAL_OP_less_equal_alt1:
		case OPCODE_REAL_OP_less_equal_alt2: fp_alu = FP_COND_BE; goto do_cmp;
		case OPCODE_REAL_OP_greater:
		case OPCODE_REAL_OP_greater_alt1:
		case OPCODE_REAL_OP_greater_alt2: fp_alu = FP_COND_A; goto do_cmp;
		case OPCODE_REAL_OP_greater_equal:
		case OPCODE_REAL_OP_greater_equal_alt1:
		case OPCODE_REAL_OP_greater_equal_alt2: fp_alu = FP_COND_AE; goto do_cmp;
		default: internal(file_line, "gen_fp_alu_jmp: unsupported operation %u", op);
	}

do_cmp:
	if ((SUPPORTED_FP >> real_type) & 1
#if defined(ARCH_ALPHA)
		&& OS_SUPPORTS_TRAPS && cpu_test_feature(CPU_FEATURE_fix)
#endif
	) {
		g(gen_frame_get(ctx, op_size, zero_x, slot_1, FR_SCRATCH_1, &reg1));
		g(gen_frame_get(ctx, op_size, zero_x, slot_2, FR_SCRATCH_2, &reg2));
		target = R_SCRATCH_1;
#if defined(ARCH_ALPHA)
		gen_insn(INSN_FP_CMP_DEST_REG_TRAP, op_size, fp_alu == FP_COND_NE ? FP_COND_E : fp_alu, 0);
		gen_one(FR_SCRATCH_3);
		gen_one(reg1);
		gen_one(reg2);
		gen_four(label_ovf);

		g(gen_mov(ctx, OP_SIZE_4, target, FR_SCRATCH_3));

		if (fp_alu == FP_COND_NE) {
			g(gen_jump(ctx, jmp_offset, OP_SIZE_NATIVE, COND_NE, target, -1U));
		} else {
			g(gen_jump(ctx, jmp_offset, OP_SIZE_NATIVE, COND_E, target, -1U));
		}

		return true;
#elif defined(ARCH_IA64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_P, 0);
		gen_one(R_CMP_RESULT);
		gen_one(reg1);
		gen_one(reg2);

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label_ovf);

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, fp_alu, 0);
		gen_one(R_CMP_RESULT);
		gen_one(reg1);
		gen_one(reg2);

		g(gen_jump(ctx, jmp_offset, OP_SIZE_NATIVE, COND_E, R_CMP_RESULT, -1U));

		return true;
#elif defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC)
		gen_insn(INSN_FP_CMP_COND, op_size, FP_COND_P, 1);
		gen_one(reg1);
		gen_one(reg2);

		gen_insn(INSN_JMP_FP_TEST, 0, FP_COND_P, 0);
		gen_four(label_ovf);

		gen_insn(INSN_FP_CMP_COND, op_size, fp_alu ^ 1, 1);
		gen_one(reg1);
		gen_one(reg2);

		g(gen_jump(ctx, jmp_offset, OP_SIZE_NATIVE, fp_alu ^ 1, -1U, -1U));

		return true;
#elif defined(ARCH_RISCV64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(reg1);
		gen_one(reg1);

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(R_SCRATCH_2);
		gen_one(reg2);
		gen_one(reg2);

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_AND, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, 0));

		g(gen_jmp_on_zero(ctx, OP_SIZE_NATIVE, R_SCRATCH_1, COND_E, label_ovf));

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, fp_alu == FP_COND_NE ? FP_COND_E : fp_alu, 0);
		gen_one(target);
		gen_one(reg1);
		gen_one(reg2);

		if (fp_alu == FP_COND_NE) {
			g(gen_jump(ctx, jmp_offset, OP_SIZE_NATIVE, COND_NE, target, -1U));
		} else {
			g(gen_jump(ctx, jmp_offset, OP_SIZE_NATIVE, COND_E, target, -1U));
		}
		return true;
#else
		gen_insn(INSN_FP_CMP, op_size, 0, 1);
		gen_one(reg1);
		gen_one(reg2);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);
		g(gen_jump(ctx, jmp_offset, op_size, fp_alu ^ 1, -1U, -1U));
		return true;
#endif
	}
	*failed = true;
	return true;
}
