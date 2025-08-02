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

static bool attr_w gen_mov(struct codegen_context *ctx, unsigned size, unsigned dest, unsigned src)
{
	if (dest == src && (size == OP_SIZE_NATIVE || reg_is_fp(dest)))
		return true;

	gen_insn(INSN_MOV, size, 0, 0);
	gen_one(dest);
	gen_one(src);

	return true;
}

static bool attr_w gen_sanitize_returned_pointer(struct codegen_context attr_unused *ctx, unsigned attr_unused reg)
{
#if defined(ARCH_X86_X32)
	g(gen_mov(ctx, OP_SIZE_ADDRESS, reg, reg));
#endif
	return true;
}

static bool alu_is_commutative(unsigned alu)
{
	return alu == ALU_ADD || alu == ALU_OR || alu == ALU_AND || alu == ALU_XOR || alu == ALU_MUL || alu == ALU_UMULH || alu == ALU_SMULH;
}

static bool attr_w gen_3address_alu(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src1, unsigned src2, unsigned writes_flags)
{
	if (unlikely(dest == src2) && alu_is_commutative(alu)) {
		unsigned swap = src1;
		src1 = src2;
		src2 = swap;
	}
	if (!ARCH_IS_3ADDRESS(alu, writes_flags) && unlikely(dest == src2) && unlikely(dest != src1)) {
		internal(file_line, "gen_3address_alu: invalid registers: %u, %u, %x, %x, %x", size, alu, dest, src1, src2);
	}
	if (!ARCH_IS_3ADDRESS(alu, writes_flags) && dest != src1) {
		g(gen_mov(ctx, OP_SIZE_NATIVE, dest, src1));

		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(size, alu, false, false, 0) | writes_flags);
		gen_one(dest);
		gen_one(dest);
		gen_one(src2);

		return true;
	}
	gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(size, alu, false, false, 0) | writes_flags);
	gen_one(dest);
	gen_one(src1);
	gen_one(src2);
	return true;
}

static bool attr_w gen_3address_alu_imm(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src, int64_t imm, unsigned writes_flags)
{
	unsigned purpose = alu_purpose(alu);
	if (!ARCH_IS_3ADDRESS_IMM(alu, writes_flags) && dest != src) {
		g(gen_mov(ctx, OP_SIZE_NATIVE, dest, src));

		g(gen_imm(ctx, imm, purpose, i_size(OP_SIZE_ADDRESS)));
		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(size, alu, false, is_imm(), ctx->const_imm) | writes_flags);
		gen_one(dest);
		gen_one(dest);
		gen_imm_offset();

		return true;
	}
	g(gen_imm(ctx, imm, purpose, i_size(OP_SIZE_ADDRESS)));
	gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(size, alu, false, is_imm(), ctx->const_imm) | writes_flags);
	gen_one(dest);
	gen_one(src);
	gen_imm_offset();

	return true;
}

static bool attr_w attr_unused gen_3address_rot(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src1, unsigned src2)
{
#ifdef ARCH_X86
	if (dest == src1 && src2 == R_CX) {
		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, 1);
		gen_one(dest);
		gen_one(src1);
		gen_one(src2);

		return true;
	}
#endif
	if (!ARCH_IS_3ADDRESS_ROT(alu, size) && dest != src1) {
		if (unlikely(dest == src2))
			internal(file_line, "gen_3address_rot: invalid registers: %u, %u, %x, %x, %x", size, alu, dest, src1, src2);

		g(gen_mov(ctx, OP_SIZE_NATIVE, dest, src1));

		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu, size, false));
		gen_one(dest);
		gen_one(dest);
		gen_one(src2);

		return true;
	}
	gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu, size, false));
	gen_one(dest);
	gen_one(src1);
	gen_one(src2);

	return true;
}

static bool attr_w gen_3address_rot_imm(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src, int64_t imm, unsigned writes_flags)
{
	if (!ARCH_IS_3ADDRESS_ROT_IMM(alu) && dest != src) {
		g(gen_mov(ctx, OP_SIZE_NATIVE, dest, src));

		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu, size, true) | writes_flags);
		gen_one(dest);
		gen_one(dest);
		gen_one(ARG_IMM);
		gen_eight(imm);

		return true;
	}
	gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu, size, true) | writes_flags);
	gen_one(dest);
	gen_one(src);
	gen_one(ARG_IMM);
	gen_eight(imm);

	return true;
}

static bool attr_w gen_2address_alu1(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src, unsigned writes_flags)
{
#if defined(ARCH_S390)
	if (alu == ALU1_NOT) {
		g(gen_3address_alu_imm(ctx, size, ALU_XOR, dest, src, -1, writes_flags));

		return true;
	}
#endif
	if (!ARCH_IS_2ADDRESS(alu) && dest != src) {
		g(gen_mov(ctx, OP_SIZE_NATIVE, dest, src));

		gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(size), size, alu, ALU1_WRITES_FLAGS(alu) | writes_flags);
		gen_one(dest);
		gen_one(dest);

		return true;
	}
	gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(size), size, alu, ALU1_WRITES_FLAGS(alu) | writes_flags);
	gen_one(dest);
	gen_one(src);

	return true;
}

static bool attr_w gen_3address_fp_alu(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src1, unsigned src2)
{
	if (!ARCH_IS_3ADDRESS_FP && unlikely(dest == src2) && unlikely(dest != src1)) {
		internal(file_line, "gen_3address_fp_alu: invalid registers: %u, %u, %x, %x, %x", size, alu, dest, src1, src2);
	}
	if (!ARCH_IS_3ADDRESS_FP && dest != src1) {
		g(gen_mov(ctx, size, dest, src1));

		gen_insn(INSN_FP_ALU, size, alu, 0);
		gen_one(dest);
		gen_one(dest);
		gen_one(src2);

		return true;
	}
	gen_insn(INSN_FP_ALU, size, alu, 0);
	gen_one(dest);
	gen_one(src1);
	gen_one(src2);

	return true;
}


static bool attr_w attr_unused gen_load_two(struct codegen_context *ctx, unsigned dest, unsigned src, int64_t offset)
{
	if (!ARCH_HAS_BWX) {
#if defined(R_OFFSET_IMM)
		if (!(offset & 7)) {
			g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
			gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
			gen_one(dest);
			gen_address_offset();

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTWL, dest, dest, src, 0));
		} else {
			g(gen_imm(ctx, offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, is_imm(), ctx->const_imm));
			gen_one(R_OFFSET_IMM);
			gen_one(src);
			gen_imm_offset();

			gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
			gen_one(dest);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_OFFSET_IMM);
			gen_eight(0);

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTWL, dest, dest, R_OFFSET_IMM, 0));
		}
#endif
#if defined(ARCH_S390)
	} else if (!cpu_test_feature(CPU_FEATURE_extended_imm)) {
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_2));
		gen_insn(INSN_MOVSX, OP_SIZE_2, 0, 0);
		gen_one(dest);
		gen_address_offset();

		g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_AND, dest, dest, 0xffff, 0));
#endif
	} else {
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_2));
		gen_insn(INSN_MOV, OP_SIZE_2, 0, 0);
		gen_one(dest);
		gen_address_offset();
	}
	return true;
}

static bool attr_w gen_load_code_32(struct codegen_context *ctx, unsigned dest, unsigned src, int64_t offset)
{
#if ARG_MODE_N == 3 && defined(ARCH_ALPHA) && !(defined(C_BIG_ENDIAN) ^ CODE_ENDIAN) && defined(R_CONST_IMM)
	if (!ARCH_HAS_BWX && UNALIGNED_TRAP) {
		if (offset & 7) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_ADD, R_OFFSET_IMM, src, offset, 0));
			src = R_OFFSET_IMM;
			offset = 0;
		}
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
		gen_one(dest);
		gen_address_offset();

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTLL, dest, dest, src, 0));

		g(gen_address(ctx, src, offset + 3, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
		gen_one(R_CONST_IMM);
		gen_address_offset();

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTLH, R_CONST_IMM, R_CONST_IMM, src, 0));

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, dest, dest, R_CONST_IMM, 0));

		return true;
	}
#endif
#if ARG_MODE_N == 3 && defined(ARCH_MIPS) && !(defined(C_BIG_ENDIAN) ^ CODE_ENDIAN)
	if (!MIPS_R6 && UNALIGNED_TRAP) {
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
		gen_insn(INSN_MOV_LR, OP_SIZE_4, !CODE_ENDIAN, 0);
		gen_one(dest);
		gen_one(dest);
		gen_address_offset();

		g(gen_address(ctx, src, offset + 3, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
		gen_insn(INSN_MOV_LR, OP_SIZE_4, CODE_ENDIAN, 0);
		gen_one(dest);
		gen_one(dest);
		gen_address_offset();

		return true;
	}
#endif
#if ARG_MODE_N == 3 && defined(R_CONST_IMM)
#if !(defined(C_BIG_ENDIAN) ^ CODE_ENDIAN)
	if (UNALIGNED_TRAP)
#endif
	{
		g(gen_load_two(ctx, dest, src, offset));
		g(gen_load_two(ctx, R_CONST_IMM, src, offset + 2));
#if CODE_ENDIAN
		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, dest, dest, 16, false));
#else
		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_CONST_IMM, R_CONST_IMM, 16, false));
#endif
		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, dest, dest, R_CONST_IMM, 0));
		return true;
	}
#endif
	g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, ARG_MODE_N - 1));
	gen_insn(INSN_MOV, ARG_MODE_N - 1, 0, 0);
	gen_one(dest);
	gen_address_offset();
	return true;
}

static bool attr_w attr_unused gen_cmp_dest_reg(struct codegen_context *ctx, unsigned attr_unused size, unsigned reg1, unsigned reg2, unsigned reg_dest, int64_t imm, unsigned cond)
{
	unsigned neg_result = false;

#if defined(ARCH_ALPHA)
	if (cond == COND_NE) {
		if (reg2 == (unsigned)-1)
			g(gen_imm(ctx, imm, IMM_PURPOSE_CMP, i_size_cmp(size)));
		gen_insn(INSN_CMP_DEST_REG, i_size_cmp(size), COND_E, 0);
		gen_one(reg_dest);
		gen_one(reg1);
		if (reg2 == (unsigned)-1)
			gen_imm_offset();
		else
			gen_one(reg2);
		neg_result = true;
		goto done;
	}
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_RISCV64)
	if (cond == COND_E || cond == COND_NE) {
		unsigned rx;
		if (reg2 == (unsigned)-1 && !imm) {
			rx = reg1;
			goto skip_xor;
		}
		if (reg2 == (unsigned)-1)
			g(gen_imm(ctx, imm, IMM_PURPOSE_XOR, i_size(size)));
		gen_insn(INSN_ALU, i_size(size), ALU_XOR, ALU_WRITES_FLAGS(i_size(size), ALU_XOR, false, reg2 == (unsigned)-1 && is_imm(), ctx->const_imm));
		gen_one(reg_dest);
		gen_one(reg1);
		if (reg2 == (unsigned)-1)
			gen_imm_offset();
		else
			gen_one(reg2);
		rx = reg_dest;
skip_xor:
		if (cond == COND_E) {
			g(gen_imm(ctx, 1, IMM_PURPOSE_CMP, i_size_cmp(size)));
			gen_insn(INSN_CMP_DEST_REG, i_size_cmp(size), COND_B, 0);
			gen_one(reg_dest);
			gen_one(rx);
			gen_imm_offset();
		} else {
			gen_insn(INSN_CMP_DEST_REG, i_size_cmp(size), COND_B, 0);
			gen_one(reg_dest);
			gen_one(ARG_IMM);
			gen_eight(0);
			gen_one(rx);
		}
		goto done;
	}
	if (cond == COND_GE || cond == COND_LE || cond == COND_AE || cond == COND_BE) {
		cond ^= 1;
		neg_result = true;
	}
#endif
#if defined(ARCH_IA64)
	if (reg2 == (unsigned)-1)
		g(gen_imm(ctx, imm, IMM_PURPOSE_CMP, i_size_cmp(size)));
	gen_insn(INSN_CMP_DEST_REG, i_size_cmp(size), cond, 0);
	gen_one(R_CMP_RESULT);
	gen_one(reg1);
	if (reg2 == (unsigned)-1)
		gen_imm_offset();
	else
		gen_one(reg2);

	g(gen_mov(ctx, OP_SIZE_NATIVE, reg_dest, R_CMP_RESULT));

	goto done;
#endif
	if (reg2 == (unsigned)-1)
		g(gen_imm(ctx, imm, IMM_PURPOSE_CMP, i_size_cmp(size)));
	gen_insn(INSN_CMP_DEST_REG, i_size_cmp(size), cond, 0);
	gen_one(reg_dest);
	gen_one(reg1);
	if (reg2 == (unsigned)-1)
		gen_imm_offset();
	else
		gen_one(reg2);

	goto done;
done:
	if (neg_result)
		g(gen_3address_alu_imm(ctx, i_size(size), ALU_XOR, reg_dest, reg_dest, 1, 0));

	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label)
{
	bool arch_use_flags = ARCH_HAS_FLAGS;
#if defined(ARCH_ARM64)
	if (insn == INSN_TEST && reg1 == reg2 && (cond == COND_E || cond == COND_NE || cond == COND_S || cond == COND_NS))
		arch_use_flags = false;
#endif
#if defined(ARCH_SPARC)
	if (insn == INSN_TEST && reg1 == reg2)
		arch_use_flags = false;
#endif
	if (arch_use_flags) {
		if (COND_IS_LOGICAL(cond)) {
			gen_insn(insn, op_size, 0, 2);
			gen_one(reg1);
			gen_one(reg2);

			gen_insn(INSN_JMP_COND_LOGICAL, op_size, cond, 0);
			gen_four(label);

			return true;
		}

		gen_insn(insn, op_size, 0, 1);
		gen_one(reg1);
		gen_one(reg2);

#if defined(ARCH_POWER) || defined(ARCH_S390)
		if (insn == INSN_TEST) {
			if (cond == COND_S)
				cond = COND_L;
			if (cond == COND_NS)
				cond = COND_GE;
		}
#endif
		gen_insn(INSN_JMP_COND, op_size, cond, 0);
		gen_four(label);
	} else {
		if (insn == INSN_CMP) {
#if defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_RISCV64) || (defined(ARCH_MIPS) && MIPS_R6)
			gen_insn(INSN_JMP_2REGS, op_size, cond, 0);
			gen_one(reg1);
			gen_one(reg2);
			gen_four(label);
			return true;
#else
#ifdef R_CMP_RESULT
			unsigned jmp_cond = COND_NE;
#if defined(ARCH_MIPS)
			if (cond == COND_E || cond == COND_NE) {
				gen_insn(INSN_JMP_2REGS, op_size, cond, 0);
				gen_one(reg1);
				gen_one(reg2);
				gen_four(label);
				return true;
			}
			if (cond == COND_AE || cond == COND_BE || cond == COND_LE || cond == COND_GE) {
				cond ^= 1;
				jmp_cond ^= 1;
			}
#endif
#if defined(ARCH_ALPHA)
			if (cond == COND_NE) {
				g(gen_3address_alu(ctx, op_size, ALU_XOR, R_CMP_RESULT, reg1, reg2, 0));
			} else
#endif
			{
				gen_insn(INSN_CMP_DEST_REG, op_size, cond, 0);
				gen_one(R_CMP_RESULT);
				gen_one(reg1);
				gen_one(reg2);
			}

			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, jmp_cond, 0);
			gen_one(R_CMP_RESULT);
			gen_four(label);
#else
			internal(file_line, "gen_cmp_test_jmp: R_CMP_RESULT not defined");
#endif
#endif
		} else if (insn == INSN_TEST) {
			if (reg1 != reg2) {
				internal(file_line, "gen_cmp_test_jmp: INSN_TEST with two distinct registers is unsupported");
			}
#if defined(ARCH_IA64)
			if (cond == COND_S)
				cond = COND_L;
			if (cond == COND_NS)
				cond = COND_GE;
			g(gen_imm(ctx, 0, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_imm_offset();

			reg1 = R_CMP_RESULT;
			cond = COND_NE;
#endif
			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(reg1);
			gen_four(label);
		}
	}
	return true;
}

static bool attr_w gen_cmp_test_imm_jmp(struct codegen_context *ctx, unsigned insn, unsigned attr_unused op_size, unsigned reg1, int64_t value, unsigned cond, uint32_t label, int attr_unused x86_scratch)
{
	if (insn == INSN_TEST && (cond == COND_E || cond == COND_NE) && is_power_of_2((uint64_t)value)) {
#ifdef HAVE_BUILTIN_CTZ
		unsigned attr_unused bit = __builtin_ctzll(value);
#else
		unsigned attr_unused bit = 0;
		uint64_t v = value;
		while ((v = v >> 1))
			bit++;
#endif
#if defined(ARCH_ALPHA) || defined(ARCH_PARISC)
		if (value == 1 && (cond == COND_E || cond == COND_NE)) {
			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond == COND_E ? COND_BLBC : COND_BLBS, 0);
			gen_one(reg1);
			gen_four(label);
			return true;
		}
#endif
#if defined(ARCH_ARM64) || defined(ARCH_PARISC)
		gen_insn(INSN_JMP_REG_BIT, OP_SIZE_NATIVE, bit | ((cond == COND_NE) << 6), 0);
		gen_one(reg1);
		gen_four(label);

		return true;
#endif
#if defined(ARCH_POWER)
		if (!is_direct_const(value, IMM_PURPOSE_TEST, OP_SIZE_NATIVE)) {
			g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_CONST_IMM, reg1, (8U << OP_SIZE_NATIVE) - 1 - bit, true));

			gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, cond == COND_E ? COND_GE : COND_L, 0);
			gen_four(label);

			return true;
		}
#endif
#if defined(ARCH_IA64)
		gen_insn(INSN_TEST_DEST_REG, OP_SIZE_NATIVE, bit | ((cond == COND_NE) << 6), 0);
		gen_one(R_CMP_RESULT);
		gen_one(reg1);

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);

		return true;
#endif
#if defined(R_CMP_RESULT)
		if (!is_direct_const(1ULL << bit, IMM_PURPOSE_AND, OP_SIZE_NATIVE) && ARCH_HAS_BTX(BTX_BTEXT, OP_SIZE_NATIVE, true)) {
			gen_insn(INSN_BTX, OP_SIZE_NATIVE, BTX_BTEXT, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_one(ARG_IMM);
			gen_eight(bit);

			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_four(label);

			return true;
		}
#endif
	}
#if ARCH_HAS_FLAGS
	if (unlikely(insn == INSN_CMP) && COND_IS_LOGICAL(cond)) {
		g(gen_imm(ctx, value, IMM_PURPOSE_CMP_LOGICAL, op_size));
		gen_insn(insn, op_size, 0, 2);
		gen_one(reg1);
		gen_imm_offset();

		gen_insn(INSN_JMP_COND_LOGICAL, op_size, cond, 0);
		gen_four(label);

		return true;
	}
#if defined(ARCH_X86)
	if (x86_scratch >= 0 && op_size == OP_SIZE_8 && unlikely(!is_direct_const(value, insn == INSN_CMP ? IMM_PURPOSE_CMP : IMM_PURPOSE_TEST, op_size))) {
		g(gen_load_constant(ctx, x86_scratch, value));
		gen_insn(insn, op_size, 0, 1);
		gen_one(reg1);
		gen_one(x86_scratch);
	} else
#endif
	{
		g(gen_imm(ctx, value, insn == INSN_CMP ? IMM_PURPOSE_CMP : IMM_PURPOSE_TEST, op_size));
		gen_insn(insn, op_size, 0, 1);
		gen_one(reg1);
		gen_imm_offset();
	}

	gen_insn(INSN_JMP_COND, op_size, cond, 0);
	gen_four(label);
#else
	if (insn == INSN_CMP) {
#if defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_RISCV64)
		g(gen_imm(ctx, value, IMM_PURPOSE_JMP_2REGS, op_size));
#if defined(ARCH_PARISC)
		gen_insn(INSN_JMP_2REGS, op_size, cond, 0);
#else
		gen_insn(INSN_JMP_2REGS, i_size_cmp(op_size), cond, 0);
#endif
		gen_one(reg1);
		gen_imm_offset();
		gen_four(label);
		return true;
#else
		unsigned final_cond = COND_NE;
#if defined(ARCH_ALPHA)
		if (cond == COND_AE || cond == COND_A || cond == COND_GE || cond == COND_G) {
			cond ^= 1;
			final_cond ^= 1;
			goto gen_const;
		} else if (cond == COND_NE) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_XOR, R_CMP_RESULT, reg1, value, 0));
		} else
gen_const:
#endif
#if defined(ARCH_MIPS)
		if (cond == COND_E || cond == COND_NE) {
			g(gen_load_constant(ctx, R_CONST_IMM, value));
			gen_insn(INSN_JMP_2REGS, OP_SIZE_NATIVE, cond, 0);
			gen_one(reg1);
			gen_one(R_CONST_IMM);
			gen_four(label);
			return true;
		}
		if (cond == COND_AE || cond == COND_BE || cond == COND_LE || cond == COND_GE) {
			cond ^= 1;
			final_cond ^= 1;
		}
		if (cond == COND_A || cond == COND_G) {
			g(gen_load_constant(ctx, R_CONST_IMM, value));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_one(R_CONST_IMM);
		} else
#endif
		{
			g(gen_imm(ctx, value, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_imm_offset();
		}

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, final_cond, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);
#endif
	} else if (insn == INSN_TEST) {
#if defined(ARCH_IA64)
		internal(file_line, "gen_cmp_test_imm_jmp: value %"PRIxMAX" not supported", (uintmax_t)value);
#endif
		g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_AND, R_CMP_RESULT, reg1, value, 0));

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);
	} else {
		internal(file_line, "gen_cmp_test_imm_jmp: invalid insn");
	}
#endif
	return true;
}

static bool attr_w gen_jmp_on_zero(struct codegen_context *ctx, unsigned attr_unused op_size, unsigned reg, unsigned cond, uint32_t label)
{
	bool jmp_reg = false;
#if defined(ARCH_ALPHA) || defined(ARCH_LOONGARCH64) || defined(ARCH_RISCV64)
	jmp_reg = true;
#endif
#if defined(ARCH_ARM64)
	if (cond == COND_E || cond == COND_NE || cond == COND_S || cond == COND_L || cond == COND_NS || cond == COND_GE)
		jmp_reg = true;
#endif
#if defined(ARCH_SPARC)
	jmp_reg |= SPARC_9;
#endif
	if (jmp_reg) {
		gen_insn(INSN_JMP_REG, i_size(op_size), cond, 0);
		gen_one(reg);
		gen_four(label);

		return true;
	}
#if defined(ARCH_POWER)
	g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), reg, 0, cond, label, -1));
#else
	g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), reg, reg, cond, label));
#endif

	return true;
}

static bool attr_w gen_jmp_if_negative(struct codegen_context *ctx, unsigned reg, uint32_t label)
{
#if defined(ARCH_ARM64) || defined(ARCH_PARISC)
	gen_insn(INSN_JMP_REG_BIT, OP_SIZE_NATIVE, (INT_DEFAULT_BITS - 1) | ((uint32_t)1 << 6), 0);
	gen_one(reg);
	gen_four(label);
#else
	g(gen_jmp_on_zero(ctx, OP_SIZE_INT, reg, COND_S, label));
#endif
	return true;
}

#if defined(ARCH_X86)
static bool attr_w gen_cmov(struct codegen_context *ctx, unsigned op_size, unsigned cond, unsigned reg, uint32_t *label)
{
	if (unlikely(op_size < OP_SIZE_4))
		internal(file_line, "gen_cmov: unsupported operand size");
	if (likely(cpu_test_feature(CPU_FEATURE_cmov))) {
		gen_insn(INSN_CMOV, op_size, cond, 0);
		gen_one(reg);
		gen_one(reg);
		*label = 0;
	} else {
		*label = alloc_label(ctx);
		if (unlikely(!*label))
			return false;
		gen_insn(INSN_JMP_COND, op_size, cond ^ 1, 0);
		gen_four(*label);
		gen_insn(INSN_MOV, op_size, 0, 0);
		gen_one(reg);
	}
	return true;
}
#endif

enum extend {
	zero_x,
	sign_x,
	native,
	garbage,
	max_x,
};

static bool attr_w gen_extend(struct codegen_context *ctx, unsigned op_size, enum extend ex, unsigned dest, unsigned src)
{
	unsigned attr_unused shift;
	if (ex == native)
		ex = ARCH_PREFERS_SX(op_size) ? sign_x : zero_x;
	ajla_assert_lo(ex == zero_x || ex == sign_x, (file_line, "gen_extend: invalid mode %u", (unsigned)ex));
	if (unlikely(op_size == OP_SIZE_NATIVE)) {
		g(gen_mov(ctx, op_size, dest, src));
		return true;
	}
	if (OP_SIZE_NATIVE == OP_SIZE_4) {
		shift = op_size == OP_SIZE_1 ? 24 : 16;
	} else if (OP_SIZE_NATIVE == OP_SIZE_8) {
		shift = op_size == OP_SIZE_1 ? 56 : op_size == OP_SIZE_2 ? 48 : 32;
	} else {
		internal(file_line, "gen_extend: invalid OP_SIZE_NATIVE");
	}
#if defined(ARCH_ARM) || defined(ARCH_IA64) || defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_X86)
#if defined(ARCH_ARM32)
	if (unlikely(!cpu_test_feature(CPU_FEATURE_armv6)))
		goto default_extend;
#endif
	gen_insn(ex == sign_x ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(dest);
	gen_one(src);
	return true;
#endif
#if defined(ARCH_POWER)
	if (ex == zero_x || op_size == OP_SIZE_2 || cpu_test_feature(CPU_FEATURE_ppc)) {
		gen_insn(ex == sign_x ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
#if defined(ARCH_ALPHA)
	if (ex == zero_x) {
		g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_ZAPNOT, dest, src, op_size == OP_SIZE_1 ? 0x1 : op_size == OP_SIZE_2 ? 0x3 : 0xf, 0));
		return true;
	} else if (op_size == OP_SIZE_4 || ARCH_HAS_BWX) {
		gen_insn(INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
#if defined(ARCH_MIPS)
	if (ex == sign_x && shift == 32) {
		g(gen_3address_rot_imm(ctx, OP_SIZE_4, ROT_SHL, dest, src, 0, 0));
		return true;
	}
	if (ex == sign_x && MIPS_HAS_ROT) {
		gen_insn(INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
#if defined(ARCH_S390)
	if (((op_size == OP_SIZE_1 || op_size == OP_SIZE_2) && cpu_test_feature(CPU_FEATURE_extended_imm)) || op_size == OP_SIZE_4) {
		gen_insn(ex == zero_x ? INSN_MOV : INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
#if defined(ARCH_SPARC)
	if (shift == 32) {
		g(gen_3address_rot_imm(ctx, OP_SIZE_4, ex == sign_x ? ROT_SAR : ROT_SHR, dest, src, 0, 0));
		return true;
	}
#endif
#if defined(ARCH_RISCV64)
	if (ex == sign_x && (op_size == OP_SIZE_4 || likely(cpu_test_feature(CPU_FEATURE_zbb)))) {
		gen_insn(INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
	if (ex == zero_x && ((op_size == OP_SIZE_1) ||
		    (op_size == OP_SIZE_2 && likely(cpu_test_feature(CPU_FEATURE_zbb))) ||
		    (op_size == OP_SIZE_4 && likely(cpu_test_feature(CPU_FEATURE_zba))))) {
		g(gen_mov(ctx, op_size, dest, src));
		return true;
	}
#endif
	goto default_extend;
default_extend:
	if (ex == zero_x && op_size <= OP_SIZE_4) {
		int64_t cnst = ((uint64_t)0x1 << (8U << op_size)) - 1;
		if (is_direct_const(cnst, IMM_PURPOSE_AND, OP_SIZE_NATIVE)) {
			g(gen_imm(ctx, 0xff, IMM_PURPOSE_AND, OP_SIZE_NATIVE));
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_AND, ALU_WRITES_FLAGS(OP_SIZE_NATIVE, ALU_AND, false, is_imm(), ctx->const_imm));
			gen_one(dest);
			gen_one(src);
			gen_imm_offset();
			return true;
		}
	}
	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, dest, src, shift, false));
	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ex == sign_x ? ROT_SAR : ROT_SHR, dest, dest, shift, false));
	return true;
}

static bool attr_w gen_cmp_extended(struct codegen_context *ctx, unsigned cmp_op_size, unsigned sub_op_size, unsigned reg, unsigned attr_unused tmp_reg, uint32_t label_ovf)
{
	if (unlikely(sub_op_size >= cmp_op_size))
		return true;
#if defined(ARCH_ARM64)
	gen_insn(INSN_CMP, cmp_op_size, 0, 1);
	gen_one(reg);
	gen_one(ARG_EXTENDED_REGISTER);
	gen_one(sub_op_size == OP_SIZE_1 ? ARG_EXTEND_SXTB : sub_op_size == OP_SIZE_2 ? ARG_EXTEND_SXTH : ARG_EXTEND_SXTW);
	gen_one(reg);

	gen_insn(INSN_JMP_COND, cmp_op_size, COND_NE, 0);
	gen_four(label_ovf);
#else
	g(gen_extend(ctx, sub_op_size, sign_x, tmp_reg, reg));

	g(gen_cmp_test_jmp(ctx, INSN_CMP, cmp_op_size, reg, tmp_reg, COND_NE, label_ovf));
#endif
	return true;
}

static bool attr_w gen_lea3(struct codegen_context *ctx, unsigned dest, unsigned base, unsigned shifted, unsigned shift, int64_t offset)
{
#if defined(ARCH_X86)
	gen_insn(INSN_LEA3, i_size(OP_SIZE_ADDRESS), shift, 0);
	gen_one(dest);
	gen_one(base);
	gen_one(shifted);
	gen_one(ARG_IMM);
	gen_eight(likely(imm_is_32bit(offset)) ? offset : 0);

	if (unlikely(!imm_is_32bit(offset)))
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, dest, dest, offset, 0));

	return true;
#endif
	if (ARCH_HAS_SHIFTED_ADD(shift)) {
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, false, 0));
		gen_one(dest);
		gen_one(base);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | shift);
		gen_one(shifted);

		if (offset) {
			g(gen_imm(ctx, offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(i_size(OP_SIZE_ADDRESS), ALU_ADD, false, is_imm(), ctx->const_imm));
			gen_one(dest);
			gen_one(dest);
			gen_imm_offset();
		}

		return true;
	}

	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, dest, shifted, shift, false));

	g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, dest, dest, base, 0));

	if (offset)
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, dest, dest, offset, 0));
	return true;
}

#if !defined(POINTER_COMPRESSION)
#define gen_pointer_compression(base)		do { } while (0)
#define gen_address_offset_compressed()		gen_address_offset()
#elif defined(ARCH_X86)
#define gen_pointer_compression(base)		do { } while (0)
#define gen_address_offset_compressed()					\
do {									\
	if (likely(!ctx->offset_reg)) {					\
		gen_one(ARG_ADDRESS_1 + POINTER_COMPRESSION);		\
		gen_one(ctx->base_reg);					\
		gen_eight(ctx->offset_imm);				\
	} else {							\
		internal(file_line, "gen_address_offset_compressed: R_OFFSET_IMM not defined");\
	}								\
} while (0)
#else
#define gen_pointer_compression(base)					\
do {									\
	if (ARCH_PREFERS_SX(OP_SIZE_4)) {				\
		g(gen_extend(ctx, OP_SIZE_4, zero_x, base, base));	\
	}								\
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, base, base, POINTER_COMPRESSION, 0));\
} while (0)
#define gen_address_offset_compressed()		gen_address_offset()
#endif


