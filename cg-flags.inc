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

static bool attr_w gen_set_1(struct codegen_context *ctx, unsigned base, frame_t slot_1, int64_t offset, bool val)
{
#ifdef HAVE_BITWISE_FRAME
	int bit = slot_1 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
	offset += slot_1 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
#if defined(ARCH_X86)
	if (OP_SIZE_BITMAP == OP_SIZE_4) {
		g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		if (val) {
			g(gen_imm(ctx, (int32_t)((uint32_t)1 << bit), IMM_PURPOSE_OR, OP_SIZE_BITMAP));
			gen_insn(INSN_ALU, OP_SIZE_BITMAP, ALU_OR, ALU_WRITES_FLAGS(ALU_OR, true));
		} else {
			g(gen_imm(ctx, ~(int32_t)((uint32_t)1 << bit), IMM_PURPOSE_AND, OP_SIZE_BITMAP));
			gen_insn(INSN_ALU, OP_SIZE_BITMAP, ALU_AND, ALU_WRITES_FLAGS(ALU_AND, true));
		}
		gen_address_offset();
		gen_address_offset();
		gen_imm_offset();
	} else {
		g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_BITMAP));
		gen_insn(INSN_BTX, OP_SIZE_BITMAP, val ? BTX_BTS : BTX_BTR, 1);
		gen_address_offset();
		gen_address_offset();
		gen_imm_offset();
	}
#else
	g(gen_address(ctx, base, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	if (!is_direct_const(!val ? ~(1ULL << bit) : 1ULL << bit, !val ? IMM_PURPOSE_AND : IMM_PURPOSE_OR, OP_SIZE_NATIVE) && ARCH_HAS_BTX(!val ? BTX_BTR : BTX_BTS, OP_SIZE_NATIVE, true)) {
		g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_NATIVE));
		gen_insn(INSN_BTX, OP_SIZE_NATIVE, !val ? BTX_BTR : BTX_BTS, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_one(R_SCRATCH_NA_1);
		gen_imm_offset();
	} else if (!val) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_1, R_SCRATCH_NA_1, ~((uintptr_t)1 << bit), 0));
	} else {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), val ? ALU_OR : ALU_ANDN, R_SCRATCH_NA_1, R_SCRATCH_NA_1, (uintptr_t)1 << bit, 0));
	}

	g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_NA_1);
#endif
#else
#if defined(ARCH_ALPHA)
	if (!ARCH_HAS_BWX) {
		g(gen_address(ctx, base, offset + (slot_1 & ~7), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_address_offset();

		if (!val) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_8, ALU_MSKBL, R_SCRATCH_NA_1, R_SCRATCH_NA_1, slot_1 & 7, 0));
		} else {
			g(gen_3address_alu_imm(ctx, OP_SIZE_8, ALU_OR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, 1ULL << ((slot_1 & 7) * 8), 0));
		}

		g(gen_address(ctx, base, offset + (slot_1 & ~7), IMM_PURPOSE_STR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_1);

		return true;
	}
#endif
	g(gen_address(ctx, base, offset + slot_1, IMM_PURPOSE_MVI_CLI_OFFSET, OP_SIZE_1));
	g(gen_imm(ctx, val, IMM_PURPOSE_STORE_VALUE, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_address_offset();
	gen_imm_offset();
#endif
	return true;
}

static bool attr_w gen_set_1_variable(struct codegen_context *ctx, unsigned slot_reg, int64_t offset, bool val)
{
#ifdef HAVE_BITWISE_FRAME
#if defined(ARCH_X86)
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(INSN_BTX, OP_SIZE_BITMAP, val ? BTX_BTS : BTX_BTR, 1);
	gen_address_offset();
	gen_address_offset();
	gen_one(slot_reg);
#else
	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHR, R_SCRATCH_NA_1, slot_reg, OP_SIZE_BITMAP + 3, false));

	if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_BITMAP)) {
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
		gen_one(R_SCRATCH_NA_1);
		gen_one(R_FRAME);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | OP_SIZE_BITMAP);
		gen_one(R_SCRATCH_NA_1);
	} else {
		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_SCRATCH_NA_1, R_SCRATCH_NA_1, OP_SIZE_BITMAP, false));

		g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SCRATCH_NA_1, R_SCRATCH_NA_1, R_FRAME, 0));
	}
	if (ARCH_HAS_BTX(!val ? BTX_BTR : BTX_BTS, OP_SIZE_BITMAP, false)) {
		g(gen_address(ctx, R_SCRATCH_NA_1, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
		gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
		gen_one(R_SCRATCH_NA_3);
		gen_address_offset();

		gen_insn(INSN_BTX, OP_SIZE_BITMAP, !val ? BTX_BTR : BTX_BTS, 0);
		gen_one(R_SCRATCH_NA_3);
		gen_one(R_SCRATCH_NA_3);
		gen_one(slot_reg);

		goto save_it;
	}
	if (ARCH_SHIFT_SIZE > OP_SIZE_BITMAP) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_3, slot_reg, (1U << (OP_SIZE_BITMAP + 3)) - 1, 0));

		g(gen_load_constant(ctx, R_SCRATCH_NA_2, 1));

		g(gen_3address_rot(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, R_SCRATCH_NA_3));
	} else {
		g(gen_load_constant(ctx, R_SCRATCH_NA_2, 1));

		g(gen_3address_rot(ctx, OP_SIZE_BITMAP, ROT_SHL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, slot_reg));
	}
	g(gen_address(ctx, R_SCRATCH_NA_1, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_3);
	gen_address_offset();

	if (!val && !ARCH_HAS_ANDN) {
		g(gen_2address_alu1(ctx, i_size(OP_SIZE_BITMAP), ALU1_NOT, R_SCRATCH_2, R_SCRATCH_2, 0));

		g(gen_3address_alu(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_3, R_SCRATCH_NA_3, R_SCRATCH_NA_2, 0));
	} else {
		g(gen_3address_alu(ctx, i_size(OP_SIZE_BITMAP), val ? ALU_OR : ALU_ANDN, R_SCRATCH_NA_3, R_SCRATCH_NA_3, R_SCRATCH_NA_2, 0));
	}

	goto save_it;
save_it:
	g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_NA_3);
#endif
#else
#if defined(ARCH_X86)
	g(gen_imm(ctx, val, IMM_PURPOSE_STORE_VALUE, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_one(ARG_ADDRESS_2);
	gen_one(R_FRAME);
	gen_one(slot_reg);
	gen_eight(offset);
	gen_imm_offset();
#else
	g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SCRATCH_NA_1, R_FRAME, slot_reg, 0));
#ifdef ARCH_ALPHA
	if (!ARCH_HAS_BWX) {
		g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_8, 0, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_address_offset();
		if (!val) {
			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_MSKBL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, R_SCRATCH_NA_1, 0));
		} else {
			g(gen_load_constant(ctx, R_SCRATCH_NA_3, 1));

			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_INSBL, R_SCRATCH_NA_3, R_SCRATCH_NA_3, R_SCRATCH_NA_1, 0));

			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_OR, R_SCRATCH_NA_2, R_SCRATCH_NA_2, R_SCRATCH_NA_3, 0));
		}
		g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_8, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_2);

		return true;
	}
#endif

	g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_MVI_CLI_OFFSET, OP_SIZE_1));
	g(gen_imm(ctx, val, IMM_PURPOSE_STORE_VALUE, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_address_offset();
	gen_imm_offset();
#endif
#endif
	return true;
}

#define TEST		0
#define TEST_CLEAR	1
#define TEST_SET	2

static bool attr_w gen_test_1(struct codegen_context *ctx, unsigned base, frame_t slot_1, int64_t offset, uint32_t label, bool jz, uint8_t test)
{
#ifdef HAVE_BITWISE_FRAME
	int bit = slot_1 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
	offset += slot_1 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
#if defined(ARCH_X86)
	if (test == TEST) {
		if (OP_SIZE_BITMAP == OP_SIZE_4) {
			g(gen_address(ctx, base, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
			g(gen_imm(ctx, (int32_t)((uint32_t)1 << bit), IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
			gen_insn(INSN_TEST, OP_SIZE_BITMAP, 0, 1);
			gen_address_offset();
			gen_imm_offset();

			gen_insn(INSN_JMP_COND, OP_SIZE_BITMAP, jz ? COND_E : COND_NE, 0);
			gen_four(label);

			return true;
		}
		g(gen_address(ctx, base, offset, test == TEST ? IMM_PURPOSE_LDR_OFFSET : IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_BITMAP));
		gen_insn(INSN_BT, OP_SIZE_BITMAP, 0, 1);
		gen_address_offset();
		gen_imm_offset();
	} else {
		g(gen_address(ctx, base, offset, test == TEST ? IMM_PURPOSE_LDR_OFFSET : IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_BITMAP));
		gen_insn(INSN_BTX, OP_SIZE_BITMAP, test == TEST_CLEAR ? BTX_BTR : BTX_BTS, 1);
		gen_address_offset();
		gen_address_offset();
		gen_imm_offset();
	}

	gen_insn(INSN_JMP_COND, OP_SIZE_1, jz ? COND_AE : COND_B, 0);
	gen_four(label);
#else
	g(gen_address(ctx, base, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	if (jz ? test == TEST_SET : test == TEST_CLEAR) {
		if (!is_direct_const(test == TEST_CLEAR ? ~(1ULL << bit) : 1ULL << bit, test == TEST_CLEAR ? IMM_PURPOSE_AND : IMM_PURPOSE_OR, OP_SIZE_NATIVE) && ARCH_HAS_BTX(test == TEST_CLEAR ? BTX_BTR : BTX_BTS, OP_SIZE_NATIVE, true)) {
			g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_NATIVE));
			gen_insn(INSN_BTX, OP_SIZE_NATIVE, test == TEST_CLEAR ? BTX_BTR : BTX_BTS, 0);
			gen_one(R_SCRATCH_NA_2);
			gen_one(R_SCRATCH_NA_1);
			gen_imm_offset();
		} else if (test == TEST_CLEAR) {
			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_2, R_SCRATCH_NA_1, ~((uintptr_t)1 << bit), 0));
		} else {
			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), test == TEST_SET ? ALU_OR : ALU_ANDN, R_SCRATCH_NA_2, R_SCRATCH_NA_1, (uintptr_t)1 << bit, 0));
		}

		g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_2);
	}
#if defined(ARCH_ARM) || defined(ARCH_IA64) || defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_S390)
	g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, (uintptr_t)1 << bit, !jz ? COND_NE : COND_E, label));
#else
	g(gen_3address_rot_imm(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_3, R_SCRATCH_NA_1, (1U << (i_size(OP_SIZE_BITMAP) + 3)) - 1 - bit, false));

	gen_insn(INSN_JMP_REG, i_size(OP_SIZE_BITMAP), !jz ? COND_S : COND_NS, 0);
	gen_one(R_SCRATCH_NA_3);
	gen_four(label);
#endif
	if (!jz ? test == TEST_SET : test == TEST_CLEAR) {
		if (!is_direct_const(test == TEST_CLEAR ? ~(1ULL << bit) : 1ULL << bit, test == TEST_CLEAR ? IMM_PURPOSE_XOR : IMM_PURPOSE_OR, OP_SIZE_NATIVE) && ARCH_HAS_BTX(test == TEST_CLEAR ? BTX_BTR : BTX_BTS, OP_SIZE_NATIVE, true)) {
			g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_NATIVE));
			gen_insn(INSN_BTX, OP_SIZE_NATIVE, test == TEST_CLEAR ? BTX_BTR : BTX_BTS, 0);
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_NA_1);
			gen_imm_offset();
		} else {
#if defined(ARCH_S390)
			if (test == TEST_CLEAR)
				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_1, R_SCRATCH_NA_1, ~((uintptr_t)1 << bit), 0));
			else
#endif
				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), test == TEST_SET ? ALU_OR : ALU_XOR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, (uintptr_t)1 << bit, 0));
		}
		g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_1);
	}
#endif
#else
#if defined(ARCH_X86) || defined(ARCH_S390)
	g(gen_address(ctx, base, offset + slot_1, IMM_PURPOSE_MVI_CLI_OFFSET, OP_SIZE_1));
	gen_insn(INSN_CMP, OP_SIZE_1, 0, 2);
	gen_address_offset();
	gen_one(ARG_IMM);
	gen_eight(0);

	if (jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}

	gen_insn(INSN_JMP_COND, OP_SIZE_1, jz ? COND_E : COND_NE, 0);
	gen_four(label);

	if (!jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}
#else
	if (!ARCH_HAS_BWX) {
#if defined(ARCH_ALPHA)
		g(gen_address(ctx, base, offset + (slot_1 & ~7), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_address_offset();

		g(gen_3address_alu_imm(ctx, OP_SIZE_8, ALU_EXTBL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, slot_1 & 7, 0));
#endif
	} else {
		g(gen_address(ctx, base, offset + slot_1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_address_offset();
	}

	if (jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}

	g(gen_jmp_on_zero(ctx, OP_SIZE_1, R_SCRATCH_NA_2, jz ? COND_E : COND_NE, label));

	if (!jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}
#endif
#endif
	return true;
}

static bool attr_w gen_test_2(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, uint32_t label)
{
	unsigned attr_unused bit1, bit2;
	frame_t attr_unused addr1, addr2;
	if (unlikely(slot_1 == slot_2)) {
		g(gen_test_1(ctx, R_FRAME, slot_1, 0, label, false, TEST));
		return true;
	}
#ifdef HAVE_BITWISE_FRAME
	addr1 = slot_1 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
	addr2 = slot_2 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
	if (addr1 != addr2)
		goto dont_optimize;
	bit1 = slot_1 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
	bit2 = slot_2 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
#if defined(ARCH_X86)
	g(gen_address(ctx, R_FRAME, addr1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	if (OP_SIZE_BITMAP == OP_SIZE_4) {
		g(gen_imm(ctx, (int32_t)(((uintptr_t)1 << bit1) | ((uintptr_t)1 << bit2)), IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
	} else {
		g(gen_imm(ctx, ((uintptr_t)1 << bit1) | ((uintptr_t)1 << bit2), IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
	}
	gen_insn(INSN_TEST, OP_SIZE_BITMAP, 0, 1);
	gen_address_offset();
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_BITMAP, COND_NE, 0);
	gen_four(label);

	return true;
#else
	g(gen_address(ctx, R_FRAME, addr1, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	if (is_direct_const(1ULL << bit1 | 1ULL << bit2, IMM_PURPOSE_TEST, OP_SIZE_BITMAP)) {
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, 1ULL << bit1 | 1ULL << bit2, COND_NE, label));
		return true;
	}
#if defined(ARCH_ARM) || defined(ARCH_IA64) || defined(ARCH_PARISC) || defined(ARCH_S390)
	g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, (uintptr_t)1 << bit1, COND_NE, label));
	g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, (uintptr_t)1 << bit2, COND_NE, label));

	return true;
#endif
	if (ARCH_HAS_BTX(BTX_BTEXT, OP_SIZE_NATIVE, true)) {
		gen_insn(INSN_BTX, OP_SIZE_NATIVE, BTX_BTEXT, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_one(R_SCRATCH_NA_1);
		gen_one(ARG_IMM);
		gen_eight(bit1);

		gen_insn(INSN_BTX, OP_SIZE_NATIVE, BTX_BTEXT, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_one(R_SCRATCH_NA_1);
		gen_one(ARG_IMM);
		gen_eight(bit2);

		g(gen_3address_alu(ctx, i_size(OP_SIZE_NATIVE), ALU_OR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, R_SCRATCH_NA_2, 0));

		gen_insn(INSN_JMP_REG, i_size(OP_SIZE_NATIVE), COND_NE, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_four(label);

		return true;
	}
	g(gen_3address_rot_imm(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_2, R_SCRATCH_NA_1, (1U << (i_size(OP_SIZE_BITMAP) + 3)) - 1 - bit1, false));
	g(gen_3address_rot_imm(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_1, R_SCRATCH_NA_1, (1U << (i_size(OP_SIZE_BITMAP) + 3)) - 1 - bit2, false));
#if defined(ARCH_POWER)
	g(gen_3address_alu(ctx, i_size(OP_SIZE_BITMAP), ALU_OR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, R_SCRATCH_NA_2, 1));

	gen_insn(INSN_JMP_COND, i_size(OP_SIZE_BITMAP), COND_L, 0);
	gen_four(label);
#else
	g(gen_3address_alu(ctx, i_size(OP_SIZE_BITMAP), ALU_OR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, R_SCRATCH_NA_2, 0));

	gen_insn(INSN_JMP_REG, i_size(OP_SIZE_BITMAP), COND_S, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_four(label);
#endif
	return true;
#endif
dont_optimize:
	g(gen_test_1(ctx, R_FRAME, slot_1, 0, label, false, TEST));
	g(gen_test_1(ctx, R_FRAME, slot_2, 0, label, false, TEST));
#else
#if defined(ARCH_X86)
	g(gen_address(ctx, R_FRAME, slot_1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_address(ctx, R_FRAME, slot_2, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
	gen_insn(INSN_ALU_PARTIAL, OP_SIZE_1, ALU_OR, 1);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_1, COND_NE, 0);
	gen_four(label);
#else
	if (!ARCH_HAS_BWX || !ARCH_HAS_FLAGS
#if defined(ARCH_S390)
	    || 1
#endif
	    ) {
		if (!ARCH_HAS_BWX && (slot_1 & ~7) == (slot_2 & ~7)) {
			g(gen_address(ctx, R_FRAME, slot_1 & ~7, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
			gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_address_offset();

			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_ZAPNOT, R_SCRATCH_1, R_SCRATCH_1, (1U << (slot_1 & 7)) | (1U << (slot_2 & 7)), 0));

			g(gen_jmp_on_zero(ctx, OP_SIZE_8, R_SCRATCH_1, COND_NE, label));
		} else {
			g(gen_test_1(ctx, R_FRAME, slot_1, 0, label, false, TEST));
			g(gen_test_1(ctx, R_FRAME, slot_2, 0, label, false, TEST));
		}
	} else {
		g(gen_address(ctx, R_FRAME, slot_1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

		g(gen_address(ctx, R_FRAME, slot_2, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_2);
		gen_address_offset();
#if defined(ARCH_ARM) || defined(ARCH_SPARC)
		gen_insn(INSN_CMN, OP_SIZE_NATIVE, 0, 1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
#else
		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2, 1));
#endif
		gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
		gen_four(label);
	}
#endif
#endif
	return true;
}

static int frame_t_compare(const void *p1, const void *p2)
{
	if (*(const frame_t *)p1 < *(const frame_t *)p2)
		return -1;
	if (likely(*(const frame_t *)p1 > *(const frame_t *)p2))
		return 1;
	return 0;
}

static bool attr_w gen_test_multiple(struct codegen_context *ctx, frame_t *variables, size_t n_variables, uint32_t label)
{
	size_t i;
	size_t attr_unused pos;
	qsort(variables, n_variables, sizeof(frame_t), frame_t_compare);

	if (!n_variables)
		goto tested;
	if (n_variables == 1) {
		g(gen_test_1(ctx, R_FRAME, variables[0], 0, label, false, TEST));
		goto tested;
	}
	if (n_variables == 2) {
		g(gen_test_2(ctx, variables[0], variables[1], label));
		goto tested;
	}
#if defined(HAVE_BITWISE_FRAME)
	pos = 0;
	while (pos < n_variables) {
		frame_t addr = variables[pos] >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
		unsigned bit = variables[pos] & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
		uintptr_t mask = (uintptr_t)1 << bit;
		unsigned n_bits = 1;
		pos++;
		while (pos < n_variables) {
			frame_t addr2 = variables[pos] >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
			unsigned bit2 = variables[pos] & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
			uintptr_t mask2 = (uintptr_t)1 << bit2;
			if (addr != addr2)
				break;
#if defined(ARCH_S390)
			if (!is_direct_const(mask | mask2, IMM_PURPOSE_TEST, OP_SIZE_BITMAP))
				break;
#endif
			mask |= mask2;
			n_bits++;
			pos++;
		}
		if (n_bits == 1) {
			g(gen_test_1(ctx, R_FRAME, variables[pos - 1], 0, label, false, TEST));
			continue;
		} else if (n_bits == 2) {
			g(gen_test_2(ctx, variables[pos - 2], variables[pos - 1], label));
			continue;
		}
#if defined(ARCH_X86)
		g(gen_address(ctx, R_FRAME, addr, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
		if (OP_SIZE_BITMAP == OP_SIZE_4) {
			g(gen_imm(ctx, (int32_t)mask, IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
		} else {
			g(gen_imm(ctx, mask, IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
		}
		gen_insn(INSN_TEST, OP_SIZE_BITMAP, 0, 1);
		gen_address_offset();
		gen_imm_offset();

		gen_insn(INSN_JMP_COND, OP_SIZE_BITMAP, COND_NE, 0);
		gen_four(label);
#else
		g(gen_address(ctx, R_FRAME, addr, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
		gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_address_offset();

		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, mask, COND_NE, label));
#endif
	}
	goto tested;
#elif !defined(HAVE_BITWISE_FRAME)
#if defined(ARCH_X86)
	g(gen_address(ctx, R_FRAME, variables[0], IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	for (i = 1; i < n_variables; i++) {
		g(gen_address(ctx, R_FRAME, variables[i], IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_ALU_PARTIAL, OP_SIZE_1, ALU_OR, 1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_address_offset();
	}

	gen_insn(INSN_JMP_COND, OP_SIZE_1, COND_NE, 0);
	gen_four(label);

	goto tested;
#endif
	if (!ARCH_HAS_BWX) {
		pos = 0;
		while (pos < n_variables) {
			frame_t addr = variables[pos] & ~7;
			unsigned bit = variables[pos] & 7;
			unsigned mask = 1U << bit;
			pos++;
			while (pos < n_variables) {
				frame_t addr2 = variables[pos] & ~7;
				unsigned bit2 = variables[pos] & 7;
				unsigned mask2 = 1U << bit2;

				if (addr != addr2)
					break;

				mask |= mask2;
				pos++;
			}
			g(gen_address(ctx, R_FRAME, addr, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
			gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_address_offset();

			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_ZAPNOT, R_SCRATCH_1, R_SCRATCH_1, mask, 0));

			g(gen_jmp_on_zero(ctx, OP_SIZE_8, R_SCRATCH_1, COND_NE, label));
		}
		goto tested;
	}
#endif
	for (i = 0; i < n_variables; i++) {
		g(gen_test_1(ctx, R_FRAME, variables[i], 0, label, false, TEST));
	}
	goto tested;
tested:
	return true;
}
