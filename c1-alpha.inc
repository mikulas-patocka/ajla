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

#define OP_SIZE_NATIVE			OP_SIZE_8
#define OP_SIZE_ADDRESS			OP_SIZE_NATIVE

#define JMP_LIMIT			JMP_SHORTEST

#define UNALIGNED_TRAP			1

#define ALU_WRITES_FLAGS(alu, im)	0
#define ALU1_WRITES_FLAGS(alu)		0
#define ROT_WRITES_FLAGS(alu)		0
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		0
#define ARCH_IS_3ADDRESS		1
#define ARCH_HAS_FLAGS			0
#define ARCH_SUPPORTS_TRAPS		OS_SUPPORTS_TRAPS
#define ARCH_PREFERS_SX(size)		((size) == OP_SIZE_4)
#define ARCH_HAS_BWX			cpu_test_feature(CPU_FEATURE_bwx)
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			0
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	((bits) == 0 || (bits) == 2 || (bits) == 3)
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_SHIFT_SIZE			OP_SIZE_8
#define ARCH_NEEDS_BARRIER		thread_needs_barriers

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		OP_SIZE_NATIVE

#define R_V0		0x00
#define R_T0		0x01
#define R_T1		0x02
#define R_T2		0x03
#define R_T3		0x04
#define R_T4		0x05
#define R_T5		0x06
#define R_T6		0x07
#define R_T7		0x08
#define R_S0		0x09
#define R_S1		0x0a
#define R_S2		0x0b
#define R_S3		0x0c
#define R_S4		0x0d
#define R_S5		0x0e
#define R_FP		0x0f
#define R_A0		0x10
#define R_A1		0x11
#define R_A2		0x12
#define R_A3		0x13
#define R_A4		0x14
#define R_A5		0x15
#define R_T8		0x16
#define R_T9		0x17
#define R_T10		0x18
#define R_T11		0x19
#define R_RA		0x1a
#define R_T12		0x1b
#define R_AT		0x1c
#define R_GP		0x1d
#define R_SP		0x1e
#define R_ZERO		0x1f

#define R_F0		0x20
#define R_F1		0x21
#define R_F2		0x22
#define R_F3		0x23
#define R_F4		0x24
#define R_F5		0x25
#define R_F6		0x26
#define R_F7		0x27
#define R_F8		0x28
#define R_F9		0x29
#define R_F10		0x2a
#define R_F11		0x2b
#define R_F12		0x2c
#define R_F13		0x2d
#define R_F14		0x2e
#define R_F15		0x2f
#define R_F16		0x30
#define R_F17		0x31
#define R_F18		0x32
#define R_F19		0x33
#define R_F20		0x34
#define R_F21		0x35
#define R_F22		0x36
#define R_F23		0x37
#define R_F24		0x38
#define R_F25		0x39
#define R_F26		0x3a
#define R_F27		0x3b
#define R_F28		0x3c
#define R_F29		0x3d
#define R_F30		0x3e
#define R_FZERO		0x3f

#define R_FRAME		R_S0
#define R_UPCALL	R_S1
#define R_TIMESTAMP	R_S2

#define R_SCRATCH_1	R_A0
#define R_SCRATCH_2	R_A1
#define R_SCRATCH_3	R_A2
#define R_SCRATCH_4	R_A3
#define R_SCRATCH_NA_1	R_T0
#define R_SCRATCH_NA_2	R_T1
#define R_SCRATCH_NA_3	R_T2

#define R_SAVED_1	R_S3
#define R_SAVED_2	R_S4

#define R_ARG0		R_A0
#define R_ARG1		R_A1
#define R_ARG2		R_A2
#define R_ARG3		R_A3
#define R_RET0		R_V0

#define R_OFFSET_IMM	R_T3
#define R_CONST_IMM	R_T4
#define R_CMP_RESULT	R_T5

#define FR_SCRATCH_1	R_F0
#define FR_SCRATCH_2	R_F1
#define FR_SCRATCH_3	R_F2

#define SUPPORTED_FP	0x6

#define FRAME_SIZE	0x40

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x20 && reg < 0x40;
}

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	unsigned r = R_ZERO;
	int16_t c1, c2, c3, c4;
	c1 = (int16_t)c;
	c &= ~0xffffUL;
	if (c1 < 0)
		c += 0x10000UL;
	c2 = (int16_t)(c >> 16);
	c &= ~0xffffffffUL;
	if (c2 < 0)
		c += 0x100000000UL;
	c3 = (int16_t)(c >> 32);
	c &= ~0xffffffffffffUL;
	if (c3 < 0)
		c += 0x1000000000000UL;
	c4 = (int16_t)(c >> 48);
	if (c4) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
		gen_one(reg);
		gen_one(R_ZERO);
		gen_one(ARG_IMM);
		gen_eight((uint64_t)c4 << 16);
		r = reg;
	}
	if (c3) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
		gen_one(reg);
		gen_one(r);
		gen_one(ARG_IMM);
		gen_eight(c3);
		r = reg;
	}
	if (r != R_ZERO) {
		gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
		gen_one(reg);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(32);
	}
	if (c2) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
		gen_one(reg);
		gen_one(r);
		gen_one(ARG_IMM);
		gen_eight((uint64_t)c2 << 16);
		r = reg;
	}
	if (c1 || r == R_ZERO) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
		gen_one(reg);
		gen_one(r);
		gen_one(ARG_IMM);
		gen_eight(c1);
	}
	return true;
}

static bool attr_w gen_address(struct codegen_context *ctx, unsigned base, int64_t imm, unsigned purpose, unsigned size)
{
	ctx->base_reg = base;
	ctx->offset_imm = imm;
	ctx->offset_reg = false;
	switch (purpose) {
		case IMM_PURPOSE_LDR_OFFSET:
		case IMM_PURPOSE_LDR_SX_OFFSET:
		case IMM_PURPOSE_STR_OFFSET:
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			if (likely(imm >= -0x8000) && likely(imm < 0x8000))
				return true;
			break;
		default:
			internal(file_line, "gen_address: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}
	g(gen_load_constant(ctx, R_OFFSET_IMM, imm));
	gen_insn(INSN_ALU, OP_SIZE_ADDRESS, ALU_ADD, 0);
	gen_one(R_OFFSET_IMM);
	gen_one(R_OFFSET_IMM);
	gen_one(base);
	ctx->base_reg = R_OFFSET_IMM;
	ctx->offset_imm = 0;
	return true;
}

static bool is_direct_const(int64_t imm, unsigned purpose, unsigned size)
{
	int64_t imm_copy = imm;
	switch (purpose) {
		case IMM_PURPOSE_STORE_VALUE:
			if (!imm)
				return true;
			break;
		case IMM_PURPOSE_SUB:
			imm_copy = -(uint64_t)imm_copy;
			/*-fallthrough*/
		case IMM_PURPOSE_ADD:
			if (likely(imm_copy >= -0x8000) && likely(imm_copy < 0x8000))
				return true;
			if (imm_copy & 0xffff)
				break;
			if (likely(imm_copy >= -0x80000000L) && likely(imm_copy < 0x80000000L))
				return true;
			break;
		case IMM_PURPOSE_CMP:
		case IMM_PURPOSE_CMP_LOGICAL:
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
		case IMM_PURPOSE_ANDN:
		case IMM_PURPOSE_TEST:
		case IMM_PURPOSE_MUL:
		case IMM_PURPOSE_MOVR:
			if (imm >= 0 && imm < 256)
				return true;
			break;
		default:
			internal(file_line, "is_direct_const: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}
	return false;
}

static bool attr_w gen_imm(struct codegen_context *ctx, int64_t imm, unsigned purpose, unsigned size)
{
	if (is_direct_const(imm, purpose, size)) {
		ctx->const_imm = imm;
		ctx->const_reg = false;
	} else {
		g(gen_load_constant(ctx, R_CONST_IMM, imm));
		ctx->const_reg = true;
	}
	return true;
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
	g(gen_imm(ctx, FRAME_SIZE, IMM_PURPOSE_SUB, OP_SIZE_NATIVE));
	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SUB, 0);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_imm_offset();

	g(gen_address(ctx, R_SP, 0, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_RA);

	g(gen_address(ctx, R_SP, 8, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_S0);

	g(gen_address(ctx, R_SP, 16, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_S1);

	g(gen_address(ctx, R_SP, 24, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_S2);

	g(gen_address(ctx, R_SP, 32, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_S3);

	g(gen_address(ctx, R_SP, 40, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_S4);

	g(gen_address(ctx, R_SP, 48, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_ARG0);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG1);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_ARG2);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_TIMESTAMP);
	gen_one(R_ARG3);

	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
	g(gen_load_constant(ctx, R_SCRATCH_1, (int32_t)ip));

	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
	g(gen_address(ctx, R_SP, 48, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RET0);
	gen_address_offset();

	g(gen_address(ctx, R_RET0, 0, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_FRAME);

	g(gen_address(ctx, R_RET0, 8, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_1);

	g(gen_address(ctx, R_SP, 0, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RA);
	gen_address_offset();

	g(gen_address(ctx, R_SP, 8, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_S0);
	gen_address_offset();

	g(gen_address(ctx, R_SP, 16, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_S1);
	gen_address_offset();

	g(gen_address(ctx, R_SP, 24, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_S2);
	gen_address_offset();

	g(gen_address(ctx, R_SP, 32, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_S3);
	gen_address_offset();

	g(gen_address(ctx, R_SP, 40, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_S4);
	gen_address_offset();

	g(gen_imm(ctx, FRAME_SIZE, IMM_PURPOSE_ADD, OP_SIZE_NATIVE));
	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_imm_offset();

	gen_insn(INSN_RET, 0, 0, 0);

	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned attr_unused n_args)
{
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_T12);
	gen_address_offset();

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_T12);

	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label);

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t label_id)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOVSX, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_TIMESTAMP, COND_E, label_id));

	return true;
}
