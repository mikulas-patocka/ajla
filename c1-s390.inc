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

#ifdef ARCH_S390_64
#define Z				1
#else
#define Z				cpu_test_feature(CPU_FEATURE_z)
#endif

#ifdef ARCH_S390_64
#define OP_SIZE_ADDRESS			OP_SIZE_8
#else
#define OP_SIZE_ADDRESS			OP_SIZE_4
#endif

#define OP_SIZE_NATIVE			(Z ? OP_SIZE_8 : OP_SIZE_4)

#define JMP_LIMIT			JMP_SHORT

#define UNALIGNED_TRAP			0

#define ALU_WRITES_FLAGS(alu, im)	((alu) != ALU_MUL)
#define ALU1_WRITES_FLAGS(alu)		1
#define ROT_WRITES_FLAGS(alu)		((alu) == ROT_SAR || (alu) == ROT_SAL)
#define COND_IS_LOGICAL(cond)		((cond) == COND_B || (cond) == COND_AE || (cond) == COND_BE || (cond) == COND_A)

#define ARCH_PARTIAL_ALU(size)		((size) < OP_SIZE_NATIVE)
#define ARCH_IS_3ADDRESS		cpu_test_feature(CPU_FEATURE_misc_45)
#define ARCH_HAS_FLAGS			1
#define ARCH_PREFERS_SX(size)		1
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			1
#define ARCH_HAS_ANDN			cpu_test_feature(CPU_FEATURE_misc_insn_ext_3)
#define ARCH_HAS_SHIFTED_ADD(bits)	0
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_SHIFT_SIZE			OP_SIZE_8
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			maximum(size, OP_SIZE_4)
#define i_size_rot(size)		maximum(size, OP_SIZE_4)

#define R_0		0x00
#define R_1		0x01
#define R_2		0x02
#define R_3		0x03
#define R_4		0x04
#define R_5		0x05
#define R_6		0x06
#define R_7		0x07
#define R_8		0x08
#define R_9		0x09
#define R_10		0x0a
#define R_11		0x0b
#define R_12		0x0c
#define R_13		0x0d
#define R_14		0x0e
#define R_15		0x0f

#define FR_0		0x10
#define FR_1		0x11
#define FR_2		0x12
#define FR_3		0x13
#define FR_4		0x14
#define FR_5		0x15
#define FR_6		0x16
#define FR_7		0x17
#define FR_8		0x18
#define FR_9		0x19
#define FR_10		0x1a
#define FR_11		0x1b
#define FR_12		0x1c
#define FR_13		0x1d
#define FR_14		0x1e
#define FR_15		0x1f

#define R_FRAME		R_12
#define R_UPCALL	R_13
#define R_TIMESTAMP	R_11

#define R_SP		R_15

#define R_SAVED_1	R_9
#define R_SAVED_2	R_10

#define R_SCRATCH_NA_1	R_1
#define R_SCRATCH_NA_2	R_6
#define R_SCRATCH_NA_3	R_7
#define R_SCRATCH_1	R_3
#define R_SCRATCH_2	R_2
#define R_SCRATCH_3	R_5
#define R_SCRATCH_4	R_4
#define R_CONST_IMM	R_0
#define R_OFFSET_IMM	R_14

#define R_ARG0		R_2
#define R_ARG1		R_3
#define R_ARG2		R_4
#define R_ARG3		R_5
#define R_ARG4		R_6
#define R_RET0		R_2

#define FR_SCRATCH_1	FR_0
#define FR_SCRATCH_2	FR_4

#define SUPPORTED_FP	0x16

#ifdef ARCH_S390_64
#define FRAME_SIZE	160
#define FRAME_REGS	48
#define FRAME_RETPTR	(FRAME_SIZE + 16)
#else
#define FRAME_SIZE	96
#define FRAME_REGS	24
#define FRAME_FP_REGS	80
#define FRAME_RETPTR	(FRAME_SIZE + 8)
#endif

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x10 && reg < 0x20;
}

static const uint8_t reg_available[] = { 1, R_8 };
#define reg_is_saved(r)	1

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	if (OP_SIZE_NATIVE == OP_SIZE_4)
		c = (int32_t)c;
	if ((int64_t)c >= -0x8000 && (int64_t)c < 0x8000) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c);
		return true;
	}
	if (cpu_test_feature(CPU_FEATURE_extended_imm)) {
		bool sign;
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight((int32_t)(int64_t)c);
		sign = ((c >> 31) & 1) != 0;
		c >>= 32;
		if (c != (sign ? 0xffffffffU : 0)) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_8, MOV_MASK_32_64, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(c);
		}
		return true;
	} else {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c);
		return true;
	}
}

static bool attr_w s390_inline_address(int64_t imm)
{
	if (likely(cpu_test_feature(CPU_FEATURE_long_displacement))) {
		if (likely(imm >= -0x80000) && likely(imm < 0x80000))
			return true;
	}
	if (imm >= 0 && imm < 0x1000)
		return true;
	return false;
}

static bool attr_w gen_address(struct codegen_context *ctx, unsigned base, int64_t imm, unsigned purpose, unsigned attr_unused size)
{
	ctx->offset_imm = imm;
	ctx->offset_reg = false;
	ctx->base_reg = base;
	switch (purpose) {
		case IMM_PURPOSE_LDR_OFFSET:
		case IMM_PURPOSE_LDR_SX_OFFSET:
		case IMM_PURPOSE_STR_OFFSET:
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			break;
		case IMM_PURPOSE_LDP_STP_OFFSET:
			if (imm >= 0 && imm < 0x1000)
				return true;
			goto load_cnst;
		default:
			internal(file_line, "gen_address: invalid purpose %d", purpose);
	}
	if (s390_inline_address(imm))
		return true;

load_cnst:
	g(gen_load_constant(ctx, R_OFFSET_IMM, imm));

	if (purpose == IMM_PURPOSE_MVI_CLI_OFFSET || purpose == IMM_PURPOSE_LDP_STP_OFFSET) {
		gen_insn(INSN_LEA3, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_OFFSET_IMM);
		gen_one(R_OFFSET_IMM);
		gen_one(base);
		gen_one(ARG_IMM);
		gen_eight(0);
		ctx->base_reg = R_OFFSET_IMM;
		ctx->offset_imm = 0;
		return true;
	}

	ctx->offset_reg = true;

	return true;
}

static bool is_direct_const(int64_t imm, unsigned purpose, unsigned size)
{
	switch (purpose) {
		case IMM_PURPOSE_ADD:
		case IMM_PURPOSE_CMP:
			if (imm >= -0x8000 && imm < 0x8000)
				return true;
			break;
		case IMM_PURPOSE_SUB:
			if (imm > -0x8000 && imm <= 0x8000)
				return true;
			break;
		case IMM_PURPOSE_AND:
			imm = ~imm;
			/*-fallthrough*/
		case IMM_PURPOSE_OR:
			if (Z) {
				if (!(imm & ~0xffffULL))
					return true;
				if (!(imm & ~0xffff0000ULL))
					return true;
				if (!(imm & ~0xffff00000000ULL))
					return true;
				if (!(imm & ~0xffff000000000000ULL))
					return true;
			}
			/*-fallthrough*/
		case IMM_PURPOSE_XOR:
			if (cpu_test_feature(CPU_FEATURE_extended_imm)) {
				if (!(imm & ~0xffffffffULL))
					return true;
				if (!(imm & ~0xffffffff00000000ULL))
					return true;
			}
			break;
		case IMM_PURPOSE_TEST:
			if (!(imm & ~0xffffULL))
				return true;
			if (!(imm & ~0xffff0000ULL))
				return true;
			if (!(imm & ~0xffff00000000ULL))
				return true;
			if (!(imm & ~0xffff000000000000ULL))
				return true;
			break;
		case IMM_PURPOSE_STORE_VALUE:
			if (size == OP_SIZE_1)
				return true;
			break;
		default:
			break;
	}
	return false;
}

static bool attr_w gen_imm(struct codegen_context *ctx, int64_t imm, unsigned purpose, unsigned size)
{
	if (is_direct_const(imm, purpose, size)/* && (purpose == IMM_PURPOSE_TEST || purpose == IMM_PURPOSE_CMP)*/) {
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
	gen_insn(INSN_S390_PUSH, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_REGS);
#if defined(ARCH_S390_32)
	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_FP_REGS);
	gen_one(FR_4);

	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_FP_REGS + 8);
	gen_one(FR_6);
#endif
	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, true));
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(-FRAME_SIZE);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_RETPTR);
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

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG4);

	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
	g(gen_load_constant(ctx, R_UPCALL, ip));

	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
#if defined(ARCH_S390_32)
	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(FR_4);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_SIZE + FRAME_FP_REGS);

	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(FR_6);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_SIZE + FRAME_FP_REGS + 8);
#endif
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_ARG0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_RETPTR);

	gen_insn(INSN_STP, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_ARG0);
	gen_eight(0);
	gen_one(R_UPCALL);
	gen_one(R_FRAME);

	gen_insn(INSN_S390_POP, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(FRAME_SIZE + FRAME_REGS);

	gen_insn(INSN_RET, 0, 0, 0);
	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args)
{
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_1);

	g(gen_upcall_end(ctx, n_args));

	return true;
}

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_TIMESTAMP);
	gen_address_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
	gen_four(escape_label);

	return true;
}
