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

#if !defined(ARCH_SPARC64)
#define SPARC_9				cpu_test_feature(CPU_FEATURE_sparc9)
#define FRAME_SIZE			0x60
#define OP_SIZE_NATIVE			(SPARC_9 ? OP_SIZE_8 : OP_SIZE_4)
#define OP_SIZE_ADDRESS			OP_SIZE_4
#else
#define SPARC_9				1
#define FRAME_SIZE			0xb0
#define OP_SIZE_NATIVE			OP_SIZE_8
#define OP_SIZE_ADDRESS			OP_SIZE_8
#endif

#define JMP_LIMIT			JMP_LONG

#define UNALIGNED_TRAP			1

#define ALU_WRITES_FLAGS(alu, im)	0
#define ALU1_WRITES_FLAGS(alu)		0
#define ROT_WRITES_FLAGS(alu)		0
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		0
#define ARCH_IS_3ADDRESS(alu)		1
#define ARCH_IS_3ADDRESS_IMM(alu)	1
#define ARCH_IS_3ADDRESS_ROT(alu)	1
#define ARCH_IS_3ADDRESS_ROT_IMM(alu)	1
#define ARCH_IS_2ADDRESS(alu)		1
#define ARCH_HAS_FLAGS			1
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			SPARC_9
#define ARCH_HAS_DIV			SPARC_9
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	0
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_SHIFT_SIZE			OP_SIZE_4
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		maximum(size, OP_SIZE_4)

/*#define SUPPORT_QUAD_PRECISION*/

#define R_G0		0x00
#define R_G1		0x01
#define R_G2		0x02
#define R_G3		0x03
#define R_G4		0x04
#define R_G5		0x05
#define R_G6		0x06
#define R_G7		0x07
#define R_O0		0x08
#define R_O1		0x09
#define R_O2		0x0a
#define R_O3		0x0b
#define R_O4		0x0c
#define R_O5		0x0d
#define R_O6		0x0e
#define R_O7		0x0f
#define R_L0		0x10
#define R_L1		0x11
#define R_L2		0x12
#define R_L3		0x13
#define R_L4		0x14
#define R_L5		0x15
#define R_L6		0x16
#define R_L7		0x17
#define R_I0		0x18
#define R_I1		0x19
#define R_I2		0x1a
#define R_I3		0x1b
#define R_I4		0x1c
#define R_I5		0x1d
#define R_I6		0x1e
#define R_I7		0x1f

#define FSR_0		0x20
#define FSR_1		0x21
#define FSR_2		0x22
#define FSR_3		0x23
#define FSR_4		0x24
#define FSR_5		0x25
#define FSR_6		0x26
#define FSR_7		0x27
#define FSR_8		0x28
#define FSR_9		0x29
#define FSR_10		0x2a
#define FSR_11		0x2b
#define FSR_12		0x2c
#define FSR_13		0x2d
#define FSR_14		0x2e
#define FSR_15		0x2f
#define FSR_16		0x30
#define FSR_17		0x31
#define FSR_18		0x32
#define FSR_19		0x33
#define FSR_20		0x34
#define FSR_21		0x35
#define FSR_22		0x36
#define FSR_23		0x37
#define FSR_24		0x38
#define FSR_25		0x39
#define FSR_26		0x3a
#define FSR_27		0x3b
#define FSR_28		0x3c
#define FSR_29		0x3d
#define FSR_30		0x3e
#define FSR_31		0x3f

#define FDR_0		0x20
#define FDR_2		0x22
#define FDR_4		0x24
#define FDR_6		0x26
#define FDR_8		0x28
#define FDR_10		0x2a
#define FDR_12		0x2c
#define FDR_14		0x2e
#define FDR_16		0x30
#define FDR_18		0x32
#define FDR_20		0x34
#define FDR_22		0x36
#define FDR_24		0x38
#define FDR_26		0x3a
#define FDR_28		0x3c
#define FDR_30		0x3e
#define FDR_32		0x21
#define FDR_34		0x23
#define FDR_36		0x25
#define FDR_38		0x27
#define FDR_40		0x29
#define FDR_42		0x2b
#define FDR_44		0x2d
#define FDR_46		0x2f
#define FDR_48		0x31
#define FDR_50		0x33
#define FDR_52		0x35
#define FDR_54		0x37
#define FDR_56		0x39
#define FDR_58		0x3b
#define FDR_60		0x3d
#define FDR_62		0x3f

#define FQR_0		0x20
#define FQR_4		0x24
#define FQR_8		0x28
#define FQR_12		0x2c
#define FQR_16		0x30
#define FQR_20		0x34
#define FQR_24		0x38
#define FQR_28		0x3c
#define FQR_32		0x21
#define FQR_36		0x25
#define FQR_40		0x29
#define FQR_44		0x2d
#define FQR_48		0x31
#define FQR_52		0x35
#define FQR_56		0x39
#define FQR_60		0x3d

#define R_ZERO		0x00
#define R_SP		R_O6

#define R_FRAME		R_I0
#define R_UPCALL	R_I1
#define R_TIMESTAMP	R_I2

#define R_SCRATCH_1	R_O1
#define R_SCRATCH_2	R_O0
#define R_SCRATCH_3	R_O3
#define R_SCRATCH_4	R_O2

#define R_SCRATCH_NA_1	R_O4
#define R_SCRATCH_NA_2	R_O5
#ifdef HAVE_BITWISE_FRAME
#define R_SCRATCH_NA_3	R_O7
#endif

#define R_SAVED_1	R_L0
#define R_SAVED_2	R_L1

#define R_ARG0		R_O0
#define R_ARG1		R_O1
#define R_ARG2		R_O2
#define R_ARG3		R_O3
#define R_RET0		R_O0

#define R_OFFSET_IMM	R_G1
#define R_CONST_IMM	R_G2
#define R_CONST_HELPER	R_G3

#ifdef SUPPORT_QUAD_PRECISION
#define FR_SCRATCH_1	FDR_0
#define FR_SCRATCH_2	FDR_4
#define SUPPORTED_FP	0x16
#else
#define FR_SCRATCH_1	FDR_0
#define FR_SCRATCH_2	FDR_2
#define SUPPORTED_FP	0x6
#endif

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x20 && reg < 0x40;
}

static const uint8_t regs_saved[] = { R_L2, R_L3, R_L4, R_L5, R_L6, R_L7, R_I3, R_I4, R_I5 };
static const uint8_t regs_volatile[] = { R_G4, R_G5,
#ifndef HAVE_BITWISE_FRAME
		R_O7,
#endif
	};
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
#ifdef SUPPORT_QUAD_PRECISION
static const uint8_t fp_volatile[] = { FDR_8, FDR_12, FDR_16, FDR_20, FDR_24, FDR_28 };
#else
static const uint8_t fp_volatile[] = { FDR_4, FDR_6, FDR_8, FDR_10, FDR_12, FDR_14, FDR_16, FDR_18, FDR_20, FDR_22, FDR_24, FDR_26, FDR_28, FDR_30 };
#endif
#define reg_is_saved(r)	((r) >= R_L0 && (r) <= R_I7)

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	int32_t cl;
	if (SPARC_9) {
		if (c >= (uint64_t)-4096) {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(R_ZERO);
			gen_one(ARG_IMM);
			gen_eight(c);
			return true;
		}
		if (c >= 0x100000000ULL) {
			int32_t cu = c >> 32;
			if (cu < -4096 || cu >= 4096) {
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_CONST_HELPER);
				gen_one(ARG_IMM);
				gen_eight(cu & 0xFFFFFC00UL);
				cu &= 0x3FFU;
				if (cu) {
					gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
					gen_one(R_CONST_HELPER);
					gen_one(R_CONST_HELPER);
					gen_one(ARG_IMM);
					gen_eight(cu);
				}
			} else {
				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
				gen_one(R_CONST_HELPER);
				gen_one(R_ZERO);
				gen_one(ARG_IMM);
				gen_eight(cu);
			}
			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
			gen_one(R_CONST_HELPER);
			gen_one(R_CONST_HELPER);
			gen_one(ARG_IMM);
			gen_eight(32);
		}
	}
	cl = c;
	if (cl < 0 || cl >= 4096) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(cl & 0xFFFFFC00UL);
		cl &= 0x3FFU;
		if (cl) {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(cl);
		}
	} else {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
		gen_one(reg);
		gen_one(R_ZERO);
		gen_one(ARG_IMM);
		gen_eight(cl);
	}
	if (SPARC_9) {
		if (c >= 0x100000000ULL) {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(R_CONST_HELPER);
		}
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
		case IMM_PURPOSE_LDP_STP_OFFSET:
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			if (likely(imm >= -4096) && likely(imm < 4096))
				return true;
			break;
		default:
			internal(file_line, "gen_address: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}

	g(gen_load_constant(ctx, R_OFFSET_IMM, imm));
	ctx->offset_reg = true;
	return true;
}

static bool is_direct_const(int64_t imm, unsigned purpose, unsigned size)
{
	switch (purpose) {
		case IMM_PURPOSE_STORE_VALUE:
			if (!imm)
				return true;
			break;
		case IMM_PURPOSE_ADD:
		case IMM_PURPOSE_SUB:
		case IMM_PURPOSE_CMP:
		case IMM_PURPOSE_CMP_LOGICAL:
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
		case IMM_PURPOSE_ANDN:
		case IMM_PURPOSE_TEST:
		case IMM_PURPOSE_MUL:
			if (likely(imm >= -4096) && likely(imm < 4096))
				return true;
			break;
		case IMM_PURPOSE_CMOV:
			if (likely(imm >= -1024) && likely(imm < 1024))
				return true;
			break;
		case IMM_PURPOSE_MOVR:
			if (likely(imm >= -512) && likely(imm < 512))
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
	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SAVE, 0);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(-FRAME_SIZE);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_I3);

	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
	g(gen_load_constant(ctx, R_I1, ip));

	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
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

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_SCRATCH_NA_1);

	g(gen_upcall_end(ctx, n_args));

	return true;
}

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_SCRATCH_1);
	gen_one(R_TIMESTAMP);

	gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
	gen_four(escape_label);

	return true;
}
