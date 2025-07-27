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

#define OP_SIZE_NATIVE			OP_SIZE_4
#define OP_SIZE_ADDRESS			OP_SIZE_4

#define JMP_LIMIT			JMP_SHORTEST

#ifndef __ARM_FEATURE_UNALIGNED
#define UNALIGNED_TRAP			1
#else
#define UNALIGNED_TRAP			0
#endif

#define ALU_WRITES_FLAGS(size, alu, is_mem, is_imm, imm)	0
#define ALU1_WRITES_FLAGS(alu)		0
#define ROT_WRITES_FLAGS(alu, size, im)	0
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		0
#define ARCH_IS_3ADDRESS(alu, f)	1
#define ARCH_IS_3ADDRESS_IMM(alu, f)	1
#define ARCH_IS_3ADDRESS_ROT(alu, size)	1
#define ARCH_IS_3ADDRESS_ROT_IMM(alu)	1
#define ARCH_IS_2ADDRESS(alu)		1
#define ARCH_IS_3ADDRESS_FP		1
#define ARCH_HAS_JMP_2REGS(cond)	0
#define ARCH_HAS_FLAGS			1
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			cpu_test_feature(CPU_FEATURE_idiv)
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	1
#define ARCH_HAS_2REG_M(st, shift, imm)	(!(imm))
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_SHIFT_SIZE			32
#define ARCH_BOOL_SIZE			OP_SIZE_4
#define ARCH_HAS_FP_GP_MOV		1
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_4
#define i_size_rot(size)		OP_SIZE_4
#define i_size_cmp(size)		OP_SIZE_4

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
#define R_FP		0x0b
#define R_IP		0x0c
#define R_SP		0x0d
#define R_LR		0x0e
#define R_PC		0x0f

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

#define FQR_0		0x20
#define FQR_2		0x22
#define FQR_4		0x24
#define FQR_6		0x26
#define FQR_8		0x28
#define FQR_10		0x2a
#define FQR_12		0x2c
#define FQR_14		0x2e
#define FQR_16		0x30
#define FQR_18		0x32
#define FQR_20		0x34
#define FQR_22		0x36
#define FQR_24		0x38
#define FQR_26		0x3a
#define FQR_28		0x3c
#define FQR_30		0x3e

#define R_FRAME		R_4
#define R_UPCALL	R_5

#define R_SCRATCH_1	R_0
#define R_SCRATCH_2	R_1
#define R_SCRATCH_3	R_2
#define R_SCRATCH_4	R_SAVED_2

#define R_SAVED_1	R_6
#define R_SAVED_2	R_7

#define R_OFFSET_IMM	R_LR
#define R_CONST_IMM	R_IP

#define R_SCRATCH_NA_1	R_10
#define R_SCRATCH_NA_2	R_FP
#ifdef HAVE_BITWISE_FRAME
#define R_SCRATCH_NA_3	R_8
#endif

#define R_ARG0		R_0
#define R_ARG1		R_1
#define R_ARG2		R_2
#define R_ARG3		R_3
#define R_RET0		R_0

#define FR_SCRATCH_1	FDR_0
#define FR_SCRATCH_2	FDR_2

#define SUPPORTED_FP		(cpu_test_feature(CPU_FEATURE_vfp) * 0x6)
#define SUPPORTED_FP_HALF_CVT	(cpu_test_feature(CPU_FEATURE_half) * 0x1)

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x20 && reg < 0x40;
}

static const uint8_t regs_saved[] = {
#ifndef HAVE_BITWISE_FRAME
	R_8,
#endif
	R_9 };
static const uint8_t regs_volatile[] = { R_3 };
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = { FDR_4, FDR_6, FDR_8, FDR_10, FDR_12, FDR_14 };
#define reg_is_saved(r)	((r) == R_8 || (r) == R_9)

static int gen_imm12(uint32_t c)
{
	int rot;
	for (rot = 0; rot < 32; rot += 2) {
		uint32_t val = c << rot | c >> (-rot & 31);
		if (val < 0x100)
			return val | (rot << 7);
	}
	return -1;
}

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint32_t c)
{
	if (gen_imm12(c) >= 0 || gen_imm12(~c) >= 0) {
		gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c);
		return true;
	}
	if (likely(cpu_test_feature(CPU_FEATURE_armv6t2))) {
		gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c & 0xffff);
		if (c >> 16) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_4, MOV_MASK_16_32, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(c >> 16);
		}
	} else {
		bool need_init = true;
		int p;
		for (p = 0; p < 32; p += 8) {
			if ((c >> p) & 0xff) {
				if (need_init) {
					gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
					gen_one(reg);
					gen_one(ARG_IMM);
					gen_eight(c & (0xff << p));
					need_init = false;
				} else {
					gen_insn(INSN_ALU, OP_SIZE_4, ALU_OR, 0);
					gen_one(reg);
					gen_one(reg);
					gen_one(ARG_IMM);
					gen_eight(c & (0xff << p));
				}
			}
		}
		if (need_init) {
			gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(0);
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
		case IMM_PURPOSE_STR_OFFSET:
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			if (size == OP_SIZE_2) {
				if (imm >= -255 && imm <= 255)
					return true;
			} else {
				if (imm >= -4095 && imm <= 4095)
					return true;
			}
			break;
		case IMM_PURPOSE_LDR_SX_OFFSET:
		case IMM_PURPOSE_LDP_STP_OFFSET:
			if (imm >= -255 && imm <= 255)
				return true;
			break;
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
			if (size < OP_SIZE_4 && imm != 0)
				break;
			if (unlikely((imm & 3) != 0))
				break;
			if (imm >= -1023 && imm <= 1023)
				return true;
			break;
		default:
			internal(file_line, "gen_address: invalid purpose %d", purpose);
	}
	if (purpose == IMM_PURPOSE_VLDR_VSTR_OFFSET) {
		if (gen_imm12(imm) >= 0) {
			gen_insn(INSN_ALU, OP_SIZE_ADDRESS, ALU_ADD, 0);
			gen_one(R_OFFSET_IMM);
			gen_one(base);
			gen_one(ARG_IMM);
			gen_eight(imm);
		} else {
			g(gen_load_constant(ctx, R_OFFSET_IMM, imm));
			gen_insn(INSN_ALU, OP_SIZE_ADDRESS, ALU_ADD, 0);
			gen_one(R_OFFSET_IMM);
			gen_one(R_OFFSET_IMM);
			gen_one(base);
		}
		ctx->base_reg = R_OFFSET_IMM;
		ctx->offset_imm = 0;
		return true;
	}
	g(gen_load_constant(ctx, R_OFFSET_IMM, imm));
	ctx->offset_reg = true;
	return true;
}

static bool is_direct_const(int64_t imm, unsigned purpose, unsigned size)
{
	int imm12;
	switch (purpose) {
		case IMM_PURPOSE_STORE_VALUE:
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
			imm12 = gen_imm12(imm);
			if (unlikely(imm12 == -1))
				break;
			return true;
		case IMM_PURPOSE_CMOV:
			if (gen_imm12(imm) >= 0 || gen_imm12(~imm) >= 0)
				return true;
			if ((uint32_t)imm < 0x10000 && likely(cpu_test_feature(CPU_FEATURE_armv6t2)))
				return true;
			break;
		case IMM_PURPOSE_MUL:
			break;
		default:
			internal(file_line, "is_direct_const: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}
	return false;
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
	gen_insn(INSN_ARM_PUSH, OP_SIZE_NATIVE, 0, 0);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG0);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_ARG1);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG3);

	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
	g(gen_load_constant(ctx, R_ARG1, ip));

	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_ARG0);
	gen_one(R_FRAME);

	gen_insn(INSN_ARM_POP, OP_SIZE_NATIVE, 0, 0);

	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
	if (unlikely(arg >= 4))
		internal(file_line, "gen_upcall_argument: only 4 arguments supported");
	return true;
}

static bool attr_w gen_get_upcall_pointer(struct codegen_context *ctx, unsigned offset, unsigned reg)
{
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(reg);
	gen_address_offset();

	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args, bool unspill)
{
	g(gen_get_upcall_pointer(ctx, offset, R_SCRATCH_NA_1));

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_NA_1);

	g(gen_upcall_end(ctx, offset, n_args, unspill));

	return true;
}

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0);

	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_2);

	gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
	gen_four(escape_label);

	return true;
}
