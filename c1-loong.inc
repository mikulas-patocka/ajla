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

#define JMP_LIMIT			JMP_LONG

#define UNALIGNED_TRAP			(!cpu_test_feature(CPU_FEATURE_unaligned))

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
#define ARCH_HAS_JMP_2REGS(cond)	((cond) == COND_E || (cond) == COND_NE)
#define ARCH_HAS_FLAGS			0
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			1
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	0
#define ARCH_HAS_BTX(btx, size, cnst)	(((btx) == BTX_BTR || (btx) == BTX_BTEXT) && (cnst))
#define ARCH_SHIFT_SIZE			OP_SIZE_4
#define ARCH_BOOL_SIZE			OP_SIZE_NATIVE
#define ARCH_HAS_FP_GP_MOV		1
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		maximum(size, OP_SIZE_4)
#define i_size_cmp(size)		OP_SIZE_NATIVE

/*#define TIMESTAMP_IN_REGISTER*/

#define R_ZERO		0x00
#define R_RA		0x01
#define R_TP		0x02
#define R_SP		0x03
#define R_A0		0x04
#define R_A1		0x05
#define R_A2		0x06
#define R_A3		0x07
#define R_A4		0x08
#define R_A5		0x09
#define R_A6		0x0a
#define R_A7		0x0b
#define R_T0		0x0c
#define R_T1		0x0d
#define R_T2		0x0e
#define R_T3		0x0f
#define R_T4		0x10
#define R_T5		0x11
#define R_T6		0x12
#define R_T7		0x13
#define R_T8		0x14
#define R_RESERVED	0x15
#define R_FP		0x16
#define R_S0		0x17
#define R_S1		0x18
#define R_S2		0x19
#define R_S3		0x1a
#define R_S4		0x1b
#define R_S5		0x1c
#define R_S6		0x1d
#define R_S7		0x1e
#define R_S8		0x1f

#define R_FA0		0x20
#define R_FA1		0x21
#define R_FA2		0x22
#define R_FA3		0x23
#define R_FA4		0x24
#define R_FA5		0x25
#define R_FA6		0x26
#define R_FA7		0x27
#define R_FT0		0x28
#define R_FT1		0x29
#define R_FT2		0x2a
#define R_FT3		0x2b
#define R_FT4		0x2c
#define R_FT5		0x2d
#define R_FT6		0x2e
#define R_FT7		0x2f
#define R_FT8		0x30
#define R_FT9		0x31
#define R_FT10		0x32
#define R_FT11		0x33
#define R_FT12		0x34
#define R_FT13		0x35
#define R_FT14		0x36
#define R_FT15		0x37
#define R_FS0		0x38
#define R_FS1		0x39
#define R_FS2		0x3a
#define R_FS3		0x3b
#define R_FS4		0x3c
#define R_FS5		0x3d
#define R_FS6		0x3e
#define R_FS7		0x3f

#define R_FRAME		R_S0
#define R_UPCALL	R_S1
#ifdef TIMESTAMP_IN_REGISTER
#define R_TIMESTAMP	R_S4
#endif

#define R_SCRATCH_1	R_A0
#define R_SCRATCH_2	R_A1
#define R_SCRATCH_3	R_A2
#define R_SCRATCH_4	R_SAVED_2
#define R_SCRATCH_NA_1	R_A4
#define R_SCRATCH_NA_2	R_A5
#define R_SCRATCH_NA_3	R_A6

#define R_SAVED_1	R_S2
#define R_SAVED_2	R_S3

#define R_ARG0		R_A0
#define R_ARG1		R_A1
#define R_ARG2		R_A2
#define R_ARG3		R_A3
#define R_RET0		R_A0
#define R_RET1		R_A1

#define R_OFFSET_IMM	R_T0
#define R_CONST_IMM	R_T1
#define R_CMP_RESULT	R_T2

#define FR_SCRATCH_1	R_FA0
#define FR_SCRATCH_2	R_FA1

#define SUPPORTED_FP	0x6

#define FRAME_SIZE	0x60

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x20 && reg < 0x40;
}

static const uint8_t regs_saved[] = {
#ifndef TIMESTAMP_IN_REGISTER
	R_S4,
#endif
	R_S5, R_S6, R_S7, R_S8, R_FP };
static const uint8_t regs_volatile[] = { R_RA, R_A3, R_A7, R_T3, R_T4, R_T5, R_T6, R_T7, R_T8 };
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = { R_FA2, R_FA3, R_FA4, R_FA5, R_FA6, R_FA7, R_FT0, R_FT1, R_FT2, R_FT3, R_FT4, R_FT5, R_FT6, R_FT7, R_FT8, R_FT9, R_FT10, R_FT11, R_FT12, R_FT13, R_FT14, R_FT15 };
#define reg_is_saved(r)	((r) >= R_FP && (r) <= R_S8)

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	uint64_t c0 = c & 0x0000000000000fffULL;
	uint64_t c1 = c & 0x00000000fffff000ULL;
	uint64_t c2 = c & 0x000fffff00000000ULL;
	uint64_t c3 = c & 0xfff0000000000000ULL;
	uint64_t top_bits = 0;
	if (!(c0 | c1 | c2)) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c3);
		return true;
	}
	if (c0 & 0x800ULL && c1 == 0xfffff000ULL) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c0 | 0xfffffffffffff000ULL);
		top_bits = 0xffffffff00000000ULL;
	} else {
		bool have_reg = false;
		if (c1) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((uint64_t)(int32_t)c1);
			top_bits = (uint64_t)(int32_t)c1 & 0xffffffff00000000ULL;
			have_reg = true;
		}
		if (!have_reg || c0) {
			if (!have_reg) {
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_one(reg);
				gen_one(ARG_IMM);
				gen_eight(c0);
			} else {
				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
				gen_one(reg);
				gen_one(reg);
				gen_one(ARG_IMM);
				gen_eight(c0);
			}
		}
	}
	if (top_bits != (c2 | c3)) {
		uint64_t c2x = c2;
		if (c2 & 0x0008000000000000ULL)
			c2x |= 0xfff0000000000000ULL;
		if (top_bits != c2x) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_32_64, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(c2x >> 32);
		}
		top_bits = c2x & 0xfff0000000000000ULL;
		if (top_bits != c3) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_52_64, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(c3 >> 52);
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
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			if (likely(imm >= -0x800) && likely(imm < 0x800)) {
				return true;
			}
			if (imm >= -0x8000 && imm < 0x8000 && !(imm & 3)) {
				if (size == OP_SIZE_NATIVE)
					return true;
				if (purpose == IMM_PURPOSE_LDR_SX_OFFSET && size == OP_SIZE_4)
					return true;
				if (purpose == IMM_PURPOSE_STR_OFFSET && size == OP_SIZE_4)
					return true;
			}
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
		case IMM_PURPOSE_CMP:
		case IMM_PURPOSE_CMP_LOGICAL:
			if (likely(imm >= -0x800) && likely(imm < 0x800))
				return true;
			break;
		case IMM_PURPOSE_SUB:
			if (likely(imm > -0x800) && likely(imm <= 0x800))
				return true;
			break;
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
			if (likely(imm >= 0) && likely(imm < 0x1000))
				return true;
			break;
		case IMM_PURPOSE_ANDN:
			break;
		case IMM_PURPOSE_TEST:
			break;
		case IMM_PURPOSE_JMP_2REGS:
			break;
		case IMM_PURPOSE_MUL:
			break;
		case IMM_PURPOSE_BITWISE:
			return true;
		default:
			internal(file_line, "is_direct_const: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}
	return false;
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
	int offset, i;

	g(gen_imm(ctx, -FRAME_SIZE, IMM_PURPOSE_ADD, OP_SIZE_NATIVE));
	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_imm_offset();

	offset = FRAME_SIZE - (1 << OP_SIZE_NATIVE);

	g(gen_address(ctx, R_SP, FRAME_SIZE - 0x08, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_RA);
	offset -= 1 << OP_SIZE_NATIVE;

	for (i = R_FP; i <= R_S8; i++) {
		g(gen_address(ctx, R_SP, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_address_offset();
		gen_one(i);
		offset -= 1 << OP_SIZE_NATIVE;
	}

#ifndef TIMESTAMP_IN_REGISTER
	g(gen_address(ctx, R_SP, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_address_offset();
	gen_one(R_ARG2);
#endif

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG0);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_ARG1);

#ifdef TIMESTAMP_IN_REGISTER
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_TIMESTAMP);
	gen_one(R_ARG2);
#endif

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG3);

	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
	g(gen_load_constant(ctx, R_RET1, ip));

	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
	int offset, i;

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RET0);
	gen_one(R_FRAME);

	offset = FRAME_SIZE - (1 << OP_SIZE_NATIVE);

	g(gen_address(ctx, R_SP, FRAME_SIZE - 0x08, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RA);
	gen_address_offset();
	offset -= 1 << OP_SIZE_NATIVE;

	for (i = R_FP; i <= R_S8; i++) {
		g(gen_address(ctx, R_SP, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(i);
		gen_address_offset();
		offset -= 1 << OP_SIZE_NATIVE;
	}

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

static bool attr_w gen_get_upcall_pointer(struct codegen_context *ctx, unsigned offset, unsigned reg)
{
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(reg);
	gen_address_offset();

	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args)
{
	g(gen_get_upcall_pointer(ctx, offset, R_SCRATCH_NA_1));

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_1);

	g(gen_upcall_end(ctx, n_args));

	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label);

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOVSX, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

#ifdef TIMESTAMP_IN_REGISTER
	g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_TIMESTAMP, COND_NE, escape_label));
#else
	g(gen_address(ctx, R_SP, 0, IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOVSX, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_2, COND_NE, escape_label));
#endif

	return true;
}
