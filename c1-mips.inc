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

#ifdef ARCH_MIPS_O32
#define OP_SIZE_NATIVE	OP_SIZE_4
#else
#define OP_SIZE_NATIVE	OP_SIZE_8
#endif

#ifdef ARCH_MIPS32
#define OP_SIZE_ADDRESS	OP_SIZE_4
#else
#define OP_SIZE_ADDRESS	OP_SIZE_8
#endif

#define JMP_LIMIT	JMP_EXTRA_LONG

#define UNALIGNED_TRAP			(!MIPS_R6)

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
#define ARCH_HAS_JMP_REG(cond)		1
#define ARCH_HAS_JMP_2REGS(cond)	((cond) == COND_E || (cond) == COND_NE || MIPS_R6)
#define ARCH_HAS_LDP_STP(r1, r2, s, o)	0
#define ARCH_HAS_FLAGS			0
#define ARCH_SUPPORTS_TRAPS(size)	(OS_SUPPORTS_TRAPS && ((size) == OP_SIZE_4 || (size) == OP_SIZE_8))
#define ARCH_TRAP_BEFORE		1
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			1
#define ARCH_HAS_ANDN			0
#define ARCH_HAS_2REG_M(st, fp, sh, im)	(false)
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_HAS_SHIFTED_ADD(bits)	(MIPS_R6 && (bits) >= 1 && (bits) <= 4)
#define ARCH_HAS_CMOV			0
#define ARCH_SHIFT_SIZE			OP_SIZE_4
#define ARCH_BOOL_SIZE			OP_SIZE_NATIVE
#define ARCH_HAS_FP_GP_MOV		1
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		maximum(size, OP_SIZE_4)
#define i_size_cmp(size)		OP_SIZE_NATIVE

#if __mips < 2
#define MIPS_LOAD_DELAY_SLOTS		1
#define MIPS_HAS_LS_DOUBLE		0
#define MIPS_HAS_SQRT			0
#define MIPS_HAS_TRUNC			0
#else
#define MIPS_LOAD_DELAY_SLOTS		0
#define MIPS_HAS_LS_DOUBLE		1
#define MIPS_HAS_SQRT			1
#define MIPS_HAS_TRUNC			1
#endif

#if __mips < 4
#define MIPS_R4000_ERRATA		1
#define MIPS_FCMP_DELAY_SLOTS		1
#define MIPS_HAS_MOVT			0
#else
#define MIPS_R4000_ERRATA		0
#define MIPS_FCMP_DELAY_SLOTS		0
#define MIPS_HAS_MOVT			1
#endif

#if __mips < 32
#define MIPS_HAS_CLZ			0
#define MIPS_HAS_MUL			0
#else
#define MIPS_HAS_CLZ			1
#define MIPS_HAS_MUL			1
#endif

#if __mips < 32 || !defined(__mips_isa_rev) || __mips_isa_rev < 2
#define MIPS_HAS_ROT			0
#else
#define MIPS_HAS_ROT			1
#endif

#if __mips < 32 || !defined(__mips_isa_rev) || __mips_isa_rev < 6
#define MIPS_R6				0
#else
#define MIPS_R6				1
#endif

#define R_ZERO		0x00
#define R_AT		0x01
#define R_V0		0x02
#define R_V1		0x03
#define R_A0		0x04
#define R_A1		0x05
#define R_A2		0x06
#define R_A3		0x07
#define R_T0		0x08
#define R_T1		0x09
#define R_T2		0x0a
#define R_T3		0x0b
#define R_T4		0x0c
#define R_T5		0x0d
#define R_T6		0x0e
#define R_T7		0x0f
#define R_S0		0x10
#define R_S1		0x11
#define R_S2		0x12
#define R_S3		0x13
#define R_S4		0x14
#define R_S5		0x15
#define R_S6		0x16
#define R_S7		0x17
#define R_T8		0x18
#define R_T9		0x19
#define R_K0		0x1a
#define R_K1		0x1b
#define R_GP		0x1c
#define R_SP		0x1d
#define R_FP		0x1e
#define R_RA		0x1f

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
#define R_F31		0x3f

#define R_FRAME		R_S0
#define R_UPCALL	R_S1

#define R_SCRATCH_1	R_A0
#define R_SCRATCH_2	R_A1
#define R_SCRATCH_3	R_A2
#define R_SCRATCH_4	R_SAVED_2
#define R_SCRATCH_NA_1	R_T0
#define R_SCRATCH_NA_2	R_T1
#define R_SCRATCH_NA_3	R_T2

#define R_SAVED_1	R_S2
#define R_SAVED_2	R_S3

#define R_ARG0		R_A0
#define R_ARG1		R_A1
#define R_ARG2		R_A2
#define R_ARG3		R_A3

#define R_RET0		R_V0
#define R_RET1		R_V1

#define R_OFFSET_IMM	R_T3
#define R_CONST_IMM	R_T4
#define R_CMP_RESULT	R_T5

#define FR_SCRATCH_1	R_F0
#define FR_SCRATCH_2	R_F2
#define FR_SCRATCH_3	R_F4
#define FR_CMP_RESULT	R_F6

#define SUPPORTED_FP	0x6

#ifdef ARCH_MIPS_O32
#define FRAME_SIZE	64
#define SAVE_OFFSET	20
#else
#define FRAME_SIZE	96
#define SAVE_OFFSET	0
#endif

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x20 && reg < 0x40;
}

static const uint8_t regs_saved[] = { R_S4, R_S5, R_S6, R_S7,
#ifndef ARCH_MIPS_O32
	R_GP,
#endif
	R_FP };
static const uint8_t regs_volatile[] = { R_A3, R_T6, R_T7, R_T8, R_T9 };
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = { R_F8, R_F10, R_F12, R_F14, R_F16, R_F18 };
#define reg_is_saved(r)	(((r) >= R_S0 && (r) <= R_S7) || (r) == R_GP || (r) == R_FP)

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	if (OP_SIZE_NATIVE == OP_SIZE_4)
		c = (int32_t)c;
	if ((int64_t)c != (int32_t)c) {
		if (MIPS_R6) {
			g(gen_load_constant(ctx, reg, (int32_t)c));
			if ((int32_t)c < 0) {
				c += 0x100000000ULL;
			}
			c &= ~0xFFFFFFFFULL;
			c >>= 32;
			if (c & 0xFFFFULL) {
				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
				gen_one(reg);
				gen_one(reg);
				gen_one(ARG_IMM);
				gen_eight((uint64_t)(int16_t)c << 32);
			}
			if ((int16_t)c < 0) {
				c += 0x10000ULL;
			}
			c &= ~0xFFFFULL;
			c >>= 16;
			if (c & 0xFFFFULL) {
				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
				gen_one(reg);
				gen_one(reg);
				gen_one(ARG_IMM);
				gen_eight(c << 48);
			}
			return true;
		}
		if (c && !(c & (c - 1))) {
			int bit = -1;
			uint64_t cc = c;
			do {
				cc >>= 1;
				bit++;
			} while (cc);
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(R_ZERO);
			gen_one(ARG_IMM);
			gen_eight(1);

			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(bit);

			return true;
		}
		if (~c && !(~c & (~c - 1))) {
			g(gen_load_constant(ctx, reg, ~c));

			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_NOT, 0);
			gen_one(reg);
			gen_one(reg);

			return true;
		}
		g(gen_load_constant(ctx, reg, (int32_t)((c & 0xFFFFFFFF00000000ULL) >> 32)));
		c &= 0xFFFFFFFFULL;
		if (c & 0xFFFF0000ULL) {
			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(16);

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(c >> 16);

			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(16);
		} else {
			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(32);
		}
		if (c & 0xFFFFULL) {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(c & 0xFFFFULL);
		}
		return true;
	}
	if (c == (uint16_t)c) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
		gen_one(reg);
		gen_one(R_ZERO);
		gen_one(ARG_IMM);
		gen_eight(c);
		return true;
	}
	if ((int64_t)c == (int16_t)c) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
		gen_one(reg);
		gen_one(R_ZERO);
		gen_one(ARG_IMM);
		gen_eight(c);
		return true;
	}
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(reg);
	gen_one(ARG_IMM);
	gen_eight(c & ~0xffffULL);
	if (c & 0xFFFFULL) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
		gen_one(reg);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c & 0xFFFFULL);
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
			if (likely(imm == (int16_t)imm))
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
	if (MIPS_R4000_ERRATA && (purpose == IMM_PURPOSE_ADD_TRAP || purpose == IMM_PURPOSE_SUB_TRAP) && size == OP_SIZE_8)
		return false;
	switch (purpose) {
		case IMM_PURPOSE_STORE_VALUE:
			if (!imm)
				return true;
			break;
		case IMM_PURPOSE_ADD:
		case IMM_PURPOSE_CMP:
		case IMM_PURPOSE_CMP_LOGICAL:
			if (likely(imm == (int16_t)imm))
				return true;
			break;
		case IMM_PURPOSE_SUB:
			if (likely(imm > -0x8000) && likely(imm <= 0x8000))
				return true;
			break;
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
		case IMM_PURPOSE_TEST:
			if (likely((uint64_t)imm == (uint16_t)imm))
				return true;
			break;
		case IMM_PURPOSE_JMP_2REGS:
		case IMM_PURPOSE_JMP_2REGS_LOGICAL:
			break;
		case IMM_PURPOSE_MUL:
			break;
		case IMM_PURPOSE_ADD_TRAP:
			if (MIPS_R6)
				break;
			if (likely(imm == (int16_t)imm))
				return true;
			break;
		case IMM_PURPOSE_SUB_TRAP:
			if (MIPS_R6)
				break;
			if (likely(imm > -0x8000) && likely(imm <= 0x8000))
				return true;
			break;
		default:
			internal(file_line, "is_direct_const: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}
	return false;
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
	int save_offset;
	unsigned reg;

	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SUB, 0);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(FRAME_SIZE);

	save_offset = SAVE_OFFSET;

	g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_address_offset();
	gen_one(R_ARG2);
	save_offset += 1 << OP_SIZE_NATIVE;

	for (reg = R_S0; reg <= R_S7; reg++) {
		g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_address_offset();
		gen_one(reg);
		save_offset += 1 << OP_SIZE_NATIVE;
	}
#ifndef ARCH_MIPS_O32
	g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_GP);
	save_offset += 1 << OP_SIZE_NATIVE;
#endif
	g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_FP);
	save_offset += 1 << OP_SIZE_NATIVE;

	g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_address_offset();
	gen_one(R_RA);

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
	g(gen_load_constant(ctx, R_RET1, (int32_t)ip));

	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
	int save_offset;
	unsigned reg;

#if defined(ARCH_MIPS_N32)
	gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
	gen_one(R_RET1);
	gen_one(R_RET1);
	gen_one(ARG_IMM);
	gen_eight(32);

	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
	gen_one(R_RET0);
	gen_one(R_FRAME);
	gen_one(R_RET1);
#else
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RET0);
	gen_one(R_FRAME);
#endif

	save_offset = SAVE_OFFSET + (1 << OP_SIZE_NATIVE);
	for (reg = R_S0; reg <= R_S7; reg++) {
		g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_address_offset();
		save_offset += 1 << OP_SIZE_NATIVE;
	}
#ifndef ARCH_MIPS_O32
	g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_GP);
	gen_address_offset();
	save_offset += 1 << OP_SIZE_NATIVE;
#endif
	g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_FP);
	gen_address_offset();
	save_offset += 1 << OP_SIZE_NATIVE;

	g(gen_address(ctx, R_SP, save_offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RA);
	gen_address_offset();

	gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(FRAME_SIZE);

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

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args, bool unspill)
{
	g(gen_get_upcall_pointer(ctx, offset, R_T9));

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_T9);

	g(gen_upcall_end(ctx, offset, n_args, unspill));

	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label);

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_address(ctx, R_SP, SAVE_OFFSET, IMM_PURPOSE_STR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_2, COND_NE, escape_label));

	return true;
}
