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

#ifdef _CALL_AIXDESC
#define AIX_CALL
#endif

#if !defined(ARCH_POWER64)

#define OP_SIZE_NATIVE			OP_SIZE_4
#define OP_SIZE_ADDRESS			OP_SIZE_4
#ifdef AIX_CALL
#define FRAME_SIZE			128
#define REGS_OFFSET			56
#define LR_OFFSET			(FRAME_SIZE + 8)
#else
#define FRAME_SIZE			80
#define REGS_OFFSET			8
#define LR_OFFSET			(FRAME_SIZE + 4)
#endif

#else

#define OP_SIZE_NATIVE			OP_SIZE_8
#define OP_SIZE_ADDRESS			OP_SIZE_8
#ifdef AIX_CALL
#define FRAME_SIZE			256
#define REGS_OFFSET			112
#define LR_OFFSET			(FRAME_SIZE + 16)
#define STRUCT_RET_OFFSET		304
#else
#define FRAME_SIZE			176
#define REGS_OFFSET			32
#define LR_OFFSET			(FRAME_SIZE + 16)
#endif

#endif

#define JMP_LIMIT			JMP_SHORT

#define UNALIGNED_TRAP			0

#define ALU_WRITES_FLAGS(alu, im)	(!(im) ?			\
						((alu) == ALU_SUB && !cpu_test_feature(CPU_FEATURE_ppc) ? 2 : (alu) == ALU_ADC || (alu) == ALU_SBB ? 2 : 0) :\
						((alu) == ALU_AND ? 1 : 0)\
					)
#define ALU1_WRITES_FLAGS(alu)		0
#define ROT_WRITES_FLAGS(alu, size, im)	0
#define COND_IS_LOGICAL(cond)		((cond) == COND_B || (cond) == COND_AE || (cond) == COND_BE || (cond) == COND_A)

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
#define ARCH_HAS_DIV			cpu_test_feature(CPU_FEATURE_ppc)
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	0
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_SHIFT_SIZE			OP_SIZE_16
#define ARCH_BOOL_SIZE			OP_SIZE_NATIVE
#define ARCH_HAS_FP_GP_MOV		0
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		maximum(size, OP_SIZE_4)
#define i_size_cmp(size)		maximum(size, OP_SIZE_4)

#define R_0				0x00
#define R_1				0x01
#define R_2				0x02
#define R_3				0x03
#define R_4				0x04
#define R_5				0x05
#define R_6				0x06
#define R_7				0x07
#define R_8				0x08
#define R_9				0x09
#define R_10				0x0a
#define R_11				0x0b
#define R_12				0x0c
#define R_13				0x0d
#define R_14				0x0e
#define R_15				0x0f
#define R_16				0x10
#define R_17				0x11
#define R_18				0x12
#define R_19				0x13
#define R_20				0x14
#define R_21				0x15
#define R_22				0x16
#define R_23				0x17
#define R_24				0x18
#define R_25				0x19
#define R_26				0x1a
#define R_27				0x1b
#define R_28				0x1c
#define R_29				0x1d
#define R_30				0x1e
#define R_31				0x1f

#define R_LR				0x20
#define R_CTR				0x21

#define R_F0				0x40
#define R_F1				0x41
#define R_F2				0x42
#define R_F3				0x43
#define R_F4				0x44
#define R_F5				0x45
#define R_F6				0x46
#define R_F7				0x47
#define R_F8				0x48
#define R_F9				0x49
#define R_F10				0x4a
#define R_F11				0x4b
#define R_F12				0x4c
#define R_F13				0x4d
#define R_F14				0x4e
#define R_F15				0x4f
#define R_F16				0x50
#define R_F17				0x51
#define R_F18				0x52
#define R_F19				0x53
#define R_F20				0x54
#define R_F21				0x55
#define R_F22				0x56
#define R_F23				0x57
#define R_F24				0x58
#define R_F25				0x59
#define R_F26				0x5a
#define R_F27				0x5b
#define R_F28				0x5c
#define R_F29				0x5d
#define R_F30				0x5e
#define R_F31				0x5f
#define R_VS32				0x60
#define R_VS33				0x61
#define R_VS34				0x62
#define R_VS35				0x63
#define R_VS36				0x64
#define R_VS37				0x65
#define R_VS38				0x66
#define R_VS39				0x67
#define R_VS40				0x68
#define R_VS41				0x69
#define R_VS42				0x6a
#define R_VS43				0x6b
#define R_VS44				0x6c
#define R_VS45				0x6d
#define R_VS46				0x6e
#define R_VS47				0x6f
#define R_VS48				0x70
#define R_VS49				0x71
#define R_VS50				0x72
#define R_VS51				0x73
#define R_VS52				0x74
#define R_VS53				0x75
#define R_VS54				0x76
#define R_VS55				0x77
#define R_VS56				0x78
#define R_VS57				0x79
#define R_VS58				0x7a
#define R_VS59				0x7b
#define R_VS60				0x7c
#define R_VS61				0x7d
#define R_VS62				0x7e
#define R_VS63				0x7f

#define R_CG_SCRATCH			R_0

#define R_SP				R_1

#define R_SCRATCH_1			R_3
#define R_SCRATCH_2			R_4
#define R_SCRATCH_3			R_5
#define R_SCRATCH_4			R_SAVED_2

#define R_SCRATCH_NA_1			R_7
#define R_SCRATCH_NA_2			R_8
#define R_SCRATCH_NA_3			R_9

#define R_FRAME				R_31
#define R_UPCALL			R_30
#define R_TIMESTAMP			R_29

#define R_SAVED_1			R_28
#define R_SAVED_2			R_27
#define R_ZERO				R_26

#define R_LOWEST_SAVED			R_14

#define R_ARG0				R_3
#define R_ARG1				R_4
#define R_ARG2				R_5
#define R_ARG3				R_6
#define R_ARG4				R_7
#define R_RET0				R_3
#define R_RET1				R_4

#define R_OFFSET_IMM			R_10
#define R_CONST_IMM			R_11

#define FR_SCRATCH_1			(real_type == 4 ? R_VS32 : R_F0)
#define FR_SCRATCH_2			(real_type == 4 ? R_VS33 : R_F1)
#define FR_SCRATCH_3			(real_type == 4 ? R_VS34 : R_F2)

#define SUPPORTED_FP			(cpu_test_feature(CPU_FEATURE_ppc) * 0x2 + 0x4 + cpu_test_feature(CPU_FEATURE_v30) * 0x10)

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x40 && reg < 0x80;
}

static bool reg_is_vs(unsigned reg)
{
	return reg >= 0x60 && reg < 0x80;
}

static const uint8_t regs_saved[] = { R_14, R_15, R_16, R_17, R_18, R_19, R_20, R_21, R_22, R_23, R_24, R_25 };
static const uint8_t regs_volatile[] = { R_6, R_12 };
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = { R_F3, R_F4, R_F5, R_F6, R_F7, R_F8, R_F9, R_F10, R_F11, R_F12, R_F13 };
static const uint8_t vector_volatile[] = { R_VS35, R_VS36, R_VS37, R_VS38, R_VS39, R_VS40, R_VS41, R_VS42, R_VS43, R_VS44, R_VS45, R_VS46, R_VS47, R_VS48, R_VS49, R_VS50, R_VS51 };
#define reg_is_saved(r)	(((r) >= R_14 && (r) <= R_31) || ((r) >= R_F14 && (r) <= R_F31) || ((r) >= R_VS52 && (r) <= R_VS63))

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	unsigned xreg = R_ZERO;
	if (OP_SIZE_NATIVE == OP_SIZE_4)
		c = (int32_t)c;
	if (c == (uint64_t)(int32_t)c) {
		if (c == (uint64_t)(int16_t)c) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((int16_t)c);
			return true;
		}
		if (c & 0xffffffffffff0000ULL) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(c & 0xffffffffffff0000ULL);
			xreg = reg;
		}
	} else {
		if (c >> 48) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((int32_t)((c >> 32) & 0xffff0000U));
			xreg = reg;
		}
		if (c & 0x0000ffff00000000ULL) {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(xreg);
			gen_one(ARG_IMM);
			gen_eight((uint16_t)(c >> 32));
			xreg = reg;
		}
		if (xreg != R_ZERO) {
			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(32);
		}
		if (c & 0xffff0000U) {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
			gen_one(reg);
			gen_one(xreg);
			gen_one(ARG_IMM);
			gen_eight(c & 0xffff0000U);
			xreg = reg;
		}
	}
	if (c & 0xffffU) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 0);
		gen_one(reg);
		gen_one(xreg);
		gen_one(ARG_IMM);
		gen_eight(c & 0xffffU);
		xreg = reg;
	}
	if (xreg == R_ZERO) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(0);
	}
	return true;
}

static bool attr_w gen_address(struct codegen_context *ctx, unsigned base, int64_t imm, unsigned purpose, unsigned size)
{
	ctx->base_reg = base;
	ctx->offset_imm = imm;
	ctx->offset_reg = false;
	switch (purpose) {
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
			if (size >= OP_SIZE_16 && imm & 15)
				break;
			/*-fallthrough*/
		case IMM_PURPOSE_LDR_SX_OFFSET:
			if (size >= OP_SIZE_4 && imm & 3)
				break;
			/*-fallthrough*/
		case IMM_PURPOSE_LDR_OFFSET:
		case IMM_PURPOSE_STR_OFFSET:
			if (size >= OP_SIZE_8 && imm & 3)
				break;
			/*-fallthrough*/
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			if (likely(imm >= -0x8000) && likely(imm < 0x8000))
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
		case IMM_PURPOSE_CMOV:
			if (!imm)
				return true;
			break;
		case IMM_PURPOSE_ANDN:
			break;
		case IMM_PURPOSE_ADD:
		case IMM_PURPOSE_CMP:
			if (likely(imm >= -0x8000) && likely(imm < 0x8000))
				return true;
			if (imm & 0xffff)
				break;
			if (likely(imm >= -0x80000000L) && likely(imm < 0x80000000L))
				return true;
			break;
		case IMM_PURPOSE_SUB:
			if (likely(imm > -0x8000) && likely(imm <= 0x8000))
				return true;
			if (imm & 0xffff)
				break;
			if (likely(imm > -0x80000000L) && likely(imm <= 0x80000000L))
				return true;
			break;
		case IMM_PURPOSE_CMP_LOGICAL:
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
		case IMM_PURPOSE_TEST:
			if (likely(imm >= 0) && likely(imm < 0x10000))
				return true;
			if (imm & 0xffff)
				break;
			if (likely(imm >= 0LL) && likely(imm < 0x100000000LL))
				return true;
			break;
		case IMM_PURPOSE_MUL:
			if (size != OP_SIZE_4)
				break;
			if (likely(imm >= -0x8000) && likely(imm < 0x8000))
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
	int i, offs;

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1_PRE_I);
	gen_one(R_SP);
	gen_eight(-FRAME_SIZE);
	gen_one(R_SP);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_3);
	gen_one(R_LR);

	for (i = R_LOWEST_SAVED, offs = REGS_OFFSET; i <= R_31; i++, offs += 1 << OP_SIZE_ADDRESS) {
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SP);
		gen_eight(offs);
		gen_one(i);
	}

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(LR_OFFSET);
	gen_one(R_SCRATCH_NA_3);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_ZERO);
	gen_one(ARG_IMM);
	gen_eight(0);

#if !defined(STRUCT_RET_OFFSET)
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG0);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_ARG1);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_TIMESTAMP);
	gen_one(R_ARG2);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG3);
#else
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(STRUCT_RET_OFFSET);
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
#endif

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
	int i, offs;

#if !defined(STRUCT_RET_OFFSET)
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RET0);
	gen_one(R_FRAME);
#else
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RET0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(STRUCT_RET_OFFSET);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_RET0);
	gen_eight(0);
	gen_one(R_FRAME);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_RET0);
	gen_eight(1U << OP_SIZE_NATIVE);
	gen_one(R_RET1);
#endif
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(LR_OFFSET);

	for (i = R_LOWEST_SAVED, offs = REGS_OFFSET; i <= R_31; i++, offs += 1 << OP_SIZE_ADDRESS) {
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(i);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SP);
		gen_eight(offs);
	}

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_LR);
	gen_one(R_SCRATCH_NA_1);

	gen_insn(INSN_ALU, OP_SIZE_NATIVE, 0, 0);
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

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args)
{
#ifndef AIX_CALL
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_12);
	gen_address_offset();

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_CTR);
	gen_one(R_12);

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_CTR);
#else
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_2);
	gen_address_offset();

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SCRATCH_NA_2);
	gen_eight(0);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_CTR);
	gen_one(R_SCRATCH_NA_1);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_2);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SCRATCH_NA_2);
	gen_eight(1 << OP_SIZE_ADDRESS);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_11);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SCRATCH_NA_2);
	gen_eight(2 << OP_SIZE_ADDRESS);

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_CTR);
#endif
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
