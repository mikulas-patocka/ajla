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

#ifdef ARCH_X86_32
#define OP_SIZE_NATIVE			OP_SIZE_4
#else
#define OP_SIZE_NATIVE			OP_SIZE_8
#endif

#ifndef ARCH_X86_64
#define OP_SIZE_ADDRESS			OP_SIZE_4
#else
#define OP_SIZE_ADDRESS			OP_SIZE_8
#endif

#define JMP_LIMIT			JMP_LONG

#define UNALIGNED_TRAP			0

#define ALU_WRITES_FLAGS(alu, im)	((alu) == ALU_ADD ? 0 : (alu) == ALU_SUB && (im) ? 0 : 3)
#define ALU1_WRITES_FLAGS(alu)		((alu) == ALU1_NOT || (alu) == ALU1_BSWAP ? 0 : 3)
#define ROT_WRITES_FLAGS(alu, size, im)	(cpu_test_feature(CPU_FEATURE_bmi2) && (alu == ROT_SHL || alu == ROT_SHR || alu == ROT_SAR) && size >= OP_SIZE_4 && !(im) ? 0 : 1)
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		((size) <= OP_SIZE_2)
#define ARCH_IS_3ADDRESS(alu, f)	((alu) == ALU_ADD && !(f))
#define ARCH_IS_3ADDRESS_IMM(alu, f)	((alu) == ALU_ADD && !(f))
#define ARCH_IS_3ADDRESS_ROT(alu, size)	(ROT_WRITES_FLAGS(alu, size, false) ? 0 : 1)
#define ARCH_IS_3ADDRESS_ROT_IMM(alu)	0
#define ARCH_IS_2ADDRESS(alu)		((alu) == ALU1_BSF || (alu) == ALU1_BSR || (alu) == ALU1_LZCNT || (alu) == ALU1_POPCNT)
#define ARCH_IS_3ADDRESS_FP		cpu_test_feature(CPU_FEATURE_avx)
#define ARCH_HAS_JMP_2REGS(cond)	0
#define ARCH_HAS_FLAGS			1
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			1
#define ARCH_HAS_ANDN			0
#define ARCH_HAS_BTX(btx, size, cnst)	((btx) != BTX_BTEXT && (size) >= OP_SIZE_2)
#define ARCH_HAS_SHIFTED_ADD(bits)	((bits) <= 3)
#define ARCH_SHIFT_SIZE			OP_SIZE_4
#define ARCH_BOOL_SIZE			log_2(sizeof(ajla_flat_option_t))
#define ARCH_HAS_FP_GP_MOV		cpu_test_feature(CPU_FEATURE_sse2)
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			(size)
#define i_size_rot(size)		(size)
#define i_size_cmp(size)		(size)

#define R_AX		0x0
#define R_CX		0x1
#define R_DX		0x2
#define R_BX		0x3
#define R_SP		0x4
#define R_BP		0x5
#define R_SI		0x6
#define R_DI		0x7
#define R_R8		0x8
#define R_R9		0x9
#define R_R10		0xa
#define R_R11		0xb
#define R_R12		0xc
#define R_R13		0xd
#define R_R14		0xe
#define R_R15		0xf

#define R_ST0		0x10
#define R_ST1		0x11
#define R_ST2		0x12
#define R_ST3		0x13
#define R_ST4		0x14
#define R_ST5		0x15
#define R_ST6		0x16
#define R_ST7		0x17

#define R_ES		0x18
#define R_CS		0x19
#define R_SS		0x1a
#define R_DS		0x1b
#define R_FS		0x1c
#define R_GS		0x1d

#define R_XMM0		0x20
#define R_XMM1		0x21
#define R_XMM2		0x22
#define R_XMM3		0x23
#define R_XMM4		0x24
#define R_XMM5		0x25
#define R_XMM6		0x26
#define R_XMM7		0x27
#define R_XMM8		0x28
#define R_XMM9		0x29
#define R_XMM10		0x2a
#define R_XMM11		0x2b
#define R_XMM12		0x2c
#define R_XMM13		0x2d
#define R_XMM14		0x2e
#define R_XMM15		0x2f
#define R_XMM16		0x30
#define R_XMM17		0x31
#define R_XMM18		0x32
#define R_XMM19		0x33
#define R_XMM20		0x34
#define R_XMM21		0x35
#define R_XMM22		0x36
#define R_XMM23		0x37
#define R_XMM24		0x38
#define R_XMM25		0x39
#define R_XMM26		0x3a
#define R_XMM27		0x3b
#define R_XMM28		0x3c
#define R_XMM29		0x3d
#define R_XMM30		0x3e
#define R_XMM31		0x3f

#define R_IS_GPR(r)	((r) < 16)
#define R_IS_XMM(r)	((r) >= R_XMM0 && (r) <= R_XMM31)

/*#define TIMESTAMP_IN_REGISTER*/

#ifndef ARCH_X86_32
static uint8_t upcall_register = R_R15;
#define R_UPCALL	upcall_register
#ifdef TIMESTAMP_IN_REGISTER
#define R_TIMESTAMP	R_R14
#endif
#define R_CONST_IMM	R_R11
#else
#define R_CONST_IMM	255	/* this should not be used */
#endif
#define R_OFFSET_IMM	255	/* this should not be used */

#if defined(ARCH_X86_32)
#define R_FRAME		R_BP
#define R_SCRATCH_1	R_AX
#define R_SCRATCH_2	R_DX
#define R_SCRATCH_3	R_CX
#define R_SCRATCH_4	R_SAVED_2
#define R_SAVED_1	R_SI
#define R_SAVED_2	R_DI
#elif defined(ARCH_X86_WIN_ABI)
#define R_FRAME		R_BP
#define R_SCRATCH_1	R_AX
#define R_SCRATCH_2	R_DX
#define R_SCRATCH_3	R_CX
#define R_SCRATCH_4	R_SAVED_2
#define R_SAVED_1	R_SI
#define R_SAVED_2	R_DI
#else
#define R_FRAME		R_BX
#define R_SCRATCH_1	R_AX
#define R_SCRATCH_2	R_DX
#define R_SCRATCH_3	R_CX
#define R_SCRATCH_4	R_SAVED_2
#define R_SAVED_1	R_BP
#define R_SAVED_2	R_R12
#endif

#define FR_SCRATCH_1	R_XMM0
#define FR_SCRATCH_2	R_XMM1

#if defined(ARCH_X86_32)
#define R_ARG0		R_AX
#define R_ARG1		R_AX
#define R_ARG2		R_AX
#define R_ARG3		R_AX
#elif defined(ARCH_X86_WIN_ABI)
#define R_ARG0		R_CX
#define R_ARG1		R_DX
#define R_ARG2		R_R8
#define R_ARG3		R_R9
#else
#define R_ARG0		R_DI
#define R_ARG1		R_SI
#define R_ARG2		R_DX
#define R_ARG3		R_CX
#endif
#define R_RET0		R_AX

#if defined(ARCH_X86_32)
#define ARG_SPACE	0x1c		/* must be 0xc modulo 0x10 */
#define ARG_OFFSET	0x14
#elif defined(ARCH_X86_WIN_ABI) && !defined(TIMESTAMP_IN_REGISTER)
#define ARG_SPACE	0x28		/* must be 0x8 modulo 0x10 */
#define ARG_OFFSET	0xa0
#elif defined(ARCH_X86_WIN_ABI)
#define ARG_SPACE	0x20		/* must be 0x0 modulo 0x10 */
#define ARG_OFFSET	0x90
#endif

#define SUPPORTED_FP		(cpu_test_feature(CPU_FEATURE_sse) * 0x2 + cpu_test_feature(CPU_FEATURE_sse2) * 0x4)
#define SUPPORTED_FP_X87	0xe
#define SUPPORTED_FP_HALF_CVT	(cpu_test_feature(CPU_FEATURE_f16c) * 0x1)

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x20 && reg < 0x40;
}

static bool reg_is_segment(unsigned reg)
{
	return reg >= 0x18 && reg < 0x1e;
}

#if defined(ARCH_X86_32)

static const uint8_t regs_saved[] = { R_BX };
static const uint8_t regs_volatile[] = { 0 };
#define n_regs_volatile 0U
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = { R_XMM2, R_XMM3, R_XMM4, R_XMM5, R_XMM6, R_XMM7 };
#define reg_is_saved(r)	((r) == R_BX)

#elif defined(ARCH_X86_WIN_ABI)

static const uint8_t regs_saved[] = { R_BX, R_R12, R_R13,
#ifndef TIMESTAMP_IN_REGISTER
	R_R14,
#endif
	};
static const uint8_t regs_volatile[] = { R_R8, R_R9, R_R10 };
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = { R_XMM2, R_XMM3, R_XMM4, R_XMM5 };
#define reg_is_saved(r)	((r) == R_BX || ((r) >= R_R12 && ((r) <= R_R15)))

#else

static const uint8_t regs_saved[] = { R_R13,
#ifndef TIMESTAMP_IN_REGISTER
	R_R14,
#endif
	R_R15,
	};
#define n_regs_saved (n_array_elements(regs_saved) - !reg_is_segment(R_UPCALL))
static const uint8_t regs_volatile[] = { R_SI, R_DI, R_R8, R_R9, R_R10 };
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = { R_XMM2, R_XMM3, R_XMM4, R_XMM5, R_XMM6, R_XMM7, R_XMM8, R_XMM9, R_XMM10, R_XMM11, R_XMM12, R_XMM13, R_XMM14, R_XMM15 };
#define reg_is_saved(r)	((r) >= R_R13 && (r) <= R_R15)
#endif

static bool attr_w imm_is_8bit(int64_t imm)
{
	return imm >= -0x80 && imm < 0x80;
}

static bool attr_w imm_is_32bit(int64_t attr_unused imm)
{
#ifdef ARCH_X86_32
	return true;
#else
	return imm >= -0x80000000LL && imm < 0x80000000LL;
#endif
}

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	if (OP_SIZE_NATIVE == OP_SIZE_4)
		c = (int32_t)c;
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(reg);
	gen_one(ARG_IMM);
	gen_eight(c);
	return true;
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
		default:
			internal(file_line, "gen_address: invalid purpose %d", purpose);
	}
#ifndef ARCH_X86_32
	if (unlikely(!imm_is_32bit(imm)))
		return false;
#endif
	return true;
}

static bool is_direct_const(int64_t attr_unused imm, unsigned attr_unused purpose, unsigned attr_unused size)
{
#ifdef ARCH_X86_32
	return true;
#else
	if (purpose == IMM_PURPOSE_SUB && imm == -(int64_t)0x80000000)
		return false;
	return imm_is_32bit(imm);
#endif
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
#if defined(ARCH_X86_32)
	gen_insn(INSN_PUSH, OP_SIZE_4, 0, 0);
	gen_one(R_BX);

	gen_insn(INSN_PUSH, OP_SIZE_4, 0, 0);
	gen_one(R_BP);

	gen_insn(INSN_PUSH, OP_SIZE_4, 0, 0);
	gen_one(R_SI);

	gen_insn(INSN_PUSH, OP_SIZE_4, 0, 0);
	gen_one(R_DI);

	gen_insn(INSN_ALU, OP_SIZE_4, ALU_SUB, 1);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(ARG_SPACE);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_FRAME);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(ARG_SPACE + ARG_OFFSET);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 12);
#elif defined(ARCH_X86_WIN_ABI)
	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_BX);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_BP);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_SI);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_DI);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R12);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R13);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R14);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R15);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_ARG0);
#ifndef TIMESTAMP_IN_REGISTER
	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_ARG3);
#endif
	gen_insn(INSN_ALU, OP_SIZE_8, ALU_SUB, 1);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(ARG_SPACE);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG1);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_ARG2);
#ifdef TIMESTAMP_IN_REGISTER
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_TIMESTAMP);
	gen_one(R_ARG3);
#endif
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(ARG_OFFSET);
#else
	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_BX);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_BP);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R12);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R13);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R14);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_R15);

	gen_insn(INSN_PUSH, OP_SIZE_8, 0, 0);
	gen_one(R_ARG2);
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG0);

	if (!reg_is_segment(R_UPCALL)) {
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_UPCALL);
		gen_one(R_ARG1);
	}
#ifdef TIMESTAMP_IN_REGISTER
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_TIMESTAMP);
	gen_one(R_ARG2);
#endif
#if defined(ARCH_X86_X32)
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_ARG3);
	gen_one(R_ARG3);
#endif
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG3);
#endif
	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
#if defined(ARCH_X86_32) || defined(ARCH_X86_64)
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_DX);
	gen_one(ARG_IMM);
	gen_eight(ip);
#else
	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(R_AX);
	gen_one(ARG_IMM);
	gen_eight((uint64_t)ip << 32);
#endif
	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
#if defined(ARCH_X86_32)
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_AX);
	gen_one(R_FRAME);

	gen_insn(INSN_ALU, OP_SIZE_4, ALU_ADD, 1);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(ARG_SPACE);

	gen_insn(INSN_POP, OP_SIZE_4, 0, 0);
	gen_one(R_DI);

	gen_insn(INSN_POP, OP_SIZE_4, 0, 0);
	gen_one(R_SI);

	gen_insn(INSN_POP, OP_SIZE_4, 0, 0);
	gen_one(R_BP);

	gen_insn(INSN_POP, OP_SIZE_4, 0, 0);
	gen_one(R_BX);

	gen_insn(INSN_RET, 0, 0, 0);
#elif defined(ARCH_X86_WIN_ABI)
	gen_insn(INSN_ALU, OP_SIZE_8, ALU_ADD, 1);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
#if defined(TIMESTAMP_IN_REGISTER)
	gen_eight(ARG_SPACE);
#else
	gen_eight(ARG_SPACE + 8);
#endif
	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_AX);

	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_AX);
	gen_eight(0);
	gen_one(R_FRAME);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_AX);
	gen_eight(8);
	gen_one(R_DX);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R15);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R14);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R13);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R12);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_DI);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_SI);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_BP);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_BX);

	gen_insn(INSN_RET, 0, 0, 0);
#else
#if defined(ARCH_X86_X32)
	gen_insn(INSN_ALU, OP_SIZE_8, ALU_ADD, 1);
	gen_one(R_AX);
	gen_one(R_AX);
	gen_one(R_FRAME);
#else
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_AX);
	gen_one(R_FRAME);
#endif
	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_CX);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R15);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R14);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R13);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_R12);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_BP);

	gen_insn(INSN_POP, OP_SIZE_8, 0, 0);
	gen_one(R_BX);

	gen_insn(INSN_RET, 0, 0, 0);
#endif
	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
#if defined(ARCH_X86_32)
	ajla_assert_lo(arg * 4 < ARG_SPACE, (file_line, "gen_upcall_argument: argument %u", arg));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(arg * 4);
	gen_one(R_ARG0);
#endif
	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args)
{
#if defined(ARCH_X86_32)
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_AX);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 4);

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_AX);
	gen_eight(offset);
#elif defined(ARCH_X86_X32)
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_AX);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_UPCALL);
	gen_eight(offset);

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_8, 0, 0);
	gen_one(R_AX);
#else
	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_UPCALL);
	gen_eight(offset);
#endif
	g(gen_upcall_end(ctx, n_args));

	return true;
}

static bool attr_w gen_get_upcall_pointer(struct codegen_context *ctx, unsigned offset, unsigned reg)
{
#if defined(ARCH_X86_32)
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(reg);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 4);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(reg);
	gen_one(ARG_ADDRESS_1);
	gen_one(reg);
	gen_eight(offset);
#else
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(reg);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_UPCALL);
	gen_eight(offset);
#endif
	return true;
}

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
#if defined(ARCH_X86_32)
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_AX);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 4);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_DX);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 8);

	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_DX);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_AX);
	gen_eight(offsetof(struct cg_upcall_vector_s, ts));
#elif defined(TIMESTAMP_IN_REGISTER)
	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_TIMESTAMP);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_UPCALL);
	gen_eight(offsetof(struct cg_upcall_vector_s, ts));
#else
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_AX);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
#if defined(ARCH_X86_WIN_ABI)
	gen_eight(ARG_SPACE);
#else
	gen_eight(0);
#endif
	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_AX);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_UPCALL);
	gen_eight(offsetof(struct cg_upcall_vector_s, ts));
#endif
	gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
	gen_four(escape_label);

	return true;
}
