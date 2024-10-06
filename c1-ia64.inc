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

#define JMP_LIMIT			(cpu_test_feature(CPU_FEATURE_brl) ? JMP_SHORT : JMP_SHORTEST)

#define UNALIGNED_TRAP			1

#define ALU_WRITES_FLAGS(alu, im)	0
#define ALU1_WRITES_FLAGS(alu)		0
#define ROT_WRITES_FLAGS(alu)		0
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		0
#define ARCH_IS_3ADDRESS		1
#define ARCH_HAS_FLAGS			0
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			0
#define ARCH_HAS_DIV			0
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	((bits) <= 4)
#define ARCH_HAS_BTX(btx, size, cnst)	(((btx) == BTX_BTS || (btx) == BTX_BTR) && (cnst))
#define ARCH_SHIFT_SIZE			32
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		OP_SIZE_NATIVE

#define R_ZERO		0x00
#define R_GP		0x01
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
#define R_SP		0x0c
#define R_TP		0x0d
#define R_14		0x0e
#define R_15		0x0f
#define R_16		0x10
#define R_17		0x11
#define R_18		0x12
#define R_19		0x13
#define R_20		0x14
#define R_21		0x15
#define R_22		0x16
#define R_23		0x17
#define R_24		0x18
#define R_25		0x19
#define R_26		0x1a
#define R_27		0x1b
#define R_28		0x1c
#define R_29		0x1d
#define R_30		0x1e
#define R_31		0x1f
#define R_32		0x20
#define R_33		0x21
#define R_34		0x22
#define R_35		0x23
#define R_36		0x24
#define R_37		0x25
#define R_38		0x26
#define R_39		0x27
#define R_40		0x28
#define R_41		0x29
#define R_42		0x2a
#define R_43		0x2b
#define R_44		0x2c
#define R_45		0x2d
#define R_46		0x2e
#define R_47		0x2f
#define R_48		0x30
#define R_49		0x31
#define R_50		0x32
#define R_51		0x33
#define R_52		0x34
#define R_53		0x35
#define R_54		0x36
#define R_55		0x37
#define R_56		0x38
#define R_57		0x39
#define R_58		0x3a
#define R_59		0x3b
#define R_60		0x3c
#define R_61		0x3d
#define R_62		0x3e
#define R_63		0x3f

#define FR_ZERO		0x80
#define FR_ONE		0x81
#define FR_2		0x82
#define FR_3		0x83
#define FR_4		0x84
#define FR_5		0x85
#define FR_6		0x86
#define FR_7		0x87
#define FR_8		0x88
#define FR_9		0x89
#define FR_10		0x8a
#define FR_11		0x8b
#define FR_12		0x8c
#define FR_13		0x8d
#define FR_14		0x8e
#define FR_15		0x8f

#define P_0		0xa0
#define P_1		0xa1
#define P_2		0xa2
#define P_3		0xa3
#define P_4		0xa4
#define P_5		0xa5
#define P_6		0xa6
#define P_7		0xa7

#define B_0		0xb0
#define B_1		0xb1
#define B_2		0xb2
#define B_3		0xb3
#define B_4		0xb4
#define B_5		0xb5
#define B_6		0xb6
#define B_7		0xb7

#define R_FRAME		R_32
#define R_UPCALL	R_33
#define R_TIMESTAMP	R_34
#define R_ENTRY		R_35
#define R_SAVED_1	R_35
#define R_SAVED_2	R_36
#define R_SAVED_B0	R_37
#define R_SAVED_AR_PFS	R_38
#define R_ARG0		R_39
#define R_ARG1		R_40
#define R_ARG2		R_41
#define R_ARG3		R_42

#define R_RET0		R_8
#define R_RET1		R_9
#define R_SCRATCH_NA_1	R_14
#define R_SCRATCH_NA_2	R_15
#define R_SCRATCH_NA_3	R_16
#define R_SCRATCH_1	R_17
#define R_SCRATCH_2	R_18
#define R_SCRATCH_3	R_19
#define R_SCRATCH_4	R_20

#define R_OFFSET_IMM	R_2
#define R_CONST_IMM	R_3
#define R_CMP_RESULT	P_6

#define R_SCRATCH_B	B_6

#define FR_SCRATCH_1	FR_6
#define FR_SCRATCH_2	FR_7

#define SUPPORTED_FP	0xe

static inline bool reg_is_gr(unsigned reg)
{
	return reg < 0x40;
}

static inline bool reg_is_fp(unsigned reg)
{
	return reg >= 0x80 && reg < 0x90;
}

static inline bool reg_is_p(unsigned reg)
{
	return reg >= 0xa0 && reg < 0xa8;
}

static inline bool reg_is_b(unsigned reg)
{
	return reg >= 0xb0 && reg < 0xb8;
}

static inline uint64_t bits_gr(unsigned reg)
{
	ajla_assert_lo(reg_is_gr(reg), (file_line, "bits_gr: register %x", reg));
	return reg;
}

static inline uint64_t bits_fp(unsigned reg)
{
	ajla_assert_lo(reg_is_fp(reg), (file_line, "bits_fp: register %x", reg));
	return reg - 0x80;
}

static inline uint64_t bits_p(unsigned reg)
{
	ajla_assert_lo(reg_is_p(reg), (file_line, "bits_p: register %x", reg));
	return reg - 0xa0;
}

static inline uint64_t bits_b(unsigned reg)
{
	ajla_assert_lo(reg_is_b(reg), (file_line, "bits_b: register %x", reg));
	return reg - 0xb0;
}

static const uint8_t reg_available[] = { 0 };
#define reg_is_saved(r)	1

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(reg);
	gen_one(ARG_IMM);
	gen_eight(c);
	return true;
}

/*static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned attr_unused n_args);*/
static bool attr_w gen_imm(struct codegen_context *ctx, int64_t imm, unsigned purpose, unsigned size);

static bool attr_w gen_address(struct codegen_context *ctx, unsigned base, int64_t imm, unsigned attr_unused purpose, unsigned attr_unused size)
{
	if (!imm) {
		ctx->offset_imm = imm;
		ctx->offset_reg = false;
		ctx->base_reg = base;
	} else {
		g(gen_imm(ctx, imm, IMM_PURPOSE_ADD, OP_SIZE_NATIVE));
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
		gen_one(R_OFFSET_IMM);
		gen_one(base);
		gen_imm_offset();
		ctx->offset_imm = 0;
		ctx->offset_reg = false;
		ctx->base_reg = R_OFFSET_IMM;
	}
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
		case IMM_PURPOSE_MOVR:
			if (imm >= -0x2000 && imm < 0x2000)
				return true;
			break;
		case IMM_PURPOSE_SUB:
			if (imm > -0x2000 && imm <= 0x2000)
				return true;
			break;
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
			if (imm >= -0x80 && imm < 0x80)
				return true;
			break;
		case IMM_PURPOSE_CMP:
			if (imm > -0x80 && imm < 0x80)
				return true;
			break;
		case IMM_PURPOSE_ANDN:
			break;
		case IMM_PURPOSE_TEST:
			break;
		case IMM_PURPOSE_BITWISE:
			return true;
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
	gen_insn(INSN_IA64_ALLOC, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_SAVED_AR_PFS);
	gen_one(ARG_IMM);
	gen_eight(11);
	gen_one(ARG_IMM);
	gen_eight(7);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_SAVED_B0);
	gen_one(B_0);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ENTRY);

	gen_insn(INSN_RET, 0, 0, 0);

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
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RET0);
	gen_one(R_FRAME);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(B_0);
	gen_one(R_SAVED_B0);

	gen_insn(INSN_IA64_DEALLOC, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_SAVED_AR_PFS);

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
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	g(gen_address(ctx, R_SCRATCH_NA_1, 0, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_2);
	gen_address_offset();

	g(gen_address(ctx, R_SCRATCH_NA_1, 8, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_GP);
	gen_address_offset();

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_SCRATCH_B);
	gen_one(R_SCRATCH_NA_2);

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_8, 0, 0);
	gen_one(R_SCRATCH_B);

	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label);

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_4, R_SCRATCH_1, R_TIMESTAMP, COND_NE, escape_label));

	return true;
}
