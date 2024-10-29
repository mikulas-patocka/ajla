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
#define ARCH_HAS_FLAGS			0
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			0
#define ARCH_HAS_DIV			0
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	((bits) <= 4)
#define ARCH_HAS_BTX(btx, size, cnst)	(((btx) == BTX_BTS || (btx) == BTX_BTR) && (cnst))
#define ARCH_SHIFT_SIZE			32
#define ARCH_BOOL_SIZE			OP_SIZE_NATIVE
#define ARCH_HAS_FP_GP_MOV		1
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		OP_SIZE_NATIVE
#define i_size_cmp(size)		maximum(size, OP_SIZE_4)

#define N_SAVED_REGS	0x40

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
#define R_64		0x40
#define R_65		0x41
#define R_66		0x42
#define R_67		0x43
#define R_68		0x44
#define R_69		0x45
#define R_70		0x46
#define R_71		0x47
#define R_72		0x48
#define R_73		0x49
#define R_74		0x4a
#define R_75		0x4b
#define R_76		0x4c
#define R_77		0x4d
#define R_78		0x4e
#define R_79		0x4f
#define R_80		0x50
#define R_81		0x51
#define R_82		0x52
#define R_83		0x53
#define R_84		0x54
#define R_85		0x55
#define R_86		0x56
#define R_87		0x57
#define R_88		0x58
#define R_89		0x59
#define R_90		0x5a
#define R_91		0x5b
#define R_92		0x5c
#define R_93		0x5d
#define R_94		0x5e
#define R_95		0x5f

#define FR_ZERO		0x60
#define FR_ONE		0x61
#define FR_2		0x62
#define FR_3		0x63
#define FR_4		0x64
#define FR_5		0x65
#define FR_6		0x66
#define FR_7		0x67
#define FR_8		0x68
#define FR_9		0x69
#define FR_10		0x6a
#define FR_11		0x6b
#define FR_12		0x6c
#define FR_13		0x6d
#define FR_14		0x6e
#define FR_15		0x6f
#define FR_16		0x70
#define FR_17		0x71
#define FR_18		0x72
#define FR_19		0x73
#define FR_20		0x74
#define FR_21		0x75
#define FR_22		0x76
#define FR_23		0x77
#define FR_24		0x78
#define FR_25		0x79
#define FR_26		0x7a
#define FR_27		0x7b
#define FR_28		0x7c
#define FR_29		0x7d
#define FR_30		0x7e
#define FR_31		0x7f
#define FR_32		0x80
#define FR_33		0x81
#define FR_34		0x82
#define FR_35		0x83
#define FR_36		0x84
#define FR_37		0x85
#define FR_38		0x86
#define FR_39		0x87
#define FR_40		0x88
#define FR_41		0x89
#define FR_42		0x8a
#define FR_43		0x8b
#define FR_44		0x8c
#define FR_45		0x8d
#define FR_46		0x8e
#define FR_47		0x8f
#define FR_48		0x90
#define FR_49		0x91
#define FR_50		0x92
#define FR_51		0x93
#define FR_52		0x94
#define FR_53		0x95
#define FR_54		0x96
#define FR_55		0x97
#define FR_56		0x98
#define FR_57		0x99
#define FR_58		0x9a
#define FR_59		0x9b
#define FR_60		0x9c
#define FR_61		0x9d
#define FR_62		0x9e
#define FR_63		0x9f

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
#define R_ARG0		(R_32 + N_SAVED_REGS - 4)
#define R_ARG1		(R_32 + N_SAVED_REGS - 3)
#define R_ARG2		(R_32 + N_SAVED_REGS - 2)
#define R_ARG3		(R_32 + N_SAVED_REGS - 1)

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
	return reg < 0x60;
}

static inline bool reg_is_fp(unsigned reg)
{
	return reg >= 0x60 && reg < 0xa0;
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
	return reg - 0x60;
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

static const uint8_t regs_saved[] = {
	R_39,
	R_40,
	R_41,
	R_42,
	R_43,
	R_44,
	R_45,
	R_46,
	R_47,
	R_48,
	R_49,
	R_50,
	R_51,
	R_52,
	R_53,
	R_54,
	R_55,
	R_56,
	R_57,
	R_58,
	R_59,
	R_60,
	R_61,
	R_62,
	R_63,
	R_64,
	R_65,
	R_66,
	R_67,
	R_68,
	R_69,
	R_70,
	R_71,
	R_72,
	R_73,
	R_74,
	R_75,
	R_76,
	R_77,
	R_78,
	R_79,
	R_80,
	R_81,
	R_82,
	R_83,
	R_84,
	R_85,
	R_86,
	R_87,
	R_88,
	R_89,
	R_90,
	R_91,
};
static const uint8_t regs_volatile[] = {
	R_10,
	R_11,
	R_21,
	R_22,
	R_23,
	R_24,
	R_25,
	R_26,
	R_27,
	R_28,
	R_29,
	R_30,
	R_31,
};
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved 0U
static const uint8_t fp_volatile[] = {
	FR_8,
	FR_9,
	FR_10,
	FR_11,
	FR_12,
	FR_13,
	FR_14,
	FR_15,
	FR_32,
	FR_33,
	FR_34,
	FR_35,
	FR_36,
	FR_37,
	FR_38,
	FR_39,
	FR_40,
	FR_41,
	FR_42,
	FR_43,
	FR_44,
	FR_45,
	FR_46,
	FR_47,
	FR_48,
	FR_49,
	FR_50,
	FR_51,
	FR_52,
	FR_53,
	FR_54,
	FR_55,
	FR_56,
	FR_57,
	FR_58,
	FR_59,
	FR_60,
	FR_61,
	FR_62,
	FR_63,
};
#define reg_is_saved(r)	((r) >= R_32 && (r) <= R_95)

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(reg);
	gen_one(ARG_IMM);
	gen_eight(c);
	return true;
}

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
		case IMM_PURPOSE_CMP_LOGICAL:
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
	gen_eight(N_SAVED_REGS);
	gen_one(ARG_IMM);
	gen_eight(N_SAVED_REGS - 4);

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

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args)
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

	g(gen_upcall_end(ctx, n_args));

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
