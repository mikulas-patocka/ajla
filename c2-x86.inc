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

#define X86_ALU_RM8_R8			0x00
#define X86_ALU_RM16_R16		0x01
#define X86_ALU_R8_RM8			0x02
#define X86_ALU_R16_RM16		0x03
#define X86_ALU_AL_IMM8			0x04
#define X86_ALU_AX_IMM16		0x05
#define X86_0F				0x0f
#define X86_ES				0x26
#define X86_CS				0x2e
#define X86_SS				0x36
#define X86_DS				0x3e
#define X86_REX				0x40
#define  X86_REX_B				0x01
#define  X86_REX_X				0x02
#define  X86_REX_R				0x04
#define  X86_REX_W				0x08
#define X86_INC_R16			0x40
#define X86_DEC_R16			0x48
#define X86_PUSH_R16			0x50
#define X86_POP_R16			0x58
#define X86_MOVSXD			0x63
#define X86_FS				0x64
#define X86_GS				0x65
#define X86_OP_SIZE			0x66
#define X86_PUSH_IMM16			0x68
#define X86_IMUL_R16_RM16_IMM16		0x69
#define X86_PUSH_IMM8			0x6a
#define X86_IMUL_R16_RM16_IMM8		0x6b
#define X86_JCC_8			0x70
#define X86_ALU_RM8_IMM8		0x80
#define X86_ALU_RM16_IMM16		0x81
#define X86_ALU_RM16_IMM8		0x83
#define X86_TEST_RM8_R8			0x84
#define X86_TEST_RM16_R16		0x85
#define X86_MOV_RM8_R8			0x88
#define X86_MOV_RM16_R16		0x89
#define X86_MOV_R8_RM8			0x8a
#define X86_MOV_R16_RM16		0x8b
#define X86_LEA_R16_RM16		0x8d
#define X86_CBW				0x98
#define X86_CWD				0x99
#define X86_MOV_AL_M16			0xa0
#define X86_MOV_AX_M16			0xa1
#define X86_MOV_M16_AL			0xa2
#define X86_MOV_M16_AX			0xa3
#define X86_MOVSB			0xa4
#define X86_TEST_AL_IMM8		0xa8
#define X86_TEST_AX_IMM16		0xa9
#define X86_STOSB			0xaa
#define X86_MOV_R16_IMM16		0xb8
#define X86_ROT_RM8_IMM8		0xc0
#define X86_ROT_RM16_IMM8		0xc1
#define X86_RET_IMM16			0xc2
#define X86_RET				0xc3
#define X86_VEX_3			0xc4
#define X86_VEX_2			0xc5
#define X86_MOV_RM8_IMM8		0xc6
#define X86_MOV_RM16_IMM16		0xc7
#define  X86_MOV_R16_IMM16_REG			0x0
#define X86_8F				0x8f
#define  X86_8F_POP				0x0
#define X86_ROT_RM8_1			0xd0
#define X86_ROT_RM16_1			0xd1
#define X86_ROT_RM8_CL			0xd2
#define X86_ROT_RM16_CL			0xd3
#define X86_JMP_16			0xe9
#define X86_JMP_8			0xeb
#define X86_REPNE			0xf2
#define X86_REPE			0xf3
#define X86_F6				0xf6
#define  X86_F6_TEST_RM8_IMM8			0x0
#define  X86_F6_NOT_RM8				0x2
#define  X86_F6_NEG_RM8				0x3
#define  X86_F6_MUL_RM8				0x4
#define  X86_F6_IMUL_RM8			0x5
#define  X86_F6_DIV_RM8				0x6
#define  X86_F6_IDIV_RM8			0x7
#define X86_F7				0xf7
#define  X86_F7_TEST_RM16_IMM16			0x0
#define  X86_F7_NOT_RM16			0x2
#define  X86_F7_NEG_RM16			0x3
#define  X86_F7_MUL_RM16			0x4
#define  X86_F7_IMUL_RM16			0x5
#define  X86_F7_DIV_RM16			0x6
#define  X86_F7_IDIV_RM16			0x7
#define X86_FE				0xfe
#define  X86_FE_INC_RM8				0x0
#define  X86_FE_DEC_RM8				0x1
#define X86_FF				0xff
#define  X86_FF_INC_RM16			0x0
#define  X86_FF_DEC_RM16			0x1
#define  X86_FF_CALL_INDIRECT			0x2
#define  X86_FF_JMP_INDIRECT			0x4
#define  X86_FF_PUSH				0x6

#define X86_0F_MOVSS_X128_M32		0x10
#define X86_0F_MOVSS_M32_X128		0x11
#define X86_0F_MOVAPS_X128_M128		0x28
#define X86_0F_MOVAPS_M128_X128		0x29
#define X86_0F_CVTSI2SS_X128_RM32	0x2a
#define X86_0F_CVTTSS2SI_X128_RM32	0x2c
#define X86_0F_UCOMISS_X128_RM32	0x2e
#define X86_0F_38			0x38
#define X86_0F_3A			0x3a
#define X86_0F_CMOVCC_R16_RM16		0x40
#define X86_0F_SQRTPS_X128_M32		0x51
#define X86_0F_ANDPS_X128_M128		0x54
#define X86_0F_ANDNPS_X128_M128		0x55
#define X86_0F_ORPS_X128_M128		0x56
#define X86_0F_XORPS_X128_M128		0x57
#define X86_0F_ADDPS_X128_M32		0x58
#define X86_0F_MULPS_X128_M32		0x59
#define X86_0F_SUBPS_X128_M32		0x5c
#define X86_0F_DIVPS_X128_M32		0x5e
#define X86_0F_MOVD_X128_RM32		0x6e
#define X86_0F_MOVD_RM32_X128		0x7e
#define X86_0F_JCC_16			0x80
#define X86_0F_SETCC_RM8		0x90
#define X86_0F_BT_RM16_R16		0xa3
#define X86_0F_BTS_RM16_R16		0xab
#define X86_0F_BTR_RM16_R16		0xb3
#define X86_0F_BTX_RM16_IMM8		0xba
#define  X86_0F_BTX_BT_RM16_IMM8		0x4
#define  X86_0F_BTX_BTS_RM16_IMM8		0x5
#define  X86_0F_BTX_BTR_RM16_IMM8		0x6
#define  X86_0F_BTX_BTC_RM16_IMM8		0x7
#define X86_0F_BSWAP			0xc8
#define X86_0F_BTC_RM16_R16		0xbb
#define X86_0F_IMUL_R16_RM16		0xaf
#define X86_0F_MOVZX_R16_RM8		0xb6
#define X86_0F_MOVZX_R16_RM16		0xb7
#define X86_0F_POPCNT_R16_RM16		0xb8
#define X86_0F_BSF_R16_RM16		0xbc
#define X86_0F_BSR_R16_RM16		0xbd
#define X86_0F_MOVSX_R16_RM8		0xbe
#define X86_0F_MOVSX_R16_RM16		0xbf
#define X86_0F_PINSRW_X128_RM16_IMM8	0xc4

#define X86_0F_38_CVTPH2PS_X128_RM64	0x13
#define X86_0F_38_ROTX			0xf7

#define X86_0F_3A_ROUNDSS_X128_M32	0x0a
#define X86_0F_3A_ROUNDSD_X128_M64	0x0b
#define X86_0F_3A_PEXTRW_RM16_X128_IMM8	0x15
#define X86_0F_3A_CVTPS2PH_RM64_X128	0x1d

#define X87_FLD_RM32			0xd9
#define  X87_FLD_RM32_X				0x0
#define X87_FLDCW			0xd9
#define  X87_FLDCW_X				0x5
#define X87_FILD_M32			0xdb
#define  X87_FILD_M32_X				0x0
#define X87_FISTTP_M32			0xdb
#define  X87_FISTTP_M32_X			0x1
#define X87_FISTP_M32			0xdb
#define  X87_FISTP_M32_X			0x3
#define X87_FLD_M80			0xdb
#define  X87_FLD_M80_X				0x5
#define X87_FLD_M64			0xdd
#define  X87_FLD_M64_X				0x0
#define X87_FSTP_M32			0xd9
#define  X87_FSTP_M32_X				0x3
#define X87_FSTP_M80			0xdb
#define  X87_FSTP_M80_X				0x7
#define X87_FSTP_RM64			0xdd
#define  X87_FSTP_RM64_X			0x3
#define X87_FALU_ST_RM32		0xd8
#define X87_FCHS			0xd9
#define  X87_FCHS_2				0xe0
#define X87_FSQRT			0xd9
#define  X87_FSQRT_2				0xfa
#define X87_FRNDINT			0xd9
#define  X87_FRNDINT_2				0xfc
#define X87_FALU_ST_M64			0xdc
#define X87_FALU_STi_ST			0xdc
#define X87_FISTTP_M64			0xdd
#define  X87_FISTTP_M64_X			0x1
#define X87_FALUP_STi_ST0		0xde
#define  X87_ALU_ADD				0x0
#define  X87_ALU_MUL				0x1
#define  X87_ALU_FCOM				0x2
#define  X87_ALU_FCOMP				0x3
#define  X87_ALU_SUBR				0x4
#define  X87_ALU_SUB				0x5
#define  X87_ALU_DIVR				0x6
#define  X87_ALU_DIV				0x7
#define X87_FCOMPP			0xde
#define  X87_FCOMPP_2				0xd9
#define X87_FILD_M16			0xdf
#define  X87_FILD_M16_X				0x0
#define X87_FISTTP_M16			0xdf
#define  X87_FISTTP_M16_X			0x1
#define X87_FISTP_M16			0xdf
#define  X87_FISTP_M16_X			0x3
#define X87_FILD_M64			0xdf
#define  X87_FILD_M64_X				0x5
#define X87_FISTP_M64			0xdf
#define  X87_FISTP_M64_X			0x7
#define X87_FNSTSW			0xdf
#define  X87_FNSTSW_2				0xe0
#define X87_FCOMIP			0xdf
#define  X87_FCOMIP_2				0xf0

#define SSE_PREFIX_NONE			0
#define SSE_PREFIX_66			1
#define SSE_PREFIX_F3			2
#define SSE_PREFIX_F2			3

#define PREFIX_NONE			0
#define PREFIX_0F			1
#define PREFIX_0F_38			2
#define PREFIX_0F_3A			3

#ifdef ARCH_X86_32
#define cgen_rex(rex)		internal(file_line, "cgen_rex: attempting to generate rex in 32-bit mode: %02x", rex)
#else
#define cgen_rex(rex)		cgen_one(rex)
#endif

#define force_vex			0x10000

static bool attr_w cgen_rm_insn(struct codegen_context *ctx, int32_t sse_prefix, uint8_t prefix, uint8_t opcode, unsigned size, bool reg_is_reg, uint8_t reg, uint8_t *arg)
{
	uint8_t rex, mod, rm;
	int16_t sib;
	int64_t imm = 0;	/* avoid warning */
	uint8_t addr_size;
	uint8_t arg_reg;
	bool need_rex;

	if (unlikely(R_IS_XMM(reg)))
		reg -= R_XMM0;
	if (unlikely(R_IS_XMM(arg[0]))) {
		arg_reg = arg[0] - R_XMM0;
		arg = &arg_reg;
	}
	if (unlikely(!R_IS_GPR(reg)))
		internal(file_line, "cgen_rm_insn: invalid register %02x", reg);

	sib = -1;
	rex = X86_REX;
	if (size == OP_SIZE_8)
		rex |= X86_REX_W;
	if (reg & 8)
		rex |= X86_REX_R;
	if (arg[0] < 0x40) {
		if (arg[0] & 8)
			rex |= X86_REX_B;
		mod = 0xc0;
		rm = arg[0] & 7;
		addr_size = 0;
	} else {
		uint8_t *imm_ptr = arg + arg_size(arg[0]) - 8;
		imm = get_imm(imm_ptr);
		if (unlikely(!imm_is_32bit(imm)))
			internal(file_line, "cgen_rm_insn: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);
		if (arg[0] == ARG_ADDRESS_0) {
address_0:
			addr_size = 4;
			mod = 0x00;
			rm = 0x4;
			sib = 0x25;
			goto gen;
		}
		if (!imm) {
			addr_size = 0;
		} else if (imm >= -0x80 && imm <= 0x7f) {
			addr_size = 1;
		} else {
			addr_size = 4;
		}
		if ((arg[1] & 7) == 0x5 && addr_size == 0)
			addr_size = 1;
		if (addr_size == 0)
			mod = 0x00;
		else if (addr_size == 1)
			mod = 0x40;
		else
			mod = 0x80;
		if (arg[0] == ARG_ADDRESS_1) {
			if (reg_is_segment(arg[1])) {
				static const uint8_t segments[6] = { X86_ES, X86_CS, X86_SS, X86_DS, X86_FS, X86_GS };
				cgen_one(segments[arg[1] - R_ES]);
				goto address_0;
			}
			if (arg[1] & 8)
				rex |= X86_REX_B;
			if ((arg[1] & 7) == 0x4) {
				rm = 0x4;
				sib = 0x24;
				goto gen;
			}
			rm = arg[1] & 7;
			goto gen;
		}
		if (arg[0] >= ARG_ADDRESS_1_2 && arg[0] <= ARG_ADDRESS_1_8) {
			if (unlikely(arg[1] == R_SP))
				internal(file_line, "cgen_rm_insn: attemptint to scale SP");
			if (arg[1] & 8)
				rex |= X86_REX_X;
			addr_size = 4;
			mod = 0x00;
			rm = 0x4;
			sib = ((arg[0] - ARG_ADDRESS_1) << 6) | ((arg[1] & 7) << 3) | 0x5;
			goto gen;
		}
		if (arg[0] >= ARG_ADDRESS_2 && arg[0] <= ARG_ADDRESS_2_8) {
			if (unlikely(arg[2] == R_SP))
				internal(file_line, "cgen_rm_insn: attemptint to scale SP");
			if (arg[1] & 8)
				rex |= X86_REX_B;
			if (arg[2] & 8)
				rex |= X86_REX_X;
			rm = 0x4;
			sib = ((arg[0] - ARG_ADDRESS_2) << 6) | ((arg[2] & 7) << 3) | (arg[1] & 7);
			goto gen;
		}
		internal(file_line, "cgen_rm_insn: invalid argument %02x", arg[0]);
	}

gen:
	if (unlikely(sse_prefix >= 0)) {
		if (likely(cpu_test_feature(CPU_FEATURE_avx)) || (sse_prefix & force_vex)) {
			if ((rex & (X86_REX_X | X86_REX_B | X86_REX_W)) == 0 && prefix == PREFIX_0F) {
				cgen_one(X86_VEX_2);
				cgen_one((~rex & X86_REX_R) << 5 | (~(sse_prefix >> 8) & 0xf) << 3 | (sse_prefix & 3));
			} else {
				cgen_one(X86_VEX_3);
				cgen_one((~rex & (X86_REX_R | X86_REX_X | X86_REX_B)) << 5 | prefix);
				cgen_one((rex & X86_REX_W) << 4 | (~(sse_prefix >> 8) & 0xf) << 3 | (sse_prefix & 3));
			}
			goto avx_done;
		}
		switch (sse_prefix & 3) {
			case SSE_PREFIX_66:	cgen_one(X86_OP_SIZE); break;
			case SSE_PREFIX_F3:	cgen_one(X86_REPE); break;
			case SSE_PREFIX_F2:	cgen_one(X86_REPNE); break;
		}
	} else {
		if (size == OP_SIZE_2)
			cgen_one(X86_OP_SIZE);
	}
	need_rex = rex != X86_REX;
	need_rex |= size == OP_SIZE_1 && ((reg_is_reg && !reg_is_fp(reg) && reg >= 4) || (mod == 0xc0 && !reg_is_fp(arg[0]) && arg[0] >= 4));
	if (prefix == PREFIX_0F && (opcode == X86_0F_MOVZX_R16_RM8 || opcode == X86_0F_MOVSX_R16_RM8)) {
		need_rex |= mod == 0xc0 && arg[0] >= 4;
	}
	if (need_rex)
		cgen_rex(rex);

	switch (prefix) {
		case PREFIX_NONE:
			break;
		case PREFIX_0F:
			cgen_one(X86_0F);
			break;
		case PREFIX_0F_38:
			cgen_one(X86_0F);
			cgen_one(X86_0F_38);
			break;
		case PREFIX_0F_3A:
			cgen_one(X86_0F);
			cgen_one(X86_0F_3A);
			break;
		default:
			internal(file_line, "cgen_rm_insn: invalid prefix %u", prefix);
	}
avx_done:
	cgen_one(opcode);
	cgen_one(mod | ((reg & 7) << 3) | (rm & 7));
	if (sib >= 0)
		cgen_one(sib);
	switch (addr_size) {
		case 1:
			cgen_one(imm);
			break;
		case 4:
			cgen_four(imm);
			break;
	}
	return true;
}

static bool attr_w cgen_sse_insn(struct codegen_context *ctx, unsigned sse_prefix, unsigned sse_op_map, uint8_t opcode, bool wide, uint8_t reg, uint8_t reg2, uint8_t *arg)
{
	g(cgen_rm_insn(ctx, sse_prefix + (reg2 << 8), sse_op_map, opcode, !wide ? OP_SIZE_4 : OP_SIZE_8, true, reg, arg));
	return true;
}

static bool attr_w cgen_push(struct codegen_context *ctx)
{
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position += arg_size(*arg1);
	if (likely(R_IS_GPR(arg1[0]))) {
		if (arg1[0] & 8)
			cgen_rex(X86_REX | X86_REX_B);
		cgen_one(X86_PUSH_R16 + (arg1[0] & 7));
		return true;
	}
	if (arg1[0] == ARG_IMM) {
		int64_t imm;
		imm = get_imm(&arg1[1]);
		if (unlikely(!imm_is_32bit(imm)))
			internal(file_line, "cgen_push: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);
		if (imm >= -0x80 && imm <= 0x7f) {
			cgen_one(X86_PUSH_IMM8);
			cgen_one(imm);
			return true;
		} else {
			cgen_one(X86_PUSH_IMM16);
			cgen_four(imm);
			return true;
		}
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_FF, OP_SIZE_4, false, X86_FF_PUSH, arg1));
	return true;
}

static bool attr_w cgen_pop(struct codegen_context *ctx)
{
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position += arg_size(*arg1);
	if (likely(R_IS_GPR(arg1[0]))) {
		if (arg1[0] & 8)
			cgen_rex(X86_REX | X86_REX_B);
		cgen_one(X86_POP_R16 + (arg1[0] & 7));
		return true;
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_8F, OP_SIZE_4, false, X86_8F_POP, arg1));
	return true;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg2[0] == ARG_IMM) {
		int rex = X86_REX;
		int64_t imm;
		imm = get_imm(&arg2[1]);
		if (R_IS_GPR(arg1[0])) {
			if (arg1[0] & 8)
				rex |= X86_REX_B;
#ifndef ARCH_X86_32
			if (imm >= 0 && imm < 0x100000000LL)
#endif
			{
				if (rex != X86_REX)
					cgen_rex(rex);
				cgen_one(X86_MOV_R16_IMM16 + (arg1[0] & 7));
				cgen_four(imm);
				return true;
			}
			if (imm >= ~(int64_t)0x7fffffff && imm < 0) {
				goto mov_rm;
			}
			rex |= X86_REX_W;
			cgen_rex(rex);
			cgen_one(X86_MOV_R16_IMM16 + (arg1[0] & 7));
			cgen_eight(imm);
			return true;
		} else {
			if (size < OP_SIZE_4) {
				g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_MOV_RM8_IMM8 : X86_MOV_RM16_IMM16, size, false, X86_MOV_R16_IMM16_REG, arg1));
				if (size == OP_SIZE_1)
					cgen_one(imm);
				else
					cgen_two(imm);
				return true;
			}
mov_rm:
			if (unlikely(!imm_is_32bit(imm)))
				internal(file_line, "cgen_mov: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_MOV_RM16_IMM16, maximum(size, OP_SIZE_4), false, X86_MOV_R16_IMM16_REG, arg1));
			cgen_four(imm);
			return true;
		}
	}
	if (arg1[0] == R_AX && size >= OP_SIZE_4 && arg2[0] == ARG_ADDRESS_0) {
		int64_t imm;
		imm = get_imm(&arg2[1]);
		if (size == OP_SIZE_8)
			cgen_rex(X86_REX | X86_REX_W);
		cgen_one(X86_MOV_AX_M16);
		cgen_eight(imm);
		return true;
	}
	if (arg1[0] == ARG_ADDRESS_0 && arg2[0] == R_AX) {
		uint8_t code = size == OP_SIZE_1 ? X86_MOV_M16_AL : X86_MOV_M16_AX;
		int64_t imm;
		imm = get_imm(&arg1[1]);
		if (size == OP_SIZE_2)
			cgen_one(X86_OP_SIZE);
		if (size == OP_SIZE_8)
			cgen_rex(X86_REX | X86_REX_W);
		cgen_one(code);
		cgen_eight(imm);
		return true;
	}
	if (R_IS_XMM(arg1[0]) && ARG_IS_ADDRESS(arg2[0])) {
		if (size == OP_SIZE_2) {
			g(cgen_sse_insn(ctx, SSE_PREFIX_66, PREFIX_0F, X86_0F_PINSRW_X128_RM16_IMM8, false, arg1[0], R_XMM7, arg2));
			cgen_one(0x00);
			return true;
		}
		if (size == OP_SIZE_16) {
			g(cgen_sse_insn(ctx, SSE_PREFIX_NONE, PREFIX_0F, X86_0F_MOVAPS_X128_M128, false, arg1[0], 0, arg2));
			return true;
		}
		g(cgen_sse_insn(ctx, size == OP_SIZE_4 ? SSE_PREFIX_F3 : SSE_PREFIX_F2, PREFIX_0F, X86_0F_MOVSS_X128_M32, false, arg1[0], 0, arg2));
		return true;
	}
	if (ARG_IS_ADDRESS(arg1[0]) && R_IS_XMM(arg2[0])) {
		if (size == OP_SIZE_2) {
			g(cgen_sse_insn(ctx, SSE_PREFIX_66, PREFIX_0F_3A, X86_0F_3A_PEXTRW_RM16_X128_IMM8, false, arg2[0], 0, arg1));
			cgen_one(0x00);
			return true;
		}
		if (size == OP_SIZE_16) {
			g(cgen_sse_insn(ctx, SSE_PREFIX_NONE, PREFIX_0F, X86_0F_MOVAPS_M128_X128, false, arg2[0], 0, arg1));
			return true;
		}
		g(cgen_sse_insn(ctx, size == OP_SIZE_4 ? SSE_PREFIX_F3 : SSE_PREFIX_F2, PREFIX_0F, X86_0F_MOVSS_M32_X128, false, arg2[0], 0, arg1));
		return true;
	}
	if (R_IS_XMM(arg1[0]) && R_IS_XMM(arg2[0])) {
		g(cgen_sse_insn(ctx, SSE_PREFIX_NONE, PREFIX_0F, X86_0F_MOVAPS_X128_M128, false, arg1[0], 0, arg2));
		return true;
	}
	if (R_IS_XMM(arg1[0]) && R_IS_GPR(arg2[0])) {
		g(cgen_sse_insn(ctx, SSE_PREFIX_66, PREFIX_0F, X86_0F_MOVD_X128_RM32, size == OP_SIZE_8, arg1[0], 0, arg2));
		return true;
	}
	if (R_IS_GPR(arg1[0]) && R_IS_XMM(arg2[0])) {
		g(cgen_sse_insn(ctx, SSE_PREFIX_66, PREFIX_0F, X86_0F_MOVD_RM32_X128, size == OP_SIZE_8, arg2[0], 0, arg1));
		return true;
	}
	if (!R_IS_GPR(arg1[0]) && unlikely(!R_IS_GPR(arg2[0]))) {
		/*debug("%s", da(ctx->fn,function)->function_name);*/
		internal(file_line, "cgen_mov: two addresses not supported");
	}
	if (!R_IS_GPR(arg1[0])) {
		uint8_t code = size == OP_SIZE_1 ? X86_MOV_RM8_R8 : X86_MOV_RM16_R16;
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, code, size, true, arg2[0], arg1));
		return true;
	} else if (size >= OP_SIZE_4) {
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_MOV_R16_RM16, size, true, arg1[0], arg2));
		return true;
	} else {
		uint8_t code = size == OP_SIZE_1 ? X86_0F_MOVZX_R16_RM8 : X86_0F_MOVZX_R16_RM16;
		g(cgen_rm_insn(ctx, -1, PREFIX_0F, code, OP_SIZE_4, false, arg1[0], arg2));
		return true;
	}
}

static bool attr_w cgen_movsx(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1, *arg2;
	if (unlikely(size == OP_SIZE_NATIVE)) {
		g(cgen_mov(ctx, size));
		return true;
	}
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (size <= OP_SIZE_2) {
		g(cgen_rm_insn(ctx, -1, PREFIX_0F, size == OP_SIZE_1 ? X86_0F_MOVSX_R16_RM8 : X86_0F_MOVSX_R16_RM16, OP_SIZE_NATIVE, true, arg1[0], arg2));
	} else {
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_MOVSXD, OP_SIZE_NATIVE, true, arg1[0], arg2));
	}
	return true;
}

static bool attr_w cgen_lea(struct codegen_context *ctx, unsigned size)
{
	uint8_t addr[11];
	uint8_t *arg1, *arg2, *arg3;

	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg3[0] == ARG_IMM) {
		int64_t imm;
		if (arg2[0] == ARG_SHIFTED_REGISTER) {
			if (unlikely((arg2[1] & ARG_SHIFT_MODE) != ARG_SHIFT_LSL) ||
			    unlikely((arg2[1] & ARG_SHIFT_AMOUNT) > 3))
				goto invalid;
			addr[0] = ARG_ADDRESS_1 + (arg2[1] & ARG_SHIFT_AMOUNT);
			addr[1] = arg2[2];
		} else {
			addr[0] = ARG_ADDRESS_1;
			addr[1] = arg2[0];
		}
		imm = get_imm(&arg3[1]);
		memcpy(&addr[2], &imm, 8);
	} else if (R_IS_GPR(arg3[0])) {
		addr[0] = ARG_ADDRESS_2;
		addr[1] = arg2[0];
		addr[2] = arg3[0];
		memset(&addr[3], 0, 8);
	} else if (arg3[0] == ARG_SHIFTED_REGISTER) {
		if (unlikely((arg3[1] & ARG_SHIFT_MODE) != ARG_SHIFT_LSL) ||
		    unlikely((arg3[1] & ARG_SHIFT_AMOUNT) > 3))
			goto invalid;
		addr[0] = ARG_ADDRESS_2 + (arg3[1] & ARG_SHIFT_AMOUNT);
		addr[1] = arg2[0];
		addr[2] = arg3[2];
		memset(&addr[3], 0, 8);
	} else {
invalid:
		internal(file_line, "cgen_lea: invalid argument %u, %02x, %02x, %02x", size, arg1[0], arg2[0], arg3[0]);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_LEA_R16_RM16, size, true, arg1[0], addr));
	return true;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags)
{
	uint8_t *arg1, *arg2, *arg3;
	if (alu != 7) {
		arg1 = ctx->code_position;
		arg2 = arg1 + arg_size(*arg1);
		arg3 = arg2 + arg_size(*arg2);
		ctx->code_position = arg3 + arg_size(*arg3);
		if (unlikely(arg_size(*arg1) != arg_size(*arg2)))
			internal(file_line, "cgen_alu: three-operand mode not supported");
		if (unlikely(memcmp(arg1, arg2, arg_size(*arg1))))
			internal(file_line, "cgen_alu: three-operand mode not supported");
	} else {
		arg1 = ctx->code_position;
		arg2 = arg1;
		arg3 = arg2 + arg_size(*arg2);
		ctx->code_position = arg3 + arg_size(*arg3);
	}

	if (unlikely(alu == ALU_MUL)) {
		if (unlikely(arg3[0] == ARG_IMM)) {
			uint8_t code;
			int64_t imm;
			imm = get_imm(&arg3[1]);
			if (unlikely(!imm_is_32bit(imm)))
				internal(file_line, "cgen_alu: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);
			code = imm_is_8bit(imm) ? X86_IMUL_R16_RM16_IMM8 : X86_IMUL_R16_RM16_IMM16;
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, code, size, true, arg1[0], arg2));
			if (code == X86_IMUL_R16_RM16_IMM8) {
				cgen_one(imm);
			} else if (size == OP_SIZE_2) {
				cgen_two(imm);
			} else {
				cgen_four(imm);
			}
			return true;
		}
		if (unlikely(size == OP_SIZE_1)) {
			if (unlikely(arg1[0] != R_AX))
				internal(file_line, "cgen_alu: imul with unsupported register");
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_F6, size, false, X86_F6_IMUL_RM8, arg3));
			return true;
		} else {
			if (unlikely(!R_IS_GPR(arg1[0])))
				internal(file_line, "cgen_alu: invalid multiply args");
			g(cgen_rm_insn(ctx, -1, PREFIX_0F, X86_0F_IMUL_R16_RM16, size, true, arg1[0], arg3));
			return true;
		}
	}

	if (arg3[0] == ARG_IMM) {
		uint8_t code;
		bool bit8;
		int64_t imm;
		imm = get_imm(&arg3[1]);
		if (unlikely(!imm_is_32bit(imm)))
			internal(file_line, "cgen_alu: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);

		if (!(writes_flags & 2)) {
			if ((alu == ALU_ADD && imm == 1) || (alu == ALU_SUB && imm == -1)) {
#ifdef ARCH_X86_32
				if (R_IS_GPR(arg1[0]) && size >= OP_SIZE_2) {
					if (size == OP_SIZE_2)
						cgen_one(X86_OP_SIZE);
					cgen_one(X86_INC_R16 + arg1[0]);
					return true;
				}
#endif
				g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_FE : X86_FF, size, false, X86_FE_INC_RM8, arg1));
				return true;
			}
			if ((alu == ALU_ADD && imm == -1) || (alu == ALU_SUB && imm == 1)) {
#ifdef ARCH_X86_32
				if (R_IS_GPR(arg1[0]) && size >= OP_SIZE_2) {
					if (size == OP_SIZE_2)
						cgen_one(X86_OP_SIZE);
					cgen_one(X86_DEC_R16 + arg1[0]);
					return true;
				}
#endif
				g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_FE : X86_FF, size, false, X86_FE_DEC_RM8, arg1));
				return true;
			}
		}

		if (arg1[0] == R_AX) {
			if (imm_is_8bit(imm) && size >= OP_SIZE_4)
				goto use_shorter;
			bit8 = false;
			code = size == OP_SIZE_1 ? X86_ALU_AL_IMM8 : X86_ALU_AX_IMM16;
			if (size == OP_SIZE_2)
				cgen_one(X86_OP_SIZE);
			if (size == OP_SIZE_8)
				cgen_rex(X86_REX | X86_REX_W);
			code += alu * 8;
			cgen_one(code);
		} else {
use_shorter:
			bit8 = imm_is_8bit(imm);
			code = size == OP_SIZE_1 ? X86_ALU_RM8_IMM8 : bit8 ? X86_ALU_RM16_IMM8 : X86_ALU_RM16_IMM16;
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, code, size, false, alu, arg1));
		}
		if (bit8 || size == OP_SIZE_1) {
			cgen_one(imm);
		} else if (size == OP_SIZE_2) {
			cgen_two(imm);
		} else {
			cgen_four(imm);
		}
		return true;
	}

	if (R_IS_XMM(arg1[0]) && size == OP_SIZE_16) {
		uint8_t code;
		switch (alu) {
			case ALU_AND:	code = X86_0F_ANDPS_X128_M128; break;
			case ALU_ANDN:	code = X86_0F_ANDNPS_X128_M128; break;
			case ALU_OR:	code = X86_0F_ORPS_X128_M128; break;
			case ALU_XOR:	code = X86_0F_XORPS_X128_M128; break;
			default:	internal(file_line, "invalid sse alu: %u", alu);
		}
		g(cgen_sse_insn(ctx, SSE_PREFIX_NONE, PREFIX_0F, code, false, arg1[0], arg2[0], arg3));
		return true;
	}

	if (!R_IS_GPR(arg1[0]) && unlikely(!R_IS_GPR(arg3[0])))
		internal(file_line, "cgen_alu: two addresses not supported");

	if (!R_IS_GPR(arg1[0])) {
		uint8_t code = size == OP_SIZE_1 ? X86_ALU_RM8_R8 : X86_ALU_RM16_R16;
		code += alu * 8;
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, code, size, true, arg3[0], arg1));
		return true;
	} else {
		uint8_t code = size == OP_SIZE_1 ? X86_ALU_R8_RM8 : X86_ALU_R16_RM16;
		code += alu * 8;
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, code, size, true, arg1[0], arg3));
		return true;
	}
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint8_t rex;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (alu == ALU1_NOT || alu == ALU1_NEG || alu == ALU1_BSWAP) {
		if (unlikely(arg1[0] != arg2[0]))
			internal(file_line, "cgen_alu1: arguments mismatch: %x, %x", arg1[0], arg2[0]);
	}
	switch (alu) {
		case ALU1_NOT:
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_F6 : X86_F7, size, false, X86_F6_NOT_RM8, arg1));
			return true;
		case ALU1_NEG:
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_F6 : X86_F7, size, false, X86_F6_NEG_RM8, arg1));
			return true;
		case ALU1_BSWAP:
			if (unlikely(size <= OP_SIZE_2))
				internal(file_line, "cgen_alu1: bytes or words not supported with this operation");
			rex = X86_REX;
			if (!R_IS_GPR(arg1[0]))
				internal(file_line, "cgen_alu1: bswap needs a register");
			if (arg1[0] & 8)
				rex |= X86_REX_B;
			if (size == OP_SIZE_8)
				rex |= X86_REX_W;
			if (rex != X86_REX)
				cgen_rex(rex);
			cgen_one(X86_0F);
			cgen_one(X86_0F_BSWAP + (arg1[0] & 7));
			return true;
		case ALU1_BSF:
		case ALU1_BSR:
		case ALU1_LZCNT:
		case ALU1_POPCNT:
			if (unlikely(size == OP_SIZE_1))
				internal(file_line, "cgen_alu1: bytes not supported with this operation");
			if (alu == ALU1_POPCNT || alu == ALU1_LZCNT)
				cgen_one(X86_REPE);
			g(cgen_rm_insn(ctx, -1, PREFIX_0F, alu == ALU1_BSF ? X86_0F_BSF_R16_RM16 : alu == ALU1_BSR || alu == ALU1_LZCNT ? X86_0F_BSR_R16_RM16 : X86_0F_POPCNT_R16_RM16, size, true, arg1[0], arg2));
			return true;
		default:
			internal(file_line, "cgen_alu1: invalid operation %u", alu);
			return false;
	}
}

static bool attr_w cgen_test(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1, *arg2;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (arg2[0] == ARG_IMM) {
		int64_t imm;
		imm = get_imm(&arg2[1]);
		if (arg1[0] == R_AX) {
			if (size == OP_SIZE_1) {
				cgen_one(X86_TEST_AL_IMM8);
			} else if (size == OP_SIZE_2) {
				cgen_one(X86_OP_SIZE);
				cgen_one(X86_TEST_AX_IMM16);
			} else if (size == OP_SIZE_4) {
				cgen_one(X86_TEST_AX_IMM16);
			} else {
				if (unlikely(!imm_is_32bit(imm)))
					internal(file_line, "cgen_Test: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);
				cgen_rex(X86_REX | X86_REX_W);
				cgen_one(X86_TEST_AX_IMM16);
			}
		} else {
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_F6 : X86_F7, size, false, X86_F6_TEST_RM8_IMM8, arg1));
		}
		if (size == OP_SIZE_1) {
			cgen_one(imm);
		} else if (size == OP_SIZE_2) {
			cgen_two(imm);
		} else if (size == OP_SIZE_4) {
			cgen_four(imm);
		} else {
			if (unlikely(!imm_is_32bit(imm)))
				internal(file_line, "cgen_Test: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);
			cgen_four(imm);
		}
		return true;
	}

	if (!R_IS_GPR(arg1[0]) && unlikely(!R_IS_GPR(arg2[0])))
		internal(file_line, "cgen_test: two addresses not supported");

	if (!R_IS_GPR(arg1[0])) {
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_TEST_RM8_R8 : X86_TEST_RM16_R16, size, true, arg2[0], arg1));
	} else {
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_TEST_RM8_R8 : X86_TEST_RM16_R16, size, true, arg1[0], arg2));
	}
	return true;
}

static bool attr_w cgen_lea3(struct codegen_context *ctx, unsigned size, unsigned shift)
{
	uint8_t addr[11];
	uint8_t *arg1, *arg2, *arg3, *arg4;

	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);

	if (unlikely(!R_IS_GPR(arg1[0])) || unlikely(!R_IS_GPR(arg2[0])) || unlikely(!R_IS_GPR(arg3[0])) || unlikely(arg4[0] != ARG_IMM))
		internal(file_line, "cgen_lea3: invalid arguments");

	addr[0] = ARG_ADDRESS_2 + shift;
	addr[1] = arg2[0];
	addr[2] = arg3[0];
	memcpy(&addr[3], &arg4[1], 8);

	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_LEA_R16_RM16, size, true, arg1[0], addr));

	return true;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, uint8_t rot, unsigned writes_flags)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (cpu_test_feature(CPU_FEATURE_bmi2) && size >= OP_SIZE_4 && arg3[0] != ARG_IMM && !writes_flags && (rot == ROT_SHL || rot == ROT_SHR || rot == ROT_SAR)) {
		int32_t sse_prefix;
		switch (rot) {
			case ROT_SHL:	sse_prefix = SSE_PREFIX_66; break;
			case ROT_SAR:	sse_prefix = SSE_PREFIX_F3; break;
			case ROT_SHR:	sse_prefix = SSE_PREFIX_F2; break;
			default:	internal(file_line, "cgen_rot: invalid rotation %x", rot);
		}
		g(cgen_sse_insn(ctx, sse_prefix + force_vex, PREFIX_0F_38, X86_0F_38_ROTX, size == OP_SIZE_8, arg1[0], arg3[0], arg2));
		return true;
	}

	if (arg1[0] != arg2[0])
		internal(file_line, "cgen_rot: invalid arguments: %x, %02x, %02x, %02x", rot, arg1[0], arg2[0], arg3[0]);

	if (arg3[0] == R_CX) {
		g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_ROT_RM8_CL : X86_ROT_RM16_CL, size, false, rot, arg1));
	} else if (likely(arg3[0] == ARG_IMM)) {
		int64_t imm;
		imm = get_imm(&arg3[1]);
		if (imm == 1) {
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_ROT_RM8_1 : X86_ROT_RM16_1, size, false, rot, arg1));
		} else {
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_ROT_RM8_IMM8 : X86_ROT_RM16_IMM8, size, false, rot, arg1));
			cgen_one(imm);
		}
	} else {
		internal(file_line, "cgen_rot: invalid argument %02x", arg3[0]);
	}
	return true;
}

static bool attr_w cgen_btxt(struct codegen_context *ctx, unsigned size, uint8_t bt, uint8_t *arg1, uint8_t *arg2)
{
	if (arg2[0] == ARG_IMM) {
		g(cgen_rm_insn(ctx, -1, PREFIX_0F, X86_0F_BTX_RM16_IMM8, size, false, X86_0F_BTX_BT_RM16_IMM8 + bt, arg1));
		cgen_one(arg2[1]);
	} else {
		g(cgen_rm_insn(ctx, -1, PREFIX_0F, X86_0F_BT_RM16_R16 + bt * 8, size, true, arg2[0], arg1));
	}
	return true;
}

static bool attr_w cgen_bt(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	return cgen_btxt(ctx, size, BTX_BT, arg1, arg2);
}

static bool attr_w cgen_btx(struct codegen_context *ctx, unsigned size, uint8_t bt)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg1[0] != arg2[0])
		internal(file_line, "cgen_btx: invalid arguments");

	return cgen_btxt(ctx, size, bt, arg1, arg3);
}

static bool attr_w cgen_mul_l(struct codegen_context *ctx, unsigned size, bool sgn)
{
	uint8_t *arg1, *arg2, *arg3, *arg4;
	uint32_t reg_up;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	reg_up = size == OP_SIZE_1 ? R_AX : R_DX;
	if (unlikely(arg1[0] != R_AX) || unlikely(arg2[0] != reg_up) || unlikely(arg3[0] != R_AX) || unlikely(arg4[0] == ARG_IMM))
		internal(file_line, "cgen_mul_l: invalid mul arguments");

	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_F6 : X86_F7, size, false, !sgn ? X86_F6_MUL_RM8 : X86_F6_IMUL_RM8, arg4));
	return true;
}

static bool attr_w cgen_div_l(struct codegen_context *ctx, unsigned size, bool sgn)
{
	uint8_t *arg1, *arg2, *arg3, *arg4, *arg5;
	uint32_t reg_up;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	arg4 = arg3 + arg_size(*arg3);
	arg5 = arg4 + arg_size(*arg4);
	ctx->code_position = arg5 + arg_size(*arg5);
	reg_up = size == OP_SIZE_1 ? R_AX : R_DX;
	if (unlikely(arg1[0] != R_AX) || unlikely(arg2[0] != reg_up) || unlikely(arg3[0] != R_AX) || unlikely(arg4[0] != reg_up) || unlikely(arg5[0] == ARG_IMM))
		internal(file_line, "cgen_div_l: invalid div arguments");

	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, size == OP_SIZE_1 ? X86_F6 : X86_F7, size, false, !sgn ? X86_F6_DIV_RM8 : X86_F6_IDIV_RM8, arg5));
	return true;
}

static bool attr_w cgen_cmov(struct codegen_context *ctx, unsigned size, unsigned cond)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != arg2[0]))
		internal(file_line, "cgen_cmov: invalid arguments");
	g(cgen_rm_insn(ctx, -1, PREFIX_0F, X86_0F_CMOVCC_R16_RM16 + cond, size, true, arg1[0], arg3));
	return true;
}

static bool attr_w cgen_memcpy(struct codegen_context *ctx)
{
	int64_t disp_dest, disp_src;
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != ARG_ADDRESS_1_POST_I) || unlikely(arg2[0] != ARG_ADDRESS_1_POST_I) || unlikely(arg3[0] != R_CX))
		goto invl;
	if (unlikely(arg1[1] != R_DI) || unlikely(arg2[1] != R_SI))
		goto invl;
	disp_dest = get_imm(&arg1[2]);
	disp_src = get_imm(&arg2[2]);
	if (unlikely(disp_dest != 0) || unlikely(disp_src != 0))
		goto invl;

	cgen_one(X86_REPE);
	cgen_one(X86_MOVSB);
	return true;

invl:
	internal(file_line, "cgen_memcpy: invalid arguments %02x, %02x, %02x", *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_memset(struct codegen_context *ctx)
{
	int64_t disp_dest;
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != ARG_ADDRESS_1_POST_I) || unlikely(arg2[0] != R_CX) || unlikely(arg3[0] != R_AX))
		goto invl;
	if (unlikely(arg1[1] != R_DI))
		goto invl;
	disp_dest = get_imm(&arg1[2]);
	if (unlikely(disp_dest != 0))
		goto invl;

	cgen_one(X86_REPE);
	cgen_one(X86_STOSB);
	return true;

invl:
	internal(file_line, "cgen_memset: invalid arguments %02x, %02x, %02x", *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_sse_cmp(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	g(cgen_sse_insn(ctx, size == OP_SIZE_4 ? SSE_PREFIX_NONE: SSE_PREFIX_66, PREFIX_0F, X86_0F_UCOMISS_X128_RM32, false, arg1[0], 0, arg2));
	return true;
}

static bool attr_w cgen_sse_alu(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint8_t opcode;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (alu) {
		case FP_ALU_ADD:	opcode = X86_0F_ADDPS_X128_M32; break;
		case FP_ALU_SUB:	opcode = X86_0F_SUBPS_X128_M32; break;
		case FP_ALU_MUL:	opcode = X86_0F_MULPS_X128_M32; break;
		case FP_ALU_DIV:	opcode = X86_0F_DIVPS_X128_M32; break;
		default:		internal(file_line, "cgen_sse_alu: invalid alu %u", alu);
	}
	g(cgen_sse_insn(ctx, size == OP_SIZE_4 ? SSE_PREFIX_F3 : SSE_PREFIX_F2, PREFIX_0F, opcode, false, arg1[0], arg2[0], arg3));
	return true;
}

static bool attr_w cgen_sse_alu1(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint8_t opcode;
	unsigned sse_pfx, sse_op_map;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (alu) {
		case FP_ALU1_SQRT:	if (size == OP_SIZE_4) {
						sse_pfx = SSE_PREFIX_F3;
					} else if (size == OP_SIZE_8) {
						sse_pfx = SSE_PREFIX_F2;
					} else {
						goto fail;
					}
					sse_op_map = PREFIX_0F;
					opcode = X86_0F_SQRTPS_X128_M32;
					break;
		case FP_ALU1_ROUND:
		case FP_ALU1_FLOOR:
		case FP_ALU1_CEIL:
		case FP_ALU1_TRUNC:	sse_pfx = SSE_PREFIX_66;
					sse_op_map = PREFIX_0F_3A;
					if (size == OP_SIZE_4) {
						opcode = X86_0F_3A_ROUNDSS_X128_M32;
					} else if (size == OP_SIZE_8) {
						opcode = X86_0F_3A_ROUNDSD_X128_M64;
					} else {
						goto fail;
					}
					break;
		fail:
		default:		internal(file_line, "cgen_sse_alu1: invalid alu %u, %u", alu, size);
	}
	g(cgen_sse_insn(ctx, sse_pfx, sse_op_map, opcode, false, arg1[0], arg1[0], arg2));
	if (OP_IS_ROUND(alu))
		cgen_one(alu - FP_ALU1_ROUND);
	return true;
}

static bool attr_w cgen_sse_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	g(cgen_sse_insn(ctx, fp_op_size == OP_SIZE_4 ? SSE_PREFIX_F3 : SSE_PREFIX_F2, PREFIX_0F, X86_0F_CVTSI2SS_X128_RM32, int_op_size == OP_SIZE_8, arg1[0], R_XMM7, arg2));
	return true;
}

static bool attr_w cgen_sse_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	g(cgen_sse_insn(ctx, fp_op_size == OP_SIZE_4 ? SSE_PREFIX_F3 : SSE_PREFIX_F2, PREFIX_0F, X86_0F_CVTTSS2SI_X128_RM32, int_op_size == OP_SIZE_8, arg1[0], 0, arg2));
	return true;
}

static bool attr_w cgen_sse_cvt(struct codegen_context *ctx, unsigned from_op_size, unsigned to_op_size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (from_op_size == OP_SIZE_2 && to_op_size == OP_SIZE_4) {
		g(cgen_sse_insn(ctx, SSE_PREFIX_66, PREFIX_0F_38, X86_0F_38_CVTPH2PS_X128_RM64, false, arg1[0], 0, arg2));
		return true;
	} else if (from_op_size == OP_SIZE_4 && to_op_size == OP_SIZE_2) {
		g(cgen_sse_insn(ctx, SSE_PREFIX_66, PREFIX_0F_3A, X86_0F_3A_CVTPS2PH_RM64_X128, false, arg2[0], 0, arg1));
		cgen_one(0x04);
		return true;
	}
	internal(file_line, "cgen_sse_cvt: unsupported arguments %u, %u", from_op_size, to_op_size);
	return false;
}

static bool attr_w cgen_x87_fld(struct codegen_context *ctx, unsigned size)
{
	unsigned c1, c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] >= R_ST0 && arg1[0] <= R_ST7)
		size = OP_SIZE_4;
	switch (size) {
		case OP_SIZE_4:
			c1 = X87_FLD_RM32; c2 = X87_FLD_RM32_X; break;
		case OP_SIZE_8:
			c1 = X87_FLD_M64; c2 = X87_FLD_M64_X; break;
		case OP_SIZE_10:
			c1 = X87_FLD_M80; c2 = X87_FLD_M80_X; break;
		default:
			internal(file_line, "cgen_x87_fld: invalid size %u", size);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, c1, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w cgen_x87_fild(struct codegen_context *ctx, unsigned size)
{
	unsigned c1, c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	switch (size) {
		case OP_SIZE_2:
			c1 = X87_FILD_M16; c2 = X87_FILD_M16_X; break;
		case OP_SIZE_4:
			c1 = X87_FILD_M32; c2 = X87_FILD_M32_X; break;
		case OP_SIZE_8:
			c1 = X87_FILD_M64; c2 = X87_FILD_M64_X; break;
		default:
			internal(file_line, "cgen_x87_fild: invalid size %u", size);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, c1, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w cgen_x87_fstp(struct codegen_context *ctx, unsigned size)
{
	unsigned c1, c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] >= R_ST0 && arg1[0] <= R_ST7)
		size = OP_SIZE_8;
	switch (size) {
		case OP_SIZE_4:
			c1 = X87_FSTP_M32; c2 = X87_FSTP_M32_X; break;
		case OP_SIZE_8:
			c1 = X87_FSTP_RM64; c2 = X87_FSTP_RM64_X; break;
		case OP_SIZE_10:
			c1 = X87_FSTP_M80; c2 = X87_FSTP_M80_X; break;
		default:
			internal(file_line, "cgen_x87_fstp: invalid size %u", size);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, c1, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w cgen_x87_fistp(struct codegen_context *ctx, unsigned size)
{
	unsigned c1, c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	switch (size) {
		case OP_SIZE_2:
			c1 = X87_FISTP_M16; c2 = X87_FISTP_M16_X; break;
		case OP_SIZE_4:
			c1 = X87_FISTP_M32; c2 = X87_FISTP_M32_X; break;
		case OP_SIZE_8:
			c1 = X87_FISTP_M64; c2 = X87_FISTP_M64_X; break;
		default:
			internal(file_line, "cgen_x87_fistp: invalid size %u", size);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, c1, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w cgen_x87_fisttp(struct codegen_context *ctx, unsigned size)
{
	unsigned c1, c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	switch (size) {
		case OP_SIZE_2:
			c1 = X87_FISTTP_M16; c2 = X87_FISTTP_M16_X; break;
		case OP_SIZE_4:
			c1 = X87_FISTTP_M32; c2 = X87_FISTTP_M32_X; break;
		case OP_SIZE_8:
			c1 = X87_FISTTP_M64; c2 = X87_FISTTP_M64_X; break;
		default:
			internal(file_line, "cgen_x87_fisttp: invalid size %u", size);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, c1, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w cgen_x87_fcomp(struct codegen_context *ctx, unsigned size)
{
	unsigned c1, c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] < ARG_REGS_MAX) {
		c1 = X87_FALU_ST_RM32;
	} else switch (size) {
		case OP_SIZE_4:
			c1 = X87_FALU_ST_RM32; break;
		case OP_SIZE_8:
			c1 = X87_FALU_ST_M64; break;
		default:
			internal(file_line, "cgen_x87_fcomp: invalid size %u", size);
	}
	c2 = X87_ALU_FCOMP;
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, c1, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w cgen_x87_alu(struct codegen_context *ctx, unsigned size, unsigned aux)
{
	unsigned c1, c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] < ARG_REGS_MAX) {
		c1 = X87_FALU_ST_RM32;
	} else switch (size) {
		case OP_SIZE_4:
			c1 = X87_FALU_ST_RM32; break;
		case OP_SIZE_8:
			c1 = X87_FALU_ST_M64; break;
		default:
			internal(file_line, "cgen_x87_alu: invalid size %u", size);
	}
	switch (aux) {
		case FP_ALU_ADD:
			c2 = X87_ALU_ADD; break;
		case FP_ALU_SUB:
			c2 = X87_ALU_SUB; break;
		case FP_ALU_MUL:
			c2 = X87_ALU_MUL; break;
		case FP_ALU_DIV:
			c2 = X87_ALU_DIV; break;
		default:
			internal(file_line, "cgen_x87_fst: invalid operation %u", aux);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, c1, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w cgen_x87_alup(struct codegen_context *ctx, unsigned aux)
{
	unsigned c2;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	switch (aux) {
		case FP_ALU_ADD:
			c2 = X87_ALU_ADD; break;
		case FP_ALU_SUB:
			c2 = X87_ALU_SUB; break;
		case FP_ALU_MUL:
			c2 = X87_ALU_MUL; break;
		case FP_ALU_DIV:
			c2 = X87_ALU_DIV; break;
		default:
			internal(file_line, "cgen_x87_fstp: invalid operation %u", aux);
	}
	g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X87_FALUP_STi_ST0, OP_SIZE_4, false, c2, arg1));
	return true;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	int64_t offs = (int64_t)ctx->label_to_pos[reloc->label_id] - (int64_t)(reloc->position + (reloc->length == JMP_SHORT ? 1 : 4));
	switch (reloc->length) {
		case JMP_SHORT: {
			int8_t i8;
			if (!imm_is_8bit(offs))
				return false;
			i8 = offs;
			memcpy(ctx->mcode + reloc->position, &i8, 1);
			return true;
		}
		case JMP_LONG: {
			int32_t i32;
			if (!imm_is_32bit(offs))
				return false;
			i32 = offs;
			memcpy(ctx->mcode + reloc->position, &i32, 4);
			return true;
		}
		default: {
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
			return false;
		}
	}
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	uint8_t imm8;
	uint16_t imm16;
	/*debug("insn: %08x", insn);*/
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			cgen_one(X86_RET);
			return true;
		case INSN_RET_IMM:
			imm16 = cget_two(ctx);
			cgen_one(X86_RET_IMM16);
			cgen_two(imm16);
			return true;
		case INSN_PUSH:
			g(cgen_push(ctx));
			return true;
		case INSN_POP:
			g(cgen_pop(ctx));
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_FF, OP_SIZE_4, false, X86_FF_CALL_INDIRECT, ctx->code_position));
			ctx->code_position += arg_size(*ctx->code_position);
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn)));
			return true;
		case INSN_MOVSX:
			g(cgen_movsx(ctx, insn_op_size(insn)));
			return true;
		case INSN_CMP:
			g(cgen_alu(ctx, insn_op_size(insn), 7, insn_writes_flags(insn)));
			return true;
		case INSN_TEST:
			g(cgen_test(ctx, insn_op_size(insn)));
			return true;
		case INSN_ALU:
		case INSN_ALU_FLAGS:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			if (!insn_writes_flags(insn) && insn_op_size(insn) <= OP_SIZE_8) {
				if (unlikely(insn_aux(insn) != ALU_ADD))
					goto invalid_insn;
				g(cgen_lea(ctx, insn_op_size(insn)));
				return true;
			}
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU_PARTIAL:
		case INSN_ALU_FLAGS_PARTIAL:
			if (unlikely(insn_op_size(insn) >= OP_SIZE_4))
				goto invalid_insn;
			if (!insn_writes_flags(insn)) {
				if (unlikely(insn_aux(insn) != ALU_ADD) || insn_op_size(insn) != OP_SIZE_2)
					goto invalid_insn;
				g(cgen_lea(ctx, insn_op_size(insn)));
				return true;
			}
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU1:
		case INSN_ALU1_FLAGS:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ALU1_PARTIAL:
		case INSN_ALU1_FLAGS_PARTIAL:
			if (unlikely(insn_op_size(insn) >= OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_LEA3:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_lea3(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ROT_PARTIAL:
			if (unlikely(insn_op_size(insn) >= OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_BT:
			if (unlikely(insn_op_size(insn) == OP_SIZE_1) || unlikely(!insn_writes_flags(insn)))
				goto invalid_insn;
			g(cgen_bt(ctx, insn_op_size(insn)));
			return true;
		case INSN_BTX:
			if (unlikely(insn_op_size(insn) == OP_SIZE_1) || unlikely(!insn_writes_flags(insn)))
				goto invalid_insn;
			g(cgen_btx(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_MUL_L:
			g(cgen_mul_l(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_DIV_L:
			g(cgen_div_l(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_CBW:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2))
				goto invalid_insn;
			if (insn_op_size(insn) == OP_SIZE_8)
				cgen_rex(X86_REX | X86_REX_W);
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			cgen_one(X86_CBW);
			return true;
		case INSN_CBW_PARTIAL:
			if (unlikely(insn_op_size(insn) != OP_SIZE_2))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			cgen_one(X86_OP_SIZE);
			cgen_one(X86_CBW);
			return true;
		case INSN_CWD:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_DX))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			if (insn_op_size(insn) == OP_SIZE_8)
				cgen_rex(X86_REX | X86_REX_W);
			cgen_one(X86_CWD);
			return true;
		case INSN_CWD_PARTIAL:
			if (unlikely(insn_op_size(insn) != OP_SIZE_2))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_DX))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_DX))
				goto invalid_insn;
			cgen_one(X86_OP_SIZE);
			cgen_one(X86_CWD);
			return true;
		case INSN_SET_COND:
			if (unlikely(insn_op_size(insn) != OP_SIZE_1))
				goto invalid_insn;
			g(cgen_rm_insn(ctx, -1, PREFIX_0F, X86_0F_SETCC_RM8 + (insn_aux(insn) & 0xf), OP_SIZE_1, false, 0, ctx->code_position));
			ctx->code_position += arg_size(*ctx->code_position);
			return true;
		case INSN_SET_COND_PARTIAL:
			if (unlikely(insn_op_size(insn) != OP_SIZE_1))
				goto invalid_insn;
			g(cgen_rm_insn(ctx, -1, PREFIX_0F, X86_0F_SETCC_RM8 + (insn_aux(insn) & 0xf), OP_SIZE_1, false, 0, ctx->code_position));
			ctx->code_position += arg_size(*ctx->code_position);
			ctx->code_position += arg_size(*ctx->code_position);
			return true;
		case INSN_CMOV:
		case INSN_CMOV_XCC:
			if (unlikely(insn_op_size(insn) == OP_SIZE_1))
				goto invalid_insn;
			g(cgen_cmov(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_MEMCPY:
			g(cgen_memcpy(ctx));
			return true;
		case INSN_MEMSET:
			g(cgen_memset(ctx));
			return true;
		case INSN_FP_CMP:
			g(cgen_sse_cmp(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_ALU:
			g(cgen_sse_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_ALU1:
			g(cgen_sse_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_FROM_INT32:
		case INSN_FP_FROM_INT64:
			g(cgen_sse_from_int(ctx, insn_opcode(insn) == INSN_FP_FROM_INT32 ? OP_SIZE_4 : OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_FP_TO_INT32:
		case INSN_FP_TO_INT64:
			g(cgen_sse_to_int(ctx, insn_opcode(insn) == INSN_FP_TO_INT32 ? OP_SIZE_4 : OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_FP_CVT:
			g(cgen_sse_cvt(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_X87_FLD:
			g(cgen_x87_fld(ctx, insn_op_size(insn)));
			return true;
		case INSN_X87_FILD:
			g(cgen_x87_fild(ctx, insn_op_size(insn)));
			return true;
		case INSN_X87_FSTP:
			g(cgen_x87_fstp(ctx, insn_op_size(insn)));
			return true;
		case INSN_X87_FISTP:
			g(cgen_x87_fistp(ctx, insn_op_size(insn)));
			return true;
		case INSN_X87_FISTTP:
			g(cgen_x87_fisttp(ctx, insn_op_size(insn)));
			return true;
		case INSN_X87_FCOMP:
			g(cgen_x87_fcomp(ctx, insn_op_size(insn)));
			return true;
		case INSN_X87_FCOMPP:
			cgen_one(X87_FCOMPP);
			cgen_one(X87_FCOMPP_2);
			return true;
		case INSN_X87_FCOMIP:
			imm8 = cget_one(ctx);
			cgen_one(X87_FCOMIP);
			cgen_one(X87_FCOMIP_2 + (imm8 & 7));
			return true;
		case INSN_X87_ALU:
			g(cgen_x87_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_X87_ALUP:
			g(cgen_x87_alup(ctx, insn_aux(insn)));
			return true;
		case INSN_X87_FCHS:
			cgen_one(X87_FCHS);
			cgen_one(X87_FCHS_2);
			return true;
		case INSN_X87_FSQRT:
			cgen_one(X87_FSQRT);
			cgen_one(X87_FSQRT_2);
			return true;
		case INSN_X87_FRNDINT:
			cgen_one(X87_FRNDINT);
			cgen_one(X87_FRNDINT_2);
			return true;
		case INSN_X87_FNSTSW:
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			if (unlikely(cget_one(ctx) != R_AX))
				goto invalid_insn;
			cgen_one(X87_FNSTSW);
			cgen_one(X87_FNSTSW_2);
			return true;
		case INSN_X87_FLDCW:
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X87_FLDCW, OP_SIZE_4, false, X87_FLDCW_X, ctx->code_position));
			ctx->code_position += arg_size(*ctx->code_position);
			return true;
		case INSN_JMP:
			if (insn_jump_size(insn) == JMP_SHORT || insn_jump_size(insn) == JMP_SHORTEST) {
				cgen_one(X86_JMP_8);
				g(add_relocation(ctx, JMP_SHORT, 0, NULL));
				cgen_one(0);
			} else if (likely(insn_jump_size(insn) == JMP_LONG)) {
				cgen_one(X86_JMP_16);
				g(add_relocation(ctx, JMP_LONG, 0, NULL));
				cgen_four(0);
			} else {
				goto invalid_insn;
			}
			return true;
		case INSN_JMP_COND:
			if (insn_jump_size(insn) == JMP_SHORT || insn_jump_size(insn) == JMP_SHORTEST) {
				cgen_one(X86_JCC_8 + (insn_aux(insn) & 0xf));
				g(add_relocation(ctx, JMP_SHORT, 0, NULL));
				cgen_one(0);
			} else if (likely(insn_jump_size(insn) == JMP_LONG)) {
				cgen_one(X86_0F);
				cgen_one(X86_0F_JCC_16 + (insn_aux(insn) & 0xf));
				g(add_relocation(ctx, JMP_LONG, 0, NULL));
				cgen_four(0);
			} else {
				goto invalid_insn;
			}
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_rm_insn(ctx, -1, PREFIX_NONE, X86_FF, OP_SIZE_4, false, X86_FF_JMP_INDIRECT, ctx->code_position));
			ctx->code_position += arg_size(*ctx->code_position);
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08lx", (unsigned long)insn);
			return false;
	}
}
