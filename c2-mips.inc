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

#define MIPS_NOP		0x00000000U
#define MIPS_SLL		0x00000000U
#define MIPS_MOVF		0x00000001U
#define MIPS_SRL		0x00000002U
#define MIPS_SRA		0x00000003U
#define MIPS_SLLV		0x00000004U
#define MIPS_SRLV		0x00000006U
#define MIPS_SRAV		0x00000007U
#define MIPS_JR			0x00000008U
#define MIPS_JALR		0x00000009U
#define MIPS_MFHI		0x00000010U
#define MIPS_MFLO		0x00000012U
#define MIPS_DSLLV		0x00000014U
#define MIPS_DSRLV		0x00000016U
#define MIPS_DSRAV		0x00000017U
#define MIPS_MULT		0x00000018U
#define MIPS_MULTU		0x00000019U
#define MIPS_DIV		0x0000001aU
#define MIPS_DIVU		0x0000001bU
#define MIPS_DMULT		0x0000001cU
#define MIPS_DMULTU		0x0000001dU
#define MIPS_DDIV		0x0000001eU
#define MIPS_DDIVU		0x0000001fU
#define MIPS_ADD		0x00000020U
#define MIPS_ADDU		0x00000021U
#define MIPS_SUB		0x00000022U
#define MIPS_SUBU		0x00000023U
#define MIPS_AND		0x00000024U
#define MIPS_OR			0x00000025U
#define MIPS_XOR		0x00000026U
#define MIPS_NOR		0x00000027U
#define MIPS_SLT		0x0000002aU
#define MIPS_SLTU		0x0000002bU
#define MIPS_DADD		0x0000002cU
#define MIPS_DADDU		0x0000002dU
#define MIPS_DSUB		0x0000002eU
#define MIPS_DSUBU		0x0000002fU
#define MIPS_DSLL		0x00000038U
#define MIPS_DSRL		0x0000003aU
#define MIPS_DSRA		0x0000003bU
#define MIPS_DSLL32		0x0000003cU
#define MIPS_DSRL32		0x0000003eU
#define MIPS_DSRA32		0x0000003fU
#define MIPS_ROTRV		0x00000046U
#define MIPS_DROTRV		0x00000056U
#define MIPS_MOVT		0x00010001U
#define MIPS_ROTR		0x00200002U
#define MIPS_DROTR		0x0020003aU
#define MIPS_DROTR32		0x0020003eU
#define MIPS_BLTZ		0x04000000U
#define MIPS_BGEZ		0x04010000U
#define MIPS_BLTZAL		0x04100000U
#define MIPS_BGEZAL		0x04110000U
#define MIPS_J			0x08000000U
#define MIPS_BEQ		0x10000000U
#define MIPS_BNE		0x14000000U
#define MIPS_BLEZ		0x18000000U
#define MIPS_BGTZ		0x1c000000U
#define MIPS_ADDI		0x20000000U
#define MIPS_ADDIU		0x24000000U
#define MIPS_SLTI		0x28000000U
#define MIPS_SLTIU		0x2c000000U
#define MIPS_ANDI		0x30000000U
#define MIPS_ORI		0x34000000U
#define MIPS_XORI		0x38000000U
#define MIPS_LUI		0x3c000000U
#define MIPS_MFC1		0x44000000U
#define MIPS_DMFC1		0x44200000U
#define MIPS_MTC1		0x44800000U
#define MIPS_DMTC1		0x44a00000U
#define MIPS_BC1F		0x45000000U
#define MIPS_BC1T		0x45010000U
#define MIPS_ADD_FP		0x46000000U
#define MIPS_SUB_FP		0x46000001U
#define MIPS_MUL_FP		0x46000002U
#define MIPS_DIV_FP		0x46000003U
#define MIPS_SQRT_FP		0x46000004U
#define MIPS_MOV_FP		0x46000006U
#define MIPS_NEG_FP		0x46000007U
#define MIPS_TRUNC_L		0x46000009U
#define MIPS_TRUNC_W		0x4600000dU
#define MIPS_C_F		0x46000030U
#define MIPS_C_UN		0x46000031U
#define MIPS_C_EQ		0x46000032U
#define MIPS_C_UEQ		0x46000033U
#define MIPS_C_OLT		0x46000034U
#define MIPS_C_ULT		0x46000035U
#define MIPS_C_OLE		0x46000036U
#define MIPS_C_ULE		0x46000037U
#define MIPS_FP_SINGLE			0x00U
#define MIPS_FP_DOUBLE			0x01U
#define MIPS_CVT_S_W		0x46800020U
#define MIPS_CVT_D_W		0x46800021U
#define MIPS_CVT_S_L		0x46a00020U
#define MIPS_CVT_D_L		0x46a00021U
#define MIPS_DADDI		0x60000000U
#define MIPS_DADDIU		0x64000000U
#define MIPS_LDL		0x68000000U
#define MIPS_LDR		0x6c000000U
#define MIPS_MUL		0x70000002U
#define MIPS_CLZ		0x70000020U
#define MIPS_DCLZ		0x70000024U
#define MIPS_WSBH		0x7c0000a0U
#define MIPS_DSBH		0x7c0000a4U
#define MIPS_DSHD		0x7c000164U
#define MIPS_SEB		0x7c000420U
#define MIPS_SEH		0x7c000620U
#define MIPS_LB			0x80000000U
#define MIPS_LH			0x84000000U
#define MIPS_LWL		0x88000000U
#define MIPS_LW			0x8c000000U
#define MIPS_LBU		0x90000000U
#define MIPS_LHU		0x94000000U
#define MIPS_LWR		0x98000000U
#define MIPS_LWU		0x9c000000U
#define MIPS_SB			0xa0000000U
#define MIPS_SH			0xa4000000U
#define MIPS_SWL		0xa8000000U
#define MIPS_SW			0xac000000U
#define MIPS_SDL		0xb0000000U
#define MIPS_SDR		0xb4000000U
#define MIPS_SWR		0xb8000000U
#define MIPS_LWC1		0xc4000000U
#define MIPS_LDC1		0xd4000000U
#define MIPS_LD			0xdc000000U
#define MIPS_SWC1		0xe4000000U
#define MIPS_SDC1		0xf4000000U
#define MIPS_SD			0xfc000000U

#define MIPS_R6_LSA		0x00000005U
#define MIPS_R6_JALR		0x00000009U
#define MIPS_R6_DLSA		0x00000015U
#define MIPS_R6_CLZ		0x00000050U
#define MIPS_R6_DCLZ		0x00000052U
#define MIPS_R6_MUL		0x00000098U
#define MIPS_R6_MULU		0x00000099U
#define MIPS_R6_DIV		0x0000009aU
#define MIPS_R6_DIVU		0x0000009bU
#define MIPS_R6_DMUL		0x0000009cU
#define MIPS_R6_DMULU		0x0000009dU
#define MIPS_R6_DDIV		0x0000009eU
#define MIPS_R6_DDIVU		0x0000009fU
#define MIPS_R6_MUH		0x000000d8U
#define MIPS_R6_MUHU		0x000000d9U
#define MIPS_R6_MOD		0x000000daU
#define MIPS_R6_MODU		0x000000dbU
#define MIPS_R6_DMUH		0x000000dcU
#define MIPS_R6_DMUHU		0x000000ddU
#define MIPS_R6_DMOD		0x000000deU
#define MIPS_R6_DMODU		0x000000dfU
#define MIPS_R6_DAHI		0x04060000U
#define MIPS_R6_DATI		0x041e0000U
#define MIPS_R6_BGEUC		0x18000000U
#define MIPS_R6_BLTUC		0x1c000000U
#define MIPS_R6_AUI		0x3c000000U
#define MIPS_R6_BC1EQZ		0x45200000U
#define MIPS_R6_BC1NEZ		0x45a00000U
#define MIPS_R6_CMP_AF		0x46800000U
#define MIPS_R6_CMP_UN		0x46800001U
#define MIPS_R6_CMP_EQ		0x46800002U
#define MIPS_R6_CMP_UEQ		0x46800003U
#define MIPS_R6_CMP_LT		0x46800004U
#define MIPS_R6_CMP_ULT		0x46800005U
#define MIPS_R6_CMP_LE		0x46800006U
#define MIPS_R6_CMP_ULE		0x46800007U
#define MIPS_R6_CMP_OR		0x46800011U
#define MIPS_R6_CMP_UNE		0x46800012U
#define MIPS_R6_CMP_NE		0x46800013U
#define MIPS_R6_BGEC		0x58000000U
#define MIPS_R6_BLTC		0x5c000000U
#define MIPS_R6_DAUI		0x74000000U
#define MIPS_R6_BITSWAP		0x7c000020U
#define MIPS_R6_DBITSWAP	0x7c000024U
#define MIPS_R6_BC		0xc8000000U
#define MIPS_R6_JIC		0xd8000000U
#define MIPS_R6_BEQZC		0xd8000000U
#define MIPS_R6_JIALC		0xf8000000U
#define MIPS_R6_BNEZC		0xf8000000U
#define MIPS_R6_BLTC		0x5c000000U
#define MIPS_R6_BGEC		0x58000000U

#define cgen_mips_3reg(mc, rd, rs, rt) \
	cgen_four((mc) | ((uint32_t)(rd) << 11) | ((uint32_t)(rs) << 21) | ((uint32_t)(rt) << 16))
#define cgen_mips_rot_imm(mc, rd, rt, sa) \
	cgen_four((mc) | ((uint32_t)(rd) << 11) | ((uint32_t)(rt) << 16) | (((sa) & 0x1f) << 6))
#define cgen_mips_imm(mc, rt, rs, imm) \
	cgen_four((mc) | ((uint32_t)(rt) << 16) | ((uint32_t)(rs) << 21) | ((imm) & 0xffff))
#define cgen_mips_fp(mc, fmt, fd, fs, ft) \
	cgen_four((mc) | ((uint32_t)(fmt) << 21) | ((uint32_t)(fd) << 6) | ((uint32_t)(fs) << 11) | ((uint32_t)(ft) << 16))

static bool attr_w cgen_jump_not_last(struct codegen_context *ctx, unsigned insns)
{
	if (MIPS_R4000_ERRATA) {
		while (unlikely((ctx->mcode_size & 0xfffU) + insns * 4 >= 0x1000U)) {
			cgen_four(MIPS_NOP);
		}
	}
	return true;
}

static bool attr_w cgen_ls(struct codegen_context *ctx, uint32_t mc, uint8_t arg1, uint8_t *arg2)
{
	int64_t imm = get_imm(&arg2[2]);
	if (unlikely(imm != (int16_t)imm))
		internal(file_line, "cgen_ls: invalid imm: %"PRIxMAX"", (uintmax_t)imm);
	cgen_mips_imm(mc, arg1, arg2[1], imm);
	return true;
}

static uint32_t cgen_fp_fmt(unsigned op_size)
{
	switch (op_size) {
		case OP_SIZE_4:		return MIPS_FP_SINGLE;
		case OP_SIZE_8:		return MIPS_FP_DOUBLE;
		default:		internal(file_line, "cgen_fp_fmt: invalid size %u", op_size);
					return -1U;
	}
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size, bool sx)
{
	int64_t imm;
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] < 32) {
		if (arg2[0] < 32) {
			if (sx && size == OP_SIZE_1) {
				cgen_mips_3reg(MIPS_SEB, arg1[0], 0, arg2[0]);
				return true;
			}
			if (sx && size == OP_SIZE_2) {
				cgen_mips_3reg(MIPS_SEH, arg1[0], 0, arg2[0]);
				return true;
			}
			if (unlikely(size != OP_SIZE_NATIVE))
				internal(file_line, "cgen_mov: unsupported size %u", size);
			cgen_mips_3reg(MIPS_OR, arg1[0], arg2[0], R_ZERO);
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			uint32_t fmt = cgen_fp_fmt(size);
			cgen_mips_fp(MIPS_MFC1, fmt, 0, arg2[0] & 31, arg1[0]);
			return true;
		}
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (unlikely((imm & 0xffff) != 0) || unlikely(imm != (int32_t)imm))
				internal(file_line, "cgen_mov: invalid imm: %"PRIxMAX"", (uintmax_t)imm);
			cgen_mips_imm(MIPS_LUI, arg1[0], 0, (uint64_t)imm >> 16);
			return true;
		}
		if (arg2[0] == ARG_ADDRESS_1) {
			if (!sx && size != OP_SIZE_NATIVE)
				g(cgen_ls(ctx, size == OP_SIZE_1 ? MIPS_LBU : size == OP_SIZE_2 ? MIPS_LHU : MIPS_LWU, arg1[0], arg2));
			else
				g(cgen_ls(ctx, size == OP_SIZE_1 ? MIPS_LB : size == OP_SIZE_2 ? MIPS_LH : size == OP_SIZE_4 ? MIPS_LW : MIPS_LD, arg1[0], arg2));
			if (MIPS_LOAD_DELAY_SLOTS)
				cgen_four(MIPS_NOP);
			return true;
		}
		goto invalid;
	}
	if (reg_is_fp(arg1[0])) {
		if (arg2[0] < 32) {
			uint32_t fmt = cgen_fp_fmt(size);
			cgen_mips_fp(MIPS_MTC1, fmt, 0, arg1[0] & 31, arg2[0]);
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			uint32_t fmt = cgen_fp_fmt(size);
			uint32_t mc = MIPS_MOV_FP;
			cgen_mips_fp(mc, fmt, arg1[0] & 31, arg2[0] & 31, 0);
			return true;
		}
		g(cgen_ls(ctx, size == OP_SIZE_4 ? MIPS_LWC1 : MIPS_LDC1, arg1[0] & 31, arg2));
		if (MIPS_LOAD_DELAY_SLOTS)
			cgen_four(MIPS_NOP);
		return true;
	}
	if (arg1[0] == ARG_ADDRESS_1) {
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (unlikely(imm != 0))
				goto invalid;
			arg2 = &z;
		}
		if (arg2[0] < 32) {
			return cgen_ls(ctx, size == OP_SIZE_1 ? MIPS_SB : size == OP_SIZE_2 ? MIPS_SH : size == OP_SIZE_4 ? MIPS_SW : MIPS_SD, arg2[0], arg1);
		}
		if (reg_is_fp(arg2[0])) {
			return cgen_ls(ctx, size == OP_SIZE_4 ? MIPS_SWC1 : MIPS_SDC1, arg2[0] & 31, arg1);
		}
		goto invalid;
	}

invalid:
	internal(file_line, "cgen_mov: invalid arguments %02x, %02x, %u, %u", arg1[0], arg2[0], size, (unsigned)sx);
	return false;
}

static bool attr_w cgen_mov_lr(struct codegen_context *ctx, unsigned size, bool r)
{
	int64_t imm;
	uint32_t mc;
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(arg1[0] != arg2[0]))
		goto invalid;

	if (arg1[0] < 32 && arg3[0] == ARG_ADDRESS_1) {
		imm = get_imm(&arg3[2]);
		if (!r)
			mc = size == OP_SIZE_4 ? MIPS_LWL : MIPS_LDL;
		else
			mc = size == OP_SIZE_4 ? MIPS_LWR : MIPS_LDR;
		cgen_mips_imm(mc, arg1[0], arg3[1], imm);
		if (MIPS_LOAD_DELAY_SLOTS)
			cgen_four(MIPS_NOP);
		return true;
	} if (arg1[0] == ARG_ADDRESS_1 && arg3[0] < 32) {
		imm = get_imm(&arg1[2]);
		if (!r)
			mc = size == OP_SIZE_4 ? MIPS_SWL : MIPS_SDL;
		else
			mc = size == OP_SIZE_4 ? MIPS_SWR : MIPS_SDR;
		cgen_mips_imm(mc, arg3[0], arg1[1], imm);
		return true;
	}

invalid:
	internal(file_line, "cgen_mov_lr: invalid parameters %02x, %02x, %02x", arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_cmp_dest_reg(struct codegen_context *ctx, unsigned aux)
{
	uint32_t mc;
	bool swap = false;
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		if (unlikely(imm != (int16_t)imm))
			internal(file_line, "cgen_cmp_dest_reg: invalid imm value %"PRIxMAX"", (intmax_t)imm);
		switch (aux) {
			case COND_B:	mc = MIPS_SLTIU; break;
			case COND_L:	mc = MIPS_SLTI; break;
			default:	goto invalid;
		}
		cgen_mips_imm(mc, arg1[0], arg2[0], imm);
		return true;
	}
	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		if (unlikely(imm != 0))
			internal(file_line, "cgen_cmp_dest_reg: non-zero second argument");
		arg2 = &z;
	}
	switch (aux) {
		case COND_B:	mc = MIPS_SLTU; break;
		case COND_A:	mc = MIPS_SLTU; swap = true; break;
		case COND_L:	mc = MIPS_SLT; break;
		case COND_G:	mc = MIPS_SLT; swap = true; break;
		default:	goto invalid;
	}
	if (swap) {
		uint8_t *argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}
	cgen_mips_3reg(mc, arg1[0], arg2[0], arg3[0]);
	return true;

invalid:
	internal(file_line, "cgen_cmp_dest_reg: invalid arguments %u, %02x, %02x, %02x", aux, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned alu, bool trap)
{
	uint32_t mc;
	int64_t imm = 0;
	bool have_imm_trap = !MIPS_R6 && !(size == OP_SIZE_8 && MIPS_R4000_ERRATA); /* R4000 has broken DADDI */
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (alu == ALU_ADD && arg2[0] == ARG_SHIFTED_REGISTER) {
		uint8_t *arg_swp = arg3;
		arg3 = arg2;
		arg2 = arg_swp;
	}
	if (alu == ALU_ADD && arg3[0] == ARG_SHIFTED_REGISTER) {
		uint32_t shift;
		if (unlikely((arg3[1] & ARG_SHIFT_MODE) != ARG_SHIFT_LSL))
			goto invalid;
		shift = arg3[1] & ARG_SHIFT_AMOUNT;
		if (unlikely(shift < 1) || unlikely(shift > 4))
			goto invalid;
		mc = size == OP_SIZE_8 ? MIPS_R6_DLSA : MIPS_R6_LSA;
		mc |= (shift - 1) << 6;
		cgen_mips_3reg(mc, arg1[0], arg3[2], arg2[0]);
		return true;
	}

	if ((alu == ALU_ADD || alu == ALU_SUB) && arg3[0] == ARG_IMM && trap && !have_imm_trap) {
		imm = get_imm(&arg3[1]);
		cgen_mips_imm(MIPS_ADDIU, R_AT, R_ZERO, imm);
		g(cgen_trap(ctx, cget_four(ctx)));
		if (alu == ALU_ADD)
			mc = size == OP_SIZE_8 ? MIPS_DADD : MIPS_ADD;
		else
			mc = size == OP_SIZE_8 ? MIPS_DSUB : MIPS_SUB;
		cgen_mips_3reg(mc, arg1[0], arg2[0], R_AT);
		return true;
	}
	if (MIPS_R6 && alu == ALU_ADD && arg3[0] == ARG_IMM && !trap) {
		imm = get_imm(&arg3[1]);
		if (imm && !(imm & 0xffff)) {
			if (imm == (int32_t)imm) {
				cgen_mips_imm(size == OP_SIZE_4 ? MIPS_R6_AUI : MIPS_R6_DAUI, arg1[0], arg2[0], (uint64_t)imm >> 16);
				return true;
			}
			if (imm & 0xFFFFFFFFLL)
				goto invalid;
			imm /= 0x100000000LL;
			if (imm == (int16_t)imm && size == OP_SIZE_8) {
				if (unlikely(arg1[0] != arg2[0]))
					goto invalid;
				cgen_mips_imm(MIPS_R6_DAHI, 0, arg1[0], imm);
				return true;
			}
			if (imm & 0xFFFFLL)
				goto invalid;
			imm /= 0x10000LL;
			if (size == OP_SIZE_8) {
				if (unlikely(arg1[0] != arg2[0]))
					goto invalid;
				cgen_mips_imm(MIPS_R6_DATI, 0, arg1[0], imm);
				return true;
			}
			goto invalid;
		}
	}

	if (trap)
		g(cgen_trap(ctx, cget_four(ctx)));

	switch (alu) {
		case ALU_MUL:
			if (MIPS_R6) {
				cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_R6_MUL : MIPS_R6_DMUL, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			if (size == OP_SIZE_4 && MIPS_HAS_MUL) {
				cgen_mips_3reg(MIPS_MUL, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_MULTU : MIPS_DMULTU, 0, arg2[0], arg3[0]);
			cgen_mips_3reg(MIPS_MFLO, arg1[0], 0, 0);
			return true;
		case ALU_UMULH:
			if (MIPS_R6) {
				cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_R6_MUHU : MIPS_R6_DMUHU, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_MULTU : MIPS_DMULTU, 0, arg2[0], arg3[0]);
			cgen_mips_3reg(MIPS_MFHI, arg1[0], 0, 0);
			return true;
		case ALU_SMULH:
			if (MIPS_R6) {
				cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_R6_MUH : MIPS_R6_DMUH, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_MULT : MIPS_DMULT, 0, arg2[0], arg3[0]);
			cgen_mips_3reg(MIPS_MFHI, arg1[0], 0, 0);
			return true;
		case ALU_UDIV:
			if (MIPS_R6) {
				cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_R6_DIVU : MIPS_R6_DDIVU, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			g(cgen_jump_not_last(ctx, 1));
			cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_DIVU : MIPS_DDIVU, 0, arg2[0], arg3[0]);
			cgen_mips_3reg(MIPS_MFLO, arg1[0], 0, 0);
			return true;
		case ALU_SDIV:
			if (MIPS_R6) {
				cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_R6_DIV : MIPS_R6_DDIV, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			g(cgen_jump_not_last(ctx, 1));
			cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_DIV : MIPS_DDIV, 0, arg2[0], arg3[0]);
			cgen_mips_3reg(MIPS_MFLO, arg1[0], 0, 0);
			return true;
		case ALU_UREM:
			if (MIPS_R6) {
				cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_R6_MODU : MIPS_R6_DMODU, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			g(cgen_jump_not_last(ctx, 1));
			cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_DIVU : MIPS_DDIVU, 0, arg2[0], arg3[0]);
			cgen_mips_3reg(MIPS_MFHI, arg1[0], 0, 0);
			return true;
		case ALU_SREM:
			if (MIPS_R6) {
				cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_R6_MOD : MIPS_R6_DMOD, arg1[0], arg2[0], arg3[0]);
				return true;
			}
			g(cgen_jump_not_last(ctx, 1));
			cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_DIV : MIPS_DDIV, 0, arg2[0], arg3[0]);
			cgen_mips_3reg(MIPS_MFHI, arg1[0], 0, 0);
			return true;
	}

	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (alu == ALU_SUB) {
			imm = -(uint64_t)imm;
			alu = ALU_ADD;
		}
		switch (alu) {
			case ALU_ADD:	if (trap) mc = size == OP_SIZE_8 ? MIPS_DADDI : MIPS_ADDI;
					else mc = size == OP_SIZE_8 ? MIPS_DADDIU : MIPS_ADDIU;
					break;
			case ALU_XOR:	mc = MIPS_XORI; break;
			case ALU_OR:	mc = MIPS_ORI; break;
			case ALU_AND:	mc = MIPS_ANDI; break;
			default:	goto invalid;
		}
		if (unlikely(imm != (alu == ALU_ADD ? (int64_t)(int16_t)imm : (int64_t)(uint16_t)imm)))
			internal(file_line, "cgen_alu: invalid imm: %"PRIxMAX" (%u)", (uintmax_t)imm, alu);
		cgen_mips_imm(mc, arg1[0], arg2[0], imm);
		return true;
	}

	switch (alu) {
		case ALU_ADD:	if (trap) mc = size == OP_SIZE_8 ? MIPS_DADD : MIPS_ADD;
				else mc = size == OP_SIZE_8 ? MIPS_DADDU : MIPS_ADDU;
				break;
		case ALU_SUB:	if (trap) mc = size == OP_SIZE_8 ? MIPS_DSUB : MIPS_SUB;
				else mc = size == OP_SIZE_8 ? MIPS_DSUBU : MIPS_SUBU;
				break;
		case ALU_XOR:	mc = MIPS_XOR; break;
		case ALU_OR:	mc = MIPS_OR; break;
		case ALU_AND:	mc = MIPS_AND; break;
		default:	goto invalid;
	}
	cgen_mips_3reg(mc, arg1[0], arg2[0], arg3[0]);
	return true;

invalid:
	internal(file_line, "cgen_alu: invalid alu %u, %u, %"PRIxMAX"", size, alu, (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu, bool trap)
{
	bool have_imm_trap = !MIPS_R6 && !(size == OP_SIZE_8 && MIPS_R4000_ERRATA); /* R4000 has broken DADDI */
	int cnst = alu == ALU1_INC ? 1 : alu == ALU1_DEC ? -1 : 0;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (cnst && trap && !have_imm_trap) {
		cgen_mips_imm(MIPS_ADDIU, R_AT, R_ZERO, cnst);
		g(cgen_trap(ctx, cget_four(ctx)));
		cgen_mips_3reg(size == OP_SIZE_8 ? MIPS_DADD : MIPS_ADD, arg1[0], arg2[0], R_AT);
		return true;
	}
	if (MIPS_R4000_ERRATA && cnst && !trap && size == OP_SIZE_8) {	/* R4000 has broken DADDIU */
		cgen_mips_imm(MIPS_ADDIU, R_AT, R_ZERO, cnst);
		cgen_mips_3reg(size == OP_SIZE_8 ? MIPS_DADDU : MIPS_ADDU, arg1[0], arg2[0], R_AT);
		return true;
	}

	if (trap)
		g(cgen_trap(ctx, cget_four(ctx)));

	switch (alu) {
		case ALU1_NOT:	cgen_mips_3reg(MIPS_NOR, arg1[0], R_ZERO, arg2[0]);
				return true;
		case ALU1_NEG:	if (trap) cgen_mips_3reg(size == OP_SIZE_8 ? MIPS_DSUB : MIPS_SUB, arg1[0], R_ZERO, arg2[0]);
				else cgen_mips_3reg(size == OP_SIZE_8 ? MIPS_DSUBU : MIPS_SUBU, arg1[0], R_ZERO, arg2[0]);
				return true;
		case ALU1_INC:
		case ALU1_DEC:	if (trap) cgen_mips_imm(size == OP_SIZE_8 ? MIPS_DADDI : MIPS_ADDI, arg1[0], arg2[0], cnst);
				else cgen_mips_imm(size == OP_SIZE_8 ? MIPS_DADDIU : MIPS_ADDIU, arg1[0], arg2[0], cnst);
				return true;
		case ALU1_LZCNT: if (!MIPS_R6)
					cgen_mips_3reg(size == OP_SIZE_8 ? MIPS_DCLZ : MIPS_CLZ, arg1[0], arg2[0], arg1[0]);
				else
					cgen_mips_3reg(size == OP_SIZE_8 ? MIPS_R6_DCLZ : MIPS_R6_CLZ, arg1[0], arg2[0], 0);
				return true;
		case ALU1_BSWAP:
		bswap:		if (size == OP_SIZE_4) {
					cgen_mips_3reg(MIPS_WSBH, arg1[0], 0, arg2[0]);
					cgen_mips_rot_imm(MIPS_ROTR, arg1[0], arg1[0], 16);
				} else {
					cgen_mips_3reg(MIPS_DSBH, arg1[0], 0, arg2[0]);
					cgen_mips_3reg(MIPS_DSHD, arg1[0], 0, arg1[0]);
				}
				return true;
		case ALU1_BSWAP16:if (size == OP_SIZE_4) {
					cgen_mips_3reg(MIPS_WSBH, arg1[0], 0, arg2[0]);
				} else {
					cgen_mips_3reg(MIPS_DSBH, arg1[0], 0, arg2[0]);
				}
				return true;
		case ALU1_BREV:	cgen_mips_3reg(size == OP_SIZE_8 ? MIPS_R6_DBITSWAP : MIPS_R6_BITSWAP, arg1[0], 0, arg2[0]);
				arg2 = arg1;
				goto bswap;
		default:	goto invalid;
	}

invalid:
	internal(file_line, "cgen_alu1: invalid alu %u, %u", size, alu);
	return false;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		switch (alu) {
			case ROT_SHL:   mc = size == OP_SIZE_4 ? MIPS_SLL : imm & 0x20 ? MIPS_DSLL32 : MIPS_DSLL; break;
			case ROT_SHR:   mc = size == OP_SIZE_4 ? MIPS_SRL : imm & 0x20 ? MIPS_DSRL32 : MIPS_DSRL; break;
			case ROT_SAR:   mc = size == OP_SIZE_4 ? MIPS_SRA : imm & 0x20 ? MIPS_DSRA32 : MIPS_DSRA; break;
			case ROT_ROR:	mc = size == OP_SIZE_4 ? MIPS_ROTR : imm & 0x20 ? MIPS_DROTR32 : MIPS_DROTR; break;
			default:	goto invalid;
		}
		cgen_mips_rot_imm(mc, arg1[0], arg2[0], imm);
		return true;
	} else {
		switch (alu) {
			case ROT_SHL:	mc = size == OP_SIZE_4 ? MIPS_SLLV : MIPS_DSLLV; break;
			case ROT_SHR:	mc = size == OP_SIZE_4 ? MIPS_SRLV : MIPS_DSRLV; break;
			case ROT_SAR:	mc = size == OP_SIZE_4 ? MIPS_SRAV : MIPS_DSRAV; break;
			case ROT_ROR:	mc = size == OP_SIZE_4 ? MIPS_ROTRV : MIPS_DROTRV; break;
			default:	goto invalid;
		}
		cgen_mips_3reg(mc, arg1[0], arg3[0], arg2[0]);
		return true;
	}

invalid:
	internal(file_line, "cgen_rot: invalid rotation %u, %u", size, alu);
	return false;
}

static bool attr_w cgen_mul_l(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1, *arg2, *arg3, *arg4;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);

	cgen_mips_3reg(size == OP_SIZE_4 ? MIPS_MULT : MIPS_DMULT, 0, arg3[0], arg4[0]);
	cgen_mips_3reg(MIPS_MFLO, arg1[0], 0, 0);
	cgen_mips_3reg(MIPS_MFHI, arg2[0], 0, 0);

	return true;
}

static bool fp_condition_negated(unsigned aux)
{
	switch (aux) {
		case FP_COND_P:		return false;
		case FP_COND_E:		return false;
		case FP_COND_B:		return false;
		case FP_COND_BE:	return false;
		case FP_COND_NP:	return true;
		case FP_COND_NE:	return true;
		case FP_COND_AE:	return true;
		case FP_COND_A:		return true;
		default:		internal(file_line, "fp_condition_negated: invalid condition %u", aux);
	}
	return false;
}

static bool attr_w cgen_fp_cmp_cond(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc, fmt;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (MIPS_R6) {
		switch (aux) {
			case FP_COND_P:		mc = MIPS_R6_CMP_UN; break;
			case FP_COND_E:		mc = MIPS_R6_CMP_EQ; break;
			case FP_COND_B:		mc = MIPS_R6_CMP_LT; break;
			case FP_COND_BE:	mc = MIPS_R6_CMP_LE; break;
			case FP_COND_NP:	mc = MIPS_R6_CMP_UN; break;
			case FP_COND_NE:	mc = MIPS_R6_CMP_EQ; break;
			case FP_COND_AE:	mc = MIPS_R6_CMP_LT; break;
			case FP_COND_A:		mc = MIPS_R6_CMP_LE; break;
			default:		internal(file_line, "cgen_fp_cmp_cond: invalid condition %u", aux);
						return false;
		}
	} else {
		switch (aux) {
			case FP_COND_P:		mc = MIPS_C_UN; break;
			case FP_COND_E:		mc = MIPS_C_EQ; break;
			case FP_COND_B:		mc = MIPS_C_OLT; break;
			case FP_COND_BE:	mc = MIPS_C_OLE; break;
			case FP_COND_NP:	mc = MIPS_C_UN; break;
			case FP_COND_NE:	mc = MIPS_C_EQ; break;
			case FP_COND_AE:	mc = MIPS_C_OLT; break;
			case FP_COND_A:		mc = MIPS_C_OLE; break;
			default:		internal(file_line, "cgen_fp_cmp_cond: invalid condition %u", aux);
						return false;
		}
	}
	fmt = cgen_fp_fmt(op_size);
	cgen_mips_fp(mc, fmt, MIPS_R6 ? FR_CMP_RESULT & 31 : 0, arg1[0] & 31, arg2[0] & 31);
	if (MIPS_FCMP_DELAY_SLOTS)
		cgen_four(MIPS_NOP);
	return true;
}

static bool attr_w cgen_fp_test_reg(struct codegen_context *ctx, unsigned aux)
{
	unsigned reg = cget_one(ctx);
	if (MIPS_R6) {
		cgen_mips_fp(MIPS_MFC1, MIPS_FP_SINGLE, 0, FR_CMP_RESULT & 31, reg);
		if (OP_SIZE_NATIVE > OP_SIZE_4) {
			cgen_mips_rot_imm(MIPS_SLL, reg, reg, 0);
		}
		if (!fp_condition_negated(aux)) {
			cgen_mips_3reg(OP_SIZE_NATIVE == OP_SIZE_8 ? MIPS_DSUBU : MIPS_SUBU, reg, R_ZERO, reg);
		} else {
			cgen_mips_imm(OP_SIZE_NATIVE == OP_SIZE_8 ? MIPS_DADDIU : MIPS_ADDIU, reg, reg, 1);
		}
		return true;
	} else if (MIPS_HAS_MOVT) {
		cgen_mips_imm(MIPS_ORI, reg, R_ZERO, 1);
		cgen_mips_3reg(!fp_condition_negated(aux) ? MIPS_MOVF : MIPS_MOVT, reg, R_ZERO, 0);
	} else {
		g(cgen_jump_not_last(ctx, 1));
		cgen_mips_imm(!fp_condition_negated(aux) ? MIPS_BC1T : MIPS_BC1F, 0, 0, 2);
		cgen_mips_imm(MIPS_ORI, reg, R_ZERO, 1);
		cgen_mips_3reg(MIPS_OR, reg, R_ZERO, R_ZERO);
	}
	return true;
}

static bool attr_w cgen_fp_alu(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc, fmt;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (aux) {
		case FP_ALU_ADD:	mc = MIPS_ADD_FP; break;
		case FP_ALU_SUB:	mc = MIPS_SUB_FP; break;
		case FP_ALU_MUL:	mc = MIPS_MUL_FP; break;
		case FP_ALU_DIV:	mc = MIPS_DIV_FP; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	fmt = cgen_fp_fmt(op_size);
	cgen_mips_fp(mc, fmt, arg1[0] & 31, arg2[0] & 31, arg3[0] & 31);
	return true;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc, fmt;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	mc = MIPS_NEG_FP; break;
		case FP_ALU1_SQRT:	mc = MIPS_SQRT_FP; break;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	fmt = cgen_fp_fmt(op_size);
	cgen_mips_fp(mc, fmt, arg1[0] & 31, arg2[0] & 31, 0);
	return true;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc, fmt;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (int_op_size) {
		case OP_SIZE_4:		mc = MIPS_TRUNC_W; break;
		case OP_SIZE_8:		mc = MIPS_TRUNC_L; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid int size %u", int_op_size);
	}
	fmt = cgen_fp_fmt(fp_op_size);
	cgen_mips_fp(mc, fmt, arg1[0] & 31, arg2[0] & 31, 0);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (int_op_size == OP_SIZE_4) {
		if (fp_op_size == OP_SIZE_4)
			mc = MIPS_CVT_S_W;
		else
			mc = MIPS_CVT_D_W;
	} else {
		if (fp_op_size == OP_SIZE_4)
			mc = MIPS_CVT_S_L;
		else
			mc = MIPS_CVT_D_L;
	}
	cgen_mips_fp(mc, 0, arg1[0] & 31, arg2[0] & 31, 0);
	return true;
}

static unsigned cgen_jmp_extra_long_length(void)
{
	return !MIPS_R6 ? 6 : 5;
}

static bool attr_w cgen_jmp_extra_long(struct codegen_context *ctx)
{
	cgen_mips_imm(MIPS_LUI, R_AT, 0, 0);
	cgen_mips_imm(MIPS_BGEZAL, 0, R_ZERO, 1);
	cgen_mips_imm(MIPS_ORI, R_AT, R_AT, 0);
	cgen_mips_3reg(OP_SIZE_ADDRESS == OP_SIZE_8 ? MIPS_DADDU : MIPS_ADDU, R_AT, R_AT, R_RA);
	if (!MIPS_R6) {
		cgen_mips_3reg(MIPS_JR, 0, R_AT, 0);
		cgen_four(MIPS_NOP);
	} else {
		cgen_mips_imm(MIPS_R6_JIC, R_AT, 0, 0);
	}
	return true;
}

static bool attr_w cgen_jmp(struct codegen_context *ctx, unsigned length)
{
	if (MIPS_R6 && length <= JMP_LONG) {
		g(cgen_jump_not_last(ctx, 1));
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_four(MIPS_R6_BC);
		return true;
	}
	if (length == JMP_SHORTEST) {
		g(cgen_jump_not_last(ctx, 1));
		g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
		cgen_mips_imm(MIPS_BEQ, R_ZERO, R_ZERO, 0);
		cgen_four(MIPS_NOP);
		return true;
	}
	g(cgen_jump_not_last(ctx, cgen_jmp_extra_long_length()));
	g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
	g(cgen_jmp_extra_long(ctx));
	return true;
}

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);

	if (arg1[0] >= 0x20)
		goto invalid;

	if (MIPS_R6 && (cond == COND_E || cond == COND_NE) && length <= JMP_SHORT) {
		mc = cond == COND_E ? MIPS_R6_BEQZC : MIPS_R6_BNEZC;
		g(cgen_jump_not_last(ctx, 1));
		g(add_relocation(ctx, JMP_SHORT, 1, NULL));
		cgen_four(mc | ((uint32_t)arg1[0] << 21));
		cgen_four(MIPS_NOP);
		return true;
	}

	if (length > JMP_SHORTEST)
		cond ^= 1;

	switch (cond) {
		case COND_E:	mc = MIPS_BEQ; break;
		case COND_NE:	mc = MIPS_BNE; break;
		case COND_S:
		case COND_L:	mc = MIPS_BLTZ; break;
		case COND_LE:	mc = MIPS_BLEZ; break;
		case COND_G:	mc = MIPS_BGTZ; break;
		case COND_NS:
		case COND_GE:	mc = MIPS_BGEZ; break;
		default:	goto invalid;
	}

	if (length == JMP_SHORTEST) {
		g(cgen_jump_not_last(ctx, 1));
		g(add_relocation(ctx, JMP_SHORTEST, 1, NULL));
		cgen_mips_imm(mc, 0, arg1[0], 0);
		cgen_four(MIPS_NOP);
		return true;
	}
	if (MIPS_R6 && length <= JMP_LONG) {
		g(cgen_jump_not_last(ctx, 3));
		cgen_mips_imm(mc, 0, arg1[0], 2);
		cgen_four(MIPS_NOP);
		g(add_relocation(ctx, JMP_LONG, 1, NULL));
		cgen_four(MIPS_R6_BC);
		return true;
	}
	g(cgen_jump_not_last(ctx, cgen_jmp_extra_long_length() + 1));
	cgen_mips_imm(mc, 0, arg1[0], cgen_jmp_extra_long_length());
	g(add_relocation(ctx, JMP_EXTRA_LONG, 1, NULL));
	g(cgen_jmp_extra_long(ctx));
	return true;

invalid:
	internal(file_line, "cgen_jmp_reg: invalid arguments %u, %u, %02x", cond, length, arg1[0]);
	return false;
}

static bool attr_w cgen_jmp_2regs(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] >= 0x20 || arg2[0] >= 0x20 || (cond != COND_E && cond != COND_NE))
		goto invalid;

	if (length > JMP_SHORTEST)
		cond ^= 1;

	mc = cond == COND_E ? MIPS_BEQ : MIPS_BNE;

	if (length == JMP_SHORTEST) {
		g(cgen_jump_not_last(ctx, 1));
		g(add_relocation(ctx, JMP_SHORTEST, 2, NULL));
		cgen_mips_imm(mc, arg1[0], arg2[0], 0);
		cgen_four(MIPS_NOP);
		return true;
	}
	g(cgen_jump_not_last(ctx, cgen_jmp_extra_long_length() + 1));
	cgen_mips_imm(mc, arg1[0], arg2[0], cgen_jmp_extra_long_length());
	g(add_relocation(ctx, JMP_EXTRA_LONG, 2, NULL));
	g(cgen_jmp_extra_long(ctx));
	return true;

invalid:
	internal(file_line, "cgen_jmp_2regs: invalid arguments %u, %u, %02x, %02x", cond, length, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_jmp_2regs_mips_r6(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint32_t mc;
	bool swap = false;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t arg3[1] = { R_AT };
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] >= 0x20 || arg2[0] >= 0x20)
		goto invalid;

	if (arg1[0] == arg2[0]) {
		cgen_mips_3reg(MIPS_OR, R_AT, arg2[0], R_ZERO);
		arg2 = arg3;
	}

	if (length > JMP_SHORTEST)
		cond ^= 1;

	switch (cond) {
		case COND_B:	mc = MIPS_R6_BLTUC; break;
		case COND_AE:	mc = MIPS_R6_BGEUC; break;
		case COND_E:	mc = MIPS_BEQ; break;
		case COND_NE:	mc = MIPS_BNE; break;
		case COND_BE:	mc = MIPS_R6_BGEUC; swap = true; break;
		case COND_A:	mc = MIPS_R6_BLTUC; swap = true; break;
		case COND_S:
		case COND_L:	mc = MIPS_R6_BLTC; break;
		case COND_NS:
		case COND_GE:	mc = MIPS_R6_BGEC; break;
		case COND_LE:	mc = MIPS_R6_BGEC; swap = true; break;
		case COND_G:	mc = MIPS_R6_BLTC; swap = true; break;
		default:	goto invalid;
	}
	if (!swap) {
		uint8_t *argx = arg1;
		arg1 = arg2;
		arg2 = argx;
	}

	if (length == JMP_SHORTEST) {
		g(add_relocation(ctx, JMP_SHORTEST, 2, NULL));
		cgen_mips_imm(mc, arg1[0], arg2[0], 0);
		cgen_four(MIPS_NOP);
		return true;
	}
	if (length <= JMP_LONG) {
		cgen_mips_imm(mc, arg1[0], arg2[0], 2);
		cgen_four(MIPS_NOP);
		g(add_relocation(ctx, JMP_LONG, 2, NULL));
		cgen_four(MIPS_R6_BC);
		return true;
	}
	cgen_mips_imm(mc, arg1[0], arg2[0], cgen_jmp_extra_long_length());
	g(add_relocation(ctx, JMP_EXTRA_LONG, 2, NULL));
	g(cgen_jmp_extra_long(ctx));
	return true;

invalid:
	internal(file_line, "cgen_jmp_2regs: invalid arguments %u, %u, %02x, %02x", cond, length, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_jmp_fp_test(struct codegen_context *ctx, unsigned aux, unsigned length)
{
	uint32_t mc;
	bool t = true;
	if (fp_condition_negated(aux))
		t = !t;
	if (length > JMP_SHORTEST)
		t = !t;
	if (MIPS_R6) {
		mc = t ? MIPS_R6_BC1NEZ : MIPS_R6_BC1EQZ;
		if (length == JMP_SHORTEST) {
			g(cgen_jump_not_last(ctx, 1));
			g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
			cgen_mips_imm(mc, FR_CMP_RESULT & 31, 0, 0);
			cgen_four(MIPS_NOP);
			return true;
		}
		if (length <= JMP_LONG) {
			g(cgen_jump_not_last(ctx, 3));
			cgen_mips_imm(mc, FR_CMP_RESULT & 31, 0, 2);
			cgen_four(MIPS_NOP);
			g(add_relocation(ctx, JMP_LONG, 0, NULL));
			cgen_four(MIPS_R6_BC);
			return true;
		}
		g(cgen_jump_not_last(ctx, cgen_jmp_extra_long_length() + 1));
		cgen_mips_imm(mc, FR_CMP_RESULT & 31, 0, cgen_jmp_extra_long_length());
		g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
		g(cgen_jmp_extra_long(ctx));
		return true;
	} else {
		mc = t ? MIPS_BC1T : MIPS_BC1F;
		if (length == JMP_SHORTEST) {
			g(cgen_jump_not_last(ctx, 1));
			g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
			cgen_mips_imm(mc, 0, 0, 0);
			cgen_four(MIPS_NOP);
			return true;
		}
		g(cgen_jump_not_last(ctx, cgen_jmp_extra_long_length() + 1));
		cgen_mips_imm(mc, 0, 0, cgen_jmp_extra_long_length());
		g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
		g(cgen_jmp_extra_long(ctx));
		return true;
	}
}

static bool attr_w cgen_jmp_call_indirect(struct codegen_context *ctx, unsigned reg, bool call)
{
	g(cgen_jump_not_last(ctx, 1));
	if (!call) {
		if (!MIPS_R6) {
			cgen_mips_3reg(MIPS_JR, 0, reg, 0);
			cgen_four(MIPS_NOP);
		} else {
			cgen_mips_imm(MIPS_R6_JIC, reg, 0, 0);
		}
	} else {
		if (!MIPS_R6) {
			cgen_mips_3reg(MIPS_JALR, R_RA, reg, 0);
			cgen_four(MIPS_NOP);
		} else {
			cgen_mips_imm(MIPS_R6_JIALC, reg, 0, 0);
		}
	}
	return true;
}


static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	int64_t offs = (int64_t)ctx->label_to_pos[reloc->label_id] - (int64_t)reloc->position;
	switch (reloc->length) {
		case JMP_SHORTEST:
			offs /= 4;
			offs--;
			if (offs != (int16_t)offs)
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0xFFFFU;
			mc |= offs & 0xFFFFU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_SHORT:
			offs /= 4;
			offs--;
			if (offs < -0x00100000 || offs >= 0x00100000)
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x001FFFFFU;
			mc |= offs & 0x001FFFFFU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_LONG:
			offs /= 4;
			offs--;
			if (offs < -0x02000000 || offs >= 0x02000000)
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x03FFFFFFU;
			mc |= offs & 0x03FFFFFFU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_EXTRA_LONG:
			offs -= 12;
			if (offs != (int32_t)offs)
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0xFFFFU;
			mc |= ((uint64_t)offs >> 16) & 0xFFFFU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			memcpy(&mc, ctx->mcode + reloc->position + 8, 4);
			mc &= ~0xFFFFU;
			mc |= offs & 0xFFFFU;
			memcpy(ctx->mcode + reloc->position + 8, &mc, 4);
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}


static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	if (unlikely(insn_writes_flags(insn))) {
		if (unlikely(insn_opcode(insn) != INSN_FP_CMP_COND))
			goto invalid_insn;
	}
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			g(cgen_jmp_call_indirect(ctx, R_RA, false));
			if (MIPS_R6)
				cgen_four(MIPS_NOP);
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_jmp_call_indirect(ctx, cget_one(ctx), true));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn), false));
			return true;
		case INSN_MOVSX:
			g(cgen_mov(ctx, insn_op_size(insn), true));
			return true;
		case INSN_MOV_LR:
			g(cgen_mov_lr(ctx, insn_op_size(insn), insn_aux(insn) != 0));
			return true;
		case INSN_CMP_DEST_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_cmp_dest_reg(ctx, insn_aux(insn)));
			return true;
		case INSN_ALU:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), false));
			return true;
		case INSN_ALU_TRAP:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), true));
			return true;
		case INSN_ALU1:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn), false));
			return true;
		case INSN_ALU1_TRAP:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn), true));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_MUL_L:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2) || unlikely(insn_op_size(insn) > OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_mul_l(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_CMP_COND:
			g(cgen_fp_cmp_cond(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_TEST_REG:
			g(cgen_fp_test_reg(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_ALU:
			g(cgen_fp_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_ALU1:
			g(cgen_fp_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_TO_INT32:
		case INSN_FP_TO_INT64:
			g(cgen_fp_to_int(ctx, insn_opcode(insn) == INSN_FP_TO_INT32 ? OP_SIZE_4 : OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_FP_FROM_INT32:
		case INSN_FP_FROM_INT64:
			g(cgen_fp_from_int(ctx, insn_opcode(insn) == INSN_FP_FROM_INT32 ? OP_SIZE_4 : OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_JMP:
			g(cgen_jmp(ctx, insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG:
			g(cgen_jmp_reg(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_2REGS:
			if (!MIPS_R6)
				g(cgen_jmp_2regs(ctx, insn_aux(insn), insn_jump_size(insn)));
			else
				g(cgen_jmp_2regs_mips_r6(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_FP_TEST:
			g(cgen_jmp_fp_test(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_call_indirect(ctx, cget_one(ctx), false));
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x in %s", insn, da(ctx->fn,function)->function_name);
			return false;
	}
}
