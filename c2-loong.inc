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

#define LOONG_CLO_W		0x00001000U
#define LOONG_CLZ_W		0x00001400U
#define LOONG_CTO_W		0x00001800U
#define LOONG_CTZ_W		0x00001c00U
#define LOONG_CLO_D		0x00002000U
#define LOONG_CLZ_D		0x00002400U
#define LOONG_CTO_D		0x00002800U
#define LOONG_CTZ_D		0x00002c00U
#define LOONG_REVB_2H		0x00003000U
#define LOONG_REVB_4H		0x00003400U
#define LOONG_REVB_2W		0x00003800U
#define LOONG_REVB_D		0x00003c00U
#define LOONG_REVH_2W		0x00004000U
#define LOONG_REVH_D		0x00004400U
#define LOONG_BITREV_W		0x00005000U
#define LOONG_BITREV_D		0x00005400U
#define LOONG_EXT_W_H		0x00005800U
#define LOONG_EXT_W_B		0x00005c00U
#define LOONG_ADD_W		0x00100000U
#define LOONG_ADD_D		0x00108000U
#define LOONG_SUB_W		0x00110000U
#define LOONG_SUB_D		0x00118000U
#define LOONG_SLT		0x00120000U
#define LOONG_SLTU		0x00128000U
#define LOONG_NOR		0x00140000U
#define LOONG_AND		0x00148000U
#define LOONG_OR		0x00150000U
#define LOONG_XOR		0x00158000U
#define LOONG_ORN		0x00160000U
#define LOONG_ANDN		0x00168000U
#define LOONG_SLL_W		0x00170000U
#define LOONG_SRL_W		0x00178000U
#define LOONG_SRA_W		0x00180000U
#define LOONG_SLL_D		0x00188000U
#define LOONG_SRL_D		0x00190000U
#define LOONG_SRA_D		0x00198000U
#define LOONG_ROTR_W		0x001b0000U
#define LOONG_ROTR_D		0x001b8000U
#define LOONG_MUL_W		0x001c0000U
#define LOONG_MULH_W		0x001c8000U
#define LOONG_MULH_WU		0x001d0000U
#define LOONG_MUL_D		0x001d8000U
#define LOONG_MULH_D		0x001e0000U
#define LOONG_MULH_DU		0x001e8000U
#define LOONG_DIV_W		0x00200000U
#define LOONG_MOD_W		0x00208000U
#define LOONG_DIV_WU		0x00210000U
#define LOONG_MOD_WU		0x00218000U
#define LOONG_DIV_D		0x00220000U
#define LOONG_MOD_D		0x00228000U
#define LOONG_DIV_DU		0x00230000U
#define LOONG_MOD_DU		0x00238000U
#define LOONG_SLLI_W		0x00408000U
#define LOONG_SLLI_D		0x00410000U
#define LOONG_SRLI_W		0x00448000U
#define LOONG_SRLI_D		0x00450000U
#define LOONG_SRAI_W		0x00488000U
#define LOONG_SRAI_D		0x00490000U
#define LOONG_ROTRI_W		0x004c8000U
#define LOONG_ROTRI_D		0x004d0000U
#define LOONG_BSTRINS_W		0x00600000U
#define LOONG_BSTRPICK_W	0x00608000U
#define LOONG_BSTRINS_D		0x00800000U
#define LOONG_BSTRPICK_D	0x00c00000U
#define LOONG_FADD_S		0x01008000U
#define LOONG_FADD_D		0x01010000U
#define LOONG_FSUB_S		0x01028000U
#define LOONG_FSUB_D		0x01030000U
#define LOONG_FMUL_S		0x01048000U
#define LOONG_FMUL_D		0x01050000U
#define LOONG_FDIV_S		0x01068000U
#define LOONG_FDIV_D		0x01070000U
#define LOONG_FNEG_S		0x01141400U
#define LOONG_FNEG_D		0x01141800U
#define LOONG_FSQRT_S		0x01144400U
#define LOONG_FSQRT_D		0x01144800U
#define LOONG_MOVFR2GR_S	0x0114b400U
#define LOONG_MOVFR2GR_D	0x0114b800U
#define LOONG_MOVCF2GR		0x0114dc00U
#define LOONG_FTINTRZ_W_S	0x011a8400U
#define LOONG_FTINTRZ_W_D	0x011a8800U
#define LOONG_FTINTRZ_L_S	0x011aa400U
#define LOONG_FTINTRZ_L_D	0x011aa800U
#define LOONG_FFINT_S_W		0x011d1000U
#define LOONG_FFINT_S_L		0x011d1800U
#define LOONG_FFINT_D_W		0x011d2000U
#define LOONG_FFINT_D_L		0x011d2800U
#define LOONG_SLTI		0x02000000U
#define LOONG_SLTUI		0x02400000U
#define LOONG_ADDI_W		0x02800000U
#define LOONG_ADDI_D		0x02c00000U
#define LOONG_LU52I_D		0x03000000U
#define LOONG_ANDI		0x03400000U
#define LOONG_ORI		0x03800000U
#define LOONG_XORI		0x03c00000U
#define LOONG_FCMP_S		0x0c100000U
#define LOONG_FCMP_D		0x0c200000U
#define  LOONG_FCMP_SIG			0x00008000U
#define  LOONG_FCMP_AF			0x00000000U
#define  LOONG_FCMP_LT			0x00010000U
#define  LOONG_FCMP_EQ			0x00020000U
#define  LOONG_FCMP_LE			0x00030000U
#define  LOONG_FCMP_UN			0x00040000U
#define  LOONG_FCMP_ULT			0x00050000U
#define  LOONG_FCMP_UEQ			0x00060000U
#define  LOONG_FCMP_ULE			0x00070000U
#define  LOONG_FCMP_NE			0x00080000U
#define  LOONG_FCMP_OR			0x000a0000U
#define  LOONG_FCMP_UNE			0x000c0000U
#define LOONG_LU12I_W		0x14000000U
#define LOONG_LU32I_D		0x16000000U
#define LOONG_LDPTR_W		0x24000000U
#define LOONG_LDPTR_D		0x26000000U
#define LOONG_STPTR_W		0x25000000U
#define LOONG_STPTR_D		0x27000000U
#define LOONG_LD_B		0x28000000U
#define LOONG_LD_H		0x28400000U
#define LOONG_LD_W		0x28800000U
#define LOONG_LD_D		0x28c00000U
#define LOONG_ST_B		0x29000000U
#define LOONG_ST_H		0x29400000U
#define LOONG_ST_W		0x29800000U
#define LOONG_ST_D		0x29c00000U
#define LOONG_LD_BU		0x2a000000U
#define LOONG_LD_HU		0x2a400000U
#define LOONG_LD_WU		0x2a800000U
#define LOONG_FLD_S		0x2b000000U
#define LOONG_FST_S		0x2b400000U
#define LOONG_FLD_D		0x2b800000U
#define LOONG_FST_D		0x2bc00000U
#define LOONG_LDX_B		0x38000000U
#define LOONG_LDX_H		0x38040000U
#define LOONG_LDX_W		0x38080000U
#define LOONG_LDX_D		0x380c0000U
#define LOONG_STX_B		0x38100000U
#define LOONG_STX_H		0x38140000U
#define LOONG_STX_W		0x38180000U
#define LOONG_STX_D		0x381c0000U
#define LOONG_LDX_BU		0x38200000U
#define LOONG_LDX_HU		0x38240000U
#define LOONG_LDX_WU		0x38280000U
#define LOONG_FLDX_S		0x38300000U
#define LOONG_FLDX_D		0x38340000U
#define LOONG_FSTX_S		0x38380000U
#define LOONG_FSTX_D		0x383c0000U
#define LOONG_BEQZ		0x40000000U
#define LOONG_BNEZ		0x44000000U
#define LOONG_BCEQZ		0x48000000U
#define LOONG_BCNEZ		0x48000100U
#define LOONG_JIRL		0x4c000000U
#define LOONG_B			0x50000000U
#define LOONG_BEQ		0x58000000U
#define LOONG_BNE		0x5c000000U
#define LOONG_BLT		0x60000000U
#define LOONG_BGE		0x64000000U
#define LOONG_BLTU		0x68000000U
#define LOONG_BGEU		0x6c000000U


#define cgen_i26(opcode, imm)			cgen_four((opcode) | ((imm) & 0xffffU) << 10 | ((imm) & 0x3ff0000) >> 16)
#define cgen_1ri20(opcode, rd, imm)		cgen_four((opcode) | (rd) | ((imm) & 0xFFFFFU) << 5)
#define cgen_1ri21(opcode, rj, imm)		cgen_four((opcode) | (rj) << 5 | ((imm) & 0xFFFFU) << 5 | ((imm) & 0x1f0000) >> 16)
#define cgen_2r(opcode, rd, rj)			cgen_four((opcode) | (rd) | (rj) << 5)
#define cgen_2ri8(opcode, rd, rj, imm)		cgen_four((opcode) | (rd) | (rj) << 5 | ((imm) & 0xffU) << 10)
#define cgen_2ri12(opcode, rd, rj, imm)		cgen_four((opcode) | (rd) | (rj) << 5 | ((imm) & 0xfffU) << 10)
#define cgen_2ri14(opcode, rd, rj, imm)		cgen_four((opcode) | (rd) | (rj) << 5 | ((imm) & 0x3fffU) << 10)
#define cgen_2ri16(opcode, rd, rj, imm)		cgen_four((opcode) | (rd) | (rj) << 5 | ((imm) & 0xffffU) << 10)
#define cgen_2r2i(opcode, rd, rj, imm_m, imm_l)	cgen_four((opcode) | (rd) | (rj) << 5 | (imm_m) << 16 | (imm_l) << 10)
#define cgen_3r(opcode, rd, rj, rk)		cgen_four((opcode) | (rd) | (rj) << 5 | ((rk) << 10))

static bool attr_w cgen_jmp_call_indirect(struct codegen_context *ctx, bool call)
{
	uint8_t reg = cget_one(ctx);
	uint8_t save = call ? R_RA : R_ZERO;
	cgen_2ri16(LOONG_JIRL, save, reg, 0);
	return true;
}

static const uint32_t st[10] =		{ LOONG_ST_B, LOONG_ST_H, LOONG_ST_W, LOONG_ST_D, LOONG_STX_B, LOONG_STX_H, LOONG_STX_W, LOONG_STX_D, LOONG_STPTR_W, LOONG_STPTR_D };
static const uint32_t ld_signed[10] =	{ LOONG_LD_B, LOONG_LD_H, LOONG_LD_W, LOONG_LD_D, LOONG_LDX_B, LOONG_LDX_H, LOONG_LDX_W, LOONG_LDX_D, LOONG_LDPTR_W, LOONG_LDPTR_D };
static const uint32_t ld_unsigned[10] =	{ LOONG_LD_BU, LOONG_LD_HU, LOONG_LD_WU, LOONG_LD_D, LOONG_LDX_BU, LOONG_LDX_HU, LOONG_LDX_WU, LOONG_LDX_D, -1U, LOONG_LDPTR_D };
static const uint32_t st_fp[10] =	{ -1U, -1U, LOONG_FST_S, LOONG_FST_D, -1U, -1U, LOONG_FSTX_S, LOONG_FSTX_D, -1U, -1U };
static const uint32_t ld_fp[10] =	{ -1U, -1U, LOONG_FLD_S, LOONG_FLD_D, -1U, -1U, LOONG_FLDX_S, LOONG_FLDX_D, -1U, -1U };

static bool cgen_ld_st(struct codegen_context *ctx, const uint32_t table[10], unsigned size, uint8_t reg, uint8_t *address)
{
	int64_t imm;
	if (address[0] == ARG_ADDRESS_1) {
		imm = get_imm(&address[2]);
		if (!(imm & 3) && imm >= -0x8000 && imm < 0x8000 && (size == OP_SIZE_4 || size == OP_SIZE_8)) {
			uint32_t mc = table[8 + size - OP_SIZE_4];
			if (mc != -1U) {
				cgen_2ri14(mc, reg, address[1], (uint64_t)imm >> 2);
				return true;
			}
		}
		if (imm >= -0x800 && imm < 0x800) {
			cgen_2ri12(table[size], reg, address[1], imm);
			return true;
		}
	} else if (address[0] == ARG_ADDRESS_2) {
		imm = get_imm(&address[3]);
		if (unlikely(imm != 0))
			goto invalid;
		cgen_3r(table[4 + size], reg, address[1], address[2]);
		return true;
	}
invalid:
	internal(file_line, "cgen_ld_st: invalid arguments %02x, %02x", reg, address[0]);
	return false;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size, bool sx)
{
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (size == OP_SIZE_NATIVE)
		sx = false;
	if (arg1[0] < 0x20) {
		if (arg2[0] < 0x20) {
			if (sx) {
				switch (size) {
					case OP_SIZE_1:
						cgen_2r(LOONG_EXT_W_B, arg1[0], arg2[0]);
						return true;
					case OP_SIZE_2:
						cgen_2r(LOONG_EXT_W_H, arg1[0], arg2[0]);
						return true;
					case OP_SIZE_4:
						cgen_2ri8(LOONG_SLLI_W, arg1[0], arg2[0], 0);
						return true;
					default:
						goto invalid;
				}
			} else {
				switch (size) {
					case OP_SIZE_1:
						cgen_2r2i(LOONG_BSTRPICK_D, arg1[0], arg2[0], 0x07, 0x00);
						return true;
					case OP_SIZE_2:
						cgen_2r2i(LOONG_BSTRPICK_D, arg1[0], arg2[0], 0x0f, 0x00);
						return true;
					case OP_SIZE_4:
						cgen_2r2i(LOONG_BSTRPICK_D, arg1[0], arg2[0], 0x1f, 0x00);
						return true;
					case OP_SIZE_8:
						cgen_3r(LOONG_OR, arg1[0], arg2[0], R_ZERO);
						return true;
					default:
						goto invalid;
				}
			}
		}
		if (arg2[0] < 0x40) {
			switch (size) {
				case OP_SIZE_4:
					cgen_2r(LOONG_MOVFR2GR_S, arg1[0], arg2[0] & 0x1f);
					return true;
				case OP_SIZE_8:
					cgen_2r(LOONG_MOVFR2GR_D, arg1[0], arg2[0] & 0x1f);
					return true;
				default:
					goto invalid;
			}
		}
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (imm >= 0 && imm < 0x1000) {
				cgen_2ri12(LOONG_ORI, arg1[0], R_ZERO, imm);
				return true;
			}
			if (imm >= -0x800 && imm < 0x800) {
				cgen_2ri12(LOONG_ADDI_D, arg1[0], R_ZERO, imm);
				return true;
			}
			if (!(imm & 0xfff) && imm == (int32_t)imm) {
				cgen_1ri20(LOONG_LU12I_W, arg1[0], (uint64_t)imm >> 12);
				return true;
			}
			if (!(imm & 0x000fffffffffffffLL)) {
				cgen_2ri12(LOONG_LU52I_D, arg1[0], R_ZERO, (uint64_t)imm >> 52);
				return true;
			}
			goto invalid;
		}
		if (arg2[0] == ARG_ADDRESS_1 || arg2[0] == ARG_ADDRESS_2) {
			if (!sx)
				return cgen_ld_st(ctx, ld_unsigned, size, arg1[0], arg2);
			else
				return cgen_ld_st(ctx, ld_signed, size, arg1[0], arg2);
		}
		goto invalid;
	}

	if (arg1[0] < 0x40) {
		if (arg2[0] == ARG_ADDRESS_1 || arg2[0] == ARG_ADDRESS_2) {
			return cgen_ld_st(ctx, ld_fp, size, arg1[0] & 0x1f, arg2);
		}
	}

	if (arg1[0] == ARG_ADDRESS_1 || arg1[0] == ARG_ADDRESS_2) {
		if (arg2[0] < 0x20) {
			return cgen_ld_st(ctx, st, size, arg2[0], arg1);
		}
		if (arg2[0] < 0x40) {
			return cgen_ld_st(ctx, st_fp, size, arg2[0] & 0x1f, arg1);
		}
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (unlikely(imm != 0))
				goto invalid;
			return cgen_ld_st(ctx, st, size, R_ZERO, arg1);
		}
	}

invalid:
	internal(file_line, "cgen_mov: invalid arguments %02x, %02x", arg1[0], arg2[0]);
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
		if (unlikely(imm < -0x800) && unlikely(imm >= 0x800))
			internal(file_line, "cgen_cmp_dest_reg: invalid imm value %"PRIxMAX"", (intmax_t)imm);
		switch (aux) {
			case COND_B:	mc = LOONG_SLTUI; break;
			case COND_L:	mc = LOONG_SLTI; break;
			default:	internal(file_line, "cgen_cmp_dest_reg: invalid condition %u", aux);
		}
		cgen_2ri12(mc, arg1[0], arg2[0], imm);
		return true;
	}
	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		if (unlikely(imm != 0))
			internal(file_line, "cgen_cmp_dest_reg: non-zero second argument");
		arg2 = &z;
	}
	switch (aux) {
		case COND_B:	mc = LOONG_SLTU; break;
		case COND_A:	mc = LOONG_SLTU; swap = true; break;
		case COND_L:	mc = LOONG_SLT; break;
		case COND_G:	mc = LOONG_SLT; swap = true; break;
		default:	internal(file_line, "cgen_cmp_dest_reg: invalid condition %u", aux);
	}
	if (swap) {
		uint8_t *argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}
	cgen_3r(mc, arg1[0], arg2[0], arg3[0]);
	return true;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		if (alu == ALU_SUB) {
			imm = -(uint64_t)imm;
			alu = ALU_ADD;
		}
		if (alu == ALU_ADD) {
			if (unlikely(imm < -0x800) || unlikely(imm >= 0x800))
				internal(file_line, "cgen_alu: invalid imm value %"PRIxMAX"", (intmax_t)imm);
		} else {
			if (unlikely(imm < 0) || unlikely(imm >= 0x1000))
				internal(file_line, "cgen_alu: invalid imm value %"PRIxMAX"", (intmax_t)imm);
		}
		switch (alu) {
			case ALU_ADD:	mc = size == OP_SIZE_8 ? LOONG_ADDI_D : LOONG_ADDI_W; break;
			case ALU_XOR:	mc = LOONG_XORI; break;
			case ALU_OR:	mc = LOONG_ORI; break;
			case ALU_AND:	mc = LOONG_ANDI; break;
			default:	internal(file_line, "cgen_alu: invalid alu %u", alu);
		}
		cgen_2ri12(mc, arg1[0], arg2[0], imm);
		return true;
	}

	switch (alu) {
		case ALU_ADD:	mc = size == OP_SIZE_8 ? LOONG_ADD_D : LOONG_ADD_W; break;
		case ALU_SUB:	mc = size == OP_SIZE_8 ? LOONG_SUB_D : LOONG_SUB_W; break;
		case ALU_XOR:	mc = LOONG_XOR; break;
		case ALU_OR:	mc = LOONG_OR; break;
		case ALU_AND:	mc = LOONG_AND; break;
		case ALU_ANDN:	mc = LOONG_ANDN; break;
		case ALU_ORN:	mc = LOONG_ORN; break;
		case ALU_MUL:	mc = size == OP_SIZE_8 ? LOONG_MUL_D : LOONG_MUL_W; break;
		case ALU_SMULH:	mc = size == OP_SIZE_8 ? LOONG_MULH_D : LOONG_MULH_W; break;
		case ALU_UDIV:	mc = size == OP_SIZE_8 ? LOONG_DIV_DU : LOONG_DIV_WU; break;
		case ALU_SDIV:	mc = size == OP_SIZE_8 ? LOONG_DIV_D : LOONG_DIV_W; break;
		case ALU_UREM:	mc = size == OP_SIZE_8 ? LOONG_MOD_DU : LOONG_MOD_WU; break;
		case ALU_SREM:	mc = size == OP_SIZE_8 ? LOONG_MOD_D : LOONG_MOD_W; break;
		default:	internal(file_line, "cgen_alu: invalid alu %u", alu);
	}
	cgen_3r(mc, arg1[0], arg2[0], arg3[0]);
	return true;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (alu) {
		case ALU1_NOT:
			cgen_3r(LOONG_NOR, arg1[0], R_ZERO, arg2[0]);
			return true;
		case ALU1_NEG:
			cgen_3r(size == OP_SIZE_4 ? LOONG_SUB_W : LOONG_SUB_D, arg1[0], R_ZERO, arg2[0]);
			return true;
		case ALU1_INC:
			cgen_2ri12(size == OP_SIZE_4 ? LOONG_ADDI_W : LOONG_ADDI_D, arg1[0], arg2[0], 1);
			return true;
		case ALU1_DEC:
			cgen_2ri12(size == OP_SIZE_4 ? LOONG_ADDI_W : LOONG_ADDI_D, arg1[0], arg2[0], -1);
			return true;
		case ALU1_BSWAP:
			if (size == OP_SIZE_4) {
				cgen_2r(LOONG_REVB_2H, arg1[0], arg2[0]);
				cgen_2ri8(LOONG_ROTRI_W, arg1[0], arg1[0], 0x10);
				return true;
			} else {
				cgen_2r(LOONG_REVB_4H, arg1[0], arg2[0]);
				cgen_2r(LOONG_REVH_D, arg1[0], arg1[0]);
				return true;
			}
		case ALU1_BSWAP16:
			cgen_2r(size == OP_SIZE_4 ? LOONG_REVB_2H : LOONG_REVB_4H, arg1[0], arg2[0]);
			return true;
		case ALU1_BREV:
			cgen_2r(size == OP_SIZE_4 ? LOONG_BITREV_W : LOONG_BITREV_D, arg1[0], arg2[0]);
			return true;
		case ALU1_BSF:
			cgen_2r(size == OP_SIZE_4 ? LOONG_CTZ_W : LOONG_CTZ_D, arg1[0], arg2[0]);
			return true;
		case ALU1_LZCNT:
			cgen_2r(size == OP_SIZE_4 ? LOONG_CLZ_W : LOONG_CLZ_D, arg1[0], arg2[0]);
			return true;
		default:
			internal(file_line, "cgen_alu1: invalid alu %u", alu);
			return false;
	}
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
		if (alu == ROT_ROL)
			imm = -(uint64_t)imm;
		imm &= size == OP_SIZE_4 ? 0x1f : 0x3f;
		switch (alu) {
			case ROT_ROL:	mc = size == OP_SIZE_4 ? LOONG_ROTRI_W : LOONG_ROTRI_D; break;
			case ROT_ROR:	mc = size == OP_SIZE_4 ? LOONG_ROTRI_W : LOONG_ROTRI_D; break;
			case ROT_SHL:	mc = size == OP_SIZE_4 ? LOONG_SLLI_W : LOONG_SLLI_D; break;
			case ROT_SHR:	mc = size == OP_SIZE_4 ? LOONG_SRLI_W : LOONG_SRLI_D; break;
			case ROT_SAR:	mc = size == OP_SIZE_4 ? LOONG_SRAI_W : LOONG_SRAI_D; break;
			default:	internal(file_line, "cgen_rot: invalid alu %u", alu);
		}
		cgen_2ri8(mc, arg1[0], arg2[0], imm);
		return true;
	}
	switch (alu) {
		case ROT_ROR:	mc = size == OP_SIZE_4 ? LOONG_ROTR_W : LOONG_ROTR_D; break;
		case ROT_SHL:	mc = size == OP_SIZE_4 ? LOONG_SLL_W : LOONG_SLL_D; break;
		case ROT_SHR:	mc = size == OP_SIZE_4 ? LOONG_SRL_W : LOONG_SRL_D; break;
		case ROT_SAR:	mc = size == OP_SIZE_4 ? LOONG_SRA_W : LOONG_SRA_D; break;
		default:	internal(file_line, "cgen_rot: invalid alu %u", alu);
	}
	cgen_3r(mc, arg1[0], arg2[0], arg3[0]);
	return true;
}

static bool attr_w cgen_btx(struct codegen_context *ctx, unsigned alu)
{
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg3[0] != ARG_IMM))
		goto invalid;
	imm = get_imm(&arg3[1]) & 0x3f;
	switch (alu) {
		case BTX_BTR:
			if (unlikely(arg1[0] != arg2[0]))
				cgen_3r(LOONG_OR, arg1[0], arg2[0], R_ZERO);
			cgen_2r2i(LOONG_BSTRINS_D, arg1[0], R_ZERO, imm, imm);
			return true;
		case BTX_BTEXT:
			cgen_2r2i(LOONG_BSTRPICK_D, arg1[0], arg2[0], imm, imm);
			return true;
	}

invalid:
	internal(file_line, "cgen_btx: bad arguments: %02x, %02x, %02x, %u", arg1[0], arg2[0], arg3[0], alu);
	return false;
}

static bool attr_w cgen_mov_mask(struct codegen_context *ctx, unsigned aux)
{
	uint64_t imm = 0;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32) || unlikely(arg3[0] != ARG_IMM))
		goto invalid;

	imm = get_imm(&arg3[1]);

	switch (aux) {
		case MOV_MASK_32_64:
			if (unlikely(arg1[0] != arg2[0]))
				goto invalid;
			cgen_1ri20(LOONG_LU32I_D, arg1[0], imm);
			return true;
		case MOV_MASK_52_64:
			cgen_2ri12(LOONG_LU52I_D, arg1[0], arg2[0], imm);
			return true;
		default:	goto invalid;
	}

invalid:
	internal(file_line, "cgen_mov_mask: bad arguments: %02x, %02x, %u, %"PRIxMAX"", arg1[0], arg2[0], aux, (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_fp_cmp_cond(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	bool swap;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	mc = op_size == OP_SIZE_4 ? LOONG_FCMP_S : LOONG_FCMP_D;

	switch (aux) {
		case FP_COND_P:		mc |= LOONG_FCMP_UN; swap = false; break;
		case FP_COND_NP:	mc |= LOONG_FCMP_OR; swap = false; break;
		case FP_COND_E:		mc |= LOONG_FCMP_EQ; swap = false; break;
		case FP_COND_NE:	mc |= LOONG_FCMP_NE; swap = false; break;
		case FP_COND_A:		mc |= LOONG_FCMP_LT; swap = true; break;
		case FP_COND_BE:	mc |= LOONG_FCMP_LE; swap = false; break;
		case FP_COND_B:		mc |= LOONG_FCMP_LT; swap = false; break;
		case FP_COND_AE:	mc |= LOONG_FCMP_LE; swap = true; break;
		default:		internal(file_line, "cgen_fp_cmp_cond: invalid condition %u", aux);
					return false;
	}

	if (swap) {
		uint8_t *argx = arg1;
		arg1 = arg2;
		arg2 = argx;
	}

	cgen_3r(mc, 0, arg1[0] & 0x1f, arg2[0] & 0x1f);
	return true;
}

static bool attr_w cgen_fp_test_reg(struct codegen_context *ctx)
{
	unsigned reg = cget_one(ctx);
	cgen_2r(LOONG_MOVCF2GR, reg, 0);
	return true;
}

static bool attr_w cgen_fp_alu(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (aux) {
		case FP_ALU_ADD:	mc = op_size == OP_SIZE_4 ? LOONG_FADD_S : LOONG_FADD_D; break;
		case FP_ALU_SUB:	mc = op_size == OP_SIZE_4 ? LOONG_FSUB_S : LOONG_FSUB_D; break;
		case FP_ALU_MUL:	mc = op_size == OP_SIZE_4 ? LOONG_FMUL_S : LOONG_FMUL_D; break;
		case FP_ALU_DIV:	mc = op_size == OP_SIZE_4 ? LOONG_FDIV_S : LOONG_FDIV_D; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	cgen_3r(mc, arg1[0] & 0x1f, arg2[0] & 0x1f, arg3[0] & 0x1f);
	return true;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	mc = op_size == OP_SIZE_4 ? LOONG_FNEG_S : LOONG_FNEG_D; break;
		case FP_ALU1_SQRT:	mc = op_size == OP_SIZE_4 ? LOONG_FSQRT_S : LOONG_FSQRT_D; break;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	cgen_2r(mc, arg1[0] & 0x1f, arg2[0] & 0x1f);
	return true;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (unlikely(!reg_is_fp(arg1[0])) || unlikely(!reg_is_fp(arg2[0])))
		internal(file_line, "cgen_fp_to_int: invalid registers %02x, %02x", arg1[0], arg2[0]);

	if (int_op_size == OP_SIZE_4) {
		if (fp_op_size == OP_SIZE_4)
			mc = LOONG_FTINTRZ_W_S;
		else
			mc = LOONG_FTINTRZ_W_D;
	} else {
		if (fp_op_size == OP_SIZE_4)
			mc = LOONG_FTINTRZ_L_S;
		else
			mc = LOONG_FTINTRZ_L_D;
	}
	cgen_2r(mc, arg1[0] & 0x1f, arg2[0] & 0x1f);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (unlikely(!reg_is_fp(arg1[0])) || unlikely(!reg_is_fp(arg2[0])))
		internal(file_line, "cgen_fp_from_int: invalid registers %02x, %02x", arg1[0], arg2[0]);

	if (int_op_size == OP_SIZE_4) {
		if (fp_op_size == OP_SIZE_4)
			mc = LOONG_FFINT_S_W;
		else
			mc = LOONG_FFINT_D_W;
	} else {
		if (fp_op_size == OP_SIZE_4)
			mc = LOONG_FFINT_S_L;
		else
			mc = LOONG_FFINT_D_L;
	}
	cgen_2r(mc, arg1[0] & 0x1f, arg2[0] & 0x1f);
	return true;
}

static bool attr_w cgen_jmp(struct codegen_context *ctx)
{
	g(add_relocation(ctx, JMP_LONG, 0, NULL));
	cgen_i26(LOONG_B, 0);
	return true;
}

static bool attr_w cgen_jmp_12regs(struct codegen_context *ctx, unsigned cond, unsigned length, unsigned reg1, unsigned reg2, int reloc_offset)
{
	uint32_t mc;
	bool swap;

	if (reg1 >= 0x20 || reg2 >= 0x20)
		goto invalid;

	if (length > JMP_SHORTEST)
		cond ^= 1;

	swap = false;
	switch (cond) {
		case COND_B:	mc = LOONG_BLTU; break;
		case COND_AE:	mc = LOONG_BGEU; break;
		case COND_E:	mc = LOONG_BEQ; break;
		case COND_NE:	mc = LOONG_BNE; break;
		case COND_BE:	mc = LOONG_BGEU; swap = true; break;
		case COND_A:	mc = LOONG_BLTU; swap = true; break;
		case COND_L:	mc = LOONG_BLT; break;
		case COND_GE:	mc = LOONG_BGE; break;
		case COND_LE:	mc = LOONG_BGE; swap = true; break;
		case COND_G:	mc = LOONG_BLT; swap = true; break;
		default:	goto invalid;
	}


	if (swap) {
		unsigned regx = reg1;
		reg1 = reg2;
		reg2 = regx;
	}

	if (length == JMP_SHORTEST) {
		g(add_relocation(ctx, JMP_SHORTEST, reloc_offset, NULL));
		cgen_2ri16(mc, reg2, reg1, 0);
		return true;
	} else {
		cgen_2ri16(mc, reg2, reg1, 2);
		g(add_relocation(ctx, JMP_LONG, reloc_offset, NULL));
		cgen_i26(LOONG_B, 0);
		return true;
	}

invalid:
	internal(file_line, "cgen_jmp_12regs: invalid arguments %02x, %02x", reg1, reg2);
	return false;
}

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] >= 0x20)
		goto invalid;

	switch (cond) {
		case COND_S:
		case COND_L:
			g(cgen_jmp_12regs(ctx, COND_L, length, arg1[0], R_ZERO, 1));
			return true;
		case COND_NS:
		case COND_GE:
			g(cgen_jmp_12regs(ctx, COND_GE, length, arg1[0], R_ZERO, 1));
			return true;
		case COND_LE:
		case COND_G:
			g(cgen_jmp_12regs(ctx, cond, length, arg1[0], R_ZERO, 1));
			return true;
	}

	if (length > JMP_SHORT)
		cond ^= 1;

	switch (cond) {
		case COND_E:	mc = LOONG_BEQZ; break;
		case COND_NE:	mc = LOONG_BNEZ; break;
		default:	goto invalid;
	}

	if (length <= JMP_SHORT) {
		g(add_relocation(ctx, JMP_SHORT, 1, NULL));
		cgen_1ri21(mc, arg1[0], 0);
		return true;
	} else {
		cgen_1ri21(mc, arg1[0], 2);
		g(add_relocation(ctx, JMP_LONG, 1, NULL));
		cgen_i26(LOONG_B, 0);
		return true;
	}

invalid:
	internal(file_line, "cgen_jmp_reg: invalid argument %02x, %u", arg1[0], cond);
	return false;
}

static bool attr_w cgen_jmp_2regs(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	g(cgen_jmp_12regs(ctx, cond, length, arg1[0], arg2[0], 2));
	return true;
}

static bool attr_w cgen_jmp_fp_test(struct codegen_context *ctx, unsigned length)
{
	if (length <= JMP_SHORT) {
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
		cgen_1ri21(LOONG_BCNEZ, 0, 0);
		return true;
	} else {
		cgen_1ri21(LOONG_BCEQZ, 0, 2);
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_i26(LOONG_B, 0);
		return true;
	}
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 2) - (int64_t)(reloc->position >> 2);
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x8000) || unlikely(offs >= 0x8000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~(0xffffU << 10);
			mc |= (offs & 0xffffU) << 10;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_SHORT:
			if (unlikely(offs < -0x100000) || unlikely(offs >= 0x100000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~((0xffffU << 10) | 0x1fU);
			mc |= ((offs & 0xffffU) << 10) | ((offs & 0x1f0000U) >> 16);
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_LONG:
			if (unlikely(offs < -0x2000000) || unlikely(offs >= 0x2000000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~((0xffffU << 10) | 0x3ffU);
			mc |= ((offs & 0xffffU) << 10) | ((offs & 0x3ff0000U) >> 16);
			memcpy(ctx->mcode + reloc->position, &mc, 4);
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
	/*debug("insn: %08x", (unsigned)insn);*/
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			cgen_2ri16(LOONG_JIRL, R_ZERO, R_RA, 0);
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_jmp_call_indirect(ctx, true));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn), false));
			return true;
		case INSN_MOVSX:
			g(cgen_mov(ctx, insn_op_size(insn), true));
			return true;
		case INSN_CMP_DEST_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_cmp_dest_reg(ctx, insn_aux(insn)));
			return true;
		case INSN_ALU:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ALU1:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_BTX:
			g(cgen_btx(ctx, insn_aux(insn)));
			return true;
		case INSN_MOV_MASK:
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_mov_mask(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_CMP_COND:
			g(cgen_fp_cmp_cond(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_TEST_REG:
			g(cgen_fp_test_reg(ctx));
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
			g(cgen_jmp(ctx));
			return true;
		case INSN_JMP_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_jmp_reg(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_2REGS:
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_jmp_2regs(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_FP_TEST:
			g(cgen_jmp_fp_test(ctx, insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_call_indirect(ctx, false));
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x in %s", insn, da(ctx->fn,function)->function_name);
			return false;
	}
}
