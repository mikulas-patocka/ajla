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

#define  PARISC_N			0x2U

#define  PARISC_COND_64			0x0020U
#define  PARISC_COND_NEVER		0x0000U
#define  PARISC_COND_ALWAYS		0x1000U
#define  PARISC_COND_EQUAL		0x2000U
#define  PARISC_COND_NOT_EQUAL		0x3000U
#define  PARISC_COND_L_S		0x4000U
#define  PARISC_COND_GE_S		0x5000U
#define  PARISC_COND_LE_S		0x6000U
#define  PARISC_COND_G_S		0x7000U
#define  PARISC_COND_L_U		0x8000U
#define  PARISC_COND_GE_U		0x9000U
#define  PARISC_COND_LE_U		0xa000U
#define  PARISC_COND_G_U		0xb000U
#define  PARISC_COND_SV			0xc000U
#define  PARISC_COND_NSV		0xd000U
#define  PARISC_COND_OD			0xe000U
#define  PARISC_COND_EV			0xf000U
#define  PARISC_COND_NEG		0x1000U

#define PARISC_LDSID		0x000010a0U
#define PARISC_MTSP		0x00001820U
#define PARISC_MTSAR		0x01601840U
#define PARISC_MTSARCM		0x016018c0U
#define PARISC_ANDCM		0x08000000U
#define PARISC_AND		0x08000200U
#define PARISC_OR		0x08000240U
#define PARISC_NOP		0x08000240U
#define PARISC_XOR		0x08000280U
#define PARISC_SUB		0x08000400U
#define PARISC_SUB_B		0x08000500U
#define PARISC_SUB_DB		0x08000520U
#define PARISC_ADD		0x08000600U
#define PARISC_ADD_C		0x08000700U
#define PARISC_ADD_DC		0x08000720U
#define PARISC_CMPCLR		0x08000880U
#define PARISC_UADDCM		0x08000980U
#define PARISC_ADD_L		0x08000a00U
#define PARISC_SHLADD_L_1	0x08000a40U
#define PARISC_SHLADD_L_2	0x08000a80U
#define PARISC_SHLADD_L_3	0x08000ac0U

#define PARISC_LD_ST		0x0c000000U
#define  PARISC_LD_ST_B			0x00000000U
#define  PARISC_LD_ST_H			0x00000040U
#define  PARISC_LD_ST_W			0x00000080U
#define  PARISC_LD_ST_D			0x000000c0U
#define  PARISC_LD_ST_IMM		0x00001000U
#define  PARISC_LD_ST_MA		0x00000020U
#define  PARISC_LD_ST_MB		0x00002020U
#define  PARISC_LD_ST_LD		0x00000000U
#define  PARISC_LD_ST_ST		0x00000200U
#define  PARISC_LD_SCALE		0x00002000U
#define PARISC_LDIL		0x20000000U
#define PARISC_ADDIL		0x28000000U
#define PARISC_LDO		0x34000000U

#define PARISC_LDB_LONG		0x40000000U
#define PARISC_LDH_LONG		0x44000000U
#define PARISC_LDW_LONG		0x48000000U
#define PARISC_LDW_M		0x4c000000U
#define PARISC_LDD		0x50000000U
#define PARISC_STB_LONG		0x60000000U
#define PARISC_STH_LONG		0x64000000U
#define PARISC_STW_LONG		0x68000000U
#define PARISC_STW_M		0x6c000000U
#define PARISC_STD		0x70000000U
#define  PARISC_LDD_STD_MA		0x00000008U
#define  PARISC_LDD_STD_MB		0x0000000cU

#define PARISC_CMPB		0x80000000U
#define PARISC_CMPIB		0x84000000U
#define PARISC_CMPB_NOT		0x88000000U
#define PARISC_CMPIB_NOT	0x8c000000U
#define PARISC_CMPICLR		0x90000000U
#define  PARISC_CMPICLR_64		0x00000800U
#define PARISC_SUBI		0x94000000U
#define PARISC_CMPB_64		0x9c000000U
#define PARISC_ADDB		0xa0000000U
#define PARISC_ADDB_NOT		0xa8000000U
#define PARISC_ADDI		0xb4000000U
#define PARISC_CMPB_64_NOT	0xbc000000U

#define PARISC_BB_1		0xc4004000U
#define PARISC_BB_64_1		0xc4006000U
#define PARISC_BB_0		0xc400c000U
#define PARISC_BB_64_0		0xc400e000U
#define PARISC_SHRPW_SAR	0xd0000000U
#define PARISC_SHRPD_SAR	0xd0000200U
#define PARISC_EXTRW_U_SAR	0xd0001000U
#define PARISC_EXTRD_U_SAR	0xd0001200U
#define PARISC_EXTRW_S_SAR	0xd0001400U
#define PARISC_EXTRD_S_SAR	0xd0001600U
#define PARISC_EXTRW_U		0xd0001800U
#define PARISC_EXTRW_S		0xd0001c00U
#define PARISC_DEPW_Z_SAR	0xd4000000U
#define PARISC_DEPD_Z_SAR	0xd4000200U
#define PARISC_DEPW_SAR		0xd4000400U
#define PARISC_DEPD_SAR		0xd4000600U
#define PARISC_DEPW_Z		0xd4000800U
#define PARISC_DEPW		0xd4000c00U
#define PARISC_DEPWI_Z_SAR	0xd4001000U
#define PARISC_DEPDI_Z_SAR	0xd4001200U
#define PARISC_DEPWI_SAR	0xd4001400U
#define PARISC_DEPDI_SAR	0xd4001600U
#define PARISC_DEPWI_Z		0xd4001800U
#define PARISC_DEPWI		0xd4001c00U
#define PARISC_EXTRD_U		0xd8001800U
#define PARISC_EXTRD_S		0xd8001c00U
#define PARISC_BE		0xe0000000U
#define PARISC_BL		0xe8000000U
#define PARISC_BLR		0xe8004000U
#define PARISC_BL_L		0xe800a000U
#define PARISC_BV		0xe800c000U
#define PARISC_BVE_RET		0xe800d000U
#define PARISC_BVE_CALL		0xe800f000U
#define PARISC_CMPIB_64		0xec000000U
#define PARISC_DEPD_Z		0xf0001000U
#define PARISC_DEPD		0xf0001400U
#define PARISC_DEPDI_Z		0xf4000000U
#define PARISC_DEPDI		0xf4000400U

#define  PARISC_FP_DOUBLE		0x00000800U
#define PARISC_FLDW		0x24001000U
#define PARISC_FSTW		0x24001200U
#define PARISC_FLDD		0x2c001000U
#define PARISC_FSTD		0x2c001200U
#define PARISC_FCMP		0x30000400U
#define  PARISC_FCMP_P			0x02U
#define  PARISC_FCMP_NE			0x04U
#define  PARISC_FCMP_AE			0x08U
#define  PARISC_FCMP_A			0x0cU
#define  PARISC_FCMP_BE			0x10U
#define  PARISC_FCMP_B			0x14U
#define  PARISC_FCMP_E			0x18U
#define  PARISC_FCMP_NP			0x1cU
#define PARISC_FADD		0x30000600U
#define PARISC_FTEST		0x30002420U
#define PARISC_FSUB		0x30002600U
#define PARISC_FCPY		0x30004000U
#define PARISC_FMPY		0x30004600U
#define PARISC_FDIV		0x30006600U
#define PARISC_FCNVXF		0x30008200U
#define  PARISC_FCNVXF_FROM_LONG	0x00000800U
#define  PARISC_FCNVXF_TO_DOUBLE	0x00002000U
#define PARISC_FSQRT		0x30008000U
#define PARISC_FNEG		0x3000c000U
#define PARISC_FCNVFXT		0x30018200U
#define  PARISC_FCNVFXT_FROM_DOUBLE	0x00000800U
#define  PARISC_FCNVFXT_TO_LONG		0x00002000U
#define PARISC_FLDD_LONG	0x50000002U
#define PARISC_FLDW_LONG	0x5c000000U
#define PARISC_FSTD_LONG	0x70000002U
#define PARISC_FSTW_LONG	0x7c000000U

static const int32_t cmp_sub_cond[0x12] = {
	PARISC_COND_SV,		PARISC_COND_NSV,	PARISC_COND_L_U,	PARISC_COND_GE_U,
	PARISC_COND_EQUAL,	PARISC_COND_NOT_EQUAL,	PARISC_COND_LE_U,	PARISC_COND_G_U,
	PARISC_COND_L_S,	PARISC_COND_GE_S,	-1,			-1,
	PARISC_COND_L_S,	PARISC_COND_GE_S,	PARISC_COND_LE_S,	PARISC_COND_G_S,
	PARISC_COND_EV,		PARISC_COND_OD,
};

static unsigned cmp_swap_arguments(unsigned cond)
{
	switch (cond) {
		case COND_B:	return COND_A;
		case COND_AE:	return COND_BE;
		case COND_E:	return COND_E;
		case COND_NE:	return COND_NE;
		case COND_BE:	return COND_AE;
		case COND_A:	return COND_B;
		case COND_L:	return COND_G;
		case COND_GE:	return COND_LE;
		case COND_LE:	return COND_GE;
		case COND_G:	return COND_L;
	}
	internal(file_line, "cmp_swap_arguments: can't swap the condition %u", cond);
	return 0;
}

static bool attr_w cgen_2reg(struct codegen_context *ctx, uint32_t mc, unsigned r1, unsigned rt)
{
	mc |= (uint32_t)r1 << 21;
	mc |= (uint32_t)rt << 16;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_3reg(struct codegen_context *ctx, uint32_t mc, unsigned r1, unsigned r2, unsigned rt)
{
	mc |= (uint32_t)r1 << 16;
	mc |= (uint32_t)r2 << 21;
	mc |= rt;
	cgen_four(mc);
	return true;
}

static uint32_t attr_unused low_sign_ext_5(unsigned bit5)
{
	return	((bit5 & 0x10) >> 4) |
		((bit5 & 0x0f) << 1);
}

static uint32_t low_sign_ext_11(unsigned bit11)
{
	return	((bit11 & 0x400) >> 10) |
		((bit11 & 0x3ff) << 1);
}

static uint32_t low_sign_ext_14(unsigned bit14)
{
	return	((bit14 & 0x2000) >> 13) |
		((bit14 & 0x1fff) << 1);
}

static uint32_t assemble_12(uint32_t bit12)
{
	return	((bit12 & 0x800) >> 11) |
		((bit12 & 0x400) >> 8) |
		((bit12 & 0x3ff) << 3);
}

static uint32_t assemble_17(uint32_t bit17)
{
	return	((bit17 & 0x10000) >> 16) |
		((bit17 & 0x0f800) << 5) |
		((bit17 & 0x00400) >> 8) |
		((bit17 & 0x003ff) << 3);
}

static uint32_t assemble_21(uint32_t bit21)
{
	return	((bit21 & 0x100000) >> 20) |
		((bit21 & 0x0ffe00) >> 8) |
		((bit21 & 0x000180) << 7) |
		((bit21 & 0x00007c) << 14) |
		((bit21 & 0x000003) << 12);
}

static uint32_t assemble_22(uint32_t bit22)
{
	return	((bit22 & 0x200000) >> 21) |
		((bit22 & 0x1f0000) << 5) |
		((bit22 & 0x00f800) << 5) |
		((bit22 & 0x000400) >> 8) |
		((bit22 & 0x0003ff) << 3);
}

static bool attr_w cgen_ret(struct codegen_context *ctx)
{
	uint32_t mc;
	if (!PA_20 && PA_SPACES) {
		mc = PARISC_LDSID;
		mc |= (uint32_t)R_RP << 21;
		mc |= R_CG_SCRATCH;
		cgen_four(mc);
		mc = PARISC_MTSP;
		mc |= (uint32_t)R_CG_SCRATCH << 16;
		cgen_four(mc);
		mc = PARISC_BE;
		mc |= (uint32_t)R_RP << 21;
		mc |= PARISC_N;
		cgen_four(mc);
	} else {
		mc = PA_20 ? PARISC_BVE_RET : PARISC_BV;
		mc |= (uint32_t)R_RP << 21;
		mc |= PARISC_N;
		cgen_four(mc);
	}
	cgen_four(PARISC_NOP);
	return true;
}

static bool attr_w cgen_call(struct codegen_context *ctx, unsigned length)
{
	if (length <= JMP_SHORT) {
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
		cgen_four(PARISC_BL | ((uint32_t)R_RP << 21) | PARISC_N);
		cgen_four(PARISC_NOP);
	} else if (length == JMP_LONG && PA_20) {
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_four(PARISC_BL_L | PARISC_N);
		cgen_four(PARISC_NOP);
	} else {
		g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
		cgen_four(PARISC_LDIL | ((uint32_t)R_CG_SCRATCH << 21));
		g(cgen_2reg(ctx, PARISC_LDO, R_CG_SCRATCH, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_RP, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_RP, R_CG_SCRATCH));
		cgen_four(PARISC_NOP);
	}
	return true;
}

static bool attr_w cgen_call_indirect(struct codegen_context *ctx)
{
	uint32_t mc;
	unsigned reg = cget_one(ctx);

	mc = PARISC_LDD | low_sign_ext_14(0x10);
	g(cgen_2reg(ctx, mc, reg, R_31));

	cgen_four(PARISC_BVE_CALL | ((uint32_t)R_31 << 21));

	mc = PARISC_LDD | low_sign_ext_14(0x18);
	g(cgen_2reg(ctx, mc, reg, R_DP));

	return true;
}

static bool attr_w cgen_ld_st(struct codegen_context *ctx, bool ld, unsigned size, uint8_t reg, uint8_t *address)
{
	int64_t imm = 0;
	uint32_t mc;

	if (address[0] == ARG_ADDRESS_1) {
		imm = get_imm(&address[2]);
		if (ld) {
			switch (size) {
				case OP_SIZE_1:	mc = PARISC_LDB_LONG; break;
				case OP_SIZE_2:	mc = PARISC_LDH_LONG; break;
				case OP_SIZE_4:	mc = PARISC_LDW_LONG; break;
				case OP_SIZE_8:	mc = PARISC_LDD; break;
				default:	goto invalid;
			}
		} else {
			switch (size) {
				case OP_SIZE_1:	mc = PARISC_STB_LONG; break;
				case OP_SIZE_2:	mc = PARISC_STH_LONG; break;
				case OP_SIZE_4:	mc = PARISC_STW_LONG; break;
				case OP_SIZE_8:	mc = PARISC_STD; break;
				default:	goto invalid;
			}
		}
		mc |= low_sign_ext_14(imm);
		g(cgen_2reg(ctx, mc, address[1], reg));
		return true;
	}
	if (address[0] == ARG_ADDRESS_1_PRE_I || address[0] == ARG_ADDRESS_1_POST_I) {
		imm = get_imm(&address[2]);
		if (size == OP_SIZE_4) {
			if (imm >= 0 && address[0] == ARG_ADDRESS_1_PRE_I)
				goto invalid;
			if (imm < 0 && address[0] == ARG_ADDRESS_1_POST_I)
				goto invalid;
		}
		if (ld) {
			switch (size) {
				case OP_SIZE_4:	mc = PARISC_LDW_M; break;
				case OP_SIZE_8:	mc = PARISC_LDD | (address[0] == ARG_ADDRESS_1_PRE_I ? PARISC_LDD_STD_MB : PARISC_LDD_STD_MA); break;
				default:	goto invalid;
			}
		} else {
			switch (size) {
				case OP_SIZE_4:	mc = PARISC_STW_M; break;
				case OP_SIZE_8:	mc = PARISC_STD | (address[0] == ARG_ADDRESS_1_PRE_I ? PARISC_LDD_STD_MB : PARISC_LDD_STD_MA); break;
				default:	goto invalid;
			}
		}
		mc |= low_sign_ext_14(imm);
		g(cgen_2reg(ctx, mc, address[1], reg));
		return true;
	}
	if (address[0] >= ARG_ADDRESS_2 && address[0] <= ARG_ADDRESS_2_8 && ld) {
		imm = get_imm(&address[3]);
		if (unlikely(imm != 0))
			goto invalid;
		mc = PARISC_LD_ST | PARISC_LD_ST_LD;
		if (address[0] == ARG_ADDRESS_2) {
		} else if (address[0] == ARG_ADDRESS_2_4 && size == OP_SIZE_4) {
			mc |= PARISC_LD_SCALE;
		} else if (address[0] == ARG_ADDRESS_2_8 && size == OP_SIZE_8) {
			mc |= PARISC_LD_SCALE;
		} else {
			goto invalid;
		}
		switch (size) {
			case OP_SIZE_1:	mc |= PARISC_LD_ST_B; break;
			case OP_SIZE_2:	mc |= PARISC_LD_ST_H; break;
			case OP_SIZE_4:	mc |= PARISC_LD_ST_W; break;
			case OP_SIZE_8:	mc |= PARISC_LD_ST_D; break;
			default:	goto invalid;
		}
		g(cgen_3reg(ctx, mc, address[2], address[1], reg));
		return true;
	}
invalid:
	internal(file_line, "cgen_ld_st: invalid address: %x, %02x, %02x, %"PRIxMAX"", size, reg, address[0], (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_fp_ld_st(struct codegen_context *ctx, bool ld, unsigned size, uint8_t reg, uint8_t *address)
{
	int64_t imm = 0;
	uint32_t mc;

	if (unlikely(address[0] != ARG_ADDRESS_1))
		goto invalid;

	imm = get_imm(&address[2]);
	if (imm >= -0x10 && imm < 0x10) {
		if (ld)
			mc = size == OP_SIZE_4 ? PARISC_FLDW : PARISC_FLDD;
		else
			mc = size == OP_SIZE_4 ? PARISC_FSTW : PARISC_FSTD;
		mc |= low_sign_ext_5(imm) << 16;
		mc |= reg & 0x1f;
		mc |= (uint32_t)address[1] << 21;
		cgen_four(mc);
		return true;
	} else {
		if (ld)
			mc = size == OP_SIZE_4 ? PARISC_FLDW_LONG : PARISC_FLDD_LONG;
		else
			mc = size == OP_SIZE_4 ? PARISC_FSTW_LONG : PARISC_FSTD_LONG;
		mc |= low_sign_ext_14(imm);
		g(cgen_2reg(ctx, mc, address[1], reg & 0x1f));
		return true;
	}

invalid:
	internal(file_line, "cgen_fp_ld_st: invalid address: %x, %02x, %02x, %"PRIxMAX"", size, reg, address[0], (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_mov_args(struct codegen_context *ctx, unsigned size, uint8_t *arg1, uint8_t *arg2)
{
	int64_t imm;
	uint32_t mc;

	if (arg1[0] < 0x20) {
		if (arg2[0] < 0x20) {
			if (size < OP_SIZE_NATIVE) {
				if (OP_SIZE_NATIVE == OP_SIZE_4) {
					switch (size) {
						case OP_SIZE_1:
							mc = PARISC_EXTRW_U ^ 0x3f8U;
							break;
						case OP_SIZE_2:
							mc = PARISC_EXTRW_U ^ 0x3f0U;
							break;
						default:
							internal(file_line, "cgen_mov_args: invalid op size %u", size);
					}
				} else {
					switch (size) {
						case OP_SIZE_1:
							mc = PARISC_EXTRD_U ^ 0x13f8U;
							break;
						case OP_SIZE_2:
							mc = PARISC_EXTRD_U ^ 0x13f0U;
							break;
						case OP_SIZE_4:
							mc = PARISC_EXTRD_U ^ 0x13e0U;
							break;
						default:
							internal(file_line, "cgen_mov_args: invalid op size %u", size);
					}
				}
				g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
				return true;
			}
			g(cgen_3reg(ctx, PARISC_OR, arg2[0], 0, arg1[0]));
			return true;
		}
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (imm >= -0x2000 && imm < 0x2000) {
				mc = PARISC_LDO;
				mc |= low_sign_ext_14(imm);
				g(cgen_2reg(ctx, mc, R_ZERO, arg1[0]));
				return true;
			}
			if (imm & 0x7ff)
				goto invalid;
			mc = PARISC_LDIL;
			mc |= (uint32_t)arg1[0] << 21;
			mc |= assemble_21((uint64_t)imm >> 11);
			cgen_four(mc);
			return true;
		}
		return cgen_ld_st(ctx, true, size, arg1[0], arg2);
	}

	if (arg2[0] < 0x20) {
		return cgen_ld_st(ctx, false, size, arg2[0], arg1);
	}
	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		if (unlikely(imm != 0))
			goto invalid;
		return cgen_ld_st(ctx, false, size, R_ZERO, arg1);
	}

	if (reg_is_fp(arg1[0]) && arg2[0] == ARG_ADDRESS_1) {
		return cgen_fp_ld_st(ctx, true, size, arg1[0], arg2);
	}
	if (reg_is_fp(arg2[0]) && arg1[0] == ARG_ADDRESS_1) {
		return cgen_fp_ld_st(ctx, false, size, arg2[0], arg1);
	}
	if (reg_is_fp(arg1[0]) && reg_is_fp(arg2[0])) {
		mc = PARISC_FCPY;
		switch (size) {
			case OP_SIZE_4:		break;
			case OP_SIZE_8:		mc |= PARISC_FP_DOUBLE; break;
			default:		internal(file_line, "cgen_fp_alu: invalid size %u", size);
		}
		g(cgen_3reg(ctx, mc, 0, arg2[0] & 0x1f, arg1[0] & 0x1f));
		return true;
	}

invalid:
	internal(file_line, "cgen_mov_args: invalid arguments %02x, %02x", arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	return cgen_mov_args(ctx, size, arg1, arg2);
}

static bool attr_w cgen_movsx(struct codegen_context *ctx, unsigned size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (unlikely(arg1[0] >= 0x20) || unlikely(arg2[0] >= 0x20))
		internal(file_line, "cgen_movsx: invalid arguments %02x, %02x", arg1[0], arg2[0]);

	if (size < OP_SIZE_NATIVE) {
		if (OP_SIZE_NATIVE == OP_SIZE_4) {
			switch (size) {
				case OP_SIZE_1:
					mc = PARISC_EXTRW_S ^ 0x3f8U;
					break;
				case OP_SIZE_2:
					mc = PARISC_EXTRW_S ^ 0x3f0U;
					break;
				default:
					internal(file_line, "cgen_movsx: invalid op size %u", size);
			}
		} else {
			switch (size) {
				case OP_SIZE_1:
					mc = PARISC_EXTRD_S ^ 0x13f8U;
					break;
				case OP_SIZE_2:
					mc = PARISC_EXTRD_S ^ 0x13f0U;
					break;
				case OP_SIZE_4:
					mc = PARISC_EXTRD_S ^ 0x13e0U;
					break;
				default:
					internal(file_line, "cgen_movsx: invalid op size %u", size);
			}
		}
		g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
		return true;
	} else {
		return cgen_mov_args(ctx, size, arg1, arg2);
	}
}

static bool attr_w cgen_cmp_dest_reg(struct codegen_context *ctx, unsigned size, unsigned cond)
{
	int32_t fc;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg3[0] == ARG_IMM) {
		cond = cmp_swap_arguments(cond);
	}

	fc = cmp_sub_cond[cond];
	fc ^= PARISC_COND_NEG;

	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		mc = PARISC_CMPICLR;
		if (size == OP_SIZE_8)
			mc |= PARISC_CMPICLR_64;
		mc |= fc;
		mc |= low_sign_ext_11(imm);
		g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
	} else {
		mc = PARISC_CMPCLR;
		if (size == OP_SIZE_8)
			mc |= PARISC_COND_64;
		mc |= fc;
		g(cgen_3reg(ctx, mc, arg2[0], arg3[0], arg1[0]));
	}

	mc = PARISC_LDO;
	mc |= low_sign_ext_14(1);
	g(cgen_2reg(ctx, mc, R_ZERO, arg1[0]));

	return true;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned writes_flags, unsigned alu, bool trap, unsigned length)
{
	uint32_t mc;
	unsigned r1, r2, rt;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(arg1[0] >= 0x20) || unlikely(arg2[0] >= 0x20))
		goto invalid;

	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		if (unlikely(writes_flags))
			goto invalid;
		if (!trap) {
			if (alu == ALU_SUB)
				imm = -(uint64_t)imm;
			else if (unlikely(alu != ALU_ADD))
				goto invalid;
			if (imm >= -0x2000 && imm < 0x2000) {
				mc = PARISC_LDO;
				mc |= low_sign_ext_14(imm);
				g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
				return true;
			} else if (!(imm & 0x7ff) && arg1[0] == R_1) {
				mc = PARISC_ADDIL;
				mc |= (uint32_t)arg2[0] << 21;
				mc |= assemble_21((uint64_t)imm >> 11);
				cgen_four(mc);
				return true;
			} else {
				goto invalid;
			}
		} else {
			if (alu == ALU_SUB)
				imm = -(uint64_t)imm;
			else if (unlikely(alu != ALU_ADD))
				goto invalid;
			if (size == OP_SIZE_8) {
				mc = PARISC_LDO;
				mc |= low_sign_ext_14(imm);
				g(cgen_2reg(ctx, mc, R_ZERO, R_CG_SCRATCH));

				mc = PARISC_ADD;
				r1 = arg2[0];
				r2 = R_CG_SCRATCH;
				rt = arg1[0];
			} else {
				mc = PARISC_ADDI;
				mc |= low_sign_ext_11(imm);
				r1 = arg1[0];
				r2 = arg2[0];
				rt = 0;
			}
			goto do_op;
		}
	}

	switch (alu) {
		case ALU_ADD:	mc = writes_flags ? PARISC_ADD : PARISC_ADD_L;
				break;
		case ALU_OR:	ajla_assert_lo(!writes_flags, (file_line, "cgen_alu: or must not write flags"));
				mc = PARISC_OR;
				break;
		case ALU_ADC:	ajla_assert_lo(writes_flags, (file_line, "cgen_alu: adc must write flags"));
				mc = size == OP_SIZE_4 ? PARISC_ADD_C : PARISC_ADD_DC;
				break;
		case ALU_SBB:	ajla_assert_lo(writes_flags, (file_line, "cgen_alu: sbb must write flags"));
				mc = size == OP_SIZE_4 ? PARISC_SUB_B : PARISC_SUB_DB;
				break;
		case ALU_AND:	ajla_assert_lo(!writes_flags, (file_line, "cgen_alu: and must not write flags"));
				mc = PARISC_AND;
				break;
		case ALU_SUB:	ajla_assert_lo(writes_flags, (file_line, "cgen_alu: sub must write flags"));
				mc = PARISC_SUB;
				break;
		case ALU_XOR:	ajla_assert_lo(!writes_flags, (file_line, "cgen_alu: xor must not write flags"));
				mc = PARISC_XOR;
				break;
		case ALU_ANDN:	ajla_assert_lo(!writes_flags, (file_line, "cgen_alu: andn must not write flags"));
				mc = PARISC_ANDCM;
				break;
		default:	goto invalid;
	}

	if (alu == ALU_ADD && arg3[0] == ARG_SHIFTED_REGISTER) {
		uint8_t *args;
		if (unlikely((arg3[1] >> 6) != 0))
			goto invalid;
		if (unlikely((arg3[1] & ARG_SHIFT_AMOUNT)) >= 4)
			goto invalid;
		mc |= (uint32_t)(arg3[1] & ARG_SHIFT_AMOUNT) << 6;
		arg3 += 2;
		args = arg3;
		arg3 = arg2;
		arg2 = args;
	}

	if (unlikely(arg3[0] >= 0x20))
		goto invalid;

#ifdef ARCH_PARISC32
	if (alu == ALU_ADD && size == OP_SIZE_4 && arg1[0] == arg2[0] && trap && length == JMP_SHORTEST) {
		bool known;
		mc = PARISC_ADDB;
		mc |= PARISC_COND_SV;
		mc |= PARISC_N;
		g(add_relocation(ctx, JMP_SHORTEST, ctx->code_position - arg1, &known));
		g(cgen_2reg(ctx, mc, arg1[0], arg3[0]));
		if (unlikely(!known))
			cgen_four(PARISC_NOP);
		return true;
	}
#endif

	r1 = arg2[0];
	r2 = arg3[0];
	rt = arg1[0];

do_op:
	if (trap) {
		if (length == JMP_EXTRA_LONG || (length == JMP_LONG && !PA_20))
			mc |= PARISC_COND_SV;
		else
			mc |= PARISC_COND_NSV;
		if (size == OP_SIZE_8)
			mc |= PARISC_COND_64;
	}

	g(cgen_3reg(ctx, mc, r1, r2, rt));

	if (trap) {
		if (length <= JMP_SHORT) {
			g(add_relocation(ctx, JMP_SHORT, ctx->code_position - arg1, NULL));
			cgen_four(PARISC_BL | PARISC_N);
		} else if (length == JMP_LONG && PA_20) {
			g(add_relocation(ctx, JMP_LONG, ctx->code_position - arg1, NULL));
			cgen_four(PARISC_BL_L | PARISC_N);
		} else {
			cgen_four(PARISC_BL | PARISC_N | assemble_12(3));
			g(add_relocation(ctx, JMP_EXTRA_LONG, ctx->code_position - arg1, NULL));
			cgen_four(PARISC_LDIL | ((uint32_t)R_CG_SCRATCH << 21));
			g(cgen_2reg(ctx, PARISC_LDO, R_CG_SCRATCH, R_CG_SCRATCH));
			g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
			g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
		}
	}

	return true;

invalid:
	internal(file_line, "cgen_alu: invalid arguments %02x, %02x, %02x, %u, %u, %u", arg1[0], arg2[0], arg3[0], alu, writes_flags, (unsigned)trap);
	return false;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned writes_flags, unsigned alu, bool trap, unsigned length)
{
	uint32_t mc;
	unsigned r1, r2, rt;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (unlikely(arg1[0] >= 0x20) || unlikely(arg2[0] >= 0x20))
		goto invalid;

	switch (alu) {
		case ALU1_NOT:	ajla_assert_lo(!writes_flags, (file_line, "cgen_alu1: not must not write flags"));
				mc = PARISC_UADDCM;
				r1 = R_ZERO;
				r2 = arg2[0];
				rt = arg1[0];
				break;
		case ALU1_NEG:	ajla_assert_lo(writes_flags, (file_line, "cgen_alu1: neg must write flags"));
				mc = PARISC_SUB;
				r1 = R_ZERO;
				r2 = arg2[0];
				rt = arg1[0];
				break;
		default:	goto invalid;
	}

	if (trap) {
		if (length == JMP_EXTRA_LONG || (length == JMP_LONG && !PA_20))
			mc |= PARISC_COND_SV;
		else
			mc |= PARISC_COND_NSV;
		if (size == OP_SIZE_8)
			mc |= PARISC_COND_64;
	}

	g(cgen_3reg(ctx, mc, r1, r2, rt));

	if (trap) {
		if (length <= JMP_SHORT) {
			g(add_relocation(ctx, JMP_SHORT, ctx->code_position - arg1, NULL));
			cgen_four(PARISC_BL | PARISC_N);
		} else if (length == JMP_LONG && PA_20) {
			g(add_relocation(ctx, JMP_LONG, ctx->code_position - arg1, NULL));
			cgen_four(PARISC_BL_L | PARISC_N);
		} else {
			cgen_four(PARISC_BL | PARISC_N | assemble_12(3));
			g(add_relocation(ctx, JMP_EXTRA_LONG, ctx->code_position - arg1, NULL));
			cgen_four(PARISC_LDIL | ((uint32_t)R_CG_SCRATCH << 21));
			g(cgen_2reg(ctx, PARISC_LDO, R_CG_SCRATCH, R_CG_SCRATCH));
			g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
			g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
		}
	}

	return true;

invalid:
	internal(file_line, "cgen_alu1: invalid arguments %02x, %02x, %u, %u", arg1[0], arg2[0], alu, writes_flags);
	return false;
}

static bool attr_w cgen_sar(struct codegen_context *ctx, bool sar_complement, uint8_t reg)
{
	uint32_t mc;
	if (!sar_complement) {
		mc = PARISC_MTSAR;
		mc |= (uint32_t)reg << 16;
		cgen_four(mc);
	} else if (PA_20) {
		mc = PARISC_MTSARCM;
		mc |= (uint32_t)reg << 16;
		cgen_four(mc);
	} else {
		mc = PARISC_LDO;
		mc |= low_sign_ext_14(-1);
		g(cgen_2reg(ctx, mc, 0, R_CG_SCRATCH));
		mc = PARISC_XOR;
		g(cgen_3reg(ctx, mc, R_CG_SCRATCH, reg, R_CG_SCRATCH));
		mc = PARISC_MTSAR;
		mc |= (uint32_t)R_CG_SCRATCH << 16;
		cgen_four(mc);
	}
	return true;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, unsigned rot)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		unsigned sh = imm & (size == OP_SIZE_4 ? 31 : 63);
		if (size == OP_SIZE_4) {
			switch (rot) {
				case ROT_SHL:
					mc = PARISC_DEPW_Z;
					mc |= sh | (sh << 5);
					break;
				case ROT_SHR:
					mc = PARISC_EXTRW_U;
					mc |= sh | ((31 - sh) << 5);
					break;
				case ROT_SAR:
					mc = PARISC_EXTRW_S;
					mc |= sh | ((31 - sh) << 5);
					break;
				default:
					goto invalid;
			}
		} else {
			switch (rot) {
				case ROT_SHL:
					mc = PARISC_DEPD_Z;
					mc |= (sh & 31) | ((sh & 31) << 5);
					if (sh & 32)
						mc ^= 0x1800;
					break;
				case ROT_SHR:
					mc = PARISC_EXTRD_U;
					mc |= (sh & 31) | ((31 - (sh & 31)) << 5);
					if (sh & 32)
						mc ^= 0x1800;
					break;
				case ROT_SAR:
					mc = PARISC_EXTRD_S;
					mc |= (sh & 31) | ((31 - (sh & 31)) << 5);
					if (sh & 32)
						mc ^= 0x1800;
					break;
				default:
					goto invalid;
			}
		}
		if (rot == ROT_SHL)
			g(cgen_2reg(ctx, mc, arg1[0], arg2[0]));
		else
			g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
		return true;
	} else if (arg3[0] < 0x20) {
		bool sar_complement = rot != ROT_SHR;
		g(cgen_sar(ctx, sar_complement, arg3[0]));
		if (size == OP_SIZE_4) {
			switch (rot) {
				case ROT_SHL:
					mc = PARISC_DEPW_Z_SAR;
					break;
				case ROT_SHR:
					mc = PARISC_SHRPW_SAR;
					break;
				case ROT_SAR:
					mc = PARISC_EXTRW_S_SAR;
					break;
				default:
					goto invalid;
			}
		} else {
			switch (rot) {
				case ROT_SHL:
					mc = PARISC_DEPD_Z_SAR | 0x100;
					break;
				case ROT_SHR:
					mc = PARISC_SHRPD_SAR;
					break;
				case ROT_SAR:
					mc = PARISC_EXTRD_S_SAR | 0x100;
					break;
				default:
					goto invalid;
			}
		}
		if (rot == ROT_SHL) {
			g(cgen_2reg(ctx, mc, arg1[0], arg2[0]));
		} else if (rot == ROT_SHR) {
			g(cgen_3reg(ctx, mc, R_ZERO, arg2[0], arg1[0]));
		} else {
			g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
		}
		return true;
	}

invalid:
	internal(file_line, "cgen_rot: invalid arguments %02x, %02x, %02x, %u, %u", arg1[0], arg2[0], arg3[0], size, rot);
	return false;
}

static bool attr_w cgen_btx(struct codegen_context *ctx, unsigned size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (aux == BTX_BTS || aux == BTX_BTR) {
		if (arg1[0] != arg2[0]) {
			g(cgen_3reg(ctx, PARISC_OR, arg2[0], 0, arg1[0]));
		}
	}

	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		unsigned bit = imm & (size == OP_SIZE_4 ? 31 : 63);
		if (size == OP_SIZE_4) {
			switch (aux) {
				case BTX_BTS:
				case BTX_BTR:
					mc = PARISC_DEPWI;
					mc |= 31U | (bit << 5);
					g(cgen_2reg(ctx, mc, arg1[0], low_sign_ext_5(aux == BTX_BTS)));
					return true;
				case BTX_BTEXT:
					mc = PARISC_EXTRW_U;
					mc |= 31U | ((31 - bit) << 5);
					g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
					return true;
				default:
					goto invalid;
			}
		} else {
			switch (aux) {
				case BTX_BTS:
				case BTX_BTR:
					mc = PARISC_DEPDI;
					mc |= 31U | ((bit & 0x1f) << 5) | ((bit & 0x20) << 6);
					g(cgen_2reg(ctx, mc, arg1[0], low_sign_ext_5(aux == BTX_BTS)));
					return true;
				case BTX_BTEXT:
					mc = PARISC_EXTRD_U;
					mc ^= 31U | 0x1000 | (((63 - bit) & 0x1f) << 5) | ((bit & 0x20) << 6);
					g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
					return true;
				default:
					goto invalid;
			}
		}
	} else {
		g(cgen_sar(ctx, true, arg3[0]));
		if (size == OP_SIZE_4) {
			switch (aux) {
				case BTX_BTS:
				case BTX_BTR:
					mc = PARISC_DEPWI_SAR;
					mc |= 31U;
					g(cgen_2reg(ctx, mc, arg1[0], low_sign_ext_5(aux == BTX_BTS)));
					return true;
				case BTX_BTEXT:
					mc = PARISC_EXTRW_U_SAR;
					mc |= 31U;
					g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
					return true;
				default:
					goto invalid;
			}
		} else {
			switch (aux) {
				case BTX_BTS:
				case BTX_BTR:
					mc = PARISC_DEPDI_SAR;
					mc |= 31U;
					g(cgen_2reg(ctx, mc, arg1[0], low_sign_ext_5(aux == BTX_BTS)));
					return true;
				case BTX_BTEXT:
					mc = PARISC_EXTRD_U_SAR;
					mc |= 31U;
					g(cgen_2reg(ctx, mc, arg2[0], arg1[0]));
					return true;
				default:
					goto invalid;
			}
		}
	}

invalid:
	internal(file_line, "cgen_btx: invalid arguments %02x, %02x, %02x, %u, %u", arg1[0], arg2[0], arg3[0], size, aux);
	return false;
}

static bool attr_w cgen_cmp_cmov(struct codegen_context *ctx, unsigned op_size, unsigned cond)
{
	int32_t fc;
	uint32_t mc;
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	uint8_t *arg5 = arg4 + arg_size(*arg4);
	ctx->code_position = arg5 + arg_size(*arg5);

	if (arg3[0] == ARG_IMM) {
		cond = cmp_swap_arguments(cond);
	}

	fc = cmp_sub_cond[cond];
	fc ^= PARISC_COND_NEG;

	if (arg5[0] == ARG_IMM) {
		imm = get_imm(&arg5[1]);
		mc = PARISC_CMPICLR;
		mc |= fc;
		mc |= low_sign_ext_11(imm);
		g(cgen_2reg(ctx, mc, arg4[0], R_ZERO));
	} else {
		mc = PARISC_CMPCLR;
		mc |= fc;
		g(cgen_3reg(ctx, mc, arg4[0], arg5[0], R_ZERO));
	}

	g(cgen_mov_args(ctx, op_size, arg1, arg3));

	return true;
}

static bool attr_w cgen_movr(struct codegen_context *ctx, unsigned cond)
{
	int32_t fc;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);

	fc = cmp_sub_cond[cond];
	fc ^= PARISC_COND_NEG;

	if (unlikely(arg1[0] != arg2[0]) || unlikely(arg1[0] >= 0x20))
		internal(file_line, "cgen_movr: invalid arguments");

	mc = PARISC_ADD_L;
	mc |= fc;
	if (OP_SIZE_NATIVE == OP_SIZE_8)
		mc |= PARISC_COND_64;

	g(cgen_3reg(ctx, mc, R_ZERO, arg3[0], R_ZERO));

	g(cgen_mov_args(ctx, OP_SIZE_NATIVE, arg1, arg4));

	return true;
}

static bool attr_w cgen_fp_cmp_cond(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	unsigned cond;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_COND_P:		cond = PARISC_FCMP_P; break;
		case FP_COND_NP:	cond = PARISC_FCMP_NP; break;
		case FP_COND_E:		cond = PARISC_FCMP_E; break;
		case FP_COND_NE:	cond = PARISC_FCMP_NE; break;
		case FP_COND_A:		cond = PARISC_FCMP_A; break;
		case FP_COND_BE:	cond = PARISC_FCMP_BE; break;
		case FP_COND_B:		cond = PARISC_FCMP_B; break;
		case FP_COND_AE:	cond = PARISC_FCMP_AE; break;
		default:		internal(file_line, "cgen_fp_cmp_cond: invalid condition %u", aux);
					return false;
	}
	mc = PARISC_FCMP;
	if (op_size == OP_SIZE_8)
		mc |= PARISC_FP_DOUBLE;
	g(cgen_3reg(ctx, mc, arg1[0] & 0x1f, arg2[0] & 0x1f, cond));
	return true;
}

static bool attr_w cgen_fp_test_reg(struct codegen_context *ctx)
{
	unsigned reg = cget_one(ctx);
	uint32_t mc;

	mc = PARISC_LDO;
	mc |= low_sign_ext_14(1);
	g(cgen_2reg(ctx, mc, R_ZERO, reg));

	cgen_four(PARISC_FTEST);

	mc = PARISC_LDO;
	mc |= low_sign_ext_14(0);
	g(cgen_2reg(ctx, mc, R_ZERO, reg));

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
		case FP_ALU_ADD:	mc = PARISC_FADD; break;
		case FP_ALU_SUB:	mc = PARISC_FSUB; break;
		case FP_ALU_MUL:	mc = PARISC_FMPY; break;
		case FP_ALU_DIV:	mc = PARISC_FDIV; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= PARISC_FP_DOUBLE; break;
		default:		internal(file_line, "cgen_fp_alu: invalid size %u", op_size);
	}
	g(cgen_3reg(ctx, mc, arg3[0] & 0x1f, arg2[0] & 0x1f, arg1[0] & 0x1f));
	return true;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	mc = PARISC_FNEG; break;
		case FP_ALU1_SQRT:	mc = PARISC_FSQRT; break;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= PARISC_FP_DOUBLE; break;
		default:		internal(file_line, "cgen_fp_alu: invalid size %u", op_size);
	}
	g(cgen_3reg(ctx, mc, 0, arg2[0] & 0x1f, arg1[0] & 0x1f));
	return true;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	mc = PARISC_FCNVFXT;
	if (int_op_size == OP_SIZE_8)
		mc |= PARISC_FCNVFXT_TO_LONG;
	if (fp_op_size == OP_SIZE_8)
		mc |= PARISC_FCNVFXT_FROM_DOUBLE;
	mc |= arg1[0] & 0x1f;
	mc |= (uint32_t)(arg2[0] & 0x1f) << 21;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	mc = PARISC_FCNVXF;
	if (int_op_size == OP_SIZE_8)
		mc |= PARISC_FCNVXF_FROM_LONG;
	if (fp_op_size == OP_SIZE_8)
		mc |= PARISC_FCNVXF_TO_DOUBLE;
	mc |= arg1[0] & 0x1f;
	mc |= (uint32_t)(arg2[0] & 0x1f) << 21;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_cond_jmp(struct codegen_context *ctx, uint32_t mc, unsigned length, unsigned reg1, unsigned reg2, int reloc_offset)
{
	if (length == JMP_SHORTEST) {
		bool known;
		mc |= PARISC_N;
		g(add_relocation(ctx, JMP_SHORTEST, reloc_offset, &known));
		g(cgen_2reg(ctx, mc, reg2, reg1));
		if (unlikely(!known))
			cgen_four(PARISC_NOP);
	} else if (length == JMP_SHORT) {
		mc |= PARISC_N;
		g(cgen_2reg(ctx, mc, reg2, reg1));
		g(add_relocation(ctx, JMP_SHORT, reloc_offset, NULL));
		cgen_four(PARISC_BL | PARISC_N);
	} else if (length == JMP_LONG && PA_20) {
		mc |= PARISC_N;
		g(cgen_2reg(ctx, mc, reg2, reg1));
		g(add_relocation(ctx, JMP_LONG, reloc_offset, NULL));
		cgen_four(PARISC_BL_L | PARISC_N);
	} else {
		mc |= PARISC_N;
		mc |= assemble_12(3);
		g(cgen_2reg(ctx, mc, reg2, reg1));
		g(add_relocation(ctx, JMP_EXTRA_LONG, reloc_offset, NULL));
		cgen_four(PARISC_LDIL | ((uint32_t)R_CG_SCRATCH << 21));
		g(cgen_2reg(ctx, PARISC_LDO, R_CG_SCRATCH, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
	}
	return true;
}

static bool attr_w cgen_jmp_12regs(struct codegen_context *ctx, unsigned size, unsigned cond, unsigned length, unsigned reg1, unsigned reg2, int reloc_offset)
{
	int32_t fc;
	uint32_t mc;
	fc = cmp_sub_cond[cond];
	if (length > JMP_SHORTEST)
		fc ^= PARISC_COND_NEG;
	if (size == OP_SIZE_4)
		mc = !(fc & PARISC_COND_NEG) ? PARISC_CMPB : PARISC_CMPB_NOT;
	else
		mc = !(fc & PARISC_COND_NEG) ? PARISC_CMPB_64 : PARISC_CMPB_64_NOT;
	mc |= ((uint32_t)fc & ~PARISC_COND_NEG);
	g(cgen_cond_jmp(ctx, mc, length, reg1, reg2, reloc_offset));
	return true;
}

static bool attr_w cgen_jmp(struct codegen_context *ctx, unsigned length)
{
	if (length <= JMP_SHORT) {
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
		cgen_four(PARISC_BL | PARISC_N);
	} else if (length == JMP_LONG && PA_20) {
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_four(PARISC_BL_L | PARISC_N);
	} else {
		g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
		cgen_four(PARISC_LDIL | ((uint32_t)R_CG_SCRATCH << 21));
		g(cgen_2reg(ctx, PARISC_LDO, R_CG_SCRATCH, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
	}
	return true;
}

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned size, unsigned cond, unsigned length)
{
	unsigned reg = cget_one(ctx);
	return cgen_jmp_12regs(ctx, size, cond, length, reg, 0, 1);
}

static bool attr_w cgen_jmp_reg_bit(struct codegen_context *ctx, unsigned size, unsigned bit, bool jnz, unsigned length)
{
	uint32_t mc;
	unsigned reg = cget_one(ctx);
	if (length > JMP_SHORTEST)
		jnz = !jnz;
	if (size == OP_SIZE_4 || bit < 32) {
		bit = 31 - bit;
		mc = jnz ? PARISC_BB_1 : PARISC_BB_0;
	} else {
		bit = 63 - bit;
		mc = jnz ? PARISC_BB_64_1 : PARISC_BB_64_0;
	}
	g(cgen_cond_jmp(ctx, mc, length, reg, bit, 1));
	return true;
}

static bool attr_w cgen_jmp_2regs(struct codegen_context *ctx, unsigned size, unsigned cond, unsigned length)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg2[0] < 0x20)
		return cgen_jmp_12regs(ctx, size, cond, length, arg1[0], arg2[0], 2);
	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		uint32_t mc;
		int32_t fc;
		cond = cmp_swap_arguments(cond);
		fc = cmp_sub_cond[cond];
		if (length > JMP_SHORTEST)
			fc ^= PARISC_COND_NEG;
		if (size == OP_SIZE_4) {
			mc = fc & PARISC_COND_NEG ? PARISC_CMPIB_NOT : PARISC_CMPIB;
			mc |= fc & ~PARISC_COND_NEG;
		} else {
			mc = PARISC_CMPIB_64;
			switch (fc) {
				case PARISC_COND_EQUAL:		mc |= 1 << 13; break;
				case PARISC_COND_NOT_EQUAL:	mc |= 5 << 13; break;
				case PARISC_COND_L_S:		mc |= 2 << 13; break;
				case PARISC_COND_GE_S:		mc |= 6 << 13; break;
				case PARISC_COND_LE_S:		mc |= 3 << 13; break;
				case PARISC_COND_G_S:		mc |= 7 << 13; break;
				case PARISC_COND_L_U:		mc |= 0 << 13; break;
				case PARISC_COND_GE_U:		mc |= 4 << 13; break;
				default:	internal(file_line, "cgen_jmp_2regs: unsupported condition %x", fc);
			}
		}
		g(cgen_cond_jmp(ctx, mc, length, low_sign_ext_5(imm), arg1[0], 10));
		return true;
	}
	internal(file_line, "cgen_jmp_2regs: invalid arguments %02x, %02x", arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_jmp_fp_test(struct codegen_context *ctx, unsigned length)
{
	cgen_four(PARISC_FTEST);
	if (length <= JMP_SHORT) {
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
		cgen_four(PARISC_BL | PARISC_N);
	} else if (length == JMP_LONG && PA_20) {
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_four(PARISC_BL_L | PARISC_N);
	} else {
		cgen_four(PARISC_BL | PARISC_N | assemble_12(0));
		cgen_four(PARISC_BL | PARISC_N | assemble_12(3));
		g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
		cgen_four(PARISC_LDIL | ((uint32_t)R_CG_SCRATCH << 21));
		g(cgen_2reg(ctx, PARISC_LDO, R_CG_SCRATCH, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
		g(cgen_2reg(ctx, PARISC_BLR | PARISC_N, R_ZERO, R_CG_SCRATCH));
	}
	return true;
}

static bool attr_w cgen_jmp_indirect(struct codegen_context *ctx, unsigned reg)
{
	uint32_t mc;
#ifdef ARCH_PARISC32
	if (PA_20) {
		if (PA_SPACES) {
			mc = PARISC_BVE_RET;
			mc |= (uint32_t)reg << 21;
			cgen_four(mc);
			mc = PARISC_STW_LONG;
			mc |= low_sign_ext_14(-0x18);
			g(cgen_2reg(ctx, mc, R_SP, R_RP));
		} else {
			mc = PARISC_BVE_RET;
			mc |= (uint32_t)reg << 21;
			mc |= PARISC_N;
			cgen_four(mc);
		}
	} else {
		if (PA_SPACES) {
			mc = PARISC_LDSID;
			mc |= (uint32_t)reg << 21;
			mc |= R_CG_SCRATCH;
			cgen_four(mc);
			mc = PARISC_MTSP;
			mc |= (uint32_t)R_CG_SCRATCH << 16;
			cgen_four(mc);
			mc = PARISC_BE;
			mc |= (uint32_t)reg << 21;
			cgen_four(mc);
			mc = PARISC_STW_LONG;
			mc |= low_sign_ext_14(-0x18);
			g(cgen_2reg(ctx, mc, R_SP, R_RP));
		} else {
			mc = PARISC_BV;
			mc |= (uint32_t)reg << 21;
			mc |= PARISC_N;
			cgen_four(mc);
		}
	}
#else
	mc = PARISC_BV;
	mc |= (uint32_t)reg << 21;
	mc |= PARISC_N;
	cgen_four(mc);
#endif
	if (unlikely(!ctx->fn))
		cgen_four(PARISC_NOP);
	return true;
}

static bool attr_w cgen_call_millicode(struct codegen_context attr_unused *ctx)
{
#ifdef ARCH_PARISC32
	uint32_t mc;
	unsigned reg = R_SCRATCH_NA_1;
	unsigned bit;

	mc = PARISC_BB_0;
	bit = 31 - 1;
	mc |= assemble_12(1);
	mc |= PARISC_N;
	g(cgen_2reg(ctx, mc, bit, reg));

	mc = PARISC_LD_ST;
	mc |= PARISC_LD_ST_W;
	mc |= PARISC_LD_ST_IMM;
	mc |= PARISC_LD_ST_LD;
	g(cgen_3reg(ctx, mc, low_sign_ext_5(2), reg, R_19));
	g(cgen_3reg(ctx, mc, low_sign_ext_5(-2), reg, reg));

	g(cgen_jmp_indirect(ctx, reg));
#endif
	return true;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	uint32_t mc4[4];
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 2) - (int64_t)(reloc->position >> 2) - 2;
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x800) || unlikely(offs >= 0x800))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x00001ffdU;
			mc |= assemble_12(offs);
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_SHORT:
			if (unlikely(offs < -0x10000) || unlikely(offs >= 0x10000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x001f1ffdU;
			mc |= assemble_17(offs);
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_LONG:
			if (unlikely(offs < -0x200000) || unlikely(offs >= 0x200000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x03ff1ffdU;
			mc |= assemble_22(offs);
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_EXTRA_LONG:
			offs -= 2;
			if (unlikely(offs != (int32_t)offs))
				return false;
			memcpy(&mc4, ctx->mcode + reloc->position, 16);
			mc4[0] &= ~0x001fffffU;
			mc4[0] |= assemble_21((uint64_t)offs >> 1 >> 11);
			mc4[1] &= ~0x00003fffU;
			mc4[1] |= low_sign_ext_14(((uint64_t)offs >> 1) & 0x7ff);
			if (offs & 1)
				mc4[2] = PARISC_NOP;
			else
				mc4[3] = PARISC_NOP;
			memcpy(ctx->mcode + reloc->position, &mc4, 16);
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	/*debug("insn: %08x", insn);*/
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			g(cgen_ret(ctx));
			return true;
		case INSN_CALL:
			g(cgen_call(ctx, insn_jump_size(insn)));
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_call_indirect(ctx));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn)));
			return true;
		case INSN_MOVSX:
			g(cgen_movsx(ctx, insn_op_size(insn)));
			return true;
		case INSN_CMP_DEST_REG:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_cmp_dest_reg(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ALU:
		case INSN_ALU_FLAGS:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_writes_flags(insn), insn_aux(insn), false, insn_jump_size(insn)));
			return true;
		case INSN_ALU_TRAP:
		case INSN_ALU_FLAGS_TRAP:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_writes_flags(insn), insn_aux(insn), true, insn_jump_size(insn)));
			return true;
		case INSN_ALU1:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_writes_flags(insn), insn_aux(insn), false, insn_jump_size(insn)));
			return true;
		case INSN_ALU1_TRAP:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_writes_flags(insn), insn_aux(insn), true, insn_jump_size(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4) || unlikely(insn_writes_flags(insn) != 0))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_BTX:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_btx(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_CMP_CMOV:
			if (unlikely(insn_writes_flags(insn) != 0))
				goto invalid_insn;
			g(cgen_cmp_cmov(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_MOVR:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE) || unlikely(insn_writes_flags(insn) != 0))
				goto invalid_insn;
			g(cgen_movr(ctx, insn_aux(insn)));
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
			g(cgen_jmp(ctx, insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_jmp_reg(ctx, insn_op_size(insn), insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG_BIT:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_jmp_reg_bit(ctx, insn_op_size(insn), insn_aux(insn) & 63, insn_aux(insn) >> 6, insn_jump_size(insn)));
			return true;
		case INSN_JMP_2REGS:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_jmp_2regs(ctx, insn_op_size(insn), insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_FP_TEST:
			g(cgen_jmp_fp_test(ctx, insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_indirect(ctx, cget_one(ctx)));
			return true;
		case INSN_CALL_MILLICODE:
			g(cgen_call_millicode(ctx));
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
