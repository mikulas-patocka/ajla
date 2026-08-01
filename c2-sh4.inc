/*
 * Copyright (C) 2026 Mikulas Patocka
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

#define SH4_MOV_B_REG_ADDR2		0x0004
#define SH4_MOV_W_REG_ADDR2		0x0005
#define SH4_MOV_L_REG_ADDR2		0x0006
#define SH4_NOP				0x0009
#define SH4_STS_MACH			0x000a
#define SH4_RTS				0x000b
#define SH4_MOV_B_ADDR2_REG		0x000c
#define SH4_MOV_W_ADDR2_REG		0x000d
#define SH4_MOV_L_ADDR2_REG		0x000e
#define SH4_STC_GBR			0x0012
#define SH4_STS_MACL			0x001a
#define SH4_BRAF			0x0023
#define SH4_MOVT			0x0029
#define SH4_STS_PR			0x002a
#define SH4_STS_FPUL			0x005a
#define SH4_STS_FPSCR			0x006a
#define SH4_MOV_L_REG_DISP_ADDR		0x1000
#define SH4_MOV_B_REG_ADDR		0x2000
#define SH4_MOV_W_REG_ADDR		0x2001
#define SH4_MOV_L_REG_ADDR		0x2002
#define SH4_MOV_B_REG_DEC_ADDR		0x2004
#define SH4_MOV_W_REG_DEC_ADDR		0x2005
#define SH4_MOV_L_REG_DEC_ADDR		0x2006
#define SH4_TST				0x2008
#define SH4_AND				0x2009
#define SH4_XOR				0x200a
#define SH4_OR				0x200b
#define SH4_CMP_EQ			0x3000
#define SH4_CMP_HS			0x3002
#define SH4_CMP_GE			0x3003
#define SH4_CMP_HI			0x3006
#define SH4_CMP_GT			0x3007
#define SH4_SUB				0x3008
#define SH4_SUBV			0x300b
#define SH4_ADD				0x300c
#define SH4_ADDV			0x300f
#define SH4_STS_L_MACH			0x4002
#define SH4_LDS_L_MACH			0x4006
#define SH4_SHLL2			0x4008
#define SH4_SHLR2			0x4009
#define SH4_LDS_MACH			0x400a
#define SH4_JSR				0x400b
#define SH4_SHAD			0x400c
#define SH4_SHLD			0x400d
#define SH4_STS_L_MACL			0x4012
#define SH4_STC_L_GBR			0x4013
#define SH4_LDS_L_MACL			0x4016
#define SH4_LDC_L_GBR			0x4017
#define SH4_SHLL8			0x4018
#define SH4_SHLR8			0x4019
#define SH4_LDS_MACL			0x401a
#define SH4_LDC_GBR			0x401e
#define SH4_STS_L_PR			0x4022
#define SH4_LDS_L_PR			0x4026
#define SH4_SHLL16			0x4028
#define SH4_SHLR16			0x4029
#define SH4_LDS_PR			0x402a
#define SH4_JMP				0x402b
#define SH4_STS_L_FPUL			0x4052
#define SH4_LDS_L_FPUL			0x4056
#define SH4_LDS_FPUL			0x405a
#define SH4_STS_L_FPSCR			0x4062
#define SH4_LDS_L_FPSCR			0x4066
#define SH4_LDS_FPSCR			0x406a
#define SH4_MOV_L_DISP_ADDR_REG		0x5000
#define SH4_MOV_B_ADDR_REG		0x6000
#define SH4_MOV_W_ADDR_REG		0x6001
#define SH4_MOV_L_ADDR_REG		0x6002
#define SH4_MOV_REG_REG			0x6003
#define SH4_MOV_B_ADDR_INC_REG		0x6004
#define SH4_MOV_W_ADDR_INC_REG		0x6005
#define SH4_MOV_L_ADDR_INC_REG		0x6006
#define SH4_NOT				0x6007
#define SH4_SWAP_B			0x6008
#define SH4_SWAP_W			0x6009
#define SH4_NEG				0x600b
#define SH4_EXTU_B			0x600c
#define SH4_EXTU_W			0x600d
#define SH4_EXTS_B			0x600e
#define SH4_EXTS_W			0x600f
#define SH4_ADD_IMM			0x7000
#define SH4_MOV_B_R0_DISP_ADDR		0x8000
#define SH4_MOV_W_R0_DISP_ADDR		0x8100
#define SH4_MOV_B_DISP_ADDR_R0		0x8400
#define SH4_MOV_W_DISP_ADDR_R0		0x8500
#define SH4_CMP_EQ_IMM			0x8800
#define SH4_BT				0x8900
#define SH4_BF				0x8b00
#define SH4_MOV_W_PCREL_REG		0x9000
#define SH4_BRA				0xa000
#define SH4_MOV_B_R0_GBR_DISP		0xc000
#define SH4_MOV_W_R0_GBR_DISP		0xc100
#define SH4_MOV_L_R0_GBR_DISP		0xc200
#define SH4_MOV_B_GBR_DISP_R0		0xc400
#define SH4_MOV_W_GBR_DISP_R0		0xc500
#define SH4_MOV_L_GBR_DISP_R0		0xc600
#define SH4_TST_IMM			0xc800
#define SH4_AND_IMM			0xc900
#define SH4_XOR_IMM			0xca00
#define SH4_OR_IMM			0xcb00
#define SH4_TST_B			0xcc00
#define SH4_AND_B			0xcd00
#define SH4_XOR_B			0xce00
#define SH4_OR_B			0xcf00
#define SH4_MOV_L_PCREL_REG		0xd000
#define SH4_MOV_IMM_REG			0xe000

static uint16_t ctrl_instrs[6][4] = {
	{ SH4_LDS_MACH,		SH4_LDS_L_MACH,		SH4_STS_MACH,		SH4_STS_L_MACH },
	{ SH4_LDS_MACL,		SH4_LDS_L_MACL,		SH4_STS_MACL,		SH4_STS_L_MACL },
	{ SH4_LDS_PR,		SH4_LDS_L_PR,		SH4_STS_PR,		SH4_STS_L_PR },
	{ SH4_LDC_GBR,		SH4_LDC_L_GBR,		SH4_STC_GBR,		SH4_STC_L_GBR },
	{ SH4_LDS_FPSCR,	SH4_LDS_L_FPSCR,	SH4_STS_FPSCR,		SH4_STS_L_FPSCR },
	{ SH4_LDS_FPUL,		SH4_LDS_L_FPUL,		SH4_STS_FPUL,		SH4_STS_L_FPUL },
};

static bool attr_w cgen_moves(struct codegen_context *ctx, unsigned size, bool sx, const uint8_t *arg1, const uint8_t *arg2)
{
	uint16_t mc;
	int64_t imm;

	if (arg1[0] < 0x10 && arg2[0] == ARG_IMM && !sx) {
		bool odd;
		if (!ctx)
			return true;
		imm = get_imm(&arg2[1]);
		if (imm_is_8bit(imm)) {
			mc = SH4_MOV_IMM_REG;
			mc |= arg1[0] << 8;
			mc |= imm & 0xff;
			cgen_two(mc);
			return true;
		}
		if (!(imm & 3) && imm >= -0x200 && imm < 0x200) {
			mc = SH4_MOV_IMM_REG;
			mc |= arg1[0] << 8;
			mc |= (imm / 4) & 0xff;
			cgen_two(mc);
			mc = SH4_SHLL2;
			mc |= arg1[0] << 8;
			cgen_two(mc);
			return true;
		}
		if (imm >= -0x8080 && imm < 0x7f80) {
			int8_t lo = imm & 0xff;
			mc = SH4_MOV_IMM_REG;
			mc |= arg1[0] << 8;
			mc |= ((imm - lo) & 0xffff) >> 8;
			cgen_two(mc);
			mc = SH4_SHLL8;
			mc |= arg1[0] << 8;
			cgen_two(mc);
			if (lo) {
				mc = SH4_ADD_IMM;
				mc |= arg1[0] << 8;
				mc |= lo & 0xff;
				cgen_two(mc);
			}
			return true;
		}
		if (imm_is_16bit(imm)) {
			mc = SH4_MOV_W_PCREL_REG;
			mc |= arg1[0] << 8;
			mc |= 1;
			cgen_two(mc);
			mc = SH4_BRA;
			mc |= 1;
			cgen_two(mc);
			mc = SH4_NOP;
			cgen_two(mc);
			mc = imm;
			cgen_two(mc);
			return true;
		}
		odd = !(ctx->mcode_size & 2);
		mc = SH4_MOV_L_PCREL_REG;
		mc |= arg1[0] << 8;
		mc |= 1;
		cgen_two(mc);
		mc = SH4_BRA;
		mc |= !odd ? 2 : 3;
		cgen_two(mc);
		mc = SH4_NOP;
		cgen_two(mc);
		if (odd) {
			mc = SH4_NOP;
			cgen_two(mc);
		}
		cgen_four(imm);
		return true;
	}

	if (arg1[0] < 0x10 && arg2[0] < 0x10) {
		switch (size) {
			case OP_SIZE_1:
				mc = !sx ? SH4_EXTU_B : SH4_EXTS_B;
				break;
			case OP_SIZE_2:
				mc = !sx ? SH4_EXTU_W : SH4_EXTS_W;
				break;
			case OP_SIZE_4:
				if (unlikely(sx))
					goto invalid;
				mc = SH4_MOV_REG_REG;
				break;
			default:
				goto invalid;
		}
		mc |= arg2[0] << 4;
		mc |= arg1[0] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}
	if ((arg1[0] == ARG_ADDRESS_1 || arg1[0] == ARG_ADDRESS_1_PRE_I) && arg1[1] < 0x10 && arg2[0] < 0x10 && !sx) {
		imm = get_imm(&arg1[2]);
		if (imm == (arg1[0] == ARG_ADDRESS_1 ? 0 : -(1 << size))) {
			switch (size) {
				case OP_SIZE_1:
					mc = arg1[0] == ARG_ADDRESS_1 ? SH4_MOV_B_REG_ADDR : SH4_MOV_B_REG_DEC_ADDR;
					break;
				case OP_SIZE_2:
					mc = arg1[0] == ARG_ADDRESS_1 ? SH4_MOV_W_REG_ADDR : SH4_MOV_W_REG_DEC_ADDR;
					break;
				case OP_SIZE_4:
					mc = arg1[0] == ARG_ADDRESS_1 ? SH4_MOV_L_REG_ADDR : SH4_MOV_L_REG_DEC_ADDR;
					break;
				default:
					goto invalid;
			}
			mc |= arg2[0] << 4;
			mc |= arg1[1] << 8;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (arg1[0] < 0x10 && (arg2[0] == ARG_ADDRESS_1 || arg2[0] == ARG_ADDRESS_1_POST_I) && arg2[1] < 0x10 && sx == (size < OP_SIZE_4)) {
		imm = get_imm(&arg2[2]);
		if (unlikely(imm == (arg2[0] == ARG_ADDRESS_1 ? 0 : 1 << size))) {
			switch (size) {
				case OP_SIZE_1:
					mc = arg2[0] == ARG_ADDRESS_1 ? SH4_MOV_B_ADDR_REG : SH4_MOV_B_ADDR_INC_REG;
					break;
				case OP_SIZE_2:
					mc = arg2[0] == ARG_ADDRESS_1 ? SH4_MOV_W_ADDR_REG : SH4_MOV_W_ADDR_INC_REG;
					break;
				case OP_SIZE_4:
					mc = arg2[0] == ARG_ADDRESS_1 ? SH4_MOV_L_ADDR_REG : SH4_MOV_L_ADDR_INC_REG;
					break;
				default:
					goto invalid;
			}
			mc |= arg2[1] << 4;
			mc |= arg1[0] << 8;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (arg1[0] == ARG_ADDRESS_1 && arg1[1] < 0x10 && arg2[0] == R_0 && size <= OP_SIZE_2 && !sx) {
		imm = get_imm(&arg1[2]);
		if (imm >= 0 && !(imm & ((1 << size) - 1)) && imm >> size < 16) {
			mc = size == OP_SIZE_1 ? SH4_MOV_B_R0_DISP_ADDR : SH4_MOV_W_R0_DISP_ADDR;
			mc |= imm >> size;
			mc |= arg1[1] << 4;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (arg1[0] == ARG_ADDRESS_1 && arg1[1] < 0x10 && arg2[0] < 0x10 && size == OP_SIZE_4 && !sx) {
		imm = get_imm(&arg1[2]);
		if (imm >= 0 && !(imm & 3) && imm >> 2 < 16) {
			mc = SH4_MOV_L_REG_DISP_ADDR;
			mc |= imm >> 2;
			mc |= arg2[0] << 4;
			mc |= arg1[1] << 8;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (arg2[0] == ARG_ADDRESS_1 && arg2[1] < 0x10 && arg1[0] == R_0 && size <= OP_SIZE_2 && sx) {
		imm = get_imm(&arg2[2]);
		if (imm >= 0 && !(imm & ((1 << size) - 1)) && imm >> size < 16) {
			mc = size == OP_SIZE_1 ? SH4_MOV_B_DISP_ADDR_R0 : SH4_MOV_W_DISP_ADDR_R0;
			mc |= imm >> size;
			mc |= arg2[1] << 4;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (arg2[0] == ARG_ADDRESS_1 && arg2[1] < 0x10 && arg1[0] < 0x10 && size == OP_SIZE_4 && !sx) {
		imm = get_imm(&arg2[2]);
		if (imm >= 0 && !(imm & 3) && imm >> 2 < 16) {
			mc = SH4_MOV_L_DISP_ADDR_REG;
			mc |= imm >> 2;
			mc |= arg2[1] << 4;
			mc |= arg1[0] << 8;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (arg1[0] == ARG_ADDRESS_2 && arg1[1] < 0x10 && arg1[2] == R_0 && !get_imm(&arg1[3]) && arg2[0] < 0x10 && !sx) {
		switch (size) {
			case OP_SIZE_1:
				mc = SH4_MOV_B_REG_ADDR2;
				break;
			case OP_SIZE_2:
				mc = SH4_MOV_W_REG_ADDR2;
				break;
			case OP_SIZE_4:
				mc = SH4_MOV_L_REG_ADDR2;
				break;
			default:
				goto invalid;
		}
		mc |= arg2[0] << 4;
		mc |= arg1[1] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}
	if (arg2[0] == ARG_ADDRESS_2 && arg2[1] < 0x10 && arg2[2] == R_0 && !get_imm(&arg2[3]) && arg1[0] < 0x10 && sx == (size < OP_SIZE_4)) {
		switch (size) {
			case OP_SIZE_1:
				mc = SH4_MOV_B_ADDR2_REG;
				break;
			case OP_SIZE_2:
				mc = SH4_MOV_W_ADDR2_REG;
				break;
			case OP_SIZE_4:
				mc = SH4_MOV_L_ADDR2_REG;
				break;
			default:
				goto invalid;
		}
		mc |= arg2[1] << 4;
		mc |= arg1[0] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}
	if (arg1[0] == ARG_ADDRESS_1 && arg1[1] == R_GBR && arg2[0] == R_0 && !sx) {
		imm = get_imm(&arg1[2]);
		if (imm >= 0 && !(imm & ((1 << size) - 1)) && imm >> size < 256) {
			switch (size) {
				case OP_SIZE_1:
					mc = SH4_MOV_B_R0_GBR_DISP;
					break;
				case OP_SIZE_2:
					mc = SH4_MOV_W_R0_GBR_DISP;
					break;
				case OP_SIZE_4:
					mc = SH4_MOV_L_R0_GBR_DISP;
					break;
				default:
					goto invalid;
			}
			mc |= imm >> size;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (arg2[0] == ARG_ADDRESS_1 && arg2[1] == R_GBR && arg1[0] == R_0 && sx == (size < OP_SIZE_4)) {
		imm = get_imm(&arg2[2]);
		if (imm >= 0 && !(imm & ((1 << size) - 1)) && imm >> size < 256) {
			switch (size) {
				case OP_SIZE_1:
					mc = SH4_MOV_B_GBR_DISP_R0;
					break;
				case OP_SIZE_2:
					mc = SH4_MOV_W_GBR_DISP_R0;
					break;
				case OP_SIZE_4:
					mc = SH4_MOV_L_GBR_DISP_R0;
					break;
				default:
					goto invalid;
			}
			mc |= imm >> size;
			if (ctx)
				cgen_two(mc);
			return true;
		}
	}
	if (reg_is_ctrl(arg1[0]) && arg2[0] < 0x10 && !sx) {
		mc = ctrl_instrs[arg1[0] - 0x10][0];
		mc |= arg2[0] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}
	if (reg_is_ctrl(arg1[0]) && arg2[0] == ARG_ADDRESS_1_POST_I && arg2[1] < 0x10 && get_imm(&arg2[2]) == 4 && !sx) {
		mc = ctrl_instrs[arg1[0] - 0x10][1];
		mc |= arg2[1] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}
	if (reg_is_ctrl(arg2[0]) && arg1[0] < 0x10 && !sx) {
		mc = ctrl_instrs[arg2[0] - 0x10][2];
		mc |= arg1[0] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}
	if (reg_is_ctrl(arg2[0]) && arg1[0] == ARG_ADDRESS_1_PRE_I && arg1[1] < 0x10 && get_imm(&arg1[2]) == -4 && !sx) {
		mc = ctrl_instrs[arg2[0] - 0x10][3];
		mc |= arg1[1] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}
	if (arg1[0] < 0x10 && arg2[0] == R_T && !sx) {
		mc = SH4_MOVT;
		mc |= arg1[0] << 8;
		if (ctx)
			cgen_two(mc);
		return true;
	}

invalid:
	if (ctx)
		internal(file_line, "cgen_mov: invalid operands: %02x %02x %u %u", arg1[0], arg2[0], size, !!sx);
	return false;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	return cgen_moves(ctx, size, false, arg1, arg2);
}

static bool attr_w cgen_movsx(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	return cgen_moves(ctx, size, true, arg1, arg2);
}

static bool attr_w cgen_cmp_dest_reg(struct codegen_context *ctx, unsigned cond)
{
	uint16_t mc;
	int64_t imm;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg1[0] == R_T && arg2[0] < 0x10 && arg3[0] < 0x10) {
		switch (cond) {
			case COND_E:
				mc = SH4_CMP_EQ;
				break;
			case COND_AE:
				mc = SH4_CMP_HS;
				break;
			case COND_A:
				mc = SH4_CMP_HI;
				break;
			case COND_GE:
				mc = SH4_CMP_GE;
				break;
			case COND_G:
				mc = SH4_CMP_GT;
				break;
			default:
				goto invalid;
		}
		mc |= arg3[0] << 4;
		mc |= arg2[0] << 8;
		cgen_two(mc);
		return true;
	}
	if (cond == COND_E && arg1[0] == R_T && arg2[0] == R_0 && arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (imm >= 0 && imm < 0x100) {
			mc = SH4_CMP_EQ_IMM;
			mc |= imm & 0xff;
			cgen_two(mc);
			return true;
		}
	}

invalid:
	internal(file_line, "cgen_cmp_dest_reg: invalid operands: %02x %02x %02x %02x", cond, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_test_dest_reg_8(struct codegen_context *ctx, unsigned cond)
{
	uint16_t mc;
	int64_t imm;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (cond == COND_E && arg1[0] == R_T && arg2[0] == ARG_ADDRESS_2 && arg2[1] == R_GBR && arg2[2] == R_0 && !get_imm(&arg2[3]) && arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		mc = SH4_TST_B;
		mc |= imm & 0xff;
		cgen_two(mc);
		return true;
	}

	internal(file_line, "cgen_test_dest_reg_8: invalid operands: %02x %02x %02x %02x", cond, arg1[0], arg2[0], arg3[0]);
	return false;
}


static bool attr_w cgen_test_dest_reg(struct codegen_context *ctx, unsigned cond)
{
	uint16_t mc;
	int64_t imm;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (cond == COND_E && arg1[0] == R_T && arg2[0] < 0x10 && arg3[0] < 0x10) {
		mc = SH4_TST;
		mc |= arg3[0] << 4;
		mc |= arg2[0] << 8;
		cgen_two(mc);
		return true;
	}
	if (cond == COND_E && arg1[0] == R_T && arg2[0] == R_0 && arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (imm >= 0 && imm < 0x100) {
			mc = SH4_TST_IMM;
			mc |= imm & 0xff;
			cgen_two(mc);
			return true;
		}
	}

	internal(file_line, "cgen_test_dest_reg: invalid operands: %02x %02x %02x %02x", cond, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_alu_8(struct codegen_context *ctx, unsigned alu)
{
	uint16_t mc;
	int64_t imm;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg1[0] == ARG_ADDRESS_2 && arg1[1] == R_GBR && arg1[2] == R_0 && !get_imm(&arg1[3]) && arg2[0] == ARG_ADDRESS_2 && arg2[1] == R_GBR && arg2[2] == R_0 && !get_imm(&arg2[3]) && arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		switch (alu) {
			case ALU_AND:
				mc = SH4_AND_B;
				break;
			case ALU_OR:
				mc = SH4_OR_B;
				break;
			case ALU_XOR:
				mc = SH4_XOR_B;
				break;
			default:
				goto invalid;
		}
		mc |= imm & 0xff;
		cgen_two(mc);
		return true;
	}

invalid:
	internal(file_line, "cgen_alu_8: invalid operands: %02x %02x %02x %02x", alu, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned alu)
{
	uint16_t mc;
	int64_t imm;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != arg2[0]) || unlikely(arg1[0] >= 0x10))
		goto invalid;

	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (alu == ALU_SUB) {
			imm = -(uint64_t)imm;
			alu = ALU_ADD;
		}
		if (alu == ALU_ADD) {
			if (unlikely(!imm_is_8bit(imm)))
				goto invalid;
			mc = SH4_ADD_IMM;
			mc |= imm & 0xff;
			mc |= arg1[0] << 8;
			cgen_two(mc);
			return true;
		}
		if (unlikely(arg1[0] != R_0))
			goto invalid;
		if (unlikely(imm < 0) || unlikely(imm >= 0x100))
			goto invalid;
		switch (alu) {
			case ALU_AND:
				mc = SH4_AND_IMM;
				break;
			case ALU_OR:
				mc = SH4_OR_IMM;
				break;
			case ALU_XOR:
				mc = SH4_XOR_IMM;
				break;
			default:
				goto invalid;
		}
		mc |= imm & 0xff;
		cgen_two(mc);
		return true;
	}
	if (arg3[0] < 0x10) {
		switch (alu) {
			case ALU_ADD:
				mc = SH4_ADD;
				break;
			case ALU_SUB:
				mc = SH4_SUB;
				break;
			case ALU_AND:
				mc = SH4_AND;
				break;
			case ALU_OR:
				mc = SH4_OR;
				break;
			case ALU_XOR:
				mc = SH4_XOR;
				break;
			default:
				goto invalid;
		}
		mc |= arg3[0] << 4;
		mc |= arg1[0] << 8;
		cgen_two(mc);
		return true;
	}

invalid:
	internal(file_line, "cgen_alu: invalid operands: %02x %02x %02x %02x", alu, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_alu_overflow(struct codegen_context *ctx, unsigned alu)
{
	uint16_t mc;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	if (arg1[0] == R_T && arg2[0] < 0x10 && arg2[0] == arg3[0] && arg4[0] < 0x10) {
		switch (alu) {
			case ALU_ADD:
				mc = SH4_ADDV;
				break;
			case ALU_SUB:
				mc = SH4_SUBV;
				break;
			default:
				goto invalid;
		}
		mc |= arg4[0] << 4;
		mc |= arg2[0] << 8;
		cgen_two(mc);
		return true;
	}

invalid:
	internal(file_line, "cgen_alu_overflow: invalid operands: %02x %02x %02x %02x %02x", alu, arg1[0], arg2[0], arg3[0], arg4[0]);
	return false;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned alu)
{
	uint16_t mc;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (arg1[0] < 0x10 && arg2[0] < 0x10) {
		switch (alu) {
			case ALU1_NOT:
				mc = SH4_NOT;
				break;
			case ALU1_NEG:
				mc = SH4_NEG;
				break;
			case ALU1_BSWAP16:
				mc = SH4_SWAP_B;
				break;
			case ALU1_BSWAP:
				mc = SH4_SWAP_B;
				break;
			default:
				goto invalid;
		}
		mc |= arg2[0] << 4;
		mc |= arg1[0] << 8;
		cgen_two(mc);
		if (alu == ALU1_BSWAP) {
			mc = SH4_SWAP_W;
			mc |= arg1[0] << 4;
			mc |= arg1[0] << 8;
			cgen_two(mc);
			mc = SH4_SWAP_B;
			mc |= arg1[0] << 4;
			mc |= arg1[0] << 8;
			cgen_two(mc);
		}
		return true;
	}

invalid:
	internal(file_line, "cgen_alu1: invalid operands: %02x %02x %02x", alu, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned alu)
{
	uint16_t mc;
	int64_t imm = 0;

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != arg2[0]) || unlikely(arg1[0] >= 0x10))
		goto invalid;

	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		/*debug("%u, %llx", alu, imm);*/
		if (alu == ROT_SHL && imm == 2) {
			mc = SH4_SHLL2;
		} else if (alu == ROT_SHR && imm == 2) {
			mc = SH4_SHLR2;
		} else if (alu == ROT_SHL && imm == 8) {
			mc = SH4_SHLL8;
		} else if (alu == ROT_SHR && imm == 8) {
			mc = SH4_SHLR8;
		} else if (alu == ROT_SHL && imm == 16) {
			mc = SH4_SHLL16;
		} else if (alu == ROT_SHR && imm == 16) {
			mc = SH4_SHLR16;
		} else {
			goto invalid;
		}
		mc |= arg1[0] << 8;
		cgen_two(mc);
		return true;
	}

	if (arg3[0] < 0x10) {
		if (alu == ROT_SHLR)
			mc = SH4_SHLD;
		else if (alu == ROT_SALR)
			mc = SH4_SHAD;
		else
			goto invalid;
		mc |= arg3[0] << 4;
		mc |= arg1[0] << 8;
		cgen_two(mc);
		return true;
	}

invalid:
	internal(file_line, "cgen_rot: invalid operands: %02x %02x %02x %02x %d", alu, arg1[0], arg2[0], arg3[0], (int)imm);
	return false;
}

static bool attr_w cgen_jmp_indirect(struct codegen_context *ctx, unsigned reg, uint16_t mc)
{
	mc |= reg << 8;
	cgen_two(mc);
	cgen_two(SH4_NOP);
	return true;
}

static bool attr_w cgen_jmp(struct codegen_context *ctx, unsigned length)
{
	uint16_t mc;
	bool odd;
	switch (length) {
		case JMP_SHORTEST:
		case JMP_SHORT:
			g(add_relocation(ctx, JMP_SHORT, 0, NULL));
			cgen_two(SH4_BRA);
			cgen_two(SH4_NOP);
			return true;
		case JMP_LONG:
			mc = SH4_MOV_W_PCREL_REG;
			mc |= 1;
			mc |= R_OFFSET_IMM << 8;
			cgen_two(mc);
			mc = SH4_BRAF;
			mc |= R_OFFSET_IMM << 8;
			cgen_two(mc);
			cgen_two(SH4_NOP);
			g(add_relocation(ctx, JMP_LONG, 0, NULL));
			cgen_two(0);
			return true;
		case JMP_EXTRA_LONG:
			odd = !!(ctx->mcode_size & 2);
			if (!odd)
				cgen_two(SH4_NOP);
			mc = SH4_MOV_L_PCREL_REG;
			mc |= 1;
			mc |= R_OFFSET_IMM << 8;
			cgen_two(mc);
			mc = SH4_BRAF;
			mc |= R_OFFSET_IMM << 8;
			cgen_two(mc);
			cgen_two(SH4_NOP);
			g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
			cgen_two(0);
			cgen_two(0);
			return true;
		default:
			internal(file_line, "cgen_jmp: invalid length %u", length);
	}
	return false;
}

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint16_t mc;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] == R_T && (cond == COND_E || cond == COND_NE)) {
		bool odd;
		if (length > JMP_SHORTEST)
			cond ^= 1;
		mc = cond == COND_E ? SH4_BF : SH4_BT;
		switch (length) {
			case JMP_SHORTEST:
				g(add_relocation(ctx, JMP_SHORTEST, 1, NULL));
				cgen_two(mc);
				return true;
			case JMP_SHORT:
				mc |= 1;
				cgen_two(mc);
				g(add_relocation(ctx, JMP_SHORT, 1, NULL));
				cgen_two(SH4_BRA);
				cgen_two(SH4_NOP);
				return true;
			case JMP_LONG:
				mc |= 3;
				cgen_two(mc);
				mc = SH4_MOV_W_PCREL_REG;
				mc |= 1;
				mc |= R_OFFSET_IMM << 8;
				cgen_two(mc);
				mc = SH4_BRAF;
				mc |= R_OFFSET_IMM << 8;
				cgen_two(mc);
				cgen_two(SH4_NOP);
				g(add_relocation(ctx, JMP_LONG, 1, NULL));
				cgen_two(0);
				return true;
			case JMP_EXTRA_LONG:
				odd = !!(ctx->mcode_size & 2);
				mc |= 4 + odd;
				cgen_two(mc);
				if (odd)
					cgen_two(SH4_NOP);
				mc = SH4_MOV_L_PCREL_REG;
				mc |= 1;
				mc |= R_OFFSET_IMM << 8;
				cgen_two(mc);
				mc = SH4_BRAF;
				mc |= R_OFFSET_IMM << 8;
				cgen_two(mc);
				cgen_two(SH4_NOP);
				g(add_relocation(ctx, JMP_EXTRA_LONG, 1, NULL));
				cgen_two(0);
				cgen_two(0);
				return true;
		}
	}
	internal(file_line, "cgen_jmp_reg: invalid operands: %02x", arg1[0]);
	return false;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint16_t mc;
	uint32_t mc4;
	int32_t offs = (uint32_t)ctx->label_to_pos[reloc->label_id] - (uint32_t)reloc->position;
	switch (reloc->length) {
		case JMP_SHORTEST:
			offs /= 2;
			offs -= 2U;
			if (!imm_is_8bit(offs))
				return false;
			memcpy(&mc, &ctx->mcode[reloc->position], 2);
			mc |= offs & 0xff;
			memcpy(&ctx->mcode[reloc->position], &mc, 2);
			break;
		case JMP_SHORT:
			offs /= 2;
			offs -= 2U;
			if (offs < -0x800 || offs >= 0x800)
				return false;
			memcpy(&mc, &ctx->mcode[reloc->position], 2);
			mc |= offs & 0xfff;
			memcpy(&ctx->mcode[reloc->position], &mc, 2);
			break;
		case JMP_LONG:
			if (!imm_is_16bit(offs))
				return false;
			memcpy(&mc, &ctx->mcode[reloc->position], 2);
			mc = offs;
			memcpy(&ctx->mcode[reloc->position], &mc, 2);
			break;
		case JMP_EXTRA_LONG:
			memcpy(&mc4, &ctx->mcode[reloc->position], 4);
			mc4 = offs;
			memcpy(&ctx->mcode[reloc->position], &mc4, 4);
			break;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return true;
}

static bool validate_insn(const struct insn_details *d)
{
	switch (insn_opcode(d->insn)) {
		case INSN_MOV:
		case INSN_MOVSX: {
			const uint8_t *arg1 = d->start + 4;
			const uint8_t *arg2 = arg1 + arg_size(*arg1);
			return cgen_moves(NULL, insn_op_size(d->insn), insn_opcode(d->insn) == INSN_MOVSX, arg1, arg2);

		}
	}
	return false;
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	switch (insn_opcode(insn)) {
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_CLAIM_RANGE:
			g(cgen_claim_range(ctx));
			return true;
		case INSN_NOP:
			cgen_two(SH4_NOP);
			return true;
		case INSN_RET:
			cgen_two(SH4_RTS);
			cgen_two(SH4_NOP);
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_jmp_indirect(ctx, cget_one(ctx), SH4_JSR));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn)));
			return true;
		case INSN_MOVSX:
			g(cgen_movsx(ctx, insn_op_size(insn)));
			return true;
		case INSN_CMP_DEST_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4))
				goto invalid_insn;
			g(cgen_cmp_dest_reg(ctx, insn_aux(insn)));
			return true;
		case INSN_TEST_DEST_REG:
			switch (insn_op_size(insn)) {
				case OP_SIZE_1:
					g(cgen_test_dest_reg_8(ctx, insn_aux(insn)));
					break;
				case OP_SIZE_4:
					g(cgen_test_dest_reg(ctx, insn_aux(insn)));
					break;
				default:
					goto invalid_insn;
			}
			return true;
		case INSN_ALU:
			switch (insn_op_size(insn)) {
				case OP_SIZE_1:
					g(cgen_alu_8(ctx, insn_aux(insn)));
					break;
				case OP_SIZE_4:
					g(cgen_alu(ctx, insn_aux(insn)));
					break;
				default:
					goto invalid_insn;
			}
			return true;
		case INSN_ALU_OVERFLOW:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu_overflow(ctx, insn_aux(insn)));
			return true;
		case INSN_ALU1:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_aux(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_aux(insn)));
			return true;
		case INSN_JMP:
			g(cgen_jmp(ctx, insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG:
			g(cgen_jmp_reg(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_indirect(ctx, cget_one(ctx), SH4_JMP));
			return true;
		invalid_insn:
		default:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
