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

#define ARM64_AND_OR_EOR	0x0a000000U
#define  ARM64_AND_OR_EOR_AND		0x00000000U
#define  ARM64_AND_OR_EOR_REG_NOT	0x00200000U
#define  ARM64_AND_OR_EOR_IMM_NOT	0x00400000U
#define  ARM64_AND_OR_EOR_ORR		0x20000000U
#define  ARM64_AND_OR_EOR_EOR		0x40000000U
#define  ARM64_AND_OR_EOR_ANDS		0x60000000U
#define  ARM64_AND_OR_EOR_SIZE		0x80000000U
#define ARM64_ADDSUB_SHIFTED	0x0b000000U
#define ARM64_ADDSUB_EXTENDED	0x0b200000U
#define ARM64_CNT		0x0e205800U
#define ARM64_ADDV		0x0e31b800U
#define  ARM64_ADDV_SIZE		0x00c00000U
#define ARM64_ADDSUB_IMM	0x11000000U
#define  ARM64_ADDSUB_IMM_SHIFT12	0x00400000U
#define  ARM64_ADDSUB_SET_FLAGS		0x20000000U
#define  ARM64_ADDSUB_SUB		0x40000000U
#define  ARM64_ADDSUB_SIZE		0x80000000U
#define ARM64_AND_OR_EOR_IMM	0x12000000U
#define ARM64_MOVN_IMM16	0x12800000U
#define  ARM64_MOVN_IMM16_SIZE		0x80000000U
#define ARM64_SUBFM		0x13000000U
#define  ARM64_SUBFM_U			0x40000000U
#define  ARM64_SUBFM_SIZE		0x80400000U
#define ARM64_EXTR		0x13800000U
#define  ARM64_EXTR_SIZE		0x80400000U
#define ARM64_B			0x14000000U
#define ARM64_ADCSBC		0x1a000000U
#define  ARM64_ADCSBC_SET_FLAGS		0x20000000U
#define  ARM64_ADCSBC_SBC		0x40000000U
#define  ARM64_ADCSBC_SIZE		0x80000000U
#define ARM64_CSEL		0x1a800000U
#define  ARM64_CSEL_SEL			0x00000000U
#define  ARM64_CSEL_INC			0x00000400U
#define  ARM64_CSEL_INV			0x40000000U
#define  ARM64_CSEL_NEG			0x40000400U
#define  ARM64_CSEL_SIZE		0x80000000U
#define ARM64_CSET		0x1a9f07e0U
#define  ARM64_CSET_SIZE		0x80000000U
#define ARM64_SUDIV		0x1ac00800U
#define  ARM64_SUDIV_SDIV		0x00000400U
#define  ARM64_SUDIV_SIZE		0x80000000U
#define ARM64_ROT		0x1ac02000U
#define  ARM64_ROT_LSL			0x00000000U
#define  ARM64_ROT_LSR			0x00000400U
#define  ARM64_ROT_ASR			0x00000800U
#define  ARM64_ROT_ROR			0x00000c00U
#define  ARM64_ROT_SIZE			0x80000000U
#define ARM64_MADDSUB		0x1b000000U
#define  ARM64_MADDSUB_MSUB		0x00008000U
#define  ARM64_MADDSUB_SIZE		0x80000000U
#define ARM64_FP_ALU		0x1e200800U
#define  ARM64_FP_ALU_MUL		0x00000000U
#define  ARM64_FP_ALU_DIV		0x00001000U
#define  ARM64_FP_ALU_ADD		0x00002000U
#define  ARM64_FP_ALU_SUB		0x00003000U
#define  ARM64_FP_ALU_SINGLE		0x00000000U
#define  ARM64_FP_ALU_DOUBLE		0x00400000U
#define  ARM64_FP_ALU_HALF		0x00c00000U
#define ARM64_FCMP		0x1e202000U
#define  ARM64_FCMP_ZERO		0x00000008U
#define  ARM64_FCMP_SINGLE		0x00000000U
#define  ARM64_FCMP_DOUBLE		0x00400000U
#define  ARM64_FCMP_HALF		0x00c00000U
#define ARM64_FP_ALU1		0x1e204000U
#define  ARM64_FP_ALU1_MOV		0x00000000U
#define  ARM64_FP_ALU1_NEG		0x00010000U
#define  ARM64_FP_ALU1_SQRT		0x00018000U
#define  ARM64_FP_ALU1_RINTN		0x00040000U
#define  ARM64_FP_ALU1_RINTP		0x00048000U
#define  ARM64_FP_ALU1_RINTM		0x00050000U
#define  ARM64_FP_ALU1_RINTZ		0x00058000U
#define  ARM64_FP_ALU1_SINGLE		0x00000000U
#define  ARM64_FP_ALU1_DOUBLE		0x00400000U
#define  ARM64_FP_ALU1_HALF		0x00c00000U
#define ARM64_SCVTF		0x1e220000U
#define  ARM64_SCVTF_SINGLE		0x00000000U
#define  ARM64_SCVTF_DOUBLE		0x00400000U
#define  ARM64_SCVTF_HALF		0x00c00000U
#define  ARM64_SCVTF_SIZE		0x80000000U
#define ARM64_FCVT		0x1e224000U
#define  ARM64_FCVT_TO_SINGLE		0x00000000U
#define  ARM64_FCVT_TO_DOUBLE		0x00008000U
#define  ARM64_FCVT_TO_HALF		0x00018000U
#define  ARM64_FCVT_FROM_SINGLE		0x00000000U
#define  ARM64_FCVT_FROM_DOUBLE		0x00400000U
#define  ARM64_FCVT_FROM_HALF		0x00c00000U
#define ARM64_FMOV		0x1e260000U
#define  ARM64_FMOV_W_S			0x00000000U
#define  ARM64_FMOV_S_W			0x00010000U
#define  ARM64_FMOV_X_D			0x80400000U
#define  ARM64_FMOV_D_X			0x80410000U
#define ARM64_FCVTZS		0x1e380000U
#define  ARM64_FCVTZS_SINGLE		0x00000000U
#define  ARM64_FCVTZS_DOUBLE		0x00400000U
#define  ARM64_FCVTZS_HALF		0x00c00000U
#define  ARM64_FCVTZS_SIZE		0x80000000U
#define ARM64_LDPSTP		0x28000000U
#define  ARM64_LDPSTP_LD		0x00400000U
#define  ARM64_LDPSTP_POST_INDEX	0x00800000U
#define  ARM64_LDPSTP_IMM		0x01000000U
#define  ARM64_LDPSTP_PRE_INDEX		0x01800000U
#define  ARM64_LDPSTP_SIZE		0x80000000U
#define ARM64_MOV		0x2a0003e0U
#define  ARM64_MOV_SIZE			0x80000000U
#define ARM64_CB		0x34000000U
#define  ARM64_CBZ_CBNZ			0x01000000U
#define  ARM64_CBZ_SIZE			0x80000000U
#define ARM64_TB		0x36000000U
#define  ARM64_TB_TBNZ			0x01000000U
#define ARM64_LDST		0x38000000U
#define  ARM64_LDST_POST_INDEX		0x00000400U
#define  ARM64_LDST_PRE_INDEX		0x00000c00U
#define  ARM64_LDST_2REGS		0x00200800U
#define   ARM64_LDST_2REGS_UXTW			0x00004000U
#define   ARM64_LDST_2REGS_NORMAL		0x00006000U
#define   ARM64_LDST_2REGS_SCALE		0x00007000U
#define   ARM64_LDST_2REGS_SXTW			0x0000c000U
#define   ARM64_LDST_2REGS_SXTX			0x0000e000U
#define  ARM64_LDST_ST			0x00000000U
#define  ARM64_LDST_LD_UX		0x00400000U
#define  ARM64_LDST_LD_SX		0x00800000U
#define  ARM64_LDST_LD_SXW		0x00c00000U
#define  ARM64_LDST_SCALED_12BIT	0x01000000U
#define  ARM64_LDST_FP			0x04000000U
#define  ARM64_LDST_SIZE1		0x40000000U
#define  ARM64_LDST_SIZE		0xc0000000U
#define  ARM64_LDST_FP_8		0x00000000U
#define  ARM64_LDST_FP_16		0x40000000U
#define  ARM64_LDST_FP_32		0x80000000U
#define  ARM64_LDST_FP_64		0xc0000000U
#define  ARM64_LDST_FP_128		0x00800000U
#define ARM64_MOV_IMM16		0x52800000U
#define  ARM64_MOV_IMM16_SIZE		0x80000000U
#define ARM64_B_COND		0x54000000U
#define ARM64_REV		0x5ac00000U
#define  ARM64_REV_1			0x00000000U
#define  ARM64_REV_16			0x00000400U
#define  ARM64_REV_32			0x00000800U
#define  ARM64_REV_64			0x00000c00U
#define  ARM64_REV_SIZE			0x80000000U
#define ARM64_CLZ		0x5ac01000U
#define  ARM64_CLZ_SIZE			0x80000000U
#define ARM64_MOVK		0x72800000U
#define  ARM64_MOVK_SIZE		0x80000000U
#define ARM64_SMADDSUBL		0x9b200000U
#define  ARM64_SMADDSUBL_SUB		0x00008000U
#define  ARM64_SMADDSUBL_U		0x00800000U
#define ARM64_SUMULH		0x9b407c00U
#define  ARM64_SUMULH_U			0x00800000U
#define ARM64_BR		0xd61f0000U
#define ARM64_BLR		0xd63f0000U
#define ARM64_RET		0xd65f03c0U

static const int8_t jmp_cond[48] = {
	0x6, 0x7, 0x3, 0x2, 0x0, 0x1, 0x9, 0x8,
	0x4, 0x5,  -1,  -1, 0xb, 0xa, 0xd, 0xc,
	 -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	 -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	 -1,  -1, 0x3, 0x2, 0x0, 0x1, 0x9, 0x8,
	 -1,  -1, 0x6, 0x7,  -1,  -1,  -1,  -1,
};

static const int16_t rot_codes[8] = {
	-1,
	ARM64_ROT_ROR,
	-1,
	-1,
	ARM64_ROT_LSL,
	ARM64_ROT_LSR,
	-1,
	ARM64_ROT_ASR,
};

static bool attr_w cgen_ldr_str(struct codegen_context *ctx, unsigned ldst_mode, unsigned size, uint8_t reg, uint8_t *address)
{
	int64_t imm;
	uint32_t mc = ARM64_LDST;
	mc |= ldst_mode;
	mc |= ARM64_LDST_SIZE1 * size;
	if (address[0] >= ARG_ADDRESS_2 && address[0] <= ARG_ADDRESS_2_SXTW) {
		imm = get_imm(&address[3]);
		if (unlikely(imm != 0))
			goto invalid;
		mc |= ARM64_LDST_2REGS;
		if (address[0] == ARG_ADDRESS_2) {
			mc |= ARM64_LDST_2REGS_NORMAL;
		} else if ((unsigned)address[0] - ARG_ADDRESS_2 == size) {
			mc |= ARM64_LDST_2REGS_SCALE;
		} else if (address[0] == ARG_ADDRESS_2_UXTW) {
			mc |= ARM64_LDST_2REGS_UXTW;
		} else if (address[0] == ARG_ADDRESS_2_SXTW) {
			mc |= ARM64_LDST_2REGS_SXTW;
		} else {
			goto invalid;
		}
		mc |= reg;
		mc |= (uint32_t)address[1] << 5;
		mc |= (uint32_t)address[2] << 16;
		cgen_four(mc);
		return true;
	}
	imm = get_imm(&address[2]);
	if (imm >= -256 && imm <= 255) {
		if (address[0] == ARG_ADDRESS_1) {
		} else if (address[0] == ARG_ADDRESS_1_PRE_I) {
			mc |= ARM64_LDST_PRE_INDEX;
		} else if (address[0] == ARG_ADDRESS_1_POST_I) {
			mc |= ARM64_LDST_POST_INDEX;
		} else {
			goto invalid;
		}
		mc |= reg;
		mc |= (uint32_t)address[1] << 5;
		mc |= (imm & 0x1ff) << 12;
		cgen_four(mc);
		return true;
	}
	if (unlikely(address[0] != ARG_ADDRESS_1))
		goto invalid;
	if (unlikely((imm & ((1 << size) - 1)) != 0) || unlikely(imm < 0))
		goto invalid;
	imm >>= size;
	if (unlikely(imm >= 0x1000))
		goto invalid;
	mc |= ARM64_LDST_SCALED_12BIT;
	mc |= reg;
	mc |= (uint32_t)address[1] << 5;
	mc |= (imm & 0xfff) << 10;
	cgen_four(mc);
	return true;

invalid:
	internal(file_line, "cgen_ldr_str: invalid address: %02x, %02x, %"PRIxMAX"", reg, address[0], (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size, bool sx)
{
	int64_t imm;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] < 32) {
		if (arg2[0] < 32) {
			if (size < (sx ? OP_SIZE_8 : OP_SIZE_4)) {
				mc = ARM64_SUBFM | (sx * ARM64_SUBFM_SIZE);
				mc |= arg1[0];
				mc |= (uint32_t)arg2[0] << 5;
				mc |= ((8U << size) - 1) << 10;
				mc |= ARM64_SUBFM_U * !sx;
				cgen_four(mc);
				return true;
			}
			if (arg1[0] == R_SP || arg2[0] == R_SP) {
				mc = ARM64_ADDSUB_IMM;
				mc |= arg1[0];
				mc |= (uint32_t)arg2[0] << 5;
			} else {
				/* !!! TODO: handle shifted register */
				mc = ARM64_MOV;
				mc |= arg1[0];
				mc |= (uint32_t)arg2[0] << 16;
			}
			mc |= ARM64_MOV_SIZE * (size == OP_SIZE_8);
			cgen_four(mc);
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			if (size < OP_SIZE_4)
				goto invalid;
			mc = ARM64_FMOV | (size == OP_SIZE_4 ? ARM64_FMOV_W_S : ARM64_FMOV_X_D);
			mc |= arg1[0];
			mc |= (uint32_t)(arg2[0] & 31) << 5;
			cgen_four(mc);
			return true;
		}
		if (arg2[0] == ARG_IMM) {
			if (unlikely(size < OP_SIZE_4))
				internal(file_line, "cgen_mov: unsupported size %u", size);
			imm = get_imm(&arg2[1]);
			if (imm >= 0 && imm < 0x10000) {
				mc = ARM64_MOV_IMM16;
				mc |= ARM64_MOV_IMM16_SIZE * (size == OP_SIZE_8);
				mc |= arg1[0];
				mc |= (uint32_t)imm << 5;
				cgen_four(mc);
				return true;
			}
			if (~imm >= 0 && ~imm < 0x10000) {
				imm = ~imm;
				mc = ARM64_MOVN_IMM16;
				mc |= ARM64_MOVN_IMM16_SIZE * (size == OP_SIZE_8);
				mc |= arg1[0];
				mc |= (uint32_t)imm << 5;
				cgen_four(mc);
				return true;
			}
			internal(file_line, "cgen_mov: immediate out of range: %"PRIxMAX"", (uintmax_t)imm);
		}
		if (!sx || size == OP_SIZE_NATIVE)
			return cgen_ldr_str(ctx, ARM64_LDST_LD_UX, size, arg1[0], arg2);
		else
			return cgen_ldr_str(ctx, ARM64_LDST_LD_SX, size, arg1[0], arg2);
	}
	if (reg_is_fp(arg1[0])) {
		if (arg2[0] < 32) {
			if (size < OP_SIZE_4)
				goto invalid;
			mc = ARM64_FMOV | (size == OP_SIZE_4 ? ARM64_FMOV_S_W : ARM64_FMOV_D_X);
			mc |= arg1[0] & 31;
			mc |= (uint32_t)arg2[0] << 5;
			cgen_four(mc);
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			mc = ARM64_FP_ALU1 | ARM64_FP_ALU1_MOV;
			switch (size) {
				case OP_SIZE_2:		mc |= ARM64_FP_ALU1_HALF; break;
				case OP_SIZE_4:		mc |= ARM64_FP_ALU1_SINGLE; break;
				case OP_SIZE_8:		mc |= ARM64_FP_ALU1_DOUBLE; break;
				default:		internal(file_line, "cgen_mov: invalid size %u", size);
			}
			mc |= arg1[0] & 31;
			mc |= ((uint32_t)(arg2[0] & 31)) << 5;
			cgen_four(mc);
			return true;
		}
		return cgen_ldr_str(ctx, ARM64_LDST_LD_UX | ARM64_LDST_FP, size, arg1[0] & 31, arg2);
	}
	if (arg2[0] < 32) {
		return cgen_ldr_str(ctx, ARM64_LDST_ST, size, arg2[0], arg1);
	}
	if (reg_is_fp(arg2[0])) {
		return cgen_ldr_str(ctx, ARM64_LDST_ST | ARM64_LDST_FP, size, arg2[0] & 31, arg1);
	}
	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		if (!imm)
			return cgen_ldr_str(ctx, ARM64_LDST_ST, size, 0x1f, arg1);
	}
invalid:
	internal(file_line, "cgen_mov: invalid arguments %u, %02x, %02x", size, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_alu_args(struct codegen_context *ctx, unsigned size, unsigned writes_flags, unsigned alu, bool not, uint8_t *arg1, uint8_t *arg2, uint8_t *arg3)
{
	uint32_t mc;
	int64_t imm;
	uint8_t z = 31;
	if (unlikely(arg1[0] >= 32))
		goto invalid;
	if (unlikely(alu == ALU_MUL)) {
		mc = ARM64_MADDSUB;
		if (size == OP_SIZE_8 &&
		    arg2[0] == ARG_EXTENDED_REGISTER && arg2[1] == ARG_EXTEND_SXTW &&
		    arg3[0] == ARG_EXTENDED_REGISTER && arg3[1] == ARG_EXTEND_SXTW) {
			arg2 += 2;
			arg3 += 2;
			mc = ARM64_SMADDSUBL;
		} else if (size == OP_SIZE_8 &&
			   arg2[0] == ARG_EXTENDED_REGISTER && arg2[1] == ARG_EXTEND_UXTW &&
			   arg3[0] == ARG_EXTENDED_REGISTER && arg3[1] == ARG_EXTEND_UXTW) {
			arg2 += 2;
			arg3 += 2;
			mc = ARM64_SMADDSUBL | ARM64_SMADDSUBL_U;
		}
		if (unlikely(arg2[0] >= 32) && unlikely(arg3[0] >= 32))
			goto invalid;
		mc |= ARM64_MADDSUB_SIZE * (size == OP_SIZE_8);
		mc |= arg1[0];
		mc |= 0x1fU << 10;
		mc |= arg2[0] << 5;
		mc |= arg3[0] << 16;
		cgen_four(mc);
		return true;
	}
	if (unlikely(arg2[0] >= 32))
		goto invalid;
	if (unlikely(alu == ALU_UMULH) || unlikely(alu == ALU_SMULH)) {
		if (unlikely(arg3[0] >= 32))
			goto invalid;
		if (unlikely(size != OP_SIZE_8))
			goto invalid;
		mc = ARM64_SUMULH;
		mc |= ARM64_SUMULH_U * (alu == ALU_UMULH);
		mc |= arg1[0];
		mc |= (uint32_t)arg2[0] << 5;
		mc |= (uint32_t)arg3[0] << 16;
		cgen_four(mc);
		return true;
	}
	if (unlikely(alu == ALU_UDIV) || unlikely(alu == ALU_SDIV)) {
		if (unlikely(arg3[0] >= 32))
			goto invalid;
		mc = ARM64_SUDIV;
		mc |= ARM64_SUDIV_SDIV * (alu == ALU_SDIV);
		mc |= ARM64_SUDIV_SIZE * (size == OP_SIZE_8);
		mc |= arg1[0];
		mc |= (uint32_t)arg2[0] << 5;
		mc |= (uint32_t)arg3[0] << 16;
		cgen_four(mc);
		return true;
	}
	if (unlikely(alu == ALU_ADC) || unlikely(alu == ALU_SBB)) {
		if (arg3[0] == ARG_IMM) {
			imm = get_imm(&arg3[1]);
			if (unlikely(imm != 0))
				goto invalid;
			arg3 = &z;
		} else if (unlikely(arg3[0] >= 32)) {
			goto invalid;
		}
		mc = ARM64_ADCSBC;
		mc |= ARM64_ADCSBC_SBC * (alu == ALU_SBB);
reg_reg_reg:
		mc |= ARM64_ADCSBC_SET_FLAGS * (uint32_t)!!writes_flags;
reg_reg_reg_2:
		mc |= ARM64_ADCSBC_SIZE * (size == OP_SIZE_8);
		mc |= arg1[0];
		mc |= (uint32_t)arg2[0] << 5;
		mc |= (uint32_t)arg3[0] << 16;
		cgen_four(mc);
		return true;
	}
	if (alu == ALU_ADD || alu == ALU_SUB) {
		mc = 0;
		mc |= ARM64_ADDSUB_SUB * (alu == ALU_SUB);
		if (arg3[0] < 32) {
			mc |= ARM64_ADDSUB_SHIFTED;
			goto reg_reg_reg;
		}
		if (arg3[0] == ARG_EXTENDED_REGISTER) {
			mc |= ARM64_ADDSUB_EXTENDED;
			mc |= (uint32_t)arg3[1] << 10;
			arg3 += 2;
			goto reg_reg_reg;
		}
		if (arg3[0] == ARG_SHIFTED_REGISTER) {
			if (unlikely((arg3[1] >> 6) == 3))
				goto invalid;
			mc |= ARM64_ADDSUB_SHIFTED;
			mc |= (uint32_t)(arg3[1] & ARG_SHIFT_AMOUNT) << 10;
			mc |= (uint32_t)(arg3[1] >> 6) << 22;
			arg3 += 2;
			goto reg_reg_reg;
		}
		if (arg3[0] == ARG_IMM) {
			mc |= ARM64_ADDSUB_IMM;
			mc |= ARM64_ADCSBC_SET_FLAGS * (uint32_t)!!writes_flags;
			imm = get_imm(&arg3[1]);
			if (likely(imm >= 0) && likely(imm < 0x1000)) {
reg_reg_imm:
				mc |= imm << 10;
				mc |= arg1[0];
				mc |= (uint32_t)arg2[0] << 5;
				mc |= ARM64_ADCSBC_SIZE * (size == OP_SIZE_8);
				cgen_four(mc);
				return true;
			}
			if (likely(!(imm & 0xfff))) {
				imm = (uint64_t)imm >> 12;
				if (likely(imm < 0x1000)) {
					mc |= ARM64_ADDSUB_IMM_SHIFT12;
					goto reg_reg_imm;
				}
			}
		}
		goto invalid;
	}
	if (alu == ALU_AND || alu == ALU_OR || alu == ALU_XOR) {
		mc = 0;
		if (not) {
			if (arg3[0] != ARG_IMM)
				mc |= ARM64_AND_OR_EOR_REG_NOT;
		}
		if (alu == ALU_AND) {
			mc |= writes_flags ? ARM64_AND_OR_EOR_ANDS : ARM64_AND_OR_EOR_AND;
		} else {
			if (unlikely(writes_flags))
				goto invalid;
			mc |= alu == ALU_OR ? ARM64_AND_OR_EOR_ORR : ARM64_AND_OR_EOR_EOR;
		}
		if (arg3[0] < 32) {
			mc |= ARM64_AND_OR_EOR;
			goto reg_reg_reg_2;
		}
		if (arg3[0] == ARG_SHIFTED_REGISTER) {
			mc |= ARM64_AND_OR_EOR;
			mc |= (uint32_t)(arg3[1] & ARG_SHIFT_AMOUNT) << 10;
			mc |= (uint32_t)(arg3[1] >> 6) << 22;
			arg3 += 2;
			goto reg_reg_reg_2;
		}
		if (arg3[0] == ARG_IMM) {
			int16_t code;
			mc |= ARM64_AND_OR_EOR_SIZE * (size == OP_SIZE_8);
			mc |= ARM64_AND_OR_EOR_IMM;
			imm = get_imm(&arg3[1]);
			if (not)
				imm = ~imm;
			if (size == OP_SIZE_4)
				imm &= 0xffffffff;
			code = value_to_code(size, imm);
			if (unlikely(code < 0))
				internal(file_line, "cgen_alu_args: invalid immediate value %"PRIxMAX"", (uintmax_t)imm);
			mc |= arg1[0];
			mc |= (uint32_t)arg2[0] << 5;
			mc ^= (uint32_t)code << 10;
			cgen_four(mc);
			return true;
		}
		goto invalid;
	}

invalid:
	internal(file_line, "cgen_alu_args: invalid arguments %02x, %02x, %02x, %u, %u", arg1[0], arg2[0], arg3[0], alu, writes_flags);
	return false;
}

static bool attr_w cgen_cmp(struct codegen_context *ctx, unsigned size, bool cmn)
{
	uint8_t z = 31;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	return cgen_alu_args(ctx, size, true, cmn ? ALU_ADD : ALU_SUB, false, &z, arg1, arg2);
}

static bool attr_w cgen_test(struct codegen_context *ctx, unsigned size)
{
	uint8_t z = 31;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	return cgen_alu_args(ctx, size, true, ALU_AND, false, &z, arg1, arg2);
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned writes_flags, unsigned alu)
{
	bool not;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	not = false;
	switch (alu) {
		case ALU_ORN:	alu = ALU_OR; not = true; break;
		case ALU_ANDN:	alu = ALU_AND; not = true; break;
		case ALU_XORN:	alu = ALU_XOR; not = true; break;
	}
	return cgen_alu_args(ctx, size, writes_flags, alu, not, arg1, arg2, arg3);
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned writes_flags, unsigned alu)
{
	uint32_t mc = 0;
	uint8_t z = 31;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (alu) {
		case ALU1_NOT:
			return cgen_alu_args(ctx, size, writes_flags, ALU_OR, true, arg1, &z, arg2);
		case ALU1_NEG:
			return cgen_alu_args(ctx, size, writes_flags, ALU_SUB, false, arg1, &z, arg2);
		case ALU1_NGC:
			return cgen_alu_args(ctx, size, writes_flags, ALU_SBB, false, arg1, &z, arg2);
		case ALU1_BSWAP:
		case ALU1_BSWAP16:
		case ALU1_BREV:
			mc = ARM64_REV;
			if (alu == ALU1_BREV) {
				mc |= ARM64_REV_1;
			} else if (alu == ALU1_BSWAP16) {
				mc |= ARM64_REV_16;
			} else if (alu == ALU1_BSWAP) {
				if (size == OP_SIZE_4)
					mc |= ARM64_REV_32;
				else
					mc |= ARM64_REV_64;
			}
			mc |= ARM64_REV_SIZE * (size == OP_SIZE_8);
			mc |= arg1[0];
			mc |= (uint32_t)arg2[0] << 5;
			cgen_four(mc);
			return true;
		case ALU1_LZCNT:
			mc = ARM64_CLZ;
			mc |= ARM64_CLZ_SIZE * (size == OP_SIZE_8);
			mc |= arg1[0];
			mc |= (uint32_t)arg2[0] << 5;
			cgen_four(mc);
			return true;
		default:
			internal(file_line, "cgen_alu1: invalid arguments");
			return false;
	}
}

static bool attr_w cgen_rot_imm(struct codegen_context *ctx, unsigned size, uint8_t rot, uint8_t *arg1, uint8_t *arg2, uint8_t imm)
{
	uint64_t mc;
	if (unlikely(rot == ROT_ROL) || rot == ROT_SHL) {
		imm = -imm;
	}
	imm &= (1U << (size + 3)) - 1;
	mc = 0;
	mc |= (rot == ROT_ROR || rot == ROT_ROL ? ARM64_EXTR_SIZE : ARM64_SUBFM_SIZE) * (size == OP_SIZE_8);
	switch (rot) {
		case ROT_ROL:
		case ROT_ROR:
			mc |= ARM64_EXTR;
			mc |= arg1[0];
			mc |= (uint32_t)arg2[0] << 5;
			mc |= (uint32_t)arg2[0] << 16;
			mc |= (uint32_t)imm << 10;
			break;
		case ROT_SHL:
			mc |= ARM64_SUBFM | ARM64_SUBFM_U;
			mc |= arg1[0];
			mc |= (uint32_t)arg2[0] << 5;
			mc |= (uint32_t)imm << 16;
			imm--;
			imm &= (1U << (size + 3)) - 1;
			mc |= (uint32_t)(imm << 10);
			break;
		case ROT_SHR:
		case ROT_SAR:
			mc |= ARM64_SUBFM;
			mc |= (rot == ROT_SHR) * ARM64_SUBFM_U;
			mc |= arg1[0];
			mc |= (uint32_t)arg2[0] << 5;
			mc |= (uint32_t)imm << 16;
			mc |= ((1U << (size + 3)) - 1) << 10;
			break;
	}
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, unsigned rot)
{
	int16_t arm_rot;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (arg3[0] == ARG_IMM)
		return cgen_rot_imm(ctx, size, rot, arg1, arg2, arg3[1]);
	arm_rot = rot_codes[rot];
	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32) || unlikely(arg3[0] >= 32) || unlikely(arm_rot < 0))
		internal(file_line, "cgen_rot: invalid arguments");
	mc = ARM64_ROT;
	mc |= ARM64_ROT_SIZE * (size == OP_SIZE_8);
	mc |= arm_rot;
	mc |= arg1[0];
	mc |= (uint32_t)arg2[0] << 5;
	mc |= (uint32_t)arg3[0] << 16;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_madd(struct codegen_context *ctx, unsigned size, bool sub)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32) || unlikely(arg3[0] >= 32) || unlikely(arg4[0] >= 32))
		internal(file_line, "cgen_madd: invalid arguments");
	mc = ARM64_MADDSUB;
	mc |= ARM64_MADDSUB_SIZE * (size == OP_SIZE_8);
	mc |= ARM64_MADDSUB_MSUB * sub;
	mc |= arg1[0];
	mc |= (uint32_t)arg2[0] << 5;
	mc |= (uint32_t)arg3[0] << 16;
	mc |= (uint32_t)arg4[0] << 10;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_set_cond(struct codegen_context *ctx, unsigned size, unsigned aux)
{
	int8_t cond;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	cond = jmp_cond[aux];
	if (unlikely(cond < 0) || unlikely(arg1[0] >= 31))
		internal(file_line, "cgen_set_cond: invalid arguments: %02x, %u, %u", arg1[0], size, aux);
	mc = ARM64_CSET;
	mc |= ARM64_CSET_SIZE * (size == OP_SIZE_8);
	mc |= (uint32_t)(cond ^ 1) << 12;
	mc |= arg1[0];
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_csel(struct codegen_context *ctx, uint32_t insn, unsigned size, unsigned aux)
{
	uint32_t mc;
	int8_t cond;
	uint8_t z = 31;
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		if (unlikely(imm != 0))
			goto invalid;
		arg2 = &z;
	}
	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (unlikely(imm != 0))
			goto invalid;
		arg3 = &z;
	}
	cond = jmp_cond[aux];
	if (unlikely(cond < 0))
		goto invalid;
	mc = ARM64_CSEL;
	switch (insn) {
		case INSN_CSEL_SEL:	mc |= ARM64_CSEL_SEL; break;
		case INSN_CSEL_INC:	mc |= ARM64_CSEL_INC; break;
		case INSN_CSEL_INV:	mc |= ARM64_CSEL_INV; break;
		case INSN_CSEL_NEG:	mc |= ARM64_CSEL_NEG; break;
		default:
			goto invalid;
	}
	mc |= ARM64_CSEL_SIZE * (size == OP_SIZE_8);
	mc |= arg1[0];
	mc |= (uint32_t)arg2[0] << 16;
	mc |= (uint32_t)arg3[0] << 5;
	mc |= (uint32_t)cond << 12;
	cgen_four(mc);
	return true;
invalid:
	internal(file_line, "cgen_csel: invalid arguments");
}

static bool attr_w cgen_ldp_stp(struct codegen_context *ctx, bool ldr, unsigned size)
{
	uint8_t *arg1, *arg2, *arg3;
	uint8_t z = 31;
	uint32_t mc;
	int64_t imm;
	if (!ldr) {
		arg1 = ctx->code_position;
		arg2 = arg1 + arg_size(*arg1);
		arg3 = arg2 + arg_size(*arg2);
		ctx->code_position = arg3 + arg_size(*arg3);
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (unlikely(imm != 0))
				goto invalid;
			arg2 = &z;
		}
		if (arg3[0] == ARG_IMM) {
			imm = get_imm(&arg3[1]);
			if (unlikely(imm != 0))
				goto invalid;
			arg3 = &z;
		}
	} else {
		arg2 = ctx->code_position;
		arg3 = arg2 + arg_size(*arg2);
		arg1 = arg3 + arg_size(*arg3);
		ctx->code_position = arg1 + arg_size(*arg1);
	}
	mc = ARM64_LDPSTP;
	mc |= ARM64_LDPSTP_LD * (uint32_t)ldr;
	mc |= ARM64_LDPSTP_SIZE * (size == OP_SIZE_8);
	if (arg1[0] == ARG_ADDRESS_1) {
		mc |= ARM64_LDPSTP_IMM;
	} else if (arg1[0] == ARG_ADDRESS_1_PRE_I) {
		mc |= ARM64_LDPSTP_PRE_INDEX;
	} else if (arg1[0] == ARG_ADDRESS_1_POST_I) {
		mc |= ARM64_LDPSTP_POST_INDEX;
	} else {
		goto invalid;
	}
	if (unlikely(arg2[0] >= 32) || unlikely(arg3[0] >= 32))
		goto invalid;
	mc |= arg2[0];
	mc |= (uint32_t)arg3[0] << 10;
	mc |= (uint32_t)arg1[1] << 5;
	imm = get_imm(&arg1[2]);
	if (unlikely((imm & ((1 << size) - 1)) != 0))
		goto invalid;
	imm /= 1 << size;
	if (unlikely(imm < -64) || unlikely(imm > 63))
		goto invalid;
	mc |= (imm & 127) << 15;
	cgen_four(mc);
	return true;

invalid:
	internal(file_line, "cgen_ldp_stp: invalid arguments %02x, %02x, %02x", arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_mov_mask(struct codegen_context *ctx, unsigned aux)
{
	uint32_t mc;
	uint64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32) || unlikely(arg3[0] != ARG_IMM))
		internal(file_line, "cgen_mov_mask: bad arguments");
	mc = ARM64_MOVK;
	mc |= ARM64_MOVK_SIZE;
	mc |= (uint32_t)aux << 21;
	imm = get_imm(&arg3[1]);
	if (unlikely(imm >= 0x10000))
		internal(file_line, "cgen_mov_mask: bad number");
	mc |= (imm & 0xffff) << 5;
	mc |= arg1[0];
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_cmp(struct codegen_context *ctx, unsigned op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM64_FCMP;
	switch (op_size) {
		case OP_SIZE_2:		mc |= ARM64_FCMP_HALF; break;
		case OP_SIZE_4:		mc |= ARM64_FCMP_SINGLE; break;
		case OP_SIZE_8:		mc |= ARM64_FCMP_DOUBLE; break;
		default:		internal(file_line, "cgen_fp_cmp: invalid size %u", op_size);
	}
	mc |= ((uint32_t)(arg1[0] & 31)) << 5;
	mc |= ((uint32_t)(arg2[0] & 31)) << 16;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_alu(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	mc = ARM64_FP_ALU;
	switch (aux) {
		case FP_ALU_ADD:	mc |= ARM64_FP_ALU_ADD; break;
		case FP_ALU_SUB:	mc |= ARM64_FP_ALU_SUB; break;
		case FP_ALU_MUL:	mc |= ARM64_FP_ALU_MUL; break;
		case FP_ALU_DIV:	mc |= ARM64_FP_ALU_DIV; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_2:		mc |= ARM64_FP_ALU_HALF; break;
		case OP_SIZE_4:		mc |= ARM64_FP_ALU_SINGLE; break;
		case OP_SIZE_8:		mc |= ARM64_FP_ALU_DOUBLE; break;
		default:		internal(file_line, "cgen_fp_alu: invalid size %u", op_size);
	}
	mc |= arg1[0] & 31;
	mc |= ((uint32_t)(arg2[0] & 31)) << 5;
	mc |= ((uint32_t)(arg3[0] & 31)) << 16;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	mc = ARM64_FP_ALU1 | ARM64_FP_ALU1_NEG; break;
		case FP_ALU1_SQRT:	mc = ARM64_FP_ALU1 | ARM64_FP_ALU1_SQRT; break;
		case FP_ALU1_ROUND:	mc = ARM64_FP_ALU1 | ARM64_FP_ALU1_RINTN; break;
		case FP_ALU1_FLOOR:	mc = ARM64_FP_ALU1 | ARM64_FP_ALU1_RINTM; break;
		case FP_ALU1_CEIL:	mc = ARM64_FP_ALU1 | ARM64_FP_ALU1_RINTP; break;
		case FP_ALU1_TRUNC:	mc = ARM64_FP_ALU1 | ARM64_FP_ALU1_RINTZ; break;
		case FP_ALU1_VCNT8:	mc = ARM64_CNT; goto do_regs;
		case FP_ALU1_ADDV:	mc = ARM64_ADDV; goto do_regs;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_2:		mc |= ARM64_FP_ALU1_HALF; break;
		case OP_SIZE_4:		mc |= ARM64_FP_ALU1_SINGLE; break;
		case OP_SIZE_8:		mc |= ARM64_FP_ALU1_DOUBLE; break;
		default:		internal(file_line, "cgen_fp_alu1: invalid size %u", op_size);
	}
do_regs:
	mc |= arg1[0] & 31;
	mc |= ((uint32_t)(arg2[0] & 31)) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM64_FCVTZS;
	switch (int_op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= ARM64_FCVTZS_SIZE; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid int size %u", int_op_size);
	}
	switch (fp_op_size) {
		case OP_SIZE_2:		mc |= ARM64_FCVTZS_HALF; break;
		case OP_SIZE_4:		mc |= ARM64_FCVTZS_SINGLE; break;
		case OP_SIZE_8:		mc |= ARM64_FCVTZS_DOUBLE; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid fp size %u", fp_op_size);
	}
	mc |= arg1[0];
	mc |= ((uint32_t)(arg2[0] & 31)) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM64_SCVTF;
	switch (int_op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= ARM64_SCVTF_SIZE; break;
		default:		internal(file_line, "cgen_fp_from_int: invalid int size %u", int_op_size);
	}
	switch (fp_op_size) {
		case OP_SIZE_2:		mc |= ARM64_SCVTF_HALF; break;
		case OP_SIZE_4:		mc |= ARM64_SCVTF_SINGLE; break;
		case OP_SIZE_8:		mc |= ARM64_SCVTF_DOUBLE; break;
		default:		internal(file_line, "cgen_fp_from_int: invalid fp size %u", fp_op_size);
	}
	mc |= arg1[0] & 31;
	mc |= ((uint32_t)arg2[0]) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_cvt(struct codegen_context *ctx, unsigned from_op_size, unsigned to_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM64_FCVT;
	switch (from_op_size) {
		case OP_SIZE_2:	mc |= ARM64_FCVT_FROM_HALF; break;
		case OP_SIZE_4: mc |= ARM64_FCVT_FROM_SINGLE; break;
		case OP_SIZE_8: mc |= ARM64_FCVT_FROM_DOUBLE; break;
		default:	internal(file_line, "cgen_fp_cvt: invalid types %u, %u", from_op_size, to_op_size);
	}
	switch (to_op_size) {
		case OP_SIZE_2:	mc |= ARM64_FCVT_TO_HALF; break;
		case OP_SIZE_4: mc |= ARM64_FCVT_TO_SINGLE; break;
		case OP_SIZE_8: mc |= ARM64_FCVT_TO_DOUBLE; break;
		default:	internal(file_line, "cgen_fp_cvt: invalid types %u, %u", from_op_size, to_op_size);
	}
	mc |= arg1[0] & 31;
	mc |= ((uint32_t)arg2[0] & 31) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_jmp_cond(struct codegen_context *ctx, unsigned aux, unsigned length)
{
	int8_t cond = jmp_cond[aux];
	if (unlikely(cond < 0))
		internal(file_line, "cgen_jmp_cond: invalid condition %u", aux);
	switch (length) {
		case JMP_SHORTEST:
		case JMP_SHORT:
			g(add_relocation(ctx, JMP_SHORT, 0, NULL));
			cgen_four(ARM64_B_COND | cond);
			return true;
		case JMP_LONG:
			cgen_four(ARM64_B_COND | (cond ^ 1) | 0x40);
			g(add_relocation(ctx, JMP_LONG, 0, NULL));
			cgen_four(ARM64_B);
			return true;
		default:
			internal(file_line, "cgen_jmp_cond: invalid length %u", length);
			return false;
	}
}

static bool attr_w cgen_jmp_reg_bit(struct codegen_context *ctx, unsigned bit, bool jnz, unsigned length);

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned size, unsigned aux, unsigned length)
{
	uint32_t mc = ARM64_CB;
	mc |= ARM64_CBZ_SIZE * (size == OP_SIZE_8);
	switch (aux) {
		case COND_E:
			break;
		case COND_NE:
			mc |= ARM64_CBZ_CBNZ;
			break;
		case COND_S:
		case COND_L:
			g(cgen_jmp_reg_bit(ctx, size == OP_SIZE_8 ? 63 : 31, true, length));
			return true;
		case COND_NS:
		case COND_GE:
			g(cgen_jmp_reg_bit(ctx, size == OP_SIZE_8 ? 63 : 31, false, length));
			return true;
		default:
			internal(file_line, "cgen_jmp_reg: invalid condition %u", aux);
	}
	mc |= cget_one(ctx);
	switch (length) {
		case JMP_SHORTEST:
		case JMP_SHORT:
			g(add_relocation(ctx, JMP_SHORT, 1, NULL));
			cgen_four(mc);
			return true;
		case JMP_LONG:
			cgen_four((mc ^ ARM64_CBZ_CBNZ) | 0x40);
			g(add_relocation(ctx, JMP_LONG, 1, NULL));
			cgen_four(ARM64_B);
			return true;
		default:
			internal(file_line, "cgen_jmp_reg: invalid length %u", length);
			return false;
	}
}

static bool attr_w cgen_jmp_reg_bit(struct codegen_context *ctx, unsigned bit, bool jnz, unsigned length)
{
	uint32_t mc = ARM64_TB;
	mc |= ARM64_TB_TBNZ * (uint32_t)jnz;
	mc |= cget_one(ctx);
	mc |= (uint32_t)(bit & 31) << 19;
	mc |= (uint32_t)(bit >> 5 << 31);
	switch (length) {
		case JMP_SHORTEST:
			g(add_relocation(ctx, JMP_SHORTEST, 1, NULL));
			cgen_four(mc);
			return true;
		case JMP_SHORT:
		case JMP_LONG:
			cgen_four((mc ^ ARM64_TB_TBNZ) | 0x40);
			g(add_relocation(ctx, JMP_LONG, 1, NULL));
			cgen_four(ARM64_B);
			return true;
		default:
			internal(file_line, "cgen_jmp_reg_bit: invalid length %u", length);
			return false;
	}
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 2) - (int64_t)(reloc->position >> 2);
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x00002000) || unlikely(offs >= 0x00002000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0xfff8001fU;
			mc |= ((uint32_t)offs << 5) & 0x0007ffe0;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_SHORT:
			if (unlikely(offs < -0x00040000) || unlikely(offs >= 0x00040000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0xff00001fU;
			mc |= ((uint32_t)offs << 5) & 0x00ffffe0;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_LONG:
			if (unlikely(offs < -0x02000000) || unlikely(offs >= 0x02000000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0xfc000000U;
			mc |= offs & 0x03ffffffU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	uint32_t reg;
	/*debug("insn: %08x (%s)", insn, da(ctx->fn,function)->function_name);*/
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			cgen_four(ARM64_RET);
			return true;
		case INSN_CALL_INDIRECT:
			reg = cget_one(ctx);
			cgen_four(ARM64_BLR | (reg << 5));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn), false));
			return true;
		case INSN_MOVSX:
			g(cgen_mov(ctx, insn_op_size(insn), true));
			return true;
		case INSN_CMP:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_cmp(ctx, insn_op_size(insn), false));
			return true;
		case INSN_CMN:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_cmp(ctx, insn_op_size(insn), true));
			return true;
		case INSN_TEST:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_test(ctx, insn_op_size(insn)));
			return true;
		case INSN_ALU:
		case INSN_ALU_FLAGS:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_writes_flags(insn), insn_aux(insn)));
			return true;
		case INSN_ALU1:
		case INSN_ALU1_FLAGS:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_writes_flags(insn), insn_aux(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_MADD:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_madd(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_SET_COND:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_set_cond(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_CMOV:
		case INSN_CMOV_XCC:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_csel(ctx, INSN_CSEL_SEL, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_CSEL_SEL:
		case INSN_CSEL_INC:
		case INSN_CSEL_INV:
		case INSN_CSEL_NEG:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_csel(ctx, insn_opcode(insn), insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_STP:
		case INSN_LDP:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_ldp_stp(ctx, insn_opcode(insn) == INSN_LDP, insn_op_size(insn)));
			return true;
		case INSN_MOV_MASK:
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_mov_mask(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_CMP:
			g(cgen_fp_cmp(ctx, insn_op_size(insn)));
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
		case INSN_FP_CVT:
			g(cgen_fp_cvt(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_JMP:
			g(add_relocation(ctx, JMP_LONG, 0, NULL));
			cgen_four(ARM64_B);
			return true;
		case INSN_JMP_COND:
			g(cgen_jmp_cond(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_jmp_reg(ctx, insn_op_size(insn), insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG_BIT:
			g(cgen_jmp_reg_bit(ctx, insn_aux(insn) & 63, insn_aux(insn) >> 6, insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			reg = cget_one(ctx);
			cgen_four(ARM64_BR | (reg << 5));
			return true;
		invalid_insn:
		default:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
