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

#define  ARM_ALWAYS			0xe0000000U
#define  ARM_WRITE_FLAGS		0x00100000U

#define  ARM_LDR_STR_LD			0x00100000U
#define  ARM_LDR_STR_W			0x00200000U
#define  ARM_LDR_STR_U			0x00800000U
#define  ARM_LDR_STR_P			0x01000000U
#define ARM_STRH_REG		0x000000b0U
#define ARM_LDRD_REG		0x000000d0U
#define ARM_STRD_REG		0x000000f0U
#define ARM_LDRSB_REG		0x001000d0U
#define ARM_LDRSH_REG		0x001000f0U
#define ARM_STRH_IMM		0x004000b0U
#define ARM_LDRD_IMM		0x004000d0U
#define ARM_STRD_IMM		0x004000f0U
#define ARM_LDRSB_IMM		0x005000d0U
#define ARM_LDRSH_IMM		0x005000f0U
#define ARM_STR_IMM		0x04000000U
#define ARM_STRB_IMM		0x04400000U
#define ARM_STR_REG		0x06000000U
#define ARM_STRB_REG		0x06400000U

#define  ARM_ALU_IMM			0x02000000U
#define  ARM_ALU_REG_SHIFTED		0x00000010U
#define  ARM_ROT_LSL			0x00000000U
#define  ARM_ROT_LSR			0x00000020U
#define  ARM_ROT_ASR			0x00000040U
#define  ARM_ROT_ROR			0x00000060U
#define ARM_AND			0x00000000U
#define ARM_EOR			0x00200000U
#define ARM_SUB			0x00400000U
#define ARM_RSB			0x00600000U
#define ARM_ADD			0x00800000U
#define ARM_ADC			0x00a00000U
#define ARM_SBC			0x00c00000U
#define ARM_RSC			0x00e00000U
#define ARM_TST			0x01100000U
#define ARM_TEQ			0x01300000U
#define ARM_CMP			0x01500000U
#define ARM_CMN			0x01700000U
#define ARM_ORR			0x01800000U
#define ARM_MOV			0x01a00000U
#define ARM_BIC			0x01c00000U
#define ARM_MVN			0x01e00000U

#define ARM_MUL			0x00000090U
#define ARM_MLA			0x00200090U
#define ARM_MLS			0x00600090U
#define ARM_UMULL		0x00800090U
#define ARM_SMULL		0x00c00090U
#define ARM_BX			0x012fff10U
#define ARM_BLX_REG		0x012fff30U
#define ARM_CLZ			0x016f0f10U
#define ARM_MOV_IMM16		0x03000000U
#define ARM_MOVT		0x03400000U
#define ARM_REV			0x06bf0f30U
#define ARM_REV16		0x06bf0fb0U
#define ARM_RBIT		0x06ff0f30U
#define ARM_SDIV		0x0710f010U
#define ARM_UDIV		0x0730f010U
#define ARM_POP			0x08bd0000U
#define ARM_PUSH		0x092d0000U
#define ARM_B			0x0a000000U

#define  ARM_V_D			0x00000100U
#define ARM_VSTR		0x0d000a00U
#define ARM_VLDR		0x0d100a00U
#define ARM_VMOV_S32_R		0x0e000a10U
#define ARM_VMOV_R_S32		0x0e100a10U
#define ARM_VMUL		0x0e200a00U
#define ARM_VADD		0x0e300a00U
#define ARM_VSUB		0x0e300a40U
#define ARM_VDIV		0x0e800a00U
#define ARM_VMOV		0x0eb00a40U
#define ARM_VNEG		0x0eb10a40U
#define ARM_VSQRT		0x0eb10ac0U
#define ARM_VCVT_F32_F16	0x0eb20a40U
#define ARM_VCVT_F16_F32	0x0eb30a40U
#define ARM_VCMP		0x0eb40a40U
#define ARM_VCVT_F_S32		0x0eb80ac0U
#define ARM_VCVT_S32_F		0x0ebd0ac0U
#define ARM_VMRS_NZCV_FPSCR	0x0ef1fa10U

#define  ARM_V_BYTE			0x00000000U
#define  ARM_V_HALF			0x00000400U
#define ARM_VST1		0xf480000fU
#define ARM_VLD1		0xf4a0000fU
#define  ARM_VCNT_8_Q			0x00000040U
#define ARM_VCNT_8		0xf3b00500U
#define ARM_VPADDL_U8		0xf3b00280U
#define ARM_VPADDL_U16		0xf3b40280U
#define ARM_VPADDL_U32		0xf3b80280U

static const uint32_t alu_codes[7] = {
	ARM_ADD,
	ARM_ORR,
	ARM_ADC,
	ARM_SBC,
	ARM_AND,
	ARM_SUB,
	ARM_EOR,
};

static const int8_t jmp_cond[48] = {
	0x6, 0x7, 0x3, 0x2, 0x0, 0x1, 0x9, 0x8,
	0x4, 0x5,  -1,  -1, 0xb, 0xa, 0xd, 0xc,
	 -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	 -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	 -1,  -1, 0x3, 0x2, 0x0, 0x1, 0x9, 0x8,
	 -1,  -1, 0x6, 0x7,  -1,  -1,  -1,  -1,
};

static const int8_t rot_codes[8] = {
	-1,
	ARM_ROT_ROR,
	-1,
	-1,
	ARM_ROT_LSL,
	ARM_ROT_LSR,
	-1,
	ARM_ROT_ASR,
};

static bool attr_w cgen_arm_push_pop(struct codegen_context *ctx, bool pop)
{
	bool need_bx = false;
	uint32_t mc = ARM_ALWAYS;
	mc |= pop ? ARM_POP : ARM_PUSH;
#if defined(__thumb__) || defined(__thumb2__)
	if (pop) {
		if (unlikely(!cpu_test_feature(CPU_FEATURE_armv5)))
			need_bx = true;
	}
#endif
	mc |= 1U << R_2;
	mc |= 1U << R_4;
	mc |= 1U << R_5;
	mc |= 1U << R_6;
	mc |= 1U << R_7;
	mc |= 1U << R_8;
	mc |= 1U << R_9;
	mc |= 1U << R_10;
	mc |= 1U << R_FP;
	mc |= 1U << (pop && !need_bx ? R_PC : R_LR);
	cgen_four(mc);
	if (need_bx) {
		mc = ARM_ALWAYS | ARM_BX;
		mc |= R_LR;
		cgen_four(mc);
	}
	return true;
}

static bool attr_w cgen_call_indirect(struct codegen_context *ctx)
{
	uint32_t mc;
	bool blx = false;
	uint8_t reg = cget_one(ctx);

#if defined(__thumb__) || defined(__thumb2__)
	blx = true;
#else
	if (likely(cpu_test_feature(CPU_FEATURE_armv6)))
		blx = true;
#endif

	if (blx) {
		mc = ARM_ALWAYS | ARM_BLX_REG;
		mc |= reg;
		cgen_four(mc);
	} else {
		mc = ARM_ALWAYS | ARM_MOV;
		mc |= (uint32_t)R_LR << 12;
		mc |= R_PC;
		cgen_four(mc);

		mc = ARM_ALWAYS | ARM_MOV;
		mc |= (uint32_t)R_PC << 12;
		mc |= reg;
		cgen_four(mc);
	}

	return true;
}

static bool attr_w cgen_ldr_str(struct codegen_context *ctx, bool ld, uint32_t cond, unsigned size, bool sx, uint8_t reg, uint8_t *address)
{
	int64_t imm;
	uint32_t mc = cond;
	if (ld)
		mc |= ARM_LDR_STR_LD;
	if (size == OP_SIZE_NATIVE)
		sx = false;
	if (address[0] >= ARG_ADDRESS_2 && address[0] <= ARG_ADDRESS_2_8) {
		imm = get_imm(&address[3]);
		if (unlikely(imm != 0))
			goto invalid;
		if (sx || size == OP_SIZE_2) {
			if (unlikely(address[0] != ARG_ADDRESS_2))
				goto invalid;
			if (sx)
				mc |= size == OP_SIZE_2 ? ARM_LDRSH_REG : ARM_LDRSB_REG;
			else
				mc |= ARM_STRH_REG;
		} else {
			mc |= size == OP_SIZE_1 ? ARM_STRB_REG : ARM_STR_REG;
		}
		mc |= ARM_LDR_STR_U;
		mc |= ARM_LDR_STR_P;
		mc |= (uint32_t)address[1] << 16;
		mc |= address[2];
		mc |= (uint32_t)reg << 12;
		mc |= (uint32_t)(address[0] - ARG_ADDRESS_2) << 7;
		cgen_four(mc);
		return true;
	}
	if (address[0] == ARG_ADDRESS_1 || address[0] == ARG_ADDRESS_1_PRE_I || address[0] == ARG_ADDRESS_1_POST_I) {
		imm = get_imm(&address[2]);
		if (!(imm >= -4095 && imm <= 4095))
			goto invalid;
		if (imm < 0) {
			imm = -imm;
		} else {
			mc |= ARM_LDR_STR_U;
		}
		if (sx || size == OP_SIZE_2) {
			if (unlikely(imm >= 256))
				goto invalid;
			if (sx)
				mc |= size == OP_SIZE_2 ? ARM_LDRSH_IMM : ARM_LDRSB_IMM;
			else
				mc |= ARM_STRH_IMM;
			mc |= imm & 0xf;
			mc |= (imm & 0xf0) << 4;
		} else {
			mc |= size == OP_SIZE_1 ? ARM_STRB_IMM : ARM_STR_IMM;
			mc |= imm;
		}
		if (address[0] == ARG_ADDRESS_1) {
			mc |= ARM_LDR_STR_P;
		} else if (address[0] == ARG_ADDRESS_1_PRE_I) {
			mc |= ARM_LDR_STR_P;
			mc |= ARM_LDR_STR_W;
		}
		mc |= (uint32_t)address[1] << 16;
		mc |= (uint32_t)reg << 12;
		cgen_four(mc);
		return true;
	}

	imm = 0;
invalid:
	internal(file_line, "cgen_ldr_str: invalid address: %02x, %02x, %"PRIxMAX"", reg, address[0], (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_vldr_vstr(struct codegen_context *ctx, bool ld, uint32_t cond, unsigned size, uint8_t reg, uint8_t *address)
{
	int64_t imm = 0;
	uint32_t mc;

	if (size < OP_SIZE_4) {
		mc = ld ? ARM_VLD1 : ARM_VST1;
		mc |= size == OP_SIZE_1 ? ARM_V_BYTE : ARM_V_HALF;
		mc |= (uint32_t)address[1] << 16;
		mc |= (uint32_t)(reg & 0x1e) << 11;
		mc |= (uint32_t)(reg & 1) << 22;
		cgen_four(mc);
		return true;
	}

	mc = cond;
	mc |= ld ? ARM_VLDR : ARM_VSTR;

	if (unlikely(address[0] != ARG_ADDRESS_1))
		goto invalid;

	imm = get_imm(&address[2]);
	if (!(imm >= -1023 && imm <= 1023))
		goto invalid;

	if (imm < 0) {
		imm = -imm;
	} else {
		mc |= ARM_LDR_STR_U;
	}

	mc |= (uint32_t)address[1] << 16;
	mc |= (uint32_t)(reg & 0x1e) << 11;
	mc |= (uint32_t)(reg & 1) << 22;
	mc |= (imm >> 2) & 0xff;
	if (size == OP_SIZE_8)
		mc |= ARM_V_D;
	cgen_four(mc);
	return true;

invalid:
	internal(file_line, "cgen_vldr_vstr: invalid address: %02x, %02x, %"PRIxMAX"", reg, address[0], (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_mov_args(struct codegen_context *ctx, uint32_t cond, unsigned size, bool sx, uint8_t *arg1, uint8_t *arg2)
{
	int64_t imm;
	uint32_t mc;
	if (arg1[0] < 16) {
		if (arg2[0] < 16) {
			if (unlikely(sx))
				internal(file_line, "cgen_mov_args: unsupported sign extension");
			if (unlikely(size != OP_SIZE_NATIVE))
				internal(file_line, "cgen_mov_args: unsupported size %u", size);
			mc = cond | ARM_MOV;
			mc |= arg2[0];
			mc |= (uint32_t)arg1[0] << 12;
			cgen_four(mc);
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			if (unlikely(sx))
				internal(file_line, "cgen_mov_args: unsupported sign extension");
			if (unlikely(size != OP_SIZE_NATIVE))
				internal(file_line, "cgen_mov_args: unsupported size %u", size);
			mc = cond | ARM_VMOV_R_S32;
			mc |= (uint32_t)(arg2[0] & 0x1e) << 15;
			mc |= (uint32_t)(arg2[0] & 1) << 7;
			mc |= (uint32_t)arg1[0] << 12;
			cgen_four(mc);
			return true;
		}
		if (arg2[0] == ARG_IMM) {
			int imm12;
			imm = get_imm(&arg2[1]);
			imm12 = gen_imm12(imm);
			if (imm12 >= 0) {
				mc = cond | ARM_MOV | ARM_ALU_IMM;
				mc |= (uint32_t)arg1[0] << 12;
				mc |= imm12;
				cgen_four(mc);
				return true;
			}
			imm12 = gen_imm12(~imm);
			if (imm12 >= 0) {
				mc = cond | ARM_MVN | ARM_ALU_IMM;
				mc |= (uint32_t)arg1[0] << 12;
				mc |= imm12;
				cgen_four(mc);
				return true;
			}
			if ((uint32_t)imm >= 0x10000)
				goto invalid;
			mc = cond | ARM_MOV_IMM16;
			mc |= (uint32_t)arg1[0] << 12;
			mc |= imm & 0xfff;
			mc |= (imm & 0xf000) << 4;
			cgen_four(mc);
			return true;
		}
		return cgen_ldr_str(ctx, true, cond, size, sx, arg1[0], arg2);
	}
	if (reg_is_fp(arg1[0])) {
		if (arg2[0] < 16) {
			if (unlikely(sx))
				internal(file_line, "cgen_mov_args: unsupported sign extension");
			if (unlikely(size != OP_SIZE_NATIVE))
				internal(file_line, "cgen_mov_args: unsupported size %u", size);
			mc = cond | ARM_VMOV_S32_R;
			mc |= (uint32_t)(arg1[0] & 0x1e) << 15;
			mc |= (uint32_t)(arg1[0] & 1) << 7;
			mc |= (uint32_t)arg2[0] << 12;
			cgen_four(mc);
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			mc = cond | ARM_VMOV;
			switch (size) {
				case OP_SIZE_4:		break;
				case OP_SIZE_8:		mc |= ARM_V_D; break;
				default:		internal(file_line, "cgen_mov_args: invalid size %u", size);
			}
			mc |= (uint32_t)(arg1[0] & 0x1e) << 11;
			mc |= (uint32_t)(arg1[0] & 1) << 22;
			mc |= (uint32_t)(arg2[0] & 0x1e) >> 1;
			mc |= (uint32_t)(arg2[0] & 1) << 5;
			cgen_four(mc);
			return true;
		}
		return cgen_vldr_vstr(ctx, true, cond, size, arg1[0] & 31, arg2);
	}
	if (arg2[0] < 16) {
		return cgen_ldr_str(ctx, false, cond, size, false, arg2[0], arg1);
	}
	if (reg_is_fp(arg2[0])) {
		return cgen_vldr_vstr(ctx, false, cond, size, arg2[0] & 31, arg1);
	}
invalid:
	internal(file_line, "cgen_mov_args: invalid arguments %02x, %02x", arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size, bool sx)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	g(cgen_mov_args(ctx, ARM_ALWAYS, size, sx, arg1, arg2));
	return true;
}

static bool attr_w cgen_alu_args(struct codegen_context *ctx, unsigned writes_flags, uint32_t mc, uint8_t *arg1, uint8_t *arg2, uint8_t *arg3)
{
	int64_t imm;
	int imm12;
	if (unlikely(arg1[0] >= 16))
		goto invalid;
	if (unlikely(arg2[0] >= 16))
		goto invalid;
	mc |= ARM_ALWAYS;
	if (writes_flags)
		mc |= ARM_WRITE_FLAGS;
	mc |= (uint32_t)arg1[0] << 12;
	mc |= (uint32_t)arg2[0] << 16;
	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		imm12 = gen_imm12(imm);
		if (unlikely(imm12 < 0))
			goto invalid;
		mc |= ARM_ALU_IMM;
		mc |= imm12;
		cgen_four(mc);
		return true;
	}
	if (likely(arg3[0] < 16)) {
		mc |= arg3[0];
		cgen_four(mc);
		return true;
	}
	if (arg3[0] == ARG_SHIFTED_REGISTER) {
		unsigned mode = arg3[1] >> 6;
		unsigned amount = arg3[1] & ARG_SHIFT_AMOUNT;
		if (!amount)
			mode = 0;
		mc |= arg3[2];
		mc |= (uint32_t)mode << 5;
		mc |= ((uint32_t)amount & 0x1f) << 7;
		cgen_four(mc);
		return true;
	}

invalid:
	internal(file_line, "cgen_alu_args: invalid arguments %02x, %02x, %02x, %08x, %u", arg1[0], arg2[0], arg3[0], (unsigned)mc, writes_flags);
	return false;
}

static bool attr_w cgen_cmp(struct codegen_context *ctx, bool cmn)
{
	uint8_t z = 0;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	return cgen_alu_args(ctx, true, cmn ? ARM_CMN : ARM_CMP, &z, arg1, arg2);
}

static bool attr_w cgen_test(struct codegen_context *ctx)
{
	uint8_t z = 0;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	return cgen_alu_args(ctx, true, ARM_TST, &z, arg1, arg2);
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned writes_flags, unsigned alu)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(alu >= 7)) {
		uint32_t mc = ARM_ALWAYS;
		if (alu == ALU_ANDN) {
			return cgen_alu_args(ctx, writes_flags, ARM_BIC, arg1, arg2, arg3);
		} else if (alu == ALU_MUL) {
			mc |= ARM_MUL;
		} else if (alu == ALU_UDIV) {
			mc |= ARM_UDIV;
		} else if (alu == ALU_SDIV) {
			mc |= ARM_SDIV;
		} else {
			internal(file_line, "cgen_alu: invalid alu %u", alu);
		}
		mc |= (uint32_t)arg1[0] << 16;
		mc |= arg2[0];
		mc |= (uint32_t)arg3[0] << 8;
		cgen_four(mc);
		return true;
	}
	return cgen_alu_args(ctx, writes_flags, alu_codes[alu], arg1, arg2, arg3);
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned writes_flags, unsigned alu)
{
	uint32_t mc;
	uint8_t z = 0;
	uint8_t z_imm[9] = { ARG_IMM, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t one_imm[9] = { ARG_IMM, 1, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (alu) {
		case ALU1_NOT:
			return cgen_alu_args(ctx, writes_flags, ARM_MVN, arg1, &z, arg2);
		case ALU1_NEG:
			return cgen_alu_args(ctx, writes_flags, ARM_RSB, arg1, arg2, z_imm);
		case ALU1_NGC:
			return cgen_alu_args(ctx, writes_flags, ARM_RSC, arg1, arg2, z_imm);
		case ALU1_INC:
			return cgen_alu_args(ctx, writes_flags, ARM_ADD, arg1, arg2, one_imm);
		case ALU1_DEC:
			return cgen_alu_args(ctx, writes_flags, ARM_SUB, arg1, arg2, one_imm);
		case ALU1_BSWAP:
			mc = ARM_ALWAYS | ARM_REV;
			break;
		case ALU1_BSWAP16:
			mc = ARM_ALWAYS | ARM_REV16;
			break;
		case ALU1_BREV:
			mc = ARM_ALWAYS | ARM_RBIT;
			break;
		case ALU1_LZCNT:
			mc = ARM_ALWAYS | ARM_CLZ;
			break;
		default:
			internal(file_line, "cgen_alu1: invalid alu %u", alu);
			return false;
	}
	mc |= (uint32_t)arg1[0] << 12;
	mc |= arg2[0];
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned writes_flags, unsigned rot)
{
	int8_t arm_rot;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	mc = ARM_ALWAYS | ARM_MOV;
	if (writes_flags)
		mc |= ARM_WRITE_FLAGS;
	arm_rot = rot_codes[rot];
	if (unlikely(arm_rot < 0))
		internal(file_line, "cgen_rot: invalid rotation %u", rot);
	if (arg3[0] == ARG_IMM) {
		uint8_t imm = arg3[1];
		if (!imm)
			arm_rot = ARM_ROT_LSL;
		mc |= (uint32_t)imm << 7;
	} else {
		mc |= ARM_ALU_REG_SHIFTED;
		mc |= (uint32_t)arg3[0] << 8;
	}
	mc |= arm_rot;
	mc |= (uint32_t)arg1[0] << 12;
	mc |= arg2[0];
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_mul_l(struct codegen_context *ctx, bool sgn)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	if (unlikely(arg1[0] >= 16) || unlikely(arg2[0] >= 16) || unlikely(arg3[0] >= 16) || unlikely(arg4[0] >= 16))
		internal(file_line, "cgen_madd: invalid arguments");
	mc = ARM_ALWAYS;
	mc |= sgn ? ARM_SMULL : ARM_UMULL;
	mc |= (uint32_t)arg1[0] << 12;
	mc |= (uint32_t)arg2[0] << 16;
	mc |= arg3[0];
	mc |= (uint32_t)arg4[0] << 8;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_madd(struct codegen_context *ctx, bool sub)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	if (unlikely(arg1[0] >= 16) || unlikely(arg2[0] >= 16) || unlikely(arg3[0] >= 16) || unlikely(arg4[0] >= 16))
		internal(file_line, "cgen_madd: invalid arguments");
	mc = ARM_ALWAYS;
	mc |= sub ? ARM_MLS : ARM_MLA;
	mc |= (uint32_t)arg1[0] << 16;
	mc |= arg2[0];
	mc |= (uint32_t)arg3[0] << 8;
	mc |= (uint32_t)arg4[0] << 12;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_cmov(struct codegen_context *ctx, unsigned size, unsigned aux)
{
	int8_t cond;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != arg2[0]))
		internal(file_line, "cgen_cmov: invalid arguments");
	cond = jmp_cond[aux];
	if (unlikely(cond < 0))
		internal(file_line, "cgen_cmov: invalid condition %u", aux);
	g(cgen_mov_args(ctx, (uint32_t)cond << 28, size, false, arg1, arg3));
	return true;
}

static bool attr_w cgen_ldp_stp(struct codegen_context *ctx, bool ldr)
{
	uint8_t *arg1, *arg2, *arg3;
	int64_t imm;
	uint32_t mc = ARM_ALWAYS;
	if (!ldr) {
		arg1 = ctx->code_position;
		arg2 = arg1 + arg_size(*arg1);
		arg3 = arg2 + arg_size(*arg2);
		ctx->code_position = arg3 + arg_size(*arg3);
	} else {
		arg2 = ctx->code_position;
		arg3 = arg2 + arg_size(*arg2);
		arg1 = arg3 + arg_size(*arg3);
		ctx->code_position = arg1 + arg_size(*arg1);
	}
	if (unlikely(arg2[0] >= 16) || unlikely(arg3[0] >= 16))
		goto invalid;
	if (unlikely((arg2[0] & 1) != 0) || unlikely(arg3[0] != arg2[0] + 1))
		goto invalid;
	if (arg1[0] == ARG_ADDRESS_1 || arg1[0] == ARG_ADDRESS_1_PRE_I || arg1[0] == ARG_ADDRESS_1_POST_I) {
		mc |= !ldr ? ARM_STRD_IMM : ARM_LDRD_IMM;
		if (arg1[0] == ARG_ADDRESS_1) {
			mc |= ARM_LDR_STR_P;
		} else if (arg1[0] == ARG_ADDRESS_1_PRE_I) {
			mc |= ARM_LDR_STR_P;
			mc |= ARM_LDR_STR_W;
		}
		imm = get_imm(&arg1[2]);
		if (!(imm >= -255 && imm <= 255))
			goto invalid;
		if (imm < 0) {
			imm = -imm;
		} else {
			mc |= ARM_LDR_STR_U;
		}
		mc |= imm & 0xf;
		mc |= (imm & 0xf0) << 4;
	} else if (arg1[0] == ARG_ADDRESS_2) {
		imm = get_imm(&arg1[3]);
		if (unlikely(imm != 0))
			goto invalid;
		mc |= !ldr ? ARM_STRD_REG : ARM_LDRD_REG;
		mc |= ARM_LDR_STR_P;
		mc |= ARM_LDR_STR_U;
		mc |= arg1[2];
	} else {
		goto invalid;
	}
	mc |= (uint32_t)arg1[1] << 16;
	mc |= (uint32_t)arg2[0] << 12;
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
	if (unlikely(arg1[0] >= 16) || unlikely(arg2[0] >= 16) || unlikely(arg3[0] != ARG_IMM) || unlikely(aux != MOV_MASK_16_32))
		internal(file_line, "cgen_mov_mask: bad arguments");
	imm = get_imm(&arg3[1]);
	if (unlikely(imm >= 0x10000))
		internal(file_line, "cgen_mov_mask: bad number");
	mc = ARM_ALWAYS | ARM_MOVT;
	mc |= (uint32_t)arg1[0] << 12;
	mc |= imm & 0xfff;
	mc |= (imm & 0xf000) << 4;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_cmp(struct codegen_context *ctx, unsigned op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM_ALWAYS;
	mc |= ARM_VCMP;
	switch (op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= ARM_V_D; break;
		default:		internal(file_line, "cgen_fp_cmp: invalid size %u", op_size);
	}
	mc |= (uint32_t)(arg1[0] & 0x1e) << 11;
	mc |= (uint32_t)(arg1[0] & 1) << 22;
	mc |= (uint32_t)(arg2[0] & 0x1e) >> 1;
	mc |= (uint32_t)(arg2[0] & 1) << 5;
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
	mc = ARM_ALWAYS;
	switch (aux) {
		case FP_ALU_ADD:	mc |= ARM_VADD; break;
		case FP_ALU_SUB:	mc |= ARM_VSUB; break;
		case FP_ALU_MUL:	mc |= ARM_VMUL; break;
		case FP_ALU_DIV:	mc |= ARM_VDIV; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= ARM_V_D; break;
		default:		internal(file_line, "cgen_fp_alu: invalid size %u", op_size);
	}
	mc |= (uint32_t)(arg1[0] & 0x1e) << 11;
	mc |= (uint32_t)(arg1[0] & 1) << 22;
	mc |= (uint32_t)(arg2[0] & 0x1e) << 15;
	mc |= (uint32_t)(arg2[0] & 1) << 7;
	mc |= (uint32_t)(arg3[0] & 0x1e) >> 1;
	mc |= (uint32_t)(arg3[0] & 1) << 5;
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
		case FP_ALU1_NEG:	mc = ARM_ALWAYS | ARM_VNEG; break;
		case FP_ALU1_SQRT:	mc = ARM_ALWAYS | ARM_VSQRT; break;
		case FP_ALU1_VCNT8:	mc = ARM_VCNT_8; goto do_regs;
		case FP_ALU1_VPADDL:	mc = op_size == OP_SIZE_1 ? ARM_VPADDL_U8 : op_size == OP_SIZE_2 ? ARM_VPADDL_U16 : op_size == OP_SIZE_4 ? ARM_VPADDL_U32 : 0;
					if (!mc)
						goto invalid_size;
					goto do_regs;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= ARM_V_D; break;
invalid_size:
		default:		internal(file_line, "cgen_fp_alu1: invalid size %u", op_size);
	}
do_regs:
	mc |= (uint32_t)(arg1[0] & 0x1e) << 11;
	mc |= (uint32_t)(arg1[0] & 1) << 22;
	mc |= (uint32_t)(arg2[0] & 0x1e) >> 1;
	mc |= (uint32_t)(arg2[0] & 1) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM_ALWAYS;
	mc |= ARM_VCVT_S32_F;
	switch (fp_op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= ARM_V_D; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid size %u", fp_op_size);
	}
	mc |= (uint32_t)(arg1[0] & 0x1e) << 11;
	mc |= (uint32_t)(arg1[0] & 1) << 22;
	mc |= (uint32_t)(arg2[0] & 0x1e) >> 1;
	mc |= (uint32_t)(arg2[0] & 1) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM_ALWAYS;
	mc |= ARM_VCVT_F_S32;
	switch (fp_op_size) {
		case OP_SIZE_4:		break;
		case OP_SIZE_8:		mc |= ARM_V_D; break;
		default:		internal(file_line, "cgen_fp_from_int: invalid size %u", fp_op_size);
	}
	mc |= (uint32_t)(arg1[0] & 0x1e) << 11;
	mc |= (uint32_t)(arg1[0] & 1) << 22;
	mc |= (uint32_t)(arg2[0] & 0x1e) >> 1;
	mc |= (uint32_t)(arg2[0] & 1) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_cvt(struct codegen_context *ctx, unsigned from_op_size, unsigned to_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = ARM_ALWAYS;
	if (from_op_size == OP_SIZE_2 && to_op_size == OP_SIZE_4) {
		mc |= ARM_VCVT_F32_F16;
	} else if (from_op_size == OP_SIZE_4 && to_op_size == OP_SIZE_2) {
		mc |= ARM_VCVT_F16_F32;
	} else {
		internal(file_line, "cgen_fp_cvt: invalid types %u, %u", from_op_size, to_op_size);
	}
	mc |= (uint32_t)(arg1[0] & 0x1e) << 11;
	mc |= (uint32_t)(arg1[0] & 1) << 22;
	mc |= (uint32_t)(arg2[0] & 0x1e) >> 1;
	mc |= (uint32_t)(arg2[0] & 1) << 5;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_jmp_cond(struct codegen_context *ctx, unsigned aux, unsigned length)
{
	int8_t cond;
	uint32_t mc;
	if (unlikely(length != JMP_SHORTEST))
		internal(file_line, "cgen_jmp_cond: invalid length %u", length);
	cond = jmp_cond[aux];
	if (unlikely(cond < 0))
		internal(file_line, "cgen_jmp_cond: invalid condition %u", aux);
	g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
	mc = (uint32_t)cond << 28;
	mc |= ARM_B;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_jmp_indirect(struct codegen_context *ctx)
{
	uint8_t pc = R_PC;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	g(cgen_mov_args(ctx, ARM_ALWAYS, OP_SIZE_ADDRESS, false, &pc, arg1));
	return true;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 2) - (int64_t)(reloc->position >> 2) - 2;
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x00800000) || unlikely(offs >= 0x00800000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0xff000000U;
			mc |= offs & 0x00ffffffU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	/*debug("insn: %08x (%s)", insn, da(ctx->fn,function)->function_name);*/
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_ARM_PUSH:
		case INSN_ARM_POP:
			g(cgen_arm_push_pop(ctx, insn_opcode(insn) == INSN_ARM_POP));
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_call_indirect(ctx));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn), false));
			return true;
		case INSN_MOVSX:
			g(cgen_mov(ctx, insn_op_size(insn), true));
			return true;
		case INSN_CMP:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_cmp(ctx, false));
			return true;
		case INSN_CMN:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_cmp(ctx, true));
			return true;
		case INSN_TEST:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_test(ctx));
			return true;
		case INSN_ALU:
		case INSN_ALU_FLAGS:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_writes_flags(insn), insn_aux(insn)));
			return true;
		case INSN_ALU1:
		case INSN_ALU1_FLAGS:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_writes_flags(insn), insn_aux(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_writes_flags(insn), insn_aux(insn)));
			return true;
		case INSN_MUL_L:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_mul_l(ctx, insn_aux(insn)));
			return true;
		case INSN_MADD:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_madd(ctx, insn_aux(insn)));
			return true;
		case INSN_CMOV:
			g(cgen_cmov(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_STP:
		case INSN_LDP:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_ldp_stp(ctx, insn_opcode(insn) == INSN_LDP));
			return true;
		case INSN_MOV_MASK:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_mov_mask(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_CMP:
			g(cgen_fp_cmp(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_TO_INT_FLAGS:
			cgen_four(ARM_ALWAYS | ARM_VMRS_NZCV_FPSCR);
			return true;
		case INSN_FP_ALU:
			g(cgen_fp_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_ALU1:
			g(cgen_fp_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_TO_INT32:
			g(cgen_fp_to_int(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_FROM_INT32:
			g(cgen_fp_from_int(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_CVT:
			g(cgen_fp_cvt(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_JMP:
			g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
			cgen_four(ARM_ALWAYS | ARM_B);
			return true;
		case INSN_JMP_COND:
			g(cgen_jmp_cond(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_indirect(ctx));
			return true;
		invalid_insn:
		default:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
