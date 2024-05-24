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

#define ALPHA_OPERATE_LITERAL		0x00001000U

#define ALPHA_ADDL		0x40000000U
#define ALPHA_ADDL_V		0x40000800U
#define ALPHA_S4ADDL		0x40000040U
#define ALPHA_S8ADDL		0x40000240U
#define ALPHA_ADDQ		0x40000400U
#define ALPHA_ADDQ_V		0x40000c00U
#define ALPHA_S4ADDQ		0x40000440U
#define ALPHA_S8ADDQ		0x40000640U
#define ALPHA_SUBL		0x40000120U
#define ALPHA_SUBL_V		0x40000920U
#define ALPHA_S4SUBL		0x40000160U
#define ALPHA_S8SUBL		0x40000360U
#define ALPHA_SUBQ		0x40000520U
#define ALPHA_SUBQ_V		0x40000d20U
#define ALPHA_S4SUBQ		0x40000560U
#define ALPHA_S8SUBQ		0x40000760U

#define ALPHA_CMOVLBS		0x44000280U
#define ALPHA_CMOVLBC		0x440002c0U
#define ALPHA_CMOVEQ		0x44000480U
#define ALPHA_CMOVNE		0x440004c0U
#define ALPHA_CMOVLT		0x44000880U
#define ALPHA_CMOVGE		0x440008c0U
#define ALPHA_CMOVLE		0x44000c80U
#define ALPHA_CMOVGT		0x44000cc0U

#define ALPHA_LDA		0x20000000U
#define ALPHA_LDAH		0x24000000U
#define ALPHA_LDBU		0x28000000U
#define ALPHA_LDQ_U		0x2c000000U
#define ALPHA_LDWU		0x30000000U
#define ALPHA_STW		0x34000000U
#define ALPHA_STB		0x38000000U
#define ALPHA_STQ_U		0x3c000000U

#define ALPHA_CMPULT		0x400003a0U
#define ALPHA_CMPEQ		0x400005a0U
#define ALPHA_CMPULE		0x400007a0U
#define ALPHA_CMPLT		0x400009a0U
#define ALPHA_CMPLE		0x40000da0U
#define ALPHA_AND		0x44000000U
#define ALPHA_ANDNOT		0x44000100U
#define ALPHA_BIS		0x44000400U
#define ALPHA_ORNOT		0x44000500U
#define ALPHA_XOR		0x44000800U
#define ALPHA_EQV		0x44000900U
#define ALPHA_MSKBL		0x48000040U
#define ALPHA_EXTBL		0x480000c0U
#define ALPHA_INSBL		0x48000160U
#define ALPHA_EXTWL		0x480002c0U
#define ALPHA_EXTLL		0x480004c0U
#define ALPHA_ZAP		0x48000600U
#define ALPHA_ZAPNOT		0x48000620U
#define ALPHA_SRL		0x48000680U
#define ALPHA_SLL		0x48000720U
#define ALPHA_SRA		0x48000780U
#define ALPHA_EXTLH		0x48000d40U
#define ALPHA_MULL		0x4c000000U
#define ALPHA_MULQ		0x4c000400U
#define ALPHA_UMULH		0x4c000600U
#define ALPHA_MULL_V		0x4c000800U
#define ALPHA_MULQ_V		0x4c000c00U

#define ALPHA_ITOFS		0x501f0080U
#define ALPHA_ITOFT		0x501f0480U
#define ALPHA_SQRTS_SU		0x53e0b160U
#define ALPHA_SQRTT_SU		0x53e0b560U

#define ALPHA_CMPTEQ		0x580014a0U
#define ALPHA_CMPTLT		0x580014c0U
#define ALPHA_CMPTLE		0x580014e0U
#define ALPHA_CMPTUN_SU		0x5800b480U
#define ALPHA_ADDS_SU		0x5800b000U
#define ALPHA_SUBS_SU		0x5800b020U
#define ALPHA_MULS_SU		0x5800b040U
#define ALPHA_DIVS_SU		0x5800b060U
#define ALPHA_ADDT_SU		0x5800b400U
#define ALPHA_SUBT_SU		0x5800b420U
#define ALPHA_MULT_SU		0x5800b440U
#define ALPHA_DIVT_SU		0x5800b460U
#define ALPHA_CVTQS		0x5be01780U
#define ALPHA_CVTQT		0x5be017c0U
#define ALPHA_CVTTQ_V		0x5be035e0U

#define ALPHA_CPYS		0x5c000400U
#define ALPHA_CPYSN		0x5c000420U
#define ALPHA_CVTLQ		0x5fe00200U
#define ALPHA_CVTQL_V		0x5fe02600U

#define ALPHA_TRAPB		0x60000000U
#define ALPHA_MB		0x60004000U
#define ALPHA_JSR_T12		0x6b5b4000U
#define ALPHA_JMP		0x6be00000U
#define ALPHA_RETURN		0x6bfa8001U

#define ALPHA_FTOIT		0x701f0e00U
#define ALPHA_FTOIS		0x701f0f00U

#define ALPHA_SEXTB		0x73e00000U
#define ALPHA_SEXTW		0x73e00020U
#define ALPHA_CTPOP		0x73e00600U
#define ALPHA_CTLZ		0x73e00640U
#define ALPHA_CTTZ		0x73e00660U

#define ALPHA_LDS		0x88000000U
#define ALPHA_LDT		0x8c000000U
#define ALPHA_STS		0x98000000U
#define ALPHA_STT		0x9c000000U

#define ALPHA_LDL		0xa0000000U
#define ALPHA_LDQ		0xa4000000U
#define ALPHA_STL		0xb0000000U
#define ALPHA_STQ		0xb4000000U

#define ALPHA_BR		0xc3e00000U

#define ALPHA_BLBC		0xe0000000U
#define ALPHA_BEQ		0xe4000000U
#define ALPHA_BLT		0xe8000000U
#define ALPHA_BLE		0xec000000U
#define ALPHA_BLBS		0xf0000000U
#define ALPHA_BNE		0xf4000000U
#define ALPHA_BGE		0xf8000000U
#define ALPHA_BGT		0xfc000000U

static bool attr_w cgen_memory(struct codegen_context *ctx, uint32_t mc, unsigned ra, unsigned rb, int64_t imm)
{
	if (unlikely(imm < -0x8000) || unlikely(imm >= 0x8000))
		internal(file_line, "cgen_memory: invalid immediate value %"PRIxMAX"", (uintmax_t)imm);
	mc |= ra << 21;
	mc |= rb << 16;
	mc |= imm & 0xffff;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_operate(struct codegen_context *ctx, uint32_t mc, unsigned ra, uint8_t *rb, unsigned rc)
{
	if (unlikely(ra >= 0x20) || unlikely(rc >= 0x20))
		goto invalid;
	mc |= ra << 21;
	mc |= rc;
	if (rb[0] < 0x20) {
		mc |= (uint32_t)rb[0] << 16;
	} else if (rb[0] == ARG_IMM) {
		int64_t imm = get_imm(&rb[1]);
		if (unlikely(imm < 0) || unlikely(imm >= 256))
			internal(file_line, "cgen_operate: invalid literal %"PRIxMAX"", (uintmax_t)imm);
		mc |= ALPHA_OPERATE_LITERAL;
		mc |= (uint32_t)(imm & 0xff) << 13;
	} else {
invalid:
		internal(file_line, "cgen_operate: invalid args %02x, %02x, %02x", ra, rb[0], rc);
	}
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_fp_operate(struct codegen_context *ctx, uint32_t mc, unsigned ra, unsigned rb, unsigned rc)
{
	if (unlikely(ra >= 0x40) || unlikely(rb >= 0x40) || unlikely(rc >= 0x40))
		internal(file_line, "cgen_fp_operate: invalid args %02x, %02x, %02x", ra, rb, rc);
	mc |= (ra & 0x1f) << 21;
	mc |= rc & 0x1f;
	mc |= (rb & 0x1f) << 16;
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_branch(struct codegen_context *ctx, uint32_t mc, unsigned ra)
{
	mc |= ra << 21;
	g(add_relocation(ctx, JMP_SHORTEST, 1, NULL));
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size)
{
	uint32_t mc;
	int64_t imm;
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] < 0x20) {
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (imm >= -0x8000L && imm < 0x8000L) {
				g(cgen_memory(ctx, ALPHA_LDA, arg1[0], R_ZERO, imm));
				return true;
			}
			if (!(imm & 0xffff) && imm >= -0x80000000L && imm < 0x80000000L) {
				g(cgen_memory(ctx, ALPHA_LDAH, arg1[0], R_ZERO, imm / 0x10000));
				return true;
			}
			internal(file_line, "cgen_mov: invalid immediate value %"PRIxMAX"", (uintmax_t)imm);
		}
		if (arg2[0] == ARG_ADDRESS_1) {
			imm = get_imm(&arg2[2]);
			switch (size) {
				case OP_SIZE_1:
					if (unlikely(!ARCH_HAS_BWX))
						goto invalid;
					mc = ALPHA_LDBU;
					break;
				case OP_SIZE_2:
					if (unlikely(!ARCH_HAS_BWX))
						goto invalid;
					mc = ALPHA_LDWU;
					break;
				case OP_SIZE_8:
					mc = ALPHA_LDQ;
					break;
				default:
					goto invalid;
			}
			g(cgen_memory(ctx, mc, *arg1, arg2[1], imm));
			return true;
		}
		if (arg2[0] < 0x20) {
			if (unlikely(size != OP_SIZE_NATIVE))
				internal(file_line, "cgen_mov: invalid size %u", size);
			g(cgen_operate(ctx, ALPHA_BIS, R_ZERO, arg2, arg1[0]));
			return true;
		}
		if (arg2[0] < 0x40) {
			mc = size == OP_SIZE_4 ? ALPHA_FTOIS : ALPHA_FTOIT;
			g(cgen_fp_operate(ctx, mc, arg2[0], 0x1f, arg1[0]));
			return true;
		}
		goto invalid;
	}
	if (arg1[0] < 0x40) {
		if (arg2[0] < 0x20) {
			mc = size == OP_SIZE_4 ? ALPHA_ITOFS : ALPHA_ITOFT;
			g(cgen_fp_operate(ctx, mc, arg2[0], 0x1f, arg1[0]));
			return true;
		}
		if (arg2[0] < 0x40)
			goto invalid;
		if (arg2[0] == ARG_ADDRESS_1) {
			imm = get_imm(&arg2[2]);
			switch (size) {
				case OP_SIZE_4:	mc = ALPHA_LDS; break;
				case OP_SIZE_8:	mc = ALPHA_LDT; break;
				default:	goto invalid;
			}
			g(cgen_memory(ctx, mc, *arg1 & 0x1f, arg2[1], imm));
			return true;
		}
		goto invalid;
	}
	if (arg1[0] == ARG_ADDRESS_1) {
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (unlikely(imm != 0))
				goto invalid;
			arg2 = &z;
		}
		if (arg2[0] < 0x20) {
			imm = get_imm(&arg1[2]);
			switch (size) {
				case OP_SIZE_1:
					if (unlikely(!ARCH_HAS_BWX))
						goto invalid;
					mc = ALPHA_STB;
					break;
				case OP_SIZE_2:
					if (unlikely(!ARCH_HAS_BWX))
						goto invalid;
					mc = ALPHA_STW;
					break;
				case OP_SIZE_4:
					mc = ALPHA_STL;
					break;
				case OP_SIZE_8:
					mc = ALPHA_STQ;
					break;
				default:
					goto invalid;
			}
			g(cgen_memory(ctx, mc, *arg2, arg1[1], imm));
			return true;
		}
		if (arg2[0] < 0x40) {
			imm = get_imm(&arg1[2]);
			switch (size) {
				case OP_SIZE_4:	mc = ALPHA_STS; break;
				case OP_SIZE_8:	mc = ALPHA_STT; break;
				default:	goto invalid;
			}
			g(cgen_memory(ctx, mc, *arg2 & 0x1f, arg1[1], imm));
			return true;
		}
		goto invalid;
	}
invalid:
	internal(file_line, "cgen_mov: invalid arguments %u, %02x, %02x", size, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_movsx(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1, *arg2;
	if (size == OP_SIZE_NATIVE) {
		g(cgen_mov(ctx, size));
		return true;
	}
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (reg_is_fp(*arg1) && reg_is_fp(*arg2) && size == OP_SIZE_4) {
		g(cgen_fp_operate(ctx, ALPHA_CVTLQ, 0x1f, *arg2, *arg1));
		return true;
	}

	if (unlikely(*arg1 >= 0x20))
		goto invalid;

	if (*arg2 == ARG_ADDRESS_1) {
		if (unlikely(size < OP_SIZE_4))
			goto invalid;
		g(cgen_memory(ctx, ALPHA_LDL, *arg1, arg2[1], get_imm(&arg2[2])));
		return true;
	}
	if (*arg2 < 0x20) {
		uint32_t mc;
		switch (size) {
			case OP_SIZE_1:
				if (unlikely(!ARCH_HAS_BWX))
					goto invalid;
				mc = ALPHA_SEXTB;
				break;
			case OP_SIZE_2:
				if (unlikely(!ARCH_HAS_BWX))
					goto invalid;
				mc = ALPHA_SEXTW;
				break;
			case OP_SIZE_4:
				mc = ALPHA_ADDL;
				break;
			default:
				goto invalid;
		}
		g(cgen_operate(ctx, mc, 0x1f, arg2, *arg1));
		return true;
	}

invalid:
	internal(file_line, "cgen_movsx: invalid parameters %u, %02x, %02x", size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_mov_u(struct codegen_context *ctx)
{
	uint8_t *arg1, *arg2;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (*arg1 < 0x20 && *arg2 == ARG_ADDRESS_1) {
		g(cgen_memory(ctx, ALPHA_LDQ_U, *arg1, arg2[1], get_imm(&arg2[2])));
		return true;
	} else if (*arg1 == ARG_ADDRESS_1 && *arg2 < 0x20) {
		g(cgen_memory(ctx, ALPHA_STQ_U, *arg2, arg1[1], get_imm(&arg1[2])));
		return true;
	}

	internal(file_line, "cgen_mov_u: invalid parameters %02x, %02x", *arg1, *arg2);
	return false;
}

static bool attr_w cgen_cmp_dest_reg(struct codegen_context *ctx, unsigned aux)
{
	uint32_t mc;
	bool swap = false;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (aux) {
		case COND_B:	mc = ALPHA_CMPULT; break;
		case COND_AE:	mc = ALPHA_CMPULE; swap = true; break;
		case COND_E:	mc = ALPHA_CMPEQ; break;
		/*case COND_NE:	mc = ALPHA_XOR; break;*/
		case COND_BE:	mc = ALPHA_CMPULE; break;
		case COND_A:	mc = ALPHA_CMPULT; swap = true; break;
		case COND_L:	mc = ALPHA_CMPLT; break;
		case COND_GE:	mc = ALPHA_CMPLE; swap = true; break;
		case COND_LE:	mc = ALPHA_CMPLE; break;
		case COND_G:	mc = ALPHA_CMPLT; swap = true; break;
		default:	internal(file_line, "cgen_cmp_dest_reg: invalid condition %u", aux);
	}
	if (swap) {
		uint8_t *argx;
		if (arg3[0] == ARG_IMM)
			internal(file_line, "cgen_cmp_dest_reg: invalid condition %u", aux);
		argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}
	g(cgen_operate(ctx, mc, *arg2, arg3, *arg1));
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
		switch (alu) {
			case ALU_SUB:
				imm = -(uint64_t)imm;
				/*-fallthrough*/
			case ALU_ADD:
				if (imm >= -0x8000 && imm < 0x8000) {
					g(cgen_memory(ctx, ALPHA_LDA, arg1[0], arg2[0], imm));
					return true;
				}
				if (!(imm & 0xffff) && imm >= -0x80000000L && imm < 0x80000000L) {
					g(cgen_memory(ctx, ALPHA_LDAH, arg1[0], arg2[0], imm / 0x10000));
					return true;
				}
				internal(file_line, "cgen_alu: invalid imm value %"PRIxMAX"", (intmax_t)imm);
		}
	}
	switch (alu) {
		case ALU_ADD:	mc = size == OP_SIZE_8 ? ALPHA_ADDQ : ALPHA_ADDL; break;
		case ALU_OR:	mc = ALPHA_BIS; break;
		case ALU_AND:	mc = ALPHA_AND; break;
		case ALU_SUB:	mc = size == OP_SIZE_8 ? ALPHA_SUBQ : ALPHA_SUBL; break;
		case ALU_XOR:	mc = ALPHA_XOR; break;
		case ALU_ORN:	mc = ALPHA_ORNOT; break;
		case ALU_ANDN:	mc = ALPHA_ANDNOT; break;
		case ALU_XORN:	mc = ALPHA_EQV; break;
		case ALU_MUL:	mc = size == OP_SIZE_8 ? ALPHA_MULQ : ALPHA_MULL; break;
		case ALU_UMULH:	mc = ALPHA_UMULH; break;
		case ALU_EXTBL:	mc = ALPHA_EXTBL; break;
		case ALU_EXTWL:	mc = ALPHA_EXTWL; break;
		case ALU_EXTLL:	mc = ALPHA_EXTLL; break;
		case ALU_EXTLH:	mc = ALPHA_EXTLH; break;
		case ALU_INSBL:	mc = ALPHA_INSBL; break;
		case ALU_MSKBL:	mc = ALPHA_MSKBL; break;
		case ALU_ZAP:	mc = ALPHA_ZAP; break;
		case ALU_ZAPNOT:mc = ALPHA_ZAPNOT; break;
		default:	internal(file_line, "cgen_alu: invalid alu %u", alu);
	}
	if (alu == ALU_ADD && arg3[0] == ARG_SHIFTED_REGISTER) {
		uint8_t *arg_swp = arg3;
		arg3 = arg2;
		arg2 = arg_swp;
	}
	if (arg2[0] == ARG_SHIFTED_REGISTER && (arg2[1] == (ARG_SHIFT_LSL | 0) || arg2[1] == (ARG_SHIFT_LSL | 2) || arg2[1] == (ARG_SHIFT_LSL | 3)) && (alu == ALU_ADD || alu == ALU_SUB)) {
		if (arg2[1] == (ARG_SHIFT_LSL | 0) && alu == ALU_ADD)
			mc = size == OP_SIZE_8 ? ALPHA_ADDQ : ALPHA_ADDL;
		else if (arg2[1] == (ARG_SHIFT_LSL | 0) && alu == ALU_SUB)
			mc = size == OP_SIZE_8 ? ALPHA_SUBQ : ALPHA_SUBL;
		else if (arg2[1] == (ARG_SHIFT_LSL | 2) && alu == ALU_ADD)
			mc = size == OP_SIZE_8 ? ALPHA_S4ADDQ : ALPHA_S4ADDL;
		else if (arg2[1] == (ARG_SHIFT_LSL | 2) && alu == ALU_SUB)
			mc = size == OP_SIZE_8 ? ALPHA_S4SUBQ : ALPHA_S4SUBL;
		else if (arg2[1] == (ARG_SHIFT_LSL | 3) && alu == ALU_ADD)
			mc = size == OP_SIZE_8 ? ALPHA_S8ADDQ : ALPHA_S8ADDL;
		else if (arg2[1] == (ARG_SHIFT_LSL | 3) && alu == ALU_SUB)
			mc = size == OP_SIZE_8 ? ALPHA_S8SUBQ : ALPHA_S8SUBL;
		else
			internal(file_line, "cgen_alu: invalid shifted register operation: %02x, %u", arg2[1], alu);
		arg2 += 2;
	}
	g(cgen_operate(ctx, mc, arg2[0], arg3, arg1[0]));
	return true;
}

static bool attr_w cgen_alu_trap(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint32_t mc;
	uint32_t trap_label;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	trap_label = cget_four(ctx);
	switch (alu) {
		case ALU_ADD:	mc = size == OP_SIZE_8 ? ALPHA_ADDQ_V : ALPHA_ADDL_V; break;
		case ALU_SUB:	mc = size == OP_SIZE_8 ? ALPHA_SUBQ_V : ALPHA_SUBL_V; break;
		case ALU_MUL:	mc = size == OP_SIZE_8 ? ALPHA_MULQ_V : ALPHA_MULL_V; break;
		default:	internal(file_line, "cgen_alu_trap: invalid alu trap %u", alu);
	}
	g(cgen_operate(ctx, mc, arg2[0], arg3, arg1[0]));
	g(cgen_trap(ctx, trap_label));
	if (!cpu_test_feature(CPU_FEATURE_precise_trap))
		cgen_four(ALPHA_TRAPB);
	return true;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu, bool trap)
{
	uint32_t mc;
	uint32_t trap_label = 0;	/* avoid warning */
	uint8_t one_imm[9] = { ARG_IMM, 1, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (trap) {
		trap_label = cget_four(ctx);
	}
	switch (alu) {
		case ALU1_NOT:
			mc = ALPHA_ORNOT;
			g(cgen_operate(ctx, mc, R_ZERO, arg2, arg1[0]));
			break;
		case ALU1_NEG:
			if (!trap)
				mc = size == OP_SIZE_8 ? ALPHA_SUBQ : ALPHA_SUBL;
			else
				mc = size == OP_SIZE_8 ? ALPHA_SUBQ_V : ALPHA_SUBL_V;
			g(cgen_operate(ctx, mc, R_ZERO, arg2, arg1[0]));
			break;
		case ALU1_INC:
			if (!trap)
				mc = size == OP_SIZE_8 ? ALPHA_ADDQ : ALPHA_ADDL;
			else
				mc = size == OP_SIZE_8 ? ALPHA_ADDQ_V : ALPHA_ADDL_V;
			g(cgen_operate(ctx, mc, arg2[0], one_imm, arg1[0]));
			break;
		case ALU1_DEC:
			if (!trap)
				mc = size == OP_SIZE_8 ? ALPHA_SUBQ : ALPHA_SUBL;
			else
				mc = size == OP_SIZE_8 ? ALPHA_SUBQ_V : ALPHA_SUBL_V;
			g(cgen_operate(ctx, mc, arg2[0], one_imm, arg1[0]));
			break;
		case ALU1_BSF:
			mc = ALPHA_CTTZ;
			g(cgen_operate(ctx, mc, 0x1f, arg2, arg1[0]));
			break;
		case ALU1_LZCNT:
			mc = ALPHA_CTLZ;
			g(cgen_operate(ctx, mc, 0x1f, arg2, arg1[0]));
			break;
		case ALU1_POPCNT:
			mc = ALPHA_CTPOP;
			g(cgen_operate(ctx, mc, 0x1f, arg2, arg1[0]));
			break;
		default:
			internal(file_line, "cgen_alu1: invalid alu %u", alu);
	}
	if (trap) {
		g(cgen_trap(ctx, trap_label));
		if (!cpu_test_feature(CPU_FEATURE_precise_trap))
			cgen_four(ALPHA_TRAPB);
	}
	return true;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned alu)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (alu) {
		case ROT_SHL:	mc = ALPHA_SLL; break;
		case ROT_SHR:	mc = ALPHA_SRL; break;
		case ROT_SAR:	mc = ALPHA_SRA; break;
		default:	internal(file_line, "cgen_rot: invalid alu %u", alu);
	}
	g(cgen_operate(ctx, mc, arg2[0], arg3, arg1[0]));
	return true;
}

static bool attr_w cgen_movr(struct codegen_context *ctx, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	switch (aux) {
		case COND_B:
		case COND_L:
		case COND_S:
			mc = ALPHA_CMOVLT; break;
		case COND_AE:
		case COND_GE:
		case COND_NS:
			mc = ALPHA_CMOVGE; break;
		case COND_E:
			mc = ALPHA_CMOVEQ; break;
		case COND_NE:
			mc = ALPHA_CMOVNE; break;
		case COND_BE:
		case COND_LE:
			mc = ALPHA_CMOVLE; break;
		case COND_A:
		case COND_G:
			mc = ALPHA_CMOVGT; break;
		case COND_BLBC:
			mc = ALPHA_CMOVLBC; break;
		case COND_BLBS:
			mc = ALPHA_CMOVLBS; break;
		default:
			internal(file_line, "cgen_movr: invalid condition %u", aux);
	}
	if (unlikely(arg1[0] != arg2[0]))
		internal(file_line, "cgen_movr: invalid arguments");
	g(cgen_operate(ctx, mc, arg3[0], arg4, arg1[0]));
	return true;
}

static bool attr_w cgen_fp_cmp_trap(struct codegen_context *ctx, unsigned aux)
{
	uint32_t mc;
	bool swap = false;
	uint32_t trap_label;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	trap_label = cget_four(ctx);
	switch (aux) {
		case FP_COND_E:		mc = ALPHA_CMPTEQ; break;
		case FP_COND_A:		mc = ALPHA_CMPTLT; swap = true; break;
		case FP_COND_BE:	mc = ALPHA_CMPTLE; break;
		case FP_COND_B:		mc = ALPHA_CMPTLT; break;
		case FP_COND_AE:	mc = ALPHA_CMPTLE; swap = true; break;
		default:		internal(file_line, "cgen_fp_cmp_trap: invalid condition %u", aux);
	}
	if (swap) {
		uint8_t *argx;
		argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}
	g(cgen_fp_operate(ctx, mc, arg2[0], arg3[0], arg1[0]));
	g(cgen_trap(ctx, trap_label));
	if (!cpu_test_feature(CPU_FEATURE_precise_trap))
		cgen_four(ALPHA_TRAPB);
	return true;
}

static bool attr_w cgen_fp_cmp_unordered(struct codegen_context *ctx)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	mc = ALPHA_CMPTUN_SU;
	g(cgen_fp_operate(ctx, mc, arg2[0], arg3[0], arg1[0]));
	if (!cpu_test_feature(CPU_FEATURE_precise_trap))
		cgen_four(ALPHA_TRAPB);
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
		case FP_ALU_ADD:	mc = op_size == OP_SIZE_4 ? ALPHA_ADDS_SU : ALPHA_ADDT_SU; break;
		case FP_ALU_SUB:	mc = op_size == OP_SIZE_4 ? ALPHA_SUBS_SU : ALPHA_SUBT_SU; break;
		case FP_ALU_MUL:	mc = op_size == OP_SIZE_4 ? ALPHA_MULS_SU : ALPHA_MULT_SU; break;
		case FP_ALU_DIV:	mc = op_size == OP_SIZE_4 ? ALPHA_DIVS_SU : ALPHA_DIVT_SU; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	g(cgen_fp_operate(ctx, mc, arg2[0], arg3[0], arg1[0]));
	if (!cpu_test_feature(CPU_FEATURE_precise_trap))
		cgen_four(ALPHA_TRAPB);
	return true;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned attr_unused op_size, unsigned aux)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	g(cgen_fp_operate(ctx, ALPHA_CPYSN, arg2[0], arg2[0], arg1[0]));
					break;
		case FP_ALU1_SQRT:	g(cgen_fp_operate(ctx, op_size == OP_SIZE_4 ? ALPHA_SQRTS_SU : ALPHA_SQRTT_SU, 0, arg2[0], arg1[0]));
					if (!cpu_test_feature(CPU_FEATURE_precise_trap))
						cgen_four(ALPHA_TRAPB);
					break;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	return true;
}

static bool attr_w cgen_fp_to_int64_trap(struct codegen_context *ctx)
{
	uint32_t mc;
	uint32_t trap_label;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	trap_label = cget_four(ctx);

	mc = ALPHA_CVTTQ_V;
	g(cgen_fp_operate(ctx, mc, 0x31, arg2[0], arg1[0]));
	g(cgen_trap(ctx, trap_label));
	if (!cpu_test_feature(CPU_FEATURE_precise_trap))
		cgen_four(ALPHA_TRAPB);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = fp_op_size == OP_SIZE_4 ? ALPHA_CVTQS : ALPHA_CVTQT;
	g(cgen_fp_operate(ctx, mc, 0x31, arg2[0], arg1[0]));
	if (!cpu_test_feature(CPU_FEATURE_precise_trap))
		cgen_four(ALPHA_TRAPB);
	return true;
}

static bool attr_w cgen_fp_int64_to_int32_trap(struct codegen_context *ctx)
{
	uint32_t mc;
	uint32_t trap_label;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	trap_label = cget_four(ctx);

	mc = ALPHA_CVTQL_V;
	g(cgen_fp_operate(ctx, mc, 0x31, arg2[0], arg1[0]));
	g(cgen_trap(ctx, trap_label));
	if (!cpu_test_feature(CPU_FEATURE_precise_trap))
		cgen_four(ALPHA_TRAPB);
	return true;
}


static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned aux)
{
	uint32_t mc;
	uint8_t reg = cget_one(ctx);
	switch (aux) {
		case COND_B:
		case COND_L:
		case COND_S:
			mc = ALPHA_BLT; break;
		case COND_AE:
		case COND_GE:
		case COND_NS:
			mc = ALPHA_BGE; break;
		case COND_E:
			mc = ALPHA_BEQ; break;
		case COND_NE:
			mc = ALPHA_BNE; break;
		case COND_BE:
		case COND_LE:
			mc = ALPHA_BLE; break;
		case COND_A:
		case COND_G:
			mc = ALPHA_BGT; break;
		case COND_BLBC:
			mc = ALPHA_BLBC; break;
		case COND_BLBS:
			mc = ALPHA_BLBS; break;
		default:
			internal(file_line, "cgen_jmp_reg: invalid condition %u", aux);
	}
	g(cgen_branch(ctx, mc, reg));
	return true;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 2) - (int64_t)(reloc->position >> 2) - 1;
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x00100000) || unlikely(offs >= 0x00100000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0xffe00000U;
			mc |= offs & 0x001fffffU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	uint8_t reg;
	/*debug("insn: %08x", insn);*/
	if (unlikely(insn_writes_flags(insn)))
		goto invalid_insn;
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_AFTER_ENTRY:
			g(cgen_after_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			cgen_four(ALPHA_RETURN);
			return true;
		case INSN_CALL_INDIRECT:
			reg = cget_one(ctx);
			if (unlikely(reg != R_T12))
				internal(file_line, "cgen_insn: invalid call register %u", (unsigned)reg);
			cgen_four(ALPHA_JSR_T12);
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn)));
			return true;
		case INSN_MOVSX:
			g(cgen_movsx(ctx, insn_op_size(insn)));
			return true;
		case INSN_MOV_U:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_mov_u(ctx));
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
		case INSN_ALU_TRAP:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu_trap(ctx, insn_op_size(insn), insn_aux(insn)));
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
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_aux(insn)));
			return true;
		case INSN_MOVR:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_movr(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_CMP_DEST_REG_TRAP:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4) && unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_fp_cmp_trap(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_CMP_UNORDERED_DEST_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4) && unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_fp_cmp_unordered(ctx));
			return true;
		case INSN_FP_ALU:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4) && unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_fp_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_ALU1:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4) && unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_fp_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_TO_INT64_TRAP:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4) && unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_fp_to_int64_trap(ctx));
			return true;
		case INSN_FP_FROM_INT64:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4) && unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_fp_from_int(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_INT64_TO_INT32_TRAP:
			g(cgen_fp_int64_to_int32_trap(ctx));
			return true;
		case INSN_JMP:
			g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
			cgen_four(ALPHA_BR);
			return true;
		case INSN_JMP_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_jmp_reg(ctx, insn_aux(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			reg = cget_one(ctx);
			cgen_four(ALPHA_JMP + ((uint32_t)reg << 16));
			return true;
		case INSN_MB:
			cgen_four(ALPHA_MB);
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
