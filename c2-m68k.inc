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

#define M68K_ADDR_D		0x0000
#define M68K_ADDR_A		0x0008
#define M68K_ADDR_AA		0x0010
#define M68K_ADDR_AA_I		0x0018
#define M68K_ADDR_AA_D		0x0020
#define M68K_ADDR_AA_D16	0x0028
#define M68K_ADDR_AA_D8_X	0x0030
#define M68K_ADDR_AW		0x0038
#define M68K_ADDR_AL		0x0039
#define M68K_ADDR_PC_D16	0x003a
#define M68K_ADDR_PC_D8_X	0x003b
#define M68K_ADDR_IMM		0x003c

#define M68K_EW_BD_N		0x0010
#define M68K_EW_BD_W		0x0020
#define M68K_EW_BD_L		0x0030
#define M68K_EW_BS		0x0080
#define M68K_EW_FULL		0x0100
#define M68K_EW_WL		0x0800
#define M68K_EW_DA		0x8000
#define M68K_EW_I_NO_IND	0x0000
#define M68K_EW_I_PREIND_0	0x0001
#define M68K_EW_I_PREIND_1	0x0002
#define M68K_EW_I_PREIND_2	0x0003
#define M68K_EW_I_POSTIND_0	0x0005
#define M68K_EW_I_POSTIND_1	0x0006
#define M68K_EW_I_POSTIND_2	0x0007
#define M68K_EW_IS_NO_IND	0x0040
#define M68K_EW_IS_IND_0	0x0041
#define M68K_EW_IS_IND_1	0x0042
#define M68K_EW_IS_IND_2	0x0043

#define M68K_SIZE_B		0x0000
#define M68K_SIZE_W		0x0040
#define M68K_SIZE_L		0x0080
#define M68K_SIZE_AW		0x00c0
#define M68K_SIZE_AL		0x01c0
#define M68K_SIZE_SWAP_ARGS	0x0100

#define M68K_COND_T		0x0
#define M68K_COND_F		0x1
#define M68K_COND_HI		0x2
#define M68K_COND_LS		0x3
#define M68K_COND_CC		0x4
#define M68K_COND_CS		0x5
#define M68K_COND_NE		0x6
#define M68K_COND_EQ		0x7
#define M68K_COND_VC		0x8
#define M68K_COND_VS		0x9
#define M68K_COND_PL		0xa
#define M68K_COND_MI		0xb
#define M68K_COND_GE		0xc
#define M68K_COND_LT		0xd
#define M68K_COND_GT		0xe
#define M68K_COND_LE		0xf

#define M68K_MOVE	0x0000
#define  M68K_MOVE_B		0x1000
#define  M68K_MOVE_L		0x2000
#define  M68K_MOVE_W		0x3000
#define M68K_ORI	0x0000
#define M68K_BTST	0x0100
#define M68K_BCHG	0x0140
#define M68K_BCLR	0x0180
#define M68K_BSET	0x01c0
#define M68K_ANDI	0x0200
#define M68K_SUBI	0x0400
#define M68K_ADDI	0x0600
#define M68K_BTST_IMM	0x0800
#define M68K_BCHG_IMM	0x0840
#define M68K_BCLR_IMM	0x0880
#define M68K_BSET_IMM	0x08c0
#define M68K_EORI	0x0a00
#define M68K_CMPI	0x0c00
#define M68K_NEGX	0x4000
#define M68K_LEA	0x41c0
#define M68K_CLR	0x4200
#define M68K_NEG	0x4400
#define M68K_NOT	0x4600
#define M68K_MOVEM	0x4880
#define  M68K_MOVEM_DR		0x0400
#define  M68K_MOVEM_SIZE	0x0040
#define M68K_EXTW	0x4880
#define M68K_EXTL	0x48c0
#define M68K_EXTBL	0x49c0
#define M68K_TST	0x4a00
#define M68K_MUL_L	0x4c00
#define  M68K_MUL_L_64		0x0400
#define  M68K_MUL_L_S		0x0800
#define M68K_DIV_L	0x4c40
#define  M68K_DIV_L_64		0x0400
#define  M68K_DIV_L_S		0x0800
#define M68K_NOP	0x4e71
#define M68K_RTS	0x4e75
#define M68K_JSR	0x4e80
#define M68K_JMP	0x4ec0
#define M68K_ADDQ	0x5000
#define M68K_SUBQ	0x5100
#define M68K_SETCC	0x50c0
#define M68K_BCC	0x6000
#define M68K_MOVEQ	0x7000
#define M68K_OR		0x8000
#define M68K_SUB	0x9000
#define M68K_SUBX	0x9100
#define M68K_CMP	0xb000
#define M68K_EOR	0xb100
#define M68K_AND	0xc000
#define M68K_EXG_DD	0xc140
#define M68K_EXG_AA	0xc148
#define M68K_EXG_DA	0xc188
#define M68K_ADD	0xd000
#define M68K_ADDX	0xd100
#define M68K_ASR	0xe000
#define M68K_LSR	0xe008
#define M68K_ROXR	0xe010
#define M68K_ROR	0xe018
#define M68K_ASL	0xe100
#define M68K_LSL	0xe108
#define M68K_ROXL	0xe110
#define M68K_ROL	0xe118
#define  M68K_ROT_R		0x0020
#define M68K_BFTST	0xe8c0
#define M68K_BFEXTU	0xe9c0
#define M68K_BFCHG	0xeac0
#define M68K_BFEXTS	0xebc0
#define M68K_BFCLR	0xecc0
#define M68K_BFFFO	0xedc0
#define M68K_BFSET	0xeec0
#define M68K_BFINS	0xefc0

static uint16_t get_size(unsigned size, bool a)
{
	uint16_t mc;
	if (a) switch (size) {
		case OP_SIZE_2:	mc = M68K_SIZE_AW; break;
		case OP_SIZE_4:	mc = M68K_SIZE_AL; break;
		default: internal(file_line, "get_size: invalid size %u", size);
	} else switch (size) {
		case OP_SIZE_1:	mc = M68K_SIZE_B; break;
		case OP_SIZE_2:	mc = M68K_SIZE_W; break;
		case OP_SIZE_4:	mc = M68K_SIZE_L; break;
		default: internal(file_line, "get_size: invalid size %u", size);
	}
	return mc;
}

static uint16_t get_move_size(unsigned size)
{
	uint16_t mc;
	switch (size) {
		case OP_SIZE_1: mc = M68K_MOVE_B; break;
		case OP_SIZE_2: mc = M68K_MOVE_W; break;
		case OP_SIZE_4: mc = M68K_MOVE_L; break;
		default:	internal(file_line, "get_move_size: invalid size %u", size);
	}
	return mc;
}

static uint16_t get_cond(unsigned cond)
{
	switch (cond) {
		case COND_O:	return M68K_COND_VS;
		case COND_NO:	return M68K_COND_VC;
		case COND_B:	return M68K_COND_CS;
		case COND_AE:	return M68K_COND_CC;
		case COND_E:	return M68K_COND_EQ;
		case COND_NE:	return M68K_COND_NE;
		case COND_BE:	return M68K_COND_LS;
		case COND_A:	return M68K_COND_HI;
		case COND_S:	return M68K_COND_MI;
		case COND_NS:	return M68K_COND_PL;
		case COND_L:	return M68K_COND_LT;
		case COND_GE:	return M68K_COND_GE;
		case COND_LE:	return M68K_COND_LE;
		case COND_G:	return M68K_COND_GT;
		case COND_ALWAYS:	return M68K_COND_T;
		case COND_NEVER:	return M68K_COND_F;
		default:	internal(file_line, "get_cond: invalid condition %u", cond);
	}
	return 0xffff;
}

static bool attr_w cgen_mov_da(struct codegen_context *ctx, uint8_t ra, uint8_t rd)
{
	uint16_t mc = M68K_MOVE | M68K_MOVE_L | ((ra & 7) << 9) | (M68K_ADDR_A << 3) | M68K_ADDR_D | (rd & 7);
	cgen_two(mc);
	return true;
}

static bool attr_w cgen_mov_ad(struct codegen_context *ctx, uint8_t rd, uint8_t ra)
{
	uint16_t mc = M68K_MOVE | M68K_MOVE_L | ((rd & 7) << 9) | (M68K_ADDR_D << 3) | M68K_ADDR_A | (ra & 7);
	cgen_two(mc);
	return true;
}

static bool attr_w cgen_prepare_address(struct codegen_context *ctx, uint8_t *arg)
{
	if (arg[0] >= ARG_ADDRESS_1 && arg[0] <= ARG_ADDRESS_2_8 && R_IS_D(arg[1])) {
		g(cgen_mov_da(ctx, R_TMP_A, arg[1]));
	}
	return true;
}

static bool attr_w cgen_imm(struct codegen_context *ctx, unsigned size, int32_t imm)
{
	switch (size) {
		case OP_SIZE_1:
			cgen_two(imm & 0xff);
			break;
		case OP_SIZE_2:
			cgen_two(imm);
			break;
		case OP_SIZE_4:
			cgen_four(imm);
			break;
		default:
			internal(file_line, "cgen_imm: invalid size %u", size);
	}
	return true;
}

#define CGO_MOVE_DEST	1

static bool attr_w cgen_operand(struct codegen_context *ctx, unsigned size, size_t instr_base, unsigned flags, uint8_t *arg)
{
	int64_t imm;
	uint16_t mc, mcx;
	if (R_IS_D(arg[0])) {
		mc = M68K_ADDR_D | (arg[0] & 7);
	} else if (R_IS_A(arg[0])) {
		mc = M68K_ADDR_A | (arg[0] & 7);
	} else if (arg[0] == ARG_ADDRESS_1) {
		imm = get_imm(&arg[2]);
		if (!imm) {
			if (!R_IS_A(arg[1]))
				mc = M68K_ADDR_AA | (R_TMP_A & 7);
			else
				mc = M68K_ADDR_AA | (arg[1] & 7);
		} else if (imm_is_16bit(imm)) {
			if (!R_IS_A(arg[1]))
				mc = M68K_ADDR_AA_D16 | (R_TMP_A & 7);
			else
				mc = M68K_ADDR_AA_D16 | (arg[1] & 7);
			cgen_two(imm);
		} else {
			if (!R_IS_A(arg[1]))
				mc = M68K_ADDR_AA_D8_X | (R_TMP_A & 7);
			else
				mc = M68K_ADDR_AA_D8_X | (arg[1] & 7);
			cgen_two(M68K_EW_FULL | M68K_EW_IS_NO_IND | M68K_EW_BD_L);
			cgen_four(imm);
		}
	} else if (arg[0] == ARG_ADDRESS_1_PRE_I) {
		imm = get_imm(&arg[2]);
		if (imm != (size == OP_SIZE_1 ? -1 : size == OP_SIZE_2 ? -2 : -4))
			internal(file_line, "cgen_operand: invalid preindex immediate %"PRIuMAX"", (uintmax_t)imm);
		if (!R_IS_A(arg[1]))
			mc = M68K_ADDR_AA_D | (R_TMP_A & 7);
		else
			mc = M68K_ADDR_AA_D | (arg[1] & 7);
	} else if (arg[0] == ARG_ADDRESS_1_POST_I) {
		imm = get_imm(&arg[2]);
		if (imm != (size == OP_SIZE_1 ? 1 : size == OP_SIZE_2 ? 2 : 4))
			internal(file_line, "cgen_operand: invalid postindex immediate %"PRIuMAX"", (uintmax_t)imm);
		if (!R_IS_A(arg[1]))
			mc = M68K_ADDR_AA_I | (R_TMP_A & 7);
		else
			mc = M68K_ADDR_AA_I | (arg[1] & 7);
	} else if (arg[0] >= ARG_ADDRESS_2 && arg[0] <= ARG_ADDRESS_2_8) {
		unsigned shift = arg[0] - ARG_ADDRESS_2;
		uint16_t ew;
		imm = get_imm(&arg[3]);
		if (!R_IS_A(arg[1]))
			mc = M68K_ADDR_AA_D8_X | (R_TMP_A & 7);
		else
			mc = M68K_ADDR_AA_D8_X | (arg[1] & 7);
		ew = M68K_EW_WL;
		ew |= R_IS_A(arg[2]) ? M68K_EW_DA : 0;
		ew |= (arg[2] & 7) << 12;
		ew |= shift << 9;
		if (imm_is_8bit(imm)) {
			ew |= imm & 0xff;
			cgen_two(ew);
		} else if (imm_is_16bit(imm)) {
			ew |= M68K_EW_FULL | M68K_EW_I_NO_IND | M68K_EW_BD_W;
			cgen_two(ew);
			cgen_two(imm);
		} else {
			ew |= M68K_EW_FULL | M68K_EW_I_NO_IND | M68K_EW_BD_L;
			cgen_two(ew);
			cgen_four(imm);
		}
	} else if (arg[0] == ARG_IMM) {
		imm = get_imm(&arg[1]);
		mc = M68K_ADDR_IMM;
		g(cgen_imm(ctx, size, imm));
	} else {
		internal(file_line, "cgen_operand: invalid operand %02x", arg[0]);
	}
	memcpy(&mcx, ctx->mcode + instr_base, 2);
	if (flags & CGO_MOVE_DEST)
		mcx |= ((mc & 7) << 9) | ((mc & 56) << 3);
	else
		mcx |= mc;
	memcpy(ctx->mcode + instr_base, &mcx, 2);
	return true;
}

static bool attr_w cgen_m68k_push_pop(struct codegen_context *ctx, bool pop)
{
	uint16_t mc = M68K_MOVEM | M68K_MOVEM_SIZE;
	if (!pop) {
		mc |= M68K_ADDR_AA_D | (RSP & 7);
	} else {
		mc |= M68K_MOVEM_DR;
		mc |= M68K_ADDR_AA_I | (RSP & 7);
	}
	cgen_two(mc);
	if (!pop) {
		cgen_two(0x3f3e);
	} else {
		cgen_two(0x7cfc);
	}
	return true;
}

static bool attr_w cgen_jmp_indirect(struct codegen_context *ctx, bool call)
{
	int64_t imm;
	uint16_t mc, ew;
	uint8_t reg;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg1[1]);
		mc = (call ? M68K_JSR : M68K_JMP) | M68K_ADDR_AL;
		cgen_two(mc);
		cgen_four(imm);
		return true;
	}
	if (R_IS_D(arg1[0])) {
		g(cgen_mov_da(ctx, R_TMP_A, arg1[0]));
		reg = R_TMP_A;
	} else if (R_IS_A(arg1[0])) {
		reg = arg1[0];
	} else if (arg1[0] == ARG_ADDRESS_1) {
		imm = get_imm(&arg1[2]);
		if (R_IS_A(arg1[1])) {
			mc = (call ? M68K_JSR : M68K_JMP) | M68K_ADDR_AA_D8_X | (arg1[1] & 7);
			cgen_two(mc);
			ew = M68K_EW_FULL | M68K_EW_WL | M68K_EW_IS_IND_0;
		} else {
			mc = (call ? M68K_JSR : M68K_JMP) | M68K_ADDR_AA_D8_X;
			cgen_two(mc);
			ew = M68K_EW_FULL | M68K_EW_BS | M68K_EW_WL | M68K_EW_I_PREIND_0;
			ew |= (arg1[1] & 7) << 12;
		}
write_imm:
		if (!imm) {
			ew |= M68K_EW_BD_N;
			cgen_two(ew);
		} else if (imm_is_16bit(imm)) {
			ew |= M68K_EW_BD_W;
			cgen_two(ew);
			cgen_two(imm);
		} else {
			ew |= M68K_EW_BD_L;
			cgen_two(ew);
			cgen_four(imm);
		}
		return true;
	} else if (arg1[0] >= ARG_ADDRESS_2 && arg1[0] <= ARG_ADDRESS_2_8) {
		unsigned shift = arg1[0] - ARG_ADDRESS_2;
		imm = get_imm(&arg1[3]);
		if (!R_IS_A(arg1[1])) {
			g(cgen_mov_da(ctx, R_TMP_A, arg1[1]));
			reg = R_TMP_A;
		} else {
			reg = arg1[0];
		}
		mc = (call ? M68K_JSR : M68K_JMP) | M68K_ADDR_AA_D8_X | (reg & 7);
		cgen_two(mc);
		ew = M68K_EW_FULL | M68K_EW_WL | M68K_EW_I_PREIND_0;
		ew |= R_IS_A(arg1[2]) ? M68K_EW_DA : 0;
		ew |= (arg1[2] & 7) << 12;
		ew |= shift << 9;
		goto write_imm;
	} else {
		internal(file_line, "cgen_jmp_indirect: invalid register %02x", arg1[0]);
	}
	mc = (call ? M68K_JSR : M68K_JMP) | M68K_ADDR_AA | (reg & 7);
	cgen_two(mc);
	return true;
}

static bool attr_w cgen_moves(struct codegen_context *ctx, unsigned size, uint8_t *arg1, uint8_t *arg2, bool sx, bool partial)
{
	size_t instr_base;
	uint16_t mc;

	g(cgen_prepare_address(ctx, arg1));
	g(cgen_prepare_address(ctx, arg2));

	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		if (!imm && !R_IS_A(arg1[0])) {
			mc = M68K_CLR;
			mc |= get_size(R_IS_DA(arg1[0]) ? OP_SIZE_4 : size, false);
			instr_base = ctx->mcode_size;
			cgen_two(mc);
			g(cgen_operand(ctx, size, instr_base, 0, arg1));
			return true;
		}
		if (imm_is_8bit(imm) && !partial && (size == OP_SIZE_4 || sx) && R_IS_D(arg1[0])) {
			mc = M68K_MOVEQ;
			mc |= (arg1[0] & 7) << 9;
			mc |= imm & 255;
			cgen_two(mc);
			return true;
		}
	}

	if (R_IS_DA(arg1[0]) && arg1[0] == arg2[0])
		goto skip_move;

	mc = M68K_MOVE;
	mc |= get_move_size(size);
	instr_base = ctx->mcode_size;
	cgen_two(mc);
	g(cgen_operand(ctx, size, instr_base, 0, arg2));
	g(cgen_operand(ctx, size, instr_base, CGO_MOVE_DEST, arg1));

skip_move:
	if (R_IS_A(arg1[0])) {
		if (size != OP_SIZE_4)
			internal(file_line, "cgen_moves: partial move to address register");
	} else if (R_IS_D(arg1[0])) {
		if (size < OP_SIZE_4 && !partial) {
			if (!sx) {
				mc = M68K_BFEXTU | M68K_ADDR_D | (arg1[0] & 7);
				cgen_two(mc);
				mc = (arg1[0] & 7) << 12;
				if (size == OP_SIZE_1) {
					mc |= 24 << 6;
					mc |= 8;
				} else {
					mc |= 16 << 6;
					mc |= 16;
				}
				cgen_two(mc);
			} else {
				mc = (size == OP_SIZE_1 ? M68K_EXTBL : M68K_EXTL) | (arg1[0] & 7);
				cgen_two(mc);
			}
		}
	}
	return true;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size, bool sx)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	g(cgen_moves(ctx, size, arg1, arg2, sx, false));

	return true;
}

static bool attr_w cgen_two_op(struct codegen_context *ctx, unsigned size, uint16_t instr, uint16_t instri, uint8_t *arg1, uint8_t *arg2)
{
	size_t instr_base;
	uint16_t mc;
	g(cgen_prepare_address(ctx, arg1));
	g(cgen_prepare_address(ctx, arg2));
	instr_base = ctx->mcode_size;
	if (instr == M68K_OR || instr == M68K_EOR || instr == M68K_AND) {
		if (R_IS_A(arg1[0]) || R_IS_A(arg2[0]))
			goto invl;
	}
	if (arg2[0] == ARG_IMM && !R_IS_A(arg1[0])) {
		int64_t imm = get_imm(&arg2[1]);
		mc = instri | get_size(size, false);
		cgen_two(mc);
		g(cgen_imm(ctx, size, imm));
		g(cgen_operand(ctx, size, instr_base, 0, arg1));
		return true;
	}
	if (!R_IS_DA(arg1[0]) || instr & M68K_SIZE_SWAP_ARGS) {
		if (instr == M68K_CMP)
			goto invl;
		if (!R_IS_D(arg2[0]))
			goto invl;
		mc = instr | get_size(size, false) | M68K_SIZE_SWAP_ARGS;
		mc |= (arg2[0] & 7) << 9;
		cgen_two(mc);
		g(cgen_operand(ctx, size, instr_base, 0, arg1));
		return true;
	}
	if (!R_IS_DA(arg1[0]))
		goto invl;
	mc = instr | get_size(size, R_IS_A(arg1[0]));
	mc |= (arg1[0] & 7) << 9;
	cgen_two(mc);
	g(cgen_operand(ctx, size, instr_base, 0, arg2));
	return true;
invl:
	internal(file_line, "cgen_two_op: invalid arguments %04x %04x %02x %02x", instr, instri, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_adc_sbb(struct codegen_context *ctx, unsigned size, uint16_t instr, uint8_t *arg1, uint8_t *arg2)
{
	uint16_t mc;
	if (!R_IS_D(arg1[0]) || !R_IS_D(arg2[0]))
		goto invl;
	mc = instr;
	mc |= get_size(size, false);
	mc |= (arg1[0] & 7) << 9;
	mc |= arg2[0] & 7;
	cgen_two(mc);
	return true;
invl:
	internal(file_line, "cgen_adc_sbb: invalid arguments %04x %02x %02x", instr, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_cmp(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		if (!imm) {
			size_t instr_base;
			uint16_t mc;
			g(cgen_prepare_address(ctx, arg1));
			mc = M68K_TST;
			mc |= get_size(size, false);
			instr_base = ctx->mcode_size;
			cgen_two(mc);
			g(cgen_operand(ctx, size, instr_base, 0, arg1));
			return true;
		}
	}
	g(cgen_two_op(ctx, size, M68K_CMP, M68K_CMPI, arg1, arg2));
	return true;
}

static bool attr_w cgen_test(struct codegen_context *ctx, unsigned size)
{
	size_t instr_base;
	uint16_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (memcmp(arg1, arg2, arg_size(*arg1)))
		internal(file_line, "cgen_test: operand mismatch");
	g(cgen_prepare_address(ctx, arg1));
	mc = M68K_TST;
	mc |= get_size(size, false);
	instr_base = ctx->mcode_size;
	cgen_two(mc);
	g(cgen_operand(ctx, size, instr_base, 0, arg1));
	return true;
}

static bool attr_w cgen_lea(struct codegen_context *ctx, uint8_t *arg1, uint8_t *arg2, uint8_t *arg3, bool neg_imm)
{
	uint16_t mc, ew;
	uint8_t reg1, reg2, reg3;
	unsigned shift;

	if (arg2[0] == ARG_SHIFTED_REGISTER) {
		uint8_t *arg_swp = arg3;
		arg3 = arg2;
		arg2 = arg_swp;
	}

	if (R_IS_D(arg1[0])) {
		reg1 = R_TMP_A;
	} else if (R_IS_A(arg1[0])) {
		reg1 = arg1[0];
	} else {
		goto invl;
	}

	if (R_IS_D(arg2[0])) {
		g(cgen_mov_da(ctx, R_TMP_A, arg2[0]));
		reg2 = R_TMP_A;
	} else if (R_IS_A(arg2[0])) {
		reg2 = arg2[0];
	} else {
		goto invl;
	}

	if (R_IS_DA(arg3[0])) {
		reg3 = arg3[0];
		shift = 0;
	} else if (arg3[0] == ARG_SHIFTED_REGISTER && (arg3[1] & ARG_SHIFT_MODE) == ARG_SHIFT_LSL) {
		reg3 = arg3[2];
		shift = arg3[1] & ARG_SHIFT_AMOUNT;
		if (shift >= 4)
			goto invl;
	} else if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		if (neg_imm)
			imm = -(uint64_t)imm;
		if (imm_is_16bit(imm)) {
			mc = M68K_LEA;
			mc |= M68K_ADDR_AA_D16;
			mc |= reg2 & 7;
			mc |= (reg1 & 7) << 9;
			cgen_two(mc);
			cgen_two(imm);
			goto instr_done;
		} else {
			mc = M68K_LEA;
			mc |= M68K_ADDR_AA_D8_X;
			mc |= reg2 & 7;
			mc |= (reg1 & 7) << 9;
			cgen_two(mc);
			cgen_two(M68K_EW_FULL | M68K_EW_IS_NO_IND | M68K_EW_BD_L);
			cgen_four(imm);
			goto instr_done;
		}
	} else {
		goto invl;
	}
	if (!R_IS_DA(reg3))
		goto invl;

	mc = M68K_LEA;
	mc |= M68K_ADDR_AA_D8_X;
	mc |= reg2 & 7;
	mc |= (reg1 & 7) << 9;
	cgen_two(mc);
	ew = M68K_EW_WL;
	ew |= R_IS_A(reg3) ? M68K_EW_DA : 0;
	ew |= (reg3 & 7) << 12;
	ew |= shift << 9;
	cgen_two(ew);

instr_done:
	if (reg1 == R_TMP_A && arg1[0] != R_TMP_A)
		g(cgen_mov_ad(ctx, arg1[0], R_TMP_A));

	return true;
invl:
	internal(file_line, "cgen_lea: invalid arguments %02x %02x %02x", arg1[0], arg2[0], arg3[0]);
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags)
{
	uint16_t instr, instri;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (arg_size(*arg1) != arg_size(*arg2) || memcmp(arg1, arg2, arg_size(*arg1)) || arg2[0] == ARG_SHIFTED_REGISTER || arg3[0] == ARG_SHIFTED_REGISTER) {
		if (writes_flags)
			goto invl;
		if (alu == ALU_ADD && size == OP_SIZE_4) {
			g(cgen_lea(ctx, arg1, arg2, arg3, false));
			return true;
		}
		goto invl;
	}
	if (arg3[0] == ARG_IMM && (alu == ALU_ADD || alu == ALU_SUB)) {
		int64_t imm = get_imm(&arg3[1]);
		if (imm >= 1 && imm <= 8) {
			size_t instr_base;
			uint16_t mc = alu == ALU_ADD ? M68K_ADDQ : M68K_SUBQ;
			mc |= get_size(size, false);
			mc |= (imm & 7) << 9;
			instr_base = ctx->mcode_size;
			cgen_two(mc);
			g(cgen_operand(ctx, size, instr_base, 0, arg1));
			return true;
		}
		if (R_IS_A(arg1[0]) && imm_is_16bit(imm)) {
			g(cgen_lea(ctx, arg1, arg2, arg3, alu == ALU_SUB));
			return true;
		}
	}
	if (alu == ALU_XOR && R_IS_D(arg1[0]) && (arg3[0] == ARG_ADDRESS_1 || arg3[0] == ARG_ADDRESS_2)) {
		size_t instr_base;
		uint16_t mc;
		uint8_t sp[10];
		sp[0] = ARG_ADDRESS_1;
		sp[1] = RSP;
		memset(&sp[2], 0, 8);

		g(cgen_prepare_address(ctx, arg3));

		mc = M68K_MOVE;
		mc |= get_move_size(size);
		instr_base = ctx->mcode_size;
		cgen_two(mc);
		g(cgen_operand(ctx, size, instr_base, 0, arg3));
		g(cgen_operand(ctx, size, instr_base, CGO_MOVE_DEST, sp));

		g(cgen_two_op(ctx, size, M68K_EOR, M68K_EORI, sp, arg1));

		mc = M68K_MOVE;
		mc |= get_move_size(size);
		instr_base = ctx->mcode_size;
		cgen_two(mc);
		g(cgen_operand(ctx, size, instr_base, 0, sp));
		g(cgen_operand(ctx, size, instr_base, CGO_MOVE_DEST, arg1));

		return true;
	}
	if (alu == ALU_MUL) {
		size_t instr_base;
		uint16_t mc;
		if (size != OP_SIZE_4 || !R_IS_D(arg1[0]))
			goto invl;

		g(cgen_prepare_address(ctx, arg3));

		mc = M68K_MUL_L;
		instr_base = ctx->mcode_size;
		cgen_two(mc);
		mc = M68K_MUL_L_S;
		mc |= (arg1[0] & 7) << 12;
		cgen_two(mc);
		g(cgen_operand(ctx, size, instr_base, 0, arg3));

		return true;
	}
	switch (alu) {
		case ALU_ADD:	instr = M68K_ADD; instri = M68K_ADDI; break;
		case ALU_SUB:	instr = M68K_SUB; instri = M68K_SUBI; break;
		case ALU_AND:	instr = M68K_AND; instri = M68K_ANDI; break;
		case ALU_OR:	instr = M68K_OR; instri = M68K_ORI; break;
		case ALU_XOR:	instr = M68K_EOR; instri = M68K_EORI; break;
		case ALU_ADC:	g(cgen_adc_sbb(ctx, size, M68K_ADDX, arg1, arg3)); return true;
		case ALU_SBB:	g(cgen_adc_sbb(ctx, size, M68K_SUBX, arg1, arg3)); return true;
		default:	goto invl;
	}
	g(cgen_two_op(ctx, size, instr, instri, arg1, arg3));
	return true;
invl:
	internal(file_line, "cgen_alu: invalid arguments %u %u %u %02x %02x %02x", size, alu, writes_flags, arg1[0], arg2[0], arg3[0]);
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	size_t instr_base;
	uint16_t instr;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (alu == ALU1_LZCNT) {
		if (!R_IS_D(arg1[0]))
			internal(file_line, "cgen_alu1: invalid register");
		g(cgen_prepare_address(ctx, arg2));
		instr_base = ctx->mcode_size;
		instr = M68K_BFFFO;
		cgen_two(instr);
		instr = (arg1[0] & 7) << 12;
		cgen_two(instr);
		g(cgen_operand(ctx, OP_SIZE_4, instr_base, 0, arg2));
		return true;
	}
	if (memcmp(arg1, arg2, arg_size(*arg1)))
		internal(file_line, "cgen_alu1: operand mismatch");
	switch (alu) {
		case ALU1_NOT:	instr = M68K_NOT; break;
		case ALU1_NEG:	instr = M68K_NEG; break;
		case ALU1_NGC:	instr = M68K_NEGX; break;
		default:	internal(file_line, "cgen_alu1: invalid alu %u", alu);
	}
	if (R_IS_A(arg1[0]))
		internal(file_line, "cgen_alu1: invalid register");
	g(cgen_prepare_address(ctx, arg1));
	instr_base = ctx->mcode_size;
	instr |= get_size(size, false);
	cgen_two(instr);
	g(cgen_operand(ctx, size, instr_base, 0, arg1));
	return true;
}

static bool attr_w cgen_lea3(struct codegen_context *ctx, unsigned shift)
{
	size_t instr_base;
	uint16_t mc;
	uint8_t addr[11];

	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);

	if (unlikely(!R_IS_DA(arg1[0])) || unlikely(!R_IS_DA(arg2[0])) || unlikely(!R_IS_DA(arg3[0])) || unlikely(arg4[0] != ARG_IMM))
		internal(file_line, "cgen_lea3: invalid arguments");

	addr[0] = ARG_ADDRESS_2 + shift;
	addr[1] = arg2[0];
	addr[2] = arg3[0];
	memcpy(&addr[3], &arg4[1], 8);

	g(cgen_prepare_address(ctx, addr));

	mc = M68K_LEA;
	if (R_IS_A(arg1[0]))
		mc |= (arg1[0] & 7) << 9;
	else
		mc |= (R_TMP_A & 7) << 9;
	instr_base = ctx->mcode_size;
	cgen_two(mc);
	g(cgen_operand(ctx, OP_SIZE_4, instr_base, 0, addr));
	if (!R_IS_A(arg1[0]))
		g(cgen_mov_ad(ctx, arg1[0], R_TMP_A));

	return true;
}

static bool attr_w cgen_rot_bf(struct codegen_context *ctx, unsigned size, unsigned alu, uint8_t *arg1, uint8_t *arg2, uint8_t *arg3)
{
	size_t instr_base;
	uint16_t instr;
	unsigned bit_size = 8U << size;
	int64_t imm;
	if (!R_IS_D(arg1[0]) || arg3[0] != ARG_IMM)
		goto invl;
	imm = get_imm(&arg3[1]);
	imm &= (bit_size - 1);
	g(cgen_prepare_address(ctx, arg2));
	switch (alu) {
		case ROT_SHR:	instr = M68K_BFEXTU; break;
		case ROT_SAR:	instr = M68K_BFEXTS; break;
		default:	goto invl;
	}
	instr_base = ctx->mcode_size;
	cgen_two(instr);
	instr = (arg1[0] & 7) << 12;
	instr |= (32 - bit_size) << 6;;
	instr |= bit_size - imm;
	cgen_two(instr);
	g(cgen_operand(ctx, size, instr_base, 0, arg2));
	return true;
invl:
	internal(file_line, "cgen_rot_bf: invalid arguments %u %u %02x %02x %02x", size, alu, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	uint16_t instr;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (!R_IS_D(arg1[0]))
		goto invl;
	if (arg1[0] != arg2[0]) {
		g(cgen_rot_bf(ctx, size, alu, arg1, arg2, arg3));
		return true;
	}
	switch (alu) {
		case ROT_ROL:	instr = M68K_ROL; break;
		case ROT_ROR:	instr = M68K_ROR; break;
		case ROT_RCL:	instr = M68K_ROXL; break;
		case ROT_RCR:	instr = M68K_ROXR; break;
		case ROT_SHL:	instr = M68K_LSL; break;
		case ROT_SHR:	instr = M68K_LSR; break;
		case ROT_SAL:	instr = M68K_ASL; break;
		case ROT_SAR:	instr = M68K_ASR; break;
		default:	internal(file_line, "cgen_rot: invalid alu %u", alu);
	}
	instr |= get_size(size, false);
	instr |= arg1[0] & 7;
	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		imm &= 0x3f;
		if (imm > 8 && imm < (8U << size) && (alu == ROT_SHR || alu == ROT_SAR)) {
			g(cgen_rot_bf(ctx, size, alu, arg1, arg2, arg3));
			return true;
		}
		while (imm) {
			uint8_t this_step = minimum(imm, 8);
			uint16_t mc = instr;
			mc |= (this_step & 7) << 9;
			cgen_two(mc);
			imm -= this_step;
		}
		return true;
	}
	if (!R_IS_D(arg3[0]))
		goto invl;
	instr |= M68K_ROT_R;
	instr |= (arg3[0] & 7) << 9;
	cgen_two(instr);
	return true;
invl:
	internal(file_line, "cgen_rot: invalid arguments %u %u %02x %02x %02x", size, alu, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_div_l(struct codegen_context *ctx, bool sgn)
{
	size_t instr_base;
	uint16_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	uint8_t *arg5 = arg4 + arg_size(*arg4);
	ctx->code_position = arg5 + arg_size(*arg5);
	if (arg1[0] != arg3[0] || arg2[0] != arg4[0] || !R_IS_D(arg1[0]) || !R_IS_D(arg2[0]))
		goto invl;
	mc = M68K_DIV_L;
	instr_base = ctx->mcode_size;
	cgen_two(mc);
	mc = sgn ? M68K_DIV_L_S : 0;
	mc |= (arg2[0] & 7) << 12;
	mc |= arg1[0] & 7;
	cgen_two(mc);
	g(cgen_operand(ctx, OP_SIZE_4, instr_base, 0, arg5));
	return true;
invl:
	internal(file_line, "cgen_div_l: invalid arguments %02x %02x %02x %02x %02x", arg1[0], arg2[0], arg3[0], arg4[0], arg5[0]);
	return false;
}

static bool attr_w cgen_btx31(struct codegen_context *ctx, uint8_t bt, uint8_t *arg1, uint8_t *arg2)
{
	size_t instr_base;
	uint16_t mc;
	g(cgen_prepare_address(ctx, arg1));
	instr_base = ctx->mcode_size;
	switch (bt) {
		case BTX_BTX31:		mc = M68K_BFTST; break;
		case BTX_BTSX31:	mc = M68K_BFSET; break;
		case BTX_BTRX31:	mc = M68K_BFCLR; break;
		case BTX_BTCX31:	mc = M68K_BFCHG; break;
		default:		goto invl;
	}
	cgen_two(mc);
	mc = 1;
	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		if (imm < 0 || imm >= 32)
			goto invl;
		mc |= (imm & 31) << 6;
	} else if (R_IS_D(arg2[0])) {
		mc |= 1 << 11;
		mc |= (arg2[0] & 7) << 6;
	} else {
		goto invl;
	}
	cgen_two(mc);
	g(cgen_operand(ctx, OP_SIZE_4, instr_base, 0, arg1));
	return true;
invl:
	internal(file_line, "cgen_btxt: invalid arguments %u %02x %02x", bt, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_btxt(struct codegen_context *ctx, unsigned size, uint8_t bt, uint8_t *arg1, uint8_t *arg2)
{
	size_t instr_base;
	uint16_t mc;
	if (bt >= BTX_BTX31 && bt <= BTX_BTCX31) {
		if (size != OP_SIZE_4)
			goto invl;
		g(cgen_btx31(ctx, bt, arg1, arg2));
		return true;
	}
	if (R_IS_A(arg1[0]) && arg2[0] == ARG_IMM) {
		uint8_t tmp_d = R_TMP_D;
		mc = M68K_EXG_DA | ((tmp_d & 7) << 9) | (arg1[0] & 7);
		cgen_two(mc);
		g(cgen_btxt(ctx, size, bt, &tmp_d, arg2));
		cgen_two(mc);
		return true;
	}
	if (size != (R_IS_D(arg1[0]) ? OP_SIZE_4 : OP_SIZE_1))
		goto invl;
	g(cgen_prepare_address(ctx, arg1));
	instr_base = ctx->mcode_size;
	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		switch (bt) {
			case BTX_BT:	mc = M68K_BTST_IMM; break;
			case BTX_BTS:	mc = M68K_BSET_IMM; break;
			case BTX_BTR:	mc = M68K_BCLR_IMM; break;
			case BTX_BTC:	mc = M68K_BCHG_IMM; break;
			default:	goto invl;
		}
		cgen_two(mc);
		cgen_two(imm & 0xff);
		g(cgen_operand(ctx, size, instr_base, 0, arg1));
		return true;
	}

	if (!R_IS_D(arg2[0]))
		goto invl;
	switch (bt) {
		case BTX_BT:	mc = M68K_BTST; break;
		case BTX_BTS:	mc = M68K_BSET; break;
		case BTX_BTR:	mc = M68K_BCLR; break;
		case BTX_BTC:	mc = M68K_BCHG; break;
		default:	goto invl;
	}
	mc |= (arg2[0] & 7) << 9;
	cgen_two(mc);
	g(cgen_operand(ctx, size, instr_base, 0, arg1));
	return true;
invl:
	internal(file_line, "cgen_btxt: invalid arguments %u %u %02x %02x", size, bt, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_bt(struct codegen_context *ctx, unsigned size, uint8_t bt)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	return cgen_btxt(ctx, size, bt, arg1, arg2);
}

static bool attr_w cgen_btx(struct codegen_context *ctx, unsigned size, uint8_t bt)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (memcmp(arg1, arg2, arg_size(*arg1)))
		internal(file_line, "cgen_btx: operand mismatch");

	return cgen_btxt(ctx, size, bt, arg1, arg3);
}

static bool attr_w cgen_set_cond(struct codegen_context *ctx, unsigned cond, bool partial)
{
	size_t instr_base;
	uint16_t mc;
	uint8_t *arg1, *arg2;
	if (!partial) {
		arg1 = ctx->code_position;
		ctx->code_position = arg1 + arg_size(*arg1);
	} else {
		arg1 = ctx->code_position;
		arg2 = arg1 + arg_size(*arg1);
		ctx->code_position = arg2 + arg_size(*arg2);
		if (memcmp(arg1, arg2, arg_size(*arg1)))
			internal(file_line, "cgen_set_cond: operand mismatch");
	}
	g(cgen_prepare_address(ctx, arg1));

	instr_base = ctx->mcode_size;
	mc = M68K_SETCC;
	mc |= get_cond(cond) << 8;
	cgen_two(mc);
	g(cgen_operand(ctx, OP_SIZE_1, instr_base, 0, arg1));

	instr_base = ctx->mcode_size;
	mc = M68K_NEG;
	mc |= get_size(OP_SIZE_1, false);
	cgen_two(mc);
	g(cgen_operand(ctx, OP_SIZE_1, instr_base, 0, arg1));

	return true;
}

static bool attr_w cgen_mov_mask(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (memcmp(arg1, arg2, arg_size(*arg1)))
		internal(file_line, "cgen_mov_mask: operand mismatch");

	g(cgen_moves(ctx, size, arg1, arg3, false, true));

	return true;
}

static bool attr_w cgen_jmp(struct codegen_context *ctx, unsigned cond, unsigned jump_size)
{
	uint16_t mc;
	g(add_relocation(ctx, jump_size, 0, NULL));
	mc = M68K_BCC;
	mc |= get_cond(cond) << 8;
	cgen_two(mc);
	if (jump_size >= JMP_SHORT)
		cgen_two(0);
	if (jump_size >= JMP_LONG)
		cgen_two(0);
	return true;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	int32_t offs = (int64_t)ctx->label_to_pos[reloc->label_id] - (int64_t)(reloc->position + 2);
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (!offs || !imm_is_8bit(offs))
				return false;
			ctx->mcode[reloc->position + 1] = offs;
			return true;
		case JMP_SHORT:
			if (!imm_is_16bit(offs))
				return false;
			ctx->mcode[reloc->position + 1] = 0;
			ctx->mcode[reloc->position + 2] = (uint32_t)offs >> 8;
			ctx->mcode[reloc->position + 3] = (uint32_t)offs;
			return true;
		case JMP_LONG:
			ctx->mcode[reloc->position + 1] = 0xff;
			ctx->mcode[reloc->position + 2] = (uint32_t)offs >> 24;
			ctx->mcode[reloc->position + 3] = (uint32_t)offs >> 16;
			ctx->mcode[reloc->position + 4] = (uint32_t)offs >> 8;
			ctx->mcode[reloc->position + 5] = (uint32_t)offs;
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}

static bool validate_arg(const uint8_t *arg)
{
	if (R_IS_DA(arg[0]))
		return true;
	if (arg[0] == ARG_ADDRESS_1 ||
	    arg[0] == ARG_ADDRESS_1_PRE_I ||
	    arg[0] == ARG_ADDRESS_1_POST_I ||
	    (arg[0] >= ARG_ADDRESS_2 && arg[0] <= ARG_ADDRESS_2_8))
		return true;
	return false;
}

static bool validate_insn(const struct insn_details attr_unused *d)
{
	switch (insn_opcode(d->insn)) {
		case INSN_MOV:
		case INSN_MOVSX:
			const uint8_t *arg1 = d->start + 4;
			const uint8_t *arg2 = arg1 + arg_size(*arg1);
			if (unlikely(!validate_arg(arg1)) || unlikely(!(validate_arg(arg2) || arg2[0] == ARG_IMM)))
				return false;
			return true;
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
			cgen_two(M68K_NOP);
			return true;
		case INSN_RET:
			cgen_two(M68K_RTS);
			return true;
		case INSN_M68K_PUSH:
		case INSN_M68K_POP:
			g(cgen_m68k_push_pop(ctx, insn_opcode(insn) == INSN_M68K_POP));
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_jmp_indirect(ctx, true));
			return true;
		case INSN_MOV:
		case INSN_MOVSX:
			g(cgen_mov(ctx, insn_op_size(insn), insn_opcode(insn) == INSN_MOVSX));
			return true;
		case INSN_CMP:
			g(cgen_cmp(ctx, insn_op_size(insn)));
			return true;
		case INSN_TEST:
			g(cgen_test(ctx, insn_op_size(insn)));
			return true;
		case INSN_ALU:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU_PARTIAL:
			if (unlikely(insn_op_size(insn) >= OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU1:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ALU1_PARTIAL:
			if (unlikely(insn_op_size(insn) >= OP_SIZE_4))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_LEA3:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4))
				goto invalid_insn;
			g(cgen_lea3(ctx, insn_aux(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ROT_PARTIAL:
			if (unlikely(insn_op_size(insn) >= OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_BT:
			g(cgen_bt(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_BTX:
			g(cgen_btx(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_DIV_L:
			g(cgen_div_l(ctx, insn_aux(insn)));
			return true;
		case INSN_SET_COND:
		case INSN_SET_COND_PARTIAL:
			if (unlikely(insn_op_size(insn) != OP_SIZE_1))
				goto invalid_insn;
			g(cgen_set_cond(ctx, insn_aux(insn), insn_opcode(insn) == INSN_SET_COND_PARTIAL));
			return true;
		case INSN_MOV_MASK:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4))
				goto invalid_insn;
			if (insn_aux(insn) == MOV_MASK_0_8)
				g(cgen_mov_mask(ctx, OP_SIZE_1));
			else if (insn_aux(insn) == MOV_MASK_0_16)
				g(cgen_mov_mask(ctx, OP_SIZE_2));
			else
				goto invalid_insn;
			return true;
		case INSN_JMP:
			g(cgen_jmp(ctx, COND_ALWAYS, insn_jump_size(insn)));
			return true;
		case INSN_JMP_COND:
			g(cgen_jmp(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_indirect(ctx, false));
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
