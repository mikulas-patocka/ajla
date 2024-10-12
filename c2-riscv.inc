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

#define RISCV_LB		0x00000003U
#define RISCV_LH		0x00001003U
#define RISCV_LW		0x00002003U
#define RISCV_LD		0x00003003U
#define RISCV_LBU		0x00004003U
#define RISCV_LHU		0x00005003U
#define RISCV_LWU		0x00006003U
#define RISCV_FL		0x00000007U
#define  RISCV_FSL_H			0x00001000U
#define  RISCV_FSL_W			0x00002000U
#define  RISCV_FSL_D			0x00003000U
#define  RISCV_FSL_Q			0x00004000U
#define RISCV_ADDI		0x00000013U
#define RISCV_BSETI		0x28001013U
#define RISCV_BCLRI		0x48001013U
#define RISCV_CLZ		0x60001013U
#define RISCV_BINVI		0x68001013U
#define RISCV_CTZ		0x60101013U
#define RISCV_CPOP		0x60201013U
#define RISCV_SEXT_B		0x60401013U
#define RISCV_SEXT_H		0x60501013U
#define RISCV_BEXTI		0x48005013U
#define RISCV_REV8		0x6b805013U
#define RISCV_SLLI		0x00001013U
#define RISCV_SLTI		0x00002013U
#define RISCV_SLTIU		0x00003013U
#define RISCV_XORI		0x00004013U
#define RISCV_SRLI		0x00005013U
#define RISCV_SRAI		0x40005013U
#define RISCV_RORI		0x60005013U
#define RISCV_ORI		0x00006013U
#define RISCV_ANDI		0x00007013U
#define RISCV_AUIPC		0x00000017U
#define RISCV_ADDIW		0x0000001bU
#define RISCV_SLLIW		0x0000101bU
#define RISCV_SRLIW		0x0000501bU
#define RISCV_SRAIW		0x4000501bU
#define RISCV_CLZW		0x6000101bU
#define RISCV_CTZW		0x6010101bU
#define RISCV_CPOPW		0x6020101bU
#define RISCV_RORIW		0x6000501bU
#define RISCV_SB		0x00000023U
#define RISCV_SH		0x00001023U
#define RISCV_SW		0x00002023U
#define RISCV_SD		0x00003023U
#define RISCV_FS		0x00000027U
#define RISCV_ADD		0x00000033U
#define RISCV_MUL		0x02000033U
#define RISCV_SUB		0x40000033U
#define RISCV_SLL		0x00001033U
#define RISCV_MULH		0x02001033U
#define RISCV_BSET		0x28001033U
#define RISCV_BCLR		0x48001033U
#define RISCV_BINV		0x68001033U
#define RISCV_ROL		0x60001033U
#define RISCV_SLT		0x00002033U
#define RISCV_SH1ADD		0x20002033U
#define RISCV_SLTU		0x00003033U
#define RISCV_XOR		0x00004033U
#define RISCV_DIV		0x02004033U
#define RISCV_SH2ADD		0x20004033U
#define RISCV_SRL		0x00005033U
#define RISCV_DIVU		0x02005033U
#define RISCV_SRA		0x40005033U
#define RISCV_BEXT		0x48005033U
#define RISCV_ROR		0x60005033U
#define RISCV_OR		0x00006033U
#define RISCV_REM		0x02006033U
#define RISCV_SH3ADD		0x20006033U
#define RISCV_AND		0x00007033U
#define RISCV_REMU		0x02007033U
#define RISCV_ANDN		0x40007033U
#define RISCV_LUI		0x00000037U
#define RISCV_ADDW		0x0000003bU
#define RISCV_ADD_UW		0x0800003bU
#define RISCV_SUBW		0x4000003bU
#define RISCV_SLLW		0x0000103bU
#define RISCV_MULW		0x0200003bU
#define RISCV_ROLW		0x6000103bU
#define RISCV_DIVW		0x0200403bU
#define RISCV_ZEXT_H		0x0800403bU
#define RISCV_SRLW		0x0000503bU
#define RISCV_DIVUW		0x0200503bU
#define RISCV_SRAW		0x4000503bU
#define RISCV_RORW		0x6000503bU
#define RISCV_REMW		0x0200603bU
#define RISCV_REMUW		0x0200703bU
#define RISCV_FADD		0x00000053U
#define RISCV_FSUB		0x08000053U
#define RISCV_FMUL		0x10000053U
#define RISCV_FDIV		0x18000053U
#define RISCV_FSGNJ		0x20000053U
#define RISCV_FLE		0xa0000053U
#define RISCV_FCVT_TO_W		0xc0000053U
#define RISCV_FCVT_TO_L		0xc0200053U
#define RISCV_FCVT_FROM_W	0xd0000053U
#define RISCV_FCVT_FROM_L	0xd0200053U
#define RISCV_FSGNJN		0x20001053U
#define RISCV_FLT		0xa0001053U
#define RISCV_FSGNJX		0x20002053U
#define RISCV_FEQ		0xa0002053U
#define RISCV_FSQRT		0x58000053U
#define  RISCV_F_RNE			0x00000000U
#define  RISCV_F_RTZ			0x00001000U
#define  RISCV_F_RDN			0x00002000U
#define  RISCV_F_RUP			0x00003000U
#define  RISCV_F_RMM			0x00004000U
#define  RISCV_F_DYN			0x00007000U
#define  RISCV_F_SINGLE			0x00000000U
#define  RISCV_F_DOUBLE			0x02000000U
#define  RISCV_F_HALF			0x04000000U
#define  RISCV_F_QUAD			0x06000000U
#define RISCV_BEQ		0x00000063U
#define RISCV_BNE		0x00001063U
#define RISCV_BLT		0x00004063U
#define RISCV_BGE		0x00005063U
#define RISCV_BLTU		0x00006063U
#define RISCV_BGEU		0x00007063U
#define RISCV_JALR		0x00000067U
#define RISCV_JAL		0x0000006fU

#define RISCV_C_J		0xa001U
#define RISCV_C_BEQZ		0xc001U
#define RISCV_C_BNEZ		0xe001U

static bool cgen_rv_compress(struct codegen_context *ctx, uint32_t insn)
{
	 if (likely(cpu_test_feature(CPU_FEATURE_c))) {
		size_t result;
		uint16_t c;
		binary_search(size_t, n_array_elements(riscv_compress), result, riscv_compress[result].l == insn, riscv_compress[result].l < insn, goto uncompressed);
		c = riscv_compress[result].s;
		cgen_two(c);
		return true;
	 }
uncompressed:
	cgen_four(insn);
	return true;
}

#define cgen_rv(dword)					\
do {							\
	if (unlikely(!cgen_rv_compress(ctx, dword)))	\
		return false;				\
} while (0)


static bool attr_w cgen_memory_load(struct codegen_context *ctx, uint32_t mc, unsigned rd, unsigned rs, int64_t imm)
{
	if (unlikely(imm < -0x800) || unlikely(imm >= 0x800))
		internal(file_line, "cgen_memory_load: invalid immediate value %"PRIxMAX"", (uintmax_t)imm);
	mc |= (uint32_t)rs << 15;
	mc |= (uint32_t)rd << 7;
	mc |= (uint32_t)imm << 20;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_memory_store(struct codegen_context *ctx, uint32_t mc, unsigned rs1, unsigned rs2, int64_t imm)
{
	if (unlikely(imm < -0x800) || unlikely(imm >= 0x800))
		internal(file_line, "cgen_memory_store: invalid immediate value %"PRIxMAX"", (uintmax_t)imm);
	mc |= (uint32_t)rs1 << 15;
	mc |= (uint32_t)rs2 << 20;
	mc |= ((uint32_t)imm & 0x1f) << 7;
	mc |= ((uint32_t)imm & 0xfe0) << 20;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_jmp_call_indirect(struct codegen_context *ctx, bool call)
{
	uint8_t reg = cget_one(ctx);
	uint32_t mc;
	mc = RISCV_JALR;
	if (call)
		mc |= (uint32_t)R_RA << 7;
	mc |= (uint32_t)reg << 15;
	cgen_rv(mc);
	return true;
}

static uint32_t riscv_fp_op_size(unsigned fp_op_size)
{
	switch (fp_op_size) {
		case OP_SIZE_2:		return RISCV_F_HALF;
		case OP_SIZE_4:		return RISCV_F_SINGLE;
		case OP_SIZE_8:		return RISCV_F_DOUBLE;
		case OP_SIZE_16:	return RISCV_F_QUAD;
		default:		internal(file_line, "riscv_fp_op_size: invalid size %u", fp_op_size);
	}
	return (uint32_t)-1;
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
			if (unlikely((imm & 0xfff) != 0) ||
			    unlikely(imm < -0x80000000LL) ||
			    unlikely(imm >= 0x80000000LL))
				internal(file_line, "cgen_mov: invalid immediate value %"PRIxMAX"", (uintmax_t)imm);
			mc = RISCV_LUI;
			mc |= (uint32_t)arg1[0] << 7;
			mc |= (uint32_t)imm;
			cgen_rv(mc);
			return true;
		}
		if (arg2[0] == ARG_ADDRESS_1) {
			imm = get_imm(&arg2[2]);
			switch (size) {
				case OP_SIZE_1:	mc = RISCV_LBU; break;
				case OP_SIZE_2:	mc = RISCV_LHU; break;
				case OP_SIZE_4:	mc = RISCV_LWU; break;
				case OP_SIZE_8:	mc = RISCV_LD; break;
				default:	goto invalid;
			}
			g(cgen_memory_load(ctx, mc, arg1[0], arg2[1], imm));
			return true;
		}
		if (arg2[0] < 0x20) {
			switch (size) {
				case OP_SIZE_1:	mc = RISCV_ANDI | ((uint32_t)0xff << 20); break;
				case OP_SIZE_2:	mc = RISCV_ZEXT_H; break;
				case OP_SIZE_4:	mc = RISCV_ADD_UW; break;
				case OP_SIZE_8:	mc = RISCV_ADDI; break;
				default:	goto invalid;
			}
			mc |= (uint32_t)arg1[0] << 7;
			mc |= (uint32_t)arg2[0] << 15;
			cgen_rv(mc);
			return true;
		}
		goto invalid;
	}
	if (reg_is_fp(arg1[0])) {
		if (reg_is_fp(arg2[0])) {
			mc = RISCV_FSGNJ;
			mc |= (uint32_t)(arg1[0] & 0x1f) << 7;
			mc |= (uint32_t)(arg2[0] & 0x1f) << 15;
			mc |= (uint32_t)(arg2[0] & 0x1f) << 20;
			mc |= riscv_fp_op_size(size);
			cgen_rv(mc);
			return true;
		}
		if (arg2[0] == ARG_ADDRESS_1) {
			imm = get_imm(&arg2[2]);
			switch (size) {
				case OP_SIZE_2:	mc = RISCV_FL | RISCV_FSL_H; break;
				case OP_SIZE_4:	mc = RISCV_FL | RISCV_FSL_W; break;
				case OP_SIZE_8:	mc = RISCV_FL | RISCV_FSL_D; break;
				case OP_SIZE_16:mc = RISCV_FL | RISCV_FSL_Q; break;
				default:	goto invalid;
			}
			g(cgen_memory_load(ctx, mc, arg1[0] & 0x1f, arg2[1], imm));
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
				case OP_SIZE_1:	mc = RISCV_SB; break;
				case OP_SIZE_2:	mc = RISCV_SH; break;
				case OP_SIZE_4:	mc = RISCV_SW; break;
				case OP_SIZE_8:	mc = RISCV_SD; break;
				default:	goto invalid;
			}
			g(cgen_memory_store(ctx, mc, arg1[1], arg2[0], imm));
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			imm = get_imm(&arg1[2]);
			switch (size) {
				case OP_SIZE_2:	mc = RISCV_FS | RISCV_FSL_H; break;
				case OP_SIZE_4:	mc = RISCV_FS | RISCV_FSL_W; break;
				case OP_SIZE_8:	mc = RISCV_FS | RISCV_FSL_D; break;
				case OP_SIZE_16:mc = RISCV_FS | RISCV_FSL_Q; break;
				default:	goto invalid;
			}
			g(cgen_memory_store(ctx, mc, arg1[1], arg2[0] & 0x1f, imm));
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

	if (unlikely(arg1[0] >= 0x20))
		goto invalid;

	if (arg2[0] == ARG_ADDRESS_1) {
		uint32_t mc;
		switch (size) {
			case OP_SIZE_1:	mc = RISCV_LB; break;
			case OP_SIZE_2:	mc = RISCV_LH; break;
			case OP_SIZE_4:	mc = RISCV_LW; break;
			default:	goto invalid;
		}
		g(cgen_memory_load(ctx, mc, arg1[0], arg2[1], get_imm(&arg2[2])));
		return true;
	}

	if (arg2[0] < 0x20) {
		uint32_t mc;
		switch (size) {
			case OP_SIZE_1:	mc = RISCV_SEXT_B; break;
			case OP_SIZE_2:	mc = RISCV_SEXT_H; break;
			case OP_SIZE_4:	mc = RISCV_ADDIW; break;
			default:	goto invalid;
		}
		mc |= (uint32_t)arg1[0] << 7;
		mc |= (uint32_t)arg2[0] << 15;
		cgen_rv(mc);
		return true;
	}

invalid:
	internal(file_line, "cgen_movsx: invalid parameters %u, %02x, %02x", size, arg1[0], arg2[0]);
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
			case COND_B:		mc = RISCV_SLTIU; break;
			case COND_L:		mc = RISCV_SLTI; break;
			default:		internal(file_line, "cgen_cmp_dest_reg: invalid condition %u", aux);
		}
		mc |= (uint32_t)arg1[0] << 7;
		mc |= (uint32_t)arg2[0] << 15;
		mc |= (uint32_t)imm << 20;
		cgen_rv(mc);
		return true;
	}
	if (arg2[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg2[1]);
		if (unlikely(imm != 0))
			internal(file_line, "cgen_cmp_dest_reg: non-zero second argument");
		arg2 = &z;
	}
	switch (aux) {
		case COND_B:		mc = RISCV_SLTU; break;
		case COND_A:		mc = RISCV_SLTU; swap = true; break;
		case COND_L:		mc = RISCV_SLT; break;
		case COND_G:		mc = RISCV_SLT; swap = true; break;
		default:		internal(file_line, "cgen_cmp_dest_reg: invalid condition %u", aux);
	}
	if (swap) {
		uint8_t *argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}
	mc |= (uint32_t)arg1[0] << 7;
	mc |= (uint32_t)arg2[0] << 15;
	mc |= (uint32_t)arg3[0] << 20;
	cgen_rv(mc);
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
		if (unlikely(imm < -0x800) || unlikely(imm >= 0x800))
			internal(file_line, "cgen_alu: invalid imm value %"PRIxMAX"", (intmax_t)imm);
		switch (alu) {
			case ALU_ADD:	mc = size == OP_SIZE_8 ? RISCV_ADDI : RISCV_ADDIW; break;
			case ALU_XOR:	mc = RISCV_XORI; break;
			case ALU_OR:	mc = RISCV_ORI; break;
			case ALU_AND:	mc = RISCV_ANDI; break;
			default:	internal(file_line, "cgen_alu: invalid alu %u", alu);
		}
		mc |= (uint32_t)arg1[0] << 7;
		mc |= (uint32_t)arg2[0] << 15;
		mc |= (uint32_t)imm << 20;
		cgen_rv(mc);
		return true;
	}
	if (alu == ALU_ADD && arg3[0] == ARG_SHIFTED_REGISTER) {
		uint8_t *arg_swp = arg3;
		arg3 = arg2;
		arg2 = arg_swp;
	}
	if (arg2[0] == ARG_SHIFTED_REGISTER) {
		if (unlikely(alu != ALU_ADD) || unlikely(size != OP_SIZE_8))
			internal(file_line, "cgen_alu: invalid shifted alu %u, %u", alu, size);
		if (arg2[1] == (ARG_SHIFT_LSL | 0))
			mc = RISCV_ADD;
		else if (arg2[1] == (ARG_SHIFT_LSL | 1))
			mc = RISCV_SH1ADD;
		else if (arg2[1] == (ARG_SHIFT_LSL | 2))
			mc = RISCV_SH2ADD;
		else if (arg2[1] == (ARG_SHIFT_LSL | 3))
			mc = RISCV_SH3ADD;
		else
			internal(file_line, "cgen_alu: invalid shifted register operation: %02x", arg2[1]);
		mc |= (uint32_t)arg1[0] << 7;
		mc |= (uint32_t)arg2[2] << 15;
		mc |= (uint32_t)arg3[0] << 20;
		cgen_rv(mc);
		return true;
	}
	switch (alu) {
		case ALU_ADD:	mc = size == OP_SIZE_8 ? RISCV_ADD : RISCV_ADDW; break;
		case ALU_SUB:	mc = size == OP_SIZE_8 ? RISCV_SUB : RISCV_SUBW; break;
		case ALU_XOR:	mc = RISCV_XOR; break;
		case ALU_OR:	mc = RISCV_OR; break;
		case ALU_AND:	mc = RISCV_AND; break;
		case ALU_ANDN:	mc = RISCV_ANDN; break;
		case ALU_MUL:	mc = size == OP_SIZE_8 ? RISCV_MUL : RISCV_MULW; break;
		case ALU_SMULH:	if (unlikely(size != OP_SIZE_8))
					goto invalid;
				mc = RISCV_MULH; break;
		case ALU_UDIV:	mc = size == OP_SIZE_8 ? RISCV_DIVU : RISCV_DIVUW; break;
		case ALU_SDIV:	mc = size == OP_SIZE_8 ? RISCV_DIV : RISCV_DIVW; break;
		case ALU_UREM:	mc = size == OP_SIZE_8 ? RISCV_REMU : RISCV_REMUW; break;
		case ALU_SREM:	mc = size == OP_SIZE_8 ? RISCV_REM : RISCV_REMW; break;
		invalid:
		default:	internal(file_line, "cgen_alu: invalid alu %u", alu);
	}
	mc |= (uint32_t)arg1[0] << 7;
	mc |= (uint32_t)arg2[0] << 15;
	mc |= (uint32_t)arg3[0] << 20;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	bool tgt20 = false;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (alu) {
		case ALU1_NOT:	mc = RISCV_XORI | ((uint32_t)-1 << 20); break;
		case ALU1_NEG:	mc = (size == OP_SIZE_8 ? RISCV_SUB : RISCV_SUBW); tgt20 = true; break;
		case ALU1_INC:	mc = (size == OP_SIZE_8 ? RISCV_ADDI : RISCV_ADDIW) | ((uint32_t)1 << 20); break;
		case ALU1_DEC:	mc = (size == OP_SIZE_8 ? RISCV_ADDI : RISCV_ADDIW) | ((uint32_t)-1 << 20); break;
		case ALU1_BSWAP:if (unlikely(size != OP_SIZE_8))
					goto invalid;
				mc = RISCV_REV8; break;
		case ALU1_BSF:	mc = size == OP_SIZE_8 ? RISCV_CTZ : RISCV_CTZW; break;
		case ALU1_LZCNT:mc = size == OP_SIZE_8 ? RISCV_CLZ : RISCV_CLZW; break;
		case ALU1_POPCNT:mc = size == OP_SIZE_8 ? RISCV_CPOP : RISCV_CPOPW; break;
		invalid:
		default:	internal(file_line, "cgen_alu1: invalid alu %u", alu);
				return false;
	}
	mc |= (uint32_t)arg1[0] << 7;
	mc |= (uint32_t)arg2[0] << (tgt20 ? 20 : 15);
	cgen_rv(mc);
	return true;
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
			case ROT_ROL:	mc = size == OP_SIZE_4 ? RISCV_RORIW : RISCV_RORI; break;
			case ROT_ROR:	mc = size == OP_SIZE_4 ? RISCV_RORIW : RISCV_RORI; break;
			case ROT_SHL:	mc = size == OP_SIZE_4 ? RISCV_SLLIW : RISCV_SLLI; break;
			case ROT_SHR:	mc = size == OP_SIZE_4 ? RISCV_SRLIW : RISCV_SRLI; break;
			case ROT_SAR:	mc = size == OP_SIZE_4 ? RISCV_SRAIW : RISCV_SRAI; break;
			default:	internal(file_line, "cgen_rot: invalid alu %u", alu);
		}
		mc |= (uint32_t)arg1[0] << 7;
		mc |= (uint32_t)arg2[0] << 15;
		mc |= (uint32_t)imm << 20;
		cgen_rv(mc);
		return true;
	}
	switch (alu) {
		case ROT_ROL:	mc = size == OP_SIZE_4 ? RISCV_ROLW : RISCV_ROL; break;
		case ROT_ROR:	mc = size == OP_SIZE_4 ? RISCV_RORW : RISCV_ROR; break;
		case ROT_SHL:	mc = size == OP_SIZE_4 ? RISCV_SLLW : RISCV_SLL; break;
		case ROT_SHR:	mc = size == OP_SIZE_4 ? RISCV_SRLW : RISCV_SRL; break;
		case ROT_SAR:	mc = size == OP_SIZE_4 ? RISCV_SRAW : RISCV_SRA; break;
		default:	internal(file_line, "cgen_rot: invalid alu %u", alu);
	}
	mc |= (uint32_t)arg1[0] << 7;
	mc |= (uint32_t)arg2[0] << 15;
	mc |= (uint32_t)arg3[0] << 20;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_btx(struct codegen_context *ctx, unsigned alu)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]) & 0x3f;
		switch (alu) {
			case BTX_BTS:	mc = RISCV_BSETI; break;
			case BTX_BTR:	mc = RISCV_BCLRI; break;
			case BTX_BTC:	mc = RISCV_BINVI; break;
			case BTX_BTEXT:	mc = RISCV_BEXTI; break;
			default:	internal(file_line, "cgen_btx: invalid alu %u", alu);
		}
		mc |= (uint32_t)arg1[0] << 7;
		mc |= (uint32_t)arg2[0] << 15;
		mc |= (uint32_t)imm << 20;
		cgen_rv(mc);
		return true;
	}
	switch (alu) {
		case BTX_BTS:	mc = RISCV_BSET; break;
		case BTX_BTR:	mc = RISCV_BCLR; break;
		case BTX_BTC:	mc = RISCV_BINV; break;
		case BTX_BTEXT:	mc = RISCV_BEXT; break;
		default:	internal(file_line, "cgen_btx: invalid alu %u", alu);
	}
	mc |= (uint32_t)arg1[0] << 7;
	mc |= (uint32_t)arg2[0] << 15;
	mc |= (uint32_t)arg3[0] << 20;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_fp_cmp_dest_reg(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	bool swap = false;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (aux) {
		case FP_COND_E:		mc = RISCV_FEQ; break;
		case FP_COND_A:		mc = RISCV_FLT; swap = true; break;
		case FP_COND_BE:	mc = RISCV_FLE; break;
		case FP_COND_B:		mc = RISCV_FLT; break;
		case FP_COND_AE:	mc = RISCV_FLE; swap = true; break;
		default:		internal(file_line, "cgen_fp_cmp_dest_reg: invalid condition %u", aux);
	}
	if (swap) {
		uint8_t *argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}
	switch (op_size) {
		case OP_SIZE_2:		mc |= RISCV_F_HALF; break;
		case OP_SIZE_4:		mc |= RISCV_F_SINGLE; break;
		case OP_SIZE_8:		mc |= RISCV_F_DOUBLE; break;
		case OP_SIZE_16:	mc |= RISCV_F_QUAD; break;
		default:		internal(file_line, "cgen_fp_cmp_dest_reg: invalid size %u", op_size);
	}
	mc |= (uint32_t)arg1[0] << 7;
	mc |= (uint32_t)(arg2[0] & 0x1f) << 15;
	mc |= (uint32_t)(arg3[0] & 0x1f) << 20;
	cgen_rv(mc);
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
		case FP_ALU_ADD:	mc = RISCV_FADD; break;
		case FP_ALU_SUB:	mc = RISCV_FSUB; break;
		case FP_ALU_MUL:	mc = RISCV_FMUL; break;
		case FP_ALU_DIV:	mc = RISCV_FDIV; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	mc |= RISCV_F_RNE;
	mc |= riscv_fp_op_size(op_size);
	mc |= (uint32_t)(arg1[0] & 0x1f) << 7;
	mc |= (uint32_t)(arg2[0] & 0x1f) << 15;
	mc |= (uint32_t)(arg3[0] & 0x1f) << 20;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	mc = RISCV_FSGNJN;
					mc |= (uint32_t)(arg1[0] & 0x1f) << 7;
					mc |= (uint32_t)(arg2[0] & 0x1f) << 15;
					mc |= (uint32_t)(arg2[0] & 0x1f) << 20;
					break;
		case FP_ALU1_SQRT:	mc = RISCV_FSQRT;
					mc |= (uint32_t)(arg1[0] & 0x1f) << 7;
					mc |= (uint32_t)(arg2[0] & 0x1f) << 15;
					mc |= RISCV_F_RNE;
					break;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	mc |= riscv_fp_op_size(op_size);
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (int_op_size) {
		case OP_SIZE_4:	mc = RISCV_FCVT_TO_W; break;
		case OP_SIZE_8: mc = RISCV_FCVT_TO_L; break;
		default:	internal(file_line, "cgen_fp_to_int: invalid int size %u", int_op_size);
	}
	mc |= RISCV_F_RTZ;
	mc |= riscv_fp_op_size(fp_op_size);
	mc |= (uint32_t)arg1[0] << 7;
	mc |= (uint32_t)(arg2[0] & 0x1f) << 15;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (int_op_size) {
		case OP_SIZE_4:	mc = RISCV_FCVT_FROM_W; break;
		case OP_SIZE_8: mc = RISCV_FCVT_FROM_L; break;
		default:	internal(file_line, "cgen_fp_from_int: invalid int size %u", int_op_size);
	}
	mc |= RISCV_F_RNE;
	mc |= riscv_fp_op_size(fp_op_size);
	mc |= (uint32_t)(arg1[0] & 0x1f) << 7;
	mc |= (uint32_t)arg2[0] << 15;
	cgen_rv(mc);
	return true;
}

static bool attr_w cgen_jmp(struct codegen_context *ctx, unsigned length)
{
	if (length == JMP_SHORTEST && likely(cpu_test_feature(CPU_FEATURE_c))) {
		g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
		cgen_two(RISCV_C_J);
	} else if (length <= JMP_LONG) {
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_four(RISCV_JAL);
	} else if (length == JMP_EXTRA_LONG) {
		g(add_relocation(ctx, JMP_EXTRA_LONG, 0, NULL));
		cgen_four(RISCV_AUIPC | ((uint32_t)R_CONST_HELPER << 7));
		cgen_four(RISCV_JALR | ((uint32_t)R_CONST_HELPER << 15));
	} else {
		internal(file_line, "cgen_jmp: invalid length %u", length);
	}
	return true;
}

static bool attr_w cgen_jmp_12regs(struct codegen_context *ctx, unsigned cond, unsigned length, unsigned reg1, unsigned reg2, int reloc_offset)
{
	uint32_t mc;
	bool swap = false;
	if (length > JMP_SHORT)
		cond ^= 1;
	switch (cond) {
		case COND_B:	mc = RISCV_BLTU; break;
		case COND_AE:	mc = RISCV_BGEU; break;
		case COND_E:	mc = RISCV_BEQ; break;
		case COND_NE:	mc = RISCV_BNE; break;
		case COND_BE:	mc = RISCV_BGEU; swap = true; break;
		case COND_A:	mc = RISCV_BLTU; swap = true; break;
		case COND_S:
		case COND_L:	mc = RISCV_BLT; break;
		case COND_NS:
		case COND_GE:	mc = RISCV_BGE; break;
		case COND_LE:	mc = RISCV_BGE; swap = true; break;
		case COND_G:	mc = RISCV_BLT; swap = true; break;
		default:	goto invalid;
	}
	if (swap) {
		unsigned regx = reg1;
		reg1 = reg2;
		reg2 = regx;
	}

	mc |= (uint32_t)reg1 << 15;
	mc |= (uint32_t)reg2 << 20;

	if (length == JMP_SHORTEST && (cond == COND_E || cond == COND_NE) && (reg1 & 0x18) == 0x8 && reg2 == R_ZERO && cpu_test_feature(CPU_FEATURE_c)) {
		uint16_t mc2 = cond == COND_E ? RISCV_C_BEQZ : RISCV_C_BNEZ;
		mc2 |= ((uint16_t)reg1 & 0x7) << 7;
		g(add_relocation(ctx, JMP_SHORTEST, reloc_offset, NULL));
		cgen_two(mc2);
	} else if (length <= JMP_SHORT) {
		g(add_relocation(ctx, JMP_SHORT, reloc_offset, NULL));
		cgen_four(mc);
	} else if (length == JMP_LONG) {
		mc |= 0x400;
		cgen_four(mc);
		g(add_relocation(ctx, JMP_LONG, reloc_offset, NULL));
		mc = RISCV_JAL;
		cgen_four(mc);
	} else if (length == JMP_EXTRA_LONG) {
		mc |= 0x600;
		cgen_four(mc);
		g(add_relocation(ctx, JMP_EXTRA_LONG, reloc_offset, NULL));
		cgen_four(RISCV_AUIPC | ((uint32_t)R_CONST_HELPER << 7));
		cgen_four(RISCV_JALR | ((uint32_t)R_CONST_HELPER << 15));
	} else {
		internal(file_line, "cgen_jmp_12regs: invalid length %u", length);
	}
	return true;

invalid:
	internal(file_line, "cgen_jmp_12regs: invalid arguments %u, %02x, %02x", cond, reg1, reg2);
	return false;
}

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (arg1[0] < 0x20) {
		return cgen_jmp_12regs(ctx, cond, length, arg1[0], R_ZERO, 1);
	}
	internal(file_line, "cgen_jmp_reg: invalid argument %02x", arg1[0]);
	return false;
}

static bool attr_w cgen_jmp_2regs(struct codegen_context *ctx, unsigned cond, unsigned length)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] < 0x20 && arg2[0] < 0x20) {
		return cgen_jmp_12regs(ctx, cond, length, arg1[0], arg2[0], 2);
	}
	internal(file_line, "cgen_jmp_2regs: invalid arguments %02x, %02x", arg1[0], arg2[0]);
	return false;
}


static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint16_t mc2;
	uint32_t mc;
	uint64_t mc8;
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 1) - (int64_t)(reloc->position >> 1);
	switch (reloc->length) {
		case JMP_SHORTEST:
			memcpy(&mc2, ctx->mcode + reloc->position, 2);
			if ((mc2 & 0xe003) == RISCV_C_J) {
				if (unlikely(offs < -0x400) || unlikely(offs >= 0x400))
					return false;
				mc2 &= 0xe003;
				mc2 |= ((uint32_t)offs & 0x7) << 3;
				mc2 |= ((uint32_t)offs & 0x8) << 8;
				mc2 |= ((uint32_t)offs & 0x10) >> 2;
				mc2 |= ((uint32_t)offs & 0x20) << 2;
				mc2 |= ((uint32_t)offs & 0x40);
				mc2 |= ((uint32_t)offs & 0x180) << 2;
				mc2 |= ((uint32_t)offs & 0x200) >> 1;
				mc2 |= ((uint32_t)offs & 0x400) << 2;
			} else if ((mc2 & 0xe003) == RISCV_C_BEQZ || (mc2 & 0xe003) == RISCV_C_BNEZ) {
				if (unlikely(offs < -0x80) || unlikely(offs >= 0x80))
					return false;
				mc2 &= 0xe383;
				mc2 |= ((uint32_t)offs & 0x3) << 3;
				mc2 |= ((uint32_t)offs & 0xc) << 8;
				mc2 |= ((uint32_t)offs & 0x10) >> 2;
				mc2 |= ((uint32_t)offs & 0x60);
				mc2 |= ((uint32_t)offs & 0x80) << 5;
			} else {
				internal(file_line, "resolve_relocation: invalid 2-byte instruction %04x", mc2);
			}
			memcpy(ctx->mcode + reloc->position, &mc2, 2);
			return true;
		case JMP_SHORT:
			if (unlikely(offs < -0x800) || unlikely(offs >= 0x800))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0x01fff07fU;
			mc |= ((uint32_t)offs & 0xf) << (8 - 0);
			mc |= ((uint32_t)offs & 0x3f0) << (25 - 4);
			mc |= ((uint32_t)offs & 0x400) >> (10 - 7);
			mc |= ((uint32_t)offs & 0x800) << (31 - 11);
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_LONG:
			if (unlikely(offs < -0x80000) || unlikely(offs >= 0x80000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0x00000fffU;
			mc |= ((uint32_t)offs & 0x3ff) << (21 - 0);
			mc |= ((uint32_t)offs & 0x400) << (20 - 10);
			mc |= ((uint32_t)offs & 0x7f800) << (12 - 11);
			mc |= ((uint32_t)offs & 0x80000) << (31 - 19);
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_EXTRA_LONG:
			offs = (uint64_t)offs << 1;
			memcpy(&mc8, ctx->mcode + reloc->position, 8);
			mc8 &= 0x000fffff00000fffULL;
			mc8 |= ((uint64_t)offs & 0xfffULL) << (32 + 20);
			if (offs & 0x800) {
				offs = (uint64_t)offs + 0x1000;
			}
			if (unlikely(offs < -0x80000000LL) || unlikely(offs >= 0x80000000LL))
				return false;
			mc8 |= ((uint64_t)offs & 0xfffff000ULL);
			memcpy(ctx->mcode + reloc->position, &mc8, 8);
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	if (unlikely(insn_writes_flags(insn)))
		goto invalid_insn;
	/*debug("insn: %08x", (unsigned)insn);*/
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			cgen_rv(RISCV_JALR | ((uint32_t)R_RA << 15));
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_jmp_call_indirect(ctx, true));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn)));
			return true;
		case INSN_MOVSX:
			g(cgen_movsx(ctx, insn_op_size(insn)));
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
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_btx(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_CMP_DEST_REG:
			g(cgen_fp_cmp_dest_reg(ctx, insn_op_size(insn), insn_aux(insn)));
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
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_jmp_reg(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_2REGS:
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
				goto invalid_insn;
			g(cgen_jmp_2regs(ctx, insn_aux(insn), insn_jump_size(insn)));
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
