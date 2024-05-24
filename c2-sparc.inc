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

#define SPARC_IMM_BIT		0x00002000U
#define SPARC_CC_BIT		0x00800000U

#define SPARC_BPCC		0x00400000U
#define  SPARC_BPCC_P			0x00080000U
#define  SPARC_BPCC_64			0x00200000U
#define  SPARC_BPCC_A			0x20000000U
#define SPARC_BCC		0x00800000U
#define  SPARC_BCC_A			0x20000000U
#define SPARC_BR		0x00c00000U
#define  SPARC_BR_BRZ			0x02000000U
#define  SPARC_BR_BRLEZ			0x04000000U
#define  SPARC_BR_BRLZ			0x06000000U
#define  SPARC_BR_BRNZ			0x0a000000U
#define  SPARC_BR_GZ			0x0c000000U
#define  SPARC_BR_GEZ			0x0e000000U
#define  SPARC_BR_A			0x20000000U
#define SPARC_NOP		0x01000000U
#define SPARC_SETHI		0x01000000U
#define SPARC_FBPCC		0x01400000U
#define  SPARC_FBPCC_P			0x00080000U
#define  SPARC_FBPCC_CC0		0x00100000U
#define  SPARC_FBPCC_CC1		0x00200000U
#define  SPARC_FBPCC_A			0x20000000U
#define SPARC_FBCC		0x01800000U
#define  SPARC_FBCC_A			0x20000000U

#define SPARC_ADD		0x80000000U
#define SPARC_AND		0x80080000U
#define SPARC_OR		0x80100000U
#define SPARC_XOR		0x80180000U
#define SPARC_SUB		0x80200000U
#define SPARC_ANDN		0x80280000U
#define SPARC_ORN		0x80300000U
#define SPARC_XORN		0x80380000U
#define SPARC_ADDC		0x80400000U
#define SPARC_MULX		0x80480000U
#define SPARC_SUBC		0x80600000U
#define SPARC_UDIVX		0x80680000U
#define SPARC_SLL		0x81280000U
#define SPARC_SRL		0x81300000U
#define SPARC_SRA		0x81380000U
#define  SPARC_S_64			0x00001000U
#define SPARC_CMOV		0x81600000U
#define  SPARC_CMOV_FCC0		0x00000000U
#define  SPARC_CMOV_FCC1		0x00000800U
#define  SPARC_CMOV_FCC2		0x00001000U
#define  SPARC_CMOV_FCC3		0x00001800U
#define  SPARC_CMOV_ICC			0x00040000U
#define  SPARC_CMOV_XCC			0x00041000U
#define SPARC_SDIVX		0x81680000U
#define SPARC_POPC		0x81700000U
#define SPARC_MOVR		0x81780000U
#define  SPARC_MOVR_Z			0x00000400U
#define  SPARC_MOVR_LEZ			0x00000800U
#define  SPARC_MOVR_LZ			0x00000c00U
#define  SPARC_MOVR_NZ			0x00001400U
#define  SPARC_MOVR_GZ			0x00001800U
#define  SPARC_MOVR_GEZ			0x00001c00U
#define SPARC_FNEG		0x81a00080U
#define SPARC_FSQRT		0x81a00500U
#define SPARC_FADD		0x81a00800U
#define SPARC_FSUB		0x81a00880U
#define SPARC_FMUL		0x81a00900U
#define SPARC_FDIV		0x81a00980U
#define  SPARC_FP_SINGLE		0x00000020U
#define  SPARC_FP_DOUBLE		0x00000040U
#define  SPARC_FP_QUAD			0x00000060U
#define SPARC_FTOI		0x81a01000U
#define  SPARC_FTOI_32			0x00000a00U
#define  SPARC_FTOI_64			0x00000000U
#define  SPARC_FTOI_SINGLE		0x00000020U
#define  SPARC_FTOI_DOUBLE		0x00000040U
#define  SPARC_FTOI_QUAD		0x00000060U
#define SPARC_ITOF		0x81a01000U
#define  SPARC_ITOF_64			0x00000000U
#define  SPARC_ITOF_32			0x00000800U
#define  SPARC_ITOF_SINGLE		0x00000080U
#define  SPARC_ITOF_DOUBLE		0x00000100U
#define  SPARC_ITOF_QUAD		0x00000180U
#define SPARC_FCMP		0x81a80a00U
#define  SPARC_FCMP_CC0			0x02000000U
#define  SPARC_FCMP_CC1			0x04000000U
#define  SPARC_FCMP_SINGLE		0x00000020U
#define  SPARC_FCMP_DOUBLE		0x00000040U
#define  SPARC_FCMP_QUAD		0x00000060U
#define SPARC_JMPL		0x81c00000U
#define SPARC_RETURN		0x81c80000U
#define SPARC_SAVE		0x81e00000U
#define SPARC_RESTORE		0x81e80000U

#define SPARC_LDUW		0xc0000000U
#define SPARC_LDUB		0xc0080000U
#define SPARC_LDUH		0xc0100000U
#define SPARC_LDD		0xc0180000U
#define SPARC_STW		0xc0200000U
#define SPARC_STB		0xc0280000U
#define SPARC_STH		0xc0300000U
#define SPARC_STD		0xc0380000U
#define SPARC_LDSW		0xc0400000U
#define SPARC_LDSB		0xc0480000U
#define SPARC_LDSH		0xc0500000U
#define SPARC_LDX		0xc0580000U
#define SPARC_STX		0xc0700000U
#define SPARC_LDF		0xc1000000U
#define SPARC_STF		0xc1200000U
#define  SPARC_LDSTF_SINGLE		0x00000000U
#define  SPARC_LDSTF_DOUBLE		0x00180000U
#define  SPARC_LDSTF_QUAD		0x00100000U


static const int8_t jmp_cond[48] = {
	0x7, 0xf, 0x5, 0xd, 0x1, 0x9, 0x4, 0xc,
	0x6, 0xe,  -1,  -1, 0x3, 0xb, 0x2, 0xa,
	 -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	 -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	 -1,  -1, 0x4, 0xb, 0x9, 0x2, 0xd, 0x6,
	 -1,  -1, 0x7, 0xf,  -1,  -1,  -1,  -1,
};

static const uint32_t alu_map[24] = {
	SPARC_ADD,
	SPARC_OR,
	SPARC_ADDC,
	SPARC_SUBC,
	SPARC_AND,
	SPARC_SUB,
	SPARC_XOR,
	-1U,
	SPARC_ORN,
	SPARC_ANDN,
	SPARC_XORN,
	-1U,
	-1U,
	-1U,
	-1U,
	-1U,
	SPARC_MULX,
	-1U,
	-1U,
	SPARC_UDIVX,
	SPARC_SDIVX,
	-1U,
	-1U,
	SPARC_SAVE,
};

#define cgen_sparc_3reg(mc, rd, rs1, rs2) \
	cgen_four((mc) | ((uint32_t)(rd) << 25) | ((uint32_t)((rs1) << 14)) | (rs2))
#define cgen_sparc_imm(mc, rd, rs1, imm) \
	cgen_four((mc) | SPARC_IMM_BIT | ((uint32_t)(rd) << 25) | ((uint32_t)((rs1) << 14)) | ((imm) & 8191))

static bool attr_w cgen_ld_st(struct codegen_context *ctx, uint32_t mc, uint8_t reg, uint8_t *address)
{
	int64_t imm;
	if (address[0] == ARG_ADDRESS_2) {
		imm = get_imm(&address[3]);
		if (unlikely(imm != 0))
			goto invalid;
		cgen_sparc_3reg(mc, reg, address[1], address[2]);
		return true;
	} else if (address[0] == ARG_ADDRESS_1) {
		imm = get_imm(&address[2]);
		if (unlikely(imm < -4096) || unlikely(imm >= 4096))
			goto invalid;
		cgen_sparc_imm(mc, reg, address[1], imm);
		return true;
	}

	imm = 0;

invalid:
	internal(file_line, "cgen_ld_st: invalid address: %02x, %02x, %"PRIxMAX"", reg, address[0], (uintmax_t)imm);
	return false;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size, bool sx)
{
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] < 32) {
		if (arg2[0] < 32) {
			if (unlikely(size != OP_SIZE_NATIVE))
				internal(file_line, "cgen_mov: unsupported size %u", size);
			cgen_sparc_3reg(SPARC_OR, arg1[0], arg2[0], R_ZERO);
			return true;
		}
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (imm >= -4096 && imm < 4096) {
				cgen_sparc_imm(SPARC_OR, arg1[0], R_ZERO, imm);
			} else {
				if (imm & ~0xfffffc00ULL)
					internal(file_line, "cgen_mov: invalid imm");
				cgen_four(SPARC_SETHI | ((uint32_t)arg1[0] << 25) | imm >> 10);
				return true;
			}
		}
		if (arg2[0] == ARG_ADDRESS_1 || arg2[0] == ARG_ADDRESS_2) {
			if (!sx || size == OP_SIZE_NATIVE) {
				return cgen_ld_st(ctx, size == OP_SIZE_1 ? SPARC_LDUB : size == OP_SIZE_2 ? SPARC_LDUH : size == OP_SIZE_4 ? SPARC_LDUW : SPARC_LDX, arg1[0], arg2);
			} else {
				return cgen_ld_st(ctx, size == OP_SIZE_1 ? SPARC_LDSB : size == OP_SIZE_2 ? SPARC_LDSH : SPARC_LDSW, arg1[0], arg2);
			}
		}
	}
	if (arg1[0] < 64) {
		if (arg2[0] < 64)
			goto invalid;
		return cgen_ld_st(ctx, SPARC_LDF | (size == OP_SIZE_4 ? SPARC_LDSTF_SINGLE : size == OP_SIZE_8 ? SPARC_LDSTF_DOUBLE : SPARC_LDSTF_QUAD), arg1[0] & 31, arg2);
	}
	if (arg2[0] < 32) {
		return cgen_ld_st(ctx, size == OP_SIZE_1 ? SPARC_STB : size == OP_SIZE_2 ? SPARC_STH : size == OP_SIZE_4 ? SPARC_STW : SPARC_STX, arg2[0], arg1);
	}
	if (arg2[0] < 64) {
		return cgen_ld_st(ctx, SPARC_STF | (size == OP_SIZE_4 ? SPARC_LDSTF_SINGLE : size == OP_SIZE_8 ? SPARC_LDSTF_DOUBLE : SPARC_LDSTF_QUAD), arg2[0] & 31, arg1);
	}
	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		if (!imm)
			return cgen_ld_st(ctx, size == OP_SIZE_1 ? SPARC_STB : size == OP_SIZE_2 ? SPARC_STH : size == OP_SIZE_4 ? SPARC_STW : SPARC_STX, R_ZERO, arg1);
	}
invalid:
	internal(file_line, "cgen_mov: invalid arguments %02x, %02x", arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_alu_args(struct codegen_context *ctx, unsigned writes_flags, uint32_t mc, uint8_t *arg1, uint8_t *arg2, uint8_t *arg3)
{
	int64_t imm;

	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32))
		goto invalid;

	if (writes_flags)
		mc |= SPARC_CC_BIT;

	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (unlikely(imm < -4096) || unlikely(imm >= 4096))
			goto invalid;
		cgen_sparc_imm(mc, arg1[0], arg2[0], imm);
		return true;
	} else if (likely(arg3[0] < 32)) {
		cgen_sparc_3reg(mc, arg1[0], arg2[0], arg3[0]);
		return true;
	}

invalid:
	internal(file_line, "cgen_alu_args: invalid arguments %02x, %02x, %02x, %08x, %u", arg1[0], arg2[0], arg3[0], (uint32_t)mc, writes_flags);
	return false;
}

static bool attr_w cgen_cmp(struct codegen_context *ctx, uint32_t mc)
{
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	return cgen_alu_args(ctx, true, mc, &z, arg1, arg2);
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned writes_flags, unsigned alu)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(alu >= 16) && unlikely(writes_flags))
		internal(file_line, "cgen_alu: alu %u can't write flags", alu);

	ajla_assert_lo(alu < n_array_elements(alu_map), (file_line, "cgen_alu: invalid alu %u", alu));
	mc = alu_map[alu];
	if (unlikely(mc == (uint32_t)-1))
		internal(file_line, "cgen_alu: invalid alu %u", alu);

	return cgen_alu_args(ctx, writes_flags, mc, arg1, arg2, arg3);
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned writes_flags, uint8_t alu)
{
	uint8_t z = R_ZERO;
	uint8_t one_imm[9] = { ARG_IMM, 1, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (alu) {
		case ALU1_NOT:
			g(cgen_alu_args(ctx, writes_flags, SPARC_XORN, arg1, arg2, &z));
			return true;
		case ALU1_NEG:
			g(cgen_alu_args(ctx, writes_flags, SPARC_SUB, arg1, &z, arg2));
			return true;
		case ALU1_INC:
			g(cgen_alu_args(ctx, writes_flags, SPARC_ADD, arg1, arg2, one_imm));
			return true;
		case ALU1_DEC:
			g(cgen_alu_args(ctx, writes_flags, SPARC_SUB, arg1, arg2, one_imm));
			return true;
		case ALU1_POPCNT:
			g(cgen_alu_args(ctx, writes_flags, SPARC_POPC, arg1, &z, arg2));
			return true;
		default:
			internal(file_line, "cgen_alu1: invalid operation %u", alu);
			return false;
	}
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, uint8_t rot)
{
	uint32_t mc;
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32) || unlikely(size < OP_SIZE_4) || unlikely(size > OP_SIZE_8))
		goto invalid;

	switch (rot) {
		case ROT_SHL:	mc = SPARC_SLL; break;
		case ROT_SHR:	mc = SPARC_SRL; break;
		case ROT_SAR:	mc = SPARC_SRA; break;
		default:
			goto invalid;
	}

	if (size == OP_SIZE_8)
		mc |= SPARC_S_64;

	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (unlikely(imm < 0) || unlikely(imm >= (size == OP_SIZE_4 ? 32 : 64)))
			goto invalid;
		cgen_sparc_imm(mc, arg1[0], arg2[0], imm);
		return true;
	} else {
		cgen_sparc_3reg(mc, arg1[0], arg2[0], arg3[0]);
		return true;
	}

invalid:
	internal(file_line, "cgen_rot: invalid arguments: %02x, %02x, %02x, %u, %u", arg1[0], arg2[0], arg3[0], size, rot);
	return false;
}

static bool attr_w cgen_cmov(struct codegen_context *ctx, unsigned aux, bool xcc)
{
	int8_t cond;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != arg2[0]))
		internal(file_line, "cgen_cmov: invalid arguments");
	mc = SPARC_CMOV;
	cond = jmp_cond[aux];
	if (unlikely(cond < 0))
		internal(file_line, "cgen_cmov: invalid condition %u", aux);
	if (aux & COND_FP) {
		mc |= SPARC_CMOV_FCC0;
	} else {
		mc |= xcc ? SPARC_CMOV_XCC : SPARC_CMOV_ICC;
	}
	mc |= (uint32_t)arg1[0] << 25;
	mc |= (uint32_t)cond << 14;
	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		mc |= SPARC_IMM_BIT;
		mc |= imm & 0x7FF;
	} else {
		mc |= arg3[0];
	}
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_movr(struct codegen_context *ctx, unsigned aux)
{
	uint32_t mc = SPARC_MOVR;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	switch (aux) {
		case COND_E:	mc |= SPARC_MOVR_Z; break;
		case COND_LE:	mc |= SPARC_MOVR_LEZ; break;
		case COND_L:	mc |= SPARC_MOVR_LZ; break;
		case COND_NE:	mc |= SPARC_MOVR_NZ; break;
		case COND_G:	mc |= SPARC_MOVR_GZ; break;
		case COND_GE:	mc |= SPARC_MOVR_GEZ; break;
		default:	internal(file_line, "cgen_movr: invalid condition %u", aux);
	}
	if (unlikely(arg1[0] != arg2[0]))
		internal(file_line, "cgen_movr: invalid arguments");
	mc |= (uint32_t)arg1[0] << 25;
	mc |= (uint32_t)arg3[0] << 14;
	if (arg4[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg4[1]);
		mc |= SPARC_IMM_BIT;
		mc |= imm & 0x3FF;
	} else {
		mc |= arg4[0];
	}
	cgen_four(mc);
	return true;
}

static bool attr_w cgen_ldp_stp(struct codegen_context *ctx, bool ldr)
{
	uint8_t *arg1, *arg2, *arg3;
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
	if (unlikely(arg2[0] >= 32) || unlikely(arg3[0] >= 32))
		goto invalid;
	if (unlikely((arg3[0] & 1) != 0) || unlikely(arg2[0] != arg3[0] + 1))
		goto invalid;

	if (ldr)
		return cgen_ld_st(ctx, SPARC_LDD, arg3[0], arg1);
	else
		return cgen_ld_st(ctx, SPARC_STD, arg3[0], arg1);

invalid:
	internal(file_line, "cgen_ldp_stp: invalid arguments %02x, %02x, %02x", arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_fp_cmp(struct codegen_context *ctx, unsigned op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = SPARC_FCMP;
	switch (op_size) {
		case OP_SIZE_4:		mc |= SPARC_FCMP_SINGLE; break;
		case OP_SIZE_8:		mc |= SPARC_FCMP_DOUBLE; break;
		case OP_SIZE_16:	mc |= SPARC_FCMP_QUAD; break;
		default:		internal(file_line, "cgen_fp_cmp: invalid size %u", op_size);
	}
	cgen_sparc_3reg(mc, 0, arg1[0] & 31, arg2[0] & 31);
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
		case FP_ALU_ADD:	mc = SPARC_FADD; break;
		case FP_ALU_SUB:	mc = SPARC_FSUB; break;
		case FP_ALU_MUL:	mc = SPARC_FMUL; break;
		case FP_ALU_DIV:	mc = SPARC_FDIV; break;
		default:		internal(file_line, "cgen_fp_alu: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_4:		mc |= SPARC_FP_SINGLE; break;
		case OP_SIZE_8:		mc |= SPARC_FP_DOUBLE; break;
		case OP_SIZE_16:	mc |= SPARC_FP_QUAD; break;
		default:		internal(file_line, "cgen_fp_alu: invalid size %u", op_size);
	}
	cgen_sparc_3reg(mc, arg1[0] & 31, arg2[0] & 31, arg3[0] & 31);
	return true;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	mc = SPARC_FNEG; break;
		case FP_ALU1_SQRT:	mc = SPARC_FSQRT; break;
		default:		internal(file_line, "cgen_fp_alu1: invalid alu %u", aux);
	}
	switch (op_size) {
		case OP_SIZE_4:		mc |= SPARC_FP_SINGLE; break;
		case OP_SIZE_8:		mc |= SPARC_FP_DOUBLE; break;
		case OP_SIZE_16:	mc |= SPARC_FP_QUAD; break;
		default:		internal(file_line, "cgen_fp_alu1: invalid size %u", op_size);
	}
	cgen_sparc_3reg(mc, arg1[0] & 31, 0, arg2[0] & 31);
	return true;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = SPARC_FTOI;
	switch (int_op_size) {
		case OP_SIZE_4:		mc |= SPARC_FTOI_32; break;
		case OP_SIZE_8:		mc |= SPARC_FTOI_64; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid int size %u", int_op_size);
	}
	switch (fp_op_size) {
		case OP_SIZE_4:		mc |= SPARC_FTOI_SINGLE; break;
		case OP_SIZE_8:		mc |= SPARC_FTOI_DOUBLE; break;
		case OP_SIZE_16:	mc |= SPARC_FTOI_QUAD; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid fp size %u", fp_op_size);
	}
	cgen_sparc_3reg(mc, arg1[0] & 31, 0, arg2[0] & 31);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = SPARC_ITOF;
	switch (int_op_size) {
		case OP_SIZE_4:		mc |= SPARC_ITOF_32; break;
		case OP_SIZE_8:		mc |= SPARC_ITOF_64; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid int size %u", int_op_size);
	}
	switch (fp_op_size) {
		case OP_SIZE_4:		mc |= SPARC_ITOF_SINGLE; break;
		case OP_SIZE_8:		mc |= SPARC_ITOF_DOUBLE; break;
		case OP_SIZE_16:	mc |= SPARC_ITOF_QUAD; break;
		default:		internal(file_line, "cgen_fp_to_int: invalid fp size %u", fp_op_size);
	}
	cgen_sparc_3reg(mc, arg1[0] & 31, 0, arg2[0] & 31);
	return true;
}

static bool attr_w cgen_jmp_cond(struct codegen_context *ctx, unsigned size, unsigned aux, unsigned length)
{
	int8_t cond;
	cond = jmp_cond[aux];
	if (unlikely(cond < 0))
		internal(file_line, "cgen_jmp_cond: invalid condition %u", aux);
	if (aux & COND_FP) {
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_four(SPARC_FBCC | ((uint32_t)cond << 25));
	} else if (size == OP_SIZE_4) {
		g(add_relocation(ctx, JMP_LONG, 0, NULL));
		cgen_four(SPARC_BCC | ((uint32_t)cond << 25));
	} else if (size == OP_SIZE_8) {
		if (length <= JMP_SHORT) {
			g(add_relocation(ctx, JMP_SHORT, 0, NULL));
			cgen_four(SPARC_BPCC | SPARC_BPCC_64 | ((uint32_t)cond << 25));
		} else {
			cgen_four(SPARC_BPCC | SPARC_BPCC_64 | ((uint32_t)(cond ^ 0x8) << 25) | 3);
			cgen_four(SPARC_NOP);
			g(add_relocation(ctx, JMP_LONG, 0, NULL));
			cgen_four(SPARC_BCC | SPARC_BCC_A | 0x8 << 25);
		}
	} else {
		internal(file_line, "cgen_jmp_cond: invalid size %u", size);
	}
	cgen_four(SPARC_NOP);
	return true;
}

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned aux, unsigned length)
{
	uint32_t mc = SPARC_BR;
	mc |= (uint32_t)cget_one(ctx) << 14;
	switch (aux) {
		case COND_E:	mc |= SPARC_BR_BRZ; break;
		case COND_LE:	mc |= SPARC_BR_BRLEZ; break;
		case COND_S:
		case COND_L:	mc |= SPARC_BR_BRLZ; break;
		case COND_NE:	mc |= SPARC_BR_BRNZ; break;
		case COND_G:	mc |= SPARC_BR_GZ; break;
		case COND_NS:
		case COND_GE:	mc |= SPARC_BR_GEZ; break;
		default:
			internal(file_line, "cgen_jmp_reg: invalid condition %u", aux);
	}
	switch (length) {
		case JMP_SHORTEST:
			g(add_relocation(ctx, JMP_SHORTEST, 1, NULL));
			cgen_four(mc);
			cgen_four(SPARC_NOP);
			return true;
		case JMP_SHORT:
		case JMP_LONG:
			cgen_four((mc ^ 0x08000000U) | 3);
			cgen_four(SPARC_NOP);
			g(add_relocation(ctx, JMP_LONG, 1, NULL));
			cgen_four(SPARC_BCC | SPARC_BCC_A | 0x8 << 25);
			return true;
		default:
			internal(file_line, "cgen_jmp_reg: invalid length %u", length);
			return false;
	}
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 2) - (int64_t)(reloc->position >> 2);
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x00008000) || unlikely(offs >= 0x00008000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x00303fffU;
			mc |= offs & 0x3fffU;
			mc |= (offs & 0xc000U) << 6;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_SHORT:
			if (unlikely(offs < -0x00040000) || unlikely(offs >= 0x00040000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x0007ffffU;
			mc |= offs & 0x0007ffffU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_LONG:
			if (unlikely(offs < -0x00200000) || unlikely(offs >= 0x00200000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= ~0x003fffffU;
			mc |= offs & 0x003fffffU;
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
	/*debug("insn: %08x", insn);*/
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
			cgen_four(SPARC_RETURN | ((uint32_t)R_I7 << 14) | SPARC_IMM_BIT | 8);
			cgen_four(SPARC_NOP);
			return true;
		case INSN_CALL_INDIRECT:
			reg = cget_one(ctx);
			cgen_sparc_imm(SPARC_JMPL, R_O7, reg, R_ZERO);
			cgen_four(SPARC_NOP);
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
			g(cgen_cmp(ctx, SPARC_SUB));
			return true;
		case INSN_CMN:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_cmp(ctx, SPARC_ADD));
			return true;
		case INSN_TEST:
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_cmp(ctx, SPARC_AND));
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
			if (unlikely(insn_op_size(insn) < OP_SIZE_4))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_CMOV:
			if (unlikely(!SPARC_9))
				goto invalid_insn;
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_cmov(ctx, insn_aux(insn), false));
			return true;
		case INSN_CMOV_XCC:
			if (unlikely(!SPARC_9))
				goto invalid_insn;
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_cmov(ctx, insn_aux(insn), true));
			return true;
		case INSN_MOVR:
			if (unlikely(!SPARC_9))
				goto invalid_insn;
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_movr(ctx, insn_aux(insn)));
			return true;
		case INSN_STP:
		case INSN_LDP:
			if (unlikely(insn_op_size(insn) != OP_SIZE_4))
				goto invalid_insn;
			g(cgen_ldp_stp(ctx, insn_opcode(insn) == INSN_LDP));
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
		case INSN_FP_TO_INT64:
#ifdef ARCH_SPARC32
			goto invalid_insn;
#endif
		case INSN_FP_TO_INT32:
			g(cgen_fp_to_int(ctx, insn_opcode(insn) == INSN_FP_TO_INT32 ? OP_SIZE_4 : OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_FP_FROM_INT64:
#ifdef ARCH_SPARC32
			goto invalid_insn;
#endif
		case INSN_FP_FROM_INT32:
			g(cgen_fp_from_int(ctx, insn_opcode(insn) == INSN_FP_FROM_INT32 ? OP_SIZE_4 : OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_JMP:
			g(add_relocation(ctx, JMP_LONG, 0, NULL));
			cgen_four(SPARC_BCC | SPARC_BCC_A | 0x8 << 25);
			return true;
		case INSN_JMP_COND:
			g(cgen_jmp_cond(ctx, insn_op_size(insn), insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG:
			if (unlikely(!SPARC_9))
				goto invalid_insn;
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_jmp_reg(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			reg = cget_one(ctx);
			cgen_sparc_imm(SPARC_JMPL, R_ZERO, reg, R_ZERO);
			cgen_four(SPARC_NOP);
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
