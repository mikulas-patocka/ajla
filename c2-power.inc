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

#define		POWER_RC		0x00000001U
#define		POWER_OE		0x00000400U
#define		POWER_CMP_L		0x00200000U

#define POWER_MULLI		0x1c000000U
#define POWER_SUBFIC		0x20000000U
#define POWER_CMPLI		0x28000000U
#define POWER_CMPI		0x2c000000U
#define POWER_ADDIC		0x30000000U
#define POWER_ADDIC_		0x34000000U
#define POWER_ADDI		0x38000000U
#define POWER_ADDIS		0x3c000000U
#define POWER_BGE		0x40800000U
#define POWER_BLE		0x40810000U
#define POWER_BNE		0x40820000U
#define POWER_BNS		0x40830000U
#define POWER_BLT		0x41800000U
#define POWER_BGT		0x41810000U
#define POWER_BEQ		0x41820000U
#define POWER_BSO		0x41830000U
#define POWER_B			0x48000000U
#define POWER_BLR		0x4e800020U
#define POWER_BCTR		0x4e800420U
#define POWER_BCTRL		0x4e800421U
#define POWER_RLWINM		0x54000000U
#define POWER_RLWNM		0x5c000000U
#define POWER_ORI		0x60000000U
#define POWER_ORIS		0x64000000U
#define POWER_XORI		0x68000000U
#define POWER_XORIS		0x6c000000U
#define POWER_ANDI_		0x70000000U
#define POWER_ANDIS_		0x74000000U
#define POWER_RLDICL		0x78000000U
#define POWER_RLDICR		0x78000004U
#define POWER_RLDCL		0x78000010U
#define POWER_RLDCR		0x78000012U
#define POWER_CMP		0x7c000000U
#define POWER_SUBFC		0x7c000010U
#define POWER_ADDC		0x7c000014U
#define POWER_ISELLT		0x7c00001eU
#define POWER_LDX		0x7c00002aU
#define POWER_LWZX		0x7c00002eU
#define POWER_SLW		0x7c000030U
#define POWER_CNTLZW		0x7c000034U
#define POWER_SLD		0x7c000036U
#define POWER_AND		0x7c000038U
#define POWER_CMPL		0x7c000040U
#define POWER_SUBF		0x7c000050U
#define POWER_ISELGT		0x7c00005eU
#define POWER_CNTLZD		0x7c000074U
#define POWER_ANDC		0x7c000078U
#define POWER_ISELEQ		0x7c00009eU
#define POWER_LBZX		0x7c0000aeU
#define POWER_NEG		0x7c0000d0U
#define POWER_ISELSO		0x7c0000deU
#define POWER_NOR		0x7c0000f8U
#define POWER_SUBFE		0x7c000110U
#define POWER_ADDE		0x7c000114U
#define POWER_STDX		0x7c00012aU
#define POWER_STWX		0x7c00012eU
#define POWER_SUBFZE		0x7c000190U
#define POWER_ADDZE		0x7c000194U
#define POWER_STBX		0x7c0001aeU
#define POWER_MULLD		0x7c0001d2U
#define POWER_ADDME		0x7c0001d4U
#define POWER_MULLW		0x7c0001d6U
#define POWER_MODUD		0x7c000212U
#define POWER_MODUW		0x7c000216U
#define POWER_ADD		0x7c000214U
#define POWER_LXVX		0x7c000218U
#define POWER_LHZX		0x7c00022eU
#define POWER_EQV		0x7c000238U
#define POWER_XOR		0x7c000278U
#define POWER_LWAX		0x7c0002aaU
#define POWER_LHAX		0x7c0002aeU
#define POWER_POPCNTW		0x7c0002f4U
#define POWER_STXVX		0x7c000318U
#define POWER_STHX		0x7c00032eU
#define POWER_ORC		0x7c000338U
#define POWER_OR		0x7c000378U
#define POWER_DIVDU		0x7c000392U
#define POWER_DIVWU		0x7c000396U
#define POWER_NAND		0x7c0003b8U
#define POWER_DIVD		0x7c0003d2U
#define POWER_DIVW		0x7c0003d6U
#define POWER_POPCNTD		0x7c0003f4U
#define POWER_LFSX		0x7c00042eU
#define POWER_SRW		0x7c000430U
#define POWER_CNTTZW		0x7c000434U
#define POWER_SRD		0x7c000436U
#define POWER_CNTTZD		0x7c000474U
#define POWER_LXSDX		0x7c000498U
#define POWER_LFDX		0x7c0004aeU
#define POWER_STFSX		0x7c00052eU
#define POWER_STXSDX		0x7c000598U
#define POWER_STFDX		0x7c0005aeU
#define POWER_MODSD		0x7c000612U
#define POWER_MODSW		0x7c000616U
#define POWER_SRAW		0x7c000630U
#define POWER_SRAD		0x7c000634U
#define POWER_SRAWI		0x7c000670U
#define POWER_SRADI		0x7c000674U
#define POWER_EXTSH		0x7c000734U
#define POWER_EXTSB		0x7c000774U
#define POWER_EXTSW		0x7c0007b4U
#define POWER_MFXER		0x7c0102a6U
#define POWER_MTXER		0x7c0103a6U
#define POWER_MFLR		0x7c0802a6U
#define POWER_MTLR		0x7c0803a6U
#define POWER_MFCTR		0x7c0902a6U
#define POWER_MTCTR		0x7c0903a6U
#define POWER_LWZ		0x80000000U
#define POWER_LBZ		0x88000000U
#define POWER_STW		0x90000000U
#define POWER_STWU		0x94000000U
#define POWER_STB		0x98000000U
#define POWER_STBU		0x9c000000U
#define POWER_LHZ		0xa0000000U
#define POWER_LHA		0xa8000000U
#define POWER_STH		0xb0000000U
#define POWER_STHU		0xb4000000U
#define POWER_LFS		0xc0000000U
#define POWER_STFS		0xd0000000U
#define POWER_LFD		0xc8000000U
#define POWER_STFD		0xd8000000U
#define POWER_LQ		0xe0000000U
#define POWER_LXSD		0xe4000002U
#define POWER_LD		0xe8000000U
#define POWER_LWA		0xe8000002U
#define POWER_FDIVS		0xec000024U
#define POWER_FSUBS		0xec000028U
#define POWER_FADDS		0xec00002aU
#define POWER_FSQRTS		0xec00002cU
#define POWER_FMULS		0xec000032U
#define POWER_FCFIDS		0xec00069cU
#define POWER_XXLOR		0xf0000497U
#define POWER_LXV		0xf4000001U
#define POWER_STXSD		0xf4000002U
#define POWER_STXV		0xf4000005U
#define POWER_STD		0xf8000000U
#define POWER_STDU		0xf8000001U
#define POWER_STQ		0xf8000002U
#define POWER_FCMPU		0xfc000000U
#define POWER_XSADDQP		0xfc000008U
#define POWER_FDIV		0xfc000024U
#define POWER_FSUB		0xfc000028U
#define POWER_FADD		0xfc00002aU
#define POWER_FSQRT		0xfc00002cU
#define POWER_FMUL		0xfc000032U
#define POWER_FCMPO		0xfc000040U
#define POWER_XSMULQP		0xfc000048U
#define POWER_FNEG		0xfc000050U
#define POWER_FMR		0xfc000090U
#define POWER_XSCMPOQP		0xfc000108U
#define POWER_XSSUBQP		0xfc000408U
#define POWER_XSDIVQP		0xfc000448U
#define POWER_XSCMPUQP		0xfc000508U
#define POWER_FCTIDZ		0xfc00065eU
#define POWER_FCFID		0xfc00069cU
#define POWER_XSCVSDQP		0xfc0a0688U
#define POWER_XSNEGQP		0xfc100648U
#define POWER_XSCVQPSDZ		0xfc190688U


#define cgen_xform(mc, rt, ra, rb, flags) \
	cgen_four((mc) | ((uint32_t)(rt) << 21) | ((uint32_t)((ra) << 16)) | ((uint32_t)(rb) << 11) | (((uint32_t)(flags) & 1) * POWER_RC))

#define cgen_dform(mc, rt, ra, imm) \
	cgen_four((mc) | ((uint32_t)(rt) << 21) | ((uint32_t)((ra) << 16)) | (uint16_t)(imm))

static const uint32_t load_a1[8] = { POWER_LBZ, POWER_LHZ, POWER_LWZ, POWER_LD, 0, POWER_LHA, POWER_LWA, 0 };
static const uint32_t load_a2[8] = { POWER_LBZX, POWER_LHZX, POWER_LWZX, POWER_LDX, 0, POWER_LHAX, POWER_LWAX, 0 };

static const uint32_t store_a1[4] = { POWER_STB, POWER_STH, POWER_STW, POWER_STD };
static const uint32_t store_a1u[4] = { POWER_STBU, POWER_STHU, POWER_STWU, POWER_STDU };
static const uint32_t store_a2[4] = { POWER_STBX, POWER_STHX, POWER_STWX, POWER_STDX };

static const uint32_t alu_imm[0x22] = {
	POWER_ADDI, POWER_ADDIS,
	POWER_ORI, POWER_ORIS,
	0, 0,
	0, 0,
	POWER_ANDI_, POWER_ANDIS_,
	0, 0,
	POWER_XORI, POWER_XORIS,
	0, 0,

	0, 0,
	0, 0,
	0, 0,
	0, 0,
	0, 0,
	0, 0,
	0, 0,
	0, 0,

	POWER_MULLI, 0,
};

static const uint32_t alu_reg[0x45] = {
	POWER_ADD, POWER_ADD, 1,
	POWER_OR, POWER_OR, 0,
	POWER_ADDE, POWER_ADDE, 1,
	POWER_SUBFE, POWER_SUBFE, 3,
	POWER_AND, POWER_AND, 0,
	POWER_SUBF, POWER_SUBF, 3,
	POWER_XOR, POWER_XOR, 0,
	0, 0, 0,

	POWER_ORC, POWER_ORC, 0,
	POWER_ANDC, POWER_ANDC, 0,
	POWER_EQV, POWER_EQV, 0,
	0, 0, 0,
	0, 0, 0,
	0, 0, 0,
	0, 0, 0,
	0, 0, 0,

	POWER_MULLW, POWER_MULLD, 1,
	0, 0, 0,
	0, 0, 0,
	POWER_DIVWU, POWER_DIVDU, 1,
	POWER_DIVW, POWER_DIVD, 1,
	POWER_MODUW, POWER_MODUD, 1,
	POWER_MODSW, POWER_MODSD, 1,
};

static const uint32_t jmp_cond[0x2c] = {
	POWER_BSO, POWER_BNS, 0, 0,
	POWER_BEQ, POWER_BNE, 0, 0,
	POWER_BLT, POWER_BGE, 0, 0,
	POWER_BLT, POWER_BGE, POWER_BLE, POWER_BGT,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,

	0, 0, POWER_BLT, POWER_BGE,
	POWER_BEQ, POWER_BNE, POWER_BLE, POWER_BGT,
	0, 0, POWER_BSO, POWER_BNS,
};

static const uint32_t jmp_cond_logical[0x8] = {
	0, 0, POWER_BLT, POWER_BGE,
	POWER_BEQ, POWER_BNE, POWER_BLE, POWER_BGT,
};

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size, bool sx)
{
	uint32_t mc;
	int64_t imm;
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (size >= OP_SIZE_NATIVE)
		sx = false;
	if (arg1[0] < 32) {
		if (arg2[0] < 32) {
			if (unlikely(size == OP_SIZE_NATIVE)) {
				cgen_xform(POWER_OR, arg2[0], arg1[0], arg2[0], false);
				return true;
			}
			if (sx) {
				switch (size) {
					case OP_SIZE_1:	mc = POWER_EXTSB; break;
					case OP_SIZE_2:	mc = POWER_EXTSH; break;
					case OP_SIZE_4:	mc = POWER_EXTSW; break;
					default:	goto invl;
				}
			} else {
				switch (size) {
					case OP_SIZE_1:	mc = POWER_RLWINM | 0x063eU; break;
					case OP_SIZE_2: mc = POWER_RLWINM | 0x043eU; break;
					case OP_SIZE_4:	mc = POWER_RLDICL | 0x0020U; break;
					default:	goto invl;
				}
			}
			cgen_xform(mc, arg2[0], arg1[0], 0, false);
			return true;
		}
		if (arg2[0] == R_CTR) {
			mc = POWER_MFCTR;
			mc |= (uint32_t)arg1[0] << 21;
			cgen_four(mc);
			return true;
		}
		if (arg2[0] == R_LR) {
			mc = POWER_MFLR;
			mc |= (uint32_t)arg1[0] << 21;
			cgen_four(mc);
			return true;
		}
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (imm >= -0x8000 && imm < 0x8000) {
				cgen_dform(POWER_ADDI, arg1[0], 0, imm);
				return true;
			} else {
				if (imm & 0xffffULL)
					internal(file_line, "cgen_mov: invalid imm");
				cgen_dform(POWER_ADDIS, arg1[0], 0, (uint64_t)imm >> 16);
				return true;
			}
		}
		if (arg2[0] == ARG_ADDRESS_1) {
			mc = load_a1[size + (unsigned)sx * 4];
			if (unlikely(!mc))
				goto invl;
			imm = get_imm(&arg2[2]);
			cgen_dform(mc, arg1[0], arg2[1], imm);
			return true;
		}
		if (arg2[0] == ARG_ADDRESS_2) {
			mc = load_a2[size + (unsigned)sx * 4];
			if (unlikely(!mc))
				goto invl;
			imm = get_imm(&arg2[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			cgen_xform(mc, arg1[0], arg2[1], arg2[2], false);
			return true;
		}
	}
	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		if (unlikely(imm != 0))
			goto invl;
		arg2 = &z;
	}
	if (arg1[0] == R_CTR && arg2[0] < 32) {
		mc = POWER_MTCTR;
		mc |= (uint32_t)arg2[0] << 21;
		cgen_four(mc);
		return true;
	}
	if (arg1[0] == R_LR && arg2[0] < 32) {
		mc = POWER_MTLR;
		mc |= (uint32_t)arg2[0] << 21;
		cgen_four(mc);
		return true;
	}
	if (arg2[0] < 32) {
		if (arg1[0] == ARG_ADDRESS_1) {
			mc = store_a1[size];
			imm = get_imm(&arg1[2]);
			cgen_dform(mc, arg2[0], arg1[1], imm);
			return true;
		}
		if (arg1[0] == ARG_ADDRESS_1_PRE_I) {
			mc = store_a1u[size];
			imm = get_imm(&arg1[2]);
			cgen_dform(mc, arg2[0], arg1[1], imm);
			return true;
		}
		if (arg1[0] == ARG_ADDRESS_2) {
			mc = store_a2[size];
			imm = get_imm(&arg1[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			cgen_xform(mc, arg2[0], arg1[1], arg1[2], false);
			return true;
		}
	}
	if (reg_is_fp(arg1[0]) && size == OP_SIZE_16) {
		if (unlikely(arg2[0] == ARG_ADDRESS_1)) {
			imm = get_imm(&arg2[2]);
			mc = POWER_LXV;
			mc |= (arg1[0] & 32) >> 2;
			cgen_dform(mc, arg1[0] & 31, arg2[1], imm);
			return true;
		}
		if (unlikely(arg2[0] == ARG_ADDRESS_2)) {
			imm = get_imm(&arg2[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			mc = POWER_LXVX;
			cgen_xform(mc, arg1[0] & 31, arg2[1], arg2[2], !!(arg1[0] & 32));
			return true;
		}
	}
	if (reg_is_fp(arg2[0]) && size == OP_SIZE_16) {
		if (unlikely(arg1[0] == ARG_ADDRESS_1)) {
			imm = get_imm(&arg1[2]);
			mc = POWER_STXV;
			mc |= (arg2[0] & 32) >> 2;
			cgen_dform(mc, arg2[0] & 31, arg1[1], imm);
			return true;
		}
		if (unlikely(arg1[0] == ARG_ADDRESS_2)) {
			imm = get_imm(&arg1[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			mc = POWER_STXVX;
			cgen_xform(mc, arg2[0] & 31, arg1[1], arg1[2], !!(arg2[0] & 32));
			return true;
		}
	}
	if (reg_is_vs(arg1[0]) && size == OP_SIZE_8) {
		if (unlikely(arg2[0] == ARG_ADDRESS_1)) {
			imm = get_imm(&arg2[2]);
			mc = POWER_LXSD;
			cgen_dform(mc, arg1[0] & 31, arg2[1], imm);
			return true;
		}
		if (unlikely(arg2[0] == ARG_ADDRESS_2)) {
			imm = get_imm(&arg2[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			mc = POWER_LXSDX;
			cgen_xform(mc, arg1[0] & 31, arg2[1], arg2[2], false);
			return true;
		}
	}
	if (reg_is_vs(arg2[0]) && size == OP_SIZE_8) {
		if (unlikely(arg1[0] == ARG_ADDRESS_1)) {
			imm = get_imm(&arg1[2]);
			mc = POWER_STXSD;
			cgen_dform(mc, arg2[0] & 31, arg1[1], imm);
			return true;
		}
		if (unlikely(arg1[0] == ARG_ADDRESS_2)) {
			imm = get_imm(&arg1[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			mc = POWER_STXSDX;
			cgen_xform(mc, arg2[0] & 31, arg1[1], arg1[2], false);
			return true;
		}
	}
	if (reg_is_fp(arg1[0]) && !reg_is_vs(arg1[0])) {
		if (unlikely(arg2[0] == ARG_ADDRESS_1)) {
			imm = get_imm(&arg2[2]);
			mc = size == OP_SIZE_4 ? POWER_LFS : POWER_LFD;
			cgen_dform(mc, arg1[0] & 31, arg2[1], imm);
			return true;
		}
		if (unlikely(arg2[0] == ARG_ADDRESS_2)) {
			imm = get_imm(&arg2[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			mc = size == OP_SIZE_4 ? POWER_LFSX : POWER_LFDX;
			cgen_xform(mc, arg1[0] & 31, arg2[1], arg2[2], false);
			return true;
		}
	}
	if (reg_is_fp(arg2[0]) && !reg_is_vs(arg2[0])) {
		if (unlikely(arg1[0] == ARG_ADDRESS_1)) {
			imm = get_imm(&arg1[2]);
			mc = size == OP_SIZE_4 ? POWER_STFS : POWER_STFD;
			cgen_dform(mc, arg2[0] & 31, arg1[1], imm);
			return true;
		}
		if (unlikely(arg1[0] == ARG_ADDRESS_2)) {
			imm = get_imm(&arg1[3]);
			if (imm)
				internal(file_line, "cgen_mov: imm is not zero");
			mc = size == OP_SIZE_4 ? POWER_STFSX : POWER_STFDX;
			cgen_xform(mc, arg2[0] & 31, arg1[1], arg1[2], false);
			return true;
		}
	}
	if (reg_is_fp(arg1[0]) && !reg_is_vs(arg1[0]) && reg_is_fp(arg2[0]) && !reg_is_vs(arg2[0])) {
		mc = POWER_FMR;
		cgen_xform(mc, arg1[0] & 31, 0, arg2[0] & 31, false);
		return true;
	}
	if (reg_is_vs(arg1[0]) && reg_is_vs(arg2[0])) {
		mc = POWER_XXLOR;
		cgen_xform(mc, arg1[0] & 31, arg2[0] & 31, arg2[0] & 31, false);
		return true;
	}

invl:
	internal(file_line, "cgen_mov: invalid arguments %u, %02x, %02x", size, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_cmp(struct codegen_context *ctx, unsigned size, unsigned writes_flags)
{
	uint32_t mc;
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		mc = writes_flags == 1 ? POWER_CMPI : POWER_CMPLI;
		if (size == OP_SIZE_8)
			mc |= POWER_CMP_L;
		cgen_dform(mc, 0, arg1[0], imm);
		return true;
	} else {
		mc = writes_flags == 1 ? POWER_CMP : POWER_CMPL;
		if (size == OP_SIZE_8)
			mc |= POWER_CMP_L;
		cgen_xform(mc, 0, arg1[0], arg2[0], false);
		return true;
	}

	internal(file_line, "cgen_cmp: invalid arguments %u, %02x, %02x, %u", size, *arg1, *arg2, writes_flags);
	return false;
}

static bool attr_w cgen_test(struct codegen_context *ctx)
{
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		if (imm >= 0 && imm < 0x10000) {
			cgen_dform(POWER_ANDI_, arg1[0], R_CG_SCRATCH, imm);
			return true;
		}
		if (imm & 0xffff)
			goto invl;
		if (likely(imm >= 0LL) && likely(imm < 0x100000000LL)) {
			cgen_dform(POWER_ANDIS_, arg1[0], R_CG_SCRATCH, (uint64_t)imm >> 16);
			return true;
		}
		goto invl;
	} else {
		cgen_xform(POWER_AND, arg1[0], R_CG_SCRATCH, arg2[0], 1);
		return true;
	}

invl:
	internal(file_line, "cgen_test: invalid arguments %02x, %02x", *arg1, *arg2);
	return false;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags)
{
	uint32_t mc;
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32))
		goto invl;

	if (arg3[0] == ARG_IMM) {
		bool shifted = false;
		imm = get_imm(&arg3[1]);
		if (!imm && (alu == ALU_ADC || alu == ALU_SBB)) {
			mc = alu == ALU_ADC ? POWER_ADDZE : POWER_ADDME;
			if (writes_flags & 1) {
				cgen_four(POWER_MFXER | ((uint32_t)R_CG_SCRATCH << 21));
				cgen_dform(POWER_ANDIS_, R_CG_SCRATCH, R_CG_SCRATCH, 0x2004U);
				cgen_four(POWER_MTXER | ((uint32_t)R_CG_SCRATCH << 21));
				mc |= POWER_OE;
			}
			cgen_xform(mc, arg1[0], arg2[0], 0, writes_flags);
			return true;
		}
		if (unlikely(writes_flags != (alu == ALU_AND)))
			goto invl;
		if (alu == ALU_SUB) {
			imm = -(uint64_t)imm;
			alu = ALU_ADD;
		}
		if (alu == ALU_MUL && size == OP_SIZE_8)
			goto invl;
		switch (alu) {
			case ALU_ADD:
			case ALU_MUL:
				if (likely(imm >= -0x8000) && likely(imm < 0x8000))
					break;
				if (imm & 0xffff)
					goto invl;
				if (likely(imm >= -0x80000000LL) && likely(imm < 0x80000000LL)) {
					shifted = true;
					break;
				}
				goto invl;
			case ALU_AND:
			case ALU_OR:
			case ALU_XOR:
				if (likely(imm >= 0) && likely(imm < 0x10000))
					break;
				if (imm & 0xffff)
					goto invl;
				if (likely(imm >= 0LL) && likely(imm < 0x100000000LL)) {
					shifted = true;
					break;
				}
				goto invl;
			default:
				goto invl;
		}
		if (unlikely(alu * 2 + (unsigned)shifted >= n_array_elements(alu_imm)))
			goto invl;
		mc = alu_imm[alu * 2 + (unsigned)shifted];
		if (unlikely(!mc))
			goto invl;
		if (shifted)
			imm = (uint64_t)imm >> 16;
		if (alu == ALU_ADD || alu == ALU_MUL)
			cgen_dform(mc, arg1[0], arg2[0], imm);
		else
			cgen_dform(mc, arg2[0], arg1[0], imm);
		return true;
	}
	if (arg3[0] < 32) {
		int flag;
		if (unlikely(alu * 3 + 2 >= n_array_elements(alu_reg)))
			goto invl;
		mc = alu_reg[alu * 3 + (size == OP_SIZE_8)];
		flag = alu_reg[alu * 3 + 2];
		if (unlikely(!mc))
			goto invl;
		if (writes_flags & 2) {
			switch (alu) {
				case ALU_ADD:	mc = POWER_ADDC; break;
				case ALU_SUB:	mc = POWER_SUBFC; break;
				case ALU_ADC:
				case ALU_SBB:	break;
				default:	goto invl;
			}
		}
		if (flag & 1 && writes_flags & 1) {
			if (alu == ALU_ADC || alu == ALU_SBB) {
				cgen_four(POWER_MFXER | ((uint32_t)R_CG_SCRATCH << 21));
				cgen_dform(POWER_ANDIS_, R_CG_SCRATCH, R_CG_SCRATCH, 0x2004U);
				cgen_four(POWER_MTXER | ((uint32_t)R_CG_SCRATCH << 21));
			} else {
				cgen_four(POWER_MTXER | ((uint32_t)R_ZERO << 21));
			}
			mc |= POWER_OE;
		}
		if (flag & 2) {
			uint8_t *t = arg2;
			arg2 = arg3;
			arg3 = t;
		}
		if (flag & 1)
			cgen_xform(mc, arg1[0], arg2[0], arg3[0], writes_flags);
		else
			cgen_xform(mc, arg2[0], arg1[0], arg3[0], writes_flags);
		return true;
	}

invl:
	internal(file_line, "cgen_alu: invalid arguments %u, %u, %02x, %02x, %02x, %u", size, alu, *arg1, *arg2, *arg3, writes_flags);
	return false;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (unlikely(arg1[0] >= 32) || unlikely(arg2[0] >= 32))
		goto invl;

	switch (alu) {
		case ALU1_NOT:
			cgen_xform(POWER_NOR, arg2[0], arg1[0], arg2[0], writes_flags);
			return true;
		case ALU1_NEG:
			if (writes_flags & 2)
				cgen_dform(POWER_SUBFIC, arg1[0], arg2[0], 0);
			else
				cgen_xform(POWER_NEG, arg1[0], arg2[0], 0, writes_flags);
			return true;
		case ALU1_NGC:
			mc = POWER_SUBFZE;
			if (writes_flags & 1) {
				cgen_four(POWER_MFXER | ((uint32_t)R_CG_SCRATCH << 21));
				cgen_dform(POWER_ANDIS_, R_CG_SCRATCH, R_CG_SCRATCH, 0x2004U);
				cgen_four(POWER_MTXER | ((uint32_t)R_CG_SCRATCH << 21));
				mc |= POWER_OE;
			}
			cgen_xform(mc, arg1[0], arg2[0], 0, writes_flags);
			return true;
		case ALU1_BSF:
			cgen_xform(size == OP_SIZE_4 ? POWER_CNTTZW : POWER_CNTTZD, arg2[0], arg1[0], 0, writes_flags);
			return true;
		case ALU1_LZCNT:
			cgen_xform(size == OP_SIZE_4 ? POWER_CNTLZW : POWER_CNTLZD, arg2[0], arg1[0], 0, writes_flags);
			return true;
		case ALU1_POPCNT:
			if (unlikely(writes_flags))
				goto invl;
			cgen_xform(size == OP_SIZE_4 ? POWER_POPCNTW : POWER_POPCNTD, arg2[0], arg1[0], 0, 0);
			return true;
		default:
			goto invl;
	}

invl:
	internal(file_line, "cgen_alu1: invalid arguments %u, %u, %02x, %02x, %u", size, alu, *arg1, *arg2, writes_flags);
	return false;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags)
{
	uint32_t mc;
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(size < OP_SIZE_4))
		goto invl;

	if (arg3[0] < 32) {
		switch (alu) {
			case ROT_ROL: mc = size == OP_SIZE_4 ? POWER_RLWNM | (31 << 1) : POWER_RLDCL; break;
			case ROT_SHL: mc = size == OP_SIZE_4 ? POWER_SLW : POWER_SLD; break;
			case ROT_SHR: mc = size == OP_SIZE_4 ? POWER_SRW : POWER_SRD; break;
			case ROT_SAR: mc = size == OP_SIZE_4 ? POWER_SRAW : POWER_SRAD; break;
			default: goto invl;
		}
		cgen_xform(mc, arg2[0], arg1[0], arg3[0], writes_flags);
		return true;
	} else if (arg3[0] == ARG_IMM) {
		uint32_t i32;
		imm = get_imm(&arg3[1]);
		i32 = (uint32_t)imm;
		if (size == OP_SIZE_4) {
			switch (alu) {
				case ROT_ROL:
					mc = POWER_RLWINM | (i32 << 11) | 0x3e;
					break;
				case ROT_SHL:
					mc = POWER_RLWINM | (i32 << 11) | ((31 - i32) << 1);
					break;
				case ROT_SHR:
					mc = POWER_RLWINM | ((-i32 << 11) & 0xf800U) | (i32 << 6) | 0x3eU;
					break;
				case ROT_SAR:
					mc = POWER_SRAWI | (i32 << 11);
					break;
				default:
					goto invl;
			}
		} else {
			switch (alu) {
				case ROT_ROL:
					mc = POWER_RLDICL;
					mc |= (i32 & 0x1f) << 11;
					mc |= (i32 & 0x20) >> 4;
					break;
				case ROT_SHL:
					mc = POWER_RLDICR;
					mc |= (i32 << 11) & 0xf800U;
					mc |= (i32 >> 4) & 0x2U;
					mc |= ((63 - i32) << 6) & 0x07c0U;
					mc |= (63 - i32) & 0x0020U;
					break;
				case ROT_SHR:
					mc = POWER_RLDICL;
					mc |= (-i32 << 11) & 0xf800U;
					mc |= (-i32 >> 4) & 0x2U;
					mc |= (i32 << 6) & 0x07c0U;
					mc |= i32 & 0x0020U;
					break;
				case ROT_SAR:
					mc = POWER_SRADI;
					mc |= (i32 << 11) & 0xf800U;
					mc |= (i32 >> 4) & 0x2U;
					break;
				default:
					goto invl;
			}
		}
		cgen_xform(mc, arg2[0], arg1[0], 0, writes_flags);
		return true;
	}

invl:
	internal(file_line, "cgen_rot: invalid arguments %u, %u, %02x, %02x, %02x", size, alu, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_cmov(struct codegen_context *ctx, unsigned aux)
{
	bool swap;
	uint32_t mc;
	int64_t imm;
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (arg2[0] == ARG_IMM) {
		imm = get_imm(&arg2[1]);
		if (unlikely(imm != 0))
			goto invl;
		arg2 = &z;
	}
	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (unlikely(imm != 0))
			goto invl;
		arg3 = &z;
	}

	switch (aux) {
		case COND_B:	aux = COND_L; break;
		case COND_BE:	aux = COND_LE; break;
		case COND_A:	aux = COND_G; break;
		case COND_AE:	aux = COND_GE; break;
	}

	switch (aux) {
		case COND_O:	mc = POWER_ISELSO; swap = false; break;
		case COND_E:	mc = POWER_ISELEQ; swap = false; break;
		case COND_L:	mc = POWER_ISELLT; swap = false; break;
		case COND_G:	mc = POWER_ISELGT; swap = false; break;
		case COND_NO:	mc = POWER_ISELSO; swap = true; break;
		case COND_NE:	mc = POWER_ISELEQ; swap = true; break;
		case COND_GE:	mc = POWER_ISELLT; swap = true; break;
		case COND_LE:	mc = POWER_ISELGT; swap = true; break;
		case FP_COND_P:	mc = POWER_ISELSO; swap = false; break;
		case FP_COND_E:	mc = POWER_ISELEQ; swap = false; break;
		case FP_COND_B:	mc = POWER_ISELLT; swap = false; break;
		case FP_COND_A:	mc = POWER_ISELGT; swap = false; break;
		case FP_COND_NP:mc = POWER_ISELSO; swap = true; break;
		case FP_COND_NE:mc = POWER_ISELEQ; swap = true; break;
		case FP_COND_AE:mc = POWER_ISELLT; swap = true; break;
		case FP_COND_BE:mc = POWER_ISELGT; swap = true; break;
		default:	goto invl;
	}

	if (swap) {
		uint8_t *t = arg2;
		arg2 = arg3;
		arg3 = t;
	}

	cgen_xform(mc, arg1[0], arg3[0], arg2[0], false);
	return true;

invl:
	internal(file_line, "cgen_cmov: invalid arguments %u, %02x, %02x, %02x", aux, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_ldp_stp(struct codegen_context *ctx, bool ldr)
{
	uint8_t *arg1, *arg2, *arg3;
	uint32_t mc;
	int64_t imm;
	if (!ldr) {
		arg1 = ctx->code_position;
		arg2 = arg1 + arg_size(*arg1);
		arg3 = arg2 + arg_size(*arg2);
		ctx->code_position = arg3 + arg_size(*arg3);
		mc = POWER_STQ;
	} else {
		arg2 = ctx->code_position;
		arg3 = arg2 + arg_size(*arg2);
		arg1 = arg3 + arg_size(*arg3);
		ctx->code_position = arg1 + arg_size(*arg1);
		mc = POWER_LQ;
	}
	if (unlikely(arg2[0] >= 32) || unlikely(arg3[0] >= 32))
		goto invalid;
	if (unlikely((arg3[0] & 1) != 0) || unlikely(arg2[0] != arg3[0] + 1))
		goto invalid;
	imm = get_imm(&arg1[2]);
	cgen_dform(mc, arg3[0], arg1[1], imm & 0xfff0);
	return true;
invalid:
	internal(file_line, "cgen_ldp_stp: invalid arguments %02x, %02x, %02x", arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_fp_cmp(struct codegen_context *ctx, unsigned attr_unused op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = op_size != OP_SIZE_16 ? POWER_FCMPU : POWER_XSCMPUQP;
	cgen_xform(mc, 0, arg1[0] & 31, arg2[0] & 31, false);
	return true;
}

static bool attr_w cgen_fp_alu(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	bool use_s = op_size == OP_SIZE_4;
	bool use_vs = op_size == OP_SIZE_16;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (aux) {
		case FP_ALU_ADD:	mc = use_vs ? POWER_XSADDQP : use_s ? POWER_FADDS : POWER_FADD; break;
		case FP_ALU_SUB:	mc = use_vs ? POWER_XSSUBQP : use_s ? POWER_FSUBS : POWER_FSUB; break;
		case FP_ALU_MUL:	mc = use_vs ? POWER_XSMULQP : use_s ? POWER_FMULS : POWER_FMUL; break;
		case FP_ALU_DIV:	mc = use_vs ? POWER_XSDIVQP : use_s ? POWER_FDIVS : POWER_FDIV; break;
		default:		goto invl;
	}
	if (aux == FP_ALU_MUL && !use_vs)
		cgen_xform(mc | ((arg3[0] & 31) << 6), arg1[0] & 31, arg2[0] & 31, 0, false);
	else
		cgen_xform(mc, arg1[0] & 31, arg2[0] & 31, arg3[0] & 31, false);
	return true;
invl:
	internal(file_line, "cgen_fp_alu: invalid arguments %u, %u, %02x, %02x, %02x", op_size, aux, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	bool use_s = op_size == OP_SIZE_4 && cpu_test_feature(CPU_FEATURE_ppc);
	bool use_vs = op_size == OP_SIZE_16;
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:	mc = use_vs ? POWER_XSNEGQP : POWER_FNEG;
					break;
		case FP_ALU1_SQRT:	if (unlikely(use_vs))
						goto invl;
					mc = use_s ? POWER_FSQRTS : POWER_FSQRT; break;
		default:		goto invl;
	}
	cgen_xform(mc, arg1[0] & 31, 0, arg2[0] & 31, false);
	return true;
invl:
	internal(file_line, "cgen_fp_alu1: invalid arguments %u, %u, %02x, %02x", op_size, aux, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = fp_op_size <= OP_SIZE_8 ? POWER_FCTIDZ : POWER_XSCVQPSDZ;
	cgen_xform(mc, arg1[0] & 31, 0, arg2[0] & 31, false);
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned fp_op_size)
{
	uint32_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	mc = fp_op_size == OP_SIZE_4 ? POWER_FCFIDS : fp_op_size == OP_SIZE_8 ? POWER_FCFID : POWER_XSCVSDQP;
	cgen_xform(mc, arg1[0] & 31, 0, arg2[0] & 31, false);
	return true;
}

static bool attr_w cgen_jmp_cond(struct codegen_context *ctx, bool lng, unsigned aux, bool logical)
{
	uint32_t mc;
	if (!lng) {
		g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
	} else {
		aux ^= 1;
	}
	if (!logical) {
		if (unlikely(aux >= n_array_elements(jmp_cond)))
			goto invl;
		mc = jmp_cond[aux];
	} else {
		if (unlikely(aux >= n_array_elements(jmp_cond_logical)))
			goto invl;
		mc = jmp_cond_logical[aux];
	}
	if (unlikely(!mc))
		goto invl;

	if (!lng) {
		cgen_four(mc);
	} else {
		cgen_four(mc | 0x8);
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
		cgen_four(POWER_B);
	}

	return true;

invl:
	internal(file_line, "cgen_jmp_cond: invalid %scondition %x", logical ? "logical " : "", aux);
	return false;
}

static bool attr_w cgen_jmp_indirect(struct codegen_context *ctx)
{
	uint32_t mc;
	unsigned reg = cget_one(ctx);

	mc = POWER_MTCTR;
	mc |= (uint32_t)reg << 21;
	cgen_four(mc);

	mc = POWER_BCTR;
	cgen_four(mc);

	return true;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint32_t mc;
	int64_t offs = (int64_t)ctx->label_to_pos[reloc->label_id] - (int64_t)reloc->position;
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x8000) || unlikely(offs >= 0x8000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0xffff0003U;
			mc |= offs & 0xfffcU;
			memcpy(ctx->mcode + reloc->position, &mc, 4);
			return true;
		case JMP_SHORT:
			if (unlikely(offs < -0x01000000) || unlikely(offs >= 0x01000000))
				return false;
			memcpy(&mc, ctx->mcode + reloc->position, 4);
			mc &= 0xfc000003U;
			mc |= offs & 0x3fffffcU;
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
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			cgen_four(POWER_BLR);
			return true;
		case INSN_CALL_INDIRECT:
			reg = cget_one(ctx);
			if (unlikely(reg != R_CTR))
				goto invalid_insn;
			cgen_four(POWER_BCTRL);
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn), false));
			return true;
		case INSN_MOVSX:
			g(cgen_mov(ctx, insn_op_size(insn), true));
			return true;
		case INSN_CMP:
			g(cgen_cmp(ctx, insn_op_size(insn), insn_writes_flags(insn)));
			return true;
		case INSN_TEST:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_test(ctx));
			return true;
		case INSN_ALU:
		case INSN_ALU_FLAGS:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE) && !((insn_aux(insn) >= ALU_UDIV && insn_aux(insn) <= ALU_SREM) || insn_aux(insn) == ALU_MUL))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU1:
		case INSN_ALU1_FLAGS:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ROT:
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_CMOV:
		case INSN_CMOV_XCC:
			if (unlikely(!cpu_test_feature(CPU_FEATURE_v203)))
				goto invalid_insn;
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_cmov(ctx, insn_aux(insn)));
			return true;
		case INSN_STP:
		case INSN_LDP:
			if (unlikely(insn_op_size(insn) != OP_SIZE_8))
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
			g(cgen_fp_to_int(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_FROM_INT64:
			g(cgen_fp_from_int(ctx, insn_op_size(insn)));
			return true;
		case INSN_JMP:
			g(add_relocation(ctx, JMP_SHORT, 0, NULL));
			cgen_four(POWER_B);
			return true;
		case INSN_JMP_COND:
			g(cgen_jmp_cond(ctx, insn_jump_size(insn) == JMP_SHORT, insn_aux(insn), false));
			return true;
		case INSN_JMP_COND_LOGICAL:
			g(cgen_jmp_cond(ctx, insn_jump_size(insn) == JMP_SHORT, insn_aux(insn), true));
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
