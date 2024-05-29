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

#define IA64_A_ALU		0x10000000000ULL
#define  IA64_A_ALU_ADD		0x00000000000ULL
#define  IA64_A_ALU_SUB		0x00028000000ULL
#define  IA64_A_ALU_AND		0x00060000000ULL
#define  IA64_A_ALU_ANDCM	0x00068000000ULL
#define  IA64_A_ALU_OR		0x00070000000ULL
#define  IA64_A_ALU_XOR		0x00078000000ULL
#define IA64_A_SHLADD		0x10080000000ULL
#define IA64_A_ADD_IMM14	0x10800000000ULL
#define IA64_A_ALU_IMM8		0x10000000000ULL
#define  IA64_A_ALU_IMM8_SUB	0x00128000000ULL
#define  IA64_A_ALU_IMM8_AND	0x00160000000ULL
#define  IA64_A_ALU_IMM8_ANDCM	0x00168000000ULL
#define  IA64_A_ALU_IMM8_OR	0x00170000000ULL
#define  IA64_A_ALU_IMM8_XOR	0x00178000000ULL
#define IA64_A_ADD_IMM22	0x12000000000ULL
#define IA64_A_CMP_LT		0x18000000000ULL
#define IA64_A_CMP_LT_IMM8	0x18800000000ULL
#define IA64_A_CMP_LTU		0x1a000000000ULL
#define IA64_A_CMP_LTU_IMM8	0x1a800000000ULL
#define IA64_A_CMP_EQ		0x1c000000000ULL
#define IA64_A_CMP_EQ_IMM8	0x1c800000000ULL
#define  IA64_A_CMP4		0x00400000000ULL

#define IA64_I_ZXT1		0x00080000000ULL
#define IA64_I_ZXT2		0x00088000000ULL
#define IA64_I_ZXT4		0x00090000000ULL
#define IA64_I_SXT1		0x000a0000000ULL
#define IA64_I_SXT2		0x000a8000000ULL
#define IA64_I_SXT4		0x000b0000000ULL
#define IA64_I_NOP		0x00008000000ULL
#define IA64_I_MOV_TO_AR	0x00150000000ULL
#define IA64_I_MOV_TO_AR_PFS	0x00004000000ULL
#define IA64_I_MOVE_FROM_BR	0x00188000000ULL
#define IA64_I_MOVE_TO_BR	0x00e00000000ULL
#define IA64_I_DEP		0x08000000000ULL
#define IA64_I_TBIT		0x0a000000000ULL
#define IA64_I_EXTR_U		0x0a400000000ULL
#define IA64_I_EXTR		0x0a400002000ULL
#define IA64_I_DEP_Z		0x0a600000000ULL
#define IA64_I_DEP_Z_IMM	0x0a604000000ULL
#define IA64_I_DEP_IMM		0x0ae00000000ULL
#define IA64_I_POPCNT		0x0e690000000ULL
#define IA64_I_MUX1_REV		0x0eca0b00000ULL
#define IA64_I_SHR_U		0x0f200000000ULL
#define IA64_I_SHR		0x0f220000000ULL
#define IA64_I_SHL		0x0f240000000ULL

#define IA64_M_NOP		0x00008000000ULL
#define IA64_M_ALLOC		0x02c00000000ULL
#define IA64_M_LD1		0x08000000000ULL
#define IA64_M_LD2		0x08040000000ULL
#define IA64_M_LD4		0x08080000000ULL
#define IA64_M_LD8		0x080c0000000ULL
#define IA64_M_GETF_SIG		0x08708000000ULL
#define IA64_M_ST1		0x08c00000000ULL
#define IA64_M_ST2		0x08c40000000ULL
#define IA64_M_ST4		0x08c80000000ULL
#define IA64_M_ST8		0x08cc0000000ULL
#define IA64_M_LDFE		0x0c000000000ULL
#define IA64_M_LDF8		0x0c040000000ULL
#define IA64_M_LDFS		0x0c080000000ULL
#define IA64_M_LDFD		0x0c0c0000000ULL
#define IA64_M_SETF_SIG		0x0c708000000ULL
#define IA64_M_STFE		0x0cc00000000ULL
#define IA64_M_STF8		0x0cc40000000ULL
#define IA64_M_STFS		0x0cc80000000ULL
#define IA64_M_STFD		0x0ccc0000000ULL

#define IA64_B_BR_JMP_INDIRECT	0x00100001000ULL
#define IA64_B_BR_RET		0x00108801100ULL
#define IA64_B_BR_CALL_INDIRECT	0x02100001000ULL
#define IA64_B_NOP		0x04000000000ULL
#define IA64_B_BR21		0x08000001000ULL
#define IA64_BR_DPNT		0x00600000000ULL

#define IA64_F_NOP		0x00008000000ULL
#define IA64_F_FMERGE_S		0x00080000000ULL
#define IA64_F_FMERGE_NS	0x00088000000ULL
#define IA64_F_FMERGE_SE	0x00090000000ULL
#define IA64_F_FCVT_FX_TRUNC	0x000d0000000ULL
#define IA64_F_FCVT_XF		0x000e0000000ULL
#define IA64_F_FCMP		0x08000000000ULL
#define  IA64_F_FCMP_EQ		0x00000000000ULL
#define  IA64_F_FCMP_LE		0x00200000000ULL
#define  IA64_F_FCMP_LT		0x01000000000ULL
#define  IA64_F_FCMP_UNORD	0x01200000000ULL
#define IA64_F_FMA		0x10000000000ULL
#define IA64_F_FMS		0x14000000000ULL
#define IA64_F_FNMA		0x18000000000ULL
#define  IA64_F_FMA_E		0x00000000000ULL
#define  IA64_F_FMA_S		0x01000000000ULL
#define  IA64_F_FMA_D		0x02000000000ULL
#define  IA64_F_FMA_PS		0x03000000000ULL

#define IA64_L_NOP		0x00000000000ULL

#define IA64_X_NOP		0x00008000000ULL
#define IA64_X_BRL		0x18000001000ULL
#define IA64_X_MOVL		0x0c000000000ULL

#define UNIT_ANY		0x0f
#define UNIT_A			0x03
#define UNIT_I			0x01
#define UNIT_M			0x02
#define UNIT_B			0x04
#define UNIT_F			0x08
#define UNIT_L			0x10
#define UNIT_X			0x20

#define STOP_01			0x01000000U
#define STOP_12			0x02000000U
#define STOP_23			0x04000000U

static const uint32_t templates[32] = {
	UNIT_M | UNIT_I << 8 | UNIT_I << 16,
	UNIT_M | UNIT_I << 8 | UNIT_I << 16 | STOP_23,
	UNIT_M | UNIT_I << 8 | UNIT_I << 16 | STOP_12,
	UNIT_M | UNIT_I << 8 | UNIT_I << 16 | STOP_12 | STOP_23,
	UNIT_M | UNIT_L << 8 | UNIT_X << 16,
	UNIT_M | UNIT_L << 8 | UNIT_X << 16 | STOP_23,
	0,
	0,
	UNIT_M | UNIT_M << 8 | UNIT_I << 16,
	UNIT_M | UNIT_M << 8 | UNIT_I << 16 | STOP_23,
	UNIT_M | UNIT_M << 8 | UNIT_I << 16 | STOP_01,
	UNIT_M | UNIT_M << 8 | UNIT_I << 16 | STOP_01 | STOP_23,
	UNIT_M | UNIT_F << 8 | UNIT_I << 16,
	UNIT_M | UNIT_F << 8 | UNIT_I << 16 | STOP_23,
	UNIT_M | UNIT_M << 8 | UNIT_F << 16,
	UNIT_M | UNIT_M << 8 | UNIT_F << 16 | STOP_23,
	UNIT_M | UNIT_I << 8 | UNIT_B << 16,
	UNIT_M | UNIT_I << 8 | UNIT_B << 16 | STOP_23,
	UNIT_M | UNIT_B << 8 | UNIT_B << 16,
	UNIT_M | UNIT_B << 8 | UNIT_B << 16 | STOP_23,
	0,
	0,
	UNIT_B | UNIT_B << 8 | UNIT_B << 16,
	UNIT_B | UNIT_B << 8 | UNIT_B << 16 | STOP_23,
	UNIT_M | UNIT_M << 8 | UNIT_B << 16,
	UNIT_M | UNIT_M << 8 | UNIT_B << 16 | STOP_23,
	0,
	0,
	UNIT_M | UNIT_F << 8 | UNIT_B << 16,
	UNIT_M | UNIT_F << 8 | UNIT_B << 16 | STOP_23,
	0,
	0,
};

#define ACCESS_MEMORY		0xfe
#define ACCESS_NOTHING		0xff

static void new_bundle(struct codegen_context *ctx)
{
	unsigned i;
	for (i = 0; i < 3; i++) {
		ctx->a.insns[i] = -1ULL;
		ctx->a.insn_units[i] = 0xff;
		ctx->a.insn_stops[i] = false;
	}
}

static void clear_wr_mask(struct codegen_context *ctx)
{
	memset(&ctx->a.wr_mask, 0, sizeof ctx->a.wr_mask);
}

static void init_arch_context(struct codegen_context *ctx)
{
	new_bundle(ctx);
	clear_wr_mask(ctx);
}

static bool test_mask(uint64_t mask[4], uint8_t bit)
{
	return mask[bit >> 6] & 1ULL << (bit & 63);
}

static void set_mask(uint64_t mask[4], uint8_t bit)
{
	if (bit == ACCESS_NOTHING)
		return;
	mask[bit >> 6] |= 1ULL << (bit & 63);
}

static uint32_t get_possible_templates(struct codegen_context *ctx)
{
	unsigned i, j;
	uint32_t result = 0;
	for (i = 0; i < 32; i++) {
		uint32_t tmpl = templates[i];
		for (j = 0; j < 3; j++) {
			uint8_t insn_unit = ctx->a.insn_units[j];
			uint8_t tmpl_unit = tmpl >> (j * 8) & 0xff;
			if (!(tmpl_unit & insn_unit)) {
				goto failed_match;
			}
			if (ctx->a.insn_stops[j] != (tmpl >> (24 + j) & 1)) {
				goto failed_match;
			}
		}
		result |= 1U << i;
failed_match:;
	}
	return result;
}

static uint64_t get_nop(unsigned unit)
{
	switch (unit) {
		case UNIT_I:	return IA64_I_NOP;
		case UNIT_M:	return IA64_M_NOP;
		case UNIT_B:	return IA64_B_NOP;
		case UNIT_F:	return IA64_F_NOP;
		case UNIT_L:	return IA64_L_NOP;
		case UNIT_X:	return IA64_X_NOP;
		default:	internal(file_line, "get_nop: invalid unit %x", unit);
				return 0;
	}
}

static unsigned get_free_slot(struct codegen_context *ctx)
{
	unsigned slot = 3;
	while (slot > 0 && ctx->a.insns[slot - 1] == -1ULL)
		slot--;
	return slot;
}

static bool attr_w ia64_purge_bundle(struct codegen_context *ctx)
{
	uint32_t tmpls;
	unsigned tmpl, i;
	uint64_t low, high;
	if (!get_free_slot(ctx))
		return true;
	tmpls = get_possible_templates(ctx);
	if (unlikely(!tmpls))
		internal(file_line, "ia64_purge_bundle: no possible templates");
	tmpl = low_bit(tmpls);
	for (i = 0; i < 3; i++) {
		if (ctx->a.insns[i] == -1ULL) {
			ctx->a.insns[i] = get_nop(templates[tmpl] >> (i * 8) & 0xff);
			ctx->a.insn_units[i] = templates[tmpl] >> (i * 8) & 0xff;
		}
	}
	low = tmpl | ctx->a.insns[0] << 5 | ctx->a.insns[1] << 46;
	high = ctx->a.insns[1] >> 18 | ctx->a.insns[2] << 23;
	cgen_eight(low);
	cgen_eight(high);
	new_bundle(ctx);
	return true;
}

static bool ia64_fill_bundle(struct codegen_context *ctx)
{
	uint32_t tmpls;
	unsigned tmpl, i;
	if (!get_free_slot(ctx))
		return false;
	tmpls = get_possible_templates(ctx);
	if (unlikely(!tmpls))
		internal(file_line, "ia64_fill_bundle: no possible templates");
	tmpl = low_bit(tmpls);
	for (i = 0; i < 3; i++) {
		if (ctx->a.insns[i] == -1ULL) {
			ctx->a.insns[i] = get_nop(templates[tmpl] >> (i * 8) & 0xff);
			ctx->a.insn_units[i] = templates[tmpl] >> (i * 8) & 0xff;
		}
	}
	return true;
}

static bool attr_w ia64_insn(struct codegen_context *ctx, uint8_t unit, uint64_t mc, uint8_t wr1, uint8_t wr2, uint8_t rd1, uint8_t rd2, uint8_t rd3)
{
	unsigned slot = get_free_slot(ctx);
	bool need_stop = false;
	need_stop |= test_mask(ctx->a.wr_mask, wr1);
	need_stop |= test_mask(ctx->a.wr_mask, wr2);
	need_stop |= test_mask(ctx->a.wr_mask, rd1);
	need_stop |= test_mask(ctx->a.wr_mask, rd2);
	need_stop |= test_mask(ctx->a.wr_mask, rd3);
	/*debug("ia64_insn: %x, %lx, %d, %u", unit, mc, need_stop, slot);*/
	if (slot > 0) {
		if (need_stop) {
try_stop_in_next_slot:
			ctx->a.insn_stops[slot - 1] = need_stop;
			if (!get_possible_templates(ctx)) {
				ctx->a.insn_stops[slot - 1] = false;
				slot++;
				if (unlikely(slot > 3))
					internal(file_line, "ia64_insn: can't set stop at the end of the bundle");
				goto try_stop_in_next_slot;
			}
		}
		if (slot == 3) {
			g(ia64_purge_bundle(ctx));
			slot = 0;
		}
		if (need_stop) {
			clear_wr_mask(ctx);
		}
	}
try_next_slot:
	ctx->a.insn_units[slot] = unit;
	if (!get_possible_templates(ctx)) {
		ctx->a.insn_units[slot] = 0xff;
		slot++;
		if (unlikely(slot == 3)) {
			g(ia64_purge_bundle(ctx));
			slot = 0;
		}
		goto try_next_slot;
	}
	ctx->a.insns[slot] = mc;
	set_mask(ctx->a.wr_mask, wr1);
	set_mask(ctx->a.wr_mask, wr2);
	return true;
}

static bool attr_w cgen_ia64_ret(struct codegen_context *ctx)
{
	uint64_t mc;
	mc = IA64_B_BR_RET;
	mc |= bits_b(B_0) << 13;
	g(ia64_insn(ctx, UNIT_B, mc, ACCESS_MEMORY, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
	mc = IA64_B_NOP;
	g(ia64_insn(ctx, UNIT_B, mc, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_MEMORY, ACCESS_NOTHING, ACCESS_NOTHING));
	return true;
}

static bool attr_w cgen_ia64_alloc(struct codegen_context *ctx)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	ia64_fill_bundle(ctx);
	mc = IA64_M_ALLOC;
	mc |= bits_gr(arg1[0]) << 6;
	mc |= get_imm(&arg2[1]) << 13;
	mc |= get_imm(&arg3[1]) << 20;
	g(ia64_insn(ctx, UNIT_M, mc, arg1[0], ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
	return true;
}

static bool attr_w cgen_ia64_dealloc(struct codegen_context *ctx)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	mc = IA64_I_MOV_TO_AR | IA64_I_MOV_TO_AR_PFS;
	mc |= bits_gr(arg1[0]) << 13;
	g(ia64_insn(ctx, UNIT_I, mc, ACCESS_NOTHING, ACCESS_NOTHING, arg1[0], ACCESS_NOTHING, ACCESS_NOTHING));
	return true;
}

static bool attr_w cgen_call_indirect(struct codegen_context *ctx)
{
	uint64_t mc;
	unsigned reg = cget_one(ctx);
	mc = IA64_B_BR_CALL_INDIRECT;
	mc |= bits_b(B_0) << 6;
	mc |= bits_b(reg) << 13;
	g(ia64_insn(ctx, UNIT_B, mc, B_0, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
	return true;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size)
{
	uint64_t mc;
	int64_t imm;
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (reg_is_gr(arg1[0])) {
		if (reg_is_gr(arg2[0])) {
			switch (size) {
				case OP_SIZE_1:
					mc = IA64_I_ZXT1;
					break;
				case OP_SIZE_2:
					mc = IA64_I_ZXT2;
					break;
				case OP_SIZE_4:
					mc = IA64_I_ZXT4;
					break;
				case OP_SIZE_NATIVE:
					mc = IA64_A_ADD_IMM14;
					mc |= bits_gr(arg1[0]) << 6;
					mc |= bits_gr(arg2[0]) << 20;
					g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
					return true;
				default:
					goto invalid;
			}
			mc |= bits_gr(arg1[0]) << 6;
			mc |= bits_gr(arg2[0]) << 20;
			g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			mc = IA64_M_GETF_SIG;
			mc |= bits_gr(arg1[0]) << 6;
			mc |= bits_fp(arg2[0]) << 13;
			g(ia64_insn(ctx, UNIT_M, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
			return true;
		}
		if (reg_is_b(arg2[0])) {
			mc = IA64_I_MOVE_FROM_BR;
			mc |= bits_gr(arg1[0]) << 6;
			mc |= bits_b(arg2[0]) << 13;
			g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
			return true;
		}
		if (reg_is_p(arg2[0])) {
			mc = IA64_A_ADD_IMM14;
			mc |= bits_gr(arg1[0]) << 6;
			mc |= (uint64_t)1 << 13;
			mc |= bits_p(arg2[0]);
			g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));

			mc = IA64_A_ADD_IMM14;
			mc |= bits_gr(arg1[0]) << 6;
			mc |= bits_p(arg2[0] ^ 1);
			g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));

			return true;
		}
		if (arg2[0] == ARG_ADDRESS_1) {
			imm = get_imm(&arg2[2]);
			if (unlikely(imm != 0))
				goto invalid;
			switch (size) {
				case OP_SIZE_1:	mc = IA64_M_LD1; break;
				case OP_SIZE_2:	mc = IA64_M_LD2; break;
				case OP_SIZE_4:	mc = IA64_M_LD4; break;
				case OP_SIZE_8:	mc = IA64_M_LD8; break;
				default:	goto invalid;
			}
			mc |= bits_gr(arg1[0]) << 6;
			mc |= bits_gr(arg2[1]) << 20;
			g(ia64_insn(ctx, UNIT_M, mc, arg1[0], ACCESS_NOTHING, arg2[1], ACCESS_MEMORY, ACCESS_NOTHING));
			return true;
		}
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (imm >= -0x200000 && imm < 0x200000) {
				mc = IA64_A_ADD_IMM22;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= (imm & 0x7f) << 13;
				mc |= ((uint64_t)imm >> 7 & 0x1ff) << 27;
				mc |= ((uint64_t)imm >> 16 & 0x1f) << 22;
				mc |= ((uint64_t)imm >> 21 & 0x1) << 36;
				g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
			} else {
				mc = (imm & 0x7fffffffffc00000ULL) >> 22;
				g(ia64_insn(ctx, UNIT_L, mc, arg1[0], ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
				mc = IA64_X_MOVL;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= (imm & 0x7f) << 13;
				mc |= ((uint64_t)imm >> 7 & 0x1ff) << 27;
				mc |= ((uint64_t)imm >> 16 & 0x1f) << 22;
				mc |= ((uint64_t)imm >> 21 & 0x1) << 21;
				mc |= ((uint64_t)imm >> 63) << 36;
				g(ia64_insn(ctx, UNIT_X, mc, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
			}
		}
	}
	if (reg_is_fp(arg1[0])) {
		if (reg_is_gr(arg2[0])) {
			mc = IA64_M_SETF_SIG;
			mc |= bits_fp(arg1[0]) << 6;
			mc |= bits_gr(arg2[0]) << 13;
			g(ia64_insn(ctx, UNIT_M, mc, arg1[0], ACCESS_NOTHING, arg2[1], ACCESS_NOTHING, ACCESS_NOTHING));
			return true;
		}
		if (arg2[0] == ARG_ADDRESS_1) {
			imm = get_imm(&arg2[2]);
			if (unlikely(imm != 0))
				goto invalid;
			switch (size) {
				case OP_SIZE_4:	mc = IA64_M_LDFS; break;
				case OP_SIZE_8:	mc = IA64_M_LDFD; break;
				case OP_SIZE_10:mc = IA64_M_LDFE; break;
				default:	goto invalid;
			}
			mc |= bits_fp(arg1[0]) << 6;
			mc |= bits_gr(arg2[1]) << 20;
			g(ia64_insn(ctx, UNIT_M, mc, arg1[0], ACCESS_NOTHING, arg2[1], ACCESS_MEMORY, ACCESS_NOTHING));
			return true;
		}
	}
	if (reg_is_b(arg1[0])) {
		if (reg_is_gr(arg2[0])) {
			mc = IA64_I_MOVE_TO_BR;
			mc |= bits_gr(arg2[0]) << 13;
			mc |= bits_b(arg1[0]) << 6;
			g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
			return true;
		}
	}
	if (arg1[0] == ARG_ADDRESS_1) {
		imm = get_imm(&arg1[2]);
		if (unlikely(imm != 0))
			goto invalid;
		if (arg2[0] == ARG_IMM) {
			imm = get_imm(&arg2[1]);
			if (unlikely(imm != 0))
				goto invalid;
			arg2 = &z;
		}
		if (reg_is_gr(arg2[0])) {
			switch (size) {
				case OP_SIZE_1:	mc = IA64_M_ST1; break;
				case OP_SIZE_2:	mc = IA64_M_ST2; break;
				case OP_SIZE_4:	mc = IA64_M_ST4; break;
				case OP_SIZE_8:	mc = IA64_M_ST8; break;
				default:	goto invalid;
			}
			mc |= bits_gr(arg2[0]) << 13;
			mc |= bits_gr(arg1[1]) << 20;
			g(ia64_insn(ctx, UNIT_M, mc, ACCESS_MEMORY, ACCESS_NOTHING, arg1[1], arg2[0], ACCESS_NOTHING));
			return true;
		}
		if (reg_is_fp(arg2[0])) {
			switch (size) {
				case OP_SIZE_4:	mc = IA64_M_STFS; break;
				case OP_SIZE_8:	mc = IA64_M_STFD; break;
				case OP_SIZE_10:mc = IA64_M_STFE; break;
				default:	goto invalid;
			}
			mc |= bits_fp(arg2[0]) << 13;
			mc |= bits_gr(arg1[1]) << 20;
			g(ia64_insn(ctx, UNIT_M, mc, ACCESS_MEMORY, ACCESS_NOTHING, arg1[1], arg2[0], ACCESS_NOTHING));
			return true;
		}
	}

invalid:
	internal(file_line, "cgen_mov: invalid arguments %02x, %02x, %u", arg1[0], arg2[0], size);
	return false;
}

static bool attr_w cgen_movsx(struct codegen_context *ctx, unsigned size)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (likely(reg_is_gr(arg1[0])) && likely(reg_is_gr(arg2[0]))) {
		switch (size) {
			case OP_SIZE_1:
				mc = IA64_I_SXT1;
				break;
			case OP_SIZE_2:
				mc = IA64_I_SXT2;
				break;
			case OP_SIZE_4:
				mc = IA64_I_SXT4;
				break;
			case OP_SIZE_NATIVE:
				mc = IA64_A_ADD_IMM14;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= bits_gr(arg2[0]) << 20;
				g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
			default:
				goto invalid;
		}
		mc |= bits_gr(arg1[0]) << 6;
		mc |= bits_gr(arg2[0]) << 20;
		g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
		return true;
	}

invalid:
	internal(file_line, "cgen_mov: invalid arguments %02x, %02x, %u", arg1[0], arg2[0], size);
	return false;
}

static bool attr_w cgen_cmp_dest_reg(struct codegen_context *ctx, unsigned op_size, unsigned cond)
{
	uint64_t mc;
	unsigned pred;
	bool swap_preds = false, swap_regs = false;
	uint8_t z = R_ZERO;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(!reg_is_p(arg1[0])) || unlikely(!reg_is_gr(arg2[0])))
		goto invalid;

	pred = arg1[0];

	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		if (likely(!imm)) {
			arg3 = &z;
			goto cmp_3reg;
		}
		if (unlikely(imm <= -0x80) || unlikely(imm >= 0x80))
			goto invalid;
		switch (cond) {
			case COND_AE:	mc = IA64_A_CMP_LTU_IMM8; imm--; break;
			case COND_B:	mc = IA64_A_CMP_LTU_IMM8; imm--; swap_preds = true; break;
			case COND_E:	mc = IA64_A_CMP_EQ_IMM8; break;
			case COND_NE:	mc = IA64_A_CMP_EQ_IMM8; swap_preds = true; break;
			case COND_BE:	mc = IA64_A_CMP_LTU_IMM8; swap_preds = true; break;
			case COND_A:	mc = IA64_A_CMP_LTU_IMM8; break;
			case COND_L:	mc = IA64_A_CMP_LT_IMM8; imm--; swap_preds = true; break;
			case COND_GE:	mc = IA64_A_CMP_LT_IMM8; imm--; break;
			case COND_LE:	mc = IA64_A_CMP_LT_IMM8; swap_preds = true; break;
			case COND_G:	mc = IA64_A_CMP_LT_IMM8; break;
			default:	goto invalid;
		}

		if (swap_preds)
			pred ^= 1;

		if (op_size == OP_SIZE_4)
			mc |= IA64_A_CMP4;

		mc |= (imm & 0x7f) << 13;
		mc |= ((uint64_t)imm >> 7 & 1) << 36;
		mc |= bits_gr(arg2[0]) << 20;
		mc |= bits_p(pred) << 6;
		mc |= bits_p(pred ^ 1) << 27;
		g(ia64_insn(ctx, UNIT_A, mc, arg1[0], arg1[0] ^ 1, arg2[0], arg3[0], ACCESS_NOTHING));
		return true;
	}

	if (!reg_is_gr(arg3[0]))
		goto invalid;

cmp_3reg:
	switch (cond) {
		case COND_B:	mc = IA64_A_CMP_LTU; break;
		case COND_AE:	mc = IA64_A_CMP_LTU; swap_preds = true; break;
		case COND_E:	mc = IA64_A_CMP_EQ; break;
		case COND_NE:	mc = IA64_A_CMP_EQ; swap_preds = true; break;
		case COND_BE:	mc = IA64_A_CMP_LTU; swap_regs = true; swap_preds = true; break;
		case COND_A:	mc = IA64_A_CMP_LTU; swap_regs = true; break;
		case COND_L:	mc = IA64_A_CMP_LT; break;
		case COND_GE:	mc = IA64_A_CMP_LT; swap_preds = true; break;
		case COND_LE:	mc = IA64_A_CMP_LT; swap_regs = true; swap_preds = true; break;
		case COND_G:	mc = IA64_A_CMP_LT; swap_regs = true; break;
		default:	goto invalid;
	}

	if (swap_regs) {
		uint8_t *argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}

	if (swap_preds)
		pred ^= 1;

	if (op_size == OP_SIZE_4)
		mc |= IA64_A_CMP4;

	mc |= bits_gr(arg2[0]) << 13;
	mc |= bits_gr(arg3[0]) << 20;
	mc |= bits_p(pred) << 6;
	mc |= bits_p(pred ^ 1) << 27;
	g(ia64_insn(ctx, UNIT_A, mc, arg1[0], arg1[0] ^ 1, arg2[0], arg3[0], ACCESS_NOTHING));
	return true;

invalid:
	internal(file_line, "cgen_cmp_dest_reg: invalid arguments %02x, %02x, %02x", arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_test_dest_reg(struct codegen_context *ctx, unsigned bit, bool jnz)
{
	uint64_t mc;
	unsigned pred;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (unlikely(!reg_is_p(arg1[0])) || unlikely(!reg_is_gr(arg2[0])))
		goto invalid;

	pred = arg1[0];

	if (jnz)
		pred ^= 1;

	mc = IA64_I_TBIT;
	mc |= (uint64_t)bit << 14;
	mc |= bits_gr(arg2[0]) << 20;
	mc |= bits_p(pred) << 6;
	mc |= bits_p(pred ^ 1) << 27;
	g(ia64_insn(ctx, UNIT_I, mc, arg1[0], arg1[0] ^ 1, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
	return true;

invalid:
	internal(file_line, "cgen_test_dest_reg: invalid arguments %02x, %02x", arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned alu)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (alu == ALU_ADD && arg2[0] == ARG_SHIFTED_REGISTER) {
		uint8_t *arg_swp = arg3;
		arg3 = arg2;
		arg2 = arg_swp;
	}

	if (unlikely(!reg_is_gr(arg1[0])) || unlikely(!reg_is_gr(arg2[0])))
		goto invalid;

gr_gr_gr:
	if (reg_is_gr(arg3[0])) {
		mc = IA64_A_ALU;
		switch (alu) {
			case ALU_ADD:	mc |= IA64_A_ALU_ADD; break;
			case ALU_SUB:	mc |= IA64_A_ALU_SUB; break;
			case ALU_AND:	mc |= IA64_A_ALU_AND; break;
			case ALU_ANDN:	mc |= IA64_A_ALU_ANDCM; break;
			case ALU_OR:	mc |= IA64_A_ALU_OR; break;
			case ALU_XOR:	mc |= IA64_A_ALU_XOR; break;
			default:	goto invalid;
		}
		mc |= bits_gr(arg1[0]) << 6;
		mc |= bits_gr(arg2[0]) << 13;
		mc |= bits_gr(arg3[0]) << 20;
		g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], arg3[0], ACCESS_NOTHING));
		return true;
	}

	if (arg3[0] == ARG_SHIFTED_REGISTER && (arg3[1] & ARG_SHIFT_MODE) == ARG_SHIFT_LSL) {
		unsigned amount = arg3[1] & ARG_SHIFT_AMOUNT;
		if (!amount) {
			arg3 += 2;
			goto gr_gr_gr;
		}
		if (unlikely(amount > 4))
			goto invalid;
		mc = IA64_A_SHLADD;
		mc |= bits_gr(arg1[0]) << 6;
		mc |= bits_gr(arg3[2]) << 13;
		mc |= bits_gr(arg2[0]) << 20;
		mc |= (amount - 1) << 27;
		g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], arg3[2], ACCESS_NOTHING));
		return true;
	}

	if (arg3[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg3[1]);
		if (alu == ALU_SUB) {
			imm = -(uint64_t)imm;
			alu = ALU_ADD;
		}
		if (alu == ALU_ADD) {
			if (unlikely(imm < -0x2000) || unlikely(imm >= 0x2000))
				goto invalid;
			mc = IA64_A_ADD_IMM14;
			mc |= bits_gr(arg1[0]) << 6;
			mc |= bits_gr(arg2[0]) << 20;
			mc |= (imm & 0x7f) << 13;
			mc |= ((uint64_t)imm >> 7 & 0x3f) << 27;
			mc |= ((uint64_t)imm >> 13 & 1) << 36;
			g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
			return true;
		} else if (alu == ALU_AND || alu == ALU_OR || alu == ALU_XOR) {
			if (unlikely(imm < -0x80) || unlikely(imm >= 0x80))
				goto invalid;
			mc = IA64_A_ALU_IMM8 | (alu == ALU_AND ? IA64_A_ALU_IMM8_AND : alu == ALU_OR ? IA64_A_ALU_IMM8_OR : IA64_A_ALU_IMM8_XOR);
			mc |= bits_gr(arg1[0]) << 6;
			mc |= bits_gr(arg2[0]) << 20;
			mc |= (imm & 0x7f) << 13;
			mc |= ((uint64_t)imm >> 7 & 1) << 36;
			g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
			return true;
		} else {
			goto invalid;
		}
	}

invalid:
	internal(file_line, "cgen_alu: invalid arguments %u, %02x, %02x, %02x", alu, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned alu)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	if (unlikely(!reg_is_gr(arg1[0])) || unlikely(!reg_is_gr(arg2[0])))
		goto invalid;


	switch (alu) {
		case ALU1_NOT:	mc = IA64_A_ALU_IMM8 | IA64_A_ALU_IMM8_ANDCM;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= bits_gr(arg2[0]) << 20;
				mc |= 0x7fULL << 13;
				mc |= 0x1ULL << 36;
				g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
		case ALU1_NEG:	mc = IA64_A_ALU_IMM8 | IA64_A_ALU_IMM8_SUB;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= bits_gr(arg2[0]) << 20;
				g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
		case ALU1_INC:	mc = IA64_A_ADD_IMM14;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= bits_gr(arg2[0]) << 20;
				mc |= 1ULL << 13;
				g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
		case ALU1_DEC:	mc = IA64_A_ADD_IMM14;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= bits_gr(arg2[0]) << 20;
				mc |= 0x7fULL << 13;
				mc |= 0x3fULL << 27;
				mc |= 0x1ULL << 36;
				g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
		case ALU1_BSWAP:mc = IA64_I_MUX1_REV;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= bits_gr(arg1[1]) << 13;
				g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
		case ALU1_POPCNT:
				mc = IA64_I_POPCNT;
				mc |= bits_gr(arg1[0]) << 6;
				mc |= bits_gr(arg2[0]) << 20;
				g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
				return true;
		default:	goto invalid;
	}

invalid:
	internal(file_line, "cgen_alu1: invalid arguments %u, %02x, %02x", alu, arg1[0], arg2[0]);
	return false;
}


static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned rot)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	if (unlikely(!reg_is_gr(arg1[0])) || unlikely(!reg_is_gr(arg2[0])))
		goto invalid;

	if (arg3[0] == ARG_IMM) {
		uint64_t pos = get_imm(&arg3[1]) & 63;
		uint64_t len = 64 - pos - 1;
		switch (rot) {
			case ROT_SHL:	mc = IA64_I_DEP_Z;
					mc |= bits_gr(arg1[0]) << 6;
					mc |= bits_gr(arg2[0]) << 13;
					mc |= (pos ^ 0x3f) << 20;
					mc |= len << 27;
					break;
			case ROT_SHR:	mc = IA64_I_EXTR_U;
					mc |= bits_gr(arg1[0]) << 6;
					mc |= pos << 14;
					mc |= bits_gr(arg2[0]) << 20;
					mc |= len << 27;
					break;
			case ROT_SAR:	mc = IA64_I_EXTR;
					mc |= bits_gr(arg1[0]) << 6;
					mc |= pos << 14;
					mc |= bits_gr(arg2[0]) << 20;
					mc |= len << 27;
					break;
			default:	goto invalid;
		}
		g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
		return true;
	}

	if (reg_is_gr(arg3[0])) {
		switch (rot) {
			case ROT_SHL:	mc = IA64_I_SHL;
					mc |= bits_gr(arg1[0]) << 6;
					mc |= bits_gr(arg2[0]) << 13;
					mc |= bits_gr(arg3[0]) << 20;
					break;
			case ROT_SHR:	mc = IA64_I_SHR_U;
					mc |= bits_gr(arg1[0]) << 6;
					mc |= bits_gr(arg3[0]) << 13;
					mc |= bits_gr(arg2[0]) << 20;
					break;
			case ROT_SAR:	mc = IA64_I_SHR;
					mc |= bits_gr(arg1[0]) << 6;
					mc |= bits_gr(arg3[0]) << 13;
					mc |= bits_gr(arg2[0]) << 20;
					break;
			default:	goto invalid;
		}
		g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], arg3[0], ACCESS_NOTHING));
		return true;
	}

invalid:
	internal(file_line, "cgen_rot: invalid arguments %02x, %02x, %02x, %u", arg1[0], arg2[0], arg3[0], rot);
	return false;
}

static bool attr_w cgen_btx(struct codegen_context *ctx, unsigned alu)
{
	uint64_t mc;
	int64_t imm;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(!reg_is_gr(arg1[0])) || unlikely(!reg_is_gr(arg2[0])) || unlikely(arg3[0] != ARG_IMM))
		goto invalid;

	imm = get_imm(&arg3[1]) & 0x3f;

	mc = IA64_I_DEP_IMM;

	switch (alu) {
		case BTX_BTS:	mc |= 1ULL << 36;
				break;
		case BTX_BTR:	break;
		default:	goto invalid;
	}

	mc |= bits_gr(arg1[0]) << 6;
	mc |= bits_gr(arg2[0]) << 20;
	mc |= 0ULL << 27;
	mc |= (imm ^ 0x3f) << 14;

	g(ia64_insn(ctx, UNIT_I, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
	return true;

invalid:
	internal(file_line, "cgen_rot: invalid arguments %02x, %02x, %02x, %u", arg1[0], arg2[0], arg3[0], alu);
	return false;
}

static bool attr_w cgen_movr(struct codegen_context *ctx, unsigned aux)
{
	uint64_t mc;
	unsigned pred;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	uint8_t *arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	if (unlikely(arg1[0] != arg2[0]) || unlikely(!reg_is_gr(arg1[0])) || unlikely(!reg_is_p(arg3[0])))
		goto invalid;

	pred = arg3[0];
	switch (aux) {
		case COND_E:	pred ^= 1; break;
		case COND_NE:	break;
		default:	goto invalid;
	}

	if (arg4[0] == ARG_IMM) {
		int64_t imm = get_imm(&arg4[1]);
		if (unlikely(imm < -0x2000) || unlikely(imm >= 0x2000))
			goto invalid;
		mc = IA64_A_ADD_IMM14;
		mc |= bits_gr(arg1[0]) << 6;
		mc |= (imm & 0x7f) << 13;
		mc |= ((uint64_t)imm >> 7 & 0x3f) << 27;
		mc |= ((uint64_t)imm >> 13 & 1) << 36;
		mc |= bits_p(pred);
		g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], arg3[0], ACCESS_NOTHING));
		return true;
	}

	if (reg_is_gr(arg4[0])) {
		mc = IA64_A_ADD_IMM14;
		mc |= bits_gr(arg1[0]) << 6;
		mc |= bits_gr(arg4[0]) << 20;
		mc |= bits_p(pred);
		g(ia64_insn(ctx, UNIT_A, mc, arg1[0], ACCESS_NOTHING, arg2[0], arg3[0], arg4[0]));
		return true;
	}

invalid:
	internal(file_line, "cgen_movr: invalid arguments %02x, %02x, %02x, %02x, %u", arg1[0], arg2[0], arg3[0], arg4[0], aux);
	return false;
}

static bool attr_w cgen_fp_cmp_dest_reg(struct codegen_context *ctx, unsigned aux)
{
	uint64_t mc;
	unsigned pred;
	bool swap_preds = false, swap_regs = false;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);

	pred = arg1[0];
	mc = IA64_F_FCMP;
	switch (aux) {
		case FP_COND_P:	mc |= IA64_F_FCMP_UNORD; break;
		case FP_COND_NP:mc |= IA64_F_FCMP_UNORD; swap_preds = true; break;
		case FP_COND_E:	mc |= IA64_F_FCMP_EQ; break;
		case FP_COND_NE:mc |= IA64_F_FCMP_EQ; swap_preds = true; break;
		case FP_COND_A:	mc |= IA64_F_FCMP_LT; swap_regs = true; break;
		case FP_COND_BE:mc |= IA64_F_FCMP_LE; break;
		case FP_COND_B:	mc |= IA64_F_FCMP_LT; break;
		case FP_COND_AE:mc |= IA64_F_FCMP_LE; swap_regs = true; break;
	}

	if (swap_regs) {
		uint8_t *argx = arg2;
		arg2 = arg3;
		arg3 = argx;
	}

	if (swap_preds)
		pred ^= 1;

	mc |= bits_fp(arg2[0]) << 13;
	mc |= bits_fp(arg3[0]) << 20;
	mc |= bits_p(pred) << 6;
	mc |= bits_p(pred ^ 1) << 27;
	g(ia64_insn(ctx, UNIT_F, mc, arg1[0], ACCESS_NOTHING, arg2[0], arg3[0], ACCESS_NOTHING));
	return true;
}

static bool attr_w cgen_fp_alu(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint64_t mc, f1, f2, f3, f4;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	switch (aux) {
		case FP_ALU_ADD:
			mc = IA64_F_FMA;
			f1 = bits_fp(arg1[0]);
			f2 = bits_fp(arg3[0]);
			f3 = bits_fp(arg2[0]);
			f4 = bits_fp(FR_ONE);
			break;
		case FP_ALU_SUB:
			mc = IA64_F_FMS;
			f1 = bits_fp(arg1[0]);
			f2 = bits_fp(arg3[0]);
			f3 = bits_fp(arg2[0]);
			f4 = bits_fp(FR_ONE);
			break;
		case FP_ALU_MUL:
			mc = IA64_F_FMA;
			f1 = bits_fp(arg1[0]);
			f2 = bits_fp(FR_ZERO);
			f3 = bits_fp(arg2[0]);
			f4 = bits_fp(arg3[0]);
			break;
		default:
			goto invalid;
	}
	switch (op_size) {
		case OP_SIZE_4:
			mc |= IA64_F_FMA_S;
			break;
		case OP_SIZE_8:
			mc |= IA64_F_FMA_D;
			break;
		case OP_SIZE_10:
			mc |= IA64_F_FMA_E;
			break;
		default:
			goto invalid;
	}
	mc |= f1 << 6;
	mc |= f2 << 13;
	mc |= f3 << 20;
	mc |= f4 << 27;
	g(ia64_insn(ctx, UNIT_F, mc, arg1[0], ACCESS_NOTHING, arg2[0], arg3[0], ACCESS_NOTHING));
	return true;

invalid:
	internal(file_line, "cgen_fp_alu: invalid arguments %u, %u, %02x, %02x, %02x", op_size, aux, arg1[0], arg2[0], arg3[0]);
	return false;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned op_size, unsigned aux)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (aux) {
		case FP_ALU1_NEG:
			mc = IA64_F_FMERGE_NS;
			mc |= bits_fp(arg1[0]) << 6;
			mc |= bits_fp(arg2[0]) << 13;
			mc |= bits_fp(arg2[0]) << 20;
			break;
		default:
			goto invalid;
	}
	g(ia64_insn(ctx, UNIT_F, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
	return true;

invalid:
	internal(file_line, "cgen_fp_alu1: invalid arguments %u, %u, %02x, %02x", op_size, aux, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	mc = IA64_F_FCVT_FX_TRUNC;
	mc |= bits_fp(arg1[0]) << 6;
	mc |= bits_fp(arg2[0]) << 13;
	g(ia64_insn(ctx, UNIT_F, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));
	return true;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned fp_op_size)
{
	uint64_t mc;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);

	mc = IA64_F_FCVT_XF;
	mc |= bits_fp(arg1[0]) << 6;
	mc |= bits_fp(arg2[0]) << 13;
	g(ia64_insn(ctx, UNIT_F, mc, arg1[0], ACCESS_NOTHING, arg2[0], ACCESS_NOTHING, ACCESS_NOTHING));

	mc = IA64_F_FMA;
	switch (fp_op_size) {
		case OP_SIZE_4:
			mc |= IA64_F_FMA_S;
			break;
		case OP_SIZE_8:
			mc |= IA64_F_FMA_D;
			break;
		case OP_SIZE_10:
			goto skip_norm;
		default:
			goto invalid;
	}
	mc |= bits_fp(arg1[0]) << 6;
	mc |= bits_fp(FR_ZERO) << 13;
	mc |= bits_fp(arg1[0]) << 20;
	mc |= bits_fp(FR_ONE) << 27;
	g(ia64_insn(ctx, UNIT_F, mc, arg1[0], ACCESS_NOTHING, arg1[0], ACCESS_NOTHING, ACCESS_NOTHING));
skip_norm:
	return true;

invalid:
	internal(file_line, "cgen_fp_from_int: invalid arguments %u, %02x, %02x", fp_op_size, arg1[0], arg2[0]);
	return false;
}

static bool attr_w cgen_jmp(struct codegen_context *ctx, unsigned length)
{
	uint64_t mc;
	unsigned bundle;
	if (length == JMP_SHORTEST) {
		g(ia64_insn(ctx, UNIT_B, IA64_B_BR21, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
		bundle = get_free_slot(ctx) - 1;
		ctx->mcode_size += bundle;
		g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
		ctx->mcode_size -= bundle;
	} else {
		g(ia64_insn(ctx, UNIT_L, 0, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
		mc = IA64_X_BRL;
		g(ia64_insn(ctx, UNIT_X, mc, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
	}
	return true;
}

static bool attr_w cgen_jmp_reg(struct codegen_context *ctx, unsigned aux, unsigned length)
{
	uint64_t mc;
	unsigned bundle;
	unsigned reg = cget_one(ctx);
	if (unlikely(!reg_is_p(reg)))
		goto invalid;
	switch (aux) {
		case COND_NE:
			break;
		case COND_E:
			reg ^= 1;
			break;
		default:
			goto invalid;
	}
	if (likely(length == JMP_SHORTEST)) {
		mc = IA64_B_BR21 | IA64_BR_DPNT;
		mc |= bits_p(reg);
		g(ia64_insn(ctx, UNIT_B, mc, ACCESS_NOTHING, ACCESS_NOTHING, reg, ACCESS_NOTHING, ACCESS_NOTHING));
		bundle = get_free_slot(ctx) - 1;
		ctx->mcode_size += bundle;
		g(add_relocation(ctx, JMP_SHORTEST, 1, NULL));
		ctx->mcode_size -= bundle;
	} else {
		g(ia64_insn(ctx, UNIT_L, 0, ACCESS_NOTHING, ACCESS_NOTHING, reg, ACCESS_NOTHING, ACCESS_NOTHING));
		mc = IA64_X_BRL | IA64_BR_DPNT;
		mc |= bits_p(reg);
		g(ia64_insn(ctx, UNIT_X, mc, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
		g(add_relocation(ctx, JMP_SHORT, 1, NULL));
	}
	return true;
invalid:
	internal(file_line, "cgen_jmp_reg: invalid arguments %x, %x, %x", reg, aux, length);
}

static bool attr_w cgen_jmp_indirect(struct codegen_context *ctx)
{
	uint64_t mc;
	unsigned reg = cget_one(ctx);

	mc = IA64_I_MOVE_TO_BR;
	mc |= bits_gr(reg) << 13;
	mc |= bits_b(R_SCRATCH_B) << 6;
	g(ia64_insn(ctx, UNIT_I, mc, R_SCRATCH_B, ACCESS_NOTHING, reg, ACCESS_NOTHING, ACCESS_NOTHING));

	mc = IA64_B_BR_JMP_INDIRECT;
	mc |= bits_b(R_SCRATCH_B) << 13;
	g(ia64_insn(ctx, UNIT_B, mc, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING, ACCESS_NOTHING));
	return true;
}

static uint64_t extract_bundle(uint8_t *ptr, unsigned bundle)
{
	uint64_t mc[2];
	memcpy(mc, ptr, 16);
	switch (bundle) {
		case 0:	return mc[0] >> 5 & 0x1ffffffffffULL;
			break;
		case 1:	return mc[0] >> 46 | (mc[1] & 0x7fffffULL) << 18;
			break;
		case 2:	return mc[1] >> 23;
			break;
		default:internal(file_line, "extract_bundle: invalid bundle %u", bundle);
	}
}

static void insert_bundle(uint8_t *ptr, unsigned bundle, uint64_t instr)
{
	uint64_t mc[2];
	memcpy(mc, ptr, 16);
	switch (bundle) {
		case 0: mc[0] = (mc[0] & ~(0x1ffffffffffULL << 5)) | instr << 5;
			break;
		case 1:	mc[0] = (mc[0] & ~(-1ULL << 46)) | instr << 46;
			mc[1] = (mc[1] & ~0x7fffffULL) | instr >> 18;
			break;
		case 2:	mc[1] = (mc[1] & ~(-1ULL << 23)) | instr << 23;
			break;
		default:internal(file_line, "insert_bundle: invalid bundle %u", bundle);
	}
	memcpy(ptr, mc, 16);
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	uint64_t mc;
	unsigned imm41;
	unsigned bundle = reloc->position & 3;
	size_t position = reloc->position & ~3;
	int64_t offs = (int64_t)(ctx->label_to_pos[reloc->label_id] >> 4) - (int64_t)(position >> 4);
	/*debug("relocation: position %lx, bundle %x, offset %lx, label %lx", reloc->position, bundle, offs, ctx->label_to_pos[reloc->label_id]);*/
	switch (reloc->length) {
		case JMP_SHORTEST:
			if (unlikely(offs < -0x100000) || unlikely(offs >= 0x100000))
				return false;
			mc = extract_bundle(ctx->mcode + position, bundle);
			mc &= ~0x011ffffe000ULL;
			mc |= (offs & 0xfffffULL) << 13;
			mc |= ((uint64_t)offs >> 20 & 1) << 36;
			insert_bundle(ctx->mcode + position, bundle, mc);
			return true;
		case JMP_SHORT:
			imm41 = extract_bundle(ctx->mcode + position, 1);
			mc = extract_bundle(ctx->mcode + position, 2);
			mc &= ~0x011ffffe000ULL;
			mc |= (offs & 0xfffffULL) << 13;
			imm41 &= ~0x1fffffffffcULL;
			imm41 |= (offs >> 20 << 2) & 0x1fffffffffcULL;
			mc |= ((uint64_t)offs >> 59 & 1) << 36;
			insert_bundle(ctx->mcode + position, 1, imm41);
			insert_bundle(ctx->mcode + position, 2, mc);
			return true;
		default:
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
	}
	return false;
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	bool full;
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			full = ia64_fill_bundle(ctx);
			if (full)
				ctx->mcode_size += 16;
			g(cgen_entry(ctx));
			if (full)
				ctx->mcode_size -= 16;
			return true;
		case INSN_LABEL:
			full = ia64_fill_bundle(ctx);
			if (full)
				ctx->mcode_size += 16;
			g(cgen_label(ctx));
			if (full)
				ctx->mcode_size -= 16;
			return true;
		case INSN_RET:
			g(cgen_ia64_ret(ctx));
			g(ia64_purge_bundle(ctx));
			return true;
		case INSN_IA64_ALLOC:
			g(cgen_ia64_alloc(ctx));
			return true;
		case INSN_IA64_DEALLOC:
			g(cgen_ia64_dealloc(ctx));
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
		case INSN_TEST_DEST_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_test_dest_reg(ctx, insn_aux(insn) & 63, insn_aux(insn) >> 6));
			return true;
		case INSN_ALU:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_aux(insn)));
			return true;
		case INSN_ALU1:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_aux(insn)));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_aux(insn)));
			return true;
		case INSN_BTX:
			g(cgen_btx(ctx, insn_aux(insn)));
			return true;
		case INSN_MOVR:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_movr(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_CMP_DEST_REG:
			g(cgen_fp_cmp_dest_reg(ctx, insn_aux(insn)));
			return true;
		case INSN_FP_ALU:
			g(cgen_fp_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_ALU1:
			g(cgen_fp_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_TO_INT64:
			g(cgen_fp_to_int(ctx));
			return true;
		case INSN_FP_FROM_INT64:
			g(cgen_fp_from_int(ctx, insn_op_size(insn)));
			return true;
		case INSN_JMP:
			g(cgen_jmp(ctx, insn_jump_size(insn)));
			return true;
		case INSN_JMP_REG:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_jmp_reg(ctx, insn_aux(insn), insn_jump_size(insn)));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_indirect(ctx));
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
