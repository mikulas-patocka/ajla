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

#define OP_SIZE_NATIVE			OP_SIZE_4
#define OP_SIZE_ADDRESS			OP_SIZE_4

#define JMP_LIMIT			JMP_EXTRA_LONG

#define UNALIGNED_TRAP			1

#define MOV_WRITES_FLAGS(dest, src)	0
#define ALU_WRITES_FLAGS(size, alu, is_mem, is_imm, imm)	0
#define ALU1_WRITES_FLAGS(alu)		0
#define ROT_WRITES_FLAGS(alu, size, im)	0
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		0
#define ARCH_IS_3ADDRESS(alu, f)	0
#define ARCH_IS_3ADDRESS_IMM(alu, f)	0
#define ARCH_IS_3ADDRESS_ROT(alu, size)	0
#define ARCH_IS_3ADDRESS_ROT_IMM(alu)	0
#define ARCH_IS_2ADDRESS(alu)		1
#define ARCH_IS_3ADDRESS_FP		0
#define ARCH_HAS_JMP_REG(cond)		0
#define ARCH_HAS_JMP_2REGS(cond)	0
#define ARCH_HAS_DELAY_SLOTS(insn)	0
#define ARCH_HAS_FUSED_MEMORY_ACCESSES	0
#define ARCH_HAS_FLAGS			0
#define ARCH_PREFERS_SX(size)		((size) < OP_SIZE_4)
#define ARCH_REQUIRES_MOV_MASK(size)	0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			0
#define ARCH_HAS_ANDN			0
#define ARCH_HAS_2REG_M(st, fp, sz, sh, im)	0
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_HAS_SHIFTED_ADD(bits)	0
#define ARCH_HAS_CMOV			0
#define ARCH_SHIFT_SIZE			32
#define ARCH_BOOL_SIZE			OP_SIZE_4
#define ARCH_HAS_FP_GP_MOV(size)	1
#define ARCH_HAS_PC_RELATIVE_ADDRESSING	0
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_4
#define i_size_rot(size)		OP_SIZE_4
#define i_size_cmp(size)		OP_SIZE_4

#define R_0				0x00
#define R_1				0x01
#define R_2				0x02
#define R_3				0x03
#define R_4				0x04
#define R_5				0x05
#define R_6				0x06
#define R_7				0x07
#define R_8				0x08
#define R_9				0x09
#define R_10				0x0a
#define R_11				0x0b
#define R_12				0x0c
#define R_13				0x0d
#define R_14				0x0e
#define R_SP				0x0f

#define R_LR				0x10
#define R_GBR				0x11
#define R_FPSCR				0x12
#define R_T				0x13

#define FR_0				0x20
#define FR_1				0x21
#define FR_2				0x22
#define FR_3				0x23
#define FR_4				0x24
#define FR_5				0x25
#define FR_6				0x26
#define FR_7				0x27
#define FR_8				0x28
#define FR_9				0x29
#define FR_10				0x2a
#define FR_11				0x2b
#define FR_12				0x2c
#define FR_13				0x2d
#define FR_14				0x2e
#define FR_15				0x2f

#define DR_0				0x20
#define DR_2				0x22
#define DR_4				0x24
#define DR_6				0x26
#define DR_8				0x28
#define DR_10				0x2a
#define DR_12				0x2c
#define DR_14				0x2e

#define R_MAX				0x30

static bool reg_is_fp(unsigned reg)
{
	return reg >= FR_0 && reg <= FR_15;
}

static bool reg_is_ctrl(unsigned reg)
{
	return reg >= 0x10 && reg <= 0x12;
}

static bool reg_is_p(unsigned reg)
{
	return reg == R_T;
}

#define R_OFFSET_IMM			R_0
#define R_CONST_IMM			R_1

#define R_SCRATCH_1			R_4
#define R_SCRATCH_2			R_5
#define R_SCRATCH_3			R_6
#define R_SCRATCH_4			R_8
#define R_SAVED_1			R_9
#define R_SAVED_2			R_SCRATCH_4

#define R_SCRATCH_NA_1			R_2
#ifdef HAVE_BITWISE_FRAME
#define R_SCRATCH_NA_2			R_3
#define R_SCRATCH_NA_3			R_14
#endif

#define R_FRAME				R_GBR
#define R_CMP_RESULT			R_T

#define FR_SCRATCH_1			FR_0
#define FR_SCRATCH_2			FR_2
#define FR_SCRATCH_3			FR_3

#define R_ARG0				R_4
#define R_ARG1				R_5
#define R_ARG2				R_6
#define R_ARG3				R_7
#define R_RET0				R_SCRATCH_1
#define R_RET_IP			R_4

#define SUPPORTED_FP			0x6
#define SUPPORTED_FP_FMA		0x2
#define FMA_NO_NEG
#define FMA_NO_SUB

#define FP_REGISTERS(real_size)		((real_size) >= 8 ? 2 : 1)
#define FP_ALIASES(real_size, reg, idx)	(!((reg) & 1) ? (reg) + (idx) : (reg))
#define N_FP_ALIASES(real_size)		FP_REGISTERS(real_size)

static const uint8_t regs_saved[] = { R_10, R_11, R_12, R_13, R_14 };
static const uint8_t regs_volatile[] = { R_7, R_3 };
#ifdef HAVE_BITWISE_FRAME
#define n_regs_saved 4U
#define n_regs_volatile 1U
#endif
static const uint8_t fp_saved[] = { FR_12, FR_13, FR_14, FR_15 };
#define n_fp_saved(real_type) (optimize_int ? 0 : n_array_elements(fp_saved))
static const uint8_t fp_volatile[] = { FR_4, FR_5, FR_6, FR_7, FR_8, FR_9, FR_10, FR_11 };

#define reg_is_saved(r) (((r) >= R_8 && (r) <= R_SP) || ((r) >= FR_12 && (r) <= FR_15) || ((r) == R_GBR) || ((r) == R_FPSCR))

#define ARCH_SWAP_CONDITION(cond, final_cond, reg1, reg2)	\
do {								\
	bool revert = false;					\
	bool swap = false;					\
	switch (cond) {						\
		case COND_NE:					\
			revert = true;				\
			break;					\
		case COND_B:					\
			swap = true;				\
			cond = COND_A;				\
			break;					\
		case COND_BE:					\
			swap = true;				\
			cond = COND_AE;				\
			break;					\
		case COND_L:					\
			swap = true;				\
			cond = COND_G;				\
			break;					\
		case COND_LE:					\
			swap = true;				\
			cond = COND_GE;				\
			break;					\
		case FP_COND_NE:				\
			revert = true;				\
			break;					\
		case FP_COND_BE:				\
			revert = true;				\
			break;					\
		case FP_COND_B:					\
			swap = true;				\
			cond = FP_COND_A;			\
			break;					\
		case FP_COND_AE:				\
			swap = true;				\
			revert = true;				\
			cond = FP_COND_BE;			\
			break;					\
	}							\
	if (swap) {						\
		unsigned r = reg1;				\
		reg1 = reg2;					\
		reg2 = r;					\
	}							\
	if (revert) {						\
		cond ^= 1;					\
		final_cond ^= 1;				\
	}							\
} while (0)

static bool imm_is_8bit(int32_t imm)
{
	return imm >= -0x80 && imm < 0x80;
}

static bool imm_is_16bit(int32_t imm)
{
	return imm >= -0x8000 && imm < 0x8000;
}

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint32_t c)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(reg);
	gen_one(ARG_IMM);
	gen_eight(c);
	return true;
}

#define DEFAULT_FP_PRECISION	(cpu_test_feature(CPU_FEATURE_sh4_float) ? 1 : 2)

#define SET_FP_PRECISION(rt)					\
do {								\
	if ((rt) != DEFAULT_FP_PRECISION)			\
		ctx->flips_fpscr = true;			\
								\
	g(gen_load_constant(ctx, R_0, ((rt) == 2) << 19));	\
								\
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);			\
	gen_one(R_FPSCR);					\
	gen_one(R_0);						\
} while (0)

static bool attr_w gen_address(struct codegen_context *ctx, unsigned base, int64_t imm, unsigned purpose, unsigned size)
{
	ctx->base_reg = base;
	ctx->offset_imm = imm;
	ctx->offset_reg = false;
	if (base == R_GBR) {
		if (imm_is_8bit(imm)) {
			gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
			gen_one(R_OFFSET_IMM);
			gen_one(R_GBR);
			gen_insn(INSN_ALU, OP_SIZE_4, ALU_ADD, 0);
			gen_one(R_OFFSET_IMM);
			gen_one(R_OFFSET_IMM);
			gen_one(ARG_IMM);
			gen_eight(imm);
		} else {
			g(gen_load_constant(ctx, R_CONST_IMM, imm));
			gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
			gen_one(R_OFFSET_IMM);
			gen_one(R_GBR);
			gen_insn(INSN_ALU, OP_SIZE_4, ALU_ADD, 0);
			gen_one(R_OFFSET_IMM);
			gen_one(R_OFFSET_IMM);
			gen_one(R_CONST_IMM);
		}
		ctx->base_reg = R_OFFSET_IMM;
		ctx->offset_imm = 0;
		return true;
	}
	if (!imm)
		return true;
	switch (purpose) {
		case IMM_PURPOSE_LDR_OFFSET:
		case IMM_PURPOSE_STR_OFFSET:
			if (size == OP_SIZE_4 && !(imm & 3) && imm >= 0 && imm < 64)
				return true;
	}
	g(gen_load_constant(ctx, R_OFFSET_IMM, imm));
	ctx->offset_reg = true;
	return true;
}

static bool is_direct_const(int32_t imm, unsigned purpose, unsigned attr_unused size)
{
	if (purpose == IMM_PURPOSE_ADD && imm >= -0x80 && imm < 0x80)
		return true;
	if (purpose == IMM_PURPOSE_SUB && imm > -0x80 && imm <= 0x80)
		return true;
	return false;
}

static bool attr_w gen_push(struct codegen_context *ctx, unsigned reg)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1_PRE_I);
	gen_one(R_SP);
	gen_eight(-4);
	gen_one(reg);
	return true;
}

static bool attr_w gen_pop(struct codegen_context *ctx, unsigned reg)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(reg);
	gen_one(ARG_ADDRESS_1_POST_I);
	gen_one(R_SP);
	gen_eight(4);
	return true;
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
	unsigned r;
	for (r = R_8; r <= R_14; r++)
		g(gen_push(ctx, r));
	if (!optimize_int) {
		for (r = FR_12; r <= FR_15; r++)
			g(gen_push(ctx, r));
	}
	g(gen_push(ctx, R_LR));
	g(gen_push(ctx, R_GBR));
	g(gen_push(ctx, R_ARG0));
	g(gen_push(ctx, R_ARG1));
	g(gen_push(ctx, R_ARG2));

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_GBR);
	gen_one(R_ARG0);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG3);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
	unsigned r;

	SET_FP_PRECISION(DEFAULT_FP_PRECISION);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_0);
	gen_one(R_GBR);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_1);
	gen_one(R_RET_IP);

	gen_insn(INSN_ALU, OP_SIZE_4, ALU_ADD, 0);
	gen_one(R_SP);
	gen_one(R_SP);
	gen_one(ARG_IMM);
	gen_eight(12);

	g(gen_pop(ctx, R_GBR));
	g(gen_pop(ctx, R_LR));

	if (!optimize_int) {
		for (r = FR_15; r >= FR_12; r--)
			g(gen_pop(ctx, r));
	}
	for (r = R_14; r >= R_8; r--)
		g(gen_pop(ctx, r));

	gen_insn(INSN_RET, 0, 0, 0);

	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
	return true;
}

static bool attr_w gen_get_upcall_pointer(struct codegen_context *ctx, unsigned offset, unsigned op_size, unsigned reg)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(reg);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(4);

	g(gen_address(ctx, reg, offset, IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(INSN_MOV, op_size, 0, 0);
	gen_one(reg);
	gen_address_offset();

	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args, bool unspill)
{
	g(gen_get_upcall_pointer(ctx, offset, OP_SIZE_4, R_3));

	SET_FP_PRECISION(DEFAULT_FP_PRECISION);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(12);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_GBR);
	gen_one(R_0);

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_4, 0, 0);
	gen_one(R_3);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_RET0);
	gen_one(R_0);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(8);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_GBR);
	gen_one(R_0);

	g(gen_upcall_end(ctx, offset, n_args, unspill));

	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label);

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_get_upcall_pointer(ctx, offsetof(struct cg_upcall_vector_s, ts), OP_SIZE_4, R_SCRATCH_1));

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0);

	g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_4, R_SCRATCH_1, R_SCRATCH_2, COND_NE, escape_label));

	return true;
}

static bool attr_w gen_callback(struct codegen_context *ctx, void (*callback)(void *ptr), void *ptr)
{
	g(gen_load_constant(ctx, R_ARG1, ptr_to_num(callback)));
	g(gen_load_constant(ctx, R_ARG0, ptr_to_num(ptr)));

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG1);

	return true;
}
