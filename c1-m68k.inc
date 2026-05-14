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

#define JMP_LIMIT			JMP_LONG

#define UNALIGNED_TRAP			0

#define ALU_WRITES_FLAGS(size, alu, is_mem, is_imm, imm)	((alu) == ALU_ADD && (size) == OP_SIZE_4 ? 0 : 1)
#define ALU1_WRITES_FLAGS(alu)		1
#define ROT_WRITES_FLAGS(alu, size, im)	1
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		((size) <= OP_SIZE_2)
#define ARCH_IS_3ADDRESS(alu, f)	((alu) == ALU_ADD && !(f))
#define ARCH_IS_3ADDRESS_IMM(alu, f)	((alu) == ALU_ADD && !(f))
#define ARCH_IS_3ADDRESS_ROT(alu, size)	0
#define ARCH_IS_3ADDRESS_ROT_IMM(alu)	0
#define ARCH_IS_2ADDRESS(alu)		((alu) == ALU1_LZCNT)
#define ARCH_IS_3ADDRESS_FP		0
#define ARCH_HAS_JMP_REG(cond)		0
#define ARCH_HAS_JMP_2REGS(cond)	0
#define ARCH_HAS_DELAY_SLOTS(insn)	0
#define ARCH_HAS_FUSED_MEMORY_ACCESSES	0
#define ARCH_HAS_FLAGS			1
#define ARCH_PREFERS_SX(size)		1
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			1
#define ARCH_HAS_ANDN			0
#define ARCH_HAS_2REG_M(st, fp, sh, im)	1
#define ARCH_HAS_BTX(btx, size, cnst)	((btx) != BTX_BTEXT && (size) == OP_SIZE_4)
#define ARCH_HAS_SHIFTED_ADD(bits)	((bits) <= 3)
#define ARCH_HAS_CMOV			0
#define ARCH_SHIFT_SIZE			OP_SIZE_8
#define ARCH_BOOL_SIZE			log_2(sizeof(ajla_flat_option_t))
#define ARCH_HAS_FP_GP_MOV		0
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			(size)
#define i_size_rot(size)		(size)
#define i_size_cmp(size)		(size)

#define CALLBACK_NEEDS_TRAMPOLINE
static void *callback_trampoline;

#define RD0				0
#define RD1				1
#define RD2				2
#define RD3				3
#define RD4				4
#define RD5				5
#define RD6				6
#define RD7				7

#define RA0				8
#define RA1				9
#define RA2				10
#define RA3				11
#define RA4				12
#define RA5				13
#define RA6				14
#define RSP				15

#define RFP0				16
#define RFP1				17
#define RFP2				18
#define RFP3				19
#define RFP4				20
#define RFP5				21
#define RFP6				22
#define RFP7				23

#define R_MAX				24

#define R_IS_D(r)			((r) <= RD7)
#define R_IS_A(r)			((r) >= RA0 && (r) <= RSP)
#define R_IS_DA(r)			((r) <= RSP)
static bool reg_is_fp(unsigned reg)
{
	return reg >= RFP0 && reg <= RFP7;
}

#define R_SCRATCH_1			RD0
#define R_SCRATCH_2			RD1
#define R_SCRATCH_3			RD2
#define R_SCRATCH_4			RD3
#define R_TMP_D				RD7

#define R_TMP_A				RA0
#define R_SAVED_1			RA2
#define R_SAVED_2			R_SCRATCH_4
#define R_FRAME				RA6

#define FR_SCRATCH_1			RFP0
#define FR_SCRATCH_2			RFP1

#define R_ARG0				RD0
#define R_ARG1				RD0
#define R_ARG2				RD0
#define R_ARG3				RD0
#define R_RET0				RD0
#define R_RET1				RD1

#define SUPPORTED_FP			0
#define SUPPORTED_FP_CVT(f, t)		(0 && (f) >= 1 && (f) <= 3 && (t) >= 1 && (t) <= 3)
#define FP_REGISTERS(real_size)		1

#define ARG_SPACE			16
#define ARG_OFFSET			((6 + 5 + 1) * 4)

static const uint8_t regs_saved[] = { RD4, RD5, RD6, RD7 };
static const uint8_t regs_volatile[] = { 0 };
#define n_regs_volatile 0U
static const uint8_t regs_address[] = { RA3, RA4, RA5, RA1 };
static const uint8_t fp_saved[] = { 0 };
#define n_fp_saved(real_type) 0U
static const uint8_t fp_volatile[] = { 0 };
#define n_fp_volatile(real_type) 0U

#define reg_is_saved(r) (((r) >= RD2 && (r) <= RD7) || ((r) >= RA2 && (r) <= RSP) || ((r) >= RFP2 && (r) <= RFP7))

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

static bool attr_w gen_address(struct codegen_context *ctx, unsigned base, int32_t imm, unsigned attr_unused purpose, unsigned attr_unused size)
{
	ctx->base_reg = base;
	ctx->offset_imm = imm;
	ctx->offset_reg = false;
	return true;
}

static bool is_direct_const(int32_t attr_unused imm, unsigned attr_unused purpose, unsigned attr_unused size)
{
	return true;
}

static bool is_direct_offset(int64_t attr_unused imm)
{
	return true;
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
	gen_insn(INSN_M68K_PUSH, OP_SIZE_4, 0, 0);

	gen_insn(INSN_ALU, OP_SIZE_4, ALU_SUB, 0);
	gen_one(RSP);
	gen_one(RSP);
	gen_one(ARG_IMM);
	gen_eight(ARG_SPACE);

	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_FRAME);
	gen_one(ARG_ADDRESS_1);
	gen_one(RSP);
	gen_eight(ARG_SPACE + ARG_OFFSET);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(RSP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 12);

	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
	g(gen_load_constant(ctx, RD1, ip));
	gen_insn(INSN_JMP, 0, 0, 0);
	gen_label_ref(escape_label);
	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(RD0);
	gen_one(R_FRAME);

	gen_insn(INSN_ALU, OP_SIZE_4, ALU_ADD, 0);
	gen_one(RSP);
	gen_one(RSP);
	gen_one(ARG_IMM);
	gen_eight(ARG_SPACE);

	gen_insn(INSN_M68K_POP, OP_SIZE_4, 0, 0);

	gen_insn(INSN_RET, 0, 0, 0);

	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
	ajla_assert_lo(arg * 4 < ARG_SPACE, (file_line, "gen_upcall_argument: argument %u", arg));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(RSP);
	gen_eight(arg * 4);
	gen_one(R_ARG0);

	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args, bool unspill)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_TMP_A);
	gen_one(ARG_ADDRESS_1);
	gen_one(RSP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 4);

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_TMP_A);
	gen_eight(offset);

	g(gen_upcall_end(ctx, offset, n_args, unspill));

	return true;
}

static bool attr_w gen_get_upcall_pointer(struct codegen_context *ctx, unsigned offset, unsigned op_size, unsigned reg)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_TMP_A);
	gen_one(ARG_ADDRESS_1);
	gen_one(RSP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 4);

	gen_insn(INSN_MOV, op_size, 0, 0);
	gen_one(reg);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_TMP_A);
	gen_eight(offset);

	return true;
}

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_get_upcall_pointer(ctx, offsetof(struct cg_upcall_vector_s, ts), OP_SIZE_4, R_SCRATCH_1));

	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_SCRATCH_1);
	gen_one(ARG_ADDRESS_1);
	gen_one(RSP);
	gen_eight(ARG_SPACE + ARG_OFFSET + 8);

	gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
	gen_label_ref(escape_label);

	return true;
}

static bool attr_w gen_callback_trampoline(struct codegen_context *ctx)
{
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(ARG_ADDRESS_1_PRE_I);
	gen_one(RSP);
	gen_eight(-4);
	gen_one(RA1);

	gen_insn(INSN_CALL_INDIRECT, 0, 0, 0);
	gen_one(RA0);

	gen_insn(INSN_ALU, OP_SIZE_4, ALU_ADD, 1);
	gen_one(RSP);
	gen_one(RSP);
	gen_one(ARG_IMM);
	gen_eight(4);

	gen_insn(INSN_RET, 0, 0, 0);

	return true;
}

static bool attr_w gen_callback(struct codegen_context *ctx, void (*callback)(void *ptr), void *ptr)
{
	g(gen_load_constant(ctx, RA0, ptr_to_num(callback)));
	g(gen_load_constant(ctx, RA1, ptr_to_num(ptr)));

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(ARG_IMM);
	gen_eight(ptr_to_num(callback_trampoline));

	return true;
}
