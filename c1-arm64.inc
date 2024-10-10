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

#define OP_SIZE_NATIVE			OP_SIZE_8
#define OP_SIZE_ADDRESS			OP_SIZE_8

#define JMP_LIMIT			JMP_LONG

#define UNALIGNED_TRAP			0

#define ALU_WRITES_FLAGS(alu, im)	0
#define ALU1_WRITES_FLAGS(alu)		0
#define ROT_WRITES_FLAGS(alu)		0
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		0
#define ARCH_IS_3ADDRESS		1
#define ARCH_HAS_FLAGS			1
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			1
#define ARCH_HAS_DIV			1
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	1
#define ARCH_HAS_BTX(btx, size, cnst)	0
#define ARCH_SHIFT_SIZE			OP_SIZE_4
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			maximum(size, OP_SIZE_4)
#define i_size_rot(size)		maximum(size, OP_SIZE_4)

#define R_0		0x00
#define R_1		0x01
#define R_2		0x02
#define R_3		0x03
#define R_4		0x04
#define R_5		0x05
#define R_6		0x06
#define R_7		0x07
#define R_8		0x08
#define R_9		0x09
#define R_10		0x0a
#define R_11		0x0b
#define R_12		0x0c
#define R_13		0x0d
#define R_14		0x0e
#define R_15		0x0f
#define R_16		0x10
#define R_17		0x11
#define R_18		0x12
#define R_19		0x13
#define R_20		0x14
#define R_21		0x15
#define R_22		0x16
#define R_23		0x17
#define R_24		0x18
#define R_25		0x19
#define R_26		0x1a
#define R_27		0x1b
#define R_28		0x1c
#define R_FP		0x1d
#define R_LR		0x1e
#define R_SP		0x1f

#define FR_0		0x20
#define FR_1		0x21
#define FR_2		0x22
#define FR_3		0x23
#define FR_4		0x24
#define FR_5		0x25
#define FR_6		0x26
#define FR_7		0x27
#define FR_8		0x28
#define FR_9		0x29
#define FR_10		0x2a
#define FR_11		0x2b
#define FR_12		0x2c
#define FR_13		0x2d
#define FR_14		0x2e
#define FR_15		0x2f
#define FR_16		0x30
#define FR_17		0x31
#define FR_18		0x32
#define FR_19		0x33
#define FR_20		0x34
#define FR_21		0x35
#define FR_22		0x36
#define FR_23		0x37
#define FR_24		0x38
#define FR_25		0x39
#define FR_26		0x3a
#define FR_27		0x3b
#define FR_28		0x3c
#define FR_29		0x3d
#define FR_30		0x3e
#define FR_31		0x3f

#define FRAME_SIZE	0x60

#define R_FRAME		R_28
#define R_UPCALL	R_27
#define R_TIMESTAMP	R_26
#define R_SAVED_1	R_25
#define R_SAVED_2	R_24
#define R_SAVED_3	R_23
#define R_SAVED_4	R_22
#define R_SAVED_5	R_21
#define R_SAVED_6	R_20
#define R_SAVED_7	R_19

#define R_SCRATCH_1	R_0
#define R_SCRATCH_2	R_1
#define R_SCRATCH_3	R_2
#define R_SCRATCH_4	R_3
#define R_SCRATCH_NA_1	R_8
#define R_SCRATCH_NA_2	R_9
#define R_SCRATCH_NA_3	R_10
#define R_OFFSET_IMM	R_16
#define R_CONST_IMM	R_17

#define R_ARG0		R_0
#define R_ARG1		R_1
#define R_ARG2		R_2
#define R_ARG3		R_3
#define R_RET0		R_0
#define R_RET1		R_1

#define FR_SCRATCH_1	FR_0
#define FR_SCRATCH_2	FR_1

#define SUPPORTED_FP		0x6
#define SUPPORTED_FP_HALF_CVT	0x1

static bool reg_is_fp(unsigned reg)
{
	return reg >= 0x20 && reg < 0x40;
}

static const uint8_t reg_available[] = { R_SAVED_7, R_SAVED_6, R_SAVED_5, R_SAVED_4, R_SAVED_3 };
#define n_reg_available n_array_elements(reg_available)
#define reg_is_saved(r)	1

struct logical_imm {
	uint64_t value;
	uint16_t code;
};

static const struct logical_imm value_to_code_4_table[] = {
#include "arm64-w.inc"
};

static const struct logical_imm value_to_code_8_table[] = {
#include "arm64-x.inc"
};

static int16_t value_to_code(uint8_t size, uint64_t value)
{
	size_t result;
	if (size == OP_SIZE_4) {
		binary_search(size_t, n_array_elements(value_to_code_4_table), result, value_to_code_4_table[result].value == value, value_to_code_4_table[result].value < value, return -1);
		return value_to_code_4_table[result].code;
	} else {
		binary_search(size_t, n_array_elements(value_to_code_8_table), result, value_to_code_8_table[result].value == value, value_to_code_8_table[result].value < value, return -1);
		return value_to_code_8_table[result].code;
	}
}

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	int16_t code;

	if (c < 0x10000)
		goto skip_lookup;

	code = value_to_code(OP_SIZE_4, c);
	if (code >= 0) {
		gen_insn(INSN_ALU, OP_SIZE_4, ALU_OR, 0);
		gen_one(reg);
		gen_one(0x1f);
		gen_one(ARG_IMM);
		gen_eight(c);
		return true;
	}

	code = value_to_code(OP_SIZE_8, c);
	if (code >= 0) {
		gen_insn(INSN_ALU, OP_SIZE_8, ALU_OR, 0);
		gen_one(reg);
		gen_one(0x1f);
		gen_one(ARG_IMM);
		gen_eight(c);
		return true;
	}

skip_lookup:
	if ((int64_t)c < 0) {
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight((c & 0xffff) | 0xffffffffffff0000ULL);
		if ((c & 0xffff0000ULL) != 0xffff0000ULL) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_8, MOV_MASK_16_32, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((c >> 16) & 0xffff);
		}
		if ((c & 0xffff00000000ULL) != 0xffff00000000ULL) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_8, MOV_MASK_32_48, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((c >> 32) & 0xffff);
		}
		if ((c & 0xffff000000000000ULL) != 0xffff000000000000ULL) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_8, MOV_MASK_48_64, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((c >> 48) & 0xffff);
		}
	} else {
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_one(reg);
		gen_one(ARG_IMM);
		gen_eight(c & 0xffff);
		if (c & 0xffff0000ULL) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_8, MOV_MASK_16_32, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((c >> 16) & 0xffff);
		}
		if (c & 0xffff00000000ULL) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_8, MOV_MASK_32_48, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((c >> 32) & 0xffff);
		}
		if (c & 0xffff000000000000ULL) {
			gen_insn(INSN_MOV_MASK, OP_SIZE_8, MOV_MASK_48_64, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((c >> 48) & 0xffff);
		}
	}
	return true;
}

static bool attr_w gen_address(struct codegen_context *ctx, unsigned base, int64_t imm, unsigned purpose, unsigned size)
{
	ctx->base_reg = base;
	ctx->offset_imm = imm;
	ctx->offset_reg = false;
	switch (purpose) {
		case IMM_PURPOSE_LDR_OFFSET:
		case IMM_PURPOSE_LDR_SX_OFFSET:
		case IMM_PURPOSE_STR_OFFSET:
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			if (likely(imm >= -256) && likely(imm <= 255))
				return true;
			if (likely(imm >= 0)) {
				if (unlikely((imm & ((1 << size) - 1)) != 0))
					break;
				if (likely((imm >> size) <= 4095))
					return true;
			}
			break;
		case IMM_PURPOSE_LDP_STP_OFFSET:
			if (unlikely((imm & ((1 << size) - 1)) != 0))
				break;
			if (imm / (1 << size) >= -64 && imm / (1 << size) <= 63)
				return true;
			break;
		default:
			internal(file_line, "gen_address: invalid purpose %d", purpose);
	}
	g(gen_load_constant(ctx, R_OFFSET_IMM, imm));
	if (purpose == IMM_PURPOSE_LDP_STP_OFFSET) {
		gen_insn(INSN_ALU, OP_SIZE_ADDRESS, ALU_ADD, 0);
		gen_one(R_OFFSET_IMM);
		gen_one(R_OFFSET_IMM);
		gen_one(base);
		ctx->base_reg = R_OFFSET_IMM;
		ctx->offset_imm = 0;
		return true;
	}
	ctx->offset_reg = true;
	return true;

}

static bool is_direct_const(int64_t imm, unsigned purpose, unsigned size)
{
	switch (purpose) {
		case IMM_PURPOSE_STORE_VALUE:
			if (!imm)
				return true;
			break;
		case IMM_PURPOSE_ADD:
		case IMM_PURPOSE_SUB:
		case IMM_PURPOSE_CMP:
		case IMM_PURPOSE_CMP_LOGICAL:
			if (imm >= 0 && imm < 4096)
				return true;
			break;
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
		case IMM_PURPOSE_ANDN:
		case IMM_PURPOSE_TEST:
			if (value_to_code(size, imm) >= 0)
				return true;
			break;
		case IMM_PURPOSE_MUL:
			break;
		default:
			internal(file_line, "is_direct_const: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}
	return false;
}

static bool attr_w gen_imm(struct codegen_context *ctx, int64_t imm, unsigned purpose, unsigned size)
{
	if (is_direct_const(imm, purpose, size)) {
		ctx->const_imm = imm;
		ctx->const_reg = false;
	} else {
		g(gen_load_constant(ctx, R_CONST_IMM, imm));
		ctx->const_reg = true;
	}
	return true;
}

static bool attr_w gen_entry(struct codegen_context *ctx)
{
	gen_insn(INSN_STP, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1_PRE_I);
	gen_one(R_SP);
	gen_eight(-FRAME_SIZE);
	gen_one(R_FP);
	gen_one(R_LR);

	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(R_FP);
	gen_one(R_SP);

	gen_insn(INSN_STP, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x10);
	gen_one(R_UPCALL);
	gen_one(R_FRAME);

	gen_insn(INSN_STP, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x20);
	gen_one(R_SAVED_1);
	gen_one(R_TIMESTAMP);

	gen_insn(INSN_STP, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x30);
	gen_one(R_SAVED_3);
	gen_one(R_SAVED_2);

	gen_insn(INSN_STP, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x40);
	gen_one(R_SAVED_5);
	gen_one(R_SAVED_4);

	gen_insn(INSN_STP, OP_SIZE_8, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x50);
	gen_one(R_SAVED_7);
	gen_one(R_SAVED_6);

	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG0);

	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_ARG1);

	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(R_TIMESTAMP);
	gen_one(R_ARG2);

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_ARG3);

	return true;
}

static bool attr_w gen_escape_arg(struct codegen_context *ctx, ip_t ip, uint32_t escape_label)
{
	g(gen_load_constant(ctx, R_RET1, ip));

	gen_insn(INSN_JMP, 0, 0, 0);
	gen_four(escape_label);

	return true;
}

static bool attr_w gen_escape(struct codegen_context *ctx)
{
	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(R_RET0);
	gen_one(R_FRAME);

	gen_insn(INSN_LDP, OP_SIZE_8, 0, 0);
	gen_one(R_SAVED_7);
	gen_one(R_SAVED_6);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x50);

	gen_insn(INSN_LDP, OP_SIZE_8, 0, 0);
	gen_one(R_SAVED_5);
	gen_one(R_SAVED_4);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x40);

	gen_insn(INSN_LDP, OP_SIZE_8, 0, 0);
	gen_one(R_SAVED_3);
	gen_one(R_SAVED_2);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x30);

	gen_insn(INSN_LDP, OP_SIZE_8, 0, 0);
	gen_one(R_SAVED_1);
	gen_one(R_TIMESTAMP);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x20);

	gen_insn(INSN_LDP, OP_SIZE_8, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_FRAME);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(0x10);

	gen_insn(INSN_LDP, OP_SIZE_8, 0, 0);
	gen_one(R_FP);
	gen_one(R_LR);
	gen_one(ARG_ADDRESS_1_POST_I);
	gen_one(R_SP);
	gen_eight(FRAME_SIZE);

	gen_insn(INSN_RET, 0, 0, 0);

	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned n_args)
{
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
	gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_8, 0, 0);
	gen_one(R_SCRATCH_NA_1);

	g(gen_upcall_end(ctx, n_args));

	return true;
}

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	gen_insn(INSN_CMP, OP_SIZE_4, 0, 1);
	gen_one(R_SCRATCH_1);
	gen_one(R_TIMESTAMP);

	gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
	gen_four(escape_label);

	return true;
}
