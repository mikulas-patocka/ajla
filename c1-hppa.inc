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

#define PA_20				cpu_test_feature(CPU_FEATURE_pa20)

#if defined(ARCH_PARISC64)
#define ARCH_PARISC_USE_STUBS
#elif defined(__hpux)
#define ARCH_PARISC_USE_STUBS
#endif

#define OP_SIZE_NATIVE			(PA_20 ? OP_SIZE_8 : OP_SIZE_4)

#ifdef ARCH_PARISC32
#define OP_SIZE_ADDRESS			OP_SIZE_4
#else
#define OP_SIZE_ADDRESS			OP_SIZE_8
#endif

#define JMP_LIMIT			JMP_EXTRA_LONG

#define UNALIGNED_TRAP			1

#define ALU_WRITES_FLAGS(alu, im)	((alu) == ALU_ADC || (alu) == ALU_SUB || (alu) == ALU_SBB ? 3 : 0)
#define ALU1_WRITES_FLAGS(alu)		((alu) == ALU1_NEG || (alu) == ALU1_INC || (alu) == ALU1_DEC ? 3 : 0)
#define ROT_WRITES_FLAGS(alu)		0
#define COND_IS_LOGICAL(cond)		0

#define ARCH_PARTIAL_ALU(size)		0
#define ARCH_IS_3ADDRESS		1
#define ARCH_HAS_FLAGS			0
#define ARCH_SUPPORTS_TRAPS		1
#define ARCH_PREFERS_SX(size)		0
#define ARCH_HAS_BWX			1
#define ARCH_HAS_MUL			0
#define ARCH_HAS_DIV			0
#define ARCH_HAS_ANDN			1
#define ARCH_HAS_SHIFTED_ADD(bits)	((bits) <= 3)
#define ARCH_HAS_BTX(btx, size, cnst)	(((btx) == BTX_BTS || (btx) == BTX_BTR || (btx) == BTX_BTEXT) && (((size) >= OP_SIZE_4)))
#define ARCH_SHIFT_SIZE			OP_SIZE_4
#define ARCH_NEEDS_BARRIER		0

#define i_size(size)			OP_SIZE_NATIVE
#define i_size_rot(size)		maximum(size, OP_SIZE_4)

#define R_ZERO		0x00
#define R_1		0x01
#define R_RP		0x02
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
#define R_DP		0x1b
#define R_RET0		0x1c
#define R_RET1		0x1d
#define R_SP		0x1e
#define R_31		0x1f

#define R_FSTATUS	0x20
#define R_F4		0x24
#define R_F5		0x25
#define R_F6		0x26
#define R_F7		0x27
#define R_F8		0x28
#define R_F9		0x29
#define R_F10		0x2a
#define R_F11		0x2b
#define R_F12		0x2c
#define R_F13		0x2d
#define R_F14		0x2e
#define R_F15		0x2f
#define R_F16		0x30
#define R_F17		0x31
#define R_F18		0x32
#define R_F19		0x33
#define R_F20		0x34
#define R_F21		0x35
#define R_F22		0x36
#define R_F23		0x37
#define R_F24		0x38
#define R_F25		0x39
#define R_F26		0x3a
#define R_F27		0x3b
#define R_F28		0x3c
#define R_F29		0x3d
#define R_F30		0x3e
#define R_F31		0x3f

#define R_FRAME		R_3
#define R_UPCALL	R_4
#define R_TIMESTAMP	R_5

#define R_SCRATCH_1	R_26
#define R_SCRATCH_2	R_25
#define R_SCRATCH_3	R_24
#define R_SCRATCH_4	R_23

#define R_SCRATCH_NA_1	R_22
#define R_SCRATCH_NA_2	R_21
#define R_SCRATCH_NA_3	R_20
#define R_CMP_RESULT	R_19

#define R_CG_SCRATCH	R_31

#define R_SAVED_1	R_6
#define R_SAVED_2	R_7

#define R_ARG0		R_26
#define R_ARG1		R_25
#define R_ARG2		R_24
#define R_ARG3		R_23

#define R_CONST_IMM	R_1
#define R_OFFSET_IMM	R_RET1

#define FR_SCRATCH_1	R_F4
#define FR_SCRATCH_2	R_F5

#define SUPPORTED_FP	0x6

#ifdef ARCH_PARISC32
#define FRAME_SIZE	0x80
/*
 * 0-20		- register save area
 * 20-64	- unused
 * 64-96	- outgoing parameters
 * 96-128	- frame marker
 */
#else
#define FRAME_SIZE	0x80
/*
 * 0-40		- register save area
 * 40-48	- unused
 * 48-112	- outgoing parameters
 * 112-128	- frame marker
 */
#endif

#ifdef ARCH_PARISC32
#define RP_OFFS	-0x14
#else
#define RP_OFFS -0x10
#endif

#if defined(ARCH_PARISC_USE_STUBS)
#if defined(ARCH_PARISC32)
static char *codegen_stub_alloc(struct codegen_context *ctx, char *code)
{
	uint32_t *stub = mem_alloc_mayfail(uint32_t *, sizeof(uint32_t) * 3, &ctx->err);
	if (unlikely(!stub))
		return NULL;
	stub[0] = ptr_to_num(code);
	stub[1] = 0;
	stub[2] = ptr_to_num(code) + ctx->entry_size;
	return cast_ptr(char *, stub) + 2;
}
#define codegen_stub_alloc	codegen_stub_alloc
#define codegen_stub_free(stub)	mem_free(cast_ptr(char *, stub) - 2)
#else
static char *codegen_stub_alloc(struct codegen_context *ctx, char *code)
{
	uint64_t *stub = mem_alloc_mayfail(uint64_t *, sizeof(uint64_t) * 4, &ctx->err);
	if (unlikely(!stub))
		return NULL;
	stub[0] = ptr_to_num(code) + ctx->entry_size;
	stub[1] = 0;
	stub[2] = ptr_to_num(code);
	stub[3] = 0;
	return cast_ptr(char *, stub);
}
#define codegen_stub_alloc	codegen_stub_alloc
#define codegen_stub_free(stub)	mem_free(stub)
#endif
#endif

static bool reg_is_fp(unsigned reg)
{
	return reg >= R_FSTATUS && reg < R_F31;
}

static bool attr_w gen_load_constant(struct codegen_context *ctx, unsigned reg, uint64_t c)
{
	unsigned r = R_ZERO;
	int32_t c1, c2, c3, c4;
	c1 = c & 0x3fffULL;
	if (c1 & 0x2000)
		c1 |= 0xffffc000U;
	if (c1 < 0)
		c += 0x4000ULL;
	c2 = (c & 0xffffc000ULL) >> 14;
	if (c2 & 0x20000)
		c2 |= 0xfffc0000U;
	if (c2 < 0)
		c += 0x100000000ULL;
	c >>= 32;
	c3 = c & 0x3fffULL;
	if (c3 & 0x2000)
		c3 |= 0xffffc000U;
	if (c3 < 0)
		c += 0x4000ULL;
	c4 = (c & 0xffffc000ULL) >> 14;
	if (c4 & 0x20000)
		c4 |= 0xfffc0000U;
	if (OP_SIZE_NATIVE == OP_SIZE_8) {
		if (c4) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((uint64_t)c4 << 14);
			r = reg;
		}
		if (c3) {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
			gen_one(reg);
			gen_one(r);
			gen_one(ARG_IMM);
			gen_eight(c3);
			r = reg;
		}
		if (r != R_ZERO) {
			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHL, 0);
			gen_one(reg);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight(32);
		}
	}
	if (c2) {
		if (r == R_ZERO) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(reg);
			gen_one(ARG_IMM);
			gen_eight((uint64_t)c2 << 14);
			r = reg;
		} else {
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
			gen_one(R_CONST_IMM);
			gen_one(r);
			gen_one(ARG_IMM);
			gen_eight((uint64_t)c2 << 14);
			r = R_CONST_IMM;
		}
	}
	if (c1 || r != reg) {
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, 0);
		gen_one(reg);
		gen_one(r);
		gen_one(ARG_IMM);
		gen_eight(c1);
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
		case IMM_PURPOSE_MVI_CLI_OFFSET:
			if (size == OP_SIZE_8) {
				if (imm & 7)
					break;
			}
			if (likely(imm >= -0x2000) && likely(imm < 0x2000))
				return true;
			break;
		case IMM_PURPOSE_VLDR_VSTR_OFFSET:
			if (likely(imm >= -0x10) && likely(imm < 0x10))
				return true;
			if (!PA_20)
				break;
			if (unlikely((imm & ((1 << size) - 1)) != 0))
				break;
			if (likely(imm >= -0x2000) && likely(imm < 0x2000))
				return true;
			break;
		default:
			internal(file_line, "gen_address: invalid purpose %u (imm %"PRIxMAX", size %u)", purpose, (uintmax_t)imm, size);
	}
	g(gen_load_constant(ctx, R_OFFSET_IMM, imm));

	if (purpose == IMM_PURPOSE_LDR_OFFSET || purpose == IMM_PURPOSE_LDR_SX_OFFSET) {
		ctx->offset_reg = true;
		return true;
	}

	gen_insn(INSN_ALU, OP_SIZE_ADDRESS, ALU_ADD, 0);
	gen_one(R_OFFSET_IMM);
	gen_one(R_OFFSET_IMM);
	gen_one(base);
	ctx->base_reg = R_OFFSET_IMM;
	ctx->offset_imm = 0;

	return true;
}

static bool is_direct_const(int64_t imm, unsigned purpose, unsigned size)
{
	int64_t imm_copy = imm;
	switch (purpose) {
		case IMM_PURPOSE_STORE_VALUE:
			if (!imm)
				return true;
			break;
		case IMM_PURPOSE_SUB:
			imm_copy = -(uint64_t)imm_copy;
			/*-fallthrough*/
		case IMM_PURPOSE_ADD:
		case IMM_PURPOSE_CMP:
		case IMM_PURPOSE_CMP_LOGICAL:
		case IMM_PURPOSE_MOVR:
			if (likely(imm_copy >= -1024) && likely(imm_copy < 1024))
				return true;
			break;
		case IMM_PURPOSE_JMP_2REGS:
#ifdef ARCH_PARISC32
			if (likely(imm >= -16) && likely(imm < 16))
				return true;
#endif
			break;
		case IMM_PURPOSE_AND:
		case IMM_PURPOSE_OR:
		case IMM_PURPOSE_XOR:
		case IMM_PURPOSE_ANDN:
		case IMM_PURPOSE_TEST:
			if (!imm)
				return true;
			break;
		case IMM_PURPOSE_BITWISE:
			return true;
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
	int i;

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(RP_OFFS);
	gen_one(R_RP);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(ARG_ADDRESS_1_POST_I);
	gen_one(R_SP);
	gen_eight(FRAME_SIZE);
	gen_one(R_3);

	for (i = R_4; i <= R_7; i++) {
		int offs = -FRAME_SIZE + ((i - R_3) << OP_SIZE_ADDRESS);
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SP);
		gen_eight(offs);
		gen_one(i);
	}

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_FRAME);
	gen_one(R_ARG0);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_UPCALL);
	gen_one(R_ARG1);

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
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
	int i;

	gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
	gen_one(R_RET0);
	gen_one(R_FRAME);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_RP);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SP);
	gen_eight(-FRAME_SIZE + RP_OFFS);

	for (i = R_4; i <= R_7; i++) {
		int offs = -FRAME_SIZE + ((i - R_3) << OP_SIZE_ADDRESS);
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(i);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SP);
		gen_eight(offs);
	}

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_3);
	gen_one(ARG_ADDRESS_1_PRE_I);
	gen_one(R_SP);
	gen_eight(-FRAME_SIZE);

	gen_insn(INSN_RET, 0, 0, 0);

	return true;
}

static bool attr_w gen_upcall_argument(struct codegen_context attr_unused *ctx, unsigned attr_unused arg)
{
	return true;
}

static bool attr_w gen_upcall(struct codegen_context *ctx, unsigned offset, unsigned attr_unused n_args)
{
#ifdef ARCH_PARISC32
	uint32_t label = alloc_call_label(ctx);
	if (unlikely(!label))
		return false;

	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	gen_insn(INSN_CALL, 0, 0, 0);
	gen_four(label);
#else
	g(gen_address(ctx, R_UPCALL, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_DP);
	gen_address_offset();

	gen_insn(INSN_CALL_INDIRECT, OP_SIZE_8, 0, 0);
	gen_one(R_DP);
#endif
	return true;
}

static bool attr_w gen_call_millicode(struct codegen_context *ctx)
{
	gen_insn(INSN_CALL_MILLICODE, 0, 0, 0);
	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label);

static bool attr_w gen_timestamp_test(struct codegen_context *ctx, uint32_t escape_label)
{
	g(gen_address(ctx, R_UPCALL, offsetof(struct cg_upcall_vector_s, ts), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
	gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_4, R_SCRATCH_1, R_TIMESTAMP, COND_NE, escape_label));

	return true;
}
