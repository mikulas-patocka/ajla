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

#include "ajla.h"

#ifndef FILE_OMIT

#include "data.h"
#include "os.h"
#include "os_util.h"
#include "util.h"
#include "ipfn.h"
#include "ipret.h"
#include "funct.h"
#include "thread.h"
#include "task.h"
#include "save.h"

#include "codegen.h"

#ifdef HAVE_CODEGEN

#define INLINE_BITMAP_SLOTS		16
#define INLINE_COPY_SIZE		64

/*#define DEBUG_INSNS*/

code_return_t (*codegen_entry)(frame_s *, struct cg_upcall_vector_s *, tick_stamp_t, void *);
static void *codegen_ptr;
static size_t codegen_size;

/*
 * insn:
 *	opcode		- 16 bits
 *	op_size		- 3 bits
 *	aux		- 7 bits
 *	writes flags	- 2 bit
 *	jmp size	- 2 bits
 */

#define INSN_OPCODE			0x0000ffffUL
#define INSN_OP_SIZE			0x00070000UL
#define INSN_AUX			0x03f80000UL
#define INSN_WRITES_FLAGS		0x0c000000UL
#define INSN_JUMP_SIZE			0x30000000UL

#define INSN_OPCODE_SHIFT		0
#define INSN_OP_SIZE_SHIFT		16
#define INSN_AUX_SHIFT			19
#define INSN_WRITES_FLAGS_SHIFT		26
#define INSN_JUMP_SIZE_SHIFT		28

#define insn_opcode(insn)		(((insn) >> INSN_OPCODE_SHIFT) & (INSN_OPCODE >> INSN_OPCODE_SHIFT))
#define insn_op_size(insn)		(((insn) >> INSN_OP_SIZE_SHIFT) & (INSN_OP_SIZE >> INSN_OP_SIZE_SHIFT))
#define insn_aux(insn)			(((insn) >> INSN_AUX_SHIFT) & (INSN_AUX >> INSN_AUX_SHIFT))
#define insn_writes_flags(insn)		(((insn) >> INSN_WRITES_FLAGS_SHIFT) & (INSN_WRITES_FLAGS >> INSN_WRITES_FLAGS_SHIFT))
#define insn_jump_size(insn)		(((insn) >> INSN_JUMP_SIZE_SHIFT) & (INSN_JUMP_SIZE >> INSN_JUMP_SIZE_SHIFT))

#define ALU_ADD				0x00
#define ALU_OR				0x01
#define ALU_ADC				0x02
#define ALU_SBB				0x03
#define ALU_AND				0x04
#define ALU_SUB				0x05
#define ALU_XOR				0x06
#define ALU_ORN				0x08
#define ALU_ANDN			0x09
#define ALU_XORN			0x0a
#define ALU_MUL				0x10
#define ALU_UMULH			0x11
#define ALU_SMULH			0x12
#define ALU_UDIV			0x13
#define ALU_SDIV			0x14
#define ALU_UREM			0x15
#define ALU_SREM			0x16
#define ALU_SAVE			0x17
#define ALU_EXTBL			0x18
#define ALU_EXTWL			0x19
#define ALU_EXTLL			0x1a
#define ALU_EXTLH			0x1b
#define ALU_INSBL			0x1c
#define ALU_MSKBL			0x1d
#define ALU_ZAP				0x20
#define ALU_ZAPNOT			0x21

#define ALU1_NOT			0x00
#define ALU1_NEG			0x01
#define ALU1_NGC			0x02
#define ALU1_INC			0x03
#define ALU1_DEC			0x04
#define ALU1_BSWAP			0x05
#define ALU1_BSWAP16			0x06
#define ALU1_BREV			0x07
#define ALU1_BSF			0x08
#define ALU1_BSR			0x09
#define ALU1_LZCNT			0x0a
#define ALU1_POPCNT			0x0b

#define FP_ALU_ADD			0
#define FP_ALU_SUB			1
#define FP_ALU_MUL			2
#define FP_ALU_DIV			3
#define FP_ALU1_NEG			0
#define FP_ALU1_SQRT			1
#define FP_ALU1_VCNT8			2
#define FP_ALU1_VPADDL			3
#define FP_ALU1_ADDV			4

#define COND_O				0x0
#define COND_NO				0x1
#define COND_B				0x2
#define COND_AE				0x3
#define COND_E				0x4
#define COND_NE				0x5
#define COND_BE				0x6
#define COND_A				0x7
#define COND_S				0x8
#define COND_NS				0x9
#define COND_P				0xa
#define COND_NP				0xb
#define COND_L				0xc
#define COND_GE				0xd
#define COND_LE				0xe
#define COND_G				0xf
#define COND_BLBC			0x10
#define COND_BLBS			0x11
#define COND_ALWAYS			0x12

#define COND_FP				0x20
#define FP_COND_P			(COND_FP | COND_P)
#define FP_COND_NP			(COND_FP | COND_NP)
#define FP_COND_E			(COND_FP | COND_E)
#define FP_COND_NE			(COND_FP | COND_NE)
#define FP_COND_A			(COND_FP | COND_A)
#define FP_COND_BE			(COND_FP | COND_BE)
#define FP_COND_B			(COND_FP | COND_B)
#define FP_COND_AE			(COND_FP | COND_AE)

#define ROT_ROL				0x0
#define ROT_ROR				0x1
#define ROT_RCL				0x2
#define ROT_RCR				0x3
#define ROT_SHL				0x4
#define ROT_SHR				0x5
#define ROT_SAR				0x7
#define ROT_SAL				0x8

#define BTX_BT				0x0
#define BTX_BTS				0x1
#define BTX_BTR				0x2
#define BTX_BTC				0x3
#define BTX_BTEXT			0x4

#define OP_SIZE_1			0
#define OP_SIZE_2			1
#define OP_SIZE_4			2
#define OP_SIZE_8			3
#define OP_SIZE_16			4
#define OP_SIZE_10			7

#define MOV_MASK_0_16			0x0
#define MOV_MASK_16_32			0x1
#define MOV_MASK_32_48			0x2
#define MOV_MASK_48_64			0x3
#define MOV_MASK_0_8			0x4
#define MOV_MASK_32_64			0x5
#define MOV_MASK_52_64			0x6

#define JMP_SHORTEST			0x0000
#define JMP_SHORT			0x0001
#define JMP_LONG			0x0002
#define JMP_EXTRA_LONG			0x0003

enum {
	INSN_ENTRY,
	INSN_LABEL,
	INSN_RET,
	INSN_RET_IMM,
	INSN_ARM_PUSH,
	INSN_ARM_POP,
	INSN_S390_PUSH,
	INSN_S390_POP,
	INSN_IA64_ALLOC,
	INSN_IA64_DEALLOC,
	INSN_PUSH,
	INSN_POP,
	INSN_CALL,
	INSN_CALL_INDIRECT,
	INSN_MOV,
	INSN_MOVSX,
	INSN_MOV_U,
	INSN_MOV_LR,
	INSN_CMP,
	INSN_CMP_DEST_REG,
	INSN_CMN,
	INSN_TEST,
	INSN_TEST_DEST_REG,
	INSN_ALU,
	INSN_ALU_PARTIAL,
	INSN_ALU_FLAGS,
	INSN_ALU_FLAGS_PARTIAL,
	INSN_ALU_TRAP,
	INSN_ALU_FLAGS_TRAP,
	INSN_ALU1,
	INSN_ALU1_PARTIAL,
	INSN_ALU1_FLAGS,
	INSN_ALU1_FLAGS_PARTIAL,
	INSN_ALU1_TRAP,
	INSN_LEA3,
	INSN_ROT,
	INSN_ROT_PARTIAL,
	INSN_BT,
	INSN_BTX,
	INSN_MUL_L,
	INSN_DIV_L,
	INSN_MADD,
	INSN_CBW,
	INSN_CBW_PARTIAL,
	INSN_CWD,
	INSN_CWD_PARTIAL,
	INSN_SET_COND,
	INSN_CMOV,
	INSN_CMOV_XCC,
	INSN_MOVR,
	INSN_CSEL_SEL,
	INSN_CSEL_INC,
	INSN_CSEL_INV,
	INSN_CSEL_NEG,
	INSN_STP,
	INSN_LDP,
	INSN_MOV_MASK,
	INSN_MEMCPY,
	INSN_MEMSET,
	INSN_FP_CMP,
	INSN_FP_CMP_DEST_REG,
	INSN_FP_CMP_DEST_REG_TRAP,
	INSN_FP_CMP_UNORDERED_DEST_REG,
	INSN_FP_CMP_COND,
	INSN_FP_TEST_REG,
	INSN_FP_TO_INT_FLAGS,
	INSN_FP_ALU,
	INSN_FP_ALU1,
	INSN_FP_TO_INT32,
	INSN_FP_TO_INT64,
	INSN_FP_TO_INT64_TRAP,
	INSN_FP_FROM_INT32,
	INSN_FP_FROM_INT64,
	INSN_FP_INT64_TO_INT32_TRAP,
	INSN_FP_CVT,
	INSN_X87_FLD,
	INSN_X87_FILD,
	INSN_X87_FSTP,
	INSN_X87_FISTP,
	INSN_X87_FISTTP,
	INSN_X87_FCOMP,
	INSN_X87_FCOMPP,
	INSN_X87_FCOMIP,
	INSN_X87_ALU,
	INSN_X87_ALUP,
	INSN_X87_FCHS,
	INSN_X87_FSQRT,
	INSN_X87_FNSTSW,
	INSN_X87_FLDCW,
	INSN_JMP,
	INSN_JMP_COND,
	INSN_JMP_COND_LOGICAL,
	INSN_JMP_REG,
	INSN_JMP_REG_BIT,
	INSN_JMP_2REGS,
	INSN_JMP_FP_TEST,
	INSN_JMP_INDIRECT,
	INSN_MB,
	INSN_CALL_MILLICODE,
};

#define ARG_REGS_MAX			0xc0
#define ARG_SHIFTED_REGISTER		0xc0
#define  ARG_SHIFT_AMOUNT			0x3f
#define  ARG_SHIFT_MODE				0xc0
#define  ARG_SHIFT_LSL				0x00
#define  ARG_SHIFT_LSR				0x40
#define  ARG_SHIFT_ASR				0x80
#define  ARG_SHIFT_ROR				0xc0
#define ARG_EXTENDED_REGISTER		0xc1
#define  ARG_EXTEND_SHIFT			0x07
#define  ARG_EXTEND_MODE			0x38
#define  ARG_EXTEND_UXTB			0x00
#define  ARG_EXTEND_UXTH			0x08
#define  ARG_EXTEND_UXTW			0x10
#define  ARG_EXTEND_UXTX			0x18
#define  ARG_EXTEND_SXTB			0x20
#define  ARG_EXTEND_SXTH			0x28
#define  ARG_EXTEND_SXTW			0x30
#define  ARG_EXTEND_SXTX			0x38
#define ARG_ADDRESS_0			0xd0
#define ARG_ADDRESS_1			0xd1
#define ARG_ADDRESS_1_2			0xd2
#define ARG_ADDRESS_1_4			0xd3
#define ARG_ADDRESS_1_8			0xd4
#define ARG_ADDRESS_1_PRE_I		0xd5
#define ARG_ADDRESS_1_POST_I		0xd6
#define ARG_ADDRESS_2			0xd7
#define ARG_ADDRESS_2_2			0xd8
#define ARG_ADDRESS_2_4			0xd9
#define ARG_ADDRESS_2_8			0xda
#define ARG_ADDRESS_2_UXTW		0xdb
#define ARG_ADDRESS_2_SXTW		0xdc
#define ARG_IMM				0xe0

#define ARG_IS_ADDRESS(a)		((a) >= ARG_ADDRESS_0 && (a) <= ARG_ADDRESS_2_SXTW)

#ifdef POINTER_COMPRESSION
#define OP_SIZE_SLOT		OP_SIZE_4
#else
#define OP_SIZE_SLOT		OP_SIZE_ADDRESS
#endif

#define OP_SIZE_BITMAP		(bitmap_64bit ? OP_SIZE_8 : OP_SIZE_4)

#define OP_SIZE_INT		log_2(sizeof(int_default_t))

#define check_insn(insn)						\
do {									\
	/*if ((insn_opcode(insn) == INSN_ALU || insn_opcode(insn) == INSN_ALU1) && insn_op_size(insn) != OP_SIZE_NATIVE) internal(file_line, "invalid insn %08x", (unsigned)(insn));*/\
	/*if (insn == 0x001a000e) internal(file_line, "invalid insn %08x", insn);*/\
} while (0)

#ifdef DEBUG_INSNS
#define gen_line()	gen_four(__LINE__)
#else
#define gen_line()	do { } while (0)
#endif

#define flag_cache_chicken	0

#ifdef ARCH_IA64
#define ARCH_CONTEXT struct {						\
	uint64_t insns[3];						\
	uint8_t insn_units[3];						\
	bool insn_stops[3];						\
	uint64_t wr_mask[4];						\
}
#endif

#define gen_insn(opcode, op_size, aux, writes_flags)			\
do {									\
	uint32_t dword = 						\
		(uint32_t)(opcode) << INSN_OPCODE_SHIFT |		\
		(uint32_t)(op_size) << INSN_OP_SIZE_SHIFT |		\
		(uint32_t)(aux) << INSN_AUX_SHIFT |			\
		(uint32_t)(writes_flags) << INSN_WRITES_FLAGS_SHIFT;	\
	check_insn(dword);						\
	gen_line();							\
	gen_four(dword);						\
} while (0)

static size_t arg_size(uint8_t arg)
{
	if (arg < ARG_REGS_MAX)
		return 1;
	if (arg >= ARG_SHIFTED_REGISTER && arg <= ARG_EXTENDED_REGISTER)
		return 3;
	if (arg == ARG_ADDRESS_0)
		return 9;
	if (arg >= ARG_ADDRESS_1 && arg <= ARG_ADDRESS_1_POST_I)
		return 10;
	if (arg >= ARG_ADDRESS_2 && arg <= ARG_ADDRESS_2_SXTW)
		return 11;
	if (arg == ARG_IMM)
		return 9;
	internal(file_line, "arg_size: invalid argument %02x", arg);
	return 0;
}

struct relocation {
	uint32_t label_id;
	uint8_t length;
	size_t position;
	size_t jmp_instr;
};

struct code_arg {
	frame_t slot;
	frame_t flags;
	frame_t type;
};

struct codegen_context {
	struct data *fn;
	struct data **local_directory;

	const code_t *instr_start;
	const code_t *current_position;
	uchar_efficient_t arg_mode;

	uint32_t label_id;
	frame_t n_entries;

	uint8_t *code;
	size_t code_size;

	uint8_t *code_position;

	uint32_t *code_labels;
	uint32_t *escape_labels;
	uint32_t call_label;
	uint32_t reload_label;

	uint8_t *mcode;
	size_t mcode_size;

	size_t *label_to_pos;
	size_t *entry_to_pos;
	struct relocation *reloc;
	size_t reloc_size;

	struct trap_record *trap_records;
	size_t trap_records_size;

	struct code_arg *args;
	size_t args_l;
	const code_t *return_values;

	int8_t *flag_cache;

	unsigned base_reg;
	bool offset_reg;
	int64_t offset_imm;

	bool const_reg;
	int64_t const_imm;

	struct data *codegen;

	ajla_error_t err;

#ifdef ARCH_CONTEXT
	ARCH_CONTEXT a;
#endif
};

static void init_ctx(struct codegen_context *ctx)
{
	ctx->local_directory = NULL;
	ctx->label_id = 0;
	ctx->n_entries = 0;
	ctx->code = NULL;
	ctx->code_labels = NULL;
	ctx->escape_labels = NULL;
	ctx->call_label = 0;
	ctx->reload_label = 0;
	ctx->mcode = NULL;
	ctx->label_to_pos = NULL;
	ctx->entry_to_pos = NULL;
	ctx->reloc = NULL;
	ctx->trap_records = NULL;
	ctx->args = NULL;
	ctx->flag_cache = NULL;
	ctx->codegen = NULL;
}

static void done_ctx(struct codegen_context *ctx)
{
	if (ctx->local_directory)
		mem_free(ctx->local_directory);
	if (ctx->code)
		mem_free(ctx->code);
	if (ctx->code_labels)
		mem_free(ctx->code_labels);
	if (ctx->escape_labels)
		mem_free(ctx->escape_labels);
	if (ctx->mcode)
		mem_free(ctx->mcode);
	if (ctx->label_to_pos)
		mem_free(ctx->label_to_pos);
	if (ctx->entry_to_pos)
		mem_free(ctx->entry_to_pos);
	if (ctx->reloc)
		mem_free(ctx->reloc);
	if (ctx->trap_records)
		mem_free(ctx->trap_records);
	if (ctx->args)
		mem_free(ctx->args);
	if (ctx->flag_cache)
		mem_free(ctx->flag_cache);
	if (ctx->codegen)
		data_free(ctx->codegen);
}

static uint32_t alloc_label(struct codegen_context *ctx)
{
	return ++ctx->label_id;
}

static uint32_t alloc_escape_label(struct codegen_context *ctx)
{
	ip_t ip = ctx->instr_start - da(ctx->fn,function)->code;
	if (!ctx->escape_labels[ip]) {
		ctx->escape_labels[ip] = alloc_label(ctx);
	}
	return ctx->escape_labels[ip];
}

static uint32_t attr_unused alloc_call_label(struct codegen_context *ctx)
{
	if (!ctx->call_label) {
		ctx->call_label = alloc_label(ctx);
	}
	return ctx->call_label;
}

static uint32_t alloc_reload_label(struct codegen_context *ctx)
{
	if (!ctx->reload_label) {
		ctx->reload_label = alloc_label(ctx);
	}
	return ctx->reload_label;
}

#define g(call)								\
do {									\
	if (unlikely(!call))						\
		return false;						\
} while (0)

#define gen_one(byte)							\
do {									\
	/*debug("gen %d: %02x", __LINE__, (uint8_t)(byte))*/;		\
	if (unlikely(!array_add_mayfail(uint8_t, &ctx->code, &ctx->code_size, byte, NULL, &ctx->err)))\
		return false;						\
} while (0)

#if defined(C_LITTLE_ENDIAN)
#define gen_two(word)							\
do {									\
	uint16_t word_ = (word);					\
	/*debug("gen %d: %04x", __LINE__, (uint16_t)(word_));*/		\
	if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->code, &ctx->code_size, cast_ptr(uint8_t *, &word_), 2, NULL, &ctx->err)))\
		return false;						\
} while (0)
#define gen_four(dword)							\
do {									\
	uint32_t dword_ = (dword);					\
	/*debug("gen %d: %08x", __LINE__, (uint32_t)(dword_));*/	\
	if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->code, &ctx->code_size, cast_ptr(uint8_t *, &dword_), 4, NULL, &ctx->err)))\
		return false;						\
} while (0)
#define gen_eight(qword)						\
do {									\
	uint64_t qword_ = (qword);					\
	/*debug("gen %d: %016lx", __LINE__, (uint64_t)(qword_));*/	\
	if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->code, &ctx->code_size, cast_ptr(uint8_t *, &qword_), 8, NULL, &ctx->err)))\
		return false;						\
} while (0)
#else
#define gen_two(word)							\
do {									\
	uint16_t word_ = (word);					\
	gen_one(word_ & 0xffU);						\
	gen_one(word_ >> 8);						\
} while (0)
#define gen_four(dword)							\
do {									\
	uint32_t dword_ = (dword);					\
	gen_two(dword_ & 0xffffU);					\
	gen_two(dword_ >> 15 >> 1);					\
} while (0)
#define gen_eight(qword)						\
do {									\
	uint64_t qword_ = (qword);					\
	gen_four(qword_ & 0xffffffffUL);				\
	gen_four(qword_ >> 15 >> 15 >> 2);				\
} while (0)
#endif

#define gen_label(label_id)						\
do {									\
	gen_insn(INSN_LABEL, 0, 0, 0);					\
	gen_four(label_id);						\
} while (0)


static uint8_t attr_unused cget_one(struct codegen_context *ctx)
{
	ajla_assert(ctx->code_position < ctx->code + ctx->code_size, (file_line, "cget_one: ran out of code"));
	return *ctx->code_position++;
}

static uint16_t attr_unused cget_two(struct codegen_context *ctx)
{
#if defined(C_LITTLE_ENDIAN)
	uint16_t r;
	ajla_assert(ctx->code_position < ctx->code + ctx->code_size, (file_line, "cget_two: ran out of code"));
	memcpy(&r, ctx->code_position, 2);
	ctx->code_position += 2;
	return r;
#else
	uint16_t r = cget_one(ctx);
	r |= cget_one(ctx) << 8;
	return r;
#endif
}

static uint32_t cget_four(struct codegen_context *ctx)
{
#if defined(C_LITTLE_ENDIAN)
	uint32_t r;
	ajla_assert(ctx->code_position < ctx->code + ctx->code_size, (file_line, "cget_four: ran out of code"));
	memcpy(&r, ctx->code_position, 4);
	ctx->code_position += 4;
	return r;
#else
	uint32_t r = cget_two(ctx);
	r |= (uint32_t)cget_two(ctx) << 16;
	return r;
#endif
}

static uint64_t attr_unused cget_eight(struct codegen_context *ctx)
{
#if defined(C_LITTLE_ENDIAN)
	uint64_t r;
	ajla_assert(ctx->code_position < ctx->code + ctx->code_size, (file_line, "cget_eight: ran out of code"));
	memcpy(&r, ctx->code_position, 8);
	ctx->code_position += 8;
	return r;
#else
	uint64_t r = cget_four(ctx);
	r |= (uint64_t)cget_four(ctx) << 32;
	return r;
#endif
}

static int64_t get_imm(uint8_t *ptr)
{
#if defined(C_LITTLE_ENDIAN)
	int64_t r;
	memcpy(&r, ptr, 8);
	return r;
#else
	int64_t r;
	r = (uint64_t)ptr[0] |
	    ((uint64_t)ptr[1] << 8) |
	    ((uint64_t)ptr[2] << 16) |
	    ((uint64_t)ptr[3] << 24) |
	    ((uint64_t)ptr[4] << 32) |
	    ((uint64_t)ptr[5] << 40) |
	    ((uint64_t)ptr[6] << 48) |
	    ((uint64_t)ptr[7] << 56);
	return r;
#endif
}

#define cgen_one(byte)							\
do {									\
	if (unlikely(!array_add_mayfail(uint8_t, &ctx->mcode, &ctx->mcode_size, byte, NULL, &ctx->err)))\
		return false;						\
} while (0)

#if defined(C_LITTLE_ENDIAN) || 1
#define cgen_two(word)							\
do {									\
	uint16_t word_ = (word);					\
	if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->mcode, &ctx->mcode_size, cast_ptr(uint8_t *, &word_), 2, NULL, &ctx->err)))\
		return false;						\
} while (0)
#define cgen_four(dword)						\
do {									\
	uint32_t dword_ = (dword);					\
	/*if (dword_ == 0x1ee02000) internal(file_line, "invalid instruction");*/\
	if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->mcode, &ctx->mcode_size, cast_ptr(uint8_t *, &dword_), 4, NULL, &ctx->err)))\
		return false;						\
} while (0)
#define cgen_eight(qword)						\
do {									\
	uint64_t qword_ = (qword);					\
	if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->mcode, &ctx->mcode_size, cast_ptr(uint8_t *, &qword_), 8, NULL, &ctx->err)))\
		return false;						\
} while (0)
#else
#define cgen_two(word)							\
do {									\
	cgen_one((word) & 0xff);					\
	cgen_one((word) >> 8);						\
} while (0)
#define cgen_four(dword)						\
do {									\
	cgen_two((dword) & 0xffff);					\
	cgen_two((dword) >> 15 >> 1);					\
} while (0)
#define cgen_eight(qword)						\
do {									\
	cgen_four((qword) & 0xffffffff);				\
	cgen_four((qword) >> 15 >> 15 >> 2);				\
} while (0)
#endif


#define IMM_PURPOSE_LDR_OFFSET		1
#define IMM_PURPOSE_LDR_SX_OFFSET	2
#define IMM_PURPOSE_STR_OFFSET		3
#define IMM_PURPOSE_LDP_STP_OFFSET	4
#define IMM_PURPOSE_VLDR_VSTR_OFFSET	5
#define IMM_PURPOSE_MVI_CLI_OFFSET	6
#define IMM_PURPOSE_STORE_VALUE		7
#define IMM_PURPOSE_ADD			8
#define IMM_PURPOSE_SUB			9
#define IMM_PURPOSE_CMP			10
#define IMM_PURPOSE_CMP_LOGICAL		11
#define IMM_PURPOSE_AND			12
#define IMM_PURPOSE_OR			13
#define IMM_PURPOSE_XOR			14
#define IMM_PURPOSE_ANDN		15
#define IMM_PURPOSE_TEST		16
#define IMM_PURPOSE_JMP_2REGS		17
#define IMM_PURPOSE_MUL			18
#define IMM_PURPOSE_CMOV		19
#define IMM_PURPOSE_MOVR		20
#define IMM_PURPOSE_BITWISE		21


static bool attr_w gen_extend(struct codegen_context *ctx, unsigned op_size, bool sx, unsigned dest, unsigned src);

#define gen_address_offset()						\
do {									\
	if (likely(!ctx->offset_reg)) {					\
		gen_one(ARG_ADDRESS_1);					\
		gen_one(ctx->base_reg);					\
		gen_eight(ctx->offset_imm);				\
	} else {							\
		gen_one(ARG_ADDRESS_2);					\
		gen_one(ctx->base_reg);					\
		gen_one(R_OFFSET_IMM);					\
		gen_eight(0);						\
	}								\
} while (0)

#define gen_imm_offset()						\
do {									\
	if (likely(!ctx->const_reg)) {					\
		gen_one(ARG_IMM);					\
		gen_eight(ctx->const_imm);				\
	} else {							\
		gen_one(R_CONST_IMM);					\
	}								\
} while (0)

#define is_imm()	(!ctx->const_reg)


#if defined(ARCH_ALPHA)
#include "c1-alpha.inc"
#elif defined(ARCH_ARM32)
#include "c1-arm.inc"
#elif defined(ARCH_ARM64)
#include "c1-arm64.inc"
#elif defined(ARCH_IA64)
#include "c1-ia64.inc"
#elif defined(ARCH_LOONGARCH64)
#include "c1-loong.inc"
#elif defined(ARCH_MIPS)
#include "c1-mips.inc"
#elif defined(ARCH_PARISC)
#include "c1-hppa.inc"
#elif defined(ARCH_POWER)
#include "c1-power.inc"
#elif defined(ARCH_S390)
#include "c1-s390.inc"
#elif defined(ARCH_SPARC)
#include "c1-sparc.inc"
#elif defined(ARCH_RISCV64)
#include "c1-riscv.inc"
#elif defined(ARCH_X86)
#include "c1-x86.inc"
#endif


#ifndef ARCH_SUPPORTS_TRAPS
#define ARCH_SUPPORTS_TRAPS	0
#endif


#if !defined(POINTER_COMPRESSION)
#define gen_pointer_compression(base)		do { } while (0)
#define gen_address_offset_compressed()		gen_address_offset()
#elif defined(ARCH_X86)
#define gen_pointer_compression(base)		do { } while (0)
#define gen_address_offset_compressed()					\
do {									\
	if (likely(!ctx->offset_reg)) {					\
		gen_one(ARG_ADDRESS_1 + POINTER_COMPRESSION);		\
		gen_one(ctx->base_reg);					\
		gen_eight(ctx->offset_imm);				\
	} else {							\
		gen_one(ARG_ADDRESS_2 + POINTER_COMPRESSION);		\
		gen_one(R_OFFSET_IMM);					\
		gen_one(ctx->base_reg);					\
		gen_eight(0);						\
	}								\
} while (0)
#else
#define gen_pointer_compression(base)					\
do {									\
	if (ARCH_PREFERS_SX(OP_SIZE_4)) {				\
		g(gen_extend(ctx, OP_SIZE_4, false, base, base));\
									\
		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(OP_SIZE_ADDRESS), OP_SIZE_ADDRESS, ROT_SHL, ROT_WRITES_FLAGS(ROT_SHL));\
		gen_one(base);						\
		gen_one(base);						\
		gen_one(ARG_IMM);					\
		gen_eight(POINTER_COMPRESSION);				\
	} else {							\
		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(OP_SIZE_ADDRESS), OP_SIZE_ADDRESS, ROT_SHL, ROT_WRITES_FLAGS(ROT_SHL));\
		gen_one(base);						\
		gen_one(base);						\
		gen_one(ARG_IMM);					\
		gen_eight(POINTER_COMPRESSION);				\
	}								\
} while (0)
#define gen_address_offset_compressed()		gen_address_offset()
#endif


#if defined(C_LITTLE_ENDIAN)
#define lo_word(size)		(0)
#define hi_word(size)		((size_t)1 << (size))
#elif defined(C_BIG_ENDIAN)
#define lo_word(size)		((size_t)1 << (size))
#define hi_word(size)		(0)
#else
endian not defined
#endif


static const struct type *get_type_of_local(struct codegen_context *ctx, frame_t pos)
{
	const struct type *t;
	const struct data *function = ctx->fn;
	t = da(function,function)->local_variables[pos].type;
	if (t)
		TYPE_TAG_VALIDATE(t->tag);
	return t;
}

static bool attr_w clear_flag_cache(struct codegen_context *ctx)
{
	memset(ctx->flag_cache, 0, function_n_variables(ctx->fn) * sizeof(int8_t));
	return true;
}

/*#define clear_flag_cache(ctx)	\
	(debug("clearing flag cache @ %d", __LINE__), memset((ctx)->flag_cache, 0, function_n_variables(ctx->fn) * sizeof(int8_t)), true)*/

static bool attr_w gen_3address_alu(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src1, unsigned src2)
{
	if (unlikely(dest == src2) && (alu == ALU_ADD || alu == ALU_OR || alu == ALU_AND || alu == ALU_XOR || alu == ALU_MUL || alu == ALU_UMULH || alu == ALU_SMULH)) {
		unsigned swap = src1;
		src1 = src2;
		src2 = swap;
	}
	if (unlikely(dest == src2)) {
		internal(file_line, "gen_3address_alu: invalid registers: %u, %u, %x, %x, %x", size, alu, dest, src1, src2);
	}
	if (!ARCH_IS_3ADDRESS && dest != src1
#if defined(ARCH_X86)
		&& alu != ALU_ADD
#endif
	    ) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(dest);
		gen_one(src1);

		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(alu, false));
		gen_one(dest);
		gen_one(dest);
		gen_one(src2);

		return true;
	}
	gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(alu, false));
	gen_one(dest);
	gen_one(src1);
	gen_one(src2);
	return true;
}

static bool attr_w gen_3address_alu_imm(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src, int64_t imm)
{
	unsigned purpose =
		alu == ALU_ADD ? IMM_PURPOSE_ADD :
		alu == ALU_SUB ? IMM_PURPOSE_SUB :
		alu == ALU_MUL ? IMM_PURPOSE_MUL :
		alu == ALU_UMULH ? IMM_PURPOSE_MUL :
		alu == ALU_SMULH ? IMM_PURPOSE_MUL :
		alu == ALU_ANDN ? IMM_PURPOSE_ANDN :
		alu == ALU_AND ? IMM_PURPOSE_AND :
		alu == ALU_OR ? IMM_PURPOSE_OR :
		alu == ALU_XOR ? IMM_PURPOSE_XOR :
		alu == ALU_EXTBL ? IMM_PURPOSE_OR :
		alu == ALU_EXTWL ? IMM_PURPOSE_OR :
		alu == ALU_EXTLL ? IMM_PURPOSE_OR :
		alu == ALU_EXTLH ? IMM_PURPOSE_OR :
		alu == ALU_INSBL ? IMM_PURPOSE_OR :
		alu == ALU_MSKBL ? IMM_PURPOSE_OR :
		alu == ALU_ZAP ? IMM_PURPOSE_ANDN :
		alu == ALU_ZAPNOT ? IMM_PURPOSE_AND :
		-1U;
	if (unlikely(purpose == -1U))
		internal(file_line, "gen_3address_alu_imm: invalid parameters: size %u, alu %u, dest %u, src %u, imm %"PRIxMAX"", size, alu, dest, src, (uintmax_t)imm);
	if (
		dest != src
#if !defined(ARCH_S390)
		&& !ARCH_IS_3ADDRESS
#endif
#if defined(ARCH_X86)
		&& alu != ALU_ADD
#endif
	    ) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(dest);
		gen_one(src);

		g(gen_imm(ctx, imm, purpose, i_size(OP_SIZE_ADDRESS)));
		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(alu, is_imm()));
		gen_one(dest);
		gen_one(dest);
		gen_imm_offset();

		return true;
	}
	g(gen_imm(ctx, imm, purpose, i_size(OP_SIZE_ADDRESS)));
	gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, ALU_WRITES_FLAGS(alu, is_imm()));
	gen_one(dest);
	gen_one(src);
	gen_imm_offset();

	return true;
}

static bool attr_w attr_unused gen_3address_rot(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src1, unsigned src2)
{
	if (unlikely(dest == src2))
		internal(file_line, "gen_3address_rot: invalid registers: %u, %u, %x, %x, %x", size, alu, dest, src1, src2);
	if (!ARCH_IS_3ADDRESS && dest != src1) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(dest);
		gen_one(src1);

		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu));
		gen_one(dest);
		gen_one(dest);
		gen_one(src2);

		return true;
	}
	gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu));
	gen_one(dest);
	gen_one(src1);
	gen_one(src2);

	return true;
}

static bool attr_w gen_3address_rot_imm(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned dest, unsigned src, int64_t imm, unsigned writes_flags)
{
	if (!ARCH_IS_3ADDRESS && dest != src) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(dest);
		gen_one(src);

		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu) | writes_flags);
		gen_one(dest);
		gen_one(dest);
		gen_one(ARG_IMM);
		gen_eight(imm);

		return true;
	}
	gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(size), size, alu, ROT_WRITES_FLAGS(alu) | writes_flags);
	gen_one(dest);
	gen_one(src);
	gen_one(ARG_IMM);
	gen_eight(imm);
	return true;
}

static bool attr_w attr_unused gen_load_two(struct codegen_context *ctx, unsigned dest, unsigned src, int64_t offset)
{
	if (!ARCH_HAS_BWX) {
		if (!(offset & 7)) {
			g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
			gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
			gen_one(dest);
			gen_address_offset();

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTWL, dest, dest, src));
		} else {
			g(gen_imm(ctx, offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
			gen_one(R_OFFSET_IMM);
			gen_one(src);
			gen_imm_offset();

			gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
			gen_one(dest);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_OFFSET_IMM);
			gen_eight(0);

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTWL, dest, dest, R_OFFSET_IMM));
		}
#if defined(ARCH_S390)
	} else if (!cpu_test_feature(CPU_FEATURE_extended_imm)) {
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_2));
		gen_insn(INSN_MOVSX, OP_SIZE_2, 0, 0);
		gen_one(dest);
		gen_address_offset();

		g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_AND, dest, dest, 0xffff));
#endif
	} else {
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_2));
		gen_insn(INSN_MOV, OP_SIZE_2, 0, 0);
		gen_one(dest);
		gen_address_offset();
	}
	return true;
}

static bool attr_w gen_load_code_32(struct codegen_context *ctx, unsigned dest, unsigned src, int64_t offset)
{
#if ARG_MODE_N == 3 && defined(ARCH_ALPHA) && !(defined(C_BIG_ENDIAN) ^ CODE_ENDIAN)
	if (!ARCH_HAS_BWX && UNALIGNED_TRAP) {
		if (offset & 7) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_ADD, R_OFFSET_IMM, src, offset));
			src = R_OFFSET_IMM;
			offset = 0;
		}
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
		gen_one(dest);
		gen_address_offset();

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTLL, dest, dest, src));

		g(gen_address(ctx, src, offset + 3, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_NATIVE, 0, 0);
		gen_one(R_CONST_IMM);
		gen_address_offset();

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_EXTLH, R_CONST_IMM, R_CONST_IMM, src));

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, dest, dest, R_CONST_IMM));

		return true;
	}
#endif
#if ARG_MODE_N == 3 && defined(ARCH_MIPS) && !(defined(C_BIG_ENDIAN) ^ CODE_ENDIAN)
	if (!MIPS_R6 && UNALIGNED_TRAP) {
		g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
		gen_insn(INSN_MOV_LR, OP_SIZE_4, !CODE_ENDIAN, 0);
		gen_one(dest);
		gen_one(dest);
		gen_address_offset();

		g(gen_address(ctx, src, offset + 3, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_4));
		gen_insn(INSN_MOV_LR, OP_SIZE_4, CODE_ENDIAN, 0);
		gen_one(dest);
		gen_one(dest);
		gen_address_offset();

		return true;
	}
#endif
#if ARG_MODE_N == 3
#if !(defined(C_BIG_ENDIAN) ^ CODE_ENDIAN)
	if (UNALIGNED_TRAP)
#endif
	{
		g(gen_load_two(ctx, dest, src, offset));
		g(gen_load_two(ctx, R_CONST_IMM, src, offset + 2));
#if CODE_ENDIAN
		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, dest, dest, 16, false));
#else
		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_CONST_IMM, R_CONST_IMM, 16, false));
#endif
		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, dest, dest, R_CONST_IMM));
		return true;
	}
#endif
	g(gen_address(ctx, src, offset, IMM_PURPOSE_LDR_OFFSET, ARG_MODE_N - 1));
	gen_insn(INSN_MOV, ARG_MODE_N - 1, 0, 0);
	gen_one(dest);
	gen_address_offset();
	return true;
}

static bool attr_w gen_cmp_dest_reg(struct codegen_context *ctx, unsigned attr_unused size, unsigned reg1, unsigned reg2, unsigned reg_dest, int64_t imm, unsigned cond)
{
	unsigned neg_result = false;

	if (reg2 == (unsigned)-1)
		g(gen_imm(ctx, imm, IMM_PURPOSE_CMP, i_size(size)));
#if defined(ARCH_ALPHA)
	if (cond == COND_NE) {
		gen_insn(INSN_CMP_DEST_REG, i_size(size), COND_E, 0);
		gen_one(reg_dest);
		gen_one(reg1);
		if (reg2 == (unsigned)-1)
			gen_imm_offset();
		else
			gen_one(reg2);
		neg_result = true;
		goto done;
	}
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_RISCV64)
	if (cond == COND_E || cond == COND_NE) {
		gen_insn(INSN_ALU, i_size(size), ALU_XOR, ALU_WRITES_FLAGS(ALU_XOR, reg2 == (unsigned)-1 ? is_imm() : false));
		gen_one(reg_dest);
		gen_one(reg1);
		if (reg2 == (unsigned)-1)
			gen_imm_offset();
		else
			gen_one(reg2);

		if (cond == COND_E) {
			g(gen_imm(ctx, 1, IMM_PURPOSE_CMP, i_size(size)));
			gen_insn(INSN_CMP_DEST_REG, i_size(size), COND_B, 0);
			gen_one(reg_dest);
			gen_one(reg_dest);
			gen_imm_offset();
		} else {
			gen_insn(INSN_CMP_DEST_REG, i_size(size), COND_B, 0);
			gen_one(reg_dest);
			gen_one(ARG_IMM);
			gen_eight(0);
			gen_one(reg_dest);
		}
		goto done;
	}
	if (cond == COND_GE || cond == COND_LE || cond == COND_AE || cond == COND_BE) {
		cond ^= 1;
		neg_result = true;
	}
#endif
#if defined(ARCH_IA64)
	gen_insn(INSN_CMP_DEST_REG, i_size(size), cond, 0);
	gen_one(R_CMP_RESULT);
	gen_one(reg1);
	if (reg2 == (unsigned)-1)
		gen_imm_offset();
	else
		gen_one(reg2);

	if (reg_dest != R_CMP_RESULT) {
		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(reg_dest);
		gen_one(R_CMP_RESULT);
	}

	goto done;
#endif
	gen_insn(INSN_CMP_DEST_REG, i_size(size), cond, 0);
	gen_one(reg_dest);
	gen_one(reg1);
	if (reg2 == (unsigned)-1)
		gen_imm_offset();
	else
		gen_one(reg2);

	goto done;
done:
	if (neg_result)
		g(gen_3address_alu_imm(ctx, i_size(size), ALU_XOR, reg_dest, reg_dest, 1));

	return true;
}

static bool attr_w gen_cmp_test_jmp(struct codegen_context *ctx, unsigned insn, unsigned op_size, unsigned reg1, unsigned reg2, unsigned cond, uint32_t label)
{
	bool arch_use_flags = ARCH_HAS_FLAGS;
#if defined(ARCH_ARM64)
	if (insn == INSN_TEST && reg1 == reg2 && (cond == COND_E || cond == COND_NE))
		arch_use_flags = false;
#endif
#if defined(ARCH_SPARC)
	if (insn == INSN_TEST && reg1 == reg2)
		arch_use_flags = false;
#endif
	if (arch_use_flags) {
		if (COND_IS_LOGICAL(cond)) {
			gen_insn(insn, op_size, 0, 2);
			gen_one(reg1);
			gen_one(reg2);

			gen_insn(INSN_JMP_COND_LOGICAL, op_size, cond, 0);
			gen_four(label);

			return true;
		}

		gen_insn(insn, op_size, 0, 1);
		gen_one(reg1);
		gen_one(reg2);

#if defined(ARCH_POWER) || defined(ARCH_S390)
		if (insn == INSN_TEST) {
			if (cond == COND_S)
				cond = COND_L;
			if (cond == COND_NS)
				cond = COND_GE;
		}
#endif
		gen_insn(INSN_JMP_COND, op_size, cond, 0);
		gen_four(label);
	} else {
		if (insn == INSN_CMP) {
#if defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_RISCV64)
			gen_insn(INSN_JMP_2REGS, op_size, cond, 0);
			gen_one(reg1);
			gen_one(reg2);
			gen_four(label);
			return true;
#else
#ifdef R_CMP_RESULT
#if defined(ARCH_MIPS)
			if (cond == COND_E || cond == COND_NE) {
				gen_insn(INSN_JMP_2REGS, op_size, cond, 0);
				gen_one(reg1);
				gen_one(reg2);
				gen_four(label);
				return true;
			}
			if (cond == COND_AE || cond == COND_BE || cond == COND_LE || cond == COND_GE) {
				cond ^= 1;
			}
#endif
#if defined(ARCH_ALPHA)
			if (cond == COND_NE) {
				g(gen_3address_alu(ctx, op_size, ALU_XOR, R_CMP_RESULT, reg1, reg2));
			} else
#endif
			{
				gen_insn(INSN_CMP_DEST_REG, op_size, cond, 0);
				gen_one(R_CMP_RESULT);
				gen_one(reg1);
				gen_one(reg2);
			}

			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
			gen_one(R_CMP_RESULT);
			gen_four(label);
#else
			internal(file_line, "gen_cmp_test_jmp: R_CMP_RESULT not defined");
#endif
#endif
		} else if (insn == INSN_TEST) {
			if (reg1 != reg2) {
				internal(file_line, "gen_cmp_test_jmp: INSN_TEST with two distinct registers is unsupported");
			}
#if defined(ARCH_IA64)
			if (cond == COND_S)
				cond = COND_L;
			if (cond == COND_NS)
				cond = COND_GE;
			g(gen_imm(ctx, 0, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_imm_offset();

			reg1 = R_CMP_RESULT;
			cond = COND_NE;
#endif
			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(reg1);
			gen_four(label);
		}
	}
	return true;
}

static bool attr_w gen_cmp_test_imm_jmp(struct codegen_context *ctx, unsigned insn, unsigned attr_unused op_size, unsigned reg1, int64_t value, unsigned cond, uint32_t label)
{
	if (insn == INSN_TEST && (cond == COND_E || cond == COND_NE) && is_power_of_2((uint64_t)value)) {
#ifdef HAVE_BUILTIN_CTZ
		unsigned attr_unused bit = __builtin_ctzll(value);
#else
		unsigned attr_unused bit = 0;
		uint64_t v = value;
		while ((v = v >> 1))
			bit++;
#endif
#if defined(ARCH_ALPHA) || defined(ARCH_PARISC)
		if (value == 1 && (cond == COND_E || cond == COND_NE)) {
			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond == COND_E ? COND_BLBC : COND_BLBS, 0);
			gen_one(reg1);
			gen_four(label);
			return true;
		}
#endif
#if defined(ARCH_ARM64) || defined(ARCH_PARISC)
		gen_insn(INSN_JMP_REG_BIT, OP_SIZE_NATIVE, bit | ((cond == COND_NE) << 6), 0);
		gen_one(reg1);
		gen_four(label);

		return true;
#endif
#if defined(ARCH_POWER)
		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_CONST_IMM, reg1, (8U << OP_SIZE_NATIVE) - 1 - bit, true));

		gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, cond == COND_E ? COND_GE : COND_L, 0);
		gen_four(label);

		return true;
#endif
#if defined(ARCH_IA64)
		gen_insn(INSN_TEST_DEST_REG, OP_SIZE_NATIVE, bit | ((cond == COND_NE) << 6), 0);
		gen_one(R_CMP_RESULT);
		gen_one(reg1);

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);

		return true;
#endif
#if defined(R_CMP_RESULT)
		if (!is_direct_const(1ULL << bit, IMM_PURPOSE_AND, OP_SIZE_NATIVE) && ARCH_HAS_BTX(BTX_BTEXT, OP_SIZE_NATIVE, true)) {
			gen_insn(INSN_BTX, OP_SIZE_NATIVE, BTX_BTEXT, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_one(ARG_IMM);
			gen_eight(bit);

			gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_four(label);

			return true;
		}
#endif
	}
#if ARCH_HAS_FLAGS
	if (unlikely(insn == INSN_CMP) && COND_IS_LOGICAL(cond)) {
		g(gen_imm(ctx, value, IMM_PURPOSE_CMP_LOGICAL, op_size));
		gen_insn(insn, op_size, 0, 2);
		gen_one(reg1);
		gen_imm_offset();

		gen_insn(INSN_JMP_COND_LOGICAL, op_size, cond, 0);
		gen_four(label);

		return true;
	}
	g(gen_imm(ctx, value, insn == INSN_CMP ? IMM_PURPOSE_CMP : IMM_PURPOSE_TEST, op_size));
	gen_insn(insn, op_size, 0, 1);
	gen_one(reg1);
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, op_size, cond, 0);
	gen_four(label);
#else
	if (insn == INSN_CMP) {
#if defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_RISCV64)
		g(gen_imm(ctx, value, IMM_PURPOSE_JMP_2REGS, op_size));
#if defined(ARCH_PARISC)
		gen_insn(INSN_JMP_2REGS, op_size, cond, 0);
#else
		gen_insn(INSN_JMP_2REGS, i_size(op_size), cond, 0);
#endif
		gen_one(reg1);
		gen_imm_offset();
		gen_four(label);
		return true;
#else
		unsigned final_cond = COND_NE;
#if defined(ARCH_ALPHA)
		if (cond == COND_AE || cond == COND_A || cond == COND_GE || cond == COND_G) {
			g(gen_load_constant(ctx, R_CONST_IMM, value));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_one(R_CONST_IMM);
		} else if (cond == COND_NE) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_XOR, R_CMP_RESULT, reg1, value));
		} else
#endif
#if defined(ARCH_MIPS)
		if (cond == COND_E || cond == COND_NE) {
			g(gen_load_constant(ctx, R_CONST_IMM, value));
			gen_insn(INSN_JMP_2REGS, OP_SIZE_NATIVE, cond, 0);
			gen_one(reg1);
			gen_one(R_CONST_IMM);
			gen_four(label);
			return true;
		}
		if (cond == COND_AE || cond == COND_BE || cond == COND_LE || cond == COND_GE) {
			cond ^= 1;
			final_cond ^= 1;
		}
		if (cond == COND_A || cond == COND_G) {
			g(gen_load_constant(ctx, R_CONST_IMM, value));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_one(R_CONST_IMM);
		} else
#endif
		{
			g(gen_imm(ctx, value, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, cond, 0);
			gen_one(R_CMP_RESULT);
			gen_one(reg1);
			gen_imm_offset();
		}

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, final_cond, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);
#endif
	} else if (insn == INSN_TEST) {
#if defined(ARCH_IA64)
		internal(file_line, "gen_cmp_test_imm_jmp: value %"PRIxMAX" not supported", (uintmax_t)value);
#endif
		g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_AND, R_CMP_RESULT, reg1, value));

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, cond, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);
	} else {
		internal(file_line, "gen_cmp_test_imm_jmp: invalid insn");
	}
#endif
	return true;
}

static bool attr_w gen_jmp_on_zero(struct codegen_context *ctx, unsigned attr_unused op_size, unsigned reg, unsigned cond, uint32_t label)
{
#if defined(ARCH_ALPHA) || defined(ARCH_ARM64) || defined(ARCH_LOONGARCH64) || defined(ARCH_RISCV64)
	if (1)
#elif defined(ARCH_SPARC)
	if (SPARC_9)
#else
	if (0)
#endif
	{
		gen_insn(INSN_JMP_REG, i_size(op_size), cond, 0);
		gen_one(reg);
		gen_four(label);

		return true;
	}
	g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), reg, reg, cond, label));

	return true;
}

static bool attr_w gen_jmp_if_negative(struct codegen_context *ctx, unsigned reg, uint32_t label)
{
#if defined(ARCH_ARM64) || defined(ARCH_PARISC)
	gen_insn(INSN_JMP_REG_BIT, OP_SIZE_NATIVE, (INT_DEFAULT_BITS - 1) | ((uint32_t)1 << 6), 0);
	gen_one(reg);
	gen_four(label);
#else
	g(gen_jmp_on_zero(ctx, OP_SIZE_INT, reg, COND_S, label));
#endif
	return true;
}

#define frame_offs(x)	((ssize_t)offsetof(struct frame_struct, x) - (ssize_t)frame_offset)

static bool attr_w gen_set_1(struct codegen_context *ctx, unsigned base, frame_t slot_1, int64_t offset, bool val)
{
#ifdef HAVE_BITWISE_FRAME
	int bit = slot_1 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
	offset += slot_1 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
#if defined(ARCH_X86)
	g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_BITMAP));
	gen_insn(INSN_BTX, OP_SIZE_BITMAP, val ? BTX_BTS : BTX_BTR, 1);
	gen_address_offset();
	gen_address_offset();
	gen_imm_offset();
#else
	g(gen_address(ctx, base, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	if (!is_direct_const(!val ? ~(1ULL << bit) : 1ULL << bit, !val ? IMM_PURPOSE_AND : IMM_PURPOSE_OR, OP_SIZE_NATIVE) && ARCH_HAS_BTX(!val ? BTX_BTR : BTX_BTS, OP_SIZE_NATIVE, true)) {
		g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_NATIVE));
		gen_insn(INSN_BTX, OP_SIZE_NATIVE, !val ? BTX_BTR : BTX_BTS, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_one(R_SCRATCH_NA_1);
		gen_imm_offset();
	} else if (!val) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_1, R_SCRATCH_NA_1, ~((uintptr_t)1 << bit)));
	} else {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), val ? ALU_OR : ALU_ANDN, R_SCRATCH_NA_1, R_SCRATCH_NA_1, (uintptr_t)1 << bit));
	}

	g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_NA_1);
#endif
#else
#if !defined(ARCH_X86)
	if (!ARCH_HAS_BWX) {
		g(gen_address(ctx, base, offset + (slot_1 & ~(frame_t)7), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_address_offset();

		if (!val) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_8, ALU_MSKBL, R_SCRATCH_NA_1, R_SCRATCH_NA_1, slot_1 & 7));
		} else {
			g(gen_3address_alu_imm(ctx, OP_SIZE_8, ALU_OR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, 1ULL << ((slot_1 & 7) * 8)));
		}

		g(gen_address(ctx, base, offset + (slot_1 & ~(frame_t)7), IMM_PURPOSE_STR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_1);

		return true;
	}
#endif
	g(gen_address(ctx, base, offset + slot_1, IMM_PURPOSE_MVI_CLI_OFFSET, OP_SIZE_1));
	g(gen_imm(ctx, val, IMM_PURPOSE_STORE_VALUE, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_address_offset();
	gen_imm_offset();
#endif
	return true;
}

static bool attr_w gen_set_1_variable(struct codegen_context *ctx, unsigned slot_reg, int64_t offset, bool val)
{
#ifdef HAVE_BITWISE_FRAME
#if defined(ARCH_X86)
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(INSN_BTX, OP_SIZE_BITMAP, val ? BTX_BTS : BTX_BTR, 1);
	gen_address_offset();
	gen_address_offset();
	gen_one(slot_reg);
#else
	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHR, R_SCRATCH_NA_1, slot_reg, OP_SIZE_BITMAP + 3, false));

	if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_BITMAP)) {
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
		gen_one(R_SCRATCH_NA_1);
		gen_one(R_FRAME);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | OP_SIZE_BITMAP);
		gen_one(R_SCRATCH_NA_1);
	} else {
		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_SCRATCH_NA_1, R_SCRATCH_NA_1, OP_SIZE_BITMAP, false));

		g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SCRATCH_NA_1, R_SCRATCH_NA_1, R_FRAME));
	}
	if (ARCH_HAS_BTX(!val ? BTX_BTR : BTX_BTS, OP_SIZE_BITMAP, false)) {
		g(gen_address(ctx, R_SCRATCH_NA_1, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
		gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
		gen_one(R_SCRATCH_NA_3);
		gen_address_offset();

		gen_insn(INSN_BTX, OP_SIZE_BITMAP, !val ? BTX_BTR : BTX_BTS, 0);
		gen_one(R_SCRATCH_NA_3);
		gen_one(R_SCRATCH_NA_3);
		gen_one(slot_reg);

		goto save_it;
	}
	if (ARCH_SHIFT_SIZE > OP_SIZE_BITMAP) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_3, slot_reg, (1U << (OP_SIZE_BITMAP + 3)) - 1));

		g(gen_load_constant(ctx, R_SCRATCH_NA_2, 1));

		g(gen_3address_rot(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, R_SCRATCH_NA_3));
	} else {
		g(gen_load_constant(ctx, R_SCRATCH_NA_2, 1));

		g(gen_3address_rot(ctx, OP_SIZE_BITMAP, ROT_SHL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, slot_reg));
	}
	g(gen_address(ctx, R_SCRATCH_NA_1, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_3);
	gen_address_offset();

	if (!val && !ARCH_HAS_ANDN) {
		gen_insn(INSN_ALU1, i_size(OP_SIZE_BITMAP), ALU1_NOT, ALU1_WRITES_FLAGS(ALU1_NOT));
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_2);

		g(gen_3address_alu(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_3, R_SCRATCH_NA_3, R_SCRATCH_NA_2));
	} else {
		g(gen_3address_alu(ctx, i_size(OP_SIZE_BITMAP), val ? ALU_OR : ALU_ANDN, R_SCRATCH_NA_3, R_SCRATCH_NA_3, R_SCRATCH_NA_2));
	}

	goto save_it;
save_it:
	g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_NA_3);
#endif
#else
#if defined(ARCH_X86)
	g(gen_imm(ctx, val, IMM_PURPOSE_STORE_VALUE, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_one(ARG_ADDRESS_2);
	gen_one(R_FRAME);
	gen_one(slot_reg);
	gen_eight(offset);
	gen_imm_offset();
#else
	g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SCRATCH_NA_1, R_FRAME, slot_reg));
	if (!ARCH_HAS_BWX) {
		g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_8, 0, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_address_offset();
		if (!val) {
			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_MSKBL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, R_SCRATCH_NA_1));
		} else {
			g(gen_load_constant(ctx, R_SCRATCH_NA_3, 1));

			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_INSBL, R_SCRATCH_NA_3, R_SCRATCH_NA_3, R_SCRATCH_NA_1));

			g(gen_3address_alu(ctx, OP_SIZE_8, ALU_OR, R_SCRATCH_NA_2, R_SCRATCH_NA_2, R_SCRATCH_NA_3));
		}
		g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV_U, OP_SIZE_8, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_2);

		return true;
	}

	g(gen_address(ctx, R_SCRATCH_NA_1, offset, IMM_PURPOSE_MVI_CLI_OFFSET, OP_SIZE_1));
	g(gen_imm(ctx, val, IMM_PURPOSE_STORE_VALUE, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_address_offset();
	gen_imm_offset();
#endif
#endif
	return true;
}

#define TEST		0
#define TEST_CLEAR	1
#define TEST_SET	2

static bool attr_w gen_test_1(struct codegen_context *ctx, unsigned base, frame_t slot_1, int64_t offset, uint32_t label, bool jz, uint8_t test)
{
#ifdef HAVE_BITWISE_FRAME
	int bit = slot_1 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
	offset += slot_1 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
#if defined(ARCH_X86)
	g(gen_address(ctx, base, offset, test == TEST ? IMM_PURPOSE_LDR_OFFSET : IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
	g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_BITMAP));
	if (test == TEST) {
		if (OP_SIZE_BITMAP == OP_SIZE_4) {
			g(gen_address(ctx, base, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
			g(gen_imm(ctx, (int32_t)((uint32_t)1 << bit), IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
			gen_insn(INSN_TEST, OP_SIZE_BITMAP, 0, 1);
			gen_address_offset();
			gen_imm_offset();

			gen_insn(INSN_JMP_COND, OP_SIZE_BITMAP, jz ? COND_E : COND_NE, 0);
			gen_four(label);

			return true;
		}
		gen_insn(INSN_BT, OP_SIZE_BITMAP, 0, 1);
		gen_address_offset();
		gen_imm_offset();
	} else {
		gen_insn(INSN_BTX, OP_SIZE_BITMAP, test == TEST_CLEAR ? BTX_BTR : BTX_BTS, 1);
		gen_address_offset();
		gen_address_offset();
		gen_imm_offset();
	}

	gen_insn(INSN_JMP_COND, OP_SIZE_1, jz ? COND_AE : COND_B, 0);
	gen_four(label);
#else
	g(gen_address(ctx, base, offset, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	if (jz ? test == TEST_SET : test == TEST_CLEAR) {
		if (!is_direct_const(test == TEST_CLEAR ? ~(1ULL << bit) : 1ULL << bit, test == TEST_CLEAR ? IMM_PURPOSE_AND : IMM_PURPOSE_OR, OP_SIZE_NATIVE) && ARCH_HAS_BTX(test == TEST_CLEAR ? BTX_BTR : BTX_BTS, OP_SIZE_NATIVE, true)) {
			g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_NATIVE));
			gen_insn(INSN_BTX, OP_SIZE_NATIVE, test == TEST_CLEAR ? BTX_BTR : BTX_BTS, 0);
			gen_one(R_SCRATCH_NA_2);
			gen_one(R_SCRATCH_NA_1);
			gen_imm_offset();
		} else if (test == TEST_CLEAR) {
			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_2, R_SCRATCH_NA_1, ~((uintptr_t)1 << bit)));
		} else {
			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), test == TEST_SET ? ALU_OR : ALU_ANDN, R_SCRATCH_NA_2, R_SCRATCH_NA_1, (uintptr_t)1 << bit));
		}

		g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_2);
	}
#if defined(ARCH_ARM) || defined(ARCH_IA64) || defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_S390)
	g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, (uintptr_t)1 << bit, !jz ? COND_NE : COND_E, label));
#else
	g(gen_3address_rot_imm(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_3, R_SCRATCH_NA_1, (1U << (i_size(OP_SIZE_BITMAP) + 3)) - 1 - bit, false));

	gen_insn(INSN_JMP_REG, i_size(OP_SIZE_BITMAP), !jz ? COND_S : COND_NS, 0);
	gen_one(R_SCRATCH_NA_3);
	gen_four(label);
#endif
	if (!jz ? test == TEST_SET : test == TEST_CLEAR) {
		if (!is_direct_const(test == TEST_CLEAR ? ~(1ULL << bit) : 1ULL << bit, test == TEST_CLEAR ? IMM_PURPOSE_XOR : IMM_PURPOSE_OR, OP_SIZE_NATIVE) && ARCH_HAS_BTX(test == TEST_CLEAR ? BTX_BTR : BTX_BTS, OP_SIZE_NATIVE, true)) {
			g(gen_imm(ctx, bit, IMM_PURPOSE_BITWISE, OP_SIZE_NATIVE));
			gen_insn(INSN_BTX, OP_SIZE_NATIVE, test == TEST_CLEAR ? BTX_BTR : BTX_BTS, 0);
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_NA_1);
			gen_imm_offset();
		} else {
#if defined(ARCH_S390)
			if (test == TEST_CLEAR)
				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), ALU_AND, R_SCRATCH_NA_1, R_SCRATCH_NA_1, ~((uintptr_t)1 << bit)));
			else
#endif
				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_BITMAP), test == TEST_SET ? ALU_OR : ALU_XOR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, (uintptr_t)1 << bit));
		}
		g(gen_address(ctx, base, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_BITMAP));
		gen_insn(INSN_MOV, OP_SIZE_BITMAP, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_NA_1);
	}
#endif
#else
#if defined(ARCH_X86) || defined(ARCH_S390)
	g(gen_address(ctx, base, offset + slot_1, IMM_PURPOSE_MVI_CLI_OFFSET, OP_SIZE_1));
	gen_insn(INSN_CMP, OP_SIZE_1, 0, 2);
	gen_address_offset();
	gen_one(ARG_IMM);
	gen_eight(0);

	if (jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}

	gen_insn(INSN_JMP_COND, OP_SIZE_1, jz ? COND_E : COND_NE, 0);
	gen_four(label);

	if (!jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}
#else
	if (!ARCH_HAS_BWX) {
		g(gen_address(ctx, base, offset + (slot_1 & ~(frame_t)7), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_8));
		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_address_offset();

		g(gen_3address_alu_imm(ctx, OP_SIZE_8, ALU_EXTBL, R_SCRATCH_NA_2, R_SCRATCH_NA_2, slot_1 & 7));
	} else {
		g(gen_address(ctx, base, offset + slot_1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_address_offset();
	}

	if (jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}

	g(gen_jmp_on_zero(ctx, OP_SIZE_1, R_SCRATCH_NA_2, jz ? COND_E : COND_NE, label));

	if (!jz ? test == TEST_SET : test == TEST_CLEAR) {
		g(gen_set_1(ctx, base, slot_1, offset, test == TEST_SET));
	}
#endif
#endif
	return true;
}

static bool attr_w gen_test_2(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, uint32_t label)
{
	unsigned attr_unused bit1, bit2;
	frame_t attr_unused addr1, addr2;
	if (unlikely(slot_1 == slot_2)) {
		g(gen_test_1(ctx, R_FRAME, slot_1, 0,label, false, TEST));
		return true;
	}
#ifdef HAVE_BITWISE_FRAME
	addr1 = slot_1 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
	addr2 = slot_2 >> (OP_SIZE_BITMAP + 3) << OP_SIZE_BITMAP;
	if (addr1 != addr2)
		goto dont_optimize;
	bit1 = slot_1 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
	bit2 = slot_2 & ((1 << (OP_SIZE_BITMAP + 3)) - 1);
#if defined(ARCH_X86)
	g(gen_address(ctx, R_FRAME, addr1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	if (OP_SIZE_BITMAP == OP_SIZE_4) {
		g(gen_imm(ctx, (int32_t)(((uintptr_t)1 << bit1) | ((uintptr_t)1 << bit2)), IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
	} else {
		g(gen_imm(ctx, ((uintptr_t)1 << bit1) | ((uintptr_t)1 << bit2), IMM_PURPOSE_TEST, OP_SIZE_BITMAP));
	}
	gen_insn(INSN_TEST, OP_SIZE_BITMAP, 0, 1);
	gen_address_offset();
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_BITMAP, COND_NE, 0);
	gen_four(label);

	return true;
#else
	g(gen_address(ctx, R_FRAME, addr1, ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_BITMAP));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_BITMAP) ? INSN_MOVSX : INSN_MOV, OP_SIZE_BITMAP, 0, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_address_offset();

	if (is_direct_const(1ULL << bit1 | 1ULL << bit2, IMM_PURPOSE_TEST, OP_SIZE_BITMAP)) {
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, 1ULL << bit1 | 1ULL << bit2, COND_NE, label));
		return true;
	}
#if defined(ARCH_ARM) || defined(ARCH_IA64) || defined(ARCH_PARISC) || defined(ARCH_S390)
	g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, (uintptr_t)1 << bit1, COND_NE, label));
	g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, i_size(OP_SIZE_BITMAP), R_SCRATCH_NA_1, (uintptr_t)1 << bit2, COND_NE, label));

	return true;
#endif
	if (ARCH_HAS_BTX(BTX_BTEXT, OP_SIZE_NATIVE, true)) {
		gen_insn(INSN_BTX, OP_SIZE_NATIVE, BTX_BTEXT, 0);
		gen_one(R_SCRATCH_NA_2);
		gen_one(R_SCRATCH_NA_1);
		gen_one(ARG_IMM);
		gen_eight(bit1);

		gen_insn(INSN_BTX, OP_SIZE_NATIVE, BTX_BTEXT, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_one(R_SCRATCH_NA_1);
		gen_one(ARG_IMM);
		gen_eight(bit2);

		g(gen_3address_alu(ctx, i_size(OP_SIZE_NATIVE), ALU_OR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, R_SCRATCH_NA_2));

		gen_insn(INSN_JMP_REG, i_size(OP_SIZE_NATIVE), COND_NE, 0);
		gen_one(R_SCRATCH_NA_1);
		gen_four(label);

		return true;
	}
	g(gen_3address_rot_imm(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_2, R_SCRATCH_NA_1, (1U << (i_size(OP_SIZE_BITMAP) + 3)) - 1 - bit1, false));
	g(gen_3address_rot_imm(ctx, i_size(OP_SIZE_BITMAP), ROT_SHL, R_SCRATCH_NA_1, R_SCRATCH_NA_1, (1U << (i_size(OP_SIZE_BITMAP) + 3)) - 1 - bit2, false));
#if defined(ARCH_POWER)
	gen_insn(INSN_ALU, i_size(OP_SIZE_BITMAP), ALU_OR, 1);
	gen_one(R_SCRATCH_NA_1);
	gen_one(R_SCRATCH_NA_1);
	gen_one(R_SCRATCH_NA_2);

	gen_insn(INSN_JMP_COND, i_size(OP_SIZE_BITMAP), COND_L, 0);
	gen_four(label);
#else
	g(gen_3address_alu(ctx, i_size(OP_SIZE_BITMAP), ALU_OR, R_SCRATCH_NA_1, R_SCRATCH_NA_1, R_SCRATCH_NA_2));

	gen_insn(INSN_JMP_REG, i_size(OP_SIZE_BITMAP), COND_S, 0);
	gen_one(R_SCRATCH_NA_1);
	gen_four(label);
#endif
	return true;
#endif
dont_optimize:
	g(gen_test_1(ctx, R_FRAME, slot_1, 0, label, false, TEST));
	g(gen_test_1(ctx, R_FRAME, slot_2, 0, label, false, TEST));
#else
#if defined(ARCH_X86)
	g(gen_address(ctx, R_FRAME, slot_1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_address(ctx, R_FRAME, slot_2, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
	gen_insn(INSN_ALU_PARTIAL, OP_SIZE_1, ALU_OR, 1);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_1, COND_NE, 0);
	gen_four(label);
#else
	if (!ARCH_HAS_BWX || !ARCH_HAS_FLAGS
#if defined(ARCH_S390)
	    || 1
#endif
	    ) {
		g(gen_test_1(ctx, R_FRAME, slot_1, 0, label, false, TEST));
		g(gen_test_1(ctx, R_FRAME, slot_2, 0, label, false, TEST));
	} else {
		g(gen_address(ctx, R_FRAME, slot_1, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

		g(gen_address(ctx, R_FRAME, slot_2, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_2);
		gen_address_offset();
#if defined(ARCH_ARM) || defined(ARCH_SPARC)
		gen_insn(INSN_CMN, OP_SIZE_NATIVE, 0, 1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
#else
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, 1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
#endif
		gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
		gen_four(label);
	}
#endif
#endif
	return true;
}

static bool attr_w gen_test_1_cached(struct codegen_context *ctx, frame_t slot_1, uint32_t label)
{
	if (!flag_cache_chicken && ctx->flag_cache[slot_1] == -1)
		return true;
	return gen_test_1(ctx, R_FRAME, slot_1, 0, label, false, TEST);
}

static bool attr_w gen_test_2_cached(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, uint32_t label)
{
	if (!flag_cache_chicken && ctx->flag_cache[slot_1] == -1)
		return gen_test_1_cached(ctx, slot_2, label);
	if (!flag_cache_chicken && ctx->flag_cache[slot_2] == -1)
		return gen_test_1_cached(ctx, slot_1, label);
	return gen_test_2(ctx, slot_1, slot_2, label);
}

static bool attr_w gen_test_1_jz_cached(struct codegen_context *ctx, frame_t slot_1, uint32_t label)
{
	const struct type *type = get_type_of_local(ctx, slot_1);
	if (!TYPE_IS_FLAT(type) && !da(ctx->fn,function)->local_variables_flags[slot_1].may_be_borrowed)
		return true;
	if (!flag_cache_chicken && ctx->flag_cache[slot_1] == 1)
		return true;
	return gen_test_1(ctx, R_FRAME, slot_1, 0, label, true, TEST);
}

static bool attr_w gen_frame_address(struct codegen_context *ctx, frame_t slot, int64_t offset, unsigned reg)
{
	offset += (size_t)slot * slot_size;
	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, reg, R_FRAME, offset));
	return true;
}

static bool attr_w gen_frame_load(struct codegen_context *ctx, unsigned size, bool sx, frame_t slot, int64_t offset, unsigned reg)
{
	if (likely(!reg_is_fp(reg)))
		sx |= ARCH_PREFERS_SX(size);
	offset += (size_t)slot * slot_size;
	if (!ARCH_HAS_BWX && size < OP_SIZE_4) {
		g(gen_address(ctx, R_FRAME, offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_4));
		gen_insn(INSN_MOVSX, OP_SIZE_4, 0, 0);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, sx, reg, reg));

		return true;
	}
#if defined(ARCH_ALPHA)
	if (size < OP_SIZE_4) {
		g(gen_address(ctx, R_FRAME, offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_one(reg);
		gen_address_offset();

		if (sx)
			g(gen_extend(ctx, size, sx, reg, reg));

		return true;
	}
#endif
#if defined(ARCH_MIPS)
	if (reg_is_fp(reg) && size == OP_SIZE_8 && !MIPS_HAS_LS_DOUBLE) {
#if defined(C_LITTLE_ENDIAN)
		g(gen_frame_load(ctx, OP_SIZE_4, false, 0, offset, reg));
		g(gen_frame_load(ctx, OP_SIZE_4, false, 0, offset + 4, reg + 1));
#else
		g(gen_frame_load(ctx, OP_SIZE_4, false, 0, offset, reg + 1));
		g(gen_frame_load(ctx, OP_SIZE_4, false, 0, offset + 4, reg));
#endif
		return true;
	}
#endif
#if defined(ARCH_IA64) || defined(ARCH_PARISC)
	if (sx) {
		g(gen_address(ctx, R_FRAME, offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : sx ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, sx, reg, reg));

		return true;
	}
#endif
#if defined(ARCH_POWER)
	if (size == OP_SIZE_1 && sx) {
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV, size, 0, 0);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, sx, reg, reg));

		return true;
	}
#endif
#if defined(ARCH_S390)
	if (size == OP_SIZE_1 && !cpu_test_feature(CPU_FEATURE_long_displacement)) {
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_0_8, 0);
		gen_one(reg);
		gen_one(reg);
		gen_address_offset();

		g(gen_extend(ctx, size, sx, reg, reg));

		return true;
	}
	if (size == OP_SIZE_16 && reg_is_fp(reg)) {
		g(gen_frame_load(ctx, OP_SIZE_8, false, 0, offset, reg));
		g(gen_frame_load(ctx, OP_SIZE_8, false, 0, offset + 8, reg + 2));

		return true;
	}
#endif
	g(gen_address(ctx, R_FRAME, offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : sx ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, size));
	gen_insn(unlikely(sx) ? INSN_MOVSX : INSN_MOV, size, 0, 0);
	gen_one(reg);
	gen_address_offset();

	return true;
}

#if defined(ARCH_X86)
static bool attr_w gen_frame_load_x87(struct codegen_context *ctx, unsigned insn, unsigned size, unsigned alu, frame_t slot)
{
	g(gen_address(ctx, R_FRAME, (size_t)slot * slot_size, IMM_PURPOSE_LDR_OFFSET, size));
	gen_insn(insn, size, alu, 0);
	gen_address_offset();
	return true;
}

static bool attr_w gen_frame_store_x87(struct codegen_context *ctx, unsigned insn, unsigned size, frame_t slot)
{
	g(gen_address(ctx, R_FRAME, (size_t)slot * slot_size, IMM_PURPOSE_STR_OFFSET, size));
	gen_insn(insn, size, 0, 0);
	gen_address_offset();
	return true;
}
#endif

static bool attr_w gen_frame_load_op(struct codegen_context *ctx, unsigned size, bool attr_unused sx, unsigned alu, unsigned writes_flags, frame_t slot, int64_t offset, unsigned reg)
{
#if defined(ARCH_X86) || defined(ARCH_S390)
#if defined(ARCH_S390)
	if (size >= OP_SIZE_4)
#endif
	{
		offset += (size_t)slot * slot_size;
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(size), size, alu, (alu == ALU_MUL ? ALU_WRITES_FLAGS(alu, false) : 1) | writes_flags);
		gen_one(reg);
		gen_one(reg);
		gen_address_offset();
		return true;
	}
#endif
#if !defined(ARCH_X86)
	g(gen_frame_load(ctx, size, sx, slot, offset, R_SCRATCH_NA_1));
	gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(i_size(size)), i_size(size), alu, ALU_WRITES_FLAGS(alu, false) | writes_flags);
	gen_one(reg);
	gen_one(reg);
	gen_one(R_SCRATCH_NA_1);
	return true;
#endif
}

static bool attr_w attr_unused gen_frame_load_op1(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags, frame_t slot, int64_t offset, unsigned reg)
{
#if defined(ARCH_X86)
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
	gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(size), size, alu, ALU1_WRITES_FLAGS(alu) | writes_flags);
	gen_one(reg);
	gen_address_offset();
	return true;
#endif
#if !defined(ARCH_X86)
	g(gen_frame_load(ctx, size, false, slot, offset, reg));
	gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(size), size, alu, ALU1_WRITES_FLAGS(alu) | writes_flags);
	gen_one(reg);
	gen_one(reg);
	return true;
#endif
}

#if ARCH_HAS_FLAGS
static bool attr_w gen_frame_load_cmp(struct codegen_context *ctx, unsigned size, bool logical, bool attr_unused sx, bool swap, frame_t slot, int64_t offset, unsigned reg)
{
#if defined(ARCH_S390) || defined(ARCH_X86)
#if defined(ARCH_S390)
	if (size < OP_SIZE_4)
		goto no_load_op;
#endif
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, size));
	gen_insn(INSN_CMP, size, 0, 1 + logical);
	if (!swap) {
		gen_one(reg);
		gen_address_offset();
	} else {
		gen_address_offset();
		gen_one(reg);
	}
	return true;
#endif
#if defined(R_SCRATCH_NA_1)
	goto no_load_op;
no_load_op:
	g(gen_frame_load(ctx, size, sx, slot, offset, R_SCRATCH_NA_1));
	gen_insn(INSN_CMP, maximum(size, OP_SIZE_4), 0, 1 + logical);
	if (!swap) {
		gen_one(reg);
		gen_one(R_SCRATCH_NA_1);
	} else {
		gen_one(R_SCRATCH_NA_1);
		gen_one(reg);
	}
	return true;
#endif
}

static bool attr_w gen_frame_load_cmp_imm(struct codegen_context *ctx, unsigned size, bool logical, bool attr_unused sx, frame_t slot, int64_t offset, int64_t value)
{
#if defined(ARCH_S390) || defined(ARCH_X86)
#if defined(ARCH_S390)
	if (size != OP_SIZE_1 || !logical)
		goto no_load_op;
#endif
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_MVI_CLI_OFFSET, size));
	g(gen_imm(ctx, value, IMM_PURPOSE_CMP, size));
	gen_insn(INSN_CMP, size, 0, 1 + logical);
	gen_address_offset();
	gen_imm_offset();
	return true;
#endif
#if defined(R_SCRATCH_NA_1)
	goto no_load_op;
no_load_op:
	g(gen_frame_load(ctx, size, sx, slot, offset, R_SCRATCH_NA_1));
	g(gen_imm(ctx, value, IMM_PURPOSE_CMP, size));
	gen_insn(INSN_CMP, i_size(size), 0, 1 + logical);
	gen_one(R_SCRATCH_NA_1);
	gen_imm_offset();
	return true;
#endif
}
#endif

static bool attr_w gen_frame_load_2(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg1, unsigned reg2)
{
#if defined(ARCH_ARM64)
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, size));
	gen_insn(INSN_LDP, size, 0, 0);
	gen_one(reg1);
	gen_one(reg2);
	gen_address_offset();
	return true;
#endif
#if defined(ARCH_ARM32)
	if (likely(!(reg1 & 1)) && likely(reg2 == reg1 + 1) && likely(cpu_test_feature(CPU_FEATURE_armv6)))
#elif defined(ARCH_SPARC32)
	if (likely(!(reg2 & 1)) && likely(reg1 == reg2 + 1))
#elif defined(ARCH_S390)
	if (likely(reg1 == reg2 + 1))
#else
	if (0)
#endif
	{
		offset += (size_t)slot * slot_size;
		if (UNALIGNED_TRAP) {
			if (unlikely((offset & ((2U << size) - 1)) != 0)) {
				offset -= (size_t)slot * slot_size;
				goto skip_ldd;
			}
		}
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, size));
		gen_insn(INSN_LDP, size, 0, 0);
		gen_one(reg1);
		gen_one(reg2);
		gen_address_offset();
		return true;
	}
	goto skip_ldd;
skip_ldd:
	g(gen_frame_load(ctx, size, false, slot, offset + lo_word(size), reg1));
	g(gen_frame_load(ctx, size, false, slot, offset + hi_word(size), reg2));
	return true;
}

static bool attr_w gen_frame_store(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg)
{
	offset += (size_t)slot * slot_size;
	if (!ARCH_HAS_BWX)
		size = maximum(OP_SIZE_4, size);
#if defined(ARCH_MIPS)
	if (reg_is_fp(reg) && size == OP_SIZE_8 && !MIPS_HAS_LS_DOUBLE) {
#if defined(C_LITTLE_ENDIAN)
		g(gen_frame_store(ctx, OP_SIZE_4, 0, offset, reg));
		g(gen_frame_store(ctx, OP_SIZE_4, 0, offset + 4, reg + 1));
#else
		g(gen_frame_store(ctx, OP_SIZE_4, 0, offset, reg + 1));
		g(gen_frame_store(ctx, OP_SIZE_4, 0, offset + 4, reg));
#endif
		return true;
	}
#endif
#if defined(ARCH_S390)
	if (size == OP_SIZE_16 && reg_is_fp(reg)) {
		g(gen_frame_store(ctx, OP_SIZE_8, 0, offset, reg));
		g(gen_frame_store(ctx, OP_SIZE_8, 0, offset + 8, reg + 2));
		return true;
	}
#endif
	g(gen_address(ctx, R_FRAME, offset, reg_is_fp(reg) ? IMM_PURPOSE_VLDR_VSTR_OFFSET : IMM_PURPOSE_STR_OFFSET, size));
	gen_insn(INSN_MOV, size, 0, 0);
	gen_address_offset();
	gen_one(reg);
	return true;
}

static bool attr_w gen_frame_store_2(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, unsigned reg1, unsigned reg2)
{
#if defined(ARCH_ARM64)
	offset += (size_t)slot * slot_size;
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, size));
	gen_insn(INSN_STP, size, 0, 0);
	gen_address_offset();
	gen_one(reg1);
	gen_one(reg2);
	return true;
#endif
#if defined(ARCH_ARM32)
	if (likely(!(reg1 & 1)) && likely(reg2 == reg1 + 1) && likely(cpu_test_feature(CPU_FEATURE_armv6)))
#elif defined(ARCH_SPARC32)
	if (likely(!(reg2 & 1)) && likely(reg1 == reg2 + 1))
#elif defined(ARCH_S390)
	if (likely(reg1 == reg2 + 1))
#else
	if (0)
#endif
	{
		offset += (size_t)slot * slot_size;
		if (UNALIGNED_TRAP) {
			if (unlikely((offset & ((2U << size) - 1)) != 0)) {
				offset -= (size_t)slot * slot_size;
				goto skip_ldd;
			}
		}
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDP_STP_OFFSET, size));
		gen_insn(INSN_STP, size, 0, 0);
		gen_address_offset();
		gen_one(reg1);
		gen_one(reg2);
		return true;
	}
	goto skip_ldd;
skip_ldd:
	g(gen_frame_store(ctx, size, slot, offset + lo_word(size), reg1));
	g(gen_frame_store(ctx, size, slot, offset + hi_word(size), reg2));
	return true;
}

static bool attr_w gen_frame_store_imm(struct codegen_context *ctx, unsigned size, frame_t slot, int64_t offset, int64_t imm)
{
	offset += (size_t)slot * slot_size;
	if (!ARCH_HAS_BWX)
		size = maximum(OP_SIZE_4, size);
	g(gen_address(ctx, R_FRAME, offset, size == OP_SIZE_1 ? IMM_PURPOSE_MVI_CLI_OFFSET : IMM_PURPOSE_STR_OFFSET, size));
	g(gen_imm(ctx, imm, IMM_PURPOSE_STORE_VALUE, size));
	gen_insn(INSN_MOV, size, 0, 0);
	gen_address_offset();
	gen_imm_offset();
	return true;
}

static bool attr_w gen_frame_clear(struct codegen_context *ctx, unsigned size, frame_t slot)
{
	g(gen_frame_store_imm(ctx, size, slot, 0, 0));
	return true;
}

#if defined(POINTER_COMPRESSION)
#define POINTER_THUNK_BIT		0
#elif defined(POINTER_IGNORE_START)
#define POINTER_THUNK_BIT		POINTER_IGNORE_TOP_BIT
#elif defined(POINTER_TAG)
#define POINTER_THUNK_BIT		POINTER_TAG_BIT
#else
unsupported pointer mode
#endif

static bool attr_w gen_ptr_is_thunk(struct codegen_context *ctx, unsigned reg, bool jnz, uint32_t label)
{
#if defined(ARCH_X86)
	if (POINTER_THUNK_BIT < 8
#if defined(ARCH_X86_32)
		&& reg < 4
#endif
		) {
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_1, reg, (uint64_t)1 << POINTER_THUNK_BIT, jnz ? COND_NE : COND_E, label));
	} else
#endif
	{
		g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_SLOT, reg, (uint64_t)1 << POINTER_THUNK_BIT, jnz ? COND_NE : COND_E, label));
	}
	return true;
}

static bool attr_w gen_barrier(struct codegen_context *ctx)
{
	if (ARCH_NEEDS_BARRIER)
		gen_insn(INSN_MB, 0, 0, 0);
	return true;
}

static bool attr_w gen_compare_refcount(struct codegen_context *ctx, unsigned ptr, unsigned val, unsigned cond, uint32_t label)
{
	unsigned op_size = log_2(sizeof(refcount_int_t));
#if defined(ARCH_X86)
	bool logical = COND_IS_LOGICAL(cond);
	g(gen_address(ctx, ptr, offsetof(struct data, refcount_), IMM_PURPOSE_LDR_OFFSET, op_size));
	g(gen_imm(ctx, val, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1 + logical);
	gen_address_offset();
	gen_imm_offset();

	gen_insn(!logical ? INSN_JMP_COND : INSN_JMP_COND_LOGICAL, op_size, cond, 0);
	gen_four(label);
#else
	g(gen_address(ctx, ptr, offsetof(struct data, refcount_), IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(INSN_MOV, op_size, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_2, val, cond, label));
#endif
	return true;
}

static bool attr_w gen_compare_ptr_tag(struct codegen_context *ctx, unsigned reg, unsigned tag, unsigned cond, uint32_t label, unsigned tmp_reg)
{
#if defined(DATA_TAG_AT_ALLOC)
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHR, tmp_reg, reg, POINTER_IGNORE_START, false));
#elif defined(REFCOUNT_TAG)
#if REFCOUNT_STEP == 256 && defined(C_LITTLE_ENDIAN) && !defined(ARCH_ALPHA)
#if defined(ARCH_X86)
	g(gen_imm(ctx, tag, IMM_PURPOSE_CMP, OP_SIZE_4));
	gen_insn(INSN_CMP, OP_SIZE_1, 0, 1);
	gen_one(ARG_ADDRESS_1);
	gen_one(reg);
	gen_eight(offsetof(struct data, refcount_));
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_1, cond, 0);
	gen_four(label);
	return true;
#else
	gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
	gen_one(tmp_reg);
	gen_one(ARG_ADDRESS_1);
	gen_one(reg);
	gen_eight(offsetof(struct data, refcount_));
#endif
#else
	gen_insn(INSN_MOV, log_2(sizeof(refcount_int_t)), 0, 0);
	gen_one(tmp_reg);
	gen_one(ARG_ADDRESS_1);
	gen_one(reg);
	gen_eight(offsetof(struct data, refcount_));

	g(gen_3address_alu_imm(ctx, log_2(sizeof(refcount_int_t)), ALU_AND, tmp_reg, tmp_reg, REFCOUNT_STEP - 1));
#endif
#else
#if defined(ARCH_S390)
	if (sizeof(tag_t) == 1 && !cpu_test_feature(CPU_FEATURE_long_displacement)) {
		g(gen_address(ctx, reg, offsetof(struct data, tag), IMM_PURPOSE_LDR_OFFSET, log_2(sizeof(tag_t))));
		gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_0_8, 0);
		gen_one(tmp_reg);
		gen_one(tmp_reg);
		gen_address_offset();

		g(gen_extend(ctx, log_2(sizeof(tag_t)), false, tmp_reg, tmp_reg));
	} else
#endif
	{
		g(gen_address(ctx, reg, offsetof(struct data, tag), IMM_PURPOSE_LDR_OFFSET, log_2(sizeof(tag_t))));
		gen_insn(INSN_MOV, log_2(sizeof(tag_t)), 0, 0);
		gen_one(tmp_reg);
		gen_address_offset();
	}
#endif
	g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(OP_SIZE_4), tmp_reg, tag, cond, label));
	return true;
}

static bool attr_w gen_compare_da_tag(struct codegen_context *ctx, unsigned reg, unsigned tag, unsigned cond, uint32_t label, unsigned tmp_reg)
{
#if defined(POINTER_COMPRESSION)
#if defined(ARCH_X86) && POINTER_COMPRESSION <= 3 && defined(REFCOUNT_TAG) && REFCOUNT_STEP == 256 && defined(C_LITTLE_ENDIAN)
	g(gen_imm(ctx, tag, IMM_PURPOSE_CMP, log_2(sizeof(tag_t))));
	gen_insn(INSN_CMP, log_2(sizeof(tag_t)), 0, 0);
	gen_one(ARG_ADDRESS_1 + POINTER_COMPRESSION);
	gen_one(reg);
	gen_eight(offsetof(struct data, refcount_));
	gen_imm_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_4, cond, 0);
	gen_four(label);

	return true;
#endif
	if (ARCH_PREFERS_SX(OP_SIZE_4)) {
		g(gen_extend(ctx, OP_SIZE_4, false, tmp_reg, reg));

		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, tmp_reg, tmp_reg, POINTER_COMPRESSION, false));
	} else {
		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, tmp_reg, reg, POINTER_COMPRESSION, false));
	}
	g(gen_compare_ptr_tag(ctx, tmp_reg, tag, cond, label, tmp_reg));
	return true;
#endif
	g(gen_compare_ptr_tag(ctx, reg, tag, cond, label, tmp_reg));
	return true;
}

static bool attr_w gen_compare_tag_and_refcount(struct codegen_context *ctx, unsigned reg, unsigned tag, uint32_t label, unsigned attr_unused tmp_reg)
{
#if defined(REFCOUNT_TAG)
	g(gen_compare_refcount(ctx, reg, tag, COND_NE, label));
#else
	g(gen_compare_ptr_tag(ctx, reg, tag, COND_NE, label, tmp_reg));
	g(gen_compare_refcount(ctx, reg, REFCOUNT_STEP, COND_AE, label));
#endif
	return true;
}

static bool attr_w gen_decompress_pointer(struct codegen_context *ctx, unsigned reg, int64_t offset)
{
#ifdef POINTER_COMPRESSION
#if defined(ARCH_X86) && POINTER_COMPRESSION <= 3
	if (offset) {
		g(gen_imm(ctx, offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
		gen_one(reg);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | POINTER_COMPRESSION);
		gen_one(reg);
		gen_imm_offset();
		return true;
	}
#endif
	if (ARCH_PREFERS_SX(OP_SIZE_4))
		g(gen_extend(ctx, OP_SIZE_4, false, reg, reg));
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, reg, reg, POINTER_COMPRESSION, false));
#endif
	if (offset)
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, reg, reg, offset));
	return true;
}

static bool attr_w gen_compress_pointer(struct codegen_context attr_unused *ctx, unsigned attr_unused reg)
{
#ifdef POINTER_COMPRESSION
	g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHR, reg, reg, POINTER_COMPRESSION, false));
#endif
	return true;
}

static bool attr_w gen_frame_get_pointer(struct codegen_context *ctx, frame_t slot, bool deref, unsigned dest)
{
	if (!deref) {
		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot, 0, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot, 0, dest));
	} else if (!da(ctx->fn,function)->local_variables_flags[slot].may_be_borrowed) {
		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot, 0, dest));
		g(gen_set_1(ctx, R_FRAME, slot, 0, false));
		ctx->flag_cache[slot] = -1;
	} else {
		uint32_t skip_label;
		skip_label = alloc_label(ctx);
		if (unlikely(!skip_label))
			return false;
		if (!flag_cache_chicken && ctx->flag_cache[slot] == 1) {
			g(gen_set_1(ctx, R_FRAME, slot, 0, false));
			goto move_it;
		}
		if (!flag_cache_chicken && ctx->flag_cache[slot] == -1) {
			goto do_reference;
		}
		g(gen_test_1(ctx, R_FRAME, slot, 0, skip_label, false, TEST_CLEAR));
do_reference:
		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot, 0, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
move_it:
		gen_label(skip_label);
		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot, 0, dest));
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot));
		ctx->flag_cache[slot] = -1;
	}
	return true;
}

static bool attr_w gen_frame_set_pointer(struct codegen_context *ctx, frame_t slot, unsigned src)
{
	g(gen_set_1(ctx, R_FRAME, slot, 0, true));
	ctx->flag_cache[slot] = 1;
	g(gen_frame_store(ctx, OP_SIZE_SLOT, slot, 0, src));
	return true;
}

static bool attr_w gen_alu_upcall(struct codegen_context *ctx, size_t upcall, frame_t slot_1, frame_t slot_2, frame_t slot_r, uint32_t label_ovf)
{
	g(gen_frame_address(ctx, slot_1, 0, R_ARG0));
	g(gen_upcall_argument(ctx, 0));
	if (slot_2 != NO_FRAME_T) {
		g(gen_frame_address(ctx, slot_2, 0, R_ARG1));
		g(gen_upcall_argument(ctx, 1));
		g(gen_frame_address(ctx, slot_r, 0, R_ARG2));
		g(gen_upcall_argument(ctx, 2));
		g(gen_upcall(ctx, upcall, 3));
	} else {
		g(gen_frame_address(ctx, slot_r, 0, R_ARG1));
		g(gen_upcall_argument(ctx, 1));
		g(gen_upcall(ctx, upcall, 2));
	}
	if (!label_ovf)
		return true;
	g(gen_jmp_on_zero(ctx, OP_SIZE_1, R_RET0, COND_E, label_ovf));
	return true;
}

static bool attr_w gen_alu_typed_upcall(struct codegen_context *ctx, size_t upcall, unsigned op_size, frame_t slot_1, frame_t slot_2, frame_t slot_r, uint32_t label_ovf)
{
	upcall += op_size * sizeof(void (*)(void));
	return gen_alu_upcall(ctx, upcall, slot_1, slot_2, slot_r, label_ovf);
}

#if defined(ARCH_X86)
static bool attr_w gen_frame_set_cond(struct codegen_context *ctx, unsigned attr_unused size, bool attr_unused logical, unsigned cond, frame_t slot)
{
	size_t offset = (size_t)slot * slot_size;
	if (sizeof(ajla_flat_option_t) > 1) {
		gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_IMM);
		gen_eight(0);

		gen_insn(INSN_SET_COND, OP_SIZE_1, cond, 0);
		gen_one(R_SCRATCH_1);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot, 0, R_SCRATCH_1));
	} else {
		g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_SET_COND, OP_SIZE_1, cond, 0);
		gen_address_offset();
	}
	return true;
}
#elif defined(ARCH_ARM64)
static bool attr_w gen_frame_set_cond(struct codegen_context *ctx, unsigned attr_unused size, bool attr_unused logical, unsigned cond, frame_t slot)
{
	gen_insn(INSN_SET_COND, OP_SIZE_4, cond, 0);
	gen_one(R_SCRATCH_1);
	g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot, 0, R_SCRATCH_1));
	return true;
}
#elif ARCH_HAS_FLAGS
static bool attr_w gen_frame_set_cond(struct codegen_context *ctx, unsigned size, bool logical, unsigned cond, frame_t slot)
{
#if defined(ARCH_POWER)
	if (!cpu_test_feature(CPU_FEATURE_v203))
#elif defined(ARCH_S390)
	if (!cpu_test_feature(CPU_FEATURE_misc_45))
#elif defined(ARCH_SPARC32)
	if (!SPARC_9)
#else
	if (0)
#endif
	{
		uint32_t label;
		g(gen_load_constant(ctx, R_SCRATCH_1, 1));
		label = alloc_label(ctx);
		if (unlikely(!label))
			return false;
		gen_insn(!logical ? INSN_JMP_COND : INSN_JMP_COND_LOGICAL, i_size(size), cond, 0);
		gen_four(label);
		g(gen_load_constant(ctx, R_SCRATCH_1, 0));
		gen_label(label);
		goto do_store;
	}
	g(gen_load_constant(ctx, R_SCRATCH_1, 1));
	g(gen_imm(ctx, 0, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
	if (cond & COND_FP) {
		gen_insn(INSN_CMOV, OP_SIZE_NATIVE, cond ^ 1, 0);
	} else {
#if defined(ARCH_S390)
		gen_insn(logical ? INSN_CMOV_XCC : INSN_CMOV, OP_SIZE_NATIVE, cond ^ 1, 0);
#else
		gen_insn(size == OP_SIZE_8 ? INSN_CMOV_XCC : INSN_CMOV, OP_SIZE_NATIVE, cond ^ 1, 0);
#endif
	}
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_1);
	gen_imm_offset();
do_store:
	g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot, 0, R_SCRATCH_1));
	return true;
}
#endif

static bool attr_w attr_unused gen_frame_cmp_imm_set_cond_reg(struct codegen_context *ctx, unsigned size, unsigned reg, int64_t imm, unsigned cond, frame_t slot_r)
{
	g(gen_cmp_dest_reg(ctx, size, reg, (unsigned)-1, reg, imm, cond));
	g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, reg));

	return true;
}

static bool attr_w gen_frame_load_cmp_set_cond(struct codegen_context *ctx, unsigned size, bool sx, frame_t slot, int64_t offset, unsigned reg, unsigned cond, frame_t slot_r)
{
#if ARCH_HAS_FLAGS
	bool logical = COND_IS_LOGICAL(cond);
	g(gen_frame_load_cmp(ctx, size, logical, sx, false, slot, offset, reg));
	g(gen_frame_set_cond(ctx, size, logical, cond, slot_r));
#else
	g(gen_frame_load(ctx, size, sx, slot, offset, R_SCRATCH_NA_1));

	g(gen_cmp_dest_reg(ctx, size, reg, R_SCRATCH_NA_1, R_SCRATCH_NA_1, 0, cond));

	g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_NA_1));
#endif
	return true;
}

static bool attr_w gen_frame_load_cmp_imm_set_cond(struct codegen_context *ctx, unsigned size, bool sx, frame_t slot, int64_t offset, int64_t value, unsigned cond, frame_t slot_r)
{
#if ARCH_HAS_FLAGS
	bool logical = COND_IS_LOGICAL(cond);
#if defined(ARCH_S390)
	if (cond == COND_E)
		logical = true;
#endif
	g(gen_frame_load_cmp_imm(ctx, size, logical, sx, slot, offset, value));
	g(gen_frame_set_cond(ctx, size, false, cond, slot_r));
#else
	g(gen_frame_load(ctx, size, sx, slot, offset, R_SCRATCH_NA_1));
	g(gen_frame_cmp_imm_set_cond_reg(ctx, size, R_SCRATCH_NA_1, value, cond, slot_r));
#endif
	return true;
}

#if defined(ARCH_X86)
static bool attr_w gen_cmov(struct codegen_context *ctx, unsigned op_size, unsigned cond, unsigned reg, uint32_t *label)
{
	if (unlikely(op_size < OP_SIZE_4))
		internal(file_line, "gen_cmov: unsupported operand size");
	if (likely(cpu_test_feature(CPU_FEATURE_cmov))) {
		gen_insn(INSN_CMOV, op_size, cond, 0);
		gen_one(reg);
		gen_one(reg);
		*label = 0;
	} else {
		*label = alloc_label(ctx);
		if (unlikely(!*label))
			return false;
		gen_insn(INSN_JMP_COND, op_size, cond ^ 1, 0);
		gen_four(*label);
		gen_insn(INSN_MOV, op_size, 0, 0);
		gen_one(reg);
	}
	return true;
}
#endif

static bool attr_w gen_extend(struct codegen_context *ctx, unsigned op_size, bool sx, unsigned dest, unsigned src)
{
	unsigned attr_unused shift;
	if (unlikely(op_size == OP_SIZE_NATIVE)) {
		if (dest != src) {
			gen_insn(INSN_MOV, op_size, 0, 0);
			gen_one(dest);
			gen_one(src);
			return true;
		}
		return true;
	}
#if defined(ARCH_IA64) || defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_X86)
	gen_insn(sx ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(dest);
	gen_one(src);
	return true;
#endif
#if defined(ARCH_POWER)
	if (!sx || op_size == OP_SIZE_2 || cpu_test_feature(CPU_FEATURE_ppc)) {
		gen_insn(sx ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
	if (OP_SIZE_NATIVE == OP_SIZE_4) {
		shift = op_size == OP_SIZE_1 ? 24 : 16;
	} else if (OP_SIZE_NATIVE == OP_SIZE_8) {
		shift = op_size == OP_SIZE_1 ? 56 : op_size == OP_SIZE_2 ? 48 : 32;
	} else {
		internal(file_line, "gen_extend: invalid OP_SIZE_NATIVE");
	}
#if defined(ARCH_ALPHA)
	if (!sx) {
		g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_ZAPNOT, dest, src, op_size == OP_SIZE_1 ? 0x1 : op_size == OP_SIZE_2 ? 0x3 : 0xf));
		return true;
	} else if (op_size == OP_SIZE_4 || ARCH_HAS_BWX) {
		gen_insn(INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
#if defined(ARCH_MIPS)
	if (sx && shift == 32) {
		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(OP_SIZE_4), OP_SIZE_4, ROT_SHL, ROT_WRITES_FLAGS(ROT_SHL));
		gen_one(dest);
		gen_one(src);
		gen_one(ARG_IMM);
		gen_eight(0);
		return true;
	}
	if (sx && MIPS_HAS_ROT) {
		gen_insn(INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
#if defined(ARCH_S390)
	if (((op_size == OP_SIZE_1 || op_size == OP_SIZE_2) && cpu_test_feature(CPU_FEATURE_extended_imm)) || op_size == OP_SIZE_4) {
		gen_insn(!sx ? INSN_MOV : INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
#if defined(ARCH_SPARC)
	if (shift == 32) {
		gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(OP_SIZE_4), OP_SIZE_4, sx ? ROT_SAR : ROT_SHR, ROT_WRITES_FLAGS(sx ? ROT_SAR : ROT_SHR));
		gen_one(dest);
		gen_one(src);
		gen_one(ARG_IMM);
		gen_eight(0);
		return true;
	}
#endif
#if defined(ARCH_RISCV64)
	if (sx && (op_size == OP_SIZE_4 || likely(cpu_test_feature(CPU_FEATURE_zbb)))) {
		gen_insn(INSN_MOVSX, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
	if (!sx && ((op_size == OP_SIZE_1) ||
		    (op_size == OP_SIZE_2 && likely(cpu_test_feature(CPU_FEATURE_zbb))) ||
		    (op_size == OP_SIZE_4 && likely(cpu_test_feature(CPU_FEATURE_zba))))) {
		gen_insn(INSN_MOV, op_size, 0, 0);
		gen_one(dest);
		gen_one(src);
		return true;
	}
#endif
	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, dest, src, shift, false));
	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, sx ? ROT_SAR : ROT_SHR, dest, dest, shift, false));

	return true;
}

static bool attr_w gen_cmp_extended(struct codegen_context *ctx, unsigned cmp_op_size, unsigned sub_op_size, unsigned reg, unsigned attr_unused tmp_reg, uint32_t label_ovf)
{
	if (unlikely(sub_op_size >= cmp_op_size))
		return true;
#if defined(ARCH_ARM64)
	gen_insn(INSN_CMP, cmp_op_size, 0, 1);
	gen_one(reg);
	gen_one(ARG_EXTENDED_REGISTER);
	gen_one(sub_op_size == OP_SIZE_1 ? ARG_EXTEND_SXTB : sub_op_size == OP_SIZE_2 ? ARG_EXTEND_SXTH : ARG_EXTEND_SXTW);
	gen_one(reg);

	gen_insn(INSN_JMP_COND, cmp_op_size, COND_NE, 0);
	gen_four(label_ovf);
#else
	g(gen_extend(ctx, sub_op_size, true, tmp_reg, reg));

	g(gen_cmp_test_jmp(ctx, INSN_CMP, cmp_op_size, reg, tmp_reg, COND_NE, label_ovf));
#endif
	return true;
}

static bool attr_w gen_lea3(struct codegen_context *ctx, unsigned dest, unsigned base, unsigned shifted, unsigned shift, int64_t offset)
{
#if defined(ARCH_X86)
	gen_insn(INSN_LEA3, i_size(OP_SIZE_ADDRESS), shift, 0);
	gen_one(dest);
	gen_one(base);
	gen_one(shifted);
	gen_one(ARG_IMM);
	gen_eight(likely(imm_is_32bit(offset)) ? offset : 0);

	if (unlikely(!imm_is_32bit(offset)))
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, dest, dest, offset));

	return true;
#endif
	if (ARCH_HAS_SHIFTED_ADD(shift)) {
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
		gen_one(dest);
		gen_one(base);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | shift);
		gen_one(shifted);

		if (offset) {
			g(gen_imm(ctx, offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
			gen_one(dest);
			gen_one(dest);
			gen_imm_offset();
		}

		return true;
	}

	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, dest, shifted, shift, false));

	g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, dest, dest, base));

	if (offset)
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, dest, dest, offset));
	return true;
}

static bool attr_w gen_memcpy(struct codegen_context *ctx, unsigned dest_base, int64_t dest_offset, unsigned src_base, int64_t src_offset, size_t size, size_t attr_unused align)
{
	if (!size)
		return true;
	if (!ARCH_HAS_BWX) {
		if (align < 4 || (size & 3))
			goto call_memcpy;
	}
#if defined(ARCH_S390)
	if (size <= 0x10) {
		if (!(size & 3) || cpu_test_feature(CPU_FEATURE_extended_imm))
			goto do_explicit_copy;
	}
	if (size <= 0x100 && dest_offset >= 0 && dest_offset < 0x1000 && src_offset >= 0 && src_offset < 0x1000) {
		gen_insn(INSN_MEMCPY, 0, 0, 0);
		gen_one(ARG_ADDRESS_1);
		gen_one(dest_base);
		gen_eight(dest_offset);
		gen_one(ARG_ADDRESS_1);
		gen_one(src_base);
		gen_eight(src_offset);
		gen_one(ARG_IMM);
		gen_eight(size);
		return true;
	}
	goto call_memcpy;
do_explicit_copy:
#endif
	if (size <= INLINE_COPY_SIZE) {
		while (size) {
			unsigned this_step;
			unsigned this_op_size;
#if defined(ARCH_ARM)
			if (size >= 2U << OP_SIZE_NATIVE
#if defined(ARCH_ARM32)
				&& align >= 1U << OP_SIZE_NATIVE
#endif
			) {
				g(gen_address(ctx, src_base, src_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_LDP, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_SCRATCH_NA_1);
				gen_one(R_SCRATCH_NA_2);
				gen_address_offset();

				g(gen_address(ctx, dest_base, dest_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_STP, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_NA_1);
				gen_one(R_SCRATCH_NA_2);

				size -= 2U << OP_SIZE_NATIVE;
				src_offset += 2U << OP_SIZE_NATIVE;
				dest_offset += 2U << OP_SIZE_NATIVE;

				continue;
			}
#endif
			if (size >= 8 && OP_SIZE_NATIVE >= OP_SIZE_8)
				this_step = 8;
			else if (size >= 4)
				this_step = 4;
			else if (size >= 2)
				this_step = 2;
			else
				this_step = 1;
			if (UNALIGNED_TRAP)
				this_step = minimum(this_step, align);
			this_op_size = log_2(this_step);

			g(gen_address(ctx, src_base, src_offset, ARCH_PREFERS_SX(this_op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, this_op_size));
			gen_insn(ARCH_PREFERS_SX(this_op_size) ? INSN_MOVSX : INSN_MOV, this_op_size, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_address_offset();

			g(gen_address(ctx, dest_base, dest_offset, IMM_PURPOSE_STR_OFFSET, this_op_size));
			gen_insn(INSN_MOV, this_op_size, 0, 0);
			gen_address_offset();
			gen_one(R_SCRATCH_1);

			size -= this_step;
			src_offset += this_step;
			dest_offset += this_step;
		}
		return true;
	}

call_memcpy:
	if (unlikely(R_ARG0 == src_base)) {
		if (unlikely(R_ARG1 == dest_base))
			internal(file_line, "gen_memcpy: swapped registers: %u, %u", src_base, dest_base);
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG1, src_base, src_offset));
		g(gen_upcall_argument(ctx, 1));
	}

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG0, dest_base, dest_offset));
	g(gen_upcall_argument(ctx, 0));

	if (R_ARG0 != src_base) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG1, src_base, src_offset));
		g(gen_upcall_argument(ctx, 1));
	}

#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
	if (cpu_test_feature(CPU_FEATURE_erms)) {
		g(gen_load_constant(ctx, R_CX, size));

		gen_insn(INSN_MEMCPY, 0, 0, 0);
		gen_one(ARG_ADDRESS_1_POST_I);
		gen_one(R_DI);
		gen_eight(0);
		gen_one(ARG_ADDRESS_1_POST_I);
		gen_one(R_SI);
		gen_eight(0);
		gen_one(R_CX);
		return true;
	}
#endif

	g(gen_load_constant(ctx, R_ARG2, size));
	g(gen_upcall_argument(ctx, 2));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, mem_copy), 3));

	return true;
}

static bool attr_w gen_clear_bitmap(struct codegen_context *ctx, unsigned additional_offset, unsigned dest_base, int64_t dest_offset, frame_t bitmap_slots)
{
	if (bitmap_slots <= INLINE_BITMAP_SLOTS) {
		bool attr_unused scratch_2_zeroed = false;
		size_t bitmap_length = (size_t)bitmap_slots * slot_size;
		size_t clear_offset = 0;
		additional_offset += (unsigned)dest_offset;
#if defined(ARCH_X86)
		gen_insn(INSN_ALU, OP_SIZE_4, ALU_XOR, ALU_WRITES_FLAGS(ALU_XOR, false));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
#endif
#if defined(ARCH_ARM32) || defined(ARCH_S390)
		g(gen_load_constant(ctx, R_SCRATCH_1, 0));
#endif
		while (clear_offset < bitmap_length) {
			size_t len = bitmap_length - clear_offset;
			if (len > frame_align)
				len = frame_align;
			if (additional_offset)
				len = minimum(len, additional_offset & -additional_offset);
#if defined(ARCH_ARM32) || defined(ARCH_S390)
			len = minimum(len, 2U << OP_SIZE_NATIVE);
			if (len == 2U << OP_SIZE_NATIVE) {
				if (!scratch_2_zeroed) {
					g(gen_load_constant(ctx, R_SCRATCH_2, 0));
					scratch_2_zeroed = true;
				}
				g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_NATIVE));
				gen_insn(INSN_STP, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_2);
				goto next_loop;
			}
#elif defined(ARCH_ARM64)
			len = minimum(len, 1U << OP_SIZE_16);
			if (len == 1U << OP_SIZE_16) {
				g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_LDP_STP_OFFSET, OP_SIZE_8));
				g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, OP_SIZE_8));
				gen_insn(INSN_STP, OP_SIZE_NATIVE, 0, 0);
				gen_address_offset();
				gen_imm_offset();
				gen_imm_offset();
				goto next_loop;
			}
#elif defined(ARCH_X86)
			len = minimum(len, 1U << OP_SIZE_16);
			if (len == 1U << OP_SIZE_16 && cpu_test_feature(CPU_FEATURE_sse)) {
				if (!scratch_2_zeroed) {
					gen_insn(INSN_ALU, OP_SIZE_16, ALU_XOR, 0);
					gen_one(R_XMM0);
					gen_one(R_XMM0);
					gen_one(R_XMM0);
					scratch_2_zeroed = true;
				}
				g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_VLDR_VSTR_OFFSET, OP_SIZE_16));
				gen_insn(INSN_MOV, OP_SIZE_16, 0, 0);
				gen_address_offset();
				gen_one(R_XMM0);
				goto next_loop;
			}
#endif
			len = minimum(len, 1U << OP_SIZE_NATIVE);
			len = (size_t)1 << high_bit(len);
#if defined(ARCH_X86) || defined(ARCH_ARM32) || defined(ARCH_S390)
			g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_STR_OFFSET, log_2(len)));
			gen_insn(INSN_MOV, log_2(len), 0, 0);
			gen_address_offset();
			gen_one(R_SCRATCH_1);
#else
			g(gen_address(ctx, dest_base, dest_offset + clear_offset, IMM_PURPOSE_STR_OFFSET, log_2(len)));
			g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, log_2(len)));
			gen_insn(INSN_MOV, log_2(len), 0, 0);
			gen_address_offset();
			gen_imm_offset();
#endif
			goto next_loop;
next_loop:
			clear_offset += len;
			additional_offset += len;
		}
		return true;
	}
#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
	if (cpu_test_feature(CPU_FEATURE_erms)) {
		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_DI, dest_base, dest_offset));

		g(gen_load_constant(ctx, R_CX, (size_t)bitmap_slots * slot_size));

		gen_insn(INSN_ALU, OP_SIZE_4, ALU_XOR, ALU_WRITES_FLAGS(ALU_XOR, false));
		gen_one(R_AX);
		gen_one(R_AX);
		gen_one(R_AX);

		gen_insn(INSN_MEMSET, 0, 0, 0);
		gen_one(ARG_ADDRESS_1_POST_I);
		gen_one(R_DI);
		gen_eight(0);
		gen_one(R_CX);
		gen_one(R_AX);

		return true;
	}
#endif
	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG0, dest_base, dest_offset));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, (size_t)bitmap_slots * slot_size));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, mem_clear), 2));

	return true;
}

static bool attr_w load_function_offset(struct codegen_context *ctx, unsigned dest, size_t fn_offset)
{
	g(gen_frame_load(ctx, OP_SIZE_ADDRESS, false, 0, frame_offs(function), dest));

	g(gen_address(ctx, dest, fn_offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(dest);
	gen_address_offset();

	return true;
}

#define MODE_FIXED	0
#define MODE_INT	1
#define MODE_BOOL	2

static bool attr_w gen_alu(struct codegen_context *ctx, unsigned mode, unsigned op_size, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_2, frame_t slot_r)
{
	unsigned alu;
	bool sgn, mod;
	switch (mode) {
		case MODE_FIXED: switch (op) {
			case OPCODE_FIXED_OP_add:		alu = ALU_ADD; goto do_alu;
			case OPCODE_FIXED_OP_subtract:		alu = ALU_SUB; goto do_alu;
			case OPCODE_FIXED_OP_multiply:		goto do_multiply;
			case OPCODE_FIXED_OP_divide:
			case OPCODE_FIXED_OP_divide_alt1:	sgn = true; mod = false; goto do_divide;
			case OPCODE_FIXED_OP_udivide:
			case OPCODE_FIXED_OP_udivide_alt1:	sgn = false; mod = false; goto do_divide;
			case OPCODE_FIXED_OP_modulo:
			case OPCODE_FIXED_OP_modulo_alt1:	sgn = true; mod = true; goto do_divide;
			case OPCODE_FIXED_OP_umodulo:
			case OPCODE_FIXED_OP_umodulo_alt1:	sgn = false; mod = true; goto do_divide;
			case OPCODE_FIXED_OP_power:		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_binary_power_int8_t), op_size, slot_1, slot_2, slot_r, 0);
			case OPCODE_FIXED_OP_and:		alu = ALU_AND; goto do_alu;
			case OPCODE_FIXED_OP_or:		alu = ALU_OR; goto do_alu;
			case OPCODE_FIXED_OP_xor:		alu = ALU_XOR; goto do_alu;
			case OPCODE_FIXED_OP_shl:		alu = ROT_SHL; goto do_shift;
			case OPCODE_FIXED_OP_shr:		alu = ROT_SAR; goto do_shift;
			case OPCODE_FIXED_OP_ushr:		alu = ROT_SHR; goto do_shift;
			case OPCODE_FIXED_OP_rol:		alu = ROT_ROL; goto do_shift;
			case OPCODE_FIXED_OP_ror:		alu = ROT_ROR; goto do_shift;
			case OPCODE_FIXED_OP_bts:		alu = BTX_BTS; goto do_bt;
			case OPCODE_FIXED_OP_btr:		alu = BTX_BTR; goto do_bt;
			case OPCODE_FIXED_OP_btc:		alu = BTX_BTC; goto do_bt;
			case OPCODE_FIXED_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_FIXED_OP_not_equal:		alu = COND_NE; goto do_compare;
			case OPCODE_FIXED_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_FIXED_OP_less_equal:	alu = COND_LE; goto do_compare;
			case OPCODE_FIXED_OP_uless:		alu = COND_B; goto do_compare;
			case OPCODE_FIXED_OP_uless_equal:	alu = COND_BE; goto do_compare;
			case OPCODE_FIXED_OP_bt:		alu = BTX_BT; goto do_bt;
			default:				internal(file_line, "gen_alu: unsupported fixed operation %u", op);
		}
		case MODE_INT: switch (op) {
			case OPCODE_INT_OP_add:			alu = ALU_ADD; goto do_alu;
			case OPCODE_INT_OP_subtract:		alu = ALU_SUB; goto do_alu;
			case OPCODE_INT_OP_multiply:		goto do_multiply;
			case OPCODE_INT_OP_divide:
			case OPCODE_INT_OP_divide_alt1:		sgn = true; mod = false; goto do_divide;
			case OPCODE_INT_OP_modulo:
			case OPCODE_INT_OP_modulo_alt1:		sgn = true; mod = true; goto do_divide;
			case OPCODE_INT_OP_power:		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_binary_power_int8_t), op_size, slot_1, slot_2, slot_r, label_ovf);
			case OPCODE_INT_OP_and:			alu = ALU_AND; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_or:			alu = ALU_OR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_xor:			alu = ALU_XOR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_shl:			alu = ROT_SHL; goto do_shift;
			case OPCODE_INT_OP_shr:			alu = ROT_SAR; goto do_shift;
			case OPCODE_INT_OP_bts:			alu = BTX_BTS; goto do_bt;
			case OPCODE_INT_OP_btr:			alu = BTX_BTR; goto do_bt;
			case OPCODE_INT_OP_btc:			alu = BTX_BTC; goto do_bt;
			case OPCODE_INT_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_INT_OP_not_equal:		alu = COND_NE; goto do_compare;
			case OPCODE_INT_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_INT_OP_less_equal:		alu = COND_LE; goto do_compare;
			case OPCODE_INT_OP_bt:			alu = BTX_BT; goto do_bt;
			default:				internal(file_line, "gen_alu: unsupported int operation %u", op);
		}
		case MODE_BOOL: switch (op) {
			case OPCODE_BOOL_OP_and:		alu = ALU_AND; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_or:			alu = ALU_OR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_equal:		alu = COND_E; goto do_compare;
			case OPCODE_BOOL_OP_not_equal:		alu = ALU_XOR; mode = MODE_FIXED; goto do_alu;
			case OPCODE_BOOL_OP_less:		alu = COND_L; goto do_compare;
			case OPCODE_BOOL_OP_less_equal:		alu = COND_LE; goto do_compare;
			default:				internal(file_line, "gen_alu: unsupported bool operation %u", op);
		}
	}
	internal(file_line, "gen_alu: unsupported mode %u", mode);

	/*******
	 * ALU *
	 *******/
do_alu: {
		size_t attr_unused offset;
		uint8_t attr_unused long_imm;
		unsigned first_flags;
		unsigned second_flags;
		unsigned second_alu;
		unsigned attr_unused op_size_flags;
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
#if !defined(ARCH_X86) && !defined(ARCH_ARM) && !defined(ARCH_PARISC) && !defined(ARCH_POWER) && !defined(ARCH_SPARC32)
			if (mode == MODE_FIXED) {
				if (alu == ALU_ADD) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_add_,TYPE_INT_MAX)), slot_1, slot_2, slot_r, 0));
					return true;
				} else if (alu == ALU_SUB) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_subtract_,TYPE_INT_MAX)), slot_1, slot_2, slot_r, 0));
					return true;
				}
			} else if (mode == MODE_INT) {
				if (alu == ALU_ADD) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_binary_add_,TYPE_INT_MAX)), slot_1, slot_2, slot_r, label_ovf));
					return true;
				} else if (alu == ALU_SUB) {
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_binary_subtract_,TYPE_INT_MAX)), slot_1, slot_2, slot_r, label_ovf));
					return true;
				}
			}
#endif
			first_flags = alu == ALU_ADD || alu == ALU_SUB ? 2 : 0;
			second_flags = mode == MODE_INT ? 1 : 0;
			second_alu = alu == ALU_ADD ? ALU_ADC : alu == ALU_SUB ? ALU_SBB : alu;
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
#if defined(ARCH_X86)
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, alu, first_flags, slot_2, lo_word(OP_SIZE_NATIVE), R_SCRATCH_1));
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, second_alu, second_flags, slot_2, hi_word(OP_SIZE_NATIVE), R_SCRATCH_2));
#else
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_2, 0, R_SCRATCH_3, R_SCRATCH_4));
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, alu, first_flags | ALU_WRITES_FLAGS(alu, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_3);
#if defined(ARCH_PARISC)
			if (mode == MODE_INT) {
				gen_insn(INSN_ALU_FLAGS_TRAP, OP_SIZE_NATIVE, second_alu, ALU_WRITES_FLAGS(second_alu, false));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_4);
				gen_four(label_ovf);
			} else
#endif
			{
				gen_insn(first_flags ? INSN_ALU_FLAGS : INSN_ALU, OP_SIZE_NATIVE, second_alu, second_flags | ALU_WRITES_FLAGS(second_alu, false));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_4);
			}
#endif
#if !defined(ARCH_PARISC)
			if (mode == MODE_INT) {
				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_O, 0);
				gen_four(label_ovf);
			}
#endif
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
			return true;
		}

#if defined(ARCH_X86)
		if (1)
#elif defined(ARCH_S390)
		if (op_size >= OP_SIZE_4)
#else
		if (0)
#endif
		{
			g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load_op(ctx, op_size, false, alu, mode == MODE_INT, slot_2, 0, R_SCRATCH_1));
			goto check_ovf_store;
		}
		op_size_flags = !ARCH_HAS_FLAGS && !ARCH_SUPPORTS_TRAPS ? OP_SIZE_NATIVE : OP_SIZE_4;
#if defined(ARCH_POWER)
		op_size_flags = OP_SIZE_NATIVE;
#endif
		g(gen_frame_load(ctx, op_size, mode == MODE_INT && (op_size < op_size_flags || ARCH_SUPPORTS_TRAPS), slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, mode == MODE_INT && (op_size < op_size_flags || ARCH_SUPPORTS_TRAPS), slot_2, 0, R_SCRATCH_2));
#if !ARCH_HAS_FLAGS
		if (mode == MODE_INT && op_size >= OP_SIZE_4) {
			if (ARCH_SUPPORTS_TRAPS) {
				gen_insn(INSN_ALU_TRAP, op_size, alu, ALU_WRITES_FLAGS(alu, false));
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_2);
				gen_four(label_ovf);
				g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
				return true;
			}
			if (op_size >= OP_SIZE_NATIVE) {
				g(gen_3address_alu(ctx, i_size(op_size), alu, R_SCRATCH_3, R_SCRATCH_1, R_SCRATCH_2));
#if defined(ARCH_IA64)
				g(gen_3address_alu(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2));
				g(gen_3address_alu(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_3));
				if (alu == ALU_ADD) {
					gen_insn(INSN_ALU, i_size(op_size), ALU_ANDN, ALU_WRITES_FLAGS(ALU_ANDN, false));
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_2);
					gen_one(R_SCRATCH_1);
				} else {
					gen_insn(INSN_ALU, i_size(op_size), ALU_ANDN, ALU_WRITES_FLAGS(ALU_ANDN, false));
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_2);
				}
				g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), R_SCRATCH_1, R_SCRATCH_1, COND_S, label_ovf));
#else
				gen_insn(INSN_CMP_DEST_REG, i_size(op_size), COND_L, 0);
				gen_one(R_SCRATCH_1);
				if (alu == ALU_ADD) {
					gen_one(R_SCRATCH_3);
					gen_one(R_SCRATCH_1);
				} else {
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_3);
				}

				g(gen_imm(ctx, 0, IMM_PURPOSE_CMP, i_size(op_size)));
				gen_insn(INSN_CMP_DEST_REG, i_size(op_size), COND_L, 0);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_imm_offset();

				g(gen_cmp_test_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_1, R_SCRATCH_2, COND_NE, label_ovf));
#endif
				g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_3));
				return true;
			}
		}
#endif
		gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(i_size(op_size)), i_size(op_size), alu, (mode == MODE_INT && op_size >= op_size_flags) | ALU_WRITES_FLAGS(alu, false));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);

		if (mode == MODE_INT && unlikely(op_size < op_size_flags)) {
			g(gen_cmp_extended(ctx, op_size_flags, op_size, R_SCRATCH_1, R_SCRATCH_2, label_ovf));
		} else
check_ovf_store:
		if (mode == MODE_INT) {
			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
	}

	/************
	 * MULTIPLY *
	 ************/
do_multiply: {
		size_t attr_unused offset;
		uint8_t attr_unused long_imm;
		if (unlikely(op_size > OP_SIZE_NATIVE) || unlikely(!ARCH_HAS_MUL)) {
			if (mode == MODE_INT) {
				g(gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_binary_multiply_int8_t), op_size, slot_1, slot_2, slot_r, label_ovf));
				return true;
			}
#if defined(ARCH_X86)
			g(gen_frame_load(ctx, OP_SIZE_NATIVE, false, slot_1, hi_word(OP_SIZE_NATIVE), R_CX));
			g(gen_frame_load(ctx, OP_SIZE_NATIVE, false, slot_2, hi_word(OP_SIZE_NATIVE), R_AX));
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, ALU_MUL, true, slot_2, lo_word(OP_SIZE_NATIVE), R_CX));
			g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, ALU_MUL, true, slot_1, lo_word(OP_SIZE_NATIVE), R_AX));
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
			gen_one(R_CX);
			gen_one(R_CX);
			gen_one(R_AX);
			g(gen_frame_load(ctx, OP_SIZE_NATIVE, false, slot_2, lo_word(OP_SIZE_NATIVE), R_AX));

			offset = (size_t)slot_1 * slot_size + lo_word(OP_SIZE_NATIVE);
			g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_NATIVE));
			gen_insn(INSN_MUL_L, OP_SIZE_NATIVE, 0, 1);
			gen_one(R_AX);
			gen_one(R_DX);
			gen_one(R_AX);
			gen_address_offset();

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
			gen_one(R_DX);
			gen_one(R_DX);
			gen_one(R_CX);

			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_AX, R_DX));

			return true;
#elif defined(ARCH_ARM32)
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_2, 0, R_SCRATCH_3, R_SCRATCH_4));

			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_1);

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, false));
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_4);

			gen_insn(INSN_MADD, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_4);

			gen_insn(INSN_MUL_L, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_3);

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_4);

			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));

			return true;
#elif defined(ARCH_ARM64)
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_2, 0, R_SCRATCH_3, R_SCRATCH_4));

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_UMULH, ALU_WRITES_FLAGS(ALU_UMULH, false));
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_3);

			gen_insn(INSN_MADD, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_NA_1);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_NA_1);

			gen_insn(INSN_MADD, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_NA_1);

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_3);

			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));

			return true;
#else
			g(gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_binary_multiply_int8_t), op_size, slot_1, slot_2, slot_r, 0));
			return true;
#endif
		}

#if defined(ARCH_X86)
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load_op(ctx, op_size, false, ALU_MUL, mode == MODE_INT, slot_2, 0, R_SCRATCH_1));
		if (mode == MODE_INT) {
			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_ALPHA)
		if (mode == MODE_INT && op_size >= OP_SIZE_4 && ARCH_SUPPORTS_TRAPS) {
			g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, true, slot_2, 0, R_SCRATCH_2));

			gen_insn(INSN_ALU_TRAP, op_size, ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);
			gen_four(label_ovf);
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

			return true;
		}
#endif
#if defined(ARCH_ARM32)
		if (mode == MODE_INT && op_size == OP_SIZE_4) {
			g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, false, slot_2, 0, R_SCRATCH_2));

			gen_insn(INSN_MUL_L, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
			gen_one(R_SCRATCH_4);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_ASR | 0x1f);
			gen_one(R_SCRATCH_3);

			gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_3));

			return true;
		}
#endif
#if defined(ARCH_ARM64)
		if (mode == MODE_INT && op_size == OP_SIZE_4) {
			g(gen_frame_load(ctx, op_size, op_size < OP_SIZE_4, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, op_size < OP_SIZE_4, slot_2, 0, R_SCRATCH_2));
			gen_insn(INSN_ALU, OP_SIZE_8, ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, false));
			gen_one(R_SCRATCH_1);
			gen_one(ARG_EXTENDED_REGISTER);
			gen_one(ARG_EXTEND_SXTW);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_EXTENDED_REGISTER);
			gen_one(ARG_EXTEND_SXTW);
			gen_one(R_SCRATCH_2);

			gen_insn(INSN_CMP, OP_SIZE_8, 0, 1);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_EXTENDED_REGISTER);
			gen_one(ARG_EXTEND_SXTW);
			gen_one(R_SCRATCH_1);

			gen_insn(INSN_JMP_COND, OP_SIZE_8, COND_NE, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

			return true;
		}
		if (mode == MODE_INT && op_size == OP_SIZE_8) {
			g(gen_frame_load(ctx, op_size, op_size < OP_SIZE_4, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, op_size < OP_SIZE_4, slot_2, 0, R_SCRATCH_2));
			gen_insn(INSN_ALU, OP_SIZE_8, ALU_SMULH, ALU_WRITES_FLAGS(ALU_SMULH, false));
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			gen_insn(INSN_ALU, OP_SIZE_8, ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			gen_insn(INSN_CMP, OP_SIZE_8, 0, 1);
			gen_one(R_SCRATCH_3);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_ASR | 0x3f);
			gen_one(R_SCRATCH_1);

			gen_insn(INSN_JMP_COND, OP_SIZE_8, COND_NE, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

			return true;
		}
#endif
#if defined(ARCH_POWER)
		if (mode == MODE_INT && op_size == OP_SIZE_NATIVE) {
			g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, true, slot_2, 0, R_SCRATCH_2));

			gen_insn(INSN_ALU, op_size, ALU_MUL, 1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

			return true;
		}
#endif
#if defined(ARCH_LOONGARCH64) || (defined(ARCH_MIPS) && MIPS_R6) || defined(ARCH_RISCV64)
		if (mode == MODE_INT && op_size == OP_SIZE_NATIVE) {
			g(gen_frame_load(ctx, op_size, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, OP_SIZE_NATIVE, slot_2, 0, R_SCRATCH_2));

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SMULH, ALU_WRITES_FLAGS(ALU_SMULH, false));
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SAR, ROT_WRITES_FLAGS(ROT_SAR));
			gen_one(R_SCRATCH_4);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_IMM);
			gen_eight(0x3f);

			g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_3, R_SCRATCH_4, COND_NE, label_ovf));

			g(gen_frame_store(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1));

			return true;
		}
#endif
#if defined(ARCH_S390)
		if (mode == MODE_INT && op_size >= OP_SIZE_4 && likely(cpu_test_feature(CPU_FEATURE_misc_insn_ext_2))) {
			g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load_op(ctx, op_size, true, ALU_MUL, 1, slot_2, 0, R_SCRATCH_1));

			gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
			gen_four(label_ovf);

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}
#endif
#if (defined(ARCH_MIPS) && !MIPS_R6) || defined(ARCH_S390)
#if defined(ARCH_MIPS)
		if (mode == MODE_INT && op_size >= OP_SIZE_4)
#endif
#if defined(ARCH_S390)
		if (mode == MODE_INT && op_size == OP_SIZE_4)
#endif
		{
			g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
			g(gen_frame_load(ctx, op_size, true, slot_2, 0, R_SCRATCH_3));

			gen_insn(INSN_MUL_L, op_size, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_3);

			g(gen_3address_rot_imm(ctx, op_size, ROT_SAR, R_SCRATCH_4, R_SCRATCH_1, (1U << (op_size + 3)) - 1, false));

			g(gen_cmp_test_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_2, R_SCRATCH_4, COND_NE, label_ovf));

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}
#endif
		if (mode == MODE_INT && op_size == OP_SIZE_NATIVE) {
			g(gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_binary_multiply_int8_t), op_size, slot_1, slot_2, slot_r, label_ovf));
			return true;
		}

		g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
		if (op_size < OP_SIZE_NATIVE && mode == MODE_INT) {
			g(gen_frame_load(ctx, op_size, true, slot_2, 0, R_SCRATCH_2));

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);
		} else {
			g(gen_frame_load_op(ctx, op_size, true, ALU_MUL, 0, slot_2, 0, R_SCRATCH_1));
		}

		if (mode == MODE_INT) {
			g(gen_cmp_extended(ctx, OP_SIZE_NATIVE, op_size, R_SCRATCH_1, R_SCRATCH_2, label_ovf));
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

		return true;
	}

	/**********
	 * DIVIDE *
	 **********/
do_divide: {
		uint32_t attr_unused label_skip = 0;	/* avoid warning */
		uint32_t attr_unused label_skip2 = 0;	/* avoid warning */
		uint32_t attr_unused label_end = 0;	/* avoid warning */
		uint32_t attr_unused label_div_0 = 0;	/* avoid warning */
		unsigned attr_unused divide_alu = 0;	/* avoid warning */
		bool attr_unused have_mod = false;
		bool attr_unused force_sx = false;
		unsigned attr_unused div_op_size = i_size(op_size);
		if (unlikely(op_size > OP_SIZE_NATIVE) || unlikely(!ARCH_HAS_DIV)
#if defined(ARCH_S390)
			|| !(Z || (op_size <= OP_SIZE_4 && sgn))
#endif
		   ) {
			size_t upcall;
			if (mode == MODE_INT) {
				upcall = !mod ? offsetof(struct cg_upcall_vector_s, INT_binary_divide_int8_t) : offsetof(struct cg_upcall_vector_s, INT_binary_modulo_int8_t);
			} else if (sgn) {
				upcall = !mod ? offsetof(struct cg_upcall_vector_s, FIXED_binary_divide_int8_t) : offsetof(struct cg_upcall_vector_s, FIXED_binary_modulo_int8_t);
			} else {
				upcall = !mod ? offsetof(struct cg_upcall_vector_s, FIXED_binary_udivide_int8_t) : offsetof(struct cg_upcall_vector_s, FIXED_binary_umodulo_int8_t);
			}
			g(gen_alu_typed_upcall(ctx, upcall, op_size, slot_1, slot_2, slot_r, mode == MODE_INT ? label_ovf : 0));
			return true;
		}
#if defined(ARCH_X86) || defined(ARCH_S390)
		if (mode == MODE_FIXED) {
			label_skip = alloc_label(ctx);
			if (unlikely(!label_skip))
				return false;
			label_end = alloc_label(ctx);
			if (unlikely(!label_end))
				return false;
			if (sgn) {
				label_skip2 = alloc_label(ctx);
				if (unlikely(!label_skip2))
					return false;
			}
		}
#if defined(ARCH_X86)
		if (R_SCRATCH_1 != R_AX || R_SCRATCH_2 != R_DX || R_SCRATCH_3 != R_CX)
			internal(file_line, "gen_alu: bad scratch registers");
#endif
		g(gen_frame_load(ctx, op_size, sgn, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, sgn, slot_2, 0, R_SCRATCH_3));

		g(gen_jmp_on_zero(ctx, i_size(op_size), R_SCRATCH_3, COND_E, mode == MODE_INT ? label_ovf : label_skip));

		if (sgn) {
			uint64_t val;
			uint32_t label_not_minus_1;
			label_not_minus_1 = alloc_label(ctx);
			if (unlikely(!label_not_minus_1))
				return false;

			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_3, -1, COND_NE, label_not_minus_1));

			val = -(uint64_t)0x80 << (((1 << op_size) - 1) * 8);
			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, op_size, R_SCRATCH_1, val, COND_E, mode == MODE_INT ? label_ovf : label_skip2));

			gen_label(label_not_minus_1);
		}

#if defined(ARCH_X86)
		if (op_size >= OP_SIZE_2) {
			if (sgn) {
				gen_insn(INSN_CWD + ARCH_PARTIAL_ALU(op_size), op_size, 0, 0);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_1);
				if (op_size == OP_SIZE_2)
					gen_one(R_SCRATCH_2);
			} else {
				gen_insn(INSN_ALU, OP_SIZE_4, ALU_XOR, 1);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
			}
		}
		gen_insn(INSN_DIV_L, op_size, sgn, 1);
		gen_one(R_SCRATCH_1);
		gen_one(i_size(op_size) == OP_SIZE_1 ? R_SCRATCH_1 : R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_one(i_size(op_size) == OP_SIZE_1 ? R_SCRATCH_1 : R_SCRATCH_2);
		gen_one(R_SCRATCH_3);
#else
		if (!sgn && op_size < OP_SIZE_4) {
			g(gen_extend(ctx, op_size, false, R_SCRATCH_1, R_SCRATCH_1));
			g(gen_extend(ctx, op_size, false, R_SCRATCH_3, R_SCRATCH_3));
		}
		if (!sgn) {
			g(gen_load_constant(ctx, R_SCRATCH_2, 0));
		} else if (op_size <= OP_SIZE_4) {
			g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_2, R_SCRATCH_1, (1U << (OP_SIZE_NATIVE + 3)) - 1, false));
		}
		gen_insn(INSN_DIV_L, i_size(op_size), sgn, 1);
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_3);
#endif
		if (mod && i_size(op_size) == OP_SIZE_1) {
			gen_insn(INSN_ROT_PARTIAL, OP_SIZE_2, ROT_SHR, 1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_IMM);
			gen_eight(8);
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		} else if (mod) {
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));
		} else {
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		}
		if (mode == MODE_FIXED) {
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(label_end);

			if (sgn) {
				gen_label(label_skip2);

				if (mod)
					g(gen_frame_clear(ctx, op_size, slot_r));
				else
					g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(label_end);
			}

			gen_label(label_skip);
			if (!mod)
				g(gen_frame_clear(ctx, op_size, slot_r));
			else
				g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			gen_label(label_end);
		}
		return true;
#else
#if defined(ARCH_MIPS)
		have_mod = true;
		div_op_size = maximum(op_size, OP_SIZE_4);
		if (op_size == OP_SIZE_4)
			force_sx = true;
#endif
#if defined(ARCH_POWER)
		have_mod = cpu_test_feature(CPU_FEATURE_v30);
		div_op_size = maximum(op_size, OP_SIZE_4);
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_RISCV64)
		have_mod = true;
		div_op_size = maximum(op_size, OP_SIZE_4);
#endif
		label_end = alloc_label(ctx);
		if (unlikely(!label_end))
			return false;

		g(gen_frame_load(ctx, op_size, (sgn && op_size < i_size(op_size)) || force_sx, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, (sgn && op_size < i_size(op_size)) || force_sx, slot_2, 0, R_SCRATCH_2));

		if (ARCH_PREFERS_SX(op_size) && !sgn && op_size < i_size(op_size)) {
			g(gen_extend(ctx, op_size, false, R_SCRATCH_1, R_SCRATCH_1));
			g(gen_extend(ctx, op_size, false, R_SCRATCH_2, R_SCRATCH_2));
		}

		if (mode == MODE_INT) {
			g(gen_jmp_on_zero(ctx, i_size(op_size), R_SCRATCH_2, COND_E, label_ovf));
			if (sgn) {
				uint64_t val;
				uint32_t label_not_minus_1;
				label_not_minus_1 = alloc_label(ctx);
				if (unlikely(!label_not_minus_1))
					return false;

				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_2, -1, COND_NE, label_not_minus_1));

				val = 0xFFFFFFFFFFFFFF80ULL << (((1 << op_size) - 1) * 8);
				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_1, val, COND_E, label_ovf));

				gen_label(label_not_minus_1);
			}
		} else {
#if !(defined(ARCH_ARM) && ARM_ASM_DIV_NO_TRAP)
			if (!mod) {
				g(gen_load_constant(ctx, R_SCRATCH_3, 0));
			} else {
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_1);
			}
			g(gen_jmp_on_zero(ctx, i_size(op_size), R_SCRATCH_2, COND_E, label_end));
			if (sgn) {
				uint64_t val;
				uint32_t label_not_minus_1;
				label_not_minus_1 = alloc_label(ctx);
				if (unlikely(!label_not_minus_1))
					return false;

				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_2, -1, COND_NE, label_not_minus_1));

				if (!mod) {
					gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
					gen_one(R_SCRATCH_3);
					gen_one(R_SCRATCH_1);
				} else {
					g(gen_load_constant(ctx, R_SCRATCH_3, 0));
				}

				val = 0xFFFFFFFFFFFFFF80ULL << (((1 << op_size) - 1) * 8);
				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_1, val, COND_E, label_end));

				gen_label(label_not_minus_1);
			}
#endif
		}
		if (mod && have_mod) {
			g(gen_3address_alu(ctx, div_op_size, sgn ? ALU_SREM : ALU_UREM, R_SCRATCH_3, R_SCRATCH_1, R_SCRATCH_2));
		} else {
			g(gen_3address_alu(ctx, div_op_size, sgn ? ALU_SDIV : ALU_UDIV, R_SCRATCH_3, R_SCRATCH_1, R_SCRATCH_2));
		}

		if (mod && !have_mod) {
#if defined(ARCH_ARM)
			gen_insn(INSN_MADD, i_size(op_size), 1, 0);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
#else
			g(gen_3address_alu(ctx, i_size(op_size), ALU_MUL, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_3));

			g(gen_3address_alu(ctx, i_size(op_size), ALU_SUB, R_SCRATCH_3, R_SCRATCH_1, R_SCRATCH_2));
#endif
		}

		gen_label(label_end);
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_3));
		return true;
#endif
	}
	/*********
	 * SHIFT *
	 *********/
do_shift: {
		bool sx;
		bool must_mask;
		unsigned op_s;
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
			size_t upcall;
			if (mode == MODE_FIXED) {
				switch (alu) {
					case ROT_SHL:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_shl_,TYPE_INT_MAX));
							break;
					case ROT_SAR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_shr_,TYPE_INT_MAX));
							break;
					case ROT_SHR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_ushr_,TYPE_INT_MAX));
							break;
					case ROT_ROL:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_rol_,TYPE_INT_MAX));
							break;
					case ROT_ROR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_ror_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid shift %u", alu);
				}
			} else {
				switch (alu) {
					case ROT_SHL:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_shl_,TYPE_INT_MAX));
							break;
					case ROT_SAR:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_shr_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid shift %u", alu);
				}
			}
			g(gen_alu_upcall(ctx, upcall, slot_1, slot_2, slot_r, mode == MODE_INT ? label_ovf : 0));
			return true;
		}
		op_s = i_size_rot(op_size);
#if defined(ARCH_X86)
		if (mode == MODE_INT && alu == ROT_SHL && op_size < OP_SIZE_NATIVE)
			op_s = op_size + 1;
#endif
		must_mask = op_size < ARCH_SHIFT_SIZE;
		sx = (alu == ROT_SAR && op_size < op_s) || (alu == ROT_SHL && op_size < OP_SIZE_NATIVE && mode == MODE_INT);
#if defined(ARCH_MIPS)
		sx |= op_size == OP_SIZE_4;
#endif
		g(gen_frame_load(ctx, op_size, sx, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, false, slot_2, 0, R_SCRATCH_3));
		if (ARCH_PREFERS_SX(op_size) && !sx && op_size < op_s)
			g(gen_extend(ctx, op_size, false, R_SCRATCH_1, R_SCRATCH_1));

		if (mode == MODE_INT) {
			int64_t imm = (1U << (op_size + 3)) - 1;
			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, maximum(op_size, OP_SIZE_4), R_SCRATCH_3, imm, COND_A, label_ovf));
		} else {
#if defined(ARCH_ARM)
			if (alu == ROT_ROL) {
				gen_insn(INSN_ALU1, OP_SIZE_4, ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_3);
				alu = ROT_ROR;
			}
#endif
#if defined(ARCH_LOONGARCH64)
			if (alu == ROT_ROL && op_size >= OP_SIZE_4) {
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_3);
				alu = ROT_ROR;
			}
#endif
#if defined(ARCH_MIPS)
			if (MIPS_HAS_ROT && alu == ROT_ROL && op_size >= OP_SIZE_4) {
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_3);
				alu = ROT_ROR;
			}
#endif
#if defined(ARCH_POWER)
			if (alu == ROT_ROR && op_size >= OP_SIZE_4) {
				gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(OP_SIZE_NATIVE), OP_SIZE_NATIVE, ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_3);
				alu = ROT_ROL;
			}
#endif
#if defined(ARCH_S390)
			if (Z && alu == ROT_ROR && op_size >= OP_SIZE_4) {
				gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(OP_SIZE_4), OP_SIZE_4, ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_3);
				alu = ROT_ROL;
			}
#endif
			if (must_mask) {
				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_4), ALU_AND, R_SCRATCH_3, R_SCRATCH_3, (1U << (op_size + 3)) - 1));
			}
		}

#if defined(ARCH_X86)
		if (mode == MODE_INT && alu == ROT_SHL && op_size == OP_SIZE_NATIVE) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
		}

		g(gen_3address_rot(ctx, op_s, alu, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));

		if (mode == MODE_INT && alu == ROT_SHL) {
			if (op_size < OP_SIZE_NATIVE) {
				gen_insn(INSN_MOVSX, op_size, 0, 0);
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_1);

				g(gen_cmp_test_jmp(ctx, INSN_CMP, op_s, R_SCRATCH_1, R_SCRATCH_3, COND_NE, label_ovf));
			} else {
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_SCRATCH_4);
				gen_one(R_SCRATCH_1);

				g(gen_3address_rot(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_4, R_SCRATCH_4, R_SCRATCH_3));

				g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_2, R_SCRATCH_4, COND_NE, label_ovf));
			}
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_ARM)
		if (op_size <= OP_SIZE_2 && alu == ROT_ROR) {
			gen_insn(INSN_ALU, OP_SIZE_4, ALU_OR, ALU_WRITES_FLAGS(ALU_OR, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | (1U << (op_size + 3)));
			gen_one(R_SCRATCH_1);
			if (op_size == OP_SIZE_1)
				alu = ROT_SHR;
		}
		goto do_generic_shift;
#endif
#if defined(ARCH_LOONGARCH64)
		if (alu == ROT_ROR && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
#if defined(ARCH_MIPS)
		if (MIPS_HAS_ROT && alu == ROT_ROR && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
#if defined(ARCH_POWER)
		if (alu == ROT_ROL && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
#if defined(ARCH_RISCV64)
		if ((alu == ROT_ROL || alu == ROT_ROR) && likely(cpu_test_feature(CPU_FEATURE_zbb))) {
			if (likely(op_size >= OP_SIZE_4)) {
				goto do_generic_shift;
			}
		}
#endif
#if defined(ARCH_S390)
		if (Z && alu == ROT_ROL && op_size >= OP_SIZE_4)
			goto do_generic_shift;
#endif
		if (alu == ROT_ROL || alu == ROT_ROR) {
			g(gen_3address_rot(ctx, op_s, alu == ROT_ROL ? ROT_SHL : ROT_SHR, R_SCRATCH_2, R_SCRATCH_1, R_SCRATCH_3));
			gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(i_size(OP_SIZE_4)), i_size(OP_SIZE_4), ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_3);
			if (must_mask) {
				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_4), ALU_AND, R_SCRATCH_3, R_SCRATCH_3, (1U << (op_size + 3)) - 1));
			}
			g(gen_3address_rot(ctx, op_s, alu == ROT_ROL ? ROT_SHR : ROT_SHL, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));
			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_OR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2));
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}

		goto do_generic_shift;
do_generic_shift:
		if (mode == MODE_INT && alu == ROT_SHL) {
#if defined(ARCH_S390)
			if (op_size >= OP_SIZE_4) {
				g(gen_3address_rot(ctx, op_size, ROT_SAL, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));

				gen_insn(INSN_JMP_COND, op_size, COND_O, 0);
				gen_four(label_ovf);
			} else
#endif
			if (op_size <= OP_SIZE_NATIVE - 1) {
				g(gen_3address_rot(ctx, OP_SIZE_NATIVE, alu, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));

				g(gen_cmp_extended(ctx, OP_SIZE_NATIVE, op_size, R_SCRATCH_1, R_SCRATCH_2, label_ovf));
			} else {
				g(gen_3address_rot(ctx, OP_SIZE_NATIVE, alu, R_SCRATCH_2, R_SCRATCH_1, R_SCRATCH_3));

				g(gen_3address_rot(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_4, R_SCRATCH_2, R_SCRATCH_3));

				g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_4, COND_NE, label_ovf));

				g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));

				return true;
			}
		} else {
			g(gen_3address_rot(ctx, op_s, alu, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
	}
	/******
	 * BT *
	 ******/
do_bt: {
		unsigned attr_unused op_s;
		bool need_mask;
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
			size_t upcall;
			if (mode == MODE_FIXED) {
				switch (alu) {
					case BTX_BTS:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_bts_,TYPE_INT_MAX));
							break;
					case BTX_BTR:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_btr_,TYPE_INT_MAX));
							break;
					case BTX_BTC:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_btc_,TYPE_INT_MAX));
							break;
					case BTX_BT:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_bt_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid bit test %u", alu);
				}
			} else {
				switch (alu) {
					case BTX_BTS:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_bts_,TYPE_INT_MAX));
							break;
					case BTX_BTR:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_btr_,TYPE_INT_MAX));
							break;
					case BTX_BTC:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_btc_,TYPE_INT_MAX));
							break;
					case BTX_BT:	upcall = offsetof(struct cg_upcall_vector_s, cat(INT_binary_bt_,TYPE_INT_MAX));
							break;
					default:	internal(file_line, "do_alu: invalid bit test %u", alu);
				}
			}
			g(gen_alu_upcall(ctx, upcall, slot_1, slot_2, slot_r, label_ovf));
			return true;
		}
		op_s = minimum(OP_SIZE_NATIVE, ARCH_SHIFT_SIZE);
		op_s = maximum(op_s, op_size);
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, false, slot_2, 0, R_SCRATCH_2));
		if (mode == MODE_INT) {
			int64_t imm = (1U << (op_size + 3)) - 1;
			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, maximum(op_size, OP_SIZE_4), R_SCRATCH_2, imm, alu == BTX_BT ? COND_A : COND_AE, label_ovf));
		}
		if (alu != BTX_BT) {
			if (!ARCH_HAS_BTX(alu, OP_SIZE_NATIVE, false))
				goto do_generic_bt;
			need_mask = !ARCH_HAS_BTX(alu, op_size, false);
		} else {
#if defined(ARCH_X86)
			need_mask = op_size < OP_SIZE_2;
#else
			if (!ARCH_HAS_BTX(BTX_BTEXT, OP_SIZE_NATIVE, false))
				goto do_generic_bt;
			need_mask = !ARCH_HAS_BTX(BTX_BTEXT, op_size, false);
#endif
		}
		if (need_mask) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_4, ALU_AND, R_SCRATCH_2, R_SCRATCH_2, (1U << (op_size + 3)) - 1));
		}
		if (alu == BTX_BT) {
#if defined(ARCH_X86)
			gen_insn(INSN_BT, maximum(op_size, OP_SIZE_2), 0, 1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			g(gen_frame_set_cond(ctx, maximum(op_size, OP_SIZE_2), false, COND_B, slot_r));
#else
			gen_insn(INSN_BTX, need_mask ? OP_SIZE_NATIVE : op_size, BTX_BTEXT, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));
#endif
		} else {
#if defined(ARCH_X86)
			gen_insn(INSN_BTX, maximum(op_size, OP_SIZE_2), alu, 1);
#else
			gen_insn(INSN_BTX, need_mask ? OP_SIZE_NATIVE : op_size, alu, 0);
#endif
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		}
		return true;

		goto do_generic_bt;
do_generic_bt:
		if (mode == MODE_FIXED && op_size < ARCH_SHIFT_SIZE) {
			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_4), ALU_AND, R_SCRATCH_2, R_SCRATCH_2, (1U << (op_size + 3)) - 1));
		}
		g(gen_load_constant(ctx, R_SCRATCH_3, 1));

		g(gen_3address_rot(ctx, op_s, ROT_SHL, R_SCRATCH_3, R_SCRATCH_3, R_SCRATCH_2));

		switch (alu) {
			case BTX_BT:
#if ARCH_HAS_FLAGS
#if defined(ARCH_S390) || defined(ARCH_POWER)
				gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(i_size(op_size)), i_size(op_size), ALU_AND, 1);
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_3);
#else
				gen_insn(INSN_TEST, i_size(op_size), 0, 1);
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_3);
#endif
				g(gen_frame_set_cond(ctx, maximum(op_size, OP_SIZE_4), false, COND_NE, slot_r));
#else
				g(gen_3address_alu(ctx, i_size(op_size), ALU_AND, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));

				g(gen_frame_cmp_imm_set_cond_reg(ctx, i_size(op_size), R_SCRATCH_1, 0, COND_NE, slot_r));
#endif
				return true;
			case BTX_BTS:
				g(gen_3address_alu(ctx, i_size(op_size), ALU_OR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));
				break;
			case BTX_BTR:
				if (!ARCH_HAS_ANDN) {
					g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_3, R_SCRATCH_3, -1));

					g(gen_3address_alu(ctx, i_size(op_size), ALU_AND, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));
					break;
				}
				g(gen_3address_alu(ctx, i_size(op_size), ALU_ANDN, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));
				break;
			case BTX_BTC:
				g(gen_3address_alu(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));
				break;
			default:
				internal(file_line, "gen_alu: unsupported bit test %u", alu);
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));

		return true;
	}
	/***********
	 * COMPARE *
	 ***********/
do_compare: {
		if (unlikely(op_size > OP_SIZE_NATIVE)) {
			size_t attr_unused upcall;
			switch (alu) {
				case COND_E:
				case COND_NE:
					g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, ALU_XOR, 0, slot_2, lo_word(OP_SIZE_NATIVE), R_SCRATCH_1));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, ALU_XOR, 0, slot_2, hi_word(OP_SIZE_NATIVE), R_SCRATCH_2));
#if defined(ARCH_ARM64)
					gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, ALU_WRITES_FLAGS(ALU_OR, false));
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_2);

					gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
					gen_one(R_SCRATCH_1);
					gen_one(ARG_IMM);
					gen_eight(0);
#else
					gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, ARCH_HAS_FLAGS);
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_2);
#endif
#if ARCH_HAS_FLAGS
					g(gen_frame_set_cond(ctx, OP_SIZE_NATIVE, false, alu, slot_r));
#else
					g(gen_frame_cmp_imm_set_cond_reg(ctx, OP_SIZE_NATIVE, R_SCRATCH_1, 0, alu, slot_r));
#endif
					return true;
#if defined(ARCH_X86) || defined(ARCH_ARM)
				case COND_L:
				case COND_B:
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, false, slot_2, lo_word(OP_SIZE_NATIVE), R_SCRATCH_2));
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, false, slot_1, hi_word(OP_SIZE_NATIVE), R_SCRATCH_1));
					g(gen_frame_load_cmp(ctx, OP_SIZE_NATIVE, false, false, true, slot_1, lo_word(OP_SIZE_NATIVE), R_SCRATCH_2));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, ALU_SBB, true, slot_2, hi_word(OP_SIZE_NATIVE), R_SCRATCH_1));
					g(gen_frame_set_cond(ctx, OP_SIZE_NATIVE, false, alu, slot_r));
					return true;
				case COND_LE:
				case COND_BE:
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, false, slot_1, lo_word(OP_SIZE_NATIVE), R_SCRATCH_2));
					g(gen_frame_load(ctx, OP_SIZE_NATIVE, false, slot_2, hi_word(OP_SIZE_NATIVE), R_SCRATCH_1));
					g(gen_frame_load_cmp(ctx, OP_SIZE_NATIVE, false, false, true, slot_2, lo_word(OP_SIZE_NATIVE), R_SCRATCH_2));
					g(gen_frame_load_op(ctx, OP_SIZE_NATIVE, false, ALU_SBB, true, slot_1, hi_word(OP_SIZE_NATIVE), R_SCRATCH_1));
					g(gen_frame_set_cond(ctx, OP_SIZE_NATIVE, false, alu == COND_LE ? COND_GE : COND_AE, slot_r));
					return true;
#else
				case COND_L:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_less_,TYPE_INT_MAX)); goto do_upcall;
				case COND_B:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_uless_,TYPE_INT_MAX)); goto do_upcall;
				case COND_LE:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_less_equal_,TYPE_INT_MAX)); goto do_upcall;
				case COND_BE:	upcall = offsetof(struct cg_upcall_vector_s, cat(FIXED_binary_uless_equal_,TYPE_INT_MAX)); goto do_upcall;
				do_upcall:	g(gen_alu_upcall(ctx, upcall, slot_1, slot_2, slot_r, 0));
						return true;
#endif
				default:
					internal(file_line, "gen_alu: unsupported condition %u", alu);
			}
			return false;
		}
#if defined(ARCH_X86)
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load_cmp_set_cond(ctx, op_size, false, slot_2, 0, R_SCRATCH_1, alu, slot_r));
#else
		g(gen_frame_load(ctx, op_size, alu == COND_L || alu == COND_LE, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_load_cmp_set_cond(ctx, op_size, alu == COND_L || alu == COND_LE, slot_2, 0, R_SCRATCH_1, alu, slot_r));
#endif
		return true;
	}
}

static bool attr_w gen_alu1(struct codegen_context *ctx, unsigned mode, unsigned op_size, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_r)
{
	unsigned alu;
	switch (mode) {
		case MODE_FIXED: switch (op) {
			case OPCODE_FIXED_OP_not:		alu = ALU1_NOT; goto do_alu;
			case OPCODE_FIXED_OP_neg:		alu = ALU1_NEG; goto do_alu;
			case OPCODE_FIXED_OP_inc:		alu = ALU1_INC; goto do_alu;
			case OPCODE_FIXED_OP_dec:		alu = ALU1_DEC; goto do_alu;
			case OPCODE_FIXED_OP_bswap:
			case OPCODE_FIXED_OP_bswap_alt1:	alu = ALU1_BSWAP; goto do_bswap;
			case OPCODE_FIXED_OP_brev:
			case OPCODE_FIXED_OP_brev_alt1:		alu = ALU1_BREV; goto do_brev;
			case OPCODE_FIXED_OP_bsf:
			case OPCODE_FIXED_OP_bsf_alt1:		alu = ALU1_BSF; goto do_bsf_bsr_popcnt;
			case OPCODE_FIXED_OP_bsr:
			case OPCODE_FIXED_OP_bsr_alt1:		alu = ALU1_BSR; goto do_bsf_bsr_popcnt;
			case OPCODE_FIXED_OP_popcnt:
			case OPCODE_FIXED_OP_popcnt_alt1:	alu = ALU1_POPCNT; goto do_bsf_bsr_popcnt;
			case OPCODE_FIXED_OP_to_int:		goto do_fixed_conv;
			case OPCODE_FIXED_OP_from_int:		goto do_fixed_conv;
			case OPCODE_FIXED_OP_uto_int:		goto conv_uto_int;
			case OPCODE_FIXED_OP_ufrom_int:		goto conv_ufrom_int;
			default:				internal(file_line, "gen_alu1: unsupported fixed operation %u", op);
		}
		case MODE_INT: switch (op) {
			case OPCODE_INT_OP_not:			alu = ALU1_NOT; mode = MODE_FIXED; goto do_alu;
			case OPCODE_INT_OP_neg:			alu = ALU1_NEG; goto do_alu;
			case OPCODE_INT_OP_inc:			alu = ALU1_INC; goto do_alu;
			case OPCODE_INT_OP_dec:			alu = ALU1_DEC; goto do_alu;
			case OPCODE_INT_OP_bsf:			alu = ALU1_BSF; goto do_bsf_bsr_popcnt;
			case OPCODE_INT_OP_bsr:			alu = ALU1_BSR; goto do_bsf_bsr_popcnt;
			case OPCODE_INT_OP_popcnt:
			case OPCODE_INT_OP_popcnt_alt1:		alu = ALU1_POPCNT; goto do_bsf_bsr_popcnt;
			case OPCODE_INT_OP_to_int:		goto do_conv;
			case OPCODE_INT_OP_from_int:		goto do_conv;
			default:				internal(file_line, "gen_alu1: unsupported int operation %u", op);
		}
		case MODE_BOOL: switch (op) {
			case OPCODE_BOOL_OP_not:		goto do_bool_not;
			default:				internal(file_line, "gen_alu1: unsupported bool operation %u", op);
		}
	}
	internal(file_line, "gen_alu1: unsupported mode %u", mode);

	/*******
	 * ALU *
	 *******/
do_alu: {
		if (op_size > OP_SIZE_NATIVE) {
#if !defined(ARCH_X86) && !defined(ARCH_ARM) && !defined(ARCH_POWER)
			if (alu == ALU1_NEG) {
				if (mode == MODE_FIXED)
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_unary_neg_,TYPE_INT_MAX)), slot_1, NO_FRAME_T, slot_r, 0));
				else
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_unary_neg_,TYPE_INT_MAX)), slot_1, NO_FRAME_T, slot_r, label_ovf));
				return true;
			}
			if (alu == ALU1_DEC) {
				if (mode == MODE_FIXED)
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_unary_dec_,TYPE_INT_MAX)), slot_1, NO_FRAME_T, slot_r, 0));
				else
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_unary_dec_,TYPE_INT_MAX)), slot_1, NO_FRAME_T, slot_r, label_ovf));
				return true;
			}
			if (alu == ALU1_INC) {
				if (mode == MODE_FIXED)
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(FIXED_unary_inc_,TYPE_INT_MAX)), slot_1, NO_FRAME_T, slot_r, 0));
				else
					g(gen_alu_upcall(ctx, offsetof(struct cg_upcall_vector_s, cat(INT_unary_inc_,TYPE_INT_MAX)), slot_1, NO_FRAME_T, slot_r, label_ovf));
				return true;
			}
#endif
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
#if defined(ARCH_S390)
			if (alu == ALU1_NOT) {
				g(gen_load_constant(ctx, R_SCRATCH_3, -1));

				g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_XOR, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_3));
				g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_XOR, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_3));

				g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
				return true;
			}
#endif
			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, alu, (alu == ALU1_INC || alu == ALU1_DEC || alu == ALU1_NEG ? 2 : 0) | ALU1_WRITES_FLAGS(alu));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			if (alu == ALU1_NOT) {
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_NOT, ALU1_WRITES_FLAGS(ALU1_NOT));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
			} else if (alu == ALU1_INC || alu == ALU1_DEC) {
				g(gen_imm(ctx, 0, alu == ALU1_INC ? IMM_PURPOSE_ADD : IMM_PURPOSE_SUB, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU, OP_SIZE_NATIVE, alu == ALU1_INC ? ALU_ADC : ALU_SBB, (mode == MODE_INT) | ALU_WRITES_FLAGS(alu == ALU1_INC ? ALU_ADC : ALU_SBB, is_imm()));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_imm_offset();
			} else {
#if defined(ARCH_X86)
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_NOT, ALU1_WRITES_FLAGS(ALU1_NOT));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);

				g(gen_imm(ctx, -1, IMM_PURPOSE_SUB, OP_SIZE_NATIVE));
				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SBB, ALU_WRITES_FLAGS(ALU_SBB, is_imm()));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_imm_offset();
#else
				gen_insn(INSN_ALU1_FLAGS, OP_SIZE_NATIVE, ALU1_NGC, (mode == MODE_INT) | ALU1_WRITES_FLAGS(ALU1_NGC));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
#endif
			}
			if (mode == MODE_INT) {
				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_O, 0);
				gen_four(label_ovf);
			}
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
			return true;
		}
		g(gen_frame_load(ctx, op_size, mode == MODE_INT && op_size >= OP_SIZE_4 && ARCH_SUPPORTS_TRAPS, slot_1, 0, R_SCRATCH_1));
#if defined(ARCH_S390)
		if (alu == ALU1_NOT) {
			g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_1, R_SCRATCH_1, -1));

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}
#endif
#if defined(ARCH_X86)
		gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(op_size), op_size, alu, (mode == MODE_INT) | ALU1_WRITES_FLAGS(alu));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
#else
		if (mode == MODE_INT) {
			bool arch_use_flags = ARCH_HAS_FLAGS;
#if defined(ARCH_POWER)
			arch_use_flags = false;
#endif
			if (!arch_use_flags && !ARCH_SUPPORTS_TRAPS && ARCH_IS_3ADDRESS && ARCH_HAS_ANDN && op_size == OP_SIZE_NATIVE) {
				gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(i_size(op_size)), i_size(op_size), alu, ALU1_WRITES_FLAGS(alu));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_1);

				if (alu == ALU1_NEG) {
					g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_AND, R_SCRATCH_3, R_SCRATCH_2, R_SCRATCH_1));
				} else if (alu == ALU1_INC) {
					g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ANDN, R_SCRATCH_3, R_SCRATCH_2, R_SCRATCH_1));
				} else if (alu == ALU1_DEC) {
					g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ANDN, R_SCRATCH_3, R_SCRATCH_1, R_SCRATCH_2));
				}
				g(gen_jmp_on_zero(ctx, OP_SIZE_NATIVE, R_SCRATCH_3, COND_S, label_ovf));

				g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));

				return true;
			}
			if (op_size <= OP_SIZE_2 || (!arch_use_flags && !ARCH_SUPPORTS_TRAPS)) {
				int64_t imm = ((alu != ALU1_INC && ARCH_PREFERS_SX(op_size) ? -0x80ULL : 0x80ULL) << (((1 << op_size) - 1) * 8)) - (alu == ALU1_INC);

				g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, imm, COND_E, label_ovf));

				mode = MODE_FIXED;
			}
		}
#if !ARCH_HAS_FLAGS
		if (mode == MODE_INT) {
			gen_insn(INSN_ALU1_TRAP, op_size, alu, ALU1_WRITES_FLAGS(alu));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_four(label_ovf);
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}
#endif
		gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(i_size(op_size)), i_size(op_size), alu, (mode == MODE_INT) | ALU1_WRITES_FLAGS(alu));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
#endif
		if (mode == MODE_INT) {
			gen_insn(INSN_JMP_COND, maximum(OP_SIZE_4, op_size), COND_O, 0);
			gen_four(label_ovf);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
	}

	/*******
	 * NOT *
	 *******/
do_bool_not: {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));

		g(gen_3address_alu_imm(ctx, i_size(op_size), ALU_XOR, R_SCRATCH_1, R_SCRATCH_1, 1));

		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
	}

	/*********
	 * BSWAP *
	 *********/
do_bswap: {
		bool attr_unused sx = false;
#if defined(ARCH_X86) || defined(ARCH_ARM) || defined(ARCH_IA64) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_RISCV64) || defined(ARCH_S390)
#if defined(ARCH_ARM32)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_armv6)))
			goto do_generic_bswap;
#endif
#if defined(ARCH_MIPS)
		if (unlikely(!MIPS_HAS_ROT))
			goto do_generic_bswap;
		sx = op_size == OP_SIZE_4;
#endif
#if defined(ARCH_RISCV64)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_zbb)))
			goto do_generic_bswap;
#endif
#if defined(ARCH_S390)
		if (op_size == OP_SIZE_2)
			goto do_generic_bswap;
#endif
#if defined(ARCH_X86)
		if (op_size >= OP_SIZE_4 && !cpu_test_feature(CPU_FEATURE_bswap))
			goto do_generic_bswap;
#endif
		if (op_size > OP_SIZE_NATIVE)
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
		else
			g(gen_frame_load(ctx, op_size, sx, slot_1, 0, R_SCRATCH_1));

		if (op_size == OP_SIZE_1) {
#if defined(ARCH_IA64) || defined(ARCH_RISCV64)
		} else if (op_size == OP_SIZE_2 || op_size == OP_SIZE_4) {
			gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(OP_SIZE_NATIVE), OP_SIZE_NATIVE, ALU1_BSWAP, ALU1_WRITES_FLAGS(ALU1_BSWAP));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);

			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SAR, ROT_WRITES_FLAGS(ROT_SAR));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_IMM);
			gen_eight(op_size == OP_SIZE_2 ? 48 : 32);
#endif
		} else if (op_size == OP_SIZE_2) {
#if defined(ARCH_X86)
			gen_insn(INSN_ROT_PARTIAL, OP_SIZE_2, ROT_ROR, 1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_IMM);
			gen_eight(8);
#else
			gen_insn(INSN_ALU1, OP_SIZE_4, ALU1_BSWAP16, ALU1_WRITES_FLAGS(ALU1_BSWAP16));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
#endif
		} else {
			gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(minimum(op_size, OP_SIZE_NATIVE)), minimum(op_size, OP_SIZE_NATIVE), ALU1_BSWAP, ALU1_WRITES_FLAGS(ALU1_BSWAP));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
		}
		if (op_size > OP_SIZE_NATIVE) {
			gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(OP_SIZE_NATIVE), OP_SIZE_NATIVE, ALU1_BSWAP, ALU1_WRITES_FLAGS(ALU1_BSWAP));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_2);
		}

		if (op_size > OP_SIZE_NATIVE)
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_2, R_SCRATCH_1));
		else
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
		goto do_generic_bswap;
do_generic_bswap:
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_bswap_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
	}
	/********
	 * BREV *
	 ********/
do_brev: {
#if defined(ARCH_ARM) || defined(ARCH_LOONGARCH64) || (defined(ARCH_MIPS) && MIPS_R6)
#if defined(ARCH_ARM32)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_armv6t2)))
			goto do_generic_brev;
#endif
		if (op_size > OP_SIZE_NATIVE)
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
		else
			g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));

		gen_insn(INSN_ALU1, minimum(maximum(OP_SIZE_4, op_size), OP_SIZE_NATIVE), ALU1_BREV, ALU1_WRITES_FLAGS(ALU1_BREV));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		if (op_size <= OP_SIZE_2) {
			gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(OP_SIZE_4), OP_SIZE_4, ROT_SHR, ROT_WRITES_FLAGS(ROT_SHR));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_IMM);
			gen_eight(op_size == OP_SIZE_1 ? 24 : 16);
		}
		if (op_size > OP_SIZE_NATIVE) {
			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_BREV, ALU1_WRITES_FLAGS(ALU1_BREV));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_2);
		}

		if (op_size > OP_SIZE_NATIVE)
			g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_2, R_SCRATCH_1));
		else
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
		goto do_generic_brev;
do_generic_brev:
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_brev_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
	}
	/******************
	 * BSF/BSR/POPCNT *
	 ******************/
do_bsf_bsr_popcnt: {
		if (op_size > OP_SIZE_NATIVE)
			goto do_generic_bsf_bsr_popcnt;
#if defined(ARCH_X86)
		if (alu == ALU1_POPCNT && unlikely(!cpu_test_feature(CPU_FEATURE_popcnt)))
			goto do_generic_bsf_bsr_popcnt;
		if (op_size == OP_SIZE_1 || ((alu == ALU1_BSR || alu == ALU1_POPCNT) && mode == MODE_INT)) {
			g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
			if ((alu == ALU1_BSR || alu == ALU1_POPCNT) && mode == MODE_INT) {
				g(gen_cmp_test_jmp(ctx, INSN_TEST, op_size, R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_BSR ? COND_LE : COND_S, label_ovf));
			}
			gen_insn(INSN_ALU1 + ARCH_PARTIAL_ALU(op_size), maximum(op_size, OP_SIZE_2), alu, 1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			if ((alu == ALU1_BSR || alu == ALU1_POPCNT) && mode == MODE_INT)
				goto x86_bsf_bsr_popcnt_finish;
		} else {
			g(gen_frame_load_op1(ctx, op_size, alu, 1, slot_1, 0, R_SCRATCH_1));
		}
		if (alu == ALU1_POPCNT)
			goto x86_bsf_bsr_popcnt_finish;
		if (mode == MODE_FIXED) {
			uint32_t cmov_label;
			gen_insn(INSN_MOV, maximum(op_size, OP_SIZE_4), 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(ARG_IMM);
			gen_eight(-1);
			g(gen_cmov(ctx, maximum(op_size, OP_SIZE_4), COND_E, R_SCRATCH_1, &cmov_label));
			gen_one(R_SCRATCH_2);
			if (cmov_label)
				gen_label(cmov_label);

		} else {
			gen_insn(INSN_JMP_COND, maximum(op_size, OP_SIZE_2), COND_E, 0);
			gen_four(label_ovf);
		}
x86_bsf_bsr_popcnt_finish:
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_ARM)
#if defined(ARCH_ARM32)
		if (alu == ALU1_BSR && unlikely(!cpu_test_feature(CPU_FEATURE_armv6)))
			goto do_generic_bsf_bsr_popcnt;
		if (alu == ALU1_BSF && unlikely(!cpu_test_feature(CPU_FEATURE_armv6t2)))
			goto do_generic_bsf_bsr_popcnt;
#endif
		if (alu == ALU1_POPCNT && unlikely(!cpu_test_feature(CPU_FEATURE_neon)))
			goto do_generic_bsf_bsr_popcnt;
		g(gen_frame_load(ctx, op_size, mode == MODE_INT, slot_1, 0, R_SCRATCH_1));
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		}

		if (alu == ALU1_POPCNT) {
			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(FR_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_insn(INSN_FP_ALU1, OP_SIZE_NATIVE, FP_ALU1_VCNT8, 0);
			gen_one(FR_SCRATCH_1);
			gen_one(FR_SCRATCH_1);
#if defined(ARCH_ARM32)
			if (op_size > OP_SIZE_1) {
				gen_insn(INSN_FP_ALU1, OP_SIZE_1, FP_ALU1_VPADDL, 0);
				gen_one(FR_SCRATCH_1);
				gen_one(FR_SCRATCH_1);
			}
			if (op_size > OP_SIZE_2) {
				gen_insn(INSN_FP_ALU1, OP_SIZE_2, FP_ALU1_VPADDL, 0);
				gen_one(FR_SCRATCH_1);
				gen_one(FR_SCRATCH_1);
			}
#else
			if (op_size > OP_SIZE_1) {
				gen_insn(INSN_FP_ALU1, OP_SIZE_1, FP_ALU1_ADDV, 0);
				gen_one(FR_SCRATCH_1);
				gen_one(FR_SCRATCH_1);
			}
#endif
			g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
			return true;
		}

		if (mode == MODE_FIXED && alu == ALU1_BSF) {
			gen_insn(INSN_TEST, i_size(op_size), 0, 1);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
		}

		if (alu == ALU1_BSF) {
			gen_insn(INSN_ALU1, i_size(op_size), ALU1_BREV, ALU1_WRITES_FLAGS(ALU1_BREV));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
		}

		gen_insn(INSN_ALU1, i_size(op_size), ALU1_LZCNT, ALU1_WRITES_FLAGS(ALU1_LZCNT));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);

		if (alu == ALU1_BSR) {
			g(gen_load_constant(ctx, R_SCRATCH_2, op_size == OP_SIZE_8 ? 63 : 31));
			gen_insn(INSN_ALU, i_size(op_size), ALU_SUB, ALU_WRITES_FLAGS(ALU_SUB, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
		}

		if (mode == MODE_FIXED && alu == ALU1_BSF) {
#if defined(ARCH_ARM32)
			g(gen_imm(ctx, -1, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
			gen_insn(INSN_CMOV, OP_SIZE_NATIVE, COND_E, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_imm_offset();
#else
			gen_insn(INSN_CSEL_INV, i_size(op_size), COND_NE, 0);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_IMM);
			gen_eight(0);
			gen_one(R_SCRATCH_1);
#endif
		}

		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_ALPHA)
		if (likely(cpu_test_feature(CPU_FEATURE_cix))) {
			if (mode == MODE_INT) {
				g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
				g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
			} else {
				g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
				if (ARCH_PREFERS_SX(op_size))
					g(gen_extend(ctx, op_size, false, R_SCRATCH_1, R_SCRATCH_1));
			}
			if (alu == ALU1_POPCNT) {
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_POPCNT, ALU1_WRITES_FLAGS(ALU1_POPCNT));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_1);
			}
			if (alu == ALU1_BSF) {
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_BSF, ALU1_WRITES_FLAGS(ALU1_BSF));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_1);

				if (mode == MODE_FIXED) {
					g(gen_imm(ctx, -1, IMM_PURPOSE_MOVR, OP_SIZE_INT));
					gen_insn(INSN_MOVR, OP_SIZE_NATIVE, COND_E, 0);
					gen_one(R_SCRATCH_2);
					gen_one(R_SCRATCH_2);
					gen_one(R_SCRATCH_1);
					gen_imm_offset();
				}
			}
			if (alu == ALU1_BSR) {
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_LZCNT, ALU1_WRITES_FLAGS(ALU1_LZCNT));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_1);

				g(gen_load_constant(ctx, R_SCRATCH_3, OP_SIZE_NATIVE == OP_SIZE_8 ? 63 : 31));

				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SUB, ALU_WRITES_FLAGS(ALU_SUB, false));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_2);
			}
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));
			return true;
		}
#endif
#if defined(ARCH_MIPS)
		if (MIPS_HAS_CLZ && alu != ALU1_POPCNT) {
			if (mode == MODE_INT) {
				g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
				g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
			} else {
				g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
			}
			if (alu == ALU1_BSF) {
				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_1);

				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_AND, ALU_WRITES_FLAGS(ALU_AND, false));
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_2);
			}
			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_LZCNT, ALU1_WRITES_FLAGS(ALU1_LZCNT));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);

			g(gen_load_constant(ctx, R_SCRATCH_3, OP_SIZE_NATIVE == OP_SIZE_8 ? 63 : 31));

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SUB, ALU_WRITES_FLAGS(ALU_SUB, false));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_2);

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));
			return true;
		}
#endif
#if defined(ARCH_POWER)
		if (alu == ALU1_BSF && (unlikely(!cpu_test_feature(CPU_FEATURE_v203)) || unlikely(!cpu_test_feature(CPU_FEATURE_v30))))
			goto do_generic_bsf_bsr_popcnt;
		if (alu == ALU1_POPCNT && unlikely(!cpu_test_feature(CPU_FEATURE_v206)))
			goto do_generic_bsf_bsr_popcnt;
		g(gen_frame_load(ctx, op_size, mode == MODE_INT, slot_1, 0, R_SCRATCH_1));
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, i_size(op_size), R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		}
		if (alu == ALU1_POPCNT) {
			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_POPCNT, ALU1_WRITES_FLAGS(ALU1_POPCNT));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
		}
		if (alu == ALU1_BSF) {
			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_BSF, ALU1_WRITES_FLAGS(ALU1_BSF));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);

			if (mode == MODE_FIXED) {
				gen_insn(INSN_ALU, i_size(op_size), ALU_AND, 1);
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_1);
				gen_one(R_SCRATCH_1);

				g(gen_imm(ctx, -1, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
				gen_insn(INSN_CMOV, OP_SIZE_NATIVE, COND_E, 0);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_imm_offset();
			}
		}
		if (alu == ALU1_BSR) {
			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_LZCNT, ALU1_WRITES_FLAGS(ALU1_LZCNT));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);

			g(gen_load_constant(ctx, R_SCRATCH_3, OP_SIZE_NATIVE == OP_SIZE_8 ? 63 : 31));

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SUB, ALU_WRITES_FLAGS(ALU_SUB, false));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_2);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));
		return true;
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_RISCV64)
#if defined(ARCH_LOONGARCH64)
		if (alu == ALU1_POPCNT)
			goto do_generic_bsf_bsr_popcnt;
#endif
#if defined(ARCH_RISCV64)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_zbb)))
			goto do_generic_bsf_bsr_popcnt;
#endif
		g(gen_frame_load(ctx, op_size, true, slot_1, 0, R_SCRATCH_1));
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		} else {
			if (op_size < OP_SIZE_4)
				g(gen_extend(ctx, op_size, false, R_SCRATCH_1, R_SCRATCH_1));
		}
		if (alu == ALU1_POPCNT) {
			gen_insn(INSN_ALU1, maximum(OP_SIZE_4, op_size), ALU1_POPCNT, ALU1_WRITES_FLAGS(ALU1_POPCNT));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);
		}
		if (alu == ALU1_BSF) {
			gen_insn(INSN_ALU1, maximum(OP_SIZE_4, op_size), ALU1_BSF, ALU1_WRITES_FLAGS(ALU1_BSF));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);

			if (mode == MODE_FIXED) {
				g(gen_imm(ctx, 1, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
				gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, COND_B, 0);
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_1);
				gen_imm_offset();

				gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_NEG, ALU1_WRITES_FLAGS(ALU1_NEG));
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_3);

				gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_OR, ALU_WRITES_FLAGS(ALU_OR, false));
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_3);
			}
		}
		if (alu == ALU1_BSR) {
			gen_insn(INSN_ALU1, maximum(OP_SIZE_4, op_size), ALU1_LZCNT, ALU1_WRITES_FLAGS(ALU1_LZCNT));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);

			g(gen_load_constant(ctx, R_SCRATCH_3, op_size <= OP_SIZE_4 ? 31 : 63));

			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_SUB, ALU_WRITES_FLAGS(ALU_SUB, false));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_3);
			gen_one(R_SCRATCH_2);
		}
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));
		return true;
#endif
#if defined(ARCH_IA64) || defined(ARCH_S390) || defined(ARCH_SPARC)
		if (alu == ALU1_BSF && !ARCH_HAS_ANDN)
			goto do_generic_bsf_bsr_popcnt;
#if defined(ARCH_S390)
		if (!cpu_test_feature(CPU_FEATURE_misc_45) || !cpu_test_feature(CPU_FEATURE_misc_insn_ext_3))
			goto do_generic_bsf_bsr_popcnt;
#endif
#if defined(ARCH_SPARC)
		if (!SPARC_9)
			goto do_generic_bsf_bsr_popcnt;
#endif
		g(gen_frame_load(ctx, op_size, mode == MODE_INT, slot_1, 0, R_SCRATCH_1));
		if (mode == MODE_INT) {
			g(gen_cmp_test_jmp(ctx, INSN_TEST, maximum(op_size, OP_SIZE_4), R_SCRATCH_1, R_SCRATCH_1, alu == ALU1_BSR ? COND_LE : alu == ALU1_BSF ? COND_E : COND_S, label_ovf));
		} else {
			if (ARCH_PREFERS_SX(op_size) && alu == ALU1_POPCNT && op_size < OP_SIZE_NATIVE)
				g(gen_extend(ctx, op_size, false, R_SCRATCH_1, R_SCRATCH_1));
		}
		if (alu == ALU1_POPCNT) {
			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_POPCNT, ALU1_WRITES_FLAGS(ALU1_POPCNT));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}
		if (alu == ALU1_BSF) {
			g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_SUB, R_SCRATCH_2, R_SCRATCH_1, 1));

			g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ANDN, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_1));

			gen_insn(INSN_ALU1, OP_SIZE_NATIVE, ALU1_POPCNT, ALU1_WRITES_FLAGS(ALU1_POPCNT));
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_2);

			if (mode == MODE_FIXED) {
				unsigned attr_unused test_reg = R_SCRATCH_1;
#if defined(ARCH_S390)
				g(gen_imm(ctx, 0, COND_IS_LOGICAL(COND_E) ? IMM_PURPOSE_CMP_LOGICAL : IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
				gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1 + COND_IS_LOGICAL(COND_E));
				gen_one(R_SCRATCH_1);
				gen_imm_offset();

				g(gen_imm(ctx, -1, IMM_PURPOSE_CMOV, OP_SIZE_NATIVE));
				gen_insn(INSN_CMOV, OP_SIZE_NATIVE, COND_E, 0);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_imm_offset();
#else
#if defined(ARCH_IA64)
				g(gen_cmp_dest_reg(ctx, OP_SIZE_NATIVE, R_SCRATCH_1, (unsigned)-1, R_CMP_RESULT, 0, COND_NE));
				test_reg = R_CMP_RESULT;
#endif
				g(gen_imm(ctx, -1, IMM_PURPOSE_MOVR, OP_SIZE_NATIVE));
				gen_insn(INSN_MOVR, OP_SIZE_NATIVE, COND_E, 0);
				gen_one(R_SCRATCH_2);
				gen_one(R_SCRATCH_2);
				gen_one(test_reg);
				gen_imm_offset();
#endif
			}

			g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_2));
			return true;
		}
#endif
do_generic_bsf_bsr_popcnt:
		if (alu == ALU1_BSF) {
			if (mode == MODE_FIXED)
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_bsf_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
			else
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_unary_bsf_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
		}
		if (alu == ALU1_BSR) {
			if (mode == MODE_FIXED)
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_bsr_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
			else
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_unary_bsr_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
		}
		if (alu == ALU1_POPCNT) {
			if (mode == MODE_FIXED)
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_unary_popcnt_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, 0);
			else
				return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, INT_unary_popcnt_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
		}
	}
	/**************
	 * CONVERSION *
	 **************/
do_fixed_conv:
do_conv: {
		unsigned src_op_size, dest_op_size;
		const struct type *src_type, *dest_type;
		src_type = get_type_of_local(ctx, slot_1);
		dest_type = get_type_of_local(ctx, slot_r);

		if (TYPE_TAG_IS_FIXED(src_type->tag)) {
			src_op_size = TYPE_TAG_IDX_FIXED(src_type->tag) >> 1;
		} else {
			src_op_size = TYPE_TAG_IDX_INT(src_type->tag);
		}

		if (TYPE_TAG_IS_FIXED(dest_type->tag)) {
			dest_op_size = TYPE_TAG_IDX_FIXED(dest_type->tag) >> 1;
		} else {
			dest_op_size = TYPE_TAG_IDX_INT(dest_type->tag);
		}

		if (src_op_size <= OP_SIZE_NATIVE) {
			g(gen_frame_load(ctx, src_op_size, true, slot_1, 0, R_SCRATCH_1));
		} else {
			g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
		}

		if (dest_op_size >= src_op_size) {
			if (dest_op_size <= OP_SIZE_NATIVE) {
				g(gen_frame_store(ctx, dest_op_size, slot_r, 0, R_SCRATCH_1));
			} else {
				if (src_op_size <= OP_SIZE_NATIVE) {
#if defined(ARCH_X86)
					if (R_SCRATCH_1 != R_AX || R_SCRATCH_2 != R_DX)
						internal(file_line, "gen_alu1: bad scratch registers");
					gen_insn(INSN_CWD, OP_SIZE_NATIVE, 0, 0);
					gen_one(R_DX);
					gen_one(R_AX);
#else
					g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SAR, R_SCRATCH_2, R_SCRATCH_1, (1U << (OP_SIZE_NATIVE + 3)) - 1, false));
#endif
				}
				g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
			}
			return true;
		} else {
			if (src_op_size > OP_SIZE_NATIVE) {
#if defined(ARCH_ARM)
				gen_insn(INSN_CMP, OP_SIZE_NATIVE, 0, 1);
				gen_one(R_SCRATCH_2);
				gen_one(ARG_SHIFTED_REGISTER);
				gen_one(ARG_SHIFT_ASR | ((1U << (OP_SIZE_NATIVE + 3)) - 1));
				gen_one(R_SCRATCH_1);

				gen_insn(INSN_JMP_COND, OP_SIZE_NATIVE, COND_NE, 0);
				gen_four(label_ovf);
#else
				gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_1);

				gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SAR, ROT_WRITES_FLAGS(ROT_SAR));
				gen_one(R_SCRATCH_3);
				gen_one(R_SCRATCH_3);
				gen_one(ARG_IMM);
				gen_eight((1U << (OP_SIZE_NATIVE + 3)) - 1);

				g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_2, R_SCRATCH_3, COND_NE, label_ovf));
#endif

				src_op_size = OP_SIZE_NATIVE;
			}
			if (src_op_size > dest_op_size) {
				g(gen_cmp_extended(ctx, OP_SIZE_NATIVE, dest_op_size, R_SCRATCH_1, R_SCRATCH_3, label_ovf));
			}
			g(gen_frame_store(ctx, dest_op_size, slot_r, 0, R_SCRATCH_1));
			return true;
		}
	}

conv_uto_int: {
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_uto_int_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
	}

conv_ufrom_int: {
		return gen_alu_typed_upcall(ctx, offsetof(struct cg_upcall_vector_s, FIXED_ufrom_int_int8_t), op_size, slot_1, NO_FRAME_T, slot_r, label_ovf);
	}
}

static bool attr_w gen_constant(struct codegen_context *ctx, unsigned op_size, bool shrt, frame_t slot_r)
{
	uintbig_t c;
	if (shrt) {
		c = (int16_t)get_unaligned_16(ctx->current_position);
	} else switch (op_size) {
#define fx(n, type, utype, sz, bits)					\
		case n:							\
			c = (type)cat(get_unaligned_,bits)(ctx->current_position);\
			break;
		for_all_fixed(fx);
#undef fx
		default:
			internal(file_line, "gen_constant: invalid type %u", op_size);
	}
	if (op_size > OP_SIZE_NATIVE) {
		g(gen_frame_store_imm(ctx, OP_SIZE_NATIVE, slot_r, lo_word(OP_SIZE_NATIVE), c));
		g(gen_frame_store_imm(ctx, OP_SIZE_NATIVE, slot_r, hi_word(OP_SIZE_NATIVE), c >> 1 >> ((1U << (OP_SIZE_NATIVE + 3)) - 1)));
		return true;
	} else {
		g(gen_frame_store_imm(ctx, op_size, slot_r, 0, c));
	}
	return true;
}

static bool attr_w gen_real_constant(struct codegen_context *ctx, const struct type *t, frame_t slot_r)
{
	int64_t offset;
	if (is_power_of_2(t->size) && t->size <= sizeof(uintbig_t))
		return gen_constant(ctx, log_2(t->size), false, slot_r);

	g(load_function_offset(ctx, R_SCRATCH_3, offsetof(struct data, u_.function.code)));

	offset = (ctx->current_position - da(ctx->fn,function)->code) * sizeof(code_t);

	g(gen_memcpy(ctx, R_FRAME, (size_t)slot_r * slot_size, R_SCRATCH_3, offset, t->size, minimum(t->align, align_of(code_t))));
	return true;
}

static bool attr_w gen_copy(struct codegen_context *ctx, unsigned op_size, frame_t slot_1, frame_t slot_r)
{
	if (unlikely(op_size > OP_SIZE_NATIVE)) {
		g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, slot_1, 0, R_SCRATCH_1, R_SCRATCH_2));
		g(gen_frame_store_2(ctx, OP_SIZE_NATIVE, slot_r, 0, R_SCRATCH_1, R_SCRATCH_2));
		return true;
	} else {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, R_SCRATCH_1));
		g(gen_frame_store(ctx, op_size, slot_r, 0, R_SCRATCH_1));
		return true;
	}
}

static unsigned real_type_to_op_size(unsigned real_type)
{
	switch (real_type) {
		case 0:	return OP_SIZE_2;
		case 1:	return OP_SIZE_4;
		case 2:	return OP_SIZE_8;
		case 3:	return OP_SIZE_10;
		case 4:	return OP_SIZE_16;
		default:
			internal(file_line, "real_type_to_op_size: invalid type %u", real_type);
			return 0;
	}
}

static bool attr_w gen_fp_alu(struct codegen_context *ctx, unsigned real_type, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_2, frame_t slot_r)
{
	unsigned attr_unused fp_alu;
	size_t upc;
	unsigned attr_unused op_size = real_type_to_op_size(real_type);
	switch (op) {
		case OPCODE_REAL_OP_add:
		case OPCODE_REAL_OP_add_alt1:
		case OPCODE_REAL_OP_add_alt2: fp_alu = FP_ALU_ADD; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_add_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_subtract:
		case OPCODE_REAL_OP_subtract_alt1:
		case OPCODE_REAL_OP_subtract_alt2: fp_alu = FP_ALU_SUB; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_subtract_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_multiply:
		case OPCODE_REAL_OP_multiply_alt1:
		case OPCODE_REAL_OP_multiply_alt2: fp_alu = FP_ALU_MUL; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_multiply_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_divide:
		case OPCODE_REAL_OP_divide_alt1:
		case OPCODE_REAL_OP_divide_alt2: fp_alu = FP_ALU_DIV; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_divide_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_modulo:
		case OPCODE_REAL_OP_power:
		case OPCODE_REAL_OP_ldexp:
		case OPCODE_REAL_OP_atan2: upc = offsetof(struct cg_upcall_vector_s, REAL_binary_modulo_real16_t) + (op - OPCODE_REAL_OP_modulo) * TYPE_REAL_N * sizeof(void (*)(void)); goto do_upcall;
		case OPCODE_REAL_OP_equal:
		case OPCODE_REAL_OP_equal_alt1:
		case OPCODE_REAL_OP_equal_alt2: fp_alu = FP_COND_E; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_equal_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_not_equal:
		case OPCODE_REAL_OP_not_equal_alt1:
		case OPCODE_REAL_OP_not_equal_alt2: fp_alu = FP_COND_NE; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_not_equal_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_less:
		case OPCODE_REAL_OP_less_alt1:
		case OPCODE_REAL_OP_less_alt2: fp_alu = FP_COND_B; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_less_real16_t); goto do_cmp;
		case OPCODE_REAL_OP_less_equal:
		case OPCODE_REAL_OP_less_equal_alt1:
		case OPCODE_REAL_OP_less_equal_alt2: fp_alu = FP_COND_BE; upc = offsetof(struct cg_upcall_vector_s, REAL_binary_less_equal_real16_t); goto do_cmp;
		default: internal(file_line, "gen_fp_alu: unsupported operation %u", op);
	}

do_alu:
	if ((SUPPORTED_FP >> real_type) & 1) {
#if defined(ARCH_IA64)
		if (unlikely(fp_alu == FP_ALU_DIV))
			goto do_upcall;
#endif
#if defined(ARCH_X86)
		if (1)
#elif defined(ARCH_S390)
		if (op_size <= OP_SIZE_8 && (size_t)slot_2 * slot_size < 4096)
#else
		if (0)
#endif
		{
			g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
			g(gen_address(ctx, R_FRAME, (size_t)slot_2 * slot_size, IMM_PURPOSE_VLDR_VSTR_OFFSET, op_size));
			gen_insn(INSN_FP_ALU, op_size, fp_alu, 0);
			gen_one(FR_SCRATCH_1);
			gen_one(FR_SCRATCH_1);
			gen_address_offset();
			g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
			return true;
		}
#if defined(ARCH_ALPHA)
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, false, slot_2, 0, FR_SCRATCH_2));
		gen_insn(INSN_FP_ALU, op_size, fp_alu, 0);
		gen_one(FR_SCRATCH_3);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_3));
#else
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, false, slot_2, 0, FR_SCRATCH_2));
		gen_insn(INSN_FP_ALU, op_size, fp_alu, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
#endif
		return true;
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		if (real_type != 3) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			g(gen_frame_load_x87(ctx, INSN_X87_ALU, op_size, fp_alu, slot_1));
		} else {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			gen_insn(INSN_X87_ALUP, op_size, fp_alu, 0);
			gen_one(R_ST1);
		}
		g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, false, slot_2, 0, FR_SCRATCH_2));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_2);
		gen_insn(INSN_FP_ALU, OP_SIZE_4, fp_alu, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
		gen_insn(INSN_FP_CVT, OP_SIZE_4, op_size, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
		return true;
	}
#endif
	goto do_upcall;

do_cmp:
	if ((SUPPORTED_FP >> real_type) & 1
#if defined(ARCH_ALPHA)
		&& ARCH_SUPPORTS_TRAPS
#endif
	) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, false, slot_2, 0, FR_SCRATCH_2));
#if defined(ARCH_ALPHA)
		gen_insn(INSN_FP_CMP_DEST_REG_TRAP, op_size, fp_alu == FP_COND_NE ? FP_COND_E : fp_alu, 0);
		gen_one(FR_SCRATCH_3);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
		gen_four(label_ovf);

		if (!cpu_test_feature(CPU_FEATURE_fix)) {
			g(gen_frame_store(ctx, OP_SIZE_4, slot_r, 0, FR_SCRATCH_3));
			g(gen_frame_load(ctx, OP_SIZE_4, false, slot_r, 0, R_SCRATCH_1));
		} else {
			gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(FR_SCRATCH_3);
		}

		if (fp_alu == FP_COND_NE) {
			g(gen_imm(ctx, 0, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
			gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, COND_E, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_imm_offset();
		} else {
			gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHR, ROT_WRITES_FLAGS(ROT_SHR));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_IMM);
			gen_eight(30);
		}

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));

		return true;
#elif defined(ARCH_IA64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_P, 0);
		gen_one(R_CMP_RESULT);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label_ovf);

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, fp_alu, 0);
		gen_one(R_CMP_RESULT);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);

		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_CMP_RESULT);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));

		return true;
#elif defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC)
		gen_insn(INSN_FP_CMP_COND, op_size, FP_COND_P, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);

		gen_insn(INSN_JMP_FP_TEST, 0, FP_COND_P, 0);
		gen_four(label_ovf);

		gen_insn(INSN_FP_CMP_COND, op_size, fp_alu, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);

		gen_insn(INSN_FP_TEST_REG, OP_SIZE_NATIVE, fp_alu, 0);
		gen_one(R_SCRATCH_1);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));

		return true;
#elif defined(ARCH_RISCV64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(R_SCRATCH_2);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_2);

		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_AND, ALU_WRITES_FLAGS(ALU_AND, false));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);

		g(gen_jmp_on_zero(ctx, OP_SIZE_NATIVE, R_SCRATCH_1, COND_E, label_ovf));

		gen_insn(INSN_FP_CMP_DEST_REG, op_size, fp_alu == FP_COND_NE ? FP_COND_E : fp_alu, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);

		if (fp_alu == FP_COND_NE) {
			g(gen_imm(ctx, 1, IMM_PURPOSE_XOR, OP_SIZE_NATIVE));
			gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_XOR, ALU_WRITES_FLAGS(ALU_AND, false));
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_1);
			gen_imm_offset();
		}

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));
		return true;
#else
		gen_insn(INSN_FP_CMP, op_size, 0, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);
		g(gen_frame_set_cond(ctx, op_size, false, fp_alu, slot_r));
		return true;
#endif
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		if (likely(cpu_test_feature(CPU_FEATURE_cmov))) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FCOMIP, op_size, 0, 0);
			gen_one(R_ST1);
			gen_insn(INSN_X87_FSTP, op_size, 0, 0);
			gen_one(R_ST0);
			gen_insn(INSN_JMP_COND, op_size, COND_P, 0);
			gen_four(label_ovf);
			g(gen_frame_set_cond(ctx, op_size, false, fp_alu & 0xf, slot_r));
			return true;
		}

		if (real_type != 3) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			g(gen_frame_load_x87(ctx, INSN_X87_FCOMP, op_size, 0, slot_2));
		} else {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_2));
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FCOMPP, op_size, 0, 0);
		}

		gen_insn(INSN_X87_FNSTSW, 0, 0, 0);
		gen_one(R_AX);
		gen_one(R_AX);

		gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
		gen_one(R_AX);
		gen_one(ARG_IMM);
		gen_eight(0x0400);

		gen_insn(INSN_JMP_COND, OP_SIZE_2, COND_NE, 0);
		gen_four(label_ovf);

		switch (fp_alu) {
			case FP_COND_E:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x4000);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_NE, slot_r));
				break;
			case FP_COND_NE:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x4000);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_E, slot_r));
				break;
			case FP_COND_B:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x0100);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_NE, slot_r));
				break;
			case FP_COND_BE:
				gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
				gen_one(R_AX);
				gen_one(ARG_IMM);
				gen_eight(0x4100);
				g(gen_frame_set_cond(ctx, OP_SIZE_2, false, COND_NE, slot_r));
				break;
			default:
				internal(file_line, "gen_fp_alu: invalid condition %u", fp_alu);
		}
		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		g(gen_frame_load(ctx, op_size, false, slot_2, 0, FR_SCRATCH_2));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_2);
		gen_insn(INSN_FP_CMP, OP_SIZE_4, 0, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_2);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);
		g(gen_frame_set_cond(ctx, op_size, false, fp_alu, slot_r));
		return true;
	}
#endif

do_upcall:
	return gen_alu_typed_upcall(ctx, upc, real_type, slot_1, slot_2, slot_r, label_ovf);
}

static bool attr_w gen_fp_alu1(struct codegen_context *ctx, unsigned real_type, unsigned op, uint32_t label_ovf, frame_t slot_1, frame_t slot_r)
{
	unsigned attr_unused fp_alu;
	size_t upc;
	unsigned attr_unused op_size = real_type_to_op_size(real_type);
	switch (op) {
		case OPCODE_REAL_OP_neg:
		case OPCODE_REAL_OP_neg_alt1:
		case OPCODE_REAL_OP_neg_alt2: fp_alu = FP_ALU1_NEG; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_neg_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_sqrt:
		case OPCODE_REAL_OP_sqrt_alt1:
		case OPCODE_REAL_OP_sqrt_alt2: fp_alu = FP_ALU1_SQRT; upc = offsetof(struct cg_upcall_vector_s, REAL_unary_sqrt_real16_t); label_ovf = 0; goto do_alu;
		case OPCODE_REAL_OP_to_int:
		case OPCODE_REAL_OP_to_int_alt1:
		case OPCODE_REAL_OP_to_int_alt2: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_to_int_real16_t); goto do_to_int;
		case OPCODE_REAL_OP_from_int:
		case OPCODE_REAL_OP_from_int_alt1:
		case OPCODE_REAL_OP_from_int_alt2: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_from_int_real16_t); label_ovf = 0; goto do_from_int;
		case OPCODE_REAL_OP_is_exception:
		case OPCODE_REAL_OP_is_exception_alt1:
		case OPCODE_REAL_OP_is_exception_alt2: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_is_exception_real16_t); label_ovf = 0; goto do_is_exception;
		default: upc = offsetof(struct cg_upcall_vector_s, REAL_unary_cbrt_real16_t) + (op - OPCODE_REAL_OP_cbrt) * TYPE_REAL_N * sizeof(void (*)(void)); label_ovf = 0; goto do_upcall;
	}

do_alu:
	if ((SUPPORTED_FP >> real_type) & 1
#if defined(ARCH_X86)
		&& !(fp_alu == FP_ALU1_NEG)
#endif
#if defined(ARCH_ALPHA)
		&& !(fp_alu == FP_ALU1_SQRT && !cpu_test_feature(CPU_FEATURE_fix))
#endif
#if defined(ARCH_IA64)
		&& !(fp_alu == FP_ALU1_SQRT)
#endif
#if defined(ARCH_MIPS)
		&& !(fp_alu == FP_ALU1_SQRT && !MIPS_HAS_SQRT)
#endif
#if defined(ARCH_PARISC)
		&& !(fp_alu == FP_ALU1_NEG && !PA_20)
#endif
#if defined(ARCH_POWER)
		&& !(fp_alu == FP_ALU1_SQRT && (!cpu_test_feature(CPU_FEATURE_p2) || real_type == 4))
#endif
		) {
#if defined(ARCH_S390)
		if (op_size <= OP_SIZE_8 && (size_t)slot_1 * slot_size < 4096 && fp_alu == FP_ALU1_SQRT) {
			g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size, IMM_PURPOSE_VLDR_VSTR_OFFSET, op_size));
			gen_insn(INSN_FP_ALU1, op_size, fp_alu, 0);
			gen_one(FR_SCRATCH_1);
			gen_address_offset();
			g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
			return true;
		}
#endif
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		gen_insn(INSN_FP_ALU1, op_size, fp_alu, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_1);
		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_2));
		return true;
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		if (fp_alu == FP_ALU1_NEG) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FCHS, op_size, 0, 0);
			g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
			return true;
		} else if (fp_alu == FP_ALU1_SQRT) {
			g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
			gen_insn(INSN_X87_FSQRT, op_size, 0, 0);
			g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
			return true;
		} else {
			internal(file_line, "gen_fp_alu1: invalid alu %u", fp_alu);
		}
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1
#if defined(ARCH_X86)
		&& !(fp_alu == FP_ALU1_NEG)
#endif
		) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_insn(INSN_FP_ALU1, OP_SIZE_4, fp_alu, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_insn(INSN_FP_CVT, OP_SIZE_4, op_size, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
		return true;
	}
#endif
	goto do_upcall;

do_to_int:
	if ((SUPPORTED_FP >> real_type) & 1
#if defined(ARCH_ALPHA)
		&& ARCH_SUPPORTS_TRAPS
#endif
#if defined(ARCH_MIPS)
		&& MIPS_HAS_TRUNC
#endif
	) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		goto do_cvt_to_int;
do_cvt_to_int:;
#if defined(ARCH_X86)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_1, sign_bit(uint_default_t), COND_E, label_ovf));

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_ARM) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS)
#if defined(ARCH_ARM)
		gen_insn(INSN_FP_CMP, op_size, 0, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);
#else
		gen_insn(INSN_FP_CMP_COND, op_size, FP_COND_P, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		gen_insn(INSN_JMP_FP_TEST, 0, FP_COND_P, 0);
		gen_four(label_ovf);
#endif
#if defined(ARCH_ARM32) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		gen_insn(INSN_MOV, OP_SIZE_INT, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
#else
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
#endif
		g(gen_imm(ctx, (int_default_t)(sign_bit(uint_default_t) + 1), IMM_PURPOSE_ADD, OP_SIZE_INT));
		gen_insn(INSN_ALU, OP_SIZE_INT, ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_imm_offset();

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_2, 1, COND_BE, label_ovf));

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_IA64)
		gen_insn(INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		gen_insn(INSN_MOV, OP_SIZE_8, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		if (OP_SIZE_INT == OP_SIZE_4) {
			g(gen_extend(ctx, OP_SIZE_4, true, R_SCRATCH_2, R_SCRATCH_1));
			g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_2, COND_NE, label_ovf));
		} else {
			g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, sign_bit(uint64_t), COND_E, label_ovf));
		}

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_SPARC)
#if defined(ARCH_POWER)
		if (!cpu_test_feature(CPU_FEATURE_ppc))
			goto do_upcall;
		if (OP_SIZE_INT == OP_SIZE_4)
			goto do_upcall;
#endif
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, FR_SCRATCH_1));
		g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_r, 0, R_SCRATCH_1));

		g(gen_imm(ctx, sign_bit(uint_default_t) + 1, IMM_PURPOSE_ADD, OP_SIZE_INT));
		gen_insn(INSN_ALU, i_size(OP_SIZE_INT), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_1);
		gen_imm_offset();

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_2, 1, COND_BE, label_ovf));

		return true;
#endif
#if defined(ARCH_ALPHA)
		gen_insn(INSN_FP_TO_INT64_TRAP, op_size, 0, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_1);
		gen_four(label_ovf);

		if (OP_SIZE_INT == OP_SIZE_4) {
			gen_insn(INSN_FP_INT64_TO_INT32_TRAP, 0, 0, 0);
			gen_one(FR_SCRATCH_3);
			gen_one(FR_SCRATCH_2);
			gen_four(label_ovf);
			g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, FR_SCRATCH_3));
		} else {
			g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, FR_SCRATCH_2));
		}
		return true;
#endif
#if defined(ARCH_S390)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 1);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		gen_insn(INSN_JMP_COND, op_size, FP_COND_P, 0);
		gen_four(label_ovf);

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
#if defined(ARCH_RISCV64)
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_TO_INT32 : INSN_FP_TO_INT64, op_size, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		g(gen_load_constant(ctx, R_SCRATCH_2, sign_bit(int_default_t)));

		g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_2, COND_E, label_ovf));

		g(gen_imm(ctx, -1, IMM_PURPOSE_XOR, i_size(size)));
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_XOR, ALU_WRITES_FLAGS(ALU_XOR, is_imm()));
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_2);
		gen_imm_offset();

		g(gen_cmp_test_jmp(ctx, INSN_CMP, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_2, COND_E, label_ovf));

		g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_SCRATCH_1));
		return true;
#endif
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));

		if (likely(cpu_test_feature(CPU_FEATURE_sse3))) {
			g(gen_frame_store_x87(ctx, INSN_X87_FISTTP, OP_SIZE_INT, slot_r));
		} else {
			gen_insn(INSN_PUSH, OP_SIZE_NATIVE, 0, 0);
			gen_one(ARG_IMM);
			gen_eight(0x0f7f);

			gen_insn(INSN_X87_FLDCW, 0, 0, 0);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SP);
			gen_eight(0);

			g(gen_frame_store_x87(ctx, INSN_X87_FISTP, OP_SIZE_INT, slot_r));

			gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SP);
			gen_eight(0);
			gen_one(ARG_IMM);
			gen_eight(0x037f);

			gen_insn(INSN_X87_FLDCW, 0, 0, 0);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SP);
			gen_eight(0);

			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, true));
			gen_one(R_SP);
			gen_one(R_SP);
			gen_one(ARG_IMM);
			gen_eight(1 << OP_SIZE_NATIVE);
		}
		g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_r, 0, R_SCRATCH_1));

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_1, sign_bit(int_default_t), COND_E, label_ovf));

		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		real_type = 1;
		op_size = real_type_to_op_size(real_type);
		goto do_cvt_to_int;
	}
#endif
	goto do_upcall;

do_from_int:
	if ((SUPPORTED_FP >> real_type) & 1) {
#if defined(ARCH_ALPHA) || defined(ARCH_ARM32) || defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_SPARC)
		int int_op_size = OP_SIZE_INT;
#if defined(ARCH_POWER)
		if (int_op_size == OP_SIZE_4)
			goto do_upcall;
		if (op_size == OP_SIZE_4 && !cpu_test_feature(CPU_FEATURE_v206))
			goto do_upcall;
		if (op_size == OP_SIZE_8 && !cpu_test_feature(CPU_FEATURE_ppc))
			goto do_upcall;
#endif
		g(gen_frame_load(ctx, int_op_size, false, slot_1, 0, FR_SCRATCH_1));
#if defined(ARCH_ALPHA)
		if (OP_SIZE_INT == OP_SIZE_4) {
			gen_insn(INSN_MOVSX, OP_SIZE_4, 0, 0);
			gen_one(FR_SCRATCH_1);
			gen_one(FR_SCRATCH_1);

			int_op_size = OP_SIZE_8;
		}
#endif
		gen_insn(int_op_size == OP_SIZE_4 ? INSN_FP_FROM_INT32 : INSN_FP_FROM_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_1);

		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_2));
		return true;
#elif defined(ARCH_IA64)
		g(gen_frame_load(ctx, OP_SIZE_INT, true, slot_1, 0, R_SCRATCH_1));

		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(R_SCRATCH_1);

		gen_insn(INSN_FP_FROM_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
		return true;
#else
		g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_1, 0, R_SCRATCH_1));

		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_FROM_INT32 : INSN_FP_FROM_INT64, op_size, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(R_SCRATCH_1);

		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
		return true;
#endif
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		g(gen_frame_load_x87(ctx, INSN_X87_FILD, OP_SIZE_INT, 0, slot_1));
		g(gen_frame_store_x87(ctx, INSN_X87_FSTP, op_size, slot_r));
		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
#if defined(ARCH_ARM32)
		g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_1, 0, FR_SCRATCH_1));

		gen_insn(INSN_FP_FROM_INT32, OP_SIZE_4, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
#else
		g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_1, 0, R_SCRATCH_1));
		gen_insn(OP_SIZE_INT == OP_SIZE_4 ? INSN_FP_FROM_INT32 : INSN_FP_FROM_INT64, OP_SIZE_4, 0, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(R_SCRATCH_1);
#endif
		gen_insn(INSN_FP_CVT, OP_SIZE_4, op_size, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		g(gen_frame_store(ctx, op_size, slot_r, 0, FR_SCRATCH_1));
		return true;
	}
#endif
	goto do_upcall;

do_is_exception:
	if ((SUPPORTED_FP >> real_type) & 1) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
#if defined(ARCH_ALPHA)
		gen_insn(INSN_FP_CMP_UNORDERED_DEST_REG, op_size, 0, 0);
		gen_one(FR_SCRATCH_2);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		if (!cpu_test_feature(CPU_FEATURE_fix)) {
			g(gen_frame_store(ctx, OP_SIZE_4, slot_r, 0, FR_SCRATCH_2));
			g(gen_frame_load(ctx, OP_SIZE_4, false, slot_r, 0, R_SCRATCH_1));
		} else {
			gen_insn(INSN_MOV, OP_SIZE_4, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(FR_SCRATCH_2);
		}

		gen_insn(INSN_ROT, OP_SIZE_NATIVE, ROT_SHR, ROT_WRITES_FLAGS(ROT_SHR));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_IMM);
		gen_eight(30);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));

		return true;
#elif defined(ARCH_IA64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_P, 0);
		gen_one(R_CMP_RESULT);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_CMP_RESULT);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));
#elif defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_PARISC)
		gen_insn(INSN_FP_CMP_COND, op_size, FP_COND_P, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		gen_insn(INSN_FP_TEST_REG, OP_SIZE_NATIVE, FP_COND_P, 0);
		gen_one(R_SCRATCH_1);

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));
#elif defined(ARCH_RISCV64)
		gen_insn(INSN_FP_CMP_DEST_REG, op_size, FP_COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);

		g(gen_imm(ctx, 1, IMM_PURPOSE_XOR, OP_SIZE_NATIVE));
		gen_insn(INSN_ALU, OP_SIZE_NATIVE, ALU_XOR, ALU_WRITES_FLAGS(ALU_XOR, is_imm()));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_imm_offset();

		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_1));
#else
		gen_insn(INSN_FP_CMP, op_size, 0, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		g(gen_frame_set_cond(ctx, op_size, false, FP_COND_P, slot_r));
#endif
		return true;
	}
#ifdef SUPPORTED_FP_X87
	if ((SUPPORTED_FP_X87 >> real_type) & 1) {
		g(gen_frame_load_x87(ctx, INSN_X87_FLD, op_size, 0, slot_1));
		if (likely(cpu_test_feature(CPU_FEATURE_cmov))) {
			gen_insn(INSN_X87_FCOMIP, op_size, 0, 0);
			gen_one(R_ST0);

			g(gen_frame_set_cond(ctx, op_size, false, COND_P, slot_r));
			return true;
		}

		gen_insn(INSN_X87_FCOMP, op_size, 0, 0);
		gen_one(R_ST0);

		gen_insn(INSN_X87_FNSTSW, 0, 0, 0);
		gen_one(R_AX);
		gen_one(R_AX);

		gen_insn(INSN_TEST, OP_SIZE_2, 0, 1);
		gen_one(R_AX);
		gen_one(ARG_IMM);
		gen_eight(0x0400);

		g(gen_frame_set_cond(ctx, op_size, false, COND_NE, slot_r));

		return true;
	}
#endif
#ifdef SUPPORTED_FP_HALF_CVT
	if ((SUPPORTED_FP_HALF_CVT >> real_type) & 1) {
		g(gen_frame_load(ctx, op_size, false, slot_1, 0, FR_SCRATCH_1));
		gen_insn(INSN_FP_CVT, op_size, OP_SIZE_4, 0);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
		gen_insn(INSN_FP_CMP, OP_SIZE_4, 0, 1);
		gen_one(FR_SCRATCH_1);
		gen_one(FR_SCRATCH_1);
#if defined(ARCH_ARM32)
		gen_insn(INSN_FP_TO_INT_FLAGS, 0, 0, 1);
#endif
		g(gen_frame_set_cond(ctx, op_size, false, FP_COND_P, slot_r));
		return true;
	}
#endif

do_upcall:
	g(gen_alu_typed_upcall(ctx, upc, real_type, slot_1, NO_FRAME_T, slot_r, label_ovf));
	return true;
}

static bool attr_w gen_is_exception(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r)
{
	uint32_t no_ex_label, escape_label;
	const struct type *type = get_type_of_local(ctx, slot_1);

	no_ex_label = alloc_label(ctx);
	if (unlikely(!no_ex_label))
		return false;
	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (TYPE_IS_FLAT(type))
		g(gen_test_1_jz_cached(ctx, slot_1, no_ex_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
	g(gen_barrier(ctx));

	if (!TYPE_IS_FLAT(type)) {
		g(gen_compare_da_tag(ctx, R_SCRATCH_1, DATA_TAG_flat, COND_E, escape_label, R_SCRATCH_1));
	}

	gen_label(no_ex_label);
	g(gen_frame_clear(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r));

	ctx->flag_cache[slot_r] = -1;

	return true;
}

static bool attr_w gen_system_property(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_1, escape_label));

	g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_1, 0, R_ARG0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, ipret_system_property), 1));

	g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_RET0));

	ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;

	return true;
}

static bool attr_w gen_flat_move_copy(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r)
{
	uint32_t escape_label;
	const struct type *type;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_1, escape_label));

	type = get_type_of_local(ctx, slot_1);

	g(gen_memcpy(ctx, R_FRAME, (size_t)slot_r * slot_size, R_FRAME, (size_t)slot_1 * slot_size, type->size, maximum(slot_size, type->align)));

	ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;

	return false;
}

static bool attr_w gen_ref_move_copy(struct codegen_context *ctx, code_t code, frame_t slot_1, frame_t slot_r)
{
	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_ARG0));
	g(gen_frame_store(ctx, OP_SIZE_SLOT, slot_r, 0, R_ARG0));
	g(gen_set_1(ctx, R_FRAME, slot_r, 0, true));
	ctx->flag_cache[slot_r] = 1;
	if (code == OPCODE_REF_COPY) {
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
	} else if (code == OPCODE_REF_MOVE && !da(ctx->fn,function)->local_variables_flags[slot_1].may_be_borrowed) {
		g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
		ctx->flag_cache[slot_1] = -1;
	} else {
		uint32_t label_id;
		if (unlikely(!(label_id = alloc_label(ctx))))
			return false;
		if (!flag_cache_chicken && ctx->flag_cache[slot_1] == 1) {
			g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
			goto move_it;
		}
		if (!flag_cache_chicken && ctx->flag_cache[slot_1] == -1) {
			goto do_reference;
		}
		g(gen_test_1(ctx, R_FRAME, slot_1, 0, label_id, false, TEST_CLEAR));
do_reference:
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
move_it:
		gen_label(label_id);
		if (code == OPCODE_REF_MOVE_CLEAR)
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
		ctx->flag_cache[slot_1] = -1;
	}
	return true;
}

static bool attr_w gen_box_move_copy(struct codegen_context *ctx, code_t code, frame_t slot_1, frame_t slot_r)
{
	gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
	gen_one(R_ARG0);
	gen_one(R_FRAME);
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, slot_1));
	g(gen_upcall_argument(ctx, 1));

	g(gen_load_constant(ctx, R_ARG2, code == OPCODE_BOX_MOVE_CLEAR));
	g(gen_upcall_argument(ctx, 2));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_copy_variable_to_pointer), 3));

	if (code == OPCODE_BOX_MOVE_CLEAR) {
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
		ctx->flag_cache[slot_1] = -1;
	}

	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	return true;
}

static bool attr_w gen_eval(struct codegen_context *ctx, frame_t slot_1)
{
	uint32_t escape_label, skip_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	skip_label = alloc_label(ctx);
	if (unlikely(!skip_label))
		return false;

	g(gen_test_1_jz_cached(ctx, slot_1, skip_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));

	gen_label(skip_label);

	return true;
}

static bool attr_w gen_jump(struct codegen_context *ctx, int32_t jmp_offset, unsigned cond)
{
	ip_t ip = (ctx->current_position - da(ctx->fn,function)->code) + (jmp_offset / (int)sizeof(code_t));
	if (likely(!ctx->code_labels[ip])) {
		ctx->code_labels[ip] = alloc_label(ctx);
		if (unlikely(!ctx->code_labels[ip]))
			return false;
	}
	if (!cond) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(ctx->code_labels[ip]);
	} else if (cond == 1) {
#if defined(ARCH_S390)
		gen_insn(INSN_JMP_COND_LOGICAL, maximum(OP_SIZE_4, log_2(sizeof(ajla_flat_option_t))), COND_E, 0);
#else
		gen_insn(COND_IS_LOGICAL(COND_E) ? INSN_JMP_COND_LOGICAL : INSN_JMP_COND, maximum(OP_SIZE_4, log_2(sizeof(ajla_flat_option_t))), COND_E, 0);
#endif
		gen_four(ctx->code_labels[ip]);
	} else if (cond == 2) {
		g(gen_jmp_on_zero(ctx, OP_SIZE_NATIVE, R_SCRATCH_1, COND_E, ctx->code_labels[ip]));
	} else {
		internal(file_line, "gen_jump: invalid condition %u", cond);
	}
	return true;
}

static bool attr_w gen_cond_jump(struct codegen_context *ctx, frame_t slot, int32_t jmp_offset)
{
	unsigned size = log_2(sizeof(ajla_flat_option_t));
#if defined(ARCH_S390) || defined(ARCH_X86)
	size_t offset = (size_t)slot * slot_size;
#if defined(ARCH_S390)
	if (size != OP_SIZE_1)
		goto no_load_op;
#endif
	g(gen_address(ctx, R_FRAME, offset, IMM_PURPOSE_MVI_CLI_OFFSET, size));
	gen_insn(INSN_CMP, size, 0, 2);
	gen_address_offset();
	gen_one(ARG_IMM);
	gen_eight(0);

	g(gen_jump(ctx, jmp_offset, 1));
	return true;
#endif
	goto no_load_op;
no_load_op:
	g(gen_frame_load(ctx, size, false, slot, 0, R_SCRATCH_1));
	g(gen_jump(ctx, jmp_offset, 2));
	return true;
}

static bool attr_w gen_load_fn_or_curry(struct codegen_context *ctx, frame_t fn_idx, frame_t slot_fn, frame_t slot_r, unsigned flags)
{
	bool curry = fn_idx == NO_FRAME_T;
	uint32_t escape_label;
	arg_t i;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_load_constant(ctx, R_ARG0, ctx->args_l));
	g(gen_upcall_argument(ctx, 0));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_function_reference_mayfail), 1));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
	gen_one(R_SAVED_1);
	gen_one(R_RET0);

	if (!curry) {
		g(load_function_offset(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.local_directory[fn_idx])));

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.u.direct), IMM_PURPOSE_STR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_1);

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.is_indirect), IMM_PURPOSE_STR_OFFSET, log_2(sizeof(bool))));
		g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(uchar_efficient_t))));
		gen_insn(INSN_MOV, log_2(sizeof(uchar_efficient_t)), 0, 0);
		gen_address_offset();
		gen_imm_offset();
	} else {
		g(gen_frame_get_pointer(ctx, slot_fn, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_SCRATCH_1));

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.u.indirect), IMM_PURPOSE_STR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_1);

		g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.function_reference.is_indirect), IMM_PURPOSE_STR_OFFSET, log_2(sizeof(bool))));
		g(gen_imm(ctx, 1, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(uchar_efficient_t))));
		gen_insn(INSN_MOV, log_2(sizeof(uchar_efficient_t)), 0, 0);
		gen_address_offset();
		gen_imm_offset();
	}

	for (i = 0; i < ctx->args_l; i++) {
		uintptr_t arg_offset_tag = offsetof(struct data, u_.function_reference.arguments[i].tag);
		uintptr_t arg_offset_ptr = offsetof(struct data, u_.function_reference.arguments[i].u.ptr);
		uintptr_t arg_offset_slot = offsetof(struct data, u_.function_reference.arguments[i].u.slot);
		frame_t arg_slot = ctx->args[i].slot;
		const struct type *t = get_type_of_local(ctx, arg_slot);
		uint32_t skip_flat_label, set_ptr_label, next_arg_label;
		skip_flat_label = alloc_label(ctx);
		if (unlikely(!skip_flat_label))
			return false;
		set_ptr_label = alloc_label(ctx);
		if (unlikely(!set_ptr_label))
			return false;
		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;
		if (TYPE_IS_FLAT(t)) {
			g(gen_test_1_cached(ctx, arg_slot, skip_flat_label));
			if (t->size <= slot_size && TYPE_TAG_IS_BUILTIN(t->tag)) {
				unsigned copy_size = OP_SIZE_SLOT;
				if (is_power_of_2(t->size))
					copy_size = log_2(t->size);
				if (!ARCH_HAS_BWX)
					copy_size = maximum(copy_size, OP_SIZE_4);
				g(gen_address(ctx, R_SAVED_1, arg_offset_tag, IMM_PURPOSE_STR_OFFSET, log_2(sizeof(type_tag_t))));
				g(gen_imm(ctx, t->tag, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(type_tag_t))));
				gen_insn(INSN_MOV, log_2(sizeof(type_tag_t)), 0, 0);
				gen_address_offset();
				gen_imm_offset();

#if defined(ARCH_S390)
				if (copy_size == OP_SIZE_1 && !cpu_test_feature(CPU_FEATURE_long_displacement)) {
					g(gen_address(ctx, R_FRAME, (size_t)arg_slot * slot_size, IMM_PURPOSE_LDR_OFFSET, copy_size));
					gen_insn(INSN_MOV_MASK, OP_SIZE_NATIVE, MOV_MASK_0_8, 0);
					gen_one(R_SCRATCH_1);
					gen_one(R_SCRATCH_1);
					gen_address_offset();
				} else
#endif
				{
					g(gen_address(ctx, R_FRAME, (size_t)arg_slot * slot_size, ARCH_PREFERS_SX(copy_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, copy_size));
					gen_insn(ARCH_PREFERS_SX(copy_size) ? INSN_MOVSX : INSN_MOV, copy_size, 0, 0);
					gen_one(R_SCRATCH_1);
					gen_address_offset();
				}

				g(gen_address(ctx, R_SAVED_1, arg_offset_slot, IMM_PURPOSE_STR_OFFSET, copy_size));
				gen_insn(INSN_MOV, copy_size, 0, 0);
				gen_address_offset();
				gen_one(R_SCRATCH_1);

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(next_arg_label);
			} else {
				gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
				gen_one(R_ARG0);
				gen_one(R_FRAME);
				g(gen_upcall_argument(ctx, 0));

				g(gen_load_constant(ctx, R_ARG1, arg_slot));
				g(gen_upcall_argument(ctx, 1));

				g(gen_imm(ctx, (size_t)arg_slot * slot_size, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
				gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
				gen_one(R_ARG2);
				gen_one(R_FRAME);
				gen_imm_offset();
				g(gen_upcall_argument(ctx, 2));

				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 3));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(set_ptr_label);
			}
		}

		gen_label(skip_flat_label);
		g(gen_frame_get_pointer(ctx, arg_slot, (ctx->args[i].flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_RET0));

		gen_label(set_ptr_label);
		g(gen_address(ctx, R_SAVED_1, arg_offset_tag, IMM_PURPOSE_STR_OFFSET, log_2(sizeof(type_tag_t))));
		g(gen_imm(ctx, TYPE_TAG_unknown, IMM_PURPOSE_STORE_VALUE, log_2(sizeof(type_tag_t))));
		gen_insn(INSN_MOV, log_2(sizeof(type_tag_t)), 0, 0);
		gen_address_offset();
		gen_imm_offset();

		g(gen_address(ctx, R_SAVED_1, arg_offset_ptr, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_address_offset();
		gen_one(R_RET0);

		gen_label(next_arg_label);
	}

	g(gen_compress_pointer(ctx, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1));

	return true;
}

static bool attr_w gen_call(struct codegen_context *ctx, code_t code, frame_t fn_idx)
{
	struct data *new_fn = ctx->local_directory[fn_idx];
	frame_t required_slots = da(new_fn,function)->frame_slots;
	frame_t bitmap_slots = da(new_fn,function)->n_bitmap_slots;
	uint32_t escape_label;
	int64_t new_fp_offset;
	uchar_efficient_t call_mode;
	arg_t i;
	bool arch_use_flags = ARCH_HAS_FLAGS;
#if defined(ARCH_POWER)
	arch_use_flags = false;
#endif

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_frame_load(ctx, log_2(sizeof(stack_size_t)), false, 0, frame_offs(available_slots), R_SCRATCH_1));
	g(gen_imm(ctx, required_slots, IMM_PURPOSE_SUB, i_size(log_2(sizeof(stack_size_t)))));
	gen_insn(INSN_ALU + ARCH_PARTIAL_ALU(i_size(log_2(sizeof(stack_size_t)))), i_size(log_2(sizeof(stack_size_t))), ALU_SUB, arch_use_flags);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_1);
	gen_imm_offset();

	if (arch_use_flags) {
		gen_insn(COND_IS_LOGICAL(COND_B) ? INSN_JMP_COND_LOGICAL : INSN_JMP_COND, log_2(sizeof(stack_size_t)), COND_B, 0);
		gen_four(escape_label);
	} else {
		g(gen_cmp_test_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, R_SCRATCH_1, R_SCRATCH_1, COND_S, escape_label));
	}

	new_fp_offset = -(ssize_t)(required_slots * slot_size);

	g(gen_frame_store(ctx, log_2(sizeof(stack_size_t)), 0, new_fp_offset + frame_offs(available_slots), R_SCRATCH_1));
	g(gen_frame_store_imm(ctx, log_2(sizeof(ip_t)), 0, new_fp_offset + frame_offs(previous_ip), ctx->return_values - da(ctx->fn,function)->code));
	g(gen_frame_load(ctx, log_2(sizeof(timestamp_t)), false, 0, frame_offs(timestamp), R_SCRATCH_1));
	g(gen_frame_store(ctx, log_2(sizeof(timestamp_t)), 0, new_fp_offset + frame_offs(timestamp), R_SCRATCH_1));
	call_mode = code == OPCODE_CALL ? CALL_MODE_NORMAL : code == OPCODE_CALL_STRICT ? CALL_MODE_STRICT : CALL_MODE_SPARK;
	g(gen_frame_store_imm(ctx, log_2(sizeof(uchar_efficient_t)), 0, new_fp_offset + frame_offs(mode), call_mode));

	g(gen_clear_bitmap(ctx, frame_offset, R_FRAME, new_fp_offset, bitmap_slots));

	for (i = 0; i < ctx->args_l; i++) {
		const struct code_arg *src_arg = &ctx->args[i];
		const struct local_arg *dest_arg = &da(new_fn,function)->args[i];
		const struct type *t = get_type_of_local(ctx, src_arg->slot);
		uint32_t non_flat_label, thunk_label, incr_ref_label, next_arg_label;
		non_flat_label = alloc_label(ctx);
		if (unlikely(!non_flat_label))
			return false;
		thunk_label = alloc_label(ctx);
		if (unlikely(!thunk_label))
			return false;
		incr_ref_label = alloc_label(ctx);
		if (unlikely(!incr_ref_label))
			return false;
		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;
		if (TYPE_IS_FLAT(t)) {
			g(gen_test_1_cached(ctx, src_arg->slot, non_flat_label));
			if (dest_arg->may_be_flat) {
				g(gen_memcpy(ctx, R_FRAME, new_fp_offset + (size_t)dest_arg->slot * slot_size, R_FRAME, (size_t)src_arg->slot * slot_size, t->size, maximum(slot_size, t->align)));
			} else {
				gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
				gen_one(R_ARG0);
				gen_one(R_FRAME);
				g(gen_upcall_argument(ctx, 0));

				g(gen_load_constant(ctx, R_ARG1, src_arg->slot));
				g(gen_upcall_argument(ctx, 1));

				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG2, R_FRAME, (size_t)src_arg->slot * slot_size));
				g(gen_upcall_argument(ctx, 2));

				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 3));

				g(gen_frame_store(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, R_RET0));

				g(gen_set_1(ctx, R_FRAME, dest_arg->slot, new_fp_offset, true));
			}

			if (!flag_cache_chicken && ctx->flag_cache[src_arg->slot] == -1)
				goto skip_ref_argument;

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		}
		gen_label(non_flat_label);

		if (dest_arg->may_be_borrowed && src_arg->flags & OPCODE_CALL_MAY_LEND) {
			g(gen_frame_load(ctx, OP_SIZE_SLOT, false, src_arg->slot, 0, R_SCRATCH_1));
			g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, thunk_label));
			g(gen_frame_store(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, R_SCRATCH_1));
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		} else if (dest_arg->may_be_borrowed && src_arg->flags & OPCODE_CALL_MAY_GIVE) {
			g(gen_test_1_cached(ctx, src_arg->slot, thunk_label));
			g(gen_frame_load(ctx, OP_SIZE_SLOT, false, src_arg->slot, 0, R_SCRATCH_1));
			g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, thunk_label));
			g(gen_frame_store(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, R_SCRATCH_1));
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, src_arg->slot));
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		}

		gen_label(thunk_label);
		g(gen_set_1(ctx, R_FRAME, dest_arg->slot, new_fp_offset, true));
		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, src_arg->slot, 0, R_ARG0));
		g(gen_frame_store(ctx, OP_SIZE_SLOT, dest_arg->slot, new_fp_offset, R_ARG0));
		if (src_arg->flags & OPCODE_FLAG_FREE_ARGUMENT) {
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, src_arg->slot));
			if (!flag_cache_chicken && ctx->flag_cache[src_arg->slot] == 1) {
				g(gen_set_1(ctx, R_FRAME, src_arg->slot, 0, false));
				ctx->flag_cache[src_arg->slot] = -1;
				goto skip_ref_argument;
			}
			if (!flag_cache_chicken && ctx->flag_cache[src_arg->slot] == -1) {
				goto do_reference;
			}
			g(gen_test_1(ctx, R_FRAME, src_arg->slot, 0, incr_ref_label, true, TEST_CLEAR));
			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);
		}
do_reference:
		gen_label(incr_ref_label);
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));

skip_ref_argument:
		gen_label(next_arg_label);
	}

	g(load_function_offset(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.local_directory[fn_idx])));

	g(gen_address(ctx, R_SCRATCH_1, 0, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
	gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_decompress_pointer(ctx, R_SCRATCH_1, 0));

	g(gen_frame_store(ctx, OP_SIZE_ADDRESS, 0, frame_offs(function) + new_fp_offset, R_SCRATCH_1));

#if !defined(ARCH_X86) && !defined(ARCH_PARISC)
	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_SUB, R_FRAME, R_FRAME, -new_fp_offset));
#else
	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_FRAME, R_FRAME, new_fp_offset));
#endif

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.codegen), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, ctx->escape_labels[0]));
	g(gen_barrier(ctx));

	gen_pointer_compression(R_SCRATCH_1);
#if (defined(ARCH_X86) && !defined(ARCH_X86_X32)) || defined(ARCH_ARM32)
	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code_base), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_address_offset_compressed();
#else
	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code_base), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset_compressed();

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_SCRATCH_1);
#endif
	g(clear_flag_cache(ctx));

	return true;
}

static bool attr_w gen_return(struct codegen_context *ctx)
{
	int64_t new_fp_offset;
	uint32_t escape_label;
	arg_t i;
	int64_t retval_offset;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	new_fp_offset = (size_t)da(ctx->fn,function)->frame_slots * slot_size;

	g(gen_frame_load(ctx, OP_SIZE_ADDRESS, false, 0, new_fp_offset + frame_offs(function), R_SCRATCH_2));

	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_SCRATCH_2, COND_E, escape_label));

	g(gen_address(ctx, R_SCRATCH_2, offsetof(struct data, u_.function.codegen), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
	g(gen_barrier(ctx));

	g(gen_frame_load(ctx, log_2(sizeof(timestamp_t)), false, 0, frame_offs(timestamp), R_SCRATCH_1));
	g(gen_frame_store(ctx, log_2(sizeof(timestamp_t)), 0, new_fp_offset + frame_offs(timestamp), R_SCRATCH_1));

	g(gen_frame_load(ctx, log_2(sizeof(ip_t)), false, 0, frame_offs(previous_ip), R_SCRATCH_1));

	g(gen_address(ctx, R_SCRATCH_2, offsetof(struct data, u_.function.code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_lea3(ctx, R_SAVED_1, R_SCRATCH_2, R_SCRATCH_1, log_2(sizeof(code_t)), 0));

	retval_offset = 0;
	for (i = 0; i < ctx->args_l; i++) {
		const struct code_arg *src_arg = &ctx->args[i];
		const struct type *t = get_type_of_local(ctx, src_arg->slot);
		uint32_t copy_ptr_label, load_write_ptr_label, write_ptr_label, next_arg_label;

		copy_ptr_label = alloc_label(ctx);
		if (unlikely(!copy_ptr_label))
			return false;

		load_write_ptr_label = alloc_label(ctx);
		if (unlikely(!load_write_ptr_label))
			return false;

		write_ptr_label = alloc_label(ctx);
		if (unlikely(!write_ptr_label))
			return false;

		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;

		g(gen_load_code_32(ctx, R_SAVED_2, R_SAVED_1, retval_offset));

		if (TYPE_IS_FLAT(t)) {
			uint32_t flat_to_data_label;
			g(gen_test_1_cached(ctx, src_arg->slot, copy_ptr_label));

			flat_to_data_label = alloc_label(ctx);
			if (unlikely(!flat_to_data_label))
				return false;

#if defined(ARCH_X86)
			g(gen_address(ctx, R_SAVED_1, retval_offset + 2 + 2 * (ARG_MODE_N >= 3), IMM_PURPOSE_LDR_OFFSET, log_2(sizeof(code_t))));
			g(gen_imm(ctx, OPCODE_MAY_RETURN_FLAT, IMM_PURPOSE_TEST, log_2(sizeof(code_t))));
			gen_insn(INSN_TEST, log_2(sizeof(code_t)), 0, 1);
			gen_address_offset();
			gen_imm_offset();

			gen_insn(INSN_JMP_COND, log_2(sizeof(code_t)), COND_E, 0);
			gen_four(flat_to_data_label);
#else
			g(gen_load_two(ctx, R_SCRATCH_1, R_SAVED_1, retval_offset + 2 + 2 * (ARG_MODE_N >= 3)));

			g(gen_cmp_test_imm_jmp(ctx, INSN_TEST, OP_SIZE_NATIVE, R_SCRATCH_1, OPCODE_MAY_RETURN_FLAT, COND_E, flat_to_data_label));
#endif
#if defined(ARCH_X86)
			if (is_power_of_2(t->size) && t->size <= 2U << OP_SIZE_NATIVE) {
				if (t->size == 2U << OP_SIZE_NATIVE) {
					g(gen_frame_load_2(ctx, OP_SIZE_NATIVE, src_arg->slot, 0, R_SCRATCH_1, R_SCRATCH_2));

					gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
					gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
					gen_one(R_FRAME);
					gen_one(R_SAVED_2);
					gen_eight(new_fp_offset + lo_word(OP_SIZE_NATIVE));
					gen_one(R_SCRATCH_1);

					gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
					gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
					gen_one(R_FRAME);
					gen_one(R_SAVED_2);
					gen_eight(new_fp_offset + hi_word(OP_SIZE_NATIVE));
					gen_one(R_SCRATCH_2);
				} else {
					g(gen_frame_load(ctx, log_2(t->size), false, src_arg->slot, 0, R_SCRATCH_1));

					gen_insn(INSN_MOV, log_2(t->size), 0, 0);
					gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
					gen_one(R_FRAME);
					gen_one(R_SAVED_2);
					gen_eight(new_fp_offset);
					gen_one(R_SCRATCH_1);
				}
			} else
#endif
			{
				g(gen_lea3(ctx, R_SCRATCH_2, R_FRAME, R_SAVED_2, OP_SIZE_SLOT, new_fp_offset));

				g(gen_memcpy(ctx, R_SCRATCH_2, 0, R_FRAME, (size_t)src_arg->slot * slot_size, t->size, maximum(slot_size, t->align)));
			}

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(next_arg_label);

			gen_label(flat_to_data_label);

			gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
			gen_one(R_ARG0);
			gen_one(R_FRAME);
			g(gen_upcall_argument(ctx, 0));

			g(gen_load_constant(ctx, R_ARG1, src_arg->slot));
			g(gen_upcall_argument(ctx, 1));

			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG2, R_FRAME, (size_t)src_arg->slot * slot_size));
			g(gen_upcall_argument(ctx, 2));

			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 3));

			if (!flag_cache_chicken && ctx->flag_cache[src_arg->slot] == -1)
				goto skip_ref_argument;

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(write_ptr_label);
		}

		gen_label(copy_ptr_label);

		if (unlikely(!(src_arg->flags & OPCODE_FLAG_FREE_ARGUMENT))) {
			g(gen_frame_load(ctx, OP_SIZE_SLOT, false, src_arg->slot, 0, R_ARG0));
			g(gen_upcall_argument(ctx, 0));
			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
		} else if (da(ctx->fn,function)->local_variables_flags[src_arg->slot].may_be_borrowed) {
			g(gen_test_1_cached(ctx, src_arg->slot, load_write_ptr_label));
			g(gen_frame_load(ctx, OP_SIZE_SLOT, false, src_arg->slot, 0, R_ARG0));
			g(gen_upcall_argument(ctx, 0));
			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
		}

		gen_label(load_write_ptr_label);

		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, src_arg->slot, 0, R_RET0));

skip_ref_argument:
		gen_label(write_ptr_label);

#if defined(ARCH_X86)
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
		gen_one(R_FRAME);
		gen_one(R_SAVED_2);
		gen_eight(new_fp_offset);
		gen_one(R_RET0);
		goto scaled_store_done;
#endif
		if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_SLOT)) {
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
			gen_one(R_SCRATCH_3);
			gen_one(R_FRAME);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | OP_SIZE_SLOT);
			gen_one(R_SAVED_2);

			g(gen_address(ctx, R_SCRATCH_3, new_fp_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
			gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_address_offset();
			gen_one(R_RET0);
			goto scaled_store_done;
		}

		g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_SCRATCH_3, R_SAVED_2, OP_SIZE_SLOT, false));

		g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, R_SCRATCH_3, R_SCRATCH_3, R_FRAME));

		g(gen_address(ctx, R_SCRATCH_3, new_fp_offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_address_offset();
		gen_one(R_RET0);

scaled_store_done:
		g(gen_set_1_variable(ctx, R_SAVED_2, new_fp_offset, true));

		gen_label(next_arg_label);

		retval_offset += 4 + 2 * (ARG_MODE_N >= 3);
	}

	g(gen_frame_load(ctx, OP_SIZE_ADDRESS, false, 0, new_fp_offset + frame_offs(function), R_SCRATCH_1));

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.function.codegen), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	g(gen_decompress_pointer(ctx, R_SCRATCH_1, 0));

	g(gen_load_code_32(ctx, R_SCRATCH_2, R_SAVED_1, retval_offset + 2));

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_FRAME, R_FRAME, new_fp_offset));

#if defined(ARCH_X86) && !defined(ARCH_X86_X32)
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(ARG_ADDRESS_2 + OP_SIZE_ADDRESS);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_2);
	gen_eight(offsetof(struct data, u_.codegen.unoptimized_code));

	goto scaled_jmp_done;
#endif
#if defined(ARCH_X86)
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_one(ARG_ADDRESS_2 + OP_SIZE_ADDRESS);
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_2);
	gen_eight(offsetof(struct data, u_.codegen.unoptimized_code));

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_SCRATCH_1);

	goto scaled_jmp_done;
#endif
#if defined(ARCH_ARM32)
	gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
	gen_one(R_SCRATCH_1);
	gen_one(R_SCRATCH_1);
	gen_one(ARG_SHIFTED_REGISTER);
	gen_one(ARG_SHIFT_LSL | OP_SIZE_ADDRESS);
	gen_one(R_SCRATCH_2);

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_address_offset();

	goto scaled_jmp_done;
#endif
	if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_ADDRESS)) {
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(ARG_SHIFTED_REGISTER);
		gen_one(ARG_SHIFT_LSL | OP_SIZE_ADDRESS);
		gen_one(R_SCRATCH_2);

		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

		gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
		gen_one(R_SCRATCH_1);

		goto scaled_jmp_done;
	}

	g(gen_3address_rot_imm(ctx, OP_SIZE_NATIVE, ROT_SHL, R_SCRATCH_2, R_SCRATCH_2, OP_SIZE_ADDRESS, false));

	g(gen_3address_alu(ctx, OP_SIZE_NATIVE, ALU_ADD, R_SCRATCH_1, R_SCRATCH_1, R_SCRATCH_2));

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.codegen.unoptimized_code), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

	gen_insn(INSN_JMP_INDIRECT, 0, 0, 0);
	gen_one(R_SCRATCH_1);

	goto scaled_jmp_done;
scaled_jmp_done:
	return true;
}

static bool attr_w gen_scaled_array_address(struct codegen_context *ctx, size_t element_size, unsigned reg_dst, unsigned reg_src, unsigned reg_index, int64_t offset_src);
static bool attr_w gen_check_array_len(struct codegen_context *ctx, unsigned reg_array, bool allocated, unsigned reg_len, unsigned cond, uint32_t escape_label);

static bool attr_w gen_structured(struct codegen_context *ctx, frame_t slot_struct, frame_t slot_elem)
{
	uint32_t escape_label;
	const struct type *struct_type, *elem_type;
	size_t i;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	struct_type = get_type_of_local(ctx, slot_struct);
	elem_type = get_type_of_local(ctx, slot_elem);

	if (TYPE_IS_FLAT(struct_type) && struct_type->tag != TYPE_TAG_flat_option) {
		if (!TYPE_IS_FLAT(elem_type)) {
			goto struct_zero;
		} else {
			g(gen_test_1_cached(ctx, slot_struct, escape_label));
			ctx->flag_cache[slot_struct] = -1;
		}
	} else {
struct_zero:
		g(gen_test_1_jz_cached(ctx, slot_struct, escape_label));
		struct_type = NULL;
	}

	g(gen_frame_address(ctx, slot_struct, 0, R_SAVED_1));

	for (i = 0; i < ctx->args_l; i++) {
		frame_t param_slot = ctx->args[i].slot;
		if (struct_type) {
			switch (ctx->args[i].flags & OPCODE_STRUCTURED_MASK) {
				case OPCODE_STRUCTURED_RECORD: {
					struct flat_record_definition_entry *e;
					ajla_assert_lo(struct_type->tag == TYPE_TAG_flat_record, (file_line, "gen_structured: invalid tag %u, expected %u", struct_type->tag, TYPE_TAG_flat_record));
					e = &type_def(struct_type,flat_record)->entries[param_slot];

					g(gen_imm(ctx, e->flat_offset, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
					gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
					gen_one(R_SAVED_1);
					gen_one(R_SAVED_1);
					gen_imm_offset();

					struct_type = e->subtype;
					break;
				}
				case OPCODE_STRUCTURED_ARRAY: {
					ajla_assert_lo(struct_type->tag == TYPE_TAG_flat_array, (file_line, "gen_structured: invalid tag %u, expected %u", struct_type->tag, TYPE_TAG_flat_array));
					g(gen_test_1_cached(ctx, param_slot, escape_label));
					ctx->flag_cache[param_slot] = -1;
					g(gen_frame_load(ctx, OP_SIZE_INT, false, param_slot, 0, R_SCRATCH_1));

					g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_1, type_def(struct_type,flat_array)->n_elements, COND_AE, escape_label));

					g(gen_scaled_array_address(ctx, type_def(struct_type,flat_array)->base->size, R_SAVED_1, R_SAVED_1, R_SCRATCH_1, 0));

					struct_type = type_def(struct_type,flat_array)->base;
					break;
				}
				default:
					internal(file_line, "gen_structured: invalid structured flags %x", (unsigned)ctx->args[i].flags);
			}
		} else {
			gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SAVED_1);
			gen_eight(0);

			g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
			g(gen_barrier(ctx));

			g(gen_decompress_pointer(ctx, R_SCRATCH_1, 0));

			g(gen_compare_refcount(ctx, R_SCRATCH_1, REFCOUNT_STEP, COND_AE, escape_label));

			switch (ctx->args[i].flags & OPCODE_STRUCTURED_MASK) {
				case OPCODE_STRUCTURED_RECORD: {
					const struct type *rec_type, *e_type;
					rec_type = da_type(ctx->fn, ctx->args[i].type);
					TYPE_TAG_VALIDATE(rec_type->tag);
					if (unlikely(rec_type->tag == TYPE_TAG_flat_record))
						rec_type = type_def(rec_type,flat_record)->base;
					e_type = type_def(rec_type,record)->types[param_slot];
					if (!TYPE_IS_FLAT(e_type) || (e_type->tag == TYPE_TAG_flat_option && !(ctx->args[i].flags & OPCODE_STRUCTURED_FLAG_END))) {
						g(gen_test_1(ctx, R_SCRATCH_1, param_slot, data_record_offset, escape_label, true, TEST));
					} else {
						g(gen_test_1(ctx, R_SCRATCH_1, param_slot, data_record_offset, escape_label, false, TEST));
						struct_type = e_type;
					}
					g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SAVED_1, R_SCRATCH_1, data_record_offset + (size_t)param_slot * slot_size));
					break;
				}
				case OPCODE_STRUCTURED_OPTION: {
					unsigned op_size = log_2(sizeof(ajla_option_t));
#if defined(ARCH_X86)
					g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.option.option), IMM_PURPOSE_LDR_OFFSET, op_size));
					g(gen_imm(ctx, param_slot, IMM_PURPOSE_CMP, op_size));
					gen_insn(INSN_CMP, op_size, 0, 1);
					gen_address_offset();
					gen_imm_offset();

					gen_insn(INSN_JMP_COND, op_size, COND_NE, 0);
					gen_four(escape_label);
#else
					g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
					gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
					gen_one(R_SCRATCH_2);
					gen_address_offset();

					g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, i_size(op_size), R_SCRATCH_2, param_slot, COND_NE, escape_label));
#endif
					g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_SAVED_1, R_SCRATCH_1, offsetof(struct data, u_.option.pointer)));
					break;
				}
				case OPCODE_STRUCTURED_ARRAY: {
					const struct type *e_type = da_type(ctx->fn, ctx->args[i].type);

					g(gen_test_1_cached(ctx, param_slot, escape_label));
					ctx->flag_cache[param_slot] = -1;

					g(gen_frame_load(ctx, OP_SIZE_INT, false, param_slot, 0, R_SCRATCH_2));

					g(gen_check_array_len(ctx, R_SCRATCH_1, false, R_SCRATCH_2, COND_AE, escape_label));

					if (!TYPE_IS_FLAT(e_type) || (e_type->tag == TYPE_TAG_flat_option && !(ctx->args[i].flags & OPCODE_STRUCTURED_FLAG_END))) {
						g(gen_compare_ptr_tag(ctx, R_SCRATCH_1, DATA_TAG_array_pointers, COND_NE, escape_label, R_SCRATCH_3));

						g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
						gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
						gen_one(R_SCRATCH_1);
						gen_address_offset();

						g(gen_scaled_array_address(ctx, slot_size, R_SAVED_1, R_SCRATCH_1, R_SCRATCH_2, 0));
					} else {
						g(gen_compare_ptr_tag(ctx, R_SCRATCH_1, DATA_TAG_array_flat, COND_NE, escape_label, R_SCRATCH_3));

						g(gen_scaled_array_address(ctx, e_type->size, R_SAVED_1, R_SCRATCH_1, R_SCRATCH_2, data_array_offset));

						struct_type = e_type;
					}
					break;
				}
				default: {
					internal(file_line, "gen_structured: invalid structured flags %x", (unsigned)ctx->args[i].flags);
				}
			}
		}
	}

	if (struct_type) {
		g(gen_test_1_cached(ctx, slot_elem, escape_label));
		ctx->flag_cache[slot_elem] = -1;
		g(gen_memcpy(ctx, R_SAVED_1, 0, R_FRAME, (size_t)slot_elem * slot_size, struct_type->size, struct_type->align));
	} else {
		uint32_t skip_deref_label;
		skip_deref_label = alloc_label(ctx);
		if (unlikely(!skip_deref_label))
			return false;

		if (TYPE_IS_FLAT(elem_type))
			g(gen_test_1_jz_cached(ctx, slot_elem, escape_label));

		gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_ARG0);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SAVED_1);
		gen_eight(0);

		g(gen_jmp_on_zero(ctx, OP_SIZE_SLOT, R_ARG0, COND_E, skip_deref_label));

		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_dereference), 1));

		gen_label(skip_deref_label);

		g(gen_frame_get_pointer(ctx, slot_elem, (ctx->args[i - 1].flags & OPCODE_STRUCTURED_FREE_VARIABLE) != 0, R_SCRATCH_1));

		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SAVED_1);
		gen_eight(0);
		gen_one(R_SCRATCH_1);
	}

	return true;
}

static bool attr_w gen_record_create(struct codegen_context *ctx, frame_t slot_r)
{
	const struct type *t;
	const struct record_definition *def;
	uint32_t escape_label;
	arg_t i, ii;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	t = get_type_of_local(ctx, slot_r);
	if (t->tag == TYPE_TAG_flat_record) {
		const struct flat_record_definition *flat_def;
		const struct type *flat_type = t;
		t = type_def(t,flat_record)->base;
		def = type_def(t,record);
		flat_def = type_def(flat_type,flat_record);
		for (i = 0; i < ctx->args_l; i++) {
			frame_t var_slot = ctx->args[i].slot;
			g(gen_test_1_cached(ctx, var_slot, escape_label));
			ctx->flag_cache[var_slot] = -1;
		}
		for (i = 0, ii = 0; i < ctx->args_l; i++, ii++) {
			frame_t var_slot, flat_offset, record_slot;
			const struct type *var_type;
			while (unlikely(record_definition_is_elided(def, ii)))
				ii++;
			var_slot = ctx->args[i].slot;
			var_type = get_type_of_local(ctx, var_slot);
			record_slot = record_definition_slot(def, ii);
			flat_offset = flat_def->entries[record_slot].flat_offset;
			g(gen_memcpy(ctx, R_FRAME, (size_t)slot_r * slot_size + flat_offset, R_FRAME, (size_t)var_slot * slot_size, var_type->size, var_type->align));
		}
		return true;
	}

	def = type_def(t,record);

	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_ARG0);
	gen_one(R_FRAME);
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, slot_r));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_record_mayfail), 2));

	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
	gen_one(R_SAVED_1);
	gen_one(R_RET0);

	g(gen_clear_bitmap(ctx, 0, R_SAVED_1, data_record_offset, bitmap_slots(def->n_slots)));

	for (i = 0, ii = 0; i < ctx->args_l; i++, ii++) {
		frame_t var_slot, var_flags, record_slot;
		const struct type *var_type, *record_type;
		uint32_t skip_flat_label, set_ptr_label, next_arg_label;

		skip_flat_label = alloc_label(ctx);
		if (unlikely(!skip_flat_label))
			return false;
		set_ptr_label = alloc_label(ctx);
		if (unlikely(!set_ptr_label))
			return false;
		next_arg_label = alloc_label(ctx);
		if (unlikely(!next_arg_label))
			return false;

		while (unlikely(record_definition_is_elided(def, ii)))
			ii++;
		var_slot = ctx->args[i].slot;
		var_type = get_type_of_local(ctx, var_slot);
		var_flags = ctx->args[i].flags;
		record_slot = record_definition_slot(def, ii);
		record_type = def->types[record_slot];
		if (TYPE_IS_FLAT(var_type)) {
			g(gen_test_1_cached(ctx, var_slot, skip_flat_label));
			if (TYPE_IS_FLAT(record_type)) {
				g(gen_memcpy(ctx, R_SAVED_1, data_record_offset + (size_t)record_slot * slot_size, R_FRAME, (size_t)var_slot * slot_size, var_type->size, maximum(slot_size, var_type->align)));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(next_arg_label);
			} else {
				gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
				gen_one(R_ARG0);
				gen_one(R_FRAME);
				g(gen_upcall_argument(ctx, 0));

				g(gen_load_constant(ctx, R_ARG1, var_slot));
				g(gen_upcall_argument(ctx, 1));

				g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG2, R_FRAME, (size_t)var_slot * slot_size));
				g(gen_upcall_argument(ctx, 2));

				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 3));

				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(set_ptr_label);
			}
		}

		gen_label(skip_flat_label);
		g(gen_frame_get_pointer(ctx, var_slot, (var_flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_RET0));

		gen_label(set_ptr_label);
		g(gen_address(ctx, R_SAVED_1, data_record_offset + (size_t)record_slot * slot_size, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_address_offset();
		gen_one(R_RET0);

		g(gen_set_1(ctx, R_SAVED_1, record_slot, data_record_offset, true));

		gen_label(next_arg_label);
	}

	g(gen_compress_pointer(ctx, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1));

	return true;
}

static bool attr_w gen_record_load(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r, frame_t rec_slot, frame_t flags)
{
	const struct type *rec_type, *entry_type;
	uint32_t escape_label;

	rec_type = get_type_of_local(ctx, slot_1);
	if (unlikely(rec_type->tag == TYPE_TAG_unknown)) {
		ajla_assert_lo(!*da(ctx->fn,function)->function_name, (file_line, "gen_record_load: function %s has record without definition", da(ctx->fn,function)->function_name));
		return false;
	}

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	/*debug("gen_record_load: %s: %u, %u", da(ctx->fn,function)->function_name, TYPE_TAG_unknown, rec_type->tag);*/
	if (TYPE_IS_FLAT(rec_type)) {
		const struct flat_record_definition_entry *ft = &type_def(rec_type,flat_record)->entries[rec_slot];
		g(gen_test_1_cached(ctx, slot_1, escape_label));
		g(gen_memcpy(ctx, R_FRAME, (size_t)slot_r * slot_size, R_FRAME, (size_t)slot_1 * slot_size + ft->flat_offset, ft->subtype->size, ft->subtype->align));
		ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
		return true;
	}
	entry_type = type_def(rec_type,record)->types[rec_slot];

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_2));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_2, true, escape_label));
	g(gen_barrier(ctx));

	g(gen_decompress_pointer(ctx, R_SCRATCH_2, 0));

	if (TYPE_IS_FLAT(entry_type)) {
		g(gen_test_1(ctx, R_SCRATCH_2, rec_slot, data_record_offset, escape_label, false, TEST));
		g(gen_memcpy(ctx, R_FRAME, (size_t)slot_r * slot_size, R_SCRATCH_2, (size_t)rec_slot * slot_size + data_record_offset, entry_type->size, entry_type->align));
		ctx->flag_cache[slot_r] = -1;
		return true;
	}

	g(gen_test_1(ctx, R_SCRATCH_2, rec_slot, data_record_offset, escape_label, true, TEST));

	g(gen_address(ctx, R_SCRATCH_2, (size_t)rec_slot * slot_size + data_record_offset, ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_ARG0);
	gen_address_offset();

	g(gen_ptr_is_thunk(ctx, R_ARG0, true, escape_label));

	if (flags & OPCODE_STRUCT_MAY_BORROW) {
		g(gen_frame_store(ctx, OP_SIZE_SLOT, slot_r, 0, R_ARG0));
		ctx->flag_cache[slot_r] = -1;
	} else {
		g(gen_frame_set_pointer(ctx, slot_r, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
	}
	return true;
}

static bool attr_w gen_option_create_empty_flat(struct codegen_context *ctx, ajla_flat_option_t opt, frame_t slot_r)
{
	g(gen_frame_store_imm(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, opt));
	ctx->flag_cache[slot_r] = -1;
	return true;
}

static bool attr_w gen_option_create_empty(struct codegen_context *ctx, ajla_option_t opt, frame_t slot_r)
{
	unsigned option_size = log_2(sizeof(ajla_option_t));
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_option_mayfail), 0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_address(ctx, R_RET0, offsetof(struct data, u_.option.option), IMM_PURPOSE_STR_OFFSET, option_size));
	g(gen_imm(ctx, opt, IMM_PURPOSE_STORE_VALUE, option_size));
	gen_insn(INSN_MOV, option_size, 0, 0);
	gen_address_offset();
	gen_imm_offset();

	g(gen_address(ctx, R_RET0, offsetof(struct data, u_.option.pointer), IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
	g(gen_imm(ctx, 0, IMM_PURPOSE_STORE_VALUE, OP_SIZE_SLOT));
	gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_address_offset();
	gen_imm_offset();

	g(gen_compress_pointer(ctx, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	return true;
}

static bool attr_w gen_option_create(struct codegen_context *ctx, ajla_option_t opt, frame_t slot_1, frame_t slot_r, frame_t flags)
{
	unsigned option_size = log_2(sizeof(ajla_option_t));
	const struct type *type;
	uint32_t escape_label, get_pointer_label, got_pointer_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	get_pointer_label = alloc_label(ctx);
	if (unlikely(!get_pointer_label))
		return false;

	got_pointer_label = alloc_label(ctx);
	if (unlikely(!got_pointer_label))
		return false;

	type = get_type_of_local(ctx, slot_1);

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_option_mayfail), 0));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
	gen_one(R_SAVED_1);
	gen_one(R_RET0);

	g(gen_address(ctx, R_RET0, offsetof(struct data, u_.option.option), IMM_PURPOSE_STR_OFFSET, option_size));
	g(gen_imm(ctx, opt, IMM_PURPOSE_STORE_VALUE, option_size));
	gen_insn(INSN_MOV, option_size, 0, 0);
	gen_address_offset();
	gen_imm_offset();

	if (TYPE_IS_FLAT(type)) {
		g(gen_test_1_cached(ctx, slot_1, get_pointer_label));

		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_ARG0);
		gen_one(R_FRAME);
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, slot_1));
		g(gen_upcall_argument(ctx, 1));

		g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG2, R_FRAME, (size_t)slot_1 * slot_size));
		g(gen_upcall_argument(ctx, 2));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 3));

		if (!flag_cache_chicken && ctx->flag_cache[slot_1] == -1)
			goto skip_get_pointer_label;

		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(got_pointer_label);
	}

	gen_label(get_pointer_label);
	g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_RET0));

skip_get_pointer_label:
	gen_label(got_pointer_label);
	g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.option.pointer), IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
	gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_address_offset();
	gen_one(R_RET0);

	g(gen_compress_pointer(ctx, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1));

	return true;
}

static bool attr_w gen_option_cmp(struct codegen_context *ctx, unsigned reg, frame_t opt, uint32_t label, frame_t slot_r)
{
	unsigned op_size = log_2(sizeof(ajla_option_t));
#if ARCH_HAS_FLAGS
#if defined(ARCH_X86)
	g(gen_address(ctx, reg, offsetof(struct data, u_.option.option), IMM_PURPOSE_LDR_OFFSET, op_size));
	g(gen_imm(ctx, opt, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1);
	gen_address_offset();
	gen_imm_offset();
#else
	g(gen_address(ctx, reg, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_imm(ctx, opt, IMM_PURPOSE_CMP, op_size));
	gen_insn(INSN_CMP, op_size, 0, 1);
	gen_one(R_SCRATCH_2);
	gen_imm_offset();
#endif
	if (label) {
		gen_insn(INSN_JMP_COND, op_size, COND_NE, 0);
		gen_four(label);
	} else {
		g(gen_frame_set_cond(ctx, op_size, false, COND_E, slot_r));
	}
	return true;
#else
	g(gen_address(ctx, reg, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_cmp_dest_reg(ctx, op_size, R_SCRATCH_2, (unsigned)-1, label ? R_CMP_RESULT : R_SCRATCH_2, opt, COND_E));

	if (label) {
		gen_insn(INSN_JMP_REG, i_size(op_size), COND_E, 0);
		gen_one(R_CMP_RESULT);
		gen_four(label);
	} else {
		g(gen_frame_store(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r, 0, R_SCRATCH_2));
	}
	return true;
#endif
}

static bool attr_w gen_option_load(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r, ajla_option_t opt, frame_t flags)
{
	const struct type *type;
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	type = get_type_of_local(ctx, slot_1);
	if (TYPE_IS_FLAT(type)) {
		g(gen_test_1_jz_cached(ctx, slot_1, escape_label));
	}

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
	g(gen_barrier(ctx));
	g(gen_decompress_pointer(ctx, R_SCRATCH_1, 0));
	g(gen_option_cmp(ctx, R_SCRATCH_1, opt, escape_label, 0));

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.option.pointer), ARCH_PREFERS_SX(OP_SIZE_SLOT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_SLOT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(R_ARG0);
	gen_address_offset();

	g(gen_ptr_is_thunk(ctx, R_ARG0, true, escape_label));

	if (flags & OPCODE_STRUCT_MAY_BORROW) {
		g(gen_frame_store(ctx, OP_SIZE_SLOT, slot_r, 0, R_ARG0));
		ctx->flag_cache[slot_r] = -1;
	} else {
		g(gen_frame_set_pointer(ctx, slot_r, R_ARG0));
		g(gen_upcall_argument(ctx, 0));
		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
	}

	return true;
}

static bool attr_w gen_option_test_flat(struct codegen_context *ctx, frame_t slot_1, frame_t opt, frame_t slot_r)
{
	unsigned op_size = log_2(sizeof(ajla_flat_option_t));
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_1, escape_label));

	ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;

	if (unlikely(opt != (ajla_flat_option_t)opt)) {
		g(gen_frame_clear(ctx, op_size, slot_r));
		return true;
	}

	g(gen_frame_load_cmp_imm_set_cond(ctx, op_size, false, slot_1, 0, opt, COND_E, slot_r));

	return true;
}

static bool attr_w gen_option_test(struct codegen_context *ctx, frame_t slot_1, frame_t opt, frame_t slot_r)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
	g(gen_barrier(ctx));

	ctx->flag_cache[slot_r] = -1;

	if (unlikely(opt != (ajla_option_t)opt)) {
		g(gen_frame_clear(ctx, log_2(sizeof(ajla_flat_option_t)), slot_r));
		return true;
	}

	g(gen_decompress_pointer(ctx, R_SCRATCH_1, 0));
	g(gen_option_cmp(ctx, R_SCRATCH_1, opt, 0, slot_r));

	return true;
}

static bool attr_w gen_option_ord(struct codegen_context *ctx, frame_t slot_1, frame_t slot_r, bool flat)
{
	unsigned op_size = log_2(sizeof(ajla_option_t));
	unsigned op_size_flat = log_2(sizeof(ajla_flat_option_t));
	uint32_t escape_label, ptr_label, store_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	ptr_label = alloc_label(ctx);
	if (unlikely(!ptr_label))
		return false;

	store_label = alloc_label(ctx);
	if (unlikely(!store_label))
		return false;

	if (flat) {
		g(gen_test_1_cached(ctx, slot_1, ptr_label));

		g(gen_frame_load(ctx, op_size_flat, false, slot_1, 0, R_SCRATCH_1));

		if (!flag_cache_chicken && ctx->flag_cache[slot_1] == -1)
			goto skip_ptr_label;

		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(store_label);
	}

	gen_label(ptr_label);
	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
	g(gen_barrier(ctx));

	g(gen_decompress_pointer(ctx, R_SCRATCH_1, 0));

	g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.option.option), ARCH_PREFERS_SX(op_size) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, op_size));
	gen_insn(ARCH_PREFERS_SX(op_size) ? INSN_MOVSX : INSN_MOV, op_size, 0, 0);
	gen_one(R_SCRATCH_1);
	gen_address_offset();

skip_ptr_label:
	gen_label(store_label);
	g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_SCRATCH_1));
	ctx->flag_cache[slot_r] = -1;

	return true;
}

static bool attr_w gen_array_create(struct codegen_context *ctx, frame_t slot_r)
{
	size_t i;
	const struct type *type;
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	ajla_assert_lo(ctx->args_l != 0, (file_line, "gen_array_create: zero entries"));

	if (unlikely(ctx->args_l >= sign_bit(uint_default_t))) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	type = get_type_of_local(ctx, ctx->args[0].slot);
	for (i = 1; i < ctx->args_l; i++) {
		const struct type *t = get_type_of_local(ctx, ctx->args[i].slot);
		if (unlikely(t != type))
			internal(file_line, "gen_array_create: types do not match: %u != %u", type->tag, t->tag);
	}

	if (TYPE_IS_FLAT(type)) {
		int64_t offset;
		for (i = 0; i < ctx->args_l; i++) {
			g(gen_test_1_cached(ctx, ctx->args[i].slot, escape_label));
			ctx->flag_cache[ctx->args[i].slot] = -1;
		}

		gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
		gen_one(R_ARG0);
		gen_one(R_FRAME);
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, ctx->args[0].slot));
		g(gen_upcall_argument(ctx, 1));

		g(gen_load_constant(ctx, R_ARG2, ctx->args_l));
		g(gen_upcall_argument(ctx, 2));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_slot_mayfail), 3));
		g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

		gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
		gen_one(R_SAVED_1);
		gen_one(R_RET0);

		offset = data_array_offset;
		for (i = 0; i < ctx->args_l; i++) {
			g(gen_memcpy(ctx, R_SAVED_1, offset, R_FRAME, (size_t)ctx->args[i].slot * slot_size, type->size, type->align));
			offset += type->size;
		}
	} else {
		int64_t offset;
		g(gen_load_constant(ctx, R_ARG0, ctx->args_l));
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, ctx->args_l));
		g(gen_upcall_argument(ctx, 1));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_pointers_mayfail), 2));
		g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

		gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
		gen_one(R_SAVED_1);
		gen_one(R_RET0);

		g(gen_address(ctx, R_RET0, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SAVED_2);
		gen_address_offset();

		offset = 0;
		for (i = 0; i < ctx->args_l; i++) {
			g(gen_frame_get_pointer(ctx, ctx->args[i].slot, (ctx->args[i].flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_SCRATCH_1));
			g(gen_address(ctx, R_SAVED_2, offset, IMM_PURPOSE_STR_OFFSET, OP_SIZE_SLOT));
			gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_address_offset();
			gen_one(R_SCRATCH_1);
			offset += sizeof(pointer_t);
		}
	}
	g(gen_compress_pointer(ctx, R_SAVED_1));
	g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1));
	return true;
}

static bool attr_w gen_array_create_empty_flat(struct codegen_context *ctx, frame_t slot_r, frame_t local_type)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
	gen_one(R_ARG0);
	gen_one(R_FRAME);
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, local_type));
	g(gen_upcall_argument(ctx, 1));

	g(gen_load_constant(ctx, R_ARG2, 0));
	g(gen_upcall_argument(ctx, 2));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_types_ptr_mayfail), 3));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_compress_pointer(ctx, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	return true;
}

static bool attr_w gen_array_create_empty(struct codegen_context *ctx, frame_t slot_r)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_load_constant(ctx, R_ARG0, 0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, 0));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_pointers_mayfail), 2));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	g(gen_compress_pointer(ctx, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	return true;
}

static bool attr_w gen_array_fill(struct codegen_context *ctx, frame_t slot_1, frame_t flags, frame_t slot_2, frame_t slot_r)
{
	const struct type *content_type, *array_type;
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_test_1_cached(ctx, slot_2, escape_label));

	content_type = get_type_of_local(ctx, slot_1);
	array_type = get_type_of_local(ctx, slot_r);

	if (TYPE_IS_FLAT(array_type)) {
		int64_t src_offset, dest_offset;
		size_t i;
		const struct flat_array_definition *def = type_def(array_type,flat_array);

		ajla_assert_lo(TYPE_IS_FLAT(content_type), (file_line, "gen_array_fill: array is flat but content is not"));

		g(gen_test_1_cached(ctx, slot_1, escape_label));

		src_offset = (size_t)slot_1 * slot_size;
		dest_offset = (size_t)slot_r * slot_size;
		for (i = 0; i < def->n_elements; i++) {
			g(gen_memcpy(ctx, R_FRAME, dest_offset, R_FRAME, src_offset, def->base->size, def->base->align));
			dest_offset += def->base->size;
		}
		ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;

		return true;
	}

	if (unlikely((flags & OPCODE_ARRAY_FILL_FLAG_SPARSE) != 0)) {
		uint32_t get_ptr_label, got_ptr_label;

		get_ptr_label = alloc_label(ctx);
		if (unlikely(!get_ptr_label))
			return false;

		got_ptr_label = alloc_label(ctx);
		if (unlikely(!got_ptr_label))
			return false;

		if (TYPE_IS_FLAT(content_type)) {
			g(gen_test_1_cached(ctx, slot_1, get_ptr_label));

			gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
			gen_one(R_ARG0);
			gen_one(R_FRAME);
			g(gen_upcall_argument(ctx, 0));

			g(gen_load_constant(ctx, R_ARG1, slot_1));
			g(gen_upcall_argument(ctx, 1));

			g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, R_ARG2, R_FRAME, (size_t)slot_1 * slot_size));
			g(gen_upcall_argument(ctx, 2));

			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_flat_to_data), 3));

			gen_insn(ARCH_PREFERS_SX(i_size(OP_SIZE_SLOT)) ? INSN_MOVSX : INSN_MOV, i_size(OP_SIZE_SLOT), 0, 0);
			gen_one(R_ARG1);
			gen_one(R_RET0);
			g(gen_upcall_argument(ctx, 1));

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(got_ptr_label);
		}

		gen_label(get_ptr_label);

		g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_ARG1));
		g(gen_upcall_argument(ctx, 1));

		gen_label(got_ptr_label);

		g(gen_frame_load(ctx, OP_SIZE_INT, true, slot_2, 0, R_ARG0));
		g(gen_jmp_if_negative(ctx, R_ARG0, escape_label));
		g(gen_upcall_argument(ctx, 0));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_sparse), 2));
	} else if (TYPE_IS_FLAT(content_type)) {
		g(gen_test_1_cached(ctx, slot_1, escape_label));
		ctx->flag_cache[slot_1] = -1;

		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_ARG0);
		gen_one(R_FRAME);
		g(gen_upcall_argument(ctx, 0));

		g(gen_frame_load(ctx, OP_SIZE_INT, true, slot_2, 0, R_ARG1));
		g(gen_jmp_if_negative(ctx, R_ARG1, escape_label));
		g(gen_upcall_argument(ctx, 1));

		g(gen_load_constant(ctx, R_ARG2, slot_1));
		g(gen_upcall_argument(ctx, 2));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_flat), 3));
	} else {
		g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_ARG3));
		g(gen_upcall_argument(ctx, 3));

		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_ARG0);
		gen_one(R_FRAME);
		g(gen_upcall_argument(ctx, 0));

		g(gen_load_constant(ctx, R_ARG1, ctx->instr_start - da(ctx->fn,function)->code));
		g(gen_upcall_argument(ctx, 1));

		g(gen_load_constant(ctx, R_ARG2, slot_2));
		g(gen_upcall_argument(ctx, 2));

		g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_create_pointers), 4));
	}
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	return true;
}

static bool attr_w gen_array_string(struct codegen_context *ctx, type_tag_t tag, uint8_t *string, frame_t len, frame_t slot_r)
{
	uint32_t escape_label;
	int64_t offset;
	const struct type *type;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	g(gen_load_constant(ctx, R_ARG0, tag));
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, len));
	g(gen_upcall_argument(ctx, 1));

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_data_alloc_array_flat_tag_mayfail), 2));
	g(gen_jmp_on_zero(ctx, OP_SIZE_ADDRESS, R_RET0, COND_E, escape_label));

	gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
	gen_one(R_SAVED_1);
	gen_one(R_RET0);

	g(gen_compress_pointer(ctx, R_RET0));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	g(load_function_offset(ctx, R_SCRATCH_3, offsetof(struct data, u_.function.code)));

	offset = string - cast_ptr(uint8_t *, da(ctx->fn,function)->code);
	type = type_get_from_tag(tag);
	g(gen_memcpy(ctx, R_SAVED_1, data_array_offset, R_SCRATCH_3, offset, (size_t)len * type->size, minimum(type->align, align_of(code_t))));

	return true;
}

static bool attr_w gen_scaled_array_address(struct codegen_context *ctx, size_t element_size, unsigned reg_dst, unsigned reg_src, unsigned reg_index, int64_t offset_src)
{
	if (is_power_of_2(element_size)) {
		unsigned shift = log_2(element_size);
#if defined(ARCH_X86)
		if (shift <= 3 && imm_is_32bit(offset_src)) {
			gen_insn(INSN_LEA3, i_size(OP_SIZE_ADDRESS), shift, 0);
			gen_one(reg_dst);
			gen_one(reg_src);
			gen_one(reg_index);
			gen_one(ARG_IMM);
			gen_eight(offset_src);
			return true;
		}
#endif
		if (ARCH_HAS_SHIFTED_ADD(shift)) {
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
			gen_one(reg_dst);
			gen_one(reg_src);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | shift);
			gen_one(reg_index);

			goto add_offset;
		}

		if (shift) {
			gen_insn(INSN_ROT + ARCH_PARTIAL_ALU(OP_SIZE_ADDRESS), OP_SIZE_ADDRESS, ROT_SHL, ROT_WRITES_FLAGS(ROT_SHL));
			gen_one(reg_index);
			gen_one(reg_index);
			gen_one(ARG_IMM);
			gen_eight(shift);
		}
	} else {
		if (ARCH_HAS_MUL) {
			g(gen_imm(ctx, element_size, IMM_PURPOSE_MUL, i_size(OP_SIZE_ADDRESS)));
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_MUL, ALU_WRITES_FLAGS(ALU_MUL, is_imm()));
			gen_one(reg_index);
			gen_one(reg_index);
			gen_imm_offset();
		} else {
			size_t e_size = element_size;
			unsigned sh = 0;
			bool first_match = true;

			gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
			gen_one(R_CONST_IMM);
			gen_one(reg_index);

			if (!e_size)
				g(gen_load_constant(ctx, reg_index, 0));

			while (e_size) {
				if (e_size & 1) {
					if (first_match) {
						if (sh)
							g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, reg_index, reg_index, sh, false));
						first_match = false;
					} else if (ARCH_HAS_SHIFTED_ADD(sh)) {
						gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
						gen_one(reg_index);
						gen_one(reg_index);
						gen_one(ARG_SHIFTED_REGISTER);
						gen_one(ARG_SHIFT_LSL | sh);
						gen_one(R_CONST_IMM);
					} else {
						if (sh) {
							g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, R_CONST_IMM, R_CONST_IMM, sh, false));
							sh = 0;
						}
						g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, reg_index, reg_index, R_CONST_IMM));
					}
				}
				sh += 1;
				e_size >>= 1;
			}
		}
	}
#if defined(ARCH_S390)
	if (offset_src && s390_inline_address(offset_src)) {
		gen_insn(INSN_LEA3, i_size(OP_SIZE_ADDRESS), 0, 0);
		gen_one(reg_dst);
		gen_one(reg_index);
		gen_one(reg_src);
		gen_one(ARG_IMM);
		gen_eight(offset_src);
		return true;
	}
#endif
	g(gen_3address_alu(ctx, i_size(OP_SIZE_ADDRESS), ALU_ADD, reg_dst, reg_index, reg_src));
	goto add_offset;

add_offset:
	if (offset_src) {
		g(gen_imm(ctx, offset_src, IMM_PURPOSE_ADD, i_size(OP_SIZE_ADDRESS)));
		gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, is_imm()));
		gen_one(reg_dst);
		gen_one(reg_dst);
		gen_imm_offset();
	}
	return true;
}

static bool attr_w gen_scaled_array_load(struct codegen_context *ctx, size_t element_size, size_t element_align, unsigned reg_src, int64_t offset_src, frame_t slot_r)
{
#if defined(ARCH_X86)
	if (is_power_of_2(element_size)) {
		unsigned shift = log_2(element_size);
		if (shift <= 3 && shift <= OP_SIZE_NATIVE && imm_is_32bit(offset_src)) {
			gen_insn(INSN_MOV, shift, 0, 0);
			gen_one(R_SCRATCH_2);
			gen_one(ARG_ADDRESS_2 + shift);
			gen_one(reg_src);
			gen_one(R_SCRATCH_2);
			gen_eight(offset_src);

			g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size, IMM_PURPOSE_STR_OFFSET, shift));
			gen_insn(INSN_MOV, shift, 0, 0);
			gen_address_offset();
			gen_one(R_SCRATCH_2);

			return true;
		}
	}
#endif
#if defined(ARCH_S390)
	if (element_size == 1 && s390_inline_address(offset_src) && cpu_test_feature(CPU_FEATURE_extended_imm)) {
		gen_insn(INSN_MOVSX, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_2);
		gen_one(ARG_ADDRESS_2);
		gen_one(reg_src);
		gen_one(R_SCRATCH_2);
		gen_eight(offset_src);

		g(gen_address(ctx, R_FRAME, (size_t)slot_r * slot_size, IMM_PURPOSE_STR_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_address_offset();
		gen_one(R_SCRATCH_2);

		return true;
	}
#endif
	g(gen_scaled_array_address(ctx, element_size, R_SCRATCH_2, reg_src, R_SCRATCH_2, 0));

	g(gen_memcpy(ctx, R_FRAME, (size_t)slot_r * slot_size, R_SCRATCH_2, offset_src, element_size, element_align));

	return true;
}

static bool attr_w gen_scaled_array_store(struct codegen_context *ctx, size_t element_size, size_t element_align, unsigned reg_src, int64_t offset_src, frame_t slot_1)
{
#if defined(ARCH_X86)
	if (is_power_of_2(element_size)) {
		unsigned shift = log_2(element_size);
		if (shift <= 3 && shift <= OP_SIZE_NATIVE && imm_is_32bit(offset_src)) {
			g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size, IMM_PURPOSE_LDR_OFFSET, shift));
			gen_insn(INSN_MOV, shift, 0, 0);
			gen_one(R_SCRATCH_3);
			gen_address_offset();

			gen_insn(INSN_MOV, shift, 0, 0);
			gen_one(ARG_ADDRESS_2 + shift);
			gen_one(reg_src);
			gen_one(R_SCRATCH_2);
			gen_eight(offset_src);
			gen_one(R_SCRATCH_3);

			return true;
		}
	}
#endif
#if defined(ARCH_S390)
	if (element_size == 1 && s390_inline_address(offset_src) && cpu_test_feature(CPU_FEATURE_extended_imm)) {
		g(gen_address(ctx, R_FRAME, (size_t)slot_1 * slot_size, IMM_PURPOSE_LDR_SX_OFFSET, OP_SIZE_1));
		gen_insn(INSN_MOVSX, OP_SIZE_1, 0, 0);
		gen_one(R_SCRATCH_3);
		gen_address_offset();

		gen_insn(INSN_MOV, OP_SIZE_1, 0, 0);
		gen_one(ARG_ADDRESS_2);
		gen_one(reg_src);
		gen_one(R_SCRATCH_2);
		gen_eight(offset_src);
		gen_one(R_SCRATCH_3);

		return true;
	}
#endif
	g(gen_scaled_array_address(ctx, element_size, R_SCRATCH_2, reg_src, R_SCRATCH_2, 0));

	g(gen_memcpy(ctx, R_SCRATCH_2, offset_src, R_FRAME, (size_t)slot_1 * slot_size, element_size, element_align));

	return true;
}

static bool attr_w gen_check_array_len(struct codegen_context *ctx, unsigned reg_array, bool allocated, unsigned reg_len, unsigned cond, uint32_t escape_label)
{
	size_t offset = !allocated ? offsetof(struct data, u_.array_flat.n_used_entries) : offsetof(struct data, u_.array_flat.n_allocated_entries);
#if defined(ARCH_X86)
	g(gen_address(ctx, reg_array, offset, IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(INSN_CMP, OP_SIZE_INT, 0, 1);
	gen_one(reg_len);
	gen_address_offset();

	gen_insn(INSN_JMP_COND, OP_SIZE_INT, cond, 0);
	gen_four(escape_label);
#else
	g(gen_address(ctx, reg_array, offset, ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_one(R_SCRATCH_3);
	gen_address_offset();

	g(gen_cmp_test_jmp(ctx, INSN_CMP, i_size(OP_SIZE_INT), reg_len, R_SCRATCH_3, cond, escape_label));
#endif
	return true;
}

static bool attr_w gen_array_load(struct codegen_context *ctx, frame_t slot_1, frame_t slot_idx, frame_t slot_r, frame_t flags)
{
	const struct type *t = get_type_of_local(ctx, slot_1);
	const struct type *tr = get_type_of_local(ctx, slot_r);
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(t->tag == TYPE_TAG_flat_array)) {
		const struct flat_array_definition *def = type_def(t,flat_array);

		g(gen_test_2_cached(ctx, slot_1, slot_idx, escape_label));
		g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_idx, 0, R_SCRATCH_2));

		g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_INT, R_SCRATCH_2, def->n_elements, COND_AE, escape_label));

		g(gen_scaled_array_load(ctx, def->base->size, def->base->align, R_FRAME, (size_t)slot_1 * slot_size, slot_r));
		return true;
	}

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
	g(gen_barrier(ctx));
	g(gen_decompress_pointer(ctx, R_SCRATCH_1, 0));

	g(gen_test_1_cached(ctx, slot_idx, escape_label));
	ctx->flag_cache[slot_idx] = -1;
	g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_idx, 0, R_SCRATCH_2));

	g(gen_check_array_len(ctx, R_SCRATCH_1, false, R_SCRATCH_2, COND_AE, escape_label));

	if (TYPE_IS_FLAT(tr)) {
		uint32_t label;
		g(gen_compare_ptr_tag(ctx, R_SCRATCH_1, DATA_TAG_array_slice, COND_A, escape_label, R_SCRATCH_4));
#if defined(ARCH_X86) || defined(ARCH_S390)
#if defined(ARCH_X86)
		if (unlikely(!cpu_test_feature(CPU_FEATURE_cmov)))
#else
		if (unlikely(!cpu_test_feature(CPU_FEATURE_misc_45)))
#endif
		{
			g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
			gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
			gen_one(R_SCRATCH_3);
			gen_address_offset();
			goto no_cmov;
		}
		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_CMOV, OP_SIZE_ADDRESS, COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_address_offset();
#elif defined(ARCH_LOONGARCH64) || defined(ARCH_MIPS) || defined(ARCH_RISCV64)
		g(gen_3address_alu_imm(ctx, OP_SIZE_NATIVE, ALU_XOR, R_SCRATCH_4, R_SCRATCH_4, DATA_TAG_array_slice));

		label = alloc_label(ctx);
		if (unlikely(!label))
			return false;

		gen_insn(INSN_JMP_REG, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_SCRATCH_4);
		gen_four(label);

		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

		gen_label(label);
#else
		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_slice.flat_data_minus_data_array_offset), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_3);
		gen_address_offset();
#if ARCH_HAS_FLAGS
#if defined(ARCH_POWER)
		if (!cpu_test_feature(CPU_FEATURE_v203))
			goto no_cmov;
#endif
#if defined(ARCH_SPARC)
		if (!SPARC_9)
			goto no_cmov;
#endif
		gen_insn(INSN_CMOV, i_size(OP_SIZE_ADDRESS), COND_E, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_3);
#else
		g(gen_imm(ctx, DATA_TAG_array_slice, IMM_PURPOSE_CMP, OP_SIZE_NATIVE));
		gen_insn(INSN_CMP_DEST_REG, OP_SIZE_NATIVE, COND_E, 0);
		gen_one(R_CMP_RESULT);
		gen_one(R_SCRATCH_4);
		gen_imm_offset();

		gen_insn(INSN_MOVR, OP_SIZE_NATIVE, COND_NE, 0);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_1);
		gen_one(R_CMP_RESULT);
		gen_one(R_SCRATCH_3);
#endif
#endif
		if (0) {
			goto no_cmov;
no_cmov:
			label = alloc_label(ctx);
			if (unlikely(!label))
				return false;
			gen_insn(INSN_JMP_COND, OP_SIZE_4, COND_NE, 0);
			gen_four(label);

			gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
			gen_one(R_SCRATCH_1);
			gen_one(R_SCRATCH_3);

			gen_label(label);
		}
		g(gen_scaled_array_load(ctx, tr->size, tr->align, R_SCRATCH_1, data_array_offset, slot_r));
		ctx->flag_cache[slot_r] = -1;
		return true;
	} else {
		g(gen_compare_ptr_tag(ctx, R_SCRATCH_1, DATA_TAG_array_pointers, COND_NE, escape_label, R_SCRATCH_3));

		g(gen_address(ctx, R_SCRATCH_1, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
		gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset();

#if defined(ARCH_X86) || defined(ARCH_ARM)
		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_ARG0);
		gen_one(ARG_ADDRESS_2 + OP_SIZE_SLOT);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
		gen_eight(0);

		goto scaled_load_done;
#endif
#if defined(ARCH_LOONGARCH64) || defined(ARCH_PARISC) || defined(ARCH_POWER) || defined(ARCH_S390) || defined(ARCH_SPARC)
		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, R_SCRATCH_2, R_SCRATCH_2, OP_SIZE_SLOT, false));

		gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_ARG0);
		gen_one(ARG_ADDRESS_2);
		gen_one(R_SCRATCH_1);
		gen_one(R_SCRATCH_2);
		gen_eight(0);

		goto scaled_load_done;
#endif
		if (ARCH_HAS_SHIFTED_ADD(OP_SIZE_SLOT)) {
			gen_insn(INSN_ALU, i_size(OP_SIZE_ADDRESS), ALU_ADD, ALU_WRITES_FLAGS(ALU_ADD, false));
			gen_one(R_SCRATCH_2);
			gen_one(ARG_SHIFTED_REGISTER);
			gen_one(ARG_SHIFT_LSL | OP_SIZE_SLOT);
			gen_one(R_SCRATCH_2);
			gen_one(R_SCRATCH_1);

			gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
			gen_one(R_ARG0);
			gen_one(ARG_ADDRESS_1);
			gen_one(R_SCRATCH_2);
			gen_eight(0);

			goto scaled_load_done;
		}

		g(gen_3address_rot_imm(ctx, OP_SIZE_ADDRESS, ROT_SHL, R_SCRATCH_2, R_SCRATCH_2, OP_SIZE_SLOT, false));

		g(gen_3address_alu(ctx, OP_SIZE_ADDRESS, ALU_ADD, R_SCRATCH_2, R_SCRATCH_2, R_SCRATCH_1));

		gen_insn(ARCH_PREFERS_SX(OP_SIZE_SLOT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_SLOT, 0, 0);
		gen_one(R_ARG0);
		gen_one(ARG_ADDRESS_1);
		gen_one(R_SCRATCH_2);
		gen_eight(0);
scaled_load_done:
		g(gen_ptr_is_thunk(ctx, R_ARG0, true, escape_label));

		if (flags & OPCODE_STRUCT_MAY_BORROW) {
			g(gen_frame_store(ctx, OP_SIZE_SLOT, slot_r, 0, R_ARG0));
			ctx->flag_cache[slot_r] = -1;
		} else {
			g(gen_frame_set_pointer(ctx, slot_r, R_ARG0));
			g(gen_upcall_argument(ctx, 0));
			g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
		}
		return true;
	}
}

static bool attr_w gen_array_len(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r)
{
	const struct type *t = get_type_of_local(ctx, slot_1);
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(t->tag == TYPE_TAG_flat_array)) {
		if (slot_2 == NO_FRAME_T) {
			g(gen_frame_store_imm(ctx, OP_SIZE_INT, slot_r, 0, (unsigned)type_def(t,flat_array)->n_elements));
		} else {
			g(gen_frame_load_cmp_imm_set_cond(ctx, OP_SIZE_INT, false, slot_2, 0, type_def(t,flat_array)->n_elements, COND_GE, slot_r));
		}
		ctx->flag_cache[slot_r] = -1;
	} else {
		g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
		g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
		g(gen_barrier(ctx));

		if (offsetof(struct data, u_.array_flat.n_used_entries) != offsetof(struct data, u_.array_slice.n_entries) ||
		    offsetof(struct data, u_.array_flat.n_used_entries) != offsetof(struct data, u_.array_pointers.n_used_entries)) {
			not_reached();
			return false;
		}
		if (DATA_TAG_array_flat != DATA_TAG_array_slice - 1 ||
		    DATA_TAG_array_slice != DATA_TAG_array_pointers - 1 ||
		    DATA_TAG_array_same < DATA_TAG_array_flat ||
		    DATA_TAG_array_btree < DATA_TAG_array_flat ||
		    DATA_TAG_array_incomplete < DATA_TAG_array_flat) {
			not_reached();
			return false;
		}

		gen_insn(INSN_MOV, OP_SIZE_NATIVE, 0, 0);
		gen_one(R_SCRATCH_2);
		gen_one(R_SCRATCH_1);

		g(gen_compare_da_tag(ctx, R_SCRATCH_1, DATA_TAG_array_pointers, COND_A, escape_label, R_SCRATCH_1));

		gen_pointer_compression(R_SCRATCH_2);
		g(gen_address(ctx, R_SCRATCH_2, offsetof(struct data, u_.array_flat.n_used_entries), ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
		gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
		gen_one(R_SCRATCH_1);
		gen_address_offset_compressed();

		if (slot_2 == NO_FRAME_T) {
			g(gen_frame_store(ctx, OP_SIZE_INT, slot_r, 0, R_SCRATCH_1));
		} else {
			g(gen_frame_load_cmp_set_cond(ctx, OP_SIZE_INT, false, slot_2, 0, R_SCRATCH_1, COND_GE, slot_r));
		}
		ctx->flag_cache[slot_r] = -1;
	}
	return true;
}

static bool attr_w gen_array_sub(struct codegen_context *ctx, frame_t slot_array, frame_t slot_from, frame_t slot_to, frame_t slot_r, frame_t flags)
{
	const struct type *t = get_type_of_local(ctx, slot_array);
	uint32_t escape_label, upcall_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	upcall_label = alloc_label(ctx);
	if (unlikely(!upcall_label))
		return false;

	if (unlikely(TYPE_IS_FLAT(t))) {
		g(gen_test_1_jz_cached(ctx, slot_array, escape_label));
	}

	g(gen_test_2_cached(ctx, slot_from, slot_to, escape_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_array, 0, R_ARG0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_from, 0, R_ARG1));
	g(gen_upcall_argument(ctx, 1));

	g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_to, 0, R_ARG2));
	g(gen_upcall_argument(ctx, 2));

	g(gen_load_constant(ctx, R_ARG3, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0));
	g(gen_upcall_argument(ctx, 3));

	if ((flags & OPCODE_FLAG_FREE_ARGUMENT) != 0) {
		g(gen_test_1_cached(ctx, slot_array, upcall_label));
		g(gen_load_constant(ctx, R_ARG3, 0));
		g(gen_upcall_argument(ctx, 3));
	}

	gen_label(upcall_label);
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_sub), 4));

	g(gen_jmp_on_zero(ctx, OP_SIZE_SLOT, R_RET0, COND_E, escape_label));

	if (slot_array != slot_r) {
		if (flags & OPCODE_FLAG_FREE_ARGUMENT) {
			g(gen_set_1(ctx, R_FRAME, slot_array, 0, false));
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_array));
			ctx->flag_cache[slot_array] = -1;
		}
	}

	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	return true;
}

static bool attr_w gen_array_skip(struct codegen_context *ctx, frame_t slot_array, frame_t slot_from, frame_t slot_r, frame_t flags)
{
	const struct type *t = get_type_of_local(ctx, slot_array);
	uint32_t escape_label, upcall_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	upcall_label = alloc_label(ctx);
	if (unlikely(!upcall_label))
		return false;

	if (unlikely(TYPE_IS_FLAT(t))) {
		g(gen_test_1_jz_cached(ctx, slot_array, escape_label));
	}

	g(gen_test_1_cached(ctx, slot_from, escape_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_array, 0, R_ARG0));
	g(gen_upcall_argument(ctx, 0));

	g(gen_frame_load(ctx, OP_SIZE_INT, false, slot_from, 0, R_ARG1));
	g(gen_upcall_argument(ctx, 1));

	g(gen_load_constant(ctx, R_ARG2, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0));
	g(gen_upcall_argument(ctx, 2));

	if ((flags & OPCODE_FLAG_FREE_ARGUMENT) != 0) {
		g(gen_test_1_cached(ctx, slot_array, upcall_label));
		g(gen_load_constant(ctx, R_ARG2, 0));
		g(gen_upcall_argument(ctx, 2));
	}

	gen_label(upcall_label);
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_skip), 3));

	g(gen_jmp_on_zero(ctx, OP_SIZE_SLOT, R_RET0, COND_E, escape_label));

	if (slot_array != slot_r) {
		if (flags & OPCODE_FLAG_FREE_ARGUMENT) {
			g(gen_set_1(ctx, R_FRAME, slot_array, 0, false));
			g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_array));
			ctx->flag_cache[slot_array] = -1;
		}
	}

	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));

	return true;
}

static bool attr_w gen_array_append(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r, frame_t flags)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(TYPE_IS_FLAT(get_type_of_local(ctx, slot_1))))
		g(gen_test_1_jz_cached(ctx, slot_1, escape_label));
	if (unlikely(TYPE_IS_FLAT(get_type_of_local(ctx, slot_2))))
		g(gen_test_1_jz_cached(ctx, slot_2, escape_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SCRATCH_1));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_1, true, escape_label));
	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_2, 0, R_SCRATCH_2));
	g(gen_ptr_is_thunk(ctx, R_SCRATCH_2, true, escape_label));
	g(gen_barrier(ctx));

	g(gen_compare_da_tag(ctx, R_SCRATCH_1, DATA_TAG_array_incomplete, COND_E, escape_label, R_SCRATCH_1));
	g(gen_compare_da_tag(ctx, R_SCRATCH_2, DATA_TAG_array_incomplete, COND_E, escape_label, R_SCRATCH_2));

	g(gen_frame_get_pointer(ctx, slot_2, (flags & OPCODE_FLAG_FREE_ARGUMENT_2) != 0, R_SAVED_1));
	g(gen_frame_get_pointer(ctx, slot_1, (flags & OPCODE_FLAG_FREE_ARGUMENT) != 0, R_ARG0));
	g(gen_upcall_argument(ctx, 0));
	gen_insn(ARCH_PREFERS_SX(i_size(OP_SIZE_SLOT)) ? INSN_MOVSX : INSN_MOV, i_size(OP_SIZE_SLOT), 0, 0);
	gen_one(R_ARG1);
	gen_one(R_SAVED_1);
	g(gen_upcall_argument(ctx, 1));
	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_array_join), 2));
	g(gen_frame_set_pointer(ctx, slot_r, R_RET0));
	return true;
}

static bool attr_w gen_array_append_one_flat(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r, frame_t flags)
{
	const struct type *type;
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(!(flags & OPCODE_FLAG_FREE_ARGUMENT))) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	type = get_type_of_local(ctx, slot_2);

	g(gen_test_1_jz_cached(ctx, slot_1, escape_label));
	g(gen_test_1_cached(ctx, slot_2, escape_label));
	ctx->flag_cache[slot_2] = -1;

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SAVED_1));
	g(gen_ptr_is_thunk(ctx, R_SAVED_1, true, escape_label));
	g(gen_barrier(ctx));

	g(gen_decompress_pointer(ctx, R_SAVED_1, 0));

	g(gen_compare_tag_and_refcount(ctx, R_SAVED_1, DATA_TAG_array_flat, escape_label, R_SCRATCH_1));

	g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.array_flat.n_used_entries), ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_one(R_SCRATCH_2);
	gen_address_offset();

	g(gen_check_array_len(ctx, R_SAVED_1, true, R_SCRATCH_2, COND_E, escape_label));

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_INT), ALU_ADD, R_SCRATCH_1, R_SCRATCH_2, 1));

	g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.array_flat.n_used_entries), IMM_PURPOSE_STR_OFFSET, OP_SIZE_INT));
	gen_insn(INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_1);

	g(gen_scaled_array_store(ctx, type->size, type->align, R_SAVED_1, data_array_offset, slot_2));

	if (slot_1 != slot_r) {
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
		g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
		ctx->flag_cache[slot_1] = -1;
		g(gen_compress_pointer(ctx, R_SAVED_1));
		g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1));
	}

	return true;
}

static bool attr_w gen_array_append_one(struct codegen_context *ctx, frame_t slot_1, frame_t slot_2, frame_t slot_r, frame_t flags)
{
	uint32_t escape_label;

	escape_label = alloc_escape_label(ctx);
	if (unlikely(!escape_label))
		return false;

	if (unlikely(!(flags & OPCODE_FLAG_FREE_ARGUMENT))) {
		gen_insn(INSN_JMP, 0, 0, 0);
		gen_four(escape_label);
		return true;
	}

	g(gen_test_1_jz_cached(ctx, slot_1, escape_label));

	g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_SAVED_1));
	g(gen_ptr_is_thunk(ctx, R_SAVED_1, true, escape_label));
	g(gen_barrier(ctx));

	g(gen_decompress_pointer(ctx, R_SAVED_1, 0));

	g(gen_compare_tag_and_refcount(ctx, R_SAVED_1, DATA_TAG_array_pointers, escape_label, R_SCRATCH_1));

	g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.array_pointers.n_used_entries), ARCH_PREFERS_SX(OP_SIZE_INT) ? IMM_PURPOSE_LDR_SX_OFFSET : IMM_PURPOSE_LDR_OFFSET, OP_SIZE_INT));
	gen_insn(ARCH_PREFERS_SX(OP_SIZE_INT) ? INSN_MOVSX : INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_one(R_SAVED_2);
	gen_address_offset();

	g(gen_check_array_len(ctx, R_SAVED_1, true, R_SAVED_2, COND_E, escape_label));

	g(gen_frame_get_pointer(ctx, slot_2, (flags & OPCODE_FLAG_FREE_ARGUMENT_2) != 0, R_SCRATCH_2));

	g(gen_3address_alu_imm(ctx, i_size(OP_SIZE_INT), ALU_ADD, R_SCRATCH_1, R_SAVED_2, 1));

	g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.array_pointers.n_used_entries), IMM_PURPOSE_STR_OFFSET, OP_SIZE_INT));
	gen_insn(INSN_MOV, OP_SIZE_INT, 0, 0);
	gen_address_offset();
	gen_one(R_SCRATCH_1);

	g(gen_address(ctx, R_SAVED_1, offsetof(struct data, u_.array_pointers.pointer), IMM_PURPOSE_LDR_OFFSET, OP_SIZE_ADDRESS));
	gen_insn(INSN_MOV, OP_SIZE_ADDRESS, 0, 0);
	gen_one(R_SCRATCH_3);
	gen_address_offset();

	g(gen_scaled_array_address(ctx, slot_size, R_SAVED_2, R_SCRATCH_3, R_SAVED_2, 0));

	gen_insn(INSN_MOV, OP_SIZE_SLOT, 0, 0);
	gen_one(ARG_ADDRESS_1);
	gen_one(R_SAVED_2);
	gen_eight(0);
	gen_one(R_SCRATCH_2);

	if (slot_1 != slot_r) {
		g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
		g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
		ctx->flag_cache[slot_1] = -1;
		g(gen_compress_pointer(ctx, R_SAVED_1));
		g(gen_frame_set_pointer(ctx, slot_r, R_SAVED_1));
	}

	return true;
}

static bool attr_w gen_io(struct codegen_context *ctx, frame_t code, frame_t slot_1, frame_t slot_2, frame_t slot_3)
{
	uint32_t reload_label;

	reload_label = alloc_reload_label(ctx);
	if (unlikely(!reload_label))
		return false;

	/*gen_insn(INSN_JMP, 0, 0, 0); gen_four(alloc_escape_label(ctx));*/

	gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
	gen_one(R_ARG0);
	gen_one(R_FRAME);
	g(gen_upcall_argument(ctx, 0));

	g(gen_load_constant(ctx, R_ARG1, ctx->instr_start - da(ctx->fn,function)->code));
	g(gen_upcall_argument(ctx, 1));

	g(gen_load_constant(ctx, R_ARG2, ((uint32_t)code << 24) | ((uint32_t)slot_1 << 16) | ((uint32_t)slot_2 << 8) | slot_3));
	g(gen_upcall_argument(ctx, 2));
	/*debug("arg2: %08x", ((uint32_t)code << 24) | ((uint32_t)slot_1 << 16) | ((uint32_t)slot_2 << 8) | slot_3);*/

	g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_ipret_io), 3));

	g(gen_cmp_test_imm_jmp(ctx, INSN_CMP, OP_SIZE_ADDRESS, R_RET0, ptr_to_num(POINTER_FOLLOW_THUNK_GO), COND_NE, reload_label));

	g(clear_flag_cache(ctx));

	return true;
}


static inline code_t get_code(struct codegen_context *ctx)
{
	ajla_assert(ctx->current_position < da(ctx->fn,function)->code + da(ctx->fn,function)->code_size, (file_line, "get_code: ran out of code"));
	return *ctx->current_position++;
}

static inline uint32_t get_uint32(struct codegen_context *ctx)
{
	uint32_t a1 = get_code(ctx);
	uint32_t a2 = get_code(ctx);
#if !CODE_ENDIAN
	return a1 + (a2 << 16);
#else
	return a2 + (a1 << 16);
#endif
}

static int32_t get_jump_offset(struct codegen_context *ctx)
{
	if (SIZEOF_IP_T == 2) {
		return (int32_t)(int16_t)get_code(ctx);
	} else if (SIZEOF_IP_T == 4) {
		return (int32_t)get_uint32(ctx);
	} else {
		not_reached();
		return -1;
	}
}

static inline void get_one(struct codegen_context *ctx, frame_t *v)
{
	if (!ctx->arg_mode) {
		code_t c = get_code(ctx);
		ajla_assert(!(c & ~0xff), (file_line, "get_one: high byte is not cleared: %u", (unsigned)c));
		*v = c & 0xff;
	} else if (ctx->arg_mode == 1) {
		*v = get_code(ctx);
#if ARG_MODE_N >= 2
	} else if (ctx->arg_mode == 2) {
		*v = get_uint32(ctx);
#endif
	} else {
		internal(file_line, "get_one: invalid arg mode %u", ctx->arg_mode);
	}
}

static inline void get_two(struct codegen_context *ctx, frame_t *v1, frame_t *v2)
{
	if (!ctx->arg_mode) {
		code_t c = get_code(ctx);
		*v1 = c & 0xff;
		*v2 = c >> 8;
	} else if (ctx->arg_mode == 1) {
		*v1 = get_code(ctx);
		*v2 = get_code(ctx);
#if ARG_MODE_N >= 2
	} else if (ctx->arg_mode == 2) {
		*v1 = get_uint32(ctx);
		*v2 = get_uint32(ctx);
#endif
	} else {
		internal(file_line, "get_two: invalid arg mode %u", ctx->arg_mode);
	}
}


static bool attr_w gen_function(struct codegen_context *ctx)
{
	ctx->current_position = da(ctx->fn,function)->code;

	while (ctx->current_position != da(ctx->fn,function)->code + da(ctx->fn,function)->code_size) {
		ip_t ip;
		code_t code;
		unsigned op, type;
		frame_t slot_1, slot_2, slot_3, slot_r, flags, fn_idx, opt;
		arg_t n_args, n_ret, i_arg;
		uint32_t label_id;
		uint32_t escape_label;

		ajla_assert_lo(ctx->current_position < da(ctx->fn,function)->code + da(ctx->fn,function)->code_size, (file_line, "gen_function: ran out of code in %s", da(ctx->fn,function)->function_name));

		ctx->instr_start = ctx->current_position;

		/*debug("%s: %04x, %s", da(ctx->fn,function)->function_name, *ctx->instr_start, decode_opcode(*ctx->instr_start, true));*/

		ip = ctx->instr_start - da(ctx->fn,function)->code;
		if (likely(!ctx->code_labels[ip])) {
			ctx->code_labels[ip] = alloc_label(ctx);
			if (unlikely(!ctx->code_labels[ip]))
				return false;
		}
		gen_label(ctx->code_labels[ip]);

		code = get_code(ctx);
		ctx->arg_mode = code / OPCODE_MODE_MULT;
		code %= OPCODE_MODE_MULT;
		ajla_assert_lo(ctx->arg_mode < ARG_MODE_N, (file_line, "gen_function: invalid opcode %04x", (unsigned)*ctx->instr_start));

		if (code >= OPCODE_FIXED_OP + uzero && code < OPCODE_INT_OP) {
			code -= OPCODE_FIXED_OP;
			op = (code / OPCODE_FIXED_OP_MULT) % OPCODE_FIXED_TYPE_MULT;
			type = code / OPCODE_FIXED_TYPE_MULT;
			if (op < OPCODE_FIXED_OP_UNARY) {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_2_cached(ctx, slot_1, slot_2, escape_label));
				g(gen_alu(ctx, MODE_FIXED, type, op, escape_label, slot_1, slot_2, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_2] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op < OPCODE_FIXED_OP_N) {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_alu1(ctx, MODE_FIXED, type, op, escape_label, slot_1, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_FIXED_OP_ldc) {
				unsigned i;
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, type, false, slot_r));
				for (i = 0; i < 1U << type; i += 2)
					get_code(ctx);
				ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_FIXED_OP_ldc16) {
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, type, true, slot_r));
				get_code(ctx);
				ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_FIXED_OP_move || op == OPCODE_FIXED_OP_copy) {
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_copy(ctx, type, slot_1, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else {
				internal(file_line, "gen_function: bad fixed code %04x", *ctx->instr_start);
			}
		} else if (code >= OPCODE_INT_OP && code < OPCODE_REAL_OP) {
			code -= OPCODE_INT_OP;
			op = (code / OPCODE_INT_OP_MULT) % OPCODE_INT_TYPE_MULT;
			type = code / OPCODE_INT_TYPE_MULT;
			if (op < OPCODE_INT_OP_UNARY) {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_2_cached(ctx, slot_1, slot_2, escape_label));
				g(gen_alu(ctx, MODE_INT, type, op, escape_label, slot_1, slot_2, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_2] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op < OPCODE_INT_OP_N) {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				if ((op == OPCODE_INT_OP_to_int || op == OPCODE_INT_OP_from_int) && slot_1 == slot_r)
					continue;
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_alu1(ctx, MODE_INT, type, op, escape_label, slot_1, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_INT_OP_ldc) {
				unsigned i;
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, type, false, slot_r));
				for (i = 0; i < 1U << type; i += 2)
					get_code(ctx);
				ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_INT_OP_ldc16) {
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, type, true, slot_r));
				get_code(ctx);
				ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_INT_OP_move || op == OPCODE_INT_OP_copy) {
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_copy(ctx, type, slot_1, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else {
				internal(file_line, "gen_function: bad integer code %04x", *ctx->instr_start);
			}
		} else if (code >= OPCODE_REAL_OP && code < OPCODE_BOOL_OP) {
			code -= OPCODE_REAL_OP;
			op = (code / OPCODE_REAL_OP_MULT) % OPCODE_REAL_TYPE_MULT;
			type = code / OPCODE_REAL_TYPE_MULT;
			if (op < OPCODE_REAL_OP_UNARY) {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_2_cached(ctx, slot_1, slot_2, escape_label));
				g(gen_fp_alu(ctx, type, op, escape_label, slot_1, slot_2, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_2] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op < OPCODE_REAL_OP_N) {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_fp_alu1(ctx, type, op, escape_label, slot_1, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_REAL_OP_ldc) {
				const struct type *t;
				unsigned i;
				get_one(ctx, &slot_r);
				t = type_get_real(type);
				g(gen_real_constant(ctx, t, slot_r));
				for (i = 0; i < t->size; i += 2)
					get_code(ctx);
				ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_REAL_OP_move || op == OPCODE_REAL_OP_copy) {
				const struct type *t;
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				t = type_get_real(type);
				g(gen_memcpy(ctx, R_FRAME, (size_t)slot_r * slot_size, R_FRAME, (size_t)slot_1 * slot_size, t->size, t->align));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else {
				internal(file_line, "gen_function: bad real code %04x", *ctx->instr_start);
			}
		} else if (code >= OPCODE_BOOL_OP && code < OPCODE_EXTRA) {
			code -= OPCODE_BOOL_OP;
			op = (code / OPCODE_BOOL_OP_MULT) % OPCODE_BOOL_TYPE_MULT;
			type = log_2(sizeof(ajla_flat_option_t));
			if (op < OPCODE_BOOL_OP_UNARY) {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_2_cached(ctx, slot_1, slot_2, escape_label));
				g(gen_alu(ctx, MODE_BOOL, type, op, escape_label, slot_1, slot_2, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_2] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op < OPCODE_BOOL_OP_N) {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_alu1(ctx, MODE_BOOL, type, op, escape_label, slot_1, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else if (op == OPCODE_BOOL_OP_move || op == OPCODE_BOOL_OP_copy) {
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_copy(ctx, type, slot_1, slot_r));
				ctx->flag_cache[slot_1] = ctx->flag_cache[slot_r] = -1;
				continue;
			} else {
				internal(file_line, "gen_function: bad boolean code %04x", *ctx->instr_start);
			}
		} else switch (code) {
			case OPCODE_INT_LDC_LONG: {
				uint32_t words, w;
				get_one(ctx, &slot_r);
				words = get_uint32(ctx);
				for (w = 0; w < words; w++)
					get_code(ctx);
unconditional_escape:
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(escape_label);
				continue;
			}
			case OPCODE_IS_EXCEPTION: {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				g(gen_is_exception(ctx, slot_1, slot_r));
				continue;
			}
			case OPCODE_EXCEPTION_CLASS:
			case OPCODE_EXCEPTION_TYPE:
			case OPCODE_EXCEPTION_AUX: {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				goto unconditional_escape;
			}
			case OPCODE_SYSTEM_PROPERTY: {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				g(gen_system_property(ctx, slot_1, slot_r));
				continue;
			}
			case OPCODE_FLAT_MOVE:
			case OPCODE_FLAT_COPY: {
				get_two(ctx, &slot_1, &slot_r);
				g(gen_flat_move_copy(ctx, slot_1, slot_r));
				continue;
			}
			case OPCODE_REF_MOVE:
			case OPCODE_REF_MOVE_CLEAR:
			case OPCODE_REF_COPY: {
				get_two(ctx, &slot_1, &slot_r);
				g(gen_ref_move_copy(ctx, code, slot_1, slot_r));
				continue;
			}
			case OPCODE_BOX_MOVE_CLEAR:
			case OPCODE_BOX_COPY: {
				get_two(ctx, &slot_1, &slot_r);
				g(gen_box_move_copy(ctx, code, slot_1, slot_r));
				continue;
			}
			case OPCODE_TAKE_BORROWED:
				get_one(ctx, &slot_1);
				if (!da(ctx->fn,function)->local_variables_flags[slot_1].may_be_borrowed)
					continue;
				if (unlikely(!(label_id = alloc_label(ctx))))
					return false;
				if (!flag_cache_chicken && ctx->flag_cache[slot_1] == 1)
					goto take_borrowed_done;
				if (!flag_cache_chicken && ctx->flag_cache[slot_1] == -1) {
					g(gen_set_1(ctx, R_FRAME, slot_1, 0, true));
					goto do_take_borrowed;
				}
				g(gen_test_1(ctx, R_FRAME, slot_1, 0, label_id, false, TEST_SET));
do_take_borrowed:
				g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_ARG0));
				g(gen_upcall_argument(ctx, 0));
				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1));
				ctx->flag_cache[slot_1] = 1;
take_borrowed_done:
				gen_label(label_id);
				continue;
			case OPCODE_DEREFERENCE:
			case OPCODE_DEREFERENCE_CLEAR: {
				bool need_bit_test;
				/*const struct type *type;*/
				get_one(ctx, &slot_1);
				if (!flag_cache_chicken && ctx->flag_cache[slot_1] == -1)
					goto skip_dereference;
				/*type = get_type_of_local(ctx, slot_1);*/
				/*need_bit_test = 1 || TYPE_IS_FLAT(type) || da(ctx->fn,function)->local_variables[slot_1].may_be_borrowed;*/
				need_bit_test = !ctx->flag_cache[slot_1];
				if (flag_cache_chicken)
					need_bit_test = true;
				if (need_bit_test) {
					if (unlikely(!(label_id = alloc_label(ctx))))
						return false;
					g(gen_test_1(ctx, R_FRAME, slot_1, 0, label_id, true, TEST_CLEAR));
				} else {
					g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
					label_id = 0;	/* avoid warning */
				}
				g(gen_frame_load(ctx, OP_SIZE_SLOT, false, slot_1, 0, R_ARG0));
				g(gen_upcall_argument(ctx, 0));
				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_dereference), 1));
				if (need_bit_test)
					gen_label(label_id);
skip_dereference:
				if (code == OPCODE_DEREFERENCE_CLEAR)
					g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
				ctx->flag_cache[slot_1] = -1;
				continue;
			}
			case OPCODE_EVAL: {
				get_one(ctx, &slot_1);
				g(gen_eval(ctx, slot_1));
				continue;
			}
			case OPCODE_CHECKPOINT: {
				g(clear_flag_cache(ctx));

				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;

				g(gen_timestamp_test(ctx, escape_label));

				get_one(ctx, &slot_1);
				gen_insn(INSN_ENTRY, 0, 0, 0);
				gen_four(slot_1);
				if (unlikely(!(slot_1 + 1)))
					return false;
				if (unlikely(slot_1 >= ctx->n_entries))
					ctx->n_entries = slot_1 + 1;
				continue;
			}
			case OPCODE_JMP: {
				int32_t x = get_jump_offset(ctx);
				g(gen_jump(ctx, x, 0));
				continue;
			}
			case OPCODE_JMP_BACK_16: {
				int32_t x = get_code(ctx);
				g(gen_jump(ctx, -x - (int)(2 * sizeof(code_t)), 0));
				continue;
			}
			case OPCODE_JMP_FALSE: {
				int32_t offs_false;
				get_one(ctx, &slot_1);
				offs_false = get_jump_offset(ctx);
				get_jump_offset(ctx);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				g(gen_cond_jump(ctx, slot_1, offs_false));
				ctx->flag_cache[slot_1] = -1;
				continue;
			}
			case OPCODE_LABEL: {
				g(clear_flag_cache(ctx));
				continue;
			}
#define init_args							\
do {									\
	if (ctx->args != NULL)						\
		mem_free(ctx->args);					\
	g(array_init_mayfail(struct code_arg, &ctx->args, &ctx->args_l, &ctx->err));\
} while (0)
#define load_args							\
do {									\
	init_args;							\
	for (i_arg = 0; i_arg < n_args; i_arg++) {			\
		struct code_arg a;					\
		get_two(ctx, &a.slot, &a.flags);			\
		a.type = 0;						\
		g(array_add_mayfail(struct code_arg, &ctx->args, &ctx->args_l, a, NULL, &ctx->err));\
	}								\
} while (0)
			case OPCODE_LOAD_FN:
				get_two(ctx, &n_args, &slot_r);
				get_one(ctx, &fn_idx);
				load_args;
				g(gen_load_fn_or_curry(ctx, fn_idx, NO_FRAME_T, slot_r, 0));
				continue;
			case OPCODE_CURRY:
				get_two(ctx, &n_args, &slot_r);
				get_two(ctx, &slot_1, &flags);
				load_args;
				g(gen_load_fn_or_curry(ctx, NO_FRAME_T, slot_1, slot_r, flags));
				continue;
			case OPCODE_CALL:
			case OPCODE_CALL_STRICT:
			case OPCODE_CALL_SPARK:
			case OPCODE_CALL_LAZY:
			case OPCODE_CALL_CACHE:
			case OPCODE_CALL_SAVE: {
				get_two(ctx, &n_args, &n_ret);
				get_one(ctx, &fn_idx);
jump_over_arguments_and_return:
				load_args;
				ctx->return_values = ctx->current_position;
				for (i_arg = 0; i_arg < n_ret; i_arg++) {
#if ARG_MODE_N >= 3
					get_uint32(ctx);
#else
					get_code(ctx);
#endif
					get_code(ctx);
				}
				if (code == OPCODE_CALL || code == OPCODE_CALL_STRICT) {
					g(gen_call(ctx, code, fn_idx));
					continue;
				}
				/*if (code == OPCODE_CALL_INDIRECT || code == OPCODE_CALL_INDIRECT_STRICT) {
					if (unlikely(!gen_call_indirect(ctx, code, slot_1, flags)))
						return false;
					continue;
				}*/
				goto unconditional_escape;
			}
			case OPCODE_CALL_INDIRECT:
			case OPCODE_CALL_INDIRECT_STRICT:
			case OPCODE_CALL_INDIRECT_SPARK:
			case OPCODE_CALL_INDIRECT_LAZY:
			case OPCODE_CALL_INDIRECT_CACHE:
			case OPCODE_CALL_INDIRECT_SAVE: {
				fn_idx = 0;		/* avoid warning */
				get_two(ctx, &n_args, &n_ret);
				get_two(ctx, &slot_1, &flags);
				goto jump_over_arguments_and_return;
			}
			case OPCODE_RETURN: {
				n_args = da(ctx->fn,function)->n_return_values;
				load_args;
				g(gen_return(ctx));
				continue;
			}
			case OPCODE_STRUCTURED: {
				init_args;
				get_two(ctx, &slot_1, &slot_2);
				do {
					struct code_arg a;
					get_two(ctx, &flags, &slot_r);
					get_one(ctx, &opt);
					a.slot = slot_r;
					a.flags = flags;
					a.type = opt;
					g(array_add_mayfail(struct code_arg, &ctx->args, &ctx->args_l, a, NULL, &ctx->err));
				} while (!(flags & OPCODE_STRUCTURED_FLAG_END));
				g(gen_structured(ctx, slot_1, slot_2));
				continue;
			}
			case OPCODE_RECORD_CREATE: {
				init_args;
				get_two(ctx, &slot_r, &n_args);
				for (i_arg = 0; i_arg < n_args; i_arg++) {
					struct code_arg a;
					get_two(ctx, &slot_1, &flags);
					a.slot = slot_1;
					a.flags = flags;
					a.type = 0;
					g(array_add_mayfail(struct code_arg, &ctx->args, &ctx->args_l, a, NULL, &ctx->err));
				}
				g(gen_record_create(ctx, slot_r));
				continue;
			}
			case OPCODE_RECORD_LOAD: {
				get_two(ctx, &slot_1, &opt);
				get_two(ctx, &slot_r, &flags);
				g(gen_record_load(ctx, slot_1, slot_r, opt, flags));
				continue;
			}
			case OPCODE_OPTION_CREATE_EMPTY_FLAT: {
				get_two(ctx, &slot_r, &opt);
				g(gen_option_create_empty_flat(ctx, opt, slot_r));
				continue;
			}
			case OPCODE_OPTION_CREATE_EMPTY: {
				get_two(ctx, &slot_r, &opt);
				g(gen_option_create_empty(ctx, opt, slot_r));
				continue;
			}
			case OPCODE_OPTION_CREATE: {
				get_two(ctx, &slot_r, &opt);
				get_two(ctx, &slot_1, &flags);
				g(gen_option_create(ctx, opt, slot_1, slot_r, flags));
				continue;
			}
			case OPCODE_OPTION_LOAD: {
				get_two(ctx, &slot_1, &opt);
				get_two(ctx, &slot_r, &flags);
				g(gen_option_load(ctx, slot_1, slot_r, opt, flags));
				continue;
			}
			case OPCODE_OPTION_TEST_FLAT: {
				get_two(ctx, &slot_1, &opt);
				get_one(ctx, &slot_r);
				g(gen_option_test_flat(ctx, slot_1, opt, slot_r));
				continue;
			}
			case OPCODE_OPTION_TEST: {
				get_two(ctx, &slot_1, &opt);
				get_one(ctx, &slot_r);
				g(gen_option_test(ctx, slot_1, opt, slot_r));
				continue;
			}
			case OPCODE_OPTION_ORD_FLAT: {
				get_two(ctx, &slot_1, &slot_r);
				g(gen_option_ord(ctx, slot_1, slot_r, true));
				continue;
			}
			case OPCODE_OPTION_ORD: {
				get_two(ctx, &slot_1, &slot_r);
				g(gen_option_ord(ctx, slot_1, slot_r, false));
				continue;
			}
			case OPCODE_ARRAY_CREATE: {
				init_args;
				get_two(ctx, &slot_r, &n_args);
				for (i_arg = 0; i_arg < n_args; i_arg++) {
					struct code_arg a;
					get_two(ctx, &slot_1, &flags);
					a.slot = slot_1;
					a.flags = flags;
					a.type = 0;
					g(array_add_mayfail(struct code_arg, &ctx->args, &ctx->args_l, a, NULL, &ctx->err));
				}
				g(gen_array_create(ctx, slot_r));
				continue;
			}
			case OPCODE_ARRAY_CREATE_EMPTY_FLAT: {
				get_two(ctx, &slot_r, &flags);
				g(gen_array_create_empty_flat(ctx, slot_r, flags));
				continue;
			}
			case OPCODE_ARRAY_CREATE_EMPTY: {
				get_one(ctx, &slot_r);
				g(gen_array_create_empty(ctx, slot_r));
				continue;
			}
			case OPCODE_ARRAY_FILL: {
				get_two(ctx, &slot_1, &flags);
				get_two(ctx, &slot_2, &slot_r);
				g(gen_array_fill(ctx, slot_1, flags, slot_2, slot_r));
				continue;
			}
			case OPCODE_ARRAY_STRING: {
				frame_t i;
				get_two(ctx, &slot_r, &i);
				g(gen_array_string(ctx, type_get_fixed(0, true)->tag, cast_ptr(uint8_t *, ctx->current_position), i, slot_r));
				ctx->current_position += (i + 1) >> 1;
				continue;
			}
			case OPCODE_ARRAY_UNICODE: {
				frame_t i;
				get_two(ctx, &slot_r, &i);
				g(gen_array_string(ctx, type_get_int(2)->tag, cast_ptr(uint8_t *, ctx->current_position), i, slot_r));
				ctx->current_position += i * 2;
				continue;
			}
			case OPCODE_ARRAY_LOAD: {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				g(gen_array_load(ctx, slot_1, slot_2, slot_r, flags));
				continue;
			}
			case OPCODE_ARRAY_LEN: {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				g(gen_array_len(ctx, slot_1, NO_FRAME_T, slot_r));
				continue;
			}
			case OPCODE_ARRAY_LEN_ATLEAST: {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				g(gen_array_len(ctx, slot_1, slot_2, slot_r));
				continue;
			}
			case OPCODE_ARRAY_SUB: {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_3, &slot_r);
				get_one(ctx, &flags);
				g(gen_array_sub(ctx, slot_1, slot_2, slot_3, slot_r, flags));
				continue;
			}
			case OPCODE_ARRAY_SKIP: {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				g(gen_array_skip(ctx, slot_1, slot_2, slot_r, flags));
				continue;
			}
			case OPCODE_ARRAY_APPEND: {
				get_two(ctx, &slot_r, &flags);
				get_two(ctx, &slot_1, &slot_2);
				g(gen_array_append(ctx, slot_1, slot_2, slot_r, flags));
				continue;
			}
			case OPCODE_ARRAY_APPEND_ONE_FLAT: {
				get_two(ctx, &slot_r, &flags);
				get_two(ctx, &slot_1, &slot_2);
				g(gen_array_append_one_flat(ctx, slot_1, slot_2, slot_r, flags));
				continue;
			}
			case OPCODE_ARRAY_APPEND_ONE: {
				get_two(ctx, &slot_r, &flags);
				get_two(ctx, &slot_1, &slot_2);
				g(gen_array_append_one(ctx, slot_1, slot_2, slot_r, flags));
				continue;
			}
			case OPCODE_ARRAY_FLATTEN: {
				get_two(ctx, &slot_r, &flags);
				get_one(ctx, &slot_1);
				goto unconditional_escape;
			}
			case OPCODE_IO: {
				frame_t i;
				get_two(ctx, &flags, &slot_1);
				get_two(ctx, &slot_2, &slot_3);
				for (i = 0; i < slot_1 + slot_2 + slot_3; i++)
					get_uint32(ctx);
				g(gen_io(ctx, flags, slot_1, slot_2, slot_3));
				continue;
			}
			case OPCODE_INTERNAL_FUNCTION:
			case OPCODE_EXIT_THREAD:
			case OPCODE_UNREACHABLE: {
				goto unconditional_escape;
			}
			default: {
#if 1
				/*if (getenv("DUMP") && !strcmp(da(ctx->fn,function)->function_name, getenv("DUMP")))*/
					warning("gen_function: %s: unknown opcode %04x, %s", da(ctx->fn,function)->function_name, *ctx->instr_start, decode_opcode(*ctx->instr_start, false));
#endif
				return false;
			}
		}
	}

	return true;
}

static bool attr_w gen_epilogues(struct codegen_context *ctx)
{
	ip_t ip;
	uint32_t escape_label;
	escape_label = alloc_label(ctx);
	if (unlikely(!escape_label))
		return false;
#if defined(ARCH_PARISC)
	if (ctx->call_label) {
		gen_label(ctx->call_label);
		g(gen_call_millicode(ctx));
	}
#endif
	if (ctx->reload_label) {
		gen_label(ctx->reload_label);
		gen_insn(INSN_MOV, i_size(OP_SIZE_ADDRESS), 0, 0);
		gen_one(R_FRAME);
		gen_one(R_RET0);
		g(gen_escape_arg(ctx, (ip_t)-1, escape_label));
	}
	for (ip = 0; ip < da(ctx->fn,function)->code_size; ip++) {
		if (ctx->escape_labels[ip]) {
			gen_label(ctx->escape_labels[ip]);
			g(gen_escape_arg(ctx, ip, escape_label));
		}
	}
	gen_label(escape_label);
	g(gen_escape(ctx));
	return true;
}

static bool attr_w cgen_entry(struct codegen_context *ctx)
{
	uint32_t entry_id = cget_four(ctx);
	ajla_assert_lo(entry_id < ctx->n_entries, (file_line, "cgen_entry: invalid entry %lx", (unsigned long)entry_id));
	ctx->entry_to_pos[entry_id] = ctx->mcode_size;
	return true;
}

static bool attr_w cgen_label(struct codegen_context *ctx)
{
	uint32_t label_id = cget_four(ctx);
	ctx->label_to_pos[label_id] = ctx->mcode_size;
	return true;
}

static bool attr_w attr_unused cgen_trap(struct codegen_context *ctx, uint32_t label)
{
	struct trap_record tr;
	tr.source_ip = ctx->mcode_size;
	tr.destination_ip = label;
	if (unlikely(!array_add_mayfail(struct trap_record, &ctx->trap_records, &ctx->trap_records_size, tr, NULL, &ctx->err)))
		return false;
	return true;
}

static bool attr_w add_relocation(struct codegen_context *ctx, unsigned length, int offset, bool *known)
{
	struct relocation rel;
	rel.label_id = cget_four(ctx);
	rel.length = length;
	rel.position = ctx->mcode_size;
	rel.jmp_instr = ctx->code_position - 8 - offset - ctx->code;
	if (unlikely(!array_add_mayfail(struct relocation, &ctx->reloc, &ctx->reloc_size, rel, NULL, &ctx->err)))
		return false;
	if (known)
		*known = ctx->label_to_pos[rel.label_id] != (size_t)-1;
	return true;
}


#if defined(ARCH_ALPHA)
#include "c2-alpha.inc"
#elif defined(ARCH_ARM32)
#include "c2-arm.inc"
#elif defined(ARCH_ARM64)
#include "c2-arm64.inc"
#elif defined(ARCH_IA64)
#include "c2-ia64.inc"
#elif defined(ARCH_LOONGARCH64)
#include "c2-loong.inc"
#elif defined(ARCH_MIPS)
#include "c2-mips.inc"
#elif defined(ARCH_PARISC)
#include "c2-hppa.inc"
#elif defined(ARCH_POWER)
#include "c2-power.inc"
#elif defined(ARCH_S390)
#include "c2-s390.inc"
#elif defined(ARCH_SPARC)
#include "c2-sparc.inc"
#elif defined(ARCH_RISCV64)
#include "c2-riscv.inc"
#elif defined(ARCH_X86)
#include "c2-x86.inc"
#endif


static bool attr_w gen_mcode(struct codegen_context *ctx)
{
	ctx->code_position = ctx->code;

	while (ctx->code_position != ctx->code + ctx->code_size) {
		uint32_t insn;
		ajla_assert_lo(ctx->code_position < ctx->code + ctx->code_size, (file_line, "gen_mcode: ran out of code"));
#ifdef DEBUG_INSNS
		insn = cget_four(ctx);
		debug("line: %u", insn);
#endif
		insn = cget_four(ctx);
		g(cgen_insn(ctx, insn));
	}

	return true;
}

#define RELOCS_RETRY	-1
#define RELOCS_FAIL	0
#define RELOCS_OK	1

static int8_t resolve_relocs(struct codegen_context *ctx)
{
	size_t i;
	int8_t status = RELOCS_OK;
	for (i = 0; i < ctx->reloc_size; i++) {
		struct relocation *reloc = &ctx->reloc[i];
		if (!resolve_relocation(ctx, reloc)) {
			uint8_t *jmp_instr;
			uint32_t insn;
			uint32_t new_length;
			status = RELOCS_RETRY;
			if (unlikely(reloc->length + zero >= JMP_LIMIT))
				return RELOCS_FAIL;
			new_length = reloc->length + 1;
			jmp_instr = ctx->code + reloc->jmp_instr;
			insn =	(uint32_t)jmp_instr[0] +
				((uint32_t)jmp_instr[1] << 8) +
				((uint32_t)jmp_instr[2] << 16) +
				((uint32_t)jmp_instr[3] << 24);
			insn &= ~INSN_JUMP_SIZE;
			insn |= (uint32_t)new_length << INSN_JUMP_SIZE_SHIFT;
			jmp_instr[0] = insn;
			jmp_instr[1] = insn >> 8;
			jmp_instr[2] = insn >> 16;
			jmp_instr[3] = insn >> 24;
		}
	}
	return status;
}

static void resolve_traps(struct codegen_context *ctx)
{
	size_t i;
	for (i = 0; i < ctx->trap_records_size; i++) {
		struct trap_record *tr = &ctx->trap_records[i];
		tr->destination_ip = ctx->label_to_pos[tr->destination_ip];
	}
}


static bool attr_w codegen_map(struct codegen_context *ctx)
{
	void *ptr;
	frame_t i;
	array_finish(uint8_t, &ctx->mcode, &ctx->mcode_size);
	ptr = os_code_map(ctx->mcode, ctx->mcode_size, &ctx->err);
	ctx->mcode = NULL;
	if (unlikely(!ptr)) {
		return false;
	}
	for (i = 0; i < ctx->n_entries; i++) {
		char *entry = cast_ptr(char *, ptr) + ctx->entry_to_pos[i];
		da(ctx->codegen,codegen)->unoptimized_code[i] = entry;
		da(ctx->codegen,codegen)->n_entries++;
	}
	da(ctx->codegen,codegen)->unoptimized_code_base = ptr;
	da(ctx->codegen,codegen)->unoptimized_code_size = ctx->mcode_size;

	return true;
}


void *codegen_fn(frame_s *fp, const code_t *ip, union internal_arg ia[])
{
	struct codegen_context ctx_;
	struct codegen_context *ctx = &ctx_;
	frame_t i;
	int8_t rr;
	struct data *codegen;
	uint32_t l;

	init_ctx(ctx);
	ctx->fn = ia[0].ptr;

#ifdef DEBUG_ENV
	if (getenv("CG") && strcmp(da(ctx->fn,function)->function_name, getenv("CG")))
		goto fail;
#endif

	ctx->local_directory = mem_alloc_array_mayfail(mem_calloc_mayfail, struct data **, 0, 0, da(ctx->fn,function)->local_directory_size, sizeof(struct data *), &ctx->err);
	if (unlikely(!ctx->local_directory))
		goto fail;

	if (0) for (i = 0; i < da(ctx->fn,function)->local_directory_size; i++) {
		struct data *callee;
		pointer_t *ptr;
		ptr = da(ctx->fn,function)->local_directory[i];
		pointer_follow(ptr, false, callee, PF_SPARK, NULL, 0,
			SUBMIT_EX(ex_);
			goto next_one,
			goto next_one;
		);
		ctx->local_directory[i] = callee;
next_one:;
	}
	for (i = 0; i < da(ctx->fn,function)->local_directory_size; i++) {
		struct data *callee;
		pointer_t *ptr;
		if (ctx->local_directory[i])
			continue;
		ptr = da(ctx->fn,function)->local_directory[i];
		pointer_follow(ptr, false, callee, PF_WAIT, fp, ip,
			done_ctx(ctx);
			return ex_,
			goto fail
		);
		ctx->local_directory[i] = callee;
		/*debug("processing call: %s -> %s", da(ctx->fn,function)->function_name, da(callee,function)->function_name);*/
	}

	if (da(ctx->fn,function)->module_designator) {
		struct function_descriptor *sfd = save_find_function_descriptor(da(ctx->fn,function)->module_designator, da(ctx->fn,function)->function_designator);
		if (sfd && sfd->unoptimized_code_size) {
			codegen = data_alloc_flexible(codegen, unoptimized_code, sfd->n_entries, &ctx->err);
			if (unlikely(!codegen))
				goto fail;
			da(codegen,codegen)->unoptimized_code_base = sfd->unoptimized_code_base;
			da(codegen,codegen)->unoptimized_code_size = sfd->unoptimized_code_size;
			da(codegen,codegen)->function = ctx->fn;
			da(codegen,codegen)->is_saved = true;
			da(codegen,codegen)->n_entries = sfd->n_entries;
			da(codegen,codegen)->offsets = NULL;
			for (i = 0; i < sfd->n_entries; i++) {
				da(codegen,codegen)->unoptimized_code[i] = cast_ptr(char *, da(codegen,codegen)->unoptimized_code_base) + sfd->entries[i];
				/*debug("%s: %p + %lx -> %p", da(ctx->fn,function)->function_name, da(codegen,codegen)->unoptimized_code_base, sfd->entries[i], da(codegen,codegen)->unoptimized_code[i]);*/
			}
#ifdef HAVE_CODEGEN_TRAPS
			da(codegen,codegen)->trap_records = sfd->trap_records;
			da(codegen,codegen)->trap_records_size = sfd->trap_records_size;
			data_trap_insert(codegen);
#endif
			goto have_codegen;
		}
	}

	/*debug("trying: %s", da(ctx->fn,function)->function_name);*/
	if (unlikely(!array_init_mayfail(uint8_t, &ctx->code, &ctx->code_size, &ctx->err)))
		goto fail;

	ctx->code_labels = mem_alloc_array_mayfail(mem_calloc_mayfail, uint32_t *, 0, 0, da(ctx->fn,function)->code_size, sizeof(uint32_t), &ctx->err);
	if (unlikely(!ctx->code_labels))
		goto fail;

	ctx->escape_labels = mem_alloc_array_mayfail(mem_calloc_mayfail, uint32_t *, 0, 0, da(ctx->fn,function)->code_size, sizeof(uint32_t), &ctx->err);
	if (unlikely(!ctx->escape_labels))
		goto fail;

	ctx->flag_cache = mem_alloc_array_mayfail(mem_calloc_mayfail, int8_t *, 0, 0, function_n_variables(ctx->fn), sizeof(int8_t), &ctx->err);
	if (unlikely(!ctx->flag_cache))
		goto fail;

	if (unlikely(!gen_function(ctx)))
		goto fail;

	if (unlikely(!gen_epilogues(ctx)))
		goto fail;

	if (unlikely(!(ctx->label_id + 1)))
		goto fail;
	if (unlikely(!(ctx->label_to_pos = mem_alloc_array_mayfail(mem_alloc_mayfail, size_t *, 0, 0, ctx->label_id + 1, sizeof(size_t), &ctx->err))))
		goto fail;

	if (unlikely(!(ctx->entry_to_pos = mem_alloc_array_mayfail(mem_alloc_mayfail, size_t *, 0, 0, ctx->n_entries, sizeof(size_t), &ctx->err))))
		goto fail;

again:
	for (l = 0; l < ctx->label_id + 1; l++)
		ctx->label_to_pos[l] = (size_t)-1;

	if (unlikely(!array_init_mayfail(uint8_t, &ctx->mcode, &ctx->mcode_size, &ctx->err)))
		goto fail;

	if (unlikely(!array_init_mayfail(struct relocation, &ctx->reloc, &ctx->reloc_size, &ctx->err)))
		goto fail;

	if (unlikely(!array_init_mayfail(struct trap_record, &ctx->trap_records, &ctx->trap_records_size, &ctx->err)))
		goto fail;

#ifdef ARCH_CONTEXT
	init_arch_context(ctx);
#endif

	if (unlikely(!gen_mcode(ctx)))
		goto fail;

	rr = resolve_relocs(ctx);
	if (unlikely(rr == RELOCS_FAIL)) {
		/*debug("relocation fail: %s", da(ctx->fn,function)->function_name);*/
		goto fail;
	}
	if (rr == RELOCS_RETRY) {
		mem_free(ctx->mcode);
		ctx->mcode = NULL;
		mem_free(ctx->reloc);
		ctx->reloc = NULL;
		mem_free(ctx->trap_records);
		ctx->trap_records = NULL;
		goto again;
	}

	resolve_traps(ctx);

#ifdef DEBUG_ENV
	/*debug("success: %"PRIuMAX" %s", (uintmax_t)ctx->mcode_size, da(ctx->fn,function)->function_name);*/
	if (getenv("DUMP") && !strcmp(getenv("DUMP"), da(ctx->fn,function)->function_name)) {
		char *hex;
		size_t hexl;
		size_t i;
		size_t mcode_size = codegen_size + ctx->mcode_size;
		uint8_t *mcode = mem_alloc(uint8_t *, mcode_size);
		memcpy(mcode, codegen_ptr, codegen_size);
		memcpy(mcode + codegen_size, ctx->mcode, ctx->mcode_size);
		if (!os_write_atomic(".", "dump.asm", cast_ptr(const char *, mcode), mcode_size, &ctx->err)) {
			warning("dump failed");
		}

		str_init(&hex, &hexl);
		for (i = 0; i < mcode_size; i++) {
			uint8_t a = mcode[i];
			if (a < 16)
				str_add_char(&hex, &hexl, '0');
			str_add_unsigned(&hex, &hexl, a, 16);
		}
		if (!os_write_atomic(".", "dump.hex", hex, hexl, &ctx->err)) {
			warning("dump failed");
		}
		mem_free(hex);

		str_init(&hex, &hexl);
#if defined(ARCH_RISCV64)
		str_add_string(&hex, &hexl, "	.attribute arch, \"rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zba1p0_zbb1p0_zbc1p0_zbs1p0\"\n");
#endif
		for (i = 0; i < mcode_size; i++) {
			uint8_t a = mcode[i];
			str_add_string(&hex, &hexl, "	.byte	0x");
			if (a < 16)
				str_add_char(&hex, &hexl, '0');
			str_add_unsigned(&hex, &hexl, a, 16);
			str_add_char(&hex, &hexl, '\n');
		}
		if (!os_write_atomic(".", "dump.s", hex, hexl, &ctx->err)) {
			warning("dump failed");
		}
		mem_free(hex);
		mem_free(mcode);
	}
#endif

	ctx->codegen = data_alloc_flexible(codegen, unoptimized_code, ctx->n_entries, &ctx->err);
	if (unlikely(!ctx->codegen))
		goto fail;
	da(ctx->codegen,codegen)->is_saved = false;
	da(ctx->codegen,codegen)->n_entries = 0;
	da(ctx->codegen,codegen)->offsets = NULL;

	if (unlikely(!codegen_map(ctx)))
		goto fail;

	codegen = ctx->codegen;
	ctx->codegen = NULL;

#ifdef HAVE_CODEGEN_TRAPS
	da(codegen,codegen)->trap_records = ctx->trap_records;
	da(codegen,codegen)->trap_records_size = ctx->trap_records_size;
	ctx->trap_records = NULL;
	data_trap_insert(codegen);
#endif

have_codegen:
	done_ctx(ctx);
	return function_return(fp, pointer_data(codegen));

fail:
	done_ctx(ctx);
	return function_return(fp, pointer_thunk(thunk_alloc_exception_error(error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), NULL, NULL, NULL pass_file_line)));
}

void codegen_free(struct data *codegen)
{
	if (unlikely(da(codegen,codegen)->offsets != NULL))
		mem_free(da(codegen,codegen)->offsets);
	if (likely(da(codegen,codegen)->is_saved))
		return;
#ifdef HAVE_CODEGEN_TRAPS
	mem_free(da(codegen,codegen)->trap_records);
#endif
	os_code_unmap(da(codegen,codegen)->unoptimized_code_base, da(codegen,codegen)->unoptimized_code_size);
}

#if defined(ARCH_IA64)
static uintptr_t ia64_stub[2];
#endif
#if defined(ARCH_PARISC32) && defined(ARCH_PARISC_USE_STUBS)
static uintptr_t parisc_stub[2];
#endif
#if defined(ARCH_PARISC64) && defined(ARCH_PARISC_USE_STUBS)
static uintptr_t parisc_stub[4];
#endif
#if defined(ARCH_POWER) && defined(AIX_CALL)
static uintptr_t ppc_stub[3];
#endif

void name(codegen_init)(void)
{
	struct codegen_context ctx_;
	struct codegen_context *ctx = &ctx_;
	void *ptr;

	init_ctx(ctx);
	ctx->fn = NULL;

	array_init(uint8_t, &ctx->code, &ctx->code_size);

	if (unlikely(!gen_entry(ctx)))
		goto fail;

	array_init(uint8_t, &ctx->mcode, &ctx->mcode_size);

#ifdef ARCH_CONTEXT
	init_arch_context(ctx);
#endif

	if (unlikely(!gen_mcode(ctx)))
		goto fail;

	array_finish(uint8_t, &ctx->mcode, &ctx->mcode_size);
	ptr = os_code_map(ctx->mcode, ctx->mcode_size, NULL);
	codegen_ptr = ptr;
	codegen_size = ctx->mcode_size;
	ctx->mcode = NULL;
#if defined(ARCH_IA64)
	ia64_stub[0] = ptr_to_num(ptr);
	ia64_stub[1] = 0;
	codegen_entry = cast_ptr(codegen_type, ia64_stub);
#elif defined(ARCH_PARISC32) && defined(ARCH_PARISC_USE_STUBS)
	parisc_stub[0] = ptr_to_num(ptr);
	parisc_stub[1] = 0;
	codegen_entry = cast_ptr(codegen_type, cast_ptr(char *, parisc_stub) + 2);
#elif defined(ARCH_PARISC64) && defined(ARCH_PARISC_USE_STUBS)
	parisc_stub[0] = 0;
	parisc_stub[1] = 0;
	parisc_stub[2] = ptr_to_num(ptr);
	parisc_stub[3] = 0;
	codegen_entry = cast_ptr(codegen_type, parisc_stub);
#elif defined(ARCH_POWER) && defined(AIX_CALL)
	ppc_stub[0] = ptr_to_num(ptr);
	ppc_stub[1] = 0;
	ppc_stub[2] = 0;
	codegen_entry = cast_ptr(codegen_type, ppc_stub);
#else
	codegen_entry = ptr;
#endif

	done_ctx(ctx);

	return;

fail:
	fatal("couldn't compile global entry");
}

void name(codegen_done)(void)
{
	os_code_unmap(codegen_ptr, codegen_size);
}

#else

void name(codegen_init)(void)
{
}

void name(codegen_done)(void)
{
}

#endif

#endif
