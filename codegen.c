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

shared_var const char *dump_code shared_init(NULL);

#ifdef HAVE_CODEGEN

#define flag_cache_chicken	0
#define must_be_flat_chicken	0
#define ra_chicken		0

#define INLINE_BITMAP_SLOTS		16
#define INLINE_COPY_SIZE		64

/*#define DEBUG_INSNS*/
/*#define DEBUG_GARBAGE*/

#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
#if defined(HAVE_SYSCALL) && defined(HAVE_ASM_PRCTL_H) && defined(HAVE_SYS_SYSCALL_H)
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif
#if (defined(HAVE_AMD64_SET_GSBASE) || defined(HAVE_SYSARCH)) && defined(HAVE_X86_SYSARCH_H)
#include <x86/sysarch.h>
#endif
#endif

code_return_t (*codegen_entry)(frame_s *, struct cg_upcall_vector_s *, tick_stamp_t, void *);
static void *codegen_ptr;
static size_t codegen_size;

static mutex_t dump_mutex;
static uint64_t dump_seq = 0;

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
#define ALU1_BSWAP			0x03
#define ALU1_BSWAP16			0x04
#define ALU1_BREV			0x05
#define ALU1_BSF			0x06
#define ALU1_BSR			0x07
#define ALU1_LZCNT			0x08
#define ALU1_POPCNT			0x09

#define FP_ALU_ADD			0
#define FP_ALU_SUB			1
#define FP_ALU_MUL			2
#define FP_ALU_DIV			3
#define FP_ALU1_NEG			0
#define FP_ALU1_SQRT			1
#define FP_ALU1_ROUND			2
#define FP_ALU1_FLOOR			3
#define FP_ALU1_CEIL			4
#define FP_ALU1_TRUNC			5
#define FP_ALU1_VCNT8			6
#define FP_ALU1_VPADDL			7
#define FP_ALU1_ADDV			8

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
#define COND_NEVER			0x13

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
	INSN_PUSH2,
	INSN_POP,
	INSN_POP2,
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
	INSN_SET_COND_PARTIAL,
	INSN_CMOV,
	INSN_CMOV_XCC,
	INSN_CMP_CMOV,
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
	INSN_X87_FRNDINT,
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
#define gen_line()	gen_four(__LINE__ + (insn_file << 24))
#else
#define gen_line()	do { } while (0)
#endif

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

struct cg_entry {
	size_t entry_to_pos;
	frame_t *variables;
	size_t n_variables;
	uint32_t entry_label;
	uint32_t nonflat_label;
};

struct cg_exit {
	uint32_t undo_label;
	uint8_t undo_opcode;
	uint8_t undo_op_size;
	uint8_t undo_aux;
	uint8_t undo_writes_flags;
	uint8_t undo_parameters[35];
	uint8_t undo_parameters_len;
	uint32_t escape_label;
};

#define FLAG_CACHE_IS_FLAT	0x01
#define FLAG_CACHE_IS_NOT_FLAT	0x02
#define FLAG_CACHE_IS_NOT_THUNK	0x04

struct codegen_context {
	struct data *fn;
	struct data **local_directory;

	const code_t *instr_start;
	const code_t *current_position;
	uchar_efficient_t arg_mode;

	uint32_t label_id;
	struct cg_entry *entries;
	frame_t n_entries;

	uint8_t *code;
	size_t code_size;

	uint8_t *code_position;

	uint32_t *code_labels;
	struct cg_exit **code_exits;
	uint32_t escape_nospill_label;
	uint32_t call_label;
	uint32_t reload_label;

	uint8_t *mcode;
	size_t mcode_size;

	size_t *label_to_pos;
	struct relocation *reloc;
	size_t reloc_size;

	struct trap_record *trap_records;
	size_t trap_records_size;

	struct code_arg *args;
	size_t args_l;
	const code_t *return_values;

	uint8_t *flag_cache;
	short *registers;
	frame_t *need_spill;
	size_t need_spill_l;

	uint8_t base_reg;
	bool offset_reg;
	int64_t offset_imm;

	uint8_t const_reg;
	int64_t const_imm;

	struct data *codegen;

	int upcall_offset;
	int8_t upcall_args;
	uint8_t n_pushes;
	bool upcall_hacked_abi;
	frame_t *var_aux;

	ajla_error_t err;

#ifdef ARCH_CONTEXT
	ARCH_CONTEXT a;
#endif
};

static void init_ctx(struct codegen_context *ctx)
{
	ctx->local_directory = NULL;
	ctx->label_id = 0;
	ctx->entries = NULL;
	ctx->n_entries = 0;
	ctx->code = NULL;
	ctx->code_labels = NULL;
	ctx->code_exits = NULL;
	ctx->escape_nospill_label = 0;
	ctx->call_label = 0;
	ctx->reload_label = 0;
	ctx->mcode = NULL;
	ctx->label_to_pos = NULL;
	ctx->reloc = NULL;
	ctx->trap_records = NULL;
	ctx->args = NULL;
	ctx->flag_cache = NULL;
	ctx->registers = NULL;
	ctx->need_spill = NULL;
	ctx->codegen = NULL;
	ctx->upcall_offset = -1;
	ctx->upcall_args = -1;
	ctx->upcall_hacked_abi = false;
	ctx->var_aux = NULL;
}

static void done_ctx(struct codegen_context *ctx)
{
	if (ctx->local_directory)
		mem_free(ctx->local_directory);
	if (ctx->entries) {
		size_t i;
		for (i = 0; i < ctx->n_entries; i++) {
			struct cg_entry *ce = &ctx->entries[i];
			if (ce->variables)
				mem_free(ce->variables);
		}
		mem_free(ctx->entries);
	}
	if (ctx->code)
		mem_free(ctx->code);
	if (ctx->code_labels)
		mem_free(ctx->code_labels);
	if (ctx->code_exits) {
		ip_t ip;
		ip_t cs = da(ctx->fn,function)->code_size;
		for (ip = 0; ip < cs; ip++) {
			if (ctx->code_exits[ip])
				mem_free(ctx->code_exits[ip]);
		}
		mem_free(ctx->code_exits);
	}
	if (ctx->mcode)
		mem_free(ctx->mcode);
	if (ctx->label_to_pos)
		mem_free(ctx->label_to_pos);
	if (ctx->reloc)
		mem_free(ctx->reloc);
	if (ctx->trap_records)
		mem_free(ctx->trap_records);
	if (ctx->args)
		mem_free(ctx->args);
	if (ctx->flag_cache)
		mem_free(ctx->flag_cache);
	if (ctx->registers)
		mem_free(ctx->registers);
	if (ctx->need_spill)
		mem_free(ctx->need_spill);
	if (ctx->codegen)
		data_free(ctx->codegen);
	if (ctx->var_aux)
		mem_free(ctx->var_aux);
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


static uint32_t alloc_label(struct codegen_context *ctx)
{
	return ++ctx->label_id;
}

static struct cg_exit *alloc_cg_exit_for_ip(struct codegen_context *ctx, const code_t *code)
{
	ip_t ip = code - da(ctx->fn,function)->code;
	struct cg_exit *ce = ctx->code_exits[ip];
	if (!ce) {
		ce = mem_calloc_mayfail(struct cg_exit *, sizeof(struct cg_exit), &ctx->err);
		if (unlikely(!ce))
			return NULL;
		ctx->code_exits[ip] = ce;
	}
	return ce;
}

static struct cg_exit *alloc_undo_label(struct codegen_context *ctx)
{
	struct cg_exit *ce = alloc_cg_exit_for_ip(ctx, ctx->instr_start);
	if (unlikely(!ce))
		return NULL;
	if (unlikely(ce->undo_label != 0))
		internal(file_line, "alloc_cg_exit: undo label already allocated");
	ce->undo_label = alloc_label(ctx);
	if (unlikely(!ce->undo_label))
		return NULL;
	return ce;
}

static uint32_t alloc_escape_label_for_ip(struct codegen_context *ctx, const code_t *code)
{
	struct cg_exit *ce = alloc_cg_exit_for_ip(ctx, code);
	if (!ce)
		return 0;
	if (!ce->escape_label)
		ce->escape_label = alloc_label(ctx);
	return ce->escape_label;
}

static uint32_t alloc_escape_label(struct codegen_context *ctx)
{
	return alloc_escape_label_for_ip(ctx, ctx->instr_start);
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

static size_t attr_unused mark_params(struct codegen_context *ctx)
{
	return ctx->code_size;
}

static void attr_unused copy_params(struct codegen_context *ctx, struct cg_exit *ce, size_t mark)
{
	if (ctx->code_size - mark > n_array_elements(ce->undo_parameters))
		internal(file_line, "undo_parameters is too small: %"PRIuMAX" > %"PRIuMAX"", (uintmax_t)(ctx->code_size - mark), (uintmax_t)n_array_elements(ce->undo_parameters));
	memcpy(ce->undo_parameters, ctx->code + mark, ctx->code_size - mark);
	ce->undo_parameters_len = ctx->code_size - mark;
	ctx->code_size = mark;
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
#define IMM_PURPOSE_ADD_TRAP		22
#define IMM_PURPOSE_SUB_TRAP		23


static unsigned alu_purpose(unsigned alu)
{
	unsigned purpose =
		alu == ALU_ADD ? IMM_PURPOSE_ADD :
		alu == ALU_ADC ? IMM_PURPOSE_ADD :
		alu == ALU_SUB ? IMM_PURPOSE_SUB :
		alu == ALU_SBB ? IMM_PURPOSE_SUB :
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
		internal(file_line, "alu_purpose: invalid alu %u", alu);
	return purpose;
}

static unsigned alu_trap_purpose(unsigned alu)
{
	unsigned purpose =
		alu == ALU_ADD ? IMM_PURPOSE_ADD_TRAP :
		alu == ALU_SUB ? IMM_PURPOSE_SUB_TRAP :
		-1U;
	if (unlikely(purpose == -1U))
		internal(file_line, "alu_trap_purpose: invalid alu %u", alu);
	return purpose;
}


static bool attr_w gen_imm(struct codegen_context *ctx, int64_t imm, unsigned purpose, unsigned size);
static bool attr_w gen_upcall_end(struct codegen_context *ctx, unsigned offset, unsigned args, bool do_unspill);

#if !defined(ARCH_X86)
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
#else
#define gen_address_offset()						\
do {									\
	if (likely(!ctx->offset_reg)) {					\
		gen_one(ARG_ADDRESS_1);					\
		gen_one(ctx->base_reg);					\
		gen_eight(ctx->offset_imm);				\
	} else {							\
		internal(file_line, "gen_address_offset: R_OFFSET_IMM not defined");\
	}								\
} while (0)
#endif

#define gen_imm_offset()						\
do {									\
	if (likely(ctx->const_reg == ARG_IMM)) {			\
		gen_one(ARG_IMM);					\
		gen_eight(ctx->const_imm);				\
	} else {							\
		gen_one(ctx->const_reg);				\
	}								\
} while (0)

#define is_imm()	(ctx->const_reg == ARG_IMM)


static inline bool slot_is_register(struct codegen_context *ctx, frame_t slot)
{
	if (frame_t_is_const(slot))
		return false;
	if (unlikely(slot >= function_n_variables(ctx->fn)))
		internal(file_line, "slot_is_register: invalid slot %lu", (unsigned long)slot);
	return ctx->registers[slot] >= 0;
}


#define insn_file		1
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
#undef insn_file


#ifndef ARCH_SUPPORTS_TRAPS
#define ARCH_SUPPORTS_TRAPS(size)	0
#define ARCH_TRAP_BEFORE		0
#endif


static bool attr_w gen_imm(struct codegen_context *ctx, int64_t imm, unsigned purpose, unsigned size)
{
	if (!is_direct_const(imm, purpose & 0xff, size))
		goto load_const;
	if (purpose >> 8 && !is_direct_const(imm, purpose >> 8, size))
		goto load_const;
	ctx->const_imm = imm;
	ctx->const_reg = ARG_IMM;
	return true;
load_const:
#if defined(R_ZERO)
	if (!imm) {
		ctx->const_reg = R_ZERO;
		return true;
	}
#endif
#if defined(ARCH_ARM64)
	if (!imm && purpose != IMM_PURPOSE_ADD && purpose != IMM_PURPOSE_SUB && purpose != IMM_PURPOSE_CMP && purpose != IMM_PURPOSE_CMP_LOGICAL) {
		ctx->const_reg = R_ZR;
		return true;
	}
#endif
#if defined(R_CONST_IMM)
	g(gen_load_constant(ctx, R_CONST_IMM, imm));
	ctx->const_reg = R_CONST_IMM;
	return true;
#else
	/*internal(file_line, "gen_imm: R_CONST_IMM not defined: %"PRIxMAX"", (uintmax_t)imm);*/
	/*warning("%s: gen_imm: R_CONST_IMM not defined", file_line);*/
	return false;
#endif
}


#define insn_file		2
#include "cg-util.inc"
#undef insn_file

#define insn_file		3
#include "cg-frame.inc"
#undef insn_file

#define insn_file		4
#include "cg-flags.inc"
#undef insn_file

#define insn_file		5
#include "cg-flcch.inc"
#undef insn_file

#define insn_file		6
#include "cg-ptr.inc"
#undef insn_file

#define insn_file		7
#include "cg-alu.inc"
#undef insn_file

#define insn_file		8
#include "cg-ops.inc"
#undef insn_file

#define insn_file		0


#ifndef n_regs_saved
#define n_regs_saved n_array_elements(regs_saved)
#endif

#ifndef n_regs_volatile
#define n_regs_volatile n_array_elements(regs_volatile)
#endif

#ifndef n_fp_saved
#define n_fp_saved n_array_elements(fp_saved)
#endif

#ifndef n_fp_volatile
#define n_fp_volatile n_array_elements(fp_volatile)
#endif

#ifndef n_vector_volatile
#define n_vector_volatile n_array_elements(vector_volatile)
#endif

static bool attr_w gen_registers(struct codegen_context *ctx)
{
	frame_t v;
	size_t index_saved = 0;
	size_t index_volatile = 0;
	size_t index_fp_saved = 0;
	size_t index_fp_volatile = 0;
	size_t attr_unused index_vector_volatile = 0;
#ifdef ARCH_S390
	bool uses_x = false;
	for (v = MIN_USEABLE_SLOT; v < function_n_variables(ctx->fn); v++) {
		const struct type *t = get_type_of_local(ctx, v);
		if (t && TYPE_TAG_IS_REAL(t->tag) && TYPE_TAG_IDX_REAL(t->tag) == 4) {
			uses_x = true;
			break;
		}
	}
#endif
	/*for (v = function_n_variables(ctx->fn) - 1; v >= MIN_USEABLE_SLOT; v--)*/
	for (v = 0; v < function_n_variables(ctx->fn); v++) {
		const struct type *t;
		ctx->registers[v] = -1;
		if (ra_chicken)
			continue;
		t = get_type_of_local(ctx, v);
		if (unlikely(!t))
			continue;
		if (!da(ctx->fn,function)->local_variables_flags[v].must_be_flat &&
		    !da(ctx->fn,function)->local_variables_flags[v].must_be_data)
			continue;
		if (!ARCH_HAS_BWX && t->size < 1U << OP_SIZE_4)
			continue;
		if (TYPE_TAG_IS_FIXED(t->tag) || TYPE_TAG_IS_INT(t->tag) || t->tag == TYPE_TAG_flat_option || t->tag == TYPE_TAG_unknown || t->tag == TYPE_TAG_record) {
			if (TYPE_TAG_IS_BUILTIN(t->tag)) {
				if (!is_power_of_2(t->size) || t->size > 1U << OP_SIZE_NATIVE)
					continue;
			}
			if (index_saved < n_regs_saved + zero
#if defined(ARCH_PARISC) || defined(ARCH_SPARC)
				&& t->size <= 1U << OP_SIZE_ADDRESS
#endif
			     ) {
				ctx->registers[v] = regs_saved[index_saved++];
			} else if (index_volatile < n_regs_volatile + zero) {
				ctx->registers[v] = regs_volatile[index_volatile++];
			} else {
				continue;
			}
		} else if (TYPE_TAG_IS_REAL(t->tag)) {
			unsigned real_type = TYPE_TAG_IDX_REAL(t->tag);
			if ((SUPPORTED_FP >> real_type) & 1) {
#ifdef ARCH_POWER
				if (real_type == 4) {
					if (index_vector_volatile < n_vector_volatile + zero) {
						ctx->registers[v] = vector_volatile[index_vector_volatile++];
						goto success;
					}
					continue;
				}
#endif
#ifdef ARCH_S390
				if (real_type == 4) {
					if (!(index_fp_saved & 1) && index_fp_saved + 1 < n_fp_saved + zero) {
						ctx->registers[v] = fp_saved[index_fp_saved++];
						index_fp_saved++;
						goto success;
					}
					if (index_fp_saved & 1 && index_fp_saved + 2 < n_fp_saved + zero) {
						index_fp_saved++;
						ctx->registers[v] = fp_saved[index_fp_saved++];
						index_fp_saved++;
						goto success;
					}
					if (!(index_fp_volatile & 1) && index_fp_volatile + 1 < n_fp_volatile + zero) {
						ctx->registers[v] = fp_volatile[index_fp_volatile++];
						index_fp_volatile++;
						goto success;
					}
					if (index_fp_volatile & 1 && index_fp_volatile + 2 < n_fp_volatile + zero) {
						index_fp_volatile++;
						ctx->registers[v] = fp_volatile[index_fp_volatile++];
						index_fp_volatile++;
						goto success;
					}
					continue;
				}
#endif
				if (index_fp_saved < n_fp_saved + zero) {
					ctx->registers[v] = fp_saved[index_fp_saved++];
				} else if (index_fp_volatile < n_fp_volatile + zero) {
					ctx->registers[v] = fp_volatile[index_fp_volatile++];
				} else {
					continue;
				}
			} else {
				continue;
			}
		} else {
			continue;
		}
		goto success;
success:
		if (!reg_is_saved(ctx->registers[v])) {
			if (unlikely(!array_add_mayfail(frame_t, &ctx->need_spill, &ctx->need_spill_l, v, NULL, &ctx->err)))
				return false;
		}
	}

	return true;
}

static bool attr_w gen_fused_binary(struct codegen_context *ctx, unsigned mode, unsigned op_size, unsigned op, uint32_t escape_label, frame_t slot_1, frame_t slot_2, frame_t slot_r, bool *failed)
{
	const code_t *backup = ctx->current_position;
	code_t code;
	frame_t slot_dr, slot_test;
	int32_t offs_false;

	*failed = false;

next_code:
	code = get_code(ctx);
	ctx->arg_mode = code / OPCODE_MODE_MULT;
	code %= OPCODE_MODE_MULT;
	ajla_assert_lo(ctx->arg_mode < ARG_MODE_N, (file_line, "gen_fused_binary: invalid opcode %04x", (unsigned)*ctx->instr_start));

	if (code == OPCODE_DEREFERENCE) {
		const struct type *t;
		get_one(ctx, &slot_dr);
		t = get_type_of_local(ctx, slot_dr);
		if (!TYPE_TAG_IS_BUILTIN(t->tag)) {
			*failed = true;
			goto fail;
		}
		if (unlikely(!flag_is_clear(ctx, slot_dr))) {
			*failed = true;
			goto fail;
		}
		goto next_code;
	}
	if (code == OPCODE_DEREFERENCE_CLEAR) {
		*failed = true;
		goto fail;
	}
	if (unlikely(code != OPCODE_JMP_FALSE))
		internal(file_line, "gen_fused_binary: binary operation is not followed by jmp false: %x, %s", code, decode_opcode(code, true));
	get_one(ctx, &slot_test);
	if (unlikely(slot_test != slot_r))
		internal(file_line, "gen_fused_binary: the result of the binary operation and the tested variable do not match");
	offs_false = get_jump_offset(ctx);
	get_jump_offset(ctx);

	if (mode == MODE_ARRAY_LEN_GT) {
		g(gen_array_len(ctx, slot_1, slot_2, slot_r, true, offs_false));
	} else if (mode == MODE_REAL) {
		g(gen_fp_alu_jmp(ctx, op_size, op, escape_label, slot_1, slot_2, offs_false, failed));
	} else {
		g(gen_alu_jmp(ctx, mode, op_size, op, slot_1, slot_2, offs_false, failed));
	}

fail:
	if (*failed)
		ctx->current_position = backup;

	return true;
}

static bool attr_w gen_function(struct codegen_context *ctx)
{
	ctx->current_position = da(ctx->fn,function)->code;

	ctx->escape_nospill_label = alloc_label(ctx);
	if (unlikely(!ctx->escape_nospill_label))
		return false;

	while (ctx->current_position != da(ctx->fn,function)->code + da(ctx->fn,function)->code_size) {
		ip_t ip;
		code_t code;
		unsigned op, type;
		frame_t slot_1, slot_2, slot_3, slot_r, flags, fn_idx, opt;
		arg_t n_args, n_ret, i_arg;
		uint32_t label_id;
		uint32_t escape_label;
		bool failed;

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
			if (op < OPCODE_FIXED_OP_C) {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_2_cached(ctx, slot_1, slot_2, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_2, false);
				flag_set(ctx, slot_r, false);
				if (flags & OPCODE_FLAG_FUSED) {
					g(gen_fused_binary(ctx, MODE_FIXED, type, op, escape_label, slot_1, slot_2, slot_r, &failed));
					if (unlikely(!failed))
						continue;
				}
				g(gen_alu(ctx, MODE_FIXED, type, op, escape_label, slot_1, slot_2, slot_r));
				continue;
			} else if (op < OPCODE_FIXED_OP_UNARY) {
				op -= OPCODE_FIXED_OP_C;
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				slot_2 = frame_t_from_const((int32_t)slot_2);
				if (flags & OPCODE_FLAG_FUSED) {
					g(gen_fused_binary(ctx, MODE_FIXED, type, op, escape_label, slot_1, slot_2, slot_r, &failed));
					if (unlikely(!failed))
						continue;
				}
				g(gen_alu(ctx, MODE_FIXED, type, op, escape_label, slot_1, slot_2, slot_r));
				continue;
			} else if (op < OPCODE_FIXED_OP_N) {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_alu1(ctx, MODE_FIXED, type, op, escape_label, slot_1, slot_r));
				continue;
			} else if (op == OPCODE_FIXED_OP_ldc) {
				unsigned i;
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, false, type, false, slot_r));
				for (i = 0; i < 1U << type; i += 2)
					get_code(ctx);
				flag_set(ctx, slot_r, false);
				continue;
			} else if (op == OPCODE_FIXED_OP_ldc16) {
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, false, type, true, slot_r));
				get_code(ctx);
				flag_set(ctx, slot_r, false);
				continue;
			} else if (op == OPCODE_FIXED_OP_move || op == OPCODE_FIXED_OP_copy) {
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_copy(ctx, type, slot_1, slot_r));
				continue;
			} else {
				internal(file_line, "gen_function: bad fixed code %04x", *ctx->instr_start);
			}
		} else if (code >= OPCODE_INT_OP && code < OPCODE_REAL_OP) {
			code -= OPCODE_INT_OP;
			op = (code / OPCODE_INT_OP_MULT) % OPCODE_INT_TYPE_MULT;
			type = code / OPCODE_INT_TYPE_MULT;
			if (op < OPCODE_INT_OP_C) {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_2_cached(ctx, slot_1, slot_2, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_2, false);
				flag_set(ctx, slot_r, false);
				if (flags & OPCODE_FLAG_FUSED) {
					g(gen_fused_binary(ctx, MODE_INT, type, op, escape_label, slot_1, slot_2, slot_r, &failed));
					if (unlikely(!failed))
						continue;
				}
				g(gen_alu(ctx, MODE_INT, type, op, escape_label, slot_1, slot_2, slot_r));
				continue;
			} else if (op < OPCODE_INT_OP_UNARY) {
				op -= OPCODE_INT_OP_C;
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				slot_2 = frame_t_from_const((int32_t)slot_2);
				if (flags & OPCODE_FLAG_FUSED) {
					g(gen_fused_binary(ctx, MODE_INT, type, op, escape_label, slot_1, slot_2, slot_r, &failed));
					if (unlikely(!failed))
						continue;
				}
				g(gen_alu(ctx, MODE_INT, type, op, escape_label, slot_1, slot_2, slot_r));
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
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_alu1(ctx, MODE_INT, type, op, escape_label, slot_1, slot_r));
				continue;
			} else if (op == OPCODE_INT_OP_ldc) {
				unsigned i;
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, false, type, false, slot_r));
				for (i = 0; i < 1U << type; i += 2)
					get_code(ctx);
				flag_set(ctx, slot_r, false);
				continue;
			} else if (op == OPCODE_INT_OP_ldc16) {
				get_one(ctx, &slot_r);
				g(gen_constant(ctx, false, type, true, slot_r));
				get_code(ctx);
				flag_set(ctx, slot_r, false);
				continue;
			} else if (op == OPCODE_INT_OP_move || op == OPCODE_INT_OP_copy) {
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_copy(ctx, type, slot_1, slot_r));
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
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_2, false);
				flag_set(ctx, slot_r, false);
				if (flags & OPCODE_FLAG_FUSED) {
					g(gen_fused_binary(ctx, MODE_REAL, type, op, escape_label, slot_1, slot_2, slot_r, &failed));
					if (unlikely(!failed))
						continue;
				}
				g(gen_fp_alu(ctx, type, op, escape_label, slot_1, slot_2, slot_r));
				continue;
			} else if (op < OPCODE_REAL_OP_N) {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_fp_alu1(ctx, type, op, escape_label, slot_1, slot_r));
				continue;
			} else if (op == OPCODE_REAL_OP_ldc) {
				const struct type *t;
				unsigned i;
				get_one(ctx, &slot_r);
				t = type_get_real(type);
				g(gen_real_constant(ctx, t, slot_r));
				for (i = 0; i < t->size; i += 2)
					get_code(ctx);
				flag_set(ctx, slot_r, false);
				continue;
			} else if (op == OPCODE_REAL_OP_move || op == OPCODE_REAL_OP_copy) {
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_memcpy_slots(ctx, slot_r, slot_1));
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
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_2, false);
				flag_set(ctx, slot_r, false);
				if (flags & OPCODE_FLAG_FUSED) {
					g(gen_fused_binary(ctx, MODE_BOOL, type, op, escape_label, slot_1, slot_2, slot_r, &failed));
					if (unlikely(!failed))
						continue;
				}
				g(gen_alu(ctx, MODE_BOOL, type, op, escape_label, slot_1, slot_2, slot_r));
				continue;
			} else if (op < OPCODE_BOOL_OP_N) {
				get_two(ctx, &slot_1, &slot_r);
				get_one(ctx, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_alu1(ctx, MODE_BOOL, type, op, escape_label, slot_1, slot_r));
				continue;
			} else if (op == OPCODE_BOOL_OP_move || op == OPCODE_BOOL_OP_copy) {
				get_two(ctx, &slot_1, &slot_r);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				g(gen_test_1_cached(ctx, slot_1, escape_label));
				flag_set(ctx, slot_1, false);
				flag_set(ctx, slot_r, false);
				g(gen_copy(ctx, type, slot_1, slot_r));
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
				if (flag_is_set(ctx, slot_1))
					goto take_borrowed_done;
				if (flag_is_clear(ctx, slot_1)) {
					g(gen_set_1(ctx, R_FRAME, slot_1, 0, true));
					goto do_take_borrowed;
				}
				g(gen_test_1(ctx, R_FRAME, slot_1, 0, label_id, false, TEST_SET));
do_take_borrowed:
				g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
				g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot_1, 0, false, R_ARG0));
				g(gen_upcall_argument(ctx, 0));
				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_reference_owned), 1, true));
				flag_set(ctx, slot_1, true);
take_borrowed_done:
				gen_label(label_id);
				continue;
			case OPCODE_DEREFERENCE:
			case OPCODE_DEREFERENCE_CLEAR: {
				bool need_bit_test;
				/*const struct type *type;*/
				get_one(ctx, &slot_1);
				if (flag_is_clear(ctx, slot_1))
					goto skip_dereference;
				/*type = get_type_of_local(ctx, slot_1);*/
				/*need_bit_test = 1 || TYPE_IS_FLAT(type) || da(ctx->fn,function)->local_variables[slot_1].may_be_borrowed;*/
				need_bit_test = !flag_is_set(ctx, slot_1);
				if (need_bit_test) {
					if (unlikely(!(label_id = alloc_label(ctx))))
						return false;
					g(gen_test_1(ctx, R_FRAME, slot_1, 0, label_id, true, TEST_CLEAR));
				} else {
					g(gen_set_1(ctx, R_FRAME, slot_1, 0, false));
					label_id = 0;	/* avoid warning */
				}
				g(gen_upcall_start(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_dereference), 1, true));
				g(gen_frame_load(ctx, OP_SIZE_SLOT, garbage, slot_1, 0, false, R_ARG0));
				g(gen_upcall_argument(ctx, 0));
				g(gen_upcall(ctx, offsetof(struct cg_upcall_vector_s, cg_upcall_pointer_dereference), 1, true));
				if (need_bit_test)
					gen_label(label_id);
skip_dereference:
				if (code == OPCODE_DEREFERENCE_CLEAR)
					g(gen_frame_clear(ctx, OP_SIZE_SLOT, slot_1));
				flag_set_unknown(ctx, slot_1);
				flag_set(ctx, slot_1, false);
				continue;
			}
			case OPCODE_EVAL: {
				get_one(ctx, &slot_1);
				g(gen_eval(ctx, slot_1));
				continue;
			}
			case OPCODE_ESCAPE_NONFLAT: {
				frame_t n, i;
				frame_t *vars;

				get_one(ctx, &n);
				vars = mem_alloc_array_mayfail(mem_alloc_mayfail, frame_t *, 0, 0, n, sizeof(frame_t), &ctx->err);
				if (unlikely(!vars))
					return false;
				for (i = 0; i < n; i++) {
					get_one(ctx, &vars[i]);
				}

				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label)) {
					mem_free(vars);
					return false;
				}

				if (unlikely(!gen_test_variables(ctx, vars, n, true, escape_label))) {
					mem_free(vars);
					return false;
				}
				mem_free(vars);

				continue;
			}
			case OPCODE_CHECKPOINT: {
				frame_t n_vars;

				g(clear_flag_cache(ctx));

				if (SIZEOF_IP_T == 2) {
					slot_1 = get_code(ctx);
				} else if (SIZEOF_IP_T == 4) {
					slot_1 = get_uint32(ctx);
				} else {
					not_reached();
					continue;
				}

				if (unlikely(!(slot_1 + 1)))
					return false;
				while (slot_1 >= ctx->n_entries) {
					void *err_entries;
					struct cg_entry e;
					if (unlikely(!ctx->entries)) {
						if (unlikely(!array_init_mayfail(struct cg_entry, &ctx->entries, &ctx->n_entries, &ctx->err)))
							return false;
					}
					memset(&e, 0, sizeof(struct cg_entry));
					if (unlikely(!array_add_mayfail(struct cg_entry, &ctx->entries, &ctx->n_entries, e, &err_entries, &ctx->err))) {
						ctx->entries = err_entries;
						return false;
					}
				}

				get_one(ctx, &n_vars);

				escape_label = 0;	/* avoid warning */
				if (likely(slot_1 != 0)) {
					escape_label = alloc_escape_label(ctx);
					if (unlikely(!escape_label))
						return false;
				}

				if (n_vars || !slot_1) {
					frame_t i;
					uint32_t entry_label, nonflat_label;
					struct cg_entry *ce = &ctx->entries[slot_1];

					if (unlikely(!array_init_mayfail(frame_t, &ce->variables, &ce->n_variables, &ctx->err)))
						return false;
					for (i = 0; i < n_vars; i++) {
						frame_t v;
						get_one(ctx, &v);
						if (unlikely(!array_add_mayfail(frame_t, &ce->variables, &ce->n_variables, v, NULL, &ctx->err)))
							return false;
					}
					if (!slot_1) {
						g(gen_test_variables(ctx, ce->variables, ce->n_variables, true, ctx->escape_nospill_label));
					}
					entry_label = alloc_label(ctx);
					if (unlikely(!entry_label))
						return false;
					gen_label(entry_label);
					ce->entry_label = entry_label;

					nonflat_label = alloc_escape_label_for_ip(ctx, ctx->current_position);
					if (unlikely(!nonflat_label))
						return false;
					ce->nonflat_label = nonflat_label;

					if (unlikely(!slot_1))
						g(gen_timestamp_test(ctx, ctx->escape_nospill_label));
					else
						g(gen_timestamp_test(ctx, escape_label));
				} else {
					g(gen_timestamp_test(ctx, escape_label));

					gen_insn(INSN_ENTRY, 0, 0, 0);
					gen_four(slot_1);
				}
				continue;
			}
			case OPCODE_JMP: {
				int32_t x = get_jump_offset(ctx);
				g(gen_jump(ctx, x, OP_SIZE_NATIVE, COND_ALWAYS, -1U, -1U));
				continue;
			}
			case OPCODE_JMP_BACK_16: {
				int32_t x = get_code(ctx);
				g(gen_jump(ctx, -x - (int)(2 * sizeof(code_t)), OP_SIZE_NATIVE, COND_ALWAYS, -1U, -1U));
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
				flag_set(ctx, slot_1, false);
				g(gen_cond_jump(ctx, slot_1, offs_false));
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
			case OPCODE_CALL_WEAKSPARK:
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
				if (unlikely(profiling))
					goto unconditional_escape;
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
			case OPCODE_CALL_INDIRECT_WEAKSPARK:
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
				if (unlikely(profiling))
					goto unconditional_escape;
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
				g(gen_array_len(ctx, slot_1, NO_FRAME_T, slot_r, false, 0));
				continue;
			}
			case OPCODE_ARRAY_LEN_GREATER_THAN: {
				get_two(ctx, &slot_1, &slot_2);
				get_two(ctx, &slot_r, &flags);
				escape_label = alloc_escape_label(ctx);
				if (unlikely(!escape_label))
					return false;
				if (flags & OPCODE_FLAG_FUSED) {
					g(gen_fused_binary(ctx, MODE_ARRAY_LEN_GT, 0, 0, escape_label, slot_1, slot_2, slot_r, &failed));
					if (unlikely(!failed))
						continue;
				}
				g(gen_array_len(ctx, slot_1, slot_2, slot_r, false, 0));
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
				get_two(ctx, &flags, &slot_1);
				get_two(ctx, &slot_2, &slot_3);
				g(gen_io(ctx, flags, slot_1, slot_2, slot_3));
				continue;
			}
			case OPCODE_INTERNAL_FUNCTION:
			case OPCODE_EXIT_THREAD:
			case OPCODE_UNREACHABLE: {
				goto unconditional_escape;
			}
			default: {
				internal(file_line, "gen_function: %s: unknown opcode %04x, %s", da(ctx->fn,function)->function_name, *ctx->instr_start, decode_opcode(*ctx->instr_start, false));
				return false;
			}
		}
	}

	return true;
}

static bool attr_w gen_entries(struct codegen_context *ctx)
{
	size_t i;
	for (i = 0; i < ctx->n_entries; i++) {
		struct cg_entry *ce = &ctx->entries[i];
		if (ce->entry_label) {
			gen_insn(INSN_ENTRY, 0, 0, 0);
			gen_four(i);

			g(gen_test_variables(ctx, ce->variables, ce->n_variables, true, ce->nonflat_label));

			gen_insn(INSN_JMP, 0, 0, 0);
			gen_four(ce->entry_label);
		}
	}
	return true;
}

static bool attr_w gen_epilogues(struct codegen_context *ctx)
{
	ip_t ip;
	uint32_t escape_label, nospill_label;
	escape_label = alloc_label(ctx);
	if (unlikely(!escape_label))
		return false;
	nospill_label = alloc_label(ctx);
	if (unlikely(!nospill_label))
		return false;
#if defined(ARCH_PARISC)
	if (ctx->call_label) {
		gen_label(ctx->call_label);
		g(gen_call_millicode(ctx));
	}
#endif
	if (ctx->reload_label) {
		gen_label(ctx->reload_label);
		g(gen_spill_all(ctx));
		g(gen_mov(ctx, i_size(OP_SIZE_ADDRESS), R_FRAME, R_RET0));
		g(gen_escape_arg(ctx, (ip_t)-1, nospill_label));
	}
	gen_label(ctx->escape_nospill_label);
	g(gen_escape_arg(ctx, 0, nospill_label));
	for (ip = 0; ip < da(ctx->fn,function)->code_size; ip++) {
		struct cg_exit *ce = ctx->code_exits[ip];
		if (ce && (ce->undo_label || ce->escape_label)) {
			if (ce->undo_label) {
				size_t i;
				gen_label(ce->undo_label);
				gen_insn(ce->undo_opcode, ce->undo_op_size, ce->undo_aux, ce->undo_writes_flags);
				for (i = 0; i < ce->undo_parameters_len; i++)
					gen_one(ce->undo_parameters[i]);
			}
			if (ce->escape_label) {
				gen_label(ce->escape_label);
			}
			g(gen_escape_arg(ctx, ip, escape_label));
		}
	}
	gen_label(escape_label);

	g(gen_spill_all(ctx));

	gen_label(nospill_label);
	g(gen_escape(ctx));
	return true;
}

static bool attr_w cgen_entry(struct codegen_context *ctx)
{
	uint32_t entry_id = cget_four(ctx);
	ajla_assert_lo(entry_id < ctx->n_entries, (file_line, "cgen_entry: invalid entry %lx", (unsigned long)entry_id));
	ctx->entries[entry_id].entry_to_pos = ctx->mcode_size;
	return true;
}

static bool attr_w cgen_label(struct codegen_context *ctx)
{
	uint32_t label_id = cget_four(ctx);
	ajla_assert_lo(ctx->label_to_pos[label_id] == (size_t)-1, (file_line, "cgen_label: label already defined"));
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
		debug("line: %u/%u", insn >> 24, insn & 0x00FFFFFFU);
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
		char *entry = cast_ptr(char *, ptr) + ctx->entries[i].entry_to_pos;
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

	ctx->code_exits = mem_alloc_array_mayfail(mem_calloc_mayfail, struct cg_exit **, 0, 0, da(ctx->fn,function)->code_size, sizeof(struct cg_exit *), &ctx->err);
	if (unlikely(!ctx->code_exits))
		goto fail;

	ctx->flag_cache = mem_alloc_array_mayfail(mem_calloc_mayfail, uint8_t *, 0, 0, function_n_variables(ctx->fn), sizeof(int8_t), &ctx->err);
	if (unlikely(!ctx->flag_cache))
		goto fail;

	ctx->registers = mem_alloc_array_mayfail(mem_alloc_mayfail, short *, 0, 0, function_n_variables(ctx->fn), sizeof(short), &ctx->err);
	if (unlikely(!ctx->registers))
		goto fail;

	if (unlikely(!array_init_mayfail(frame_t, &ctx->need_spill, &ctx->need_spill_l, &ctx->err)))
		goto fail;

	if (unlikely(!gen_registers(ctx)))
		goto fail;

	if (unlikely(!gen_function(ctx)))
		goto fail;

	if (unlikely(!gen_entries(ctx)))
		goto fail;

	if (unlikely(!gen_epilogues(ctx)))
		goto fail;

	if (unlikely(!(ctx->label_id + 1)))
		goto fail;
	if (unlikely(!(ctx->label_to_pos = mem_alloc_array_mayfail(mem_alloc_mayfail, size_t *, 0, 0, ctx->label_id + 1, sizeof(size_t), &ctx->err))))
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

	if (dump_code && (!dump_code[0] || !strcmp(dump_code, da(ctx->fn,function)->function_name))) {
		char *hex;
		size_t hexl;
		size_t i;
		handle_t h;

		mutex_lock(&dump_mutex);
		str_init(&hex, &hexl);
		str_add_string(&hex, &hexl, "_");
		str_add_unsigned(&hex, &hexl, dump_seq++, 10);
		str_add_string(&hex, &hexl, "_");
		str_add_string(&hex, &hexl, da(ctx->fn,function)->function_name);
		str_add_string(&hex, &hexl, ":");
		for (i = 0; i < hexl; i++)
			if (hex[i] == '/')
				hex[i] = '_';
		for (i = 0; i < ctx->mcode_size; i++) {
			uint8_t a = ctx->mcode[i];
			if (!(i & 0xff))
				str_add_string(&hex, &hexl, "\n	.byte	0x");
			else
				str_add_string(&hex, &hexl, ",0x");
			if (a < 16)
				str_add_char(&hex, &hexl, '0');
			str_add_unsigned(&hex, &hexl, a, 16);
		}
		str_add_string(&hex, &hexl, "\n");
		h = os_open(os_cwd, "dump.s", O_WRONLY | O_APPEND, 0600, NULL);
		os_write_all(h, hex, hexl, NULL);
		os_close(h);
		mem_free(hex);
		mutex_unlock(&dump_mutex);
	}

	ctx->codegen = data_alloc_flexible(codegen, unoptimized_code, ctx->n_entries, &ctx->err);
	if (unlikely(!ctx->codegen))
		goto fail;
	da(ctx->codegen,codegen)->function = ctx->fn;
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
	/*debug("FAILED: %s", da(ctx->fn,function)->function_name);*/
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

#if (defined(ARCH_X86_64) || defined(ARCH_X86_X32)) && !defined(ARCH_X86_WIN_ABI)
#if defined(HAVE_SYSCALL) && defined(HAVE_ASM_PRCTL_H) && defined(HAVE_SYS_SYSCALL_H)
	if (!dll) {
		int r;
		EINTR_LOOP(r, syscall(SYS_arch_prctl, ARCH_SET_GS, &cg_upcall_vector));
		if (!r)
			upcall_register = R_GS;
	}
#elif defined(HAVE_AMD64_SET_GSBASE) && defined(HAVE_X86_SYSARCH_H)
	if (!dll) {
		int r;
		EINTR_LOOP(r, amd64_set_gsbase(&cg_upcall_vector));
		if (!r)
			upcall_register = R_GS;
	}
#elif defined(HAVE_SYSARCH) && defined(HAVE_X86_SYSARCH_H) && defined(X86_64_SET_GSBASE)
	if (!dll) {
		int r;
		void *ptr = &cg_upcall_vector;
		EINTR_LOOP(r, sysarch(X86_64_SET_GSBASE, &ptr));
		if (!r)
			upcall_register = R_GS;
	}
#endif
#endif

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

	mutex_init(&dump_mutex);
	if (dump_code) {
		size_t i;
		char *hex;
		size_t hexl;
		str_init(&hex, &hexl);
#if defined(ARCH_RISCV64)
		str_add_string(&hex, &hexl, "	.attribute arch, \"rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zba1p0_zbb1p0_zbc1p0_zbs1p0\"\n");
#endif
		for (i = 0; i < codegen_size; i++) {
			uint8_t a = cast_ptr(uint8_t *, codegen_ptr)[i];
			str_add_string(&hex, &hexl, "	.byte	0x");
			if (a < 16)
				str_add_char(&hex, &hexl, '0');
			str_add_unsigned(&hex, &hexl, a, 16);
			str_add_char(&hex, &hexl, '\n');
		}
		os_write_atomic(".", "dump.s", hex, hexl, NULL);
		mem_free(hex);
	}

	return;

fail:
	fatal("couldn't compile global entry");
}

void name(codegen_done)(void)
{
	os_code_unmap(codegen_ptr, codegen_size);
	mutex_done(&dump_mutex);
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
