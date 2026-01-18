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

static uint8_t attr_unused oget_one(uint8_t *ptr)
{
	return *ptr;
}

static uint16_t attr_unused oget_two(uint8_t *ptr)
{
#if defined(C_LITTLE_ENDIAN)
	uint16_t r;
	memcpy(&r, ptr, 2);
	return r;
#else
	uint16_t r = oget_one(ptr);
	r |= (uint16_t)oget_one(ptr + 1) << 8;
	return r;
#endif
}

static uint32_t attr_unused oget_four(uint8_t *ptr)
{
#if defined(C_LITTLE_ENDIAN)
	uint32_t r;
	memcpy(&r, ptr, 4);
	return r;
#else
	uint32_t r = oget_two(ptr);
	r |= (uint32_t)oget_two(ptr + 2) << 16;
	return r;
#endif
}

static uint64_t attr_unused oget_eight(uint8_t *ptr)
{
#if defined(C_LITTLE_ENDIAN)
	uint64_t r;
	memcpy(&r, ptr, 8);
	return r;
#else
	uint64_t r = oget_four(ptr);
	r |= (uint64_t)oget_four(ptr + 4) << 32;
	return r;
#endif
}

#if R_MAX < 0x78 && TYPE_FIXED_N >= 5

typedef uint128_t reg_map;

static inline void reg_map_init(reg_map *rm) { *rm = 0; }
static inline void reg_map_set(reg_map *rm, unsigned reg) { *rm |= (reg_map)1 << reg; }

#else

typedef struct {
	uint32_t map[8];
} reg_map;

static inline void reg_map_init(reg_map *rm) { memset(rm, 0, sizeof(reg_map)); }
static inline void reg_map_set(reg_map *rm, unsigned reg) { rm->map[reg >> 5] |= (uint32_t)1 << (reg & 31); }

#endif

struct insn_details {
	uint8_t *start;
	unsigned length;
	bool barrier;
	reg_map rd;
	reg_map wr;
};

static unsigned arg_read(struct insn_details *d, uint8_t *ptr)
{
	if (ptr[0] < ARG_REGS_MAX) {
		reg_map_set(&d->rd, ptr[0]);
		return 1;
	}
	if (ptr[0] >= ARG_SHIFTED_REGISTER && ptr[0] <= ARG_EXTENDED_REGISTER) {
		reg_map_set(&d->rd, ptr[2]);
		return 1;
	}
	if (ptr[0] == ARG_ADDRESS_0) {
		return 9;
	}
	if (ptr[0] == ARG_ADDRESS_1 && ptr[0] <= ARG_ADDRESS_1_8) {
		reg_map_set(&d->rd, ptr[1]);
		return 10;
	}
	if (ptr[0] == ARG_ADDRESS_1_PRE_I && ptr[0] <= ARG_ADDRESS_1_POST_I) {
		reg_map_set(&d->rd, ptr[1]);
		reg_map_set(&d->wr, ptr[1]);
		return 10;
	}
	if (ptr[0] >= ARG_ADDRESS_2 && ptr[0] <= ARG_ADDRESS_2_SXTW) {
		reg_map_set(&d->rd, ptr[1]);
		reg_map_set(&d->rd, ptr[2]);
		return 11;
	}
	if (ptr[0] == ARG_IMM) {
		return 9;
	}
	internal(file_line, "arg_read: invalid argument %02x", ptr[0]);
}

static unsigned arg_write(struct insn_details *d, uint8_t *ptr)
{
	if (ptr[0] < ARG_REGS_MAX) {
		reg_map_set(&d->wr, ptr[0]);
		return 1;
	}
	return arg_read(d, ptr);
}

static void identify_insn(struct codegen_context *ctx, uint8_t *ptr, struct insn_details *d)
{
	uint8_t *orig_ptr = ptr;
	uint32_t insn;
	insn = oget_four(ptr);
	ptr += 4;
	d->start = orig_ptr;
	d->barrier = false;
	reg_map_init(&d->rd);
	reg_map_init(&d->wr);

	switch (insn_opcode(insn)) {
		uint32_t label_id;
		case INSN_LABEL:
			label_id = oget_four(ptr);
			ptr += 4;
			d->barrier = ctx->label_used[label_id];
			break;
		case INSN_RET:
			d->barrier = true;
			break;
		case INSN_ARM_PUSH:
		case INSN_ARM_POP:
		case INSN_S390_PUSH:
		case INSN_S390_POP:
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_IA64_ALLOC:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_IA64_DEALLOC:
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_PUSH:
			ptr += arg_read(d, ptr);
			d->barrier = true;
			break;
		case INSN_PUSH2:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			d->barrier = true;
			break;
		case INSN_POP:
			ptr += arg_write(d, ptr);
			d->barrier = true;
			break;
		case INSN_POP2:
			ptr += arg_write(d, ptr);
			ptr += arg_write(d, ptr);
			d->barrier = true;
			break;
		case INSN_CALL:
			ptr += 4;
			d->barrier = true;
			break;
		case INSN_CALL_INDIRECT:
			ptr += arg_read(d, ptr);
			d->barrier = true;
			break;
		case INSN_MOV:
		case INSN_MOVSX:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_MOV_U:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_MOV_LR:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CMP:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CMP_DEST_REG:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CMN:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_TEST:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_TEST_DEST_REG:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_ALU:
		case INSN_ALU_FLAGS:
		case INSN_ALU_PARTIAL:
		case INSN_ALU_FLAGS_PARTIAL:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_ALU_TRAP:
		case INSN_ALU_FLAGS_TRAP:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += 4;
			break;
		case INSN_ALU1:
		case INSN_ALU1_FLAGS:
		case INSN_ALU1_PARTIAL:
		case INSN_ALU1_FLAGS_PARTIAL:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_ALU1_TRAP:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += 4;
			break;
		case INSN_LEA3:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_ROT:
		case INSN_ROT_PARTIAL:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_BT:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_BTX:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_MUL_L:
			ptr += arg_write(d, ptr);
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_DIV_L:
			ptr += arg_write(d, ptr);
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_MADD:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CBW:
		case INSN_CBW_PARTIAL:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CWD:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CWD_PARTIAL:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_SET_COND:
			ptr += arg_write(d, ptr);
			break;
		case INSN_SET_COND_PARTIAL:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CMOV:
		case INSN_CMOV_XCC:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CMP_CMOV:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_MOVR:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_CSEL_SEL:
		case INSN_CSEL_INC:
		case INSN_CSEL_INV:
		case INSN_CSEL_NEG:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_STP:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_LDP:
			ptr += arg_write(d, ptr);
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_MOV_MASK:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_MEMCPY:
		case INSN_MEMSET:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			d->barrier = true;
			break;
		case INSN_FP_CMP:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_FP_CMP_DEST_REG:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_FP_CMP_DEST_REG_TRAP:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += 4;
			break;
		case INSN_FP_CMP_UNORDERED_DEST_REG:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_FP_CMP_COND:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_FP_TEST_REG:
			ptr += arg_write(d, ptr);
			break;
		case INSN_FP_TO_INT_FLAGS:
			break;
		case INSN_FP_ALU:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_FP_ALU1:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_FP_TO_INT32:
		case INSN_FP_TO_INT64:
		case INSN_FP_FROM_INT32:
		case INSN_FP_FROM_INT64:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_FP_TO_INT64_TRAP:
		case INSN_FP_INT64_TO_INT32_TRAP:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += 4;
			break;
		case INSN_FP_CVT:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_X87_FLD:
		case INSN_X87_FILD:
			ptr += arg_read(d, ptr);
			break;
		case INSN_X87_FSTP:
		case INSN_X87_FISTP:
		case INSN_X87_FISTTP:
			ptr += arg_read(d, ptr);
			break;
		case INSN_X87_FCOMP:
		case INSN_X87_FCOMPP:
		case INSN_X87_FCOMIP:
			ptr += arg_read(d, ptr);
			break;
		case INSN_X87_ALU:
		case INSN_X87_ALUP:
			ptr += arg_read(d, ptr);
			break;
		case INSN_X87_FCHS:
		case INSN_X87_FSQRT:
		case INSN_X87_FRNDINT:
			break;
		case INSN_X87_FNSTSW:
			ptr += arg_write(d, ptr);
			ptr += arg_read(d, ptr);
			break;
		case INSN_X87_FLDCW:
			ptr += arg_read(d, ptr);
			break;
		case INSN_JMP:
			ptr += 4;
			break;
		case INSN_JMP_COND:
		case INSN_JMP_COND_LOGICAL:
			ptr += 4;
			break;
		case INSN_JMP_REG:
			ptr += arg_read(d, ptr);
			ptr += 4;
			break;
		case INSN_JMP_REG_BIT:
			ptr += arg_read(d, ptr);
			ptr += 4;
			break;
		case INSN_JMP_2REGS:
			ptr += arg_read(d, ptr);
			ptr += arg_read(d, ptr);
			ptr += 4;
			break;
		case INSN_JMP_FP_TEST:
			ptr += 4;
			break;
		case INSN_JMP_INDIRECT:
			ptr += arg_read(d, ptr);
			break;
		case INSN_VZEROUPPER:
			break;
		case INSN_MB:
			break;
		case INSN_STOP_BIT:
			break;
		case INSN_CALL_MILLICODE:
			break;
		default:
			internal(file_line, "identify_insn: invalid insn %08lx", (unsigned long)insn);
	}
	d->length = ptr - orig_ptr;
}

static bool attr_w process_basic_block(struct codegen_context *ctx)
{
	size_t i;
	for (i = 0; i < ctx->basic_block_position; i++) {
		struct insn_details *d = &ctx->basic_block[i];
		if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->new_code, &ctx->new_code_size, d->start, d->length, NULL, &ctx->err)))
			return false;
	}
	ctx->basic_block_position = 0;
	return true;
}

static bool attr_w cg_optimize(struct codegen_context *ctx)
{
	if (unlikely(!array_init_mayfail(uint8_t, &ctx->new_code, &ctx->new_code_size, &ctx->err)))
		return false;

	if (unlikely(!array_init_mayfail(struct insn_details, &ctx->basic_block, &ctx->basic_block_size, &ctx->err)))
		return false;
	ctx->basic_block_position = 0;

	ctx->code_position = ctx->code;

	while (ctx->code_position != ctx->code + ctx->code_size) {
		struct insn_details *d;
		uint8_t *start;
		unsigned length;

		ajla_assert_lo(ctx->code_position < ctx->code + ctx->code_size, (file_line, "cg_optimize: ran out of code"));

		if (unlikely(ctx->basic_block_position == ctx->basic_block_size)) {
			struct insn_details dc;
			memset(&dc, 0, sizeof(struct insn_details));
			if (!unlikely(array_add_mayfail(struct insn_details, &ctx->basic_block, &ctx->basic_block_size, dc, NULL, &ctx->err)))
				return false;
		}
		d = &ctx->basic_block[ctx->basic_block_position];

		identify_insn(ctx, ctx->code_position, d);

		start = d->start;
		length = d->length;

		if (d->barrier) {
			g(process_basic_block(ctx));
			if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->new_code, &ctx->new_code_size, start, length, NULL, &ctx->err)))
				return false;
		} else {
			ctx->basic_block_position++;
		}
		ctx->code_position += length;
	}

	g(process_basic_block(ctx));

	mem_free(ctx->basic_block);
	ctx->basic_block = NULL;

	flip_buffers(ctx);

	return true;
}
