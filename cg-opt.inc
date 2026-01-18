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

struct insn_details {
	unsigned length;
	bool barrier;
};

static void attr_unused identify_insn(struct codegen_context *ctx, uint8_t *ptr, struct insn_details *d)
{
	uint8_t *orig_ptr = ptr;
	uint32_t insn;
	insn = oget_four(ptr);
	ptr += 4;
	d->barrier = false;
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
		case INSN_POP:
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_PUSH2:
		case INSN_POP2:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_CALL:
			ptr += 4;
			d->barrier = true;
			break;
		case INSN_CALL_INDIRECT:
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_MOV:
		case INSN_MOVSX:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_MOV_U:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_MOV_LR:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_CMP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CMP_DEST_REG:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CMN:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_TEST:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_TEST_DEST_REG:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_ALU:
		case INSN_ALU_FLAGS:
		case INSN_ALU_PARTIAL:
		case INSN_ALU_FLAGS_PARTIAL:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_ALU_TRAP:
		case INSN_ALU_FLAGS_TRAP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += 4;
			break;
		case INSN_ALU1:
		case INSN_ALU1_FLAGS:
		case INSN_ALU1_PARTIAL:
		case INSN_ALU1_FLAGS_PARTIAL:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_ALU1_TRAP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += 4;
			break;
		case INSN_LEA3:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_ROT:
		case INSN_ROT_PARTIAL:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_BT:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_BTX:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_MUL_L:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_DIV_L:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_MADD:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CBW:
		case INSN_CBW_PARTIAL:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CWD:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CWD_PARTIAL:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_SET_COND:
			ptr += arg_size(*ptr);
			break;
		case INSN_SET_COND_PARTIAL:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CMOV:
		case INSN_CMOV_XCC:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CMP_CMOV:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_MOVR:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_CSEL_SEL:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_STP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_LDP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_MOV_MASK:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_MEMCPY:
		case INSN_MEMSET:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			d->barrier = true;
			break;
		case INSN_FP_CMP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_CMP_DEST_REG:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_CMP_DEST_REG_TRAP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += 4;
			break;
		case INSN_FP_CMP_UNORDERED_DEST_REG:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_CMP_COND:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_TEST_REG:
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_TO_INT_FLAGS:
			break;
		case INSN_FP_ALU:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_ALU1:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_TO_INT32:
		case INSN_FP_TO_INT64:
		case INSN_FP_FROM_INT32:
		case INSN_FP_FROM_INT64:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_FP_TO_INT64_TRAP:
		case INSN_FP_INT64_TO_INT32_TRAP:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += 4;
			break;
		case INSN_FP_CVT:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_X87_FLD:
		case INSN_X87_FILD:
			ptr += arg_size(*ptr);
			break;
		case INSN_X87_FSTP:
		case INSN_X87_FISTP:
		case INSN_X87_FISTTP:
			ptr += arg_size(*ptr);
			break;
		case INSN_X87_FCOMP:
		case INSN_X87_FCOMPP:
		case INSN_X87_FCOMIP:
			ptr += arg_size(*ptr);
			break;
		case INSN_X87_ALU:
		case INSN_X87_ALUP:
			ptr += arg_size(*ptr);
			break;
		case INSN_X87_FCHS:
		case INSN_X87_FSQRT:
		case INSN_X87_FRNDINT:
			break;
		case INSN_X87_FNSTSW:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_X87_FLDCW:
			ptr += arg_size(*ptr);
			break;
		case INSN_JMP:
			ptr += 4;
			break;
		case INSN_JMP_COND:
		case INSN_JMP_COND_LOGICAL:
			ptr += 4;
			break;
		case INSN_JMP_REG:
			ptr += arg_size(*ptr);
			ptr += 4;
			break;
		case INSN_JMP_REG_BIT:
			ptr += arg_size(*ptr);
			ptr += 4;
			break;
		case INSN_JMP_2REGS:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += 4;
			break;
		case INSN_JMP_FP_TEST:
			ptr += 4;
			break;
		case INSN_JMP_INDIRECT:
			ptr += arg_size(*ptr);
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

static bool attr_w cg_optimize(struct codegen_context *ctx)
{
	if (unlikely(!array_init_mayfail(uint8_t, &ctx->new_code, &ctx->new_code_size, &ctx->err)))
		return false;

	ctx->code_position = ctx->code;

#if 0
	while (ctx->code_position != ctx->code + ctx->code_size) {
		struct insn_details d;
		ajla_assert_lo(ctx->code_position < ctx->code + ctx->code_size, (file_line, "cg_optimize: ran out of code"));
		identify_insn(ctx, ctx->code_position, &d);
		/*debug("insn: %08x, %u", oget_four(ctx->code_position), d.length);*/
		ctx->code_position += d.length;
	}
#endif

	return true;
}
