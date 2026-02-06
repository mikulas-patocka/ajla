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

#define QUASH_INSNS		1
#define MARK_QUASHED_INSNS	0
#define REPORT_QUASHED_INSNS	0

#ifdef DEBUG_INSNS
#define debug_offset		8
#else
#define debug_offset		0
#endif

static bool validate_insn(const struct insn_details *d);
static bool can_be_in_delay_slot(const struct insn_details *d);

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

#define R_FLAGS		(R_MAX + 0)
#define R_X87		(R_MAX + 1)
#define R_MEMORY	(R_MAX + 2)
#define R_MEMORY_FRAME	(R_MAX + 3)
#define R_TOP		(R_MAX + 4)

#if R_TOP <= 0x80 && TYPE_FIXED_N >= 5

typedef uint128_t reg_map;

static inline void reg_map_init(reg_map *rm) { *rm = 0; }
static inline void reg_map_set(reg_map *rm, unsigned reg) { *rm |= (reg_map)1 << reg; }
static inline void reg_map_clear(reg_map *rm, unsigned reg) { *rm &= ~((reg_map)1 << reg); }
static inline bool reg_map_is_set(reg_map rm, unsigned reg) { return (rm >> reg) & 1; }
static inline reg_map reg_map_intersection(reg_map rm1, reg_map rm2) { return rm1 & rm2; }
static inline reg_map reg_map_union(reg_map rm1, reg_map rm2) { return rm1 | rm2; }
static inline reg_map reg_map_neg(reg_map rm) { return ~rm; }
static inline bool reg_map_is_empty(reg_map rm) { return !rm; }

#else

#define map_bits	EFFICIENT_WORD_SIZE
#define map_len		((R_TOP + map_bits - 1) / map_bits)

#define map_typ		cat4(uint,map_bits,_,t)

typedef struct {
	map_typ map[map_len];
} reg_map;

static inline void reg_map_init(reg_map *rm) { memset(rm, 0, sizeof(reg_map)); }
static inline void reg_map_set(reg_map *rm, unsigned reg) { rm->map[reg / map_bits] |= (map_typ)1 << (reg % map_bits); }
static inline void reg_map_clear(reg_map *rm, unsigned reg) { rm->map[reg / map_bits] &= ~((map_typ)1 << (reg % map_bits)); }
static inline bool reg_map_is_set(reg_map rm, unsigned reg) { return (rm.map[reg / map_bits] >> (reg % map_bits)) & 1; }
static inline reg_map reg_map_intersection(reg_map rm1, reg_map rm2)
{
	unsigned i;
	reg_map result;
	for (i = 0; i < map_len; i++)
		result.map[i] = rm1.map[i] & rm2.map[i];
	return result;
}
static inline reg_map reg_map_union(reg_map rm1, reg_map rm2)
{
	unsigned i;
	reg_map result;
	for (i = 0; i < map_len; i++)
		result.map[i] = rm1.map[i] | rm2.map[i];
	return result;
}
static inline reg_map reg_map_neg(reg_map rm)
{
	unsigned i;
	reg_map result;
	for (i = 0; i < map_len; i++)
		result.map[i] = ~rm.map[i];
	return result;
}
static inline bool reg_map_is_empty(reg_map rm)
{
	unsigned i;
	for (i = 0; i < map_len; i++)
		if (rm.map[i])
			return false;
	return true;
}

#endif

#define VALUE_TAG_NONE		0
#define VALUE_TAG_REGISTER	1
#define VALUE_TAG_FRAME		2
#define VALUE_TAG_RANGE		3
#define VALUE_TAG_FLAGS		4

struct value {
	uint8_t tag;
	uint8_t size;
	bool range_signed;
	uint64_t value;
	uint64_t value_hi;
};

struct equality {
	struct value v1;
	struct value v2;
};

struct insn_details {
	uint8_t *start;
	unsigned length;
	uint32_t insn;
	bool barrier;
	bool quash;
	bool mark;
	reg_map rd;
	reg_map wr;
	uint32_t target_label;
	struct value write_frame;
	frame_t rd_frame;
	frame_t wr_frame;
	reg_map live_after;
	reg_map live_before;
};

struct opt_status {
	reg_map regs_volatile;
	reg_map regs_volatile_hacked;
	reg_map regs_saved;
	reg_map regs_common;
	reg_map op_boundary_regs;
	reg_map all_used_regs;
	reg_map jmp_quickret_regs;
};

static bool attr_w setup_register_maps(struct codegen_context *ctx)
{
	frame_t v;
	size_t i;
	unsigned r;
	reg_map all_regs;

	reg_map_init(&all_regs);
	reg_map_set(&all_regs, R_SP);
	reg_map_set(&all_regs, R_FRAME);
#ifdef R_UPCALL
	reg_map_set(&all_regs, R_UPCALL);
#endif
#ifdef R_TIMESTAMP
	reg_map_set(&all_regs, R_TIMESTAMP);
#endif
#ifdef R_ZERO
	reg_map_set(&all_regs, R_ZERO);
#endif
#ifdef R_LR
	reg_map_set(&all_regs, R_LR);
#endif
	reg_map_set(&all_regs, R_SCRATCH_1);
	reg_map_set(&all_regs, R_SCRATCH_2);
	reg_map_set(&all_regs, R_SCRATCH_3);
	reg_map_set(&all_regs, R_SCRATCH_4);
	reg_map_set(&all_regs, R_SAVED_1);
	reg_map_set(&all_regs, R_SAVED_2);
#ifdef R_SCRATCH_NA_1
	reg_map_set(&all_regs, R_SCRATCH_NA_1);
#endif
#ifdef R_SCRATCH_NA_2
	reg_map_set(&all_regs, R_SCRATCH_NA_2);
#endif
#ifdef R_SCRATCH_NA_3
	reg_map_set(&all_regs, R_SCRATCH_NA_3);
#endif
	reg_map_set(&all_regs, R_ARG0);
	reg_map_set(&all_regs, R_ARG1);
	reg_map_set(&all_regs, R_ARG2);
	reg_map_set(&all_regs, R_ARG3);
#ifdef R_ARG4
	reg_map_set(&all_regs, R_ARG4);
#endif
	reg_map_set(&all_regs, R_RET0);
#ifdef R_RET1
	reg_map_set(&all_regs, R_RET1);
#endif
#ifdef R_OFFSET_IMM
	reg_map_set(&all_regs, R_OFFSET_IMM);
#endif
#ifdef R_CONST_IMM
	reg_map_set(&all_regs, R_CONST_IMM);
#endif
#ifdef R_CMP_RESULT
	reg_map_set(&all_regs, R_CMP_RESULT);
#endif
#ifdef R_SCRATCH_B
	reg_map_set(&all_regs, R_SCRATCH_B);
#endif
	reg_map_set(&all_regs, FR_SCRATCH_1);
	reg_map_set(&all_regs, FR_SCRATCH_2);
#ifdef FR_SCRATCH_3
	reg_map_set(&all_regs, FR_SCRATCH_3);
#endif
#ifdef FR_SCRATCH_128_1
	reg_map_set(&all_regs, FR_SCRATCH_128_1);
#endif
#ifdef FR_SCRATCH_128_2
	reg_map_set(&all_regs, FR_SCRATCH_128_2);
#endif
#ifdef FR_SCRATCH_16
	reg_map_set(&all_regs, FR_SCRATCH_16);
#endif
	for (i = 0; i < n_regs_saved + zero; i++)
		reg_map_set(&all_regs, regs_saved[i]);
	for (i = 0; i < n_regs_volatile + zero; i++)
		reg_map_set(&all_regs, regs_volatile[i]);
	for (i = 0; i < n_fp_saved + zero; i++)
		reg_map_set(&all_regs, fp_saved[i]);
	for (i = 0; i < n_fp_volatile + zero; i++) {
		reg_map_set(&all_regs, fp_volatile[i]);
#if defined(ARCH_390)
		if (ctx->a.uses_x)
			reg_map_set(&all_regs, fp_volatile[i] ^ 2);
#endif
	}
#ifdef FR_SCRATCH_128_1
	for (i = 0; i < n_vector_volatile + zero; i++)
		reg_map_set(&all_regs, vector_volatile[i]);
#endif
	reg_map_init(&ctx->opt_status->regs_volatile);
	reg_map_set(&ctx->opt_status->regs_volatile, R_FLAGS);
	reg_map_set(&ctx->opt_status->regs_volatile, R_X87);
	reg_map_init(&ctx->opt_status->regs_saved);
	for (r = 0; r < R_MAX; r++) {
		if (reg_map_is_set(all_regs, r)) {
			if (!reg_is_saved(r))
				reg_map_set(&ctx->opt_status->regs_volatile, r);
			else
				reg_map_set(&ctx->opt_status->regs_saved, r);
		}
	}
	ctx->opt_status->regs_volatile_hacked = ctx->opt_status->regs_volatile;
	for (i = 0; i < n_regs_volatile + zero; i++)
		reg_map_clear(&ctx->opt_status->regs_volatile_hacked, regs_volatile[i]);

	reg_map_init(&ctx->opt_status->regs_common);
	reg_map_set(&ctx->opt_status->regs_common, R_X87);
	reg_map_set(&ctx->opt_status->regs_common, R_MEMORY);
	reg_map_set(&ctx->opt_status->regs_common, R_MEMORY_FRAME);
	reg_map_set(&ctx->opt_status->regs_common, R_FRAME);
	reg_map_set(&ctx->opt_status->regs_common, R_SP);
#ifdef R_UPCALL
	reg_map_set(&ctx->opt_status->regs_common, R_UPCALL);
#endif
#ifdef R_TIMESTAMP
	reg_map_set(&ctx->opt_status->regs_common, R_TIMESTAMP);
#endif
#ifdef R_ZERO
	reg_map_set(&ctx->opt_status->regs_common, R_ZERO);
#endif

	ctx->opt_status->op_boundary_regs = ctx->opt_status->regs_common;
	for (v = MIN_USEABLE_SLOT; v < function_n_variables(ctx->fn); v++) {
		if (slot_is_register(ctx, v)) {
			reg_map_set(&ctx->opt_status->op_boundary_regs, ctx->registers[v]);
#ifdef ARCH_S390
			if (ctx->a.uses_x && reg_is_fp(ctx->registers[v]))
				reg_map_set(&ctx->opt_status->op_boundary_regs, ctx->registers[v] ^ 2);
#endif
		}
	}
	ctx->opt_status->all_used_regs = ctx->opt_status->op_boundary_regs;
	reg_map_set(&ctx->opt_status->all_used_regs, R_SCRATCH_1);
	reg_map_set(&ctx->opt_status->all_used_regs, R_SCRATCH_2);
	reg_map_set(&ctx->opt_status->all_used_regs, R_SCRATCH_3);
	reg_map_set(&ctx->opt_status->all_used_regs, R_SCRATCH_4);
	reg_map_set(&ctx->opt_status->all_used_regs, R_SAVED_1);
	reg_map_set(&ctx->opt_status->all_used_regs, R_SAVED_2);
#ifdef R_SCRATCH_NA_1
	reg_map_set(&ctx->opt_status->all_used_regs, R_SCRATCH_NA_1);
#endif
#ifdef R_SCRATCH_NA_2
	reg_map_set(&ctx->opt_status->all_used_regs, R_SCRATCH_NA_2);
#endif
#ifdef R_SCRATCH_NA_3
	reg_map_set(&ctx->opt_status->all_used_regs, R_SCRATCH_NA_3);
#endif
	reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_1);
	reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_2);
#ifdef ARCH_S390
	if (ctx->a.uses_x) {
		reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_1 + 2);
		reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_2 + 2);
	}
#endif
#ifdef FR_SCRATCH_3
	reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_3);
#endif
#ifdef FR_SCRATCH_16
	reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_16);
#endif
#ifdef FR_SCRATCH_128_1
	reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_128_1);
#endif
#ifdef FR_SCRATCH_128_2
	reg_map_set(&ctx->opt_status->all_used_regs, FR_SCRATCH_128_2);
#endif
	reg_map_set(&ctx->opt_status->all_used_regs, R_ARG0);
	reg_map_set(&ctx->opt_status->all_used_regs, R_ARG1);
	reg_map_set(&ctx->opt_status->all_used_regs, R_ARG2);
	reg_map_set(&ctx->opt_status->all_used_regs, R_ARG3);
#ifdef R_ARG4
	reg_map_set(&ctx->opt_status->all_used_regs, R_ARG4);
#endif
	reg_map_set(&ctx->opt_status->all_used_regs, R_RET0);
#ifdef R_RET1
	reg_map_set(&ctx->opt_status->all_used_regs, R_RET1);
#endif

	ctx->opt_status->jmp_quickret_regs = ctx->opt_status->regs_common;
	if (ctx->quickret_regs_valid) {
		for (i = 0; i < da(ctx->fn,function)->n_return_values; i++)
			reg_map_set(&ctx->opt_status->jmp_quickret_regs, ctx->quickret_regs[i]);
	}

	return true;
}

static unsigned arg_common(struct insn_details *d, uint8_t *ptr)
{
	if (ptr[0] >= ARG_SHIFTED_REGISTER && ptr[0] <= ARG_EXTENDED_REGISTER) {
		reg_map_set(&d->rd, ptr[2]);
		return 3;
	}
	if (ptr[0] == ARG_ADDRESS_0) {
		return 9;
	}
	if (ptr[0] >= ARG_ADDRESS_1 && ptr[0] <= ARG_ADDRESS_1_8) {
		reg_map_set(&d->rd, ptr[1]);
		return 10;
	}
	if (ptr[0] >= ARG_ADDRESS_1_PRE_I && ptr[0] <= ARG_ADDRESS_1_POST_I) {
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
	internal(file_line, "arg_common: invalid argument %02x", ptr[0]);
	return 0;
}

static frame_t is_slot(struct codegen_context *ctx, uint8_t *ptr, unsigned size)
{
	if (unlikely(size > 1U << OP_SIZE_SLOT))
		return 0;
	if (ptr[0] == ARG_ADDRESS_1 && ptr[1] == R_FRAME) {
		const struct type *type;
		uint64_t off, slot;
		off = oget_eight(ptr + 2);
		if (unlikely(off & ((1U << OP_SIZE_SLOT) - 1)))
			return 0;
		slot = off >> OP_SIZE_SLOT;
		if (unlikely(slot < ctx->min_slot) || unlikely(slot >= function_n_variables(ctx->fn)))
			return 0;
		type = da(ctx->fn,function)->local_variables[slot].type;
		if (unlikely(!type))
			return 0;
		if (unlikely(type->size != size))
			return 0;
		return slot;
	}
	return 0;
}

static unsigned arg_read(struct codegen_context *ctx, struct insn_details *d, uint8_t *ptr, unsigned size)
{
	if (ptr[0] < ARG_REGS_MAX) {
		reg_map_set(&d->rd, ptr[0]);
#ifdef ARCH_S390
		if (reg_is_fp(ptr[0]) && insn_op_size(d->insn) == OP_SIZE_16)
			reg_map_set(&d->rd, ptr[0] + 2);
#endif
		return 1;
	}
	if (ptr[0] != ARG_IMM) {
		frame_t slot = is_slot(ctx, ptr, size);
		if (slot && !d->rd_frame) {
			d->rd_frame = slot;
			goto just_frame;
		}
		reg_map_set(&d->rd, R_MEMORY);
just_frame:
		reg_map_set(&d->rd, R_MEMORY_FRAME);
	}
	return arg_common(d, ptr);
}

static unsigned arg_write(struct codegen_context *ctx, struct insn_details *d, uint8_t *ptr, unsigned size)
{
	if (ptr[0] < ARG_REGS_MAX) {
		reg_map_set(&d->wr, ptr[0]);
#ifdef ARCH_S390
		if (reg_is_fp(ptr[0]) && insn_op_size(d->insn) == OP_SIZE_16)
			reg_map_set(&d->wr, ptr[0] + 2);
#endif
		return 1;
	}
	if (ptr[0] == ARG_ADDRESS_1 && ptr[1] == R_FRAME && size <= 255) {
		frame_t slot;
		d->write_frame.tag = VALUE_TAG_FRAME;
		d->write_frame.size = size;
		d->write_frame.value = oget_eight(ptr + 2);
		slot = is_slot(ctx, ptr, size);
		if (slot && !d->wr_frame) {
			d->wr_frame = slot;
			goto just_frame;
		}
	}
	reg_map_set(&d->rd, R_MEMORY);
	reg_map_set(&d->wr, R_MEMORY);
just_frame:
	reg_map_set(&d->rd, R_MEMORY_FRAME);
	reg_map_set(&d->wr, R_MEMORY_FRAME);
	return arg_common(d, ptr);
}

static unsigned arg_jmp(struct insn_details *d, uint8_t *ptr)
{
	d->target_label = oget_four(ptr);
	return 4;
}

static unsigned op_size_to_size(unsigned op_size)
{
	if (op_size == OP_SIZE_10)
		return 10;
	else
		return 1U << op_size;
}

static void identify_insn(struct codegen_context *ctx, uint8_t *ptr, struct insn_details *d)
{
	uint32_t insn;
	unsigned attr_unused i;
	unsigned size;

#ifdef DEBUG_INSNS
	insn = oget_four(ptr);
	debug("line: %u/%u (seq %x)", insn >> 24, insn & 0x00FFFFFFU, oget_four(ptr + 4));
	ptr += 8;
#endif
	memset(d, 0, sizeof(struct insn_details));
	insn = oget_four(ptr);

	d->start = ptr;
	d->insn = insn;

	ptr += 4;

	size = op_size_to_size(insn_op_size(insn));

	if (insn_writes_flags(insn))
		reg_map_set(&d->wr, R_FLAGS);

	switch (insn_opcode(insn)) {
		uint32_t label_id;
		unsigned r1, r2;
		case INSN_LABEL:
			label_id = oget_four(ptr);
			ptr += 4;
			d->barrier = !!(ctx->label_flags[label_id] & LABEL_USED);
			if (d->barrier) {
				if (ctx->label_flags[label_id] & LABEL_OP_BOUNDARY)
					d->rd = ctx->opt_status->op_boundary_regs;
				else
					d->rd = ctx->opt_status->all_used_regs;
			}
			break;
		case INSN_CLAIM_RANGE:
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			ptr += arg_size(*ptr);
			break;
		case INSN_NOP:
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY);
			reg_map_set(&d->rd, R_MEMORY_FRAME);
			reg_map_set(&d->wr, R_MEMORY_FRAME);
			break;
		case INSN_RET:
			d->rd = ctx->opt_status->regs_saved;
			reg_map_set(&d->rd, R_RET0);
#ifdef R_RET1
			reg_map_set(&d->rd, R_RET1);
#endif
#ifdef R_LR
			reg_map_set(&d->rd, R_LR);
#endif
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->rd, R_MEMORY_FRAME);
			d->barrier = true;
			break;
#ifdef ARCH_ARM32
		case INSN_ARM_PUSH:
			reg_map_set(&d->rd, R_2);
			reg_map_set(&d->rd, R_4);
			reg_map_set(&d->rd, R_5);
			reg_map_set(&d->rd, R_6);
			reg_map_set(&d->rd, R_7);
			reg_map_set(&d->rd, R_8);
			reg_map_set(&d->rd, R_9);
			reg_map_set(&d->rd, R_10);
			reg_map_set(&d->rd, R_FP);
			reg_map_set(&d->rd, R_LR);
			reg_map_set(&d->rd, R_SP);
			reg_map_set(&d->wr, R_SP);
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY);
			break;
		case INSN_ARM_POP:
			reg_map_set(&d->rd, R_RET0);
			reg_map_set(&d->rd, R_RET1);
			reg_map_set(&d->rd, R_SP);
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->rd, R_MEMORY_FRAME);
			d->barrier = true;
			break;
#endif
#ifdef ARCH_S390
		case INSN_S390_PUSH: {
			unsigned r;
			ptr += arg_write(ctx, d, ptr, size * (R_15 - insn_aux(insn) + 1));
			for (r = insn_aux(insn); r <= R_15; r++)
				reg_map_set(&d->rd, r);
			break;
		}
		case INSN_S390_POP: {
			unsigned r;
			ptr += arg_read(ctx, d, ptr, size * (R_15 - insn_aux(insn) + 1));
			for (r = insn_aux(insn); r <= R_15; r++)
				reg_map_set(&d->wr, r);
			break;
		}
#endif
		case INSN_IA64_ALLOC:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, 0);
			ptr += arg_read(ctx, d, ptr, 0);
			d->rd = reg_map_union(d->rd, ctx->opt_status->regs_volatile);
			d->wr = reg_map_union(d->wr, ctx->opt_status->regs_volatile);
			d->rd = reg_map_union(d->rd, ctx->opt_status->regs_saved);
			d->wr = reg_map_union(d->wr, ctx->opt_status->regs_saved);
			break;
		case INSN_IA64_DEALLOC:
			ptr += arg_read(ctx, d, ptr, size);
			d->rd = reg_map_union(d->rd, ctx->opt_status->regs_volatile);
			d->wr = reg_map_union(d->wr, ctx->opt_status->regs_volatile);
			d->rd = reg_map_union(d->rd, ctx->opt_status->regs_saved);
			d->wr = reg_map_union(d->wr, ctx->opt_status->regs_saved);
			break;
		case INSN_PUSH:
			ptr += arg_read(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_SP);
			reg_map_set(&d->wr, R_SP);
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY);
			break;
		case INSN_PUSH2:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_SP);
			reg_map_set(&d->wr, R_SP);
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY);
			break;
		case INSN_POP:
			ptr += arg_write(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_SP);
			reg_map_set(&d->wr, R_SP);
			reg_map_set(&d->rd, R_MEMORY);
			break;
		case INSN_POP2:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_write(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_SP);
			reg_map_set(&d->wr, R_SP);
			reg_map_set(&d->rd, R_MEMORY);
			break;
		case INSN_CALL:
			ptr += 4;
#ifdef ARCH_PARISC
			reg_map_set(&d->rd, R_22);
			reg_map_set(&d->wr, R_22);
			reg_map_set(&d->wr, R_19);
#endif
			goto do_call;
		case INSN_CALL_INDIRECT:
			ptr += arg_read(ctx, d, ptr, size);
do_call:
			if (insn_aux(insn)) {
#ifdef ARCH_X86
				reg_map_set(&d->rd, R_DX);
				reg_map_set(&d->rd, R_CX);
				reg_map_set(&d->rd, R_AX);
#endif
			} else {
				reg_map_set(&d->rd, R_ARG0);
				reg_map_set(&d->rd, R_ARG1);
				reg_map_set(&d->rd, R_ARG2);
				reg_map_set(&d->rd, R_ARG3);
			}
			reg_map_set(&d->rd, R_SP);
			reg_map_set(&d->wr, R_SP);
			reg_map_set(&d->wr, R_RET0);
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY);
			reg_map_set(&d->rd, R_MEMORY_FRAME);
			reg_map_set(&d->wr, R_MEMORY_FRAME);
			if (insn_aux(insn))
				d->wr = reg_map_union(d->wr, ctx->opt_status->regs_volatile_hacked);
			else
				d->wr = reg_map_union(d->wr, ctx->opt_status->regs_volatile);
			break;
		case INSN_MOV:
		case INSN_MOVSX:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_MOV_U:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_MOV_LR:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CMP:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CMP_DEST_REG:
			ptr += arg_write(ctx, d, ptr, 1U << OP_SIZE_NATIVE);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CMN:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_TEST:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_TEST_DEST_REG:
			ptr += arg_write(ctx, d, ptr, 1U << OP_SIZE_NATIVE);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_ALU:
		case INSN_ALU_PARTIAL:
			if (unlikely(insn_aux(insn) == ALU_ADC) || unlikely(insn_aux(insn) == ALU_SBB))
				reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			r1 = ptr[0];
			r2 = ptr[1];
			if (insn_opcode(insn) == INSN_ALU && r1 < ARG_REGS_MAX && r2 < ARG_REGS_MAX && r1 == r2 && (
					insn_aux(insn) == ALU_XOR ||
					unlikely(insn_aux(insn) == ALU_SUB) ||
					unlikely(insn_aux(insn) == ALU_SBB) ||
					unlikely(insn_aux(insn) == ALU_ANDN))) {
				ptr += 2;
				goto skip_reads;
			}
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
skip_reads:
			break;
		case INSN_ALU_TRAP:
			if (unlikely(insn_aux(insn) == ALU_ADC) || unlikely(insn_aux(insn) == ALU_SBB))
				reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += 4;
			break;
		case INSN_ALU1:
		case INSN_ALU1_PARTIAL:
			if (unlikely(insn_aux(insn) == ALU1_NGC))
				reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_ALU1_TRAP:
			if (unlikely(insn_aux(insn) == ALU1_NGC))
				reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += 4;
			break;
		case INSN_LEA3:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_ROT:
		case INSN_ROT_PARTIAL:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_SHD:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_BT:
			ptr += arg_read(ctx, d, ptr, -1);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_BTX:
			ptr += arg_write(ctx, d, ptr, -1);
			ptr += arg_read(ctx, d, ptr, -1);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_MUL_L:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_DIV_L:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_MADD:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CBW:
		case INSN_CBW_PARTIAL:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CWD:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CWD_PARTIAL:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_SET_COND:
			reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			break;
		case INSN_SET_COND_PARTIAL:
			reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CMOV:
		case INSN_CMOV_XCC:
			reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CMP_CMOV:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_MOVR:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_CSEL_SEL:
		case INSN_CSEL_INC:
		case INSN_CSEL_INV:
		case INSN_CSEL_NEG:
			reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_STP:
			ptr += arg_write(ctx, d, ptr, size * 2);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_LDP:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size * 2);
			break;
		case INSN_MOV_MASK:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_MEMCPY:
		case INSN_MEMSET:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->rd, R_MEMORY_FRAME);
			reg_map_set(&d->wr, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY_FRAME);
			break;
		case INSN_FP_CMP:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_CMP_DEST_REG:
			ptr += arg_write(ctx, d, ptr, 1U << OP_SIZE_NATIVE);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_CMP_DEST_REG_TRAP:
			ptr += arg_write(ctx, d, ptr, 1U << OP_SIZE_NATIVE);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += 4;
			break;
		case INSN_FP_CMP_UNORDERED_DEST_REG:
			ptr += arg_write(ctx, d, ptr, 1U << OP_SIZE_NATIVE);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_CMP_COND:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_TEST_REG:
			reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, size);
			break;
		case INSN_FP_TO_INT_FLAGS:
			reg_map_set(&d->rd, R_FLAGS);
			break;
		case INSN_FP_ALU:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_ALU1:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_TO_INT32:
			ptr += arg_write(ctx, d, ptr, 4);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_TO_INT64:
			ptr += arg_write(ctx, d, ptr, 8);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_FP_FROM_INT32:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, 4);
			break;
		case INSN_FP_FROM_INT64:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, 8);
			break;
		case INSN_FP_TO_INT64_TRAP:
			ptr += arg_write(ctx, d, ptr, 8);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += 4;
			break;
		case INSN_FP_INT64_TO_INT32_TRAP:
			ptr += arg_write(ctx, d, ptr, 4);
			ptr += arg_read(ctx, d, ptr, 8);
			ptr += 4;
			break;
		case INSN_FP_CVT:
			ptr += arg_write(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			break;
		case INSN_X87_FLD:
		case INSN_X87_FILD:
			ptr += arg_read(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			break;
		case INSN_X87_FSTP:
		case INSN_X87_FISTP:
		case INSN_X87_FISTTP:
			ptr += arg_write(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			break;
		case INSN_X87_FCOMP:
		case INSN_X87_FCOMPP:
			ptr += arg_read(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			break;
		case INSN_X87_FCOMIP:
			ptr += arg_read(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			reg_map_set(&d->wr, R_FLAGS);
			break;
		case INSN_X87_ALU:
		case INSN_X87_ALUP:
			ptr += arg_read(ctx, d, ptr, size);
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			break;
		case INSN_X87_FCHS:
		case INSN_X87_FSQRT:
		case INSN_X87_FRNDINT:
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			break;
		case INSN_X87_FNSTSW:
			reg_map_set(&d->rd, R_FLAGS);
			ptr += arg_write(ctx, d, ptr, 2);
			ptr += arg_read(ctx, d, ptr, 2);
			reg_map_set(&d->rd, R_X87);
			break;
		case INSN_X87_FLDCW:
			ptr += arg_read(ctx, d, ptr, 2);
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			break;
		case INSN_JMP:
			ptr += arg_jmp(d, ptr);
			break;
		case INSN_JMP_COND:
		case INSN_JMP_COND_LOGICAL:
			ptr += arg_jmp(d, ptr);
			reg_map_set(&d->rd, R_FLAGS);
			break;
		case INSN_JMP_REG:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_jmp(d, ptr);
			break;
		case INSN_JMP_REG_BIT:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_jmp(d, ptr);
			break;
		case INSN_JMP_2REGS:
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_read(ctx, d, ptr, size);
			ptr += arg_jmp(d, ptr);
			break;
		case INSN_JMP_FP_TEST:
			ptr += arg_jmp(d, ptr);
			reg_map_set(&d->rd, R_FLAGS);
			break;
		case INSN_JMP_INDIRECT:
			ptr += arg_read(ctx, d, ptr, size);
			if (insn_aux(insn))
				d->rd = reg_map_union(d->rd, ctx->opt_status->jmp_quickret_regs);
			else
				d->rd = reg_map_union(d->rd, ctx->opt_status->regs_common);
			d->barrier = true;
			break;
#if defined(ARCH_X86)
		case INSN_VZEROUPPER:
			for (i = 0; i < 16; i++) {
				reg_map_set(&d->rd, R_XMM0 + i);
				reg_map_set(&d->wr, R_XMM0 + i);
			}
			reg_map_set(&d->rd, R_X87);
			reg_map_set(&d->wr, R_X87);
			break;
#endif
		case INSN_MB:
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY);
			break;
		case INSN_STOP_BIT:
			reg_map_set(&d->rd, R_MEMORY);
			reg_map_set(&d->wr, R_MEMORY);
			reg_map_set(&d->rd, R_MEMORY_FRAME);
			reg_map_set(&d->wr, R_MEMORY_FRAME);
			d->rd = reg_map_union(d->rd, ctx->opt_status->regs_volatile);
			d->wr = reg_map_union(d->wr, ctx->opt_status->regs_volatile);
			d->rd = reg_map_union(d->rd, ctx->opt_status->regs_saved);
			d->wr = reg_map_union(d->wr, ctx->opt_status->regs_saved);
			break;
		case INSN_CALL_MILLICODE:
			d->barrier = true;
			break;
		default:
			internal(file_line, "identify_insn: invalid insn %08lx", (unsigned long)insn);
	}
	d->length = ptr - d->start;
}

static bool can_be_in_delay_slot(const struct insn_details *d)
{
	switch (insn_opcode(d->insn)) {
		case INSN_LABEL:
		case INSN_CLAIM_RANGE:
		case INSN_RET:
		case INSN_CALL:
		case INSN_CALL_INDIRECT:
		case INSN_ALU_TRAP:
		case INSN_ALU1_TRAP:
		case INSN_FP_CMP_DEST_REG_TRAP:
		case INSN_FP_TO_INT64_TRAP:
		case INSN_FP_INT64_TO_INT32_TRAP:
		case INSN_JMP:
		case INSN_JMP_COND:
		case INSN_JMP_COND_LOGICAL:
		case INSN_JMP_REG:
		case INSN_JMP_REG_BIT:
		case INSN_JMP_2REGS:
		case INSN_JMP_FP_TEST:
		case INSN_JMP_INDIRECT:
		case INSN_CALL_MILLICODE:
			return false;
	}
	return true;
}

static bool attr_w prepare_new_insn(struct codegen_context *ctx)
{
	ctx->new_insn_mark = ctx->new_code_size;

	return true;
}

static bool attr_w finish_new_insn(struct codegen_context *ctx, struct insn_details *d)
{
	size_t len = ctx->new_code_size - ctx->new_insn_mark;
	uint8_t *new_insn;
	void *err_ptr;

	new_insn = mem_alloc_mayfail(uint8_t *, len, &ctx->err);
	if (unlikely(!new_insn))
		return false;

	memcpy(new_insn, ctx->new_code + ctx->new_insn_mark, len);
	ctx->new_code_size = ctx->new_insn_mark;

	if (!unlikely(array_add_mayfail(uint8_t *, &ctx->new_insns, &ctx->new_insns_size, new_insn, &err_ptr, &ctx->err))) {
		ctx->new_insns = err_ptr;
		mem_free(new_insn);
		return false;
	}

	identify_insn(ctx, new_insn, d);

	return true;
}

static bool arg_to_val(struct insn_details *d, uint8_t *ptr, struct value *value)
{
	if (ptr[0] < ARG_REGS_MAX) {
		value->tag = VALUE_TAG_REGISTER;
		value->size = op_size_to_size(insn_op_size(d->insn));
		value->range_signed = false;
		value->value = ptr[0];
		value->value_hi = value->value;
		return true;
	}
	if (ptr[0] == ARG_ADDRESS_1 && ptr[1] == R_FRAME) {
		value->tag = VALUE_TAG_FRAME;
		value->size = op_size_to_size(insn_op_size(d->insn));
		value->range_signed = false;
		value->value = oget_eight(ptr + 2);
		value->value_hi = value->value;
		return true;
	}
	if (ptr[0] == ARG_IMM) {
		value->tag = VALUE_TAG_RANGE;
		value->size = op_size_to_size(insn_op_size(d->insn));
		value->range_signed = false;
		value->value = oget_eight(ptr + 1);
		value->value_hi = value->value;
		return true;
	}
	return false;
}

static bool attr_w val_to_arg(struct codegen_context *ctx, struct value *v)
{
	switch (v->tag) {
		case VALUE_TAG_REGISTER:
			gen_one(v->value);
			return true;
		case VALUE_TAG_FRAME:
			gen_one(ARG_ADDRESS_1);
			gen_one(R_FRAME);
			gen_eight(v->value);
			return true;
		case VALUE_TAG_RANGE:
			if (unlikely(v->value != v->value_hi))
				internal(file_line, "val_to_arg: invalid range");
			gen_one(ARG_IMM);
			gen_eight(v->value);
			return true;
	}
	internal(file_line, "val_to_arg: invalid tag %u", v->tag);
	return false;
}

static bool compare_values(const struct value *v1, const struct value *v2)
{
	/*if (v1->tag == v2->tag && v1->size != v2->size && v1->value == v2->value && v1->value_hi == v2->value_hi) debug("size: %u, %u", v1->size, v2->size);*/
	return v1->tag == v2->tag && v1->size == v2->size && v1->value == v2->value && v1->value_hi == v2->value_hi;
}

static bool search_equalities(struct codegen_context *ctx, const struct equality *eq)
{
	size_t i;
	for (i = 0; i < ctx->equalities_used; i++) {
		struct equality *e = &ctx->equalities[i];
		if (compare_values(&e->v1, &eq->v1) && compare_values(&e->v2, &eq->v2))
			return true;
		if (compare_values(&e->v1, &eq->v2) && compare_values(&e->v2, &eq->v1))
			return true;
	}
	return false;
}

static bool test_subrange(struct value *v1, struct value *v2)
{
	if (v1->tag != VALUE_TAG_RANGE || v2->tag != VALUE_TAG_RANGE) {
		return false;
	}
	if ((int64_t)v1->value >= 0 && (int64_t)v2->value >= 0) {
		return v1->value >= v2->value && v1->value_hi <= v2->value_hi;
	}
	if (v1->range_signed && v2->range_signed) {
		return (int64_t)v1->value >= (int64_t)v2->value && (int64_t)v1->value_hi <= (int64_t)v2->value_hi;
	}
	if (!v1->range_signed && !v2->range_signed) {
		return v1->value >= v2->value && v1->value_hi <= v2->value_hi;
	}
	if (!v1->range_signed && v2->range_signed && (int64_t)v2->value_hi >= 0) {
		return v1->value_hi <= v2->value_hi;
	}
	return false;
}

static bool is_in_range(struct codegen_context *ctx, struct value *reg, struct value *range, unsigned depth)
{
	size_t i;
	/*debug("is_in_range(%u) %x %x %x %lx-%lx - %x %x %x %lx-%lx", depth, reg->tag, reg->size, reg->range_signed, reg->value, reg->value_hi, range->tag, range->size, range->range_signed, range->value, range->value_hi);*/
	for (i = 0; i < ctx->equalities_used; i++) {
		struct equality *eq = &ctx->equalities[i];
		/*debug("testing equality %x %x %x %lx-%lx - %x %x %x %lx-%lx", eq->v1.tag, eq->v1.size, eq->v1.range_signed, eq->v1.value, eq->v1.value_hi, eq->v2.tag, eq->v2.size, eq->v2.range_signed, eq->v2.value, eq->v2.value_hi);*/
		if (compare_values(&eq->v1, reg)) {
			if (depth < 1 && eq->v2.tag == VALUE_TAG_REGISTER) {
				if (is_in_range(ctx, &eq->v2, range, depth + 1))
					return true;
			}
			if (test_subrange(&eq->v2, range))
				return true;
		}
		if (compare_values(&eq->v2, reg)) {
			if (depth < 1 && eq->v1.tag == VALUE_TAG_REGISTER) {
				if (is_in_range(ctx, &eq->v1, range, depth + 1))
					return true;
			}
			if (test_subrange(&eq->v1, range))
				return true;
		}
	}
	return false;
}

static bool check_interference(struct insn_details *d, struct value *v)
{
	uintptr_t s1, e1, s2, e2;
	switch (v->tag) {
		case VALUE_TAG_NONE:
			return false;
		case VALUE_TAG_REGISTER:
			return reg_map_is_set(d->wr, v->value);
		case VALUE_TAG_FRAME:
			if (!reg_map_is_set(d->wr, R_MEMORY_FRAME))
				return false;
			if (unlikely(d->write_frame.tag != VALUE_TAG_FRAME))
				return true;
			s1 = (uintptr_t)d->write_frame.value;
			e1 = (uintptr_t)d->write_frame.value + d->write_frame.size;
			s2 = (uintptr_t)v->value;
			e2 = (uintptr_t)v->value + v->size;
			return !(s1 >= e2 || s2 >= e1);
		case VALUE_TAG_RANGE:
			return false;
		case VALUE_TAG_FLAGS:
			return reg_map_is_set(d->wr, R_FLAGS);
		default:
			internal(file_line, "check_interference: invalid tag %u", v->tag);
	}
}

static void quash_equalities(struct codegen_context *ctx, struct insn_details *d)
{
	size_t i;
	for (i = 0; i < ctx->equalities_used; i++) {
		struct equality *eq = &ctx->equalities[i];
		if (check_interference(d, &eq->v1) ||
		    check_interference(d, &eq->v2)) {
			/*debug("deleting equality %x %x %x %lx-%lx - %x %x %x %lx-%lx", eq->v1.tag, eq->v1.size, eq->v1.range_signed, eq->v1.value, eq->v1.value_hi, eq->v2.tag, eq->v2.size, eq->v2.range_signed, eq->v2.value, eq->v2.value_hi);*/
			eq->v1.tag = VALUE_TAG_NONE;
			eq->v2.tag = VALUE_TAG_NONE;
			continue;
		}
	}
}

static struct value *find_range(struct codegen_context *ctx, struct value *v1)
{
	size_t i;
	for (i = 0; i < ctx->equalities_used; i++) {
		struct equality *e = &ctx->equalities[i];
		if (e->v2.tag == VALUE_TAG_RANGE && compare_values(&e->v1, v1))
			return &e->v2;
	}
	return NULL;
}

static struct value *find_equality(struct codegen_context *ctx, struct value *v1)
{
	size_t i;
	struct value *val;
	for (i = 0; i < ctx->equalities_used; i++) {
		struct equality *e = &ctx->equalities[i];
		if (e->v2.tag != VALUE_TAG_NONE && compare_values(&e->v1, v1)) {
			val = &e->v2;
			goto found;
		}
		if (e->v1.tag != VALUE_TAG_NONE && compare_values(&e->v2, v1)) {
			val = &e->v1;
found:
			if (val->tag == VALUE_TAG_RANGE && val->value != val->value_hi)
				continue;
			return val;
		}
	}
	return NULL;
}

static bool attr_w insert_equality(struct codegen_context *ctx, struct equality *eq)
{
	size_t i;
	if (unlikely(compare_values(&eq->v1, &eq->v2)))
		return true;
	/*debug("inserting equality %x %x %x %lx-%lx - %x %x %x %lx-%lx", eq->v1.tag, eq->v1.size, eq->v1.range_signed, eq->v1.value, eq->v1.value_hi, eq->v2.tag, eq->v2.size, eq->v2.range_signed, eq->v2.value, eq->v2.value_hi);*/
	for (i = 0; i < ctx->equalities_used; i++) {
		if (ctx->equalities[i].v1.tag == VALUE_TAG_NONE) {
			ctx->equalities[i] = *eq;
			return true;
		}
	}
	if (likely(ctx->equalities_used < ctx->equalities_size)) {
		ctx->equalities[ctx->equalities_used++] = *eq;
		return true;
	}
	if (!unlikely(array_add_mayfail(struct equality, &ctx->equalities, &ctx->equalities_size, *eq, NULL, &ctx->err)))
		return false;
	ctx->equalities_used = ctx->equalities_size;
	return true;
}

static bool attr_w equality_analysis(struct codegen_context *ctx)
{
	struct equality eq, rng;
	struct value value;
	struct value *rp;
	size_t i;
	ctx->equalities_used = 0;
	for (i = 0; i < ctx->basic_block_position; i++) {
		struct insn_details *d = &ctx->basic_block[i];
		if (d->quash)
			continue;
		switch (insn_opcode(d->insn)) {
		case INSN_CLAIM_RANGE: {
			uint8_t *pd = d->start + 4;
			uint8_t *low = pd + arg_size(*pd);
			uint8_t *high = low + arg_size(*low);
			if (!arg_to_val(d, pd, &rng.v1))
				goto skip;
			if (*low != ARG_IMM || *high != ARG_IMM)
				goto skip;
			if (!arg_to_val(d, low, &eq.v1))
				goto skip;
			if (!arg_to_val(d, high, &eq.v2))
				goto skip;
			rng.v2.tag = VALUE_TAG_RANGE;
			rng.v2.size = op_size_to_size(insn_op_size(d->insn));
			rng.v2.range_signed = false;
			rng.v2.value = eq.v1.value;
			rng.v2.value_hi = eq.v2.value;
			g(insert_equality(ctx, &rng));
			continue;
		}
		case INSN_MOV:
		case INSN_MOVSX: {
			bool eq_valid = false;
			bool rng_valid = false;
			uint8_t *pd = d->start + 4;
			uint8_t *ps = pd + arg_size(*pd);
			bool is_fp = reg_is_fp(*pd) || reg_is_fp(*ps);
			if (!arg_to_val(d, pd, &eq.v1))
				goto skip;
			eq_valid = arg_to_val(d, ps, &eq.v2);
			if (likely(!is_fp) && insn_op_size(d->insn) != OP_SIZE_NATIVE && eq.v1.tag == VALUE_TAG_REGISTER) {
				rng.v1 = eq.v1;
				rng.v1.size = op_size_to_size(OP_SIZE_NATIVE);
				rng.v2.tag = VALUE_TAG_RANGE;
				rng.v2.size = op_size_to_size(OP_SIZE_NATIVE);
				rng.v2.range_signed = false;
				rng.v2.value = 0;
				rng.v2.value_hi = ((uint64_t)1 << (8 << insn_op_size(d->insn))) - 1;
				if (insn_opcode(d->insn) == INSN_MOVSX) {
					rng.v2.range_signed = true;
					rng.v2.value_hi >>= 1;
					rng.v2.value = ~rng.v2.value_hi;
				}
				rng_valid = true;
				value = eq.v2;
				value.size = op_size_to_size(OP_SIZE_NATIVE);
				if (eq_valid && is_in_range(ctx, &value, &rng.v2, 0)) {
					if (*pd < ARG_REGS_MAX && *ps == *pd) {
						d->quash = true;
						if (REPORT_QUASHED_INSNS)
							debug("quashing extension");
						continue;
					}
					eq.v1.size = op_size_to_size(OP_SIZE_NATIVE);
					eq.v2.size = op_size_to_size(OP_SIZE_NATIVE);
				} else {
					goto dont_quash_mov;
				}
			}
			if (eq_valid && search_equalities(ctx, &eq)) {
				d->quash = true;
				if (REPORT_QUASHED_INSNS)
					debug("quashing mov due to equality");
				continue;
			}
dont_quash_mov:
			if (eq_valid) {
				rp = find_equality(ctx, &eq.v2);
				if (rp) {
					struct insn_details nd;
					g(prepare_new_insn(ctx));
					gen_insn(insn_opcode(d->insn), insn_op_size(d->insn), 0, 0);
					gen_stream(pd, arg_size(*pd));
					g(val_to_arg(ctx, rp));
					/*g(val_to_arg(ctx, &eq.v2));*/
					g(finish_new_insn(ctx, &nd));
					if (nd.length <= d->length && validate_insn(&nd)) {
						*d = nd;
					}
				}
			}
			quash_equalities(ctx, d);
			if (eq_valid)
				g(insert_equality(ctx, &eq));
			if (rng_valid)
				g(insert_equality(ctx, &rng));
			continue;
		}
		case INSN_CMP: {
			uint8_t *ps1 = d->start + 4;
			uint8_t *ps2 = ps1 + arg_size(*ps1);
			if (!arg_to_val(d, ps1, &eq.v1))
				goto skip;
			if (*ps2 == ARG_IMM) {
				uint64_t val = oget_eight(ps2 + 1);
				if (eq.v1.tag == VALUE_TAG_REGISTER)
					eq.v1.size = op_size_to_size(OP_SIZE_NATIVE);
				if (!val) {
					rng.v2.tag = VALUE_TAG_RANGE;
					rng.v2.size = eq.v1.size;
					rng.v2.range_signed = false;
					rng.v2.value = 0;
					rng.v2.value_hi = 0;
					if (is_in_range(ctx, &eq.v1, &rng.v2, 0)) {
						quash_equalities(ctx, d);
						rng.v1.tag = VALUE_TAG_FLAGS;
						rng.v1.size = 0;
						rng.v1.range_signed = false;
						rng.v1.value = 0;
						rng.v1.value_hi = 0;
						rng.v2.tag = VALUE_TAG_RANGE;
						rng.v2.size = 0;
						rng.v2.range_signed = false;
						rng.v2.value = (1ULL << COND_E) | (1ULL << COND_NE);
						rng.v2.value_hi = 1ULL << COND_E;
						g(insert_equality(ctx, &rng));
						continue;
					}
					goto skip;
				}
				rng.v2.tag = VALUE_TAG_RANGE;
				rng.v2.size = eq.v1.size;
				rng.v2.range_signed = false;
				rng.v2.value = 0;
				rng.v2.value_hi = val - 1;
				if (is_in_range(ctx, &eq.v1, &rng.v2, 0)) {
					quash_equalities(ctx, d);
					rng.v1.tag = VALUE_TAG_FLAGS;
					rng.v1.size = 0;
					rng.v1.range_signed = false;
					rng.v1.value = 0;
					rng.v1.value_hi = 0;
					rng.v2.tag = VALUE_TAG_RANGE;
					rng.v2.size = 0;
					rng.v2.range_signed = false;
					rng.v2.value = (1ULL << COND_B) | (1ULL << COND_AE);
					rng.v2.value_hi = 1ULL << COND_B;
					g(insert_equality(ctx, &rng));
					continue;
				}
			}
			if (!arg_to_val(d, ps2, &eq.v2))
				goto skip;
			quash_equalities(ctx, d);
			if (search_equalities(ctx, &eq)) {
				rng.v1.tag = VALUE_TAG_FLAGS;
				rng.v1.size = 0;
				rng.v1.range_signed = false;
				rng.v1.value = 0;
				rng.v1.value_hi = 0;
				rng.v2.tag = VALUE_TAG_RANGE;
				rng.v2.size = 0;
				rng.v2.range_signed = false;
				rng.v2.value = (1ULL << COND_E) | (1ULL << COND_NE);
				rng.v2.value_hi = 1ULL << COND_E;
				g(insert_equality(ctx, &rng));
			}
			continue;
		}
		case INSN_ALU: {
			uint8_t *pd = d->start + 4;
			uint8_t *ps1 = pd + arg_size(*pd);
			uint8_t *ps2 = ps1 + arg_size(*ps1);
			if (insn_aux(d->insn) == ALU_XOR && *ps2 == ARG_IMM && oget_eight(ps2 + 1) == 1) {
				if (!arg_to_val(d, pd, &eq.v1))
					goto skip;
				if (!arg_to_val(d, ps1, &eq.v2))
					goto skip;
				if (eq.v1.tag == VALUE_TAG_REGISTER)
					eq.v1.size = op_size_to_size(OP_SIZE_NATIVE);
				if (eq.v2.tag == VALUE_TAG_REGISTER)
					eq.v2.size = op_size_to_size(OP_SIZE_NATIVE);
				rp = find_range(ctx, &eq.v2);
				if (rp && !(rp->value & 1) && (rp->value_hi & 1)) {
					eq.v2 = *rp;
					quash_equalities(ctx, d);
					g(insert_equality(ctx, &eq));
					continue;
				}
			}
			goto skip;
		}
		case INSN_CWD: {
			bool must_be_zero = false;
			uint8_t *pd = d->start + 4;
			uint8_t *ps = pd + arg_size(*pd);
			if (!arg_to_val(d, pd, &rng.v1))
				goto skip;
			if (!arg_to_val(d, ps, &rng.v2))
				goto skip;
			rp = find_range(ctx, &rng.v2);
			if (rp && !rp->range_signed && rp->value_hi <= ((uint64_t)1 << (rng.v1.size * 8 - 1)) - 1) {
				must_be_zero = true;
			}
			quash_equalities(ctx, d);
			if (must_be_zero) {
				rng.v2.tag = VALUE_TAG_RANGE;
				rng.v2.size = rng.v1.size;
				rng.v2.range_signed = false;
				rng.v2.value = 0;
				rng.v2.value_hi = 0;
				g(insert_equality(ctx, &rng));
			}
			continue;
		}
		case INSN_SET_COND: {
			uint8_t *pd = d->start + 4;
			if (!arg_to_val(d, pd, &rng.v1))
				goto skip;
			if (*pd < ARG_REGS_MAX)
				rng.v1.size = op_size_to_size(OP_SIZE_NATIVE);
			rng.v2.tag = VALUE_TAG_RANGE;
			rng.v2.size = rng.v1.size;
			rng.v2.range_signed = false;
			rng.v2.value = 0;
			rng.v2.value_hi = 1;
			quash_equalities(ctx, d);
			g(insert_equality(ctx, &rng));
			continue;
		}
		case INSN_JMP_COND:
		case INSN_JMP_COND_LOGICAL: {
			rng.v1.tag = VALUE_TAG_FLAGS;
			rng.v1.size = 0;
			rng.v1.range_signed = false;
			rng.v1.value = 0;
			rng.v1.value_hi = 0;
			rp = find_range(ctx, &rng.v1);
			if (rp) {
				unsigned cond = insn_aux(d->insn);
				if (rp->value & (1ULL << cond) && !(rp->value_hi & (1ULL << cond))) {
					d->quash = true;
					continue;
				}
			}
			quash_equalities(ctx, d);
			continue;
		}
		default: {
skip:
			quash_equalities(ctx, d);
		}
		}
	}

	return true;
}

static bool attr_w live_register_analysis(struct codegen_context *ctx, reg_map live_registers)
{
	size_t i;
	memset(ctx->live_frame, 1, function_n_variables(ctx->fn));
	for (i = ctx->basic_block_position; i--; ) {
		struct insn_details *d = &ctx->basic_block[i];
		if (unlikely(d->quash))
			continue;
		d->live_after = live_registers;
		if (d->target_label) {
			if (ctx->label_flags[d->target_label] & LABEL_OP_BOUNDARY) {
				live_registers = reg_map_union(live_registers, ctx->opt_status->op_boundary_regs);
			} else {
				live_registers = reg_map_union(live_registers, ctx->opt_status->all_used_regs);
			}
			memset(ctx->live_frame, 1, function_n_variables(ctx->fn));
		} else if (reg_map_is_empty(reg_map_intersection(d->wr, live_registers))) {
			unsigned opc = insn_opcode(d->insn);
			if (opc != INSN_LABEL && REPORT_QUASHED_INSNS) {
#ifdef DEBUG_INSNS
				uint32_t insn = oget_four(d->start - 8);
				uint32_t seq = oget_four(d->start - 4);
				debug("pointless instruction at %u/%u (seq %x): %x", insn >> 24, insn & 0x00FFFFFFU, seq, oget_four(d->start));
#else
				debug("pointless instruction: %x", oget_four(d->start));
#endif
			}
			d->quash = true;
			continue;
		}
		if (d->wr_frame && !reg_map_is_set(d->wr, R_MEMORY)) {
			if (!ctx->live_frame[d->wr_frame]) {
				reg_map dwr = d->wr;
				reg_map_clear(&dwr, R_MEMORY_FRAME);
				if (reg_map_is_empty(reg_map_intersection(dwr, live_registers))) {
					if (REPORT_QUASHED_INSNS) {
#ifdef DEBUG_INSNS
						uint32_t insn = oget_four(d->start - 8);
						uint32_t seq = oget_four(d->start - 4);
						debug("pointless frame write at %u/%u (seq %x): %x", insn >> 24, insn & 0x00FFFFFFU, seq, oget_four(d->start));
#else
						debug("pointless frame write: %x", oget_four(d->start));
#endif
					}
					d->quash = true;
					continue;
				}
			}
			ctx->live_frame[d->wr_frame] = 0;
		}
		if (d->rd_frame && !reg_map_is_set(d->rd, R_MEMORY)) {
			ctx->live_frame[d->rd_frame] = 1;
		}
		live_registers = reg_map_intersection(live_registers, reg_map_neg(d->wr));
		live_registers = reg_map_union(live_registers, d->rd);
		if (reg_map_is_set(d->rd, R_MEMORY))
			memset(ctx->live_frame, 1, function_n_variables(ctx->fn));
		d->live_before = live_registers;
	}
	return true;
}

static bool fuse_mem_accesses(const uint8_t *r1, const uint8_t *r2, const uint8_t *a1, const uint8_t *a2, unsigned op_size)
{
	int64_t imm1, imm2;
	if (r1[0] >= ARG_REGS_MAX || r2[0] >= ARG_REGS_MAX) {
		if (!(r1[0] == ARG_IMM && r2[0] == ARG_IMM && !get_imm(&r1[1]) && !get_imm(&r2[1])))
			return false;
	}
	if (a1[0] != ARG_ADDRESS_1 || a2[0] != ARG_ADDRESS_1)
		return false;
	if (a1[1] != a2[1])
		return false;
	imm1 = get_imm(&a1[2]);
	imm2 = get_imm(&a2[2]);
	return (uint64_t)imm1 + op_size_to_size(op_size) == (uint64_t)imm2;
}

static bool attr_w peephole(struct codegen_context *ctx)
{
	size_t i, j, k;
	ctx->equalities_used = 0;
	for (i = 0; i < ctx->basic_block_position; i++) {
		struct insn_details *d1, *d2, *d3;
		d1 = &ctx->basic_block[i];
		if (unlikely(d1->quash))
			continue;
		j = i + 1;
new_d2:
		if (unlikely(!j) || unlikely(j >= ctx->basic_block_position))
			continue;
		d2 = &ctx->basic_block[j];
		if (unlikely(d2->quash)) {
			j++;
			goto new_d2;
		}
		if ((insn_opcode(d1->insn) == INSN_JMP_COND || insn_opcode(d1->insn) == INSN_JMP_COND_LOGICAL) && insn_opcode(d2->insn) == INSN_JMP) {
			uint32_t label1 = d1->target_label;
			uint32_t label2 = d2->target_label;
			if (ctx->label_flags[label1] & LABEL_ESCAPE && !(ctx->label_flags[label2] & LABEL_ESCAPE)) {
				g(prepare_new_insn(ctx));
				gen_insn(insn_opcode(d1->insn), insn_op_size(d1->insn), insn_aux(d1->insn) ^ 1, 0);
				gen_four(label2);
				g(finish_new_insn(ctx, d1));
				g(prepare_new_insn(ctx));
				gen_insn(INSN_JMP, 0, 0, 0);
				gen_four(label1);
				g(finish_new_insn(ctx, d2));
				continue;
			}
		}

		if (insn_opcode(d1->insn) != INSN_JMP && ARCH_HAS_DELAY_SLOTS(insn_opcode(d1->insn)) && can_be_in_delay_slot(d2)) {
			reg_map live_registers;
			live_registers = reg_map_intersection(d1->live_before, d2->wr);
			if (reg_map_is_empty(live_registers) && !reg_map_is_set(d2->rd, R_MEMORY)) {
				g(prepare_new_insn(ctx));
				gen_insn(insn_opcode(d1->insn) | INSN_DELAY_SLOT, insn_op_size(d1->insn), insn_aux(d1->insn), insn_writes_flags(d1->insn));
				gen_stream(d1->start + 4, d1->length - 4);
				g(finish_new_insn(ctx, d1));
				i = j;
				continue;
			}
		}
		if (insn_opcode(d2->insn) == INSN_JMP && ARCH_HAS_DELAY_SLOTS(insn_opcode(d2->insn)) && can_be_in_delay_slot(d1)) {
			struct insn_details jmp_d;
			g(prepare_new_insn(ctx));
			gen_insn(insn_opcode(d2->insn) | INSN_DELAY_SLOT, insn_op_size(d2->insn), insn_aux(d2->insn), insn_writes_flags(d2->insn));
			gen_stream(d2->start + 4, d2->length - 4);
			g(finish_new_insn(ctx, &jmp_d));
			*d2 = *d1;
			*d1 = jmp_d;
			i = j;
			continue;
		}

#if defined(ARCH_ARM64) || defined(ARCH_X86)
		if ((insn_opcode(d1->insn) == INSN_SET_COND || insn_opcode(d1->insn) == INSN_SET_COND_PARTIAL) &&
		    (insn_opcode(d2->insn) == INSN_ALU || insn_opcode(d2->insn) == INSN_ALU_PARTIAL) && insn_aux(d2->insn) == ALU_XOR) {
			uint8_t *d1w, *d2w, *d2r, *d2c;
			if (unlikely(reg_map_is_set(d2->live_after, R_FLAGS)) && unlikely(insn_writes_flags(d2->insn)))
				goto skip_setc_xor;
			d1w = d1->start + 4;
			d2w = d2->start + 4;
			d2r = d2w + arg_size(*d2w);
			d2c = d2r + arg_size(*d2r);
			if (*d2c != ARG_IMM || oget_eight(d2c + 1) != 1)
				goto skip_setc_xor;
			if (!arg_equal(d1w, d2w) || !arg_equal(d2w, d2r))
				goto skip_setc_xor;
			g(prepare_new_insn(ctx));
			gen_insn(insn_opcode(d1->insn), insn_op_size(d1->insn), insn_aux(d1->insn) ^ 1, insn_writes_flags(d1->insn));
			gen_stream(d1w, arg_size(*d1w));
			if (insn_opcode(d1->insn) == INSN_SET_COND_PARTIAL) {
				uint8_t *dr1 = d1w + arg_size(*d1w);
				gen_stream(dr1, arg_size(*dr1));
			}
			g(finish_new_insn(ctx, d1));
			d2->quash = true;
			goto retry;
		}
skip_setc_xor:
#endif

		if (ARCH_HAS_FUSED_MEMORY_ACCESSES && insn_opcode(d1->insn) == INSN_MOV && insn_opcode(d2->insn) == INSN_MOV && insn_op_size(d1->insn) == insn_op_size(d2->insn)) {
			struct insn_details nd;
			const uint8_t *d1w = d1->start + 4;
			const uint8_t *d1r = d1w + arg_size(*d1w);
			const uint8_t *d2w = d2->start + 4;
			const uint8_t *d2r = d2w + arg_size(*d2w);
			if (fuse_mem_accesses(d1w, d2w, d1r, d2r, insn_op_size(d1->insn))) {
				g(prepare_new_insn(ctx));
				gen_insn(INSN_LDP, insn_op_size(d1->insn), 0, 0);
				gen_stream(d1w, arg_size(d1w[0]));
				gen_stream(d2w, arg_size(d2w[0]));
				gen_stream(d1r, arg_size(d1r[0]));
				g(finish_new_insn(ctx, &nd));
				goto gen_nd;
			}
			if (fuse_mem_accesses(d2w, d1w, d2r, d1r, insn_op_size(d1->insn))) {
				g(prepare_new_insn(ctx));
				gen_insn(INSN_LDP, insn_op_size(d1->insn), 0, 0);
				gen_stream(d2w, arg_size(d2w[0]));
				gen_stream(d1w, arg_size(d1w[0]));
				gen_stream(d2r, arg_size(d2r[0]));
				g(finish_new_insn(ctx, &nd));
				goto gen_nd;
			}
			if (fuse_mem_accesses(d1r, d2r, d1w, d2w, insn_op_size(d1->insn))) {
				g(prepare_new_insn(ctx));
				gen_insn(INSN_STP, insn_op_size(d1->insn), 0, 0);
				gen_stream(d1w, arg_size(d1w[0]));
				gen_stream(d1r, arg_size(d1r[0]));
				gen_stream(d2r, arg_size(d2r[0]));
				g(finish_new_insn(ctx, &nd));
				goto gen_nd;
			}
			if (fuse_mem_accesses(d2r, d1r, d2w, d1w, insn_op_size(d1->insn))) {
				g(prepare_new_insn(ctx));
				gen_insn(INSN_STP, insn_op_size(d1->insn), 0, 0);
				gen_stream(d2w, arg_size(d2w[0]));
				gen_stream(d2r, arg_size(d2r[0]));
				gen_stream(d1r, arg_size(d1r[0]));
				g(finish_new_insn(ctx, &nd));
				goto gen_nd;
			}
			if (false) {
gen_nd:
				if (validate_insn(&nd)) {
					*d1 = nd;
					d2->quash = true;
					continue;
				}
			}
		}

		k = j + 1;
new_d3:
		if (unlikely(!k) || unlikely(k >= ctx->basic_block_position))
			continue;
		d3 = &ctx->basic_block[k];
		if (unlikely(d3->quash)) {
			k++;
			goto new_d3;
		}
#if defined(ARCH_X86)
		if ((insn_opcode(d1->insn) == INSN_SET_COND || insn_opcode(d1->insn) == INSN_SET_COND_PARTIAL) &&
		    insn_opcode(d2->insn) == INSN_CMP &&
		    insn_opcode(d3->insn) == INSN_JMP_COND && (insn_aux(d3->insn) == COND_E || insn_aux(d3->insn) == COND_NE)) {
			uint8_t *d1w, *d2r, *d2c;
			if (insn_op_size(d1->insn) != insn_op_size(d2->insn) || insn_op_size(d1->insn) != insn_op_size(d3->insn))
				goto skip_setc_cmp_jmp;
			if (unlikely(reg_map_is_set(d3->live_after, R_FLAGS)))
				goto skip_setc_cmp_jmp;
			d1w = d1->start + 4;
			d2r = d2->start + 4;
			d2c = d2r + arg_size(*d2r);
			if (*d2c != ARG_IMM || oget_eight(d2c + 1) != 0)
				goto skip_setc_cmp_jmp;
			if (!arg_equal(d1w, d2r))
				goto skip_setc_cmp_jmp;
			d2->quash = true;

			g(prepare_new_insn(ctx));
			gen_insn(insn_opcode(d3->insn), insn_op_size(d3->insn), insn_aux(d1->insn) ^ (insn_aux(d3->insn) == COND_E), insn_writes_flags(d3->insn));
			gen_four(d3->target_label);
			g(finish_new_insn(ctx, d3));
			continue;
		}
skip_setc_cmp_jmp:
#endif

		if (false) {
			goto retry;
retry:
			i--;
		}
	}
	return true;
}

static bool attr_w process_basic_block(struct codegen_context *ctx, reg_map live_bottom)
{
	size_t i;

	g(equality_analysis(ctx));
	g(live_register_analysis(ctx, live_bottom));
	g(peephole(ctx));

	for (i = 0; i < ctx->basic_block_position; i++) {
		struct insn_details *d = &ctx->basic_block[i];
		if (d->quash) {
			if (MARK_QUASHED_INSNS || d->mark)
				gen_insn(INSN_NOP, 0, 0, 0);
			if (QUASH_INSNS && !d->mark)
				continue;
		}
		if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->new_code, &ctx->new_code_size, d->start - debug_offset, d->length + debug_offset, NULL, &ctx->err)))
			return false;
	}

	ctx->basic_block_position = 0;
	for (i = 0; i < ctx->new_insns_size; i++)
		mem_free(ctx->new_insns[i]);
	ctx->new_insns_size = 0;
	return true;
}

static bool attr_w cg_optimize(struct codegen_context *ctx)
{
	if (unlikely((chicken & CHICKEN_CG_OPTIMIZE) != 0))
		return true;

	/*debug("%lu : %s", function_n_variables(ctx->fn), da(ctx->fn,function)->function_name);*/

	if (unlikely(!array_init_mayfail(uint8_t, &ctx->new_code, &ctx->new_code_size, &ctx->err)))
		return false;

	ctx->opt_status = mem_alloc_mayfail(struct opt_status *, sizeof(struct opt_status), &ctx->err);
	if (unlikely(!ctx->opt_status))
		return false;

	if (unlikely(!array_init_mayfail(struct insn_details, &ctx->basic_block, &ctx->basic_block_size, &ctx->err)))
		return false;
	ctx->basic_block_position = 0;

	if (unlikely(!array_init_mayfail(struct equality, &ctx->equalities, &ctx->equalities_size, &ctx->err)))
		return false;

	if (unlikely(!array_init_mayfail(uint8_t *, &ctx->new_insns, &ctx->new_insns_size, &ctx->err)))
		return false;

	ctx->live_frame = mem_alloc_array_mayfail(mem_alloc_mayfail, char *, 0, 0, function_n_variables(ctx->fn), sizeof(bool), &ctx->err);
	if (unlikely(!ctx->live_frame))
		return false;

	g(setup_register_maps(ctx));

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
			g(process_basic_block(ctx, d->rd));
			if (unlikely(!array_add_multiple_mayfail(uint8_t, &ctx->new_code, &ctx->new_code_size, start - debug_offset, length + debug_offset, NULL, &ctx->err)))
				return false;
		} else {
			if (unlikely(insn_opcode(d->insn) == INSN_LABEL))
				goto skip_insn;
			ctx->basic_block_position++;
		}
skip_insn:
		ctx->code_position += debug_offset + length;
	}

	ajla_assert_lo(!ctx->basic_block_position, (file_line, "cg_optimize: the code doesn't end with barrier"));

	mem_free(ctx->opt_status);
	ctx->opt_status = NULL;

	mem_free(ctx->basic_block);
	ctx->basic_block = NULL;

	mem_free(ctx->equalities);
	ctx->equalities = NULL;

	mem_free(ctx->new_insns);
	ctx->new_insns = NULL;

	mem_free(ctx->live_frame);
	ctx->live_frame = NULL;

	flip_buffers(ctx);

	return true;
}
