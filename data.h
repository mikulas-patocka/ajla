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

#ifndef AJLA_DATA_H
#define AJLA_DATA_H

#include "args.h"
#include "type.h"
#include "mem_al.h"
#include "util.h"
#include "refcount.h"
#include "addrlock.h"
#include "mpint.h"
#include "ptrcomp.h"
#include "tree.h"
#include "thread.h"
#include "tick.h"
#include "profile.h"


#define stack_alloc			name(stack_alloc)
#define stack_expand			name(stack_expand)
#define stack_split			name(stack_split)
#define stack_trace_init		name(stack_trace_init)
#define stack_trace_free		name(stack_trace_free)
#define stack_trace_capture		name(stack_trace_capture)
#define stack_trace_string		name(stack_trace_string)
#define stack_trace_print		name(stack_trace_print)
#define stack_trace_get_location	name(stack_trace_get_location)
#define data_alloc_flat_mayfail		name(data_alloc_flat_mayfail)
#define data_alloc_longint_mayfail	name(data_alloc_longint_mayfail)
#define data_alloc_record_mayfail	name(data_alloc_record_mayfail)
#define data_alloc_option_mayfail	name(data_alloc_option_mayfail)
#define data_alloc_array_flat_mayfail	name(data_alloc_array_flat_mayfail)
#define data_alloc_array_slice_mayfail	name(data_alloc_array_slice_mayfail)
#define data_alloc_array_pointers_mayfail	name(data_alloc_array_pointers_mayfail)
#define data_alloc_array_same_mayfail	name(data_alloc_array_same_mayfail)
#define data_alloc_array_incomplete	name(data_alloc_array_incomplete)
#define data_alloc_function_reference_mayfail	name(data_alloc_function_reference_mayfail)
#define data_fill_function_reference	name(data_fill_function_reference)
#define data_fill_function_reference_flat	name(data_fill_function_reference_flat)
#define data_alloc_resource_mayfail	name(data_alloc_resource_mayfail)
#define out_of_memory_ptr		name(out_of_memory_ptr)
#define thunk_alloc_exception_error	name(thunk_alloc_exception_error)
#define pointer_error			name(pointer_error)
#define thunk_exception_string		name(thunk_exception_string)
#define thunk_exception_payload		name(thunk_exception_payload)
#define thunk_exception_print		name(thunk_exception_print)
#define thunk_alloc_function_call	name(thunk_alloc_function_call)
#define thunk_alloc_blackhole		name(thunk_alloc_blackhole)
#define are_there_dereferenced		name(are_there_dereferenced)
#define execution_control_unlink_and_submit	name(execution_control_unlink_and_submit)
#define execution_control_acquire	name(execution_control_acquire)
#define wake_up_wait_list		name(wake_up_wait_list)
#define thunk_terminate			name(thunk_terminate)
#define execution_control_alloc		name(execution_control_alloc)
#define execution_control_free		name(execution_control_free)
#define execution_control_terminate	name(execution_control_terminate)
#define free_cache_entry		name(free_cache_entry)
#define pointer_dereference_		name(pointer_dereference_)
#define pointer_reference_		name(pointer_reference_)
#define pointer_reference_maybe_	name(pointer_reference_maybe_)
#define copy_from_function_reference_to_frame	name(copy_from_function_reference_to_frame)
#define pointer_follow_thunk_		name(pointer_follow_thunk_)
#define pointer_resolve_result		name(pointer_resolve_result)
#define pointer_follow_wait		name(pointer_follow_wait)
#define data_is_nan			name(data_is_nan)
#define flat_to_data			name(flat_to_data)
#define data_to_flat			name(data_to_flat)
#define struct_clone			name(struct_clone)
#define pointer_deep_eval		name(pointer_deep_eval)
#define frame_pointer_deep_eval		name(frame_pointer_deep_eval)
#define mpint_export			name(mpint_export)
#define mpint_export_unsigned		name(mpint_export_unsigned)
#define data_compare_numbers		name(data_compare_numbers)
#define data_compare			name(data_compare)
#define save_index_mp			name(save_index_mp)
#define data_save			name(data_save)
#define data_save_init_stack		name(data_save_init_stack)
#define data_trap_lookup		name(data_trap_lookup)
#define data_trap_insert		name(data_trap_insert)


#ifdef DEBUG_TRACE
#define trace_enabled	name(trace_enabled)
extern atomic_type uchar_efficient_t trace_enabled;
#endif


struct data;
struct thunk;
struct execution_control;


/***************
 * DEFAULT INT *
 ***************/

#if (INT_MASK & (1 << 2)) && defined(POINTER_COMPRESSION)
#define INT_DEFAULT_BITS	32
#elif (INT_MASK & (1 << 3)) && defined(BIT64)
#define INT_DEFAULT_BITS	64
#elif (INT_MASK & (1 << 2))
#define INT_DEFAULT_BITS	32
#elif (INT_MASK & (1 << 3))
#define INT_DEFAULT_BITS	64
#elif (INT_MASK & (1 << 4))
#define INT_DEFAULT_BITS	128
#elif (INT_MASK & (1 << 1))
#define INT_DEFAULT_BITS	16
#elif (INT_MASK & (1 << 0))
#define INT_DEFAULT_BITS	8
#else
unknown integer size
#endif

#define int_default_t		cat4(int,INT_DEFAULT_BITS,_,t)
#define uint_default_t		cat4(uint,INT_DEFAULT_BITS,_,t)

/*#define	INT_DEFAULT_N		log_2(INT_DEFAULT_BITS / 8)*/
#if INT_DEFAULT_BITS == 8
#define INT_DEFAULT_N		0
#elif INT_DEFAULT_BITS == 16
#define INT_DEFAULT_N		1
#elif INT_DEFAULT_BITS == 32
#define INT_DEFAULT_N		2
#elif INT_DEFAULT_BITS == 64
#define INT_DEFAULT_N		3
#elif INT_DEFAULT_BITS == 128
#define INT_DEFAULT_N		4
#endif


/*************
 * ALIGNMENT *
 *************/

#ifdef HAVE_MAX_ALIGN_T
#define scalar_align_max_align_t_		(align_of(max_align_t) - 1) |
#else
#define scalar_align_max_align_t_
#endif
#define scalar_align_fixed_(n, s, u, sz, bits)		(align_of(s) - 1) |
#define scalar_align_int_(n, s, u, sz, bits)		(align_of(s) - 1) |
#define scalar_align_real_(n, t, nt, pack, unpack)	(align_of(t) - 1) |
#define scalar_align ((							\
			for_all_fixed(scalar_align_fixed_)		\
			for_all_int(scalar_align_int_, for_all_empty)	\
			for_all_real(scalar_align_real_, for_all_empty)	\
			scalar_align_max_align_t_			\
			(align_of(ajla_flat_option_t) - 1) |		\
			(align_of(void *) - 1) |			\
			1) + 1)


/***************
 * COMPRESSION *
 ***************/

#if defined(POINTER_COMPRESSION)

#define pointer_compress_test(ptr, fat)					\
do {									\
	if (unlikely((ptr_to_num(ptr) & ~((uintptr_t)0xfffffffeUL << POINTER_COMPRESSION)) != 0)) {\
		if (fat)						\
			fatal("the allocator returned pointer %p that is not compatible with %d-bit compression", (ptr), POINTER_COMPRESSION);\
		else							\
			ajla_assert(false, (file_line, "pointer_compress_test: pointer %p is not compatible with %d-bit compression", (ptr), POINTER_COMPRESSION));\
	}								\
} while (0)

static inline uint32_t pointer_compress(const void *ptr)
{
	return (uint32_t)(ptr_to_num(ptr) >> POINTER_COMPRESSION);
}

static inline void *pointer_decompress(uint32_t num)
{
	return num_to_ptr((uintptr_t)num << POINTER_COMPRESSION);
}

#define pointer_compress_alignment	(2 << POINTER_COMPRESSION)

#else

#ifdef POINTER_TAG
#define pointer_compress_test(ptr, fat)					\
do {									\
	if (unlikely((ptr_to_num(ptr) & POINTER_TAG) != 0)) {		\
		if (fat)						\
			fatal("the allocator returned pointer %p that is not compatible with tag %"PRIuMAX"", (ptr), (uintmax_t)POINTER_TAG);\
		else							\
			ajla_assert(false, (file_line, "pointer_compress_test: pointer %p is not compatible with %"PRIuMAX"", (ptr), (uintmax_t)POINTER_TAG));\
	}								\
} while (0)
#define pointer_compress_alignment		(POINTER_TAG * 2)
#else
#define pointer_compress_test(ptr, fat)		do { } while (0)
#define pointer_compress_alignment		1
#endif

#define pointer_compress			ptr_to_num
#define pointer_decompress			num_to_ptr

#endif


/***********
 * POINTER *
 ***********/

#if defined(POINTER_COMPRESSION)

typedef uint32_t pointer_t;

#define pointer_validate(ptr)

static attr_always_inline pointer_t pointer_thunk(struct thunk *thunk)
{
	pointer_compress_test(thunk, false);
	return pointer_compress(thunk) | 1;
}

static attr_always_inline pointer_t pointer_data(const struct data *data)
{
	pointer_compress_test(data, false);
	return pointer_compress(data);
}

static attr_always_inline bool pointer_is_thunk(const pointer_t ptr)
{
	return ptr & 1;
}

static attr_always_inline void *pointer_get_value_(const pointer_t ptr)
{
	return pointer_decompress(ptr);
}

static attr_always_inline void *pointer_get_value_strip_tag_(const pointer_t ptr)
{
	return pointer_get_value_(ptr & ~(uint32_t)1);
}

static attr_always_inline void *pointer_get_value_sub_tag_(const pointer_t ptr)
{
	return pointer_get_value_(ptr - 1);
}

#elif defined(POINTER_IGNORE_START)

#define POINTER_TAG_AT_ALLOC

typedef void *pointer_t;

#define pointer_validate(ptr)

static attr_always_inline pointer_t pointer_thunk(struct thunk *thunk)
{
	ajla_assert((ptr_to_num(thunk) & POINTER_IGNORE_TOP) != 0, (file_line, "pointer_thunk: pointer is not tagged: %p", thunk));
	return (pointer_t)thunk;
}

static attr_always_inline pointer_t pointer_data(const struct data *data)
{
	ajla_assert((ptr_to_num(data) & POINTER_IGNORE_TOP) == 0, (file_line, "pointer_data: pointer is tagged: %p", data));
	return (pointer_t)data;
}

static attr_always_inline bool pointer_is_thunk(const pointer_t ptr)
{
	return (ptr_to_num(ptr) & POINTER_IGNORE_TOP) != 0;
}

static attr_always_inline void *pointer_get_value_(const pointer_t ptr)
{
	return ptr;
}

static attr_always_inline void *pointer_get_value_strip_tag_(const pointer_t ptr)
{
	return ptr;
}

static attr_always_inline void *pointer_get_value_sub_tag_(const pointer_t ptr)
{
	return ptr;
}

#elif defined(POINTER_TAG)

#define POINTER_TAG_USED

typedef void *pointer_t;

#define pointer_validate(ptr)

static attr_always_inline pointer_t pointer_thunk(struct thunk *thunk)
{
	return POINTER_TAG_ADD(thunk);
}

static attr_always_inline pointer_t pointer_data(const struct data *data)
{
	return (pointer_t)data;
}

static attr_always_inline bool pointer_is_thunk(const pointer_t ptr)
{
	return POINTER_TAG_GET(ptr) != 0;
}

static attr_always_inline void *pointer_get_value_(const pointer_t ptr)
{
	return ptr;
}

static attr_always_inline void *pointer_get_value_strip_tag_(const pointer_t ptr)
{
	return POINTER_TAG_CLEAR(ptr);
}

static attr_always_inline void *pointer_get_value_sub_tag_(const pointer_t ptr)
{
	return POINTER_TAG_SUB(ptr);
}

#else

#ifdef DEBUG
#define POINTER_THUNK_BIAS	0x20
#else
#define POINTER_THUNK_BIAS	0x00
#endif

typedef struct {
	void *ptr;
	unsigned char thunk;
} pointer_t;

#define pointer_validate(ptr_)						\
do {									\
	ajla_assert((unsigned)((ptr_).thunk - POINTER_THUNK_BIAS) <= 1, (file_line, "pointer_validate: invalid pointer type %x, value %p", ptr_.thunk, ptr_.ptr));\
	ajla_assert((ptr_).ptr != BAD_POINTER_1 && (ptr_).ptr != BAD_POINTER_2 && (ptr_).ptr != BAD_POINTER_3, (file_line, "pointer_validate: invalid pointer type %x, value %p", ptr_.thunk, ptr_.ptr));\
} while (0)

static attr_always_inline pointer_t pointer_thunk(struct thunk *thunk)
{
	pointer_t ptr;
	ptr.ptr = thunk;
	ptr.thunk = POINTER_THUNK_BIAS + 1;
	return ptr;
}

static attr_always_inline pointer_t pointer_data(const struct data *data)
{
	pointer_t ptr;
	ptr.ptr = (void *)data;
	ptr.thunk = POINTER_THUNK_BIAS;
	return ptr;
}

static attr_always_inline bool pointer_is_thunk(const pointer_t ptr)
{
	pointer_validate(ptr);
	ajla_assert((unsigned)(ptr.thunk - POINTER_THUNK_BIAS) <= 1, (file_line, "pointer_is_thunk: invalid pointer type %x", ptr.thunk));
	return (bool)(ptr.thunk - POINTER_THUNK_BIAS);
}

static attr_always_inline void *pointer_get_value_(const pointer_t ptr)
{
	pointer_validate(ptr);
	return ptr.ptr;
}

static attr_always_inline void *pointer_get_value_strip_tag_(const pointer_t ptr)
{
	pointer_validate(ptr);
	return ptr.ptr;
}

static attr_always_inline void *pointer_get_value_sub_tag_(const pointer_t ptr)
{
	pointer_validate(ptr);
	return ptr.ptr;
}

#endif

static attr_always_inline bool pointer_is_equal(pointer_t ptr1, pointer_t ptr2)
{
	bool ret;
#if defined(POINTER_COMPRESSION) || defined(POINTER_TAG_USED) || defined(POINTER_TAG_AT_ALLOC)
	ret = ptr1 == ptr2;
#else
	ret = likely(ptr1.ptr == ptr2.ptr) && likely(ptr1.thunk == ptr2.thunk);
#endif
	return ret;
}

static attr_always_inline pointer_t pointer_empty(void)
{
#if defined(POINTER_COMPRESSION)
	return 0;
#else
	return pointer_data(NULL);
#endif
}

static attr_always_inline bool pointer_is_empty(pointer_t ptr)
{
	return pointer_is_equal(ptr, pointer_empty());
}

static attr_always_inline pointer_t pointer_mark(void)
{
#if defined(POINTER_COMPRESSION)
	return 1;
#elif defined(POINTER_TAG_AT_ALLOC)
	return (pointer_t)POINTER_IGNORE_TOP;
#else
	return pointer_thunk(NULL);
#endif
}

static attr_always_inline bool pointer_is_mark(pointer_t ptr)
{
	return pointer_is_equal(ptr, pointer_mark());
}

static attr_always_inline void pointer_poison(pointer_t attr_unused *ptr)
{
#ifdef DEBUG
	*ptr = pointer_data((struct data *)num_to_ptr(2048));
#endif
}

#define verify_thunk_(ptr_, value_, file_line_)	ajla_assert(pointer_is_thunk(ptr_) == (value_), (file_line_, "pointer %p is %sa thunk", pointer_get_value_(ptr_), (value_) ? "not " : ""))

static attr_always_inline struct thunk *pointer_get_thunk_(pointer_t ptr argument_position)
{
	verify_thunk_(ptr, true, caller_file_line);
	return (struct thunk *)pointer_get_value_sub_tag_(ptr);
}

static attr_always_inline struct data *pointer_get_data_(pointer_t ptr argument_position)
{
	verify_thunk_(ptr, false, caller_file_line);
	return (struct data *)pointer_get_value_(ptr);
}

#define pointer_get_thunk(ptr_)	pointer_get_thunk_(ptr_ pass_file_line)
#define pointer_get_data(ptr_)	pointer_get_data_(ptr_ pass_file_line)


#define slot_bits	(		\
	sizeof(pointer_t) <= 2 ? 1 :	\
	sizeof(pointer_t) <= 4 ? 2 :	\
	sizeof(pointer_t) <= 8 ? 3 :	\
	sizeof(pointer_t) <= 16 ? 4 :	\
	(5))

#define slot_size		((size_t)1 << slot_bits)
#if defined(ARCH_ALPHA) || defined(ARCH_PARISC)
/*
 * This improves generated code on parisc.
 * The ldd/std instructions require 8-byte alignment.
 * Aligning the offset avoids offset-generating instructions.
 *
 * On alpha, we need this, so that we can access flags using the ldq
 * instruction.
 */
#define slot_align		maximum(slot_size, 8)
#else
#define slot_align		slot_size
#endif

#define max_frame_align		maximum(scalar_align, slot_align)
#define frame_align		maximum(scalar_align, slot_align)


/**************
 * ALLOCATION *
 **************/

static inline void *ptrcomp_verify(void *ptr)
{
	pointer_compress_test(ptr, true);
	return ptr;
}

#define mem_align_compressed_mayfail(type, size, align, mayfail)		cast_ptr(type, ptrcomp_verify(mem_align_mayfail(void *, size, maximum(pointer_compress_alignment, align), mayfail)))
#define mem_calign_compressed_mayfail(type, size, align, mayfail)		cast_ptr(type, ptrcomp_verify(mem_calign_mayfail(void *, size, maximum(pointer_compress_alignment, align), mayfail)))
#define mem_alloc_compressed_mayfail(type, size, mayfail)			mem_align_compressed_mayfail(type, size, 1, mayfail)
#define mem_free_compressed(ptr)						mem_free_aligned(ptr)

static inline bool data_element_is_const(const unsigned char *flat, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++)
		if (flat[i] != flat[0])
			return false;
	return true;
}


/****************
 * FRAME COMMON *
 ****************/

typedef struct frame_s_ frame_s;
struct frame_struct;

#ifndef INLINE_WORKS
#define frame_char_(fp)		(cast_ptr(unsigned char *, fp))
#define frame_uint32_(fp)	(cast_ptr(uint32_t *, fp))
#define frame_uint64_(fp)	(cast_ptr(uint64_t *, fp))
#else
static attr_always_inline unsigned char *frame_char_(frame_s *fp)
{
	return cast_ptr(unsigned char *, fp);
}

static attr_always_inline uint32_t *frame_uint32_(frame_s *fp)
{
	return cast_ptr(uint32_t *, fp);
}

static attr_always_inline uint64_t *frame_uint64_(frame_s *fp)
{
	return cast_ptr(uint64_t *, fp);
}
#endif

#define frame_var(fp, idx)		(cast_ptr(unsigned char *, __builtin_assume_aligned(frame_char_(fp) + ((size_t)(idx) << slot_bits), slot_size)))
#define frame_idx(fp, var)		((frame_t)((cast_ptr(char *, var) - frame_char_(fp)) / slot_size))

#define frame_slot_(p, type)			\
	(cast_ptr(type *, assert_alignment(p, align_of(type))))
#define frame_slot(fp, pos, type)		\
	frame_slot_(frame_var(fp, pos), type)

#define frame_pointer(p, pos)			\
	frame_slot(p, pos, pointer_t)

#if defined(HAVE_BITWISE_FRAME)
#define frame_flags_per_slot_bits	(slot_bits + 3)
#if defined(INLINE_ASM_GCC_X86)
#define bitmap_64bit			0
static attr_always_inline void frame_set_flag(frame_s *fp, frame_t idx)
{
	__asm__ volatile("bts %k0, %1"::"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory");
}
static attr_always_inline void frame_clear_flag(frame_s *fp, frame_t idx)
{
	__asm__ volatile("btr %k0, %1"::"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory");
}
static attr_always_inline bool frame_test_flag(frame_s *fp, frame_t idx)
{
#ifndef INLINE_ASM_GCC_LABELS
	bool res;
	__asm__ volatile("bt %k1, %2; setc %0":"=q"(res):"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory");
	return res;
#else
	__asm__ goto("bt %k0, %1; jc %l[flag_set]"::"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory":flag_set);
	return false;
flag_set:
	return true;
#endif
}
static attr_always_inline bool frame_test_2(frame_s *fp, frame_t idx1, frame_t idx2)
{
#ifndef INLINE_ASM_GCC_LABELS
	return frame_test_flag(fp, idx1) || frame_test_flag(fp, idx2);
#else
	__asm__ goto("bt %k0, %2; jc 1f; bt %k1, %2; 1:jc %l[flag_set]"::"r"((size_t)idx1),"r"((size_t)idx2),"m"(*(unsigned char *)fp):"cc","memory":flag_set);
	return false;
flag_set:
	return true;
#endif
}
static attr_always_inline bool frame_test_and_set_flag(frame_s *fp, frame_t idx)
{
#ifndef INLINE_ASM_GCC_LABELS
	bool res;
	__asm__ volatile("bts %k1, %2; setc %0":"=q"(res):"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory");
	return res;
#else
	__asm__ goto("bts %k0, %1; jc %l[flag_set]"::"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory":flag_set);
	return false;
flag_set:
	return true;
#endif
}
static attr_always_inline bool frame_test_and_clear_flag(frame_s *fp, frame_t idx)
{
#ifndef INLINE_ASM_GCC_LABELS
	bool res;
	__asm__ volatile("btr %k1, %2; setc %0":"=q"(res):"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory");
	return res;
#else
	__asm__ goto("btr %k0, %1; jc %l[flag_set]"::"r"((size_t)idx),"m"(*(unsigned char *)fp):"cc","memory":flag_set);
	return false;
flag_set:
	return true;
#endif
}
#else
#if defined(ARCH_ARM64) || defined(ARCH_RISCV64)
#define bitmap_64bit			(slot_size >= sizeof(uint64_t) && EFFICIENT_WORD_SIZE >= 64)
#else
#define bitmap_64bit			0
#endif
static attr_always_inline void frame_set_flag(frame_s *fp, frame_t idx)
{
	if (bitmap_64bit) {
		frame_uint64_(fp)[idx / 64] |= (uint64_t)1 << (idx & 63);
	} else {
		frame_uint32_(fp)[idx / 32] |= (uint32_t)1 << (idx & 31);
	}
}
static attr_always_inline void frame_clear_flag(frame_s *fp, frame_t idx)
{
	if (bitmap_64bit) {
		frame_uint64_(fp)[idx / 64] &= ~((uint64_t)1 << (idx & 63));
	} else {
		frame_uint32_(fp)[idx / 32] &= ~((uint32_t)1 << (idx & 31));
	}
}
static attr_always_inline bool frame_test_flag(frame_s *fp, frame_t idx)
{
	if (bitmap_64bit) {
		return (frame_uint64_(fp)[idx / 64] & ((uint64_t)1 << (idx & 63))) != 0;
	} else {
		return (frame_uint32_(fp)[idx / 32] & ((uint32_t)1 << (idx & 31))) != 0;
	}
}
static attr_always_inline bool frame_test_and_set_flag(frame_s *fp, frame_t idx)
{
	bool ret;
	if (bitmap_64bit) {
		uint64_t val = frame_uint64_(fp)[idx / 64];
		ret = (val & ((uint64_t)1 << (idx & 63))) != 0;
		val |= (uint64_t)1 << (idx & 63);
		frame_uint64_(fp)[idx / 64] = val;
		return ret;
	} else {
		uint32_t val = frame_uint32_(fp)[idx / 32];
		ret = (val & ((uint32_t)1 << (idx & 31))) != 0;
		val |= (uint32_t)1 << (idx & 31);
		frame_uint32_(fp)[idx / 32] = val;
		return ret;
	}
}
static attr_always_inline bool frame_test_and_clear_flag(frame_s *fp, frame_t idx)
{
	bool ret;
	if (bitmap_64bit) {
		uint64_t val = frame_uint64_(fp)[idx / 64];
		ret = (val & ((uint64_t)1 << (idx & 63))) != 0;
		val &= ~((uint64_t)1 << (idx & 63));
		frame_uint64_(fp)[idx / 64] = val;
		return ret;
	} else {
		uint32_t val = frame_uint32_(fp)[idx / 32];
		ret = (val & ((uint32_t)1 << (idx & 31))) != 0;
		val &= ~((uint32_t)1 << (idx & 31));
		frame_uint32_(fp)[idx / 32] = val;
		return ret;
	}
}
static attr_always_inline bool frame_test_2(frame_s *fp, frame_t idx1, frame_t idx2)
{
	return frame_test_flag(fp, idx1) || frame_test_flag(fp, idx2);
}
#endif
#else
#define frame_flags_per_slot_bits		(slot_bits)
static attr_always_inline void frame_set_flag(frame_s *fp, frame_t idx)
{
	ajla_assert(frame_char_(fp)[idx] <= 1, (file_line, "frame_set_flag: invalid value %d at index %"PRIuMAX"", (int)frame_char_(fp)[idx], (uintmax_t)idx));
	frame_char_(fp)[idx] = 1;
}
static attr_always_inline void frame_clear_flag(frame_s *fp, frame_t idx)
{
	ajla_assert(frame_char_(fp)[idx] <= 1, (file_line, "frame_clear_flag: invalid value %d at index %"PRIuMAX"", (int)frame_char_(fp)[idx], (uintmax_t)idx));
	frame_char_(fp)[idx] = 0;
}
static attr_always_inline bool frame_test_flag(frame_s *fp, frame_t idx)
{
#if 0
	unsigned char r1;
	__asm__ ("movb (%2,%1), %0" : "=q"(r1) : "r"(fp), "r"(idx) : "memory");
	return r1;
#else
	unsigned char val = frame_char_(fp)[idx];
	ajla_assert(val <= 1, (file_line, "frame_test_flag: invalid value %d at index %"PRIuMAX"", (int)val, (uintmax_t)idx));
	return val;
#endif
}
static attr_always_inline bool frame_test_and_set_flag(frame_s *fp, frame_t idx)
{
	unsigned char val = frame_char_(fp)[idx];
	ajla_assert(val <= 1, (file_line, "frame_test_and_set_flag: invalid value %d at index %"PRIuMAX"", (int)val, (uintmax_t)idx));
	if (val) return true;
	frame_char_(fp)[idx] = 1;
	return false;
}
static attr_always_inline bool frame_test_and_clear_flag(frame_s *fp, frame_t idx)
{
	unsigned char val = frame_char_(fp)[idx];
	ajla_assert(val <= 1, (file_line, "frame_test_and_clear_flag: invalid value %d at index %"PRIuMAX"", (int)val, (uintmax_t)idx));
	if (!val) return false;
	frame_char_(fp)[idx] = 0;
	return true;
}
/*
 * On many RISC architectures, gcc generates bogus unsigned extension
 * instruction after the "or" operator and it generates better code with "plus".
 * On CISC architectures, it generates better code with "or".
 */
#if defined(__arm__) || defined(__i386__) || defined(__m68k__) || defined(__sh__) || defined(__s390__) || defined(__x86_64__)
#define frame_test_operator	|
#else	/* defined(__alpha__) || defined(__aarch64__) || defined(__hppa) || defined(__mips) || defined(__powerpc__) */
#define frame_test_operator	+
#endif	/* doesn't care: defined(__riscv) || defined(__sparc__) */
#ifndef INLINE_WORKS
#define frame_test_2(fp, idx1, idx2)		(frame_char_(fp)[idx1] frame_test_operator frame_char_(fp)[idx2])
#else
static attr_always_inline bool frame_test_2(frame_s *fp, frame_t idx1, frame_t idx2)
{
	return frame_char_(fp)[idx1] frame_test_operator frame_char_(fp)[idx2];
}
#endif
#endif

#define bitmap_slots(n_vars)		(round_up((frame_t)(n_vars), 1 << frame_flags_per_slot_bits) >> frame_flags_per_slot_bits)

static inline void memcpy_slots(unsigned char *dest, const unsigned char *src, frame_t n_slots)
{
	src = assert_alignment(src, slot_size);
	dest = assert_alignment(dest, slot_size);
	memcpy_fast(dest, src, n_slots * slot_size);
}

#define MIN_USEABLE_SLOT		1


/********
 * DATA *
 ********/

struct data_flat {
	type_tag_t data_type;
	unsigned char flexible_array[FLEXIBLE_ARRAY_GCC];
};

struct data_longint {
	mpint_t mp;
};

struct data_record {
	const struct type *definition;
	char flexible_array[FLEXIBLE_ARRAY_GCC];
};

struct data_option {
	ajla_option_t option;
	pointer_t pointer;
};

struct data_array_flat {
	int_default_t n_used_entries;
	int_default_t n_allocated_entries;
	const struct type *type;
	unsigned char flexible_array[FLEXIBLE_ARRAY_GCC];
};

struct data_array_slice {
	int_default_t n_entries;
	pointer_t reference;
	const struct type *type;
	unsigned char *flat_data_minus_data_array_offset;
};

struct data_array_pointers {
	int_default_t n_used_entries;
	int_default_t n_allocated_entries;
	pointer_t *pointer;
	pointer_t pointer_array[FLEXIBLE_ARRAY_GCC];
};

#if !defined(DEBUG_ARRAY_INDICES) && !defined(UNUSUAL)
#if !defined(POINTER_COMPRESSION) && defined(SIZEOF_VOID_P) && SIZEOF_VOID_P && SIZEOF_VOID_P * 8 <= INT_DEFAULT_BITS
#define SCALAR_ARRAY_INDEX_T
#elif defined(POINTER_COMPRESSION) && 32 <= INT_DEFAULT_BITS
#define SCALAR_ARRAY_INDEX_T
#endif
#endif

#ifndef SCALAR_ARRAY_INDEX_T
typedef struct {
	uint_default_t val;
	mpint_t *mp;
#ifdef DEBUG_ARRAY_INDICES
	void *test_leak;
#endif
} array_index_t;
#else
typedef uint_default_t array_index_t;
#endif

typedef uchar_efficient_t btree_entries_t;

struct data_array_same {
	array_index_t n_entries;
	pointer_t pointer;
};

struct btree_level {
	array_index_t end_index;
	pointer_t node;
};

struct data_array_btree {
	btree_entries_t n_used_btree_entries;
	btree_entries_t n_allocated_btree_entries;
	uchar_efficient_t depth;
	struct btree_level btree[FLEXIBLE_ARRAY_GCC];
};

struct data_array_incomplete {
	pointer_t first;  /* a pointer to non-empty array */
	pointer_t next;   /* a pointer to array or array_incomplete or thunk */
};

struct function_argument {
	type_tag_t tag;	/* TYPE_TAG_unknown or primitive type tag */
	union {
		pointer_t ptr;
		unsigned char slot[slot_size];
	} u;
};

struct data_function_reference {
	union {
		pointer_t indirect;
		pointer_t *direct;
	} u;
	uchar_efficient_t is_indirect;
	arg_t n_curried_arguments;
#ifdef DEBUG
	/* deliberately misalign variables to catch alignment errors */
	char misalign;
#endif
	struct function_argument arguments[FLEXIBLE_ARRAY_GCC];
};

struct data_resource {
	void (*close)(struct data *);
#ifdef DEBUG
	/* deliberately misalign variables to catch alignment errors */
	char misalign;
#endif
	char flexible_array[FLEXIBLE_ARRAY_GCC];
};

/* a rough estimation to make sure that the size of data_function_reference doesn't overflow */
#define ARG_LIMIT	(sign_bit(size_t) / sizeof(struct function_argument))

struct local_variable {
	const struct type *type;
};

struct local_variable_flags {
	bool may_be_borrowed;
	bool must_be_flat;
	bool must_be_data;
};

struct local_arg {
	frame_t slot;
	char may_be_borrowed;
	char may_be_flat;
};

struct line_position {
	ip_t ip;
	unsigned line;
};

struct cache_entry;

struct cache_entry_return {
	struct cache_entry *ce;
	pointer_t ptr;
	struct execution_control *ex;
};

struct cache_entry {
	struct tree_entry entry;
	arg_t n_pending;
	bool save;
	struct list wait_list;
	struct cache_entry_return *returns;
	pointer_t arguments[FLEXIBLE_ARRAY];
};

struct escape_data {
	atomic_type profile_counter_t counter;
};

struct module_designator;

struct data_function {
	frame_t frame_slots;	/* (frame_offset + args + ret + vars) / slot_size */
	frame_t n_bitmap_slots;
	arg_t n_arguments;
	arg_t n_return_values;
	code_t *code;
	ip_t code_size;
	const struct local_variable *local_variables;			/* indexed by slot */
	const struct local_variable_flags *local_variables_flags;	/* indexed by slot */
	const struct local_arg *args;					/* indexed by argument */
	pointer_t types_ptr;
	const struct type *record_definition;
	const struct module_designator *module_designator;
	const struct function_designator *function_designator;
	char *function_name;
	struct line_position *lp;
	size_t lp_size;
#ifdef HAVE_CODEGEN
	pointer_t codegen;
	atomic_type uchar_efficient_t codegen_failed;
#endif
	struct data *loaded_cache;
	struct tree cache;
	atomic_type profile_counter_t profiling_counter;
	atomic_type profile_counter_t call_counter;
	struct escape_data *escape_data;
	bool leaf;
	bool is_saved;
	frame_t local_directory_size;
	pointer_t *local_directory[FLEXIBLE_ARRAY_GCC];
};

struct data_function_types {
	size_t n_types;
	const struct type *types[FLEXIBLE_ARRAY_GCC];
};

#ifdef HAVE_CODEGEN
#if defined(ARCH_X86_32) || defined(ARCH_ARM32) || defined(ARCH_MIPS32) || defined(ARCH_POWER32) || defined(ARCH_SPARC32)
typedef uint64_t code_return_t;
#else
typedef struct {
	void *fp;
#if defined(ARCH_MIPS64) || defined(ARCH_PARISC64) || defined(ARCH_S390) || defined(ARCH_SPARC64)
	unsigned long ip;
#else
	ip_t ip;
#endif
} code_return_t;
#endif
struct cg_upcall_vector_s;

struct trap_record {
	size_t source_ip;
	size_t destination_ip;
};

struct data_codegen {
#ifdef HAVE_CODEGEN_TRAPS
	struct tree_entry codegen_tree;
	struct trap_record *trap_records;
	size_t trap_records_size;
#endif
	void *unoptimized_code_base;
	size_t unoptimized_code_size;
	struct data *function;
	bool is_saved;
	frame_t n_entries;
	size_t *offsets;
	char *unoptimized_code[FLEXIBLE_ARRAY_GCC];
};
#endif

union internal_arg {
	void *ptr;
	size_t i;
};

struct data_internal {
	void *(*fn)(frame_s *fp, const code_t *ip, union internal_arg *);
	union internal_arg arguments[FLEXIBLE_ARRAY_GCC];
};

struct data_saved {
	size_t total_size;
	size_t n_offsets;
	size_t offsets[FLEXIBLE_ARRAY_GCC];
};

struct data_saved_cache {
	size_t n_entries;
	arg_t n_arguments;
	arg_t n_return_values;
	pointer_t pointers[FLEXIBLE_ARRAY_GCC];
};

typedef uchar_efficient_t tag_t;

#define DATA_TAG_START				1
#define DATA_TAG_flat				1
#define DATA_TAG_longint			2
#define DATA_TAG_record				3
#define DATA_TAG_option				4
#define DATA_TAG_array_flat			5
#define DATA_TAG_array_slice			6
#define DATA_TAG_array_pointers			7
#define DATA_TAG_array_same			8
#define DATA_TAG_array_btree			9
#define DATA_TAG_array_incomplete		10
#define DATA_TAG_function_reference		11
#define DATA_TAG_resource			12
#define DATA_TAG_function			13
#define DATA_TAG_function_types			14
#ifdef HAVE_CODEGEN
#define DATA_TAG_codegen			15
#endif
#define DATA_TAG_internal			16
#define DATA_TAG_saved				17
#define DATA_TAG_saved_cache			18
#define DATA_TAG_END				19

#define THUNK_TAG_START				19
#define THUNK_TAG_FUNCTION_CALL			19
#define THUNK_TAG_BLACKHOLE			20
#define THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED	21
#define THUNK_TAG_BLACKHOLE_DEREFERENCED	22
#define THUNK_TAG_RESULT			23
#define THUNK_TAG_MULTI_RET_REFERENCE		24
#define THUNK_TAG_EXCEPTION			25
#define THUNK_TAG_END				26

#define TAG_END					26

#if defined(POINTER_TAG_AT_ALLOC) && DATA_TAG_END <= (1 << POINTER_IGNORE_BITS) / 2
#define DATA_TAG_AT_ALLOC
#endif

struct data {
	refcount_t refcount_;
#if !defined(REFCOUNT_TAG)
	tag_t tag;
#endif
	union {
		struct data_flat flat;
		struct data_longint longint;
		struct data_record record;
		struct data_option option;
		struct data_array_flat array_flat;
		struct data_array_slice array_slice;
		struct data_array_pointers array_pointers;
		struct data_array_same array_same;
		struct data_array_btree array_btree;
		struct data_array_incomplete array_incomplete;
		struct data_function_reference function_reference;
		struct data_resource resource;

		/* these do not appear on the ajla heap */
		struct data_function function;
		struct data_function_types function_types;
#ifdef HAVE_CODEGEN
		struct data_codegen codegen;
#endif
		struct data_internal internal;

		/* this only appears in saved stream */
		struct data_saved saved;
		struct data_saved_cache saved_cache;
	} u_;
};

#if defined(DATA_TAG_AT_ALLOC)
#define da_tag_(data)		((tag_t)(ptr_to_num(data) >> POINTER_IGNORE_START))
#elif defined(REFCOUNT_TAG)
#define da_tag_(data)		(refcount_tag_get((refcount_const refcount_t *)&(data)->refcount_))
#else
#define da_tag_(data)		((data)->tag)
#endif
#define da_tag(data)		(ajla_assert(da_tag_(data) >= DATA_TAG_START && da_tag_(data) < DATA_TAG_END, (file_line, "invalid data tag %u", da_tag_(data))), da_tag_(data))
#define da_assert(data, kind)	(ajla_assert(da_tag_(data) == DATA_TAG_##kind, (file_line, "data tag %u, expected %u", da_tag_(data), DATA_TAG_##kind)))
#define da(data, kind)		(da_assert(data,kind), &(data)->u_.kind)

#define data_flat_offset_	(round_up(offsetof(struct data, u_.flat.flexible_array), scalar_align))
#define data_record_offset_	(round_up(offsetof(struct data, u_.record.flexible_array), slot_align))
#define data_array_offset_	(round_up(offsetof(struct data, u_.array_flat.flexible_array), scalar_align))
#define data_resource_offset_	(round_up(offsetof(struct data, u_.resource.flexible_array), scalar_align))
#ifndef UNUSUAL
#define data_flat_offset	data_flat_offset_
#define data_record_offset	data_record_offset_
#define data_array_offset	data_array_offset_
#define data_resource_offset	data_resource_offset_
#else
	/* add some value to make sure that we don't forget it */
#define data_flat_offset	(data_flat_offset_ + scalar_align)
#define data_record_offset	(data_record_offset_ + slot_align)
#define data_array_offset	(data_array_offset_ + scalar_align)
#define data_resource_offset	(data_resource_offset_ + scalar_align)
#endif
#define data_function_types_offset	offsetof(struct data, u_.function_types.types)

static attr_always_inline unsigned char *da_flat(struct data *d)
{
	da_assert(d,flat);
	return cast_ptr(unsigned char *, d) + data_flat_offset;
}
static attr_always_inline frame_s *da_record_frame(struct data *d)
{
	da_assert(d,record);
	return cast_ptr(frame_s *, cast_ptr(const char *, d) + data_record_offset);
}
static attr_always_inline unsigned char *da_array_flat(struct data *d)
{
	da_assert(d,array_flat);
	return cast_ptr(unsigned char *, d) + data_array_offset;
}
#define DATA_TAG_is_array(tag)		((tag) >= DATA_TAG_array_flat && (tag) <= DATA_TAG_array_btree)
#define da_array_flat_element_size(d) ((size_t)da(d,array_flat)->type->size)
#define da_array_depth(d)	(ajla_assert(DATA_TAG_is_array(da_tag(d)), (file_line, "da_array_depth: invalid tag %u", da_tag(d))), da_tag(d) == DATA_TAG_array_btree ? (int)da(d,array_btree)->depth : -1)
#define da_array_assert_son(parent, son)	(			\
	ajla_assert(da(parent,array_btree)->n_used_btree_entries >= 2 && da(parent,array_btree)->n_used_btree_entries <= BTREE_MAX_SIZE, (file_line, "da_array_assert_son: invalid parent size %"PRIuMAX"", (uintmax_t)da(parent,array_btree)->n_used_btree_entries)),\
	ajla_assert(da_array_depth(son) + 1 == da_array_depth(parent), (file_line, "da_array_assert_son: depth mismatch: %d, %d", da_array_depth(parent), da_array_depth(son)))\
	)

static attr_always_inline const struct type *da_type(struct data *fn, size_t idx)
{
	struct data *t = pointer_get_data(da(fn,function)->types_ptr);
	ajla_assert(idx < da(t,function_types)->n_types, (file_line, "da_type: access out of range: %"PRIuMAX" >= %"PRIuMAX"", (uintmax_t)idx, (uintmax_t)da(t,function_types)->n_types));
	return da(t,function_types)->types[idx];
}

#define function_frame_size(fn)		((size_t)da(fn,function)->frame_slots * slot_size)
#define function_n_variables(fn)	((size_t)da(fn,function)->frame_slots - frame_offset / slot_size)

static inline void *da_resource(struct data *d)
{
	da_assert(d,resource);
	return cast_ptr(void *, cast_ptr(const char *, d) + data_resource_offset);
}


static attr_always_inline struct data *data_init_(struct data *d, tag_t tag)
{
	if (unlikely(!d))
		return NULL;
#if defined(DATA_TAG_AT_ALLOC)
	d = cast_cpp(struct data *, num_to_ptr(ptr_to_num(d) + ((uintptr_t)tag << POINTER_IGNORE_START)));
#endif
#if defined(REFCOUNT_TAG)
	refcount_init_tag(&d->refcount_, tag);
#else
	d->tag = tag;
	refcount_init(&d->refcount_);
#endif
	return d;
}

static attr_always_inline void *data_pointer_tag(void *d, tag_t attr_unused tag)
{
#if defined(DATA_TAG_AT_ALLOC)
	d = cast_cpp(void *, num_to_ptr(ptr_to_num(d) + ((uintptr_t)tag << POINTER_IGNORE_START)));
#endif
	return d;
}

#define data_alloc(kind, mayfail)					data_init_(mem_alloc_compressed_mayfail(struct data *, partial_sizeof(struct data, u_.kind), mayfail), DATA_TAG_##kind)
#define data_align(kind, size, align, mayfail)				data_init_(mem_align_compressed_mayfail(struct data *, maximum_maybe0(size, partial_sizeof_lower_bound(struct data)), align, mayfail), DATA_TAG_##kind)
#define data_calign(kind, size, align, mayfail)				data_init_(mem_calign_compressed_mayfail(struct data *, maximum_maybe0(size, partial_sizeof_lower_bound(struct data)), align, mayfail), DATA_TAG_##kind)
#define data_alloc_flexible(kind, array, size, mayfail)			data_init_(struct_alloc_array_mayfail(mem_alloc_compressed_mayfail, struct data, u_.kind.array, size, mayfail), DATA_TAG_##kind)

static inline void *data_untag_(void *d, const char attr_unused *fl)
{
#if defined(DATA_TAG_AT_ALLOC)
	unsigned mask = DATA_TAG_END - 1;
	mask = mask | (mask >> 1);
	mask = mask | (mask >> 2);
	mask = mask | (mask >> 4);
	mask = mask | (mask >> 8);
	ajla_assert((ptr_to_num(d) & ((uintptr_t)mask << POINTER_IGNORE_START)) != 0, (fl, "data_untag_: pointer not tagged: %p", d));
	return num_to_ptr(ptr_to_num(d) & ~((uintptr_t)mask << POINTER_IGNORE_START));
#else
	return d;
#endif
}
#define data_untag(d)	data_untag_(d, file_line)
#define data_free(d)	do { refcount_poison_tag(&(d)->refcount_); mem_free_compressed(data_untag(d)); } while (0)
#define data_free_r1(d)	do { ajla_assert(refcount_is_one(&(d)->refcount_), (file_line, "freeing data with invalid refcount")); data_free(d); } while (0)


/*********
 * THUNK *
 *********/

struct stack_trace_entry {
	const struct module_designator *module_designator;
	const char *function_name;
	unsigned line;
};

struct stack_trace {
	struct stack_trace_entry *trace;
	size_t trace_n;
};

struct thunk_exception {
	ajla_error_t err;
	char *msg;
	struct stack_trace tr;
};

struct thunk_result {
	pointer_t ptr;
	bool wanted;
};

struct thunk {
	refcount_t refcount_;
#ifndef REFCOUNT_TAG
	tag_t tag;
#endif
	union {
		/* THUNK_TAG_FUNCTION_CALL */
		/* THUNK_TAG_BLACKHOLE */
		/* THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED */
		/* THUNK_TAG_BLACKHOLE_DEREFERENCED */
		/* THUNK_TAG_RESULT */
		struct {
			union {
				/* THUNK_TAG_FUNCTION_CALL */
				pointer_t function_reference;
				/* THUNK_TAG_BLACKHOLE */
				/* THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED */
				/* THUNK_TAG_BLACKHOLE_DEREFERENCED */
				struct execution_control *execution_control;
			} u;
			struct thunk_result results[1];
		} function_call;
		/* THUNK_TAG_MULTI_RET_REFERENCE */
		struct {
			struct thunk *thunk;
			arg_t idx;
		} multi_ret_reference;
		/* THUNK_TAG_EXCEPTION */
		struct thunk_exception exception;
	} u;
};

static inline tag_t thunk_tag_(struct thunk *t, const char attr_unused *position)
{
	tag_t tag;
#ifndef REFCOUNT_TAG
	tag = t->tag;
#else
	tag = refcount_tag_get(&t->refcount_);
#endif
	ajla_assert(tag >= THUNK_TAG_START && tag < THUNK_TAG_END, (position, "invalid thunk tag %u", tag));
	return tag;
}
#define thunk_tag(t)		thunk_tag_(t, file_line)

static inline tag_t thunk_tag_volatile_(struct thunk *t, const char attr_unused *position)
{
	tag_t tag;
#ifndef REFCOUNT_TAG
	tag = *cast_ptr(thread_volatile tag_t *, &t->tag);
#else
	tag = refcount_tag_get(&t->refcount_);
#endif
	ajla_assert(tag >= THUNK_TAG_START && tag < THUNK_TAG_END, (position, "invalid thunk tag %u", tag));
	return tag;
}
#define thunk_tag_volatile(t)	thunk_tag_volatile_(t, file_line)

static inline void thunk_tag_set_(struct thunk *t, tag_t attr_unused old_tag, tag_t new_tag, const char attr_unused *position)
{
#ifndef REFCOUNT_TAG
	ajla_assert(t->tag == old_tag, (position, "thunk_tag_set: tag does not match: %u != %u; new tag %u", t->tag, old_tag, new_tag));
	t->tag = new_tag;
#else
	refcount_tag_set_(&t->refcount_, old_tag, new_tag, position);
#endif
}
#define thunk_tag_set(t, old_tag, new_tag)	thunk_tag_set_(t, old_tag, new_tag, file_line)

static inline tag_t da_thunk_tag_(void *dt, const char attr_unused *position)
{
	tag_t tag;
#ifndef REFCOUNT_TAG
	ajla_assert(offsetof(struct data, tag) == offsetof(struct thunk, tag), (position, "da_thunk_tag: the data_structure doesn't match the thunk structure"));
	tag = *cast_ptr(tag_t *, cast_ptr(char *, dt) + offsetof(struct data, tag));
#else
	ajla_assert(offsetof(struct data, refcount_) == offsetof(struct thunk, refcount_), (position, "da_thunk_tag: the data_structure doesn't match the thunk structure"));
	tag = refcount_tag_get(cast_ptr(refcount_t *, cast_ptr(char *, dt) + offsetof(struct data, refcount_)));
#endif
	ajla_assert(tag >= DATA_TAG_START && tag < TAG_END, (position, "invalid thunk tag %u", tag));
	return tag;
}
#define da_thunk_tag(dt)			da_thunk_tag_(dt, file_line)

#define tag_is_thunk(tag)	((tag) >= THUNK_TAG_START)

static inline refcount_t *da_thunk_refcount_(void *dt, const char attr_unused *position)
{
	ajla_assert(offsetof(struct data, refcount_) == offsetof(struct thunk, refcount_), (position, "da_thunk_tag: the data_structure doesn't match the thunk structure"));
	return cast_ptr(refcount_t *, cast_ptr(char *, dt) + offsetof(struct data, refcount_));
}
#define da_thunk_refcount(dt)			da_thunk_refcount_(dt, file_line)

/*
 * May be called if the thunk is locked or if the thunk is on current frame
 * (so that it won't be modified asynchronously)
 */
static inline bool thunk_is_finished(struct thunk *t)
{
	tag_t tag = thunk_tag_volatile(t);
	return   tag == THUNK_TAG_RESULT ||
		(tag == THUNK_TAG_MULTI_RET_REFERENCE && thunk_tag_volatile(t->u.multi_ret_reference.thunk) == THUNK_TAG_RESULT);
}

static inline struct thunk *thunk_pointer_tag(struct thunk *t)
{
#ifdef POINTER_TAG_AT_ALLOC
	t = cast_cpp(struct thunk *, num_to_ptr(ptr_to_num(t) | POINTER_IGNORE_TOP));
#endif
	return t;
}

static inline void *thunk_untag_(struct thunk *t, const char attr_unused *fl)
{
#if defined(POINTER_TAG_AT_ALLOC)
	ajla_assert((ptr_to_num(t) & POINTER_IGNORE_TOP) != 0, (fl, "thunk_untag_: pointer not tagged: %p", t));
	return num_to_ptr(ptr_to_num(t) & ~POINTER_IGNORE_TOP);
#else
	return t;
#endif
}
#define thunk_untag(t)				thunk_untag_(t, file_line)
#define thunk_free(t)				do { refcount_poison_tag(&t->refcount_); mem_free_compressed(thunk_untag(t)); } while (0)

#if defined(POINTER_COMPRESSION)
#define SAVED_DATA_ALIGN			maximum(maximum(maximum(align_of(struct data), align_of(struct thunk)), sizeof(refcount_int_t)), pointer_compress_alignment)
#else
#define SAVED_DATA_ALIGN			maximum(maximum(align_of(struct data), align_of(struct thunk)), sizeof(refcount_int_t))
#endif


/*********
 * FRAME *
 *********/

typedef unsigned timestamp_t;

#define CALL_MODE_NORMAL	1
#define CALL_MODE_STRICT	2
#define CALL_MODE_SPARK		3
#define CALL_MODE_WEAKSPARK	4
#define CALL_MODE_VALID(v)	((v) >= 1 && (v) <= 4)

struct frame_struct {
	struct data *function;
	ip_t previous_ip;
	timestamp_t timestamp;
	stack_size_t available_slots;
	uchar_efficient_t mode;
#ifdef DEBUG
	/* deliberately misalign variables to catch alignment errors */
	char misalign;
#endif
	char variables_[FLEXIBLE_ARRAY];
};

struct stack_bottom {
	struct execution_control *ex;
	stack_size_t useable_slots;
	pointer_t ret;
};

#define SIZEOF_FRAME_STRUCT	partial_sizeof_array(struct frame_struct, variables_, 0)
#define SIZEOF_STACK_BOTTOM	round_up(sizeof(struct stack_bottom), max_frame_align)
#define frame_offset		round_up(offsetof(struct frame_struct, variables_), slot_align)

#ifndef INLINE_WORKS
#define ptr_frame(fp)	(cast_ptr(frame_s *, cast_ptr(const char *, fp) + frame_offset))
#define get_frame(fp)	(cast_ptr(struct frame_struct *, cast_ptr(const char *, fp) - frame_offset))
#else
static attr_always_inline frame_s *ptr_frame(const struct frame_struct *fp)
{
	return cast_ptr(frame_s *, cast_ptr(const char *, fp) + frame_offset);
}
static attr_always_inline struct frame_struct *get_frame(const frame_s *fp)
{
	return cast_ptr(struct frame_struct *, cast_ptr(const char *, fp) - frame_offset);
}
#endif

static inline const struct type *frame_get_type_of_local(const frame_s *fp, frame_t pos)
{
	const struct type *t;
	const struct data *function = get_frame(fp)->function;
	t = da(function,function)->local_variables[pos].type;
	TYPE_TAG_VALIDATE(t->tag);
	return t;
}

static inline ip_t frame_ip(const frame_s *fp, const code_t *ip)
{
	ajla_assert(ip >= da(get_frame(fp)->function,function)->code, (file_line, "frame_ip: invalid ip pointer: %p, %p", ip, da(get_frame(fp)->function,function)->code));
	return (ip_t)(ip - da(get_frame(fp)->function,function)->code);
}

static inline frame_s * attr_fastcall frame_up(frame_s *fp)
{
	char *next = cast_ptr(char *, fp) + function_frame_size(get_frame(fp)->function);
	return cast_ptr(frame_s *, next);
}

static inline bool frame_is_top(frame_s *fp)
{
	return get_frame(fp)->function == NULL;
}

static inline struct stack_bottom *frame_stack_bottom(frame_s *fp)
{
	char *bottom = cast_ptr(char *, get_frame(fp)) - get_frame(fp)->available_slots * slot_size - SIZEOF_STACK_BOTTOM;
	return cast_ptr(struct stack_bottom *, bottom);
}

static inline struct execution_control *frame_execution_control(frame_s *fp)
{
	return frame_stack_bottom(fp)->ex;
}

static inline void stack_free(struct stack_bottom *stack)
{
	mem_free_aligned(stack);
}

static inline void frame_init(frame_s *fp, struct data *function, timestamp_t timestamp, uchar_efficient_t mode)
{
	ajla_assert(!(da(function,function)->frame_slots & (frame_align / slot_size - 1)), (file_line, "frame_init: function size %"PRIuMAX" is not aligned to %x", (uintmax_t)da(function,function)->frame_slots, (unsigned)(frame_align / slot_size)));
	ajla_assert(CALL_MODE_VALID(mode), (file_line, "frame_init: invalid mode %u", mode));
	if (unlikely(profiling)) {
		profile_counter_t call_counter = load_relaxed(&da(function,function)->call_counter);
		call_counter++;
		store_relaxed(&da(function,function)->call_counter, call_counter);
	}
	get_frame(fp)->timestamp = timestamp;
	get_frame(fp)->mode = mode;
#ifdef DEBUG
	(void)memset(fp, rand(), da(function,function)->frame_slots * slot_size - frame_offset);
#endif
	(void)memset(fp, 0, da(function,function)->n_bitmap_slots * slot_size);
}

frame_s * attr_fastcall stack_alloc(struct execution_control *ex, struct data *function, ajla_error_t *mayfail);
frame_s * attr_fastcall stack_expand(frame_s *fp, struct data *function, ajla_error_t *mayfail);
frame_s * attr_fastcall stack_split(frame_s *from_fp, frame_s *to_fp, frame_s **high, ajla_error_t *mayfail);

/*void frame_cleanup(frame_s *fp);*/

/***************
 * STACK TRACE *
 ***************/

void stack_trace_init(struct stack_trace *st);
void stack_trace_free(struct stack_trace *st);
bool stack_trace_get_location(struct data *function, ip_t ip_rel, struct stack_trace_entry *result);
void stack_trace_capture(struct stack_trace *st, frame_s *fp, const code_t *ip, unsigned max_depth);
char *stack_trace_string(struct stack_trace *st, ajla_error_t *err);
void stack_trace_print(struct stack_trace *st);


/*********************
 * OBJECT ALLOCATION *
 *********************/

struct data * attr_fastcall data_alloc_flat_mayfail(type_tag_t type, const unsigned char *flat, size_t size, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_longint_mayfail(unsigned long bits, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_option_mayfail(ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_record_mayfail(const struct record_definition *def, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_array_flat_mayfail(const struct type *type, int_default_t n_allocated, int_default_t n_used, bool clear, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_array_slice_mayfail(struct data *base, unsigned char *data, int_default_t start, int_default_t len, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_array_pointers_mayfail(int_default_t n_allocated, int_default_t n_used, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_array_same_mayfail(array_index_t n_entries, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_array_incomplete(struct data *first, pointer_t next, ajla_error_t *mayfail argument_position);
struct data * attr_fastcall data_alloc_function_reference_mayfail(arg_t n_curried_arguments, ajla_error_t *mayfail argument_position);
void attr_fastcall data_fill_function_reference(struct data *function_reference, arg_t a, pointer_t ptr);
void attr_fastcall data_fill_function_reference_flat(struct data *function_reference, arg_t a, const struct type *type, const unsigned char *data);
struct data * attr_fastcall data_alloc_resource_mayfail(size_t size, void (*close)(struct data *), ajla_error_t *mayfail argument_position);

extern pointer_t *out_of_memory_ptr;
struct thunk * attr_fastcall thunk_alloc_exception_error(ajla_error_t err, char *msg, frame_s *fp, const code_t *ip argument_position);
pointer_t attr_fastcall pointer_error(ajla_error_t err, frame_s *fp, const code_t *ip argument_position);
char *thunk_exception_string(struct thunk *thunk, ajla_error_t *err);
char *thunk_exception_payload(struct thunk *thunk, ajla_error_t *err);
void thunk_exception_print(struct thunk *thunk);

bool attr_fastcall thunk_alloc_function_call(pointer_t function_reference, arg_t n_return_values, struct thunk *result[], ajla_error_t *mayfail);
bool attr_fastcall thunk_alloc_blackhole(struct execution_control *ex, arg_t n_return_values, struct thunk *result[], ajla_error_t *mayfail);


/*********************
 * EXECUTION CONTROL *
 *********************/

#define N_EXECUTION_CONTROL_WAIT	2

#define EXECUTION_CONTROL_NORMAL	4
#define EXECUTION_CONTROL_ARMED		3
#define EXECUTION_CONTROL_FIRED		1

/*
 * execution_control_wait->thunk == NULL
 *	- unused entry
 * execution_control_wait->thunk != NULL, list_is_empty(&execution_control_wait->wait_entry)
 *	- unused, but we must take thunk lock to clear it
 * execution_control_wait->thunk != NULL, !list_is_empty(execution_control_wait->wait_entry.next)
 *	- wait_entry is linked to an existing execution control
 */

struct execution_control_wait {
	struct list wait_entry;
	mutex_t *mutex_to_lock;
	struct execution_control *execution_control;
};

struct execution_control {
	ip_t current_ip;
	frame_s *current_frame;
	struct stack_bottom *stack;

	struct thunk *thunk;
	struct list wait_list;

	void (*callback)(void *, pointer_t);
	void *callback_cookie;

	refcount_t wait_state;
	struct list waiting_list_entry;
	void *waiting_list_head;
	struct execution_control_wait wait[N_EXECUTION_CONTROL_WAIT];

	uint64_t atomic;
	bool atomic_interrupted;
};

bool are_there_dereferenced(void);
void execution_control_unlink_and_submit(struct execution_control *ex, unsigned spawn_mode);
bool execution_control_acquire(struct execution_control *ex);
void wake_up_wait_list(struct list *wait_list, mutex_t *mutex_to_lock, unsigned spawn_mode);
void *thunk_terminate(struct thunk *t, arg_t n_return_values);
struct execution_control *execution_control_alloc(ajla_error_t *mayfail);
void execution_control_free(struct execution_control *ex);
void execution_control_terminate(struct execution_control *ex, pointer_t ptr);


/**********************
 * POINTER OPERATIONS *
 **********************/

void free_cache_entry(struct data *d, struct cache_entry *ce);

static attr_always_inline refcount_t *pointer_get_refcount_(pointer_t ptr)
{
	void *p = pointer_get_value_strip_tag_(ptr);
	return !pointer_is_thunk(ptr) ? &((struct data *)p)->refcount_ : &((struct thunk *)p)->refcount_;
}

void attr_fastcall pointer_dereference_(pointer_t ptr argument_position);
#define pointer_dereference(ptr)	pointer_dereference_(ptr pass_file_line)

static inline void data_dereference(struct data *data)
{
	pointer_dereference(pointer_data(data));
}

static inline void pointer_reference_owned(pointer_t ptr)
{
	refcount_t *r = pointer_get_refcount_(ptr);
	if (likely(!refcount_is_read_only(r)))
		refcount_inc(r);
}

static inline void pointer_reference_owned_multiple(pointer_t ptr, refcount_int_t n)
{
	refcount_t *r = pointer_get_refcount_(ptr);
	if (likely(!refcount_is_read_only(r)))
		refcount_add(r, n);
}

static inline void data_reference(struct data *d)
{
	if (likely(!refcount_is_read_only(&d->refcount_)))
		refcount_inc(&d->refcount_);
}

static inline void thunk_reference(struct thunk *t)
{
	if (likely(!refcount_is_read_only(&t->refcount_)))
		refcount_inc(&t->refcount_);
}

static inline void thunk_reference_nonatomic(struct thunk *t)
{
	refcount_inc_nonatomic(&t->refcount_);
}

static inline bool thunk_dereference_nonatomic(struct thunk *t)
{
	return refcount_dec_nonatomic(&t->refcount_);
}

static inline bool thunk_refcount_is_one_nonatomic(struct thunk *t)
{
	return refcount_is_one_nonatomic(&t->refcount_);
}

static inline refcount_int_t thunk_refcount_get_nonatomic(struct thunk *t)
{
	return refcount_get_nonatomic(&t->refcount_);
}

static inline void thunk_assert_refcount(struct thunk attr_unused *t)
{
	ajla_assert_lo(!refcount_is_invalid(&t->refcount_), (file_line, "thunk_assert_refcount: invalid refcount"));
}

pointer_t attr_fastcall pointer_reference_(pointer_t *ptr argument_position);
#define pointer_reference(ptr)				pointer_reference_(ptr pass_file_line)
void pointer_reference_maybe_(frame_s *fp, frame_t result, pointer_t *ptr, unsigned char flags argument_position);
#define pointer_reference_maybe(fp, result, ptr, flags)	pointer_reference_maybe_(fp, result, ptr, flags pass_file_line)


static inline bool data_is_writable(struct data *d)
{
	return refcount_is_one(&d->refcount_);
}

static inline bool thunk_is_writable(struct thunk *t)
{
	return refcount_is_one(&t->refcount_);
}


#ifdef POINTER_FOLLOW_IS_LOCKLESS
#define pointer_volatile(ptr)		((thread_volatile pointer_t *)(ptr))
#define pointer_lock(ptr)		do { } while (0)
#define pointer_unlock(ptr)		do { } while (0)
#define pointer_dependency_barrier()	barrier_data_dependency()
#else
#define pointer_volatile(ptr)		(ptr)
#define pointer_lock(ptr)		address_lock(ptr, DEPTH_POINTER)
#define pointer_unlock(ptr)		address_unlock(ptr, DEPTH_POINTER)
#define pointer_dependency_barrier()	do { } while (0)
#endif

static inline pointer_t pointer_locked_read(pointer_t *ptr)
{
	pointer_t ret;
	pointer_lock(ptr);
	ret = *pointer_volatile(ptr);
	pointer_validate(ret);
	if (!pointer_is_thunk(ret))
		pointer_dependency_barrier();
	pointer_unlock(ptr);
	return ret;
}

static inline void pointer_locked_write(pointer_t *ptr, pointer_t val)
{
	pointer_validate(val);
	pointer_lock(ptr);
	*pointer_volatile(ptr) = val;
	pointer_unlock(ptr);
}

#define POINTER_FOLLOW_THUNK_EXIT	NULL
#define POINTER_FOLLOW_THUNK_RETRY	SPECIAL_POINTER_1
#define POINTER_FOLLOW_THUNK_EXCEPTION	SPECIAL_POINTER_2
#define POINTER_FOLLOW_THUNK_GO		SPECIAL_POINTER_3

void copy_from_function_reference_to_frame(frame_s *new_fp, struct data *ref, arg_t ia, char can_move);
#define POINTER_FOLLOW_THUNK_NOEVAL	NULL
#define POINTER_FOLLOW_THUNK_SPARK	SPECIAL_POINTER_1
void * attr_fastcall pointer_follow_thunk_(pointer_t *ptr, void *ex_wait);
void attr_fastcall pointer_resolve_result(pointer_t *ptr);
void attr_fastcall pointer_follow_wait(frame_s *fp, const code_t *ip);

#define pointer_follow_thunk_noeval(ptr, retry_code, exception_code, uneval_code)\
do {									\
	void *ex__ = pointer_follow_thunk_(ptr, POINTER_FOLLOW_THUNK_NOEVAL);\
	if (ex__ == POINTER_FOLLOW_THUNK_RETRY) {			\
		{ retry_code; }						\
		not_reached();						\
	} else if (ex__ == POINTER_FOLLOW_THUNK_EXCEPTION) {		\
		{ exception_code; }					\
		not_reached();						\
	} else {							\
		ajla_assert(ex__ == POINTER_FOLLOW_THUNK_EXIT, (file_line, "pointer_follow_thunk_noeval: invalid return value %p", ex__));\
		{ uneval_code; }					\
		not_reached();						\
	}								\
} while (1)

#define PF_SPARK	(-2)
#define PF_NOEVAL	(-1)
#define PF_WAIT		(0)
#define PF_PREPARE0	(2)
#define PF_PREPARE1	(3)

#define pointer_follow(ptr, owned, result, wait_idx, fp, ip, xc_code, exception_code)\
do {									\
	pointer_t p_;							\
	if (!(owned))							\
		p_ = pointer_locked_read(ptr);				\
	else								\
		p_ = *(ptr);						\
	if (likely(!pointer_is_thunk(p_))) {				\
		(result) = pointer_get_data(p_);			\
		break;							\
	} else {							\
		void *ex__;						\
		ex__ = pointer_follow_thunk_(ptr, (wait_idx) >= 0 ? &frame_execution_control(fp)->wait[(wait_idx) & 1] : (wait_idx) == PF_NOEVAL ? POINTER_FOLLOW_THUNK_NOEVAL : POINTER_FOLLOW_THUNK_SPARK);\
		if (ex__ == POINTER_FOLLOW_THUNK_RETRY)			\
			continue;					\
		if (ex__ == POINTER_FOLLOW_THUNK_EXCEPTION) {		\
			struct thunk attr_unused *thunk_;		\
			thunk_ = pointer_get_thunk(*(ptr));		\
			{ exception_code; }				\
			not_reached();					\
		}							\
		{							\
			struct execution_control attr_unused *ex_;	\
			ex_ = cast_cpp(struct execution_control *, ex__);\
			if ((wait_idx) >= 0 && !((wait_idx) & 2)) {	\
				pointer_follow_wait(fp, ip);		\
			}						\
			{ xc_code; }					\
			not_reached();					\
		}							\
	}								\
} while (1)

#define pointer_follow_fastfail(ptr, owned, result, success_code)	\
do {									\
	pointer_t p_;							\
	if (!(owned))							\
		p_ = pointer_locked_read(ptr);				\
	else								\
		p_ = *(ptr);						\
	if (likely(!pointer_is_thunk(p_))) {				\
		(result) = pointer_get_data(p_);			\
		{ success_code; }					\
	}								\
} while (0)


bool attr_fastcall data_is_nan(type_tag_t type, const unsigned char *ptr);
pointer_t flat_to_data(const struct type *type, const unsigned char *flat);
bool attr_fastcall data_to_flat(frame_s *fp, frame_t slot);
void attr_fastcall struct_clone(pointer_t *ptr);

void * attr_fastcall pointer_deep_eval(pointer_t *ptr, frame_s *fp, const code_t *ip, struct thunk **thunk);
void * attr_fastcall frame_pointer_deep_eval(frame_s *fp, const code_t *ip, frame_t slot, struct thunk **thunk);

bool attr_fastcall mpint_export(const mpint_t *m, unsigned char *ptr, unsigned intx, ajla_error_t *err);
bool attr_fastcall mpint_export_unsigned(const mpint_t *m, unsigned char *ptr, unsigned intx, ajla_error_t *err);

int data_compare_numbers(type_tag_t tt, unsigned char *flat1, pointer_t ptr1, unsigned char *flat2, pointer_t ptr2);
#define DATA_COMPARE_OOM	-2
int attr_fastcall data_compare(pointer_t ptr1, pointer_t ptr2, ajla_error_t *mayfail);


static inline bool attr_hot_fastcall frame_variable_is_flat(frame_s *fp, frame_t slot)
{
	return !frame_test_flag(fp, slot) && TYPE_IS_FLAT(frame_get_type_of_local(fp, slot));
}

static attr_always_inline void attr_hot_fastcall frame_free(frame_s *fp, frame_t slot)
{
	if (frame_test_and_clear_flag(fp, slot)) {
		pointer_dereference(*frame_pointer(fp, slot));
		/* when the flag is not set, we must not clear the slot */
		*frame_pointer(fp, slot) = pointer_empty();
	}
}

static attr_always_inline void attr_hot_fastcall frame_free_and_clear(frame_s *fp, frame_t slot)
{
	frame_free(fp, slot);
	*frame_pointer(fp, slot) = pointer_empty();
}

static attr_always_inline void attr_hot_fastcall frame_free_and_set_pointer(frame_s *fp, frame_t slot, pointer_t ptr)
{
	if (frame_test_and_set_flag(fp, slot))
		pointer_dereference(*frame_pointer(fp, slot));
	*frame_pointer(fp, slot) = ptr;
}

static attr_always_inline void frame_set_pointer(frame_s *fp, frame_t slot, pointer_t ptr)
{
	ajla_assert(!frame_test_flag(fp, slot), (file_line, "frame_set_pointer: flag for slot %"PRIuMAX" already set", (uintmax_t)slot));
	frame_set_flag(fp, slot);
	*frame_pointer(fp, slot) = ptr;
}

static attr_always_inline pointer_t frame_get_pointer_reference(frame_s *fp, frame_t slot, bool deref)
{
	pointer_t ptr = *frame_pointer(fp, slot);
	pointer_validate(ptr);
	if (!deref) {
		goto do_ref_owned;
	} else {
		*frame_pointer(fp, slot) = pointer_empty();
		if (!frame_test_and_clear_flag(fp, slot))
do_ref_owned:
			pointer_reference_owned(ptr);
	}
	return ptr;
}


/**********************
 * DATA SERIALIZATION *
 **********************/

struct stack_entry;

struct stack_entry_type {
	void *(*get_ptr)(struct stack_entry *ste);
	bool (*get_properties)(struct stack_entry *ste, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_len);
	void (*fixup_after_copy)(void *new_ptr);
	void (*fixup_sub_ptr)(void *loc, uintptr_t offset);
	bool wrap_on_save;
};

struct stack_entry {
	const struct stack_entry_type *t;
	void *ptr;
	size_t align;
	size_t size;
};

bool data_save(void *p, uintptr_t offset, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l);
bool data_save_init_stack(pointer_t *ptr, struct stack_entry **stk, size_t *stk_l);

/*********
 * TRAPS *
 *********/

void *data_trap_lookup(void *ptr);
void data_trap_insert(struct data *codegen);

#endif
