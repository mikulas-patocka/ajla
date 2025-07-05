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

#include "tree.h"
#include "thread.h"
#include "addrlock.h"
#include "mem_al.h"
#include "os.h"

#include "amalloc.h"

#ifdef USE_AMALLOC

/*#define AMALLOC_EAGER_FREE*/
/*#define AMALLOC_TRIM_MIDBLOCKS*/
/*#define AMALLOC_USE_RANDOM_ROVER*/

#if defined(OS_OS2)
#ifndef OBJ_ANY
#define OBJ_ANY		0x0400
#endif
static ULONG dosallocmem_attrib = PAG_READ | PAG_WRITE |
#ifdef CODEGEN_USE_HEAP
			PAG_EXECUTE |
#endif
			OBJ_ANY;
#else
#ifndef CODEGEN_USE_HEAP
#define PROT_HEAP	(PROT_READ | PROT_WRITE)
#else
#define PROT_HEAP	(PROT_READ | PROT_WRITE | PROT_EXEC)
#endif
#endif

#define ARENA_BITS	21
#define ARENA_SIZE	((size_t)1 << ARENA_BITS)

#define MIDBLOCK_BITS	9
#define MIDBLOCK_SIZE	((size_t)1 << MIDBLOCK_BITS)

#define SMALL_BLOCK_TRIES	16

#define MIN_ALLOC	16
#define DIRECT_LIMIT	512
#define N_CLASSES	(DIRECT_LIMIT / MIN_ALLOC)
#define SIZE_TO_INDEX(s) (((unsigned)(s) + MIN_ALLOC - 1) / MIN_ALLOC)
#define INDEX_TO_CLASS(i) (!(i) ? 0 : (i) - 1)
#define CLASS_TO_SIZE(c) (((size_t)(c) + 1) * MIN_ALLOC)

#define ARENA_MIDBLOCKS	(ARENA_SIZE / MIDBLOCK_SIZE)

#define BITMAP_BITS	EFFICIENT_WORD_SIZE
#define bitmap_t	cat4(uint,BITMAP_BITS,_,t)

struct arena {
	struct tree midblock_free;
	struct tree_entry arena_entry;
	ushort_efficient_t max_midblock_run;
	uchar_efficient_t attached;
	int numa_node;
	ushort_efficient_t map[ARENA_MIDBLOCKS];
};

#define MAP_FREE	0x8000

#define ARENA_PREFIX	(round_up(sizeof(struct arena), MIDBLOCK_SIZE) >> MIDBLOCK_BITS)
#define MIDBLOCK_LIMIT	((ARENA_SIZE - (ARENA_PREFIX << MIDBLOCK_BITS)) / 2)

union midblock {
	struct tree_entry free_entry;
	struct {
		bitmap_t map;
		atomic_type bitmap_t atomic_map;
#ifdef AMALLOC_EAGER_FREE
		size_t index;
#endif
		uchar_efficient_t reserved_bits;
		uchar_efficient_t cls;
		ushort_efficient_t size;
		ushort_efficient_t reciprocal;
#define RECIPROCAL_BASE		0x8000
	} s;
};

struct huge_entry {
	void *ptr;
	size_t len;
	struct tree_entry entry;
};

struct per_thread {
	struct arena *arena;
	union midblock *small_runs[N_CLASSES + 1];
	tls_destructor_t destructor;
};

int u_name(task_get_numa_node)(void);
int c_name(task_get_numa_node)(void);

static union midblock full_midblock;

static struct per_thread thread1;

static tls_decl(struct per_thread *, per_thread);

static uchar_efficient_t amalloc_threads_initialized;

static struct tree arena_tree;
static mutex_t arena_tree_mutex;

static struct tree huge_tree;
static mutex_t huge_tree_mutex;

static size_t page_size;

static struct small_block_cache {
	union midblock **array;
	size_t array_size;
	size_t allocated_size;
#ifndef AMALLOC_USE_RANDOM_ROVER
	size_t rover;
#else
	unsigned rover;
#endif
	mutex_t mutex;
} small_block_cache[N_CLASSES];


#if BITMAP_BITS == 16
#define BITMAP_ASM_X86_SUFFIX	"w"
#elif BITMAP_BITS == 32
#define BITMAP_ASM_X86_SUFFIX	"l"
#elif BITMAP_BITS == 64
#define BITMAP_ASM_X86_SUFFIX	"q"
#endif

static attr_always_inline size_t find_bit(bitmap_t bitmap)
{
#if defined(BITMAP_ASM_X86_SUFFIX) && defined(INLINE_ASM_GCC_X86)
	__asm__ ("rep; bsf"BITMAP_ASM_X86_SUFFIX" %1, %0" : "=r"(bitmap) : "r"(bitmap) : "cc");
	return bitmap;
#endif
#if BITMAP_BITS == 32 && defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_RBIT) && defined(HAVE_ARM_ASSEMBLER_CLZ)
	if (likely(cpu_test_feature(CPU_FEATURE_armv6t2))) {
		__asm__ (ARM_ASM_PREFIX "rbit %0, %1; clz %0, %0" : "=r"(bitmap) : "r"(bitmap) : "cc");
		return bitmap;
	}
#endif
#if defined(ARCH_ALPHA) && defined(HAVE_GCC_ASSEMBLER)
	if (likely(cpu_test_feature(CPU_FEATURE_cix))) {
		__asm__ (".arch ev68; cttz %1, %0" : "=r"(bitmap) : "r"(bitmap));
		return bitmap;
	}
#endif
#if defined(ARCH_RISCV64) && defined(HAVE_GCC_ASSEMBLER) && !defined(__riscv_zbb)
	if (likely(cpu_test_feature(CPU_FEATURE_zbb))) {
		if (BITMAP_BITS == 32) {
			__asm__ ("mv t6, %1; .word 0x601f9f9b; mv %0, t6" : "=r"(bitmap) : "r"(bitmap) : "t6");
			return bitmap;
		}
		if (BITMAP_BITS == 64) {
			__asm__ ("mv t6, %1; .word 0x601f9f93; mv %0, t6" : "=r"(bitmap) : "r"(bitmap) : "t6");
			return bitmap;
		}
	}
#endif
#if defined(ARCH_S390_64) && defined(HAVE_GCC_ASSEMBLER) && !(__ARCH__ >= 7)
	if (likely(cpu_test_feature(CPU_FEATURE_extended_imm))) {
		if (BITMAP_BITS == 32) {
			__asm__("llgfr %%r1, %1; .long 0xb9830001; lgr %0, %%r0" : "=r"(bitmap) : "r"(bitmap & -bitmap) : "r0", "r1", "cc");
			return 63 - bitmap;
		}
		if (BITMAP_BITS == 64) {
			__asm__("lgr %%r1, %1; .long 0xb9830001; lgr %0, %%r0" : "=r"(bitmap) : "r"(bitmap & -bitmap) : "r0", "r1", "cc");
			return 63 - bitmap;
		}
	}
#endif
#if defined(ARCH_SPARC64) && defined(HAVE_GCC_ASSEMBLER)
	__asm__ ("popc %1, %0" : "=r"(bitmap) : "r"((bitmap - 1) & ~bitmap));
	return bitmap;
#endif
#if defined(HAVE_STDBIT_H)
	if (BITMAP_BITS == sizeof(unsigned) * 8)
		return stdc_trailing_zeros_ui(bitmap);
	if (BITMAP_BITS == sizeof(unsigned long) * 8)
		return stdc_trailing_zeros_ul(bitmap);
#endif
#if BITMAP_BITS == 32 && SIZEOF_UNSIGNED == 4 && defined(HAVE_BUILTIN_CTZ)
	return __builtin_ctz(bitmap);
#elif BITMAP_BITS == 64 && SIZEOF_UNSIGNED_LONG_LONG == 8 && defined(HAVE_BUILTIN_CTZ)
	return __builtin_ctzll(bitmap);
#elif BITMAP_BITS == 32 && SIZEOF_UNSIGNED == 4 && defined(HAVE_FFS)
	return ffs(bitmap) - 1;
#elif BITMAP_BITS == 64 && SIZEOF_UNSIGNED_LONG_LONG == 8 && defined(HAVE_FFSLL)
	return ffsll(bitmap) - 1;
#else
	{
		unsigned ret = 0;
		while (1) {
			if (bitmap & 1)
				break;
			ret++;
			bitmap >>= 1;
		}
		return ret;
	}
#endif
}

static attr_always_inline unsigned count_bits(bitmap_t bitmap)
{
#if defined(BITMAP_ASM_X86_SUFFIX) && defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_POPCNT)
	if (likely(cpu_test_feature(CPU_FEATURE_popcnt))) {
		__asm__ ("popcnt"BITMAP_ASM_X86_SUFFIX" %1, %0" : "=r"(bitmap) : "r"(bitmap) : "cc");
		return bitmap;
	}
#endif
#if BITMAP_BITS == 32 && defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_VFP)
	if (likely(cpu_test_feature(CPU_FEATURE_neon))) {
		__asm__ (ARM_ASM_PREFIX "				\n\
			vld1.32		d0[0], [ %0 ]			\n\
			vcnt.8		d0, d0				\n\
			vpaddl.u8	d0, d0				\n\
			vpaddl.u16	d0, d0				\n\
			vst1.32		d0[0], [ %0 ]			\n\
		" : : "r"(&bitmap) : "d0", "memory");
		return bitmap;
	}
#endif
#if BITMAP_BITS == 64 && defined(INLINE_ASM_GCC_ARM64)
	if (likely(cpu_test_feature(CPU_FEATURE_neon))) {
		unsigned result;
		__asm__ (ARM_ASM_PREFIX "				\n\
			fmov		d0, %1				\n\
			cnt		v0.8b, v0.8b			\n\
			uaddlv		h0, v0.8b			\n\
			fmov		%w0, s0				\n\
		" : "=r"(result) : "r"(bitmap) : "d0");
		return result;
	}
#endif
#if defined(ARCH_SPARC64) && defined(HAVE_GCC_ASSEMBLER)
	__asm__ ("popc %1, %0" : "=r"(bitmap) : "r"(bitmap));
	return bitmap;
#endif
#if defined(ARCH_ALPHA) && defined(HAVE_GCC_ASSEMBLER)
	if (likely(cpu_test_feature(CPU_FEATURE_cix))) {
		__asm__ (".arch ev68; ctpop %1, %0" : "=r"(bitmap) : "r"(bitmap));
		return bitmap;
	}
#endif
#if defined(HAVE_STDBIT_H)
	if (BITMAP_BITS == sizeof(unsigned) * 8)
		return stdc_count_ones_ui(bitmap);
	if (BITMAP_BITS == sizeof(unsigned long) * 8)
		return stdc_count_ones_ul(bitmap);
#endif
#if BITMAP_BITS == 32 && SIZEOF_UNSIGNED == 4 && defined(HAVE_BUILTIN_POPCOUNT)
	return __builtin_popcount(bitmap);
#elif BITMAP_BITS == 64 && SIZEOF_UNSIGNED_LONG_LONG == 8 && defined(HAVE_BUILTIN_POPCOUNT)
	return __builtin_popcountll(bitmap);
#else
	{
		unsigned ret = 0;
		while (bitmap)
			bitmap &= bitmap - 1, ret++;
		return ret;
	}
#endif
}

static attr_always_inline uint16_t div_16(uint16_t x, uint16_t y)
{
#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_SDIV_UDIV)
	if (likely(cpu_test_feature(CPU_FEATURE_idiv))) {
		uint16_t result;
		__asm__ (ARM_ASM_PREFIX "udiv %0, %1, %2" : "=r"(result) : "r"((unsigned)x), "r"((unsigned)y));
		return result;
	}
#endif
	return x / y;
}

static attr_always_inline void amalloc_atomic_or(atomic_type bitmap_t *bitmap, bitmap_t value)
{
#if defined(HAVE_C11_ATOMICS)
	atomic_fetch_or_explicit(bitmap, value, memory_order_release);
#elif defined(BITMAP_ASM_X86_SUFFIX) && defined(INLINE_ASM_GCC_X86)
	__asm__ volatile ("lock; or"BITMAP_ASM_X86_SUFFIX" %2, %0":"=m"(*bitmap):"m"(*bitmap),"ir"(value):"cc","memory");
#elif defined(HAVE_SYNC_AND_FETCH)
	__sync_or_and_fetch(bitmap, value);
#else
	if (likely(amalloc_threads_initialized))
		address_lock((void *)bitmap, DEPTH_ARENA);
	*bitmap |= value;
	if (likely(amalloc_threads_initialized))
		address_unlock((void *)bitmap, DEPTH_ARENA);
#endif
}

static attr_always_inline bitmap_t amalloc_atomic_xchg(atomic_type bitmap_t *bitmap, bitmap_t value)
{
#if defined(HAVE_C11_ATOMICS)
	return atomic_exchange_explicit(bitmap, value, memory_order_acquire);
#elif defined(BITMAP_ASM_X86_SUFFIX) && defined(INLINE_ASM_GCC_X86)
	__asm__ volatile ("xchg"BITMAP_ASM_X86_SUFFIX" %1, %0":"=m"(*bitmap),"=r"(value):"m"(*bitmap),"1"(value):"memory");
	return value;
#elif defined(HAVE_SYNC_AND_FETCH)
	bitmap_t v;
	do {
		v = *bitmap;
	} while (unlikely(!__sync_bool_compare_and_swap(bitmap, v, value)));
	return v;
#else
	bitmap_t v;
	if (likely(amalloc_threads_initialized))
		address_lock((void *)bitmap, DEPTH_ARENA);
	v = *bitmap;
	*bitmap = value;
	if (likely(amalloc_threads_initialized))
		address_unlock((void *)bitmap, DEPTH_ARENA);
	return v;
#endif
}


static inline struct arena *addr_to_arena(void *addr)
{
	return num_to_ptr(ptr_to_num(addr) & ~((1 << ARENA_BITS) - 1));
}

static inline union midblock *idx_to_midblock(struct arena *a, unsigned midblock)
{
	return cast_ptr(union midblock *, cast_ptr(char *, a) + (midblock * MIDBLOCK_SIZE));
}

static inline unsigned midblock_to_idx(struct arena *a, void *m)
{
	return (ptr_to_num(m) - ptr_to_num(a)) >> MIDBLOCK_BITS;
}


static void huge_tree_lock(void);
static void huge_tree_unlock(void);

#ifdef OS_OS2

static struct list pad_list;

struct pad_descriptor {
	struct list pad_entry;
	void *base;
	size_t size;
};

static void amalloc_do_unmap(void *ptr, size_t attr_unused size)
{
	APIRET r;
again:
	r = DosFreeMem(ptr);
	if (unlikely(r)) {
		if (r == ERROR_INTERRUPT)
			goto again;
		internal(file_line, "amalloc_do_unmap: DosFreeMem(%p) returned error: %lu", ptr, r);
	}
}

static void *do_dosallocmem(size_t size, bool commit)
{
	APIRET r;
	void *ptr;
again:
	r = DosAllocMem(&ptr, size, dosallocmem_attrib | (commit ? PAG_COMMIT : 0));
	if (unlikely(r)) {
		if (r == ERROR_INTERRUPT)
			goto again;
		return NULL;
	}
	return ptr;
}

static bool do_commitmem(void *ptr, size_t size)
{
	APIRET r;
again:
	r = DosSetMem(ptr, size, PAG_READ | PAG_WRITE |
#ifdef CODEGEN_USE_HEAP
		PAG_EXECUTE |
#endif
		PAG_COMMIT);
	if (unlikely(r)) {
		if (r == ERROR_INTERRUPT)
			goto again;
		return false;
	}
	return true;
}

static void *os2_alloc_aligned(size_t size)
{
	void *ptr, *pad;
	size_t offset, aligned_size;

	huge_tree_lock();

	aligned_size = round_up(size, ARENA_SIZE);
	if (unlikely(!aligned_size))
		goto ret_null;
try_again:
	ptr = do_dosallocmem(aligned_size, likely(size == aligned_size));
	if (unlikely(!ptr))
		goto ret_null;
	offset = ptr_to_num(ptr) & (ARENA_SIZE - 1);
	if (unlikely(offset != 0)) {
		struct pad_descriptor *pd;
		amalloc_do_unmap(ptr, size);
		pad = do_dosallocmem(ARENA_SIZE - offset, false);
		if (unlikely(!pad))
			goto ret_null;
		pd = malloc(sizeof(struct pad_descriptor));
		if (unlikely(!pd)) {
			amalloc_do_unmap(pad, ARENA_SIZE - offset);
			goto ret_null;
		}
		pd->base = pad;
		pd->size = ARENA_SIZE - offset;
		list_add(&pad_list, &pd->pad_entry);
		goto try_again;
	}
	if (unlikely(size != aligned_size)) {
		if (unlikely(!do_commitmem(ptr, size))) {
			amalloc_do_unmap(ptr, aligned_size);
			goto ret_null;
		}
	}

	huge_tree_unlock();

	return ptr;

ret_null:
	huge_tree_unlock();

	return NULL;
}

bool os2_test_for_32bit_tcpip(const char *ptr);

static void amalloc_os_init(void)
{
	if (dosallocmem_attrib & OBJ_ANY) {
		void *ptr;
		ptr = do_dosallocmem(0x1000, true);
		if (ptr) {
			if (ptr_to_num(ptr) < 0x20000000UL) {
				dosallocmem_attrib &= ~OBJ_ANY;
			} else {
				if (!os2_test_for_32bit_tcpip(ptr))
					dosallocmem_attrib &= ~OBJ_ANY;
			}
			amalloc_do_unmap(ptr, 0x1000);
		} else {
			dosallocmem_attrib &= ~OBJ_ANY;
		}
	}
	list_init(&pad_list);
	page_size = 4096;
}

static void amalloc_os_done(void)
{
	while (!list_is_empty(&pad_list)) {
		struct pad_descriptor *pd = get_struct(pad_list.prev, struct pad_descriptor, pad_entry);
		list_del(&pd->pad_entry);
		amalloc_do_unmap(pd->base, pd->size);
		free(pd);
	}
}

#else

static inline void amalloc_do_unmap(void *ptr, size_t size)
{
	os_munmap(ptr, size, false);
}

static void amalloc_os_init(void)
{
	page_size = os_getpagesize();
}

static void amalloc_os_done(void)
{
}

#endif

#ifdef POINTER_COMPRESSION_POSSIBLE

static bool do_enable_mapping(void *ptr, size_t size, bool attr_unused clr)
{
#if defined(OS_CYGWIN) || defined(OS_WIN32)
	ajla_error_t sink;
	if (unlikely(!os_mprotect(ptr, size, PROT_HEAP, &sink)))
		return false;
	if (unlikely(clr))
		memset(ptr, 0, size);
	return true;
#else
	ajla_error_t sink;
	void *r = os_mmap(ptr, size, PROT_HEAP, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, handle_none, 0, &sink);
	if (likely(r == MAP_FAILED))
		return false;
	if (unlikely(r != ptr))
		internal(file_line, "do_enable_mapping: os_mmap(MAP_FIXED) returned different pointer: %p != %p", r, ptr);
	return true;
#endif
}

static void do_disable_mapping(void *ptr, size_t size)
{
#if defined(OS_CYGWIN) || defined(OS_WIN32)
	ajla_error_t err;
	if (unlikely(!os_mprotect(ptr, size, PROT_NONE, &err))) {
		warning("failed to clear existing mapping: mprotect(%p, %"PRIxMAX") returned error: %s", ptr, (uintmax_t)size, error_decode(err));
		return;
	}
#else
	ajla_error_t err;
	void *r = os_mmap(ptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, handle_none, 0, &err);
	if (unlikely(r == MAP_FAILED)) {
		warning("failed to clear existing mapping: os_mmap(%p, %"PRIxMAX") returned error: %s", ptr, (uintmax_t)size, error_decode(err));
		return;
	}
	if (unlikely(r != ptr))
		internal(file_line, "do_disable_mapping: os_mmap(MAP_FIXED) returned different pointer: %p != %p", r, ptr);
#endif
}

static struct tree rmap_tree;

static struct reserved_map {
	struct tree_entry free_entry;
	unsigned f;
} *rmap;

static mutex_t rmap_mutex;

#define RESERVED_MAP_ENTRIES	((uintptr_t)1 << (32 + POINTER_COMPRESSION_POSSIBLE - ARENA_BITS))

static void rmap_lock(void)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	mutex_lock(&rmap_mutex);
}

static void rmap_unlock(void)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	mutex_unlock(&rmap_mutex);
}

static int rmap_compare(const struct tree_entry *entry, uintptr_t idx2)
{
	struct reserved_map *rmap1 = get_struct(entry, struct reserved_map, free_entry);
	unsigned idx1 = rmap1 - rmap;
	unsigned len1, len2;
	len1 = rmap[idx1].f + 1 - idx1;
	len2 = rmap[idx2].f + 1 - idx2;
	if (len1 != len2)
		return len1 < len2 ? -1 : 1;
	if (idx1 < idx2)
		return -1;
	return 1;
}

static void reserve_free_merge_run(unsigned idx, unsigned len)
{
	struct tree_insert_position ins;
	if (rmap[idx - 1].f) {
		unsigned more = idx - rmap[idx - 1].f;
		idx -= more;
		len += more;
		tree_delete(&rmap[idx].free_entry);
	}
	if (idx + len < RESERVED_MAP_ENTRIES && rmap[idx + len].f) {
		unsigned more = rmap[idx + len].f + 1 - (idx + len);
		tree_delete(&rmap[idx + len].free_entry);
		len += more;
	}
	rmap[idx].f = idx + len - 1;
	rmap[idx + len - 1].f = idx;
	tree_find_for_insert(&rmap_tree, rmap_compare, idx, &ins);
	tree_insert_after_find(&rmap[idx].free_entry, &ins);
}

static void reserve_sub_alloc(unsigned idx1, unsigned len1, unsigned idx, unsigned len)
{
	struct reserved_map *rmap1 = &rmap[idx1];
	rmap[idx].f = 0;
	rmap[idx + len - 1].f = 0;
	tree_delete(&rmap1->free_entry);
	if (idx > idx1) {
		reserve_free_merge_run(idx1, idx - idx1);
	}
	if (idx + len < idx1 + len1) {
		reserve_free_merge_run(idx + len, (idx1 + len1) - (idx + len));
	}
}

static int rmap_find(const struct tree_entry *entry, uintptr_t len)
{
	struct reserved_map *rmap1 = get_struct(entry, struct reserved_map, free_entry);
	unsigned idx1 = rmap1 - rmap;
	unsigned len1 = rmap[idx1].f + 1 - idx1;
	if (len1 < len)
		return -1;
	if (len1 > len)
		return 1;
	return 0;
}

static unsigned reserve_alloc_run(unsigned al, unsigned len)
{
	struct tree_entry *ee;
	ee = tree_find_best(&rmap_tree, rmap_find, len + al - 1);
	if (likely(ee != NULL)) {
		struct reserved_map *rmap1 = get_struct(ee, struct reserved_map, free_entry);
		unsigned idx1 = rmap1 - rmap;
		unsigned len1 = rmap[idx1].f + 1 - idx1;
		unsigned idx = round_up(idx1, al);
		reserve_sub_alloc(idx1, len1, idx, len);
		return idx;
	}
	return 0;
}

static bool reserve_realloc_run(unsigned start, unsigned old_len, unsigned new_len)
{
	unsigned xlen;
	if (unlikely(old_len >= new_len)) {
		if (unlikely(old_len == new_len))
			return true;
		rmap[start + new_len - 1].f = 0;
		reserve_free_merge_run(start + new_len, old_len - new_len);
		return true;
	}
	if (unlikely(start + old_len == RESERVED_MAP_ENTRIES))
		return false;
	if (!rmap[start + old_len].f)
		return false;
	xlen = rmap[start + old_len].f + 1 - (start + old_len);
	if (xlen < new_len - old_len)
		return false;
	tree_delete(&rmap[start + old_len].free_entry);
	rmap[start + new_len - 1].f = 0;
	if (xlen > new_len - old_len)
		reserve_free_merge_run(start + new_len, xlen - (new_len - old_len));
	return true;
}

static unsigned reserve_last_run(unsigned len)
{
	struct tree_entry *e;
	struct reserved_map *rmap1;
	unsigned idx1, len1;
	unsigned best_idx = 0;
	for (e = tree_first(&rmap_tree); e; e = tree_next(e)) {
		rmap1 = get_struct(e, struct reserved_map, free_entry);
		idx1 = rmap1 - rmap;
		len1 = rmap[idx1].f + 1 - idx1;
		if (likely(len1 >= len)) {
			if (idx1 > best_idx)
				best_idx = idx1;
		}
	}
	if (unlikely(!best_idx))
		return 0;
	idx1 = best_idx;
	rmap1 = &rmap[idx1];
	len1 = rmap[idx1].f + 1 - idx1;
	reserve_sub_alloc(idx1, len1, idx1 + len1 - len, len);
	return idx1 + len1 - len;
}

bool amalloc_ptrcomp_try_reserve_range(void *ptr, size_t length)
{
	unsigned idx, len;
	struct tree_entry *e;

	if (unlikely(!length))
		return true;

	if (unlikely(ptr_to_num(ptr) & (ARENA_SIZE - 1)))
		return false;
	idx = ptr_to_num(ptr) >> ARENA_BITS;
	len = (length + ARENA_SIZE - 1) >> ARENA_BITS;

	rmap_lock();

	for (e = tree_first(&rmap_tree); e; e = tree_next(e)) {
		struct reserved_map *rmap1 = get_struct(e, struct reserved_map, free_entry);
		unsigned idx1 = rmap1 - rmap;
		unsigned len1 = rmap[idx1].f + 1 - idx1;
		if (idx >= idx1 && idx + len <= idx1 + len1) {
			reserve_sub_alloc(idx1, len1, idx, len);
			rmap_unlock();
			return true;
		}
	}

	rmap_unlock();

	return false;
}

static bool try_to_reserve_memory(void *ptr, size_t len)
{
	ajla_error_t sink;
	void *res;
	int extra_flags =
#ifdef MAP_EXCL
		MAP_FIXED | MAP_EXCL |
#endif
		0;

	if (ptr_to_num(ptr) + len > (uintptr_t)1 << (32 + POINTER_COMPRESSION_POSSIBLE))
		return false;

	res = os_mmap(ptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | extra_flags, handle_none, 0, &sink);
	if (unlikely(res == MAP_FAILED))
		return false;

	if (res != ptr) {
		os_munmap(res, len, false);
		return false;
	}

	return true;
}

static void reserve_memory(void)
{
	uintptr_t ptr, step;
	tree_init(&rmap_tree);
	rmap = os_mmap(NULL, RESERVED_MAP_ENTRIES * sizeof(struct reserved_map), PROT_HEAP, MAP_PRIVATE | MAP_ANONYMOUS, handle_none, 0, NULL);
#if defined(OS_CYGWIN)
	step = ARENA_SIZE * 256;
	ptr = round_up((uintptr_t)1 << 34, step);
#elif defined(__sun__)
	step = ARENA_SIZE;
	ptr = round_up((uintptr_t)1 << 31, step);
#else
	step = ARENA_SIZE;
	ptr = ARENA_SIZE;
#endif
	while (ptr < (uintptr_t)1 << (32 + POINTER_COMPRESSION_POSSIBLE)) {
		size_t len, bit;

		if (!try_to_reserve_memory(num_to_ptr(ptr), step)) {
			ptr += step;
			continue;
		}
		os_munmap(num_to_ptr(ptr), step, false);

		len = ((uintptr_t)1 << (32 + POINTER_COMPRESSION_POSSIBLE)) - ptr;
		if (try_to_reserve_memory(num_to_ptr(ptr), len)) {
			reserve_free_merge_run(ptr >> ARENA_BITS, len >> ARENA_BITS);
			break;
		}

		len = 0;
		bit = (uintptr_t)1 << (32 + POINTER_COMPRESSION_POSSIBLE - 1);

		for (; bit >= step; bit >>= 1) {
			if (try_to_reserve_memory(num_to_ptr(ptr), len | bit)) {
				os_munmap(num_to_ptr(ptr), len | bit, false);
				len |= bit;
			}
		}

		if (len) {
			if (likely(try_to_reserve_memory(num_to_ptr(ptr), len))) {
				reserve_free_merge_run(ptr >> ARENA_BITS, len >> ARENA_BITS);
			} else {
				ptr += step;
				continue;
			}
		}

		ptr += len + step;
	}
	if (unlikely(tree_is_empty(&rmap_tree)))
		fatal("unable to reserve any memory for pointer compression");
}

static void unreserve_memory(void)
{
	while (!tree_is_empty(&rmap_tree)) {
		struct reserved_map *rmap1 = get_struct(tree_any(&rmap_tree), struct reserved_map, free_entry);
		unsigned idx1 = rmap1 - rmap;
		unsigned len1 = rmap[idx1].f + 1 - idx1;
		amalloc_do_unmap(num_to_ptr((uintptr_t)idx1 << ARENA_BITS), (size_t)len1 << ARENA_BITS);
		tree_delete(&rmap[idx1].free_entry);
	}
	amalloc_do_unmap(rmap, RESERVED_MAP_ENTRIES * sizeof(struct reserved_map));
}

#endif


void amalloc_run_free(void *ptr, size_t length)
{
	if (unlikely(!length))
		return;
#ifdef POINTER_COMPRESSION_POSSIBLE
	if (pointer_compression_enabled) {
		unsigned idx = ptr_to_num(ptr) >> ARENA_BITS;
		size_t l = (length + ARENA_SIZE - 1) >> ARENA_BITS;
		do_disable_mapping(ptr, l << ARENA_BITS);
		rmap_lock();
		reserve_free_merge_run(idx, l);
		rmap_unlock();
		return;
	}
#endif
	amalloc_do_unmap(ptr, length);
}

void *amalloc_run_alloc(size_t al, size_t length, bool attr_unused clr, bool attr_unused saved)
{
	size_t attr_unused extra_length;
	void *ptr;
	void attr_unused *base_address;
	uintptr_t attr_unused nptr, aptr, fptr, eptr;
	int node;
#if !defined(OS_OS2)
	ajla_error_t sink;
#endif

	if (unlikely(al < page_size))
		al = page_size;

	length = round_up(length, page_size);
	if (unlikely(!length))
		return NULL;

#ifdef POINTER_COMPRESSION_POSSIBLE
	if (pointer_compression_enabled) {
		size_t l;
		unsigned res;
		if (unlikely(al < ARENA_SIZE))
			al = ARENA_SIZE;
		al >>= ARENA_BITS;
		l = round_up(length, ARENA_SIZE) >> ARENA_BITS;
		if (unlikely(!l))
			return NULL;
		if (unlikely(l != (unsigned)l))
			return NULL;
		rmap_lock();
		if (unlikely(saved))
			res = reserve_last_run(l);
		else
			res = reserve_alloc_run(al, l);
		rmap_unlock();
		if (unlikely(!res))
			return NULL;
		ptr = num_to_ptr((uintptr_t)res << ARENA_BITS);
		if (unlikely(!do_enable_mapping(ptr, length, clr))) {
			rmap_lock();
			reserve_free_merge_run(res, l);
			rmap_unlock();
			return NULL;
		}
		goto madvise_ret;
	}
#endif

	base_address = NULL;
	if (unlikely(saved)) {
		base_address = num_to_ptr(round_down(ptr_to_num(&saved) / 2, page_size));
	}

#if defined(OS_OS2)
	if (unlikely(al > ARENA_SIZE))
		return NULL;
	ptr = os2_alloc_aligned(length);
#elif defined(MAP_ALIGNED) && !defined(__minix__)
	if (unlikely(al != (bitmap_t)al))
		return NULL;
	ptr = os_mmap(base_address, length, PROT_HEAP, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALIGNED(find_bit(al)), handle_none, 0, &sink);
	if (unlikely(ptr == MAP_FAILED))
		return NULL;
	if (unlikely((ptr_to_num(ptr) & (al - 1)) != 0))
		fatal("os_mmap returned unaligned pointer: %p, required alignment %lx", ptr, (unsigned long)ARENA_SIZE);
#else
	if (likely(length == ARENA_SIZE) && likely(al == ARENA_SIZE)) {
		ptr = os_mmap(base_address, length, PROT_HEAP, MAP_PRIVATE | MAP_ANONYMOUS, handle_none, 0, &sink);
		if (unlikely(ptr == MAP_FAILED))
			return NULL;
		if (likely(!(ptr_to_num(ptr) & (al - 1))))
			goto madvise_ret;
		os_munmap(ptr, length, false);
	}

	extra_length = length + al - page_size;
	if (unlikely(extra_length < length))
		return NULL;
	ptr = os_mmap(base_address, extra_length, PROT_HEAP, MAP_PRIVATE | MAP_ANONYMOUS, handle_none, 0, &sink);
	if (unlikely(ptr == MAP_FAILED))
		return NULL;

	nptr = ptr_to_num(ptr);
	aptr = round_up(nptr, al);
	fptr = aptr + length;
	eptr = nptr + extra_length;
	amalloc_run_free(num_to_ptr(nptr), aptr - nptr);
	amalloc_run_free(num_to_ptr(fptr), eptr - fptr);

	ptr = num_to_ptr(aptr);
#endif

	goto madvise_ret;
madvise_ret:

	node = call(task_get_numa_node)();
	if (node >= 0)
		os_numa_bind_memory(ptr, length, node);

#if !defined(AMALLOC_TRIM_MIDBLOCKS) && defined(HAVE_MADVISE) && defined(MADV_HUGEPAGE)
	if (length == ARENA_SIZE) {
		int madv = MADV_HUGEPAGE;
		int r;
		EINTR_LOOP(r, madvise(ptr, length, madv));
		/*if (unlikely(r == -1)) {
			int er = errno;
			warning("madvise(%d) failed: %d, %s", madv, er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}*/
	}
#endif

	return ptr;
}

static void *amalloc_run_realloc(void *ptr, size_t old_length, size_t new_length)
{
	void attr_unused *n;

	old_length = round_up(old_length, page_size);
	new_length = round_up(new_length, page_size);
	if (unlikely(!new_length))
		return NULL;

#ifdef POINTER_COMPRESSION_POSSIBLE
	if (pointer_compression_enabled) {
		bool f;
		size_t old_length_arenas = round_up(old_length, ARENA_SIZE) >> ARENA_BITS;
		size_t new_length_arenas = round_up(new_length, ARENA_SIZE) >> ARENA_BITS;
		if (unlikely(!new_length_arenas))
			return NULL;
		if (unlikely(new_length_arenas != (unsigned)new_length_arenas))
			return NULL;
		rmap_lock();
		f = reserve_realloc_run(ptr_to_num(ptr) >> ARENA_BITS, old_length_arenas, new_length_arenas);
		rmap_unlock();
		/*debug("try realloc: %p, %d", ptr, f);*/
		if (f) {
			if (likely(old_length < new_length)) {
				if (unlikely(!do_enable_mapping(cast_ptr(char *, ptr) + old_length, new_length - old_length, false))) {
					rmap_lock();
					reserve_free_merge_run((ptr_to_num(ptr) >> ARENA_BITS) + old_length_arenas, new_length_arenas - old_length_arenas);
					rmap_unlock();
					return NULL;
				}
			} else if (old_length > new_length) {
				do_disable_mapping(cast_ptr(char *, ptr) + new_length, old_length - new_length);
			}
			return ptr;
		}
		return NULL;
	}
#endif

#if defined(OS_OS2) || defined(OS_WIN32)
	if (new_length == old_length)
		return ptr;
	return NULL;
#else
	if (unlikely(new_length <= old_length)) {
		amalloc_run_free(cast_ptr(char *, ptr) + new_length, old_length - new_length);
		return ptr;
	}

#if defined(OS_HAS_MREMAP)
	{
		ajla_error_t sink;
		void *r = os_mremap(ptr, old_length, new_length, 0, NULL, &sink);
		if (r != MAP_FAILED) {
			if (unlikely(r != ptr))
				internal(file_line, "amalloc_run_realloc: os_mremap returned different pointer: %p != %p", r, ptr);
			return ptr;
		}
	}
#else
	{
		ajla_error_t sink;
		n = os_mmap(cast_ptr(char *, ptr) + old_length, new_length - old_length, PROT_HEAP, MAP_PRIVATE | MAP_ANONYMOUS, handle_none, 0, &sink);
		if (likely(n != MAP_FAILED)) {
			if (n == cast_ptr(char *, ptr) + old_length)
				return ptr;
			amalloc_do_unmap(n, new_length - old_length);
		}
	}
#endif

	n = amalloc_run_alloc(ARENA_SIZE, new_length, false, false);
	if (unlikely(!n))
		return NULL;

#if defined(OS_HAS_MREMAP) && defined(MREMAP_FIXED)
	{
		ajla_error_t sink;
		void *r = os_mremap(ptr, old_length, new_length, MREMAP_MAYMOVE | MREMAP_FIXED, n, &sink);
		if (likely(r != MAP_FAILED)) {
			if (unlikely(r != n))
				internal(file_line, "amalloc_run_realloc: os_mremap returned different pointer: %p != %p", r, n);
			return n;
		}
	}
#endif

	memcpy(n, ptr, old_length);
	amalloc_run_free(ptr, old_length);
	return n;
#endif
}


static inline void sbc_lock(struct small_block_cache *sbc)
{
	if (likely(amalloc_threads_initialized))
		mutex_lock(&sbc->mutex);
}

static inline void sbc_unlock(struct small_block_cache *sbc)
{
	if (likely(amalloc_threads_initialized))
		mutex_unlock(&sbc->mutex);
}

static inline void arena_lock(struct arena *a)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	address_lock(a, DEPTH_ARENA);
}

static inline void arena_unlock(struct arena *a)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	address_unlock(a, DEPTH_ARENA);
}

static void arena_tree_lock(void)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	mutex_lock(&arena_tree_mutex);
}

static void arena_tree_unlock(void)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	mutex_unlock(&arena_tree_mutex);
}

static void huge_tree_lock(void)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	mutex_lock(&huge_tree_mutex);
}

static void huge_tree_unlock(void)
{
	if (unlikely(!amalloc_threads_initialized))
		return;
	mutex_unlock(&huge_tree_mutex);
}

static int huge_tree_compare(const struct tree_entry *entry, uintptr_t addr)
{
	struct huge_entry *e = get_struct(entry, struct huge_entry, entry);
	if (ptr_to_num(e->ptr) < addr)
		return -1;
	if (ptr_to_num(e->ptr) > addr)
		return 1;
	return 0;
}

static attr_noinline struct huge_entry *huge_tree_find(void *ptr)
{
	struct tree_entry *entry;
	huge_tree_lock();
	entry = tree_find(&huge_tree, huge_tree_compare, ptr_to_num(ptr));
	ajla_assert_lo(entry != NULL, (file_line, "huge_tree_find: entry for address %p not found", ptr));
	huge_tree_unlock();
	return get_struct(entry, struct huge_entry, entry);
}

static void huge_tree_insert(struct huge_entry *e)
{
	struct tree_insert_position ins;
	struct tree_entry attr_unused *ee;
	huge_tree_lock();
	ee = tree_find_for_insert(&huge_tree, huge_tree_compare, ptr_to_num(e->ptr), &ins);
	ajla_assert_lo(ee == NULL, (file_line, "huge_tree_insert: entry for address %p is already present", e->ptr));
	tree_insert_after_find(&e->entry, &ins);
	huge_tree_unlock();
}

static struct huge_entry *huge_tree_delete(void *ptr)
{
	struct tree_entry *entry;
	huge_tree_lock();
	entry = tree_find(&huge_tree, huge_tree_compare, ptr_to_num(ptr));
	ajla_assert_lo(entry != NULL, (file_line, "huge_tree_delete: entry for address %p not found", ptr));
	tree_delete(entry);
	huge_tree_unlock();
	return get_struct(entry, struct huge_entry, entry);
}


static attr_always_inline struct per_thread *amalloc_per_thread(void)
{
#ifdef HAVE___THREAD
	struct per_thread *pt = tls_get(struct per_thread *, per_thread);
	if (likely(pt != NULL))
		return pt;
	if (!amalloc_threads_initialized)
		return &thread1;
	return NULL;
#else
	if (unlikely(!amalloc_threads_initialized))
		return &thread1;
	else
		return tls_get(struct per_thread *, per_thread);
#endif
}

static void arena_detach(struct arena *a);
static bool amalloc_detach_small(struct small_block_cache *sbc, union midblock *m);
#ifdef AMALLOC_EAGER_FREE
static void amalloc_test_free_small(struct small_block_cache *sbc, size_t idx, union midblock *m);
#endif

static void set_small_run(struct per_thread *pt, unsigned i, union midblock *m)
{
	if (!i)
		pt->small_runs[0] = m;
	pt->small_runs[i + 1] = m;
}

static void detach_pt_data(struct per_thread *pt)
{
	unsigned i;
	struct arena *a;
	for (i = 0; i < N_CLASSES; i++) {
		union midblock *m = pt->small_runs[i + 1];
		struct small_block_cache *sbc = &small_block_cache[i];
#ifdef AMALLOC_EAGER_FREE
		size_t idx;
#endif
		set_small_run(pt, i, NULL);
		if (m == &full_midblock)
			continue;
		sbc_lock(sbc);
		amalloc_atomic_or(&m->s.atomic_map, m->s.map);
		m->s.map = 0;
		if (unlikely(!amalloc_detach_small(sbc, m))) {
			int er = errno;
			fatal("arealloc failed: %d, %s", er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
#ifdef AMALLOC_EAGER_FREE
		idx = m->s.index;
#endif
		sbc_unlock(sbc);
#ifdef AMALLOC_EAGER_FREE
		amalloc_test_free_small(sbc, idx, m);
#endif
	}
	a = pt->arena;
	pt->arena = BAD_POINTER_1;
	if (a) {
		arena_lock(a);
		arena_detach(a);
		arena_unlock(a);
	}
}

static void per_thread_destructor(tls_destructor_t *destr)
{
	struct per_thread *pt = get_struct(destr, struct per_thread, destructor);
	detach_pt_data(pt);
	free(pt);
}

static void amalloc_per_thread_init(struct per_thread *pt)
{
	unsigned i;
	pt->arena = NULL;
	for (i = 0; i < N_CLASSES; i++)
		set_small_run(pt, i, &full_midblock);
}

static bool amalloc_per_thread_alloc(void)
{
	struct per_thread *pt;
	pt = malloc(sizeof(struct per_thread));
	if (unlikely(!pt))
		return false;
	amalloc_per_thread_init(pt);
	tls_destructor(&pt->destructor, per_thread_destructor);
	tls_set(struct per_thread *, per_thread, pt);
	return true;
}

static int arena_tree_compare(const struct tree_entry *entry, uintptr_t a2_)
{
	struct arena *a = get_struct(entry, struct arena, arena_entry);
	struct arena *a2 = num_to_ptr(a2_);
	if (unlikely(a->numa_node < a2->numa_node))
		return -1;
	if (unlikely(a->numa_node > a2->numa_node))
		return 1;
	if (a->max_midblock_run < a2->max_midblock_run)
		return -1;
	return 1;
}

static void arena_insert_locked(struct arena *a)
{
	struct tree_insert_position ins;
	struct tree_entry attr_unused *ee;
	if (a->max_midblock_run == ARENA_MIDBLOCKS - ARENA_PREFIX) {
		/*debug("freeing empty arena %p", a);*/
		amalloc_run_free(a, ARENA_SIZE);
		return;
	}
	ee = tree_find_for_insert(&arena_tree, arena_tree_compare, ptr_to_num(a), &ins);
	ajla_assert(ee == NULL, (file_line, "arena_insert_locked: entry for address %p is already present", a));
	tree_insert_after_find(&a->arena_entry, &ins);
}

static void arena_relink(struct arena *a, unsigned new_run)
{
	if (!a->attached) {
		bool full_free = new_run == ARENA_MIDBLOCKS - ARENA_PREFIX;
		if (new_run >= (unsigned)a->max_midblock_run * 2 || full_free) {
			arena_tree_lock();
			if (!a->attached) {
				tree_delete(&a->arena_entry);
				a->max_midblock_run = new_run;
				arena_insert_locked(a);
			}
			arena_tree_unlock();
		}
	}
}

static int midblock_compare(const struct tree_entry *entry, uintptr_t idx2)
{
	union midblock *m1 = get_struct(entry, union midblock, free_entry);
	struct arena *a = addr_to_arena(m1);
	unsigned idx1 = midblock_to_idx(a, m1);
	unsigned len1, len2;
	ajla_assert(a->map[idx1] & MAP_FREE, (file_line, "midblock_compare: idx1 is not free"));
	ajla_assert(a->map[idx2] & MAP_FREE, (file_line, "midblock_compare: idx2 is not free"));
	len1 = (a->map[idx1] & ~MAP_FREE) + 1 - idx1;
	len2 = (a->map[idx2] & ~MAP_FREE) + 1 - idx2;
	if (len1 != len2)
		return len1 < len2 ? -1 : 1;
	if (idx1 < idx2)
		return -1;
	return 1;
}

static void arena_free_midblock(struct arena *a, unsigned start, unsigned len)
{
	struct tree_insert_position ins;
	a->map[start] = MAP_FREE | (start + len - 1);
	a->map[start + len - 1] = MAP_FREE | start;
	tree_find_for_insert(&a->midblock_free, midblock_compare, start, &ins);
	tree_insert_after_find(&idx_to_midblock(a, start)->free_entry, &ins);
}

static void arena_free_merge_midblock(struct arena *a, unsigned start, unsigned len)
{
	uintptr_t attr_unused start_ptr, end_ptr;
	if (start && a->map[start - 1] & MAP_FREE) {
		unsigned more = start - (a->map[start - 1] & ~MAP_FREE);
		start -= more;
		len += more;
		tree_delete(&idx_to_midblock(a, start)->free_entry);
	}
	if (start + len < ARENA_MIDBLOCKS && a->map[start + len] & MAP_FREE) {
		unsigned more = (a->map[start + len] & ~MAP_FREE) + 1 - (start + len);
		tree_delete(&idx_to_midblock(a, start + len)->free_entry);
		len += more;
	}
#if defined(AMALLOC_TRIM_MIDBLOCKS) && defined(HAVE_MADVISE) && ((defined(__linux__) && defined(MADV_DONTNEED)) || (!defined(__linux__) && defined(MADV_FREE)))
	start_ptr = round_up(ptr_to_num(idx_to_midblock(a, start)), page_size);
	end_ptr = round_down(ptr_to_num(idx_to_midblock(a, start + len)), page_size);
	if (start_ptr < end_ptr) {
#ifdef __linux__
		int madv = MADV_DONTNEED;
#else
		int madv = MADV_FREE;
#endif
		int r;
		EINTR_LOOP(r, madvise(num_to_ptr(start_ptr), end_ptr - start_ptr, madv));
		if (unlikely(r == -1)) {
			int er = errno;
			warning("madvise(%d) failed: %d, %s", madv, er, error_decode(error_from_errno(EC_SYSCALL, er)));
		}
	}
#endif
	arena_free_midblock(a, start, len);
	arena_relink(a, len);
}

static void arena_grab_midblocks(struct arena *a, unsigned idx1, unsigned idx, unsigned len)
{
	unsigned found_end;
	union midblock *m = idx_to_midblock(a, idx1);
	tree_delete(&m->free_entry);
	found_end = (a->map[idx1] & ~MAP_FREE) + 1;
	if (unlikely(idx > idx1))
		arena_free_midblock(a, idx1, idx - idx1);
	if (found_end > idx + len)
		arena_free_midblock(a, idx + len, found_end - (idx + len));
}

static int midblock_find(const struct tree_entry *entry, uintptr_t len)
{
	union midblock *m1 = get_struct(entry, union midblock, free_entry);
	struct arena *a = addr_to_arena(m1);
	unsigned idx1 = midblock_to_idx(a, m1);
	unsigned len1 = (a->map[idx1] & ~MAP_FREE) + 1 - idx1;
	if (len1 < len)
		return -1;
	if (len1 > len)
		return 1;
	return 0;
}

static union midblock *arena_alloc_midblock(struct arena *a, unsigned midblock_alignment, unsigned midblocks)
{
	struct tree_entry *ee;
	ee = tree_find_best(&a->midblock_free, midblock_find, midblocks + midblock_alignment - 1);
	if (likely(ee != NULL)) {
		union midblock *m = get_struct(ee, union midblock, free_entry);
		unsigned best = midblock_to_idx(a, m);
		unsigned best_aligned = round_up(best, midblock_alignment);
		arena_grab_midblocks(a, best, best_aligned, midblocks);
		a->map[best_aligned] = best_aligned + midblocks - 1;
		a->map[best_aligned + midblocks - 1] = best_aligned;
		return idx_to_midblock(a, best_aligned);
	}
	return NULL;
}

static bool arena_try_realloc_midblock(struct arena *a, unsigned base, unsigned orig_len, unsigned new_len)
{
	unsigned free_len;
	if (unlikely(new_len <= orig_len)) {
		if (new_len == orig_len)
			return true;
		a->map[base] = base + new_len - 1;
		a->map[base + new_len - 1] = base;
		arena_free_merge_midblock(a, base + new_len, orig_len - new_len);
	} else {
		if (unlikely(base + new_len > ARENA_MIDBLOCKS))
			return false;
		if (!(a->map[base + orig_len] & MAP_FREE))
			return false;
		free_len = (a->map[base + orig_len] & ~MAP_FREE) + 1 - (base + orig_len);
		if (free_len < new_len - orig_len)
			return false;
		arena_grab_midblocks(a, base + orig_len, base + orig_len, new_len - orig_len);
		a->map[base] = base + new_len - 1;
		a->map[base + new_len - 1] = base;
	}
	return true;
}

static struct arena *arena_alloc(void)
{
	struct arena *a;
	a = amalloc_run_alloc(ARENA_SIZE, ARENA_SIZE, false, false);
	if (unlikely(!a))
		return NULL;
	tree_init(&a->midblock_free);
	a->map[0] = ARENA_PREFIX - 1;
	a->map[ARENA_PREFIX - 1] = 0;
	a->attached = true;
	a->numa_node = call(task_get_numa_node)();
	if (unlikely(a->numa_node < 0))
		a->numa_node = 0;
	arena_free_midblock(a, ARENA_PREFIX, ARENA_MIDBLOCKS - ARENA_PREFIX);
	/*debug("allocating arena %p", a);*/
	return a;
}


static unsigned arena_compute_max_run(struct arena *a)
{
	struct tree_entry *e = tree_last(&a->midblock_free);
	if (!e) {
		return 0;
	} else {
		union midblock *m = get_struct(e, union midblock, free_entry);
		unsigned idx = midblock_to_idx(a, m);
		return (a->map[idx] & ~MAP_FREE) + 1 - idx;
	}
}

static void arena_detach(struct arena *a)
{
	a->max_midblock_run = arena_compute_max_run(a);
	arena_tree_lock();
	a->attached = false;
	arena_insert_locked(a);
	arena_tree_unlock();
}

struct arena_tree_find_param {
	unsigned midblocks;
	int numa_node;
};

static int arena_tree_find(const struct tree_entry *entry, uintptr_t p_)
{
	struct arena *a = get_struct(entry, struct arena, arena_entry);
	struct arena_tree_find_param *p = num_to_ptr(p_);
	if (unlikely(a->numa_node < p->numa_node))
		return -1;
	if (unlikely(a->numa_node > p->numa_node))
		return 1;
	if (a->max_midblock_run < p->midblocks)
		return -1;
	if (a->max_midblock_run > p->midblocks)
		return 1;
	return 0;
}

static struct arena *arena_attach(unsigned midblocks)
{
	struct arena *a;
	struct tree_entry *ee;
	struct arena_tree_find_param p;
	arena_tree_lock();
	p.midblocks = midblocks;
	p.numa_node = call(task_get_numa_node)();
	if (p.numa_node < 0)
		p.numa_node = 0;
	ee = tree_find_best(&arena_tree, arena_tree_find, ptr_to_num(&p));
	if (ee) {
		a = get_struct(ee, struct arena, arena_entry);
		a->attached = true;
		tree_delete(&a->arena_entry);
		arena_tree_unlock();
		return a;
	}
	arena_tree_unlock();
	return arena_alloc();
}

static void *amalloc_mid(struct per_thread *pt, unsigned midblock_alignment, unsigned midblocks)
{
	struct arena *a = pt->arena;
	bool looped = false;
	if (likely(a != NULL)) {
		union midblock *m;
do_alloc:
		arena_lock(a);
		m = arena_alloc_midblock(a, midblock_alignment, midblocks);
		if (likely(m != NULL)) {
			arena_unlock(a);
			return m;
		}
		arena_detach(a);
		arena_unlock(a);
		pt->arena = NULL;
	}
	if (likely(!looped))
		a = arena_attach(midblocks + midblock_alignment - 1);
	else
		a = arena_alloc();
	if (unlikely(!a))
		return NULL;
	pt->arena = a;
	looped = true;
	goto do_alloc;
}

static void *amalloc_huge(size_t al, size_t size, bool clr)
{
	struct huge_entry *e;
	void *ptr;
	size = round_up(size, page_size);
	ptr = amalloc_run_alloc(al, size, clr, false);
	if (unlikely(!ptr))
		return NULL;
	e = malloc(sizeof(struct huge_entry));
	if (unlikely(!e)) {
		amalloc_run_free(ptr, size);
		return NULL;
	}
	e->ptr = ptr;
	e->len = size;
	huge_tree_insert(e);
	return ptr;
}

static attr_noinline void *amalloc_mid_huge(struct per_thread *pt, size_t size, bool clr)
{
	if (unlikely(size > MIDBLOCK_LIMIT)) {
		return amalloc_huge(ARENA_SIZE, size, clr);
	} else {
		unsigned midblocks = round_up(size, MIDBLOCK_SIZE) >> MIDBLOCK_BITS;
		void *ptr = amalloc_mid(pt, 1, midblocks);
		if (likely(ptr != NULL) && clr)
			memset(ptr, 0, size);
		return ptr;
	}
}

static attr_noinline void *amemalign_mid_huge(size_t al, size_t size, bool clr)
{
	if (size + al > MIDBLOCK_LIMIT) {
		if (al < ARENA_SIZE)
			al = ARENA_SIZE;
		return amalloc_huge(al, size, clr);
	} else {
		unsigned midblocks, midblock_alignment;
		void *ptr;
		struct per_thread *pt = amalloc_per_thread();
		if (unlikely(!pt)) {
			if (unlikely(!amalloc_per_thread_alloc()))
				return NULL;
			pt = amalloc_per_thread();
		}
		midblocks = round_up(size, MIDBLOCK_SIZE) >> MIDBLOCK_BITS;
		midblock_alignment = round_up(al, MIDBLOCK_SIZE) >> MIDBLOCK_BITS;
		ptr = amalloc_mid(pt, midblock_alignment, midblocks);
		if (likely(ptr != NULL) && clr)
			memset(ptr, 0, size);
		return ptr;
	}
}

static unsigned reserved_bits(unsigned cls)
{
	size_t size = CLASS_TO_SIZE(cls);
	unsigned reserved_bits = div_16(sizeof(full_midblock.s) + size - 1, size);
	return reserved_bits;
}

static union midblock *create_small_run(struct per_thread *pt, unsigned cls)
{
	struct arena *a;
	unsigned idx, i, res;
	size_t size = CLASS_TO_SIZE(cls);
	unsigned midblocks = (size * BITMAP_BITS + MIDBLOCK_SIZE - 1) >> MIDBLOCK_BITS;
	union midblock *m = amalloc_mid(pt, 1, midblocks);
	if (unlikely(!m))
		return NULL;
	a = addr_to_arena(m);
	idx = midblock_to_idx(a, m);
	for (i = 0; i < midblocks; i++) {
		a->map[idx + i] = idx;
	}
	res = reserved_bits(cls);
	m->s.map = (bitmap_t)-1 << res;
	store_relaxed(&m->s.atomic_map, 0);
#ifdef AMALLOC_EAGER_FREE
	m->s.index = (size_t)-1;
#endif
	m->s.reserved_bits = res;
	m->s.cls = cls;
	m->s.size = size;
	m->s.reciprocal = div_16(RECIPROCAL_BASE + size - 1, size);
	return m;
}

static void amalloc_free_small(union midblock *m)
{
	struct arena *a = addr_to_arena(m);
	unsigned idx = midblock_to_idx(a, m);
	unsigned midblocks = (m->s.size * BITMAP_BITS + MIDBLOCK_SIZE - 1) >> MIDBLOCK_BITS;
	/*debug("midblock (%d): %lx / %lx", m->s.cls, m->s.map, m->s.atomic_map);*/
	arena_lock(a);
	arena_free_merge_midblock(a, idx, midblocks);
	arena_unlock(a);
}

#ifdef AMALLOC_EAGER_FREE
static attr_noinline void amalloc_test_free_small(struct small_block_cache *sbc, size_t idx, union midblock *m)
{
	sbc_lock(sbc);
	if (likely(idx < sbc->array_size) && likely(sbc->array[idx] == m) && likely(load_relaxed(&m->s.atomic_map) == (bitmap_t)-1 << m->s.reserved_bits)) {
		(sbc->array[idx] = sbc->array[--sbc->array_size])->s.index = idx;
	} else {
		m = NULL;
	}
	sbc_unlock(sbc);
	if (likely(m != NULL)) {
		amalloc_free_small(m);
		/*debug("freed small");*/
	}
}
#endif

static bool amalloc_detach_small(struct small_block_cache *sbc, union midblock *m)
{
	size_t index;
	if (unlikely(sbc->array_size == sbc->allocated_size)) {
		union midblock **a;
		size_t s = sbc->allocated_size * 2;
		if (unlikely(s > (size_t)-1 / sizeof(union midblock *)))
			return false;
		a = arealloc(sbc->array, s * sizeof(union midblock *));
		if (unlikely(!a))
			return false;
		sbc->array = a;
		sbc->allocated_size = s;
		/*debug("amalloc_detach_small: %ld - %ld - %p", sbc - small_block_cache, s, a);*/
	}
	index = sbc->array_size++;
#ifdef AMALLOC_EAGER_FREE
	m->s.index = index;
#endif
	sbc->array[index] = m;
	return true;
}

static attr_noinline void *amalloc_small_empty(struct per_thread *pt, size_t size)
{
	unsigned idx = SIZE_TO_INDEX(size);
	unsigned cls = INDEX_TO_CLASS(idx);
	unsigned i, best_idx, best_count, bit, all_free;
	union midblock *m = pt->small_runs[cls + 1];
	struct small_block_cache *sbc = &small_block_cache[cls];
	int node = call(task_get_numa_node)();
	sbc_lock(sbc);
	if (likely(m != &full_midblock)) {
		if (unlikely(!amalloc_detach_small(sbc, m))) {
			sbc_unlock(sbc);
			return false;
		}
		all_free = BITMAP_BITS - m->s.reserved_bits;
	} else {
		all_free = BITMAP_BITS - reserved_bits(cls);
	}
	best_idx = 0;
	best_count = 0;
	i = minimum(SMALL_BLOCK_TRIES, sbc->array_size);
	while (i--) {
		unsigned test_count;
		union midblock *test;
		bitmap_t map;
		size_t test_idx;
#ifndef AMALLOC_USE_RANDOM_ROVER
		test_idx = ++sbc->rover;
		if (unlikely(test_idx >= sbc->array_size)) {
			test_idx = sbc->rover = 0;
		}
#else
		test_idx = rand_r(&sbc->rover) % sbc->array_size;
#endif
		test = sbc->array[test_idx];
		map = load_relaxed(&test->s.atomic_map);
		if (!map)
			continue;
		test_count = count_bits(map);
		if (best_count == all_free) {
			if (test_count == all_free && test_idx != best_idx && sbc->array_size - 1 != best_idx) {
				/*debug("freeing cached slab: %u, %p", cls, test);*/
				(sbc->array[test_idx] = sbc->array[--sbc->array_size])
#ifdef AMALLOC_EAGER_FREE
					->s.index = test_idx
#endif
					;
				amalloc_free_small(test);
				if (!sbc->array_size)
					break;
			}
		} else {
			if (test_count > best_count) {
				struct arena *a = addr_to_arena(test);
				if (node >= 0 && unlikely(node != a->numa_node))
					continue;
				best_idx = test_idx;
				best_count = test_count;
			}
		}
	}
	if (likely(best_count)) {
		m = sbc->array[best_idx];
		(sbc->array[best_idx] = sbc->array[--sbc->array_size])
#ifdef AMALLOC_EAGER_FREE
			->s.index = best_idx
#endif
			;
		sbc_unlock(sbc);
		m->s.map = amalloc_atomic_xchg(&m->s.atomic_map, 0);
#ifdef AMALLOC_EAGER_FREE
		m->s.index = (size_t)-1;
#endif
	} else {
		sbc_unlock(sbc);
		m = create_small_run(pt, cls);
		if (unlikely(!m)) {
			set_small_run(pt, cls, &full_midblock);
			return NULL;
		}
	}
	set_small_run(pt, cls, m);
	bit = find_bit(m->s.map);
	m->s.map &= ~((bitmap_t)1 << bit);
	return cast_ptr(char *, m) + bit * m->s.size;
}

static attr_noinline void *amalloc_alloc_pt(size_t size, bool clr)
{
	if (unlikely(!amalloc_per_thread_alloc()))
		return NULL;
	if (likely(!clr))
		return amalloc(size);
	else
		return acalloc(size);
}

static attr_always_inline void *amalloc_small(struct per_thread *pt, size_t size)
{
	size_t bit;
	unsigned idx = SIZE_TO_INDEX(size);
	union midblock *m = pt->small_runs[idx];
	if (likely(m->s.map != 0)) {
		goto found_bit;
	}
	if (load_relaxed(&m->s.atomic_map) != 0) {
		m->s.map = amalloc_atomic_xchg(&m->s.atomic_map, 0);
		goto found_bit;
	}
	return amalloc_small_empty(pt, size);
found_bit:
	bit = find_bit(m->s.map);
#if defined(ARCH_X86) || (defined(ARCH_RISCV64) && defined(__riscv_zbs))
	m->s.map &= ~((bitmap_t)1 << bit);
#else
	m->s.map &= m->s.map - 1;
#endif
	return cast_ptr(char *, m) + bit * m->s.size;
}

void * attr_fastcall amalloc(size_t size)
{
	struct per_thread *pt = amalloc_per_thread();
	if (unlikely(!pt))
		return amalloc_alloc_pt(size, false);
	if (unlikely(size > DIRECT_LIMIT))
		return amalloc_mid_huge(pt, size, false);
	return amalloc_small(pt, size);
}

void * attr_fastcall acalloc(size_t size)
{
	void *ptr;
	struct per_thread *pt = amalloc_per_thread();
	if (unlikely(!pt))
		return amalloc_alloc_pt(size, true);
	if (unlikely(size > DIRECT_LIMIT))
		return amalloc_mid_huge(pt, size, true);
	ptr = amalloc_small(pt, size);
	if (unlikely(!ptr))
		return NULL;
	return memset(ptr, 0, size);
}

void * attr_fastcall amemalign(size_t al, size_t size)
{
	size_t size2;
	if (likely(al <= minimum(DIRECT_LIMIT, MIDBLOCK_SIZE))) {
		size2 = round_up(size, al);
		if (unlikely(size2 < size))
			return NULL;
		return amalloc(size);
	}
	return amemalign_mid_huge(al, size, false);
}

void * attr_fastcall acmemalign(size_t al, size_t size)
{
	if (likely(al <= minimum(DIRECT_LIMIT, MIDBLOCK_SIZE))) {
		size_t size2;
		size2 = round_up(size, al);
		if (unlikely(size2 < size))
			return NULL;
		return acalloc(size);
	}
	return amemalign_mid_huge(al, size, true);
}


static attr_noinline void afree_huge(void *ptr)
{
	struct huge_entry *e = huge_tree_delete(ptr);
	amalloc_run_free(ptr, e->len);
	free(e);
}

static attr_noinline void afree_mid(struct arena *a, unsigned idx)
{
	arena_lock(a);
	arena_free_merge_midblock(a, idx, a->map[idx] + 1 - idx);
	arena_unlock(a);
}

void attr_fastcall afree(void *ptr)
{
	unsigned idx, bit;
	unsigned attr_unused bit2;
	bitmap_t bit_or;
	union midblock *m;
	struct per_thread *pt;
	struct arena *a = addr_to_arena(ptr);
	if (unlikely((void *)a == ptr)) {
		afree_huge(ptr);
		return;
	}
	idx = midblock_to_idx(a, ptr);
	m = idx_to_midblock(a, a->map[idx]);
	if (unlikely((void *)m >= ptr)) {
		afree_mid(a, idx);
		return;
	}
	bit = ((unsigned)(cast_ptr(char *, ptr) - cast_ptr(char *, m)) * m->s.reciprocal) / RECIPROCAL_BASE;
	bit2 = (unsigned)(cast_ptr(char *, ptr) - cast_ptr(char *, m)) / m->s.size;
	ajla_assert(bit == bit2, (file_line, "afree: reciprocal doesn't match: size %u, reciprocal %u, %u != %u", m->s.size, m->s.reciprocal, bit, bit2));
	bit_or = (bitmap_t)1 << bit;
	pt = amalloc_per_thread();
	if (likely(pt != NULL) && likely(pt->small_runs[m->s.cls + 1] == m)) {
		m->s.map |= bit_or;
	} else {
#ifdef AMALLOC_EAGER_FREE
		size_t idx = (size_t)-1;
		struct small_block_cache *sbc = NULL;
		if (unlikely((load_relaxed(&m->s.atomic_map) | bit_or) == (bitmap_t)-1 << m->s.reserved_bits)) {
			idx = m->s.index;
			sbc = &small_block_cache[m->s.cls];
		}
#endif
		amalloc_atomic_or(&m->s.atomic_map, bit_or);
#ifdef AMALLOC_EAGER_FREE
		if (unlikely(idx != (size_t)-1)) {
			amalloc_test_free_small(sbc, idx, m);
		}
#endif
	}
}

static attr_noinline void *arealloc_malloc(void *ptr, size_t old_size, size_t new_size)
{
	void *n;
	if (unlikely(new_size == old_size))
		return ptr;
	n = amalloc(new_size);
	if (unlikely(!n))
		return NULL;
	memcpy(n, ptr, minimum(new_size, old_size));
	afree(ptr);
	return n;
}

static attr_noinline void *arealloc_huge(void *ptr, size_t size)
{
	struct huge_entry *e = huge_tree_delete(ptr);
	if (likely(size >= page_size)) {
		void *n;
		size = round_up(size, page_size);
		n = amalloc_run_realloc(ptr, e->len, size);
		if (n) {
			e->len = size;
			e->ptr = n;
			huge_tree_insert(e);
			return n;
		}
	}
	huge_tree_insert(e);
	return arealloc_malloc(ptr, e->len, size);
}

static attr_noinline void *arealloc_mid(struct arena *a, unsigned idx, size_t size)
{
	unsigned existing_blocks = a->map[idx] + 1 - idx;
	if (size > DIRECT_LIMIT && size <= ARENA_SIZE) {
		bool f;
		unsigned new_blocks = round_up(size, MIDBLOCK_SIZE) >> MIDBLOCK_BITS;
		arena_lock(a);
		f = arena_try_realloc_midblock(a, idx, existing_blocks, new_blocks);
		arena_unlock(a);
		if (f)
			return idx_to_midblock(a, idx);
	}
	return arealloc_malloc(idx_to_midblock(a, idx), (size_t)existing_blocks << MIDBLOCK_BITS, size);
}

void * attr_fastcall arealloc(void *ptr, size_t size)
{
	unsigned idx;
	union midblock *m;
	struct arena *a = addr_to_arena(ptr);
	if (unlikely((void *)a == ptr)) {
		return arealloc_huge(ptr, size);
	}
	idx = midblock_to_idx(a, ptr);
	m = idx_to_midblock(a, a->map[idx]);
	if (unlikely((void *)m >= ptr)) {
		return arealloc_mid(a, idx, size);
	}
	if (INDEX_TO_CLASS(SIZE_TO_INDEX(size)) != m->s.cls) {
		return arealloc_malloc(ptr, m->s.size, size);
	}
	return ptr;
}

size_t asize(void *ptr)
{
	unsigned idx;
	union midblock *m;
	struct arena *a = addr_to_arena(ptr);
	if (unlikely((void *)a == ptr)) {
		struct huge_entry *he = huge_tree_find(ptr);
		return he->len;
	}
	idx = midblock_to_idx(a, ptr);
	m = idx_to_midblock(a, a->map[idx]);
	if (unlikely((void *)m >= ptr)) {
		unsigned existing_blocks = a->map[idx] + 1 - idx;
		return (size_t)existing_blocks << MIDBLOCK_BITS;
	}
	return CLASS_TO_SIZE(m->s.cls);
}

bool attr_fastcall aptr_is_huge(void *ptr)
{
	struct arena *a = addr_to_arena(ptr);
	return (void *)a == ptr;
}


void amalloc_init(void)
{
	unsigned i;
	os_numa_init();
#if defined(DEBUG)
	{
		unsigned size;
		for (size = MIN_ALLOC; size <= DIRECT_LIMIT; size += MIN_ALLOC) {
			ushort_efficient_t reciprocal = div_16(RECIPROCAL_BASE + size - 1, size);
			for (i = 1; i < BITMAP_BITS; i++) {
				unsigned offs = i * size;
				unsigned ii = (offs * reciprocal) / RECIPROCAL_BASE;
				if (unlikely(ii != i))
					internal(file_line, "amalloc_init: reciprocal doesn't match: size %u, i %u, ii %u", size, i, ii);
			}
		}
	}
#endif
	amalloc_os_init();
	if (unlikely(!amalloc_enabled))
		return;
#ifdef POINTER_COMPRESSION_POSSIBLE
	if (pointer_compression_enabled)
		reserve_memory();
#endif
	amalloc_threads_initialized = false;
	amalloc_per_thread_init(&thread1);
	tree_init(&huge_tree);
	tree_init(&arena_tree);
	for (i = 0; i < N_CLASSES; i++) {
		small_block_cache[i].array = amalloc(DIRECT_LIMIT * 2);
		if (unlikely(!small_block_cache[i].array)) {
			fatal("amalloc failed");
		}
		small_block_cache[i].array_size = 0;
		small_block_cache[i].allocated_size = DIRECT_LIMIT * 2 / sizeof(union midblock *);
		small_block_cache[i].rover = 0;
	}
}

void amalloc_init_multithreaded(void)
{
	unsigned i;
	if (unlikely(!amalloc_enabled))
		return;
	if (unlikely(amalloc_threads_initialized))
		internal(file_line, "amalloc_init_multithreaded: amalloc_threads_initialized already set");
	mutex_init(&huge_tree_mutex);
	mutex_init(&arena_tree_mutex);
	tls_init(struct per_thread *, per_thread);
	tls_set(struct per_thread *, per_thread, &thread1);
	for (i = 0; i < N_CLASSES; i++) {
		mutex_init(&small_block_cache[i].mutex);
	}
#ifdef POINTER_COMPRESSION_POSSIBLE
	if (pointer_compression_enabled)
		mutex_init(&rmap_mutex);
#endif
	amalloc_threads_initialized = true;
#if 0
	{
		void *x = amalloc(0x2000000);
		debug("x: %p", x);
		x = arealloc(x, 0x4000000);
		debug("x: %p", x);
		x = arealloc(x, 0x2000000);
		debug("x: %p", x);
		x = arealloc(x, 0x4000000);
		debug("x: %p", x);
		afree(x);
	}
#endif
}

void amalloc_done_multithreaded(void)
{
	unsigned i;
	if (unlikely(!amalloc_enabled))
		return;
	if (unlikely(!amalloc_threads_initialized))
		internal(file_line, "amalloc_done_multithreaded: amalloc_threads_initialized not set");
	amalloc_threads_initialized = false;
#ifdef POINTER_COMPRESSION_POSSIBLE
	if (pointer_compression_enabled)
		mutex_done(&rmap_mutex);
#endif
	for (i = 0; i < N_CLASSES; i++) {
		mutex_done(&small_block_cache[i].mutex);
	}
	tls_set(struct per_thread *, per_thread, NULL);
	tls_done(struct per_thread *, per_thread);
	mutex_done(&arena_tree_mutex);
	mutex_done(&huge_tree_mutex);
}

void amalloc_done(void)
{
	unsigned i;
	if (unlikely(!amalloc_enabled))
		goto os_done;
	if (unlikely(amalloc_threads_initialized))
		internal(file_line, "amalloc_done: amalloc_threads_initialized set");
	detach_pt_data(&thread1);
	for (i = 0; i < N_CLASSES; i++) {
		struct small_block_cache *sbc = &small_block_cache[i];
		bitmap_t all_free = (bitmap_t)-1 << reserved_bits(i);
		size_t j;
		for (j = 0; j < sbc->array_size; j++) {
			union midblock *m = sbc->array[j];
			if (unlikely(load_relaxed(&m->s.atomic_map) != all_free))
				internal(file_line, "amalloc_done: small block memory leak, class %u", i);
			/*debug("end: freeing cached slab: %u, %p", i, m);*/
			amalloc_free_small(m);
		}
		afree(sbc->array);
		sbc->array = BAD_POINTER_1;
	}
	if (unlikely(!tree_is_empty(&huge_tree)))
		internal(file_line, "amalloc_done: huge tree is not empty");
	if (unlikely(!tree_is_empty(&arena_tree)))
		internal(file_line, "amalloc_done: arena tree is not empty");
os_done:
	amalloc_os_done();
#if 0
	{
		struct tree_entry *e, *f;
		debug("%x", (unsigned)(ARENA_MIDBLOCKS - ARENA_PREFIX));
		for (e = tree_first(&arena_tree); e; e = tree_next(e)) {
			struct arena *a = get_struct(e, struct arena, arena_entry);
			debug("leaked arena %p, %x", a, a->max_midblock_run);
			for (f = tree_first(&a->midblock_free); f; f = tree_next(f)) {
				union midblock *m = get_struct(f, union midblock, free_entry);
				unsigned idx = midblock_to_idx(a, m);
				unsigned len = (a->map[idx] & ~MAP_FREE) + 1 - idx;
				debug("free midblock: %p: %x, %x", m, idx, len);
				if (idx + len < ARENA_MIDBLOCKS) {
					union midblock *m2 = idx_to_midblock(a, idx + len);
					debug("small run(%p): %lx, atomic_map: %lx, size: %u, class %u", m2, m2->s.map, m2->s.atomic_map, m2->s.size, m2->s.cls);
				}
			}
		}
	}
#endif
#ifdef POINTER_COMPRESSION_POSSIBLE
	if (pointer_compression_enabled)
		unreserve_memory();
#endif
	os_numa_done();
}

#endif
