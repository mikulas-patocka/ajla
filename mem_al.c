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

#include "list.h"
#include "thread.h"
#include "str.h"
#include "refcount.h"
#include "addrlock.h"
#include "amalloc.h"

#include "mem_al.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#if defined(POINTER_COMPRESSION_POSSIBLE)
uchar_efficient_t pointer_compression_enabled = 0;
#endif

#if defined(USE_AMALLOC)
uchar_efficient_t amalloc_enabled = 1;
#endif

/*#define TEST_OOM*/

#if defined(TEST_OOM)
#define alloc_should_fail(mayfail)	true
#elif 1
#define alloc_should_fail(mayfail)	false
#else
static bool alloc_should_fail(ajla_error_t *mayfail)
{
	static int count = 0;
	if (!mayfail)
		return false;
	count++;
	/*debug("%d", count);*/
	if (!(rand() & 0xffff)) {
		debug("failing allocation");
		return true;
	}
	return false;
}
#endif

#if defined(HAVE_MALLOC) && HAVE_MALLOC
#define heap_notzero(x)		(x)
#else
#define heap_notzero(x)		(likely((x) != 0) ? (x) : 1)
#endif

#define heap_malloc(x)		(likely(amalloc_enabled) ? amalloc(x) : malloc(heap_notzero(x)))
#define heap_calloc(x)		(likely(amalloc_enabled) ? acalloc(x) : calloc(1, heap_notzero(x)))
#define heap_realloc(x, y)	(likely(amalloc_enabled) ? arealloc(x, y) : realloc(x, y))
#define heap_free(x)		(likely(amalloc_enabled) ? afree(x) : free(cast_cpp(void *, x)))
#define heap_memalign(al, sz)	(likely(amalloc_enabled) ? amemalign(al, sz) : do_memalign(al, sz))
#define heap_cmemalign(al, sz)	(likely(amalloc_enabled) ? acmemalign(al, sz) : zmem(do_memalign(al, sz), sz))
#define heap_free_aligned(x)	(likely(amalloc_enabled) ? afree(x) : do_free_aligned(x))

static void *zmem(void *ptr, size_t size)
{
	if (likely(ptr != NULL))
		return memset(ptr, 0, size);
	return ptr;
}

#if !defined(UNUSUAL_NO_MEMALIGN) && defined(HAVE_MEMALIGN) && defined(__DJGPP__)
/* DJGPP has swapped arguments */
static inline void *do_memalign(size_t al, size_t sz)
{
	return memalign(heap_notzero(sz), al);
}
#define do_free_aligned		free
#elif !defined(UNUSUAL_NO_MEMALIGN) && defined(HAVE_MEMALIGN) && !defined(__sun__)
#define do_memalign		memalign
#define do_free_aligned		free
#elif !defined(UNUSUAL_NO_MEMALIGN) && defined(HAVE_POSIX_MEMALIGN)
static inline void *do_memalign(size_t align, size_t sz)
{
	void *ptr = NULL;	/* avoid warning */
	sz = heap_notzero(sz);
	if (unlikely(align < sizeof(void *)))
		align = sizeof(void *);
	if (unlikely(posix_memalign(&ptr, align, sz)))
		return NULL;
	return ptr;
}
#define do_free_aligned		free
#elif !defined(UNUSUAL_NO_MEMALIGN) && defined(HAVE_ALIGNED_ALLOC)
static inline void *do_memalign(size_t align, size_t sz)
{
	size_t rsz;
	sz = heap_notzero(sz);
	rsz = round_up(sz, align);
	if (unlikely(rsz < sz))
		return NULL;
	return aligned_alloc(align, rsz);
}
#define do_free_aligned		free
#else
typedef size_t align_bytes_t;
static inline void *do_memalign(size_t align, size_t sz)
{
	size_t extra, sz2;
	void *p, *p2;
	if (align < HEAP_ALIGN)
		align = HEAP_ALIGN;
	extra = align - 1 + sizeof(align_bytes_t);
	/*debug("align: %x, %x", sz, align);*/
	if (unlikely(extra != (align_bytes_t)extra))
		internal(file_line, "do_memalign: too big alignment %"PRIuMAX"", (uintmax_t)align);
	sz2 = sz + extra;
	if (unlikely(sz2 < sz))
		return NULL;
	p = heap_malloc(sz2);
	if (unlikely(!p))
		return NULL;
	p2 = cast_ptr(char *, p) + sizeof(align_bytes_t);
	p2 = num_to_ptr(round_up(ptr_to_num(p2), align));
	(cast_ptr(align_bytes_t *, p2))[-1] = (align_bytes_t)(cast_ptr(char *, p2) - cast_ptr(char *, p));
	return p2;
}
static inline void do_free_aligned(void *p)
{
	align_bytes_t a = (cast_ptr(align_bytes_t *, p))[-1];
	heap_free(cast_ptr(char *, p) - a);
}
#endif

static void attr_cold *oom_calloc(size_t size, ajla_error_t *mayfail, position_t position)
{
	if (mayfail == MEM_DONT_TRY_TO_FREE)
		return NULL;
	while (mem_trim_cache()) {
		void *p = heap_calloc(size);
		if (p)
			return p;
	}
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), mayfail, "out of memory for malloc, %"PRIuMAX" bytes at %s", (uintmax_t)size, position_string(position));
	return NULL;
}

static void attr_cold *oom_cmemalign(size_t size, size_t alignment, ajla_error_t *mayfail, position_t position)
{
	if (mayfail == MEM_DONT_TRY_TO_FREE)
		return NULL;
	while (mem_trim_cache()) {
		void *p = heap_cmemalign(alignment, size);
		if (p)
			return p;
	}
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), mayfail, "out of memory for memalign, %"PRIuMAX" bytes, alignment %"PRIuMAX" at %s", (uintmax_t)size, (uintmax_t)alignment, position_string(position));
	return NULL;
}

static void attr_cold *oom_realloc(void attr_unused *ptr, size_t size, ajla_error_t *mayfail, position_t position)
{
	if (mayfail == MEM_DONT_TRY_TO_FREE)
		return NULL;
	while (mem_trim_cache()) {
		void *p = heap_realloc(ptr, size);
		if (p)
			return p;
	}
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), mayfail, "out of memory for realloc, %"PRIuMAX" bytes at %s", (uintmax_t)size, position_string(position));
	return NULL;
}

#define MEMORY_DEBUG_MAGIC		1
#define MEMORY_DEBUG_REDZONE		2
#define MEMORY_DEBUG_FILL		4
#define MEMORY_DEBUG_TRACK_BLOCKS	8
#define MEMORY_DEBUG_HISTOGRAM		16

#ifdef DEBUG_MEMORY_POSSIBLE

static int memory_debug = 0;

#define USE_RED_ZONE	(likely(memory_debug & MEMORY_DEBUG_REDZONE))
#define USE_FILL	(likely(memory_debug & MEMORY_DEBUG_FILL))
#define USE_LIST	(likely(memory_debug & MEMORY_DEBUG_TRACK_BLOCKS))
#define USE_HISTOGRAM	(unlikely(memory_debug & MEMORY_DEBUG_HISTOGRAM))

#define RED_ZONE	'R'

struct histogram_entry {
	uintmax_t cnt;
	position_t position;
};

struct per_thread {
	struct list block_list;
	uintptr_t bytes;
	uintptr_t blocks;
	struct histogram_entry *histogram;
	size_t histogram_size;
	mutex_t mutex;
#ifndef THREAD_NONE
	struct list free_list;
	struct list used_list;
	tls_destructor_t destructor;
#endif
};

#define ALLOC_MAGIC		0xa110c
#define ALLOC_MAGIC_ALIGNED	0xa11167
#define ALLOC_MAGIC_FREE	0xf4ee
#define ALLOC_MAGIC_REALLOC	0x4ea110c

typedef uint32_t ah_magic_t;

struct alloc_header {
#ifndef THREAD_NONE
	struct per_thread *per_thread;
#endif
	struct list entry;
	position_t position;
	size_t size;
	size_t padding;
	ah_magic_t magic_[1];
};

#define AH_SIZE			round_up(sizeof(struct alloc_header), HEAP_ALIGN)
#define AH_DATA(ah)		(cast_ptr(unsigned char *, ah) + AH_SIZE)
#define AH_MAGIC(ah)		(cast_ptr(ah_magic_t *, AH_DATA(ah))[-1])
#define AH_RED_ZONE(ah)		(AH_DATA(ah)[ah->size])
#define AH_MALLOC_BLOCK(ah)	(cast_ptr(unsigned char *, (ah)) - (ah)->padding)
#define AH_FROM_PTR(ptr)	cast_ptr(struct alloc_header *, (cast_ptr(unsigned char *, ptr) - AH_SIZE))

static struct per_thread thread1;
static bool memory_threads_initialized;

tls_decl(unsigned char, memory_fill);

static unsigned char get_memory_fill(void)
{
	if (!memory_threads_initialized) {
		static unsigned char memory_fill_preinit = 0;
		return (unsigned char)++memory_fill_preinit;
	} else {
		unsigned char mf = tls_get(unsigned char, memory_fill);
		mf++;
		tls_set(unsigned char, memory_fill, mf);
		return mf;
	}
}

static inline void mem_per_thread_init(struct per_thread *pt)
{
	list_init(&pt->block_list);
	pt->bytes = 0;
	pt->blocks = 0;
	if (USE_HISTOGRAM) {
		pt->histogram_size = 2;
		pt->histogram = heap_calloc(pt->histogram_size * sizeof(struct histogram_entry));
	}
}

static void increment_histogram(struct per_thread *pt, size_t sz, uintmax_t count, position_t position)
{
	size_t old_count, new_count;
#if 0
	sz = round_up(sz, 16);
#endif
	if (unlikely(sz >= pt->histogram_size)) {
		size_t new_size, i;
		struct histogram_entry *new_histogram;
		new_size = pt->histogram_size;
		do {
			new_size = new_size * 2 - 1;
			if (unlikely(new_size > (size_t)-1 / sizeof(struct histogram_entry)))
				return;
		} while (sz >= new_size);
		new_histogram = heap_calloc(new_size * sizeof(struct histogram_entry));
		if (unlikely(!new_histogram))
			return;
		for (i = 0; i < pt->histogram_size; i++) {
			if (unlikely(pt->histogram[i].cnt != 0))
				new_histogram[i] = pt->histogram[i];
		}
		heap_free(pt->histogram);
		pt->histogram = new_histogram;
		pt->histogram_size = new_size;
	}
	old_count = pt->histogram[sz].cnt;
	new_count = old_count + count;
	if (unlikely(new_count < count))
		new_count = -1;
	pt->histogram[sz].cnt = new_count;
	if ((new_count ^ old_count) >= old_count)
		pt->histogram[sz].position = position;
}

#ifndef THREAD_NONE

static tls_decl(struct per_thread *, mem_per_thread);

static void mem_per_thread_free(struct per_thread *pt)
{
	thread1.bytes += pt->bytes;
	thread1.blocks += pt->blocks;
	if (unlikely(thread1.bytes < pt->bytes) || unlikely(thread1.blocks < pt->blocks))
		internal(file_line, "mem_per_thread_free: memory counters underflow: %"PRIuMAX", %"PRIuMAX" < %"PRIuMAX", %"PRIuMAX"", (uintmax_t)thread1.bytes, (uintmax_t)thread1.blocks, (uintmax_t)pt->bytes, (uintmax_t)pt->blocks);
	if (USE_HISTOGRAM) {
		size_t i;
		for (i = 0; i < pt->histogram_size; i++)
			if (unlikely(pt->histogram[i].cnt != 0))
				increment_histogram(&thread1, i, pt->histogram[i].cnt, pt->histogram[i].position);
		heap_free(pt->histogram);
	}
	while (!list_is_empty(&pt->block_list)) {
		struct alloc_header *ah = get_struct(pt->block_list.prev, struct alloc_header, entry);
		if (unlikely(ah->per_thread != pt))
			internal(file_line, "mem_per_thread_free: block is on wrong list: %p != %p (block allocated at %s)", ah->per_thread, pt, position_string(ah->position));
		ah->per_thread = &thread1;
		list_del(&ah->entry);
		list_add(&thread1.block_list, &ah->entry);
	}
	mutex_done(&pt->mutex);
	mem_free_aligned(pt);
}

#ifndef THREAD_NONE
static void mem_per_thread_destructor(tls_destructor_t *destr)
{
	struct per_thread *pt = get_struct(destr, struct per_thread, destructor);
	tls_set(struct per_thread *, mem_per_thread, &thread1);

	ajla_assert_lo(memory_threads_initialized, (file_line, "mem_per_thread_destructor called when threads are not initialized"));

	mutex_lock(&thread1.mutex);
	list_del(&pt->used_list);
	list_add(&thread1.free_list, &pt->free_list);
	mutex_unlock(&thread1.mutex);
}
#endif

static attr_noinline struct per_thread *mem_per_thread_alloc(void)
{
	struct per_thread *pt;
	ajla_error_t sink;
	tls_set(struct per_thread *, mem_per_thread, &thread1);
	mutex_lock(&thread1.mutex);
	if (!list_is_empty(&thread1.free_list)) {
		pt = get_struct(thread1.free_list.prev, struct per_thread, free_list);
		list_del(&pt->free_list);
		mutex_unlock(&thread1.mutex);
		goto have_pt;
	}
	mutex_unlock(&thread1.mutex);
	pt = mem_align_mayfail(struct per_thread *, round_up(sizeof(struct per_thread), SMP_ALIAS_ALIGNMENT), SMP_ALIAS_ALIGNMENT, &sink);
	if (likely(pt != NULL)) {
		mutex_init(&pt->mutex);
		mem_per_thread_init(pt);
have_pt:
		mutex_lock(&thread1.mutex);
		list_add(&thread1.used_list, &pt->used_list);
		mutex_unlock(&thread1.mutex);
		tls_set(struct per_thread *, mem_per_thread, pt);
		tls_destructor(&pt->destructor, mem_per_thread_destructor);
	} else {
		tls_set(struct per_thread *, mem_per_thread, NULL);
		pt = &thread1;
	}
	return pt;
}

static struct per_thread *mem_current_thread(void)
{
	struct per_thread *pt;
	if (unlikely(!memory_threads_initialized)) {
		pt = &thread1;
	} else {
		pt = tls_get(struct per_thread *, mem_per_thread);
		if (unlikely(!pt)) {
			pt = mem_per_thread_alloc();
		}
	}
	return pt;
}

#endif

static struct per_thread *mem_mutex_lock(struct alloc_header attr_unused *ah)
{
	struct per_thread *pt;
#ifndef THREAD_NONE
	pt = ah->per_thread;
#else
	pt = &thread1;
#endif
	if (likely(memory_threads_initialized)) {
		mutex_lock(&pt->mutex);
#ifndef THREAD_NONE
		ajla_assert(pt == ah->per_thread, (file_line, "mem_mutex_lock: per_thread changed: %p != %p", pt, ah->per_thread));
#endif
	}
	return pt;
}

static void mem_mutex_unlock(struct per_thread *pt)
{
	if (likely(memory_threads_initialized)) {
		mutex_unlock(&pt->mutex);
	}
}

#define VFY_UNALIGNED	1
#define VFY_ALIGNED	2
#define VFY_ANY		3

#ifdef POINTER_IGNORE_START
#define verify_no_tag(ah, position, fn)					\
do {									\
	if (unlikely((ptr_to_num(ah) & POINTER_IGNORE_MASK) != 0))\
		internal(position_string(position), "%s: pointer is tagged: %p", fn, AH_DATA(ah));\
} while (0)
#else
#define verify_no_tag(ah, position, fn)					\
do {									\
} while (0)
#endif

#define verify_block(ah, aligned, position, fn)				\
do {									\
	verify_no_tag(ah, position, fn);				\
	if (!(								\
	    ((aligned) & VFY_UNALIGNED && likely(AH_MAGIC(ah) == ALLOC_MAGIC)) ||\
	    ((aligned) & VFY_ALIGNED && likely(AH_MAGIC(ah) == ALLOC_MAGIC_ALIGNED))\
	))								\
		internal(position_string(position), "%s: magic doesn't match: %08lx", fn, (unsigned long)AH_MAGIC(ah));\
	if (USE_RED_ZONE && unlikely(AH_RED_ZONE(ah) != RED_ZONE))	\
		internal(position_string(position), "%s: red zone damaged: %02x (block allocated at %s)", fn, AH_RED_ZONE(ah), position_string(ah->position));\
} while (0)

static size_t get_needed_size(size_t size, size_t extra)
{
	size_t needed_size = size + AH_SIZE + USE_RED_ZONE;
	if (unlikely(needed_size < size))
		fatal("allocation size overflow");
	needed_size += extra;
	if (unlikely(needed_size < extra))
		fatal("allocation size overflow");
	return needed_size;
}

static attr_noinline void *debug_mem_alloc(size_t size, size_t alignment, bool aligned, bool clear, ajla_error_t *mayfail, position_t position)
{
	unsigned char *result;
	size_t padding;
	struct alloc_header *ah;
	size_t needed_size;
	if (unlikely(!is_power_of_2(alignment)))
		internal(position_string(position), "debug_mem_alloc: invalid alignment %"PRIuMAX", size %"PRIuMAX"", (uintmax_t)alignment, (uintmax_t)size);
	needed_size = get_needed_size(size, alignment - 1);
	result = cast_cpp(unsigned char *, alloc_should_fail(mayfail) ? NULL : !clear ? heap_malloc(needed_size) : heap_calloc(needed_size));
	if (unlikely(!result)) {
		result = cast_cpp(unsigned char *, oom_calloc(needed_size, mayfail, position));
		if (!result)
			return NULL;
	}
	padding = -(size_t)ptr_to_num(result + AH_SIZE) & (alignment - 1);
	ah = cast_ptr(struct alloc_header *, result + padding);
	ah->padding = padding;
	ah->position = position;
	ah->size = size;
	if (USE_FILL && !clear)
		(void)memset(AH_DATA(ah), get_memory_fill(), size);
	AH_MAGIC(ah) = !aligned ? ALLOC_MAGIC : ALLOC_MAGIC_ALIGNED;
	if (USE_RED_ZONE)
		AH_RED_ZONE(ah) = RED_ZONE;
#ifndef THREAD_NONE
	ah->per_thread = mem_current_thread();
#endif
	if (USE_LIST | USE_HISTOGRAM) {
		struct per_thread *pt;
		pt = mem_mutex_lock(ah);
		if (USE_LIST) {
			list_add(&pt->block_list, &ah->entry);
			if (unlikely(pt->bytes + ah->size < pt->bytes) || unlikely(!(pt->blocks + 1)))
				internal(file_line, "debug_mem_alloc: memory counters overflow: %"PRIuMAX", %"PRIuMAX", %"PRIuMAX"", (uintmax_t)pt->bytes, (uintmax_t)ah->size, (uintmax_t)pt->blocks);
			pt->bytes += ah->size;
			pt->blocks++;
			/*debug("size: %lu, amount: %lu, blocks: %lu", ah->size, memory_amount, memory_blocks);*/
		}
		if (USE_HISTOGRAM)
			increment_histogram(pt, ah->size, 1, ah->position);
		mem_mutex_unlock(pt);
	}
	return AH_DATA(ah);
}

static attr_noinline void *debug_mem_realloc(void *ptr, size_t size, ajla_error_t *mayfail, position_t position)
{
	size_t needed_size, padding;
	unsigned char *result;
	struct alloc_header *new_ah;
	struct alloc_header *ah;
	struct per_thread *pt;

	if (unlikely(!ptr))
		internal(position_string(position), "debug_mem_realloc(NULL, %"PRIuMAX")", (uintmax_t)size);

	ah = AH_FROM_PTR(ptr);
	verify_block(ah, VFY_UNALIGNED, position, "debug_mem_realloc");
	if (USE_FILL && size < ah->size)
		(void)memset(AH_DATA(ah) + size, get_memory_fill(), ah->size - size);
	pt = mem_mutex_lock(ah);
	AH_MAGIC(ah) = ALLOC_MAGIC_REALLOC;
	padding = ah->padding;
	needed_size = get_needed_size(size, padding);
	result = cast_cpp(unsigned char *, alloc_should_fail(mayfail) ? NULL : heap_realloc(AH_MALLOC_BLOCK(ah), needed_size));
	if (unlikely(!result)) {
		AH_MAGIC(ah) = ALLOC_MAGIC;
		mem_mutex_unlock(pt);
		result = cast_cpp(unsigned char *, oom_calloc(needed_size, mayfail, position));
		if (!result) {
			if (size <= ah->size) {
				ah->size = size;
				if (USE_RED_ZONE)
					AH_RED_ZONE(ah) = RED_ZONE;
				return ptr;
			}
			return NULL;
		}
		pt = mem_mutex_lock(ah);
		(void)memcpy(result + padding, ah, minimum(size, ah->size) + AH_SIZE);
		AH_MAGIC(ah) = ALLOC_MAGIC_REALLOC;
		heap_free(ah);
	}
	new_ah = cast_ptr(struct alloc_header *, result + padding);
	AH_MAGIC(new_ah) = ALLOC_MAGIC;
	if (USE_LIST) {
		new_ah->entry.next->prev = &new_ah->entry;
		new_ah->entry.prev->next = &new_ah->entry;
		if (unlikely(pt->bytes < new_ah->size) || unlikely(!pt->blocks))
			internal(file_line, "debug_mem_realloc: memory counters underflow: %"PRIuMAX", %"PRIuMAX", %"PRIuMAX"", (uintmax_t)pt->bytes, (uintmax_t)new_ah->size, (uintmax_t)pt->blocks);
		pt->bytes -= new_ah->size;
		if (unlikely(pt->bytes + size < pt->bytes))
			internal(file_line, "debug_mem_realloc: memory counters overflow: %"PRIuMAX", %"PRIuMAX", %"PRIuMAX"", (uintmax_t)pt->bytes, (uintmax_t)size, (uintmax_t)pt->blocks);
		pt->bytes += size;
	}
	new_ah->size = size;
	if (USE_RED_ZONE)
		AH_RED_ZONE(new_ah) = RED_ZONE;
	if (USE_HISTOGRAM)
		increment_histogram(pt, size, 1, new_ah->position);
	mem_mutex_unlock(pt);
	return AH_DATA(new_ah);
}

static attr_noinline void debug_mem_free(const void *ptr, unsigned vfy, position_t position)
{
	struct alloc_header *ah;

	if (unlikely(!ptr))
		internal(position_string(position), "debug_mem_free(NULL)");

	ah = AH_FROM_PTR(ptr);
	verify_block(ah, vfy, position, "debug_mem_free");
	if (USE_FILL && (!amalloc_enabled || !aptr_is_huge(AH_MALLOC_BLOCK(ah)))) {
		unsigned char mf = get_memory_fill();
		unsigned char *zero_p = AH_DATA(ah);
		size_t zero_size = ah->size;
		if (zero_size > sizeof(refcount_t) && (int8_t)mf >= -0x70) {
			zero_p += sizeof(refcount_t);
			zero_size -= sizeof(refcount_t);
#ifndef DEBUG_REFCOUNTS
			refcount_init((refcount_t *)AH_DATA(ah));
#endif
		}
		(void)memset(zero_p, mf, zero_size);
	}
	if (USE_LIST | USE_HISTOGRAM) {
		struct per_thread *pt;
		pt = mem_mutex_lock(ah);
		if (USE_LIST) {
			list_del(&ah->entry);
			if (unlikely(pt->bytes < ah->size) || unlikely(!pt->blocks))
				internal(file_line, "debug_mem_free: memory counters underflow: %"PRIuMAX", %"PRIuMAX", %"PRIuMAX"", (uintmax_t)pt->bytes, (uintmax_t)ah->size, (uintmax_t)pt->blocks);
			pt->bytes -= ah->size;
			pt->blocks--;
		}
		mem_mutex_unlock(pt);
	}
	AH_MAGIC(ah) = ALLOC_MAGIC_FREE;
	heap_free(AH_MALLOC_BLOCK(ah));
}

/* this should not be called concurrently */
static attr_noinline void debug_mem_set_position(const void *ptr, position_t position)
{
	struct alloc_header *ah;

	if (unlikely(!ptr))
		internal(position_string(position), "debug_mem_set_position(NULL)");

	ah = AH_FROM_PTR(ptr);
	verify_block(ah, VFY_ANY, position, "debug_mem_set_position");

	ah->position = position;
}

static attr_noinline const char *debug_mem_get_position(const void *ptr, position_t position)
{
	struct alloc_header *ah;

	if (unlikely(!ptr))
		internal(position_string(position), "debug_mem_get_position(NULL)");

	ah = AH_FROM_PTR(ptr);
	verify_block(ah, VFY_ANY, position, "debug_mem_get_position");

	return position_string(ah->position);
}

static attr_noinline void debug_mem_verify(const void *ptr, position_t position)
{
	struct alloc_header *ah;
	ah = AH_FROM_PTR(ptr);
	verify_block(ah, VFY_UNALIGNED, position, "debug_mem_verify");
}

static attr_noinline void debug_mem_verify_aligned(const void *ptr, position_t position)
{
	struct alloc_header *ah;
	ah = AH_FROM_PTR(ptr);
	verify_block(ah, VFY_ALIGNED, position, "debug_mem_verify_aligned");
}

#endif

#define verify_size							\
	do {								\
		if (sizeof(ptrdiff_t) < 8 &&				\
		    (unlikely(size != (size_t)(ptrdiff_t)size) ||	\
		     unlikely((ptrdiff_t)size < 0))) {			\
			fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "allocation size overflow: %"PRIuMAX" bytes", (uintmax_t)size);\
			return NULL;					\
		}							\
	} while (0)

void * attr_hot_fastcall mem_alloc_position(size_t size, ajla_error_t *mayfail argument_position)
{
	void *new_ptr;
	if (likely(mayfail != MEM_DONT_TRY_TO_FREE))
		address_lock_verify();
	verify_size;
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_debug))
		return debug_mem_alloc(size, 1, false, false, mayfail, position_arg);
#endif
	new_ptr = alloc_should_fail(mayfail) ? NULL : heap_malloc(size);
	if (unlikely(!new_ptr)) {
		new_ptr = oom_calloc(size, mayfail, position_arg);
	}
	return new_ptr;
}

void * attr_hot_fastcall mem_calloc_position(size_t size, ajla_error_t *mayfail argument_position)
{
	void *new_ptr;
	if (likely(mayfail != MEM_DONT_TRY_TO_FREE))
		address_lock_verify();
	verify_size;
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_debug))
		return debug_mem_alloc(size, 1, false, true, mayfail, position_arg);
#endif
	new_ptr = alloc_should_fail(mayfail) ? NULL : heap_calloc(size);
	if (!new_ptr) {
		new_ptr = oom_calloc(size, mayfail, position_arg);
	}
	return new_ptr;

}

void * attr_hot_fastcall mem_align_position(size_t size, size_t alignment, ajla_error_t *mayfail argument_position)
{
	void *new_ptr;
	if (likely(mayfail != MEM_DONT_TRY_TO_FREE))
		address_lock_verify();
	verify_size;
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_debug))
		return debug_mem_alloc(size, alignment, true, false, mayfail, position_arg);
#endif
	new_ptr = alloc_should_fail(mayfail) ? NULL : heap_memalign(alignment, size);
	if (unlikely(!new_ptr)) {
		new_ptr = oom_cmemalign(size, alignment, mayfail, position_arg);
	}
	return new_ptr;
}

void * attr_hot_fastcall mem_calign_position(size_t size, size_t alignment, ajla_error_t *mayfail argument_position)
{
	void *new_ptr;
	if (likely(mayfail != MEM_DONT_TRY_TO_FREE))
		address_lock_verify();
	verify_size;
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_debug))
		return debug_mem_alloc(size, alignment, true, true, mayfail, position_arg);
#endif
	new_ptr = alloc_should_fail(mayfail) ? NULL : heap_cmemalign(alignment, size);
	if (unlikely(!new_ptr)) {
		new_ptr = oom_cmemalign(size, alignment, mayfail, position_arg);
	}
	return new_ptr;
}

void * attr_hot_fastcall mem_realloc_position(void *ptr, size_t size, ajla_error_t *mayfail argument_position)
{
	void *new_ptr;
	if (likely(mayfail != MEM_DONT_TRY_TO_FREE))
		address_lock_verify();
	verify_size;
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_debug))
		return debug_mem_realloc(ptr, size, mayfail, position_arg);
#endif
	if (unlikely(!size)) {
		new_ptr = mem_alloc_position(0, mayfail pass_position);
		if (likely(new_ptr != NULL))
			mem_free_position(ptr pass_position);
		return new_ptr;
	}
	new_ptr = alloc_should_fail(mayfail) ? NULL : heap_realloc(ptr, size);
	if (!new_ptr) {
		new_ptr = oom_realloc(ptr, size, mayfail, position_arg);
	}
	return new_ptr;
}

void attr_hot_fastcall mem_free_position(const void *ptr argument_position)
{
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_debug)) {
		debug_mem_free(ptr, VFY_UNALIGNED, position_arg);
		return;
	}
#endif
	heap_free((void *)ptr);
}

void attr_hot_fastcall mem_free_aligned_position(const void *ptr argument_position)
{
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_debug)) {
		debug_mem_free(ptr, VFY_ALIGNED, position_arg);
		return;
	}
#endif
	heap_free_aligned((void *)ptr);
}

#ifdef DEBUG_MEMORY_POSSIBLE
void attr_fastcall mem_set_position(const void *ptr argument_position)
{
	if (unlikely(memory_debug)) {
		debug_mem_set_position(ptr, position_arg);
	}
}
const char * attr_fastcall mem_get_position(const void *ptr argument_position)
{
	if (unlikely(memory_debug)) {
		return debug_mem_get_position(ptr, position_arg);
	}
	return "unknown position";
}
void attr_fastcall mem_verify_position(const void *ptr argument_position)
{
	if (unlikely(memory_debug)) {
		debug_mem_verify(ptr, position_arg);
	}
}
void attr_fastcall mem_verify_aligned_position(const void *ptr argument_position)
{
	if (unlikely(memory_debug)) {
		debug_mem_verify_aligned(ptr, position_arg);
	}
}
#endif

bool attr_cold mem_trim_cache(void)
{
	/* !!! TODO */
	return false;
}

#ifdef DEBUG_MEMORY_POSSIBLE
static mutex_t mem_report_mutex;

struct memory_entry {
	position_t position;
	size_t size;
	uintptr_t cumulative_size;
	uintptr_t n_blocks;
};

static bool attr_cold add_memory_entry(struct memory_entry **me, size_t *me_l, struct alloc_header *ah)
{
	if (unlikely(!(*me_l & (*me_l - 1)))) {
		struct memory_entry *m;
		size_t ns = !*me_l ? 1 : *me_l * 2;
		if (unlikely(!ns) || ns > (size_t)-1 / sizeof(struct alloc_header))
			return false;
		m = heap_realloc(*me, ns * sizeof(struct alloc_header));
		if (unlikely(!m))
			return false;
		*me = m;
	}
	(*me)[*me_l].position = ah->position;
	(*me)[*me_l].size = ah->size;
	(*me)[*me_l].cumulative_size = ah->size;
	(*me)[*me_l].n_blocks = 1;
	(*me_l)++;
	return true;
}

static bool attr_cold add_memory_entries(struct memory_entry **me, size_t *me_l, struct per_thread *pt)
{
	struct list *l;
	list_for_each(l, &pt->block_list) {
		struct alloc_header *ah = get_struct(l, struct alloc_header, entry);
		if (unlikely(!add_memory_entry(me, me_l, ah)))
			return false;
	}
	return true;
}

static int attr_cold mem_compare_file_line(const void *me1_, const void *me2_)
{
	const struct memory_entry *me1 = me1_;
	const struct memory_entry *me2 = me2_;
	const char *p1 = position_string_alloc(me1->position);
	const char *p2 = position_string_alloc(me2->position);
#ifdef HAVE_STRVERSCMP
	int c = strverscmp(p1, p2);
#else
	int c = strcmp(p1, p2);
#endif
	position_string_free(p1);
	position_string_free(p2);
	return c;
}

static int attr_cold mem_compare_cumulative_size(const void *me1_, const void *me2_)
{
	const struct memory_entry *me1 = me1_;
	const struct memory_entry *me2 = me2_;
	if (me1->cumulative_size < me2->cumulative_size)
		return 1;
	if (me1->cumulative_size > me2->cumulative_size)
		return -1;
	if (me1->n_blocks < me2->n_blocks)
		return 1;
	if (me1->n_blocks > me2->n_blocks)
		return -1;
	return mem_compare_file_line(me1, me2);
}

void attr_cold mem_report_usage(int mode, const char *string)
{
	struct memory_entry *me;
	size_t me_l, me_l2, mr;
	uintptr_t total;
	bool ok;
#ifndef THREAD_NONE
	struct list *l;
#endif
	size_t max_ps, max_digits;

	if (!USE_LIST) {
		warning("memory list not available, use --debug=leak");
		return;
	}

	if (memory_threads_initialized) mutex_lock(&mem_report_mutex);

	me_l = 0;
	me = heap_malloc(1);
	if (!me)
		goto oom;

	if (memory_threads_initialized) mutex_lock(&thread1.mutex);
	ok = add_memory_entries(&me, &me_l, &thread1);
#ifndef THREAD_NONE
	list_for_each(l, &thread1.used_list) {
		struct per_thread *pt = get_struct(l, struct per_thread, used_list);
		if (memory_threads_initialized) mutex_lock(&pt->mutex);
		if (ok) ok = add_memory_entries(&me, &me_l, pt);
		if (memory_threads_initialized) mutex_unlock(&pt->mutex);
	}
	list_for_each(l, &thread1.free_list) {
		struct per_thread *pt = get_struct(l, struct per_thread, free_list);
		if (memory_threads_initialized) mutex_lock(&pt->mutex);
		if (ok) ok = add_memory_entries(&me, &me_l, pt);
		if (memory_threads_initialized) mutex_unlock(&pt->mutex);
	}
#endif
	if (memory_threads_initialized) mutex_unlock(&thread1.mutex);
	if (unlikely(!ok))
		goto oom;

	total = 0;
	for (mr = 0; mr < me_l; mr++)
		total += me[mr].cumulative_size;

	debug("allocated memory%s%s: %"PRIuMAX" / %"PRIuMAX" = %"PRIuMAX"", *string ? " at " : "", string, (uintmax_t)total, (uintmax_t)me_l, (uintmax_t)(total / (me_l ? me_l : 1)));

	if (mode == MR_SUMMARY) {
		goto free_ret;
	} else if (mode == MR_MOST_ALLOCATED) {
		qsort(me, me_l, sizeof(struct memory_entry), mem_compare_file_line);
		me_l2 = 0;
		for (mr = 0; mr < me_l; mr++) {
			me[me_l2] = me[mr];
			while (mr + 1 < me_l && !mem_compare_file_line(&me[mr], &me[mr + 1])) {
				mr++;
				me[me_l2].cumulative_size += me[mr].size;
				me[me_l2].n_blocks++;
			}
			me_l2++;
		}
	} else if (mode == MR_LARGEST_BLOCKS) {
		me_l2 = me_l;
	} else {
		internal(file_line, "mem_report_usage: invalid mode %d", mode);
	}
	qsort(me, me_l2, sizeof(struct memory_entry), mem_compare_cumulative_size);

	max_ps = 0;
	for (mr = 0; mr < me_l2; mr++) {
		const char *ps = position_string_alloc(me[mr].position);
		size_t psl = strlen(ps);
		position_string_free(ps);
		if (psl > max_ps)
			max_ps = psl;
	}
	if (me_l2) {
		char *max_str = str_from_unsigned(me[0].cumulative_size, 10);
		max_digits = strlen(max_str);
		mem_free(max_str);
	} else {
		max_digits = 0;
	}

	for (mr = 0; mr < me_l2; mr++) {
		const char *ps;
		char *s;
		size_t sl, psl;
		str_init(&s, &sl);
		ps = position_string_alloc(me[mr].position);
		str_add_string(&s, &sl, ps);
		position_string_free(ps);
		ps = str_from_unsigned(me[mr].cumulative_size, 10);
		psl = strlen(ps);
		while (sl < max_ps + 1 + (max_digits - psl))
			str_add_char(&s, &sl, ' ');
		str_add_string(&s, &sl, ps);
		mem_free(ps);
		if (mode == MR_MOST_ALLOCATED) {
			str_add_bytes(&s, &sl, " / ", 3);
			str_add_unsigned(&s, &sl, me[mr].n_blocks, 10);
			str_add_bytes(&s, &sl, " = ", 3);
			str_add_unsigned(&s, &sl, me[mr].cumulative_size / me[mr].n_blocks, 10);
		} else if (mode == MR_LARGEST_BLOCKS) {
			size_t mq;
			for (mq = mr + 1; mq < me_l2; mq++) {
				if (mem_compare_file_line(&me[mr], &me[mq]))
					break;
				if (me[mr].cumulative_size != me[mq].cumulative_size)
					break;
			}
			if (mq > mr + 1) {
				str_add_bytes(&s, &sl, " x ", 3);
				str_add_unsigned(&s, &sl, mq - mr, 10);
			}
			mr = mq - 1;
		}
		str_finish(&s, &sl);
		debug("%s", s);
		mem_free(s);
	}

free_ret:
	if (memory_threads_initialized) mutex_unlock(&mem_report_mutex);
	heap_free(me);
	return;

oom:
	if (memory_threads_initialized) mutex_unlock(&mem_report_mutex);
	if (me) heap_free(me);
	warning("out of memory for memory list, allocated size %"PRIuMAX"", (uintmax_t)me_l);
}
#endif

#ifdef DEBUG_MEMORY_POSSIBLE
static attr_noreturn attr_cold mem_dump_leaks(void)
{
	struct list leaked_list;
	struct list *lv;
	char *s;
	size_t sl;
	const char *head = "memory leak: ";
	size_t strlen_head = strlen(head);
	const char *first_pos = file_line;
	uintmax_t n_blocks = 0;
	uintmax_t n_bytes = 0;

	list_take(&leaked_list, &thread1.block_list);
	str_init(&s, &sl);

	list_for_each_back(lv, &leaked_list) {
		struct alloc_header *ah;
		const char *pos_str;
		char *t;
		size_t tl;

		ah = get_struct(lv, struct alloc_header, entry);
		pos_str = position_string(ah->position);

		str_init(&t, &tl);
		str_add_unsigned(&t, &tl, ptr_to_num((char *)ah + AH_SIZE), 16);
		str_add_string(&t, &tl, ":");
		str_add_unsigned(&t, &tl, ah->size, 10);
		str_add_string(&t, &tl, " @ ");
		str_add_string(&t, &tl, pos_str);
		str_finish(&t, &tl);

		if (sl && strlen_head + sl + 2 + tl > 174 - 15) {
			str_finish(&s, &sl);
			debug("memory leak: %s", s);
			mem_free(s);
			str_init(&s, &sl);
		}

		if (sl) str_add_string(&s, &sl, ", ");
		else first_pos = pos_str;
		str_add_string(&s, &sl, t);
		mem_free(t);

		n_blocks++;
		n_bytes += ah->size;
	}

	str_finish(&s, &sl);

	internal(first_pos, "memory leak (%"PRIuMAX" blocks, %"PRIuMAX" bytes): %s", n_blocks, n_bytes, s);
}
#endif

bool mem_enable_debugging_option(const char *option, size_t l)
{
#ifndef DEBUG_MEMORY_POSSIBLE
	int memory_debug = 0;
#endif
	if (!option)
		memory_debug |= MEMORY_DEBUG_MAGIC | MEMORY_DEBUG_REDZONE | MEMORY_DEBUG_FILL | MEMORY_DEBUG_TRACK_BLOCKS;
	else if (l == 5 && !strncmp(option, "magic", l))
		memory_debug |= MEMORY_DEBUG_MAGIC;
	else if (l == 7 && !strncmp(option, "redzone", l))
		memory_debug |= MEMORY_DEBUG_REDZONE;
	else if (l == 4 && !strncmp(option, "fill", l))
		memory_debug |= MEMORY_DEBUG_FILL;
	else if (l == 4 && !strncmp(option, "leak", l))
		memory_debug |= MEMORY_DEBUG_TRACK_BLOCKS;
	else if (l == 6 && !strncmp(option, "memory", l))
		memory_debug |= MEMORY_DEBUG_MAGIC | MEMORY_DEBUG_REDZONE | MEMORY_DEBUG_FILL | MEMORY_DEBUG_TRACK_BLOCKS;
	else
		return false;
	return true;
}

bool mem_al_enable_profile(const char *option, size_t l)
{
#ifndef DEBUG_MEMORY_POSSIBLE
	int memory_debug = 0;
#endif
	if (!option)
		memory_debug |= MEMORY_DEBUG_HISTOGRAM;
	else if (l == 6 && !strncmp(option, "memory", l))
		memory_debug |= MEMORY_DEBUG_HISTOGRAM;
	else
		return false;
	return true;
}

void mem_al_set_ptrcomp(const char attr_unused *str)
{
#ifdef POINTER_COMPRESSION_POSSIBLE
	pointer_compression_enabled = 1;
#endif
}

void mem_al_set_system_malloc(const char attr_unused *str)
{
#ifdef USE_AMALLOC
	amalloc_enabled = 0;
#endif
}

void mem_init(void)
{
#if defined(POINTER_COMPRESSION_POSSIBLE) && defined(USE_AMALLOC)
	if (pointer_compression_enabled && !amalloc_enabled)
		fatal("The options --ptrcomp and --system-malloc are not compatible");
#endif
#ifdef DEBUG_MEMORY_POSSIBLE
	if (USE_LIST | USE_HISTOGRAM) {
		mem_per_thread_init(&thread1);
	}
	memory_threads_initialized = false;
	/*if (memory_debug & MEMORY_DEBUG_REDZONE && dl_sym("EF_Abort", NULL)) {
		debug("Electric Fence detected, disabling red zone");
		memory_debug &= ~MEMORY_DEBUG_REDZONE;
	}*/
#ifndef THREAD_NONE
	list_init(&thread1.used_list);
#endif
#endif
}

void mem_init_multithreaded(void)
{
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_threads_initialized))
		internal(file_line, "mem_init_multithreaded: memory_threads_initialized already set");
	if (USE_LIST | USE_HISTOGRAM) {
		mutex_init(&thread1.mutex);
		mutex_init(&mem_report_mutex);
		tls_init(unsigned char, memory_fill);
#ifndef THREAD_NONE
		list_init(&thread1.free_list);
		tls_init(struct per_thread *, mem_per_thread);
		tls_set(struct per_thread *, mem_per_thread, &thread1);
#endif
		memory_threads_initialized = true;
	}
#endif
}

void mem_done_multithreaded(void)
{
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(!!memory_threads_initialized != !!(USE_LIST | USE_HISTOGRAM)))
		internal(file_line, "mem_done_multithreaded: memory_threads_initialized %sset", memory_threads_initialized ? "" : "not ");
	if (USE_LIST | USE_HISTOGRAM) {
		memory_threads_initialized = false;
#ifndef THREAD_NONE
		tls_done(struct per_thread *, mem_per_thread);
		while (!list_is_empty(&thread1.free_list)) {
			struct per_thread *pt = get_struct(thread1.free_list.next, struct per_thread, free_list);
			list_del(&pt->free_list);
			mem_per_thread_free(pt);
			/* { static unsigned x = 0; debug("freeing per_thread: %u", ++x); } */
		}
		if (!list_is_empty(&thread1.used_list)) {
			internal(file_line, "mem_done_multithreaded: used_list is not empty");
		}
#endif
		tls_done(unsigned char, memory_fill);
		mutex_done(&mem_report_mutex);
		mutex_done(&thread1.mutex);
	}
#endif
}

void mem_done(void)
{
#ifdef DEBUG_MEMORY_POSSIBLE
	if (unlikely(memory_threads_initialized))
		internal(file_line, "mem_done: memory_threads_initialized set");
	if (USE_LIST) {
		if (unlikely(!list_is_empty(&thread1.block_list)))
			mem_dump_leaks();
		if (unlikely(thread1.bytes != 0) || unlikely(thread1.blocks != 0))
			internal(file_line, "mem_done: memory counters leaked: %"PRIuMAX", %"PRIuMAX"", (uintmax_t)thread1.bytes, (uintmax_t)thread1.blocks);
	}
	if (USE_HISTOGRAM) {
		size_t i;
		for (i = 0; i < thread1.histogram_size; i++)
			if (unlikely(thread1.histogram[i].cnt != 0))
				debug("%"PRIuMAX"(%"PRIxMAX") : %"PRIuMAX"\t\t%s", (uintmax_t)i, (uintmax_t)i, thread1.histogram[i].cnt, position_string(thread1.histogram[i].position));
		heap_free(thread1.histogram);
		thread1.histogram = NULL;
	}
#endif
}
