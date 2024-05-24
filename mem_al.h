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

#ifndef AJLA_MEM_AL_H
#define AJLA_MEM_AL_H

#if defined(USE_AMALLOC)
extern uchar_efficient_t amalloc_enabled;
#else
#define amalloc_enabled		0
#endif

void * attr_fastcall mem_alloc_position(size_t size, ajla_error_t *mayfail argument_position);
void * attr_fastcall mem_calloc_position(size_t size, ajla_error_t *mayfail argument_position);
void * attr_fastcall mem_align_position(size_t size, size_t alignment, ajla_error_t *mayfail argument_position);
void * attr_fastcall mem_calign_position(size_t size, size_t alignment, ajla_error_t *mayfail argument_position);
void * attr_fastcall mem_realloc_position(void *ptr, size_t size, ajla_error_t *mayfail argument_position);
void attr_fastcall mem_free_position(const void *ptr argument_position);
void attr_fastcall mem_free_aligned_position(const void *ptr argument_position);

#define mem_alloc_fn(x, y)		mem_alloc_position(x, y pass_file_line)
#define mem_calloc_fn(x, y)		mem_calloc_position(x, y pass_file_line)
#define mem_align_fn(x, y, z)		mem_align_position(x, y, z pass_file_line)
#define mem_calign_fn(x, y, z)		mem_calign_position(x, y, z pass_file_line)
#define mem_realloc_fn(x, y, z)		mem_realloc_position(x, y, z pass_file_line)
#define mem_free(x)			mem_free_position(x pass_file_line)
#define mem_free_aligned(x)		mem_free_aligned_position(x pass_file_line)

#define mem_alloc_mayfail(t, x, y)	cast_ptr(t, mem_alloc_fn(x, y))
#define mem_calloc_mayfail(t, x, y)	cast_ptr(t, mem_calloc_fn(x, y))
#define mem_align_mayfail(t, x, y, z)	cast_ptr(t, mem_align_fn(x, y, z))
#define mem_calign_mayfail(t, x, y, z)	cast_ptr(t, mem_calign_fn(x, y, z))
#define mem_realloc_mayfail(t, x, y, z)	cast_ptr(t, mem_realloc_fn(x, y, z))

#define mem_alloc(t, x)			mem_alloc_mayfail(t, x, NULL)
#define mem_calloc(t, x)		mem_calloc_mayfail(t, x, NULL)
#define mem_align(t, x, y)		mem_align_mayfail(t, x, y, NULL)
#define mem_calign(t, x, y)		mem_calign_mayfail(t, x, y, NULL)
#define mem_realloc(t, x, y)		mem_realloc_mayfail(t, x, y, NULL)

#ifdef DEBUG_MEMORY_POSSIBLE
void attr_fastcall mem_set_position(const void *ptr argument_position);
const char * attr_fastcall mem_get_position(const void *ptr argument_position);
void attr_fastcall mem_verify_position(const void attr_unused *ptr argument_position);
void attr_fastcall mem_verify_aligned_position(const void attr_unused *ptr argument_position);
#else
static inline void mem_set_position(const void attr_unused *ptr argument_position) { }
static inline const char *mem_get_position(const void attr_unused *ptr argument_position) { return "unknown position"; }
static inline void mem_verify_position(const void attr_unused *ptr argument_position) { }
static inline void mem_verify_aligned_position(const void attr_unused *ptr argument_position) { }
#endif

#define mem_get_pos(x)			mem_get_position(x pass_file_line)
#define mem_verify(x)			mem_verify_position(x pass_file_line)
#define mem_verify_aligned(x)		mem_verify_aligned_position(x pass_file_line)

bool mem_trim_cache(void);

#define MR_SUMMARY			0
#define MR_MOST_ALLOCATED		1
#define MR_LARGEST_BLOCKS		2
#ifdef DEBUG_MEMORY_POSSIBLE
void mem_report_usage(int mode, const char *string);
#else
static inline void mem_report_usage(int attr_unused mode, const char attr_unused *string) { }
#endif

bool mem_enable_debugging_option(const char *option, size_t l);
bool mem_al_enable_profile(const char *option, size_t l);
void mem_al_set_ptrcomp(const char *str);
void mem_al_set_system_malloc(const char attr_unused *str);
void mem_init(void);
void mem_init_multithreaded(void);
void mem_done_multithreaded(void);
void mem_done(void);

static inline bool mem_check_overflow(size_t prefix, size_t n_elements, size_t el_size, ajla_error_t *err)
{
	if (unlikely(n_elements > (size_t_limit - prefix) / el_size)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SIZE_OVERFLOW), err, "allocation size overflow: %" PRIuMAX " + %" PRIuMAX " * %" PRIuMAX "", (uintmax_t)prefix, (uintmax_t)n_elements, (uintmax_t)el_size);
		return false;
	}
	return true;
}

#define struct_check_overflow(full, part, n_elements, err)		mem_check_overflow(offsetof(full, part), n_elements, sizeof(((full *)NULL)->part[0]), err)

#define mem_alloc_array_mayfail(alloc, type, minimum, prefix, n_elements, el_size, err)\
	(unlikely(!mem_check_overflow(prefix, n_elements, el_size, err)) ? cast_ptr(type, NULL) : alloc(type, maximum_maybe0((size_t)(prefix) + (size_t)(n_elements) * (size_t)(el_size), (size_t)(minimum)), err))

#define struct_alloc_array_mayfail(alloc, full, part, n_elements, err)\
	mem_alloc_array_mayfail(alloc, full *, partial_sizeof_lower_bound(full), offsetof(full, part), n_elements, sizeof(((full *)NULL)->part[0]), err)

#endif
