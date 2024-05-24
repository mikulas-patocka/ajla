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

#ifndef AJLA_AMALLOC_H
#define AJLA_AMALLOC_H

#ifdef USE_AMALLOC

void * attr_fastcall amalloc(size_t size);
void * attr_fastcall acalloc(size_t size);
void * attr_fastcall amemalign(size_t al, size_t size);
void * attr_fastcall acmemalign(size_t al, size_t size);
void attr_fastcall afree(void *ptr);
void * attr_fastcall arealloc(void *ptr, size_t size);
bool attr_fastcall aptr_is_huge(void *ptr);

#ifdef POINTER_COMPRESSION_POSSIBLE
bool amalloc_ptrcomp_try_reserve_range(void *ptr, size_t length);
#endif
void *amalloc_run_alloc(size_t al, size_t length, bool clr, bool saved);
void amalloc_run_free(void *ptr, size_t length);

void amalloc_init(void);
void amalloc_init_multithreaded(void);
void amalloc_done_multithreaded(void);
void amalloc_done(void);

#else

static inline void * attr_fastcall amalloc(size_t attr_unused size) { return NULL; }
static inline void * attr_fastcall acalloc(size_t attr_unused size) { return NULL; }
static inline void * attr_fastcall amemalign(size_t attr_unused al, size_t attr_unused size) { return NULL; }
static inline void * attr_fastcall acmemalign(size_t attr_unused al, size_t attr_unused size) { return NULL; }
static inline void attr_fastcall afree(void attr_unused *ptr) { }
static inline void * attr_fastcall arealloc(void attr_unused *ptr, size_t attr_unused size) { return NULL; }
static inline bool attr_fastcall aptr_is_huge(void attr_unused *ptr) { return false; }

#define amalloc_init() do { } while(0)
#define amalloc_init_multithreaded() do { } while(0)
#define amalloc_done_multithreaded() do { } while(0)
#define amalloc_done() do { } while(0)

#endif

#endif
