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

#include "thread.h"

#include "addrlock.h"

static union {
	mutex_t lock;
	char padding[mutex_padding_size];
} attr_aligned(64) address_hash[N_POINTER_DEPTHS][POINTER_HASH_SIZE];


static union {
	rwmutex_t lock;
	char padding[rwmutex_padding_size];
} attr_aligned(64) address_rwmutex_hash[POINTER_HASH_SIZE];

#if defined(DEBUG) || defined(DEBUG_ALLOC_INSIDE_LOCKS)
#define TEST_INIT
#endif

#ifdef TEST_INIT
static bool address_hash_initialized = false;
#endif

static unsigned address_hash_value(const void *p)
{
	uintptr_t num = ptr_to_num(p);
	return (unsigned)(num ^ (num >> POINTER_HASH_BITS) ^ (num >> POINTER_HASH_BITS * 2)) & (POINTER_HASH_SIZE - 1);
}

void attr_fastcall address_lock(const void *p, addrlock_depth d)
{
	unsigned hash;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_lock: address_hash_initialized not set");
#endif
	hash = address_hash_value(p);
	mutex_lock(&address_hash[d][hash].lock);
}

void attr_fastcall address_unlock(const void *p, addrlock_depth d)
{
	unsigned hash;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_unlock: address_hash_initialized not set");
#endif
	hash = address_hash_value(p);
	mutex_unlock(&address_hash[d][hash].lock);
}

void attr_fastcall address_lock_two(const void *p1, const void *p2, addrlock_depth d)
{
	unsigned hash1, hash2;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_lock_two: address_hash_initialized not set");
#endif
	hash1 = address_hash_value(p1);
	hash2 = address_hash_value(p2);
	if (hash1 < hash2) {
		mutex_lock(&address_hash[d][hash1].lock);
		mutex_lock(&address_hash[d][hash2].lock);
	} else if (likely(hash1 > hash2)) {
		mutex_lock(&address_hash[d][hash2].lock);
		mutex_lock(&address_hash[d][hash1].lock);
	} else {
		mutex_lock(&address_hash[d][hash1].lock);
	}
}

bool attr_fastcall address_trylock_second(const void *p1, const void *p2, addrlock_depth d)
{
	unsigned hash1, hash2;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_trylock_second: address_hash_initialized not set");
#endif
	hash1 = address_hash_value(p1);
	hash2 = address_hash_value(p2);
	if (hash1 < hash2) {
		mutex_lock(&address_hash[d][hash2].lock);
		return true;
	}
	if (likely(hash1 > hash2)) {
		return mutex_trylock(&address_hash[d][hash2].lock);
	}
	return true;
}

void attr_fastcall address_unlock_second(const void *p1, const void *p2, addrlock_depth d)
{
	unsigned hash1, hash2;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_unlock_second: address_hash_initialized not set");
#endif
	hash1 = address_hash_value(p1);
	hash2 = address_hash_value(p2);
	if (likely(hash1 != hash2))
		mutex_unlock(&address_hash[d][hash2].lock);
}

mutex_t * attr_fastcall address_get_mutex(const void *p, addrlock_depth d)
{
	unsigned hash;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_get_mutex: address_hash_initialized not set");
#endif
	hash = address_hash_value(p);
	return &address_hash[d][hash].lock;
}

void address_read_lock(const void *p)
{
	unsigned hash;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_read_lock: address_hash_initialized not set");
#endif
	hash = address_hash_value(p);
	rwmutex_lock_read(&address_rwmutex_hash[hash].lock);
}

void address_read_unlock(const void *p)
{
	unsigned hash;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_read_unlock: address_hash_initialized not set");
#endif
	hash = address_hash_value(p);
	rwmutex_unlock_read(&address_rwmutex_hash[hash].lock);
}

void address_write_lock(const void *p)
{
	unsigned hash;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_write_lock: address_hash_initialized not set");
#endif
	hash = address_hash_value(p);
	rwmutex_lock_write(&address_rwmutex_hash[hash].lock);
}

void address_write_unlock(const void *p)
{
	unsigned hash;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_write_unlock: address_hash_initialized not set");
#endif
	hash = address_hash_value(p);
	rwmutex_unlock_write(&address_rwmutex_hash[hash].lock);
}

#ifdef DEBUG_ALLOC_INSIDE_LOCKS
void address_lock_verify(void)
{
	addrlock_depth i;
	if (!address_hash_initialized)
		return;
	for (i = 0; i < N_POINTER_DEPTHS; i++) {
		address_lock(NULL, i);
		address_unlock(NULL, i);
	}
	address_write_lock(NULL);
	address_write_unlock(NULL);
}
#endif

void address_lock_init(void)
{
	unsigned i, j;
#ifdef TEST_INIT
	if (unlikely(address_hash_initialized))
		internal(file_line, "address_lock_init: address_hash_initialized already set");
#endif
	for (j = 0; j < N_POINTER_DEPTHS; j++)
		for (i = 0; i < POINTER_HASH_SIZE; i++)
			mutex_init(&address_hash[j][i].lock);
	for (i = 0; i < POINTER_HASH_SIZE; i++)
		rwmutex_init(&address_rwmutex_hash[i].lock);
#ifdef TEST_INIT
	address_hash_initialized = true;
#endif
}

void address_lock_done(void)
{
	unsigned i, j;
#ifdef TEST_INIT
	if (unlikely(!address_hash_initialized))
		internal(file_line, "address_lock_done: address_hash_initialized not set");
	address_hash_initialized = false;
#endif
	for (j = 0; j < N_POINTER_DEPTHS; j++)
		for (i = 0; i < POINTER_HASH_SIZE; i++)
			mutex_done(&address_hash[j][i].lock);
	for (i = 0; i < POINTER_HASH_SIZE; i++)
		rwmutex_done(&address_rwmutex_hash[i].lock);
}
