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

#include "mem_al.h"
#include "str.h"
#include "list.h"
#include "tree.h"
#include "thread.h"
#include "os.h"

#include "resolver.h"

/*#include <unistd.h>*/

#ifndef PIPE_BUF
#define PIPE_BUF		512
#endif

#define RESOLVER_THREADS_MAX	4

#define RESOLVER_WORK_GETADDRINFO	1
#define RESOLVER_WORK_GETNAMEINFO	2

struct resolver_request {
	struct list entry;
	handle_t p;
	char type;
	int port;
	size_t name_len;
	char name[FLEXIBLE_ARRAY];
};

#ifndef THREAD_NONE
static struct list resolver_queue;
static uchar_efficient_t resolver_end;
static cond_t resolver_cond;
static thread_t *resolver_threads;
static size_t resolver_threads_l;
static size_t resolver_threads_idle;
#endif

static void resolver_free_result(struct address *result, size_t result_l)
{
	size_t i;
	for (i = 0; i < result_l; i++)
		mem_free(result[i].address);
	mem_free(result);
}

static int address_compare(const struct tree_entry *e1, uintptr_t e2)
{
	struct address *addr1 = get_struct(e1, struct address, entry);
	struct address *addr2 = num_to_ptr(e2);
	if (unlikely(addr1->address_length < addr2->address_length))
		return -1;
	if (unlikely(addr1->address_length > addr2->address_length))
		return 1;
	return memcmp(addr1->address, addr2->address, addr1->address_length);
}

static void resolver_do_lookup(struct resolver_request *work)
{
	ajla_error_t err;
	char error_record[9];
	struct address *result = NULL;
	size_t result_l = 0;	/* avoid warning */
	size_t i;
	char *str = NULL;
	size_t str_l;
	struct tree dedup_tree;
	char *name;
	size_t l;

	if (unlikely(os_write(work->p, "", 1, &err) != 1))
		return;

	if (unlikely(!array_init_mayfail(char, &str, &str_l, &err)))
		goto fail;

	if (unlikely(!array_add_mayfail(char, &str, &str_l, 0, NULL, &err)))
		goto fail;

	switch (work->type) {
	case RESOLVER_WORK_GETADDRINFO:
		if (unlikely(!os_getaddrinfo(work->name, work->port, &result, &result_l, &err)))
			goto fail;
		tree_init(&dedup_tree);
		for (i = 0; i < result_l; i++) {
			struct address *addr = &result[i];
			char c[2];
			struct tree_insert_position pos;

			if (unlikely(tree_find_for_insert(&dedup_tree, address_compare, ptr_to_num(addr), &pos) != NULL))
				continue;
#ifdef THREAD_NONE
			if (str_l + 4 + addr->address_length > PIPE_BUF - 1)
				continue;
#endif
			tree_insert_after_find(&addr->entry, &pos);

			c[0] = addr->address_length;
			c[1] = addr->address_length >> 8;
			if (unlikely(!array_add_multiple_mayfail(char, &str, &str_l, c, 2, NULL, &err)))
				goto fail;
			if (unlikely(!array_add_multiple_mayfail(char, &str, &str_l, addr->address, addr->address_length, NULL, &err)))
				goto fail;
		}
		resolver_free_result(result, result_l);
		break;
	case RESOLVER_WORK_GETNAMEINFO:
		name = os_getnameinfo(cast_ptr(unsigned char *, work->name), work->name_len, &err);
		if (unlikely(!name))
			goto fail;
		l = strlen(name);
		if (unlikely(!array_add_multiple_mayfail(char, &str, &str_l, name, l, NULL, &err)))
			goto fail;
		mem_free(name);
		break;
	default:
		internal(file_line, "resolver_do_lookup: invalid work type %d", work->type);
	}

	os_write(work->p, str, str_l, &err);

	mem_free(str);

	return;

fail:
	if (result)
		resolver_free_result(result, result_l);
	if (str)
		mem_free(str);
	error_record[0] = 1;
	error_record[1] = err.error_class;
	error_record[2] = err.error_class >> 8;
	error_record[3] = err.error_type;
	error_record[4] = err.error_type >> 8;
	error_record[5] = err.error_aux;
	error_record[6] = err.error_aux >> 8;
	error_record[7] = err.error_aux >> 16;
	error_record[8] = err.error_aux >> 24;
	os_write(work->p, error_record, 9, &err);
}

#ifndef THREAD_NONE
thread_function_decl(resolver_thread_function,
	struct resolver_request *work;
	uchar_efficient_t end;

next:
	cond_lock(&resolver_cond);
	while (list_is_empty(&resolver_queue)) {
		if (resolver_end) {
			cond_unlock(&resolver_cond);
			goto ret;
		}
		resolver_threads_idle++;
		cond_wait(&resolver_cond);
		resolver_threads_idle--;
	}
	work = get_struct(resolver_queue.prev, struct resolver_request, entry);
	list_del(&work->entry);
	end = resolver_end;
	cond_unlock(&resolver_cond);

	if (unlikely(end))
		goto close_next;

	resolver_do_lookup(work);

close_next:
	os_close(work->p);
	mem_free(work);
	goto next;
ret:;
)
#endif

static bool resolver_submit_work(struct resolver_request *work, ajla_error_t attr_unused *err)
{
#ifndef THREAD_NONE
	cond_lock(&resolver_cond);
	if (!resolver_threads_idle && resolver_threads_l < (os_getaddrinfo_is_thread_safe() ? RESOLVER_THREADS_MAX : 1)) {
		thread_t resolver_thread;
		if (unlikely(!thread_spawn(&resolver_thread, resolver_thread_function, NULL, PRIORITY_IO, err))) {
			cond_unlock(&resolver_cond);
			mem_free(work);
			return false;
		}
		array_add(thread_t, &resolver_threads, &resolver_threads_l, resolver_thread);
	}
	list_add(&resolver_queue, &work->entry);
	cond_unlock_signal(&resolver_cond);
#else
	resolver_do_lookup(work);
	os_close(work->p);
	mem_free(work);
#endif
	return true;
}

bool resolver_resolve(char *name, int port, handle_t p, ajla_error_t *err)
{
	struct resolver_request *work;

	if (unlikely(port < 0) || unlikely(port >= 65536)) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "invalid port: %d", port);
		return false;
	}

	work = struct_alloc_array_mayfail(mem_alloc_mayfail, struct resolver_request, name, strlen(name) + 1, err);
	if (unlikely(!work))
		return false;

	work->p = p;
	work->type = RESOLVER_WORK_GETADDRINFO;
	work->port = port;
	strcpy(work->name, name);

	return resolver_submit_work(work, err);
}

bool resolver_resolve_reverse(char *addr, size_t addrlen, handle_t p, ajla_error_t *err)
{
	struct resolver_request *work;

	work = struct_alloc_array_mayfail(mem_alloc_mayfail, struct resolver_request, name, addrlen, err);
	if (unlikely(!work))
		return false;

	work->p = p;
	work->type = RESOLVER_WORK_GETNAMEINFO;
	work->name_len = addrlen;
	memcpy(work->name, addr, addrlen);

	return resolver_submit_work(work, err);
}

void resolver_init(void)
{
#ifndef THREAD_NONE
	list_init(&resolver_queue);
	resolver_end = false;
	cond_init(&resolver_cond);
	array_init(thread_t, &resolver_threads, &resolver_threads_l);
	resolver_threads_idle = 0;
#endif
}

void resolver_done(void)
{
#ifndef THREAD_NONE
	size_t i;
	cond_lock(&resolver_cond);
	resolver_end = true;
	cond_unlock_broadcast(&resolver_cond);
	for (i = 0; i < resolver_threads_l; i++)
		thread_join(&resolver_threads[i]);
	mem_free(resolver_threads);
	cond_done(&resolver_cond);
#endif
}
