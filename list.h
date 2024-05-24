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

#ifndef AJLA_LIST_H
#define AJLA_LIST_H

struct list {
	struct list *next, *prev;
};

#ifdef DEBUG_LIST
static inline void list_verify(const struct list *head, const char *function, const char *position)
{
	if (unlikely(head->next->prev != head) ||
	    unlikely(head->prev->next != head))
		internal(position, "list corrupted in %s: head %p, head->next %p, head->next->prev %p, head->prev %p, head->prev->next %p", function, (const void *)head, (const void *)head->next, (const void *)head->next->prev, (const void *)head->prev, (const void *)head->prev->next);
}
#else
#define list_verify(head, position, function)	((void)0)
#endif

#define list_is_empty(entry)		list_is_empty_(entry, file_line)

#define list_for_each(var, list)					\
	for (list_verify(list, "list_for_each 1", file_line),		\
	     (var) = (list)->next,					\
	     list_verify(var, "list_for_each 2", file_line);		\
	     (var) != (list);						\
	     (var) = (var)->next,					\
	     list_verify(var, "list_for_each 3", file_line))

#define list_for_each_back(var, list)					\
	for (list_verify(list, "list_for_each 1", file_line),		\
	     (var) = (list)->prev,					\
	     list_verify(var, "list_for_each_back 3", file_line);	\
	     (var) != (list);						\
	     (var) = (var)->prev,					\
	     list_verify(var, "list_for_each_back 3", file_line))

static inline void list_init(struct list *head)
{
	head->next = head->prev = head;
}

static inline void list_init_add(struct list *head, struct list *entry)
{
	head->next = head->prev = entry;
	entry->next = entry->prev = head;
}

static inline void list_add_(struct list *head, struct list *entry, const char attr_unused *position)
{
#ifdef DEBUG_LIST
	struct list *l;
	unsigned i = 0;
	list_for_each(l, head) {
		if (unlikely(l == entry))
			internal(position, "list_add: adding entry %p twice", entry);
		if (++i >= 100)
			break;
	}
#endif
	/*list_verify(head, "list_add 1", position);
	list_verify(head->next, "list_add 2", position);*/
	entry->prev = head;
	entry->next = head->next;
	head->next->prev = entry;
	head->next = entry;
}

#define list_add(head, entry)	list_add_(head, entry, file_line)

static inline void list_del_(struct list *entry, const char attr_unused *position)
{
	list_verify(entry, "list_del", position);
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
#ifdef DEBUG_LIST
	entry->next = cast_cpp(struct list *, BAD_POINTER_1);
	entry->prev = cast_cpp(struct list *, BAD_POINTER_2);
#endif
}

#define list_del(entry)		list_del_(entry, file_line)

static inline bool list_is_empty_(struct list *head, const char attr_unused *position)
{
	list_verify(head, "list_is_empty", position);
	return head->next == head;
}

static inline void list_take_(struct list *dst, struct list *src, const char attr_unused *position)
{
	if (list_is_empty_(src, position)) {
		list_init(dst);
	} else {
		*dst = *src;
		dst->next->prev = dst;
		dst->prev->next = dst;
		list_init(src);
	}
}

#define list_take(dst, src)	list_take_(dst, src, file_line)

#if 0
static inline void list_join_(struct list *dst, struct list *src, const char attr_unused *position)
{
	list_verify(dst, "list_join dst", position);
	if (!list_is_empty_(src, position)) {
		src->next->prev = dst;
		src->prev->next = dst->next;
		dst->next->prev = src->prev;
		dst->next = src->next;
	}
}
#define list_join(dst, src)	list_join_(dst, src, file_line)
#endif

#endif
