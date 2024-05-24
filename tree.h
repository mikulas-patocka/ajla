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

#ifndef AJLA_TREE_H
#define AJLA_TREE_H

struct tree_entry {
	struct tree_entry *children[2];
	struct tree_entry **parent;
	uchar_efficient_t color;
	uchar_efficient_t idx;
};

#define RB_BLACK	0
#define RB_RED		1

#define RB_IDX_LEFT	0
#define RB_IDX_RIGHT	1
#define RB_IDX_ROOT	2

struct tree {
	struct tree_entry *root;
};

static inline void tree_init(struct tree *root)
{
	root->root = NULL;
}

static inline bool tree_is_empty(struct tree *root)
{
	return !root->root;
}

#ifdef DEBUG_RBTREE
void tree_verify_node(struct tree_entry *);
#else
#define tree_verify_node(n)	((void)0)
#endif

struct tree_insert_position {
	size_t idx;
	struct tree_entry **link;
};

static inline struct tree_entry *tree_find_for_insert(
	struct tree *root,
	int (*compare)(const struct tree_entry *, uintptr_t),
	uintptr_t key,
	struct tree_insert_position *pos)
{
	struct tree_entry *p = root->root;
	if (pos) {
		pos->idx = RB_IDX_ROOT;
		pos->link = &root->root;
	}
	while (p) {
		int c;
		size_t cc;
		tree_verify_node(p);
		c = compare(p, key);
		if (!c)
			return p;
		cc = c < 0;
		/*__asm__("" : "=r"(cc) : "0"(cc));*/
		if (pos) {
			pos->idx = cc;
			pos->link = &p->children[cc];
		}
		p = p->children[cc];
	}
	return NULL;
}

static inline struct tree_entry *tree_find(
	struct tree *root,
	int (*compare)(const struct tree_entry *, uintptr_t),
	uintptr_t key)
{
	return tree_find_for_insert(root, compare, key, NULL);
}

static inline struct tree_entry *tree_find_next(
	struct tree *root,
	int (*compare)(const struct tree_entry *, uintptr_t),
	uintptr_t key)
{
	struct tree_entry *p = root->root;
	struct tree_entry *last_candidate = NULL;
	while (p) {
		int c;
		size_t cc;
		tree_verify_node(p);
		c = compare(p, key);
		if (c > 0)
			last_candidate = p;
		cc = c <= 0;
		p = p->children[cc];
	}
	return last_candidate;
}

static inline struct tree_entry *tree_find_best(
	struct tree *root,
	int (*compare)(const struct tree_entry *, uintptr_t),
	uintptr_t key)
{
	struct tree_entry *p = root->root;
	struct tree_entry *last_candidate = NULL;
	while (p) {
		int c;
		size_t cc;
		tree_verify_node(p);
		c = compare(p, key);
		if (c >= 0)
			last_candidate = p;
		if (!c)
			break;
		cc = c < 0;
		p = p->children[cc];
	}
	return last_candidate;
}

void attr_fastcall tree_insert_after_find_impl(struct tree_entry *, uchar_efficient_t idx, struct tree_entry **link);

static inline void tree_insert_after_find(struct tree_entry *p, const struct tree_insert_position *pos)
{
	tree_insert_after_find_impl(p, (uchar_efficient_t)pos->idx, pos->link);
}

void attr_fastcall tree_delete(struct tree_entry *);

struct tree_entry * attr_fastcall tree_first(struct tree *);
struct tree_entry * attr_fastcall tree_next(struct tree_entry *);
struct tree_entry * attr_fastcall tree_last(struct tree *);

static inline struct tree_entry *tree_any(struct tree *root)
{
	return root->root;
}

#endif
