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

#include "tree.h"

#define NEG(idx)	((idx) ^ 1)

static struct tree_entry *rb_parent(struct tree_entry *n)
{
#ifdef DEBUG_RBTREE
	if (n->idx != RB_IDX_LEFT && n->idx != RB_IDX_RIGHT)
		internal(file_line, "rb_parent: invalid index %d", n->idx);
#endif
	return get_struct(n->parent - n->idx, struct tree_entry, children[0]);
}

#ifdef DEBUG_RBTREE
static void rb_verify_node_no_color(struct tree_entry *n)
{
	if (unlikely(n->color != RB_BLACK && n->color != RB_RED))
		internal(file_line, "rb_verify_node_no_color(%p): invalid color %d", n, n->color);
	if (unlikely(!n->parent))
		internal(file_line, "rb_verify_node_no_color(%p): no parent link", n);
	if (unlikely(*n->parent != n))
		internal(file_line, "rb_verify_node_no_color(%p): bad parent link: %p, %p", n, *n->parent, n);
	if (unlikely(n->idx != RB_IDX_ROOT)) {
		struct tree_entry *p = rb_parent(n);
		if (unlikely(p->idx != RB_IDX_LEFT && p->idx != RB_IDX_RIGHT && p->idx != RB_IDX_ROOT))
			internal(file_line, "rb_verify_node_no_color(%p): invalid parent: %p, %d", n, p, p->idx);
	}
	if (n->children[0] && (n->children[0]->parent != &n->children[0] || n->children[0]->idx != RB_IDX_LEFT))
		internal(file_line, "rb_verify_node_no_color(%p): bad left child: %p, %p, %d", n, n->children[0]->parent, &n->children[0], n->children[0]->idx);
	if (n->children[1] && (n->children[1]->parent != &n->children[1] || n->children[1]->idx != RB_IDX_RIGHT))
		internal(file_line, "rb_verify_node_no_color(%p): bad right child: %p, %p, %d", n, n->children[1]->parent, &n->children[1], n->children[1]->idx);
}
void tree_verify_node(struct tree_entry *n)
{
	rb_verify_node_no_color(n);
	if (n->idx == RB_IDX_ROOT && n->color == RB_RED)
		internal(file_line, "tree_verify_node(%p): root is red", n);
	if (n->color == RB_RED) {
		if ((n->children[0] && n->children[0]->color != RB_BLACK) ||
		    (n->children[1] && n->children[1]->color != RB_BLACK))
			internal(file_line, "tree_verify_node(%p): red node has a red child", n);
		if (n->idx != RB_IDX_ROOT) {
			struct tree_entry *p = rb_parent(n);
			if (p->color != RB_BLACK)
				internal(file_line, "tree_verify_node(%p): red parent %p has a red child", n, p);
		}
	}
}
#else
#define rb_verify_node_no_color(n)	((void)0)
#endif

static attr_noinline void rb_rotate(struct tree_entry *p, struct tree_entry *n)
{
	uchar_efficient_t neg_n_idx;
	struct tree_entry *ch;

	rb_verify_node_no_color(p);
	rb_verify_node_no_color(n);

	*p->parent = n;
	n->parent = p->parent;
	neg_n_idx = NEG(n->idx);
	ch = p->children[n->idx] = n->children[neg_n_idx];
	if (ch) {
		ch->parent = &p->children[n->idx];
		ch->idx = n->idx;
	}
	p->parent = &n->children[neg_n_idx];
	n->children[neg_n_idx] = p;
	n->idx = p->idx;
	p->idx = neg_n_idx;

	rb_verify_node_no_color(p);
	rb_verify_node_no_color(n);
}

void attr_fastcall tree_insert_after_find_impl(struct tree_entry *n, uchar_efficient_t idx, struct tree_entry **link)
{
	*link = n;
	n->color = RB_RED;
	n->idx = idx;
	n->parent = link;
	n->children[0] = n->children[1] = NULL;

	rb_verify_node_no_color(n);

	while (1) {
		struct tree_entry *p, *gp, *un;
		if (n->idx == RB_IDX_ROOT) {
			n->color = RB_BLACK;
			break;
		}
		p = rb_parent(n);
		rb_verify_node_no_color(p);
		if (p->color == RB_BLACK)
			break;
		gp = rb_parent(p);
		rb_verify_node_no_color(gp);
		un = gp->children[NEG(p->idx)];
		if (un && un->color == RB_RED) {
			rb_verify_node_no_color(un);
			gp->color = RB_RED;
			p->color = RB_BLACK;
			un->color = RB_BLACK;
			n = gp;
		} else {
			if (n->idx != p->idx) {
				struct tree_entry *tmp;
				rb_rotate(p, n);
				tmp = p;
				p = n;
				n = tmp;
			}
			rb_rotate(gp, p);
			p->color = RB_BLACK;
			gp->color = RB_RED;
			break;
		}
	}
}

static void rb_fix_ptrs(struct tree_entry *n)
{
	*n->parent = n;
	if (n->children[0]) n->children[0]->parent = &n->children[0];
	if (n->children[1]) n->children[1]->parent = &n->children[1];
}

void attr_fastcall tree_delete(struct tree_entry *n)
{
	uchar_efficient_t idx;
	struct tree_entry *ch, *p;

	tree_verify_node(n);

	if (!n->children[0]) {
		idx = RB_IDX_RIGHT;
	} else if (!n->children[1]) {
		idx = RB_IDX_LEFT;
	} else {
		struct tree_entry *c, tmp;
		c = n->children[1];
		tree_verify_node(c);
		while (c->children[0]) {
			c = c->children[0];
			tree_verify_node(c);
		}
		tmp = *c;
		if (tmp.parent == &n->children[1]) tmp.parent = &c->children[1];
		*c = *n;
		if (c->children[1] == c) c->children[1] = n;
		*n = tmp;
		rb_fix_ptrs(c);
		rb_fix_ptrs(n);
		tree_verify_node(c);
		tree_verify_node(n);
		idx = RB_IDX_RIGHT;
	}
	ch = n->children[idx];
	*n->parent = ch;
	if (ch) {
		ch->parent = n->parent;
		ch->idx = n->idx;
	}
	if (n->color == RB_RED)
		return;
again:
	idx = n->idx;
	if (idx == RB_IDX_ROOT)
		goto set_ch_black;
	p = rb_parent(n);
	rb_verify_node_no_color(p);
	if (!ch || ch->color == RB_BLACK) {
		struct tree_entry *s, *z;
again2:
		s = p->children[NEG(idx)];
		rb_verify_node_no_color(s);
		if (s->color == RB_BLACK) {
			z = s->children[NEG(idx)];
			if (z && z->color == RB_RED) {
				rb_verify_node_no_color(z);
				z->color = RB_BLACK;
rotate_p_s_return:
				s->color = p->color;
				p->color = RB_BLACK;
				rb_rotate(p, s);
				return;
			}
			z = s->children[idx];
			if (z && z->color == RB_RED) {
				rb_verify_node_no_color(z);
				z->color = RB_BLACK;
				rb_rotate(s, z);
				s = z;
				goto rotate_p_s_return;
			}
			s->color = RB_RED;

			ch = n = p;
			goto again;
		} else {
			rb_rotate(p, s);
			p->color = RB_RED;
			s->color = RB_BLACK;
			goto again2;
		}
	}
set_ch_black:
	if (ch)
		ch->color = RB_BLACK;
}

struct tree_entry * attr_fastcall tree_first(struct tree *root)
{
	struct tree_entry *n = root->root;
	if (unlikely(!n))
		return NULL;
	tree_verify_node(n);
	while (n->children[0]) {
		n = n->children[0];
		tree_verify_node(n);
	}
	return n;
}

struct tree_entry * attr_fastcall tree_next(struct tree_entry *e)
{
	tree_verify_node(e);
	if (e->children[1]) {
		e = e->children[1];
		tree_verify_node(e);
		while (e->children[0]) {
			e = e->children[0];
			tree_verify_node(e);
		}
		return e;
	}
	while (e->idx == RB_IDX_RIGHT) {
		e = rb_parent(e);
		tree_verify_node(e);
	}
	if (e->idx == RB_IDX_LEFT) {
		e = rb_parent(e);
		tree_verify_node(e);
		return e;
	}
	return NULL;
}

struct tree_entry * attr_fastcall tree_last(struct tree *root)
{
	struct tree_entry *n = root->root;
	if (unlikely(!n))
		return NULL;
	tree_verify_node(n);
	while (n->children[1]) {
		n = n->children[1];
		tree_verify_node(n);
	}
	return n;
}
