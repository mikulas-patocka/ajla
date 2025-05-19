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

#ifndef FILE_OMIT

#include "mem_al.h"
#include "tree.h"
#include "thread.h"
#include "task.h"
#include "array.h"
#include "arrayu.h"
#include "codegen.h"
#include "save.h"

#include "data.h"


#ifdef DEBUG_TRACE
atomic_type uchar_efficient_t trace_enabled = 0;
#endif

#ifdef HAVE_CODEGEN_TRAPS
static rwmutex_t traps_lock;
static struct tree traps_tree;
#endif


static refcount_t n_dereferenced;


/*********
 * FRAME *
 *********/

static struct stack_bottom *stack_alloc_space(size_t needed_size, bool leaf, ajla_error_t *mayfail)
{
	const size_t additional_space = SIZEOF_STACK_BOTTOM + SIZEOF_FRAME_STRUCT;
	size_t test_size, extra_space;
	size_t slots;
	ajla_error_t sink;
	struct stack_bottom *stack;
	struct frame_struct *stack_end;

	if (unlikely(needed_size + additional_space < additional_space) ||
	    unlikely(needed_size / slot_size >= sign_bit(stack_size_t))) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "stack allocation size overflow");
		return NULL;
	}
	if (leaf)
		goto exact;
	test_size = STACK_INITIAL_SIZE;
	if (unlikely(test_size < additional_space))
		goto exact;
	while (test_size - additional_space < needed_size) {
		size_t new_test_size = test_size * 2;
		if (unlikely(new_test_size <= test_size))
			goto exact;
		test_size = new_test_size;
	}
	extra_space = round_down(test_size - additional_space - needed_size, frame_align);
	slots = (extra_space + needed_size) / slot_size;
	if (unlikely(slots >= sign_bit(stack_size_t)))
		goto exact;
	stack = mem_align_mayfail(struct stack_bottom *, extra_space + needed_size + additional_space, frame_align, &sink);
	if (unlikely(!stack)) {
exact:
		extra_space = 0;
		slots = (extra_space + needed_size) / slot_size;
		stack = mem_align_mayfail(struct stack_bottom *, needed_size + additional_space, frame_align, mayfail);
		if (unlikely(!stack))
			return NULL;
	}
	stack_end = cast_ptr(struct frame_struct *, cast_ptr(char *, stack) + SIZEOF_STACK_BOTTOM + extra_space + needed_size);
	stack_end->function = NULL;
	stack_end->available_slots = stack->useable_slots = (stack_size_t)slots;
	return stack;
}

frame_s * attr_fastcall stack_alloc(struct execution_control *ex, struct data *function, ajla_error_t *mayfail)
{
	struct stack_bottom *stack;
	char *stack_start, *stack_end;
	frame_s *frame;

	stack = stack_alloc_space(function_frame_size(function), da(function,function)->leaf, mayfail);
	if (unlikely(!stack))
		return NULL;

	if ((stack->ex = ex))
		ex->stack = stack;
	stack_start = cast_ptr(char *, stack) + SIZEOF_STACK_BOTTOM;
	stack_end = stack_start + stack->useable_slots * slot_size;
	frame = ptr_frame(cast_ptr(struct frame_struct *, stack_end - function_frame_size(function)));
	get_frame(frame)->available_slots = stack->useable_slots - da(function,function)->frame_slots;
	get_frame(frame)->function = function;
	return frame;
}

frame_s * attr_fastcall stack_expand(frame_s *fp, struct data *function, ajla_error_t *mayfail)
{
	struct stack_bottom *old_stack, *new_stack;
	size_t new_size, old_stack_size;
	char *old_stack_end, *new_stack_end;
	frame_s *new_fp;

	old_stack = frame_stack_bottom(fp);
	new_size = (old_stack->useable_slots - get_frame(fp)->available_slots) * slot_size + function_frame_size(function);
	if (unlikely(new_size < function_frame_size(function))) {
		fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "stack allocation size overflow");
		return NULL;
	}

	new_stack = stack_alloc_space(new_size, false, mayfail);
	if (unlikely(!new_stack))
		return NULL;

	old_stack_end = cast_ptr(char *, old_stack) + SIZEOF_STACK_BOTTOM + old_stack->useable_slots * slot_size;
	old_stack_size = old_stack_end - cast_ptr(char *, get_frame(fp));
	new_stack_end = cast_ptr(char *, new_stack) + SIZEOF_STACK_BOTTOM + new_stack->useable_slots * slot_size;
	(void)memcpy(new_stack_end - old_stack_size, old_stack_end - old_stack_size, old_stack_size);
	(new_stack->ex = old_stack->ex)->stack = new_stack;
	stack_free(old_stack);

	new_fp = ptr_frame(cast_ptr(const struct frame_struct *, new_stack_end - old_stack_size - function_frame_size(function)));
	get_frame(new_fp)->function = function;
	fp = new_fp;
	do {
		get_frame(fp)->available_slots = (stack_size_t)((size_t)(cast_ptr(char *, get_frame(fp)) - cast_ptr(char *, new_stack) - SIZEOF_STACK_BOTTOM) / slot_size);
		fp = frame_up(fp);
	} while (!frame_is_top(fp));

	return new_fp;
}

frame_s * attr_fastcall stack_split(frame_s *from_fp, frame_s *to_fp, frame_s **high, ajla_error_t *mayfail)
{
	struct stack_bottom *new_stack;
	char *new_stack_end;
	frame_s *fp, *new_fp;
	size_t new_stack_size = cast_ptr(char *, to_fp) - cast_ptr(char *, from_fp);

	new_stack = stack_alloc_space(new_stack_size, false, mayfail);
	if (unlikely(!new_stack))
		return NULL;

	new_stack_end = cast_ptr(char *, new_stack) + SIZEOF_STACK_BOTTOM + new_stack->useable_slots * slot_size;
	new_fp = ptr_frame(memcpy(new_stack_end - new_stack_size, get_frame(from_fp), new_stack_size));

	fp = new_fp;
	do {
		get_frame(fp)->available_slots = (stack_size_t)((size_t)(cast_ptr(char *, get_frame(fp)) - cast_ptr(char *, new_stack) - SIZEOF_STACK_BOTTOM) / slot_size);
		*high = fp;
		fp = frame_up(fp);
	} while (!frame_is_top(fp));

	return new_fp;
}

static void frame_cleanup(frame_s *fp)
{
	frame_t l;
	const struct data *function = get_frame(fp)->function;

	for (l = MIN_USEABLE_SLOT; l < function_n_variables(function); l++) {
		if (!frame_test_flag(fp, l))
			continue;
		pointer_dereference(*frame_pointer(fp, l));
	}
}


/***************
 * STACK TRACE *
 ***************/

void stack_trace_init(struct stack_trace *st)
{
	st->trace = NULL;
	st->trace_n = 0;
}

void stack_trace_free(struct stack_trace *st)
{
	if (st->trace)
		mem_free(st->trace);
}

bool stack_trace_get_location(struct data *function, ip_t ip_rel, struct stack_trace_entry *result)
{
	size_t idx;
	struct line_position *lp, *my_lp;
	size_t n_lp;
	lp = da(function,function)->lp;
	n_lp = da(function,function)->lp_size;
	if (!n_lp)
		return false;
	binary_search(code_t, da(function,function)->lp_size, idx, false, idx + 1 >= n_lp ? false : lp[idx + 1].ip < ip_rel, break);
	my_lp = &lp[idx];
	result->module_designator = da(function,function)->module_designator;
	result->function_name = da(function,function)->function_name;
	result->line = my_lp->line;
	return true;
}

void stack_trace_capture(struct stack_trace *st, frame_s *fp, const code_t *ip, unsigned max_depth)
{
	struct data *function;
	ip_t ip_rel, previous_ip;
	struct stack_trace_entry ste;
	ajla_error_t sink;
	if (!fp)
		return;
	if (!array_init_mayfail(struct stack_trace_entry, &st->trace, &st->trace_n, &sink))
		return;

go_up:
	function = get_frame(fp)->function;
	ip_rel = ip - da(function,function)->code;
	if (unlikely(!stack_trace_get_location(function, ip_rel, &ste)))
		goto skip_this_frame;
	if (unlikely(!array_add_mayfail(struct stack_trace_entry, &st->trace, &st->trace_n, ste, NULL, &sink))) {
		return;
	}

	if (!--max_depth)
		goto ret;

skip_this_frame:
	previous_ip = get_frame(fp)->previous_ip;
	fp = frame_up(fp);
	if (!frame_is_top(fp)) {
		ip = da(get_frame(fp)->function,function)->code + previous_ip;
		goto go_up;
	}

ret:
	array_finish(struct stack_trace_entry, &st->trace, &st->trace_n);
}

char * attr_cold stack_trace_string(struct stack_trace *st, ajla_error_t *err)
{
	char *msg;
	size_t msg_l;
	size_t t;
	if (unlikely(!array_init_mayfail(char, &msg, &msg_l, err)))
		return NULL;

	for (t = 0; t < st->trace_n; t++) {
		size_t xl;
		char buffer[11];
		char *b;
		struct stack_trace_entry *ste = &st->trace[t];
		if (unlikely(!array_add_mayfail(char, &msg, &msg_l, ' ', NULL, err)))
			return NULL;
		if (unlikely(!array_add_multiple_mayfail(char, &msg, &msg_l, ste->module_designator->path, ste->module_designator->path_len, NULL, err)))
			return NULL;
		if (unlikely(!array_add_multiple_mayfail(char, &msg, &msg_l, " : ", 3, NULL, err)))
			return NULL;
		xl = strlen(ste->function_name);
		if (unlikely(!array_add_multiple_mayfail(char, &msg, &msg_l, ste->function_name, xl, NULL, err)))
			return NULL;
		if (unlikely(!array_add_mayfail(char, &msg, &msg_l, ':', NULL, err)))
			return NULL;
		b = buffer;
		str_add_unsigned(&b, NULL, ste->line & 0xffffffffU, 10);
		xl = strlen(buffer);
		if (unlikely(!array_add_multiple_mayfail(char, &msg, &msg_l, buffer, xl, NULL, err)))
			return NULL;
		if (unlikely(!array_add_mayfail(char, &msg, &msg_l, '\n', NULL, err)))
			return NULL;
	}
	if (unlikely(!array_add_mayfail(char, &msg, &msg_l, 0, NULL, err)))
		return NULL;
	return msg;
}


void attr_cold stack_trace_print(struct stack_trace *st)
{
	ajla_error_t sink;
	char *m = stack_trace_string(st, &sink);
	if (unlikely(!m))
		return;
	if (*m) {
		stderr_msg("stack trace:");
		m[strlen(m) - 1] = 0;
		stderr_msg("%s", m);
	}
	mem_free(m);
}


/*********************
 * OBJECT ALLOCATION *
 *********************/

/* !!! TODO: make it return pointer_t */
struct data * attr_fastcall data_alloc_flat_mayfail(type_tag_t type, const unsigned char *flat, size_t size, ajla_error_t *mayfail argument_position)
{
	struct data *d = data_align(flat, data_flat_offset + size, scalar_align, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	da(d,flat)->data_type = type;
	memcpy_fast(da_flat(d), flat, size);
	return d;
}

struct data * attr_fastcall data_alloc_longint_mayfail(unsigned long bits, ajla_error_t *mayfail argument_position)
{
	struct data *d = data_alloc(longint, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	if (unlikely(!mpint_alloc_mayfail(&da(d,longint)->mp, bits, mayfail))) {
		data_free_r1(d);
		return NULL;
	}
	return d;
}

struct data * attr_fastcall data_alloc_record_mayfail(const struct record_definition *def, ajla_error_t *mayfail argument_position)
{
	struct data *d = data_align(record, data_record_offset + def->n_slots * slot_size, def->alignment, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	da(d,record)->definition = &def->type;
	return d;
}

struct data * attr_fastcall data_alloc_option_mayfail(ajla_error_t *mayfail argument_position)
{
	struct data *d = data_alloc(option, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	return d;
}

struct data * attr_fastcall data_alloc_array_flat_mayfail(const struct type *type, int_default_t n_allocated, int_default_t n_used, bool clear, ajla_error_t *mayfail argument_position)
{
	struct data *d;
	size_t size;
	ajla_assert(TYPE_IS_FLAT(type), (caller_file_line, "data_alloc_array_flat_mayfail: type is not flat, tag %u", type->tag));
	ajla_assert((n_allocated | n_used) >= 0, (caller_file_line, "data_alloc_array_flat_mayfail: negative size %"PRIdMAX", %"PRIdMAX"", (intmax_t)n_allocated, (intmax_t)n_used));
#if defined(HAVE_BUILTIN_ADD_SUB_OVERFLOW) && defined(HAVE_BUILTIN_MUL_OVERFLOW) && !defined(UNUSUAL)
	if (unlikely(__builtin_mul_overflow((uint_default_t)n_allocated, type->size, &size)))
		goto ovf;
	if (unlikely(__builtin_add_overflow(size, data_array_offset, &size)))
		goto ovf;
#else
	size = (uint_default_t)n_allocated * (size_t)type->size;
	if (unlikely((size_t)type->size + uzero >= 0x100) || unlikely((uint_default_t)n_allocated + (size_t)uzero >= sign_bit(size_t) / 0x100)) {
		if (unlikely(size / type->size != (uint_default_t)n_allocated))
			goto ovf;
		if ((size_t)(size + data_array_offset) < size)
			goto ovf;
	}
	size += data_array_offset;
#endif
	if (likely(!clear))
		d = data_align(array_flat, size, scalar_align, mayfail);
	else
		d = data_calign(array_flat, size, scalar_align, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	da(d,array_flat)->type = type;
	da(d,array_flat)->n_allocated_entries = n_allocated;
	da(d,array_flat)->n_used_entries = n_used;
	return d;

ovf:
	fatal_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW), mayfail, "flat array allocation size overflow");
	return NULL;
}

struct data * attr_fastcall data_alloc_array_slice_mayfail(struct data *base, unsigned char *data, int_default_t start, int_default_t len, ajla_error_t *mayfail argument_position)
{
	const struct type *t;

	struct data *d;
	d = data_alloc(array_slice, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);

	data_reference(base);

	t = da(base,array_flat)->type;
	da(d,array_slice)->type = t;
	da(d,array_slice)->reference = pointer_data(base);
	da(d,array_slice)->flat_data_minus_data_array_offset = data - data_array_offset + start * t->size;
	da(d,array_slice)->n_entries = len;

	return d;
}

struct data * attr_fastcall data_alloc_array_pointers_mayfail(int_default_t n_allocated, int_default_t n_used, ajla_error_t *mayfail argument_position)
{
	struct data *d;
	d = data_alloc_flexible(array_pointers, pointer_array, n_allocated, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	da(d,array_pointers)->pointer = da(d,array_pointers)->pointer_array;
	da(d,array_pointers)->n_allocated_entries = n_allocated;
	da(d,array_pointers)->n_used_entries = n_used;
	return d;
}

struct data * attr_fastcall data_alloc_array_same_mayfail(array_index_t n_entries, ajla_error_t *mayfail argument_position)
{
	struct data *d = data_alloc(array_same, mayfail);
	if (unlikely(!d)) {
		index_free(&n_entries);
		return NULL;
	}
	mem_set_position(data_untag(d) pass_position);
	da(d,array_same)->n_entries = n_entries;
	return d;
}

struct data * attr_fastcall data_alloc_array_incomplete(struct data *first, pointer_t next, ajla_error_t *mayfail argument_position)
{
	struct data *d;
	ajla_assert(!array_is_empty(first), (caller_file_line, "data_alloc_array_incomplete: the first array is empty"));
	d = data_alloc(array_incomplete, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	da(d,array_incomplete)->first = pointer_data(first);
	da(d,array_incomplete)->next = next;
	return d;
}

struct data * attr_fastcall data_alloc_function_reference_mayfail(arg_t n_curried_arguments, ajla_error_t *mayfail argument_position)
{
	struct data *d;
	arg_t alloc_size = n_curried_arguments;

	d = data_alloc_flexible(function_reference, arguments, alloc_size, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	da(d,function_reference)->n_curried_arguments = n_curried_arguments;

	return d;
}

void attr_fastcall data_fill_function_reference(struct data *function_reference, arg_t a, pointer_t ptr)
{
	if (unlikely(!function_reference)) {
		pointer_dereference(ptr);
		return;
	}

	ajla_assert(a < da(function_reference,function_reference)->n_curried_arguments, (file_line, "data_fill_function_reference: invalid argument %"PRIuMAX" (%"PRIuMAX" arguments)", (uintmax_t)a, (uintmax_t)da(function_reference,function_reference)->n_curried_arguments));

	da(function_reference,function_reference)->arguments[a].tag = TYPE_TAG_unknown;
	da(function_reference,function_reference)->arguments[a].u.ptr = ptr;
}

void attr_fastcall data_fill_function_reference_flat(struct data *function_reference, arg_t a, const struct type *type, const unsigned char *data)
{
	if (unlikely(!function_reference))
		return;

	if (type->size <= slot_size && TYPE_TAG_IS_BUILTIN(type->tag)) {
		da(function_reference,function_reference)->arguments[a].tag = type->tag;
		memcpy_fast(da(function_reference,function_reference)->arguments[a].u.slot, data, type->size);
	} else {
		pointer_t ptr = flat_to_data(type, data);
		data_fill_function_reference(function_reference, a, ptr);
	}
}

struct data * attr_fastcall data_alloc_resource_mayfail(size_t size, void (*close)(struct data *), ajla_error_t *mayfail argument_position)
{
	struct data *d = data_calign(resource, data_resource_offset + size, scalar_align, mayfail);
	if (unlikely(!d))
		return NULL;
	mem_set_position(data_untag(d) pass_position);
	da(d,resource)->close = close;
	return d;
}


static inline void thunk_init_refcount_tag(struct thunk *t, tag_t tag)
{
#ifndef REFCOUNT_TAG
	t->tag = tag;
	refcount_init(&t->refcount_);
#else
	refcount_init_tag(&t->refcount_, tag);
#endif
}

static attr_always_inline struct thunk *thunk_alloc_exception_mayfail(ajla_error_t err, ajla_error_t *mayfail argument_position)
{
	struct thunk *thunk;
#if 0
	if (mayfail)
		return NULL;
#endif
	/*debug("thunk_alloc_exception(%s) at %s", error_decode(err), position_arg);*/
	thunk = mem_alloc_compressed_mayfail(struct thunk *, partial_sizeof(struct thunk, u.exception), mayfail);
	if (unlikely(!thunk))
		return NULL;
	mem_set_position(thunk pass_position);
	thunk = thunk_pointer_tag(thunk);
	thunk_init_refcount_tag(thunk, THUNK_TAG_EXCEPTION);
	thunk->u.exception.err = err;
	thunk->u.exception.msg = NULL;
	stack_trace_init(&thunk->u.exception.tr);
	return thunk;
}

static pointer_t out_of_memory_thunk;
pointer_t *out_of_memory_ptr = &out_of_memory_thunk;

struct thunk * attr_fastcall thunk_alloc_exception_error(ajla_error_t err, char *msg, frame_s *fp, const code_t *ip argument_position)
{
	ajla_error_t sink;
	struct thunk *thunk;
	/*debug("thunk_alloc_exception_error: %d, %d @ %p", err.error_type, err.error_code, __builtin_return_address(0));*/
	thunk = thunk_alloc_exception_mayfail(err, &sink pass_position);
	if (unlikely(!thunk)) {
		pointer_reference_owned(out_of_memory_thunk);
		return pointer_get_thunk(out_of_memory_thunk);
	}
	if (msg)
		thunk->u.exception.msg = str_dup(msg, -1, &sink);
	if (fp) {
		stack_trace_capture(&thunk->u.exception.tr, fp, ip, -1);
		/*debug("err: %d, %d, %d", err.error_class, err.error_type, err.error_aux);
		stack_trace_print(&thunk->u.exception.tr);*/
	}
	return thunk;
}

pointer_t attr_fastcall pointer_error(ajla_error_t err, frame_s *fp, const code_t *ip argument_position)
{
	struct thunk *thunk = thunk_alloc_exception_error(err, NULL, fp, ip pass_position);
	return pointer_thunk(thunk);
}

char * attr_cold thunk_exception_string(struct thunk *thunk, ajla_error_t *err)
{
	const char *m;
	char *msg;
	size_t msg_l, ml;
	ajla_assert_lo(thunk_tag(thunk) == THUNK_TAG_EXCEPTION, (file_line, "thunk_exception_string: invalid thunk tag %u", thunk_tag(thunk)));
	if (unlikely(!array_init_mayfail(char, &msg, &msg_l, err)))
		return NULL;
	m = error_decode(thunk->u.exception.err);
	ml = strlen(m);
	if (unlikely(!array_add_multiple_mayfail(char, &msg, &msg_l, m, ml, NULL, err)))
		return NULL;
	if (thunk->u.exception.msg && *thunk->u.exception.msg) {
		size_t xl;
		if (unlikely(!array_add_multiple_mayfail(char, &msg, &msg_l, " (", 2, NULL, err)))
			return NULL;
		xl = strlen(thunk->u.exception.msg);
		if (unlikely(!array_add_multiple_mayfail(char, &msg, &msg_l, thunk->u.exception.msg, xl, NULL, err)))
			return NULL;
		if (unlikely(!array_add_mayfail(char, &msg, &msg_l, ')', NULL, err)))
			return NULL;
	}
	if (unlikely(!array_add_mayfail(char, &msg, &msg_l, 0, NULL, err)))
		return NULL;
	return msg;
}

char * attr_cold thunk_exception_payload(struct thunk *thunk, ajla_error_t *err)
{
	const char *m;
	ajla_assert_lo(thunk_tag(thunk) == THUNK_TAG_EXCEPTION, (file_line, "thunk_exception_payload: invalid thunk tag %u", thunk_tag(thunk)));
	m = thunk->u.exception.msg;
	if (!m)
		m = "";
	return str_dup(m, -1, err);
}

void attr_cold thunk_exception_print(struct thunk *thunk)
{
	char *m;
#if defined(DEBUG_ERROR) && defined(DEBUG_TRACK_FILE_LINE)
	stderr_msg("error at %s", thunk->u.exception.err.position);
#endif
	m = thunk_exception_string(thunk, NULL);
	stderr_msg("exception: %s", m);
	mem_free(m);
	stack_trace_print(&thunk->u.exception.tr);
}

static struct thunk * attr_fastcall thunk_alloc_struct(tag_t tag, arg_t n_return_values, ajla_error_t *mayfail)
{
	size_t s;
	struct thunk *t;

	/* not needed because of ARG_LIMIT
	if (!struct_check_overflow(struct thunk, u.function_call.results, n_return_values, mayfail))
		return NULL;
	*/

	s = partial_sizeof_array(struct thunk, u.function_call.results, n_return_values);

	t = mem_alloc_compressed_mayfail(struct thunk *, s, mayfail);
	if (unlikely(!t))
		return NULL;

	t = thunk_pointer_tag(t);

	thunk_init_refcount_tag(t, tag);

	return t;
}

static bool attr_fastcall thunk_alloc_result(struct thunk *t, arg_t n_return_values, struct thunk *result[], ajla_error_t *mayfail)
{
	arg_t ia;

	if (n_return_values == 1) {
		*result = t;
	} else for (ia = 0; ia < n_return_values; ia++) {
		struct thunk *tm;
		if (ia)
			thunk_reference_nonatomic(t);
		t->u.function_call.results[ia].wanted = true;
		tm = thunk_alloc_struct(THUNK_TAG_MULTI_RET_REFERENCE, 1, mayfail);
		if (unlikely(!tm)) {
			while (ia) {
				ia--;
				thunk_free(result[ia]);
			}
			thunk_free(t);
			return false;
		}
		tm->u.multi_ret_reference.thunk = t;
		tm->u.multi_ret_reference.idx = ia;
		result[ia] = tm;
	}
	return true;
}

bool attr_fastcall thunk_alloc_function_call(pointer_t function_reference, arg_t n_return_values, struct thunk *result[], ajla_error_t *mayfail)
{
	struct thunk *t;

	t = thunk_alloc_struct(THUNK_TAG_FUNCTION_CALL, n_return_values, mayfail);
	if (unlikely(!t))
		return false;

	t->u.function_call.u.function_reference = function_reference;

	return thunk_alloc_result(t, n_return_values, result, mayfail);
}

bool attr_fastcall thunk_alloc_blackhole(struct execution_control *ex, arg_t n_return_values, struct thunk *result[], ajla_error_t *mayfail)
{
	struct thunk *t;

	t = thunk_alloc_struct(THUNK_TAG_BLACKHOLE, n_return_values, mayfail);
	if (unlikely(!t))
		return false;

	t->u.function_call.u.execution_control = ex;
	ex->thunk = t;

	return thunk_alloc_result(t, n_return_values, result, mayfail);
}

bool are_there_dereferenced(void)
{
	return !refcount_is_one(&n_dereferenced);
}

static void execution_control_unlink(struct execution_control *ex)
{
	unsigned i;
	waiting_list_remove(ex);
	for (i = 0; i < N_EXECUTION_CONTROL_WAIT; i++) {
		struct execution_control_wait *w = &ex->wait[i];
		mutex_t *t = w->mutex_to_lock;
		if (unlikely(t != NULL)) {
			mutex_lock(t);
			list_del(&w->wait_entry);
			w->mutex_to_lock = NULL;
			mutex_unlock(t);
		}
	}
	refcount_set(&ex->wait_state, EXECUTION_CONTROL_NORMAL);
}

void execution_control_unlink_and_submit(struct execution_control *ex, bool can_allocate_memory)
{
	execution_control_unlink(ex);
	task_submit(ex, can_allocate_memory);
}

bool execution_control_acquire(struct execution_control *ex)
{
	return refcount_xchgcmp(&ex->wait_state, EXECUTION_CONTROL_FIRED, EXECUTION_CONTROL_ARMED);
}

static struct execution_control *execution_control_acquire_from_thunk(struct thunk *t)
{
	struct execution_control *ex = t->u.function_call.u.execution_control;
	ajla_assert_lo(ex->thunk == t, (file_line, "execution_control_acquire_from_thunk: pointer mismatch"));

	return execution_control_acquire(ex) ? ex : NULL;
}

static void *wake_up_wait_list_internal(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory)
{
	struct list ex_to_resume;
	void *ret = POINTER_FOLLOW_THUNK_EXIT;

	list_init(&ex_to_resume);

	while (!list_is_empty(wait_list)) {
		struct execution_control_wait *w = get_struct(wait_list->prev, struct execution_control_wait, wait_entry);
		ajla_assert_lo(w->mutex_to_lock == mutex_to_lock, (file_line, "wake_up_wait_list: mutex_to_lock pointer does not match: %p != %p", w->mutex_to_lock, mutex_to_lock));
		list_del(&w->wait_entry);
		if (likely(refcount_xchgcmp(&w->execution_control->wait_state, EXECUTION_CONTROL_FIRED, EXECUTION_CONTROL_ARMED))) {
			w->mutex_to_lock = NULL;
			list_add(&ex_to_resume, &w->wait_entry);
		} else {
			list_init(&w->wait_entry);
		}
	}
	mutex_unlock(mutex_to_lock);

	while (!list_is_empty(&ex_to_resume)) {
		struct execution_control_wait *w;
		struct execution_control *new_ex;
		w = get_struct(ex_to_resume.prev, struct execution_control_wait, wait_entry);
		list_del(&w->wait_entry);
		new_ex = w->execution_control;
		if (ret == POINTER_FOLLOW_THUNK_EXIT) {
			execution_control_unlink(new_ex);
			ret = new_ex;
		} else {
			execution_control_unlink_and_submit(new_ex, can_allocate_memory);
		}
	}

	return ret;
}

void wake_up_wait_list(struct list *wait_list, mutex_t *mutex_to_lock, bool can_allocate_memory)
{
	void *ex = wake_up_wait_list_internal(wait_list, mutex_to_lock, can_allocate_memory);
	if (ex != POINTER_FOLLOW_THUNK_EXIT)
		task_submit(ex, can_allocate_memory);
}

void *thunk_terminate(struct thunk *t, arg_t n_return_values)
{
	tag_t tag;
	arg_t i;
	struct execution_control *ex;
	void *ret;

	address_lock(t, DEPTH_THUNK);
	ex = t->u.function_call.u.execution_control;
	tag = thunk_tag(t);
	ajla_assert((
		likely(tag == THUNK_TAG_BLACKHOLE) ||
		(tag == THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED && n_return_values > 1) ||
		(tag == THUNK_TAG_BLACKHOLE_DEREFERENCED)
	    ), (file_line, "thunk_terminate: invalid thunk tag %u (n_return_values %lu)", tag, (unsigned long)n_return_values));
	if (unlikely(tag == THUNK_TAG_BLACKHOLE_DEREFERENCED)) {
		thunk_init_refcount_tag(t, THUNK_TAG_BLACKHOLE_DEREFERENCED);
		goto return_dereference_unused;
	}
	thunk_tag_set(t, tag, THUNK_TAG_RESULT);
#ifdef barrier_write_before_unlock_lock
	barrier_write_before_unlock_lock();
#endif
	if (tag == THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED) {
		thunk_reference_nonatomic(t);
return_dereference_unused:
		address_unlock(t, DEPTH_THUNK);
		i = 0;
		do {
			if (n_return_values == 1 || !t->u.function_call.results[i].wanted) {
				pointer_dereference(t->u.function_call.results[i].ptr);
				pointer_poison(&t->u.function_call.results[i].ptr);
			}
		} while (++i < n_return_values);
		address_lock(t, DEPTH_THUNK);
		thunk_assert_refcount(t);
		if (thunk_dereference_nonatomic(t)) {
			if (unlikely(tag == THUNK_TAG_BLACKHOLE_DEREFERENCED))
				refcount_add(&n_dereferenced, -1);
			thunk_free(t);
		}
	}

	ret = wake_up_wait_list_internal(&ex->wait_list, address_get_mutex(t, DEPTH_THUNK), true);

	execution_control_free(ex);

	return ret;
}

static void thunk_terminate_with_value(struct thunk *t, arg_t n_return_values, pointer_t val)
{
	arg_t i;
	void *ex;
	for (i = 0; i < n_return_values; i++) {
		if (i)
			pointer_reference_owned(val);
		t->u.function_call.results[i].ptr = val;
	}
	ex = thunk_terminate(t, n_return_values);
	if (ex != POINTER_FOLLOW_THUNK_EXIT)
		task_submit(ex, true);
}


/*********************
 * EXECUTION CONTROL *
 *********************/

struct execution_control *execution_control_alloc(ajla_error_t *mayfail)
{
	unsigned i;
	struct execution_control *ex = mem_alloc_mayfail(struct execution_control *, sizeof(struct execution_control), mayfail);
	if (unlikely(!ex))
		return NULL;

	ex->stack = NULL;
	ex->callback = NULL;

	list_init(&ex->wait_list);
	refcount_init_val(&ex->wait_state, EXECUTION_CONTROL_NORMAL);
	for (i = 0; i < N_EXECUTION_CONTROL_WAIT; i++) {
		struct execution_control_wait *w = &ex->wait[i];
		w->execution_control = ex;
		w->mutex_to_lock = NULL;
	}

	ex->atomic = 0;
	ex->atomic_interrupted = false;

	ex->numa_node = task_ex_control_started();

	return ex;
}

void execution_control_free(struct execution_control *ex)
{
	if (ex->stack)
		stack_free(ex->stack);

	task_ex_control_exited(ex->numa_node);

	mem_free(ex);
}

void execution_control_terminate(struct execution_control *ex, pointer_t ptr)
{
	arg_t n_return_values;
	frame_s *fp;

	if (ex->callback)
		ex->callback(ex->callback_cookie, ptr);

	fp = ex->current_frame;
	do {
		n_return_values = da(get_frame(fp)->function,function)->n_return_values;

		frame_cleanup(fp);

		fp = frame_up(fp);
	} while (!frame_is_top(fp));

	ajla_assert_lo(frame_stack_bottom(fp)->ex == ex, (file_line, "execution_control_terminate: execution control pointer mismatch: %p != %p", frame_stack_bottom(fp)->ex, ex));

	if (ex->thunk) {
		struct thunk *err = thunk_alloc_exception_error(error_ajla(EC_ASYNC, AJLA_ERROR_NOT_SUPPORTED), NULL, NULL, NULL pass_file_line);
		thunk_terminate_with_value(ex->thunk, n_return_values, pointer_thunk(err));
	} else {
		execution_control_free(ex);
	}
}


/**********************
 * POINTER OPERATIONS *
 **********************/

struct compare_status {
	pointer_t ptr1;
	pointer_t ptr2;
	tag_t tag;
	void (attr_fastcall *destruct)(struct compare_status *cs);
	union {
		struct {
			arg_t ai;
		} record;
		struct {
			array_index_t idx;
			array_index_t len;
			pointer_t p1;
			pointer_t p2;
		} array;
		struct {
			size_t l;
			struct function_argument **args1;
			struct function_argument **args2;
		} function_reference;
	} u;
};

struct data_method {
	void *(attr_fastcall *get_sub)(void *data);
	void (attr_fastcall *free_object)(void *data);
	bool (attr_fastcall *deep_eval)(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err);
	int (attr_fastcall *compare)(struct compare_status *cs, struct compare_status *new_cs, bool init);
	bool (attr_fastcall *save)(void *data, uintptr_t offset, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l);
};

static struct data_method data_method_table[TAG_END];

static void * attr_hot_fastcall no_sub(void attr_unused *data)
{
	return NULL;
}

static void attr_hot_fastcall free_primitive(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	data_free(d);
}

static void attr_hot_fastcall free_primitive_thunk(void *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);
	thunk_free(t);
}

static void attr_hot_fastcall free_none(void attr_unused *data)
{
}

static void attr_hot_fastcall free_integer(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	mpint_free(&da(d,longint)->mp);
	data_free(d);
}

static void attr_hot_fastcall free_array_same(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	index_free(&da(d,array_same)->n_entries);
	data_free(d);
}

static void attr_hot_fastcall free_resource(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	da(d,resource)->close(d);
	data_free(d);
}

void free_cache_entry(struct data *d, struct cache_entry *ce)
{
	arg_t i;
	for (i = 0; i < da(d,function)->n_arguments; i++)
		pointer_dereference(ce->arguments[i]);
	for (i = 0; i < da(d,function)->n_return_values; i++)
		pointer_dereference(ce->returns[i].ptr);
	mem_free(ce->returns);
	mem_free(ce);
}

static void attr_fastcall free_function(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	pointer_dereference(da(d,function)->types_ptr);
#ifdef HAVE_CODEGEN
	pointer_dereference(da(d,function)->codegen);
#endif
	if (unlikely(!da(d,function)->is_saved))
		mem_free(da(d,function)->code);
	mem_free(da(d,function)->local_variables);
	if (unlikely(!da(d,function)->is_saved))
		mem_free(da(d,function)->local_variables_flags);
	if (da(d,function)->args)
		mem_free(da(d,function)->args);
	mem_free(da(d,function)->function_name);
	if (unlikely(!da(d,function)->is_saved) && da(d,function)->lp)
		mem_free(da(d,function)->lp);
	while (unlikely(!tree_is_empty(&da(d,function)->cache))) {
		struct cache_entry *ce = get_struct(tree_any(&da(d,function)->cache), struct cache_entry, entry);
		tree_delete(&ce->entry);
		free_cache_entry(d, ce);
	}
	if (profiling_escapes)
		mem_free(da(d,function)->escape_data);
	data_free(d);
}

#ifdef HAVE_CODEGEN
static void attr_fastcall free_codegen(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
#ifdef HAVE_CODEGEN_TRAPS
#ifndef DEBUG_CRASH_HANDLER
	if (da(d,codegen)->trap_records_size)
#endif
	{
		rwmutex_lock_write(&traps_lock);
		tree_delete(&da(d,codegen)->codegen_tree);
		rwmutex_unlock_write(&traps_lock);
	}
#endif
	codegen_free(d);
	data_free(d);
}
#endif

static void * attr_hot_fastcall get_sub_record(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	const struct record_definition *def = type_def(da(d,record)->definition,record);
	frame_s *f = da_record_frame(d);
	frame_t slot;
	for (slot = 0; slot < def->n_slots; slot++) {
		pointer_t *ptr;
		/* !!! TODO: test multiple flags at once */
		if (!frame_test_flag(f, slot))
			continue;
		ptr = frame_pointer(f, slot);
		if (!pointer_is_empty(*ptr))
			return ptr;
		frame_clear_flag(f, slot);
	}
	return NULL;
}

static void * attr_hot_fastcall get_sub_option(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	pointer_t *ptr;
	ptr = &da(d,option)->pointer;
	if (!pointer_is_empty(*ptr))
		return ptr;
	return NULL;
}

static void * attr_hot_fastcall get_sub_array_slice(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	pointer_t *ptr = &da(d,array_slice)->reference;
	if (!pointer_is_empty(*ptr))
		return ptr;
	return NULL;
}

static void * attr_hot_fastcall get_sub_array_pointers(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	int_default_t x = da(d,array_pointers)->n_used_entries;
	while (x--) {
		pointer_t *ptr = &da(d,array_pointers)->pointer[x];
		if (!pointer_is_empty(*ptr))
			return ptr;
		da(d,array_pointers)->n_used_entries = x;
	}
	return NULL;
}

static void * attr_hot_fastcall get_sub_array_same(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	pointer_t *ptr = &da(d,array_same)->pointer;
	if (!pointer_is_empty(*ptr))
		return ptr;
	return NULL;
}

static void * attr_hot_fastcall get_sub_array_btree(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	btree_entries_t x = da(d,array_btree)->n_used_btree_entries;
	while (x--) {
		pointer_t *ptr = &da(d,array_btree)->btree[x].node;
		if (!pointer_is_empty(*ptr))
			return ptr;
		da(d,array_btree)->n_used_btree_entries = x;
		index_free(&da(d,array_btree)->btree[x].end_index);
	}
	return NULL;
}

static void * attr_hot_fastcall get_sub_array_incomplete(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	if (!pointer_is_empty(da(d,array_incomplete)->first))
		return &da(d,array_incomplete)->first;
	if (!pointer_is_empty(da(d,array_incomplete)->next))
		return &da(d,array_incomplete)->next;
	return NULL;
}

static void * attr_hot_fastcall get_sub_function_reference(void *data)
{
	struct data *d = cast_cpp(struct data *, data);
	arg_t ia = da(d,function_reference)->n_curried_arguments;
	pointer_t *prev;

	ia = da(d,function_reference)->n_curried_arguments;
	while (ia--) {
		if (da(d,function_reference)->arguments[ia].tag == TYPE_TAG_unknown) {
			pointer_t *ptr = &da(d,function_reference)->arguments[ia].u.ptr;
			if (!pointer_is_empty(*ptr))
				return ptr;
		}
		da(d,function_reference)->n_curried_arguments = ia;
	}

	if (da(d,function_reference)->is_indirect) {
		prev = &da(d,function_reference)->u.indirect;
		if (!pointer_is_empty(*prev))
			return prev;
	}

	return NULL;
}

static void * attr_hot_fastcall get_sub_function_call(void *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);

	address_unlock(t, DEPTH_THUNK);

	if (!pointer_is_empty(t->u.function_call.u.function_reference))
		return &t->u.function_call.u.function_reference;

	return NULL;
}

static void * attr_hot_fastcall get_sub_blackhole(void *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);
	struct execution_control *ex;

	refcount_add(&n_dereferenced, 1);
	thunk_tag_set(t, THUNK_TAG_BLACKHOLE, THUNK_TAG_BLACKHOLE_DEREFERENCED);
	ex = execution_control_acquire_from_thunk(t);
	address_unlock(t, DEPTH_THUNK);
	if (ex)
		execution_control_unlink_and_submit(ex, true);

	return NULL;
}

static void * attr_hot_fastcall get_sub_blackhole_some_dereferenced(void *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);
	struct execution_control *ex;

	refcount_add(&n_dereferenced, 1);
	thunk_tag_set(t, THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED, THUNK_TAG_BLACKHOLE_DEREFERENCED);
	ex = execution_control_acquire_from_thunk(t);
	address_unlock(t, DEPTH_THUNK);
	if (ex)
		execution_control_unlink_and_submit(ex, true);

	return NULL;
}

static void * attr_cold attr_fastcall get_sub_blackhole_dereferenced(void attr_unused *data)
{
	internal(file_line, "get_sub_blackhole_dereferenced called");
	return NULL;
}

static void attr_cold attr_fastcall free_blackhole_dereferenced(void attr_unused *data)
{
	internal(file_line, "free_blackhole_dereferenced called");
}

static void * attr_hot_fastcall get_sub_result(void *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);
	pointer_t *ptr;

	address_unlock(t, DEPTH_THUNK);

	ptr = &t->u.function_call.results[0].ptr;
	if (!pointer_is_empty(*ptr))
		return ptr;

	return NULL;
}

static void * attr_hot_fastcall get_sub_exception(void *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);

	address_unlock(t, DEPTH_THUNK);

	return NULL;
}

static void * attr_hot_fastcall get_sub_multi_ret_reference(void *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);
	struct thunk *mt;
	struct execution_control *ex = NULL;
	tag_t tag;
	arg_t idx;

	address_unlock(t, DEPTH_THUNK);

	mt = t->u.multi_ret_reference.thunk;

	address_lock(mt, DEPTH_THUNK);

	idx = t->u.multi_ret_reference.idx;

	tag = thunk_tag(mt);
	if (tag == THUNK_TAG_FUNCTION_CALL) {
		if (thunk_refcount_is_one_nonatomic(mt)) {
			/* get_sub_function_call unlocks mt */
			pointer_t *ptr = get_sub_function_call(mt);
			if (ptr)
				return ptr;
			thunk_free(mt);
			return NULL;
		}
		(void)thunk_dereference_nonatomic(mt);
		mt->u.function_call.results[idx].wanted = false;
		goto unlock_ret_false;
	}
	if (tag == THUNK_TAG_BLACKHOLE) {
		thunk_tag_set(mt, THUNK_TAG_BLACKHOLE, THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED);
		tag = THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED;
	}
	if (tag == THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED) {
		mt->u.function_call.results[idx].wanted = false;
		if (thunk_dereference_nonatomic(mt)) {
			refcount_add(&n_dereferenced, 1);
			thunk_tag_set(mt, THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED, THUNK_TAG_BLACKHOLE_DEREFERENCED);
			tag = THUNK_TAG_BLACKHOLE_DEREFERENCED;
			ex = execution_control_acquire_from_thunk(mt);
		}
		goto unlock_ret_false;
	}
	if (likely(tag == THUNK_TAG_RESULT)) {
		pointer_t *ptr = &mt->u.function_call.results[idx].ptr;
		if (!pointer_is_empty(*ptr)) {
			address_unlock(mt, DEPTH_THUNK);
			return ptr;
		}
		if (thunk_dereference_nonatomic(mt))
			thunk_free(mt);
		goto unlock_ret_false;
	}
	internal(file_line, "get_sub_multi_ret_reference: invalid thunk tag %u", tag);
unlock_ret_false:
	address_unlock(mt, DEPTH_THUNK);
	if (ex)
		execution_control_unlink_and_submit(ex, true);
	return NULL;
}

static void attr_cold attr_fastcall free_exception(void attr_unused *data)
{
	struct thunk *t = cast_cpp(struct thunk *, data);

	stack_trace_free(&t->u.exception.tr);
	if (t->u.exception.msg)
		mem_free(t->u.exception.msg);
	thunk_free(t);
}


void attr_hot_fastcall pointer_dereference_(pointer_t top_ptr argument_position)
{
	refcount_t *r;
	const struct data_method *m;
	void *p;
	pointer_t current_ptr, backlink, *sub_ptr;
	tag_t tag;

	current_ptr = top_ptr;
	backlink = pointer_mark();

retry_sub:
	r = pointer_get_refcount_(current_ptr);
	if (unlikely(refcount_is_read_only(r)))
		goto go_to_backlink;
	if (!refcount_dec_(r, caller_file_line_x))
		goto go_to_backlink;

process_current:
	p = pointer_get_value_strip_tag_(current_ptr);

	if (unlikely(pointer_is_thunk(current_ptr))) {
		struct thunk *thunk = cast_cpp(struct thunk *, p);
		address_lock(thunk, DEPTH_THUNK);
		tag = thunk_tag(thunk);
	} else {
		struct data *data = cast_cpp(struct data *, p);
		tag = da_tag(data);
	}
	m = &data_method_table[tag];

	sub_ptr = m->get_sub(p);
	if (sub_ptr) {
		ajla_assert(!pointer_is_empty(*sub_ptr), (file_line, "pointer_dereference_: empty pointer returned from %p", cast_ptr(void *, m)));

		if (!pointer_is_equal(current_ptr, backlink)) {
#if defined(__IBMC__)
			/* a compiler bug */
			volatile
#endif
			pointer_t old_current_ptr = current_ptr;
			current_ptr = *sub_ptr;
			*sub_ptr = backlink;
			backlink = old_current_ptr;
			goto retry_sub;
		} else {
			backlink = *sub_ptr;
			*sub_ptr = pointer_empty();
			goto process_current;
		}
	}

	m->free_object(p);

go_to_backlink:
	if (!pointer_is_mark(backlink)) {
		current_ptr = backlink;
		goto process_current;
	}
}


static inline bool pointer_verify(pointer_t attr_unused *ptr, pointer_t attr_unused val)
{
#ifndef THREAD_NONE
	bool ret;
	pointer_lock(ptr);
	ret = pointer_is_equal(*pointer_volatile(ptr), val);
	pointer_unlock(ptr);
	return ret;
#else
	return true;
#endif
}

pointer_t attr_hot_fastcall pointer_reference_(pointer_t *ptr argument_position)
{
#ifdef POINTER_FOLLOW_IS_LOCKLESS
	pointer_t p;
	refcount_t *r;
retry:
	p = *pointer_volatile(ptr);
	r = pointer_get_refcount_(p);
	if (likely(!pointer_is_thunk(p))) {
		pointer_dependency_barrier();
		if (unlikely(refcount_is_read_only(r)))
			return p;
		refcount_inc_(r, caller_file_line_x);
		return p;
	} else {
		struct thunk *t = pointer_get_thunk(p);
		if (likely(!refcount_is_read_only(r))) {
			address_lock(t, DEPTH_THUNK);
			if (unlikely(!pointer_verify(ptr, p))) {
				address_unlock(t, DEPTH_THUNK);
				goto retry;
			}
			if (thunk_is_finished(t)) {
				address_unlock(t, DEPTH_THUNK);
				pointer_follow_thunk_(ptr, POINTER_FOLLOW_THUNK_NOEVAL);
				goto retry;
			}
			refcount_inc_(r, caller_file_line_x);
			address_unlock(t, DEPTH_THUNK);
		}
		return p;
	}
#else
	pointer_t p;
	refcount_t *r;
	pointer_lock(ptr);
	p = *ptr;
	r = pointer_get_refcount_(p);
	if (likely(!refcount_is_read_only(r)))
		refcount_inc_(r, caller_file_line_x);
	pointer_unlock(ptr);
	return p;
#endif
}

void pointer_reference_maybe_(frame_s *fp, frame_t result, pointer_t *ptr, unsigned char flags argument_position)
{
	pointer_t p;
	if (flags & OPCODE_STRUCT_MAY_BORROW) {
		p = pointer_locked_read(ptr);
		if (likely(!pointer_is_thunk(p))) {
			ajla_assert(!frame_test_flag(fp, result), (file_line, "pointer_reference_maybe_: flag for slot %"PRIuMAX" already set", (uintmax_t)result));
			*frame_pointer(fp, result) = p;
			return;
		}
	}
	p = pointer_reference_(ptr pass_position);
	frame_set_pointer(fp, result, p);
}

void copy_from_function_reference_to_frame(frame_s *new_fp, struct data *ref, arg_t ia, char can_move)
{
	struct data *function = get_frame(new_fp)->function;
	while (1) {
		arg_t pi;
		if (!data_is_writable(ref))
			can_move = 0;

		pi = da(ref,function_reference)->n_curried_arguments;

		while (pi--) {
			frame_t target = da(function,function)->args[--ia].slot;
			type_tag_t tag = da(ref,function_reference)->arguments[pi].tag;
			if (tag != TYPE_TAG_unknown) {
				const struct type *new_type = frame_get_type_of_local(new_fp, target);
				if (TYPE_IS_FLAT(new_type)) {
					ajla_assert_lo(TYPE_TAG_IS_BUILTIN(new_type->tag) && new_type->size <= slot_size, (file_line, "copy_from_function_reference_to_frame: invalid type tag %u,%u,%u", new_type->tag, new_type->size, new_type->align));
					memcpy_fast(frame_var(new_fp, target), da(ref,function_reference)->arguments[pi].u.slot, new_type->size);
				} else {
					pointer_t ptr_data = flat_to_data(type_get_from_tag(tag), da(ref,function_reference)->arguments[pi].u.slot);
					frame_set_pointer(new_fp, target, ptr_data);
				}
			} else {
				pointer_t *p = &da(ref,function_reference)->arguments[pi].u.ptr;
				if (!can_move) {
					frame_set_pointer(new_fp, target, pointer_reference(p));
				} else {
					frame_set_pointer(new_fp, target, *p);
					*p = pointer_empty();
				}
			}
		}
		if (!da(ref,function_reference)->is_indirect)
			break;
		ref = pointer_get_data(da(ref,function_reference)->u.indirect);
	}

	ajla_assert_lo(!ia, (file_line, "copy_from_function_reference_to_frame: the number of arguments doesn't match: %s, %"PRIuMAX"", da(function,function)->function_name, (uintmax_t)ia));
}


void * attr_hot_fastcall pointer_follow_thunk_(pointer_t *ptr, void *ex_wait)
{
	pointer_t *orig_ptr = ptr;
	pointer_t pv;
	void *ret;
	struct execution_control *new_ex = NULL;
	struct thunk *t;
	struct thunk *error_thunk = NULL;
	tag_t t_tag;

	ajla_assert(ex_wait == POINTER_FOLLOW_THUNK_NOEVAL || ex_wait == POINTER_FOLLOW_THUNK_SPARK || !((struct execution_control_wait *)ex_wait)->mutex_to_lock, (file_line, "pointer_follow_thunk_: execution_control_wait is already waiting on %p", ((struct execution_control_wait *)ex_wait)->mutex_to_lock));

retry:
	pv = pointer_locked_read(ptr);
	if (unlikely(!pointer_is_thunk(pv))) {
		ret = POINTER_FOLLOW_THUNK_RETRY;
		goto return_ret;
	}
	t = pointer_get_thunk(pv);
	address_lock(t, DEPTH_THUNK);
	if (unlikely(!pointer_verify(ptr, pointer_thunk(t)))) {
		address_unlock(t, DEPTH_THUNK);
		ret = POINTER_FOLLOW_THUNK_RETRY;
		goto return_ret;
	}

	t_tag = thunk_tag(t);
	if (unlikely(t_tag == THUNK_TAG_EXCEPTION)) {
		if (unlikely(orig_ptr != ptr)) {
			thunk_reference(t);
			address_unlock(t, DEPTH_THUNK);
			if (unlikely(error_thunk != NULL))
				pointer_dereference(pointer_thunk(error_thunk));
			error_thunk = t;
			ptr = orig_ptr;
			goto retry;
		}
		address_unlock(t, DEPTH_THUNK);
		ret = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto return_ret;
	}

	if (unlikely(error_thunk != NULL)) {
		pointer_locked_write(ptr, pointer_thunk(error_thunk));
		address_unlock(t, DEPTH_THUNK);

		pointer_dereference(pointer_thunk(t));
		error_thunk = NULL;
		ret = unlikely(orig_ptr != ptr) ? POINTER_FOLLOW_THUNK_RETRY : POINTER_FOLLOW_THUNK_EXCEPTION;
		goto return_ret;
	}

	if (t_tag == THUNK_TAG_RESULT) {
process_result:
		pointer_lock(ptr);
		if (thunk_is_writable(t)) {
			*pointer_volatile(ptr) = t->u.function_call.results[0].ptr;
			pointer_unlock(ptr);
			address_unlock(t, DEPTH_THUNK);

			thunk_free(t);
		} else {
			pointer_t px = t->u.function_call.results[0].ptr;
			pointer_reference_owned(px);
			*pointer_volatile(ptr) = px;
			pointer_unlock(ptr);
			address_unlock(t, DEPTH_THUNK);

			pointer_dereference(pointer_thunk(t));
		}
		ret = POINTER_FOLLOW_THUNK_RETRY;
		goto return_ret;
	}

	if (t_tag == THUNK_TAG_MULTI_RET_REFERENCE) {
		struct thunk *mt = t->u.multi_ret_reference.thunk;
		tag_t mt_tag;
		if (unlikely(!address_trylock_second(t, mt, DEPTH_THUNK))) {
			address_unlock(t, DEPTH_THUNK);
			address_lock_two(t, mt, DEPTH_THUNK);
			if (unlikely(!pointer_verify(ptr, pointer_thunk(t))) || unlikely(thunk_tag(t) != THUNK_TAG_MULTI_RET_REFERENCE)) {
				address_unlock_second(t, mt, DEPTH_THUNK);
				address_unlock(t, DEPTH_THUNK);
				ret = POINTER_FOLLOW_THUNK_RETRY;
				goto return_ret;
			}
		}
		mt_tag = thunk_tag(mt);
		if (mt_tag == THUNK_TAG_RESULT) {
			arg_t idx = t->u.multi_ret_reference.idx;
			thunk_tag_set(t, THUNK_TAG_MULTI_RET_REFERENCE, THUNK_TAG_RESULT);
			t->u.function_call.results[0].ptr = mt->u.function_call.results[idx].ptr;
			pointer_poison(&mt->u.function_call.results[idx].ptr);
			if (thunk_dereference_nonatomic(mt)) {
				address_unlock_second(t, mt, DEPTH_THUNK);
				address_unlock(t, DEPTH_THUNK);
				thunk_free(mt);
				ret = POINTER_FOLLOW_THUNK_RETRY;
				goto return_ret;
			}
			address_unlock_second(t, mt, DEPTH_THUNK);
			goto process_result;
		}
		address_unlock_second(mt, t, DEPTH_THUNK);
		t = mt;
		t_tag = mt_tag;
	}

	if (ex_wait == POINTER_FOLLOW_THUNK_NOEVAL) {
		/* the user doesn't want to evaluate the thunk */
		ret = POINTER_FOLLOW_THUNK_EXIT;
		address_unlock(t, DEPTH_THUNK);
		goto return_ret;
	}

	if (t_tag == THUNK_TAG_FUNCTION_CALL) {
		ajla_error_t mayfail;
		frame_s *new_fp;
		struct data *top_reference, *function, *function_reference;
		arg_t total_arguments;

		pointer_t *pr, pq;

		total_arguments = 0;
		pr = &t->u.function_call.u.function_reference;
		while (1) {
			pq = pointer_locked_read(pr);
			if (unlikely(pointer_is_thunk(pq))) {
evaluate_thunk:
				ptr = pr;
				address_unlock(t, DEPTH_THUNK);
				goto retry;
			}
			function_reference = pointer_get_data(pq);
			total_arguments += da(function_reference,function_reference)->n_curried_arguments;
			if (!da(function_reference,function_reference)->is_indirect)
				break;
			pr = &da(function_reference,function_reference)->u.indirect;
		}
		pr = da(function_reference,function_reference)->u.direct;
		pq = pointer_locked_read(pr);
		if (unlikely(pointer_is_thunk(pq)))
			goto evaluate_thunk;
		function = pointer_get_data(pq);

		ajla_assert_lo(da(function,function)->n_arguments == total_arguments, (file_line, "pointer_follow_thunk_: the number of arguments does not match: %s: %"PRIuMAX", %"PRIuMAX"", da(function,function)->function_name, (uintmax_t)da(function,function)->n_arguments, (uintmax_t)total_arguments));

		if (likely(!new_ex)) {
			new_ex = execution_control_alloc(MEM_DONT_TRY_TO_FREE);
			if (unlikely(!new_ex)) {
				address_unlock(t, DEPTH_THUNK);
				new_ex = execution_control_alloc(&mayfail);
				if (unlikely(!new_ex)) {
					error_thunk = thunk_alloc_exception_error(mayfail, NULL, NULL, NULL pass_file_line);
				}
				goto retry;
			}

		}
		new_ex->thunk = t;
		if (likely(ex_wait != POINTER_FOLLOW_THUNK_SPARK)) {
			list_add(&new_ex->wait_list, &((struct execution_control_wait *)ex_wait)->wait_entry);
			((struct execution_control_wait *)ex_wait)->mutex_to_lock = address_get_mutex(t, DEPTH_THUNK);
		}
		top_reference = pointer_get_data(t->u.function_call.u.function_reference);
		t->u.function_call.u.execution_control = new_ex;
		if (da(function,function)->n_return_values == 1 || likely(thunk_refcount_get_nonatomic(t) == da(function,function)->n_return_values))
			thunk_tag_set(t, THUNK_TAG_FUNCTION_CALL, THUNK_TAG_BLACKHOLE);
		else
			thunk_tag_set(t, THUNK_TAG_FUNCTION_CALL, THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED);
		address_unlock(t, DEPTH_THUNK);

#if 0
		if (!(rand() & 127)) {
			new_fp = NULL;
			mayfail = error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY);
			debug("testing failure");
		}
		else
#endif
		new_fp = stack_alloc(new_ex, function, &mayfail);
		if (unlikely(!new_fp)) {
			new_ex->stack = NULL;
			data_dereference(top_reference);
			error_thunk = thunk_alloc_exception_error(mayfail, NULL, NULL, NULL pass_file_line);
			thunk_terminate_with_value(new_ex->thunk, da(function,function)->n_return_values, pointer_thunk(error_thunk));
			error_thunk = NULL;
			new_ex = NULL;
			ret = POINTER_FOLLOW_THUNK_EXIT;
			goto return_ret;
		}
		new_ex->current_frame = new_fp;
		new_ex->current_ip = 0;

		frame_init(new_fp, function, 0, CALL_MODE_NORMAL);
		copy_from_function_reference_to_frame(new_fp, top_reference, da(function,function)->n_arguments, true);

		data_dereference(top_reference);

		ret = new_ex;
		new_ex = NULL;
		goto return_ret;
	}

	if (t_tag == THUNK_TAG_BLACKHOLE || t_tag == THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED) {
		if (likely(ex_wait != POINTER_FOLLOW_THUNK_SPARK)) {
			list_add(&t->u.function_call.u.execution_control->wait_list, &((struct execution_control_wait *)ex_wait)->wait_entry);
			((struct execution_control_wait *)ex_wait)->mutex_to_lock = address_get_mutex(t, DEPTH_THUNK);
		}
		address_unlock(t, DEPTH_THUNK);

		ret = POINTER_FOLLOW_THUNK_EXIT;
		goto return_ret;
	}

	ret = NULL;
	internal(file_line, "pointer_follow_thunk_: invalid thunk tag %u", t_tag);

return_ret:
	if (unlikely(error_thunk != NULL))
		pointer_dereference(pointer_thunk(error_thunk));
	if (unlikely(new_ex != NULL))
		mem_free(new_ex);
	return ret;
}

void attr_fastcall pointer_resolve_result(pointer_t *ptr)
{
again:
	if (pointer_is_thunk(*ptr))
		pointer_follow_thunk_noeval(ptr, goto again, break, break);
}

void attr_fastcall pointer_follow_wait(frame_s *fp, const code_t *ip)
{
	struct execution_control *ex = frame_execution_control(fp);
	ex->current_frame = fp;
	ex->current_ip = frame_ip(fp, ip);

	waiting_list_add(ex);

	if (unlikely(refcount_dec(&ex->wait_state)))
		execution_control_unlink_and_submit(ex, true);
}

bool attr_fastcall data_is_nan(type_tag_t type, const unsigned char attr_unused *ptr)
{
	switch (type) {
#define f(n, t, nt, pack, unpack)				\
		case TYPE_TAG_real + n: {			\
			t val;					\
			barrier_aliasing();			\
			val = *(t *)ptr;			\
			barrier_aliasing();			\
			return cat(isnan_,t)(val);		\
		}
		for_all_real(f, for_all_empty)
#undef f
	}
	return false;
}

pointer_t flat_to_data(const struct type *type, const unsigned char *flat)
{
	ajla_error_t err;

	struct data *d;
	unsigned tag = type->tag;

	if (tag == TYPE_TAG_flat_option) {
		d = data_alloc_option_mayfail(&err pass_file_line);
		if (unlikely(!d))
			goto fail;
		da(d,option)->pointer = pointer_empty();
		da(d,option)->option = *cast_ptr(ajla_flat_option_t *, flat);
	} else if (TYPE_TAG_IS_FIXED(tag) || TYPE_TAG_IS_REAL(tag) || TYPE_TAG_IS_INT(tag)) {
		size_t size;
		size = type->size;
		if (unlikely(data_is_nan(tag, flat))) {
			err = error_ajla(EC_SYNC, AJLA_ERROR_NAN);
			goto fail;
		}
		d = data_alloc_flat_mayfail(tag, flat, size, &err pass_file_line);
		if (unlikely(!d))
			goto fail;
	} else if (tag == TYPE_TAG_flat_record) {
		arg_t ai;
		const struct record_definition *def = type_def(type_def(type,flat_record)->base,record);
		d = data_alloc_record_mayfail(def, &err pass_file_line);
		if (unlikely(!d))
			goto fail;
		(void)memset(da_record_frame(d), 0, bitmap_slots(def->n_slots) * slot_size);
		for (ai = 0; ai < def->n_entries; ai++) {
			frame_t slot = record_definition_slot(def,ai);
			flat_size_t flat_offset = type_def(type,flat_record)->entries[slot].flat_offset;
			const struct type *entry_type = def->types[slot];
			const struct type *flat_type = type_def(type,flat_record)->entries[slot].subtype;
			if (TYPE_IS_FLAT(entry_type)) {
				ajla_assert_lo(type_is_equal(entry_type, flat_type), (file_line, "flat_to_data: copying between different types (%u,%u,%u) -> (%u,%u,%u)", flat_type->tag, flat_type->size, flat_type->align, entry_type->tag, entry_type->size, entry_type->align));
				memcpy_fast(frame_var(da_record_frame(d), slot), flat + flat_offset, entry_type->size);
			} else {
				pointer_t ptr = flat_to_data(flat_type, flat + flat_offset);
				frame_set_pointer(da_record_frame(d), slot, ptr);
			}
		}
	} else if (tag == TYPE_TAG_flat_array) {
		const struct flat_array_definition *flat_def = type_def(type,flat_array);
		ajla_assert(type->size == flat_def->n_elements * flat_def->base->size, (file_line, "flat_to_data: array size mismatch: %"PRIuMAX" != %"PRIuMAX" * %"PRIuMAX"", (uintmax_t)type->size, (uintmax_t)flat_def->n_elements, (uintmax_t)flat_def->base->size));
		d = data_alloc_array_flat_mayfail(flat_def->base, flat_def->n_elements, flat_def->n_elements, false, &err pass_file_line);
		if (unlikely(!d))
			goto fail;
		(void)memcpy(da_array_flat(d), flat, type->size);
	} else {
		internal(file_line, "flat_to_data: unknown type %u", tag);
	}
	return pointer_data(d);

fail:
	return pointer_error(err, NULL, NULL pass_file_line);
}


void attr_fastcall struct_clone(pointer_t *ptr)
{
	ajla_error_t err;
	struct data *orig, *clone;

	orig = pointer_get_data(*ptr);
	switch (da_tag(orig)) {
		case DATA_TAG_record: {
			const struct record_definition *def;
			frame_t n_slots, slot;

			def = type_def(da(orig,record)->definition,record);
			n_slots = def->n_slots;
			clone = data_alloc_record_mayfail(def, &err pass_file_line);
			if (unlikely(!clone))
				goto fail;
			(void)memcpy_slots(cast_ptr(unsigned char *, da_record_frame(clone)), cast_ptr(unsigned char *, da_record_frame(orig)), n_slots);
			for (slot = 0; slot < n_slots; slot++) {
				if (frame_test_flag(da_record_frame(orig), slot))
					*frame_pointer(da_record_frame(clone), slot) = pointer_reference(frame_pointer(da_record_frame(orig), slot));
			}
			break;
		}
		case DATA_TAG_option: {
			clone = data_alloc(option, &err);
			if (unlikely(!clone))
				goto fail;
			da(clone,option)->option = da(orig,option)->option;
			if (likely(!pointer_is_empty(da(orig,option)->pointer)))
				da(clone,option)->pointer = pointer_reference(&da(orig,option)->pointer);
			else
				da(clone,option)->pointer = pointer_empty();
			break;
		}
		case DATA_TAG_array_flat:
		case DATA_TAG_array_slice:
		case DATA_TAG_array_pointers:
		case DATA_TAG_array_same:
		case DATA_TAG_array_btree: {
			if (!array_clone(ptr, &err))
				goto fail;
			return;
		}
		case DATA_TAG_array_incomplete: {
			pointer_t first = pointer_reference(&da(orig,array_incomplete)->first);
			pointer_t next = pointer_reference(&da(orig,array_incomplete)->next);
			clone = data_alloc_array_incomplete(pointer_get_data(first), next, &err pass_file_line);
			if (unlikely(!clone)) {
				pointer_dereference(first);
				pointer_dereference(next);
				goto fail;
			}
			break;
		}
		default:
			internal(file_line, "struct_clone: invalid data tag %u", da_tag(orig));
	}
	pointer_dereference(*ptr);
	*ptr = pointer_data(clone);
	return;

fail:
	pointer_dereference(*ptr);
	*ptr = pointer_error(err, NULL, NULL pass_file_line);
}


static bool attr_fastcall deep_eval_nothing(struct data attr_unused *d, pointer_t attr_unused ***data_stack, size_t attr_unused *data_stack_size, ajla_error_t attr_unused *err)
{
	return true;
}

static bool attr_fastcall deep_eval_flat(struct data *d, pointer_t attr_unused ***data_stack, size_t attr_unused *data_stack_size, ajla_error_t *err)
{
	if (unlikely(data_is_nan(da(d,flat)->data_type, da_flat(d)))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NAN), err, "NaN");
		return false;
	}
	return true;
}

static bool attr_fastcall deep_eval_record(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err)
{
	const struct record_definition *def = type_def(da(d,record)->definition,record);
	frame_s *f = da_record_frame(d);
	frame_t slot = def->n_slots;
	while (slot--) {
		pointer_t *ptr;
		if (!frame_test_flag(f, slot)) {
			const struct type *t = def->types[slot];
			if (!t)
				continue;
			if (unlikely(data_is_nan(t->tag, frame_var(f, slot)))) {
				fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NAN), err, "NaN");
				return false;
			}
			continue;
		}
		ptr = frame_pointer(f, slot);
		if (unlikely(!array_add_mayfail(pointer_t *, data_stack, data_stack_size, ptr, NULL, err)))
			return false;
	}
	return true;
}

static bool attr_fastcall deep_eval_option(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err)
{
	if (pointer_is_empty(da(d,option)->pointer))
		return true;
	return array_add_mayfail(pointer_t *, data_stack, data_stack_size, &da(d,option)->pointer, NULL, err);
}

struct real_pos {
	unsigned char tag;
	flat_size_t pos;
};

static bool recurse_type(const struct type *type, flat_size_t offset, struct real_pos **rp, size_t *rp_size, ajla_error_t *err)
{
	if (TYPE_TAG_IS_REAL(type->tag)) {
		struct real_pos p;
		p.tag = type->tag;
		p.pos = offset;
		if (!array_add_mayfail(struct real_pos, rp, rp_size, p, NULL, err))
			return false;
	} else if (type->tag == TYPE_TAG_flat_record) {
		const struct flat_record_definition *def = type_def(type, flat_record);
		const struct record_definition *rec_def = type_def(def->base, record);
		frame_t slot;
		for (slot = 0; slot < rec_def->n_slots; slot++) {
			const struct flat_record_definition_entry *frde;
			const struct type *t = rec_def->types[slot];
			if (!t)
				continue;
			frde = &def->entries[slot];
			if (unlikely(!recurse_type(frde->subtype, offset + frde->flat_offset, rp, rp_size, err)))
				return false;
		}
	} else if (type->tag == TYPE_TAG_flat_array) {
		const struct flat_array_definition *def = type_def(type, flat_array);
		const struct type *base = def->base;
		flat_size_t i;
		for (i = 0; i < def->n_elements; i++, offset += base->size) {
			if (unlikely(!recurse_type(base, offset, rp, rp_size, err)))
				return false;
		}
	}
	return true;
}

static bool deep_eval_array_test_nan(const struct type *type, unsigned char *flat_data, int_default_t n_entries, ajla_error_t *err)
{
	struct real_pos *rp;
	size_t rp_size;
	int_default_t i;

	if (TYPE_TAG_IS_FIXED(type->tag) || likely(TYPE_TAG_IS_INT(type->tag)) || type->tag == TYPE_TAG_flat_option)
		return true;

	if (unlikely(!array_init_mayfail(struct real_pos, &rp, &rp_size, err)))
		return false;

	if (unlikely(!recurse_type(type, 0, &rp, &rp_size, err)))
		return false;

	if (likely(!rp_size))
		goto free_ret;

	for (i = 0; i < n_entries; i++, flat_data += type->size) {
		size_t j;
		j = 0;
		do {
			if (unlikely(data_is_nan(rp[j].tag, flat_data + rp[j].pos))) {
				fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_NAN), err, "NaN");
				mem_free(rp);
				return false;
			}
		} while (unlikely(++j < rp_size));
	}

free_ret:
	mem_free(rp);
	return true;
}

static bool attr_fastcall deep_eval_array_flat(struct data *d, pointer_t attr_unused ***data_stack, size_t attr_unused *data_stack_size, ajla_error_t *err)
{
	return deep_eval_array_test_nan(da(d,array_flat)->type, da_array_flat(d), da(d,array_flat)->n_used_entries, err);
}

static bool attr_fastcall deep_eval_array_slice(struct data *d, pointer_t attr_unused ***data_stack, size_t attr_unused *data_stack_size, ajla_error_t *err)
{
	return deep_eval_array_test_nan(da(d,array_slice)->type, da(d,array_slice)->flat_data_minus_data_array_offset + data_array_offset, da(d,array_slice)->n_entries, err);
}

static bool attr_fastcall deep_eval_array_pointers(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err)
{
	int_default_t x = da(d,array_pointers)->n_used_entries;
	while (x--) {
		pointer_t *ptr = &da(d,array_pointers)->pointer[x];
		if (unlikely(!array_add_mayfail(pointer_t *, data_stack, data_stack_size, ptr, NULL, err)))
			return false;
	}
	return true;
}

static bool attr_fastcall deep_eval_array_same(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err)
{
	return array_add_mayfail(pointer_t *, data_stack, data_stack_size, &da(d,array_same)->pointer, NULL, err);
}

static bool attr_fastcall deep_eval_array_btree(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err)
{
	btree_entries_t x = da(d,array_btree)->n_used_btree_entries;
	while (x--) {
		pointer_t *ptr = &da(d,array_btree)->btree[x].node;
		if (unlikely(!array_add_mayfail(pointer_t *, data_stack, data_stack_size, ptr, NULL, err)))
			return false;
	}
	return true;
}

static bool attr_fastcall deep_eval_array_incomplete(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err)
{
	return likely(array_add_mayfail(pointer_t *, data_stack, data_stack_size, &da(d,array_incomplete)->first, NULL, err)) &&
	       likely(array_add_mayfail(pointer_t *, data_stack, data_stack_size, &da(d,array_incomplete)->next, NULL, err));
}

static bool attr_fastcall deep_eval_function_reference(struct data *d, pointer_t ***data_stack, size_t *data_stack_size, ajla_error_t *err)
{
	arg_t ia;

	ia = da(d,function_reference)->n_curried_arguments;
	while (ia--) {
		if (da(d,function_reference)->arguments[ia].tag == TYPE_TAG_unknown)
			if (unlikely(!array_add_mayfail(pointer_t *, data_stack, data_stack_size, &da(d,function_reference)->arguments[ia].u.ptr, NULL, err)))
				return false;
	}
	if (da(d,function_reference)->is_indirect) {
		return array_add_mayfail(pointer_t *, data_stack, data_stack_size, &da(d,function_reference)->u.indirect, NULL, err);
	} else {
		return array_add_mayfail(pointer_t *, data_stack, data_stack_size, da(d,function_reference)->u.direct, NULL, err);
	}
}

struct processed_pointer {
	struct tree_entry entry;
	pointer_t *ptr;
};

static int processed_compare(const struct tree_entry *e, uintptr_t v)
{
	struct processed_pointer *p = get_struct(e, struct processed_pointer, entry);
	if (ptr_to_num(p->ptr) < v)
		return -1;
	if (likely(ptr_to_num(p->ptr) > v))
		return 1;
	return 0;
}

void * attr_fastcall pointer_deep_eval(pointer_t *ptr, frame_s *fp, const code_t *ip, struct thunk **thunk)
{
	ajla_error_t err;
	struct data *d;
	tag_t tag;

	pointer_t **data_stack;
	size_t data_stack_size;

	struct tree processed;

	void *ret;

	tree_init(&processed);

	if (unlikely(!array_init_mayfail(pointer_t *, &data_stack, &data_stack_size, &err))) {
return_err:
		*thunk = pointer_get_thunk(pointer_error(err, NULL, NULL pass_file_line));
		ret = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto free_tree_ret;
	}

go_sub:
	pointer_follow(ptr, false, d, PF_WAIT, fp, ip,
		ret = ex_;
		goto free_tree_ret,
		thunk_reference(thunk_);
		*thunk = thunk_;
		ret = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto free_tree_ret;
	);

	tag = da_tag(d);

	if (unlikely(!data_method_table[tag].deep_eval(d, &data_stack, &data_stack_size, &err)))
		goto return_err;

	if (data_stack_size) {
		struct tree_insert_position ins;
		struct processed_pointer *pp = mem_alloc_mayfail(struct processed_pointer *, sizeof(struct processed_pointer), &err);
		if (unlikely(!pp))
			goto return_err;

		pp->ptr = ptr;
		if (unlikely(tree_find_for_insert(&processed, processed_compare, ptr_to_num(ptr), &ins) != NULL))
			internal(file_line, "pointer_deep_eval: pointer %p is already in the tree", ptr);
		tree_insert_after_find(&pp->entry, &ins);

pop_another:
		ptr = data_stack[--data_stack_size];
		ajla_assert(!pointer_is_empty(*ptr), (file_line, "pointer_deep_eval: empty pointer, last tag %u", tag));

		if (unlikely(tree_find(&processed, processed_compare, ptr_to_num(ptr)) != NULL)) {
			if (data_stack_size)
				goto pop_another;
		} else {
			goto go_sub;
		}
	}

	ret = POINTER_FOLLOW_THUNK_GO;

free_tree_ret:
	if (likely(data_stack != NULL))
		mem_free(data_stack);

	while (!tree_is_empty(&processed)) {
		struct processed_pointer *pp = get_struct(tree_any(&processed), struct processed_pointer, entry);
		tree_delete(&pp->entry);
		mem_free(pp);
	}

	return ret;
}

void * attr_fastcall frame_pointer_deep_eval(frame_s *fp, const code_t *ip, frame_t slot, struct thunk **thunk)
{
	if (frame_variable_is_flat(fp, slot)) {
		ajla_error_t err;
		if (unlikely(!deep_eval_array_test_nan(frame_get_type_of_local(fp, slot), frame_var(fp, slot), 1, &err))) {
			*thunk = pointer_get_thunk(pointer_error(err, NULL, NULL pass_file_line));
			return POINTER_FOLLOW_THUNK_EXCEPTION;
		}
		return POINTER_FOLLOW_THUNK_GO;
	}
	return pointer_deep_eval(frame_pointer(fp, slot), fp, ip, thunk);
}


bool attr_fastcall mpint_export(const mpint_t *m, unsigned char *ptr, unsigned intx, ajla_error_t *err)
{
#define f(n, s, u, sz, bits)						\
		case n: {						\
			bool ret;					\
			barrier_aliasing();				\
			ret = cat(mpint_export_to_,s)(m, cast_ptr(s *, ptr), err);\
			barrier_aliasing();				\
			return ret;					\
		}
	switch (intx) {
		for_all_fixed(f)
		default:
			internal(file_line, "mpint_export: invalid type %d", intx);
	}
#undef f
	not_reached();
	return false;
}

bool attr_fastcall mpint_export_unsigned(const mpint_t *m, unsigned char *ptr, unsigned intx, ajla_error_t *err)
{
#define f(n, s, u, sz, bits)						\
		case n: {						\
			bool ret;					\
			barrier_aliasing();				\
			ret = cat(mpint_export_to_,u)(m, cast_ptr(u *, ptr), err);\
			barrier_aliasing();				\
			return ret;					\
		}
	switch (intx) {
		for_all_fixed(f)
		default:
			internal(file_line, "mpint_export_unsigned: invalid type %d", intx);
	}
#undef f
	not_reached();
	return false;
}

int data_compare_numbers(type_tag_t tt, unsigned char *flat1, pointer_t ptr1, unsigned char *flat2, pointer_t ptr2)
{
	struct data *d1 = NULL, *d2 = NULL;	/* avoid warning */
	union {
		intbig_t big;
		ajla_flat_option_t opt;
		unsigned char flat[1];
	} u1;
	union {
		intbig_t big;
		ajla_flat_option_t opt;
		unsigned char flat[1];
	} u2;
	ajla_flat_option_t r;
	ajla_error_t exp_err;
	if (!flat1) {
		tag_t tag1;
		ajla_option_t opt1;
		d1 = pointer_get_data(ptr1);
		tag1 = da_tag(d1);
		switch (tag1) {
			case DATA_TAG_flat:
				tt = da(d1,flat)->data_type;
				flat1 = da_flat(d1);
				break;
			case DATA_TAG_longint:
				if (tt == TYPE_TAG_unknown) {
					if (!flat2) {
						d2 = pointer_get_data(ptr2);
						if (da_tag(d2) == DATA_TAG_flat)
							tt = da(d2,flat)->data_type;
					}
				}
				if (tt != TYPE_TAG_unknown) {
					if (mpint_export(&da(d1,longint)->mp, u1.flat, TYPE_TAG_IDX_INT(tt), &exp_err))
						flat1 = u1.flat;
				}
				break;
			case DATA_TAG_option:
				tt = TYPE_TAG_flat_option;
				opt1 = da(d1,option)->option;
				if (unlikely(opt1 != (ajla_flat_option_t)opt1))
					return 1;
				u1.opt = opt1;
				flat1 = u1.flat;
				break;
			default:
				internal(file_line, "data_compare_numbers: invalid tag %u", tag1);
		}
	}
	if (!flat2) {
		tag_t tag2;
		ajla_option_t opt2;
		d2 = pointer_get_data(ptr2);
		tag2 = da_tag(d2);
		switch (tag2) {
			case DATA_TAG_flat:
				tt = da(d2,flat)->data_type;
				flat2 = da_flat(d2);
				break;
			case DATA_TAG_longint:
				if (tt != TYPE_TAG_unknown) {
					if (mpint_export(&da(d2,longint)->mp, u2.flat, TYPE_TAG_IDX_INT(tt), &exp_err))
						flat2 = u2.flat;
				}
				break;
			case DATA_TAG_option:
				tt = TYPE_TAG_flat_option;
				opt2 = da(d2,option)->option;
				if (unlikely(opt2 != (ajla_flat_option_t)opt2))
					return -1;
				u2.opt = opt2;
				flat2 = u2.flat;
				break;
			default:
				internal(file_line, "data_compare_numbers: invalid tag %u", tag2);
		}
	}
	if (flat1 && flat2) {
		int c = type_memcmp(flat1, flat2, type_get_from_tag(tt), 1);
		if (c < 0)
			return -1;
		if (c > 0)
			return 1;
		return 0;
	}
	if (flat1)
		return -1;
	if (flat2)
		return 1;
	mpint_less(&da(d1,longint)->mp, &da(d2,longint)->mp, &r, NULL);
	if (r)
		return -1;
	mpint_equal(&da(d1,longint)->mp, &da(d2,longint)->mp, &r, NULL);
	if (r)
		return 0;
	return 1;
}

struct array_compare_context {
	unsigned char *flat;
	const struct type *type;
	int_default_t n_elements;
	pointer_t *ptr;
};

static int_default_t array_compare_callback(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t *ptr, void *context)
{
	struct array_compare_context *ac = context;
	ajla_assert_lo(n_elements > 0, (file_line, "array_compare_callback: unexpected thunk"));
	ac->flat = flat;
	ac->type = type;
	ac->n_elements = n_elements;
	ac->ptr = ptr;
	return 0;
}

static void attr_fastcall cs_empty_destruct(struct compare_status attr_unused *cs)
{
}

static int attr_fastcall data_compare_nothing(struct compare_status attr_unused *cs, struct compare_status attr_unused *new_cs, bool attr_unused init)
{
	struct data *d1 = pointer_get_data(cs->ptr1);
	struct data *d2 = pointer_get_data(cs->ptr2);
	internal(file_line, "data_compare_nothing: comparing tags %u, %u", da_tag(d1), da_tag(d2));
	return DATA_COMPARE_OOM;
}

static int attr_fastcall data_compare_number(struct compare_status *cs, struct compare_status attr_unused *new_cs, bool attr_unused init)
{
	return data_compare_numbers(TYPE_TAG_unknown, NULL, cs->ptr1, NULL, cs->ptr2);
}

static int attr_fastcall data_compare_record(struct compare_status *cs, struct compare_status *new_cs, bool init)
{
	struct data *d1 = pointer_get_data(cs->ptr1);
	struct data *d2 = pointer_get_data(cs->ptr2);
	frame_s *f1 = da_record_frame(d1);
	frame_s *f2 = da_record_frame(d2);
	const struct record_definition *def = type_def(da(d1,record)->definition,record);
	ajla_assert(def->n_slots == type_def(da(d2,record)->definition,record)->n_slots, (file_line, "data_compare_record: mismatched record definition"));
	if (init)
		cs->u.record.ai = 0;
	while (cs->u.record.ai < def->n_entries) {
		frame_t slot = record_definition_slot(def, cs->u.record.ai);
		const struct type *t = def->types[slot];
		if (frame_test_flag(f1, slot) && frame_test_flag(f2, slot)) {
			new_cs->ptr1 = *frame_pointer(f1, slot);
			new_cs->ptr2 = *frame_pointer(f2, slot);
			cs->u.record.ai++;
			return 2;
		} else {
			unsigned char *flat1 = !frame_test_flag(f1, slot) ? frame_var(f1, slot) : NULL;
			unsigned char *flat2 = !frame_test_flag(f2, slot) ? frame_var(f2, slot) : NULL;
			pointer_t ptr1 = !frame_test_flag(f1, slot) ? pointer_empty() : *frame_pointer(f1, slot);
			pointer_t ptr2 = !frame_test_flag(f2, slot) ? pointer_empty() : *frame_pointer(f2, slot);
			int c = data_compare_numbers(t->tag, flat1, ptr1, flat2, ptr2);
			if (c)
				return c;
			cs->u.record.ai++;
		}
	}
	return 0;
}

static int attr_fastcall data_compare_option(struct compare_status *cs, struct compare_status *new_cs, bool init)
{
	struct data *d1 = pointer_get_data(cs->ptr1);
	struct data *d2 = pointer_get_data(cs->ptr2);
	pointer_t ptr1, ptr2;
	if (da(d1,option)->option < da(d2,option)->option)
		return -1;
	if (da(d1,option)->option > da(d2,option)->option)
		return 1;
	ptr1 = da(d1,option)->pointer;
	ptr2 = da(d2,option)->pointer;
	ajla_assert(pointer_is_empty(ptr1) == pointer_is_empty(ptr2), (file_line, "data_compare_option: mismatching pointers"));
	if (init && !pointer_is_empty(ptr1)) {
		new_cs->ptr1 = ptr1;
		new_cs->ptr2 = ptr2;
		return 2;
	}
	return 0;
}

static void attr_fastcall cs_array_destruct(struct compare_status *cs)
{
	index_free(&cs->u.array.len);
	index_free(&cs->u.array.idx);
	if (!pointer_is_empty(cs->u.array.p1))
		pointer_dereference(cs->u.array.p1);
	if (!pointer_is_empty(cs->u.array.p2))
		pointer_dereference(cs->u.array.p2);
}

static int attr_fastcall data_compare_array(struct compare_status *cs, struct compare_status *new_cs, bool init)
{
	struct data *d1 = pointer_get_data(cs->ptr1);
	struct data *d2 = pointer_get_data(cs->ptr2);
	if (init) {
		array_index_t len1, len2;
		cs->u.array.p1 = pointer_empty();
		cs->u.array.p2 = pointer_empty();
		len1 = array_len(d1);
		len2 = array_len(d2);
		if (!index_ge_index(len1, len2)) {
			index_free(&len1);
			index_free(&len2);
			return -1;
		}
		if (!index_ge_index(len2, len1)) {
			index_free(&len1);
			index_free(&len2);
			return 1;
		}
		index_free(&len2);
		cs->u.array.len = len1;
		index_from_int(&cs->u.array.idx, 0);
		cs->destruct = cs_array_destruct;
	}

	while (!index_ge_index(cs->u.array.idx, cs->u.array.len)) {
		pointer_t ptr;
		struct array_compare_context ctx1, ctx2;

		if (!pointer_is_empty(cs->u.array.p1))
			pointer_dereference(cs->u.array.p1), cs->u.array.p1 = pointer_empty();
		if (!pointer_is_empty(cs->u.array.p2))
			pointer_dereference(cs->u.array.p2), cs->u.array.p2 = pointer_empty();

		ptr = pointer_data(d1);
		if (unlikely(array_btree_iterate(&ptr, &cs->u.array.idx, array_compare_callback, &ctx1)))
			internal(file_line, "data_compare_array: iterator unexpectedly succeeded");
		ptr = pointer_data(d2);
		if (unlikely(array_btree_iterate(&ptr, &cs->u.array.idx, array_compare_callback, &ctx2)))
			internal(file_line, "data_compare_array: iterator unexpectedly succeeded");

		if (ctx1.flat && ctx2.flat) {
			int c;
			int_default_t m = minimum(ctx1.n_elements, ctx2.n_elements);
			ajla_assert(ctx1.type->tag == ctx2.type->tag, (file_line, "data_compare_array: array types do not match: %u,%u", ctx1.type->tag, ctx2.type->tag));
			c = type_memcmp(ctx1.flat, ctx2.flat, ctx1.type, m);
			if (c) {
				if (c < 0)
					return -1;
				else
					return 1;
			}
			index_add_int(&cs->u.array.idx, m);
		} else {
			struct thunk *thunk;
			if (unlikely(ctx1.flat != NULL)) {
				new_cs->ptr1 = cs->u.array.p1 = flat_to_data(ctx1.type, ctx1.flat);
				if (unlikely(pointer_deep_eval(&cs->u.array.p1, NULL, NULL, &thunk) == POINTER_FOLLOW_THUNK_EXCEPTION)) {
					pointer_dereference(pointer_thunk(thunk));
					return DATA_COMPARE_OOM;
				}
			} else {
				new_cs->ptr1 = *ctx1.ptr;
			}
			if (unlikely(ctx2.flat != NULL)) {
				new_cs->ptr2 = cs->u.array.p2 = flat_to_data(ctx2.type, ctx2.flat);
				if (unlikely(pointer_deep_eval(&cs->u.array.p2, NULL, NULL, &thunk) == POINTER_FOLLOW_THUNK_EXCEPTION)) {
					pointer_dereference(pointer_thunk(thunk));
					return DATA_COMPARE_OOM;
				}
			} else {
				new_cs->ptr2 = *ctx2.ptr;
			}
			index_add_int(&cs->u.array.idx, 1);
			return 2;
		}
	}

	return 0;
}

static void attr_fastcall cs_function_reference_destruct(struct compare_status *cs)
{
	mem_free(cs->u.function_reference.args1);
	mem_free(cs->u.function_reference.args2);
}

static void acquire_function_reference_args(struct data *d, struct function_argument ***args, size_t *n_args, struct data **function)
{
	array_init(struct function_argument *, args, n_args);
	while (1) {
		arg_t ai;
		ai = da(d,function_reference)->n_curried_arguments;
		while (ai--) {
			array_add(struct function_argument *, args, n_args, &da(d,function_reference)->arguments[ai]);
		}
		if (!da(d,function_reference)->is_indirect)
			break;
		d = pointer_get_data(da(d,function_reference)->u.indirect);
	}
	*function = pointer_get_data(*da(d,function_reference)->u.direct);
}

static int attr_fastcall data_compare_function_reference(struct compare_status *cs, struct compare_status *new_cs, bool init)
{
	struct data *d1 = pointer_get_data(cs->ptr1);
	struct data *d2 = pointer_get_data(cs->ptr2);
	if (init) {
		size_t l1, l2;
		struct data *fn1, *fn2;
		acquire_function_reference_args(d1, &cs->u.function_reference.args1, &l1, &fn1);
		acquire_function_reference_args(d2, &cs->u.function_reference.args2, &l2, &fn2);
		cs->destruct = cs_function_reference_destruct;
		if (ptr_to_num(fn1) != ptr_to_num(fn2)) {
			/* !!! FIXME: compare function unique id here */
			if (ptr_to_num(fn1) < ptr_to_num(fn2))
				return -1;
			else
				return 1;
		}
		ajla_assert(l1 == l2, (file_line, "data_compare_function_reference: the number of arguments doesn't match: %"PRIuMAX" != %"PRIuMAX"", (uintmax_t)l1, (uintmax_t)l2));
		cs->u.function_reference.l = l1;
	}
	while (cs->u.function_reference.l--) {
		struct function_argument *a1 = cs->u.function_reference.args1[cs->u.function_reference.l];
		struct function_argument *a2 = cs->u.function_reference.args2[cs->u.function_reference.l];
		if (a1->tag == TYPE_TAG_unknown && a2->tag == TYPE_TAG_unknown) {
			new_cs->ptr1 = a1->u.ptr;
			new_cs->ptr2 = a2->u.ptr;
			return 2;
		} else {
			unsigned char *flat1 = a1->tag != TYPE_TAG_unknown ? a1->u.slot : NULL;
			unsigned char *flat2 = a2->tag != TYPE_TAG_unknown ? a2->u.slot : NULL;
			pointer_t ptr1 = a1->tag != TYPE_TAG_unknown ? pointer_empty() : a1->u.ptr;
			pointer_t ptr2 = a2->tag != TYPE_TAG_unknown ? pointer_empty() : a2->u.ptr;
			type_tag_t tt = a1->tag != TYPE_TAG_unknown ? a1->tag : a2->tag;
			int c = data_compare_numbers(tt, flat1, ptr1, flat2, ptr2);
			if (c)
				return c;
		}
	}
	return 0;
}

static int attr_fastcall data_compare_resource(struct compare_status *cs, struct compare_status attr_unused *new_cs, bool attr_unused init)
{
	uintptr_t p1 = ptr_to_num(pointer_get_data(cs->ptr1));
	uintptr_t p2 = ptr_to_num(pointer_get_data(cs->ptr2));
	if (p1 < p2)
		return -1;
	if (p1 > p2)
		return 1;
	return 0;
}

int attr_fastcall data_compare(pointer_t ptr1, pointer_t ptr2, ajla_error_t *mayfail)
{
	void *err_ptr;
	struct compare_status *cs;
	size_t cs_len, i;
	struct compare_status ccs;
	int c;

	ccs.ptr1 = ptr1;
	ccs.ptr2 = ptr2;
	if (unlikely(!array_init_mayfail(struct compare_status, &cs, &cs_len, mayfail)))
		return DATA_COMPARE_OOM;

new_ptr:
	ccs.tag = da_tag(pointer_get_data(ccs.ptr1));
	ccs.destruct = cs_empty_destruct;
	if (unlikely(!array_add_mayfail(struct compare_status, &cs, &cs_len, ccs, &err_ptr, mayfail))) {
		cs = err_ptr;
		c = DATA_COMPARE_OOM;
		goto ret_c;
	}

	if (pointer_is_equal(ccs.ptr1, ccs.ptr2)) {
		c = 0;
		goto go_up;
	}

	ajla_assert(data_method_table[cs[cs_len - 1].tag].compare == data_method_table[da_tag(pointer_get_data(ccs.ptr2))].compare, (file_line, "data_compare: mismatching tags: %u, %u", cs[cs_len - 1].tag, da_tag(pointer_get_data(ccs.ptr2))));
	c = data_method_table[cs[cs_len - 1].tag].compare(&cs[cs_len - 1], &ccs, true);
test_c:
	if (c) {
		if (c == 2)
			goto new_ptr;
		goto ret_c;
	}

go_up:
	cs[cs_len - 1].destruct(&cs[cs_len - 1]);
	if (--cs_len) {
		c = data_method_table[cs[cs_len - 1].tag].compare(&cs[cs_len - 1], &ccs, false);
		goto test_c;
	}

ret_c:
	for (i = 0; i < cs_len; i++)
		cs[i].destruct(&cs[i]);
	mem_free(cs);
	return c;
}


/*********************
 * DATA SERIALIATION *
 *********************/

static const struct stack_entry_type save_type;

static void no_fixup_after_copy(void attr_unused *new_ptr)
{
}

static void *save_run_get_ptr(struct stack_entry *ste)
{
	void *p;
	memcpy(&p, ste->ptr, sizeof(void *));
	return p;
}

static bool save_run_get_properties(struct stack_entry *ste, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_len)
{
	*align = ste->align;
	*size = ste->size;
	*subptrs = NULL;
	*subptrs_len = 0;
	return true;
}

static void ptr_fixup_sub_ptr(void *loc, uintptr_t offset)
{
#if defined(HAVE_REAL_GNUC) && !GNUC_ATLEAST(3,0,0)	/* EGCS bug */
	*(char **)loc += offset;
#else
	void *p;
	uintptr_t num;
	memcpy(&p, loc, sizeof(void *));
	num = ptr_to_num(p);
	num += offset;
	p = num_to_ptr(num);
	memcpy(loc, &p, sizeof(void *));
#endif
}

static const struct stack_entry_type save_run = {
	save_run_get_ptr,
	save_run_get_properties,
	no_fixup_after_copy,
	ptr_fixup_sub_ptr,
	true,
};

static const struct stack_entry_type save_slice = {
	NULL,
	save_run_get_properties,
	no_fixup_after_copy,
	ptr_fixup_sub_ptr,
	true,
};


static bool save_type_get_properties(struct stack_entry *ste, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_len)
{
	ajla_error_t sink;
	const struct type *t = *cast_ptr(const struct type **, ste->ptr);
	switch (t->tag) {
		case TYPE_TAG_record: {
			struct record_definition *rec = type_def(t,record);
			struct stack_entry *subp;
			size_t i, ii;
			if (unlikely(!((size_t)rec->n_entries + 1)))
				return false;
			subp = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, (size_t)rec->n_entries + 1, sizeof(struct stack_entry), &sink);
			if (unlikely(!subp))
				return false;
			subp[0].t = &save_run;
			subp[0].ptr = &rec->idx_to_frame;
			subp[0].align = align_of(frame_t);
			subp[0].size = rec->n_entries * sizeof(frame_t);
			ii = 1;
			for (i = 0; i < rec->n_entries; i++) {
				frame_t slot = rec->idx_to_frame[i];
				if (unlikely(slot == NO_FRAME_T))
					continue;
				subp[ii].t = &save_type;
				subp[ii].ptr = &rec->types[slot];
				ii++;
			}
			*subptrs = subp;
			*subptrs_len = ii;
			*align = align_of(struct record_definition);
			*size = offsetof(struct record_definition, types[rec->n_slots]);
			break;
		}
		case TYPE_TAG_flat_record: {
			struct flat_record_definition *def = type_def(t,flat_record);
			struct record_definition *rec = type_def(def->base,record);
			struct stack_entry *subp;
			size_t i, ii;
			if (unlikely(!((size_t)rec->n_entries + 1)))
				return false;
			subp = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, (size_t)rec->n_entries + 1, sizeof(struct stack_entry), &sink);
			if (unlikely(!subp))
				return false;
			subp[0].t = &save_type;
			subp[0].ptr = &def->base;
			ii = 1;
			for (i = 0; i < rec->n_entries; i++) {
				frame_t slot = rec->idx_to_frame[i];
				if (unlikely(slot == NO_FRAME_T))
					continue;
				subp[ii].t = &save_type;
				subp[ii].ptr = &def->entries[slot].subtype;
				ii++;
			}
			*align = align_of(struct flat_record_definition);
			*size = offsetof(struct flat_record_definition, entries[rec->n_slots]);
			*subptrs = subp;
			*subptrs_len = ii;
			break;
		}
		case TYPE_TAG_flat_array: {
			struct flat_array_definition *def = type_def(t,flat_array);
			struct stack_entry *subp = mem_alloc_mayfail(struct stack_entry *, sizeof(struct stack_entry), &sink);
			if (unlikely(!subp))
				return false;
			subp->t = &save_type;
			subp->ptr = &def->base;
			*align = align_of(struct flat_array_definition);
			*size = sizeof(struct flat_array_definition);
			*subptrs = subp;
			*subptrs_len = 1;
			break;
		}
		default: {
			TYPE_TAG_VALIDATE(t->tag);
			*align = align_of(struct type);
			*size = sizeof(struct type);
			*subptrs = NULL;
			*subptrs_len = 0;
			break;
		}
	}
	return true;
}

static const struct stack_entry_type save_type = {
	save_run_get_ptr,
	save_type_get_properties,
	no_fixup_after_copy,
	ptr_fixup_sub_ptr,
	true,
};

static void *save_index_get_ptr(struct stack_entry *ste)
{
	array_index_t *idx = ste->ptr;
	mpint_t *mp = index_get_mp(*idx);
	return mp;
}

static bool save_index_get_properties(struct stack_entry *ste, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_len)
{
	ajla_error_t sink;
	mpint_t *mp = save_index_get_ptr(ste);
	struct stack_entry *subp;
	*align = align_of(mpint_t);
	*size = sizeof(mpint_t);
	if (unlikely(!mp->_mp_size)) {
		*subptrs = NULL;
		*subptrs_len = 0;
		return true;
	}
	subp = mem_alloc_mayfail(struct stack_entry *, sizeof(struct stack_entry), &sink);
	if (unlikely(!subp))
		return false;
	subp->t = &save_run;
	subp->ptr = &mp->_mp_d;
	subp->align = align_of(mp_limb_t);
	subp->size = (size_t)abs(mp->_mp_size) * sizeof(mp_limb_t);
	*subptrs = subp;
	*subptrs_len = 1;
	return true;
}

static void save_index_fixup_sub_ptr(void *loc, uintptr_t offset)
{
	array_index_t *idx = loc;
	mpint_t *mp = index_get_mp(*idx);
	mp = num_to_ptr(ptr_to_num(mp) + offset);
	index_set_mp(idx, mp);
}

static const struct stack_entry_type save_index = {
	save_index_get_ptr,
	save_index_get_properties,
	no_fixup_after_copy,
	save_index_fixup_sub_ptr,
	true,
};

static void *save_pointer_get_ptr(struct stack_entry *ste)
{
	pointer_t *ptr = cast_ptr(pointer_t *, ste->ptr);
	pointer_resolve_result(ptr);
	if (likely(!pointer_is_thunk(*ptr)))
		return data_untag(pointer_get_value_strip_tag_(*ptr));
	else
		return thunk_untag(pointer_get_value_strip_tag_(*ptr));
}

static bool save_pointer_get_properties(struct stack_entry *ste, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_len)
{
	return data_save(save_pointer_get_ptr(ste), 0, align, size, subptrs, subptrs_len);
}

static void save_pointer_fixup_after_copy(void *new_ptr)
{
	refcount_set_read_only(da_thunk_refcount(new_ptr));
}

static void save_pointer_fixup_sub_ptr(void *loc, uintptr_t offset)
{
	pointer_t *ptr = loc;
	if (!pointer_is_thunk(*ptr)) {
		uintptr_t num = ptr_to_num(pointer_get_data(*ptr));
		num += offset;
		*ptr = pointer_data(num_to_ptr(num));
	} else {
		uintptr_t num = ptr_to_num(pointer_get_thunk(*ptr));
		num += offset;
		*ptr = pointer_thunk(num_to_ptr(num));
	}
}

static const struct stack_entry_type save_pointer = {
	save_pointer_get_ptr,
	save_pointer_get_properties,
	save_pointer_fixup_after_copy,
	save_pointer_fixup_sub_ptr,
	false,
};

static const struct stack_entry_type save_data_saved = {
	NULL,
	NULL,
	NULL,
	ptr_fixup_sub_ptr,
	false,
};

static bool attr_fastcall no_save(void attr_unused *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t attr_unused *size, struct stack_entry attr_unused **subptrs, size_t attr_unused *subptrs_l)
{
	return false;
}

static bool attr_fastcall save_flat(void *data, uintptr_t attr_unused offset, size_t *align, size_t *size, struct stack_entry attr_unused **subptrs, size_t attr_unused *subptrs_l)
{
	struct data *d = data;
	const struct type *t = type_get_from_tag(da(d,flat)->data_type);
	*align = t->align;
	*size = data_flat_offset + t->size;
	return true;
}

static bool attr_fastcall save_longint(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t attr_unused *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	*size = partial_sizeof(struct data, u_.longint);
	if (unlikely(!da(d,longint)->mp._mp_size)) {
		return true;
	}
	*subptrs = mem_alloc_mayfail(struct stack_entry *, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	(*subptrs)[0].t = &save_run;
	(*subptrs)[0].ptr = &da(d,longint)->mp._mp_d;
	(*subptrs)[0].align = align_of(mp_limb_t);
	(*subptrs)[0].size = (size_t)abs(da(d,longint)->mp._mp_size) * sizeof(mp_limb_t);
	*subptrs_l = 1;
	return true;
}

static bool attr_fastcall save_record(void *data, uintptr_t offset, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	const struct type *t = num_to_ptr(ptr_to_num(da(d,record)->definition) + offset);
	const struct record_definition *def = type_def(t,record);
	frame_s *f;
	frame_t slot;

	*align = def->alignment;
	*size = data_record_offset + def->n_slots * slot_size;

	if (unlikely(!((size_t)def->n_slots + 1)))
		return false;
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, (size_t)def->n_slots + 1, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	(*subptrs)[0].t = &save_type;
	(*subptrs)[0].ptr = &da(d,record)->definition;
	*subptrs_l = 1;

	f = da_record_frame(d);
	slot = def->n_slots;
	while (slot--) {
		char *ch;
		if (!frame_test_flag(f, slot))
			continue;
		ch = cast_ptr(char *, frame_pointer(f, slot));
		(*subptrs)[*subptrs_l].t = &save_pointer;
		(*subptrs)[*subptrs_l].ptr = ch;
		(*subptrs_l)++;
	}
	return true;
}

static bool attr_fastcall save_option(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	*size = partial_sizeof(struct data, u_.option);
	if (!pointer_is_empty(da(d,option)->pointer)) {
		*subptrs = mem_alloc_mayfail(struct stack_entry *, sizeof(struct stack_entry), &sink);
		if (unlikely(!*subptrs))
			return false;
		(*subptrs)[0].t = &save_pointer;
		(*subptrs)[0].ptr = &da(d,option)->pointer;
		*subptrs_l = 1;
	}
	return true;
}

static bool attr_fastcall save_array_flat(void *data, uintptr_t offset, size_t *align, size_t *size, struct stack_entry attr_unused **subptrs, size_t attr_unused *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	const struct type *t = num_to_ptr(ptr_to_num(da(d,array_flat)->type) + offset);
	ajla_assert_lo((da(d,array_flat)->n_allocated_entries | da(d,array_flat)->n_used_entries) >= 0, (file_line, "save_array_flat: negative size %"PRIdMAX", %"PRIdMAX"", (intmax_t)da(d,array_flat)->n_allocated_entries, (intmax_t)da(d,array_flat)->n_used_entries));
	if (da(d,array_flat)->n_allocated_entries != da(d,array_flat)->n_used_entries)
		da(d,array_flat)->n_allocated_entries = da(d,array_flat)->n_used_entries;
	*align = t->align;
	*size = data_array_offset + (size_t)t->size * da(d,array_flat)->n_allocated_entries;
	*subptrs = mem_alloc_mayfail(struct stack_entry *, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	(*subptrs)[0].t = &save_type;
	(*subptrs)[0].ptr = &da(d,array_flat)->type;
	*subptrs_l = 1;
	return true;
}

static bool attr_fastcall save_array_slice(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	ajla_assert_lo(da(d,array_slice)->n_entries >= 0, (file_line, "save_array_slice: negative size %"PRIdMAX"", (intmax_t)da(d,array_slice)->n_entries));
	*size = partial_sizeof(struct data, u_.array_slice);
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, 3, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	(*subptrs)[*subptrs_l].t = &save_pointer;
	(*subptrs)[*subptrs_l].ptr = &da(d,array_slice)->reference;
	(*subptrs_l)++;
	if (da(d,array_slice)->n_entries) {
		(*subptrs)[*subptrs_l].t = &save_slice;
		(*subptrs)[*subptrs_l].ptr = &da(d,array_slice)->flat_data_minus_data_array_offset;
		(*subptrs)[*subptrs_l].align = 1;
		(*subptrs)[*subptrs_l].size = 0;
		(*subptrs_l)++;
	}
	(*subptrs)[*subptrs_l].t = &save_type;
	(*subptrs)[*subptrs_l].ptr = &da(d,array_slice)->type;
	(*subptrs_l)++;
	return true;
}

static bool attr_fastcall save_array_pointers(void *data, uintptr_t offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	size_t n = da(d,array_pointers)->n_used_entries;
	pointer_t *ptr = da(d,array_pointers)->pointer;
	ajla_assert_lo((da(d,array_pointers)->n_allocated_entries | da(d,array_pointers)->n_used_entries) >= 0, (file_line, "save_array_pointers: negative size %"PRIdMAX", %"PRIdMAX"", (intmax_t)da(d,array_pointers)->n_allocated_entries, (intmax_t)da(d,array_pointers)->n_used_entries));
	if (!offset) {
		if (unlikely(ptr != da(d,array_pointers)->pointer_array)) {
			memmove(da(d,array_pointers)->pointer_array, ptr, n * sizeof(pointer_t));
		}
	}
	if (ptr != da(d,array_pointers)->pointer_array)
		da(d,array_pointers)->pointer = da(d,array_pointers)->pointer_array;
	if ((size_t)da(d,array_pointers)->n_allocated_entries != n)
		da(d,array_pointers)->n_allocated_entries = n;
	*size = partial_sizeof_array(struct data, u_.array_pointers.pointer_array, n);
	/*debug("pointers: %zx - %zx", *size, partial_sizeof(struct data, u_.array_pointers.pointer_array[n]));*/
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, n, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	*subptrs_l = n;
	while (n--) {
		(*subptrs)[n].t = &save_pointer;
		(*subptrs)[n].ptr = &da(d,array_pointers)->pointer_array[n];
	}
	return true;
}

static void save_array_index(array_index_t *idx, struct stack_entry **subptrs, size_t *subptrs_l)
{
	index_detach_leak(idx);
	if (likely(!index_is_mp(*idx)))
		return;
	(*subptrs)[*subptrs_l].t = &save_index;
	(*subptrs)[*subptrs_l].ptr = idx;
	(*subptrs_l)++;
}

static bool attr_fastcall save_array_same(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	*size = partial_sizeof(struct data, u_.array_same);
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, 2, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	(*subptrs)[0].t = &save_pointer;
	(*subptrs)[0].ptr = &da(d,array_same)->pointer;
	*subptrs_l = 1;
	save_array_index(&da(d,array_same)->n_entries, subptrs, subptrs_l);
	return true;
}

static bool attr_fastcall save_array_btree(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	size_t n = da(d,array_btree)->n_used_btree_entries;
	size_t i;
	if (da(d,array_btree)->n_allocated_btree_entries != n)
		da(d,array_btree)->n_allocated_btree_entries = n;
	*size = partial_sizeof_array(struct data, u_.array_btree.btree, n);
	/*debug("btree: %zx - %zx", *size, partial_sizeof(struct data, u_.array_btree.btree[n]));*/
	if (unlikely(n * 2 < n))
		return false;
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, n * 2, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	for (i = 0; i < n; i++) {
		(*subptrs)[*subptrs_l].t = &save_pointer;
		(*subptrs)[*subptrs_l].ptr = &da(d,array_btree)->btree[i].node;
		(*subptrs_l)++;
		save_array_index(&da(d,array_btree)->btree[i].end_index, subptrs, subptrs_l);
	}
	return true;
}

static bool attr_fastcall save_array_incomplete(void attr_unused *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	*size = partial_sizeof(struct data, u_.array_incomplete);
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, 2, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	(*subptrs)[0].t = &save_pointer;
	(*subptrs)[0].ptr = &da(d,array_incomplete)->first;
	(*subptrs)[1].t = &save_pointer;
	(*subptrs)[1].ptr = &da(d,array_incomplete)->next;
	*subptrs_l = 2;
	return true;
}

static bool attr_fastcall save_function_types(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry attr_unused **subptrs, size_t attr_unused *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	size_t i;
	*size = data_function_types_offset + da(d,function_types)->n_types * sizeof(const struct type *);
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, da(d,function_types)->n_types, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	for (i = 0; i < da(d,function_types)->n_types; i++) {
		(*subptrs)[i].t = &save_type;
		(*subptrs)[i].ptr = &da(d,function_types)->types[i];
	}
	*subptrs_l = da(d,function_types)->n_types;
	return true;
}

static bool attr_fastcall save_saved(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	size_t i;
	*size = da(d,saved)->total_size;
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, da(d,saved)->n_offsets, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	*subptrs_l = da(d,saved)->n_offsets;
	for (i = 0; i < da(d,saved)->n_offsets; i++) {
		(*subptrs)[i].t = &save_data_saved;
		(*subptrs)[i].ptr = cast_ptr(char *, d) + da(d,saved)->offsets[i];
	}
	return true;
}

static bool attr_fastcall save_saved_cache(void *data, uintptr_t attr_unused offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct data *d = data;
	size_t i;
	size_t n_pointers = da(d,saved_cache)->n_entries * (da(d,saved_cache)->n_arguments + da(d,saved_cache)->n_return_values);
	*size = offsetof(struct data, u_.saved_cache.pointers[n_pointers]);
	*subptrs = mem_alloc_array_mayfail(mem_alloc_mayfail, struct stack_entry *, 0, 0, n_pointers, sizeof(struct stack_entry), &sink);
	if (unlikely(!*subptrs))
		return false;
	*subptrs_l = n_pointers;
	for (i = 0; i < n_pointers; i++) {
		(*subptrs)[i].t = &save_pointer;
		(*subptrs)[i].ptr = &da(d,saved_cache)->pointers[i];
	}
	return true;
}

static bool attr_fastcall save_exception(void *data, uintptr_t offset, size_t attr_unused *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	ajla_error_t sink;
	struct thunk *t = data;
	if (t->u.exception.tr.trace_n) {
		stack_trace_free(&t->u.exception.tr);
		stack_trace_init(&t->u.exception.tr);
	}
	if (t->u.exception.err.error_class == EC_ASYNC)
		return false;
	*size = partial_sizeof(struct thunk, u.exception);
	if (t->u.exception.msg) {
		const char *msg = num_to_ptr(ptr_to_num(t->u.exception.msg) + offset);
		*subptrs = mem_alloc_mayfail(struct stack_entry *, sizeof(struct stack_entry), &sink);
		if (unlikely(!*subptrs))
			return false;
		(*subptrs)[0].t = &save_run;
		(*subptrs)[0].ptr = &t->u.exception.msg;
		(*subptrs)[0].align = align_of(char);
		(*subptrs)[0].size = strlen(msg) + 1;
		*subptrs_l = 1;
	}
	return true;
}

bool data_save(void *p, uintptr_t offset, size_t *align, size_t *size, struct stack_entry **subptrs, size_t *subptrs_l)
{
	tag_t tag = da_thunk_tag(p);
	if (tag >= DATA_TAG_START && tag < DATA_TAG_END) {
		p = data_pointer_tag(p, tag);
	} else {
		p = thunk_pointer_tag(p);
	}
	*align = 1;
	*subptrs = NULL;
	*subptrs_l = 0;
	if (unlikely(!data_method_table[tag].save(p, offset, align, size, subptrs, subptrs_l))) {
#if 0
		debug("failure on tag: %u", tag);
		if (tag == THUNK_TAG_FUNCTION_CALL) {
			struct thunk *t = p;
			pointer_t ref;
			ref = t->u.function_call.u.function_reference;
			while (1) {
				if (pointer_is_thunk(ref)) {
					debug("ref is thunk");
					goto ret;
				}
				if (!da(pointer_get_data(ref),function_reference)->is_indirect)
					break;
				ref = da(pointer_get_data(ref),function_reference)->u.indirect;
			}
			ref = *da(pointer_get_data(ref),function_reference)->u.direct;
			if (pointer_is_thunk(ref)) {
				debug("function not evaluated");
				goto ret;
			}
			debug("function: '%s'", da(pointer_get_data(ref),function)->function_name);
		}
		ret:
#endif
		return false;
	}
	*align = maximum(*align, SAVED_DATA_ALIGN);
	return true;
}

bool data_save_init_stack(pointer_t *ptr, struct stack_entry **stk, size_t *stk_l)
{
	struct stack_entry ste;
	ajla_error_t sink;
	if (unlikely(!array_init_mayfail(struct stack_entry, stk, stk_l, &sink)))
		return false;
	ste.t = &save_pointer;
	ste.ptr = ptr;
	ste.align = ste.size = 0;	/* avoid warning */
	if (unlikely(!array_add_mayfail(struct stack_entry, stk, stk_l, ste, NULL, &sink)))
		return false;
	return true;
}

#ifdef HAVE_CODEGEN_TRAPS
static int data_traps_tree_compare(const struct tree_entry *e, uintptr_t ptr)
{
	const struct data_codegen *dc = get_struct(e, struct data_codegen, codegen_tree);
	uintptr_t base = ptr_to_num(dc->unoptimized_code_base);
	if (ptr < base)
		return 1;
	if (ptr >= base + dc->unoptimized_code_size)
		return -1;
	return 0;
}

void *data_trap_lookup(void *ptr)
{
	uintptr_t offset;
	size_t res;
	struct tree_entry *e;
	const struct data_codegen *dc;
	uintptr_t ptr_num = ptr_to_num(ptr);

	rwmutex_lock_read(&traps_lock);
	e = tree_find(&traps_tree, data_traps_tree_compare, ptr_num);
	if (unlikely(!e))
		internal(file_line, "data_trap_lookup: could not find function for address %p", ptr);
	rwmutex_unlock_read(&traps_lock);
	dc = get_struct(e, struct data_codegen, codegen_tree);

	offset = ptr_num - ptr_to_num(dc->unoptimized_code_base);

	binary_search(size_t, dc->trap_records_size, res, dc->trap_records[res].source_ip == offset, dc->trap_records[res].source_ip < offset,
		internal(file_line, "data_trap_lookup(%s): could not find trap for address %p, offset %"PRIxMAX"", da(dc->function,function)->function_name, ptr, (uintmax_t)offset));

	return cast_ptr(char *, dc->unoptimized_code_base) + dc->trap_records[res].destination_ip;
}

void data_trap_insert(struct data *codegen)
{
	struct tree_insert_position ins;
	struct tree_entry *e;
#ifndef DEBUG_CRASH_HANDLER
	if (!da(codegen,codegen)->trap_records_size)
		return;
#endif
	/*debug("inserting trap for %p, %lx", da(codegen,codegen)->unoptimized_code_base, da(codegen,codegen)->unoptimized_code_size);*/
	rwmutex_lock_write(&traps_lock);
	e = tree_find_for_insert(&traps_tree, data_traps_tree_compare, ptr_to_num(da(codegen,codegen)->unoptimized_code_base), &ins);
	if (unlikely(e != NULL))
		internal(file_line, "data_insert_traps: the requested range is already in the tree");
	tree_insert_after_find(&da(codegen,codegen)->codegen_tree, &ins);
	rwmutex_unlock_write(&traps_lock);
}
#endif

void name(data_init)(void)
{
	unsigned i;
	struct thunk *oom;

	if (slot_size < sizeof(pointer_t))
		internal(file_line, "data_init: invalid slot size: %lu < %lu", (unsigned long)slot_size, (unsigned long)sizeof(pointer_t));

	refcount_init(&n_dereferenced);

	for (i = DATA_TAG_START; i < DATA_TAG_END; i++) {
		data_method_table[i].get_sub = no_sub;
		data_method_table[i].free_object = free_primitive;
		data_method_table[i].deep_eval = deep_eval_nothing;
		data_method_table[i].compare = data_compare_nothing;
		data_method_table[i].save = no_save;
	}
	for (i = THUNK_TAG_START; i < THUNK_TAG_END; i++) {
		data_method_table[i].free_object = free_primitive_thunk;
		data_method_table[i].save = no_save;
	}

	data_method_table[DATA_TAG_longint].free_object = free_integer;
	data_method_table[DATA_TAG_array_same].free_object = free_array_same;
	data_method_table[DATA_TAG_resource].free_object = free_resource;
	data_method_table[DATA_TAG_function].free_object = free_function;
#ifdef HAVE_CODEGEN
	data_method_table[DATA_TAG_codegen].free_object = free_codegen;
#endif
	data_method_table[DATA_TAG_record].get_sub = get_sub_record;
	data_method_table[DATA_TAG_option].get_sub = get_sub_option;
	data_method_table[DATA_TAG_array_slice].get_sub = get_sub_array_slice;
	data_method_table[DATA_TAG_array_pointers].get_sub = get_sub_array_pointers;
	data_method_table[DATA_TAG_array_same].get_sub = get_sub_array_same;
	data_method_table[DATA_TAG_array_btree].get_sub = get_sub_array_btree;
	data_method_table[DATA_TAG_array_incomplete].get_sub = get_sub_array_incomplete;
	data_method_table[DATA_TAG_function_reference].get_sub = get_sub_function_reference;

	data_method_table[THUNK_TAG_FUNCTION_CALL].get_sub = get_sub_function_call;
	data_method_table[THUNK_TAG_BLACKHOLE].get_sub = get_sub_blackhole;
	data_method_table[THUNK_TAG_BLACKHOLE].free_object = free_none;
	data_method_table[THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED].get_sub = get_sub_blackhole_some_dereferenced;
	data_method_table[THUNK_TAG_BLACKHOLE_SOME_DEREFERENCED].free_object = free_none;
	data_method_table[THUNK_TAG_BLACKHOLE_DEREFERENCED].get_sub = get_sub_blackhole_dereferenced;
	data_method_table[THUNK_TAG_BLACKHOLE_DEREFERENCED].free_object = free_blackhole_dereferenced;
	data_method_table[THUNK_TAG_RESULT].get_sub = get_sub_result;
	data_method_table[THUNK_TAG_MULTI_RET_REFERENCE].get_sub = get_sub_multi_ret_reference;
	data_method_table[THUNK_TAG_EXCEPTION].get_sub = get_sub_exception;
	data_method_table[THUNK_TAG_EXCEPTION].free_object = free_exception;

	data_method_table[DATA_TAG_flat].deep_eval = deep_eval_flat;
	data_method_table[DATA_TAG_record].deep_eval = deep_eval_record;
	data_method_table[DATA_TAG_option].deep_eval = deep_eval_option;
	data_method_table[DATA_TAG_array_flat].deep_eval = deep_eval_array_flat;
	data_method_table[DATA_TAG_array_slice].deep_eval = deep_eval_array_slice;
	data_method_table[DATA_TAG_array_pointers].deep_eval = deep_eval_array_pointers;
	data_method_table[DATA_TAG_array_same].deep_eval = deep_eval_array_same;
	data_method_table[DATA_TAG_array_btree].deep_eval = deep_eval_array_btree;
	data_method_table[DATA_TAG_array_incomplete].deep_eval = deep_eval_array_incomplete;
	data_method_table[DATA_TAG_function_reference].deep_eval = deep_eval_function_reference;

	data_method_table[DATA_TAG_flat].compare = data_compare_number;
	data_method_table[DATA_TAG_longint].compare = data_compare_number;
	data_method_table[DATA_TAG_record].compare = data_compare_record;
	data_method_table[DATA_TAG_option].compare = data_compare_option;
	data_method_table[DATA_TAG_array_flat].compare = data_compare_array;
	data_method_table[DATA_TAG_array_slice].compare = data_compare_array;
	data_method_table[DATA_TAG_array_pointers].compare = data_compare_array;
	data_method_table[DATA_TAG_array_same].compare = data_compare_array;
	data_method_table[DATA_TAG_array_btree].compare = data_compare_array;
	data_method_table[DATA_TAG_array_incomplete].compare = data_compare_array;
	data_method_table[DATA_TAG_function_reference].compare = data_compare_function_reference;
	data_method_table[DATA_TAG_resource].compare = data_compare_resource;

	data_method_table[DATA_TAG_flat].save = save_flat;
	data_method_table[DATA_TAG_longint].save = save_longint;
	data_method_table[DATA_TAG_record].save = save_record;
	data_method_table[DATA_TAG_option].save = save_option;
	data_method_table[DATA_TAG_array_flat].save = save_array_flat;
	data_method_table[DATA_TAG_array_slice].save = save_array_slice;
	data_method_table[DATA_TAG_array_pointers].save = save_array_pointers;
	data_method_table[DATA_TAG_array_same].save = save_array_same;
	data_method_table[DATA_TAG_array_btree].save = save_array_btree;
	data_method_table[DATA_TAG_array_incomplete].save = save_array_incomplete;
	data_method_table[DATA_TAG_function_types].save = save_function_types;
	data_method_table[DATA_TAG_saved].save = save_saved;
	data_method_table[DATA_TAG_saved_cache].save = save_saved_cache;
	data_method_table[THUNK_TAG_EXCEPTION].save = save_exception;

	oom = thunk_alloc_exception_mayfail(error_ajla(EC_ASYNC, AJLA_ERROR_OUT_OF_MEMORY), NULL pass_file_line);
	out_of_memory_thunk = pointer_thunk(oom);

#ifdef HAVE_CODEGEN_TRAPS
	rwmutex_init(&traps_lock);
	tree_init(&traps_tree);
#endif
}

void name(data_done)(void)
{
	if (unlikely(!refcount_is_one(&n_dereferenced)))
		internal(file_line, "data_done: n_dereferenced_leaked: %"PRIxMAX"", (uintmax_t)refcount_get_nonatomic(&n_dereferenced));

#ifdef HAVE_CODEGEN_TRAPS
	rwmutex_done(&traps_lock);
	ajla_assert_lo(tree_is_empty(&traps_tree), (file_line, "data_done: traps_tree is not empty"));
#endif
	pointer_dereference(out_of_memory_thunk);
}

#endif
