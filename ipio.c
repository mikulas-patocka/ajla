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

#include <fcntl.h>

#include "ipunalg.h"
#include "data.h"
#include "arindex.h"
#include "array.h"
#include "arrayu.h"
#include "tick.h"
#include "obj_reg.h"
#include "os.h"
#include "iomux.h"
#include "timer.h"
#include "resolver.h"
#include "ipfn.h"
#include "module.h"
#include "pcode.h"
#include "args.h"
#include "builtin.h"
#include "save.h"
#include "task.h"
#include "ipret.h"

#include "ipio.h"

#if defined(OS_HAS_DLOPEN) && defined(HAVE_LIBFFI)
#include <ffi.h>
#define SUPPORTS_FFI
#endif

#ifndef PIPE_BUF
#define PIPE_BUF	512
#endif

#if !defined(OS_WIN32)
extern char **environ;
#endif

struct resource_handle {
	handle_t fd;
	bool nonblocking;
	os_termios_t *old_termios;
};

struct resource_dir_handle {
	dir_handle_t fd;
};

struct resource_notify_handle {
	notify_handle_t id;
	uint64_t seq;
};

struct resource_proc_handle {
	struct proc_handle *ph;
};

struct msgqueue_entry {
	pointer_t tag;
	pointer_t ptr;
};

struct resource_msgqueue {
	struct msgqueue_entry *queue;
	size_t queue_len;
	size_t queue_allocated;
	struct list wait_list;
	struct list list_entry;
};

static mutex_t lib_path_mutex;
static char *lib_path;
static size_t lib_path_len;

static mutex_t msgqueue_list_mutex;
static struct list msgqueue_list;

#define IO_STATUS_STARTED	0
#define IO_STATUS_PROGRESS	1
#define IO_STATUS_TIMEOUT	2
#define IO_STATUS_IOERR		3
#define IO_STATUS_THUNK		4
#define IO_STATUS_BLOCKED	5

struct io_ctx {
	frame_s *fp;
	const code_t *ip;
	const code_t *outputs;
	const code_t *inputs;
	const code_t *params;
	uchar_efficient_t n_outputs;
	uchar_efficient_t n_inputs;
	uchar_efficient_t n_params;
	uchar_efficient_t status;

	ajla_error_t err;

	uchar_efficient_t code;

	tick_stamp_t ts;
	pointer_t *array_ptr;

	char *str;
	size_t str_l;
	char *str2;
	size_t str2_l;

	char **strs;
	size_t strs_l;

	void **ptrs;
	size_t ptrs_l;

	handle_t *h_src;
	size_t h_src_l;
	int *h_dst;
	size_t h_dst_l;

	uchar_efficient_t *args;
	size_t args_l;

	struct resource_ffi *rf;

	struct resource_handle *handle;
	struct resource_handle *handle2;
	struct resource_dir_handle *dir_handle;
	struct resource_dir_handle *dir_handle2;
	struct resource_msgqueue *msgqueue;
	os_off_t position;
	os_off_t position2;
	os_off_t length;
};

static void handle_no_close(struct data *d)
{
	struct resource_handle *h = da_resource(d);
	if (unlikely(h->old_termios != NULL)) {
		ajla_error_t sink;
		os_tcsetattr(h->fd, h->old_termios, &sink);
		mem_free(h->old_termios);
	}
}

static void handle_close(struct data *d)
{
	struct resource_handle *h;
	handle_no_close(d);
	h = da_resource(d);
	os_close(h->fd);
}

static void dir_handle_close(struct data *d)
{
	struct resource_dir_handle *h = da_resource(d);
	if (dir_handle_is_valid(h->fd))
		os_dir_close(h->fd);
}

static void notify_handle_close(struct data *d)
{
	struct resource_notify_handle *h = da_resource(d);
	iomux_directory_handle_free(h->id);
}

static void proc_handle_close(struct data *d)
{
	struct resource_proc_handle *rph = da_resource(d);
	os_proc_free_handle(rph->ph);
}

static void msgqueue_close(struct data *d)
{
	size_t i;
	struct resource_msgqueue *q = da_resource(d);

	mutex_lock(&msgqueue_list_mutex);
	list_del(&q->list_entry);
	mutex_unlock(&msgqueue_list_mutex);

	for (i = 0; i < q->queue_len; i++) {
		struct msgqueue_entry *qe = &q->queue[i];
		pointer_dereference(qe->tag);
		pointer_dereference(qe->ptr);
	}
	mem_free(q->queue);
}

#define verify_file_handle(d)						\
do {									\
	struct resource_handle *h;					\
	if (da(d,resource)->close == handle_no_close)			\
		break;							\
	h = da_resource(d);						\
	obj_registry_verify(OBJ_TYPE_HANDLE, (obj_id)h->fd, file_line);	\
} while (0)

#ifndef NO_DIR_HANDLES
#define verify_dir_handle(d)						\
do {									\
	struct resource_dir_handle *h;					\
	h = da_resource(d);						\
	if (dir_handle_is_valid(h->fd))					\
		obj_registry_verify(OBJ_TYPE_HANDLE, (obj_id)h->fd, file_line);\
} while (0)
#else
#define verify_dir_handle(d)	do { } while (0)
#endif

static inline frame_t get_output(const struct io_ctx *ctx, unsigned offset)
{
	ajla_assert(offset < ctx->n_outputs, (file_line, "get_output: invalid output %u >= %u", offset, (unsigned)ctx->n_outputs));
	return get_unaligned_32(ctx->outputs + offset * 2);
}

static inline frame_t get_input(const struct io_ctx *ctx, unsigned offset)
{
	ajla_assert(offset < ctx->n_inputs, (file_line, "get_input: invalid input %u >= %u", offset, (unsigned)ctx->n_inputs));
	return get_unaligned_32(ctx->inputs + offset * 2);
}

static inline frame_t get_param(const struct io_ctx *ctx, unsigned offset)
{
	ajla_assert(offset < ctx->n_params, (file_line, "get_param: invalid param %u >= %u", offset, (unsigned)ctx->n_params));
	return get_unaligned_32(ctx->params + offset * 2);
}

static void io_terminate_with_thunk(struct io_ctx *ctx, struct thunk *thunk)
{
	unsigned i;

	pointer_reference_owned_multiple(pointer_thunk(thunk), ctx->n_outputs);

	for (i = 0; i < ctx->n_outputs; i++)
		frame_free_and_set_pointer(ctx->fp, get_output(ctx, i), pointer_thunk(thunk));

	pointer_dereference(pointer_thunk(thunk));
}

static void io_terminate_with_error(struct io_ctx *ctx, ajla_error_t err, bool stack_trace, char *msg)
{
	struct thunk *t = thunk_alloc_exception_error(err, msg, stack_trace ? ctx->fp : NULL, stack_trace ? ctx->ip : NULL pass_file_line);
	io_terminate_with_thunk(ctx, t);
}

static void *io_deep_eval(struct io_ctx *ctx, const char *input_positions, bool copy_world)
{
	for (; *input_positions; input_positions++) {
		void *ex;
		struct thunk *thunk;
		frame_t slot = get_input(ctx, *input_positions - '0');
		ex = frame_pointer_deep_eval(ctx->fp, ctx->ip, slot, &thunk);
		if (likely(ex == POINTER_FOLLOW_THUNK_GO))
			continue;
		if (ex == POINTER_FOLLOW_THUNK_EXCEPTION) {
			io_terminate_with_thunk(ctx, thunk);
		}
		return ex;
	}

	if (copy_world) {
		ajla_assert_lo(get_input(ctx, 0) != get_output(ctx, 0), (file_line, "io_deep_eval: input and output slot is the same"));
		frame_free(ctx->fp, get_output(ctx, 0));
		ipret_copy_variable(ctx->fp, get_input(ctx, 0), ctx->fp, get_output(ctx, 0), false);
	}

	return POINTER_FOLLOW_THUNK_GO;
}

static void io_get_handle(struct io_ctx *ctx, frame_t slot)
{
	pointer_t ptr;
	struct data *d;
	struct resource_handle *h;

	ptr = *frame_pointer(ctx->fp, slot);
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_get_handle: pointer is thunk"));
	d = pointer_get_data(ptr);

	h = da_resource(d);
	ctx->handle = h;

	verify_file_handle(d);
}

static void io_get_dir_handle(struct io_ctx *ctx, frame_t slot)
{
	pointer_t ptr;
	struct data *d;
	struct resource_dir_handle *h;

	ptr = *frame_pointer(ctx->fp, slot);
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_get_dir_handle: pointer is thunk"));
	d = pointer_get_data(ptr);

	h = da_resource(d);
	ctx->dir_handle = h;

	verify_dir_handle(d);
}

static void io_block_on_handle(struct io_ctx *ctx, bool wr, bool attr_unused packet_mode)
{
	struct execution_control *ex = frame_execution_control(ctx->fp);
#if defined(OS_DOS)
	if (packet_mode) {
		dos_wait_on_packet(&ex->wait[0].mutex_to_lock, &ex->wait[0].wait_entry);
	} else
#endif
	{
		iomux_register_wait(ctx->handle->fd, wr, &ex->wait[0].mutex_to_lock, &ex->wait[0].wait_entry);
	}
	pointer_follow_wait(ctx->fp, ctx->ip);
}


static unsigned char *io_get_flat_pointer(struct io_ctx *ctx, frame_t slot)
{
	if (likely(frame_variable_is_flat(ctx->fp, slot))) {
		return frame_var(ctx->fp, slot);
	} else {
		pointer_t ptr;
		struct data *d;
		ptr = *frame_pointer(ctx->fp, slot);
		ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_get_flat_pointer: pointer is thunk"));
		d = pointer_get_data(ptr);
		ajla_assert_lo(da_tag(d) == DATA_TAG_flat, (file_line, "io_get_flat_pointer: invalid data tag %u", da_tag(d)));
		return da_flat(d);
	}
}

static void io_get_pcode_t(struct io_ctx *ctx, frame_t slot, pcode_t *result)
{
	unsigned char *ptr;
	ajla_assert(frame_get_type_of_local(ctx->fp, slot)->tag == type_get_fixed(2, false)->tag, (file_line, "io_get_pcode_t: invalid type %u", (unsigned)frame_get_type_of_local(ctx->fp, slot)->tag));
	ptr = io_get_flat_pointer(ctx, slot);
	barrier_aliasing();
	*result = *cast_ptr(pcode_t *, ptr);
	barrier_aliasing();
}

static void attr_unused io_get_int32_t(struct io_ctx *ctx, frame_t slot, int32_t *result, const mpint_t **mp)
{
	ajla_assert(frame_get_type_of_local(ctx->fp, slot)->tag == type_get_int(2)->tag ||
		    frame_get_type_of_local(ctx->fp, slot)->tag == type_get_fixed(2, false)->tag ||
		    frame_get_type_of_local(ctx->fp, slot)->tag == type_get_fixed(2, true)->tag, (file_line, "io_get_int32_t: invalid type %u", (unsigned)frame_get_type_of_local(ctx->fp, slot)->tag));
	if (mp)
		*mp = NULL;
	if (likely(!frame_test_flag(ctx->fp, slot))) {
		barrier_aliasing();
		*result = *frame_slot(ctx->fp, slot, int32_t);
		barrier_aliasing();
	} else {
		pointer_t ptr;
		struct data *d;
		ptr = *frame_pointer(ctx->fp, slot);
		ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_get_int32_t: pointer is thunk"));
		d = pointer_get_data(ptr);
		if (da_tag(d) == DATA_TAG_flat) {
			*result = *cast_ptr(int32_t *, da_flat(d));
		} else if (likely(da_tag(d) == DATA_TAG_longint)) {
			if (unlikely(!mp))
				internal(file_line, "io_get_int32: unexpected long int");
			*mp = &da(d,longint)->mp;
		} else {
			internal(file_line, "io_get_int32_t: invalid data tag %u", da_tag(d));
		}
	}
}

static void io_get_int64_t(struct io_ctx *ctx, frame_t slot, int64_t *result, const mpint_t **mp)
{
	ajla_assert(frame_get_type_of_local(ctx->fp, slot)->tag == type_get_int(3)->tag ||
		    frame_get_type_of_local(ctx->fp, slot)->tag == type_get_fixed(3, false)->tag ||
		    frame_get_type_of_local(ctx->fp, slot)->tag == type_get_fixed(3, true)->tag, (file_line, "io_get_int64_t: invalid type %u", (unsigned)frame_get_type_of_local(ctx->fp, slot)->tag));
	if (mp)
		*mp = NULL;
	if (likely(!frame_test_flag(ctx->fp, slot))) {
		barrier_aliasing();
		*result = *frame_slot(ctx->fp, slot, int64_t);
		barrier_aliasing();
	} else {
		pointer_t ptr;
		struct data *d;
		ptr = *frame_pointer(ctx->fp, slot);
		ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_get_int64: pointer is thunk"));
		d = pointer_get_data(ptr);
		if (da_tag(d) == DATA_TAG_flat) {
			*result = *cast_ptr(int64_t *, da_flat(d));
		} else if (likely(da_tag(d) == DATA_TAG_longint)) {
			if (unlikely(!mp))
				internal(file_line, "io_get_int64: unexpected long int");
			*mp = &da(d,longint)->mp;
		} else {
			internal(file_line, "io_get_int64: invalid data tag %u", da_tag(d));
		}
	}
}

static void io_get_option(struct io_ctx *ctx, frame_t slot, ajla_option_t *result, struct data **pointer)
{
	if (likely(frame_variable_is_flat(ctx->fp, slot))) {
		ajla_assert(frame_get_type_of_local(ctx->fp, slot)->tag == TYPE_TAG_flat_option, (file_line, "io_get_int32_t: invalid type %u", (unsigned)frame_get_type_of_local(ctx->fp, slot)->tag));
		*result = *frame_slot(ctx->fp, slot, ajla_flat_option_t);
		if (pointer)
			*pointer = NULL;
	} else {
		pointer_t ptr;
		struct data *d;
		ptr = *frame_pointer(ctx->fp, slot);
		ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_get_option: pointer is thunk"));
		d = pointer_get_data(ptr);
		ajla_assert_lo(da_tag(d) == DATA_TAG_option, (file_line, "io_get_option: invalid data tag %u", da_tag(d)));
		*result = da(d,option)->option;
		if (pointer) {
			if (!pointer_is_empty(da(d,option)->pointer))
				*pointer = pointer_get_data(da(d,option)->pointer);
			else
				*pointer = NULL;
		}
	}
}

static void *io_get_array_index(struct io_ctx *ctx, frame_s *fp_slot, frame_t slot, array_index_t *i argument_position)
{
	pointer_t thunk;
	void *ex = ipret_get_index(ctx->fp, ctx->ip, fp_slot, slot, false, i, &thunk pass_position);
	if (unlikely(ex == POINTER_FOLLOW_THUNK_EXCEPTION)) {
		io_terminate_with_thunk(ctx, pointer_get_thunk(thunk));
	}
	return ex;
}

static void io_store_flat_option(struct io_ctx *ctx, frame_t slot, ajla_flat_option_t val)
{
	ajla_assert(frame_get_type_of_local(ctx->fp, slot)->tag == TYPE_TAG_flat_option, (file_line, "io_store_flat_option: invalid type %u", (unsigned)frame_get_type_of_local(ctx->fp, slot)->tag));
	frame_free(ctx->fp, slot);
	barrier_aliasing();
	*frame_slot(ctx->fp, slot, ajla_flat_option_t) = val;
	barrier_aliasing();
}

static void io_store_integer(struct io_ctx *ctx, frame_t slot, array_index_t val)
{
	ajla_assert(frame_get_type_of_local(ctx->fp, slot)->tag == type_get_int(INT_DEFAULT_N)->tag, (file_line, "io_store_integer: invalid type %u", (unsigned)frame_get_type_of_local(ctx->fp, slot)->tag));
	frame_free(ctx->fp, slot);
	if (likely(index_is_int(val))) {
		barrier_aliasing();
		*frame_slot(ctx->fp, slot, int_default_t) = index_to_int(val);
		barrier_aliasing();
	} else {
		struct data *d;
		d = data_alloc_longint_mayfail(sizeof(int_default_t) * 16, NULL pass_file_line);
		index_to_mpint(val, &da(d,longint)->mp);
		frame_set_pointer(ctx->fp, slot, pointer_data(d));
	}
}

#define io_get_positive_number(ctx, fp_slot, slot, result_type_, result_)\
do {									\
	array_index_t int_;						\
	result_type_ r_ = 0;	/* avoid warning */			\
	result_ = 0;		/* avoid warning */			\
									\
	test = io_get_array_index(ctx, fp_slot, slot, &int_ pass_file_line);\
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))			\
		break;							\
									\
	if (likely(index_is_int(int_))) {				\
		int_default_t id = index_to_int(int_);			\
		r_ = id;						\
		if ((is_unsigned(result_type_) && unlikely(id < 0)) ||	\
		    unlikely((int_default_t)r_ != id)) {		\
			index_free(&int_);				\
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), true, NULL);\
			test = POINTER_FOLLOW_THUNK_EXCEPTION;		\
			break;						\
		}							\
	} else {							\
		bool success;						\
		if (sizeof(result_type_) < sizeof(int_default_t) ||	\
		   (sizeof(result_type_) == sizeof(int_default_t) && !is_unsigned(result_type_))) {\
			index_free(&int_);				\
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), true, NULL);\
			test = POINTER_FOLLOW_THUNK_EXCEPTION;		\
			break;						\
		}							\
		mpint_export_to_variable(index_get_mp(int_), result_type_, r_, success);\
		if (unlikely(!success)) {				\
			index_free(&int_);				\
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), true, NULL);\
			test = POINTER_FOLLOW_THUNK_EXCEPTION;		\
			break;						\
		}							\
	}								\
	test = POINTER_FOLLOW_THUNK_GO;					\
	index_free(&int_);						\
	result_ = r_;							\
} while (0)

#define io_get_number(ctx, slot, slot_type_, result_type_, result_)	\
do {									\
	slot_type_ int_;						\
	const mpint_t *mp_;						\
	result_type_ r_ = 0;						\
	cat(io_get_,slot_type_)(ctx, slot, &int_, &mp_);		\
	if (likely(!mp_)) {						\
		r_ = int_;						\
		if ((is_unsigned(result_type_) && unlikely(int_ < 0)) ||\
		    unlikely((slot_type_)r_ != int_)) {			\
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), true, NULL);\
			test = POINTER_FOLLOW_THUNK_EXCEPTION;		\
			break;						\
		}							\
	} else {							\
		bool success;						\
		mpint_export_to_variable(mp_, result_type_, r_, success);\
		if (unlikely(!success)) {				\
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE), true, NULL);\
			test = POINTER_FOLLOW_THUNK_EXCEPTION;		\
			break;						\
		}							\
	}								\
	test = POINTER_FOLLOW_THUNK_GO;					\
	result_ = r_;							\
} while (0)

#define io_store_typed_number(ctx, slot, slot_type_, slot_type_idx, result_type_, result_)\
do {									\
	result_type_ r_;						\
	ajla_assert(frame_get_type_of_local(ctx->fp, slot)->tag == type_get_int(slot_type_idx)->tag, (file_line, "io_store_typed_number: invalid type %u, expected %u", (unsigned)frame_get_type_of_local(ctx->fp, slot)->tag, (unsigned)type_get_int(slot_type_idx)->tag));\
	r_ = (result_);							\
	frame_free(ctx->fp, slot);					\
	if (!(is_unsigned(result_type_) && unlikely((slot_type_)(r_) < (slot_type_)zero)) &&\
	    likely((r_) == (result_type_)(slot_type_)(r_))) {		\
		barrier_aliasing();					\
		*frame_slot(ctx->fp, slot, slot_type_) = (r_);		\
		barrier_aliasing();					\
	} else {							\
		struct data *d;						\
		d = data_alloc_longint_mayfail(sizeof(result_type_) * 8, &ctx->err pass_file_line);\
		if (unlikely(!d)) {					\
			io_terminate_with_error(ctx, ctx->err, true, NULL);\
			test = POINTER_FOLLOW_THUNK_EXCEPTION;		\
			break;						\
		}							\
		mpint_import_from_variable(&da(d,longint)->mp, result_type_, r_);\
		frame_set_pointer(ctx->fp, slot, pointer_data(d));	\
	}								\
	test = POINTER_FOLLOW_THUNK_GO;					\
} while (0)

#define io_get_time(ctx, slot, result)					\
	io_get_number(ctx, slot, int64_t, int64_t, result)
#define io_store_time(ctx, slot, result)				\
	io_store_typed_number(ctx, slot, int64_t, 3, ajla_time_t, result)

static void io_get_bytes(struct io_ctx *ctx, frame_t slot)
{
	array_onstack_to_bytes(ctx->fp, slot, &ctx->str, &ctx->str_l);
}

static void io_get_bytes2(struct io_ctx *ctx, frame_t slot)
{
	array_onstack_to_bytes(ctx->fp, slot, &ctx->str2, &ctx->str2_l);
}

static void free_strings(struct io_ctx *ctx)
{
	size_t i;
	for (i = 0; i < ctx->strs_l; i++) {
		if (ctx->strs[i])
			mem_free(ctx->strs[i]);
	}
	mem_free(ctx->strs);
}

static int_default_t io_get_strings_callback(unsigned char *flat, const struct type attr_unused * type, int_default_t n_elements, pointer_t *ptr, void *ctx_)
{
	struct io_ctx *ctx = cast_ptr(struct io_ctx *, ctx_);
	if (unlikely(flat != NULL)) {
		internal(file_line, "io_get_strings_callback: flat type");
	} else {
		char *str;
		size_t str_l;
		array_to_bytes(ptr, &str, &str_l);
		array_add(char *, &ctx->strs, &ctx->strs_l, str);
	}
	return n_elements;
}

static void io_get_strings(struct io_ctx *ctx, frame_t slot)
{
	array_index_t idx;
	array_init(char *, &ctx->strs, &ctx->strs_l);
	index_from_int(&idx, 0);

	if (!array_onstack_iterate(ctx->fp, slot, &idx, io_get_strings_callback, ctx))
		internal(file_line, "io_get_strings: array_onstack_iterate failed");

	index_free(&idx);
}

/* see option unit_type in system.ajla */
static void set_uniq_type(struct io_ctx *ctx)
{
	frame_t slot = get_output(ctx, 0);
	const struct type *t = frame_get_type_of_local(ctx->fp, slot);

	if (likely(t == type_get_fixed(0, 1))) {
		*frame_slot(ctx->fp, slot, uint8_t) = 0;
	} else {
		struct data *d;
		pointer_t ptr;
		ajla_error_t err;
#if 0
		d = data_alloc_option_mayfail(&err pass_file_line);
		if (unlikely(!d)) {
			ptr = pointer_error(err, ctx->fp, ctx->ip pass_file_line);
		} else {
			da(d,option)->pointer = pointer_empty();
			da(d,option)->option = 0;
			ptr = pointer_data(d);
		}
#else
		uint8_t val = 0;
		d = data_alloc_flat_mayfail(t->tag, &val, 1, &err pass_file_line);
		if (unlikely(!d)) {
			ptr = pointer_error(err, ctx->fp, ctx->ip pass_file_line);
		} else {
			ptr = pointer_data(d);
		}
#endif
		frame_set_pointer(ctx->fp, slot, ptr);
	}
}


static void * attr_fastcall io_exception_make_handler(struct io_ctx *ctx)
{
	ajla_error_t e;
	void *test;
	ajla_option_t stack_trace;

	ctx->str = NULL;

	if (ctx->n_inputs >= 4) {
		short error_class, error_type;
		int error_aux;

		test = io_deep_eval(ctx, "0123", false);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;

		if (ctx->n_inputs >= 5) {
			test = io_deep_eval(ctx, "4", false);
			if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
				goto ret_test;

			io_get_bytes(ctx, get_input(ctx, 4));
		}

		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 0), short, error_class);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 1), short, error_type);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), int, error_aux);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;

		io_get_option(ctx, get_input(ctx, 3), &stack_trace, NULL);

		if (unlikely(error_class <= 0) || unlikely(error_class >= EC_N))
			e = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		else if (unlikely(error_type < AJLA_ERROR_BASE) || unlikely(error_type >= AJLA_ERROR_N))
			e = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		else
			e = error_ajla_aux(error_class, error_type, error_aux);
	} else {
		e = error_ajla_aux(get_param(ctx, 0), get_param(ctx, 1), get_param(ctx, 2));
		stack_trace = get_param(ctx, 3);
	}

	io_terminate_with_error(ctx, e, stack_trace, ctx->str);

	test = POINTER_FOLLOW_THUNK_EXCEPTION;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	return test;
}

#define IOESS_STRING	1
#define IOESS_PAYLOAD	2
#define IOESS_STACK	3

static void *io_exception_string_stack(struct io_ctx *ctx, int mode)
{
	void *ex;
	char *msg;
	struct thunk *thunk;
	void *test;
	struct data *a;

	ex = frame_pointer_deep_eval(ctx->fp, ctx->ip, get_input(ctx, 0), &thunk);
	if (unlikely(ex == POINTER_FOLLOW_THUNK_GO)) {
		io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}
	if (ex != POINTER_FOLLOW_THUNK_EXCEPTION)
		return ex;

	switch (mode) {
		case IOESS_STRING:
			msg = thunk_exception_string(thunk, &ctx->err);
			break;
		case IOESS_PAYLOAD:
			msg = thunk_exception_payload(thunk, &ctx->err);
			break;
		case IOESS_STACK:
			msg = stack_trace_string(&thunk->u.exception.tr, &ctx->err);
			break;
		default:
			internal(file_line, "io_exception_string_stack: invalid mode %d", mode);
	}
	pointer_dereference(pointer_thunk(thunk));
	if (unlikely(!msg)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	a = array_from_flat_mem(type_get_fixed(0, true), msg, strlen(msg), &ctx->err);
	mem_free(msg);
	if (unlikely(!a)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(a));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_exception_string_handler(struct io_ctx *ctx)
{
	return io_exception_string_stack(ctx, IOESS_STRING);
}

static void * attr_fastcall io_exception_payload_handler(struct io_ctx *ctx)
{
	return io_exception_string_stack(ctx, IOESS_PAYLOAD);
}

static void * attr_fastcall io_exception_stack_handler(struct io_ctx *ctx)
{
	return io_exception_string_stack(ctx, IOESS_STACK);
}

static void * attr_fastcall io_n_std_handles_handler(struct io_ctx attr_unused *ctx)
{
	unsigned n;

	void *test;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	n = os_n_std_handles();

	io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, unsigned, n);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	return POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_get_std_handle_handler(struct io_ctx attr_unused *ctx)
{
	struct resource_handle *h;
	struct data *d;
	unsigned p;

	void *test;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 1), unsigned, p);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_no_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;
	h = da_resource(d);
	h->fd = os_get_std_handle(p);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));
	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_get_args_handler(struct io_ctx *ctx)
{
	void *test;
	struct data *a;
	int i;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	a = data_alloc_array_pointers_mayfail(n_args_left, n_args_left, &ctx->err pass_file_line);
	if (unlikely(!a))
		goto ret_thunk;
	for (i = 0; i < n_args_left; i++) {
		da(a,array_pointers)->pointer[i] = pointer_empty();
	}

	for (i = 0; i < n_args_left; i++) {
		struct data *b;
		b = array_from_flat_mem(type_get_fixed(0, true), args_left[i], strlen(args_left[i]), &ctx->err);
		if (unlikely(!b))
			goto free_a_ret_thunk;
		da(a,array_pointers)->pointer[i] = pointer_data(b);
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(a));
	return POINTER_FOLLOW_THUNK_GO;

free_a_ret_thunk:
	data_dereference(a);
ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_get_environment_handler(struct io_ctx *ctx)
{
	void *test;
	struct data *b;
#if !defined(OS_WIN32)
	size_t i;
#endif

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;
#if defined(OS_WIN32)
	os_get_environment(&ctx->str, &ctx->str_l);
#else
	array_init(char, &ctx->str, &ctx->str_l);

	for (i = 0; environ[i]; i++) {
		const char *e = environ[i];
		if (unlikely(!strchr(e, '=')))
			continue;
#if defined(OS_OS2) || defined(OS_WIN32)
		while (*e != '=') {
			char c = *e++;
			if (c >= 'a' && c <= 'z')
				c -= 0x20;
			array_add(char, &ctx->str, &ctx->str_l, c);
		}
#endif
		array_add_multiple(char, &ctx->str, &ctx->str_l, e, strlen(e) + 1);
	}
#endif
	b = array_from_flat_mem(type_get_fixed(0, true), ctx->str, ctx->str_l, NULL);
	mem_free(ctx->str);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(b));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_stream_open_handler(struct io_ctx *ctx)
{
	struct resource_handle *h;
	handle_t p = handle_none;
	struct data *d;
	int ajla_flags;
	int flags;
	int mode;
	bool test_symlink;
	os_stat_t st;
	void *test;

	ctx->str = NULL;
	d = NULL;
	h = NULL;	/* avoid warning */

	test = io_deep_eval(ctx, "01234", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int, ajla_flags);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 4), int, mode);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	if (ajla_flags & -IO_Open_Flag_N)
		goto invalid_op;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	io_get_bytes(ctx, get_input(ctx, 2));

	d = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	flags = 0;
	test_symlink = false;

	if (ajla_flags & IO_Open_Flag_No_Follow) {
		ajla_flags &= ~IO_Open_Flag_No_Follow;
#if !defined(OS_DOS) && !defined(OS_OS2) && !defined(OS_WIN32)
#if defined(O_NOFOLLOW)
		flags |= O_NOFOLLOW;
#else
		test_symlink = true;
#endif
#endif
	}

	if (ctx->code == IO_Stream_Open_Read) {
		if (ajla_flags)
			goto invalid_op;
		flags |= O_RDONLY;
	} else if (ctx->code == IO_Stream_Open_Write) {
		if (ajla_flags & (IO_Open_Flag_Read | IO_Open_Flag_Write))
			goto invalid_op;
		flags |= O_WRONLY | O_APPEND;
		if (!(ajla_flags & IO_Open_Flag_Append))
			flags |= O_TRUNC;
	} else {
		switch (ajla_flags & (IO_Open_Flag_Read | IO_Open_Flag_Write)) {
			case 0x0:
				goto invalid_op;
			case IO_Open_Flag_Read:
				flags |= O_RDONLY; break;
			case IO_Open_Flag_Write:
				flags |= O_WRONLY; break;
			case IO_Open_Flag_Read | IO_Open_Flag_Write:
				flags |= O_RDWR; break;
			default:
				internal(file_line, "invalid flags %x", ajla_flags);
		}
	}

	if (ajla_flags & IO_Open_Flag_Create)
		flags |= O_CREAT;
	if (ajla_flags & IO_Open_Flag_Must_Create) {
		if (ajla_flags & IO_Open_Flag_Create)
			flags |= O_EXCL;
		else
			goto invalid_op;
	}

	flags |= O_NONBLOCK;

	p = os_open(ctx->dir_handle->fd, ctx->str, flags, mode, &ctx->err);
	if (unlikely(!handle_is_valid(p)))
		goto ret_thunk;

	if (ctx->code == IO_Block_Open || test_symlink) {
		if (unlikely(!os_fstat(p, &st, &ctx->err)))
			goto ret_thunk;
	}
	if (ctx->code == IO_Block_Open) {
		if (unlikely(!S_ISREG(st.st_mode))
#ifdef S_ISBLK
		 && unlikely(!S_ISBLK(st.st_mode))
#endif
		    )
			goto invalid_op;
	}
	if (test_symlink) {
#ifdef S_ISLNK
		os_stat_t st2;
		if (unlikely(!os_stat(ctx->dir_handle->fd, ctx->str, true, &st2, &ctx->err)))
			goto ret_thunk;
		if (unlikely(memcmp(&st.st_dev, &st2.st_dev, sizeof st.st_dev)) ||
		    unlikely(st.st_ino != st2.st_ino)) {
			if (S_ISLNK(st2.st_mode)) {
				ctx->err = error_ajla_aux(EC_SYSCALL, AJLA_ERROR_SYSTEM, SYSTEM_ERROR_ELOOP);
				goto ret_thunk;
			}
			goto invalid_op;
		}
#endif
	}

	h = da_resource(d);
	h->fd = p;
	h->nonblocking = true;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	mem_free(ctx->str);
	return POINTER_FOLLOW_THUNK_GO;

invalid_op:
	ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
ret_thunk:
	if (handle_is_valid(p))
		os_close(p);
	if (d)
		data_free_r1(d);
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	if (ctx->str)
		mem_free(ctx->str);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_stream_read_handler(struct io_ctx *ctx)
{
	struct data *a;
	array_index_t idx;
	int_default_t this_step;
	ssize_t rd;
	struct data *result = NULL;
	void *test;

	test = io_deep_eval(ctx, ctx->code != IO_Block_Read ? "012" : "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	test = io_get_array_index(ctx, ctx->fp, get_input(ctx, 2), &idx pass_file_line);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	if (ctx->code == IO_Block_Read) {
		io_get_number(ctx, get_input(ctx, 3), int64_t, os_off_t, ctx->position);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto idx_free_ret_test;
		if (unlikely(ctx->position < 0)) {
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
			goto ret_thunk;
		}
	}

	do {
		if (likely(index_is_int(idx))) {
			this_step = index_to_int(idx);
		} else {
			this_step = signed_maximum(int_default_t);
		}
		if (unlikely(this_step > signed_maximum(int) + zero))
			this_step = (int_default_t)signed_maximum(int);

try_alloc_again:
		a = data_alloc_array_flat_mayfail(type_get_fixed(0, true), this_step, 0, false, &ctx->err pass_file_line);
		if (unlikely(!a)) {
			this_step >>= 1;
			if (this_step)
				goto try_alloc_again;
			goto ret_thunk;
		}

		if (ctx->code != IO_Block_Read) {
			if (!ctx->handle->nonblocking) {
				if (!iomux_test_handle(ctx->handle->fd, false))
					goto block;
			}
			rd = os_read(ctx->handle->fd, data_untag(da_array_flat(a)), this_step, &ctx->err);
			if (unlikely(rd == OS_RW_WOULDBLOCK)) {
block:
				data_free_r1(a);
				if (result)
					break;
				io_block_on_handle(ctx, false, false);
				goto ret_exit;
			}
		} else {
			rd = os_pread(ctx->handle->fd, data_untag(da_array_flat(a)), this_step, ctx->position, &ctx->err);
		}

		if (unlikely(rd == OS_RW_ERROR)) {
			data_free_r1(a);
			if (result)
				break;
			goto ret_thunk;
		}

		if (ctx->code == IO_Block_Read) {
			ctx->position += rd;
		}
		da(a,array_flat)->n_used_entries = rd;

		index_sub_int(&idx, rd);

		if (likely(!result)) {
			result = a;
		} else {
			result = array_join(result, a, &ctx->err);
			if (!result)
				goto ret_thunk;
		}

	} while (unlikely(rd != 0) && unlikely(index_ge_int(idx, 1)) && ctx->code == IO_Block_Read);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(result));

	index_free(&idx);

	return POINTER_FOLLOW_THUNK_GO;

ret_exit:
	test = POINTER_FOLLOW_THUNK_EXIT;
	goto idx_free_ret_test;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;

idx_free_ret_test:
	if (result)
		data_dereference(result);
	index_free(&idx);
ret_test:
	return test;
}

static int_default_t io_write_callback(unsigned char *flat, const struct type attr_unused * type, int_default_t n_elements, pointer_t *ptr, void *ctx_)
{
	struct io_ctx *ctx = cast_ptr(struct io_ctx *, ctx_);
	if (tick_elapsed(&ctx->ts) && ctx->status == IO_STATUS_PROGRESS) {
		ctx->status = IO_STATUS_TIMEOUT;
		return 0;
	}
	if (flat) {
		ssize_t rd;

		if (unlikely(n_elements > signed_maximum(int) + zero))
			n_elements = signed_maximum(int);

		if (ctx->code != IO_Block_Write) {
			if (!ctx->handle->nonblocking) {
				if (!iomux_test_handle(ctx->handle->fd, true))
					goto block;
				if (n_elements > PIPE_BUF + zero)
					n_elements = PIPE_BUF + zero;
			}
			rd = os_write(ctx->handle->fd, data_untag(flat), n_elements, &ctx->err);
			if (unlikely(rd == OS_RW_WOULDBLOCK)) {
block:
				if (ctx->status == IO_STATUS_STARTED) {
					io_block_on_handle(ctx, true, false);
					ctx->status = IO_STATUS_BLOCKED;
				}
				return 0;
			}
		} else {
			rd = os_pwrite(ctx->handle->fd, data_untag(flat), n_elements, ctx->position, &ctx->err);
		}

		if (unlikely(rd == OS_RW_ERROR)) {
			if (ctx->status == IO_STATUS_STARTED)
				ctx->status = IO_STATUS_IOERR;
			return 0;
		}
		if (ctx->code == IO_Block_Write) {
			ctx->position += rd;
		}
		ctx->status = IO_STATUS_PROGRESS;
		return rd;
	} else {
		ajla_assert_lo(pointer_is_thunk(*ptr), (file_line, "io_write_callback: pointer is not thunk (tag %u)", da_tag(pointer_get_data(*ptr))));
		ctx->status = IO_STATUS_THUNK;
		ctx->array_ptr = ptr;
		return 0;
	}
}

static void * attr_fastcall io_stream_write_handler(struct io_ctx *ctx)
{
	array_index_t idx;
	void *test;

	test = io_deep_eval(ctx, ctx->code != IO_Block_Write ? "01" : "013", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

again:
	index_from_int(&idx, 0);

	if (ctx->code == IO_Block_Write) {
		io_get_number(ctx, get_input(ctx, 3), int64_t, os_off_t, ctx->position);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto idx_free_ret_test;
		if (unlikely(ctx->position < 0)) {
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
			goto ret_thunk;
		}
	}

	ctx->status = IO_STATUS_STARTED;
	tick_start(&ctx->ts);
	if (array_onstack_iterate(ctx->fp, get_input(ctx, 2), &idx, io_write_callback, ctx))
		goto free_index_go;

	switch (ctx->status) {
		case IO_STATUS_PROGRESS:
			/* IO_STATUS_PROGRESS happens if size is trimmed to PIPE_BUF or if write returns less bytes than supplied */
		case IO_STATUS_TIMEOUT: {
			goto free_index_go;
		}
		case IO_STATUS_IOERR: {
			goto ret_thunk;
		}
		case IO_STATUS_THUNK: {
			struct data attr_unused *data;
			if (index_ge_int(idx, 1))
				goto free_index_go;
			pointer_follow(ctx->array_ptr, false, data, PF_WAIT, ctx->fp, ctx->ip,
				test = ex_;
				goto idx_free_ret_test,

				thunk_reference(thunk_);
				io_terminate_with_thunk(ctx, thunk_);
				goto free_index_go;
			);
			index_free(&idx);
			goto again;
		}
		case IO_STATUS_BLOCKED: {
			test = POINTER_FOLLOW_THUNK_EXIT;
			goto idx_free_ret_test;
		}
		default:
			internal(file_line, "io_stream_write_handler: invalid status %u", ctx->status);
	}

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
free_index_go:
	test = POINTER_FOLLOW_THUNK_GO;
	io_store_integer(ctx, get_output(ctx, 1), idx);
idx_free_ret_test:
	index_free(&idx);
ret_test:
	return test;
}

static void * attr_fastcall io_lseek_handler(struct io_ctx *ctx)
{
	void *test;
	unsigned mode;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_number(ctx, get_input(ctx, 2), int64_t, os_off_t, ctx->position);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	mode = get_param(ctx, 0);

	if (unlikely(!os_lseek(ctx->handle->fd, mode, ctx->position, &ctx->position, &ctx->err)))
		goto ret_thunk;

	io_store_typed_number(ctx, get_output(ctx, 1), int64_t, 3, os_off_t, ctx->position);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_ftruncate_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_number(ctx, get_input(ctx, 2), int64_t, os_off_t, ctx->position);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	if (unlikely(ctx->position < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
		goto ret_thunk;
	}

	if (unlikely(!os_ftruncate(ctx->handle->fd, ctx->position, &ctx->err)))
		goto ret_thunk;

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_fallocate_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_number(ctx, get_input(ctx, 2), int64_t, os_off_t, ctx->position);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	if (unlikely(ctx->position < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
		goto ret_thunk;
	}

	io_get_number(ctx, get_input(ctx, 3), int64_t, os_off_t, ctx->length);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	if (unlikely(ctx->length < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
		goto ret_thunk;
	}

	if (unlikely(!os_fallocate(ctx->handle->fd, ctx->position, ctx->length, &ctx->err)))
		goto ret_thunk;

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_fclone_range_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "012345", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));
	ctx->handle2 = ctx->handle;

	io_get_number(ctx, get_input(ctx, 2), int64_t, os_off_t, ctx->position);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	if (unlikely(ctx->position < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
		goto ret_thunk;
	}
	ctx->position2 = ctx->position;

	io_get_handle(ctx, get_input(ctx, 3));

	io_get_number(ctx, get_input(ctx, 4), int64_t, os_off_t, ctx->position);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	if (unlikely(ctx->position < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
		goto ret_thunk;
	}

	io_get_number(ctx, get_input(ctx, 4), int64_t, os_off_t, ctx->length);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	if (unlikely(ctx->length < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
		goto ret_thunk;
	}

	if (unlikely(!os_clone_range(ctx->handle2->fd, ctx->position2, ctx->handle->fd, ctx->position, ctx->length, &ctx->err)))
		goto ret_thunk;
	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_fsync_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	if (unlikely(!os_fsync(ctx->handle->fd, get_param(ctx, 0), &ctx->err)))
		goto ret_thunk;

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_sync_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	if (unlikely(!os_fsync(handle_none, 3, &ctx->err)))
		goto ret_thunk;

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_read_console_packet_handler(struct io_ctx *ctx)
{
	struct data *a;
	ssize_t rd;
	void *test;
	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	a = data_alloc_array_flat_mayfail(type_get_fixed(2, false), CONSOLE_PACKET_ENTRIES, CONSOLE_PACKET_ENTRIES, false, &ctx->err pass_file_line);
	if (unlikely(!a))
		goto ret_thunk;

	rd = os_read_console_packet(ctx->handle->fd, data_untag(da_array_flat(a)), &ctx->err);
	if (rd == OS_RW_WOULDBLOCK) {
		data_free_r1(a);
		io_block_on_handle(ctx, false, true);
		test = POINTER_FOLLOW_THUNK_EXIT;
		goto ret_test;
	}
	if (unlikely(rd == OS_RW_ERROR)) {
		data_free_r1(a);
		goto ret_thunk;
	}
	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(a));
	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_GO;
ret_test:
	return test;
}

static void * attr_fastcall io_write_console_packet_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_bytes(ctx, get_input(ctx, 2));

	if (unlikely(!os_write_console_packet(ctx->handle->fd, cast_ptr(struct console_write_packet *, ctx->str), &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_GO;
		goto free_ret_test;
	}

free_ret_test:
	mem_free(ctx->str);
ret_test:
	return test;
}

static void * attr_fastcall io_pipe_handler(struct io_ctx *ctx)
{
	struct data *d1 = NULL, *d2 = NULL;
	struct resource_handle *h1, *h2;
	void *test;
	handle_t result[2];

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d1 = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d1))
		goto ret_thunk;

	d2 = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d2))
		goto ret_thunk;

	if (unlikely(!os_pipe(result, 3, &ctx->err)))
		goto ret_thunk;

	h1 = da_resource(d1);
	h1->fd = result[0];
	h1->nonblocking = true;

	h2 = da_resource(d2);
	h2->fd = result[1];
	h2->nonblocking = true;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d1));
	frame_set_pointer(ctx->fp, get_output(ctx, 2), pointer_data(d2));

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	if (d1)
		data_free_r1(d1);
	if (d2)
		data_free_r1(d2);
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_root_dir_handler(struct io_ctx *ctx)
{
	struct resource_dir_handle *h;
	dir_handle_t p;
	frame_t fn;
	struct data *d;
	void *test;

	d = NULL;
	h = NULL;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = data_alloc_resource_mayfail(sizeof(struct resource_dir_handle), dir_handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	fn = get_param(ctx, 0);
	switch (fn) {
		case 1:
			p = os_dir_root(&ctx->err);
			break;
		case 2:
			p = os_dir_cwd(&ctx->err);
			break;
		case 3:
			p = os_dir_open(os_cwd, builtin_lib_path, 0, &ctx->err);
			break;
		case 4:
			p = os_dir_open(dir_none, os_get_path_to_exe(), 0, &ctx->err);
			break;
		case 5:
			p = dir_none;
			goto set_p;
		default:
			internal(file_line, "io_root_dir_handler: invalid function code %u", (unsigned)fn);
	}
	if (unlikely(!dir_handle_is_valid(p)))
		goto ret_thunk;
set_p:
	h = da_resource(d);
	h->fd = p;

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(d));

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	if (d)
		data_free_r1(d);
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void get_lib_path(void)
{
	mutex_lock(&lib_path_mutex);
	if (unlikely(!lib_path)) {
		const char *e;

		array_init(char, &lib_path, &lib_path_len);
		array_add_multiple(char, &lib_path, &lib_path_len, builtin_lib_path, strlen(builtin_lib_path));
		array_add_multiple(char, &lib_path, &lib_path_len, "/stdlib", strlen("/stdlib") + 1);

#ifdef AJLA_FRAMEWORKS
		if (os_path_is_absolute(AJLA_FRAMEWORKS)) {
			array_add_multiple(char, &lib_path, &lib_path_len, AJLA_FRAMEWORKS, strlen(AJLA_FRAMEWORKS) + 1);
		} else
#endif
		{
			array_add_multiple(char, &lib_path, &lib_path_len, builtin_lib_path, strlen(builtin_lib_path));
			array_add_multiple(char, &lib_path, &lib_path_len, "/fw", strlen("/fw") + 1);
		}

		e = getenv("AJLA_LIBPATH");
		if (e) {
			size_t l;
next_component:
			for (l = 0; e[l] && !os_is_env_separator(e[l]); l++) ;
			if (l) {
				char *dup = str_dup(e, l, NULL);
				if (os_path_is_absolute(dup)) {
					array_add_multiple(char, &lib_path, &lib_path_len, e, l);
					array_add(char, &lib_path, &lib_path_len, 0);
				}
				mem_free(dup);
			}
			e += l;
			if (*e) {
				e++;
				goto next_component;
			}
		}

		if (os_path_is_absolute("/")) {
			array_add_multiple(char, &lib_path, &lib_path_len, "/", 2);
		} else {
#ifdef NO_DIR_HANDLES
			char *root = os_dir_root(NULL);
			array_add_multiple(char, &lib_path, &lib_path_len, root, strlen(root) + 1);
			mem_free(root);
#else
			fatal("get_lib_path: NO_DIR_HANDLES is not set");
#endif
		}
		array_finish(char, &lib_path, &lib_path_len);
#if 0
		{
			size_t i;
			for (i = 0; i < lib_path_len; i += strlen(lib_path + i) + 1)
				debug("libpath: '%s'", lib_path + i);
		}
#endif
	}
	mutex_unlock(&lib_path_mutex);
}

static void * attr_fastcall io_lib_path_handler(struct io_ctx *ctx)
{
	struct data *b;

	get_lib_path();

	b = array_from_flat_mem(type_get_fixed(0, true), lib_path, lib_path_len, &ctx->err);
	if (unlikely(!b))
		goto ret_thunk;

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(b));

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_open_dir_handler(struct io_ctx *ctx)
{
	struct resource_dir_handle *h;
	dir_handle_t p;
	struct data *d;
	void *test;
	int ajla_flags;
	int flags;
	bool test_symlink;

	ctx->str = NULL;
	d = NULL;
	h = NULL;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int_default_t, ajla_flags);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	if (ajla_flags & -IO_Open_Flag_N)
		goto invalid_op;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	io_get_bytes(ctx, get_input(ctx, 2));

	d = data_alloc_resource_mayfail(sizeof(struct resource_dir_handle), dir_handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	flags = 0;
	test_symlink = false;

	if (ajla_flags & IO_Open_Flag_No_Follow) {
		ajla_flags &= ~IO_Open_Flag_No_Follow;
#if !defined(OS_DOS) && !defined(OS_OS2) && !defined(OS_WIN32)
#if defined(O_NOFOLLOW)
		flags |= O_NOFOLLOW;
#else
		test_symlink = true;
#endif
#endif
	}

	if (unlikely(ajla_flags != 0))
		goto invalid_op;

	p = os_dir_open(ctx->dir_handle->fd, ctx->str, flags, &ctx->err);
	if (unlikely(!dir_handle_is_valid(p)))
		goto ret_thunk;

	if (test_symlink) {
#ifdef S_ISLNK
		os_stat_t st;
		os_stat_t st2;
		if (unlikely(!os_stat(p, ".", true, &st, &ctx->err)))
			goto ret_thunk;
		if (unlikely(!os_stat(ctx->dir_handle->fd, ctx->str, true, &st2, &ctx->err)))
			goto ret_thunk;
		if (unlikely(memcmp(&st.st_dev, &st2.st_dev, sizeof st.st_dev)) ||
		    unlikely(st.st_ino != st2.st_ino)) {
			if (S_ISLNK(st2.st_mode)) {
				ctx->err = error_ajla_aux(EC_SYSCALL, AJLA_ERROR_SYSTEM, SYSTEM_ERROR_ELOOP);
				goto ret_thunk;
			}
			goto invalid_op;
		}
#endif
	}

	h = da_resource(d);
	h->fd = p;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	mem_free(ctx->str);
	return POINTER_FOLLOW_THUNK_GO;

invalid_op:
	ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
ret_thunk:
	if (d)
		data_free_r1(d);
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	if (ctx->str)
		mem_free(ctx->str);
	return POINTER_FOLLOW_THUNK_GO;
}

static int name_cmp(const void *p1, const void *p2)
{
	int diff;
	unsigned char *c1 = *cast_ptr(unsigned char **, p1);
	unsigned char *c2 = *cast_ptr(unsigned char **, p2);
next:
	diff = *c1 - *c2;
	if (likely(diff) || !*c1) return diff;
	c1++;
	c2++;
	goto next;
}

static void * attr_fastcall io_read_dir_handler(struct io_ctx *ctx)
{
	void *test;
	char **files;
	size_t n_files;
	struct data *a;
	size_t i;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	if (unlikely(!dir_handle_is_valid(ctx->dir_handle->fd))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), &ctx->err, "dummy dir handle");
		goto ret_error;
	}

	if (unlikely(!os_dir_read(ctx->dir_handle->fd, &files, &n_files, &ctx->err)))
		goto ret_error;

	qsort(files, n_files, sizeof(char *), name_cmp);

	a = data_alloc_array_pointers_mayfail(n_files, n_files, &ctx->err pass_file_line);
	if (unlikely(!a)) {
		goto free_dir_ret_error;
	}

	for (i = 0; i < n_files; i++) {
		da(a,array_pointers)->pointer[i] = pointer_empty();
	}

	for (i = 0; i < n_files; i++) {
		struct data *b;
		b = array_from_flat_mem(type_get_fixed(0, true), files[i], strlen(files[i]), &ctx->err);
		if (unlikely(!b))
			goto free_a_ret_error;
		da(a,array_pointers)->pointer[i] = pointer_data(b);
	}

	os_dir_free(files, n_files);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(a));

	return POINTER_FOLLOW_THUNK_GO;

free_a_ret_error:
	data_dereference(a);
free_dir_ret_error:
	os_dir_free(files, n_files);
ret_error:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_dir_path_handler(struct io_ctx *ctx)
{
	void *test;
	char *lnk;
	struct data *a;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	if (unlikely(!dir_handle_is_valid(ctx->dir_handle->fd))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), &ctx->err, "dummy dir handle");
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	lnk = os_dir_path(ctx->dir_handle->fd, &ctx->err);
	if (unlikely(!lnk)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	a = array_from_flat_mem(type_get_fixed(0, true), lnk, strlen(lnk), &ctx->err);
	mem_free(lnk);
	if (unlikely(!a)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(a));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_dmonitor_prepare_handler(struct io_ctx *ctx)
{
	struct resource_notify_handle *h;
	struct data *d;
	void *test;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	if (unlikely(!dir_handle_is_valid(ctx->dir_handle->fd))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), &ctx->err, "dummy dir handle");
		goto ret_thunk;
	}

	d = data_alloc_resource_mayfail(sizeof(struct resource_notify_handle), notify_handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;
	h = da_resource(d);

	if (unlikely(!iomux_directory_handle_alloc(ctx->dir_handle->fd, &h->id, &h->seq, &ctx->err))) {
		data_free_r1(d);
		goto ret_thunk;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	return POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_dmonitor_wait_handler(struct io_ctx *ctx)
{
	pointer_t ptr;
	struct data *d;
	struct resource_notify_handle *h;
	struct execution_control *ex;
	void *test;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 1));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_dmonitor_wait_handler: pointer is thunk"));
	d = pointer_get_data(ptr);

	h = da_resource(d);
	ex = frame_execution_control(ctx->fp);
	/*debug("testing wait");*/
	if (!iomux_directory_handle_wait(h->id, h->seq, &ex->wait[0].mutex_to_lock, &ex->wait[0].wait_entry)) {
		/*debug("waiting");*/
		pointer_follow_wait(ctx->fp, ctx->ip);
		return POINTER_FOLLOW_THUNK_EXIT;
	}
	/*debug("early exit");*/

	return POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void *io_stat(struct io_ctx *ctx, os_stat_t *st, unsigned stat_select)
{
	struct data *o;
	int pos;
	int64_t val;
	int popc = pop_count(stat_select);

	o = data_alloc_array_flat_mayfail(type_get_int(3), popc, popc, false, &ctx->err pass_file_line);
	if (unlikely(!o)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	pos = 0;
	while (stat_select) {
		unsigned bit = 1U << low_bit(stat_select);
		stat_select &= ~bit;
		switch (bit) {
			case IO_Stat_Flag_DevMajor:
				val = os_dev_t_major(st->st_dev);
				break;
			case IO_Stat_Flag_DevMinor:
				val = os_dev_t_minor(st->st_dev);
				break;
			case IO_Stat_Flag_Inode:
				val = st->st_ino;
				break;
			case IO_Stat_Flag_Type:
				if (S_ISREG(st->st_mode)) { val = IO_Stat_Type_File; break; }
				if (S_ISDIR(st->st_mode)) { val = IO_Stat_Type_Directory; break; }
#ifdef S_ISLNK
				if (S_ISLNK(st->st_mode)) { val = IO_Stat_Type_Link; break; }
#endif
				if (S_ISFIFO(st->st_mode)) { val = IO_Stat_Type_Pipe; break; }
				if (S_ISCHR(st->st_mode)) { val = IO_Stat_Type_CharDev; break; }
#ifdef S_ISBLK
				if (S_ISBLK(st->st_mode)) { val = IO_Stat_Type_BlockDev; break; }
#endif
#ifdef S_ISSOCK
				if (S_ISSOCK(st->st_mode)) { val = IO_Stat_Type_Socket; break; }
#endif
				io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_SYSTEM_RETURNED_INVALID_DATA), true, NULL);
				return POINTER_FOLLOW_THUNK_EXCEPTION;
			case IO_Stat_Flag_Mode:
				val = st->st_mode & 07777;
				break;
			case IO_Stat_Flag_NLink:
				val = st->st_nlink;
				break;
			case IO_Stat_Flag_UID:
				val = st->st_uid;
				break;
			case IO_Stat_Flag_GID:
				val = st->st_gid;
				break;
			case IO_Stat_Flag_RDevMajor:
				val = os_dev_t_major(st->st_rdev);
				break;
			case IO_Stat_Flag_RDevMinor:
				val = os_dev_t_minor(st->st_rdev);
				break;
			case IO_Stat_Flag_Size:
				val = st->st_size;
				break;
			case IO_Stat_Flag_OptimalIOSize:
				val = st->st_blksize;
				break;
			case IO_Stat_Flag_Allocated:
#if defined(__DJGPP__)
				val = st->st_size;
#else
				val = (uint64_t)st->st_blocks * 512;
#endif
				break;
			case IO_Stat_Flag_ATime:
#if defined(HAVE_STRUCT_STAT_ST_ATIM)
				val = os_timespec_to_ajla_time(&st->st_atim);
#elif defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
				val = os_timespec_to_ajla_time(&st->st_atimespec);
#else
				val = os_time_t_to_ajla_time(st->st_atime);
#endif
				break;
			case IO_Stat_Flag_MTime:
#if defined(HAVE_STRUCT_STAT_ST_ATIM)
				val = os_timespec_to_ajla_time(&st->st_mtim);
#elif defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
				val = os_timespec_to_ajla_time(&st->st_mtimespec);
#else
				val = os_time_t_to_ajla_time(st->st_mtime);
#endif
				break;
			case IO_Stat_Flag_CTime:
#if defined(HAVE_STRUCT_STAT_ST_ATIM)
				val = os_timespec_to_ajla_time(&st->st_ctim);
#elif defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
				val = os_timespec_to_ajla_time(&st->st_ctimespec);
#else
				val = os_time_t_to_ajla_time(st->st_ctime);
#endif
				break;
			default:
				pointer_dereference(pointer_data(o));
				io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
				return POINTER_FOLLOW_THUNK_EXCEPTION;
		}
		cast_ptr(int64_t *, da_array_flat(o))[pos] = val;
		pos++;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(o));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_stat_handler(struct io_ctx *ctx)
{
	void *test;
	os_stat_t st;
	unsigned stat_select;
	frame_t fn;
	bool lnk;

	ctx->str = NULL;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	io_get_bytes(ctx, get_input(ctx, 2));

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), unsigned, stat_select);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	fn = get_param(ctx, 0);
	switch (fn) {
		case 1:
			lnk = false;
			break;
		case 2:
			lnk = true;
			break;
		default:
			internal(file_line, "io_stat_handler: invalid function code %u", (unsigned)fn);
	}

	if (unlikely(!os_stat(ctx->dir_handle->fd, ctx->str, lnk, &st, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	mem_free(ctx->str);

	return io_stat(ctx, &st, stat_select);

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	return test;
}

static void * attr_fastcall io_fstat_handler(struct io_ctx *ctx)
{
	void *test;
	os_stat_t st;
	unsigned stat_select;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), unsigned, stat_select);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	if (unlikely(!os_fstat(ctx->handle->fd, &st, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	return io_stat(ctx, &st, stat_select);

ret_test:
	return test;
}

static void *io_statfs(struct io_ctx *ctx, os_statvfs_t *st, unsigned stat_select)
{
	struct data *o;
	int pos;
	int64_t val;
	int popc = pop_count(stat_select);

	o = data_alloc_array_flat_mayfail(type_get_int(3), popc, popc, false, &ctx->err pass_file_line);
	if (unlikely(!o)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	pos = 0;
	while (stat_select) {
		unsigned bit = 1U << low_bit(stat_select);
		stat_select &= ~bit;
		switch (bit) {
			case IO_StatFS_Flag_BSize:
				val = st->f_bsize;
				break;
			case IO_StatFS_Flag_FrSize:
				val = st->f_frsize;
				break;
			case IO_StatFS_Flag_FrTotal:
				val = st->f_blocks;
				break;
			case IO_StatFS_Flag_FrFree:
				val = st->f_bfree;
				break;
			case IO_StatFS_Flag_FrAvail:
				val = st->f_bavail;
				break;
			case IO_StatFS_Flag_InTotal:
				val = st->f_files;
				break;
			case IO_StatFS_Flag_InFree:
				val = st->f_ffree;
				break;
			case IO_StatFS_Flag_InAvail:
				val = st->f_favail;
				break;
			case IO_StatFS_Flag_FSId:
				val = st->f_fsid;
				break;
			case IO_StatFS_Flag_Flags:
				val = 0;
#ifdef ST_RDONLY
				if (st->f_flag & ST_RDONLY)
					val |= IO_StatFS_ST_ReadOnly;
#endif
#ifdef ST_NOSUID
				if (st->f_flag & ST_NOSUID)
					val |= IO_StatFS_ST_NoSuid;
#endif
#ifdef ST_NODEV
				if (st->f_flag & ST_NODEV)
					val |= IO_StatFS_ST_NoDev;
#endif
#ifdef ST_NOEXEC
				if (st->f_flag & ST_NOEXEC)
					val |= IO_StatFS_ST_NoExec;
#endif
#ifdef ST_SYNCHRONOUS
				if (st->f_flag & ST_SYNCHRONOUS)
					val |= IO_StatFS_ST_Synchronous;
#endif
#ifdef ST_MANDLOCK
				if (st->f_flag & ST_MANDLOCK)
					val |= IO_StatFS_ST_MandLock;
#endif
#ifdef ST_NOATIME
				if (st->f_flag & ST_NOATIME)
					val |= IO_StatFS_ST_NoAtime;
#endif
#ifdef ST_NODIRATIME
				if (st->f_flag & ST_NODIRATIME)
					val |= IO_StatFS_ST_NoDirAtime;
#endif
#ifdef ST_RELATIME
				if (st->f_flag & ST_RELATIME)
					val |= IO_StatFS_ST_RelAtime;
#endif
				break;
			case IO_StatFS_Flag_NameLen:
				val = st->f_namemax;
				break;
			default:
				pointer_dereference(pointer_data(o));
				io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
				return POINTER_FOLLOW_THUNK_EXCEPTION;
		}
		cast_ptr(int64_t *, da_array_flat(o))[pos] = val;
		pos++;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(o));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_fstatfs_handler(struct io_ctx *ctx)
{
	void *test;
	os_statvfs_t st;
	unsigned stat_select;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), unsigned, stat_select);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	if (unlikely(!os_fstatvfs(ctx->handle->fd, &st, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	return io_statfs(ctx, &st, stat_select);
}

static void * attr_fastcall io_dstatfs_handler(struct io_ctx *ctx)
{
	void *test;
	os_statvfs_t st;
	unsigned stat_select;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	if (unlikely(!dir_handle_is_valid(ctx->dir_handle->fd))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), &ctx->err, "dummy dir handle");
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), unsigned, stat_select);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	if (unlikely(!os_dstatvfs(ctx->dir_handle->fd, &st, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	return io_statfs(ctx, &st, stat_select);
}

static void * attr_fastcall io_readlink_handler(struct io_ctx *ctx)
{
	void *test;
	char *lnk;
	struct data *a;

	ctx->str = NULL;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	io_get_bytes(ctx, get_input(ctx, 2));

	lnk = os_readlink(ctx->dir_handle->fd, ctx->str, &ctx->err);
	if (unlikely(!lnk)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	a = array_from_flat_mem(type_get_fixed(0, true), lnk, strlen(lnk), &ctx->err);
	mem_free(lnk);
	if (unlikely(!a)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(a));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	return test;
}

static void * attr_fastcall io_dir_action_handler(struct io_ctx *ctx)
{
	void *test;
	int mode = 0;
	ajla_time_t dev_major = 0, dev_minor = 0;
	int action;

	ctx->str = NULL;
	ctx->str2 = NULL;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	io_get_bytes(ctx, get_input(ctx, 2));

	action = get_param(ctx, 0);

	if (action == IO_Action_Mk_Dir || action == IO_Action_Mk_Pipe || action == IO_Action_Mk_Socket || action == IO_Action_Mk_CharDev || action == IO_Action_Mk_BlockDev || action == IO_Action_ChMod) {
		test = io_deep_eval(ctx, "3", false);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int, mode);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
	}

	if (action == IO_Action_Mk_CharDev || action == IO_Action_Mk_BlockDev) {
		test = io_deep_eval(ctx, "45", false);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 4), ajla_time_t, dev_major);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 5), ajla_time_t, dev_minor);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
	}

	if (action == IO_Action_UTime || action == IO_Action_LUTime) {
		test = io_deep_eval(ctx, "34", false);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_time(ctx, get_input(ctx, 3), dev_major);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			return test;
		io_get_time(ctx, get_input(ctx, 4), dev_minor);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			return test;
	}

	if (action == IO_Action_Mk_SymLink) {
		test = io_deep_eval(ctx, "3", false);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_bytes2(ctx, get_input(ctx, 3));
	}

	if (action == IO_Action_ChOwn || action == IO_Action_LChOwn) {
		test = io_deep_eval(ctx, "34", false);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), ajla_time_t, dev_major);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
		io_get_positive_number(ctx, ctx->fp, get_input(ctx, 4), ajla_time_t, dev_minor);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
	}

	if (unlikely(!os_dir_action(ctx->dir_handle->fd, ctx->str, action, mode, dev_major, dev_minor, ctx->str2, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	if (ctx->str2)
		mem_free(ctx->str2);
	return test;
}

static void * attr_fastcall io_dir2_action_handler(struct io_ctx *ctx)
{
	void *test;
	int action;

	ctx->str = NULL;
	ctx->str2 = NULL;

	test = io_deep_eval(ctx, "01234", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_dir_handle(ctx, get_input(ctx, 3));
	ctx->dir_handle2 = ctx->dir_handle;
	io_get_bytes2(ctx, get_input(ctx, 4));

	io_get_dir_handle(ctx, get_input(ctx, 1));
	io_get_bytes(ctx, get_input(ctx, 2));

	action = get_param(ctx, 0);

	if (unlikely(!os_dir2_action(ctx->dir_handle->fd, ctx->str, action, ctx->dir_handle2->fd, ctx->str2, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	if (ctx->str2)
		mem_free(ctx->str2);
	return test;
}

static void * attr_fastcall io_stty_handler(struct io_ctx *ctx)
{
	void *test;
	int flags;
	os_termios_t t;
	os_termios_t *new_termios = NULL;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), int, flags);

	new_termios = mem_alloc_mayfail(os_termios_t *, sizeof(os_termios_t), &ctx->err);
	if (unlikely(!new_termios))
		goto ret_error;

	address_lock(ctx->handle, DEPTH_THUNK);
	if (!ctx->handle->old_termios) {
		ctx->handle->old_termios = new_termios;
		new_termios = NULL;
		if (unlikely(!os_tcgetattr(ctx->handle->fd, ctx->handle->old_termios, &ctx->err))) {
			new_termios = ctx->handle->old_termios;
			ctx->handle->old_termios = NULL;
			goto unlock_ret_error;
		}
	}
	memcpy(&t, ctx->handle->old_termios, sizeof(os_termios_t));
	os_tcflags(&t, flags);
	if (unlikely(!os_tcsetattr(ctx->handle->fd, &t, &ctx->err)))
		goto unlock_ret_error;
	address_unlock(ctx->handle, DEPTH_THUNK);

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (new_termios)
		mem_free(new_termios);
	return test;

unlock_ret_error:
	address_unlock(ctx->handle, DEPTH_THUNK);
ret_error:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_tty_size_handler(struct io_ctx *ctx)
{
	void *test;
	int x = 0, y = 0;	/* avoid warning */
	int nx, ny;
	struct execution_control *ex;
	int ts;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));
	io_get_number(ctx, get_input(ctx, 2), int_default_t, int, x);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 3), int_default_t, int, y);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ex = frame_execution_control(ctx->fp);
	ts = os_tty_size(ctx->handle->fd, x, y, &nx, &ny, &ex->wait[0].mutex_to_lock, &ex->wait[0].wait_entry, &ctx->err);
	if (unlikely(!ts)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}
	if (ts == 2) {
		pointer_follow_wait(ctx->fp, ctx->ip);
		test = POINTER_FOLLOW_THUNK_EXIT;
		goto ret_test;
	}

	io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, int, nx);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 2), int_default_t, INT_DEFAULT_N, int, ny);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static int_default_t io_get_spawn_handles_callback(unsigned char *flat, const struct type attr_unused * type, int_default_t n_elements, pointer_t *ptr, void *ctx_)
{
	struct io_ctx *ctx = cast_ptr(struct io_ctx *, ctx_);
	if (flat) {
		internal(file_line, "io_get_spawn_handles_callback: flat type");
	} else {
		struct data *rec;
		const struct record_definition *def;
		frame_t slot_1, slot_2;
		struct data *d;
		struct resource_handle *h;
		int dst_h;
		void *test;

		rec = pointer_get_data(*ptr);
		def = type_def(da(rec,record)->definition,record);
		ajla_assert_lo(def->n_entries == 2, (file_line, "io_get_spawn_handles_callback: record doesn't have 2 entries"));
		slot_1 = record_definition_slot(def, 0);
		slot_2 = record_definition_slot(def, 1);
		ajla_assert(frame_test_flag(da_record_frame(rec), slot_2), (file_line, "io_get_spawn_handles_callback: bit for slot %u not set", slot_2));

		d = pointer_get_data(*frame_pointer(da_record_frame(rec), slot_2));
		h = da_resource(d);
		verify_file_handle(d);
		array_add(handle_t, &ctx->h_src, &ctx->h_src_l, h->fd);

		io_get_positive_number(ctx, da_record_frame(rec), slot_1, int, dst_h);
		if (test != POINTER_FOLLOW_THUNK_GO)
			return 0;

		if (unlikely(dst_h < 0)) {
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
			return 0;
		}

		array_add(int, &ctx->h_dst, &ctx->h_dst_l, dst_h);
	}
	return n_elements;
}

static int cmp_int(const void *p1, const void *p2)
{
	int i1 = *cast_ptr(const int *, p1);
	int i2 = *cast_ptr(const int *, p2);
	if (i1 < i2)
		return -1;
	if (i1 > i2)
		return 1;
	return 0;
}

static bool io_get_spawn_handles(struct io_ctx *ctx, frame_t slot)
{
	bool ret;
	array_index_t idx;
	int *h_dst_sorted;
	size_t i;

	array_init(handle_t, &ctx->h_src, &ctx->h_src_l);
	array_init(int, &ctx->h_dst, &ctx->h_dst_l);
	index_from_int(&idx, 0);

	ret = array_onstack_iterate(ctx->fp, slot, &idx, io_get_spawn_handles_callback, ctx);

	index_free(&idx);
	array_finish(handle_t, &ctx->h_src, &ctx->h_src_l);
	array_finish(int, &ctx->h_dst, &ctx->h_dst_l);

	if (!ret)
		return false;

	h_dst_sorted = mem_alloc_array_mayfail(mem_alloc_mayfail, int *, 0, 0, ctx->h_dst_l, sizeof(int), &ctx->err);
	if (!unlikely(h_dst_sorted != NULL)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return false;
	}
	memcpy(h_dst_sorted, ctx->h_dst, ctx->h_dst_l * sizeof(int));
	qsort(h_dst_sorted, ctx->h_dst_l, sizeof(int), cmp_int);
	for (i = 1; i < ctx->h_dst_l; i++) {
		if (h_dst_sorted[i - 1] == h_dst_sorted[i]) {
			mem_free(h_dst_sorted);
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
			return false;
		}
	}
	mem_free(h_dst_sorted);

	return true;
}

static void * attr_fastcall io_uname_handler(struct io_ctx *ctx)
{
	void *test;
	unsigned uname_select;
	os_utsname_t un;
	int popc;
	struct data *o;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 0), unsigned, uname_select);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	if (uname_select & (IO_UName_Flag_System | IO_UName_Flag_Release | IO_UName_Flag_Version | IO_UName_Flag_Machine))
		os_get_uname(&un);

	popc = pop_count(uname_select);
	o = data_alloc_array_pointers_mayfail(popc, 0, &ctx->err pass_file_line);
	if (unlikely(!o)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	while (uname_select) {
		const char *str;
		struct data *a;
		unsigned bit = 1U << low_bit(uname_select);
		uname_select &= ~bit;
		switch (bit) {
			case IO_UName_Flag_Ajla_Version:
				str = AJLA_VERSION;
				break;
			case IO_UName_Flag_Flavor:
				str = os_get_flavor();
				break;
			case IO_UName_Flag_System:
				str = un.sysname;
				break;
			case IO_UName_Flag_Release:
				str = un.release;
				break;
			case IO_UName_Flag_Version:
				str = un.version;
				break;
			case IO_UName_Flag_Machine:
				str = un.machine;
				break;
			default:
				pointer_dereference(pointer_data(o));
				io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
				return POINTER_FOLLOW_THUNK_EXCEPTION;
		}
		a = array_from_flat_mem(type_get_fixed(0, true), str, strlen(str), &ctx->err);
		if (unlikely(!a)) {
			pointer_dereference(pointer_data(o));
			io_terminate_with_error(ctx, ctx->err, true, NULL);
			return POINTER_FOLLOW_THUNK_EXCEPTION;
		}
		da(o,array_pointers)->pointer[da(o,array_pointers)->n_used_entries++] = pointer_data(a);
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(o));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_get_host_name_handler(struct io_ctx *ctx)
{
	void *test;
	char *hn;
	struct data *a;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	hn = os_get_host_name(&ctx->err);
	if (unlikely(!hn)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	a = array_from_flat_mem(type_get_fixed(0, true), hn, strlen(hn), &ctx->err);
	mem_free(hn);
	if (unlikely(!a)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(a));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_spawn_handler(struct io_ctx *ctx)
{
	struct data *d = NULL;
	char *exe_path = NULL;
	char *envc = NULL;
	void *test;
	struct resource_proc_handle *h;
	struct proc_handle *handle;

	ctx->str = NULL;
	ctx->strs = NULL;
	ctx->h_src = NULL;
	ctx->h_dst = NULL;

	test = io_deep_eval(ctx, "012345", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_dir_handle(ctx, get_input(ctx, 1));

	if (unlikely(!dir_handle_is_valid(ctx->dir_handle->fd))) {
		fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), &ctx->err, "dummy dir handle");
		goto ret_thunk;
	}

	if (!io_get_spawn_handles(ctx, get_input(ctx, 2))) {
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	io_get_bytes(ctx, get_input(ctx, 3));
	exe_path = ctx->str;
	ctx->str = NULL;

	io_get_strings(ctx, get_input(ctx, 4));

	io_get_bytes(ctx, get_input(ctx, 5));
	envc = ctx->str;
	ctx->str = NULL;

	d = data_alloc_resource_mayfail(sizeof(struct resource_proc_handle), proc_handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	array_add(char *, &ctx->strs, &ctx->strs_l, NULL);

	handle = os_proc_spawn(ctx->dir_handle->fd, exe_path, ctx->h_src_l, ctx->h_src, ctx->h_dst, ctx->strs, envc, &ctx->err);
	if (unlikely(!handle))
		goto ret_thunk;

	h = da_resource(d);
	h->ph = handle;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	test = POINTER_FOLLOW_THUNK_GO;
	goto ret_free;

ret_thunk:
	test = POINTER_FOLLOW_THUNK_GO;
	io_terminate_with_error(ctx, ctx->err, true, NULL);
ret_test:
	if (d)
		data_free_r1(d);
ret_free:
	if (ctx->h_src)
		mem_free(ctx->h_src);
	if (ctx->h_dst)
		mem_free(ctx->h_dst);
	if (ctx->strs)
		free_strings(ctx);
	if (ctx->str)
		mem_free(ctx->str);
	if (envc)
		mem_free(envc);
	if (exe_path)
		mem_free(exe_path);
	return test;
}

static void * attr_fastcall io_wait_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t *ptr;
	struct data *d;
	struct execution_control *ex;
	struct resource_proc_handle *h;
	int status;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = frame_pointer(ctx->fp, get_input(ctx, 1));

	pointer_follow(ptr, true, d, PF_WAIT, ctx->fp, ctx->ip,
		test = ex_;
		goto ret_test,
		thunk_reference(thunk_);
		io_terminate_with_thunk(ctx, thunk_);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	);

	h = da_resource(d);

	ex = frame_execution_control(ctx->fp);
	if (os_proc_register_wait(h->ph, &ex->wait[0].mutex_to_lock, &ex->wait[0].wait_entry, &status)) {
		io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, int, status);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;
	} else {
		pointer_follow_wait(ctx->fp, ctx->ip);
		test = POINTER_FOLLOW_THUNK_EXIT;
		goto ret_test;
	}

ret_test:
	return test;
}

static void * attr_fastcall io_get_time_handler(struct io_ctx *ctx)
{
	void *test;
	frame_t fn;
	ajla_time_t t;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	fn = get_param(ctx, 0);
	switch (fn) {
		case 1:
			t = os_time_real();
			break;
		case 2:
			t = os_time_monotonic();
			break;
		default:
			internal(file_line, "io_get_time_handler: invalid function code %u", (unsigned)fn);
	}

	io_store_time(ctx, get_output(ctx, 1), t);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	return POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_time_to_calendar_handler(struct io_ctx *ctx)
{
	void *test;
	ajla_time_t t = 0;	/* avoid warning */
	ajla_option_t local;
	int year, month, day, hour, min, sec, usec, yday, wday, is_dst;

	test = io_deep_eval(ctx, "01", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_time(ctx, get_input(ctx, 0), t);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_option(ctx, get_input(ctx, 1), &local, NULL);

	if (unlikely(!os_time_to_calendar(t, local, &year, &month, &day, &hour, &min, &sec, &usec, &yday, &wday, &is_dst, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	io_store_typed_number(ctx, get_output(ctx, 0), int_default_t, INT_DEFAULT_N, int, year);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, int, month);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 2), int_default_t, INT_DEFAULT_N, int, day);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 3), int_default_t, INT_DEFAULT_N, int, hour);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 4), int_default_t, INT_DEFAULT_N, int, min);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 5), int_default_t, INT_DEFAULT_N, int, sec);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 6), int_default_t, INT_DEFAULT_N, int, usec);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 7), int_default_t, INT_DEFAULT_N, int, yday);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 8), int_default_t, INT_DEFAULT_N, int, wday);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_store_typed_number(ctx, get_output(ctx, 9), int_default_t, INT_DEFAULT_N, int, is_dst);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_calendar_to_time_handler(struct io_ctx *ctx)
{
	void *test;
	ajla_time_t t;
	int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0, usec = 0, is_dst = 0;	/* avoid warning */
	ajla_option_t local;

	test = io_deep_eval(ctx, "012345678", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 0), int_default_t, int, year);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 1), int_default_t, int, month);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 2), int_default_t, int, day);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 3), int_default_t, int, hour);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 4), int_default_t, int, min);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 5), int_default_t, int, sec);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 6), int_default_t, int, usec);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_number(ctx, get_input(ctx, 7), int_default_t, int, is_dst);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	io_get_option(ctx, get_input(ctx, 8), &local, NULL);

	if (unlikely(!os_calendar_to_time(local, year, month, day, hour, min, sec, usec, is_dst, &t, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	io_store_time(ctx, get_output(ctx, 0), t);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	return POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_sleep_handler(struct io_ctx *ctx)
{
	struct execution_control *ex;
	void *test;
	ajla_time_t mt = 0;	/* avoid warning */

	frame_s *fp = ctx->fp;
	frame_t slot_r = get_output(ctx, 0);
	frame_t slot_1 = get_input(ctx, 0);

	test = io_deep_eval(ctx, "1", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_time(ctx, get_input(ctx, 1), mt);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	if (mt <= os_time_monotonic()) {
		ipret_copy_variable(fp, slot_1, fp, slot_r, false);
		return POINTER_FOLLOW_THUNK_GO;
	}

	ex = frame_execution_control(ctx->fp);
	if (unlikely(!timer_register_wait(mt, &ex->wait[0].mutex_to_lock, &ex->wait[0].wait_entry, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}
	pointer_follow_wait(ctx->fp, ctx->ip);
	return POINTER_FOLLOW_THUNK_EXIT;
}

static void * attr_fastcall io_any_handler(struct io_ctx *ctx)
{
	frame_s *fp = ctx->fp;
	frame_t slot_b = get_output(ctx, 0);
	frame_t slot_1 = get_input(ctx, 0);
	frame_t slot_2 = get_input(ctx, 1);

retry_1:
	if (!frame_variable_is_flat(fp, slot_1) && pointer_is_thunk(*frame_pointer(fp, slot_1))) {
		pointer_follow_thunk_noeval(frame_pointer(fp, slot_1),
			goto retry_1,
			goto return_1,
			break
		);
	} else {
return_1:
		io_store_flat_option(ctx, slot_b, false);
		return POINTER_FOLLOW_THUNK_GO;
	}
retry_2:
	if (!frame_variable_is_flat(fp, slot_2) && pointer_is_thunk(*frame_pointer(fp, slot_2))) {
		pointer_follow_thunk_noeval(frame_pointer(fp, slot_2),
			goto retry_2,
			goto return_2,
			break
		);
	} else {
return_2:
		io_store_flat_option(ctx, slot_b, true);
		return POINTER_FOLLOW_THUNK_GO;
	}

	eval_both(ctx->fp, ctx->ip, slot_1, slot_2);

	return POINTER_FOLLOW_THUNK_EXIT;
}

static void * attr_fastcall io_never_handler(struct io_ctx *ctx)
{
	struct execution_control *ex;

	ex = frame_execution_control(ctx->fp);

	iomux_never(&ex->wait[0].mutex_to_lock, &ex->wait[0].wait_entry);
	pointer_follow_wait(ctx->fp, ctx->ip);

	return POINTER_FOLLOW_THUNK_EXIT;
}

static void * attr_fastcall io_fork_handler(struct io_ctx *ctx)
{
	frame_s *fp = ctx->fp;
	frame_t slot_r1 = get_output(ctx, 0);
	frame_t slot_r2 = get_output(ctx, 1);
	frame_t slot = get_input(ctx, 0);

	ipret_copy_variable(fp, slot, fp, slot_r1, false);
	ipret_copy_variable(fp, slot, fp, slot_r2, false);

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_atomic_enter_handler(struct io_ctx *ctx)
{
	void *test;
	struct execution_control *ex;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO) && unlikely(test != POINTER_FOLLOW_THUNK_EXCEPTION))
		return test;

	ex = frame_execution_control(ctx->fp);
	ex->atomic++;

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_atomic_exit_handler(struct io_ctx *ctx)
{
	void *test;
	struct execution_control *ex;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO) && unlikely(test != POINTER_FOLLOW_THUNK_EXCEPTION))
		return test;

	ex = frame_execution_control(ctx->fp);

	if (unlikely(!ex->atomic))
		return POINTER_FOLLOW_THUNK_GO;

	if (likely(!--ex->atomic) && unlikely(ex->atomic_interrupted)) {
		ex->atomic_interrupted = false;
		ex->current_frame = ctx->fp;
		ex->current_ip = frame_ip(ctx->fp, ctx->ip);
		task_submit(ex, true);
		return POINTER_FOLLOW_THUNK_EXIT;
	}

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_int_to_native_handler(struct io_ctx *ctx)
{
	void *test;
	ajla_option_t o;
	frame_t f;
	union {
		short x0;
		unsigned short x1;
		int x2;
		unsigned x3;
		long x4;
		unsigned long x5;
#ifdef HAVE_LONG_LONG
		long long x6;
		unsigned long long x7;
#endif
		int16_t x8;
		uint16_t x9;
		int32_t x10;
		uint32_t x11;
#if TYPE_FIXED_N >= 4
		int64_t x12;
		uint64_t x13;
#endif
	} u;
	size_t size;
	struct data *d;

	test = io_deep_eval(ctx, "01", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	f = get_input(ctx, 1);

	io_get_option(ctx, get_input(ctx, 0), &o, NULL);

	switch (o) {
#define int_to_native_case(i, t)					\
		case i:	{						\
			io_get_number(ctx, f, int_default_t, t, u.x##i);\
			if (unlikely(test != POINTER_FOLLOW_THUNK_GO))	\
				return test;				\
			size = sizeof(t);				\
			break;						\
		}
		int_to_native_case(0, short);
		int_to_native_case(1, unsigned short);
		int_to_native_case(2, int);
		int_to_native_case(3, unsigned);
		int_to_native_case(4, long);
		int_to_native_case(5, unsigned long);
#ifdef HAVE_LONG_LONG
		int_to_native_case(6, long long);
		int_to_native_case(7, unsigned long long);
#endif
		int_to_native_case(8, int16_t);
		int_to_native_case(9, uint16_t);
		int_to_native_case(10, int32_t);
		int_to_native_case(11, uint32_t);
#if TYPE_FIXED_N >= 4
		int_to_native_case(12, int64_t);
		int_to_native_case(13, uint64_t);
#endif
		default:
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
			return POINTER_FOLLOW_THUNK_EXCEPTION;
#undef int_to_native_case
	}

	d = data_alloc_array_flat_mayfail(type_get_fixed(0, true), size, size, false, &ctx->err pass_file_line);
	if (unlikely(!d)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_GO;
	}

	memcpy(da_array_flat(d), &u, size);

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(d));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_native_to_int_handler(struct io_ctx *ctx)
{
	void *test;
	ajla_option_t o;
	frame_t f;

	test = io_deep_eval(ctx, "01", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	f = get_output(ctx, 0);

	io_get_bytes(ctx, get_input(ctx, 1));

	io_get_option(ctx, get_input(ctx, 0), &o, NULL);

	switch (o) {
#define native_to_int_case(i, t)					\
		case i: {						\
			t s;						\
			if (unlikely(ctx->str_l - 1 != sizeof(t)))	\
				goto invalid_op;			\
			s = *cast_ptr(t *, ctx->str);			\
			mem_free(ctx->str);				\
			io_store_typed_number(ctx, f, int_default_t, INT_DEFAULT_N, t, s);\
			if (unlikely(test != POINTER_FOLLOW_THUNK_GO))	\
				goto ret_test;				\
			break;						\
		}
		native_to_int_case(0, short);
		native_to_int_case(1, unsigned short);
		native_to_int_case(2, int);
		native_to_int_case(3, unsigned);
		native_to_int_case(4, long);
		native_to_int_case(5, unsigned long);
#ifdef HAVE_LONG_LONG
		native_to_int_case(6, long long);
		native_to_int_case(7, unsigned long long);
#endif
		native_to_int_case(8, int16_t);
		native_to_int_case(9, uint16_t);
		native_to_int_case(10, int32_t);
		native_to_int_case(11, uint32_t);
#if TYPE_FIXED_N >= 4
		native_to_int_case(12, int64_t);
		native_to_int_case(13, uint64_t);
#endif
		default:
		invalid_op:
			mem_free(ctx->str);
			io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), true, NULL);
			test = POINTER_FOLLOW_THUNK_EXCEPTION;
			goto ret_test;
#undef native_to_int_case
	}

	return POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_socket_handler(struct io_ctx *ctx)
{
	int pf, type, protocol;
	struct data *d = NULL;
	struct resource_handle *h;
	void *test;
	handle_t result;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 1), int, pf);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;
	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), int, type);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;
	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int, protocol);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	result = os_socket(pf, type, protocol, &ctx->err);
	if (unlikely(!handle_is_valid(result)))
		goto ret_thunk;

	h = da_resource(d);
	h->fd = result;
	h->nonblocking = true;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	if (d)
		data_free_r1(d);
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_bind_connect_handler(struct io_ctx *ctx)
{
	void *test;

	ctx->str = NULL;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));
	io_get_bytes(ctx, get_input(ctx, 2));
	ctx->str_l--;

	if (unlikely(!os_bind_connect(unlikely(ctx->code == IO_Bind), ctx->handle->fd, cast_ptr(unsigned char *, ctx->str), ctx->str_l, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_GO;
		goto ret_test;
	}

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	return test;
}

static void * attr_fastcall io_connect_wait_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	if (!iomux_test_handle(ctx->handle->fd, true)) {
		io_block_on_handle(ctx, true, false);
		return POINTER_FOLLOW_THUNK_EXIT;
	}

	if (unlikely(!os_connect_completed(ctx->handle->fd, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_GO;
	}

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_listen_handler(struct io_ctx *ctx)
{
	void *test;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	if (unlikely(!os_listen(ctx->handle->fd, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_GO;
	}

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_accept_handler(struct io_ctx *ctx)
{
	struct data *d = NULL;
	struct resource_handle *h;
	void *test;
	int r;
	handle_t result;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	d = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	r = os_accept(ctx->handle->fd, &result, &ctx->err);
	if (r == OS_RW_WOULDBLOCK) {
		data_free_r1(d);
		io_block_on_handle(ctx, false, false);
		return POINTER_FOLLOW_THUNK_EXIT;
	}
	if (unlikely(r == OS_RW_ERROR))
		goto ret_thunk;

	h = da_resource(d);
	h->fd = result;
	h->nonblocking = true;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	if (d)
		data_free_r1(d);
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_getsockpeername_handler(struct io_ctx *ctx)
{
	unsigned char *addr;
	size_t addr_len;
	struct data *a;
	void *test;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	if (unlikely(!os_getsockpeername(ctx->code == IO_Get_Peer_Name, ctx->handle->fd, &addr, &addr_len, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_GO;
	}

	a = array_from_flat_mem(type_get_fixed(0, true), cast_ptr(const char *, addr), addr_len, &ctx->err);
	mem_free(addr);
	if (unlikely(!a)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_GO;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(a));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_recvfrom_handler(struct io_ctx *ctx)
{
	void *test;
	int flags;
	int_default_t length;
	struct data *a = NULL, *d = NULL;
	unsigned char *addr = NULL;
	size_t addr_len;
	ssize_t rd;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));
	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), int_default_t, length);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;
	if (unlikely(length < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INT_TOO_LARGE);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}
	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int, flags);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = data_alloc_array_flat_mayfail(type_get_fixed(0, true), length, 0, false, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	rd = os_recvfrom(ctx->handle->fd, data_untag(da_array_flat(d)), length, flags, &addr, &addr_len, &ctx->err);
	if (rd == OS_RW_WOULDBLOCK) {
		data_free_r1(d);
		io_block_on_handle(ctx, false, false);
		return POINTER_FOLLOW_THUNK_EXIT;
	}
	if (unlikely(rd == OS_RW_ERROR))
		goto ret_thunk;

	da(d,array_flat)->n_used_entries = rd;

	a = data_alloc_array_flat_mayfail(type_get_fixed(0, true), addr_len, addr_len, false, &ctx->err pass_file_line);
	if (unlikely(!a))
		goto ret_thunk;

	memcpy(da_array_flat(a), addr, addr_len);
	mem_free(addr), addr = NULL;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));
	frame_set_pointer(ctx->fp, get_output(ctx, 2), pointer_data(a));

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	if (addr)
		mem_free(addr);
	if (d)
		data_free_r1(d);
	if (a)
		data_free_r1(a);
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_sendto_handler(struct io_ctx *ctx)
{
	int flags;
	void *test;
	ssize_t wr;

	test = io_deep_eval(ctx, "01234", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int, flags);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_handle(ctx, get_input(ctx, 1));
	io_get_bytes(ctx, get_input(ctx, 2));
	io_get_bytes2(ctx, get_input(ctx, 4));

	wr = os_sendto(ctx->handle->fd, ctx->str, ctx->str_l - 1, flags, cast_ptr(unsigned char *, ctx->str2), ctx->str2_l - 1, &ctx->err);

	mem_free(ctx->str);
	mem_free(ctx->str2);

	if (wr == OS_RW_WOULDBLOCK) {
		io_block_on_handle(ctx, false, false);
		test = POINTER_FOLLOW_THUNK_EXIT;
		goto ret_test;
	}
	if (unlikely(wr == OS_RW_ERROR)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_GO;
		goto ret_test;
	}
	io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, ssize_t, wr);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	return POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
}

static void * attr_fastcall io_getsockopt_handler(struct io_ctx *ctx)
{
	void *test;
	int l, opt;
	char b;
	char *result;
	size_t result_size;
	struct data *o;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), int, l);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int, opt);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	b = os_getsockopt(ctx->handle->fd, l, opt, &result, &result_size, &ctx->err);
	if (unlikely(!b))
		goto ret_thunk;

	o = data_alloc_array_flat_mayfail(type_get_fixed(0, true), result_size, result_size, false, &ctx->err pass_file_line);
	if (unlikely(!o)) {
		mem_free(result);
		goto ret_thunk;
	}

	memcpy(da_array_flat(o), result, result_size);
	mem_free(result);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(o));

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_setsockopt_handler(struct io_ctx *ctx)
{
	void *test;
	int l, opt;
	bool b;

	test = io_deep_eval(ctx, "01234", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_handle(ctx, get_input(ctx, 1));

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), int, l);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), int, opt);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_bytes(ctx, get_input(ctx, 4));

	b = os_setsockopt(ctx->handle->fd, l, opt, ctx->str, ctx->str_l - 1, &ctx->err);
	mem_free(ctx->str);
	if (unlikely(!b))
		goto ret_thunk;

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_getaddrinfo_handler(struct io_ctx *ctx)
{
	struct data *d;
	struct resource_handle *h;
	void *test;
	handle_t result[2];
	int port;

	ctx->str = NULL;
	d = NULL;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	io_get_bytes(ctx, get_input(ctx, 1));
	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 2), int, port);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_exc;

	if (unlikely(!os_pipe(result, 1, &ctx->err)))
		goto ret_thunk;

	h = da_resource(d);
	h->fd = result[0];
	h->nonblocking = true;

	if (!resolver_resolve(ctx->str, port, result[1], &ctx->err))
		goto ret_thunk_close;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	mem_free(ctx->str);

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk_close:
	os_close(result[0]);
	os_close(result[1]);
ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
ret_exc:
	if (d)
		data_free_r1(d);
	if (ctx->str)
		mem_free(ctx->str);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_getnameinfo_handler(struct io_ctx *ctx)
{
	struct data *d;
	struct resource_handle *h;
	void *test;
	handle_t result[2];

	ctx->str = NULL;
	d = NULL;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	io_get_bytes(ctx, get_input(ctx, 1));
	ctx->str_l--;

	if (unlikely(!os_pipe(result, 1, &ctx->err)))
		goto ret_thunk;

	h = da_resource(d);
	h->fd = result[0];
	h->nonblocking = true;

	if (!resolver_resolve_reverse(ctx->str, ctx->str_l, result[1], &ctx->err))
		goto ret_thunk_close;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	mem_free(ctx->str);

	return POINTER_FOLLOW_THUNK_GO;

ret_thunk_close:
	os_close(result[0]);
	os_close(result[1]);
ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	if (d)
		data_free_r1(d);
	if (ctx->str)
		mem_free(ctx->str);
	return POINTER_FOLLOW_THUNK_GO;
}

static void io_get_msgqueue(struct io_ctx *ctx, frame_t slot)
{
	pointer_t ptr;
	struct data *d;
	struct resource_msgqueue *q;

	ptr = *frame_pointer(ctx->fp, slot);

	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_get_handle: pointer is thunk"));
	d = pointer_get_data(ptr);

	q = da_resource(d);
	ctx->msgqueue = q;
}

static void * attr_fastcall io_msgqueue_new_handler(struct io_ctx *ctx)
{
	struct data *d;
	struct resource_msgqueue *q;
	void *test;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = data_alloc_resource_mayfail(sizeof(struct resource_msgqueue), msgqueue_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_thunk;

	q = da_resource(d);
	q->queue = mem_alloc_array_mayfail(mem_alloc_mayfail, struct msgqueue_entry *, 0, 0, 1, sizeof(struct msgqueue_entry), &ctx->err);
	if (unlikely(!q->queue))
		goto free_d_ret_thunk;
	q->queue_len = 0;
	q->queue_allocated = 1;

	list_init(&q->wait_list);

	mutex_lock(&msgqueue_list_mutex);
	list_add(&msgqueue_list, &q->list_entry);
	mutex_unlock(&msgqueue_list_mutex);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	return POINTER_FOLLOW_THUNK_GO;

free_d_ret_thunk:
	data_free_r1(d);
ret_thunk:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_msgqueue_send_handler(struct io_ctx *ctx)
{
	void *test;
	struct resource_msgqueue *q;
	struct msgqueue_entry qe;
	struct msgqueue_entry *to_free;
	size_t to_free_len;
	struct msgqueue_entry *prealloc;
	size_t need_alloc;
	unsigned params = get_param(ctx, 0);
	bool replace = !!(params & 1);

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_msgqueue(ctx, get_input(ctx, 1));

	q = ctx->msgqueue;

	qe.tag = ipret_copy_variable_to_pointer(ctx->fp, get_input(ctx, 2), false);
	if (unlikely(pointer_is_thunk(qe.tag))) {
		io_terminate_with_thunk(ctx, pointer_get_thunk(qe.tag));
		return POINTER_FOLLOW_THUNK_GO;
	}
	qe.ptr = ipret_copy_variable_to_pointer(ctx->fp, get_input(ctx, 3), false);

	prealloc = NULL;
	need_alloc = 0;
alloc_more:
	if (unlikely(prealloc != NULL)) {
		mem_free(prealloc);
		prealloc = NULL;
	}
	if (unlikely(need_alloc != 0)) {
		prealloc = mem_alloc_array_mayfail(mem_alloc_mayfail, struct msgqueue_entry *, 0, 0, need_alloc, sizeof(struct msgqueue_entry), &ctx->err);
		if (unlikely(!prealloc)) {
free_ret_ex:
			pointer_dereference(qe.tag);
			pointer_dereference(qe.ptr);
			io_terminate_with_error(ctx, ctx->err, true, NULL);
			return POINTER_FOLLOW_THUNK_GO;
		}
	}

	to_free = NULL;
	to_free_len = 0;

	address_lock(q, DEPTH_THUNK);
	if (replace) {
		if (need_alloc < q->queue_len) {
			need_alloc = q->queue_len;
			address_unlock(q, DEPTH_THUNK);
			goto alloc_more;
		}
		memcpy(prealloc, q->queue, q->queue_len * sizeof(struct msgqueue_entry));
		to_free = prealloc;
		to_free_len = q->queue_len;
		q->queue_len = 0;
		prealloc = NULL;
	}
	if (unlikely(q->queue_len == q->queue_allocated)) {
		if (need_alloc <= q->queue_allocated) {
			need_alloc = q->queue_allocated * 2;
			address_unlock(q, DEPTH_THUNK);
			if (unlikely(need_alloc <= q->queue_allocated)) {
				ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
				goto free_ret_ex;
			}
			goto alloc_more;
		}
		memcpy(prealloc, q->queue, q->queue_len * sizeof(struct msgqueue_entry));
		to_free = q->queue;
		to_free_len = 0;
		q->queue = prealloc;
		q->queue_allocated = need_alloc;
	} else {
		if (unlikely(prealloc != NULL)) {
			to_free = prealloc;
			to_free_len = 0;
		}
	}
	q->queue[q->queue_len] = qe;
	q->queue_len++;
	wake_up_wait_list(&q->wait_list, address_get_mutex(q, DEPTH_THUNK), true);

	if (to_free) {
		size_t i;
		for (i = 0; i < to_free_len; i++) {
			pointer_dereference(to_free[i].tag);
			pointer_dereference(to_free[i].ptr);
		}
		mem_free(to_free);
	}
	return POINTER_FOLLOW_THUNK_GO;
}

static bool msgqueue_numbers_equal(pointer_t num1, pointer_t num2)
{
	return !data_compare_numbers(TYPE_TAG_unknown, NULL, num1, NULL, num2);
}

static void * attr_fastcall io_msgqueue_receive_handler(struct io_ctx *ctx)
{
	void *test;
	struct resource_msgqueue *q;
	struct msgqueue_entry qe;
	size_t pos;
	pointer_t select_number = pointer_empty();	/* avoid warning */
	unsigned params = get_param(ctx, 0);
	bool select_tag = !!(params & 1);
	bool nonblock = !!(params & 2);
	bool peek = !!(params & 4);

	test = io_deep_eval(ctx, !select_tag ? "01" : "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_msgqueue(ctx, get_input(ctx, 1));
	q = ctx->msgqueue;

	if (select_tag) {
		select_number = ipret_copy_variable_to_pointer(ctx->fp, get_input(ctx, 2), false);
		if (unlikely(pointer_is_thunk(select_number))) {
			io_terminate_with_thunk(ctx, pointer_get_thunk(select_number));
			return POINTER_FOLLOW_THUNK_GO;
		}
	}
	address_lock(q, DEPTH_THUNK);
	for (pos = 0; pos < q->queue_len; pos++) {
		if (!select_tag)
			goto found;
		if (msgqueue_numbers_equal(q->queue[pos].tag, select_number))
			goto found;
	}

	if (!nonblock) {
		struct execution_control *ex = frame_execution_control(ctx->fp);
		list_add(&q->wait_list, &ex->wait[0].wait_entry);
		ex->wait[0].mutex_to_lock = address_get_mutex(q, DEPTH_THUNK);
		address_unlock(q, DEPTH_THUNK);
		pointer_follow_wait(ctx->fp, ctx->ip);
		if (select_tag)
			pointer_dereference(select_number);
		return POINTER_FOLLOW_THUNK_EXIT;
	} else {
		ajla_error_t e;
		struct thunk *t;
		address_unlock(q, DEPTH_THUNK);
		e = error_ajla(EC_SYNC, AJLA_ERROR_NOT_FOUND);
		t = thunk_alloc_exception_error(e, NULL, ctx->fp, ctx->ip pass_file_line);
		pointer_reference_owned(pointer_thunk(t));
		frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_thunk(t));
		frame_set_pointer(ctx->fp, get_output(ctx, 2), pointer_thunk(t));
		if (select_tag)
			pointer_dereference(select_number);
		return POINTER_FOLLOW_THUNK_GO;
	}

found:
	qe = q->queue[pos];
	if (!peek) {
		memmove(q->queue + pos, q->queue + pos + 1, (q->queue_len - pos - 1) * sizeof(struct msgqueue_entry));
		q->queue_len--;
	} else {
		pointer_reference_owned(qe.tag);
		pointer_reference_owned(qe.ptr);
	}
	address_unlock(q, DEPTH_THUNK);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), qe.tag);
	frame_set_pointer(ctx->fp, get_output(ctx, 2), qe.ptr);

	if (select_tag)
		pointer_dereference(select_number);

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_msgqueue_wait_handler(struct io_ctx *ctx)
{
	void *test;
	struct resource_msgqueue *q;

	test = io_deep_eval(ctx, "01", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_msgqueue(ctx, get_input(ctx, 1));
	q = ctx->msgqueue;

	address_lock(q, DEPTH_THUNK);
	if (!q->queue_len) {
		struct execution_control *ex = frame_execution_control(ctx->fp);
		list_add(&q->wait_list, &ex->wait[0].wait_entry);
		ex->wait[0].mutex_to_lock = address_get_mutex(q, DEPTH_THUNK);
		address_unlock(q, DEPTH_THUNK);
		pointer_follow_wait(ctx->fp, ctx->ip);
		return POINTER_FOLLOW_THUNK_EXIT;
	}
	address_unlock(q, DEPTH_THUNK);

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_msgqueue_is_nonempty_handler(struct io_ctx *ctx)
{
	void *test;
	struct resource_msgqueue *q;
	ajla_flat_option_t val;

	test = io_deep_eval(ctx, "01", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_msgqueue(ctx, get_input(ctx, 1));
	q = ctx->msgqueue;

	address_lock(q, DEPTH_THUNK);
	val = !!q->queue_len;
	address_unlock(q, DEPTH_THUNK);

	io_store_flat_option(ctx, get_output(ctx, 0), val);

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_load_program_handler(struct io_ctx *ctx)
{
	void *test;
	size_t i;
	unsigned path_idx;
	struct module_designator *md = NULL;
	struct function_designator *fd = NULL;
	pointer_t *main_ptr;
	struct data *main_ref;

	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_bytes(ctx, get_input(ctx, 1));
	ctx->str_l--;

	if (ctx->str_l >= 5 && !strcasecmp(ctx->str + ctx->str_l - 5, ".ajla")) {
		ctx->str_l -= 5;
	}

	get_lib_path();
	path_idx = 0;
	for (i = 0; i < lib_path_len; i++)
		path_idx += !lib_path[i];
	path_idx--;

	md = module_designator_alloc(path_idx, cast_ptr(const uint8_t *, ctx->str), ctx->str_l, true, &ctx->err);
	mem_free(ctx->str);

	if (unlikely(!md))
		goto ret_err;

	fd = function_designator_alloc_single(0, &ctx->err);
	if (unlikely(!fd)) {
		module_designator_free(md);
		goto ret_err;
	}

	main_ptr = module_load_function(md, fd, false, &ctx->err);
	module_designator_free(md);
	function_designator_free(fd);

	if (!main_ptr)
		goto ret_err;

	main_ref = data_alloc_function_reference_mayfail(0, &ctx->err pass_file_line);
	if (unlikely(!main_ref))
		goto ret_err;
	da(main_ref,function_reference)->is_indirect = false;
	da(main_ref,function_reference)->u.direct = main_ptr;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(main_ref));
	return POINTER_FOLLOW_THUNK_GO;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	return test;
}

static void * attr_fastcall io_get_function_ptr_handler(struct io_ctx *ctx)
{
	void *test;
	struct data *d;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	d = pointer_get_data(*frame_pointer(ctx->fp, get_input(ctx, 0)));

	ajla_assert_lo(!da(d,function_reference)->is_indirect, (file_line, "io_get_function_ptr_handler: the reference is not direct"));

	barrier_aliasing();
	*frame_slot(ctx->fp, get_output(ctx, 0), uint64_t) = ptr_to_num(da(d,function_reference)->u.direct);
	barrier_aliasing();

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_get_subfunctions_handler(struct io_ctx *ctx)
{
	void *test;
	int64_t i64;
	pointer_t *fptr;
	struct data *function, *o;
	frame_t x;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_int64_t(ctx, get_input(ctx, 0), &i64, NULL);
	fptr = num_to_ptr((uintptr_t)i64);

	pointer_follow(fptr, false, function, PF_WAIT, ctx->fp, ctx->ip,
		return ex_,
		thunk_reference(thunk_);
		io_terminate_with_thunk(ctx, thunk_);
		return POINTER_FOLLOW_THUNK_GO;
	);

	o = data_alloc_array_flat_mayfail(type_get_fixed(3, true), da(function,function)->local_directory_size, da(function,function)->local_directory_size, false, &ctx->err pass_file_line);
	if (unlikely(!o)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		return POINTER_FOLLOW_THUNK_EXCEPTION;
	}

	for (x = 0; x < da(function,function)->local_directory_size; x++) {
		uintptr_t sub = ptr_to_num(da(function,function)->local_directory[x]);
		cast_ptr(uint64_t *, da_array_flat(o))[x] = sub;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(o));

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_load_optimized_pcode_handler(struct io_ctx *ctx)
{
	void *test;
	pcode_t path_idx;
	ajla_option_t program;
	struct module_designator *md = NULL;
	struct function_designator *fd = NULL;
	pointer_t *ptr;

	ctx->str = NULL;
	ctx->str2 = NULL;

	test = io_deep_eval(ctx, "0123", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_pcode_t(ctx, get_input(ctx, 0), &path_idx);
	io_get_bytes(ctx, get_input(ctx, 1));
	io_get_option(ctx, get_input(ctx, 2), &program, NULL);
	io_get_bytes2(ctx, get_input(ctx, 3));

	md = module_designator_alloc(path_idx, cast_ptr(uint8_t *, ctx->str), ctx->str_l - 1, program, &ctx->err);
	if (unlikely(!md)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}
	fd = function_designator_alloc(cast_ptr(pcode_t *, ctx->str2), &ctx->err);
	if (unlikely(!fd)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	ptr = module_load_function(md, fd, true, &ctx->err);
	if (unlikely(!ptr)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_reference(ptr));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	if (ctx->str2)
		mem_free(ctx->str2);
	if (md)
		module_designator_free(md);
	if (fd)
		function_designator_free(fd);
	return test;
}

static void * attr_fastcall io_register_dependence_handler(struct io_ctx *ctx)
{
	void *test;
	test = io_deep_eval(ctx, "01", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_bytes(ctx, get_input(ctx, 1));
	save_register_dependence(ctx->str);
	mem_free(ctx->str);
	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_deep_eval_handler(struct io_ctx *ctx)
{
	void *test;
	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	ipret_copy_variable(ctx->fp, get_input(ctx, 0), ctx->fp, get_output(ctx, 0), false);

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_evaluate_handler(struct io_ctx *ctx)
{
	void *test;
	pcode_t src_type, dest_type, op;
	const struct type *src_t, *dest_t;
	pointer_t fn = pointer_empty();
	frame_s *fp = NULL;
	struct stack_bottom *st = NULL;
	pointer_t res_ptr = pointer_empty();
	pcode_t *res_blob = NULL;
	size_t res_blob_len;
	struct data *a;

	ctx->str = NULL;
	ctx->str2 = NULL;

	test = io_deep_eval(ctx, ctx->n_inputs == 4 ? "0123" : "01234", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

#if 0
	goto unsup;
#endif

	io_get_pcode_t(ctx, get_input(ctx, 0), &src_type);
	io_get_pcode_t(ctx, get_input(ctx, 1), &dest_type);
	io_get_pcode_t(ctx, get_input(ctx, 2), &op);

	ajla_assert_lo(Op_IsBinary(op) || Op_IsUnary(op), (file_line, "io_evaluate_handler: invalid operator %ld (%ld, %ld)", (long)op, (long)src_type, (long)dest_type));
	ajla_assert_lo(ctx->n_inputs == (uchar_efficient_t)(Op_IsBinary(op) ? 5 : 4), (file_line, "io_evaluate_handler: bad number of arguments %u, op %ld", ctx->n_inputs, (long)op));

	src_t = pcode_get_type(src_type);
	dest_t = pcode_get_type(dest_type);

	if (unlikely(!src_t) || unlikely(!dest_t))
		goto unsup;

	if (unlikely(ipret_is_privileged)) {
		if (unlikely(op == Un_SystemProperty))
			goto unsup;
		if (TYPE_TAG_IS_REAL(src_t->tag) || TYPE_TAG_IS_REAL(dest_t->tag))
			goto unsup;
	}

	io_get_bytes(ctx, get_input(ctx, 3));
	ctx->str_l--;
	if (ctx->n_inputs == 5) {
		io_get_bytes2(ctx, get_input(ctx, 4));
		ctx->str2_l--;
	} else {
		ctx->str2_l = 0;
	}

	ajla_assert_lo(!(ctx->str_l % sizeof(pcode_t)) && !(ctx->str2_l % sizeof(pcode_t)), (file_line, "io_evaluate_handler: invalid length of blobs: %"PRIuMAX", %"PRIuMAX"", (uintmax_t)ctx->str_l, (uintmax_t)ctx->str2_l));

	fn = pcode_build_eval_function(src_type, dest_type, op, cast_ptr(pcode_t *, ctx->str), ctx->str_l / sizeof(pcode_t), cast_ptr(pcode_t *, ctx->str2), ctx->str2_l / sizeof(pcode_t), &ctx->err);
	if (unlikely(pointer_is_empty(fn))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	fp = stack_alloc(NULL, pointer_get_data(fn), &ctx->err);
	if (unlikely(!fp))
		goto ret_test;

	frame_init(fp, pointer_get_data(fn), 0, CALL_MODE_STRICT);

	st = frame_stack_bottom(fp);
	st->ret = pointer_empty();

	run(fp, 0);

	res_ptr = st->ret;

	ajla_assert_lo(!pointer_is_empty(res_ptr), (file_line, "io_evaluate_handler: the result pointer was not set"));

	if (unlikely(pointer_is_thunk(res_ptr))) {
		pointer_reference_owned(res_ptr);
		io_terminate_with_thunk(ctx, pointer_get_thunk(res_ptr));
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	if (unlikely(!pcode_generate_blob_from_value(res_ptr, dest_type, &res_blob, &res_blob_len, &ctx->err))) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	a = array_from_flat_mem(type_get_fixed(log_2(sizeof(pcode_t)), false), cast_ptr(const char *, res_blob), res_blob_len, &ctx->err);
	if (unlikely(!a)) {
		io_terminate_with_error(ctx, ctx->err, true, NULL);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(a));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	if (ctx->str2)
		mem_free(ctx->str2);
	if (!pointer_is_empty(fn))
		pointer_dereference(fn);
	if (st)
		stack_free(st);
	if (!pointer_is_empty(res_ptr))
		pointer_dereference(res_ptr);
	if (res_blob)
		mem_free(res_blob);
	return test;

unsup:
	io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), false, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_debug_handler(struct io_ctx *ctx)
{
	void *test;
	unsigned p;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		return test;

	io_get_bytes(ctx, get_input(ctx, 0));

	p = get_param(ctx, 0);

	if (!p) {
#if 1
		debug("%s", ctx->str);
#else
		debug("%u: %s", tick_stamp, ctx->str);
#endif
	} else if (p == 1) {
		struct stack_trace st;
		stack_trace_capture(&st, ctx->fp, ctx->ip, 20);
		stack_trace_print(&st);
		stack_trace_free(&st);
		internal(file_line, "%s", ctx->str);
	} else if (p == 2) {
		debug("stop at %s", ctx->str);
		os_stop();
	} else if (p == 3) {
		mem_report_usage(MR_SUMMARY, ctx->str);
	} else if (p == 4) {
		mem_report_usage(MR_MOST_ALLOCATED, ctx->str);
	} else if (p == 5) {
		mem_report_usage(MR_LARGEST_BLOCKS, ctx->str);
	} else {
		internal(file_line, "io_debug_handler: invalid parameter %u", p);
	}

	mem_free(ctx->str);

	set_uniq_type(ctx);

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_stacktrace_handler(struct io_ctx *ctx)
{
	void *ex;
	struct thunk *thunk;
	frame_t slot = get_input(ctx, 0);

	ex = frame_pointer_deep_eval(ctx->fp, ctx->ip, slot, &thunk);
	if (likely(ex != POINTER_FOLLOW_THUNK_EXCEPTION))
		return ex;

	thunk_exception_print(thunk);

	pointer_dereference(pointer_thunk(thunk));

	set_uniq_type(ctx);

	return POINTER_FOLLOW_THUNK_GO;
}

static void * attr_fastcall io_trace_ctl_handler(struct io_ctx *ctx)
{
	frame_t p = get_param(ctx, 0);

	if (!p) {
#ifdef DEBUG_TRACE
		store_relaxed(&trace_enabled, 0);
#endif
	} else if (p == 1) {
#ifdef DEBUG_TRACE
		store_relaxed(&trace_enabled, 1);
#endif
	} else {
		internal(file_line, "io_trace_ctl_handler: invalid parameter %"PRIuMAX"", (uintmax_t)p);
	}

	set_uniq_type(ctx);

	return POINTER_FOLLOW_THUNK_GO;
}

#if defined(SUPPORTS_FFI)
#include "ipio_ffi.inc"
#else
static void * attr_fastcall io_ffi_unsupported(struct io_ctx *ctx)
{
	io_terminate_with_error(ctx, error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED), true, NULL);
	return POINTER_FOLLOW_THUNK_EXCEPTION;
}
#define io_ffi_get_size_alignment_handler	io_ffi_unsupported
#define io_ffi_create_structure_handler		io_ffi_unsupported
#define io_ffi_structure_offset_handler		io_ffi_unsupported
#define io_ffi_poke_handler			io_ffi_unsupported
#define io_ffi_peek_handler			io_ffi_unsupported
#define io_ffi_poke_array_handler		io_ffi_unsupported
#define io_ffi_peek_array_handler		io_ffi_unsupported
#define io_ffi_create_function_handler		io_ffi_unsupported
#define io_ffi_call_function_handler		io_ffi_unsupported
#define io_ffi_destructor_new_handler		io_ffi_unsupported
#define io_ffi_destructor_allocate_handler	io_ffi_unsupported
#define io_ffi_destructor_free_handler		io_ffi_unsupported
#define io_ffi_destructor_call_handler		io_ffi_unsupported
#define io_ffi_handle_to_number_handler		io_ffi_unsupported
#define io_ffi_number_to_handle_handler		io_ffi_unsupported
#endif

static void * attr_fastcall io_ffi_encode_real_handler(struct io_ctx *ctx)
{
	void *test;
	frame_t slot;
	const struct type *type;
	unsigned char *var;
	struct data *d;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	slot = get_input(ctx, 0);
	type = frame_get_type_of_local(ctx->fp, slot);

	var = io_get_flat_pointer(ctx, slot);

	d = data_alloc_longint_mayfail(type->size * 8, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_err;
	mpz_import(&da(d,longint)->mp, type->size, -1, 1, 0, 0, var);
	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(d));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;
ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_decode_real_handler(struct io_ctx *ctx)
{
	void *test;
	frame_t slot, slot_out;
	const struct type *type;
	int_default_t in;
	const mpint_t *mp = NULL;
	mpint_t m;
	unsigned char *result;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	slot = get_input(ctx, 0);
	slot_out = get_output(ctx, 0);
	type = frame_get_type_of_local(ctx->fp, slot_out);
	result = frame_var(ctx->fp, slot_out);

	memset(result, 0, type->size);

	cat(io_get_,int_default_t)(ctx, slot, &in, &mp);

	if (!mp) {
		if (unlikely(!mpint_alloc_mayfail(&m, sizeof(int_default_t) * 8, &ctx->err)))
			goto ret_err;
		mpint_import_from_variable(&m, int_default_t, in);
		mp = &m;
	}

	if (unlikely(mpz_sgn(mp) < 0))
		goto doesnt_fit;
	if (unlikely(mpz_sizeinbase(mp, 2) > (size_t)8 * type->size))
		goto doesnt_fit;
	mpz_export(result, NULL, -1, 1, 0, 0, mp);

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (mp == &m)
		mpint_free(&m);
	return test;

doesnt_fit:
	ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT);
ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static const struct {
	void *(attr_fastcall *do_io)(struct io_ctx *ctx);
} io_handlers [] = {
	{ io_exception_make_handler },
	{ io_exception_string_handler },
	{ io_exception_payload_handler },
	{ io_exception_stack_handler },
	{ io_n_std_handles_handler },
	{ io_get_std_handle_handler },
	{ io_get_args_handler },
	{ io_get_environment_handler },
	{ io_stream_open_handler },
	{ io_stream_read_handler },
	{ io_stream_open_handler },
	{ io_stream_write_handler },
	{ io_read_console_packet_handler },
	{ io_write_console_packet_handler },
	{ io_pipe_handler },
	{ io_stream_open_handler },
	{ io_stream_read_handler },
	{ io_stream_write_handler },
	{ io_lseek_handler },
	{ io_ftruncate_handler },
	{ io_fallocate_handler },
	{ io_fclone_range_handler },
	{ io_fsync_handler },
	{ io_sync_handler },
	{ io_root_dir_handler },
	{ io_lib_path_handler },
	{ io_open_dir_handler },
	{ io_read_dir_handler },
	{ io_dir_path_handler },
	{ io_dmonitor_prepare_handler },
	{ io_dmonitor_wait_handler },
	{ io_stat_handler },
	{ io_fstat_handler },
	{ io_fstatfs_handler },
	{ io_dstatfs_handler },
	{ io_readlink_handler },
	{ io_dir_action_handler },
	{ io_dir2_action_handler },
	{ io_stty_handler },
	{ io_tty_size_handler },
	{ io_uname_handler },
	{ io_get_host_name_handler },
	{ io_spawn_handler },
	{ io_wait_handler },
	{ io_get_time_handler },
	{ io_time_to_calendar_handler },
	{ io_calendar_to_time_handler },
	{ io_sleep_handler },
	{ io_any_handler },
	{ io_never_handler },
	{ io_fork_handler },
	{ io_atomic_enter_handler },
	{ io_atomic_exit_handler },
	{ io_int_to_native_handler },
	{ io_native_to_int_handler },
	{ io_socket_handler },
	{ io_bind_connect_handler },
	{ io_connect_wait_handler },
	{ io_bind_connect_handler },
	{ io_listen_handler },
	{ io_accept_handler },
	{ io_getsockpeername_handler },
	{ io_getsockpeername_handler },
	{ io_recvfrom_handler },
	{ io_sendto_handler },
	{ io_getsockopt_handler },
	{ io_setsockopt_handler },
	{ io_getaddrinfo_handler },
	{ io_getnameinfo_handler },
	{ io_msgqueue_new_handler },
	{ io_msgqueue_send_handler },
	{ io_msgqueue_receive_handler },
	{ io_msgqueue_wait_handler },
	{ io_msgqueue_is_nonempty_handler },
	{ io_load_program_handler },
	{ io_get_function_ptr_handler },
	{ io_get_subfunctions_handler },
	{ io_load_optimized_pcode_handler },
	{ io_register_dependence_handler },
	{ io_deep_eval_handler },
	{ io_evaluate_handler },
	{ io_debug_handler },
	{ io_stacktrace_handler },
	{ io_trace_ctl_handler },
	{ io_ffi_get_size_alignment_handler },
	{ io_ffi_create_structure_handler },
	{ io_ffi_structure_offset_handler },
	{ io_ffi_poke_handler },
	{ io_ffi_peek_handler },
	{ io_ffi_poke_array_handler },
	{ io_ffi_peek_array_handler },
	{ io_ffi_handle_to_number_handler },
	{ io_ffi_number_to_handle_handler },
	{ io_ffi_create_function_handler },
	{ io_ffi_call_function_handler },
	{ io_ffi_encode_real_handler },
	{ io_ffi_decode_real_handler },
	{ io_ffi_destructor_new_handler },
	{ io_ffi_destructor_allocate_handler },
	{ io_ffi_destructor_free_handler },
	{ io_ffi_destructor_call_handler },
};

void *ipret_io(frame_s *fp, const code_t *ip, unsigned char io_code, unsigned char n_outputs, unsigned char n_inputs, unsigned char n_params)
{
	struct io_ctx ctx;
	void *ex;
	if (n_array_elements(io_handlers) != IO_N)
		internal(file_line, "io_handlers doesn't match consts.txt: %lu != %lu", (unsigned long)n_array_elements(io_handlers), (unsigned long)IO_N);
	ctx.code = io_code;
	ctx.fp = fp;
	ctx.ip = ip;
	ctx.outputs = ip + 3;
	ctx.inputs = ctx.outputs + n_outputs * 2;
	ctx.params = ctx.inputs + n_inputs * 2;
	ctx.n_outputs = n_outputs;
	ctx.n_inputs = n_inputs;
	ctx.n_params = n_params;
	ajla_assert_lo(io_code < n_array_elements(io_handlers), (file_line, "ipret_io: invalid io code %d", (int)io_code));
	ex = io_handlers[io_code].do_io(&ctx);
	if (unlikely(ex == POINTER_FOLLOW_THUNK_EXCEPTION))
		ex = POINTER_FOLLOW_THUNK_GO;
	return ex;
}

void name(ipio_init)(void)
{
	mutex_init(&lib_path_mutex);
	lib_path = NULL;

	mutex_init(&msgqueue_list_mutex);
	list_init(&msgqueue_list);
}

void name(ipio_done)(void)
{
	struct list *l;
	if (unlikely(!list_is_empty(&msgqueue_list)))
		warning("there was leaked message queue");
again:
	list_for_each(l, &msgqueue_list) {
		struct resource_msgqueue *q = get_struct(l, struct resource_msgqueue, list_entry);
		if (q->queue_len) {
			struct msgqueue_entry qe = q->queue[q->queue_len - 1];
			q->queue_len--;
			pointer_dereference(qe.tag);
			pointer_dereference(qe.ptr);
			goto again;
		}
	}
	mutex_done(&msgqueue_list_mutex);

	if (lib_path)
		mem_free(lib_path);
	mutex_done(&lib_path_mutex);
}

#endif
