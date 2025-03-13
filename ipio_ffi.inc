/*
 * Copyright (C) 2024, 2025 Mikulas Patocka
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

#define MAX_FFI_TYPE_SIZE	16

struct ffi_library {
	struct list list_entry;
	struct dl_handle_t *dlh;
	uintptr_t refcount;
	void (*destructor)(void);
	bool hold;
	char name[FLEXIBLE_ARRAY];
};

static mutex_t ffi_libraries_mutex;
static struct list ffi_libraries;

static void library_destroy(struct ffi_library *lib)
{
	if (lib->destructor)
		lib->destructor();
	os_dlclose(lib->dlh);
	list_del(&lib->list_entry);
	mem_free(lib);
}

static struct ffi_library *library_load(const char *name, bool hold, const char *destructor, ajla_error_t *err, char **err_msg)
{
	struct list *l;
	struct ffi_library *lib;
	void *sym;
	*err_msg = NULL;
	if (name) {
		if (unlikely(!name[0])) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION), err, "invalid library name");
			return NULL;
		}
	} else {
		name = "";
	}
	mutex_lock(&ffi_libraries_mutex);
	list_for_each(l, &ffi_libraries) {
		lib = get_struct(l, struct ffi_library, list_entry);
		if (!strcmp(lib->name, name)) {
			lib->refcount++;
			if (hold)
				lib->hold = true;
			mutex_unlock(&ffi_libraries_mutex);
			return lib;
		}
	}
	lib = struct_alloc_array_mayfail(mem_alloc_mayfail, struct ffi_library, name, strlen(name) + 1, err);
	if (unlikely(!lib)) {
		mutex_unlock(&ffi_libraries_mutex);
		return NULL;
	}
	lib->refcount = 1;
	lib->hold = hold;
	strcpy(lib->name, name);
	lib->dlh = os_dlopen(name, err, err_msg);
	if (unlikely(!lib->dlh)) {
		mutex_unlock(&ffi_libraries_mutex);
		mem_free(lib);
		return NULL;
	}
	if (destructor && destructor[0]) {
		if (unlikely(!os_dlsym(lib->dlh, destructor, &sym))) {
			fatal_mayfail(error_ajla(EC_SYNC, AJLA_ERROR_SYMBOL_NOT_FOUND), err, "destructor symbol not found");
			os_dlclose(lib->dlh);
			mutex_unlock(&ffi_libraries_mutex);
			mem_free(lib);
			return NULL;
		}
		lib->destructor = cast_ptr(void (*)(void), sym);
	} else {
		lib->destructor = NULL;
	}
	list_add(&ffi_libraries, &lib->list_entry);
	mutex_unlock(&ffi_libraries_mutex);
	return lib;
}

static void library_unload(struct ffi_library *lib)
{
	mutex_lock(&ffi_libraries_mutex);
	ajla_assert_lo(lib->refcount != 0, (file_line, "library_unload: refcount underflow"));
	if (!--lib->refcount && !lib->hold)
		library_destroy(lib);
	mutex_unlock(&ffi_libraries_mutex);
}

struct resource_ffi_library {
	struct ffi_library *lib;
};

struct resource_ffi {
	struct resource_ffi_library *rfl;
	void *sym;
	ajla_option_t err_type;
	ffi_type **args;
	uchar_efficient_t *ctx_args;
	unsigned n_args;
	ffi_type *ret_ffi_type;
	ajla_option_t ret_type;
	ffi_cif cif;
};

struct resource_ffi_structure {
	ffi_type typ;
	unsigned n_elements;
	size_t *offsets;
};

static void free_type(ffi_type *ft)
{
	if (ft->type == FFI_TYPE_STRUCT) {
		struct resource_ffi_structure *rfs = get_struct(ft, struct resource_ffi_structure, typ);
		struct data *da = cast_ptr(struct data *, cast_ptr(char *, rfs) - data_resource_offset);
		pointer_dereference(pointer_data(da));
	}
}

static void resource_ffi_library_close(struct data *d)
{
	struct resource_ffi_library *rfl = da_resource(d);
	library_unload(rfl->lib);
}

static void resource_ffi_close(struct data *d)
{
	unsigned i;
	struct resource_ffi *rf = da_resource(d);
	struct data *da = cast_ptr(struct data *, cast_ptr(char *, rf->rfl) - data_resource_offset);
	pointer_dereference(pointer_data(da));
	for (i = 0; i < rf->n_args; i++)
		free_type(rf->args[i]);
	mem_free(rf->args);
	mem_free(rf->ctx_args);
	free_type(rf->ret_ffi_type);
}

static void resource_ffi_structure_close(struct data *d)
{
	unsigned i;
	struct resource_ffi_structure *rfs = da_resource(d);
	for (i = 0; i < rfs->n_elements; i++)
		free_type(rfs->typ.elements[i]);
	mem_free(rfs->typ.elements);
	mem_free(rfs->offsets);
}

#define T_VOID			0
#define T_UNSIGNED		1
#define T_SIGNED		2
#define T_REAL			3

/* this must be in sync with option ffi_type */
static const struct {
	ffi_type *ft;
	unsigned char size;
	unsigned char sign;
} ajla_type_to_ffi_type_table[24] = {
	{ &ffi_type_void,	0,			T_VOID,		},
	{ &ffi_type_uint8,	1,			T_UNSIGNED,	},
	{ &ffi_type_sint8,	1,			T_SIGNED,	},
	{ &ffi_type_uint16,	2,			T_UNSIGNED,	},
	{ &ffi_type_sint16,	2,			T_SIGNED,	},
	{ &ffi_type_uint32,	4,			T_UNSIGNED,	},
	{ &ffi_type_sint32,	4,			T_SIGNED,	},
	{ &ffi_type_uint64,	8,			T_UNSIGNED,	},
	{ &ffi_type_sint64,	8,			T_SIGNED,	},
	{ &ffi_type_float,	sizeof(float),		T_REAL,		},
	{ &ffi_type_double,	sizeof(double),		T_REAL,		},
#if REAL_MASK & 0x08
	{ &ffi_type_longdouble,	sizeof(real80_t),	T_REAL,		},
#elif REAL_MASK & 0x10
	{ &ffi_type_longdouble,	sizeof(real128_t),	T_REAL,		},
#else
	{ &ffi_type_longdouble,	sizeof(double),		T_REAL,		},
#endif
	{ &ffi_type_pointer,	sizeof(void *),		T_UNSIGNED,	},
	{ &ffi_type_uchar,	1,			T_UNSIGNED,	},
	{ &ffi_type_schar,	1,			T_SIGNED,	},
	{ &ffi_type_ushort,	sizeof(unsigned short),	T_UNSIGNED,	},
	{ &ffi_type_sshort,	sizeof(short),		T_SIGNED,	},
	{ &ffi_type_uint,	sizeof(unsigned),	T_UNSIGNED,	},
	{ &ffi_type_sint,	sizeof(int),		T_SIGNED,	},
	{ &ffi_type_ulong,	sizeof(unsigned long),	T_UNSIGNED,	},
	{ &ffi_type_slong,	sizeof(long),		T_SIGNED,	},
	{ sizeof(size_t) == 4 ? &ffi_type_uint32 : sizeof(size_t) == 8 ? &ffi_type_uint64 : NULL,	sizeof(size_t),	T_UNSIGNED, },
	{ sizeof(ssize_t) == 4 ? &ffi_type_sint32 : sizeof(ssize_t) == 8 ? &ffi_type_sint64 : NULL,	sizeof(ssize_t), T_SIGNED, },
	{ sizeof(bool) == 1 ? &ffi_type_uint8 : sizeof(bool) == 4 ? &ffi_type_uint32 : NULL,		sizeof(bool),	T_UNSIGNED, },
};

static const struct type *ajla_type_to_type(ajla_option_t a)
{
	if (a >= 1 && a < 9) {
		a -= 1;
		return type_get_fixed(a >> 1, !(a & 1));
	}
	if (a == 9)
		return type_get_real(1);
	if (a == 10)
		return type_get_real(2);
	if (a == 11) {
#if REAL_MASK & 0x18
		return type_get_real(3);
#else
		return type_get_real(2);
#endif
	}
	return NULL;
}

static ffi_type *ajla_type_to_ffi_type(ajla_option_t a, struct data *struc, bool ref)
{
	if (struc) {
		struct resource_ffi_structure *str;
		if (ref)
			pointer_reference_owned(pointer_data(struc));
		str = da_resource(struc);
		return &str->typ;
	}
	if (unlikely(a >= n_array_elements(ajla_type_to_ffi_type_table)))
		internal(file_line, "ajla_type_to_ffi_type: invalid ffi type %u", (unsigned)a);
	return ajla_type_to_ffi_type_table[a].ft;
}

static void * attr_fastcall io_ffi_get_size_alignment_handler(struct io_ctx *ctx)
{
	void *test;
	ajla_option_t a;
	struct data *struc;
	ffi_type *ft;
	size_t v;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_option(ctx, get_input(ctx, 0), &a, &struc);

	ft = ajla_type_to_ffi_type(a, struc, false);
	switch (get_param(ctx, 0)) {
		case 0:	v = ft->size;
			break;
		case 1:	v = ft->alignment;
			break;
		default:internal(file_line, "io_ffi_get_size_alignment_handler: invalid parameter %u", (unsigned)get_param(ctx, 0));
	}

	io_store_typed_number(ctx, get_output(ctx, 0), int_default_t, INT_DEFAULT_N, size_t, v);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

}

static bool io_ffi_argument(struct io_ctx *ctx, ajla_option_t opt, struct data *struc)
{
	if (unlikely(!array_add_mayfail(uchar_efficient_t, &ctx->args, &ctx->args_l, opt, NULL, &ctx->err)))
		return false;
	if (unlikely(!array_add_mayfail(void *, &ctx->ptrs, &ctx->ptrs_l, struc, NULL, &ctx->err)))
		return false;
	return true;
}

static int_default_t io_get_argument_type_callback(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t *ptr, void *ctx_)
{
	struct io_ctx *ctx = cast_ptr(struct io_ctx *, ctx_);
	if (flat) {
		int_default_t i;
		for (i = n_elements; i; i--, flat += type->size) {
			if (unlikely(!io_ffi_argument(ctx, *cast_ptr(ajla_flat_option_t *, flat), NULL)))
				return 0;
		}
	} else {
		struct data *opt = pointer_get_data(*ptr);
		pointer_t ptr = da(opt,option)->pointer;
		struct data *struc = pointer_is_empty(ptr) ? NULL : pointer_get_data(ptr);
		if (unlikely(!io_ffi_argument(ctx, da(opt,option)->option, struc)))
			return 0;
	}
	return n_elements;
}

static void io_ffi_free_args(struct io_ctx *ctx, ffi_type **args)
{
	unsigned i;
	if (args) {
		for (i = 0; i < ctx->args_l; i++)
			if (args[i])
				free_type(args[i]);
		mem_free(args);
	}
}

static ffi_type **io_ffi_load_arg_list(struct io_ctx *ctx, unsigned slot)
{
	array_index_t idx;
	unsigned i;
	ffi_type **args;

	if (unlikely(!array_init_mayfail(uchar_efficient_t, &ctx->args, &ctx->args_l, &ctx->err)))
		return NULL;

	if (unlikely(!array_init_mayfail(void *, &ctx->ptrs, &ctx->ptrs_l, &ctx->err)))
		return NULL;

	index_from_int(&idx, 0);
	if (!array_onstack_iterate(ctx->fp, get_input(ctx, slot), &idx, io_get_argument_type_callback, ctx)) {
		index_free(&idx);
		return NULL;
	}
	index_free(&idx);
	if (unlikely(ctx->args_l >= -1U)) {
		ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
		return NULL;
	}

	args = mem_alloc_array_mayfail(mem_calloc_mayfail, ffi_type **, 0, 0, ctx->args_l + 1, sizeof(ffi_type *), &ctx->err);
	if (unlikely(!args))
		return NULL;
	for (i = 0; i < ctx->args_l; i++) {
		if (unlikely(!ctx->args[i])) {
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
			goto free_args_fail;
		}
		args[i] = ajla_type_to_ffi_type(ctx->args[i], ctx->ptrs[i], true);
		if (unlikely(!args[i]))
			goto free_args_fail;
	}

	return args;

free_args_fail:
	io_ffi_free_args(ctx, args);
	return NULL;
}

static void * attr_fastcall io_ffi_create_structure_handler(struct io_ctx *ctx)
{
	void *test;
	struct data *d = NULL;
	struct data *a = NULL;
	struct resource_ffi_structure *rfs;
	ffi_type **args = NULL;
	size_t *offsets = NULL;
	ffi_cif cif;
	size_t pos;
	unsigned i;

	ctx->args = NULL;
	ctx->ptrs = NULL;

	test = io_deep_eval(ctx, "0", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	args = io_ffi_load_arg_list(ctx, 0);
	if (unlikely(!args))
		goto ret_err;

	test = POINTER_FOLLOW_THUNK_GO;

	offsets = mem_alloc_array_mayfail(mem_alloc_mayfail, size_t *, 0, 0, ctx->args_l, sizeof(size_t), &ctx->err);
	if (unlikely(!offsets))
		goto ret_err;

	d = data_alloc_resource_mayfail(sizeof(struct resource_ffi_structure), resource_ffi_structure_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_err;
	rfs = da_resource(d);

	rfs->n_elements = ctx->args_l;
	rfs->offsets = offsets;
	rfs->typ.size = 0;
	rfs->typ.alignment = 0;
	rfs->typ.type = FFI_TYPE_STRUCT;
	rfs->typ.elements = args;
	args = NULL;

	if (unlikely(ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 0, &rfs->typ, NULL) != FFI_OK)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}

	a = data_alloc_array_flat_mayfail(type_get_int(INT_DEFAULT_N), ctx->args_l, ctx->args_l, false, &ctx->err pass_file_line);
	if (unlikely(!a))
		goto ret_err;

	pos = 0;
	for (i = 0; i < ctx->args_l; i++) {
		int_default_t p;
		pos = round_up(pos, rfs->typ.elements[i]->alignment);
		offsets[i] = pos;
		p = pos;
		if (unlikely(p < 0) || unlikely((uint_default_t)p != pos)) {
			ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
			goto ret_err;
		}
		cast_ptr(int_default_t *, da_array_flat(a))[i] = p;
		pos += rfs->typ.elements[i]->size;
		if (unlikely(pos < rfs->typ.elements[i]->size)) {
			ctx->err = error_ajla(EC_ASYNC, AJLA_ERROR_SIZE_OVERFLOW);
			goto ret_err;
		}
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(d));
	d = NULL;
	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(a));
	a = NULL;
	offsets = NULL;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (a)
		data_free_r1(a);
	if (d)
		data_free_r1(d);
	if (offsets)
		mem_free(offsets);
	io_ffi_free_args(ctx, args);
	if (ctx->ptrs)
		mem_free(ctx->ptrs);
	if (ctx->args)
		mem_free(ctx->args);
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_structure_offset_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t ptr;
	struct resource_ffi_structure *s;
	unsigned n;
	size_t off;

	test = io_deep_eval(ctx, "01", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 0));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_structure_offset_handler: pointer is thunk"));
	s = da_resource(pointer_get_data(ptr));

	io_get_number(ctx, get_input(ctx, 1), int_default_t, unsigned, n);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	if (unlikely(n >= s->n_elements)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}
	off = s->offsets[n];
	io_store_typed_number(ctx, get_output(ctx, 0), int_default_t, INT_DEFAULT_N, unsigned, off);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static bool io_get_argument_from_flat(struct io_ctx *ctx, uchar_efficient_t t, int_default_t num);
static bool io_get_argument_from_longint(struct io_ctx *ctx, uchar_efficient_t t, const mpint_t *m);

static void * attr_fastcall io_ffi_poke_handler(struct io_ctx *ctx)
{
	void *test;
	frame_t slot;
	uintptr_t addr;
	ajla_option_t a;
	struct data *struc;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 1), int_default_t, uintptr_t, addr);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_option(ctx, get_input(ctx, 2), &a, &struc);
	if (unlikely(struc != NULL)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}

	slot = get_input(ctx, 3);

	ctx->ptrs = NULL;
	ctx->str = num_to_ptr(addr);
	if (likely(!frame_test_flag(ctx->fp, slot))) {
		int_default_t in;
		barrier_aliasing();
		in = *frame_slot(ctx->fp, slot, int_default_t);
		barrier_aliasing();
		if (unlikely(!io_get_argument_from_flat(ctx, a, in)))
			goto ret_err;
	} else {
		struct data *d = pointer_get_data(*frame_pointer(ctx->fp, slot));
		if (da_tag(d) == DATA_TAG_flat) {
			if (unlikely(!io_get_argument_from_flat(ctx, a, *cast_ptr(int_default_t *, da_flat(d)))))
				goto ret_err;
		} else {
			if (unlikely(!io_get_argument_from_longint(ctx, a, &da(d,longint)->mp)))
				goto ret_err;
		}
	}

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_peek_handler(struct io_ctx *ctx)
{
	void *test;
	frame_t slot;
	uintptr_t addr;
	void *ad;
	ajla_option_t a;
	struct data *struc;
	size_t sz;

	union {
		uint8_t u8;
		uint16_t u16;
		uint32_t u32;
		uint64_t u64;
		int8_t s8;
		int16_t s16;
		int32_t s32;
		int64_t s64;
	} u;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 1), int_default_t, uintptr_t, addr);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	ad = num_to_ptr(addr);

	io_get_option(ctx, get_input(ctx, 2), &a, &struc);
	if (unlikely(struc != NULL)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}

	slot = get_output(ctx, 1);

	sz = ajla_type_to_ffi_type_table[a].size;
	switch (ajla_type_to_ffi_type_table[a].sign) {
		case T_VOID: {
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
			goto ret_err;
		}
		case T_REAL: {
			struct data *dl = data_alloc_longint_mayfail(sz * 8, &ctx->err pass_file_line);
			if (unlikely(!dl))
				goto ret_err;
			mpz_import(&da(dl,longint)->mp, sz, -1, 1, 0, 0, ad);
			frame_set_pointer(ctx->fp, slot, pointer_data(dl));
			break;
		}
		case T_UNSIGNED: {
			memcpy(&u, ad, sz);
			switch (sz) {
				case 1:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, uint8_t, u.u8); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				case 2:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, uint16_t, u.u16); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				case 4:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, uint32_t, u.u32); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				case 8:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, uint64_t, u.u64); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				default:internal(file_line, "io_ffi_peek_handler: invalid size %"PRIuMAX"", (uintmax_t)sz);
			}
			break;
		}
		case T_SIGNED: {
			memcpy(&u, ad, sz);
			switch (sz) {
				case 1:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, int8_t, u.s8); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				case 2:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, int16_t, u.s16); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				case 4:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, int32_t, u.s32); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				case 8:	io_store_typed_number(ctx, slot, int_default_t, INT_DEFAULT_N, int64_t, u.s64); if (unlikely(test != POINTER_FOLLOW_THUNK_GO)) goto ret_test; break;
				default:internal(file_line, "io_ffi_peek_handler: invalid size %"PRIuMAX"", (uintmax_t)sz);
			}
			break;
		}
		default:
			internal(file_line, "io_ffi_peek_handler: invalid type %u", (unsigned)a);
	}

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;

}

static int_default_t io_ffi_poke_array_callback(unsigned char *flat, const struct type *type, int_default_t n_elements, pointer_t attr_unused *ptr, void *ctx_)
{
	struct io_ctx *ctx = cast_ptr(struct io_ctx *, ctx_);
	if (flat) {
		if (unlikely(!TYPE_TAG_IS_FIXED(type->tag)) &&
		    unlikely(!TYPE_TAG_IS_REAL(type->tag))) {
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
			return 0;
		}
		ctx->str = mempcpy(ctx->str, flat, (size_t)type->size * (size_t)n_elements);
		return n_elements;
	} else {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		return 0;
	}
}

static void * attr_fastcall io_ffi_poke_array_handler(struct io_ctx *ctx)
{
	void *test;
	uintptr_t addr;
	frame_t slot;
	array_index_t idx;
	bool ret;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 1), int_default_t, uintptr_t, addr);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	ctx->str = num_to_ptr(addr);

	slot = get_input(ctx, 2);

	index_from_int(&idx, 0);
	ret = array_onstack_iterate(ctx->fp, slot, &idx, io_ffi_poke_array_callback, ctx);
	index_free(&idx);

	if (unlikely(!ret))
		goto ret_err;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_peek_array_handler(struct io_ctx *ctx)
{
	void *test;
	uintptr_t addr;
	ajla_option_t a;
	struct data *struc;
	const struct type *type;
	int_default_t size;
	struct data *d;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 1), int_default_t, uintptr_t, addr);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 2), int_default_t, int_default_t, size);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	if (unlikely(size < 0)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NEGATIVE_INDEX);
		goto ret_err;
	}

	io_get_option(ctx, get_input(ctx, 3), &a, &struc);
	if (unlikely(struc != NULL) || unlikely(!(type = ajla_type_to_type(a)))) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}

	d = data_alloc_array_flat_mayfail(type, size, size, false, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_err;

	memcpy(da_array_flat(d), num_to_ptr(addr), (size_t)size * type->size);

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_open_library_handler(struct io_ctx *ctx)
{
	void *test;
	bool hold;
	struct data *d;
	struct resource_ffi_library *rfl;
	char *err_msg;

	ctx->str = NULL;
	ctx->str2 = NULL;

	if (ctx->n_inputs == 3) {
		ajla_option_t opt;
		test = io_deep_eval(ctx, "012", false);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto ret_test;

		io_get_bytes(ctx, get_input(ctx, 0));
		io_get_option(ctx, get_input(ctx, 1), &opt, NULL);
		hold = opt;
		io_get_bytes2(ctx, get_input(ctx, 2));
	} else {
		hold = true;
	}

	d = data_alloc_resource_mayfail(sizeof(struct resource_ffi_library), resource_ffi_library_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_err;

	rfl = da_resource(d);
	rfl->lib = library_load(ctx->str, hold, ctx->str2, &ctx->err, &err_msg);
	if (unlikely(!rfl->lib)) {
		data_free_r1(d);
		io_terminate_with_error(ctx, ctx->err, true, err_msg);
		test = POINTER_FOLLOW_THUNK_EXCEPTION;
		goto ret_test;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(d));
	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (ctx->str)
		mem_free(ctx->str);
	if (ctx->str2)
		mem_free(ctx->str2);
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_create_function_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t ptr;
	struct resource_ffi_library *rfl;
	void *sym;
	struct data *d;
	struct resource_ffi *rf;
	char *open_msg = NULL;
	unsigned attr_unused nvargs;
	ajla_option_t err_type;
	ajla_option_t rtype;
	struct data *r_struc;
	ffi_type *ret = NULL;
	ffi_type **args = NULL;

	ctx->args = NULL;
	ctx->ptrs = NULL;
	ctx->str = NULL;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 0));
	d = pointer_get_data(ptr);
	rfl = da_resource(d);
	test = io_deep_eval(ctx, "012345", false);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 0));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_create_function_handler: pointer is thunk"));
	d = pointer_get_data(ptr);
	rfl = da_resource(d);

	io_get_bytes(ctx, get_input(ctx, 1));

	if (unlikely(!os_dlsym(rfl->lib->dlh, ctx->str, &sym))) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_SYMBOL_NOT_FOUND);
		goto ret_err;
	}

	io_get_option(ctx, get_input(ctx, 2), &err_type, NULL);

	io_get_positive_number(ctx, ctx->fp, get_input(ctx, 3), unsigned, nvargs);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_option(ctx, get_input(ctx, 4), &rtype, &r_struc);

	args = io_ffi_load_arg_list(ctx, 5);
	if (unlikely(!args))
		goto ret_err;

	ret = ajla_type_to_ffi_type(rtype, r_struc, true);
	if (unlikely(!ret))
		goto ret_err;

	d = data_alloc_resource_mayfail(sizeof(struct resource_ffi), resource_ffi_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_err;
	rf = da_resource(d);

#ifdef HAVE_FFI_PREP_CIF_VAR
	if (!nvargs) {
#endif
		if (unlikely(ffi_prep_cif(&rf->cif, FFI_DEFAULT_ABI, ctx->args_l, ret, args) != FFI_OK)) {
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
			goto ret_err;
		}
#ifdef HAVE_FFI_PREP_CIF_VAR
	} else {
		if (unlikely(ffi_prep_cif_var(&rf->cif, FFI_DEFAULT_ABI, ctx->args_l - nvargs, ctx->args_l, ret, args) != FFI_OK)) {
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
			goto ret_err;
		}
	}
#endif

	rf->rfl = rfl;
	rf->sym = sym;
	rf->err_type = err_type;
	rf->ctx_args = ctx->args;
	rf->n_args = ctx->args_l;
	ctx->args = NULL;
	rf->args = args;
	args = NULL;
	rf->ret_ffi_type = ret;
	rf->ret_type = rtype;
	ret = NULL;

	pointer_reference_owned(ptr);

	frame_set_pointer(ctx->fp, get_output(ctx, 0), pointer_data(d));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	io_ffi_free_args(ctx, args);
	if (ret)
		free_type(ret);
	if (ctx->str)
		mem_free(ctx->str);
	if (ctx->ptrs)
		mem_free(ctx->ptrs);
	if (ctx->args)
		mem_free(ctx->args);
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, open_msg);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static bool io_add_argument(struct io_ctx *ctx, void *ptr, size_t size)
{
	void *xerr;
	void *cpy;
	if (!ctx->ptrs) {
		memcpy_fast(ctx->str, ptr, size);
		return true;
	}
#if defined(__x86_64__) && defined(__ILP32__)
	/* ffi/x32 bug */
	cpy = mem_alloc_mayfail(void *, maximum(size, 8), &ctx->err);
	if (unlikely(!cpy))
		return false;
	memset(cpy, 0, 8);
#else
	cpy = mem_alloc_mayfail(void *, size, &ctx->err);
	if (unlikely(!cpy))
		return false;
#endif
	memcpy_fast(cpy, ptr, size);
	if (unlikely(!array_add_mayfail(void *, &ctx->ptrs, &ctx->ptrs_l, cpy, &xerr, &ctx->err))) {
		ctx->ptrs = xerr;
		return false;
	}
	return true;
}

static bool io_get_argument_from_longint(struct io_ctx *ctx, uchar_efficient_t t, const mpint_t *m)
{
	size_t size = ajla_type_to_ffi_type_table[t].size;
	unsigned idx;
	bool uns;

	union {
		ffi_arg rc;
		ffi_sarg src;
		unsigned char pool[MAX_FFI_TYPE_SIZE];

		/* force alignment */
		long l;
		int64_t i64;
		uint64_t ui64;
#ifdef HAVE_LONG_LONG
		long long ll;
#endif
		double dbl;
#ifdef HAVE_LONG_DOUBLE
		long double ld;
#endif
	} u;

	if (ajla_type_to_ffi_type_table[t].sign == T_REAL) {
		if (unlikely(mpz_sgn(m) < 0))
			goto doesnt_fit;
		if (mpz_sizeinbase(m, 2) > 8 * sizeof u.pool)
			goto doesnt_fit;
		memset(u.pool, 0, sizeof u.pool);
		mpz_export(u.pool, NULL, -1, 1, 0, 0, m);
		goto add;
	}

	idx = log_2(size);
	uns = ajla_type_to_ffi_type_table[t].sign == T_UNSIGNED;

	if (!uns) {
		if (unlikely(!mpint_export(m, u.pool, idx, &ctx->err)))
			return false;
	} else {
		if (unlikely(!mpint_export_unsigned(m, u.pool, idx, &ctx->err)))
			return false;
	}

add:
	return io_add_argument(ctx, u.pool, size);

doesnt_fit:
	ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT);
	return false;
}

static bool io_get_argument_from_flat(struct io_ctx *ctx, uchar_efficient_t t, int_default_t num)
{
	size_t size = ajla_type_to_ffi_type_table[t].size;
	unsigned idx;
	bool uns;

	if (ajla_type_to_ffi_type_table[t].sign == T_REAL) {
		bool ret;
		mpint_t m;
		if (unlikely(!cat(mpint_init_from_,int_default_t)(&m, 0, &ctx->err)))
			return false;
		ret = io_get_argument_from_longint(ctx, t, &m);
		mpint_free(&m);
		return ret;
	}

	idx = log_2(size);
	uns = ajla_type_to_ffi_type_table[t].sign == T_UNSIGNED;

#define f(n, stype, utype, sz, bits)					\
	case n: {							\
		union {							\
			stype s;					\
			utype u;					\
		} u;							\
		if (uns) {						\
			if (unlikely(num < 0) || unlikely((uint_default_t)num > (utype)(-1 + zero)))\
				goto doesnt_fit;			\
			u.u = num;					\
		} else {						\
			if (unlikely(num < sign_bit(stype) + zero) || unlikely(num > signed_maximum(stype) + zero))\
				goto doesnt_fit;			\
			u.s = num;					\
		}							\
		if (unlikely(!io_add_argument(ctx, &u, sizeof u)))	\
			return false;					\
		break;							\
	}
	switch (idx) {
		for_all_fixed(f)
		default:
			ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_NOT_SUPPORTED);
			return false;
	}
#undef f
	return true;

doesnt_fit:
	ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_DOESNT_FIT);
	return false;
}

static int_default_t io_get_argument_callback(unsigned char *flat, const struct type attr_unused *type, int_default_t n_elements, pointer_t *ptr, void *ctx_)
{
	struct io_ctx *ctx = cast_ptr(struct io_ctx *, ctx_);
	if (unlikely(flat != NULL)) {
		int_default_t i;
		for (i = n_elements; i; i--, flat += sizeof(int_default_t)) {
			int_default_t num = *cast_ptr(int_default_t *, flat);
			if (unlikely(!io_get_argument_from_flat(ctx, ctx->rf->ctx_args[ctx->ptrs_l], num)))
				return 0;
		}
	} else {
		struct data *d = pointer_get_data(*ptr);
		if (unlikely(!io_get_argument_from_longint(ctx, ctx->rf->ctx_args[ctx->ptrs_l], &da(d,longint)->mp)))
			return 0;
	}
	return n_elements;
}

static void * attr_fastcall io_ffi_call_function_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t ptr;
	struct data *d;
	struct resource_ffi *rf = NULL;		/* avoid warning */
	array_index_t idx;
	union {
		ffi_arg rc;
		ffi_sarg src;
		unsigned char pool[MAX_FFI_TYPE_SIZE];

		/* force alignment */
		long l;
		int64_t i64;
		uint64_t ui64;
#ifdef HAVE_LONG_LONG
		long long ll;
#endif
		double dbl;
#ifdef HAVE_LONG_DOUBLE
		long double ld;
#endif
	} u;
	size_t i;
	uint32_t e = 0;		/* avoid warning */
	bool store = false;

	ctx->ptrs = NULL;
	ctx->ptrs_l = 0;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 1));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_call_function_handler: pointer is thunk"));
	d = pointer_get_data(ptr);
	ctx->rf = rf = da_resource(d);

	if (unlikely(!array_init_mayfail(void *, &ctx->ptrs, &ctx->ptrs_l, &ctx->err)))
		goto ret_err;

	index_from_int(&idx, 0);
	if (!array_onstack_iterate(ctx->fp, get_input(ctx, 2), &idx, io_get_argument_callback, ctx)) {
		index_free(&idx);
		goto ret_err;
	}
	index_free(&idx);
	if (unlikely(ctx->ptrs_l != rf->n_args)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}

	ffi_call(&rf->cif, rf->sym, &u.rc, ctx->ptrs);
	store = true;

	switch (rf->err_type) {
		case 0:	e = 0; break;
		case 1: e = errno; break;
		case 2:	e = os_get_last_error(); break;
		case 3:	e = os_get_last_socket_error(); break;
		default:
			internal(file_line, "io_ffi_call_function_handler: invalid error specifier %u", (unsigned)rf->err_type);
	}

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	for (i = 0; i < ctx->ptrs_l; i++)
		mem_free(ctx->ptrs[i]);
	if (ctx->ptrs)
		mem_free(ctx->ptrs);

	if (likely(store)) {
		if (ajla_type_to_ffi_type_table[rf->ret_type].sign == T_VOID) {
			io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, int, 0);
			if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
				goto store_failed;
		} else if (ajla_type_to_ffi_type_table[rf->ret_type].sign == T_REAL) {
			struct data *dl = data_alloc_longint_mayfail(ajla_type_to_ffi_type_table[rf->ret_type].size * 8, &ctx->err pass_file_line);
			if (unlikely(!dl)) {
				io_terminate_with_error(ctx, ctx->err, true, NULL);
				return POINTER_FOLLOW_THUNK_EXCEPTION;
			}
			mpz_import(&da(dl,longint)->mp, ajla_type_to_ffi_type_table[rf->ret_type].size, -1, 1, 0, 0, &u.pool);
			frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(dl));
		} else if (ajla_type_to_ffi_type_table[rf->ret_type].size > sizeof(u.rc)) {
			if (ajla_type_to_ffi_type_table[rf->ret_type].sign != T_SIGNED) {
				io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, uint64_t, u.ui64);
				if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
					goto store_failed;
			} else {
				io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, int64_t, u.i64);
				if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
					goto store_failed;
			}
		} else if (ajla_type_to_ffi_type_table[rf->ret_type].sign != T_SIGNED) {
			io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, ffi_arg, u.rc);
			if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
				goto store_failed;
		} else {
			io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, ffi_sarg, u.src);
			if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
				goto store_failed;
		}
		io_store_typed_number(ctx, get_output(ctx, 2), int_default_t, INT_DEFAULT_N, uint32_t, e);
		if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
			goto store_failed;
	}

store_failed:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

struct destructor_call {
	struct data *d;
	void **args;
	size_t args_l;
};

struct resource_ffi_destructor {
	void **ptrs;
	size_t ptrs_l;
	struct destructor_call *calls;
	size_t calls_l;
	pointer_t *handles;
	size_t handles_l;
};

static void resource_ffi_destructor_close(struct data *d)
{
	size_t i;
	struct resource_ffi_destructor *rfd = da_resource(d);
	i = rfd->calls_l;
	while (i) {
		size_t j;
		union {
			ffi_arg rc;
			ffi_sarg src;
			unsigned char pool[MAX_FFI_TYPE_SIZE];

			/* force alignment */
			long l;
			int64_t i64;
			uint64_t ui64;
#ifdef HAVE_LONG_LONG
			long long ll;
#endif
			double dbl;
#ifdef HAVE_LONG_DOUBLE
			long double ld;
#endif
		} u;
		struct destructor_call *call = &rfd->calls[--i];
		struct resource_ffi *rf = da_resource(call->d);
		ffi_call(&rf->cif, rf->sym, &u, call->args);
		pointer_dereference(pointer_data(call->d));
		for (j = 0; j < call->args_l; j++)
			mem_free(call->args[j]);
		mem_free(call->args);
	}
	mem_free(rfd->calls);
	for (i = 0; i < rfd->handles_l; i++)
		pointer_dereference(rfd->handles[i]);
	mem_free(rfd->handles);
	for (i = 0; i < rfd->ptrs_l; i++)
		mem_free_aligned(rfd->ptrs[i]);
	mem_free(rfd->ptrs);
}

static void * attr_fastcall io_ffi_destructor_new_handler(struct io_ctx *ctx)
{
	void *test;
	struct data *d;
	struct resource_ffi_destructor *rfd;

	test = io_deep_eval(ctx, "0", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	d = data_alloc_resource_mayfail(sizeof(struct resource_ffi_destructor), resource_ffi_destructor_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_err;
	rfd = da_resource(d);

	if (unlikely(!array_init_mayfail(void *, &rfd->ptrs, &rfd->ptrs_l, &ctx->err))) {
		data_free_r1(d);
		goto ret_err;
	}
	if (unlikely(!array_init_mayfail(struct destructor_call, &rfd->calls, &rfd->calls_l, &ctx->err))) {
		mem_free(rfd->ptrs);
		data_free_r1(d);
		goto ret_err;
	}
	if (unlikely(!array_init_mayfail(pointer_t, &rfd->handles, &rfd->handles_l, &ctx->err))) {
		mem_free(rfd->calls);
		mem_free(rfd->ptrs);
		data_free_r1(d);
		goto ret_err;
	}

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_destructor_allocate_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t ptr;
	struct resource_ffi_destructor *rfd = NULL;
	size_t size, align;
	ajla_option_t z;
	void *n;
	void *old;

	test = io_deep_eval(ctx, "01234", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 1));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_destructor_allocate_handler: pointer is thunk"));
	rfd = da_resource(pointer_get_data(ptr));

	io_get_number(ctx, get_input(ctx, 2), int_default_t, size_t, size);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 3), int_default_t, size_t, align);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_option(ctx, get_input(ctx, 4), &z, NULL);

	if (unlikely(!is_power_of_2(align))) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}

	if (!z)
		n = mem_align_mayfail(void *, size, align, &ctx->err);
	else
		n = mem_calign_mayfail(void *, size, align, &ctx->err);
	if (unlikely(!n))
		goto ret_err;

	address_lock(rfd, DEPTH_AUX);
	if (unlikely(!array_add_mayfail(void *, &rfd->ptrs, &rfd->ptrs_l, n, &old, &ctx->err))) {
		rfd->ptrs = old;
		address_unlock(rfd, DEPTH_AUX);
		mem_free_aligned(n);
		goto ret_err;
	}
	address_unlock(rfd, DEPTH_AUX);

	io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, uintptr_t, ptr_to_num(n));
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_destructor_free_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t ptr;
	struct resource_ffi_destructor *rfd = NULL;
	uintptr_t nn;
	void *n;
	size_t i;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 1));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_destructor_free_handler: pointer is thunk"));
	rfd = da_resource(pointer_get_data(ptr));

	io_get_number(ctx, get_input(ctx, 2), int_default_t, uintptr_t, nn);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;
	n = num_to_ptr(nn);

	address_lock(rfd, DEPTH_AUX);
	for (i = 0; i < rfd->ptrs_l; i++) {
		if (rfd->ptrs[i] == n) {
			memmove(&rfd->ptrs[i], &rfd->ptrs[i + 1], (rfd->ptrs_l - i - 1) * sizeof(void *));
			rfd->ptrs_l--;
			address_unlock(rfd, DEPTH_AUX);
			mem_free_aligned(n);
			test = POINTER_FOLLOW_THUNK_GO;
			goto ret_test;
		}
	}
	address_unlock(rfd, DEPTH_AUX);

	ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
	goto ret_err;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_destructor_call_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t ptr;
	struct resource_ffi_destructor *rfd = NULL;
	array_index_t idx;
	size_t i;
	void *old;
	struct destructor_call call;

	ctx->ptrs = NULL;
	ctx->ptrs_l = 0;

	test = io_deep_eval(ctx, "0123", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 1));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_destructor_call_handler: pointer is thunk"));
	rfd = da_resource(pointer_get_data(ptr));

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 2));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_destructor_call_handler: pointer is thunk"));
	call.d = pointer_get_data(ptr);
	ctx->rf = da_resource(call.d);

	if (unlikely(!array_init_mayfail(void *, &ctx->ptrs, &ctx->ptrs_l, &ctx->err)))
		goto ret_err;

	index_from_int(&idx, 0);
	if (!array_onstack_iterate(ctx->fp, get_input(ctx, 3), &idx, io_get_argument_callback, ctx)) {
		index_free(&idx);
		goto ret_err;
	}
	index_free(&idx);
	if (unlikely(ctx->ptrs_l != ctx->rf->n_args)) {
		ctx->err = error_ajla(EC_SYNC, AJLA_ERROR_INVALID_OPERATION);
		goto ret_err;
	}

	call.args = ctx->ptrs;
	call.args_l = ctx->ptrs_l;

	address_lock(rfd, DEPTH_AUX);
	if (unlikely(!array_add_mayfail(struct destructor_call, &rfd->calls, &rfd->calls_l, call, &old, &ctx->err))) {
		rfd->calls = old;
		address_unlock(rfd, DEPTH_AUX);
		goto ret_err;
	}
	address_unlock(rfd, DEPTH_AUX);

	ctx->ptrs = NULL;
	ctx->ptrs_l = 0;
	pointer_reference_owned(pointer_data(call.d));

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	for (i = 0; i < ctx->ptrs_l; i++)
		mem_free(ctx->ptrs[i]);
	if (ctx->ptrs)
		mem_free(ctx->ptrs);

	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_handle_to_number_handler(struct io_ctx *ctx)
{
	void *test;
	pointer_t ptr, hptr;
	struct resource_ffi_destructor *rfd;
	uintptr_t n;
	void *old;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	ptr = *frame_pointer(ctx->fp, get_input(ctx, 1));
	ajla_assert_lo(!pointer_is_thunk(ptr), (file_line, "io_ffi_handle_to_number_handler: pointer is thunk"));
	rfd = da_resource(pointer_get_data(ptr));

	hptr = *frame_pointer(ctx->fp, get_input(ctx, 2));

	address_lock(rfd, DEPTH_AUX);
	if (unlikely(!array_add_mayfail(pointer_t, &rfd->handles, &rfd->handles_l, hptr, &old, &ctx->err))) {
		rfd->handles = old;
		address_unlock(rfd, DEPTH_AUX);
		goto ret_err;
	}
	pointer_reference_owned(hptr);
	address_unlock(rfd, DEPTH_AUX);

	io_get_handle(ctx, get_input(ctx, 2));

	n = os_handle_to_number(ctx->handle->fd);

	io_store_typed_number(ctx, get_output(ctx, 1), int_default_t, INT_DEFAULT_N, uintptr_t, n);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}

static void * attr_fastcall io_ffi_number_to_handle_handler(struct io_ctx *ctx)
{
	void *test;
	uintptr_t n = 0;	/* avoid warning */
	ajla_option_t sckt;
	handle_t hn;
	struct data *d = NULL;
	struct resource_handle *h;

	test = io_deep_eval(ctx, "012", true);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_test;

	io_get_number(ctx, get_input(ctx, 1), int_default_t, uintptr_t, n);
	if (unlikely(test != POINTER_FOLLOW_THUNK_GO))
		goto ret_err;

	io_get_option(ctx, get_input(ctx, 2), &sckt, NULL);

	d = data_alloc_resource_mayfail(sizeof(struct resource_handle), handle_close, &ctx->err pass_file_line);
	if (unlikely(!d))
		goto ret_err;
	h = da_resource(d);

	hn = os_number_to_handle(n, !!sckt, &ctx->err);
	if (unlikely(!handle_is_valid(hn)))
		goto ret_err;

	h->fd = hn;

	frame_set_pointer(ctx->fp, get_output(ctx, 1), pointer_data(d));

	d = NULL;
	test = POINTER_FOLLOW_THUNK_GO;

ret_test:
	if (d)
		data_free_r1(d);
	return test;

ret_err:
	io_terminate_with_error(ctx, ctx->err, true, NULL);
	test = POINTER_FOLLOW_THUNK_EXCEPTION;
	goto ret_test;
}
