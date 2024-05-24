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

#if REAL_MASK & 0x1
#define type real16_t
#define TYPE_MASK 0x1
#define TYPE_BITS 16
#include file_inc
#undef type
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if REAL_MASK & 0x2
#define type real32_t
#define TYPE_MASK 0x2
#define TYPE_BITS 32
#include file_inc
#undef type
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if REAL_MASK & 0x4
#define type real64_t
#define TYPE_MASK 0x4
#define TYPE_BITS 64
#include file_inc
#undef type
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if REAL_MASK & 0x8
#define type real80_t
#define TYPE_MASK 0x8
#define TYPE_BITS 80
#include file_inc
#undef type
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if REAL_MASK & 0x10
#define type real128_t
#define TYPE_MASK 0x10
#define TYPE_BITS 128
#include file_inc
#undef type
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#undef file_inc
