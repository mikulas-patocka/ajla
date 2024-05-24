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

#if TYPE_FIXED_N > 0
#define type int8_t
#define utype uint8_t
#define TYPE_MASK 0x1
#define TYPE_BITS 8
#include file_inc
#undef type
#undef utype
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if TYPE_FIXED_N > 1
#define type int16_t
#define utype uint16_t
#define TYPE_MASK 0x2
#define TYPE_BITS 16
#include file_inc
#undef type
#undef utype
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if TYPE_FIXED_N > 2
#define type int32_t
#define utype uint32_t
#define TYPE_MASK 0x4
#define TYPE_BITS 32
#include file_inc
#undef type
#undef utype
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if TYPE_FIXED_N > 3
#define type int64_t
#define utype uint64_t
#define TYPE_MASK 0x8
#define TYPE_BITS 64
#include file_inc
#undef type
#undef utype
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#if TYPE_FIXED_N > 4
#define type int128_t
#define utype uint128_t
#define TYPE_MASK 0x10
#define TYPE_BITS 128
#include file_inc
#undef type
#undef utype
#undef TYPE_MASK
#undef TYPE_BITS
#endif

#undef file_inc
