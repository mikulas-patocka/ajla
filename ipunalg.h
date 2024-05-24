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

#ifndef AJLA_IPUNALGN_H
#define AJLA_IPUNALGN_H

#include "code-op.h"

static attr_always_inline uint8_t get_unaligned_8(const code_t *p)
{
	return (uint8_t)*p;
}

static attr_always_inline uint16_t get_unaligned_16(const code_t *p)
{
	return *p;
}

static attr_always_inline uint32_t get_unaligned_32(const code_t *p)
{
#if ((defined(C_LITTLE_ENDIAN) && !CODE_ENDIAN) || (defined(C_BIG_ENDIAN) && CODE_ENDIAN)) && defined(UNALIGNED_ACCESS)
	struct unaligned_32 { uint32_t val; } attr_unaligned;
	return cast_ptr(const struct unaligned_32 *, p)->val;
#else
	return (uint32_t)p[CODE_ENDIAN] | ((uint32_t)p[!CODE_ENDIAN] << 16);
#endif
}

#if TYPE_FIXED_N >= 4
static inline uint64_t get_unaligned_64(const code_t *p)
{
#if ((defined(C_LITTLE_ENDIAN) && !CODE_ENDIAN) || (defined(C_BIG_ENDIAN) && CODE_ENDIAN)) && defined(UNALIGNED_ACCESS)
	struct unaligned_64 { uint64_t val; } attr_unaligned;
	return cast_ptr(const struct unaligned_64 *, p)->val;
#else
	return (uint64_t)p[0 ^ (CODE_ENDIAN * 3)] | ((uint64_t)p[1 ^ (CODE_ENDIAN * 3)] << 16) | ((uint64_t)p[2 ^ (CODE_ENDIAN * 3)] << 32) | ((uint64_t)p[3 ^ (CODE_ENDIAN * 3)] << 48);
#endif
}
#endif

#if TYPE_FIXED_N >= 5
static inline uint128_t get_unaligned_128(const code_t *p)
{
#if ((defined(C_LITTLE_ENDIAN) && !CODE_ENDIAN) || (defined(C_BIG_ENDIAN) && CODE_ENDIAN)) && defined(UNALIGNED_ACCESS)
	struct unaligned_128 { uint128_t val; } attr_unaligned;
	return cast_ptr(const struct unaligned_128 *, p)->val;
#else
	return get_unaligned_64(p + CODE_ENDIAN * 4) | ((uint128_t)get_unaligned_64(p + (4 - CODE_ENDIAN * 4)) << 64);
#endif
}
#endif

#endif
