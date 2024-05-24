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

#if TYPE_BITS <= EFFICIENT_WORD_SIZE
#define maybe_inline ipret_inline
#else
#define maybe_inline
#endif

#if defined(INLINE_ASM_GCC_ARM64) && (TYPE_MASK == 1 || TYPE_MASK == 2 || TYPE_MASK == 4)
gen_arm_div_mod(type, utype, uint32_t, "w", _)
#elif defined(INLINE_ASM_GCC_ARM64) && (TYPE_MASK == 8)
gen_arm_div_mod(type, utype, uint64_t, "x", _)
#else
gen_generic_div_functions(type, utype)
#endif

gen_generic_power(type, utype)

#if defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 1
gen_x86_rot(rol, type, utype, b, "=q"X86_ASM_M)
gen_x86_rot(ror, type, utype, b, "=q"X86_ASM_M)
#elif defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 2
gen_x86_rot(rol, type, utype, w, "=r"X86_ASM_M)
gen_x86_rot(ror, type, utype, w, "=r"X86_ASM_M)
#elif defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 4
gen_x86_rot(rol, type, utype, l, "=r"X86_ASM_M)
gen_x86_rot(ror, type, utype, l, "=r"X86_ASM_M)
#elif defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 8 && !defined(INLINE_ASM_GCC_I386)
gen_x86_rot(rol, type, utype, q, "=r"X86_ASM_M)
gen_x86_rot(ror, type, utype, q, "=r"X86_ASM_M)
#elif defined(INLINE_ASM_GCC_ARM) && (TYPE_MASK == 1 || TYPE_MASK == 2 || TYPE_MASK == 4)
gen_arm_rot(rol, type, utype, uint32_t, false, "")
gen_arm_rot(ror, type, utype, uint32_t, true, "")
#elif defined(INLINE_ASM_GCC_ARM64) && (TYPE_MASK == 1 || TYPE_MASK == 2 || TYPE_MASK == 4)
gen_arm_rot(rol, type, utype, uint32_t, false, "w")
gen_arm_rot(ror, type, utype, uint32_t, true, "w")
#elif defined(INLINE_ASM_GCC_ARM64) && (TYPE_MASK == 8)
gen_arm_rot(rol, type, utype, uint64_t, false, "x")
gen_arm_rot(ror, type, utype, uint64_t, true, "x")
#else
gen_generic_rot(rol, type, utype, false)
gen_generic_rot(ror, type, utype, true)
#endif

#if defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 1
gen_x86_bit_mask(type, utype, b, "=q"X86_ASM_M)
#elif defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 2
gen_x86_bit_mask(type, utype, w, "=r"X86_ASM_M)
#elif defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 4
gen_x86_bit_mask(type, utype, l, "=r"X86_ASM_M)
#elif defined(INLINE_ASM_GCC_X86) && TYPE_MASK == 8 && !defined(INLINE_ASM_GCC_I386)
gen_x86_bit_mask(type, utype, q, "=r"X86_ASM_M)
#else
gen_generic_bit_mask(type, utype)
#endif
gen_generic_bit_functions(type, utype)

cat(gen_generic_bswap_,TYPE_BITS)()

#if defined(INLINE_ASM_GCC_ARM64) && (TYPE_MASK == 1 || TYPE_MASK == 2 || TYPE_MASK == 4)
gen_arm_brev(type, utype, uint32_t, "w", _)
#elif defined(INLINE_ASM_GCC_ARM64) && (TYPE_MASK == 8)
gen_arm_brev(type, utype, uint64_t, "x", _)
#elif defined(INLINE_ASM_GCC_ARM64) && (TYPE_MASK == 16)
gen_arm_brev_2reg(type, utype, uint64_t, "x", _)
#else
gen_generic_brev(type, utype)
#endif

gen_generic_bsfr_functions(type, utype)
gen_generic_popcnt(type, utype)

#undef maybe_inline
