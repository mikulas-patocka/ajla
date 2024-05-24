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
#define maybe_inline attr_noinline
#endif

#if defined(INLINE_ASM_GCC_X86) && !(defined(HAVE_BUILTIN_ADD_SUB_OVERFLOW) && !defined(INLINE_ASM_GCC_LABELS) && TYPE_BITS <= EFFICIENT_WORD_SIZE)

#if TYPE_MASK == 1
gen_x86_binary(add, type, utype, add, b, "=q", "q", "q"X86_ASM_M)
gen_x86_binary(subtract, type, utype, sub, b, "=q", "q", "q"X86_ASM_M)
gen_generic_multiply(type, utype)
#elif TYPE_MASK == 2
gen_x86_binary(add, type, utype, add, w, "=r", "r", "r"X86_ASM_M)
gen_x86_binary(subtract, type, utype, sub, w, "=r", "r", "r"X86_ASM_M)
gen_x86_binary(multiply, type, utype, imul, w, "=r", "r", "r"X86_ASM_M)
#elif TYPE_MASK == 4
gen_x86_binary(add, type, utype, add, l, "=r", "r", "r"X86_ASM_M)
gen_x86_binary(subtract, type, utype, sub, l, "=r", "r", "r"X86_ASM_M)
gen_x86_binary(multiply, type, utype, imul, l, "=r", "r", "r"X86_ASM_M)
#elif TYPE_MASK == 8 && defined(INLINE_ASM_GCC_I386)
gen_x86_binary_2reg(add, type, utype, add, adc, l, e)
gen_x86_binary_2reg(subtract, type, utype, sub, sbb, l, e)
gen_generic_multiply(type, utype)
#elif TYPE_MASK == 8
gen_x86_binary(add, type, utype, add, q, "=r", "r", "r"X86_ASM_M)
gen_x86_binary(subtract, type, utype, sub, q, "=r", "r", "r"X86_ASM_M)
gen_x86_binary(multiply, type, utype, imul, q, "=r", "r", "r"X86_ASM_M)
#elif TYPE_MASK == 16 && !defined(INLINE_ASM_GCC_I386) && defined(HAVE_ASSEMBLER___INT128)
gen_x86_binary_2reg(add, type, utype, add, adc, q, r)
gen_x86_binary_2reg(subtract, type, utype, sub, sbb, q, r)
gen_generic_multiply(type, utype)
#else
gen_generic_addsub(add, type, utype, 0)
gen_generic_addsub(subtract, type, utype, 1)
gen_generic_multiply(type, utype)
#endif

#elif defined(INLINE_ASM_GCC_ARM) && !(defined(HAVE_BUILTIN_ADD_SUB_OVERFLOW) && !defined(INLINE_ASM_GCC_LABELS) && TYPE_BITS <= EFFICIENT_WORD_SIZE)
#if TYPE_MASK == 4
gen_arm_addsub(add, type, utype, adds, "")
gen_arm_addsub(subtract, type, utype, subs, "")
#if ARM_VERSION >= 4
gen_arm_multiply(type, utype)
#else
gen_generic_multiply(type, utype)
#endif
#elif TYPE_MASK == 8 && ARM_VERSION >= 5
gen_arm_addsub_2reg(add, type, utype, adds, adcs)
gen_arm_addsub_2reg(subtract, type, utype, subs, sbcs)
gen_generic_multiply(type, utype)
#else
gen_generic_addsub(add, type, utype, 0)
gen_generic_addsub(subtract, type, utype, 1)
gen_generic_multiply(type, utype)
#endif

#elif defined(INLINE_ASM_GCC_ARM64) && !(defined(HAVE_BUILTIN_ADD_SUB_OVERFLOW) && !defined(INLINE_ASM_GCC_LABELS))

#if TYPE_MASK == 4
gen_arm_addsub(add, type, utype, adds, "w")
gen_arm_addsub(subtract, type, utype, subs, "w")
gen_generic_multiply(type, utype)
#elif TYPE_MASK == 8
gen_arm_addsub(add, type, utype, adds, "x")
gen_arm_addsub(subtract, type, utype, subs, "x")
gen_generic_multiply(type, utype)
#elif TYPE_MASK == 16 && defined(HAVE_ASSEMBLER___INT128)
gen_arm_addsub_2reg(add, type, utype, adds, adcs)
gen_arm_addsub_2reg(subtract, type, utype, subs, sbcs)
gen_generic_multiply(type, utype)
#else
gen_generic_addsub(add, type, utype, 0)
gen_generic_addsub(subtract, type, utype, 1)
gen_generic_multiply(type, utype)
#endif

#else

gen_generic_addsub(add, type, utype, 0)
gen_generic_addsub(subtract, type, utype, 1)
gen_generic_multiply(type, utype)

#endif

gen_generic_divmod(divide, type, utype, /)
#if INT_DIVIDE_ALT1_TYPES & TYPE_MASK
gen_generic_divmod_alt1(divide, type, utype)
#endif
gen_generic_divmod(modulo, type, utype, %)
#if INT_MODULO_ALT1_TYPES & TYPE_MASK
gen_generic_divmod_alt1(modulo, type, utype)
#endif

gen_generic_int_power(type, utype)

gen_generic_shl(type, utype)
gen_generic_shr(type, utype)

gen_generic_btx(bts, type, utype, 0)
gen_generic_btx(btr, type, utype, 1)
gen_generic_btx(btc, type, utype, 2)
gen_generic_bt(type, utype)

gen_generic_not(type, utype)

#if defined(INLINE_ASM_GCC_X86) && defined(INLINE_ASM_GCC_LABELS)

#if TYPE_MASK == 1
gen_x86_neg(type, utype, b, "q")
gen_x86_inc_dec(inc, type, utype, b, "q")
gen_x86_inc_dec(dec, type, utype, b, "q")
#elif TYPE_MASK == 2
gen_x86_neg(type, utype, w, "r")
gen_x86_inc_dec(inc, type, utype, w, "r")
gen_x86_inc_dec(dec, type, utype, w, "r")
#elif TYPE_MASK == 4
gen_x86_neg(type, utype, l, "r")
gen_x86_inc_dec(inc, type, utype, l, "r")
gen_x86_inc_dec(dec, type, utype, l, "r")
#elif TYPE_MASK == 8 && defined(INLINE_ASM_GCC_I386)
gen_x86_neg_2reg(type, utype, l, e)
gen_generic_inc_dec(type, utype)
#elif TYPE_MASK == 8
gen_x86_neg(type, utype, q, "r")
gen_x86_inc_dec(inc, type, utype, q, "r")
gen_x86_inc_dec(dec, type, utype, q, "r")
#elif TYPE_MASK == 16 && !defined(INLINE_ASM_GCC_I386) && defined(HAVE_ASSEMBLER___INT128)
gen_x86_neg_2reg(type, utype, q, r)
gen_generic_inc_dec(type, utype)
#else
gen_generic_neg(type, utype)
gen_generic_inc_dec(type, utype)
#endif

#elif defined(INLINE_ASM_GCC_ARM) && defined(INLINE_ASM_GCC_LABELS)

#if TYPE_MASK == 4
gen_arm_neg(type, utype, "")
#elif TYPE_MASK == 8 && defined(ARM_ASM_STRD)
gen_arm_neg_2reg(type, utype)
#else
gen_generic_neg(type, utype)
#endif
gen_generic_inc_dec(type, utype)

#elif defined(INLINE_ASM_GCC_ARM64) && defined(INLINE_ASM_GCC_LABELS)

#if TYPE_MASK == 4
gen_arm_neg(type, utype, "w")
#elif TYPE_MASK == 8
gen_arm_neg(type, utype, "x")
#elif TYPE_MASK == 16 && defined(HAVE_ASSEMBLER___INT128)
gen_arm_neg_2reg(type, utype)
#else
gen_generic_neg(type, utype)
#endif
gen_generic_inc_dec(type, utype)

#else

gen_generic_neg(type, utype)
gen_generic_inc_dec(type, utype)

#endif

gen_generic_int_bsfr(bsf, type, utype, TYPE_BITS, false)
gen_generic_int_bsfr(bsr, type, utype, TYPE_BITS, true)
gen_generic_int_popcnt(type, utype, TYPE_BITS)
#if INT_POPCNT_ALT1_TYPES & TYPE_MASK
gen_generic_int_popcnt_alt1(type, utype, TYPE_BITS)
#endif

#undef maybe_inline
