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

#if INT_DEFAULT_BITS == 8
#define z			b
#elif INT_DEFAULT_BITS == 16
#define z			w
#elif INT_DEFAULT_BITS == 32
#define z			l
#elif INT_DEFAULT_BITS == 64
#define z			q
#endif

#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_F16C) && TYPE_MASK == 0x1
#define REAL16_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_f16c))
#define REAL16_ALT1_TYPES	0x1
gen_f16c_ops(z)
#endif
#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_SSE) && TYPE_MASK == 0x2
#define REAL32_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_sse))
#define REAL32_ALT1_TYPES	0x2
gen_sse_ops(type, s, z)
#endif
#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_SSE2) && TYPE_MASK == 0x4
#define REAL64_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_sse2))
#define REAL64_ALT1_TYPES	0x4
gen_sse_ops(type, d, z)
#endif
#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_FP16) && TYPE_MASK == 0x1
#define REAL16_ALT2_FEATURES	(cpu_feature_mask(CPU_FEATURE_fp16))
#define REAL16_ALT2_TYPES	0x1
gen_fp16_ops(z)
#endif
#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_AVX) && TYPE_MASK == 0x2
#define REAL32_ALT2_FEATURES	(cpu_feature_mask(CPU_FEATURE_avx))
#define REAL32_ALT2_TYPES	0x2
gen_avx_ops(type, s, z)
#endif
#if defined(INLINE_ASM_GCC_X86) && defined(HAVE_X86_ASSEMBLER_AVX) && TYPE_MASK == 0x4
#define REAL64_ALT2_FEATURES	(cpu_feature_mask(CPU_FEATURE_avx))
#define REAL64_ALT2_TYPES	0x4
gen_avx_ops(type, d, z)
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_HALF_PRECISION) && TYPE_MASK == 0x1
#define REAL16_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_half) | cpu_feature_mask(CPU_FEATURE_neon))
#define REAL16_ALT1_TYPES	0x1
gen_vfp_half_ops()
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_VFP) && TYPE_MASK == 0x2
#define REAL32_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_vfp))
#define REAL32_ALT1_TYPES	0x2
gen_vfp_ops(type, "f32", "s")
#endif

#if defined(INLINE_ASM_GCC_ARM) && defined(HAVE_ARM_ASSEMBLER_VFP) && TYPE_MASK == 0x4
#define REAL64_ALT1_FEATURES	(cpu_feature_mask(CPU_FEATURE_vfp))
#define REAL64_ALT1_TYPES	0x4
gen_vfp_ops(type, "f64", "d")
#endif
