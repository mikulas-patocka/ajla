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

#ifdef ARCH_ALPHA
#include "asm-alph.inc"
#endif
#ifdef ARCH_ARM
#include "asm-arm.inc"
#endif
#ifdef ARCH_IA64
#include "asm-ia64.inc"
#endif
#ifdef ARCH_LOONGARCH64
#include "asm-loon.inc"
#endif
#ifdef ARCH_PARISC
#include "asm-hppa.inc"
#endif
#ifdef ARCH_POWER
#include "asm-ppc.inc"
#endif
#ifdef ARCH_RISCV64
#include "asm-rv.inc"
#endif
#ifdef ARCH_S390
#include "asm-s390.inc"
#endif
#ifdef ARCH_SPARC
#include "asm-spar.inc"
#endif
#ifdef ARCH_X86
#include "asm-x86.inc"
#endif
