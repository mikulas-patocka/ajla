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

#ifndef AJLA_ASM_H
#define AJLA_ASM_H

#include "code-op.h"

typedef unsigned cpu_feature_mask_t;

extern cpu_feature_mask_t cpu_feature_flags;

enum {
#define ASM_INC_ENUM
#include "asm.inc"
#undef ASM_INC_ENUM
	CPU_FEATURE_max
};

enum {
cpu_feature_static_flags = 0
#define ASM_INC_STATIC
#include "asm.inc"
#undef ASM_INC_STATIC
};

#define cpu_feature_mask(feature)	((cpu_feature_mask_t)1 << (feature))
#ifdef DEBUG_ENV
#define cpu_test_feature(feature)	(!!(cpu_feature_flags & cpu_feature_mask(feature)))
#else
#define cpu_test_feature(feature)	(cpu_feature_static_flags & cpu_feature_mask(feature) || cpu_feature_flags & cpu_feature_mask(feature))
#endif


void asm_setup_thread(void);
code_t code_alt(code_t code);


void asm_init(void);
void asm_done(void);

#endif
