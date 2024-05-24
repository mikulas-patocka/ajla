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

#ifdef ASM_INC_ENUM
	cat(CPU_FEATURE_,feature_name),
#endif
#ifdef ASM_INC_NAMES
	stringify(feature_name),
#endif
#ifdef ASM_INC_STATIC
#if cat(static_test_,feature_name)
	| (1 << cat(CPU_FEATURE_,feature_name))
#else
	| 0
#endif
#endif
#ifdef ASM_INC_DYNAMIC
	if (likely(dynamic_test != 0))
		cpu_feature_flags |= 1U << cat(CPU_FEATURE_,feature_name);
#endif

#undef feature_name
#undef dynamic_test
