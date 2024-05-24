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

#if cat(OPF,TYPES) & TYPE_MASK
#ifdef EMIT_ALTTABLE
EMIT_ALTTABLE(OPC(orig_op), OPC(op), cat(OPF,FEATURES))
#endif
DEF(type)
#endif

#undef DEF
#undef orig_op
#undef op
#undef OPF
