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

#ifndef AJLA_LAYOUT_H
#define AJLA_LAYOUT_H

struct layout;

struct layout *layout_start(uchar_efficient_t slot_bits_, char_efficient_t flags_per_slot_bits, frame_t alignment, frame_t alignment_offset, ajla_error_t *mayfail);
bool layout_add(struct layout *l, frame_t size, frame_t align, ajla_error_t *mayfail);
bool layout_compute(struct layout *l, bool linear, ajla_error_t *mayfail);
frame_t layout_get(struct layout *l, frame_t idx);
frame_t layout_size(const struct layout *l);
frame_t layout_alignment(const struct layout *l);
void layout_free(struct layout *l);

#endif
