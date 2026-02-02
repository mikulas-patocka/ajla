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

#ifndef AJLA_ARGS_H
#define AJLA_ARGS_H

#define CHICKEN_CG		0x00000001
#define CHICKEN_CG_FLAG_CACHE	0x00000002
#define CHICKEN_CG_MUST_BE_FLAT	0x00000004
#define CHICKEN_CG_RA		0x00000008
#define CHICKEN_CG_OPTIMIZE	0x00000010
typedef uint8_t chicken_mask_t;
extern chicken_mask_t chicken;

extern const char * const * args_left;
extern int n_args_left;
extern const char *program_name;
extern const char *arg0;

void args_init(int argc, const char * const argv[]);
void args_done(void);

#endif
