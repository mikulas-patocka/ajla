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

#ifndef AJLA_RESOLVER_H
#define AJLA_RESOLVER_H

#include "os.h"

bool resolver_resolve(char *name, int port, handle_t p, ajla_error_t *err);
bool resolver_resolve_reverse(char *addr, size_t addrlen, handle_t p, ajla_error_t *err);

void resolver_init(void);
void resolver_done(void);

#endif
