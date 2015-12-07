/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef STDINT_H
#define STDINT_H

typedef char int8_t;
typedef unsigned char uint8_t;

typedef short int int16_t;
typedef unsigned short int uint16_t;

typedef long int int32_t;
typedef unsigned long int uint32_t;

typedef long long int int64_t;
typedef unsigned long long int uint64_t;

#define INT64_MIN (-9223372036854775808)
#define INT64_MAX (9223372036854775807)
#define UINT64_MAX (18446744073709551615)

#endif
