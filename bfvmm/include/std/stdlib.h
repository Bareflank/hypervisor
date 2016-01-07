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

#ifndef STDLIB_H
#define STDLIB_H

#include <stddef.h>
#include <stdint.h>



#ifdef __cplusplus
extern "C" {
#endif

/*
 * Since itoa can take any base, the largest number that you can represent
 * would be base 2 (i.e. binary), which would be 64 characters long, which
 * means that the minimum buffer size is 65 character which includes space
 * for all of the digits, and a '\0'. It should be noted that we do not need
 * to add space for a negative, because all of the numbers are treated as
 * unsigned expect for base 10, which is signed, and the number of digits
 * is far less than 65
 */
#define IOTA_MIN_BUF_SIZE 65

#ifdef CROSS_COMPILED
char *itoa(int64_t value, char *str, uint64_t base);
#endif

char *bfitoa(int64_t value, char *str, uint64_t base);

#ifdef __cplusplus
}
#endif

#endif
