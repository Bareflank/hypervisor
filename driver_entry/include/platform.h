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

#ifndef PLATFORM_H
#define PLATFORM_H

#include <types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate Memory
 *
 * Used by the common code to allocate virtual memory.
 *
 * @param len the size of virtual memory to be allocated in bytes.
 * @return a virtual address pointing to the newly allocated memory
 */
void *
platform_alloc(int64_t len);

/**
 * Allocate Executable Memory
 *
 * Used by the common code to allocate executable virtual memory.
 *
 * @param len the size of virtual memory to be allocated in bytes.
 * @return a virtual address pointing to the newly allocated memory
 */
void *
platform_alloc_exec(int64_t len);

/**
 * Free Memory
 *
 * Used by the common code to free virtual memory that was allocated
 * using the platform_alloc function.
 *
 * @param addr the virtual address returned from platform_alloc
 */
void
platform_free(void *addr);

/**
 * Free Executable Memory
 *
 * Used by the common code to free virtual memory that was allocated
 * using the platform_alloc_exec function.
 *
 * @param addr the virtual address returned from platform_alloc_exec
 * @param len the size of the memory allocated
 */
void
platform_free_exec(void *addr, int64_t len);

#ifdef __cplusplus
}
#endif

#endif
