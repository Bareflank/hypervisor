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

#include <stdlib.h>
#include <platform.h>
#include <sys/mman.h>

void *
platform_alloc(int64_t len)
{
    return malloc(len);
}

void *
platform_alloc_exec(int64_t len)
{
    return mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANON, -1, 0);
}

void
platform_free(void *addr)
{
    free(addr);
}

void
platform_free_exec(void *addr, int64_t len)
{
    munmap(addr, len);
}
