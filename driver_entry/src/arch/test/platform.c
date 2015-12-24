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

#include <stdio.h>
#include <stdlib.h>
#include <platform.h>
#include <sys/mman.h>

int alloc_count = 0;
int alloc_exec_count = 0;
int alloc_page_count = 0;

int
verify_no_mem_leaks(void)
{
    printf("alloc_count: %d\n", alloc_count);
    printf("alloc_exec_count: %d\n", alloc_exec_count);
    printf("alloc_page_count: %d\n", alloc_page_count);

    return (alloc_count == 0) &&
           (alloc_exec_count == 0) &&
           (alloc_page_count == 0);
}

void *
platform_alloc(int64_t len)
{
    alloc_count++;
    return malloc(len);
}

void *
platform_alloc_exec(int64_t len)
{
    alloc_exec_count++;
    return mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANON, -1, 0);
}

struct page_t
platform_alloc_page(void)
{
    struct page_t pg;

    pg.virt = (void *)48;
    pg.phys = (void *)1516;
    pg.size = 2342;

    alloc_page_count++;

    return pg;
}

void
platform_free(void *addr)
{
    alloc_count--;
    free(addr);
}

void
platform_free_exec(void *addr, int64_t len)
{
    alloc_exec_count--;
    munmap(addr, len);
}

void
platform_free_page(struct page_t pg)
{
    alloc_page_count--;
}
