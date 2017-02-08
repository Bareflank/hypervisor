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

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <platform.h>
#include <sys/mman.h>
#include <constants.h>

int alloc_count_rw = 0;
int alloc_count_rwe = 0;

#define PAGE_ROUND_UP(x) ( (((uintptr_t)(x)) + MAX_PAGE_SIZE-1)  & (~(MAX_PAGE_SIZE-1)) )

uint64_t g_malloc_fails = 0;
uint64_t g_set_afinity_fails = 0;
uint64_t g_vmcall = 0;

int
verify_no_mem_leaks(void)
{
    printf("alloc_count_rw: %d\n", alloc_count_rw);
    printf("alloc_count_rwe: %d\n", alloc_count_rwe);

    return (alloc_count_rw == 0) && (alloc_count_rwe == 0);
}

void *
platform_alloc_rw(uint64_t len)
{
    if (g_malloc_fails == len)
        return 0;

    alloc_count_rw++;
    return malloc(len);
}

#include <errno.h>

void *
platform_alloc_rwe(uint64_t len)
{
    void *addr = 0;

    if (g_malloc_fails == len)
        return 0;

    len = PAGE_ROUND_UP(len);

    if (posix_memalign(&addr, MAX_PAGE_SIZE, len) != 0)
        return 0;

    if (mprotect(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        platform_free_rw(addr, len);
        return 0;
    }

    alloc_count_rwe++;

    return addr;
}

void
platform_free_rw(void *addr, uint64_t len)
{
    (void)len;

    alloc_count_rw--;
    free(addr);
}

void
platform_free_rwe(void *addr, uint64_t len)
{
    (void) len;

    alloc_count_rwe--;
    free(addr);
}

void *
platform_virt_to_phys(void *virt)
{
    return virt;
}

void
platform_memset(void *ptr, char value, uint64_t num)
{
    if (!ptr)
        return;

    memset(ptr, value, num);
}

void
platform_memcpy(void *dst, const void *src, uint64_t num)
{
    if (!dst || !src)
        return;

    memcpy(dst, src, num);
}

void
platform_start(void)
{
}

void
platform_stop(void)
{
}

int64_t
platform_num_cpus(void)
{
    return 1;
}

int64_t
platform_set_affinity(int64_t affinity)
{
    (void) affinity;

    if (g_set_afinity_fails != 0)
        return -1;

    return 0;
}

void
platform_restore_affinity(int64_t affinity)
{
    (void) affinity;
}

void
platform_vmcall(struct vmcall_registers_t *regs)
{
    regs->r01 = g_vmcall;
}

void
platform_vmcall_event(struct vmcall_registers_t *regs)
{
    regs->r01 = g_vmcall;
}
