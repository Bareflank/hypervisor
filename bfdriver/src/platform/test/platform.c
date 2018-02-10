/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
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
#include <string.h>

#include <bfplatform.h>
#include <bfconstants.h>

#ifdef WIN64
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define PAGE_ROUND_UP(x) ( (((uintptr_t)(x)) + MAX_PAGE_SIZE-1)  & (~(MAX_PAGE_SIZE-1)) )

void *
platform_alloc_rw(uint64_t len)
{ return malloc(len); }

void *
platform_alloc_rwe(uint64_t len)
{
    void *addr = 0;

#ifdef WIN64
    DWORD oldProtect;
#else
    int ret;
#endif

    len = PAGE_ROUND_UP(len);
    addr = aligned_alloc(MAX_PAGE_SIZE, len);

#ifdef WIN64
    VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProtect);
#else
    ret = mprotect(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
    bfignored(ret);
#endif

    return addr;
}

void
platform_free_rw(const void *addr, uint64_t len)
{
    bfignored(len);
    free((void *)addr);
}

void
platform_free_rwe(const void *addr, uint64_t len)
{
    bfignored(len);
    free((void *)addr);
}

void *
platform_virt_to_phys(void *virt)
{ return virt; }

void *
platform_memset(void *ptr, char value, uint64_t num)
{ return memset(ptr, value, num); }

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{ return memcpy(dst, src, num); }

void
platform_start(void)
{ }

void
platform_stop(void)
{ }

int64_t
platform_num_cpus(void)
{ return 1; }

int64_t
platform_set_affinity(int64_t affinity)
{
    bfignored(affinity);
    return 0;
}

void
platform_restore_affinity(int64_t affinity)
{ bfignored(affinity); }

int64_t
platform_get_current_cpu_num(void)
{ return 0; }

void
platform_restore_preemption(void)
{ }
