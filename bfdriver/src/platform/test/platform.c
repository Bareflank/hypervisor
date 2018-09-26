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

#include <common.h>
#include <bfplatform.h>
#include <bfconstants.h>

#ifdef WIN64
#include <windows.h>
#else
#include <sys/mman.h>
#endif

int platform_info_should_fail = 0;

#define PAGE_ROUND_UP(x) ( (((uintptr_t)(x)) + BAREFLANK_PAGE_SIZE-1)  & (~(BAREFLANK_PAGE_SIZE-1)) )

int64_t
platform_init(void)
{ return BF_SUCCESS; }

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
    addr = aligned_alloc(BAREFLANK_PAGE_SIZE, len);

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

int64_t
platform_num_cpus(void)
{ return 1; }

int64_t
platform_call_vmm_on_core(
    uint64_t cpuid, uint64_t request, uintptr_t arg1, uintptr_t arg2)
{
    return common_call_vmm(cpuid, request, arg1, arg2);
}

void *
platform_get_rsdp(void)
{ return 0; }
