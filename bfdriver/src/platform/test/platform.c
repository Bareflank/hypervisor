/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
platform_free_rw(void *addr, uint64_t len)
{
    bfignored(len);
    free(addr);
}

void
platform_free_rwe(void *addr, uint64_t len)
{
    bfignored(len);
    free(addr);
}

void *
platform_virt_to_phys(void *virt)
{ return virt; }

void *
platform_memset(void *ptr, char value, uint64_t num)
{ return memset(ptr, value, num); }

int64_t
platform_memcpy(
    void *dst, uint64_t dst_size, const void *src, uint64_t src_size, uint64_t num)
{
    bfignored(dst_size);
    bfignored(src_size);

    memcpy(dst, src, num);
    return SUCCESS;
}

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
