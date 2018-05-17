/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <ntddk.h>

#include <bfdebug.h>
#include <bfplatform.h>

#define BF_TAG 'BFLK'
#define BF_NX_TAG 'BFNX'

void *
platform_alloc_rw(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc: invalid length\n");
        return addr;
    }

    addr = ExAllocatePoolWithTag(NonPagedPool, len, BF_TAG);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rw: failed to ExAllocatePoolWithTag mem: %lld\n", len);
    }

    return addr;
}

void *
platform_alloc_rwe(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc: invalid length\n");
        return addr;
    }

    addr = ExAllocatePoolWithTag(NonPagedPoolExecute, len, BF_TAG);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rw: failed to ExAllocatePoolWithTag mem: %lld\n", len);
    }

    return addr;
}

void *
platform_virt_to_phys(void *virt)
{
    PHYSICAL_ADDRESS addr = MmGetPhysicalAddress(virt);
    return (void *)addr.QuadPart;
}

void
platform_free_rw(const void *addr, uint64_t len)
{
    (void) len;

    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    ExFreePoolWithTag((void *)addr, BF_TAG);
}

void
platform_free_rwe(const void *addr, uint64_t len)
{
    (void) len;

    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    ExFreePoolWithTag((void *)addr, BF_TAG);
}

void *
platform_memset(void *ptr, char value, uint64_t num)
{
    if (ptr == nullptr) {
        return nullptr;
    }

    RtlFillMemory(ptr, num, value);
    return ptr;
}

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{
    if (dst == nullptr || src == nullptr) {
        return nullptr;
    }

    RtlCopyMemory(dst, src, num);
    return dst;
}

void
platform_start()
{

}

void
platform_stop()
{

}

int64_t
platform_num_cpus()
{
    KAFFINITY k_affin;
    return (int64_t)KeQueryActiveProcessorCount(&k_affin);
}

int64_t
platform_set_affinity(int64_t affinity)
{
    KAFFINITY new_affinity = (1ULL << affinity);
    return (int64_t)KeSetSystemAffinityThreadEx(new_affinity);
}

void
platform_restore_affinity(int64_t affinity)
{
    KeRevertToUserAffinityThreadEx((KAFFINITY)(affinity));
}

int64_t
platform_get_current_cpu_num(void)
{
    return KeGetCurrentProcessorNumberEx(nullptr);
}

void
platform_restore_preemption(void)
{
}

int64_t
platform_populate_info(struct platform_info_t *info)
{
    if (info) {
        platform_memset(info, 0, sizeof(struct platform_info_t));
    }

    return BF_SUCCESS;
}

void
platform_unload_info(struct platform_info_t *info)
{
    (void) info;
}
