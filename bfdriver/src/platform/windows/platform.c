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
