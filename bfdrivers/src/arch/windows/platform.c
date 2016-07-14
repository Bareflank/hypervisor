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

#include <platform.h>

#include <debug.h>

#define BF_TAG 'BFLK'
#define BF_NX_TAG 'BFNX'

void *
platform_alloc_rw(int64_t len)
{
    void *addr = NULL;

    if (len == 0)
    {
        ALERT("platform_alloc: invalid length\n");
        return addr;
    }

    addr = ExAllocatePoolWithTag(NonPagedPool, len, BF_TAG);

    if (addr) RtlZeroMemory(addr, len);

    return addr;
}

void *
platform_alloc_rwe(int64_t len)
{
    void *addr = NULL, *addr_remap = NULL;

    if (len == 0)
    {
        ALERT("platform_alloc_exec: invalid length\n");
        return addr;
    }

    addr = MmAllocateNonCachedMemory(len);

    PMDL mdl = IoAllocateMdl(addr, (ULONG)len, FALSE, FALSE, NULL);

    MmBuildMdlForNonPagedPool(mdl);

    MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);

    addr_remap = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, addr, FALSE, 0);

    DEBUG("%d\r\n", MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE));

    if (addr_remap == NULL)
        ALERT("platform_alloc: failed to ExAllocatePoolWithTag mem: %lld\n", len);

    return addr_remap;
}

void *
platform_virt_to_phys(void *virt)
{
    PHYSICAL_ADDRESS addr = MmGetPhysicalAddress(virt);

    return (void *)addr.QuadPart;
}

void
platform_free_rw(void *addr, int64_t size)
{
    (void)size;
    if (addr == NULL)
    {
        ALERT("platform_free: invalid address %p\n", addr);
        return;
    }

    ExFreePoolWithTag(addr, BF_TAG);
}

void
platform_free_rwe(void *addr, int64_t len)
{
    if (addr == NULL)
    {
        ALERT("platform_free_exec: invalid address %p\n", addr);
        return;
    }

    MmFreeNonCachedMemory(addr, len);
}

void
platform_memset(void *ptr, char value, int64_t num)
{
    if (!ptr)
        return;

    RtlFillMemory(ptr, num, value);
}

void
platform_memcpy(void *dst, const void *src, int64_t num)
{
    if (!dst || !src)
        return;

    RtlCopyMemory(dst, src, num);
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
