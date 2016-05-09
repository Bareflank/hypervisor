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

#include <libkern/OSMalloc.h>
#include <vm/pmap.h>
#include <libkern/libkern.h>
#include <sys/conf.h>
#include <mach/mach_types.h>
extern "C" {
#include <kern/assert.h>
#include <kern/kext_alloc.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
}

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>


OSMallocTag bf_mem_tag = NULL;
extern vm_map_t kernel_map;
extern int kernel_pmap;
extern "C" kern_return_t kmem_alloc(vm_map_t        map,
                                    vm_offset_t     *addrp,
                                    vm_size_t       size,
                                    vm_prot_t        prot);

typedef int pmap_t;
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);

void *
platform_alloc(int64_t len)
{
    void *addr = NULL;

    if (len == 0)
    {
        IOLog("platform_alloc: invalid length\n");
        return addr;
    }

    addr = OSMalloc((uint32_t)len, bf_mem_tag);

    if (addr == NULL)
    {
        IOLog("platform_alloc: failed to vmalloc mem: %lld\n", len);
    }

    return addr;
}

void *
platform_alloc_exec(int64_t len)
{
    void *ptr = platform_alloc(len);

    return ptr;
}

void *
platform_virt_to_phys(void *virt)
{
    void *ptr = 0x00;
    IOMemoryDescriptor *mem_desc;

    mem_desc = IOMemoryDescriptor::withAddress(virt, 4096, kIODirectionInOut);

    mem_desc->prepare();

    ptr = (void *)mem_desc->getPhysicalAddress();

    return ptr;
}

void
platform_free(void *addr, int64_t len)
{
    if (addr == NULL)
    {
        IOLog("platform_free: invalid address %p\n", addr);
        return;
    }


    OSFree(addr, (uint32_t)len, bf_mem_tag);
}

void
platform_free_exec(void *addr, int64_t len)
{
    if (addr == NULL)
    {
        IOLog("platform_free_exec: invalid address %p\n", addr);
        return;
    }

    platform_free(addr, len);
}

void
platform_memset(void *ptr, char value, int64_t num)
{
    if (!ptr)
        return;

    memset(ptr, value, num);
}

void
platform_memcpy(void *dst, const void *src, int64_t num)
{
    if (!dst || !src)
        return;

    memcpy(dst, src, num);
}

void
platform_start()
{

}

void
platform_stop()
{

}
