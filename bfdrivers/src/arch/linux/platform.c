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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

#include <asm/tlbflush.h>

void *
platform_alloc(int64_t len)
{
    void *addr = NULL;

    if (len == 0)
    {
        ALERT("platform_alloc: invalid length\n");
        return addr;
    }

    addr = vmalloc(len);

    if (addr == NULL)
        ALERT("platform_alloc: failed to vmalloc mem: %lld\n", len);

    return addr;
}

void *
platform_alloc_exec(int64_t len)
{
    void *addr = NULL;

    if (len == 0)
    {
        ALERT("platform_alloc_exec: invalid length\n");
        return addr;
    }

    addr = __vmalloc(len, GFP_KERNEL, PAGE_KERNEL_EXEC);

    if (addr == NULL)
        ALERT("platform_alloc_exec: failed to vmalloc executable mem: %lld\n", len);

    return addr;
}

void *
platform_virt_to_phys(void *virt)
{
    if (is_vmalloc_addr(virt))
        return (void *)page_to_phys(vmalloc_to_page(virt));
    else
        return (void *)virt_to_phys(virt);
}

void
platform_free(void *addr, int64_t len)
{
    (void)len;

    if (addr == NULL)
    {
        ALERT("platform_free: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
}

void
platform_free_exec(void *addr, int64_t len)
{
    if (addr == NULL)
    {
        ALERT("platform_free_exec: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
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
platform_start(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
    cr4_init_shadow();
#endif
}

void
platform_stop(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
    cr4_init_shadow();
#endif
}
