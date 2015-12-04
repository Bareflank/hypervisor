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
#include <linux/module.h>

void *
platform_alloc(int32_t len)
{
    void *addr;

    if (len == 0)
    {
        ALERT("platform_alloc: invalid length\n");
        return NULL;
    }

    addr = vmalloc(len);

    if (addr == NULL)
    {
        ALERT("platform_alloc: failed to vmalloc mem: %d\n", len);
        return NULL;
    }

    return addr;
}

void *
platform_alloc_exec(int32_t len)
{
    void *addr;

    if (len == 0)
    {
        ALERT("platform_alloc_exec: invalid length\n");
        return NULL;
    }

    addr = __vmalloc(len, GFP_KERNEL, PAGE_KERNEL_EXEC);

    if (addr == NULL)
    {
        ALERT("platform_alloc_exec: failed to vmalloc executable mem: %d\n", len);
        return NULL;
    }

    return addr;
}

void
platform_free(void *addr)
{
    if (addr == NULL)
    {
        ALERT("platform_free: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
}

void
platform_free_exec(void *addr)
{
    if (addr == NULL)
    {
        ALERT("platform_free_exec: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
}
