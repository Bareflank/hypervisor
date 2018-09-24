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

#include <bfarch.h>
#include <bfdebug.h>
#include <bfplatform.h>

#include <common.h>

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>

#if defined(BF_AARCH64)
#   include <asm/io.h>
#endif

typedef long (*set_affinity_fn)(pid_t, const struct cpumask *);
set_affinity_fn set_cpu_affinity = nullptr;

int64_t
platform_init(void)
{
    set_cpu_affinity = (set_affinity_fn)kallsyms_lookup_name("sched_setaffinity");
    if (set_cpu_affinity == nullptr) {
        BFALERT("Failed to locate sched_setaffinity\n");
        return -1;
    }

    return BF_SUCCESS;
}

void *
platform_alloc_rw(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc_rw: invalid length\n");
        return addr;
    }

    addr = vmalloc(len);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rw: failed to vmalloc rw mem: %lld\n", len);
    }

    return addr;
}

void *
platform_alloc_rwe(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc_rwe: invalid length\n");
        return addr;
    }

    addr = __vmalloc(len, GFP_KERNEL, PAGE_KERNEL_EXEC);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rwe: failed to vmalloc rwe mem: %lld\n", len);
    }

    return addr;
}

void
platform_free_rw(const void *addr, uint64_t len)
{
    bfignored(len);

    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
}

void
platform_free_rwe(const void *addr, uint64_t len)
{
    bfignored(len);

    if (addr == nullptr) {
        BFALERT("platform_free_rwe: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
}

void *
platform_virt_to_phys(void *virt)
{
    if (is_vmalloc_addr(virt)) {
        return (void *)page_to_phys(vmalloc_to_page(virt));
    }
    else {
        return (void *)virt_to_phys(virt);
    }
}

void *
platform_memset(void *ptr, char value, uint64_t num)
{
    if (!ptr) {
        return nullptr;
    }

    return memset(ptr, value, num);
}

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{
    if (!dst || !src) {
        return nullptr;
    }

    return memcpy(dst, src, num);
}

int64_t
platform_num_cpus(void)
{
    int64_t num_cpus = num_online_cpus();

    if (num_cpus < 0) {
        return 0;
    }

    return num_cpus;
}

int64_t
platform_call_vmm_on_core(
    uint64_t cpuid, uint64_t request, uintptr_t arg1, uintptr_t arg2)
{
    if (set_cpu_affinity(current->pid, cpumask_of(cpuid)) != 0) {
        return BF_ERROR_UNKNOWN;
    }

    return common_call_vmm(cpuid, request, arg1, arg2);
}

void *
platform_get_rsdp(void)
{ return 0; }
