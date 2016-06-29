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

#ifndef MEMORY_H
#define MEMORY_H

#ifndef KERNEL
#include <stdint.h>
#else
#include <types.h>
#endif

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Memory Manger Error Codes
 */
#define MEMORY_MANAGER_SUCCESS 0
#define MEMORY_MANAGER_FAILURE -1LL

/**
 * Memory Types
 */
#define MEMORY_TYPE_R 0x1
#define MEMORY_TYPE_W 0x2
#define MEMORY_TYPE_E 0x4

/**
 * Memory Descriptor
 *
 * A memory descriptor provides information about a block of memory.
 * Typically, each page of memory that the VMM uses will have a memory
 * descriptor assocaited with it. The VMM will use this information to create
 * it's resources, as well as generate page tables as needed.
 *
 * @var memory_descriptor::phys
 *     the starting physical address of the block of memory
 * @var memory_descriptor::virt
 *     the starting virtual address of the block of memory
 * @var memory_descriptor::type
 *     the type of meory block. This is likely archiecture specific as
 *     this holds information about access rights, etc...
 */
struct memory_descriptor
{
    void *phys;
    void *virt;
    uint8_t type;
};

/**
 * Add Memory Descriptor
 *
 * This is used by the driver entry to add an MD to VMM. The driver entry
 * will need to collect memory descriptors for every page of memory that the
 * VMM is using so that the memory manager can provide mappings as needed.
 */
typedef int64_t (*add_md_t)(struct memory_descriptor *md);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
