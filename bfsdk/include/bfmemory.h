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

/**
 * @file bfmemory.h
 */

#ifndef BFMEMORY_H
#define BFMEMORY_H

#include <bftypes.h>
#include <bfconstants.h>
#include <bferrorcodes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/* @cond */

#define MEMORY_TYPE_R 0x1U
#define MEMORY_TYPE_W 0x2U
#define MEMORY_TYPE_E 0x4U

/* @endcond */

/**
 * @struct memory_descriptor
 *
 * Memory Descriptor
 *
 * A memory descriptor provides information about a block of memory.
 * Typically, each page of memory that the VMM uses will have a memory
 * descriptor associated with it. The VMM will use this information to create
 * its resources, as well as generate page tables as needed.
 *
 * @var memory_descriptor::phys
 *     the starting physical address of the block of memory
 * @var memory_descriptor::virt
 *     the starting virtual address of the block of memory
 * @var memory_descriptor::type
 *     the type of memory block. This is likely architecture specific as
 *     this holds information about access rights, etc...
 */
struct memory_descriptor {
    uint64_t phys;
    uint64_t virt;
    uint64_t type;
};

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
