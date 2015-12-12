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

#include <constants.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Memory Manger Error Codes
 */
#define MEMORY_MANAGER_SUCCESS 0
#define MEMORY_MANAGER_FAILURE -1

/**
 * Page
 *
 * The following defines a page. This structure is used by the driver entry
 * point to provide the VMM with information about a page that the driver
 * entry point has allocated.
 */
struct page_t
{
    void *phys;
    void *virt;
    unsigned long long size;
};

/**
 * Memory Manager Typedefs
 *
 * This is used by the driver entry to as the function signature for
 * memory manager functions
 */
typedef long long int (*add_page_t)(struct page_t *pg);
typedef long long int (*remove_page_t)(struct page_t *pg);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
