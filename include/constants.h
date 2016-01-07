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

#ifndef CONSTANTS_H
#define CONSTANTS_H

/*
 * Max Supported vCPUs
 *
 * This defines the maximum number of vCPUs that are supported by the VMM.
 * Note that if this is changed, code withing the VMM will likely have to
 * change as well as the exit handlers are not dynamically allocated (i.e.
 * an exit handler is defined for each vCPU).
 */
#ifndef MAX_VCPUS
#define MAX_VCPUS (1)
#endif

/*
 * Cache Line Size
 *
 * The memory manager at the moment keeps track of blocks using a cache line
 * for performance reasons. If the cache line size is different, this value
 * might need to be tweaked.
 *
 * Note: defined in bytes
 */
#ifndef MAX_CACHE_LINE_SIZE
#define MAX_CACHE_LINE_SIZE (64)
#endif

/*
 * Page Size
 *
 * Defines the size of a page, which is used in a lot of places in the code.
 * Note that the memory manager handles memory of this size differently as well
 * for perforamnce reasons, so the value might need to be tweaked on other
 * systems.
 *
 * Note: defined in bytes
 */
#ifndef MAX_PAGE_SIZE
#define MAX_PAGE_SIZE (4096)
#endif

/*
 * Max Blocks
 *
 * This defines the maximum number of blocks that the memory manager will store
 * for new / delete. This value will also be used to define the alloc/free
 * bookkeeping. Note that each block is a cache line. Also note that we define
 * the total number of blocks using the max page size, which will ensure that
 * our mem pool is both a multiple of the cache line size, and of the page
 * size.
 */
#ifndef MAX_BLOCKS
#define MAX_BLOCKS (16 * MAX_PAGE_SIZE)
#endif

/*
 * Convience Macros
 *
 * These macros provide some useful information about how the memory manager
 * is defined. These should not be set by the compiler, but instead, are here
 * to calculate stats about how the compiler setup the other macros.
 */
#define BLOCKS_PER_PAGE (MAX_PAGE_SIZE / MAX_CACHE_LINE_SIZE)
#define TOTAL_NUM_PAGES (MAX_BLOCKS / BLOCKS_PER_PAGE)

/*
 * Max Internal Mem Pool
 *
 * This defines the internal memory that the hypervisor allocates to use
 * during setup by new/delete. Note that this is not the same
 * memory that is used by each guest VM as this memory will be provided by
 * the driver entry points when talking to the hypervisor as memory must
 * be reserved by the host OS for this purpose.
 *
 * Note: defined in bytes
 */
#ifndef MAX_MEM_POOL
#define MAX_MEM_POOL (MAX_CACHE_LINE_SIZE * MAX_BLOCKS)
#endif

/*
 * Max Supported Modules
 *
 * The maximum number of modules supported by the VMM. Note that the ELF loader
 * has it's own version of this that likely will need to be changed if this
 * value changes.
 */
#ifndef MAX_NUM_MODULES
#define MAX_NUM_MODULES (25)
#endif

/*
 * Max Number of Memory Descriptors
 *
 * The driver entry has to collect information about each page of memory that
 * the VMM uses, and then fills this information into a memory descriptor and
 * provides the info to the memory manager during initialization. This
 * defines the total number of descriptors that the memory manager can support
 * which caps the total amount of memory that the VMM can consume. This
 * includes it's internal memory for new / delete, but also all of the memory
 * used by every single module. If the driver entry is having a problem, this
 * number might need to be increased.
 *
 * Note: This caps the VMM at 100MB (i.e. 100MB / Page Size)
 */
#ifndef MAX_NUM_MEMORY_DESCRIPTORS
#define MAX_NUM_MEMORY_DESCRIPTORS (25600)
#endif

/**
 * Debug Ring Size
 *
 * Defines the size of the debug ring. Note that each vCPU gets one of these,
 * and thus the total amount of memory that is used can add up quickly. That
 * being said, make these as large as you can afford. Also note that these
 * will be allocated using the mem pool, so make sure that it is large enough
 * to hold the debug rings for each vCPU and then some.
 *
 * Note: defined in bytes
 */
#ifndef DEBUG_RING_SIZE
#define DEBUG_RING_SIZE (10 * 4096)
#endif

/**
 * Alignment
 *
 * Defines how the memory pool is aligned. Note that the larger this is made,
 * the larger the potential size of the module could be. Note that at minimum,
 * this needs to be aligned to the MAX_CACHE_LINE_SIZE
 */
#ifndef ALIGN
#define ALIGN __attribute__((aligned(MAX_CACHE_LINE_SIZE)))
#endif

#endif
