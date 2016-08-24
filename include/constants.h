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
 * Cache Line Shift
 *
 * The memory manager at the moment keeps track of blocks using a cache line
 * for performance reasons. If the cache line size is different, this value
 * might need to be tweaked. Note that this defines the shift that will be
 * used by MAX_CACHE_LINE_SIZE
 *
 * Note: defined in bits
 */
#ifndef MAX_CACHE_LINE_SHIFT
#define MAX_CACHE_LINE_SHIFT (6ULL)
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
#define MAX_CACHE_LINE_SIZE (1 << MAX_CACHE_LINE_SHIFT)
#endif

/*
 * Max Page Shift
 *
 * Defines the maximum page size that is supported by the VMM (not the max
 * size supported by hardware, which is likely different). For now, this is
 * set to a value that is likely supported by most hardware. All pages must
 * be translated to this value, as the VMM only supports one page size.
 *
 * Note: defined in bits
 */
#ifndef MAX_PAGE_SHIFT
#define MAX_PAGE_SHIFT (12ULL)
#endif


/*
 * Max Page Size
 *
 * Defines the maximum page size that is supported by the VMM (not the max
 * size supported by hardware, which is likely different). For now, this is
 * set to a value that is likely supported by most hardware. All pages must
 * be translated to this value, as the VMM only supports one page size.
 *
 * Note: defined in bytes
 */
#ifndef MAX_PAGE_SIZE
#define MAX_PAGE_SIZE (1ULL << MAX_PAGE_SHIFT)
#endif

/*
 * Max Heap Pool
 *
 * This defines the internal memory that the hypervisor allocates to use
 * during setup by new/delete. Note that things like the debug_ring and
 * anything that uses a std::container uses this heap so it does need to
 * have some size to it. Pages do not come from this pool.
 *
 * Note: defined in bytes (defaults to 8MB)
 */
#ifndef MAX_HEAP_POOL
#define MAX_HEAP_POOL (256ULL * MAX_PAGE_SIZE)
#endif

/*
 * Max Page Pool
 *
 * This defines the internal memory that the hypervisor allocates to use
 * for allocating pages.
 *
 * Note: defined in bytes (defaults to 8MB)
 */
#ifndef MAX_PAGE_POOL
#define MAX_PAGE_POOL (256ULL)
#endif

/*
 * Max Supported Modules
 *
 * The maximum number of modules supported by the VMM. Note that the ELF loader
 * has it's own version of this that likely will need to be changed if this
 * value changes.
 */
#ifndef MAX_NUM_MODULES
#define MAX_NUM_MODULES (25LL)
#endif

/**
 * Debug Ring Shift
 *
 * Defines the size of the debug ring. Note that each vCPU gets one of these,
 * and thus the total amount of memory that is used can add up quickly. That
 * being said, make these as large as you can afford. Also note that these
 * will be allocated using the mem pool, so make sure that it is large enough
 * to hold the debug rings for each vCPU and then some.
 *
 * Note: defined in shifted bits
 */
#ifndef DEBUG_RING_SHIFT
#define DEBUG_RING_SHIFT (15)
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
#define DEBUG_RING_SIZE (1 << DEBUG_RING_SHIFT)

/// Stack Size
///
/// Each entry function is guarded with a custom stack to prevent stack
/// overflows from corrupting the kernel, as well as providing a larger stack
/// that common in userspace code, but not in the kernel. If stack corruption
/// is occuring, this function likely needs to be increased. Note one stack
/// frame is allocated per CPU, so only increase this if needed.
///
/// Note: define in 64bits (i.e. an array of uint64_t)
///
#ifndef STACK_SIZE
#define STACK_SIZE 0x8000
#endif

#endif
