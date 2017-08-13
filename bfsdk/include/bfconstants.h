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

#ifndef BFCONSTANTS_H
#define BFCONSTANTS_H

#include <bftypes.h>

/*
 * Hypervisor Version
 *
 * Uses http://semver.org
 */
#define BAREFLANK_VERSION_MAJOR 1ULL
#define BAREFLANK_VERSION_MINOR 2ULL
#define BAREFLANK_VERSION_PATCH 0ULL

/*
 * User Version
 *
 * Uses http://semver.org
 */
#ifndef USER_VERSION_MAJOR
#define USER_VERSION_MAJOR 0ULL
#endif

#ifndef USER_VERSION_MINOR
#define USER_VERSION_MINOR 0ULL
#endif

#ifndef USER_VERSION_PATCH
#define USER_VERSION_PATCH 0ULL
#endif

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
#define MAX_HEAP_POOL (256ULL * MAX_PAGE_SIZE * sizeof(uintptr_t))
#endif

/*
 * Max Page Pool
 *
 * This defines the internal memory that the hypervisor allocates to use
 * for allocating pages.
 *
 * Note: defined in bytes (defaults to 32MB)
 */
#ifndef MAX_PAGE_POOL
#define MAX_PAGE_POOL (32 * 256ULL * MAX_PAGE_SIZE)
#endif

/*
 * Max Memory Map Pool
 *
 * This defines the virtual memory that the hypervisor will use for mapping
 * memory
 *
 * Note: defined in bytes (defaults to 8MB)
 */
#ifndef MAX_MEM_MAP_POOL
#define MAX_MEM_MAP_POOL (256ULL * MAX_PAGE_SIZE * sizeof(uintptr_t))
#endif

/*
 * Memory Map Pool Start
 *
 * This defines the starting location of the virtual memory that is used
 * for memory mapping.
 *
 * Note: defined in bytes (defaults to 2MB)
 */
#ifndef MEM_MAP_POOL_START
#define MEM_MAP_POOL_START 0x200000ULL
#endif

/*
 * Max Supported Modules
 *
 * The maximum number of modules supported by the VMM. Note that the ELF loader
 * has its own version of this that likely will need to be changed if this
 * value changes.
 */
#ifndef MAX_NUM_MODULES
#define MAX_NUM_MODULES (75LL)
#endif

/*
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

/*
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

/*
 * Stack Size
 *
 * Each entry function is guarded with a custom stack to prevent stack
 * overflows from corrupting the kernel, as well as providing a larger stack
 * that's common in userspace code, but not in the kernel. If stack corruption
 * is occuring, this function likely needs to be increased. Note one stack
 * frame is allocated per CPU, so only increase this if needed.
 *
 * Note: Must be defined using a bit shift as we will mask to get the
 *       bottom of the stack if needed.
 *
 * Note: This is hard coded in the thread_context.asm as there is no way to
 *       use this include in NASM. If you change this, you must change the
 *       value in that file as well.
 */
#ifndef STACK_SIZE
#define STACK_SIZE (1ULL << 15)
#endif

/*
 * Thread Local Storage (TLS) Size
 *
 * Bareflank don't support threads, but it does support Multi-Core, and
 * we need a way to store CPU specific information. Certain libc++
 * operations (for example, std::uncaught_exceptions) need to use this CPU
 * specific storage so that the cores are not interfering with each other.
 * So as far as the code is concerned, TLS is being used, even if a "thread"
 * in the traditional sense isn't.
 *
 * Note: Defined in bytes
 */
#ifndef THREAD_LOCAL_STORAGE_SIZE
#define THREAD_LOCAL_STORAGE_SIZE (0x1000ULL)
#endif

/*
 * Stack Reserved
 *
 * The bottom of the stack is reserved for storing useful information
 * (similar to the Linux kernel). The following defines how much of the
 * stack is reserved.
 *
 * Note: Defined in bytes
 */
#ifndef STACK_RESERVED
#define STACK_RESERVED (0x20)
#endif

/*
 * VMCall In Buffer Size (MAX)
 *
 * Note: Defined in bytes
 */
#ifndef VMCALL_IN_BUFFER_SIZE
#define VMCALL_IN_BUFFER_SIZE (32 * MAX_PAGE_SIZE)
#endif

/*
 * VMCall Out Buffer Size (MAX)
 *
 * Note: Defined in bytes
 */
#ifndef VMCALL_OUT_BUFFER_SIZE
#define VMCALL_OUT_BUFFER_SIZE (32 * MAX_PAGE_SIZE)
#endif

/*
 * Default Serial COM Port
 *
 * Possible values include (but not limited to):
 *    - 0x03F8U  // COM1
 *    - 0x02F8U  // COM2
 *    - 0x03E8U  // COM3
 *    - 0x02E8U  // COM4
 *    - 0xE000U
 *    - 0xE010U
 *
 * Note: See bfvmm/serial/serial_port_intel_x64.h
 */
#ifndef DEFAULT_COM_PORT
#define DEFAULT_COM_PORT 0x3F8U
#endif

/*
 * Default Serial Baud Rate
 *
 * Note: See bfvmm/serial/serial_port_intel_x64.h
 */
#ifndef DEFAULT_BAUD_RATE
#define DEFAULT_BAUD_RATE baud_rate_115200
#endif

/*
 * Default Serial Data Bits
 *
 * Note: See bfvmm/serial/serial_port_intel_x64.h
 */
#ifndef DEFAULT_DATA_BITS
#define DEFAULT_DATA_BITS char_length_8
#endif

/*
 * Default Serial Stop Bits
 *
 * Note: See bfvmm/serial/serial_port_intel_x64.h
 */
#ifndef DEFAULT_STOP_BITS
#define DEFAULT_STOP_BITS stop_bits_1
#endif

/*
 * Default Serial Parity Bits
 *
 * Note: See bfvmm/serial/serial_port_intel_x64.h
 */
#ifndef DEFAULT_PARITY_BITS
#define DEFAULT_PARITY_BITS parity_none
#endif

/*
 * Debug Level
 *
 * Defines how noisy Bareflank is. This defaults to 0 which only prints status
 * information. Raise this level to include additional verbosity. Note that
 * as you increase this level, performance will degrade.
 */
#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#endif
