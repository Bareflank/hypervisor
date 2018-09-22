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

#ifndef BFCONSTANTS_H
#define BFCONSTANTS_H

#include <bfarch.h>
#include <bftypes.h>

/*
 * Max Physical Address
 *
 * Defines the maximum physical address the system can access. This can be
 * used by CR3 and EPT to define the memory map used by the VMM. Note that
 * if this value is too large, its possible additional memory would be needed
 * by the VMM to setup CR3 or EPT depending on the granulairty used.
 *
 * Note: defined in bytes
 */
#ifndef MAX_PHYS_ADDR
#define MAX_PHYS_ADDR 0x1000000000
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
#ifndef BAREFLANK_PAGE_SIZE
#define BAREFLANK_PAGE_SIZE (0x1000ULL)
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
#define DEBUG_RING_SIZE (1 << 15ULL)

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
#define STACK_SIZE (1ULL << 15ULL)
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
 * Default Serial COM Port
 *
 * On x64, possible values include (but not limited to):
 *    - 0x03F8U  // COM1
 *    - 0x02F8U  // COM2
 *    - 0x03E8U  // COM3
 *    - 0x02E8U  // COM4
 *    - 0xE000U
 *    - 0xE010U
 *
 * On aarch64, the value is the serial peripheral's physical base address.
 *
 * Note: See bfvmm/serial/serial_ns16550a.h
 */
#ifndef DEFAULT_COM_PORT
#if defined(BF_AARCH64)
#   define DEFAULT_COM_PORT 0x09000000
#else
#   define DEFAULT_COM_PORT 0x03F8U
#   define DEFAULT_COM_DRIVER serial_ns16550a
#endif
#endif

/*
 * Serial Port Driver
 *
 * Possible values include:
 *     - serial_ns16550a
 *     - serial_pl011
 *
 * On x64, this should always be serial_ns16550a.
 */
#ifndef DEFAULT_COM_DRIVER
#if defined(BF_AARCH64)
#   define DEFAULT_COM_DRIVER serial_pl011
#else
#   define DEFAULT_COM_DRIVER serial_ns16550a
#endif
#endif

/*
 * Serial port memory length (aarch64 only)
 *
 * This is the length of the memory region occupied by the memory-mapped
 * serial port.
 */
#if !defined(DEFAULT_COM_LENGTH) && defined(BF_AARCH64)
#define DEFAULT_COM_LENGTH 0x1000
#endif

/*
 * Default Serial Baud Rate
 *
 * Note: See bfvmm/serial/serial_ns16550a.h
 */
#ifndef DEFAULT_BAUD_RATE
#define DEFAULT_BAUD_RATE baud_rate_115200
#endif

/*
 * Default serial baud rate divisor, integer part (for PL011)
 *
 * Note: See bfvmm/serial/serial_pl011.h
 */
#ifndef DEFAULT_BAUD_RATE_INT
#define DEFAULT_BAUD_RATE_INT 0x4
#endif

/*
 * Default serial baud rate divisor, fractional part (for PL011)
 *
 * Note: See bfvmm/serial/serial_pl011.h
 */
#ifndef DEFAULT_BAUD_RATE_FRAC
#define DEFAULT_BAUD_RATE_FRAC 0x0
#endif

/*
 * Default Serial Data Bits
 *
 * Note: See bfvmm/serial/serial_ns16550a.h
 */
#ifndef DEFAULT_DATA_BITS
#define DEFAULT_DATA_BITS char_length_8
#endif

/*
 * Default Serial Stop Bits
 *
 * Note: See bfvmm/serial/serial_ns16550a.h
 */
#ifndef DEFAULT_STOP_BITS
#define DEFAULT_STOP_BITS stop_bits_1
#endif

/*
 * Default Serial Parity Bits
 *
 * Note: See bfvmm/serial/serial_ns16550a.h
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
