/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef EFI_MEMORY_DESCRIPTOR_H
#define EFI_MEMORY_DESCRIPTOR_H

#include <efi/efi_types.h>

/**
 * @brief Memory cacheability attribute: The memory region supports being
 *   configured as not cacheable.
 */
#define EFI_MEMORY_UC 0x0000000000000001

/**
 * @brief Memory cacheability attribute: The memory region supports being
 *   configured as write combining.
 */
#define EFI_MEMORY_WC 0x0000000000000002

/**
 * @brief Memory cacheability attribute: The memory region supports being
 *   configured as cacheable with a “write through” policy. Writes that
 *   hit in the cache will also be written to main memory.
 */
#define EFI_MEMORY_WT 0x0000000000000004

/**
 * @brief Memory cacheability attribute: The memory region supports being
 *   configured as cacheable with a “write back” policy. Reads and writes
 *   that hit in the cache do not propagate to main memory. Dirty data is
 *   written back to main memory when a new cache line is allocated.
 */
#define EFI_MEMORY_WB 0x0000000000000008

/**
 * @brief Memory cacheability attribute: The memory region supports being
 *   configured as not cacheable, exported, and supports the “fetch and
 *   add” semaphore mechanism.
 */
#define EFI_MEMORY_UCE 0x0000000000000010

/**
 * @brief Physical memory protection attribute: The memory region supports
 *   being configured as write-protected by system hardware. This is
 *   typically used as a cacheability attribute today. The memory region
 *   supports being configured as cacheable with a "write protected"
 *   policy. Reads come from cache lines when possible, and read misses
 *   cause cache fills. Writes are propagated to the system bus and cause
 *   corresponding cache lines on all processors on the bus to be
 *   invalidated.
 */
#define EFI_MEMORY_WP 0x0000000000001000

/**
 * @brief Physical memory protection attribute: The memory region supports
 *   being configured as read-protected by system hardware.
 */
#define EFI_MEMORY_RP 0x0000000000002000

/**
 * @brief Physical memory protection attribute: The memory region supports
 *   being configured so it is protected by system hardware from
 *   executing code.
 */
#define EFI_MEMORY_XP 0x0000000000004000

/**
 * @brief Runtime memory attribute: The memory region refers to persistent
 *   memory
 */
#define EFI_MEMORY_NV 0x0000000000008000

/**
 * @brief The memory region provides higher reliability relative to other
 *   memory in the system. If all memory has the same reliability, then
 *   this bit is not used.
 */
#define EFI_MEMORY_MORE_RELIABLE 0x0000000000010000

/**
 * @brief Physical memory protection attribute: The memory region supports
 *   making this memory range read-only by system hardware.
 */
#define EFI_MEMORY_RO 0x0000000000020000

/**
 * @brief Specific-purpose memory (SPM). The memory is earmarked for
 *   specific purposes such as for specific device drivers or applications.
 *   The SPM attribute serves as a hint to the OS to avoid allocating this
 *   memory for core OS data or code that can not be relocated.
 *   Prolonged use of this memory for purposes other than the intended
 *   purpose may result in suboptimal platform performance.
 */
#define EFI_MEMORY_SP 0x0000000000040000

/**
 * @brief If this flag is set, the memory region is capable of being
 *   protected with the CPU’s memory cryptographic
 *   capabilities. If this flag is clear, the memory region is not
 *   capable of being protected with the CPU’s memory
 *   cryptographic capabilities or the CPU does not support CPU
 *   memory cryptographic capabilities.
 */
#define EFI_MEMORY_CPU_CRYPTO 0x0000000000080000

/**
 * @brief Runtime memory attribute: The memory region needs to be given a
 *   virtual mapping by the operating system when
 *   SetVirtualAddressMap() is called
 */
#define EFI_MEMORY_RUNTIME 0x8000000000000000

/**
 * @struct EFI_MEMORY_DESCRIPTOR
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_MEMORY_DESCRIPTOR struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct
{
    /**
     * @brief Type of the memory region. Type EFI_MEMORY_TYPE is defined in
     *   the AllocatePages() function description.
     */
    UINT32 Type;

    /**
     * @brief Physical address of the first byte in the memory region.
     *   PhysicalStart must be aligned on a 4 KiB boundary, and must not be
     *   above 0xfffffffffffff000.
     */
    EFI_PHYSICAL_ADDRESS PhysicalStart;

    /**
     * @brief Virtual address of the first byte in the memory region.
     *   VirtualStart must be aligned on a 4 KiB boundary, and must not be
     *   above 0xfffffffffffff000.
     */
    EFI_VIRTUAL_ADDRESS VirtualStart;

    /**
     * @brief Number of 4 KiB pages in the memory region. NumberOfPages must
     *   not be 0, and must not be any value that would represent a memory
     *   page with a start address, either physical or virtual, above
     *   0xfffffffffffff000
     */
    UINT64 NumberOfPages;

    /**
     * @brief Attributes of the memory region that describe the bit mask of
     *   capabilities for that memory region, and not necessarily the current
     *   settings for that memory region.
     */
    UINT64 Attribute;

} EFI_MEMORY_DESCRIPTOR;

#endif
