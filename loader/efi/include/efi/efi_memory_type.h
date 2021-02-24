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

#ifndef EFI_MEMORY_TYPE_H
#define EFI_MEMORY_TYPE_H

/**
 * @struct EFI_MEMORY_TYPE
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_MEMORY_TYPE struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef enum
{
    /**
     * @brief Not usable.
     */
    EfiReservedMemoryType,

    /**
     * @brief The code portions of a loaded UEFI application.
     */
    EfiLoaderCode,

    /**
     * @brief The data portions of a loaded UEFI application and the default
     *   data allocation type used by a UEFI application to allocate pool
     *   memory.
     */
    EfiLoaderData,

    /**
     * @brief The code portions of a loaded UEFI Boot Service Driver.
     */
    EfiBootServicesCode,

    /**
     * @brief The data portions of a loaded UEFI Boot Serve Driver, and the
     *   default data allocation type used by a UEFI Boot Service Driver to
     *   allocate pool memory.
     */
    EfiBootServicesData,

    /**
     * @brief The code portions of a loaded UEFI Runtime Driver
     */
    EfiRuntimeServicesCode,

    /**
     * @brief The data portions of a loaded UEFI Runtime Driver and the
     *   default data allocation type used by a UEFI Runtime Driver to
     *   allocate pool memory.
     */
    EfiRuntimeServicesData,

    /**
     * @brief Free (unallocated) memory.
     */
    EfiConventionalMemory,

    /**
     * @brief Memory in which errors have been detected.
     */
    EfiUnusableMemory,

    /**
     * @brief Memory that holds the ACPI tables.
     */
    EfiACPIReclaimMemory,

    /**
     * @brief Address space reserved for use by the firmware.
     */
    EfiACPIMemoryNVS,

    /**
     * @brief Used by system firmware to request that a memory-mapped IO
     *   region be mapped by the OS to a virtual address so it can be accessed
     *   by EFI runtime services.
     */
    EfiMemoryMappedIO,

    /**
     * @brief System memory-mapped IO region that is used to translate memory
     *   cycles to IO cycles by the processor.
     */
    EfiMemoryMappedIOPortSpace,

    /**
     * @brief Address space reserved by the firmware for code that is part of
     *   the processor.
     */
    EfiPalCode,

    /**
     * @brief A memory region that operates as EfiConventionalMemory. However,
     *   it happens to also support byte-addressable non-volatility.
     */
    EfiPersistentMemory,

    /**
     * @brief The end of the enum
     */
    EfiMaxMemoryType

} EFI_MEMORY_TYPE;

#endif
