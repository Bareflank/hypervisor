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

#ifndef EXTENDED_PROCESSOR_INFORMATION_H
#define EXTENDED_PROCESSOR_INFORMATION_H

#include <efi/efi_cpu_physical_location2.h>

/** @brief Defined in EFI_MP_SERVICES_PROTOCOL.GetProcessorInfo() */
#define CPU_V2_EXTENDED_TOPOLOGY BIT24

/**
 * <!-- description -->
 *   @brief Defines the layout of the EXTENDED_PROCESSOR_INFORMATION struct:
 *     https://uefi.org/sites/default/files/resources/PI_Spec_1_7_A_final_May1.pdf
 */
typedef union
{
    /**
     * @brief The 6-level physical location of the processor, including the
     *   physical package number that identifies the cartridge, the physical
     *   module number within package, the physical tile number within the
     *   module, the physical die number within the tile, the physical core
     *   number within package, and logical thread number within core.
     */
    EFI_CPU_PHYSICAL_LOCATION2 Location2;

} EXTENDED_PROCESSOR_INFORMATION;

#endif
