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

#ifndef EFI_PROCESSOR_INFORMATION_H
#define EFI_PROCESSOR_INFORMATION_H

#include "efi_cpu_physical_location.h"
#include "efi_types.h"
#include "extened_processor_information.h"

/**
 * @brief This bit indicates whether the processor is playing the role of BSP.
 *   If the bit is 1, then the processor is BSP. Otherwise, it is AP.
 */
#define PROCESSOR_AS_BSP_BIT 0x00000001

/**
 * @brief This bit indicates whether the processor is enabled. If the bit is 1,
 *   then the processor is enabled. Otherwise, it is disabled.
 */
#define PROCESSOR_ENABLED_BIT 0x00000002

/**
 * @brief This bit indicates whether the processor is healthy. If the bit is 1,
 *   then the processor is healthy. Otherwise, some fault has been detected for
 *   the processor.
 */
#define PROCESSOR_HEALTH_STATUS_BIT 0x00000004

/**
 * @struct EFI_PROCESSOR_INFORMATION
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_PROCESSOR_INFORMATION struct:
 *     https://uefi.org/sites/default/files/resources/PI_Spec_1_7_A_final_May1.pdf
 */
typedef struct
{
    /**
     * @brief The unique processor ID determined by system hardware. For IPF,
     *   the lower 16 bits contains id/eid, and higher bits are reserved.
     */
    UINT64 ProcessorId;

    /**
     * @brief Flags indicating if the processor is BSP or AP, if the processor
     *   is enabled or disabled, and if the processor is healthy. The bit
     *   format is defined below.
     */
    UINT32 StatusFlag;

    /**
     * @brief The physical location of the processor, including the physical
     *   package number that identifies the cartridge, the physical core number
     *   within package, and logical thread number within core.
     */
    EFI_CPU_PHYSICAL_LOCATION Location;

    /**
     * @brief The extended information of the processor. This field is filled
     *   only when CPU_V2_EXTENDED_TOPOLOGY is set in parameter ProcessorNumber.
     */
    EXTENDED_PROCESSOR_INFORMATION ExtendedInformation;

} EFI_PROCESSOR_INFORMATION;

#endif
