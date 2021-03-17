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

#ifndef EFI_CPU_PHYSICAL_LOCATION2_H
#define EFI_CPU_PHYSICAL_LOCATION2_H

/**
 * @struct EFI_CPU_PHYSICAL_LOCATION2
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_CPU_PHYSICAL_LOCATION2 struct:
 *     https://uefi.org/sites/default/files/resources/PI_Spec_1_7_A_final_May1.pdf
 */
typedef struct
{
    /**
     * @brief Zero-based physical package number that identifies the cartridge
     *   of the processor.
     */
    UINT32 Package;

    /**
     * @brief Zero-based physical module number within package of the processor.
     */
    UINT32 Module;

    /**
     * @brief Zero-based physical tile number within module of the processor.
     */
    UINT32 Tile;

    /**
     * @brief Zero-based physical die number within tile of the processor.
     */
    UINT32 Die;

    /**
     * @brief Zero-based physical core number within die of the processor.
     */
    UINT32 Core;

    /**
     * @brief Zero-based logical thread number within core of the processor.
     */
    UINT32 Thread;

} EFI_CPU_PHYSICAL_LOCATION2;

#endif
