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

#ifndef EFI_DEVICE_PATH_PROTOCOL_H
#define EFI_DEVICE_PATH_PROTOCOL_H

#include <efi/efi_types.h>

/** @brief Defined in EFI_DEVICE_PATH_PROTOCOL */
#define EFI_DEVICE_PATH_PROTOCOL_LENGTH_SIZE 2

/**
 * @struct EFI_DEVICE_PATH_PROTOCOL
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_DEVICE_PATH_PROTOCOL struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct _EFI_DEVICE_PATH_PROTOCOL
{
    /**
     * @brief Defined in EFI_DEVICE_PATH_PROTOCOL
     */
    UINT8 Type;

    /**
     * @brief Defined in EFI_DEVICE_PATH_PROTOCOL
     */
    UINT8 SubType;

    /**
     * @brief Defined in EFI_DEVICE_PATH_PROTOCOL
     */
    UINT8 Length[EFI_DEVICE_PATH_PROTOCOL_LENGTH_SIZE];

} EFI_DEVICE_PATH_PROTOCOL;

#endif
