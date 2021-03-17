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

#ifndef EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_H
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_H

#include "efi_file_protocol.h"
#include "efi_status.h"
#include "efi_types.h"

/** @brief defines the GUID for EFI_SIMPLE_FILE_SYSTEM_PROTOCOL */
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID                                                       \
    {                                                                                              \
        0x0964e5b22, 0x6459, 0x11d2,                                                               \
        {                                                                                          \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b                                         \
        }                                                                                          \
    }

/** @brief defines the Revision Number for EFI_SIMPLE_FILE_SYSTEM_PROTOCOL */
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION 0x00010000

/** @brief prototype for _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL */
struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

/** @brief prototype for EFI_SIMPLE_FILE_SYSTEM_PROTOCOL */
typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

/**
 * <!-- description -->
 *   @brief The SetMem() function fills a buffer with a specified value.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the volume to open the root directory of. See the type
 *     EFI_SIMPLE_FILE_SYSTEM_PROTOCOL description.
 *   @param Root A pointer to the location to return the opened file handle for
 *     the root directory. See the type EFI_FILE_PROTOCOL description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME)(
    IN EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This, OUT EFI_FILE_PROTOCOL **Root);

/**
 * @struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
{
    /**
     * @brief The version of the EFI_FILE_PROTOCOL. The version specified by
     *   this specification is 0x00010000. All future revisions must be
     *   backwards compatible. If a future version is not backwards compatible,
     *   it is not the same GUID.
     */
    UINT64 Revision;

    /**
     * @brief Opens the volume for file I/O access. See the OpenVolume()
     *     function description.
     */
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME OpenVolume;

} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

#endif
