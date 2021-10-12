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

#ifndef EFI_FILE_INFO_H
#define EFI_FILE_INFO_H

#include <efi/efi_time.h>
#include <efi/efi_types.h>

/** @brief defines the GUID for EFI_FILE_INFO */
#define EFI_FILE_INFO_ID                                                                           \
    {                                                                                              \
        0x09576e92, 0x6d3f, 0x11d2,                                                                \
        {                                                                                          \
            0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b                                         \
        }                                                                                          \
    }

/**
 * <!-- description -->
 *   @brief Defines the layout of the EFI_FILE_INFO struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct
{
    /**
     * @brief Size of the EFI_FILE_INFO structure, including the
     *   Null-terminated FileName string.
     */
    UINT64 Size;

    /**
     * @brief The size of the file in bytes.
     */
    UINT64 FileSize;

    /**
     * @brief The amount of physical space the file consumes on the file
     *   system volume.
     */
    UINT64 PhysicalSize;

    /**
     * @brief The time the file was created.
     */
    EFI_TIME CreateTime;

    /**
     * @brief The time when the file was last accessed.
     */
    EFI_TIME LastAccessTime;

    /**
     * @brief The time when the file’s contents were last modified.
     */
    EFI_TIME ModificationTime;

    /**
     * @brief The attribute bits for the file.
     */
    UINT64 Attribute;

    /**
     * @brief The Null-terminated name of the file. For a root directory, the
     *   name is an empty string.
     */
    CHAR16 FileName[];

} EFI_FILE_INFO;

#endif
