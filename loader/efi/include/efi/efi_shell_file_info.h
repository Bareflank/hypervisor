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

#ifndef EFI_SHELL_FILE_INFO_H
#define EFI_SHELL_FILE_INFO_H

#include <efi/efi_file_info.h>
#include <efi/efi_list_entry.h>
#include <efi/efi_types.h>

/** @brief n/a */
typedef VOID *SHELL_FILE_HANDLE;

/**
 * @struct EFI_SHELL_FILE_INFO
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_SHELL_FILE_INFO struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Shell_2_2.pdf
 */
typedef struct
{
    /**
     * @brief Points to the next and previous entries in the file list.
     *   If NULL, then no more files.
     */
    EFI_LIST_ENTRY Link;

    /**
     * @brief The status returned when calling OpenFile() for the entry in
     *   the file list.
     */
    EFI_STATUS Status;

    /**
     * @brief Specifies the full name of the file, including the path.
     */
    CONST CHAR16 *FullName;

    /**
     * @brief n/a
     */
    CONST CHAR16 *FileName;

    /**
     * @brief The file handle of the file after it was opened.
     */
    SHELL_FILE_HANDLE Handle;

    /**
     * @brief The file information for the opened file.
     */
    EFI_FILE_INFO *Info;

} EFI_SHELL_FILE_INFO;

#endif
