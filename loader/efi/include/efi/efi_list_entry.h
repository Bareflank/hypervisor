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

#ifndef EFI_LIST_ENTRY_H
#define EFI_LIST_ENTRY_H

/** @brief prototype for _EFI_LIST_ENTRY */
struct _EFI_LIST_ENTRY;

/** @brief prototype for EFI_LIST_ENTRY */
typedef struct _EFI_LIST_ENTRY EFI_LIST_ENTRY;

/**
 * <!-- description -->
 *   @brief Defines the layout of the EFI_LIST_ENTRY struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Shell_2_2.pdf
 */
typedef struct _EFI_LIST_ENTRY
{
    /**
     * @brief n/a
     */
    struct _EFI_LIST_ENTRY *Flink;

    /**
     * @brief n/a
     */
    struct _EFI_LIST_ENTRY *Blink;

} EFI_LIST_ENTRY;

#endif
