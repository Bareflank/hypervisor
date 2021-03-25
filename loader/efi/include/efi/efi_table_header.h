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

#ifndef EFI_TABLE_HEADER_H
#define EFI_TABLE_HEADER_H

#include <efi/efi_types.h>

/**
 * @struct EFI_TABLE_HEADER
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_TABLE_HEADER struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct
{
    /**
     * @brief A 64-bit signature that identifies the type of table that
     *   follows. Unique signatures have been generated for the EFI System
     *   Table, the EFI Boot Services Table, and the EFI Runtime Services
     *   Table.
     */
    UINT64 Signature;

    /**
     * @brief The revision of the EFI Specification to which this table
     *   conforms. The upper 16 bits of this field contain the major revision
     *   value, and the lower 16 bits contain the minor revision value. The
     *   minor revision values are binary coded decimals and are limited to
     *   the range of 00..99.
     *
     *   When printed or displayed UEFI spec revision is referred as (Major
     *   revision).(Minor revision upper decimal).(Minor revision lower
     *   decimal) or (Major revision).(Minor revision upper decimal) in case
     *   Minor revision lower decimal is set to 0. For example:
     *
     *   A specification with the revision value ((2<<16) | (30)) would be
     *   referred as 2.3;
     *
     *   A specification with the revision value ((2<<16) | (31)) would be
     *   referred as 2.3.1
     */
    UINT32 Revision;

    /**
     * @brief The size, in bytes, of the entire table including the
     *   EFI_TABLE_HEADER
     */
    UINT32 HeaderSize;

    /**
     * @brief The 32-bit CRC for the entire table. This value is computed by
     *   setting this field to 0, and computing the 32-bit CRC for HeaderSize
     *   bytes.
     */
    UINT32 CRC32;

    /**
     * @brief Reserved field that must be set to 0.
     */
    UINT32 Reserved;

} EFI_TABLE_HEADER;

#endif
