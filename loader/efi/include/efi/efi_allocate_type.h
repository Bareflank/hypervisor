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

#ifndef EFI_ALLOCATE_TYPE_H
#define EFI_ALLOCATE_TYPE_H

/**
 * @struct EFI_ALLOCATE_TYPE
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_ALLOCATE_TYPE struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef enum
{
    /**
     * @brief Allocation requests of Type AllocateAnyPages allocate any
     *   available range of pages that satisfies the request. On input, the
     *   address pointed to by Memory is ignored.
     */
    AllocateAnyPages,

    /**
     * @brief Allocation requests of Type AllocateMaxAddress allocate any
     *   available range of pages whose uppermost address is less than or equal
     *   to the address pointed to by Memory on input.
     */
    AllocateMaxAddress,

    /**
     * @brief Allocation requests of Type AllocateAddress allocate pages at
     *   the address pointed to by Memory on input.
     */
    AllocateAddress,

    /**
     * @brief The end of the enum
     */
    MaxAllocateType

} EFI_ALLOCATE_TYPE;

#endif
