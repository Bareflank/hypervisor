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

#ifndef EFI_LOCATE_SEARCH_TYPE_H
#define EFI_LOCATE_SEARCH_TYPE_H

/**
 * <!-- description -->
 *   @brief Defines the layout of the EFI_LOCATE_SEARCH_TYPE struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef enum
{
    /**
     * @brief Protocol and SearchKey are ignored and the function returns an
     *   array of every handle in the system.
     */
    AllHandles,

    /**
     * @brief SearchKey supplies the Registration value returned by
     *   EFI_BOOT_SERVICES.RegisterProtocolNotify(). The function returns
     *   the next handle that is new for the registration. Only one handle is
     *   returned at a time, starting with the first, and the caller must loop
     *   until no more handles are returned. Protocol is ignored for this
     *   search type.
     */
    ByRegisterNotify,

    /**
     * @brief All handles that support Protocol are returned. SearchKey is
     *   ignored for this search type.
     */
    ByProtocol

} EFI_LOCATE_SEARCH_TYPE;

#endif
