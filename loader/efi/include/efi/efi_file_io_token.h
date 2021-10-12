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

#ifndef EFI_FILE_IO_TOKEN_H
#define EFI_FILE_IO_TOKEN_H

/**
 * <!-- description -->
 *   @brief Defines the layout of the EFI_FILE_IO_TOKEN struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct
{
    /**
     * @brief If Event is NULL, then blocking I/O is performed. If Event is not
     *   NULL and non-blocking I/O is supported, then non-blocking I/O is
     *   performed, and Event will be signaled when the read request is
     *   completed. The caller must be prepared to handle the case where the
     *   callback associated with Event occurs before the original asynchronous
     *   I/O request call returns.
     */
    EFI_EVENT Event;

    /**
     * @brief Defines whether or not the signaled event encountered an error.
     */
    EFI_STATUS Status;

    /**
     * @brief
     *   For OpenEx(): Not Used, ignored
     *
     *   For ReadEx():On input, the size of the Buffer. On output, the
     *   amount of data returned in Buffer. In both cases, the size is measured
     *   in bytes.
     *
     *   For WriteEx(): On input, the size of the Buffer. On output, the
     *   amount of data actually written. In both cases, the size is measured
     *   in bytes.
     *
     *   For FlushEx(): Not used, ignored
     */
    UINTN BufferSize;

    /**
     * @brief
     *   For OpenEx(): Not Used, ignored
     *   For ReadEx(): The buffer into which the data is read
     *   For WriteEx(): The buffer of data to write.
     *   For FlushEx(): Not Used, ignored
     */
    VOID *Buffer;

} EFI_FILE_IO_TOKEN;

#endif
