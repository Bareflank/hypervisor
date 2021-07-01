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

#ifndef GET_MK_HUGE_POOL_HEAD_H
#define GET_MK_HUGE_POOL_HEAD_H

#include <mutable_span_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function gets the addr of the microkernel's huge pool
 *
 * <!-- inputs/outputs -->
 *   @param huge_pool a pointer to a mutable_span_t that stores the huge pool
 *   @param base_virt provide the base virtual address that the huge pool
 *     was mapped to.
 *   @param addr where to store the resulting addr of the huge pool
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t get_mk_huge_pool_addr(
    struct mutable_span_t const *const huge_pool, uint64_t const base_virt, uint8_t **const addr);

#endif
