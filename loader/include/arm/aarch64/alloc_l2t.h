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

#ifndef ALLOC_L2T_H
#define ALLOC_L2T_H

#include <l1t_t.h>
#include <l2t_t.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief Given a l1t_t and a virtual address, this function allocates a
     *     l2t_t and adds it to the l1t_t. If an l2t_t has already been allocated,
     *     this function will fail.
     *
     * <!-- inputs/outputs -->
     *   @param l1 the l1t_t to add the newly allocated l2t_t to
     *   @param virt the virtual address to get the l1t_t offset from.
     *   @return a pointer to the newly allocated l2t_t on success, NULLPTR
     *     otherwise.
     */
    NODISCARD struct l2t_t *alloc_l2t(struct l1t_t *const l1, uint64_t const virt);

#ifdef __cplusplus
}
#endif

#endif
