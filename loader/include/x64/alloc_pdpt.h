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

#ifndef ALLOC_PDPT_H
#define ALLOC_PDPT_H

#include <pdpt_t.h>
#include <pml4t_t.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief Given a pml4t and a virtual address, this function allocates a
     *     pdpt and adds it to the pml4t. If a pdpt has already been allocated,
     *     this function will fail.
     *
     * <!-- inputs/outputs -->
     *   @param pmut_pml4t the pml4t to add the newly allocated pdpt to
     *   @param virt the virtual address to get the PML4 offset from.
     *   @return a pointer to the newly allocated pdpt on success, NULLPTR otherwise.
     */
    NODISCARD struct pdpt_t *
    alloc_pdpt(struct pml4t_t *const pmut_pml4t, uint64_t const virt) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
