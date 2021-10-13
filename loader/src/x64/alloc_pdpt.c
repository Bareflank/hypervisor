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

#include <debug.h>
#include <pdpt_t.h>
#include <platform.h>
#include <pml4t_t.h>
#include <pml4te_t.h>
#include <pml4to.h>
#include <types.h>

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
alloc_pdpt(struct pml4t_t *const pmut_pml4t, uint64_t const virt) NOEXCEPT
{
    uint64_t mut_phys = ((uint64_t)0);
    struct pdpt_t *pmut_mut_pdpt = NULLPTR;
    struct pml4te_t *pmut_mut_pml4te = NULLPTR;

    pmut_mut_pml4te = &pmut_pml4t->entires[pml4to(virt)];
    if (((uint64_t)0) != (uint64_t)pmut_mut_pml4te->p) {
        bferror_x64("pdpt already present", virt);
        return NULLPTR;
    }

    pmut_mut_pdpt = (struct pdpt_t *)platform_alloc(sizeof(struct pdpt_t));
    if (NULLPTR == pmut_mut_pdpt) {
        bferror("platform_alloc failed");
        goto platform_alloc_pdpt_failed;
    }

    mut_phys = platform_virt_to_phys(pmut_mut_pdpt);
    if (((uint64_t)0) == mut_phys) {
        bferror("platform_virt_to_phys_pdpt failed");
        goto platform_virt_to_phys_pdpt_failed;
    }

    pmut_pml4t->tables[pml4to(virt)] = pmut_mut_pdpt;
    pmut_mut_pml4te->phys = (mut_phys >> HYPERVISOR_PAGE_SHIFT);
    pmut_mut_pml4te->p = ((uint64_t)1);
    pmut_mut_pml4te->rw = ((uint64_t)1);

    return pmut_mut_pdpt;

platform_virt_to_phys_pdpt_failed:

    platform_free(pmut_mut_pdpt, sizeof(struct pdpt_t));
platform_alloc_pdpt_failed:

    return NULLPTR;
}
