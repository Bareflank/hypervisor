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

#include <constants.h>
#include <debug.h>
#include <flush_cache.h>
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
 *   @param pml4t the pml4t to add the newly allocated pdpt to
 *   @param virt the virtual address to get the PML4 offset from.
 *   @return a pointer to the newly allocated pdpt on success, ((void *)0) otherwise.
 */
struct pdpt_t *
alloc_pdpt(struct pml4t_t *const pml4t, uint64_t const virt)
{
    uint64_t i;
    uint64_t phys;
    struct pdpt_t *pdpt;
    struct pml4te_t *pml4te;

    pml4te = &pml4t->entires[pml4to(virt)];
    if (pml4te->p != ((uint64_t)0)) {
        bferror_x64("pdpt already present", virt);
        return ((void *)0);
    }

    pdpt = (struct pdpt_t *)platform_alloc(sizeof(struct pdpt_t));
    if (((void *)0) == pdpt) {
        bferror("platform_alloc failed");
        goto platform_alloc_pdpt_failed;
    }

    for (i = 0; i < LOADER_NUM_PDPT_ENTRIES; ++i) {
        flush_cache(&(pdpt->entires[i]));
    }

    phys = platform_virt_to_phys(pdpt);
    if (((uint64_t)0) == phys) {
        bferror("platform_virt_to_phys_pdpt failed");
        goto platform_virt_to_phys_pdpt_failed;
    }

    pml4t->tables[pml4to(virt)] = pdpt;
    pml4te->phys = (phys >> HYPERVISOR_PAGE_SHIFT);
    pml4te->p = ((uint64_t)1);
    pml4te->rw = ((uint64_t)1);

    flush_cache(pml4te);
    return pdpt;

platform_virt_to_phys_pdpt_failed:

    platform_free(pdpt, sizeof(struct pdpt_t));
platform_alloc_pdpt_failed:

    return ((void *)0);
}
