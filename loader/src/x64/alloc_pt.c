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
#include <pdt_t.h>
#include <pdte_t.h>
#include <pdto.h>
#include <platform.h>
#include <pt_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Given a pdt and a virtual address, this function allocates a
 *     pt and adds it to the pdt. If a pt has already been allocated,
 *     this function will fail.
 *
 * <!-- inputs/outputs -->
 *   @param pdt the pdt to add the newly allocated pt to
 *   @param virt the virtual address to get the PDT offset from.
 *   @return a pointer to the newly allocated pt on success, ((void *)0) otherwise.
 */
struct pt_t *
alloc_pt(struct pdt_t *const pdt, uint64_t const virt)
{
    uint64_t i;
    uint64_t phys;
    struct pt_t *pt;
    struct pdte_t *pdte;

    pdte = &pdt->entires[pdto(virt)];
    if (pdte->p != ((uint64_t)0)) {
        bferror_x64("pt already present", virt);
        return ((void *)0);
    }

    pt = (struct pt_t *)platform_alloc(sizeof(struct pt_t));
    if (((void *)0) == pt) {
        bferror("platform_alloc failed");
        goto platform_alloc_pt_failed;
    }

    for (i = 0; i < LOADER_NUM_PT_ENTRIES; ++i) {
        flush_cache(&(pt->entires[i]));
    }

    phys = platform_virt_to_phys(pt);
    if (((uint64_t)0) == phys) {
        bferror("platform_virt_to_phys_pt failed");
        goto platform_virt_to_phys_pt_failed;
    }

    pdt->tables[pdto(virt)] = pt;
    pdte->phys = (phys >> HYPERVISOR_PAGE_SHIFT);
    pdte->p = ((uint64_t)1);
    pdte->rw = ((uint64_t)1);

    flush_cache(pdte);
    return pt;

platform_virt_to_phys_pt_failed:

    platform_free(pt, sizeof(struct pt_t));
platform_alloc_pt_failed:

    return ((void *)0);
}
