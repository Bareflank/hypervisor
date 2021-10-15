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
 *   @param pmut_pdt the pdt to add the newly allocated pt to
 *   @param virt the virtual address to get the PDT offset from.
 *   @return a pointer to the newly allocated pt on success, NULLPTR otherwise.
 */
NODISCARD struct pt_t *
alloc_pt(struct pdt_t *const pmut_pdt, uint64_t const virt) NOEXCEPT
{
    uint64_t mut_phys = ((uint64_t)0);
    struct pt_t *pmut_mut_pt = NULLPTR;
    struct pdte_t *pmut_mut_pdte = NULLPTR;

    pmut_mut_pdte = &pmut_pdt->entires[pdto(virt)];
    if (((uint64_t)0) != (uint64_t)pmut_mut_pdte->p) {
        bferror_x64("pt already present", virt);
        return NULLPTR;
    }

    pmut_mut_pt = (struct pt_t *)platform_alloc(sizeof(struct pt_t));
    if (NULLPTR == pmut_mut_pt) {
        bferror("platform_alloc failed");
        goto platform_alloc_pt_failed;
    }

    mut_phys = platform_virt_to_phys(pmut_mut_pt);
    if (((uint64_t)0) == mut_phys) {
        bferror("platform_virt_to_phys_pt failed");
        goto platform_virt_to_phys_pt_failed;
    }

    pmut_pdt->tables[pdto(virt)] = pmut_mut_pt;
    pmut_mut_pdte->phys = (mut_phys >> HYPERVISOR_PAGE_SHIFT);
    pmut_mut_pdte->p = ((uint64_t)1);
    pmut_mut_pdte->rw = ((uint64_t)1);

    return pmut_mut_pt;

platform_virt_to_phys_pt_failed:

    platform_free(pmut_mut_pt, sizeof(struct pt_t));
platform_alloc_pt_failed:

    return NULLPTR;
}
