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

#include <alloc_pdpt.h>
#include <alloc_pdt.h>
#include <alloc_pt.h>
#include <bfelf/bfelf_elf64_phdr_t.h>
#include <debug.h>
#include <map_4k_page.h>
#include <pdpt_t.h>
#include <pdpto.h>
#include <pdt_t.h>
#include <pdto.h>
#include <platform.h>
#include <pml4to.h>
#include <pt_t.h>
#include <pte_t.h>
#include <pto.h>
#include <root_page_table_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function maps a 4k page given a physical address into a
 *     provided root page table at the provided virtual address. If the page
 *     is already mapped, this function will fail. Also note that this memory
 *     might need to allocate memory to expand the size of the page table
 *     tree. If this function fails, it will NOT attempt to cleanup memory
 *     that it allocated. Instead, you should free the provided root page
 *     table as a whole on error, or once it is no longer needed.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to map phys to
 *   @param phys the physical address to map
 *   @param flags the p_flags field from the segment associated with this page
 *   @param pmut_rpt the root page table to place the resulting map
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
NODISCARD int64_t
map_4k_page(
    uint64_t const virt,
    uint64_t const phys,
    uint32_t const flags,
    root_page_table_t *const pmut_rpt) NOEXCEPT
{
    uint64_t mut_phys = phys;

    int32_t mut_added_pdpt = 0;
    int32_t mut_added_pdt = 0;

    struct pdpt_t *pmut_mut_pdpt = NULLPTR;
    struct pdt_t *pmut_mut_pdt = NULLPTR;
    struct pt_t *pmut_mut_pt = NULLPTR;
    struct pte_t *pmut_mut_pte = NULLPTR;

    if (((uint64_t)0) == virt) {
        bferror_x64("virt is NULL", virt);
        return LOADER_FAILURE;
    }

    if (((uint64_t)0) != (virt & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1)))) {
        bferror_x64("virt is not page aligned", virt);
        return LOADER_FAILURE;
    }

    if (((uint64_t)0) == mut_phys) {
        mut_phys = platform_virt_to_phys((void *)virt);
        if (((uint64_t)0) == mut_phys) {
            bferror("platform_virt_to_phys failed");
            return LOADER_FAILURE;
        }

        bf_touch();
    }
    else {
        bf_touch();
    }

    if (((uint64_t)0) != (mut_phys & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1)))) {
        bferror_x64("phys is not page aligned", mut_phys);
        return LOADER_FAILURE;
    }

    pmut_mut_pdpt = pmut_rpt->tables[pml4to(virt)];
    if (NULLPTR == pmut_mut_pdpt) {
        pmut_mut_pdpt = alloc_pdpt(pmut_rpt, virt);
        if (NULLPTR == pmut_mut_pdpt) {
            bferror_x64("failed to allocate pdpt for virt", virt);
            return LOADER_FAILURE;
        }

        mut_added_pdpt = 1;
    }
    else {
        bf_touch();
    }

    pmut_mut_pdt = pmut_mut_pdpt->tables[pdpto(virt)];
    if (NULLPTR == pmut_mut_pdt) {
        pmut_mut_pdt = alloc_pdt(pmut_mut_pdpt, virt);
        if (NULLPTR == pmut_mut_pdt) {
            bferror_x64("failed to allocate pdt for virt", virt);
            goto alloc_pdt_failed;
        }

        mut_added_pdt = 1;
    }
    else {
        bf_touch();
    }

    pmut_mut_pt = pmut_mut_pdt->tables[pdto(virt)];
    if (NULLPTR == pmut_mut_pt) {
        pmut_mut_pt = alloc_pt(pmut_mut_pdt, virt);
        if (NULLPTR == pmut_mut_pt) {
            bferror_x64("failed to allocate pt for virt", virt);
            goto alloc_pt_failed;
        }

        bf_touch();
    }
    else {
        bf_touch();
    }

    pmut_mut_pte = &pmut_mut_pt->entires[pto(virt)];
    if (((uint64_t)0) != (uint64_t)pmut_mut_pte->p) {
        bferror_x64("virt already mapped", virt);
        return LOADER_FAILURE;
    }

    pmut_mut_pte->phys = (mut_phys >> HYPERVISOR_PAGE_SHIFT);
    pmut_mut_pte->p = ((uint64_t)1);
    pmut_mut_pte->g = ((uint64_t)1);

    if (0U != (flags & bfelf_pf_w)) {
        pmut_mut_pte->rw = ((uint64_t)1);
    }
    else {
        bf_touch();
    }

    if (0U == (flags & bfelf_pf_x)) {
        pmut_mut_pte->nx = ((uint64_t)1);
    }
    else {
        bf_touch();
    }

    return LOADER_SUCCESS;

    /**
 * NOTE:
 * - You might notice that we do not cleanup the PT on error, and we
 *   return without cleaning up if we hit the already exists case.
 *   This is because if the page already exists, it means that we
 *   never allocated any tables, so there is nothing to clean up (you
 *   cannot have a page that is already mapped if you had to add a
 *   table to get there)
 *
 * - Because of this, we don't clean up the PTs because if it has an
 *   error there is no PTs to clean up, and if it succeeds there
 *   are no more possible errors.
 */

alloc_pt_failed:

    if (mut_added_pdt) {
        platform_free(pmut_mut_pdt, sizeof(struct pdt_t));
        pmut_mut_pdpt->tables[pdpto(virt)] = NULLPTR;
    }
    else {
        bf_touch();
    }

alloc_pdt_failed:

    if (mut_added_pdpt) {
        platform_free(pmut_mut_pdpt, sizeof(struct pdpt_t));
        pmut_rpt->tables[pml4to(virt)] = NULLPTR;
    }
    else {
        bf_touch();
    }

    return LOADER_FAILURE;
}
