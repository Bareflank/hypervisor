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
#include <bfelf_elf64_phdr_t.h>
#include <constants.h>
#include <debug.h>
#include <pdpt_t.h>
#include <pdpto.h>
#include <pdt_t.h>
#include <pdto.h>
#include <platform.h>
#include <pml4t_t.h>
#include <pml4to.h>
#include <pt_t.h>
#include <pte_t.h>
#include <pto.h>
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
 *   @param pml4t the root page table to place the resulting map
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
map_4k_page(
    uint64_t const virt,
    uint64_t phys,
    uint32_t const flags,
    struct pml4t_t *const pml4t)
{
    struct pdpt_t *pdpt;
    struct pdt_t *pdt;
    struct pt_t *pt;
    struct pte_t *pte;

    if ((virt & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1))) != ((uint64_t)0)) {
        BFERROR("virt is not page aligned: 0x%" PRIx64 "\n", virt);
        return LOADER_FAILURE;
    }

    if ((phys & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1))) != ((uint64_t)0)) {
        BFERROR("phys is not page aligned: 0x%" PRIx64 "\n", phys);
        return LOADER_FAILURE;
    }

    if (((uint64_t)0) == phys) {
        phys = platform_virt_to_phys((void *)virt);
        if (((uint64_t)0) == phys) {
            BFERROR("platform_virt_to_phys failed\n");
            return LOADER_FAILURE;
        }
    }

    pdpt = pml4t->tables[pml4to(virt)];
    if (NULL == pdpt) {
        pdpt = alloc_pdpt(pml4t, virt);
    }

    pdt = pdpt->tables[pdpto(virt)];
    if (NULL == pdt) {
        pdt = alloc_pdt(pdpt, virt);
    }

    pt = pdt->tables[pdto(virt)];
    if (NULL == pt) {
        pt = alloc_pt(pdt, virt);
    }

    pte = &pt->entires[pto(virt)];
    if (pte->p != ((uint64_t)0)) {
        BFERROR("page already mapped: 0x%" PRIx64 "\n", virt);
        return LOADER_FAILURE;
    }

    pte->phys = (phys >> HYPERVISOR_PAGE_SHIFT);
    pte->p = ((uint64_t)1);
    pte->g = ((uint64_t)1);

    if ((flags & bfelf_pf_w) != 0U) {
        pte->rw = ((uint64_t)1);
    }

    if ((flags & bfelf_pf_x) == 0U) {
        pte->nx = ((uint64_t)1);
    }

    return LOADER_SUCCESS;
}
