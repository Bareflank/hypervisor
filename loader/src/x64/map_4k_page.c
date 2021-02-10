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
#include <map_4k_page.h>
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
 *   @brief The microkernel needs to be able to walk its own page tables and
 *     to do that, it expects the that all of the page tables are mapped in
 *     the direct map (allowing the microkernel to look up a virtual address
 *     given a physical address). When the map function maps a virtual address,
 *     it might be required to allocate new page tables. These newly allocated
 *     page tables are recorded and mapped once the map function is complete
 *     using this function.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address of the page table
 *   @param pml4t the root page table to place the resulting map
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
map_4k_page_table(void const *const virt, struct pml4t_t *const pml4t)
{
    uint64_t phys;
    uint64_t const base_virt = HYPERVISOR_DIRECT_MAP_ADDR;
    bfelf_elf64_word const rw = bfelf_pf_w | bfelf_pf_r;

    if (((void *)0) == virt) {
        return LOADER_SUCCESS;
    }

    phys = platform_virt_to_phys(virt);
    if (((uint64_t)0) == phys) {
        BFERROR("platform_virt_to_phys failed\n");
        return LOADER_FAILURE;
    }

    if (map_4k_page(phys + base_virt, phys, rw, pml4t)) {
        BFERROR("map_4k_page failed\n");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

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
    struct pdpt_t *pdpt = ((void *)0);
    struct pdt_t *pdt = ((void *)0);
    struct pt_t *pt = ((void *)0);
    struct pte_t *pte = ((void *)0);

    void *pdpt_to_map = ((void *)0);
    void *pdt_to_map = ((void *)0);
    void *pt_to_map = ((void *)0);

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
    if (((void *)0) == pdpt) {
        pdpt = alloc_pdpt(pml4t, virt);
        pdpt_to_map = pdpt;
    }

    pdt = pdpt->tables[pdpto(virt)];
    if (((void *)0) == pdt) {
        pdt = alloc_pdt(pdpt, virt);
        pdt_to_map = pdt;
    }

    pt = pdt->tables[pdto(virt)];
    if (((void *)0) == pt) {
        pt = alloc_pt(pdt, virt);
        pt_to_map = pt;
    }

    pte = &pt->entires[pto(virt)];
    if (pte->p != ((uint64_t)0)) {
        goto SUCCESS;
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

SUCCESS:

    if (map_4k_page_table(pdpt_to_map, pml4t)) {
        BFERROR("map_4k_page_table failed\n");
        return LOADER_FAILURE;
    }

    if (map_4k_page_table(pdt_to_map, pml4t)) {
        BFERROR("map_4k_page_table failed\n");
        return LOADER_FAILURE;
    }

    if (map_4k_page_table(pt_to_map, pml4t)) {
        BFERROR("map_4k_page_table failed\n");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
