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

#include <alloc_l1t.h>
#include <alloc_l2t.h>
#include <alloc_l3t.h>
#include <bfelf/bfelf_elf64_phdr_t.h>
#include <constants.h>
#include <debug.h>
#include <flush_cache.h>
#include <l0t_t.h>
#include <l0to.h>
#include <l1t_t.h>
#include <l1to.h>
#include <l2t_t.h>
#include <l2to.h>
#include <l3t_t.h>
#include <l3te_t.h>
#include <l3to.h>
#include <map_4k_page.h>
#include <platform.h>
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
 *   @param rpt the root page table to place the resulting map
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t
map_4k_page(uint64_t const virt, uint64_t phys, uint32_t const flags, root_page_table_t *const rpt)
{
    struct l1t_t *l1t = ((void *)0);
    struct l2t_t *l2t = ((void *)0);
    struct l3t_t *l3t = ((void *)0);
    struct l3te_t *l3te = ((void *)0);

    if (((uint64_t)0) == virt) {
        bferror_x64("virt is NULL", virt);
        return LOADER_FAILURE;
    }

    if (((uint64_t)0) == phys) {
        phys = platform_virt_to_phys((void *)virt);
        if (((uint64_t)0) == phys) {
            bferror("platform_virt_to_phys failed");
            return LOADER_FAILURE;
        }
    }

    if ((virt & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1))) != ((uint64_t)0)) {
        bferror_x64("virt is not page aligned", virt);
        return LOADER_FAILURE;
    }

    if ((phys & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1))) != ((uint64_t)0)) {
        bferror_x64("phys is not page aligned", phys);
        return LOADER_FAILURE;
    }

    l1t = rpt->tables[l0to(virt)];
    if (((void *)0) == l1t) {
        l1t = alloc_l1t(rpt, virt);
    }

    l2t = l1t->tables[l1to(virt)];
    if (((void *)0) == l2t) {
        l2t = alloc_l2t(l1t, virt);
    }

    l3t = l2t->tables[l2to(virt)];
    if (((void *)0) == l3t) {
        l3t = alloc_l3t(l2t, virt);
    }

    l3te = &l3t->entires[l3to(virt)];
    if (l3te->p != ((uint64_t)0)) {
        bferror_x64("virt already mapped", virt);
        return LOADER_FAILURE;
    }

    l3te->phys = (phys >> HYPERVISOR_PAGE_SHIFT);
    l3te->p = ((uint64_t)0x1);
    l3te->page = ((uint64_t)0x1);
    l3te->af = ((uint64_t)0x1);

    if ((flags & bfelf_pf_w) == 0U) {
        l3te->ap = ((uint64_t)0x2);
    }

    if ((flags & bfelf_pf_x) == 0U) {
        l3te->xn = ((uint64_t)0x1);
    }

    if ((flags & bfelf_pf_nc) == 0U) {
        l3te->attr_indx = ((uint64_t)0x3);
        l3te->sh = ((uint64_t)0x3);
    }

    flush_cache(l3te);
    return LOADER_SUCCESS;
}
