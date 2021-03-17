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
#include <map_4k_page_rw.h>
#include <mutable_span_t.h>
#include <platform.h>
#include <pml4t_t.h>

/**
 * <!-- description -->
 *   @brief This function maps the microkernel's huge pool into the
 *     microkernel's root page tables.
 *
 * <!-- inputs/outputs -->
 *   @param huge_pool a pointer to a mutable_span_t that stores the huge pool
 *     being mapped
 *   @param pml4t the root page table to map the huge pool into
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
map_mk_huge_pool(struct mutable_span_t const *const huge_pool, struct pml4t_t *const pml4t)
{
    uint64_t off;
    uint64_t base_phys;
    uint64_t const base_virt = HYPERVISOR_DIRECT_MAP_ADDR;

    base_phys = platform_virt_to_phys(huge_pool->addr);
    if (((uint64_t)0) == base_phys) {
        bferror("platform_virt_to_phys failed");
        return LOADER_FAILURE;
    }

    for (off = ((uint64_t)0); off < huge_pool->size; off += HYPERVISOR_PAGE_SIZE) {

        uint64_t phys = platform_virt_to_phys(huge_pool->addr + off);
        if (((uint64_t)0) == phys) {
            bferror("platform_virt_to_phys failed");
            return LOADER_FAILURE;
        }

        if (phys != base_phys + off) {
            bferror("huge pool is not physically contiguous");
            return LOADER_FAILURE;
        }

        if (map_4k_page_rw((void *)(base_virt + phys), phys, pml4t)) {
            bferror("map_4k_page_rw failed");
            return LOADER_FAILURE;
        }
    }

    return LOADER_SUCCESS;
}
