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
#include <debug_ring_t.h>
#include <map_4k_page_rw.h>
#include <root_page_table_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function maps the microkernel's debug_ring into the
 *     microkernel's root page tables.
 *
 * <!-- inputs/outputs -->
 *   @param debug_ring a pointer to a debug_ring_t that stores the debug_ring
 *     being mapped
 *   @param pmut_rpt the root page table to map the debug_ring into
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
NODISCARD int64_t
map_mk_debug_ring(
    struct debug_ring_t const *const debug_ring, root_page_table_t *const pmut_rpt) NOEXCEPT
{
    uint64_t mut_i;

    for (mut_i = ((uint64_t)0); mut_i < HYPERVISOR_DEBUG_RING_SIZE; mut_i += HYPERVISOR_PAGE_SIZE) {
        if (map_4k_page_rw(((uint8_t *)debug_ring) + mut_i, ((uint64_t)0), pmut_rpt)) {
            bferror("map_4k_page_rw failed");
            return LOADER_FAILURE;
        }

        bf_touch();
    }

    return LOADER_SUCCESS;
}
