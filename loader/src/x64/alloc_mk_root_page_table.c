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
#include <flush_cache.h>
#include <map_4k_page_rw.h>
#include <platform.h>
#include <pml4t_t.h>
#include <root_page_table_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function allocates the root page table
 *
 * <!-- inputs/outputs -->
 *   @param rpt where to return the resulting root page table
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t
alloc_mk_root_page_table(root_page_table_t **const rpt)
{
    uint64_t i;

    *rpt = (root_page_table_t *)platform_alloc(sizeof(root_page_table_t));
    if (((void *)0) == *rpt) {
        bferror("platform_alloc failed");
        return LOADER_FAILURE;
    }

    for (i = 0; i < LOADER_NUM_PML4T_ENTRIES; ++i) {
        flush_cache(&((*rpt)->entires[i]));
    }

    if (map_4k_page_rw(*rpt, ((uint64_t)0), *rpt)) {
        bferror("map_4k_page_rw failed");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
