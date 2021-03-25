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

#ifndef MAP_MK_PAGE_POOL_H
#define MAP_MK_PAGE_POOL_H

#include <mutable_span_t.h>
#include <root_page_table_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function maps the microkernel's page pool into the
 *     microkernel's root page tables.
 *
 *   @note Unlike other map functions, this function needs to set up the
 *     direct map. This is because the only part of the direct map the
 *     microkernel needs is the page pool. What this means is each page
 *     is mapped to the direct map base address (virt), with the
 *     physical address added (i.e., to get the physical address of a
 *     page from the page pool, just take it's virtual address and
 *     subtract virt). Then, the first 64 bits of the page store the
 *     address of the next page in the page pool (using the direct map
 *     address). This way, all we need to do is pass virt to the
 *     microkernel, and it will have the HEAD of a linked list of pages
 *     that can be used as a page pool.
 *
 * <!-- inputs/outputs -->
 *   @param page_pool a pointer to a mutable_span_t that stores the page pool
 *     being mapped
 *   @param rpt the root page table to map the page pool into
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
map_mk_page_pool(struct mutable_span_t const *const page_pool, root_page_table_t *const rpt);

#endif
