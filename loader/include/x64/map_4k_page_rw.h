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

#ifndef MAP_4K_PAGE_RW_H
#define MAP_4K_PAGE_RW_H

#include <pml4t_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function maps a 4k page given a physical address into a
 *     provided root page table at the provided virtual address. If the page
 *     is already mapped, this function will fail. Also note that this memory
 *     might need to allocate memory to expand the size of the page table
 *     tree. If this function fails, it will NOT attempt to cleanup memory
 *     that it allocated. Instead, you should free the provided root page
 *     table as a whole on error, or once it is no longer needed. Finally,
 *     this function will map using read/write access permissions.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to map phys to
 *   @param phys the physical address to map
 *   @param pml4t the root page table to place the resulting map
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t map_4k_page_rw(void const *const virt, uint64_t const phys, struct pml4t_t *const pml4t);

#endif
