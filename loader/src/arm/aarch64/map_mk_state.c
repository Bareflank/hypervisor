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

#include <bfelf/bfelf_elf64_phdr_t.h>
#include <constants.h>
#include <debug.h>
#include <l3te_t.h>
#include <map_4k_page.h>
#include <map_4k_page_rw.h>
#include <platform.h>
#include <root_page_table_t.h>
#include <state_save_t.h>

/**
 * <!-- description -->
 *   @brief This function maps the microkernel's state into the microkernel's
 *     root page tables.
 *
 * <!-- inputs/outputs -->
 *   @param state a pointer to a state_save_t that stores the state
 *     being mapped
 *   @param rpt the root page table to map the state into
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t
map_mk_state(struct state_save_t const *const state, root_page_table_t *const rpt)
{
    uint64_t uart0_addr = 0;
    bfelf_elf64_word const rwnc = bfelf_pf_w | bfelf_pf_r | bfelf_pf_nc;

    if (map_4k_page_rw(state, ((uint64_t)0), rpt)) {
        bferror("map_4k_page_rw failed");
        return LOADER_FAILURE;
    }

    uart0_addr |= ((uint64_t)HYPERVISOR_SERIAL_PORTH) << ((uint64_t)16);
    uart0_addr |= ((uint64_t)HYPERVISOR_SERIAL_PORTL);

    if (map_4k_page(uart0_addr, ((uint64_t)0), rwnc, rpt)) {
        bferror("map_4k_page failed");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
