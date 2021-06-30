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

#include <code_aliases_t.h>
#include <debug.h>
#include <demote.h>
#include <esr.h>
#include <exception_vectors.h>
#include <map_4k_page_rx.h>
#include <platform.h>
#include <promote.h>
#include <root_page_table_t.h>
#include <serial_write_c.h>
#include <serial_write_hex.h>

/**
 * <!-- description -->
 *   @brief This function maps the code aliases into the microkernel's
 *     root page tables. For more information about how this mapping is
 *     performed, please see alloc_and_copy_mk_code_aliases.
 *
 * <!-- inputs/outputs -->
 *   @param a a pointer to a code_aliases_t that stores the aliases
 *     being mapped
 *   @param rpt the root page table to map the code aliases into
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
map_mk_code_aliases(struct code_aliases_t const *const a, root_page_table_t *const rpt)
{
    if (map_4k_page_rx(demote, ((uint64_t)0), rpt)) {
        bferror("map_4k_page_rx failed");
        return LOADER_FAILURE;
    }

    if (map_4k_page_rx(promote, ((uint64_t)0), rpt)) {
        bferror("map_4k_page_rx failed");
        return LOADER_FAILURE;
    }

    if (map_4k_page_rx(esr, ((uint64_t)0), rpt)) {
        bferror("map_4k_page_rx failed");
        return LOADER_FAILURE;
    }

    if (map_4k_page_rx(exception_vectors, ((uint64_t)0), rpt)) {
        bferror("map_4k_page_rx failed");
        return LOADER_FAILURE;
    }

    if (map_4k_page_rx(serial_write_c, ((uint64_t)0), rpt)) {
        bferror("map_4k_page_rx failed");
        return LOADER_FAILURE;
    }

    if (map_4k_page_rx(serial_write_hex, ((uint64_t)0), rpt)) {
        bferror("map_4k_page_rx failed");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
