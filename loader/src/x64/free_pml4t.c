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
#include <free_pdpt.h>
#include <pdpt_t.h>
#include <platform.h>
#include <pml4t_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Given a pml4t_t, this function will free any previously allocated
 *     tables.
 *
 * <!-- inputs/outputs -->
 *   @param pml4t the pml4t_t to free
 */
void
free_pml4t(struct pml4t_t *const pml4t)
{
    uint64_t idx;

    for (idx = ((uint64_t)0); idx < LOADER_NUM_PML4T_ENTRIES; ++idx) {
        struct pdpt_t *const pdpt = pml4t->tables[idx];
        if (NULL != pdpt) {
            free_pdpt(pdpt);
            platform_free(pdpt, sizeof(struct pdpt_t));
        }
    }
}
