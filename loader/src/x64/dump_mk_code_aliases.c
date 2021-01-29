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
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided code_aliases_t.
 *
 * <!-- inputs/outputs -->
 *   @param a the code_aliases_t to output
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
void
dump_mk_code_aliases(struct code_aliases_t *const a)
{
    BFINFO("mk code aliases:\n");

    BFINFO(" - demote: 0x%016" PRIx64 "\n", (uint64_t)a->demote);
    BFINFO(" - promote: 0x%016" PRIx64 "\n", (uint64_t)a->promote);
    BFINFO(" - esr_default: 0x%016" PRIx64 "\n", (uint64_t)a->esr_default);
    BFINFO(" - esr_df: 0x%016" PRIx64 "\n", (uint64_t)a->esr_df);
    BFINFO(" - esr_gpf: 0x%016" PRIx64 "\n", (uint64_t)a->esr_gpf);
    BFINFO(" - esr_nmi: 0x%016" PRIx64 "\n", (uint64_t)a->esr_nmi);
    BFINFO(" - esr_pf: 0x%016" PRIx64 "\n", (uint64_t)a->esr_pf);
}
