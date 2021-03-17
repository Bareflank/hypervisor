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
    bfdebug("mk code aliases:");
    bfdebug_ptr(" - demote", a->demote);
    bfdebug_ptr(" - promote", a->promote);
    bfdebug_ptr(" - esr_default", a->esr_default);
    bfdebug_ptr(" - esr_df", a->esr_df);
    bfdebug_ptr(" - esr_gpf", a->esr_gpf);
    bfdebug_ptr(" - esr_nmi", a->esr_nmi);
    bfdebug_ptr(" - esr_pf", a->esr_pf);
}
