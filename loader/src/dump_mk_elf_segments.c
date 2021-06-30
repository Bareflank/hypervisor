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
#include <elf_segment_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided array of mk ELF segments
 *
 * <!-- inputs/outputs -->
 *   @param segments the array of mk ELF segments to output
 */
void
dump_mk_elf_segments(struct elf_segment_t *const segments)
{
    uint64_t idx;

    if (((void *)0) == segments) {
        bferror("segments is NULL");
        return;
    }

    for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_SEGMENTS; ++idx) {
        if (((void *)0) != segments[idx].addr) {
            bfdebug_d32("mk elf segment", (uint32_t)idx);
            bfdebug_ptr(" - addr", segments[idx].addr);
            bfdebug_x64(" - size", segments[idx].size);
            bfdebug_x64(" - virt", segments[idx].virt);
            bfdebug_x32(" - flgs", segments[idx].flags);
        }
    }
}
