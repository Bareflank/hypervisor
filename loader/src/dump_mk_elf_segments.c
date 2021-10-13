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
#include <dump_mk_elf_segments.h>
#include <elf_segment_t.h>
#include <platform.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided array of mk ELF segments
 *
 * <!-- inputs/outputs -->
 *   @param segments the array of mk ELF segments to output
 */
void
dump_mk_elf_segments(struct elf_segment_t const *const segments) NOEXCEPT
{
    uint64_t mut_i;
    platform_expects(NULLPTR != segments);

    for (mut_i = ((uint64_t)0); mut_i < HYPERVISOR_MAX_SEGMENTS; ++mut_i) {
        if (NULLPTR != segments[mut_i].addr) {
            bfdebug_d32("mk elf segment", (uint32_t)mut_i);
            bfdebug_ptr(" - addr", segments[mut_i].addr);
            bfdebug_x64(" - size", segments[mut_i].size);
            bfdebug_x64(" - virt", segments[mut_i].virt);
            bfdebug_x32(" - flgs", segments[mut_i].flags);
        }
        else {
            bf_touch();
        }
    }
}
