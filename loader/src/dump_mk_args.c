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

#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <debug.h>
#include <dump_mk_args.h>
#include <mk_args_t.h>
#include <mutable_span_t.h>
#include <platform.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided mk args.
 *
 * <!-- inputs/outputs -->
 *   @param args the mk args to output
 *   @param cpu the CPU that this mk args belongs to
 */
void
dump_mk_args(struct mk_args_t const *const args, uint32_t const cpu) NOEXCEPT
{
    uint64_t mut_i;
    platform_expects(NULLPTR != args);

    bfdebug_d32("mk args on cpu", cpu);
    bfdebug_x16(" - online_pps", args->online_pps);
    bfdebug_ptr(" - mk_state", args->mk_state);
    bfdebug_ptr(" - root_vp_state", args->root_vp_state);
    bfdebug_ptr(" - debug_ring", args->debug_ring);
    bfdebug_ptr(" - mk_elf_file", args->mk_elf_file);

    for (mut_i = ((uint64_t)0); mut_i < HYPERVISOR_MAX_EXTENSIONS; ++mut_i) {
        if (NULLPTR != args->ext_elf_files[mut_i]) {
            bfdebug_ptr(" - ext_elf_files", args->ext_elf_files[mut_i]);
        }
        else {
            bf_touch();
        }
    }

    bfdebug_ptr(" - rpt", args->rpt);
    bfdebug_x64(" - rpt_phys", args->rpt_phys);
    bfdebug_ptr(" - page_pool.addr", args->page_pool.addr);
    bfdebug_x64(" - page_pool.size", args->page_pool.size);
    bfdebug_ptr(" - huge_pool.addr", args->huge_pool.addr);
    bfdebug_x64(" - huge_pool.size", args->huge_pool.size);
}
