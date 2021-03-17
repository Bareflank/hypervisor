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
#include <mk_args_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided mk args.
 *
 * <!-- inputs/outputs -->
 *   @param args the mk args to output
 *   @param cpu the CPU that this mk args belongs to
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
void
dump_mk_args(struct mk_args_t *const args, uint32_t const cpu)
{
    uint64_t idx;

    bfdebug_d32("mk args on cpu", cpu);
    bfdebug_x16(" - online_pps", args->online_pps);
    bfdebug_ptr(" - mk_state", args->mk_state);
    bfdebug_ptr(" - root_vp_state", args->root_vp_state);
    bfdebug_ptr(" - debug_ring", args->debug_ring);
    bfdebug_ptr(" - mk_elf_file.addr", args->mk_elf_file.addr);
    bfdebug_x64(" - mk_elf_file.size", args->mk_elf_file.size);

    for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_EXTENSIONS; ++idx) {
        if (((void *)0) != args->ext_elf_files[idx].addr) {
            bfdebug_ptr(" - ext_elf_files.addr", args->ext_elf_files[idx].addr);
            bfdebug_x64(" - ext_elf_files.size", args->ext_elf_files[idx].size);
        }
    }

    bfdebug_ptr(" - rpt", args->rpt);
    bfdebug_x64(" - rpt_phys", args->rpt_phys);
    bfdebug_ptr(" - page_pool.addr", args->page_pool.addr);
    bfdebug_x64(" - page_pool.size", args->page_pool.size);
    bfdebug_ptr(" - huge_pool.addr", args->huge_pool.addr);
    bfdebug_x64(" - huge_pool.size", args->huge_pool.size);
}
