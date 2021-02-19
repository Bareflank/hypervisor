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

    // clang-format off

    BFINFO("mk args on cpu #%u:\n", cpu);
    BFINFO(" - online_pps: 0x%04x\n", args->online_pps);
    BFINFO(" - mk_state: 0x%016" PRIx64 "\n", (uint64_t)args->mk_state);
    BFINFO(" - root_vp_state: 0x%016" PRIx64 "\n", (uint64_t)args->root_vp_state);
    BFINFO(" - debug_ring: 0x%016" PRIx64 "\n", (uint64_t)args->debug_ring);
    BFINFO(" - mk_elf_file.addr: 0x%016" PRIx64 "\n",(uint64_t)args->mk_elf_file.addr);
    BFINFO(" - mk_elf_file.size: 0x%016" PRIx64 "\n", args->mk_elf_file.size);

    for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_EXTENSIONS; ++idx) {
        if (((void *)0) != args->ext_elf_files[idx].addr) {
            BFINFO(" - ext_elf_files[%" PRIu64 "].addr: 0x%016" PRIx64 "\n",
                idx, (uint64_t)args->ext_elf_files[idx].addr);
            BFINFO(" - ext_elf_files[%" PRIu64 "].size: 0x%016" PRIx64 "\n",
                idx, args->ext_elf_files[idx].size);
        }
    }

    BFINFO(" - rpt: 0x%016" PRIx64 "\n", (uint64_t)args->rpt);
    BFINFO(" - rpt_phys: 0x%016" PRIx64 "\n", args->rpt_phys);
    BFINFO(" - page_pool.addr: 0x%016" PRIx64 "\n", (uint64_t)args->page_pool.addr);
    BFINFO(" - page_pool.size: 0x%016" PRIx64 "\n", args->page_pool.size);
    BFINFO(" - huge_pool.addr: 0x%016" PRIx64 "\n", (uint64_t)args->huge_pool.addr);
    BFINFO(" - huge_pool.size: 0x%016" PRIx64 "\n", args->huge_pool.size);
}
