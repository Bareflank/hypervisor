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
#include <free_ext_elf_files.h>
#include <free_mk_elf_file.h>
#include <free_mk_elf_segments.h>
#include <free_mk_huge_pool.h>
#include <free_mk_page_pool.h>
#include <free_mk_root_page_table.h>
#include <g_ext_elf_files.h>
#include <g_mk_elf_file.h>
#include <g_mk_elf_segments.h>
#include <g_mk_huge_pool.h>
#include <g_mk_page_pool.h>
#include <g_mk_root_page_table.h>
#include <g_vmm_status.h>
#include <platform.h>
#include <stop_vmm_per_cpu.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Stops and frees the VMM. This function is used by both the
 *     stop_vmm() function and the start_vmm() function (in the event a
 *     perviously started VMM has not yet been stopped). The guts of actually
 *     stopping the VMM is defined here. There stop_vmm() function simply
 *     validates user inputs and then calls this function.
 */
void
stop_and_free_the_vmm(void)
{
    if (VMM_STATUS_STOPPED == g_vmm_status) {
        return;
    }

    if (VMM_STATUS_CORRUPT == g_vmm_status) {
        bferror("Unable to stop, previous VMM stopped in a corrupt state");
        return;
    }

    if (platform_on_each_cpu(stop_vmm_per_cpu, PLATFORM_REVERSE)) {
        bferror("stop_vmm_per_cpu failed");
        goto stop_vmm_per_cpu_failed;
    }

    free_mk_huge_pool(&g_mk_huge_pool);
    free_mk_page_pool(&g_mk_page_pool);
    free_mk_elf_segments(g_mk_elf_segments);
    free_ext_elf_files(g_ext_elf_files);
    free_mk_elf_file(&g_mk_elf_file);
    free_mk_root_page_table(&g_mk_root_page_table);

    g_vmm_status = VMM_STATUS_STOPPED;
    return;

stop_vmm_per_cpu_failed:

    g_vmm_status = VMM_STATUS_CORRUPT;
    return;
}
