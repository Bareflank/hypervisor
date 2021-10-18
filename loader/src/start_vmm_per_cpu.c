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

#include <alloc_and_copy_mk_state.h>
#include <alloc_and_copy_root_vp_state.h>
#include <alloc_mk_args.h>
#include <alloc_mk_stack.h>
#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <check_cpu_configuration.h>
#include <debug.h>
#include <demote.h>
#include <dump_mk_args.h>
#include <dump_mk_stack.h>
#include <dump_mk_state.h>
#include <dump_root_vp_state.h>
#include <elf_file_t.h>
#include <g_mut_cpu_status.h>
#include <g_mut_ext_elf_files.h>
#include <g_mut_mk_args.h>
#include <g_mut_mk_elf_file.h>
#include <g_mut_mk_huge_pool.h>
#include <g_mut_mk_page_pool.h>
#include <g_mut_mk_stack.h>
#include <g_mut_mk_state.h>
#include <g_mut_root_vp_state.h>
#include <g_pmut_mut_mk_debug_ring.h>
#include <g_pmut_mut_mk_root_page_table.h>
#include <get_mk_huge_pool_addr.h>
#include <get_mk_page_pool_addr.h>
#include <map_mk_args.h>
#include <map_mk_stack.h>
#include <map_mk_state.h>
#include <map_root_vp_state.h>
#include <mk_args_t.h>
#include <mutable_span_t.h>
#include <platform.h>
#include <send_command_report_on.h>
#include <span_t.h>
#include <state_save_t.h>
#include <stop_vmm_per_cpu.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms for starting the VMM. This function
 *     will call platform and architecture specific functions as needed.
 *     Unlike start_vmm, this function is called on each CPU.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the id of the cpu to start
 *   @return Returns 0 on success
 */
NODISCARD int64_t
start_vmm_per_cpu(uint32_t const cpu) NOEXCEPT
{
    int64_t mut_ret;
    uint64_t mut_i;
    uint8_t *pmut_mut_addr;
    uint64_t mut_mk_stack_offs;
    uint64_t mut_mk_stack_virt;

    if (((uint64_t)cpu) >= HYPERVISOR_MAX_PPS) {
        bferror("cpu out of range");
        return LOADER_FAILURE;
    }

    if (CPU_STATUS_STOPPED != g_mut_cpu_status[cpu]) {
        bferror("cannot start cpu that is already running/corrupt");
        return LOADER_FAILURE;
    }

    mut_mk_stack_offs = (HYPERVISOR_MK_STACK_SIZE + HYPERVISOR_PAGE_SIZE) * (uint64_t)cpu;
    mut_mk_stack_virt = (HYPERVISOR_MK_STACK_ADDR + mut_mk_stack_offs);

    if (platform_arch_init()) {
        bferror("platform_arch_init failed");
        return LOADER_FAILURE;
    }

    if (check_cpu_configuration()) {
        bferror("check_cpu_configuration failed");
        return LOADER_FAILURE;
    }

    if (alloc_mk_stack(&g_mut_mk_stack[cpu])) {
        bferror("alloc_mk_stack failed");
        goto alloc_mk_stack_failed;
    }

    mut_ret = alloc_and_copy_mk_state(    // --
        g_pmut_mut_mk_root_page_table,    // --
        &g_mut_mk_elf_file,               // --
        &g_mut_mk_stack[cpu],             // --
        mut_mk_stack_virt,                // --
        &g_mut_mk_state[cpu]);

    if (mut_ret) {
        bferror("alloc_and_copy_mk_state failed");
        goto alloc_and_copy_mk_state_failed;
    }

    if (alloc_and_copy_root_vp_state(&g_mut_root_vp_state[cpu])) {
        bferror("alloc_and_copy_root_vp_state failed");
        goto alloc_and_copy_root_vp_state_failed;
    }

    if (alloc_mk_args(&g_mut_mk_args[cpu])) {
        bferror("alloc_mk_args failed");
        goto alloc_mk_args_failed;
    }

    if (map_mk_stack(&g_mut_mk_stack[cpu], mut_mk_stack_virt, g_pmut_mut_mk_root_page_table)) {
        bferror("map_mk_stack failed");
        goto map_mk_stack_failed;
    }

    if (map_mk_state(g_mut_mk_state[cpu], g_pmut_mut_mk_root_page_table)) {
        bferror("map_mk_state failed");
        goto map_mk_state_failed;
    }

    if (map_root_vp_state(g_mut_root_vp_state[cpu], g_pmut_mut_mk_root_page_table)) {
        bferror("map_root_vp_state failed");
        goto map_root_vp_state_failed;
    }

    if (map_mk_args(g_mut_mk_args[cpu], g_pmut_mut_mk_root_page_table)) {
        bferror("map_mk_args failed");
        goto map_mk_args_failed;
    }

    g_mut_mk_args[cpu]->ppid = ((uint16_t)cpu);

    /**
         * NOTE:
         * - We cannot ask for the total number of CPUs on any AP from UEFI, so
         *   we only do this for the BSP, and then use the BSP value to get the
         *   total CPU count from that point on.
         */

    if (((uint32_t)0) == cpu) {
        g_mut_mk_args[cpu]->online_pps = ((uint16_t)platform_num_online_cpus());
    }
    else {
        g_mut_mk_args[cpu]->online_pps = g_mut_mk_args[0]->online_pps;
    }

    g_mut_mk_args[cpu]->mk_state = g_mut_mk_state[cpu];
    g_mut_mk_args[cpu]->root_vp_state = g_mut_root_vp_state[cpu];
    g_mut_mk_args[cpu]->debug_ring = g_pmut_mut_mk_debug_ring;

    g_mut_mk_args[cpu]->mk_elf_file = g_mut_mk_elf_file.addr;
    for (mut_i = ((uint64_t)0); mut_i < HYPERVISOR_MAX_EXTENSIONS; ++mut_i) {
        g_mut_mk_args[cpu]->ext_elf_files[mut_i] = g_mut_ext_elf_files[mut_i].addr;
    }

    g_mut_mk_args[cpu]->rpt = g_pmut_mut_mk_root_page_table;
    g_mut_mk_args[cpu]->rpt_phys = platform_virt_to_phys(g_pmut_mut_mk_root_page_table);

    mut_ret =
        get_mk_page_pool_addr(&g_mut_mk_page_pool, HYPERVISOR_MK_PAGE_POOL_ADDR, &pmut_mut_addr);
    if (mut_ret) {
        bferror("get_mk_page_pool_addr failed");
        goto get_mk_page_pool_addr_failed;
    }

    g_mut_mk_args[cpu]->page_pool.addr = pmut_mut_addr;
    g_mut_mk_args[cpu]->page_pool.size = g_mut_mk_page_pool.size / HYPERVISOR_PAGE_SIZE;

    mut_ret =
        get_mk_huge_pool_addr(&g_mut_mk_huge_pool, HYPERVISOR_MK_HUGE_POOL_ADDR, &pmut_mut_addr);
    if (mut_ret) {
        bferror("get_mk_huge_pool_addr failed");
        goto get_mk_huge_pool_addr_failed;
    }

    g_mut_mk_args[cpu]->huge_pool.addr = pmut_mut_addr;
    g_mut_mk_args[cpu]->huge_pool.size = g_mut_mk_huge_pool.size / HYPERVISOR_PAGE_SIZE;

#ifdef DEBUG_LOADER
    dump_mk_stack(&g_mut_mk_stack[cpu], cpu);
    dump_mk_state(g_mut_mk_state[cpu], cpu);
    dump_root_vp_state(g_mut_root_vp_state[cpu], cpu);
    dump_mk_args(g_mut_mk_args[cpu], cpu);
#endif

    platform_mark_gdt_writable();
    mut_ret = demote(g_mut_mk_args[cpu], g_mut_mk_state[cpu], g_mut_root_vp_state[cpu]);
    platform_mark_gdt_readonly();

    if (mut_ret) {
        bferror("demote failed");
        goto demote_failed;
    }

    send_command_report_on();
    g_mut_cpu_status[cpu] = CPU_STATUS_RUNNING;
    return LOADER_SUCCESS;

demote_failed:
get_mk_huge_pool_addr_failed:
get_mk_page_pool_addr_failed:
map_mk_args_failed:
map_root_vp_state_failed:
map_mk_state_failed:
map_mk_stack_failed:
alloc_mk_args_failed:
alloc_and_copy_root_vp_state_failed:
alloc_and_copy_mk_state_failed:
alloc_mk_stack_failed:

    (void)stop_vmm_per_cpu(cpu);
    return LOADER_FAILURE;
}
