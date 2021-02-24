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

#define DEBUG_LOADER

#include <alloc_and_copy_mk_state.h>
#include <alloc_and_copy_root_vp_state.h>
#include <alloc_mk_args.h>
#include <alloc_mk_stack.h>
#include <constants.h>
#include <debug.h>
#include <demote.h>
#include <dump_mk_args.h>
#include <dump_mk_stack.h>
#include <dump_mk_state.h>
#include <dump_root_vp_state.h>
#include <free_mk_args.h>
#include <free_mk_stack.h>
#include <free_mk_state.h>
#include <free_root_vp_state.h>
#include <g_ext_elf_files.h>
#include <g_mk_args.h>
#include <g_mk_debug_ring.h>
#include <g_mk_elf_file.h>
#include <g_mk_huge_pool.h>
#include <g_mk_page_pool.h>
#include <g_mk_root_page_table.h>
#include <g_mk_stack.h>
#include <g_mk_state.h>
#include <g_root_vp_state.h>
#include <get_mk_huge_pool_addr.h>
#include <get_mk_page_pool_addr.h>
#include <map_mk_args.h>
#include <map_mk_stack.h>
#include <map_mk_state.h>
#include <map_root_vp_state.h>
#include <platform.h>
#include <send_command_report_on.h>
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
int64_t
start_vmm_per_cpu(uint32_t const cpu)
{
    int64_t ret;
    uint64_t idx;
    uint8_t *addr;
    uint64_t mk_stack_offs;
    uint64_t mk_stack_virt;

    if (((uint64_t)cpu) >= HYPERVISOR_MAX_VPS_PER_VM) {
        BFERROR("cpu out of range\n");
        return LOADER_FAILURE;
    }

    mk_stack_offs = (HYPERVISOR_MK_STACK_SIZE + HYPERVISOR_PAGE_SIZE) * cpu;
    mk_stack_virt = (g_mk_stack_virt + mk_stack_offs);

    if (alloc_mk_stack(0U, &g_mk_stack[cpu])) {
        BFERROR("alloc_mk_stack failed\n");
        goto alloc_mk_stack_failed;
    }

    ret = alloc_and_copy_mk_state(
        g_mk_root_page_table,
        &g_mk_elf_file,
        &g_mk_stack[cpu],
        mk_stack_virt,
        &g_mk_state[cpu]);

    if (ret) {
        BFERROR("alloc_and_copy_mk_state failed\n");
        goto alloc_and_copy_mk_state_failed;
    }

    if (alloc_and_copy_root_vp_state(&g_root_vp_state[cpu])) {
        BFERROR("alloc_and_copy_root_vp_state failed\n");
        goto alloc_and_copy_root_vp_state_failed;
    }

    if (alloc_mk_args(&g_mk_args[cpu])) {
        BFERROR("alloc_mk_args failed\n");
        goto alloc_mk_args_failed;
    }

    if (map_mk_stack(&g_mk_stack[cpu], mk_stack_virt, g_mk_root_page_table)) {
        BFERROR("map_mk_stack failed\n");
        goto map_mk_stack_failed;
    }

    if (map_mk_state(g_mk_state[cpu], g_mk_root_page_table)) {
        BFERROR("map_mk_state failed\n");
        goto map_mk_state_failed;
    }

    if (map_root_vp_state(g_root_vp_state[cpu], g_mk_root_page_table)) {
        BFERROR("map_root_vp_state failed\n");
        goto map_root_vp_state_failed;
    }

    if (map_mk_args(g_mk_args[cpu], g_mk_root_page_table)) {
        BFERROR("map_mk_args failed\n");
        goto map_mk_args_failed;
    }

    g_mk_args[cpu]->pp = ((uint16_t)cpu);
    g_mk_args[cpu]->online_pps = ((uint16_t)platform_num_online_cpus());
    g_mk_args[cpu]->mk_state = g_mk_state[cpu];
    g_mk_args[cpu]->root_vp_state = g_root_vp_state[cpu];
    g_mk_args[cpu]->debug_ring = g_mk_debug_ring;

    g_mk_args[cpu]->mk_elf_file = g_mk_elf_file;
    for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_EXTENSIONS; ++idx) {
        g_mk_args[cpu]->ext_elf_files[idx] = g_ext_elf_files[idx];
    }

    g_mk_args[cpu]->rpt = g_mk_root_page_table;
    g_mk_args[cpu]->rpt_phys = platform_virt_to_phys(g_mk_root_page_table);

    ret = get_mk_page_pool_addr(
        &g_mk_page_pool, HYPERVISOR_DIRECT_MAP_ADDR, &addr);
    if (ret) {
        BFERROR("get_mk_page_pool_addr failed\n");
        goto get_mk_page_pool_addr_failed;
    }

    g_mk_args[cpu]->page_pool.addr = addr;
    g_mk_args[cpu]->page_pool.size = g_mk_page_pool.size;
    g_mk_args[cpu]->page_pool_base_virt = HYPERVISOR_DIRECT_MAP_ADDR;

    ret = get_mk_huge_pool_addr(
        &g_mk_huge_pool, HYPERVISOR_DIRECT_MAP_ADDR, &addr);
    if (ret) {
        BFERROR("get_mk_huge_pool_addr failed\n");
        goto get_mk_huge_pool_addr_failed;
    }

    g_mk_args[cpu]->huge_pool.addr = addr;
    g_mk_args[cpu]->huge_pool.size = g_mk_huge_pool.size;
    g_mk_args[cpu]->huge_pool_base_virt = HYPERVISOR_DIRECT_MAP_ADDR;

#ifdef DEBUG_LOADER
    dump_mk_stack(&g_mk_stack[cpu], cpu);
    dump_mk_state(g_mk_state[cpu], cpu);
    dump_root_vp_state(g_root_vp_state[cpu], cpu);
    dump_mk_args(g_mk_args[cpu], cpu);
#endif

    if (demote(g_mk_args[cpu], g_mk_state[cpu], g_root_vp_state[cpu])) {
        BFERROR("demote failed\n");
        goto demote_failed;
    }

    send_command_report_on();
    return LOADER_SUCCESS;

demote_failed:

get_mk_huge_pool_addr_failed:
get_mk_page_pool_addr_failed:

map_mk_args_failed:
map_root_vp_state_failed:
map_mk_state_failed:
map_mk_stack_failed:

    free_mk_args(&g_mk_args[cpu]);
alloc_mk_args_failed:
    free_root_vp_state(&g_root_vp_state[cpu]);
alloc_and_copy_root_vp_state_failed:
    free_mk_state(&g_mk_state[cpu]);
alloc_and_copy_mk_state_failed:
    free_mk_stack(&g_mk_stack[cpu]);
alloc_mk_stack_failed:

    return LOADER_FAILURE;
}
