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
#include <free_mk_args.h>
#include <free_mk_stack.h>
#include <free_mk_state.h>
#include <free_root_vp_state.h>
#include <g_mk_args.h>
#include <g_mk_stack.h>
#include <g_mk_state.h>
#include <g_root_vp_state.h>
#include <send_command_report_off.h>
#include <send_command_stop.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms for stopping the VMM. This function
 *     will call platform and architecture specific functions as needed.
 *     Unlike stop_vmm, this function is called on each CPU.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the id of the cpu to stop
 *   @return Returns 0 on success
 */
int64_t
stop_vmm_per_cpu(uint32_t const cpu)
{
    if (((uint64_t)cpu) >= HYPERVISOR_MAX_VPS_PER_VM) {
        BFERROR("cpu out of range\n");
        return LOADER_FAILURE;
    }

    send_command_report_off();

    if (send_command_stop()) {
        BFERROR("send_command_stop failed\n");
        return LOADER_FAILURE;
    }

    free_mk_args(&g_mk_args[cpu]);
    free_root_vp_state(&g_root_vp_state[cpu]);
    free_mk_state(&g_mk_state[cpu]);
    free_mk_stack(&g_mk_stack[cpu]);

    return LOADER_SUCCESS;
}
