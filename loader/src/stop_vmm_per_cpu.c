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
#include <free_mk_args.h>
#include <free_mk_stack.h>
#include <free_mk_state.h>
#include <free_root_vp_state.h>
#include <g_mut_cpu_status.h>
#include <g_mut_mk_args.h>
#include <g_mut_mk_stack.h>
#include <g_mut_mk_state.h>
#include <g_mut_root_vp_state.h>
#include <mk_args_t.h>
#include <send_command_report_off.h>
#include <send_command_stop.h>
#include <span_t.h>
#include <state_save_t.h>
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
NODISCARD int64_t
stop_vmm_per_cpu(uint32_t const cpu) NOEXCEPT
{
    if (((uint64_t)cpu) >= HYPERVISOR_MAX_PPS) {
        bferror("cpu out of range");
        return LOADER_FAILURE;
    }

    if (CPU_STATUS_CORRUPT == g_mut_cpu_status[cpu]) {
        bferror_d32("Unable to stop, previous CPU stopped in a corrupt state", cpu);
        return LOADER_FAILURE;
    }

    if (CPU_STATUS_RUNNING == g_mut_cpu_status[cpu]) {
        send_command_report_off();

        if (send_command_stop()) {
            bferror("send_command_stop failed");
            g_mut_cpu_status[cpu] = CPU_STATUS_CORRUPT;
            return LOADER_FAILURE;
        }

        bf_touch();
    }
    else {
        bf_touch();
    }

    free_mk_args(&g_mut_mk_args[cpu]);
    free_root_vp_state(&g_mut_root_vp_state[cpu]);
    free_mk_state(&g_mut_mk_state[cpu]);
    free_mk_stack(&g_mut_mk_stack[cpu]);

    g_mut_cpu_status[cpu] = CPU_STATUS_STOPPED;
    return LOADER_SUCCESS;
}
