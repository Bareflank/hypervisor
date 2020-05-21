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

#include <loader.h>
#include <loader_arch.h>
#include <loader_debug.h>
#include <loader_global_resources.h>
#include <loader_platform.h>
#include <loader_types.h>

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
    if (cpu >= MAX_NUMBER_OF_ROOT_VCPUS) {
        BFERROR("cpu index %u is out of range\n", cpu);
        return FAILURE;
    }

    if (VMM_STARTED == g_contexts[cpu].started) {
        BFALERT("cpu %u was never stopped. stopping now\n", cpu);
        if (stop_vmm_per_cpu(cpu) != 0) {
            BFERROR("stop_vmm_per_cpu failed\n");
            return FAILURE;
        }
    }

    if (platform_memset(&g_contexts[cpu], 0, sizeof(g_contexts[cpu]))) {
        BFERROR("platform_memset failed\n");
        return FAILURE;
    }

    if (platform_memset(&g_arch_contexts[cpu], 0, sizeof(g_arch_contexts[cpu]))) {
        BFERROR("platform_memset failed\n");
        return FAILURE;
    }

    if (arch_start_vmm_per_cpu(cpu, &g_contexts[cpu], &g_arch_contexts[cpu])) {
        BFERROR("arch_start_vmm_per_cpu failed\n");
        arch_stop_vmm_per_cpu(cpu, &g_contexts[cpu], &g_arch_contexts[cpu]);
        return FAILURE;
    }

    g_contexts[cpu].started = VMM_STARTED;
    return 0;
}
