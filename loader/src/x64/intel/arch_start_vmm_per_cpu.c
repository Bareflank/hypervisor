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

#include <loader_arch.h>
#include <loader_arch_context.h>
#include <loader_context.h>
#include <loader_debug.h>
#include <loader_platform.h>
#include <loader_types.h>

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for starting the VMM. This function
 *     will call platform specific functions as needed. Unlike start_vmm,
 *     this function is called on each CPU.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the id of the cpu to start
 *   @param context the common context for this cpu
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
arch_start_vmm_per_cpu(                  // --
    uint32_t const cpu,                  // --
    struct loader_context_t *context,    // --
    struct loader_arch_context_t *arch_context)
{
    if (arch_check_hvm_support()) {
        BFERROR("arch_check_hvm_support failed\n");
        return FAILURE;
    }

    if (arch_prepare_context(arch_context)) {
        BFERROR("arch_prepare_context failed\n");
        return FAILURE;
    }

    /**
     * TODO: Once the context is loaded with the current CPU state, this
     *       code will need to jump into the C++ code with the ELF binaries
     *       and memory blocks that non-arch code prepared before this
     *       function was called. From there, the kernel will actually
     *       fill out the virtualization related pieces and start the
     *       hypervisor.
     */

    /**
     * NOTE: For now, this code will call from this point on tmp_xxx code
     *       that will do the same thing the kernel will eventually do
     *       which is start the hypervisor. All code that has the "tmp_"
     *       prefix will eventually be removed from the loader
     */

    return 0;
}
