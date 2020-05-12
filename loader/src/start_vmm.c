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
 *   @return Returns 0 on success
 */
static int64_t
start_vmm_per_cpu(uint64_t const cpu)
{
    return 0;
}

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms for starting the VMM. This function
 *     will call platform and architecture specific functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t
start_vmm(void)
{
    /**
     * TODO: This function will eventually be given all of the ELF binaries
     *       that make up the kernel and it will need to load each of these
     *       binaries into memory using an ELF loader into a contiguous
     *       block of memory that is given to the arch specific logic as
     *       that code will be responsible for jumping into the actual c++
     *       logic
     *
     * TODO: This code will also need to allocate memory for both a page
     *       pool and a physically contiguous memory block that the kernel
     *       can use as needed. This memory will also need to be given to
     *       the arch code so that it can load the kernel as needed.
     */

    if (platform_on_each_cpu(start_vmm_per_cpu) != 0) {
        return FAILURE;
    }

    return arch_start_vmm();
}
