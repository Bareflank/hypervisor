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

#include <loader_debug.h>
#include <loader_intrinsics.h>
#include <loader_types.h>
#include <loader.h>

/**
 * <!-- description -->
 *   @brief This function checks to see if AMD SVM support is available on
 *     the currently running CPU
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t
arch_check_hve_support(void)
{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t msr;

    rax = CPUID_FN0000_0000;
    rbx = 0U;
    rcx = 0U;
    rdx = 0U;
    arch_cpuid(&rax, &rbx, &rcx, &rdx);
    if ((rbx != CPUID_FN0000_0000_EBX_VENDOR_ID) ||    // --
        (rcx != CPUID_FN0000_0000_ECX_VENDOR_ID) ||    // --
        (rdx != CPUID_FN0000_0000_EDX_VENDOR_ID)) {
        BFERROR("CPUID vendor not supported\n");
        return LOADER_FAILURE;
    }

    rax = CPUID_FN8000_0001;
    rbx = 0U;
    rcx = 0U;
    rdx = 0U;
    arch_cpuid(&rax, &rbx, &rcx, &rdx);
    if ((rcx & CPUID_FN8000_0001_ECX_SVM) == 0) {
        BFERROR("This CPU does not support SVM\n");
        return LOADER_FAILURE;
    }

    msr = arch_rdmsr(MSR_VM_CR);
    if ((msr & MSR_VM_CR_SVMDIS) != 0) {
        BFERROR("SVM has been disabled in BIOS. SVM not supported\n");
        return LOADER_FAILURE;
    }

    return 0;
}
