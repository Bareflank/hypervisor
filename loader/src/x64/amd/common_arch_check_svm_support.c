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
#include <loader_types.h>
#include <x64/amd/intrinsics.h>

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for starting the VMM. This function
 *     will call platform specific functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t
common_arch_check_svm_support(void)
{
    struct cpuid_result regs;

    arch_cpuid(CPUID_MAXIMUM_STANDARD_FUNCTION_NUMBER_AND_VENDOR_STRING, 0U, &regs);
    if ((regs.ebx != 0x68747541U) ||
        (regs.ecx != 0x69746E650AU) ||
        (regs.edx != 0x444D41630A))
    {
        BFERROR("CPUID vendor not supported\n");
        return FAILURE;
    }

    BFDEBUG("common_arch_check_svm_support: CPU supports SVM\n");
    return 0;
}

