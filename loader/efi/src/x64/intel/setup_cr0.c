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
#include <intrinsic_lcr0.h>
#include <intrinsic_rdmsr.h>
#include <intrinsic_scr0.h>
#include <types.h>

/** @brief defines the MSR_VMX_CR0_FIXED0 MSR  */
#define MSR_VMX_CR0_FIXED0 ((uint32_t)0x00000486)
/** @brief defines the MSR_VMX_CR0_FIXED1 MSR  */
#define MSR_VMX_CR0_FIXED1 ((uint32_t)0x00000487)

/**
 * <!-- description -->
 *   @brief Ensures that CR0 is set up properly.
 */
void
setup_cr0(void)
{
    uint64_t cr0 = intrinsic_scr0();
    uint64_t ia32_vmx_cr0_fixed0 = intrinsic_rdmsr(MSR_VMX_CR0_FIXED0);
    uint64_t ia32_vmx_cr0_fixed1 = intrinsic_rdmsr(MSR_VMX_CR0_FIXED1);

    cr0 |= ia32_vmx_cr0_fixed0;
    cr0 &= ia32_vmx_cr0_fixed1;

    intrinsic_lcr0(cr0);
}
