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
#include <intrinsic_lcr4.h>
#include <intrinsic_rdmsr.h>
#include <intrinsic_scr4.h>
#include <types.h>

/** @brief defines the MSR_VMX_CR4_FIXED0 MSR  */
#define MSR_VMX_CR4_FIXED0 ((uint32_t)0x00000488)
/** @brief defines the MSR_VMX_CR4_FIXED1 MSR  */
#define MSR_VMX_CR4_FIXED1 ((uint32_t)0x00000489)

/** @brief defines the VME CR4 field */
#define CR4_VMXE (((uint64_t)1) << ((uint64_t)13))

/**
 * <!-- description -->
 *   @brief Ensures that CR4 is set up properly.
 */
void
setup_cr4(void)
{
    uint64_t cr4 = intrinsic_scr4();
    uint64_t vmx_cr4_fixed0 = intrinsic_rdmsr(MSR_VMX_CR4_FIXED0);
    uint64_t vmx_cr4_fixed1 = intrinsic_rdmsr(MSR_VMX_CR4_FIXED1);

    cr4 |= vmx_cr4_fixed0;
    cr4 &= vmx_cr4_fixed1;

    intrinsic_lcr4(cr4 & (~CR4_VMXE));
}
