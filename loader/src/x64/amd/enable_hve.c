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
#include <intrinsic_rdmsr.h>
#include <intrinsic_wrmsr.h>
#include <platform.h>
#include <state_save_t.h>
#include <types.h>

/** @brief defines the MSR_IA32_EFER MSR  */
#define MSR_IA32_EFER ((uint32_t)0xC0000080)
/** @brief defines the EFER_SVME MSR field */
#define EFER_SVME (((uint64_t)1) << ((uint64_t)12))

/** @brief defines the MSR_VM_HSAVE_PA MSR  */
#define MSR_IA32_VM_HSAVE_PA ((uint32_t)0xC0010117)

/**
 * <!-- description -->
 *   @brief Enables AMD SVE
 *
 * <!-- inputs/outputs -->
 *   @param state the mk state save containing the HVE page
 *   @return Returns 0 on success
 */
int64_t
enable_hve(struct state_save_t *const state)
{
    uint64_t phys;
    uint64_t efer;

    phys = platform_virt_to_phys(state->hve_page);
    if (((uint64_t)0) == phys) {
        BFERROR("platform_virt_to_phys failed\n");
        return LOADER_FAILURE;
    }

    efer = intrinsic_rdmsr(MSR_IA32_EFER);
    if ((efer & EFER_SVME) != 0) {
        BFERROR("SVM is already running. Is another hypervisor running?\n");
        return LOADER_FAILURE;
    }

    intrinsic_wrmsr(MSR_IA32_EFER, efer | EFER_SVME);
    intrinsic_wrmsr(MSR_IA32_VM_HSAVE_PA, phys);

    return LOADER_SUCCESS;
}
