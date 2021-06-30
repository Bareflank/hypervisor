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
#include <intrinsic_vmxon.h>
#include <platform.h>
#include <state_save_t.h>
#include <types.h>

/** @brief defines the VME CR4 field */
#define CR4_VMXE (((uint64_t)1) << ((uint64_t)13))

/** @brief defines the MSR address for VMX information */
#define MSR_IA32_VMX_BASIC ((uint32_t)0x480)
/** @brief defines the VMX revision ID */
#define VMX_BASIC_REVISION_ID ((uint64_t)0x000000007FFFFFFF)

/** @brief defines the MSR address for VMX information */
#define MSR_IA32_FEATURE_CONTROL ((uint32_t)0x3A)

/**
 * <!-- description -->
 *   @brief Enables Hardware Virtualization Extensions
 *
 * <!-- inputs/outputs -->
 *   @param state the mk state save containing the HVE page
 *   @return Returns 0 on success
 */
int64_t
enable_hve(struct state_save_t *const state)
{
    uint64_t cr4;
    uint64_t phys;
    uint64_t revision_id;

    cr4 = intrinsic_scr4();
    if ((cr4 & CR4_VMXE) != 0) {
        bferror("VT-x is already running. Is another hypervisor running?");
        return LOADER_FAILURE;
    }

    phys = platform_virt_to_phys(state->hve_page);
    if (((uint64_t)0) == phys) {
        bferror("platform_virt_to_phys failed");
        return LOADER_FAILURE;
    }

    revision_id = intrinsic_rdmsr(MSR_IA32_VMX_BASIC) & VMX_BASIC_REVISION_ID;
    ((uint32_t *)state->hve_page)[0] = ((uint32_t)revision_id);

    intrinsic_lcr4(cr4 | CR4_VMXE);

    if (intrinsic_vmxon(&phys)) {
        bferror("intrinsic_vmxon failed");
        goto intrinsic_vmxon_failure;
    }

    return LOADER_SUCCESS;

intrinsic_vmxon_failure:

    intrinsic_lcr4(intrinsic_scr4() & ~CR4_VMXE);
    return LOADER_FAILURE;
}
