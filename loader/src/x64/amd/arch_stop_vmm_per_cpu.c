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
#include <loader_intrinsics.h>
#include <loader_platform.h>
#include <loader_types.h>

/**
 * <!-- description -->
 *   @brief This resets the host state save area back to 0. This way, the
 *     old value is not cached in the MSR which might cause problems later.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, FAILURE otherwise.
 */
void
reset_host_state_save(void)
{
    arch_wrmsr(MSR_VM_HSAVE_PA, 0);
}

/**
 * <!-- description -->
 *   @brief Disable Secure Virtual Machine support. This turns off the
 *     ability to use the VMRUN, VMLOAD and VMSAVE instructions, as well
 *     as some other support instructions like stgi and clgi.
 */
void
disable_svm(void)
{
    arch_wrmsr(MSR_EFER, arch_rdmsr(MSR_EFER) & (~MSR_EFER_SVME));
}

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for stoping the VMM. This function
 *     will call platform specific functions as needed. Unlike stop_vmm,
 *     this function is called on each CPU.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the id of the cpu to stop
 *   @param context the common context for this cpu
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
arch_stop_vmm_per_cpu(                   // --
    uint32_t const cpu,                  // --
    struct loader_context_t *context,    // --
    struct loader_arch_context_t *arch_context)
{
    if (NULL == context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    BFDEBUG("stopping hypervisor on cpu: %u\n", cpu);

    reset_host_state_save();

    platform_free(arch_context->host_vmcb_virt, sizeof(struct vmcb_t));
    arch_context->host_vmcb_virt = NULL;
    arch_context->host_vmcb_phys = 0;

    platform_free(arch_context->guest_vmcb_virt, sizeof(struct vmcb_t));
    arch_context->guest_vmcb_virt = NULL;
    arch_context->guest_vmcb_phys = 0;

    platform_free(arch_context->host_state_save_virt, arch_context->page_size);
    arch_context->host_state_save_virt = NULL;
    arch_context->host_state_save_phys = 0;

    disable_svm();

    return 0;
}
