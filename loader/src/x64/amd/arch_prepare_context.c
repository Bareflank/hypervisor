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
#include <loader_debug.h>
#include <loader_platform.h>
#include <loader_types.h>

int64_t
prepare_host_vmcb(struct loader_arch_context_t *context)
{
    uintptr_t virt;
    uintptr_t phys;

    virt = (uintptr_t)platform_alloc(sizeof(struct vmcb_t));
    if (0 == virt) {
        BFERROR("failed to allocate host vmcb\n");
        return FAILURE;
    }

    phys = platform_virt_to_phys(virt);
    if (0 == phys) {
        BFERROR("failed to get the host vmcb's physical address\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if ((virt & (sizeof(struct vmcb_t) - 1)) != 0) {
        BFERROR("host vmcb virt is not properly aligned\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if ((phys & (sizeof(struct vmcb_t) - 1)) != 0) {
        BFERROR("host vmcb phys is not properly aligned\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    context->tmp_host_vmcb_virt = (struct vmcb_t *)virt;
    context->tmp_host_vmcb_phys = phys;

    return 0;
}

int64_t
prepare_guest_vmcb(struct loader_arch_context_t *context)
{
    uintptr_t virt;
    uintptr_t phys;

    virt = (uintptr_t)platform_alloc(sizeof(struct vmcb_t));
    if (0 == virt) {
        BFERROR("failed to allocate guest vmcb\n");
        return FAILURE;
    }

    phys = platform_virt_to_phys(virt);
    if (0 == phys) {
        BFERROR("failed to get the guest vmcb's physical address\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if ((virt & (sizeof(struct vmcb_t) - 1)) != 0) {
        BFERROR("guest vmcb virt is not properly aligned\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if ((phys & (sizeof(struct vmcb_t) - 1)) != 0) {
        BFERROR("guest vmcb phys is not properly aligned\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    context->tmp_guest_vmcb_virt = (struct vmcb_t *)virt;
    context->tmp_guest_vmcb_phys = phys;

    return 0;
}

/**
 * <!-- description -->
 *   @brief This function prepares the context structure. The context
 *     structure stores all of the pre-vcpu state that the loader is
 *     responsible for setting up. This context structure will be shared
 *     with the kernel which will use it to virtualize the root vCPUs.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, FAILURE otherwise.
 */
int64_t
arch_prepare_context(struct loader_arch_context_t *context)
{
    if (prepare_host_vmcb(context)) {
        BFERROR("prepare_host_vmcb failed\n");
        return FAILURE;
    }

    if (prepare_guest_vmcb(context)) {
        BFERROR("prepare_guest_vmcb failed\n");
        return FAILURE;
    }

    return 0;
}
