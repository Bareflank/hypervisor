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

/**
 * <!-- description -->
 *   @brief This function releases the context structure. This is run
 *     once the hypervisor is stopped, ensuring that all of the resources
 *     the hypervisor needs remain pinned until the hypevisor is complete.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, FAILURE otherwise.
 */
int64_t
arch_release_context(struct loader_arch_context_t *context)
{
    platform_free(context->tmp_host_vmcb_virt, sizeof(struct vmcb_t));
    context->tmp_host_vmcb_virt = NULL;
    context->tmp_host_vmcb_phys = 0;

    platform_free(context->tmp_guest_vmcb_virt, sizeof(struct vmcb_t));
    context->tmp_guest_vmcb_virt = NULL;
    context->tmp_guest_vmcb_phys = 0;

    return 0;
}
