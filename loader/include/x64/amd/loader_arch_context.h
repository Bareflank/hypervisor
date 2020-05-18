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

#ifndef LOADER_ARCH_CONTEXT_H
#define LOADER_ARCH_CONTEXT_H

#include <loader_types.h>
#include <tmp_vmcb.h>

/**
 * @class loader_arch_context_t
 *
 * <!-- description -->
 *   @brief Stores per-cpu resources that are needed by the
 *     arch specific code.
 */
struct loader_arch_context_t
{
    /** @brief tmp_ will be removed once the kernel is in place */
    struct vmcb_t *tmp_host_vmcb_virt;
    /** @brief tmp_ will be removed once the kernel is in place */
    uintptr_t tmp_host_vmcb_phys;

    /** @brief tmp_ will be removed once the kernel is in place */
    struct vmcb_t *tmp_guest_vmcb_virt;
    /** @brief tmp_ will be removed once the kernel is in place */
    uintptr_t tmp_guest_vmcb_phys;
};

#endif
