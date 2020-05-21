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
    /** @brief store the architecture's page size */
    uint64_t page_size;
    /** @brief stores number of physical address bits supported */
    uint32_t physical_address_bits;

    /** @brief stores the virtual address of the host vmcb */
    struct vmcb_t *host_vmcb_virt;
    /** @brief stores the physical address of the host vmcb */
    uintptr_t host_vmcb_phys;

    /** @brief stores the virtual address of the guest vmcb */
    struct vmcb_t *guest_vmcb_virt;
    /** @brief stores the physical address of the guest vmcb */
    uintptr_t guest_vmcb_phys;

    /** @brief stores the virtual address of the host state save */
    void *host_state_save_virt;
    /** @brief stores the physical address of the host state save */
    uintptr_t host_state_save_phys;
};

#endif
