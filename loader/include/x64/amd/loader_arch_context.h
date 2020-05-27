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

#include <vmcb_t.h>
#include <state_save_t.h>
#include <loader_types.h>

#pragma pack(push, 1)

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
    uintptr_t page_size;    // 0x00
    /** @brief stores number of physical address bits supported */
    uintptr_t physical_address_bits;    // 0x08

    /** @brief stores a pointer to the stack the host will use */
    void *host_stack;    // 0x10
    /** @brief stores the size of the host's stack */
    uintptr_t host_stack_size;    // 0x18

    /** @brief stores the virtual address of the host vmcb */
    struct vmcb_t *host_vmcb;    // 0x20
    /** @brief stores the physical address of the host vmcb */
    uintptr_t host_vmcb_phys;    // 0x28

    /** @brief stores the virtual address of the guest vmcb */
    struct vmcb_t *guest_vmcb;    // 0x30
    /** @brief stores the physical address of the guest vmcb */
    uintptr_t guest_vmcb_phys;    // 0x38

    /** @brief stores the virtual address of the host state save */
    struct state_save_t *host_save;    // 0x40
    /** @brief stores the physical address of the host state save */
    uintptr_t host_save_phys;    // 0x48

    /** @brief stores the virtual address of the guest state save */
    struct state_save_t *guest_save;    // 0x50
    /** @brief stores the physical address of the guest state save */
    uintptr_t guest_save_phys;    // 0x58

    /** @brief stores the virtual address of the host xsave area */
    void *host_xsave;    // 0x60
    /** @brief stores the physical address of the host xsave area */
    uintptr_t host_xsave_phys;    // 0x68

    /** @brief stores the virtual address of the guest xsave area */
    void *guest_xsave;    // 0x70
    /** @brief stores the physical address of the guest xsave area */
    uintptr_t guest_xsave_phys;    // 0x78

    /** @brief stores the address of the exit handler */
    void *exit_handler;    // 0x80
};

_Static_assert(sizeof(struct loader_arch_context_t) == 0x88, "");

#pragma pack(pop)

#endif
