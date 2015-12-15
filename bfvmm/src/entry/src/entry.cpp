//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <vmm_entry.h>

#include <iostream>
#include <entry/entry_factory.h>

#ifndef INIT_IOSTREAM
#define INIT_IOSTREAM()
#endif

// =============================================================================
// Entry Functions
// =============================================================================

void *
start_vmm(void *arg)
{
    auto *vmmr = (vmm_resources_t *)arg;

    if (arg == 0)
        return VMM_ERROR_INVALID_ARG;

    // TODO: At some point, we are going to have to be told what CPU we are
    // starting on, and then get the VCPU for that CPU and initialize it.
    // Since we only support single core for now, we use 0.

    // TODO: There are a lot of train wrecks in the code here that need to be
    //       removed.

    auto vcpu = ef()->get_vcpu_factory()->get_vcpu(0);
    auto memory_manager = ef()->get_memory_manager();

    if (vcpu == 0 || memory_manager == 0)
        return VMM_ERROR_INVALID_ENTRY_FACTORY;

    // -------------------------------------------------------------------------
    // Initialize Debugging

    // if (vcpu->get_debug_ring()->init(vmmr->drr) != debug_ring_error::success)
    //     return VMM_ERROR_INVALID_DRR;

    INIT_IOSTREAM();

    // -------------------------------------------------------------------------
    // Memory Managment

    for (auto i = 0; i < MAX_PAGES; i++)
    {
        auto pg = page(vmmr->pages[i]);

        if (memory_manager->add_page(pg) != memory_manager_error::success)
            return VMM_ERROR_INVALID_PAGES;
    }

    // -------------------------------------------------------------------------
    // Initialize and Start the VMM

    auto vmm = vcpu->get_vmm();
    auto intrinsics = vcpu->get_intrinsics();

    if (vmm->init(intrinsics, memory_manager) != vmm_error::success)
        return VMM_ERROR_VMM_INIT_FAILED;

    if (vmm->start() != vmm_error::success)
        return VMM_ERROR_VMM_START_FAILED;

    // -------------------------------------------------------------------------
    // Initialize and Luanch the VMCS

    auto vmcs = vcpu->get_vmcs();

    if (vmcs->init(intrinsics, memory_manager) != vmcs_error::success)
        return VMM_ERROR_VMM_INIT_FAILED;

    if (vmcs->launch() != vmcs_error::success)
        return VMM_ERROR_VMM_START_FAILED;

    return 0;
}

void *
stop_vmm(void *arg)
{
    if (arg != 0)
        return VMM_ERROR_INVALID_ARG;

    auto vcpu = ef()->get_vcpu_factory()->get_vcpu(0);
    auto memory_manager = ef()->get_memory_manager();

    if (vcpu == 0 || memory_manager == 0)
        return VMM_ERROR_INVALID_ENTRY_FACTORY;

    // -------------------------------------------------------------------------
    // Stop the VMM

    auto vmm = vcpu->get_vmm();

    if (vmm->stop() != vmm_error::success)
        return VMM_ERROR_VMM_STOP_FAILED;

    return 0;
}
