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

#include <string.h>
#include <vmm_entry.h>

#include <std/iostream>
#include <debug_ring/debug_ring.h>
#include <memory_manager/memory_manager.h>

// =============================================================================
// Entry Functions
// =============================================================================

void *
start_vmm(void *arg)
{
    vmm_resources_t *vmmr = (vmm_resources_t *)arg;

    if (arg == 0)
        return VMM_ERROR_INVALID_ARG;

    // if (debug_ring::instance().init(vmmr->drr) != debug_ring_error::success)
    //     return VMM_ERROR_DEBUG_RING_INIT_FAILED;

    // std::cout.init();

    // if (memory_manager::instance().init() != memory_manager_error::success)
    //     return VMM_ERROR_MEMORY_MANAGER_FAILED;

    // for (auto i = 0; i < MAX_PAGES; i++)
    // {
    //     auto pg = page(vmmr->pages[i]);

    //     if (memory_manager::instance().add_page(pg) != memory_manager_error::success)
    //         return VMM_ERROR_INVALID_PAGES;
    // }

    return 0;
}

void *
stop_vmm(void *arg)
{
    if (arg != 0)
        return VMM_ERROR_INVALID_ARG;

    return 0;
}

// =============================================================================
// C++ Support Functions
// =============================================================================

void operator delete(void *ptr)
{
}

void operator delete[](void *p)
{
}

extern "C"
{

    void __cxa_pure_virtual()
    {
    }

    int atexit(void (*func)(void))
    {
        return 0;
    }

}
