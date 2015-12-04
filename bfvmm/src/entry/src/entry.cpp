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
#include <debug_ring/debug_ring.h>

// =============================================================================
// Global
// =============================================================================

// Since bareflank uses shared libraries for everything, there is no
// initialization function to run the constructor and destructor for globally
// defined classes. Therefore, make sure that all globally defined classes
// don't use a constructor or destructor as these funcions will not be
// executed.

debug_ring g_dr;

// =============================================================================
// Entry Functions
// =============================================================================

void *
start_vmm(void *arg)
{
    vmm_resources_t *vmmr = (vmm_resources_t *)arg;

    if (arg == 0)
        return VMM_ERROR_INVALID_ARG;

    if (g_dr.init(vmmr->drr) != debug_ring_error::success)
        return VMM_ERROR_INVALID_ARG;

    auto msg = "Hello world from the VMM\n";
    g_dr.write(msg, strlen(msg));
    g_dr.write(msg, strlen(msg));

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
}
