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

#include <entry.h>
#include <vcpu/vcpu_manager.h>

int
init_vmm_trampoline(int arg)
{
    (void) arg;

    if (g_vcm->init(0) != vcpu_manager_error::success)
        return ENTRY_ERROR_VMM_INIT_FAILED;

    return ENTRY_SUCCESS;
}

int
start_vmm_trampoline(int arg)
{
    (void) arg;

    if (g_vcm->start(0) != vcpu_manager_error::success)
        return ENTRY_ERROR_VMM_START_FAILED;

    return ENTRY_SUCCESS;
}

int
stop_vmm_trampoline(int arg)
{
    (void) arg;

    if (g_vcm->stop(0) != vcpu_manager_error::success)
        return ENTRY_ERROR_VMM_STOP_FAILED;

    return ENTRY_SUCCESS;
}

extern "C" int
init_vmm(int arg)
{
    (void) arg;

    return init_vmm_trampoline(arg);
}

extern "C" int
start_vmm(int arg)
{
    (void) arg;

    return start_vmm_trampoline(arg);
}

extern "C" int
stop_vmm(int arg)
{
    (void) arg;

    return stop_vmm_trampoline(arg);
}

// -----------------------------------------------------------------------------
// REMOVE ME
// -----------------------------------------------------------------------------
//
// The following should be removed once we fully support global constructors

extern "C" void
__cxa_pure_virtual(void)
{
}

extern "C" int
atexit(void (*func)(void)) throw ()
{
    (void) func;

    return 0;
}
