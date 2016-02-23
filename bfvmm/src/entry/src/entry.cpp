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

#include <debug.h>
#include <entry.h>
#include <constants.h>
#include <vcpu/vcpu_manager.h>
#include <memory_manager/memory_manager.h>

int64_t
init_vmm_trampoline(int64_t arg)
{
    (void) arg;

    if (g_vcm->init(0) != vcpu_manager_error::success)
        return ENTRY_ERROR_VMM_INIT_FAILED;

    return ENTRY_SUCCESS;
}

int64_t
start_vmm_trampoline(int64_t arg)
{
    (void) arg;

    if (g_vcm->start(0) != vcpu_manager_error::success)
        return ENTRY_ERROR_VMM_START_FAILED;

    bfdebug << "started:" << bfendl;
    bfdebug << "    - free blocks: " << g_mm->free_blocks() << " out of: "
            << MAX_BLOCKS << " = " << g_mm->free_blocks() * 100 / MAX_BLOCKS
            << "%" << bfendl;

    return ENTRY_SUCCESS;
}

int64_t
stop_vmm_trampoline(int64_t arg)
{
    (void) arg;

    if (g_vcm->stop(0) != vcpu_manager_error::success)
        return ENTRY_ERROR_VMM_STOP_FAILED;

    bfdebug << "stopped:" << bfendl;
    bfdebug << "    - free blocks: " << g_mm->free_blocks() << " out of: "
            << MAX_BLOCKS << " = " << g_mm->free_blocks() * 100 / MAX_BLOCKS
            << "%" << bfendl;

    return ENTRY_SUCCESS;
}

extern "C" int64_t
init_vmm(int64_t arg)
{
    (void) arg;

    return init_vmm_trampoline(arg);
}

extern "C" int64_t
start_vmm(int64_t arg)
{
    (void) arg;

    return start_vmm_trampoline(arg);
}

extern "C" int64_t
stop_vmm(int64_t arg)
{
    (void) arg;

    return stop_vmm_trampoline(arg);
}
