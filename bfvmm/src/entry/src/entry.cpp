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
#include <debug.h>
#include <constants.h>
#include <exception.h>
#include <eh_frame_list.h>
#include <vcpu/vcpu_manager.h>
#include <debug_ring/debug_ring.h>
#include <memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Global
// -----------------------------------------------------------------------------

auto g_eh_frame_list_num = 0ULL;
struct eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

#include <vmxon/vmxon_exceptions_intel_x64.h>

template<typename T> int64_t
catch_all(T func)
{
    int64_t result = ENTRY_ERROR_UNKNOWN;

    try
    {
        result = func();
    }
    catch (bfn::general_exception &ge)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- General Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << "" << ge << bfendl;
    }
    catch (std::exception &e)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Standard Exception Caught            -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << "" << e.what() << bfendl;
    }
    catch (...)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Unknown Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
    }

    return result;
}

void
terminate()
{
    bferror << "FATAL ERROR: terminate called" << bfendl;
    abort();
}

void
new_handler()
{
    bferror << "FATAL ERROR: out of memory" << bfendl;
    std::terminate();
}

// -----------------------------------------------------------------------------
// Entry Points
// -----------------------------------------------------------------------------

extern "C" int64_t
init_vmm(int64_t arg)
{
    (void) arg;

    std::set_terminate(terminate);
    std::set_new_handler(new_handler);

    return catch_all([&]() -> int64_t
    {
        if (g_vcm->init(0) != vcpu_manager_error::success)
            return ENTRY_ERROR_VMM_INIT_FAILED;

        return ENTRY_SUCCESS;
    });
}

extern "C" int64_t
start_vmm(int64_t arg)
{
    (void) arg;

    return catch_all([&]() -> int64_t
    {
        if (g_vcm->start(0) != vcpu_manager_error::success)
            return ENTRY_ERROR_VMM_START_FAILED;

        bfdebug << "started:" << bfendl;
        bfdebug << "    - free blocks: " << g_mm->free_blocks() << bfendl;

        return ENTRY_SUCCESS;
    });
}

extern "C" int64_t
stop_vmm(int64_t arg)
{
    (void) arg;

    return catch_all([&]() -> int64_t
    {
        if (g_vcm->stop(0) != vcpu_manager_error::success)
            return ENTRY_ERROR_VMM_STOP_FAILED;

        bfdebug << "started:" << bfendl;
        bfdebug << "    - free blocks: " << g_mm->free_blocks() << bfendl;

        return ENTRY_SUCCESS;
    });
}

extern "C" int64_t
add_mdl(struct memory_descriptor *mdl, int64_t num)
{
    return catch_all([&]() -> int64_t
    {
        g_mm->add_mdl(mdl, num);
        return ENTRY_SUCCESS;
    });
}

// -----------------------------------------------------------------------------
// C Runtime Support
// -----------------------------------------------------------------------------

extern "C" struct eh_frame_t *
get_eh_frame_list()
{
    return g_eh_frame_list;
}

extern "C" void
register_eh_frame(void *addr, uint64_t size)
{
    if (g_eh_frame_list_num >= MAX_NUM_MODULES)
        return;

    g_eh_frame_list[g_eh_frame_list_num].addr = addr;
    g_eh_frame_list[g_eh_frame_list_num].size = size;
    g_eh_frame_list_num++;
}
