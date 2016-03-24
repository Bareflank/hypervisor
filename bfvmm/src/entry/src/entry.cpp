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

#include <memory>

#include <debug.h>
#include <entry.h>
#include <entry/entry.h>
#include <exception.h>
#include <eh_frame_list.h>
#include <vcpu/vcpu_manager.h>

// -----------------------------------------------------------------------------
// Global
// -----------------------------------------------------------------------------

auto g_eh_frame_list_num = 0ULL;
struct eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

#define guard(a) \
    guard_stack([&]() -> int64_t \
    { return guard_exceptions([&]() { a; }); });

/// Guard Stack
///
/// Since we are using userspace style code / libraries (like libc++) in this
/// code, we could end up overrunning the stack, as we do not have control of
/// all of the code, and some of it assumes that the stack is very large. This
/// guard provides a new stack that is much larger, ensuring that the kernel's
/// stack is not corrupted.
///
/// Note: Order matters here. You must catch all exceptions first before
/// calling this function. Since the execute with stack function uses
/// assembly, there is no FDE entry for this function which means that stack
/// unwinding cannot continue past this point.
///
/// Note: We can use make_unqiue here because bad_alloc always results in
/// an abort (i.e. system halt).
///
template<typename T> int64_t
guard_stack(T func)
{
    auto num = 0;
    auto ret = ENTRY_ERROR_UNKNOWN;
    auto stack = std::make_unique<uint64_t[]>(STACK_SIZE);

    for (num = 0; num < STACK_SIZE; num++)
        stack[num] = 0xFFFFFFFFFFFFFFFF;

    ret = execute_with_stack(func, stack.get(), STACK_SIZE << 3);

    for (num = 0; num < STACK_SIZE; num++)
        if (stack[num] != 0xFFFFFFFFFFFFFFFF)
            break;

    // bfinfo << std::dec;
    // bfdebug << "    - free heap space: " << (g_mm->free_blocks() >> 4)
    //         << " kbytes" << bfendl;
    // bfdebug << "    - free stack space: " << (num >> 7)
    //         << " kbytes" << bfendl;

    return ret;
}

/// Guard Exceptions
///
/// The following attempts to catch all of the different types of execptions
/// that could be thrown. The default bareflank implementation only throws
/// general exceptions. Libc++ however could also throw a standard exception,
/// which also needs to be caught. We also provide a catch all incase a
/// non-standard exception is thrown, preventing exceptions from moving
/// beyond this point.
///
template<typename T> int64_t
guard_exceptions(T func)
{
    try
    {
        func();

        return ENTRY_SUCCESS;
    }
    catch (bfn::general_exception &ge)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- General Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << ge << bfendl;
    }
    catch (std::exception &e)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Standard Exception Caught            -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << e.what() << bfendl;
    }
    catch (...)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Unknown Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
    }

    return ENTRY_ERROR_UNKNOWN;
}

// -----------------------------------------------------------------------------
// Entry Points
// -----------------------------------------------------------------------------

extern "C" int64_t
init_vmm(int64_t arg)
{
    (void) arg;

    return guard(g_vcm->init(0));
}

extern "C" int64_t
start_vmm(int64_t arg)
{
    (void) arg;

    return guard(g_vcm->start(0));
}

extern "C" int64_t
stop_vmm(int64_t arg)
{
    (void) arg;

    return guard(g_vcm->stop(0));
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
    if (addr == nullptr || size == 0)
        return;

    if (g_eh_frame_list_num >= MAX_NUM_MODULES)
        return;

    g_eh_frame_list[g_eh_frame_list_num].addr = addr;
    g_eh_frame_list[g_eh_frame_list_num].size = size;
    g_eh_frame_list_num++;
}
