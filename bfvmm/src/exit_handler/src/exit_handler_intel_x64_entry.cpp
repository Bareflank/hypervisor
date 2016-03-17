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
#include <vcpu/vcpu_manager.h>
#include <exit_handler/exit_handler_intel_x64_entry.h>
#include <exit_handler/exit_handler_intel_x64_support.h>
#include <exit_handler/exit_handler_intel_x64_exceptions.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Guard Exceptions
///
/// The following attempts to catch all of the different types of execptions
/// that could be thrown. The default bareflank implementation only throws
/// general exceptions. Libc++ however could also throw a standard exception,
/// which also needs to be caught. We also provide a catch all incase a
/// non-standard exception is thrown, preventing exceptions from moving
/// beyond this point.
///
template<typename T> void
guard_exceptions(T func)
{
    try
    {
        return func();
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

    for (auto i = 0; i < 1000000; i++);
    g_vcm->halt(0);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

extern "C" void
exit_handler(void)
{
    guard_exceptions([&]()
    { g_vcm->dispatch(0); });
}
