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

#include <test.h>
#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_entry.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

void
exit_handler_intel_x64_ut::test_entry_valid()
{
    MockRepository mocks;
    auto &&eh = mocks.Mock<exit_handler_intel_x64>();

    mocks.OnCall(eh, exit_handler_intel_x64::halt);
    mocks.OnCall(eh, exit_handler_intel_x64::dispatch);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ exit_handler(eh); });
    });
}

void
exit_handler_intel_x64_ut::test_entry_throws_general_exception()
{
    MockRepository mocks;
    auto &&eh = mocks.Mock<exit_handler_intel_x64>();

    mocks.ExpectCall(eh, exit_handler_intel_x64::halt);
    mocks.OnCall(eh, exit_handler_intel_x64::dispatch).Throw(bfn::general_exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ exit_handler(eh); });
    });
}

void
exit_handler_intel_x64_ut::test_entry_throws_standard_exception()
{
    MockRepository mocks;
    auto &&eh = mocks.Mock<exit_handler_intel_x64>();

    mocks.ExpectCall(eh, exit_handler_intel_x64::halt);
    mocks.OnCall(eh, exit_handler_intel_x64::dispatch).Throw(std::exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ exit_handler(eh); });
    });
}

void
exit_handler_intel_x64_ut::test_entry_throws_any_exception()
{
    MockRepository mocks;
    auto &&eh = mocks.Mock<exit_handler_intel_x64>();

    mocks.ExpectCall(eh, exit_handler_intel_x64::halt);
    mocks.OnCall(eh, exit_handler_intel_x64::dispatch).Throw(10);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ exit_handler(eh); });
    });
}
