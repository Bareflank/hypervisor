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
#include <vcpu/vcpu_manager.h>
#include <exit_handler/exit_handler_intel_x64_entry.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

void
exit_handler_intel_x64_ut::test_entry_valid()
{
    MockRepository mocks;
    vcpu_manager *vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::dispatch);
    mocks.OnCall(vcm, vcpu_manager::halt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(exit_handler());
    });
}

void
exit_handler_intel_x64_ut::test_entry_throws_general_exception()
{
    MockRepository mocks;
    vcpu_manager *vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::dispatch).Throw(bfn::general_exception());
    mocks.OnCall(vcm, vcpu_manager::halt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(exit_handler());
    });
}

void
exit_handler_intel_x64_ut::test_entry_throws_standard_exception()
{
    MockRepository mocks;
    vcpu_manager *vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::dispatch).Throw(std::exception());
    mocks.OnCall(vcm, vcpu_manager::halt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(exit_handler());
    });
}

void
exit_handler_intel_x64_ut::test_entry_throws_any_exception()
{
    MockRepository mocks;
    vcpu_manager *vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::dispatch).Throw(10);
    mocks.OnCall(vcm, vcpu_manager::halt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(exit_handler());
    });
}
