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
#include <entry/entry.h>
#include <vcpu/vcpu_manager.h>

#include <memory.h>
#include <eh_frame_list.h>

void
entry_ut::test_start_vmm_success()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { start_vmm(0); });
    });
}

void
entry_ut::test_start_vmm_throws_general_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu).Throw(bfn::general_exception());
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { start_vmm(0); });
    });
}

void
entry_ut::test_start_vmm_throws_standard_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu).Throw(std::exception());
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { start_vmm(0); });
    });
}

void
entry_ut::test_start_vmm_throws_bad_alloc()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu).Throw(std::bad_alloc());
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { start_vmm(0); });
    });
}

void
entry_ut::test_start_vmm_throws_any_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu).Throw(10);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { start_vmm(0); });
    });
}

void
entry_ut::test_stop_vmm_success()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { stop_vmm(0); });
    });
}

void
entry_ut::test_stop_vmm_throws_general_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu).Throw(bfn::general_exception());
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { stop_vmm(0); });
    });
}

void
entry_ut::test_stop_vmm_throws_standard_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu).Throw(std::exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { stop_vmm(0); });
    });
}

void
entry_ut::test_stop_vmm_throws_bad_alloc()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu).Throw(std::bad_alloc());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { stop_vmm(0); });
    });
}

void
entry_ut::test_stop_vmm_throws_any_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::create_vcpu);
    mocks.OnCall(vcm, vcpu_manager::delete_vcpu).Throw(10);
    mocks.OnCall(vcm, vcpu_manager::run_vcpu);
    mocks.OnCall(vcm, vcpu_manager::hlt_vcpu);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { stop_vmm(0); });
    });
}
