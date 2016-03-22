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
#include <memory_manager/memory_manager.h>

#include <memory.h>
#include <eh_frame_list.h>

void
entry_ut::test_init_vmm_success()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(init_vmm(0));
    });
}

void
entry_ut::test_init_vmm_throws_general_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(bfn::general_exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(init_vmm(0));
    });
}

void
entry_ut::test_init_vmm_throws_standard_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(std::exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(init_vmm(0));
    });
}

void
entry_ut::test_init_vmm_throws_any_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(10);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(init_vmm(0));
    });
}

void
entry_ut::test_start_vmm_success()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(start_vmm(0));
    });
}

void
entry_ut::test_start_vmm_throws_general_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(bfn::general_exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(start_vmm(0));
    });
}

void
entry_ut::test_start_vmm_throws_standard_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(std::exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(start_vmm(0));
    });
}

void
entry_ut::test_start_vmm_throws_any_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(10);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(start_vmm(0));
    });
}

void
entry_ut::test_stop_vmm_success()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(stop_vmm(0));
    });
}

void
entry_ut::test_stop_vmm_throws_general_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(bfn::general_exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(stop_vmm(0));
    });
}

void
entry_ut::test_stop_vmm_throws_standard_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(std::exception());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(stop_vmm(0));
    });
}

void
entry_ut::test_stop_vmm_throws_any_exception()
{
    MockRepository mocks;
    auto vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(vcm, vcpu_manager::init).Throw(10);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(stop_vmm(0));
    });
}

void
entry_ut::test_get_eh_frame_list_success()
{
    ASSERT_TRUE(get_eh_frame_list() != nullptr);
}

void
entry_ut::test_register_eh_frame_invalid_addr()
{
    register_eh_frame(0, 10);

    EXPECT_TRUE(get_eh_frame_list()[0].addr == nullptr);
    EXPECT_TRUE(get_eh_frame_list()[0].size == 0);
}

void
entry_ut::test_register_eh_frame_invalid_size()
{
    register_eh_frame((void *)10, 0);

    EXPECT_TRUE(get_eh_frame_list()[0].addr == nullptr);
    EXPECT_TRUE(get_eh_frame_list()[0].size == 0);
}

void
entry_ut::test_register_eh_frame_success()
{
    register_eh_frame((void *)10, 10);

    EXPECT_TRUE(get_eh_frame_list()[0].addr == (void *)10);
    EXPECT_TRUE(get_eh_frame_list()[0].size == 10);
}

void
entry_ut::test_register_eh_frame_too_many()
{
    for (auto i = 1ULL; i < MAX_NUM_MODULES; i++)
        register_eh_frame((void *)(10 + i), 10 + i);

    register_eh_frame((void *)10, 10);

    EXPECT_TRUE(get_eh_frame_list()[MAX_NUM_MODULES - 1].addr == (void *)(10 + MAX_NUM_MODULES - 1));
    EXPECT_TRUE(get_eh_frame_list()[MAX_NUM_MODULES - 1].size == 10 + MAX_NUM_MODULES - 1);
}
