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
#include <vcpu/vcpu.h>
#include <vcpu/vcpu_factory.h>
#include <vcpu/vcpu_manager.h>

std::shared_ptr<vcpu> g_vcpu;

class vcpu_factory_ut : public vcpu_factory
{
public:

    vcpu_factory_ut() {}
    virtual ~vcpu_factory_ut() {}

    virtual std::shared_ptr<vcpu> make_vcpu(uint64_t) override
    { return g_vcpu; }
};

void
vcpu_ut::test_vcpu_manager_valid()
{
    ASSERT_TRUE(g_vcm != nullptr);

    g_vcm->set_factory(std::make_shared<vcpu_factory_ut>());
}

void
vcpu_ut::test_vcpu_manager_create_vcpu_invalid_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->create_vcpu(RESERVED_VCPUIDS + 1), std::invalid_argument);
}

void
vcpu_ut::test_vcpu_manager_create_vcpu_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::hlt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->delete_vcpu(0));
    });
}

void
vcpu_ut::test_vcpu_manager_create_vcpu_success_twice()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::hlt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->delete_vcpu(0));
    });
}

void
vcpu_ut::test_vcpu_manager_run_uninitialized_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->run_vcpu(0), std::invalid_argument);
}

void
vcpu_ut::test_vcpu_manager_run_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::hlt);
    mocks.ExpectCall(g_vcpu.get(), vcpu::run);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->run_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->hlt_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->delete_vcpu(0));
    });
}

void
vcpu_ut::test_vcpu_manager_hlt_uninitialized_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->hlt_vcpu(0), std::invalid_argument);
}

void
vcpu_ut::test_vcpu_manager_hlt_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.ExpectCall(g_vcpu.get(), vcpu::hlt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->hlt_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->delete_vcpu(0));
    });
}

void
vcpu_ut::test_vcpu_manager_hlt_twice()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.ExpectCall(g_vcpu.get(), vcpu::hlt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->hlt_vcpu(0));
        ASSERT_EXCEPTION(g_vcm->hlt_vcpu(0), std::invalid_argument);
    });
}

void
vcpu_ut::test_vcpu_manager_write_uninitialized_vcpuid()
{
    EXPECT_NO_EXCEPTION(g_vcm->write(0, "hello world"));
}

void
vcpu_ut::test_vcpu_manager_write_uninitialized_vcpuid_with_valid_vcpu()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::hlt);
    mocks.ExpectCall(g_vcpu.get(), vcpu::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->write(1, "hello world"));
        ASSERT_NO_EXCEPTION(g_vcm->hlt_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->delete_vcpu(0));
    });
}

void
vcpu_ut::test_vcpu_manager_write_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::hlt);
    mocks.ExpectCall(g_vcpu.get(), vcpu::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->create_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->write(0, "hello world"));
        ASSERT_NO_EXCEPTION(g_vcm->hlt_vcpu(0));
        ASSERT_NO_EXCEPTION(g_vcm->delete_vcpu(0));
    });
}
