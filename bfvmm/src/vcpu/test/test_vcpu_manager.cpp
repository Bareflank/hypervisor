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

    virtual std::shared_ptr<vcpu> make_vcpu(int64_t) override
    { return g_vcpu; }
};

void
vcpu_ut::test_vcpu_manager_valid()
{
    ASSERT_TRUE(g_vcm != nullptr);

    g_vcm->set_factory(std::make_shared<vcpu_factory_ut>());
}

void
vcpu_ut::test_vcpu_manager_init_negative_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->init(-1), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_init_invalid_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->init(10000), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_init_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_init_success_twice()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_start_negative_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->start(-1), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_start_invalid_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->start(10000), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_start_uninitialized_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->start(0), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_start_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::start);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->start(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_dispatch_negative_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->dispatch(-1), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_dispatch_invalid_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->dispatch(10000), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_dispatch_uninitialized_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->dispatch(0), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_dispatch_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::dispatch);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->dispatch(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_stop_negative_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->stop(-1), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_stop_invalid_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->stop(10000), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_stop_uninitialized_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->stop(0), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_stop_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.ExpectCall(g_vcpu.get(), vcpu::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_stop_twice()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.ExpectCall(g_vcpu.get(), vcpu::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
        EXPECT_EXCEPTION(g_vcm->stop(0), bfn::invalid_argument_error);
    });
}

void
vcpu_ut::test_vcpu_manager_halt_negative_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->halt(-1), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_halt_invalid_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->halt(10000), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_halt_uninitialized_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->halt(0), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_halt_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::halt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->halt(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_promote_negative_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->promote(-1), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_promote_invalid_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->promote(10000), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_promote_uninitialized_vcpuid()
{
    EXPECT_EXCEPTION(g_vcm->promote(0), bfn::invalid_argument_error);
}

void
vcpu_ut::test_vcpu_manager_promote_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::promote);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->promote(0));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_write_negative_vcpuid()
{
    EXPECT_NO_EXCEPTION(g_vcm->write(-1, "hello world"));
}

void
vcpu_ut::test_vcpu_manager_write_invalid_vcpuid()
{
    EXPECT_NO_EXCEPTION(g_vcm->write(10000, "hello world"));
}

void
vcpu_ut::test_vcpu_manager_write_uninitialized_vcpuid()
{
    EXPECT_NO_EXCEPTION(g_vcm->write(0, "hello world"));
}

void
vcpu_ut::test_vcpu_manager_write_negative_vcpuid_with_valid_vcpu()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->write(-1, "hello world"));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_write_invalid_vcpuid_with_valid_vcpu()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->write(10000, "hello world"));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_write_uninitialized_vcpuid_with_valid_vcpu()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->write(1, "hello world"));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}

void
vcpu_ut::test_vcpu_manager_write_success()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_shared<vcpu>(mocks);

    mocks.OnCall(g_vcpu.get(), vcpu::stop);
    mocks.ExpectCall(g_vcpu.get(), vcpu::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ASSERT_NO_EXCEPTION(g_vcm->init(0));
        ASSERT_NO_EXCEPTION(g_vcm->write(0, "hello world"));
        ASSERT_NO_EXCEPTION(g_vcm->stop(0));
    });
}
