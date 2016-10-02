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
#include <vcpu/vcpu_manager.h>

extern bool make_vcpu_throws;
extern vcpu *g_vcpu;

void
vcpu_ut::test_vcpu_manager_create_valid()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { g_vcm->create_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_create_valid_twice_overwrites()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { g_vcm->create_vcpu(0); });
        this->expect_no_exception([&] { g_vcm->create_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_create_make_vcpu_returns_null()
{
    this->expect_exception([&] { g_vcm->create_vcpu(0); }, ""_ut_ree);
}

void
vcpu_ut::test_vcpu_manager_create_make_vcpu_throws()
{
    make_vcpu_throws = true;
    this->expect_exception([&] { g_vcm->create_vcpu(0); }, ""_ut_ree);
    make_vcpu_throws = false;
}

void
vcpu_ut::test_vcpu_manager_create_init_throws()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::fini);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&] { g_vcm->create_vcpu(0); }, ""_ut_ree);
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_delete_valid()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_no_exception([&] { g_vcm->delete_vcpu(0); });
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_delete_valid_twice()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_no_exception([&] { g_vcm->delete_vcpu(0); });
        this->expect_no_exception([&] { g_vcm->delete_vcpu(0); });
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_delete_no_create()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { g_vcm->delete_vcpu(0); });
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_delete_fini_throws()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_exception([&] { g_vcm->delete_vcpu(0); }, ""_ut_ree);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_valid()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_no_exception([&] { g_vcm->run_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_valid_twice()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_no_exception([&] { g_vcm->run_vcpu(0); });
        this->expect_no_exception([&] { g_vcm->run_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_run_throws()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_exception([&] { g_vcm->run_vcpu(0); }, ""_ut_ree);
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_hlt_throws()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::hlt).Throw(std::logic_error("error"));
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_exception([&] { g_vcm->run_vcpu(0); }, ""_ut_ree);
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_is_guest_vm_vcpu_throws()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_exception([&] { g_vcm->run_vcpu(0); }, ""_ut_ree);
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_no_create()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&] { g_vcm->run_vcpu(0); }, ""_ut_iae);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_is_running()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_exception([&] { g_vcm->run_vcpu(0); }, ""_ut_lee);
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_run_is_guest_vm()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        this->expect_no_exception([&] { g_vcm->run_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_hlt_valid()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->run_vcpu(0);

        mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

        this->expect_no_exception([&] { g_vcm->hlt_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_hlt_valid_twice()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->run_vcpu(0);

        mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

        this->expect_no_exception([&] { g_vcm->hlt_vcpu(0); });
        this->expect_no_exception([&] { g_vcm->hlt_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_hlt_hlt_throws()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->run_vcpu(0);

        mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

        this->expect_exception([&] { g_vcm->hlt_vcpu(0); }, ""_ut_ree);
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_hlt_is_guest_vm_vcpu_throws()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->run_vcpu(0);

        mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);
        mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Throw(std::runtime_error("error"));

        this->expect_exception([&] { g_vcm->hlt_vcpu(0); }, ""_ut_ree);
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_hlt_no_create()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { g_vcm->hlt_vcpu(0); });
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_hlt_is_running()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->run_vcpu(0);
        this->expect_no_exception([&] { g_vcm->hlt_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_hlt_is_guest_vm()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);
    mocks.OnCall(g_vcpu, vcpu::is_guest_vm_vcpu).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->run_vcpu(0);

        mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

        this->expect_no_exception([&] { g_vcm->hlt_vcpu(0); });
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_write_null()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.ExpectCall(g_vcpu, vcpu::write).With(""_s);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->write(0, "");
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_write_hello()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.ExpectCall(g_vcpu, vcpu::write).With("hello"_s);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->create_vcpu(0);
        g_vcm->write(0, "hello");
        g_vcm->delete_vcpu(0);
    });

    g_vcpu = nullptr;
}

void
vcpu_ut::test_vcpu_manager_write_no_create()
{
    MockRepository mocks;
    g_vcpu = bfn::mock_no_delete<vcpu>(mocks);

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.NeverCall(g_vcpu, vcpu::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vcm->write(0, "hello");
    });

    g_vcpu = nullptr;
}
