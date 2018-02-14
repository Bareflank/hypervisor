//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <vcpu/vcpu.h>
#include <vcpu/vcpu_factory.h>
#include <vcpu/vcpu_manager.h>

bool make_vcpu_throws = false;
bfvmm::vcpu *g_vcpu = nullptr;

auto
setup_vcpu(MockRepository &mocks)
{
    auto vcpu = mocks.Mock<bfvmm::vcpu>();
    mocks.OnCallDestructor(vcpu);

    mocks.OnCall(vcpu, bfvmm::vcpu::init);
    mocks.OnCall(vcpu, bfvmm::vcpu::fini);
    mocks.OnCall(vcpu, bfvmm::vcpu::run);
    mocks.OnCall(vcpu, bfvmm::vcpu::hlt);
    mocks.OnCall(vcpu, bfvmm::vcpu::is_running).Return(false);

    return vcpu;
}

namespace bfvmm
{

WEAK_SYM std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *data)
{
    bfignored(vcpuid);
    bfignored(data);

    if (make_vcpu_throws) {
        throw std::runtime_error("make_vcpu error");
    }

    return std::unique_ptr<bfvmm::vcpu>(g_vcpu);
}

}

TEST_CASE("vcpu_manager: support")
{
    bfvmm::vcpu_factory factory{};
    CHECK_NOTHROW(factory.make_vcpu(0, nullptr));
}

TEST_CASE("vcpu_manager: create_valid")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    CHECK_NOTHROW(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: create_valid_twice_overwrites")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    CHECK_NOTHROW(g_vcm->create_vcpu(0));
    CHECK_NOTHROW(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: create_make_vcpu_returns_null")
{
    CHECK_THROWS(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: create_make_vcpu_throws")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    make_vcpu_throws = true;
    auto ___ = gsl::finally([&] {
        make_vcpu_throws = false;
    });

    CHECK_THROWS(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: create_init_throws")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    mocks.OnCall(g_vcpu, bfvmm::vcpu::init).Throw(std::runtime_error("error"));

    CHECK_THROWS(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: delete_valid")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->delete_vcpu(0));
}

TEST_CASE("vcpu_manager: delete_valid_twice")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->delete_vcpu(0));
    CHECK_NOTHROW(g_vcm->delete_vcpu(0));
}

TEST_CASE("vcpu_manager: delete_no_create")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    CHECK_NOTHROW(g_vcm->delete_vcpu(0));
}

TEST_CASE("vcpu_manager: delete_fini_throws")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    mocks.OnCall(g_vcpu, bfvmm::vcpu::fini).Throw(std::runtime_error("error"));

    g_vcm->create_vcpu(0);
    CHECK_THROWS(g_vcm->delete_vcpu(0));
}

TEST_CASE("vcpu_manager: run_valid")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: run_valid_twice")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->run_vcpu(0));
    CHECK_NOTHROW(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: run_run_throws")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    mocks.OnCall(g_vcpu, bfvmm::vcpu::run).Throw(std::runtime_error("error"));

    g_vcm->create_vcpu(0);
    CHECK_THROWS(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: run_no_create")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    CHECK_NOTHROW(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: hlt_valid")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    mocks.OnCall(g_vcpu, bfvmm::vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    g_vcm->run_vcpu(0);

    mocks.OnCall(g_vcpu, bfvmm::vcpu::is_running).Return(true);

    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: hlt_valid_twice")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    mocks.OnCall(g_vcpu, bfvmm::vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    g_vcm->run_vcpu(0);

    mocks.OnCall(g_vcpu, bfvmm::vcpu::is_running).Return(true);

    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));
    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: hlt_hlt_throws")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    mocks.OnCall(g_vcpu, bfvmm::vcpu::hlt).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, bfvmm::vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    g_vcm->run_vcpu(0);

    mocks.OnCall(g_vcpu, bfvmm::vcpu::is_running).Return(true);

    CHECK_THROWS(g_vcm->hlt_vcpu(0));
    g_vcm->delete_vcpu(0);
}

TEST_CASE("vcpu_manager: hlt_no_create")
{
    MockRepository mocks;
    g_vcpu = setup_vcpu(mocks);

    auto ___ = gsl::finally([&] {
        g_vcpu = nullptr;
    });

    mocks.OnCall(g_vcpu, bfvmm::vcpu::is_running).Return(true);

    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));
    g_vcm->delete_vcpu(0);
}
