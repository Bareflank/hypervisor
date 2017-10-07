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
vcpu *g_vcpu = nullptr;

class vcpu_factory_ut : public vcpu_factory
{
public:
    std::unique_ptr<vcpu>
    make_vcpu(vcpuid::type id, user_data *data) override
    {
        (void) id;
        (void) data;

        if (make_vcpu_throws) {
            throw std::runtime_error("make_vcpu error");
        }

        return std::unique_ptr<vcpu>(g_vcpu);
    }
};

template<typename T> auto
mock_no_delete(MockRepository &mocks)
{
    auto &&ptr = mocks.Mock<T>();
    mocks.OnCallDestructor(ptr);

    return ptr;
}

TEST_CASE("vcpu_manager: create_valid")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    CHECK_NOTHROW(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: create_valid_twice_overwrites")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    CHECK_NOTHROW(g_vcm->create_vcpu(0));
    CHECK_NOTHROW(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: create_make_vcpu_returns_null")
{
    CHECK_THROWS(g_vcm->create_vcpu(0));
}

TEST_CASE("vcpu_manager: create_make_vcpu_throws")
{
    make_vcpu_throws = true;
    CHECK_THROWS(g_vcm->create_vcpu(0));
    make_vcpu_throws = false;
}

TEST_CASE("vcpu_manager: create_init_throws")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::fini);

    CHECK_THROWS(g_vcm->create_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: delete_valid")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->delete_vcpu(0));

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: delete_valid_twice")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->delete_vcpu(0));
    CHECK_NOTHROW(g_vcm->delete_vcpu(0));

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: delete_no_create")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);

    CHECK_NOTHROW(g_vcm->delete_vcpu(0));

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: delete_fini_throws")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini).Throw(std::runtime_error("error"));

    g_vcm->create_vcpu(0);
    CHECK_THROWS(g_vcm->delete_vcpu(0));

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: run_valid")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: run_valid_twice")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    CHECK_NOTHROW(g_vcm->run_vcpu(0));
    CHECK_NOTHROW(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: run_run_throws")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    CHECK_THROWS(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: run_hlt_throws")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::hlt).Throw(std::logic_error("error"));
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    CHECK_THROWS(g_vcm->run_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: run_no_create")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    CHECK_NOTHROW(g_vcm->run_vcpu(0));

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: hlt_valid")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    g_vcm->run_vcpu(0);

    mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: hlt_valid_twice")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    g_vcm->run_vcpu(0);

    mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));
    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: hlt_hlt_throws")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt).Throw(std::runtime_error("error"));
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(false);

    g_vcm->create_vcpu(0);
    g_vcm->run_vcpu(0);

    mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

    CHECK_THROWS(g_vcm->hlt_vcpu(0));
    g_vcm->delete_vcpu(0);

    g_vcpu = nullptr;
}

TEST_CASE("vcpu_manager: hlt_no_create")
{
    MockRepository mocks;
    g_vcpu = mock_no_delete<vcpu>(mocks);
    g_vcm->set_factory(std::make_unique<vcpu_factory_ut>());

    mocks.OnCall(g_vcpu, vcpu::init);
    mocks.OnCall(g_vcpu, vcpu::fini);
    mocks.OnCall(g_vcpu, vcpu::run);
    mocks.OnCall(g_vcpu, vcpu::hlt);
    mocks.OnCall(g_vcpu, vcpu::is_running).Return(true);

    CHECK_NOTHROW(g_vcm->hlt_vcpu(0));

    g_vcpu = nullptr;
}
