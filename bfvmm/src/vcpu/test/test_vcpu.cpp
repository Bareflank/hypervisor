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
#include <debug_ring/debug_ring.h>

void
vcpu_ut::test_vcpu_invalid_id()
{
    this->expect_exception([&] { std::make_unique<vcpu>(vcpuid::reserved, nullptr); }, ""_ut_iae);
}

void
vcpu_ut::test_vcpu_null_debug_ring()
{
    this->expect_no_exception([&] { std::make_unique<vcpu>(0, nullptr); });
}

void
vcpu_ut::test_vcpu_valid()
{
    auto dr = std::unique_ptr<debug_ring>(nullptr);
    this->expect_no_exception([&] { std::make_unique<vcpu>(0, std::move(dr)); });
}

void
vcpu_ut::test_vcpu_write_empty_string()
{
    char rb[DEBUG_RING_SIZE];
    debug_ring_resources_t *drr = nullptr;
    auto &&vc = std::make_unique<vcpu>(0);

    vc->write("");
    get_drr(0, &drr);

    this->expect_true(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 0);
}

void
vcpu_ut::test_vcpu_write_hello_world()
{
    char rb[DEBUG_RING_SIZE];
    debug_ring_resources_t *drr = nullptr;
    auto &&vc = std::make_unique<vcpu>(0);

    vc->write("hello world");
    get_drr(0, &drr);

    this->expect_true(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 11);
}

void
vcpu_ut::test_vcpu_init_null_attr()
{
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_initialized());
    vc->init(nullptr);
    this->expect_true(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_init_valid_attr()
{
    user_data data{};
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_initialized());
    vc->init(&data);
    this->expect_true(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_fini_null_attr()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->init();

    this->expect_true(vc->is_initialized());
    vc->fini(nullptr);
    this->expect_false(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_fini_valid_attr()
{
    user_data data{};
    auto &&vc = std::make_unique<vcpu>(0);

    vc->init();

    this->expect_true(vc->is_initialized());
    vc->fini(&data);
    this->expect_false(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_fini_without_init_without_run()
{
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_running());
    this->expect_false(vc->is_initialized());
    vc->fini();
    this->expect_false(vc->is_running());
    this->expect_false(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_fini_with_init_without_run()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->init();

    this->expect_false(vc->is_running());
    this->expect_true(vc->is_initialized());
    vc->fini();
    this->expect_false(vc->is_running());
    this->expect_false(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_fini_without_init_with_run()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->run();

    this->expect_true(vc->is_running());
    this->expect_false(vc->is_initialized());
    vc->fini();
    this->expect_false(vc->is_running());
    this->expect_false(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_fini_with_init_with_run()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->init();
    vc->run();

    this->expect_true(vc->is_running());
    this->expect_true(vc->is_initialized());
    vc->fini();
    this->expect_false(vc->is_running());
    this->expect_false(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_run_null_attr()
{
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_running());
    vc->run(nullptr);
    this->expect_true(vc->is_running());
}

void
vcpu_ut::test_vcpu_run_valid_attr()
{
    user_data data{};
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_running());
    vc->run(&data);
    this->expect_true(vc->is_running());
}

void
vcpu_ut::test_vcpu_run_without_init()
{
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_running());
    vc->run();
    this->expect_true(vc->is_running());
}

void
vcpu_ut::test_vcpu_run_with_init()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->init();

    this->expect_false(vc->is_running());
    vc->run();
    this->expect_true(vc->is_running());
}

void
vcpu_ut::test_vcpu_hlt_null_attr()
{
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_running());
    vc->hlt(nullptr);
    this->expect_false(vc->is_running());
}

void
vcpu_ut::test_vcpu_hlt_valid_attr()
{
    user_data data{};
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_running());
    vc->hlt(&data);
    this->expect_false(vc->is_running());
}

void
vcpu_ut::test_vcpu_hlt_without_run()
{
    auto &&vc = std::make_unique<vcpu>(0);

    this->expect_false(vc->is_running());
    vc->hlt();
    this->expect_false(vc->is_running());
}

void
vcpu_ut::test_vcpu_hlt_with_run()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->run();

    this->expect_true(vc->is_running());
    vc->hlt();
    this->expect_false(vc->is_running());
}

void
vcpu_ut::test_vcpu_id()
{
    auto vc = std::make_unique<vcpu>(1);
    this->expect_true(vc->id() == 1);
}

void
vcpu_ut::test_vcpu_is_bootstrap_vcpu()
{
    auto &&vc = std::make_unique<vcpu>(0);
    this->expect_true(vc->is_bootstrap_vcpu());
}

void
vcpu_ut::test_vcpu_is_not_bootstrap_vcpu()
{
    auto vc = std::make_unique<vcpu>(1);
    this->expect_false(vc->is_bootstrap_vcpu());
}

void
vcpu_ut::test_vcpu_is_host_vm_vcpu()
{
    auto vc = std::make_unique<vcpu>(1);
    this->expect_true(vc->is_host_vm_vcpu());
}

void
vcpu_ut::test_vcpu_is_not_host_vm_vcpu()
{
    auto vc = std::make_unique<vcpu>(0x0000000100000000);
    this->expect_false(vc->is_host_vm_vcpu());
}

void
vcpu_ut::test_vcpu_is_guest_vm_vcpu()
{
    auto vc = std::make_unique<vcpu>(0x0000000100000000);
    this->expect_true(vc->is_guest_vm_vcpu());
}

void
vcpu_ut::test_vcpu_is_not_guest_vm_vcpu()
{
    auto vc = std::make_unique<vcpu>(1);
    this->expect_false(vc->is_guest_vm_vcpu());
}

void
vcpu_ut::test_vcpu_is_running_vm_vcpu()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->run();
    this->expect_true(vc->is_running());
}

void
vcpu_ut::test_vcpu_is_not_running_vm_vcpu()
{
    auto &&vc = std::make_unique<vcpu>(0);
    this->expect_false(vc->is_running());
}

void
vcpu_ut::test_vcpu_is_initialized_vm_vcpu()
{
    auto &&vc = std::make_unique<vcpu>(0);

    vc->init();
    this->expect_true(vc->is_initialized());
}

void
vcpu_ut::test_vcpu_is_not_initialized_vm_vcpu()
{
    auto &&vc = std::make_unique<vcpu>(0);
    this->expect_false(vc->is_initialized());
}
