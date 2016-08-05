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
    EXPECT_EXCEPTION(std::make_shared<vcpu>(VCPUID_RESERVED, nullptr), std::invalid_argument);
}

void
vcpu_ut::test_vcpu_null_debug_ring()
{
    EXPECT_NO_EXCEPTION(std::make_shared<vcpu>(0, nullptr));
}

void
vcpu_ut::test_vcpu_valid()
{
    auto dr = std::shared_ptr<debug_ring>(0);

    EXPECT_NO_EXCEPTION(std::make_shared<vcpu>(0, dr));
}

void
vcpu_ut::test_vcpu_write_empty_string()
{
    char rb[DEBUG_RING_SIZE];
    debug_ring_resources_t *drr = nullptr;
    auto vc = std::make_shared<vcpu>(0);

    vc->write("");
    get_drr(0, &drr);

    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == 0);
}

void
vcpu_ut::test_vcpu_write_hello_world()
{
    char rb[DEBUG_RING_SIZE];
    debug_ring_resources_t *drr = nullptr;
    auto vc = std::make_shared<vcpu>(0);

    vc->write("hello world");
    get_drr(0, &drr);

    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == 11);
}

class test_vcpu: public vcpu
{
public:

    test_vcpu(uint64_t vcpuid) :
        vcpu(vcpuid)
    {
        write("hello world");
    }

    ~test_vcpu()
    {
        write("hello world");
    }
};

void
vcpu_ut::test_vcpu_write_from_constructor()
{
    char rb[DEBUG_RING_SIZE];
    debug_ring_resources_t *drr = nullptr;
    auto vc = std::make_shared<test_vcpu>(0);

    get_drr(0, &drr);
    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == 11);
}

void
vcpu_ut::test_vcpu_write_from_destructor()
{
    char rb[DEBUG_RING_SIZE];
    debug_ring_resources_t *drr = nullptr;

    {
        auto vc = std::make_shared<test_vcpu>(0);
    }

    get_drr(0, &drr);
    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == 22);
}

void
vcpu_ut::test_vcpu_init_null_attr()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_initialized() == false);
    vc->init(nullptr);
    EXPECT_TRUE(vc->is_initialized() == true);
}

void
vcpu_ut::test_vcpu_init_valid_attr()
{
    int i = 0;
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_initialized() == false);
    vc->init(&i);
    EXPECT_TRUE(vc->is_initialized() == true);
}

void
vcpu_ut::test_vcpu_fini_null_attr()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->init();

    EXPECT_TRUE(vc->is_initialized() == true);
    vc->fini(nullptr);
    EXPECT_TRUE(vc->is_initialized() == false);
}

void
vcpu_ut::test_vcpu_fini_valid_attr()
{
    int i = 0;
    auto vc = std::make_shared<vcpu>(0);

    vc->init();

    EXPECT_TRUE(vc->is_initialized() == true);
    vc->fini(&i);
    EXPECT_TRUE(vc->is_initialized() == false);
}

void
vcpu_ut::test_vcpu_fini_without_init_without_run()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
    EXPECT_TRUE(vc->is_initialized() == false);
    vc->fini();
    EXPECT_TRUE(vc->is_running() == false);
    EXPECT_TRUE(vc->is_initialized() == false);
}

void
vcpu_ut::test_vcpu_fini_with_init_without_run()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->init();

    EXPECT_TRUE(vc->is_running() == false);
    EXPECT_TRUE(vc->is_initialized() == true);
    vc->fini();
    EXPECT_TRUE(vc->is_running() == false);
    EXPECT_TRUE(vc->is_initialized() == false);
}

void
vcpu_ut::test_vcpu_fini_without_init_with_run()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->run();

    EXPECT_TRUE(vc->is_running() == true);
    EXPECT_TRUE(vc->is_initialized() == false);
    vc->fini();
    EXPECT_TRUE(vc->is_running() == false);
    EXPECT_TRUE(vc->is_initialized() == false);
}

void
vcpu_ut::test_vcpu_fini_with_init_with_run()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->init();
    vc->run();

    EXPECT_TRUE(vc->is_running() == true);
    EXPECT_TRUE(vc->is_initialized() == true);
    vc->fini();
    EXPECT_TRUE(vc->is_running() == false);
    EXPECT_TRUE(vc->is_initialized() == false);
}

void
vcpu_ut::test_vcpu_run_null_attr()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
    vc->run(nullptr);
    EXPECT_TRUE(vc->is_running() == true);
}

void
vcpu_ut::test_vcpu_run_valid_attr()
{
    int i = 0;
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
    vc->run(&i);
    EXPECT_TRUE(vc->is_running() == true);
}

void
vcpu_ut::test_vcpu_run_without_init()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
    vc->run();
    EXPECT_TRUE(vc->is_running() == true);
}

void
vcpu_ut::test_vcpu_run_with_init()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->init();

    EXPECT_TRUE(vc->is_running() == false);
    vc->run();
    EXPECT_TRUE(vc->is_running() == true);
}

void
vcpu_ut::test_vcpu_hlt_null_attr()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
    vc->hlt(nullptr);
    EXPECT_TRUE(vc->is_running() == false);
}

void
vcpu_ut::test_vcpu_hlt_valid_attr()
{
    int i = 0;
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
    vc->hlt(&i);
    EXPECT_TRUE(vc->is_running() == false);
}

void
vcpu_ut::test_vcpu_hlt_without_run()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
    vc->hlt();
    EXPECT_TRUE(vc->is_running() == false);
}

void
vcpu_ut::test_vcpu_hlt_with_run()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->run();

    EXPECT_TRUE(vc->is_running() == true);
    vc->hlt();
    EXPECT_TRUE(vc->is_running() == false);
}

void
vcpu_ut::test_vcpu_id()
{
    auto vc = std::make_shared<vcpu>(1);

    EXPECT_TRUE(vc->id() == 1);
}

void
vcpu_ut::test_vcpu_is_bootstrap_vcpu()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_bootstrap_vcpu() == true);
}

void
vcpu_ut::test_vcpu_is_not_bootstrap_vcpu()
{
    auto vc = std::make_shared<vcpu>(1);

    EXPECT_TRUE(vc->is_bootstrap_vcpu() == false);
}

void
vcpu_ut::test_vcpu_is_host_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(1);

    EXPECT_TRUE(vc->is_host_vm_vcpu() == true);
}

void
vcpu_ut::test_vcpu_is_not_host_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(0x0000000100000000);

    EXPECT_TRUE(vc->is_host_vm_vcpu() == false);
}

void
vcpu_ut::test_vcpu_is_guest_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(0x0000000100000000);

    EXPECT_TRUE(vc->is_guest_vm_vcpu() == true);
}

void
vcpu_ut::test_vcpu_is_not_guest_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(1);

    EXPECT_TRUE(vc->is_guest_vm_vcpu() == false);
}

void
vcpu_ut::test_vcpu_is_running_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->run();
    EXPECT_TRUE(vc->is_running() == true);
}

void
vcpu_ut::test_vcpu_is_not_running_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_running() == false);
}

void
vcpu_ut::test_vcpu_is_initialized_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(0);

    vc->init();
    EXPECT_TRUE(vc->is_initialized() == true);
}

void
vcpu_ut::test_vcpu_is_not_initialized_vm_vcpu()
{
    auto vc = std::make_shared<vcpu>(0);

    EXPECT_TRUE(vc->is_initialized() == false);
}
