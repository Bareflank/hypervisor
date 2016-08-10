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

bool make_vcpu_throws;
std::shared_ptr<vcpu> g_vcpu;

class vcpu_factory_ut : public vcpu_factory
{
public:

    vcpu_factory_ut() {}
    virtual ~vcpu_factory_ut() {}

    virtual std::shared_ptr<vcpu> make_vcpu(uint64_t id, void *attr) override
    {
        (void) id;
        (void) attr;

        if (make_vcpu_throws)
            throw std::runtime_error("error");

        return g_vcpu;
    }
};

vcpu_ut::vcpu_ut()
{
}

bool
vcpu_ut::init()
{
    make_vcpu_throws = false;
    g_vcm->set_factory(std::make_shared<vcpu_factory_ut>());

    return true;
}

bool
vcpu_ut::fini()
{
    return true;
}

bool
vcpu_ut::list()
{
    this->test_vcpu_invalid_id();
    this->test_vcpu_null_debug_ring();
    this->test_vcpu_valid();
    this->test_vcpu_write_empty_string();
    this->test_vcpu_write_hello_world();
    this->test_vcpu_write_from_constructor();
    this->test_vcpu_write_from_destructor();
    this->test_vcpu_init_null_attr();
    this->test_vcpu_init_valid_attr();
    this->test_vcpu_fini_null_attr();
    this->test_vcpu_fini_valid_attr();
    this->test_vcpu_fini_without_init_without_run();
    this->test_vcpu_fini_with_init_without_run();
    this->test_vcpu_fini_without_init_with_run();
    this->test_vcpu_fini_with_init_with_run();
    this->test_vcpu_run_null_attr();
    this->test_vcpu_run_valid_attr();
    this->test_vcpu_run_without_init();
    this->test_vcpu_run_with_init();
    this->test_vcpu_hlt_null_attr();
    this->test_vcpu_hlt_valid_attr();
    this->test_vcpu_hlt_without_run();
    this->test_vcpu_hlt_with_run();
    this->test_vcpu_id();
    this->test_vcpu_is_bootstrap_vcpu();
    this->test_vcpu_is_not_bootstrap_vcpu();
    this->test_vcpu_is_host_vm_vcpu();
    this->test_vcpu_is_not_host_vm_vcpu();
    this->test_vcpu_is_guest_vm_vcpu();
    this->test_vcpu_is_not_guest_vm_vcpu();
    this->test_vcpu_is_running_vm_vcpu();
    this->test_vcpu_is_not_running_vm_vcpu();
    this->test_vcpu_is_initialized_vm_vcpu();
    this->test_vcpu_is_not_initialized_vm_vcpu();

    this->test_vcpu_intel_x64_invalid_id();
    this->test_vcpu_intel_x64_null_params_valid_intrinsics();
    this->test_vcpu_intel_x64_valid_params_null_intrinsics();
    this->test_vcpu_intel_x64_valid();
    this->test_vcpu_intel_x64_init_null_params_valid_intrinsics();
    this->test_vcpu_intel_x64_init_valid_params_null_intrinsics();
    this->test_vcpu_intel_x64_init_valid();
    this->test_vcpu_intel_x64_init_vmcs_throws();
    this->test_vcpu_intel_x64_fini_null_params_valid_intrinsics();
    this->test_vcpu_intel_x64_fini_valid_params_null_intrinsics();
    this->test_vcpu_intel_x64_fini_valid();
    this->test_vcpu_intel_x64_fini_no_init();
    this->test_vcpu_intel_x64_run_launch();
    this->test_vcpu_intel_x64_run_launch_is_host_vcpu();
    this->test_vcpu_intel_x64_run_resume();
    this->test_vcpu_intel_x64_run_no_init();
    this->test_vcpu_intel_x64_run_vmxon_throws();
    this->test_vcpu_intel_x64_run_vmcs_throws();
    this->test_vcpu_intel_x64_hlt_no_init();
    this->test_vcpu_intel_x64_hlt_no_run();
    this->test_vcpu_intel_x64_hlt_valid();
    this->test_vcpu_intel_x64_hlt_valid_is_host_vcpu();
    this->test_vcpu_intel_x64_hlt_vmxon_throws();
    this->test_vcpu_intel_x64_coveralls_cleanup();

    this->test_vcpu_manager_create_valid();
    this->test_vcpu_manager_create_valid_twice_overwrites();
    this->test_vcpu_manager_create_make_vcpu_returns_null();
    this->test_vcpu_manager_create_make_vcpu_throws();
    this->test_vcpu_manager_create_init_throws();
    this->test_vcpu_manager_delete_valid();
    this->test_vcpu_manager_delete_valid_twice();
    this->test_vcpu_manager_delete_no_create();
    this->test_vcpu_manager_delete_fini_throws();
    this->test_vcpu_manager_run_valid();
    this->test_vcpu_manager_run_valid_twice();
    this->test_vcpu_manager_run_run_throws();
    this->test_vcpu_manager_run_hlt_throws();
    this->test_vcpu_manager_run_is_guest_vm_vcpu_throws();
    this->test_vcpu_manager_run_no_create();
    this->test_vcpu_manager_run_is_running();
    this->test_vcpu_manager_run_is_guest_vm();
    this->test_vcpu_manager_hlt_valid();
    this->test_vcpu_manager_hlt_valid_twice();
    this->test_vcpu_manager_hlt_hlt_throws();
    this->test_vcpu_manager_hlt_is_guest_vm_vcpu_throws();
    this->test_vcpu_manager_hlt_no_create();
    this->test_vcpu_manager_hlt_is_running();
    this->test_vcpu_manager_hlt_is_guest_vm();
    this->test_vcpu_manager_write_null();
    this->test_vcpu_manager_write_hello();
    this->test_vcpu_manager_write_no_create();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vcpu_ut);
}
