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

#ifndef TEST_H
#define TEST_H

#include <unittest.h>

class vcpu_ut : public unittest
{
public:

    vcpu_ut();
    ~vcpu_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_vcpu_invalid_id();
    void test_vcpu_null_debug_ring();
    void test_vcpu_valid();
    void test_vcpu_write_empty_string();
    void test_vcpu_write_hello_world();
    void test_vcpu_init_null_attr();
    void test_vcpu_init_valid_attr();
    void test_vcpu_fini_null_attr();
    void test_vcpu_fini_valid_attr();
    void test_vcpu_fini_without_init_without_run();
    void test_vcpu_fini_with_init_without_run();
    void test_vcpu_fini_without_init_with_run();
    void test_vcpu_fini_with_init_with_run();
    void test_vcpu_run_null_attr();
    void test_vcpu_run_valid_attr();
    void test_vcpu_run_without_init();
    void test_vcpu_run_with_init();
    void test_vcpu_hlt_null_attr();
    void test_vcpu_hlt_valid_attr();
    void test_vcpu_hlt_without_run();
    void test_vcpu_hlt_with_run();
    void test_vcpu_id();
    void test_vcpu_is_bootstrap_vcpu();
    void test_vcpu_is_not_bootstrap_vcpu();
    void test_vcpu_is_host_vm_vcpu();
    void test_vcpu_is_not_host_vm_vcpu();
    void test_vcpu_is_guest_vm_vcpu();
    void test_vcpu_is_not_guest_vm_vcpu();
    void test_vcpu_is_running_vm_vcpu();
    void test_vcpu_is_not_running_vm_vcpu();
    void test_vcpu_is_initialized_vm_vcpu();
    void test_vcpu_is_not_initialized_vm_vcpu();

    void test_vcpu_intel_x64_invalid_id();
    void test_vcpu_intel_x64_valid();
    void test_vcpu_intel_x64_init_null_params();
    void test_vcpu_intel_x64_init_valid_params();
    void test_vcpu_intel_x64_init_valid();
    void test_vcpu_intel_x64_init_vmcs_throws();
    void test_vcpu_intel_x64_fini_null_params();
    void test_vcpu_intel_x64_fini_valid_params();
    void test_vcpu_intel_x64_fini_valid();
    void test_vcpu_intel_x64_fini_no_init();
    void test_vcpu_intel_x64_run_launch();
    void test_vcpu_intel_x64_run_launch_is_host_vcpu();
    void test_vcpu_intel_x64_run_resume();
    void test_vcpu_intel_x64_run_no_init();
    void test_vcpu_intel_x64_run_vmxon_throws();
    void test_vcpu_intel_x64_run_vmcs_throws();
    void test_vcpu_intel_x64_hlt_no_init();
    void test_vcpu_intel_x64_hlt_no_run();
    void test_vcpu_intel_x64_hlt_valid();
    void test_vcpu_intel_x64_hlt_valid_is_host_vcpu();
    void test_vcpu_intel_x64_hlt_vmxon_throws();

    void test_vcpu_manager_create_valid();
    void test_vcpu_manager_create_valid_twice_overwrites();
    void test_vcpu_manager_create_make_vcpu_returns_null();
    void test_vcpu_manager_create_make_vcpu_throws();
    void test_vcpu_manager_create_init_throws();
    void test_vcpu_manager_delete_valid();
    void test_vcpu_manager_delete_valid_twice();
    void test_vcpu_manager_delete_no_create();
    void test_vcpu_manager_delete_fini_throws();
    void test_vcpu_manager_run_valid();
    void test_vcpu_manager_run_valid_twice();
    void test_vcpu_manager_run_run_throws();
    void test_vcpu_manager_run_hlt_throws();
    void test_vcpu_manager_run_no_create();
    void test_vcpu_manager_hlt_valid();
    void test_vcpu_manager_hlt_valid_twice();
    void test_vcpu_manager_hlt_hlt_throws();
    void test_vcpu_manager_hlt_no_create();
    void test_vcpu_manager_write_null();
    void test_vcpu_manager_write_hello();
    void test_vcpu_manager_write_no_create();
};

#endif
