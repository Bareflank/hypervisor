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

vcpu_ut::vcpu_ut()
{
}

bool
vcpu_ut::init()
{
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
    this->test_vcpu_id_too_large();
    this->test_vcpu_invalid_debug_ring();
    this->test_vcpu_valid();
    this->test_vcpu_write();

    this->test_vcpu_intel_x64_id_too_large();
    this->test_vcpu_intel_x64_invalid_objects();
    this->test_vcpu_intel_x64_valid();
    this->test_vcpu_intel_x64_run_vmxon_start_failed();
    this->test_vcpu_intel_x64_run_vmcs_launch_failed();
    this->test_vcpu_intel_x64_run_success();
    this->test_vcpu_intel_x64_hlt();

    this->test_vcpu_manager_valid();
    this->test_vcpu_manager_create_vcpu_invalid_vcpuid();
    this->test_vcpu_manager_create_vcpu_success();
    this->test_vcpu_manager_create_vcpu_success_twice();
    this->test_vcpu_manager_run_uninitialized_vcpuid();
    this->test_vcpu_manager_run_success();
    this->test_vcpu_manager_hlt_uninitialized_vcpuid();
    this->test_vcpu_manager_hlt_success();
    this->test_vcpu_manager_hlt_twice();
    this->test_vcpu_manager_write_uninitialized_vcpuid();
    this->test_vcpu_manager_write_uninitialized_vcpuid_with_valid_vcpu();
    this->test_vcpu_manager_write_success();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vcpu_ut);
}
