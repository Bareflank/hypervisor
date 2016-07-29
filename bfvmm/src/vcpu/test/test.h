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
    ~vcpu_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_vcpu_id_too_large();
    void test_vcpu_invalid_debug_ring();
    void test_vcpu_valid();
    void test_vcpu_write();

    void test_vcpu_intel_x64_id_too_large();
    void test_vcpu_intel_x64_invalid_objects();
    void test_vcpu_intel_x64_valid();
    void test_vcpu_intel_x64_run_vmxon_start_failed();
    void test_vcpu_intel_x64_run_vmcs_launch_failed();
    void test_vcpu_intel_x64_run_success();
    void test_vcpu_intel_x64_hlt();

    void test_vcpu_manager_valid();
    void test_vcpu_manager_create_vcpu_invalid_vcpuid();
    void test_vcpu_manager_create_vcpu_success();
    void test_vcpu_manager_create_vcpu_success_twice();
    void test_vcpu_manager_run_uninitialized_vcpuid();
    void test_vcpu_manager_run_success();
    void test_vcpu_manager_hlt_uninitialized_vcpuid();
    void test_vcpu_manager_hlt_success();
    void test_vcpu_manager_hlt_twice();
    void test_vcpu_manager_write_uninitialized_vcpuid();
    void test_vcpu_manager_write_uninitialized_vcpuid_with_valid_vcpu();
    void test_vcpu_manager_write_success();
};

#endif
