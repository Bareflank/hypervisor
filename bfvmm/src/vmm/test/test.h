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

class vmm_ut : public unittest
{
public:

    vmm_ut();
    ~vmm_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_vmm_start_uninitialized();
    void test_vmm_stop_uninitialized();
    void test_verify_cpuid_vmx_supported_failed();
    void test_verify_cpuid_vmx_supported_success();
    void test_verify_vmx_capabilities_msr_failed_invalid_physical_address_width();
    void test_verify_vmx_capabilities_msr_failed_invalid_memory_type();
    void test_verify_vmx_capabilities_msr_success();
    void test_verify_ia32_vmx_cr0_fixed_msr_failed_fixed0();
    void test_verify_ia32_vmx_cr0_fixed_msr_failed_fixed1();
    void test_verify_ia32_vmx_cr0_fixed_msr_success();
    void test_verify_ia32_vmx_cr4_fixed_msr_failed_fixed0();
    void test_verify_ia32_vmx_cr4_fixed_msr_failed_fixed1();
    void test_verify_ia32_vmx_cr4_fixed_msr_success();
    void test_verify_ia32_feature_control_msr_failed();
    void test_verify_ia32_feature_control_msr_success();
    void test_verify_v8086_disabled_failed();
    void test_verify_v8086_disabled_success();
    void test_verify_vmx_operation_enabled_failed();
    void test_verify_vmx_operation_enabled_success();
    void test_verify_vmx_operation_disabled_failed();
    void test_verify_vmx_operation_disabled_success();
    void test_enable_vmx_operation_success();
    void test_disable_vmx_operation_success();
    void test_create_vmxon_region_out_of_memory();
    void test_create_vmxon_region_misaligned_page();
    void test_create_vmxon_region_not_page_aligned();
    void test_release_vmxon_region();
    void test_execute_vmxon_already_on();
    void test_execute_vmxon_failed();
    void test_execute_vmxoff_already_off();
    void test_execute_vmxoff_failed();
};

#endif
