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

vmxon_ut::vmxon_ut()
{
}

bool
vmxon_ut::init()
{
    return true;
}

bool
vmxon_ut::fini()
{
    return true;
}

bool
vmxon_ut::list()
{
    this->test_constructor_null_intrinsics();
    this->test_start_success();
    this->test_start_start_twice();
    this->test_start_execute_vmxon_already_on_failure();
    this->test_start_execute_vmxon_failure();
    this->test_start_check_ia32_vmx_cr4_fixed0_msr_failure();
    this->test_start_check_ia32_vmx_cr4_fixed1_msr_failure();
    this->test_start_enable_vmx_operation_failure();
    this->test_start_v8086_disabled_failure();
    this->test_start_check_ia32_feature_control_msr();
    this->test_start_check_ia32_vmx_cr0_fixed0_msr();
    this->test_start_check_ia32_vmx_cr0_fixed1_msr();
    this->test_start_check_vmx_capabilities_msr_memtype_failure();
    this->test_start_check_vmx_capabilities_msr_addr_width_failure();
    this->test_start_check_vmx_capabilities_true_based_controls_failure();
    this->test_start_check_cpuid_vmx_supported_failure();
    this->test_start_virt_to_phys_failure();
    this->test_stop_success();
    this->test_stop_stop_twice();
    this->test_stop_vmxoff_check_failure();
    this->test_stop_vmxoff_failure();
    this->test_coveralls_cleanup();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vmxon_ut);
}
