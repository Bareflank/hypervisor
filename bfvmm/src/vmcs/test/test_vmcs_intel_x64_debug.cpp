//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#include <test.h>
#include <vmcs/vmcs_intel_x64_debug.h>

using namespace intel_x64;
using namespace msrs;
using namespace vmcs;
using namespace debug;

void
vmcs_ut::test_debug_dump()
{
    this->expect_no_exception([&] { dump(); });
}

void
vmcs_ut::test_debug_dump_16bit_control_fields()
{
    this->expect_no_exception([&] { dump_16bit_control_fields(); });
}

void
vmcs_ut::test_debug_dump_16bit_guest_state_fields()
{
    this->expect_no_exception([&] { dump_16bit_guest_state_fields(); });
}

void
vmcs_ut::test_debug_dump_16bit_host_state_fields()
{
    this->expect_no_exception([&] { dump_16bit_host_state_fields(); });
}

void
vmcs_ut::test_debug_dump_64bit_control_fields()
{
    this->expect_no_exception([&] { dump_64bit_control_fields(); });
}

void
vmcs_ut::test_debug_dump_64bit_read_only_data_field()
{
    this->expect_no_exception([&] { dump_64bit_read_only_data_field(); });
}

void
vmcs_ut::test_debug_dump_64bit_guest_state_fields()
{
    this->expect_no_exception([&] { dump_64bit_guest_state_fields(); });
}

void
vmcs_ut::test_debug_dump_64bit_host_state_fields()
{
    this->expect_no_exception([&] { dump_64bit_host_state_fields(); });
}

void
vmcs_ut::test_debug_dump_32bit_control_fields()
{
    this->expect_no_exception([&] { dump_32bit_control_fields(); });
}

void
vmcs_ut::test_debug_dump_32bit_read_only_data_fields()
{
    this->expect_no_exception([&] { dump_32bit_read_only_data_fields(); });
}

void
vmcs_ut::test_debug_dump_32bit_guest_state_fields()
{
    this->expect_no_exception([&] { dump_32bit_guest_state_fields(); });
}

void
vmcs_ut::test_debug_dump_32bit_host_state_field()
{
    this->expect_no_exception([&] { dump_32bit_host_state_field(); });
}

void
vmcs_ut::test_debug_dump_natural_width_control_fields()
{
    this->expect_no_exception([&] { dump_natural_width_control_fields(); });
}

void
vmcs_ut::test_debug_dump_natural_width_read_only_data_fields()
{
    this->expect_no_exception([&] { dump_natural_width_read_only_data_fields(); });
}

void
vmcs_ut::test_debug_dump_natural_width_guest_state_fields()
{
    this->expect_no_exception([&] { dump_natural_width_guest_state_fields(); });
}

void
vmcs_ut::test_debug_dump_natural_width_host_state_fields()
{
    this->expect_no_exception([&] { dump_natural_width_host_state_fields(); });
}

void
vmcs_ut::test_debug_dump_vmx_controls()
{
    this->expect_no_exception([&] { dump_vmx_controls(); });
}

void
vmcs_ut::test_debug_dump_pin_based_vm_execution_controls()
{
    this->expect_no_exception([&] { dump_pin_based_vm_execution_controls(); });
}

void
vmcs_ut::test_debug_dump_primary_processor_based_vm_execution_controls()
{
    this->expect_no_exception([&] { dump_primary_processor_based_vm_execution_controls(); });
}

void
vmcs_ut::test_debug_dump_secondary_processor_based_vm_execution_controls()
{
    proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    this->expect_no_exception([&] { dump_secondary_processor_based_vm_execution_controls(); });

    proc_ctl_disallow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    this->expect_no_exception([&] { dump_secondary_processor_based_vm_execution_controls(); });
}

void
vmcs_ut::test_debug_dump_vm_exit_control_fields()
{
    this->expect_no_exception([&] { dump_vm_exit_control_fields(); });
}

void
vmcs_ut::test_debug_dump_vm_entry_control_fields()
{
    this->expect_no_exception([&] { dump_vm_entry_control_fields(); });
}

void
vmcs_ut::test_debug_dump_vmcs_field()
{
    auto addr = 0x00UL;
    auto name = "test";
    auto exists = true;

    this->expect_no_exception([&] { dump_vmcs_field(addr, name, exists); });
    this->expect_no_exception([&] { dump_vmcs_field(addr, name, !exists); });
}

void
vmcs_ut::test_debug_dump_vm_control()
{
    auto name = "test";
    auto is_set = true;

    this->expect_no_exception([&] { dump_vm_control(name, is_set); });
    this->expect_no_exception([&] { dump_vm_control(name, !is_set); });
}
