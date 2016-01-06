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

#include <iomanip>
#include <iostream>

#include <vmcs/vmcs_intel_x64.h>

void
vmcs_intel_x64::check_vm_instruction_error()
{
    auto check_vm_instruction = vmread(VMCS_VM_INSTRUCTION_ERROR);

    if (check_vm_instruction == 0)
        return;

    // The following error codes are defined in the Intel Software Developers
    // Manual, Chapter 3, Section 30.4.

    std::cout << "VM Instruction Error:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    switch (check_vm_instruction)
    {
        case 1:
            std::cout << "VMCALL executed in VMX root operation" << std::endl;
            break;

        case 2:
            std::cout << "VMCLEAR with invalid physical address" << std::endl;
            break;

        case 3:
            std::cout << "VMCLEAR with VMXON pointer" << std::endl;
            break;

        case 4:
            std::cout << "VMLAUNCH with non-clear VMCS" << std::endl;
            break;

        case 5:
            std::cout << "VMRESUME with non-launched VMCS" << std::endl;
            break;

        case 6:
            std::cout << "VMRESUME after VMXOFF (VMXOFF and VMXON between VMLAUNCH and VMRESUME)" << std::endl;
            break;

        case 7:
            std::cout << "VM entry with invalid control field(s)" << std::endl;
            break;

        case 8:
            std::cout << "VM entry with invalid host-state field(s)" << std::endl;
            break;

        case 9:
            std::cout << "VMPTRLD with invalid physical address" << std::endl;
            break;

        case 10:
            std::cout << "VMPTRLD with VMXON pointer" << std::endl;
            break;

        case 11:
            std::cout << "VMPTRLD with incorrect VMCS revision identifier" << std::endl;
            break;

        case 12:
            std::cout << "VMREAD/VMWRITE from/to unsupported VMCS component" << std::endl;
            break;

        case 13:
            std::cout << "VMWRITE to read-only VMCS component" << std::endl;
            break;

        case 15:
            std::cout << "VMXON executed in VMX root operation" << std::endl;
            break;

        case 16:
            std::cout << "VM entry with invalid executive-VMCS pointer" << std::endl;
            break;

        case 17:
            std::cout << "VM entry with non-launched executive VMCS" << std::endl;
            break;

        case 18:
            std::cout << "VM entry with executive-VMCS pointer not VMXON pointer (when attempting "
                      << "to deactivate the dual-monitor treatment of SMIs and SMM)" << std::endl;
            break;

        case 19:
            std::cout << "VMCALL with non-clear VMCS (when attempting to activate the dual-monitor "
                      << "treatment of SMIs and SMM)" << std::endl;
            break;

        case 20:
            std::cout << "VMCALL with invalid VM-exit control fields" << std::endl;
            break;

        case 22:
            std::cout << "VMCALL with incorrect MSEG revision identifier (when attempting to "
                      << "activate the dual-monitor treatment of SMIs and SMM)" << std::endl;
            break;

        case 23:
            std::cout << "VMXOFF under dual-monitor treatment of SMIs and SMM" << std::endl;
            break;

        case 24:
            std::cout << "VMCALL with invalid SMM-monitor features (when attempting to activate the "
                      << "dual-monitor treatment of SMIs and SMM)" << std::endl;
            break;

        case 25:
            std::cout << "VM entry with invalid VM-execution control fields in executive VMCS (when "
                      << "attempting to return from SMM)" << std::endl;
            break;

        case 26:
            std::cout << "VM entry with events blocked by MOV SS." << std::endl;
            break;

        case 28:
            std::cout << "Invalid operand to INVEPT/INVVPID." << std::endl;
            break;

        default:
            std::cout << "Unknown vm instruction error: " << check_vm_instruction << std::endl;
    }

    std::cout << std::endl;
}

bool
vmcs_intel_x64::check_is_address_canonical(uint64_t addr)
{
    if (((addr <= 0x00007FFFFFFFFFFF)) ||
        ((addr >= 0xFFFF800000000000) && (addr <= 0xFFFFFFFFFFFFFFFF)))
    {
        return true;
    }

    return false;
}

bool
vmcs_intel_x64::check_vmcs_host_state()
{
    auto result = true;

    result &= check_host_control_registers_and_msrs();
    result &= check_host_segment_and_descriptor_table_registers();
    result &= check_host_checks_related_to_address_space_size();

    return result;
}

bool
vmcs_intel_x64::check_vmcs_guest_state()
{
    auto result = true;

    result &= check_guest_checks_on_guest_control_registers_debug_registers_and_msrs();
    result &= check_guest_checks_on_guest_segment_registers();
    result &= check_guest_checks_on_guest_descriptor_table_registers();
    result &= check_guest_checks_on_guest_rip_and_rflags();
    result &= check_guest_checks_on_guest_non_register_state();

    return result;
}

bool
vmcs_intel_x64::check_vmcs_control_state()
{
    auto result = true;

    result &= check_control_checks_on_vm_execution_control_fields();
    result &= check_control_checks_on_vm_exit_control_fields();
    result &= check_control_checks_on_vm_entry_control_fields();

    return result;
}
