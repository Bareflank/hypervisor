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

#include <vmcs/vmcs_intel_x64.h>
#include <intrinsics/cpuid_x64.h>

using namespace x64;
using namespace intel_x64;

std::string
vmcs_intel_x64::get_vm_instruction_error()
{
    switch (vm::read(VMCS_VM_INSTRUCTION_ERROR))
    {
        case 1:
            return "VMCALL executed in VMX root operation";

        case 2:
            return "VMCLEAR with invalid physical address";

        case 3:
            return "VMCLEAR with VMXON pointer";

        case 4:
            return "VMLAUNCH with non-clear VMCS";

        case 5:
            return "VMRESUME with non-launched VMCS";

        case 6:
            return "VMRESUME after VMXOFF (VMXOFF and VMXON between "
                   "VMLAUNCH and VMRESUME)";

        case 7:
            return "VM entry with invalid control field(s)";

        case 8:
            return "VM entry with invalid host-state field(s)";

        case 9:
            return "VMPTRLD with invalid physical address";

        case 10:
            return "VMPTRLD with VMXON pointer";

        case 11:
            return "VMPTRLD with incorrect VMCS revision identifier";

        case 12:
            return "VMREAD/VMWRITE from/to unsupported VMCS component";

        case 13:
            return "VMWRITE to read-only VMCS component";

        case 15:
            return "VMXON executed in VMX root operation";

        case 16:
            return "VM entry with invalid executive-VMCS pointer";

        case 17:
            return "VM entry with non-launched executive VMCS";

        case 18:
            return "VM entry with executive-VMCS pointer not VMXON "
                   "pointer (when attempting to deactivate the "
                   "dual-monitor treatment of SMIs and SMM)";

        case 19:
            return "VMCALL with non-clear VMCS (when attempting to "
                   "activate the dual-monitor treatment of SMIs and "
                   "SMM)";

        case 20:
            return "VMCALL with invalid VM-exit control fields";

        case 22:
            return "VMCALL with incorrect MSEG revision identifier "
                   "(when attempting to activate the dual-monitor "
                   "treatment of SMIs and SMM)";

        case 23:
            return "VMXOFF under dual-monitor treatment of SMIs and "
                   "SMM";

        case 24:
            return "VMCALL with invalid SMM-monitor features (when "
                   "attempting to activate the dual-monitor treatment "
                   "of SMIs and SMM)";

        case 25:
            return "VM entry with invalid VM-execution control fields "
                   "in executive VMCS (when attempting to return from "
                   "SMM)";

        case 26:
            return "VM entry with events blocked by MOV SS.";

        case 28:
            return "Invalid operand to INVEPT/INVVPID.";

        default:
            return "Unknown VM instruction error";
    }
}

bool
vmcs_intel_x64::is_address_canonical(uint64_t addr)
{
    return ((addr <= 0x00007FFFFFFFFFFF) || (addr >= 0xFFFF800000000000));
}

bool
vmcs_intel_x64::is_linear_address_valid(uint64_t addr)
{
    return is_address_canonical(addr);
}

bool
vmcs_intel_x64::is_physical_address_valid(uint64_t addr)
{
    auto bits = cpuid::addr_size::phys::get();
    auto mask = (0xFFFFFFFFFFFFFFFFULL >> bits) << bits;

    return ((addr & mask) == 0);
}

bool
vmcs_intel_x64::is_enabled_v8086() const
{
    return vmcs::guest_rflags::virtual_8086_mode::get() == 1;
}


bool
vmcs_intel_x64::is_supported_eptp_switching() const
{
    if (!msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1())
        return false;

    if ((msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask << 32) == 0)
        return false;

    return ((vm::read(VMCS_VM_FUNCTION_CONTROLS) & VM_FUNCTION_CONTROL_EPTP_SWITCHING) != 0);
}

bool
vmcs_intel_x64::is_supported_event_injection_instr_length_of_0() const
{
    return msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get();
}

bool
vmcs_intel_x64::check_pat(uint64_t pat)
{
    switch (pat)
    {
        case 0:
        case 1:
        case 4:
        case 5:
        case 6:
        case 7:
            return true;

        default:
            return false;
    }
}
