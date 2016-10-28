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

uint64_t
vmcs_intel_x64::get_proc2_ctls() const
{
    if (!vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::is_enabled())
        return 0;

    return vm::read(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
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
vmcs_intel_x64::is_enabled_virtualized_apic() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES) == 0)
        return false;

    if (!is_supported_virtualized_apic())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_ept() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_EPT) == 0)
        return false;

    if (!is_supported_ept())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_descriptor_table_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING) == 0)
        return false;

    if (!is_supported_descriptor_table_exiting())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdtscp() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP) == 0)
        return false;

    if (!is_supported_rdtscp())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_x2apic_mode() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE) == 0)
        return false;

    if (!is_supported_x2apic_mode())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_vpid() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_VPID) == 0)
        return false;

    if (!is_supported_vpid())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_wbinvd_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_WBINVD_EXITING) == 0)
        return false;

    if (!is_supported_wbinvd_exiting())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_unrestricted_guests() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST) == 0)
        return false;

    if (!is_supported_unrestricted_guests())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_apic_register_virtualization() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION) == 0)
        return false;

    if (!is_supported_apic_register_virtualization())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_virtual_interrupt_delivery() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY) == 0)
        return false;

    if (!is_supported_virtual_interrupt_delivery())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_pause_loop_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING) == 0)
        return false;

    if (!is_supported_pause_loop_exiting())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdrand_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_RDRAND_EXITING) == 0)
        return false;

    if (!is_supported_rdrand_exiting())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_pml() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_PML) == 0)
        return false;

    if (!is_supported_pml())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_invpcid() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_INVPCID) == 0)
        return false;

    if (!is_supported_invpcid())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_vm_functions() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS) == 0)
        return false;

    if (!is_supported_vm_functions())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_vmcs_shadowing() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VMCS_SHADOWING) == 0)
        return false;

    if (!is_supported_vmcs_shadowing())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdseed_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_RDSEED_EXITING) == 0)
        return false;

    if (!is_supported_rdseed_exiting())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_ept_violation_ve() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE) == 0)
        return false;

    if (!is_supported_ept_violation_ve())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_enabled_xsave_xrestore() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS) == 0)
        return false;

    if (!is_supported_xsave_xrestore())
        return false;

    return true;
}

bool
vmcs_intel_x64::is_supported_virtualized_apic() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_ept() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_descriptor_table_exiting() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_rdtscp() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_x2apic_mode() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_vpid() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_ENABLE_VPID << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_wbinvd_exiting() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_WBINVD_EXITING << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_unrestricted_guests() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_apic_register_virtualization() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_virtual_interrupt_delivery() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_pause_loop_exiting() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_rdrand_exiting() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_RDRAND_EXITING << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_invpcid() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_ENABLE_INVPCID << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_vm_functions() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_vmcs_shadowing() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_rdseed_exiting() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_RDSEED_EXITING << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_pml() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_ENABLE_PML << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_ept_violation_ve() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_xsave_xrestore() const
{
    return (msrs::ia32_vmx_procbased_ctls2::get() & (VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS << 32)) != 0;
}

bool
vmcs_intel_x64::is_supported_eptp_switching() const
{
    if (!msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1())
        return false;

    if (!this->is_supported_vm_functions())
        return false;

    return ((vm::read(VMCS_VM_FUNCTION_CONTROLS) & VM_FUNCTION_CONTROL_EPTP_SWITCHING) != 0);
}

bool
vmcs_intel_x64::is_supported_event_injection_instr_length_of_0() const
{
    return msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get() != 0;
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
