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

bool
vmcs_intel_x64::check_control_checks_on_vm_execution_control_fields()
{
    auto result = true;

    result &= check_control_pin_based_ctls_reserved_properly_set();
    result &= check_control_proc_based_ctls_reserved_properly_set();
    result &= check_control_vm_entry_ctls_reserved_properly_set();
    result &= check_control_cr3_count_less_then_4();
    result &= check_control_io_bitmap_address_bits();
    result &= check_control_msr_bitmap_address_bits();
    result &= check_control_tpr_shadow_and_virtual_apic();
    result &= check_control_nmi_exiting_and_virtual_nmi();
    result &= check_control_virtual_nmi_and_nmi_window();
    result &= check_control_virtual_apic_address_bits();
    result &= check_control_virtual_x2apic_and_tpr();
    result &= check_control_register_apic_mode_and_tpr();
    result &= check_control_virtual_interrupt_delivery_and_tpr();
    result &= check_control_x2apic_mode_and_virtual_apic_access();
    result &= check_control_virtual_interrupt_and_external_interrupt();
    result &= check_control_process_posted_interrupt_checks();
    result &= check_control_vpid_checks();
    result &= check_control_enable_ept_checks();
    result &= check_control_unrestricted_guests();
    result &= check_control_enable_vm_functions();
    result &= check_control_enable_vmcs_shadowing();
    result &= check_control_enable_ept_violation_checks();

    return result;
}

bool
vmcs_intel_x64::check_control_pin_based_ctls_reserved_properly_set()
{
    auto controls = vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);
    auto controls_lower = ((controls >> 00) & 0x00000000FFFFFFFF);
    auto controls_upper = ((controls >> 32) & 0x00000000FFFFFFFF);
    auto lower = ((m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR) >> 00) & 0x00000000FFFFFFFF);
    auto upper = ((m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR) >> 32) & 0x00000000FFFFFFFF);

    if((lower & controls_lower) != lower || (upper & ~controls_upper) != upper)
    {
        std::cout << "check_control_pin_based_ctls_reserved_properly_set failed. "
                  << "pin based controls not setup properly: " << std::endl
                  << std::hex
                  << "    - lower: 0x" << lower << std::endl
                  << "    - upper: 0x" << upper << std::endl
                  << "    - controls_lower: 0x" << controls_lower << std::endl
                  << "    - controls_upper: 0x" << controls_upper << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_proc_based_ctls_reserved_properly_set()
{
    auto controls = vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    auto controls_lower = ((controls >> 00) & 0x00000000FFFFFFFF);
    auto controls_upper = ((controls >> 32) & 0x00000000FFFFFFFF);
    auto lower = ((m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR) >> 00) & 0x00000000FFFFFFFF);
    auto upper = ((m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR) >> 32) & 0x00000000FFFFFFFF);

    if((lower & controls_lower) != lower || (upper & ~controls_upper) != upper)
    {
        std::cout << "check_control_proc_based_ctls_reserved_properly_set failed. "
                  << "proc based controls not setup properly: " << std::endl
                  << std::hex
                  << "    - lower: 0x" << lower << std::endl
                  << "    - upper: 0x" << upper << std::endl
                  << "    - controls_lower: 0x" << controls_lower << std::endl
                  << "    - controls_upper: 0x" << controls_upper << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_cr3_count_less_then_4()
{
    auto cr3_target_count = vmread(VMCS_CR3_TARGET_COUNT);

    if (cr3_target_count > 4)
    {
        std::cout << "check_control_cr3_count_less_then_4 failed: "
                  << "cr3 count must be between 0 - 4"
                  << std::hex
                  << "    - cr3_target_count: 0x" << cr3_target_count << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_io_bitmap_address_bits()
{
    auto controls = vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_P_PROC_BASED_USE_I_O_BITMAPS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_io_bitmap_address_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_msr_bitmap_address_bits()
{
    auto controls = vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_msr_bitmap_address_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_tpr_shadow_and_virtual_apic()
{
    auto controls = vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_tpr_shadow_and_virtual_apic"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_nmi_exiting_and_virtual_nmi()
{
    auto controls = vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_PIN_BASED_NMI_EXITING) != 0 &&
        (controls & VM_EXEC_PIN_BASED_VIRTUAL_NMIS) != 0 )
    {
        std::cout << "check_control_nmi_exiting_and_virtual_nmi failed: "
                  << "if nmi exiting is 0, virtual nmi must be 0"
                  << std::hex
                  << "    - controls: 0x" << controls << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_virtual_nmi_and_nmi_window()
{
    auto controls1 = vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);
    auto controls2 = vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls1 & VM_EXEC_PIN_BASED_NMI_EXITING) != 0 &&
        (controls2 & VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING) != 0 )
    {
        std::cout << "check_control_nmi_exiting_and_virtual_nmi failed: "
                  << "if nmi exiting is 0, virtual nmi must be 0"
                  << std::hex
                  << "    - pin controls: 0x" << controls1 << std::endl
                  << "    - proc controls: 0x" << controls2 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_virtual_apic_address_bits()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_virtual_apic_address_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_virtual_x2apic_and_tpr()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_virtual_x2apic_and_tpr"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_register_apic_mode_and_tpr()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_register_apic_mode_and_tpr"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_virtual_interrupt_delivery_and_tpr()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_virtual_interrupt_delivery_and_tpr"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_x2apic_mode_and_virtual_apic_access()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_x2apic_mode_and_virtual_apic_access"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_virtual_interrupt_and_external_interrupt()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_virtual_interrupt_and_external_interrupt"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_process_posted_interrupt_checks()
{
    auto controls = vmread(VM_EXEC_PIN_BASED_NMI_EXITING);

    // There are multiple checks that are missing here

    if ((controls & VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_process_posted_interrupt_checks"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_vpid_checks()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_VPID) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_vpid_checks"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_enable_ept_checks()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    // There are multiple checks that are missing here

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_EPT) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_enable_ept_checks"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_unrestricted_guests()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    // There are multiple checks in the control section. If this bit is enabled
    // all of the checks in the VMCS should be updated. Ideally, at some point
    // the VMCS will have all of the checks needed to support this setting,
    // even if the default VMCS does not support unrestricted guests.

    if ((controls & VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_unrestricted_guests"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_enable_vm_functions()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    // There are multiple checks that are missing here

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_enable_vm_functions"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_enable_vmcs_shadowing()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    // There are multiple checks that are missing here

    if ((controls & VM_EXEC_S_PROC_BASED_VMCS_SHADOWING) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_enable_vmcs_shadowing"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_enable_ept_violation_checks()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    // There are multiple checks that are missing here

    if ((controls & VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_enable_ept_violation_checks"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_checks_on_vm_exit_control_fields()
{
    auto result = true;

    result &= check_control_vm_exit_ctls_reserved_properly_set();
    result &= check_control_activate_and_save_premeption_timer_must_be_0();
    result &= check_control_exit_msr_store_address();
    result &= check_control_exit_msr_load_address();

    return result;
}

bool
vmcs_intel_x64::check_control_vm_exit_ctls_reserved_properly_set()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);
    auto controls_lower = ((controls >> 00) & 0x00000000FFFFFFFF);
    auto controls_upper = ((controls >> 32) & 0x00000000FFFFFFFF);
    auto lower = ((m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR) >> 00) & 0x00000000FFFFFFFF);
    auto upper = ((m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR) >> 32) & 0x00000000FFFFFFFF);

    if((lower & controls_lower) != lower || (upper & ~controls_upper) != upper)
    {
        std::cout << "check_control_vm_exit_ctls_reserved_properly_set failed. "
                  << "vm exit controls not setup properly: " << std::endl
                  << std::hex
                  << "    - lower: 0x" << lower << std::endl
                  << "    - upper: 0x" << upper << std::endl
                  << "    - controls_lower: 0x" << controls_lower << std::endl
                  << "    - controls_upper: 0x" << controls_upper << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_activate_and_save_premeption_timer_must_be_0()
{
    auto controls1 = vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);
    auto controls2 = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls1 & VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER) != 0 &&
        (controls2 & VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE) != 0 )
    {
        std::cout << "check_control_activate_and_save_premeption_timer_must_be_0 failed: "
                  << "if activate preempt timer is 0, save preempt timer must also be 0"
                  << std::hex
                  << "    - pin controls: 0x" << controls1 << std::endl
                  << "    - exit controls: 0x" << controls2 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_exit_msr_store_address()
{
    auto msr_store_count = vmread(VMCS_VM_EXIT_MSR_STORE_COUNT);

    // There are multiple checks that are missing here

    if (msr_store_count != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_msr_store_address"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_exit_msr_load_address()
{
    auto msr_load_count = vmread(VMCS_VM_EXIT_MSR_LOAD_COUNT);

    // There are multiple checks that are missing here

    if (msr_load_count != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_msr_load_address"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_checks_on_vm_entry_control_fields()
{
    auto result = true;

    result &= check_control_vm_entry_ctls_reserved_properly_set();
    result &= check_control_event_injection_checks();
    result &= check_control_entry_msr_load_address();

    return result;
}

bool
vmcs_intel_x64::check_control_vm_entry_ctls_reserved_properly_set()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);
    auto controls_lower = ((controls >> 00) & 0x00000000FFFFFFFF);
    auto controls_upper = ((controls >> 32) & 0x00000000FFFFFFFF);
    auto lower = ((m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR) >> 00) & 0x00000000FFFFFFFF);
    auto upper = ((m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR) >> 32) & 0x00000000FFFFFFFF);

    if((lower & controls_lower) != lower || (upper & ~controls_upper) != upper)
    {
        std::cout << "check_control_vm_entry_ctls_reserved_properly_set failed. "
                  << "vm entry controls not setup properly: " << std::endl
                  << std::hex
                  << "    - lower: 0x" << lower << std::endl
                  << "    - upper: 0x" << upper << std::endl
                  << "    - controls_lower: 0x" << controls_lower << std::endl
                  << "    - controls_upper: 0x" << controls_upper << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_event_injection_checks()
{
    auto entry_interruption = vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    // There are multiple checks that are missing here

    if (entry_interruption != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_event_injection_checks"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_control_entry_msr_load_address()
{
    auto msr_load_count = vmread(VMCS_VM_ENTRY_MSR_LOAD_COUNT);

    // There are multiple checks that are missing here

    if (msr_load_count != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_control_entry_msr_load_address"
                  << std::endl;
        return false;
    }

    return true;
}
