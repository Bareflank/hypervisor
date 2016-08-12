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

#include <gsl/gsl>

#include <view_as_pointer.h>
#include <vmcs/vmcs_intel_x64.h>
#include <memory_manager/memory_manager.h>

void
vmcs_intel_x64::check_vmcs_control_state()
{
    checks_on_vm_execution_control_fields();
    checks_on_vm_exit_control_fields();
    checks_on_vm_entry_control_fields();
}

void
vmcs_intel_x64::checks_on_vm_execution_control_fields()
{
    check_control_pin_based_ctls_reserved_properly_set();
    check_control_proc_based_ctls_reserved_properly_set();
    check_control_proc_based_ctls2_reserved_properly_set();
    check_control_cr3_count_less_then_4();
    check_control_io_bitmap_address_bits();
    check_control_msr_bitmap_address_bits();
    check_control_tpr_shadow_and_virtual_apic();
    check_control_nmi_exiting_and_virtual_nmi();
    check_control_virtual_nmi_and_nmi_window();
    check_control_virtual_apic_address_bits();
    check_control_x2apic_mode_and_virtual_apic_access();
    check_control_virtual_interrupt_and_external_interrupt();
    check_control_process_posted_interrupt_checks();
    check_control_vpid_checks();
    check_control_enable_ept_checks();
    check_control_unrestricted_guests();
    check_control_enable_vm_functions();
    check_control_enable_vmcs_shadowing();
    check_control_enable_ept_violation_checks();
}

void
vmcs_intel_x64::check_control_pin_based_ctls_reserved_properly_set()
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR);

    auto allowed_zero = ((ia32_vmx_pinbased_ctls_msr >> 00) & 0x00000000FFFFFFFF);
    auto allowed_one = ((ia32_vmx_pinbased_ctls_msr >> 32) & 0x00000000FFFFFFFF);

    auto ctls = get_pin_ctls();
    auto ctls_lower = (ctls & 0x00000000FFFFFFFF);

    if ((allowed_zero & ctls_lower) != allowed_zero || (ctls_lower & ~allowed_one) != 0)
    {
        bferror << " failed: check_control_pin_based_ctls_reserved_properly_set" << bfendl;
        bferror << "    - allowed_zero: " << view_as_pointer(allowed_zero) << bfendl;
        bferror << "    - allowed_one: " << view_as_pointer(allowed_one) << bfendl;
        bferror << "    - ctls: " << view_as_pointer(ctls) << bfendl;

        throw std::logic_error("invalid pin based controls");
    }
}

void
vmcs_intel_x64::check_control_proc_based_ctls_reserved_properly_set()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    auto allowed_zero = ((ia32_vmx_procbased_ctls_msr >> 00) & 0x00000000FFFFFFFF);
    auto allowed_one = ((ia32_vmx_procbased_ctls_msr >> 32) & 0x00000000FFFFFFFF);

    auto ctls = get_proc_ctls();
    auto ctls_lower = (ctls & 0x00000000FFFFFFFF);

    if ((allowed_zero & ctls_lower) != allowed_zero || (ctls_lower & ~allowed_one) != 0)
    {
        bferror << " failed: check_control_proc_based_ctls_reserved_properly_set" << bfendl;
        bferror << "    - allowed_zero: " << view_as_pointer(allowed_zero) << bfendl;
        bferror << "    - allowed_one: " << view_as_pointer(allowed_one) << bfendl;
        bferror << "    - ctls: " << view_as_pointer(ctls) << bfendl;

        throw std::logic_error("invalid proc based controls");
    }
}

void
vmcs_intel_x64::check_control_proc_based_ctls2_reserved_properly_set()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    auto allowed_zero = ((ia32_vmx_procbased_ctls2_msr >> 00) & 0x00000000FFFFFFFF);
    auto allowed_one = ((ia32_vmx_procbased_ctls2_msr >> 32) & 0x00000000FFFFFFFF);

    auto ctls2 = get_proc2_ctls();
    auto ctls2_lower = (ctls2 & 0x00000000FFFFFFFF);

    if ((allowed_zero & ctls2_lower) != allowed_zero || (ctls2_lower & ~allowed_one) != 0)
    {
        bferror << " failed: check_control_proc_based_ctls2_reserved_properly_set" << bfendl;
        bferror << "    - allowed_zero: " << view_as_pointer(allowed_zero) << bfendl;
        bferror << "    - allowed_one: " << view_as_pointer(allowed_one) << bfendl;
        bferror << "    - ctls2: " << view_as_pointer(ctls2) << bfendl;

        throw std::logic_error("invalid proc based secondary controls");
    }
}

void
vmcs_intel_x64::check_control_cr3_count_less_then_4()
{
    auto cr3_target_count = vmread(VMCS_CR3_TARGET_COUNT);

    if (cr3_target_count > 4)
        throw std::logic_error("cr3 target count > 4");
}

void
vmcs_intel_x64::check_control_io_bitmap_address_bits()
{
    if (!is_enabled_io_bitmaps())
        return;

    auto addr_a = vmread(VMCS_ADDRESS_OF_IO_BITMAP_A_FULL);
    auto addr_b = vmread(VMCS_ADDRESS_OF_IO_BITMAP_B_FULL);

    if ((addr_a & 0x0000000000000FFF) != 0)
        throw std::logic_error("io bitmap a addr not page aligned");

    if ((addr_b & 0x0000000000000FFF) != 0)
        throw std::logic_error("io bitmap b addr not page aligned");

    if (!is_physical_address_valid(addr_a))
        throw std::logic_error("io bitmap a addr too large");

    if (!is_physical_address_valid(addr_b))
        throw std::logic_error("io bitmap b addr too large");
}

void
vmcs_intel_x64::check_control_msr_bitmap_address_bits()
{
    if (!is_enabled_msr_bitmaps())
        return;

    auto addr = vmread(VMCS_ADDRESS_OF_MSR_BITMAPS_FULL);

    if ((addr & 0x0000000000000FFF) != 0)
        throw std::logic_error("msr bitmap addr not page aligned");

    if (!is_physical_address_valid(addr))
        throw std::logic_error("msr bitmap addr too large");
}

void
vmcs_intel_x64::check_control_tpr_shadow_and_virtual_apic()
{
    if (is_enabled_tpr_shadow())
    {
        auto phys_addr = vmread(VMCS_VIRTUAL_APIC_ADDRESS_FULL);

        if (phys_addr == 0)
            throw std::logic_error("virtual apic physical addr is NULL");

        if ((phys_addr & 0x0000000000000FFF) != 0)
            throw std::logic_error("virtual apic addr not 4k aligned");

        if (!is_physical_address_valid(phys_addr))
            throw std::logic_error("virtual apic addr too large");

        if (!is_enabled_virtual_interrupt_delivery())
            throw std::logic_error("tpr_shadow is enabled, but virtual interrupt delivery is disabled");

        auto tpr_threshold = vmread(VMCS_TPR_THRESHOLD);

        if ((tpr_threshold & 0x00000000FFFFFFF0) != 0)
            throw std::logic_error("bits 31:4 of the tpr threshold must be 0");

        if (!is_enabled_virtualized_apic())
            throw std::logic_error("tpr_shadow is enabled, but virtual apic is disabled");

        auto virt_addr = static_cast<uint8_t *>(g_mm->phys_to_virt_ptr(phys_addr));

        if (virt_addr == nullptr)
            throw std::logic_error("virtual apic virtual addr is NULL");

        auto virt_addr_span = gsl::span<uint8_t>(virt_addr, 0x81);
        auto vtpr = virt_addr_span[0x80];
        auto vtpr_74 = (vtpr & 0xF0) >> 4;
        auto tpr_threshold_30 = static_cast<uint8_t>(tpr_threshold & 0x000000000000000F);

        if (tpr_threshold_30 > vtpr_74)
            throw std::logic_error("invalid TPR threshold");
    }
    else
    {
        if (is_enabled_x2apic_mode())
            throw std::logic_error("x2apic mode must be disabled if tpr shadow is disabled");

        if (is_enabled_apic_register_virtualization())
            throw std::logic_error("apic register virtualization must be disabled if tpr shadow is disabled");

        if (is_enabled_virtual_interrupt_delivery())
            throw std::logic_error("virtual interrupt delivery must be disabled if tpr shadow is disabled");
    }
}

void
vmcs_intel_x64::check_control_nmi_exiting_and_virtual_nmi()
{
    auto nmi_exiting = is_enabled_nmi_exiting();
    auto virtual_nmis = is_enabled_virtual_nmis();

    if (!nmi_exiting && virtual_nmis)
        throw std::logic_error("virtual NMI must be 0 if NMI exiting is 0");
}

void
vmcs_intel_x64::check_control_virtual_nmi_and_nmi_window()
{
    auto virtual_nmis = is_enabled_virtual_nmis();
    auto nmi_window_exiting = is_enabled_nmi_window_exiting();

    if (!virtual_nmis && nmi_window_exiting)
        throw std::logic_error("NMI window exiting must be 0 if virtual NMI is 0");
}

void
vmcs_intel_x64::check_control_virtual_apic_address_bits()
{
    if (!is_enabled_virtualized_apic())
        return;

    auto phys_addr = vmread(VMCS_APIC_ACCESS_ADDRESS_FULL);

    if (phys_addr == 0)
        throw std::logic_error("apic access physical addr is NULL");

    if ((phys_addr & 0x0000000000000FFF) != 0)
        throw std::logic_error("apic access addr not 4k aligned");

    if (!is_physical_address_valid(phys_addr))
        throw std::logic_error("apic access addr too large");
}

void
vmcs_intel_x64::check_control_x2apic_mode_and_virtual_apic_access()
{
    auto x2apic_mode = is_enabled_x2apic_mode();
    auto virtualized_apic = is_enabled_virtualized_apic();

    if (x2apic_mode && virtualized_apic)
        throw std::logic_error("apic accesses must be 0 if x2 apic mode is 1");
}

void
vmcs_intel_x64::check_control_virtual_interrupt_and_external_interrupt()
{
    auto virtual_interrupt_delivery = is_enabled_virtual_interrupt_delivery();
    auto external_interrupt_exiting = is_enabled_external_interrupt_exiting();

    if (virtual_interrupt_delivery && !external_interrupt_exiting)
        throw std::logic_error("external interrupt exiting must be 1 "
                               "if virtual interrupt delivery is 1");
}

void
vmcs_intel_x64::check_control_process_posted_interrupt_checks()
{
    if (!is_enabled_posted_interrupts())
        return;

    if (!is_enabled_virtual_interrupt_delivery())
        throw std::logic_error("virtual interrupt delivery must be 1 "
                               "if posted interrupts is 1");

    if (!is_enabled_ack_interrupt_on_exit())
        throw std::logic_error("ack interrupt on exit must be 1 "
                               "if posted interrupts is 1");

    auto vector = vmread(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR);

    if ((vector & 0xFFFFFFFFFFFFFF00) != 0)
        throw std::logic_error("bits 15:8 of the notification vector must "
                               "be 0 if posted interrupts is 1");

    auto addr = vmread(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL);

    if ((addr & 0x000000000000003F) != 0)
        throw std::logic_error("bits 5:0 of the interrupt descriptor addr "
                               "must be 0 if posted interrupts is 1");

    if (!is_physical_address_valid(addr))
        throw std::logic_error("interrupt descriptor addr too large");
}

void
vmcs_intel_x64::check_control_vpid_checks()
{
    if (!is_enabled_vpid())
        return;

    if (vmread(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER) == 0)
        throw std::logic_error("vpid cannot equal 0");
}

void
vmcs_intel_x64::check_control_enable_ept_checks()
{
    if (!is_enabled_ept())
        return;

    auto eptp = vmread(VMCS_EPT_POINTER_FULL);

    auto ia32_vmx_ept_vpid_cap_msr =
        m_intrinsics->read_msr(IA32_VMX_EPT_VPID_CAP_MSR);

    auto uncacheable = (ia32_vmx_ept_vpid_cap_msr & IA32_VMX_EPT_VPID_CAP_UC);
    auto write_back = (ia32_vmx_ept_vpid_cap_msr & IA32_VMX_EPT_VPID_CAP_WB);

    if ((eptp & EPTP_MEMORY_TYPE) == 0 && uncacheable == 0)
        throw std::logic_error("hardware does not support ept memory type: uncachable");

    if ((eptp & EPTP_MEMORY_TYPE) == 6 && write_back == 0)
        throw std::logic_error("hardware does not support ept memory type: write-back");

    if ((eptp & EPTP_MEMORY_TYPE) != 0 && (eptp & EPTP_MEMORY_TYPE) != 6)
        throw std::logic_error("unknown eptp memory type");

    if ((eptp & EPTP_PAGE_WALK_LENGTH) >> 3 != 3)
        throw std::logic_error("the ept walk-through length must be 1 less than 4, i.e. 3");

    auto ad = (ia32_vmx_ept_vpid_cap_msr & IA32_VMX_EPT_VPID_CAP_AD);

    if ((eptp & EPTP_ACCESSED_DIRTY_FLAGS_ENABLED) != 0 && ad == 0)
        throw std::logic_error("hardware does not support dirty / accessed flags for ept");

    if ((eptp & 0xFFFF000000000000) != 0 || (eptp & 0x0000000000000F80) != 0)
        throw std::logic_error("bits 11:7 and 63:48 of the eptp must be 0");
}

void
vmcs_intel_x64::check_control_unrestricted_guests()
{
    if (!is_enabled_unrestricted_guests())
        return;

    if (!is_enabled_ept())
        throw std::logic_error("enable ept must be 1 if unrestricted guest is 1");
}

void
vmcs_intel_x64::check_control_enable_vm_functions()
{
    if (!is_enabled_vm_functions())
        return;

    auto vmcs_vm_function_controls =
        vmread(VMCS_VM_FUNCTION_CONTROLS_FULL);

    auto ia32_vmx_vmfunc_msr =
        m_intrinsics->read_msr(IA32_VMX_VMFUNC_MSR);

    if ((~ia32_vmx_vmfunc_msr & vmcs_vm_function_controls) != 0)
        throw std::logic_error("unsupported vm function control bit set");

    if ((VM_FUNCTION_CONTROL_EPTP_SWITCHING & vmcs_vm_function_controls) == 0)
        return;

    if (!is_enabled_ept())
        throw std::logic_error("enable ept must be 1 if eptp switching is 1");

    auto eptp_list = vmread(VMCS_EPTP_LIST_ADDRESS_FULL);

    if ((eptp_list & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for eptp list address");

    if (!is_physical_address_valid(eptp_list))
        throw std::logic_error("eptp list address addr too large");
}

void
vmcs_intel_x64::check_control_enable_vmcs_shadowing()
{
    if (!is_enabled_vmcs_shadowing())
        return;

    auto vmcs_vmread_bitmap_address =
        vmread(VMCS_VMREAD_BITMAP_ADDRESS_FULL);

    auto vmcs_vmwrite_bitmap_address =
        vmread(VMCS_VMWRITE_BITMAP_ADDRESS_FULL);

    if ((vmcs_vmread_bitmap_address & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for the vmcs read bitmap address");

    if ((vmcs_vmwrite_bitmap_address & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for the vmcs write bitmap address");

    if (!is_physical_address_valid(vmcs_vmread_bitmap_address))
        throw std::logic_error("vmcs read bitmap address addr too large");

    if (!is_physical_address_valid(vmcs_vmwrite_bitmap_address))
        throw std::logic_error("vmcs write bitmap address addr too large");
}

void
vmcs_intel_x64::check_control_enable_ept_violation_checks()
{
    if (!is_enabled_ept_violation_ve())
        return;

    auto vmcs_virt_except_info_address =
        vmread(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL);

    if ((vmcs_virt_except_info_address & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for the vmcs virt except info address");

    if (!is_physical_address_valid(vmcs_virt_except_info_address))
        throw std::logic_error("vmcs virt except info address addr too large");
}

void
vmcs_intel_x64::checks_on_vm_exit_control_fields()
{
    check_control_vm_exit_ctls_reserved_properly_set();
    check_control_activate_and_save_premeption_timer_must_be_0();
    check_control_exit_msr_store_address();
    check_control_exit_msr_load_address();
}

void
vmcs_intel_x64::check_control_vm_exit_ctls_reserved_properly_set()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    auto allowed_zero = ((ia32_vmx_exit_ctls_msr >> 00) & 0x00000000FFFFFFFF);
    auto allowed_one = ((ia32_vmx_exit_ctls_msr >> 32) & 0x00000000FFFFFFFF);

    auto ctls = get_exit_ctls();
    auto ctls_lower = (ctls & 0x00000000FFFFFFFF);

    if ((allowed_zero & ctls_lower) != allowed_zero || (ctls_lower & ~allowed_one) != 0)
    {
        bferror << " failed: check_control_vm_exit_ctls_reserved_properly_set" << bfendl;
        bferror << "    - allowed_zero: " << view_as_pointer(allowed_zero) << bfendl;
        bferror << "    - allowed_one: " << view_as_pointer(allowed_one) << bfendl;
        bferror << "    - ctls: " << view_as_pointer(ctls) << bfendl;

        throw std::logic_error("invalid exit controls");
    }
}

void
vmcs_intel_x64::check_control_activate_and_save_premeption_timer_must_be_0()
{
    auto vmx_preemption_timer = is_enabled_vmx_preemption_timer();
    auto save_vmx_preemption_timer_on_exit = is_enabled_save_vmx_preemption_timer_on_exit();

    if (!vmx_preemption_timer && save_vmx_preemption_timer_on_exit)
        throw std::logic_error("save vmx preemption timer must be 0 "
                               "if activate vmx preemption timer is 0");
}

void
vmcs_intel_x64::check_control_exit_msr_store_address()
{
    auto msr_store_count = vmread(VMCS_VM_EXIT_MSR_STORE_COUNT);

    if (msr_store_count == 0)
        return;

    auto msr_store_addr = vmread(VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL);

    if ((msr_store_addr & 0x000000000000000F) != 0)
        throw std::logic_error("bits 3:0 must be 0 for the exit msr store address");

    if (!is_physical_address_valid(msr_store_addr))
        throw std::logic_error("exit msr store addr too large");

    auto msr_store_addr_end = msr_store_addr + (msr_store_count * 16) - 1;

    if (!is_physical_address_valid(msr_store_addr_end))
        throw std::logic_error("end of exit msr store area too large");
}

void
vmcs_intel_x64::check_control_exit_msr_load_address()
{
    auto msr_load_count = vmread(VMCS_VM_EXIT_MSR_LOAD_COUNT);

    if (msr_load_count == 0)
        return;

    auto msr_load_addr = vmread(VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL);

    if ((msr_load_addr & 0x000000000000000F) != 0)
        throw std::logic_error("bits 3:0 must be 0 for the exit msr load address");

    if (!is_physical_address_valid(msr_load_addr))
        throw std::logic_error("exit msr load addr too large");

    auto msr_load_addr_end = msr_load_addr + (msr_load_count * 16) - 1;

    if (!is_physical_address_valid(msr_load_addr_end))
        throw std::logic_error("end of exit msr load area too large");
}

void
vmcs_intel_x64::checks_on_vm_entry_control_fields()
{
    check_control_vm_entry_ctls_reserved_properly_set();
    check_control_event_injection_type_vector_checks();
    check_control_event_injection_delivery_ec_checks();
    check_control_event_injection_reserved_bits_checks();
    check_control_event_injection_ec_checks();
    check_control_event_injection_instr_length_checks();
    check_control_entry_msr_load_address();
}

void
vmcs_intel_x64::check_control_vm_entry_ctls_reserved_properly_set()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    auto allowed_zero = ((ia32_vmx_entry_ctls_msr >> 00) & 0x00000000FFFFFFFF);
    auto allowed_one = ((ia32_vmx_entry_ctls_msr >> 32) & 0x00000000FFFFFFFF);

    auto ctls = get_entry_ctls();
    auto ctls_lower = (ctls & 0x00000000FFFFFFFF);

    if ((allowed_zero & ctls_lower) != allowed_zero || (ctls_lower & ~allowed_one) != 0)
    {
        bferror << " failed: check_control_vm_entry_ctls_reserved_properly_set" << bfendl;
        bferror << "    - allowed_zero: " << view_as_pointer(allowed_zero) << bfendl;
        bferror << "    - allowed_one: " << view_as_pointer(allowed_one) << bfendl;
        bferror << "    - ctls: " << view_as_pointer(ctls) << bfendl;

        throw std::logic_error("invalid exit controls");
    }
}

void
vmcs_intel_x64::check_control_event_injection_type_vector_checks()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;

    if (type == 1)
        throw std::logic_error("interrupt information field type of 1 is reserved");

    if (!is_supported_monitor_trap_flag() && type == 7)
        throw std::logic_error("interrupt information field type of 7 "
                               "is reserved on this hardware");

    auto vector = interrupt_info_field & VM_INTERRUPT_INFORMATION_VECTOR;

    if (type == 2 && vector != 2)
        throw std::logic_error("interrupt information field vector must be "
                               "2 if the type field is 2 (NMI)");

    if (type == 3 && vector > 31)
        throw std::logic_error("interrupt information field vector must be "
                               "0->31 if the type field is 3 (HE)");

    if (type == 7 && vector != 0)
        throw std::logic_error("interrupt information field vector must be "
                               "0 if the type field is 7 (other)");
}

void
vmcs_intel_x64::check_control_event_injection_delivery_ec_checks()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_DELIVERY_ERROR) == 0)
        return;

    auto cr0 = vmread(VMCS_GUEST_CR0);

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;
    auto vector = (interrupt_info_field & VM_INTERRUPT_INFORMATION_VECTOR) >> 0;

    if (is_enabled_unrestricted_guests())
    {
        if ((cr0 & CRO_PE_PROTECTION_ENABLE) == 0)
            throw std::logic_error("unrestricted guest must be 0 or PE must "
                                   "be enabled in cr0 if deliver error code bit is set");
    }

    if (type != 3)
        throw std::logic_error("interrupt information field type must be "
                               "3 if deliver error code bit is set");

    switch (vector)
    {
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            break;

        default:
            throw std::logic_error("vector must indicate exception that would nomrally "
                                   "deliver an error code if deliver error code bit is set");
    }
}

void
vmcs_intel_x64::check_control_event_injection_reserved_bits_checks()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    if ((interrupt_info_field & 0x000000007FFFF000) != 0)
        throw std::logic_error("reserved bits of the interrupt info field must be 0");
}

void
vmcs_intel_x64::check_control_event_injection_ec_checks()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    auto exception_error_code =
        vmread(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_DELIVERY_ERROR) == 0)
        return;

    if ((exception_error_code & 0x00000000FFFF8000) != 0)
        throw std::logic_error("bits 31:15 of the exception error code field must be 0 "
                               "if deliver error code bit is set in the interrupt info field");
}

void
vmcs_intel_x64::check_control_event_injection_instr_length_checks()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    auto instruction_length =
        vmread(VMCS_VM_ENTRY_INSTRUCTION_LENGTH);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;

    switch (type)
    {
        case 4: // Software interrupt
        case 5: // Privileged software exception
        case 6: // Software exception
            break;

        default:
            return;
    }

    if ((instruction_length < 1) || (instruction_length > 15))
        throw std::logic_error("instruction length must be in the range of 1-15 if type is 4, 5, 6");
}

void
vmcs_intel_x64::check_control_entry_msr_load_address()
{
    auto msr_load_count = vmread(VMCS_VM_ENTRY_MSR_LOAD_COUNT);

    if (msr_load_count == 0)
        return;

    auto msr_load_addr = vmread(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL);

    if ((msr_load_addr & 0x000000000000000F) != 0)
        throw std::logic_error("bits 3:0 must be 0 for the entry msr load address");

    if (!is_physical_address_valid(msr_load_addr))
        throw std::logic_error("entry msr load addr too large");

    auto msr_load_addr_end = msr_load_addr + (msr_load_count * 16) - 1;

    if (!is_physical_address_valid(msr_load_addr_end))
        throw std::logic_error("end of entry msr load area too large");
}
