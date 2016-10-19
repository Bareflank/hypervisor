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

using namespace intel_x64;

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
    check_control_enable_pml_checks();
    check_control_unrestricted_guests();
    check_control_enable_vm_functions();
    check_control_enable_vmcs_shadowing();
    check_control_enable_ept_violation_checks();
}

void
vmcs_intel_x64::check_control_ctls_reserved_properly_set(uint64_t msr_addr, uint64_t ctls,
        const std::string &name)
{
    using namespace intel_x64;

    auto allowed0 = (msrs::get(msr_addr) & 0x00000000FFFFFFFFUL);
    auto allowed1 = ((msrs::get(msr_addr) >> 32) & 0x00000000FFFFFFFFUL);

    if ((allowed0 & ctls) != allowed0)
    {
        bferror << " failed: check_control_ctls_reserved_properly_set" << bfendl;
        bferror << "    - allowed0: " << view_as_pointer(allowed0) << bfendl;
        bferror << "    - bad ctls: " << view_as_pointer(ctls) << bfendl;

        throw std::logic_error(std::string("invalid ") + name);
    }

    if ((ctls & ~allowed1) != 0UL)
    {
        bferror << " failed: check_control_ctls_reserved_properly_set" << bfendl;
        bferror << "    - allowed1: " << view_as_pointer(allowed1) << bfendl;
        bferror << "    - bad ctls: " << view_as_pointer(ctls) << bfendl;

        throw std::logic_error(std::string("invalid ") + name);
    }
}

void
vmcs_intel_x64::check_control_pin_based_ctls_reserved_properly_set()
{
    auto msr_addr = msrs::ia32_vmx_true_pinbased_ctls::addr;
    auto ctls = vmcs::pin_based_vm_execution_controls::get();
    auto name = vmcs::pin_based_vm_execution_controls::name;

    this->check_control_ctls_reserved_properly_set(msr_addr, ctls, name);
}

void
vmcs_intel_x64::check_control_proc_based_ctls_reserved_properly_set()
{
    auto msr_addr = msrs::ia32_vmx_true_procbased_ctls::addr;
    auto ctls = vmcs::primary_processor_based_vm_execution_controls::get();
    auto name = vmcs::primary_processor_based_vm_execution_controls::name;

    this->check_control_ctls_reserved_properly_set(msr_addr, ctls, name);
}

// TODO: this will be updated on the next PR
void
vmcs_intel_x64::check_control_proc_based_ctls2_reserved_properly_set()
{
    auto ia32_vmx_procbased_ctls2_msr = msrs::ia32_vmx_procbased_ctls2::get();

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
    if (vmcs::cr3_target_count::get() > 4)
        throw std::logic_error("cr3 target count > 4");
}

void
vmcs_intel_x64::check_control_io_bitmap_address_bits()
{
    if (!vmcs::primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled())
        return;

    auto addr_a = vm::read(VMCS_ADDRESS_OF_IO_BITMAP_A);
    auto addr_b = vm::read(VMCS_ADDRESS_OF_IO_BITMAP_B);

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
    if (!vmcs::primary_processor_based_vm_execution_controls::use_msr_bitmaps::is_enabled())
        return;

    auto addr = vm::read(VMCS_ADDRESS_OF_MSR_BITMAPS);

    if ((addr & 0x0000000000000FFF) != 0)
        throw std::logic_error("msr bitmap addr not page aligned");

    if (!is_physical_address_valid(addr))
        throw std::logic_error("msr bitmap addr too large");
}

void
vmcs_intel_x64::check_control_tpr_shadow_and_virtual_apic()
{
    if (vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow::is_enabled())
    {
        auto phys_addr = vm::read(VMCS_VIRTUAL_APIC_ADDRESS);

        if (phys_addr == 0)
            throw std::logic_error("virtual apic physical addr is NULL");

        if ((phys_addr & 0x0000000000000FFF) != 0)
            throw std::logic_error("virtual apic addr not 4k aligned");

        if (!is_physical_address_valid(phys_addr))
            throw std::logic_error("virtual apic addr too large");

        if (is_enabled_virtual_interrupt_delivery())
            throw std::logic_error("tpr_shadow is enabled, but virtual interrupt delivery is enabled");

        auto tpr_threshold = vm::read(VMCS_TPR_THRESHOLD);

        if ((tpr_threshold & 0x00000000FFFFFFF0) != 0)
            throw std::logic_error("bits 31:4 of the tpr threshold must be 0");

        if (is_enabled_virtualized_apic())
            throw std::logic_error("tpr_shadow is enabled, but virtual apic is enabled");

        auto virt_addr = static_cast<uint8_t *>(g_mm->physint_to_virtptr(phys_addr));

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
    using namespace vmcs::pin_based_vm_execution_controls;

    if (!nmi_exiting::is_enabled() && virtual_nmis::is_enabled())
        throw std::logic_error("virtual NMI must be 0 if NMI exiting is 0");
}

void
vmcs_intel_x64::check_control_virtual_nmi_and_nmi_window()
{
    using namespace vmcs::pin_based_vm_execution_controls;
    using namespace vmcs::primary_processor_based_vm_execution_controls;

    if (!virtual_nmis::is_enabled() && nmi_window_exiting::is_enabled())
        throw std::logic_error("NMI window exiting must be 0 if virtual NMI is 0");
}

void
vmcs_intel_x64::check_control_virtual_apic_address_bits()
{
    if (!is_enabled_virtualized_apic())
        return;

    auto phys_addr = vm::read(VMCS_APIC_ACCESS_ADDRESS);

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
    using namespace vmcs::pin_based_vm_execution_controls;

    auto virtual_interrupt_delivery = is_enabled_virtual_interrupt_delivery();

    if (virtual_interrupt_delivery && !external_interrupt_exiting::is_enabled())
        throw std::logic_error("external_interrupt_exiting must be 1 "
                               "if virtual_interrupt_delivery is 1");
}

void
vmcs_intel_x64::check_control_process_posted_interrupt_checks()
{
    if (!vmcs::pin_based_vm_execution_controls::process_posted_interrupts::is_enabled())
        return;

    if (!is_enabled_virtual_interrupt_delivery())
        throw std::logic_error("virtual interrupt delivery must be 1 "
                               "if posted interrupts is 1");

    if (!vmcs::vm_exit_controls::acknowledge_interrupt_on_exit::is_enabled())
        throw std::logic_error("ack interrupt on exit must be 1 "
                               "if posted interrupts is 1");

    auto vector = vmcs::posted_interrupt_notification_vector::get();

    if ((vector & 0xFFFFFFFFFFFFFF00) != 0)
        throw std::logic_error("bits 15:8 of the notification vector must "
                               "be 0 if posted interrupts is 1");

    auto addr = vm::read(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS);

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

    if (vmcs::virtual_processor_identifier::get() == 0)
        throw std::logic_error("vpid cannot equal 0");
}

void
vmcs_intel_x64::check_control_enable_ept_checks()
{
    using namespace msrs::ia32_vmx_ept_vpid_cap;

    if (!is_enabled_ept())
        return;

    auto eptp = vm::read(VMCS_EPT_POINTER);

    if ((eptp & EPTP_MEMORY_TYPE) == 0 && memory_type_uncacheable_supported::get() == 0)
        throw std::logic_error("hardware does not support ept memory type: uncachable");

    if ((eptp & EPTP_MEMORY_TYPE) == 6 && memory_type_write_back_supported::get() == 0)
        throw std::logic_error("hardware does not support ept memory type: write-back");

    if ((eptp & EPTP_MEMORY_TYPE) != 0 && (eptp & EPTP_MEMORY_TYPE) != 6)
        throw std::logic_error("unknown eptp memory type");

    if ((eptp & EPTP_PAGE_WALK_LENGTH) >> 3 != 3)
        throw std::logic_error("the ept walk-through length must be 1 less than 4, i.e. 3");

    if ((eptp & EPTP_ACCESSED_DIRTY_FLAGS_ENABLED) != 0 && accessed_dirty_support::get() == 0)
        throw std::logic_error("hardware does not support dirty / accessed flags for ept");

    if ((eptp & 0x0000000000000F80) != 0)
        throw std::logic_error("bits 11:7 and 63:48 of the eptp must be 0");

    if (!is_physical_address_valid(eptp))
        throw std::logic_error("eptp must be a valid physical address");
}

void
vmcs_intel_x64::check_control_enable_pml_checks()
{
    auto pml_addr = vm::read(VMCS_PML_ADDRESS);

    if (is_enabled_pml() && !is_enabled_ept())
        throw std::logic_error("ept must be enabled if pml is enabled");

    if (!is_physical_address_valid(pml_addr))
        throw std::logic_error("pml address must be a valid physical address");

    if ((pml_addr & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 of the pml address must be 0");
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

    auto ia32_vmx_vmfunc_msr = msrs::ia32_vmx_vmfunc::get();
    auto vmcs_vm_function_controls = vm::read(VMCS_VM_FUNCTION_CONTROLS);

    if ((~ia32_vmx_vmfunc_msr & vmcs_vm_function_controls) != 0)
        throw std::logic_error("unsupported vm function control bit set");

    if ((VM_FUNCTION_CONTROL_EPTP_SWITCHING & vmcs_vm_function_controls) == 0)
        return;

    if (!is_enabled_ept())
        throw std::logic_error("enable ept must be 1 if eptp switching is 1");

    auto eptp_list = vm::read(VMCS_EPTP_LIST_ADDRESS);

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
        vm::read(VMCS_VMREAD_BITMAP_ADDRESS);

    auto vmcs_vmwrite_bitmap_address =
        vm::read(VMCS_VMWRITE_BITMAP_ADDRESS);

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
        vm::read(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS);

    if ((vmcs_virt_except_info_address & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for the vmcs virt except info address");

    if (!is_physical_address_valid(vmcs_virt_except_info_address))
        throw std::logic_error("vmcs virt except info address addr too large");
}

void
vmcs_intel_x64::checks_on_vm_exit_control_fields()
{
    check_control_vm_exit_ctls_reserved_properly_set();
    check_control_activate_and_save_preemption_timer_must_be_0();
    check_control_exit_msr_store_address();
    check_control_exit_msr_load_address();
}

void
vmcs_intel_x64::check_control_vm_exit_ctls_reserved_properly_set()
{
    auto msr_addr = msrs::ia32_vmx_true_exit_ctls::addr;
    auto ctls = vmcs::vm_exit_controls::get();
    auto name = vmcs::vm_exit_controls::name;

    this->check_control_ctls_reserved_properly_set(msr_addr, ctls, name);
}

void
vmcs_intel_x64::check_control_activate_and_save_preemption_timer_must_be_0()
{
    using namespace vmcs::pin_based_vm_execution_controls;
    using namespace vmcs::vm_exit_controls;

    if (!activate_vmx_preemption_timer::is_enabled() && save_vmx_preemption_timer_value::is_enabled())
        throw std::logic_error("save vmx preemption timer must be 0 "
                               "if activate vmx preemption timer is 0");
}

void
vmcs_intel_x64::check_control_exit_msr_store_address()
{
    auto msr_store_count = vmcs::vm_exit_msr_store_count::get();

    if (msr_store_count == 0)
        return;

    auto msr_store_addr = vm::read(VMCS_VM_EXIT_MSR_STORE_ADDRESS);

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
    auto msr_load_count = vmcs::vm_exit_msr_load_count::get();

    if (msr_load_count == 0)
        return;

    auto msr_load_addr = vm::read(VMCS_VM_EXIT_MSR_LOAD_ADDRESS);

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
    auto msr_addr = msrs::ia32_vmx_true_entry_ctls::addr;
    auto ctls = vmcs::vm_entry_controls::get();
    auto name = vmcs::vm_entry_controls::name;

    this->check_control_ctls_reserved_properly_set(msr_addr, ctls, name);
}

void
vmcs_intel_x64::check_control_event_injection_type_vector_checks()
{
    using namespace vmcs::vm_entry_interruption_information_field;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    if (!valid_bit::is_set())
        return;

    auto vector = vector::get();
    auto type = type::get();

    if (type == type::reserved)
        throw std::logic_error("interrupt information field type of 1 is reserved");

    if (!monitor_trap_flag::is_allowed1() && type == type::other_event)
        throw std::logic_error("interrupt information field type of 7 "
                               "is reserved on this hardware");

    if (type == type::non_maskable_interrupt && vector != 2)
        throw std::logic_error("interrupt information field vector must be "
                               "2 if the type field is 2 (NMI)");

    if (type == type::hardware_exception && vector > 31)
        throw std::logic_error("interrupt information field vector must be "
                               "at most 31 if the type field is 3 (HE)");

    if (type == type::other_event && vector != 0)
        throw std::logic_error("interrupt information field vector must be "
                               "0 if the type field is 7 (other)");
}

void
vmcs_intel_x64::check_control_event_injection_delivery_ec_checks()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    if (!valid_bit::is_set())
        return;

    auto type = type::get();
    auto vector = vector::get();

    if (is_enabled_unrestricted_guests())
    {
        if (vmcs::guest_cr0::protection_enable::get() == 0 && deliver_error_code_bit::is_set())
            throw std::logic_error("unrestricted guest must be 0 or PE must "
                                   "be enabled in cr0 if deliver_error_code_bit is set");
    }

    if (type != type::hardware_exception && deliver_error_code_bit::is_set())
        throw std::logic_error("interrupt information field type must be "
                               "3 if deliver_error_code_bit is set");

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
            if (deliver_error_code_bit::is_set())
                throw std::logic_error("vector must indicate exception that would normally "
                                       "deliver an error code if deliver_error_code_bit is set");
    }

    if (!deliver_error_code_bit::is_set())
        throw std::logic_error("deliver_error_code_bit must be 1");
}

void
vmcs_intel_x64::check_control_event_injection_reserved_bits_checks()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    if (!valid_bit::is_set())
        return;

    if (reserved::get() != 0)
        throw std::logic_error("reserved bits of the interrupt info field must be 0");
}

void
vmcs_intel_x64::check_control_event_injection_ec_checks()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    if (!valid_bit::is_set())
        return;

    if (!deliver_error_code_bit::is_set())
        return;

    if ((vmcs::vm_entry_exception_error_code::get() & 0x00000000FFFF8000UL) != 0)
        throw std::logic_error("bits 31:15 of the exception error code field must be 0 "
                               "if deliver error code bit is set in the interrupt info field");
}

void
vmcs_intel_x64::check_control_event_injection_instr_length_checks()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    if (!valid_bit::is_set())
        return;

    auto type = type::get();
    auto instruction_length = vmcs::vm_entry_instruction_length::get();

    switch (type)
    {
        case type::software_interrupt:
        case type::privileged_software_exception:
        case type::software_exception:
            break;

        default:
            return;
    }

    if (instruction_length == 0 && !is_supported_event_injection_instr_length_of_0())
        throw std::logic_error("instruction length must be greater than zero");

    if (instruction_length > 15)
        throw std::logic_error("instruction length must be in the range of 0-15 if type is 4, 5, 6");
}

void
vmcs_intel_x64::check_control_entry_msr_load_address()
{
    auto msr_load_count = vmcs::vm_entry_msr_load_count::get();

    if (msr_load_count == 0)
        return;

    auto msr_load_addr = vm::read(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS);

    if ((msr_load_addr & 0x000000000000000F) != 0)
        throw std::logic_error("bits 3:0 must be 0 for the entry msr load address");

    if (!is_physical_address_valid(msr_load_addr))
        throw std::logic_error("entry msr load addr too large");

    auto msr_load_addr_end = msr_load_addr + (msr_load_count * 16) - 1;

    if (!is_physical_address_valid(msr_load_addr_end))
        throw std::logic_error("end of entry msr load area too large");
}
