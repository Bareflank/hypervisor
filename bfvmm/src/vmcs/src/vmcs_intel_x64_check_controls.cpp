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
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <gsl/gsl>
#include <view_as_pointer.h>
#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_check.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>

#include <memory_manager/memory_manager_x64.h>

using namespace intel_x64;
using namespace vmcs;

void
check::control_vmx_controls_all()
{
    check::control_vm_execution_control_fields_all();
    check::control_vm_exit_control_fields_all();
    check::control_vm_entry_control_fields_all();
}

void
check::control_vm_execution_control_fields_all()
{
    check::control_pin_based_ctls_reserved_properly_set();
    check::control_proc_based_ctls_reserved_properly_set();
    check::control_proc_based_ctls2_reserved_properly_set();
    check::control_cr3_count_less_then_4();
    check::control_io_bitmap_address_bits();
    check::control_msr_bitmap_address_bits();
    check::control_tpr_shadow_and_virtual_apic();
    check::control_nmi_exiting_and_virtual_nmi();
    check::control_virtual_nmi_and_nmi_window();
    check::control_virtual_apic_address_bits();
    check::control_x2apic_mode_and_virtual_apic_access();
    check::control_virtual_interrupt_and_external_interrupt();
    check::control_process_posted_interrupt_checks();
    check::control_vpid_checks();
    check::control_enable_ept_checks();
    check::control_enable_pml_checks();
    check::control_unrestricted_guests();
    check::control_enable_vm_functions();
    check::control_enable_vmcs_shadowing();
    check::control_enable_ept_violation_checks();
}

void
check::control_pin_based_ctls_reserved_properly_set()
{
    auto msr_addr = msrs::ia32_vmx_true_pinbased_ctls::addr;
    auto ctls = vmcs::pin_based_vm_execution_controls::get();
    auto name = vmcs::pin_based_vm_execution_controls::name;

    check::control_reserved_properly_set(msr_addr, ctls, name);
}

void
check::control_proc_based_ctls_reserved_properly_set()
{
    auto msr_addr = msrs::ia32_vmx_true_procbased_ctls::addr;
    auto ctls = vmcs::primary_processor_based_vm_execution_controls::get();
    auto name = vmcs::primary_processor_based_vm_execution_controls::name;

    check::control_reserved_properly_set(msr_addr, ctls, name);
}

void
check::control_proc_based_ctls2_reserved_properly_set()
{
    if (!vmcs::secondary_processor_based_vm_execution_controls::exists())
        throw std::logic_error("the secondary controls field doesn't exist");

    auto msr_addr = msrs::ia32_vmx_procbased_ctls2::addr;
    auto ctls = vmcs::secondary_processor_based_vm_execution_controls::get();
    auto name = vmcs::secondary_processor_based_vm_execution_controls::name;

    check::control_reserved_properly_set(msr_addr, ctls, name);
}

void
check::control_cr3_count_less_then_4()
{
    if (vmcs::cr3_target_count::get() > 4)
        throw std::logic_error("cr3 target count > 4");
}

void
check::control_io_bitmap_address_bits()
{
    if (primary_processor_based_vm_execution_controls::use_io_bitmaps::is_disabled())
        return;

    auto addr_a = vmcs::address_of_io_bitmap_a::get();
    auto addr_b = vmcs::address_of_io_bitmap_b::get();

    if ((addr_a & 0x0000000000000FFF) != 0)
        throw std::logic_error("io bitmap a addr not page aligned");

    if ((addr_b & 0x0000000000000FFF) != 0)
        throw std::logic_error("io bitmap b addr not page aligned");

    if (!x64::is_physical_address_valid(addr_a))
        throw std::logic_error("io bitmap a addr too large");

    if (!x64::is_physical_address_valid(addr_b))
        throw std::logic_error("io bitmap b addr too large");
}

void
check::control_msr_bitmap_address_bits()
{
    if (primary_processor_based_vm_execution_controls::use_msr_bitmaps::is_disabled())
        return;

    auto addr = vmcs::address_of_msr_bitmaps::get();

    if ((addr & 0x0000000000000FFF) != 0)
        throw std::logic_error("msr bitmap addr not page aligned");

    if (!x64::is_physical_address_valid(addr))
        throw std::logic_error("msr bitmap addr too large");
}

void
check::control_tpr_shadow_and_virtual_apic()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    auto secondary_ctls_enabled = activate_secondary_controls::is_enabled();

    if (use_tpr_shadow::is_enabled())
    {
        auto phys_addr = vmcs::virtual_apic_address::get();

        if (phys_addr == 0)
            throw std::logic_error("virtual apic physical addr is NULL");

        if ((phys_addr & 0x0000000000000FFFUL) != 0)
            throw std::logic_error("virtual apic addr not 4k aligned");

        if (!x64::is_physical_address_valid(phys_addr))
            throw std::logic_error("virtual apic addr too large");

        if (secondary_ctls_enabled && virtual_interrupt_delivery::is_enabled_if_exists())
            throw std::logic_error("tpr_shadow is enabled, but virtual interrupt delivery is enabled");

        auto tpr_threshold = tpr_threshold::get();

        if ((tpr_threshold & 0xFFFFFFF0UL) != 0)
            throw std::logic_error("bits 31:4 of the tpr threshold must be 0");

        if (secondary_ctls_enabled && virtualize_apic_accesses::is_enabled_if_exists())
            throw std::logic_error("tpr_shadow is enabled, but virtual apic is enabled");

        auto virt_addr = static_cast<uint8_t *>(g_mm->physint_to_virtptr(phys_addr));

        if (virt_addr == nullptr)
            throw std::logic_error("virtual apic virtual addr is NULL");

        auto virt_addr_span = gsl::span<uint8_t>(virt_addr, 0x81);
        auto vtpr = virt_addr_span[0x80];
        auto vtpr_74 = (vtpr & 0xF0U) >> 4;
        auto tpr_threshold_30 = static_cast<uint8_t>(tpr_threshold & 0x0000000FUL);

        if (tpr_threshold_30 > vtpr_74)
            throw std::logic_error("invalid TPR threshold");
    }
    else
    {
        if (activate_secondary_controls::is_disabled())
            return;

        if (virtualize_x2apic_mode::is_enabled_if_exists())
            throw std::logic_error("virtualize_x2apic_mode must be disabled if tpr shadow is disabled");

        if (apic_register_virtualization::is_enabled_if_exists())
            throw std::logic_error("apic_register_virtualization must be disabled if tpr shadow is disabled");

        if (virtual_interrupt_delivery::is_enabled_if_exists())
            throw std::logic_error("virtual_interrupt_delivery must be disabled if tpr shadow is disabled");
    }
}

void
check::control_nmi_exiting_and_virtual_nmi()
{
    if (pin_based_vm_execution_controls::nmi_exiting::is_enabled())
        return;

    if (pin_based_vm_execution_controls::virtual_nmis::is_enabled())
        throw std::logic_error("virtual NMI must be 0 if NMI exiting is 0");
}

void
check::control_virtual_nmi_and_nmi_window()
{
    if (pin_based_vm_execution_controls::virtual_nmis::is_enabled())
        return;

    if (primary_processor_based_vm_execution_controls::nmi_window_exiting::is_enabled())
        throw std::logic_error("NMI window exiting must be 0 if virtual NMI is 0");
}

void
check::control_virtual_apic_address_bits()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::is_disabled_if_exists())
        return;

    auto phys_addr = vmcs::apic_access_address::get_if_exists();

    if (phys_addr == 0)
        throw std::logic_error("apic access physical addr is NULL");

    if ((phys_addr & 0x0000000000000FFF) != 0)
        throw std::logic_error("apic access addr not 4k aligned");

    if (!x64::is_physical_address_valid(phys_addr))
        throw std::logic_error("apic access addr too large");
}

void
check::control_x2apic_mode_and_virtual_apic_access()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::is_disabled_if_exists())
        return;

    if (secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::is_enabled_if_exists())
        throw std::logic_error("apic accesses must be 0 if x2 apic mode is 1");
}

void
check::control_virtual_interrupt_and_external_interrupt()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::is_disabled_if_exists())
        return;

    if (pin_based_vm_execution_controls::external_interrupt_exiting::is_disabled())
        throw std::logic_error("external_interrupt_exiting must be 1 "
                               "if virtual_interrupt_delivery is 1");
}

void
check::control_process_posted_interrupt_checks()
{
    if (pin_based_vm_execution_controls::process_posted_interrupts::is_disabled())
        return;

    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        throw std::logic_error("virtual interrupt delivery must be 1 "
                               "if posted interrupts is 1");

    if (secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::is_disabled_if_exists())
        throw std::logic_error("virtual interrupt delivery must be 1 "
                               "if posted interrupts is 1");

    if (vm_exit_controls::acknowledge_interrupt_on_exit::is_disabled())
        throw std::logic_error("ack interrupt on exit must be 1 "
                               "if posted interrupts is 1");

    auto vector = posted_interrupt_notification_vector::get();

    if ((vector & 0x000000000000FF00UL) != 0)
        throw std::logic_error("bits 15:8 of the notification vector must "
                               "be 0 if posted interrupts is 1");

    auto addr = vmcs::posted_interrupt_descriptor_address::get();

    if ((addr & 0x000000000000003FUL) != 0)
        throw std::logic_error("bits 5:0 of the interrupt descriptor addr "
                               "must be 0 if posted interrupts is 1");

    if (!x64::is_physical_address_valid(addr))
        throw std::logic_error("interrupt descriptor addr too large");
}

void
check::control_vpid_checks()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_vpid::is_disabled_if_exists())
        return;

    if (virtual_processor_identifier::get_if_exists() == 0)
        throw std::logic_error("vpid cannot equal 0");
}

void
check::control_enable_ept_checks()
{
    using namespace msrs::ia32_vmx_ept_vpid_cap;
    using namespace vmcs::ept_pointer;

    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_ept::is_disabled_if_exists())
        return;

    auto mem_type = vmcs::ept_pointer::memory_type::get_if_exists();

    if (mem_type == memory_type::uncacheable && !memory_type_uncacheable_supported::get())
        throw std::logic_error("hardware does not support ept memory type: uncachable");

    if (mem_type == memory_type::write_back && !memory_type_write_back_supported::get())
        throw std::logic_error("hardware does not support ept memory type: write-back");

    if (mem_type != memory_type::uncacheable && mem_type != memory_type::write_back)
        throw std::logic_error("unknown eptp memory type");

    if (page_walk_length_minus_one::get_if_exists() != 3)
        throw std::logic_error("the ept walk-through length must be 1 less than 4, i.e. 3");

    if (accessed_and_dirty_flags::is_enabled_if_exists() && !accessed_dirty_support::get())
        throw std::logic_error("hardware does not support dirty / accessed flags for ept");

    if (ept_pointer::reserved::get_if_exists() != 0)
        throw std::logic_error("bits 11:7 and 63:48 of the eptp must be 0");
}

void
check::control_enable_pml_checks()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_pml::is_disabled_if_exists())
        return;

    auto pml_addr = vmcs::pml_address::get_if_exists();

    if (secondary_processor_based_vm_execution_controls::enable_ept::is_disabled_if_exists())
        throw std::logic_error("ept must be enabled if pml is enabled");

    if (!x64::is_physical_address_valid(pml_addr))
        throw std::logic_error("pml address must be a valid physical address");

    if ((pml_addr & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 of the pml address must be 0");
}

void
check::control_unrestricted_guests()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::unrestricted_guest::is_disabled_if_exists())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_ept::is_disabled_if_exists())
        throw std::logic_error("enable ept must be 1 if unrestricted guest is 1");
}

void
check::control_enable_vm_functions()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_vm_functions::is_disabled_if_exists())
        return;

    if (!vmcs::vm_function_controls::exists())
        return;

    if ((~msrs::ia32_vmx_vmfunc::get() & vmcs::vm_function_controls::get()) != 0)
        throw std::logic_error("unsupported vm function control bit set");

    if (vmcs::vm_function_controls::eptp_switching::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_ept::is_disabled_if_exists())
        throw std::logic_error("enable ept must be 1 if eptp switching is 1");

    auto eptp_list = vmcs::eptp_list_address::get_if_exists();

    if ((eptp_list & 0x0000000000000FFFU) != 0)
        throw std::logic_error("bits 11:0 must be 0 for eptp list address");

    if (!x64::is_physical_address_valid(eptp_list))
        throw std::logic_error("eptp list address addr too large");
}

void
check::control_enable_vmcs_shadowing()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::vmcs_shadowing::is_disabled_if_exists())
        return;

    auto vmcs_vmread_bitmap_address = vmread_bitmap_address::get_if_exists();
    auto vmcs_vmwrite_bitmap_address = vmwrite_bitmap_address::get_if_exists();

    if ((vmcs_vmread_bitmap_address & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for the vmcs read bitmap address");

    if ((vmcs_vmwrite_bitmap_address & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for the vmcs write bitmap address");

    if (!x64::is_physical_address_valid(vmcs_vmread_bitmap_address))
        throw std::logic_error("vmcs read bitmap address addr too large");

    if (!x64::is_physical_address_valid(vmcs_vmwrite_bitmap_address))
        throw std::logic_error("vmcs write bitmap address addr too large");
}

void
check::control_enable_ept_violation_checks()
{
    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::ept_violation_ve::is_disabled_if_exists())
        return;

    auto vmcs_virt_except_info_address =
        virtualization_exception_information_address::get_if_exists();

    if ((vmcs_virt_except_info_address & 0x0000000000000FFF) != 0)
        throw std::logic_error("bits 11:0 must be 0 for the vmcs virt except info address");

    if (!x64::is_physical_address_valid(vmcs_virt_except_info_address))
        throw std::logic_error("vmcs virt except info address addr too large");
}

void
check::control_vm_exit_control_fields_all()
{
    check::control_vm_exit_ctls_reserved_properly_set();
    check::control_activate_and_save_preemption_timer_must_be_0();
    check::control_exit_msr_store_address();
    check::control_exit_msr_load_address();
}

void
check::control_vm_exit_ctls_reserved_properly_set()
{
    auto msr_addr = msrs::ia32_vmx_true_exit_ctls::addr;
    auto ctls = vmcs::vm_exit_controls::get();
    auto name = vmcs::vm_exit_controls::name;

    check::control_reserved_properly_set(msr_addr, ctls, name);
}

void
check::control_activate_and_save_preemption_timer_must_be_0()
{
    if (pin_based_vm_execution_controls::activate_vmx_preemption_timer::is_enabled())
        return;

    if (vm_exit_controls::save_vmx_preemption_timer_value::is_enabled())
        throw std::logic_error("save vmx preemption timer must be 0 "
                               "if activate vmx preemption timer is 0");
}

void
check::control_exit_msr_store_address()
{
    auto msr_store_count = vm_exit_msr_store_count::get();

    if (msr_store_count == 0)
        return;

    auto msr_store_addr = vmcs::vm_exit_msr_store_address::get();

    if ((msr_store_addr & 0x000000000000000F) != 0)
        throw std::logic_error("bits 3:0 must be 0 for the exit msr store address");

    if (!x64::is_physical_address_valid(msr_store_addr))
        throw std::logic_error("exit msr store addr too large");

    auto msr_store_addr_end = msr_store_addr + (msr_store_count * 16) - 1;

    if (!x64::is_physical_address_valid(msr_store_addr_end))
        throw std::logic_error("end of exit msr store area too large");
}

void
check::control_exit_msr_load_address()
{
    auto msr_load_count = vm_exit_msr_load_count::get();

    if (msr_load_count == 0)
        return;

    auto msr_load_addr = vmcs::vm_exit_msr_load_address::get();

    if ((msr_load_addr & 0x000000000000000F) != 0)
        throw std::logic_error("bits 3:0 must be 0 for the exit msr load address");

    if (!x64::is_physical_address_valid(msr_load_addr))
        throw std::logic_error("exit msr load addr too large");

    auto msr_load_addr_end = msr_load_addr + (msr_load_count * 16) - 1;

    if (!x64::is_physical_address_valid(msr_load_addr_end))
        throw std::logic_error("end of exit msr load area too large");
}

void
check::control_vm_entry_control_fields_all()
{
    check::control_vm_entry_ctls_reserved_properly_set();
    check::control_event_injection_type_vector_checks();
    check::control_event_injection_delivery_ec_checks();
    check::control_event_injection_reserved_bits_checks();
    check::control_event_injection_ec_checks();
    check::control_event_injection_instr_length_checks();
    check::control_entry_msr_load_address();
}

void
check::control_vm_entry_ctls_reserved_properly_set()
{
    auto msr_addr = msrs::ia32_vmx_true_entry_ctls::addr;
    auto ctls = vm_entry_controls::get();
    auto name = vm_entry_controls::name;

    check::control_reserved_properly_set(msr_addr, ctls, name);
}

void
check::control_event_injection_type_vector_checks()
{
    using namespace vm_entry_interruption_information_field;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    if (vm_entry_interruption_information_field::valid_bit::is_disabled())
        return;

    auto vector = vm_entry_interruption_information_field::vector::get();
    auto type = vm_entry_interruption_information_field::interruption_type::get();

    if (type == interruption_type::reserved)
        throw std::logic_error("interrupt information field type of 1 is reserved");

    if (!monitor_trap_flag::is_allowed1() && type == interruption_type::other_event)
        throw std::logic_error("interrupt information field type of 7 "
                               "is reserved on this hardware");

    if (type == interruption_type::non_maskable_interrupt && vector != 2)
        throw std::logic_error("interrupt information field vector must be "
                               "2 if the type field is 2 (NMI)");

    if (type == interruption_type::hardware_exception && vector > 31)
        throw std::logic_error("interrupt information field vector must be "
                               "at most 31 if the type field is 3 (HE)");

    if (type == interruption_type::other_event && vector != 0)
        throw std::logic_error("interrupt information field vector must be "
                               "0 if the type field is 7 (other)");
}

void
check::control_event_injection_delivery_ec_checks()
{
    using namespace vm_entry_interruption_information_field;
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vm_entry_interruption_information_field::valid_bit::is_disabled())
        return;

    auto type = vm_entry_interruption_information_field::interruption_type::get();
    auto vector = vm_entry_interruption_information_field::vector::get();

    if (unrestricted_guest::is_enabled() && activate_secondary_controls::is_enabled())
    {
        if (guest_cr0::protection_enable::is_disabled() && deliver_error_code_bit::is_enabled())
            throw std::logic_error("unrestricted guest must be 0 or PE must "
                                   "be enabled in cr0 if deliver_error_code_bit is set");
    }

    if (type != interruption_type::hardware_exception && deliver_error_code_bit::is_enabled())
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
            if (deliver_error_code_bit::is_enabled())
                throw std::logic_error("vector must indicate exception that would normally "
                                       "deliver an error code if deliver_error_code_bit is set");
    }

    if (deliver_error_code_bit::is_disabled())
        throw std::logic_error("deliver_error_code_bit must be 1");
}

void
check::control_event_injection_reserved_bits_checks()
{
    if (vm_entry_interruption_information_field::valid_bit::is_disabled())
        return;

    if (vm_entry_interruption_information_field::reserved::get() != 0)
        throw std::logic_error("reserved bits of the interrupt info field must be 0");
}

void
check::control_event_injection_ec_checks()
{
    if (vm_entry_interruption_information_field::valid_bit::is_disabled())
        return;

    if (vm_entry_interruption_information_field::deliver_error_code_bit::is_disabled())
        return;

    if ((vm_entry_exception_error_code::get() & 0x00000000FFFF8000UL) != 0)
        throw std::logic_error("bits 31:15 of the exception error code field must be 0 "
                               "if deliver error code bit is set in the interrupt info field");
}

void
check::control_event_injection_instr_length_checks()
{
    using namespace vm_entry_interruption_information_field;

    if (vm_entry_interruption_information_field::valid_bit::is_disabled())
        return;

    auto type = vm_entry_interruption_information_field::interruption_type::get();
    auto instruction_length = vm_entry_instruction_length::get();

    switch (type)
    {
        case interruption_type::software_interrupt:
        case interruption_type::privileged_software_exception:
        case interruption_type::software_exception:
            break;

        default:
            return;
    }

    if (instruction_length == 0 && !msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get())
        throw std::logic_error("instruction length must be greater than zero");

    if (instruction_length > 15)
        throw std::logic_error("instruction length must be in the range of 0-15 if type is 4, 5, 6");
}

void
check::control_entry_msr_load_address()
{
    auto msr_load_count = vm_entry_msr_load_count::get();

    if (msr_load_count == 0)
        return;

    auto msr_load_addr = vmcs::vm_entry_msr_load_address::get();

    if ((msr_load_addr & 0x000000000000000F) != 0)
        throw std::logic_error("bits 3:0 must be 0 for the entry msr load address");

    if (!x64::is_physical_address_valid(msr_load_addr))
        throw std::logic_error("entry msr load addr too large");

    auto msr_load_addr_end = msr_load_addr + (msr_load_count * 16) - 1;

    if (!x64::is_physical_address_valid(msr_load_addr_end))
        throw std::logic_error("end of entry msr load area too large");
}
