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


vmcs_ut::vmcs_ut()
{
}

bool
vmcs_ut::init()
{
    return true;
}

bool
vmcs_ut::fini()
{
    return true;
}

bool
vmcs_ut::list()
{
    // Base vmcs tests
    this->test_no_intrinsics();
    this->test_launch_vmclear_failure();
    this->test_launch_vmptrld_failure();
    this->test_launch_vmwrite_failure();
    this->test_launch_vmread_failure();
    this->test_launch_success();

    // VMCS Control checks
    this->test_check_control_pin_based_ctls_reserved_properly_set_success();
    this->test_check_control_pin_based_ctls_reserved_properly_set_fail_lower();
    this->test_check_control_pin_based_ctls_reserved_properly_set_fail_upper();

    this->test_check_control_proc_based_ctls_reserved_properly_set_success();
    this->test_check_control_proc_based_ctls_reserved_properly_set_fail_lower();
    this->test_check_control_proc_based_ctls_reserved_properly_set_fail_upper();

    this->test_check_control_proc_based_ctls2_reserved_properly_set_success();
    this->test_check_control_proc_based_ctls2_reserved_properly_set_fail_lower();
    this->test_check_control_proc_based_ctls2_reserved_properly_set_fail_upper();

    this->test_check_control_cr3_count_less_then_4_fail();
    this->test_check_control_cr3_count_less_then_4_success();

    this->test_check_control_io_bitmap_address_bits_success();
    this->test_check_control_io_bitmap_address_bits_fail_alignment_a();
    this->test_check_control_io_bitmap_address_bits_fail_alignment_b();
    this->test_check_control_io_bitmap_address_bits_fail_size_a();
    this->test_check_control_io_bitmap_address_bits_fail_size_b();

    this->test_check_control_msr_bitmap_address_bits_success();
    this->test_check_control_msr_bitmap_address_bits_fail_alignment();
    this->test_check_control_msr_bitmap_address_bits_fail_size();

    this->test_check_control_tpr_shadow_and_virtual_apic_success_enabled();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_null_phys_page();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_unaligned();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_bad_physaddr();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_virtual_interrupt_delivery_unsupported();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_invalid_tpr_threshold();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_virtual_apic_unsupported();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_invalid_apic_vaddr();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_vtpr_range_check();
    this->test_check_control_tpr_shadow_and_virtual_apic_success_disabled();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_x2apic_enabled();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_apic_reg_virt_enabled();
    this->test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_virtual_interrupt_delivery_enabled();

    this->test_check_control_nmi_exiting_and_virtual_nmi_success();
    this->test_check_control_nmi_exiting_and_virtual_nmi_fail_vnmis_and_nmi_exiting_enabled();

    this->test_check_control_virtual_nmi_and_nmi_window_success_one();
    this->test_check_control_virtual_nmi_and_nmi_window_success_two();
    this->test_check_control_virtual_nmi_and_nmi_window_success_three();
    this->test_check_control_virtual_nmi_and_nmi_window_fail_nmi_window_exiting_enabled_vnmis_disabled();

    this->test_check_control_virtual_apic_address_bits_success_enabled();
    this->test_check_control_virtual_apic_address_bits_success_disabled_one();
    this->test_check_control_virtual_apic_address_bits_success_disabled_two();
    this->test_check_control_virtual_apic_address_bits_fail_null_physaddr();
    this->test_check_control_virtual_apic_address_bits_fail_unaligned_physaddr();
    this->test_check_control_virtual_apic_address_bits_fail_invalid_physaddr();

    this->test_check_control_x2apic_mode_and_virtual_apic_access_success_one();
    this->test_check_control_x2apic_mode_and_virtual_apic_access_success_two();
    this->test_check_control_x2apic_mode_and_virtual_apic_access_success_three();
    this->test_check_control_x2apic_mode_and_virtual_apic_access_fail();

    this->test_check_control_virtual_interrupt_and_external_interrupt_success_one();
    this->test_check_control_virtual_interrupt_and_external_interrupt_success_two();
    this->test_check_control_virtual_interrupt_and_external_interrupt_success_three();
    this->test_check_control_virtual_interrupt_and_external_interrupt_fail();

    this->test_check_control_process_posted_interrupt_checks_success_disabled();
    this->test_check_control_process_posted_interrupt_checks_success_enabled();
    this->test_check_control_process_posted_interrupt_checks_fail_no_virtual_interrupt_delivery();
    this->test_check_control_process_posted_interrupt_checks_fail_no_ack_interrupt_on_exit();
    this->test_check_control_process_posted_interrupt_checks_fail_invalid_vector();
    this->test_check_control_process_posted_interrupt_checks_fail_invalid_alignment();
    this->test_check_control_process_posted_interrupt_checks_fail_invalid_physaddr();

    this->test_check_control_vpid_checks_success_early();
    this->test_check_control_vpid_checks_success();
    this->test_check_control_vpid_checks_fail_invalid_vpid();

    this->test_check_control_enable_ept_checks_success_early();
    this->test_check_control_enable_ept_checks_success();
    this->test_check_control_enable_ept_checks_fail_invalid_uncache();
    this->test_check_control_enable_ept_checks_fail_invalid_writeback();
    this->test_check_control_enable_ept_checks_fail_invalid_memtype();
    this->test_check_control_enable_ept_checks_fail_invalid_page_walk_length();
    this->test_check_control_enable_ept_checks_fail_no_dirty_support();
    this->test_check_control_enable_ept_checks_fail_invalid_eptp_one();
    this->test_check_control_enable_ept_checks_fail_invalid_eptp_two();

    this->test_check_control_unrestricted_guests_success();
    this->test_check_control_unrestricted_guests_success_early();
    this->test_check_control_unrestricted_guests_fail_no_ept();

    this->test_check_control_enable_vm_functions_success_early();
    this->test_check_control_enable_vm_functions_success();
    this->test_check_control_enable_vm_functions_fail_vm_func_ctrl_bit();
    this->test_check_control_enable_vm_functions_success_no_eptp_switching();
    this->test_check_control_enable_vm_functions_fail_no_ept_enabled();
    this->test_check_control_enable_vm_functions_fail_invalid_alignment();
    this->test_check_control_enable_vm_functions_fail_invalid_physaddr();

    this->test_check_control_enable_vmcs_shadowing_success_early();
    this->test_check_control_enable_vmcs_shadowing_success();
    this->test_check_control_enable_vmcs_shadowing_fail_vmread_bitmap_unaligned();
    this->test_check_control_enable_vmcs_shadowing_fail_vmwrite_bitmap_unaligned();
    this->test_check_control_enable_vmcs_shadowing_fail_vmread_bitmap_invalid_physaddr();
    this->test_check_control_enable_vmcs_shadowing_fail_vmwrite_bitmap_invalid_physaddr();

    this->test_check_control_enable_ept_violation_checks_early_success();
    this->test_check_control_enable_ept_violation_checks_success();
    this->test_check_control_enable_ept_violation_checks_fail_unaligned();
    this->test_check_control_enable_ept_violation_checks_fail_invalid_physaddr();

    // exit controls
    this->test_check_control_vm_exit_ctls_reserved_properly_set_success();
    this->test_check_control_vm_exit_ctls_reserved_properly_set_fail_lower();
    this->test_check_control_vm_exit_ctls_reserved_properly_set_fail_upper();

    this->test_check_control_activate_and_save_premeption_timer_must_be_0_success_one();
    this->test_check_control_activate_and_save_premeption_timer_must_be_0_success_two();
    this->test_check_control_activate_and_save_premeption_timer_must_be_0_success_three();
    this->test_check_control_activate_and_save_premeption_timer_must_be_0_fail();

    this->test_check_control_exit_msr_store_address_success_early();
    this->test_check_control_exit_msr_store_address_success();
    this->test_check_control_exit_msr_store_address_fail_unaligned();
    this->test_check_control_exit_msr_store_address_fail_invalid_start_physaddr();
    this->test_check_control_exit_msr_store_address_fail_invalid_end_physaddr();

    this->test_check_control_exit_msr_load_address_success_early();
    this->test_check_control_exit_msr_load_address_success();
    this->test_check_control_exit_msr_load_address_fail_unaligned();
    this->test_check_control_exit_msr_load_address_fail_invalid_start_physaddr();
    this->test_check_control_exit_msr_load_address_fail_invalid_end_physaddr();

    // entry controls
    this->test_check_control_vm_entry_ctls_reserved_properly_set_success();
    this->test_check_control_vm_entry_ctls_reserved_properly_set_fail_lower();
    this->test_check_control_vm_entry_ctls_reserved_properly_set_fail_upper();

    this->test_check_control_event_injection_type_vector_checks_early_success();
    this->test_check_control_event_injection_type_vector_checks_success();
    this->test_check_control_event_injection_type_vector_checks_fail_reserved_set();
    this->test_check_control_event_injection_type_vector_checks_fail_no_monitor_trap_support();
    this->test_check_control_event_injection_type_vector_checks_fail_nmi_vector_mismatch();
    this->test_check_control_event_injection_type_vector_checks_fail_hw_exception_mismatch();
    this->test_check_control_event_injection_type_vector_checks_fail_other_blank_vector();

    this->test_check_control_event_injection_delivery_ec_checks_early_success_one();
    this->test_check_control_event_injection_delivery_ec_checks_early_success_two();
    this->test_check_control_event_injection_delivery_ec_checks_success_with_unrestricted_guests();
    this->test_check_control_event_injection_delivery_ec_checks_fail_invalid_cr0();
    this->test_check_control_event_injection_delivery_ec_checks_success_without_unrestricted_guests();
    this->test_check_control_event_injection_delivery_ec_checks_fail_invalid_information_field();
    this->test_check_control_event_injection_delivery_ec_checks_fail_invalid_exception();

    this->test_check_control_event_injection_reserved_bits_checks_early_success();
    this->test_check_control_event_injection_reserved_bits_checks_success();
    this->test_check_control_event_injection_reserved_bits_checks_fail();

    this->test_check_control_event_injection_ec_checks_early_success_one();
    this->test_check_control_event_injection_ec_checks_early_success_two();
    this->test_check_control_event_injection_ec_checks_early_success();
    this->test_check_control_event_injection_ec_checks_fail();

    this->test_check_control_event_injection_instr_length_checks_early_success_one();
    this->test_check_control_event_injection_instr_length_checks_early_success_two();
    this->test_check_control_event_injection_instr_length_checks_success();
    this->test_check_control_event_injection_instr_length_checks_fail_invalid_instr_length_high();
    this->test_check_control_event_injection_instr_length_checks_fail_invalid_instr_length_low();

    this->test_check_control_entry_msr_load_address_early_success();
    this->test_check_control_entry_msr_load_address_success();
    this->test_check_control_entry_msr_load_address_fail_unaligned();
    this->test_check_control_entry_msr_load_address_fail_invalid_start_physaddr();
    this->test_check_control_entry_msr_load_address_fail_invalid_end_physaddr();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vmcs_ut);
}
