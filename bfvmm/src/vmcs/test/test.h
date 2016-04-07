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

#ifndef TEST_H
#define TEST_H

#include <unittest.h>

class vmcs_ut : public unittest
{
public:

    vmcs_ut();
    ~vmcs_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:
    ///////////////////////////////////////////////////////////////////////////
    // Constructor test
    ///////////////////////////////////////////////////////////////////////////
    void test_no_intrinsics();

    ///////////////////////////////////////////////////////////////////////////
    // vmcs_intel_x64::launch
    ///////////////////////////////////////////////////////////////////////////
    void test_launch_create_vmcs_region_failure();
    void test_launch_create_exit_handler_stack_failure();
    void test_launch_vmclear_failure();
    void test_launch_vmptrld_failure();
    void test_launch_vmwrite_failure();
    void test_launch_vmread_failure();
    void test_launch_vmlaunch_failure();
    void test_launch_is_supported_host_address_space_size_failure();
    void test_launch_is_supported_ia_32e_mode_guest_failure();
    void test_launch_success();

    ///////////////////////////////////////////////////////////////////////////
    // vmcs_intel_x64::promote (can't test?)
    ///////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////
    // vmcs_intel_x64::check_vmcs_control_state
    ///////////////////////////////////////////////////////////////////////////
    void test_check_control_pin_based_ctls_reserved_properly_set_success();
    void test_check_control_pin_based_ctls_reserved_properly_set_fail_lower();
    void test_check_control_pin_based_ctls_reserved_properly_set_fail_upper();

    void test_check_control_proc_based_ctls_reserved_properly_set_success();
    void test_check_control_proc_based_ctls_reserved_properly_set_fail_lower();
    void test_check_control_proc_based_ctls_reserved_properly_set_fail_upper();

    void test_check_control_proc_based_ctls2_reserved_properly_set_success();
    void test_check_control_proc_based_ctls2_reserved_properly_set_fail_lower();
    void test_check_control_proc_based_ctls2_reserved_properly_set_fail_upper();

    void test_check_control_cr3_count_less_then_4_fail();
    void test_check_control_cr3_count_less_then_4_success();

    void test_check_control_io_bitmap_address_bits_success();
    void test_check_control_io_bitmap_address_bits_fail_alignment_a();
    void test_check_control_io_bitmap_address_bits_fail_alignment_b();
    void test_check_control_io_bitmap_address_bits_fail_size_a();
    void test_check_control_io_bitmap_address_bits_fail_size_b();

    void test_check_control_msr_bitmap_address_bits_success();
    void test_check_control_msr_bitmap_address_bits_fail_alignment();
    void test_check_control_msr_bitmap_address_bits_fail_size();

    void test_check_control_tpr_shadow_and_virtual_apic_success_enabled();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_null_phys_page();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_unaligned();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_bad_physaddr();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_virtual_interrupt_delivery_unsupported();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_invalid_tpr_threshold();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_virtual_apic_unsupported();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_invalid_apic_vaddr();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_vtpr_range_check();
    void test_check_control_tpr_shadow_and_virtual_apic_success_disabled();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_x2apic_enabled();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_apic_reg_virt_enabled();
    void test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_virtual_interrupt_delivery_enabled();

    void test_check_control_nmi_exiting_and_virtual_nmi_success();
    void test_check_control_nmi_exiting_and_virtual_nmi_fail_vnmis_and_nmi_exiting_enabled();

    void test_check_control_virtual_nmi_and_nmi_window_success_one();
    void test_check_control_virtual_nmi_and_nmi_window_success_two();
    void test_check_control_virtual_nmi_and_nmi_window_success_three();
    void test_check_control_virtual_nmi_and_nmi_window_fail_nmi_window_exiting_enabled_vnmis_disabled();

    void test_check_control_virtual_apic_address_bits_success_enabled();
    void test_check_control_virtual_apic_address_bits_success_disabled_one();
    void test_check_control_virtual_apic_address_bits_success_disabled_two();
    void test_check_control_virtual_apic_address_bits_fail_null_physaddr();
    void test_check_control_virtual_apic_address_bits_fail_unaligned_physaddr();
    void test_check_control_virtual_apic_address_bits_fail_invalid_physaddr();

    void test_check_control_x2apic_mode_and_virtual_apic_access_success_one();
    void test_check_control_x2apic_mode_and_virtual_apic_access_success_two();
    void test_check_control_x2apic_mode_and_virtual_apic_access_success_three();
    void test_check_control_x2apic_mode_and_virtual_apic_access_fail();

    void test_check_control_virtual_interrupt_and_external_interrupt_success_one();
    void test_check_control_virtual_interrupt_and_external_interrupt_success_two();
    void test_check_control_virtual_interrupt_and_external_interrupt_success_three();
    void test_check_control_virtual_interrupt_and_external_interrupt_fail();

    void test_check_control_process_posted_interrupt_checks_success_disabled();
    void test_check_control_process_posted_interrupt_checks_success_enabled();
    void test_check_control_process_posted_interrupt_checks_fail_no_virtual_interrupt_delivery();
    void test_check_control_process_posted_interrupt_checks_fail_no_ack_interrupt_on_exit();
    void test_check_control_process_posted_interrupt_checks_fail_invalid_vector();
    void test_check_control_process_posted_interrupt_checks_fail_invalid_alignment();
    void test_check_control_process_posted_interrupt_checks_fail_invalid_physaddr();

    void test_check_control_vpid_checks_success_early();
    void test_check_control_vpid_checks_success();
    void test_check_control_vpid_checks_fail_invalid_vpid();

    void test_check_control_enable_ept_checks_success_early();
    void test_check_control_enable_ept_checks_success();
    void test_check_control_enable_ept_checks_fail_invalid_uncache();
    void test_check_control_enable_ept_checks_fail_invalid_writeback();
    void test_check_control_enable_ept_checks_fail_invalid_memtype();
    void test_check_control_enable_ept_checks_fail_invalid_page_walk_length();
    void test_check_control_enable_ept_checks_fail_no_dirty_support();
    void test_check_control_enable_ept_checks_fail_invalid_eptp_one();
    void test_check_control_enable_ept_checks_fail_invalid_eptp_two();

    void test_check_control_unrestricted_guests_success();
    void test_check_control_unrestricted_guests_success_early();
    void test_check_control_unrestricted_guests_fail_no_ept();

    void test_check_control_enable_vm_functions_success_early();
    void test_check_control_enable_vm_functions_success();
    void test_check_control_enable_vm_functions_fail_vm_func_ctrl_bit();
    void test_check_control_enable_vm_functions_success_no_eptp_switching();
    void test_check_control_enable_vm_functions_fail_no_ept_enabled();
    void test_check_control_enable_vm_functions_fail_invalid_alignment();
    void test_check_control_enable_vm_functions_fail_invalid_physaddr();

    void test_check_control_enable_vmcs_shadowing_success_early();
    void test_check_control_enable_vmcs_shadowing_success();
    void test_check_control_enable_vmcs_shadowing_fail_vmread_bitmap_unaligned();
    void test_check_control_enable_vmcs_shadowing_fail_vmwrite_bitmap_unaligned();
    void test_check_control_enable_vmcs_shadowing_fail_vmread_bitmap_invalid_physaddr();
    void test_check_control_enable_vmcs_shadowing_fail_vmwrite_bitmap_invalid_physaddr();

    void test_check_control_enable_ept_violation_checks_early_success();
    void test_check_control_enable_ept_violation_checks_success();
    void test_check_control_enable_ept_violation_checks_fail_unaligned();
    void test_check_control_enable_ept_violation_checks_fail_invalid_physaddr();

    void test_check_control_vm_exit_ctls_reserved_properly_set_success();
    void test_check_control_vm_exit_ctls_reserved_properly_set_fail_lower();
    void test_check_control_vm_exit_ctls_reserved_properly_set_fail_upper();

    void test_check_control_activate_and_save_premeption_timer_must_be_0_success_one();
    void test_check_control_activate_and_save_premeption_timer_must_be_0_success_two();
    void test_check_control_activate_and_save_premeption_timer_must_be_0_success_three();
    void test_check_control_activate_and_save_premeption_timer_must_be_0_fail();

    void test_check_control_exit_msr_store_address_success_early();
    void test_check_control_exit_msr_store_address_success();
    void test_check_control_exit_msr_store_address_fail_unaligned();
    void test_check_control_exit_msr_store_address_fail_invalid_start_physaddr();
    void test_check_control_exit_msr_store_address_fail_invalid_end_physaddr();

    void test_check_control_exit_msr_load_address_success_early();
    void test_check_control_exit_msr_load_address_success();
    void test_check_control_exit_msr_load_address_fail_unaligned();
    void test_check_control_exit_msr_load_address_fail_invalid_start_physaddr();
    void test_check_control_exit_msr_load_address_fail_invalid_end_physaddr();

    void test_check_control_vm_entry_ctls_reserved_properly_set_success();
    void test_check_control_vm_entry_ctls_reserved_properly_set_fail_lower();
    void test_check_control_vm_entry_ctls_reserved_properly_set_fail_upper();

    void test_check_control_event_injection_type_vector_checks_early_success();
    void test_check_control_event_injection_type_vector_checks_success();
    void test_check_control_event_injection_type_vector_checks_fail_reserved_set();
    void test_check_control_event_injection_type_vector_checks_fail_no_monitor_trap_support();
    void test_check_control_event_injection_type_vector_checks_fail_nmi_vector_mismatch();
    void test_check_control_event_injection_type_vector_checks_fail_hw_exception_mismatch();
    void test_check_control_event_injection_type_vector_checks_fail_other_blank_vector();

    void test_check_control_event_injection_delivery_ec_checks_early_success_one();
    void test_check_control_event_injection_delivery_ec_checks_early_success_two();
    void test_check_control_event_injection_delivery_ec_checks_success_with_unrestricted_guests();
    void test_check_control_event_injection_delivery_ec_checks_fail_invalid_cr0();
    void test_check_control_event_injection_delivery_ec_checks_success_without_unrestricted_guests();
    void test_check_control_event_injection_delivery_ec_checks_fail_invalid_information_field();
    void test_check_control_event_injection_delivery_ec_checks_fail_invalid_exception();

    void test_check_control_event_injection_reserved_bits_checks_early_success();
    void test_check_control_event_injection_reserved_bits_checks_success();
    void test_check_control_event_injection_reserved_bits_checks_fail();

    void test_check_control_event_injection_ec_checks_early_success_one();
    void test_check_control_event_injection_ec_checks_early_success_two();
    void test_check_control_event_injection_ec_checks_early_success();
    void test_check_control_event_injection_ec_checks_fail();

    void test_check_control_event_injection_instr_length_checks_early_success_one();
    void test_check_control_event_injection_instr_length_checks_early_success_two();
    void test_check_control_event_injection_instr_length_checks_success();
    void test_check_control_event_injection_instr_length_checks_fail_invalid_instr_length_high();
    void test_check_control_event_injection_instr_length_checks_fail_invalid_instr_length_low();

    void test_check_control_entry_msr_load_address_early_success();
    void test_check_control_entry_msr_load_address_success();
    void test_check_control_entry_msr_load_address_fail_unaligned();
    void test_check_control_entry_msr_load_address_fail_invalid_start_physaddr();
    void test_check_control_entry_msr_load_address_fail_invalid_end_physaddr();
};

#endif
