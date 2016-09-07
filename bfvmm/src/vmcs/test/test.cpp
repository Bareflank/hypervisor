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
#include <new_delete.h>

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
    this->test_constructor_null_intrinsics();
    this->test_launch_success();
    this->test_launch_vmlaunch_failure();
    this->test_launch_create_vmcs_region_failure();
    this->test_launch_create_exit_handler_stack_failure();
    this->test_launch_clear_failure();
    this->test_launch_load_failure();
    this->test_promote_failure();
    this->test_resume_failure();
    this->test_vmread_failure();
    this->test_vmwrite_failure();

    this->test_check_control_pin_based_ctls_reserved_properly_set();
    this->test_check_control_proc_based_ctls_reserved_properly_set();
    this->test_check_control_proc_based_ctls2_reserved_properly_set();
    this->test_check_control_cr3_count_less_than_4();
    this->test_check_control_io_bitmap_address_bits();
    this->test_check_control_msr_bitmap_address_bits();
    this->test_check_control_tpr_shadow_and_virtual_apic();
    this->test_check_control_nmi_exiting_and_virtual_nmi();
    this->test_check_control_virtual_nmi_and_nmi_window();
    this->test_check_control_virtual_apic_address_bits();
    this->test_check_control_x2apic_mode_and_virtual_apic_access();
    this->test_check_control_virtual_interrupt_and_external_interrupt();
    this->test_check_control_process_posted_interrupt_checks();
    this->test_check_control_vpid_checks();
    this->test_check_control_enable_ept_checks();
    this->test_check_control_enable_pml_checks();
    this->test_check_control_unrestricted_guests();
    this->test_check_control_enable_vm_functions();
    this->test_check_control_enable_vmcs_shadowing();
    this->test_check_control_enable_ept_violation_checks();
    this->test_check_control_vm_exit_ctls_reserved_properly_set();
    this->test_check_control_activate_and_save_preemption_timer_must_be_0();
    this->test_check_control_exit_msr_store_address();
    this->test_check_control_exit_msr_load_address();
    this->test_check_control_vm_entry_ctls_reserved_properly_set();
    this->test_check_control_event_injection_type_vector_checks();
    this->test_check_control_event_injection_delivery_ec_checks();
    this->test_check_control_event_injection_reserved_bits_checks();
    this->test_check_control_event_injection_ec_checks();
    this->test_check_control_event_injection_instr_length_checks();
    this->test_check_control_entry_msr_load_address();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vmcs_ut);
}
