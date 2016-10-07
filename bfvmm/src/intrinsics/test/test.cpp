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

intrinsics_ut::intrinsics_ut()
{
}

bool
intrinsics_ut::init()
{
    return true;
}

bool
intrinsics_ut::fini()
{
    return true;
}

bool
intrinsics_ut::list()
{
    this->test_gdt_constructor_no_size();
    this->test_gdt_constructor_zero_size();
    this->test_gdt_constructor_size();
    this->test_gdt_constructor_null_intrinsics();
    this->test_gdt_base();
    this->test_gdt_limit();
    this->test_gdt_set_base_zero_index();
    this->test_gdt_set_base_invalid_index();
    this->test_gdt_set_base_tss_at_end_of_gdt();
    this->test_gdt_set_base_descriptor_success();
    this->test_gdt_set_base_tss_success();
    this->test_gdt_base_zero_index();
    this->test_gdt_base_invalid_index();
    this->test_gdt_base_tss_at_end_of_gdt();
    this->test_gdt_base_descriptor_success();
    this->test_gdt_base_tss_success();
    this->test_gdt_set_limit_zero_index();
    this->test_gdt_set_limit_invalid_index();
    this->test_gdt_set_limit_descriptor_success();
    this->test_gdt_limit_zero_index();
    this->test_gdt_limit_invalid_index();
    this->test_gdt_limit_descriptor_success();
    this->test_gdt_limit_descriptor_in_bytes_success();
    this->test_gdt_set_access_rights_zero_index();
    this->test_gdt_set_access_rights_invalid_index();
    this->test_gdt_set_access_rights_descriptor_success();
    this->test_gdt_access_rights_zero_index();
    this->test_gdt_access_rights_invalid_index();
    this->test_gdt_access_rights_descriptor_success();

    this->test_idt_constructor_no_size();
    this->test_idt_constructor_zero_size();
    this->test_idt_constructor_size();
    this->test_idt_constructor_null_intrinsics();
    this->test_idt_base();
    this->test_idt_limit();

    this->test_ia32_feature_control();
    this->test_ia32_feature_control_lock_bit();
    this->test_ia32_feature_control_enable_vmx_inside_smx();
    this->test_ia32_feature_control_enable_vmx_outside_smx();
    this->test_ia32_vmx_basic();
    this->test_ia32_vmx_basic_revision_id();
    this->test_ia32_vmx_basic_vmxon_vmcs_region_size();
    this->test_ia32_vmx_basic_physical_address_width();
    this->test_ia32_vmx_basic_dual_monitor_mode_support();
    this->test_ia32_vmx_basic_memory_type();
    this->test_ia32_vmx_basic_ins_outs_exit_information();
    this->test_ia32_vmx_basic_true_based_controls();
    this->test_ia32_vmx_misc();
    this->test_ia32_vmx_misc_preemption_timer_decrement();
    this->test_ia32_vmx_misc_store_efer_lma_on_vm_exit();
    this->test_ia32_vmx_misc_activity_state_hlt_support();
    this->test_ia32_vmx_misc_activity_state_shutdown_support();
    this->test_ia32_vmx_misc_activity_state_wait_for_sipi_support();
    this->test_ia32_vmx_misc_processor_trace_support();
    this->test_ia32_vmx_misc_rdmsr_in_smm_support();
    this->test_ia32_vmx_misc_cr3_targets();
    this->test_ia32_vmx_misc_max_num_msr_load_store_on_exit();
    this->test_ia32_vmx_misc_vmxoff_blocked_smi_support();
    this->test_ia32_vmx_misc_vmwrite_all_fields_support();
    this->test_ia32_vmx_misc_injection_with_instruction_length_of_zero();
    this->test_ia32_vmx_cr0_fixed0();
    this->test_ia32_vmx_cr0_fixed1();
    this->test_ia32_vmx_cr4_fixed0();
    this->test_ia32_vmx_cr4_fixed1();
    this->test_ia32_vmx_procbased_ctls2();
    this->test_ia32_vmx_procbased_ctls2_virtualize_apic_accesses();
    this->test_ia32_vmx_procbased_ctls2_enable_ept();
    this->test_ia32_vmx_procbased_ctls2_descriptor_table_exiting();
    this->test_ia32_vmx_procbased_ctls2_enable_rdtscp();
    this->test_ia32_vmx_procbased_ctls2_virtualize_x2apic_mode();
    this->test_ia32_vmx_procbased_ctls2_enable_vpid();
    this->test_ia32_vmx_procbased_ctls2_wbinvd_exiting();
    this->test_ia32_vmx_procbased_ctls2_unrestricted_guest();
    this->test_ia32_vmx_procbased_ctls2_apic_register_virtualization();
    this->test_ia32_vmx_procbased_ctls2_virtual_interrupt_delivery();
    this->test_ia32_vmx_procbased_ctls2_pause_loop_exiting();
    this->test_ia32_vmx_procbased_ctls2_rdrand_exiting();
    this->test_ia32_vmx_procbased_ctls2_enable_invpcid();
    this->test_ia32_vmx_procbased_ctls2_enable_vm_functions();
    this->test_ia32_vmx_procbased_ctls2_vmcs_shadowing();
    this->test_ia32_vmx_procbased_ctls2_rdseed_exiting();
    this->test_ia32_vmx_procbased_ctls2_enable_pml();
    this->test_ia32_vmx_procbased_ctls2_ept_violation_ve();
    this->test_ia32_vmx_procbased_ctls2_enable_xsaves_xrstors();
    this->test_ia32_vmx_ept_vpid_cap();
    this->test_ia32_vmx_ept_vpid_cap_execute_only_translation();
    this->test_ia32_vmx_ept_vpid_cap_page_walk_length_of_4();
    this->test_ia32_vmx_ept_vpid_cap_memory_type_uncacheable_supported();
    this->test_ia32_vmx_ept_vpid_cap_memory_type_write_back_supported();
    this->test_ia32_vmx_ept_vpid_cap_pde_2mb_support();
    this->test_ia32_vmx_ept_vpid_cap_pdpte_1mb_support();
    this->test_ia32_vmx_ept_vpid_cap_invept_support();
    this->test_ia32_vmx_ept_vpid_cap_accessed_dirty_support();
    this->test_ia32_vmx_ept_vpid_cap_invept_single_context_support();
    this->test_ia32_vmx_ept_vpid_cap_invept_all_context_support();
    this->test_ia32_vmx_ept_vpid_cap_invvpid_support();
    this->test_ia32_vmx_ept_vpid_cap_invvpid_individual_address_support();
    this->test_ia32_vmx_ept_vpid_cap_invvpid_single_context_support();
    this->test_ia32_vmx_ept_vpid_cap_invvpid_all_context_support();
    this->test_ia32_vmx_ept_vpid_cap_invvpid_single_context_retaining_globals_support();
    this->test_ia32_vmx_true_pinbased_ctls();
    this->test_ia32_vmx_true_pinbased_ctls_external_interrupt_exiting();
    this->test_ia32_vmx_true_pinbased_ctls_nmi_exiting();
    this->test_ia32_vmx_true_pinbased_ctls_virtual_nmis();
    this->test_ia32_vmx_true_pinbased_ctls_activate_vmx_preemption_timer();
    this->test_ia32_vmx_true_pinbased_ctls_process_posted_interrupts();
    this->test_ia32_vmx_true_procbased_ctls();
    this->test_ia32_vmx_true_procbased_ctls_interrupt_window_exiting();
    this->test_ia32_vmx_true_procbased_ctls_use_tsc_offsetting();
    this->test_ia32_vmx_true_procbased_ctls_hlt_exiting();
    this->test_ia32_vmx_true_procbased_ctls_invlpg_exiting();
    this->test_ia32_vmx_true_procbased_ctls_mwait_exiting();
    this->test_ia32_vmx_true_procbased_ctls_rdpmc_exiting();
    this->test_ia32_vmx_true_procbased_ctls_rdtsc_exiting();
    this->test_ia32_vmx_true_procbased_ctls_cr3_load_exiting();
    this->test_ia32_vmx_true_procbased_ctls_cr3_store_exiting();
    this->test_ia32_vmx_true_procbased_ctls_cr8_load_exiting();
    this->test_ia32_vmx_true_procbased_ctls_cr8_store_exiting();
    this->test_ia32_vmx_true_procbased_ctls_use_tpr_shadow();
    this->test_ia32_vmx_true_procbased_ctls_nmi_window_exiting();
    this->test_ia32_vmx_true_procbased_ctls_mov_dr_exiting();
    this->test_ia32_vmx_true_procbased_ctls_unconditional_io_exiting();
    this->test_ia32_vmx_true_procbased_ctls_use_io_bitmaps();
    this->test_ia32_vmx_true_procbased_ctls_monitor_trap_flag();
    this->test_ia32_vmx_true_procbased_ctls_use_msr_bitmaps();
    this->test_ia32_vmx_true_procbased_ctls_monitor_exiting();
    this->test_ia32_vmx_true_procbased_ctls_pause_exiting();
    this->test_ia32_vmx_true_procbased_ctls_activate_secondary_controls();
    this->test_ia32_vmx_true_exit_ctls();
    this->test_ia32_vmx_true_exit_ctls_save_debug_controls();
    this->test_ia32_vmx_true_exit_ctls_host_address_space_size();
    this->test_ia32_vmx_true_exit_ctls_load_ia32_perf_global_ctrl();
    this->test_ia32_vmx_true_exit_ctls_acknowledge_interrupt_on_exit();
    this->test_ia32_vmx_true_exit_ctls_save_ia32_pat();
    this->test_ia32_vmx_true_exit_ctls_load_ia32_pat();
    this->test_ia32_vmx_true_exit_ctls_save_ia32_efer();
    this->test_ia32_vmx_true_exit_ctls_load_ia32_efer();
    this->test_ia32_vmx_true_exit_ctls_save_vmx_preemption_timer_value();
    this->test_ia32_vmx_true_entry_ctls();
    this->test_ia32_vmx_true_entry_ctls_load_debug_controls();
    this->test_ia32_vmx_true_entry_ctls_ia_32e_mode_guest();
    this->test_ia32_vmx_true_entry_ctls_entry_to_smm();
    this->test_ia32_vmx_true_entry_ctls_deactivate_dual_monitor_treatment();
    this->test_ia32_vmx_true_entry_ctls_load_ia32_perf_global_ctrl();
    this->test_ia32_vmx_true_entry_ctls_load_ia32_pat();
    this->test_ia32_vmx_true_entry_ctls_load_ia32_efer();
    this->test_ia32_vmx_vmfunc();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(intrinsics_ut);
}
