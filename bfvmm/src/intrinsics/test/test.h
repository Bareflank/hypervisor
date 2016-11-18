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

extern std::map<uint32_t, uint32_t> g_eax_cpuid;

class intrinsics_ut : public unittest
{
public:

    intrinsics_ut();
    ~intrinsics_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_gdt_reg_set_get();
    void test_gdt_reg_base_set_get();
    void test_gdt_reg_limit_set_get();
    void test_gdt_constructor_no_size();
    void test_gdt_constructor_zero_size();
    void test_gdt_constructor_size();
    void test_gdt_base();
    void test_gdt_limit();
    void test_gdt_set_base_zero_index();
    void test_gdt_set_base_invalid_index();
    void test_gdt_set_base_tss_at_end_of_gdt();
    void test_gdt_set_base_descriptor_success();
    void test_gdt_set_base_tss_success();
    void test_gdt_base_zero_index();
    void test_gdt_base_invalid_index();
    void test_gdt_base_tss_at_end_of_gdt();
    void test_gdt_base_descriptor_success();
    void test_gdt_base_tss_success();
    void test_gdt_set_limit_zero_index();
    void test_gdt_set_limit_invalid_index();
    void test_gdt_set_limit_descriptor_success();
    void test_gdt_limit_zero_index();
    void test_gdt_limit_invalid_index();
    void test_gdt_limit_descriptor_success();
    void test_gdt_limit_descriptor_in_bytes_success();
    void test_gdt_set_access_rights_zero_index();
    void test_gdt_set_access_rights_invalid_index();
    void test_gdt_set_access_rights_descriptor_success();
    void test_gdt_access_rights_zero_index();
    void test_gdt_access_rights_invalid_index();
    void test_gdt_access_rights_descriptor_success();

    void test_idt_reg_set_get();
    void test_idt_reg_base_set_get();
    void test_idt_reg_limit_set_get();
    void test_idt_constructor_no_size();
    void test_idt_constructor_zero_size();
    void test_idt_constructor_size();
    void test_idt_base();
    void test_idt_limit();

    void test_general_msr_access();
    void test_ia32_feature_control();
    void test_ia32_feature_control_lock_bit();
    void test_ia32_feature_control_enable_vmx_inside_smx();
    void test_ia32_feature_control_enable_vmx_outside_smx();
    void test_ia32_feature_control_senter_local_function_enables();
    void test_ia32_feature_control_senter_gloabl_function_enable();
    void test_ia32_feature_control_sgx_launch_control_enable();
    void test_ia32_feature_control_sgx_global_enable();
    void test_ia32_feature_control_lmce();
    void test_ia32_sysenter_cs();
    void test_ia32_sysenter_esp();
    void test_ia32_sysenter_eip();
    void test_ia32_debugctl();
    void test_ia32_debugctl_lbr();
    void test_ia32_debugctl_btf();
    void test_ia32_debugctl_tr();
    void test_ia32_debugctl_bts();
    void test_ia32_debugctl_btint();
    void test_ia32_debugctl_bt_off_os();
    void test_ia32_debugctl_bt_off_user();
    void test_ia32_debugctl_freeze_lbrs_on_pmi();
    void test_ia32_debugctl_freeze_perfmon_on_pmi();
    void test_ia32_debugctl_enable_uncore_pmi();
    void test_ia32_debugctl_freeze_while_smm();
    void test_ia32_debugctl_rtm_debug();
    void test_ia32_debugctl_reserved();
    void test_ia32_pat();
    void test_ia32_pat_pa0();
    void test_ia32_pat_pa1();
    void test_ia32_pat_pa2();
    void test_ia32_pat_pa3();
    void test_ia32_pat_pa4();
    void test_ia32_pat_pa5();
    void test_ia32_pat_pa6();
    void test_ia32_pat_pa7();
    void test_ia32_perf_global_ctrl();
    void test_ia32_perf_global_ctrl_pmc0();
    void test_ia32_perf_global_ctrl_pmc1();
    void test_ia32_perf_global_ctrl_pmc2();
    void test_ia32_perf_global_ctrl_pmc3();
    void test_ia32_perf_global_ctrl_pmc4();
    void test_ia32_perf_global_ctrl_pmc5();
    void test_ia32_perf_global_ctrl_pmc6();
    void test_ia32_perf_global_ctrl_pmc7();
    void test_ia32_perf_global_ctrl_fixed_ctr0();
    void test_ia32_perf_global_ctrl_fixed_ctr1();
    void test_ia32_perf_global_ctrl_fixed_ctr2();
    void test_ia32_vmx_basic();
    void test_ia32_vmx_basic_revision_id();
    void test_ia32_vmx_basic_vmxon_vmcs_region_size();
    void test_ia32_vmx_basic_physical_address_width();
    void test_ia32_vmx_basic_dual_monitor_mode_support();
    void test_ia32_vmx_basic_memory_type();
    void test_ia32_vmx_basic_ins_outs_exit_information();
    void test_ia32_vmx_basic_true_based_controls();
    void test_ia32_vmx_misc();
    void test_ia32_vmx_misc_preemption_timer_decrement();
    void test_ia32_vmx_misc_store_efer_lma_on_vm_exit();
    void test_ia32_vmx_misc_activity_state_hlt_support();
    void test_ia32_vmx_misc_activity_state_shutdown_support();
    void test_ia32_vmx_misc_activity_state_wait_for_sipi_support();
    void test_ia32_vmx_misc_processor_trace_support();
    void test_ia32_vmx_misc_rdmsr_in_smm_support();
    void test_ia32_vmx_misc_cr3_targets();
    void test_ia32_vmx_misc_max_num_msr_load_store_on_exit();
    void test_ia32_vmx_misc_vmxoff_blocked_smi_support();
    void test_ia32_vmx_misc_vmwrite_all_fields_support();
    void test_ia32_vmx_misc_injection_with_instruction_length_of_zero();
    void test_ia32_vmx_cr0_fixed0();
    void test_ia32_vmx_cr0_fixed1();
    void test_ia32_vmx_cr4_fixed0();
    void test_ia32_vmx_cr4_fixed1();
    void test_ia32_vmx_procbased_ctls2();
    void test_ia32_vmx_procbased_ctls2_virtualize_apic_accesses();
    void test_ia32_vmx_procbased_ctls2_enable_ept();
    void test_ia32_vmx_procbased_ctls2_descriptor_table_exiting();
    void test_ia32_vmx_procbased_ctls2_enable_rdtscp();
    void test_ia32_vmx_procbased_ctls2_virtualize_x2apic_mode();
    void test_ia32_vmx_procbased_ctls2_enable_vpid();
    void test_ia32_vmx_procbased_ctls2_wbinvd_exiting();
    void test_ia32_vmx_procbased_ctls2_unrestricted_guest();
    void test_ia32_vmx_procbased_ctls2_apic_register_virtualization();
    void test_ia32_vmx_procbased_ctls2_virtual_interrupt_delivery();
    void test_ia32_vmx_procbased_ctls2_pause_loop_exiting();
    void test_ia32_vmx_procbased_ctls2_rdrand_exiting();
    void test_ia32_vmx_procbased_ctls2_enable_invpcid();
    void test_ia32_vmx_procbased_ctls2_enable_vm_functions();
    void test_ia32_vmx_procbased_ctls2_vmcs_shadowing();
    void test_ia32_vmx_procbased_ctls2_rdseed_exiting();
    void test_ia32_vmx_procbased_ctls2_enable_pml();
    void test_ia32_vmx_procbased_ctls2_ept_violation_ve();
    void test_ia32_vmx_procbased_ctls2_enable_xsaves_xrstors();
    void test_ia32_vmx_ept_vpid_cap();
    void test_ia32_vmx_ept_vpid_cap_execute_only_translation();
    void test_ia32_vmx_ept_vpid_cap_page_walk_length_of_4();
    void test_ia32_vmx_ept_vpid_cap_memory_type_uncacheable_supported();
    void test_ia32_vmx_ept_vpid_cap_memory_type_write_back_supported();
    void test_ia32_vmx_ept_vpid_cap_pde_2mb_support();
    void test_ia32_vmx_ept_vpid_cap_pdpte_1mb_support();
    void test_ia32_vmx_ept_vpid_cap_invept_support();
    void test_ia32_vmx_ept_vpid_cap_accessed_dirty_support();
    void test_ia32_vmx_ept_vpid_cap_invept_single_context_support();
    void test_ia32_vmx_ept_vpid_cap_invept_all_context_support();
    void test_ia32_vmx_ept_vpid_cap_invvpid_support();
    void test_ia32_vmx_ept_vpid_cap_invvpid_individual_address_support();
    void test_ia32_vmx_ept_vpid_cap_invvpid_single_context_support();
    void test_ia32_vmx_ept_vpid_cap_invvpid_all_context_support();
    void test_ia32_vmx_ept_vpid_cap_invvpid_single_context_retaining_globals_support();
    void test_ia32_vmx_true_pinbased_ctls();
    void test_ia32_vmx_true_pinbased_ctls_external_interrupt_exiting();
    void test_ia32_vmx_true_pinbased_ctls_nmi_exiting();
    void test_ia32_vmx_true_pinbased_ctls_virtual_nmis();
    void test_ia32_vmx_true_pinbased_ctls_activate_vmx_preemption_timer();
    void test_ia32_vmx_true_pinbased_ctls_process_posted_interrupts();
    void test_ia32_vmx_true_procbased_ctls();
    void test_ia32_vmx_true_procbased_ctls_interrupt_window_exiting();
    void test_ia32_vmx_true_procbased_ctls_use_tsc_offsetting();
    void test_ia32_vmx_true_procbased_ctls_hlt_exiting();
    void test_ia32_vmx_true_procbased_ctls_invlpg_exiting();
    void test_ia32_vmx_true_procbased_ctls_mwait_exiting();
    void test_ia32_vmx_true_procbased_ctls_rdpmc_exiting();
    void test_ia32_vmx_true_procbased_ctls_rdtsc_exiting();
    void test_ia32_vmx_true_procbased_ctls_cr3_load_exiting();
    void test_ia32_vmx_true_procbased_ctls_cr3_store_exiting();
    void test_ia32_vmx_true_procbased_ctls_cr8_load_exiting();
    void test_ia32_vmx_true_procbased_ctls_cr8_store_exiting();
    void test_ia32_vmx_true_procbased_ctls_use_tpr_shadow();
    void test_ia32_vmx_true_procbased_ctls_nmi_window_exiting();
    void test_ia32_vmx_true_procbased_ctls_mov_dr_exiting();
    void test_ia32_vmx_true_procbased_ctls_unconditional_io_exiting();
    void test_ia32_vmx_true_procbased_ctls_use_io_bitmaps();
    void test_ia32_vmx_true_procbased_ctls_monitor_trap_flag();
    void test_ia32_vmx_true_procbased_ctls_use_msr_bitmaps();
    void test_ia32_vmx_true_procbased_ctls_monitor_exiting();
    void test_ia32_vmx_true_procbased_ctls_pause_exiting();
    void test_ia32_vmx_true_procbased_ctls_activate_secondary_controls();
    void test_ia32_vmx_true_exit_ctls();
    void test_ia32_vmx_true_exit_ctls_save_debug_controls();
    void test_ia32_vmx_true_exit_ctls_host_address_space_size();
    void test_ia32_vmx_true_exit_ctls_load_ia32_perf_global_ctrl();
    void test_ia32_vmx_true_exit_ctls_acknowledge_interrupt_on_exit();
    void test_ia32_vmx_true_exit_ctls_save_ia32_pat();
    void test_ia32_vmx_true_exit_ctls_load_ia32_pat();
    void test_ia32_vmx_true_exit_ctls_save_ia32_efer();
    void test_ia32_vmx_true_exit_ctls_load_ia32_efer();
    void test_ia32_vmx_true_exit_ctls_save_vmx_preemption_timer_value();
    void test_ia32_vmx_true_exit_ctls_clear_ia32_bndcfgs();
    void test_ia32_vmx_true_entry_ctls();
    void test_ia32_vmx_true_entry_ctls_load_debug_controls();
    void test_ia32_vmx_true_entry_ctls_ia_32e_mode_guest();
    void test_ia32_vmx_true_entry_ctls_entry_to_smm();
    void test_ia32_vmx_true_entry_ctls_deactivate_dual_monitor_treatment();
    void test_ia32_vmx_true_entry_ctls_load_ia32_perf_global_ctrl();
    void test_ia32_vmx_true_entry_ctls_load_ia32_pat();
    void test_ia32_vmx_true_entry_ctls_load_ia32_efer();
    void test_ia32_vmx_true_entry_ctls_load_ia32_bndcfgs();
    void test_ia32_vmx_vmfunc();
    void test_ia32_vmx_vmfunc_eptp_switching();
    void test_ia32_efer();
    void test_ia32_efer_sce();
    void test_ia32_efer_lme();
    void test_ia32_efer_lma();
    void test_ia32_efer_nxe();
    void test_ia32_efer_reserved();
    void test_ia32_fs_base();
    void test_ia32_gs_base();

    void test_rflags_x64();
    void test_rflags_x64_carry_flag();
    void test_rflags_x64_parity_flag();
    void test_rflags_x64_auxiliary_carry_flag();
    void test_rflags_x64_zero_flag();
    void test_rflags_x64_sign_flag();
    void test_rflags_x64_trap_flag();
    void test_rflags_x64_interrupt_enable_flag();
    void test_rflags_x64_direction_flag();
    void test_rflags_x64_overflow_flag();
    void test_rflags_x64_privilege_level();
    void test_rflags_x64_nested_task();
    void test_rflags_x64_resume_flag();
    void test_rflags_x64_virtual_8086_mode();
    void test_rflags_x64_alignment_check_access_control();
    void test_rflags_x64_virtual_interupt_flag();
    void test_rflags_x64_virtual_interupt_pending();
    void test_rflags_x64_id_flag();
    void test_rflags_x64_reserved();
    void test_rflags_x64_always_disabled();
    void test_rflags_x64_always_enabled();

    void test_cr0_intel_x64();
    void test_cr0_intel_x64_protection_enable();
    void test_cr0_intel_x64_monitor_coprocessor();
    void test_cr0_intel_x64_emulation();
    void test_cr0_intel_x64_task_switched();
    void test_cr0_intel_x64_extension_type();
    void test_cr0_intel_x64_numeric_error();
    void test_cr0_intel_x64_write_protect();
    void test_cr0_intel_x64_alignment_mask();
    void test_cr0_intel_x64_not_write_through();
    void test_cr0_intel_x64_cache_disable();
    void test_cr0_intel_x64_paging();
    void test_cr3_intel_x64();
    void test_cr4_intel_x64();
    void test_cr4_intel_x64_v8086_mode_extensions();
    void test_cr4_intel_x64_protected_mode_virtual_interrupts();
    void test_cr4_intel_x64_time_stamp_disable();
    void test_cr4_intel_x64_debugging_extensions();
    void test_cr4_intel_x64_page_size_extensions();
    void test_cr4_intel_x64_physical_address_extensions();
    void test_cr4_intel_x64_machine_check_enable();
    void test_cr4_intel_x64_page_global_enable();
    void test_cr4_intel_x64_performance_monitor_counter_enable();
    void test_cr4_intel_x64_osfxsr();
    void test_cr4_intel_x64_osxmmexcpt();
    void test_cr4_intel_x64_vmx_enable_bit();
    void test_cr4_intel_x64_smx_enable_bit();
    void test_cr4_intel_x64_fsgsbase_enable_bit();
    void test_cr4_intel_x64_pcid_enable_bit();
    void test_cr4_intel_x64_osxsave();
    void test_cr4_intel_x64_smep_enable_bit();
    void test_cr4_intel_x64_smap_enable_bit();
    void test_cr4_intel_x64_protection_key_enable_bit();

    void test_srs_x64_es();
    void test_srs_x64_es_rpl();
    void test_srs_x64_es_ti();
    void test_srs_x64_es_index();
    void test_srs_x64_cs();
    void test_srs_x64_cs_rpl();
    void test_srs_x64_cs_ti();
    void test_srs_x64_cs_index();
    void test_srs_x64_ss();
    void test_srs_x64_ss_rpl();
    void test_srs_x64_ss_ti();
    void test_srs_x64_ss_index();
    void test_srs_x64_ds();
    void test_srs_x64_ds_rpl();
    void test_srs_x64_ds_ti();
    void test_srs_x64_ds_index();
    void test_srs_x64_fs();
    void test_srs_x64_fs_rpl();
    void test_srs_x64_fs_ti();
    void test_srs_x64_fs_index();
    void test_srs_x64_gs();
    void test_srs_x64_gs_rpl();
    void test_srs_x64_gs_ti();
    void test_srs_x64_gs_index();
    void test_srs_x64_ldtr();
    void test_srs_x64_ldtr_rpl();
    void test_srs_x64_ldtr_ti();
    void test_srs_x64_ldtr_index();
    void test_srs_x64_tr();
    void test_srs_x64_tr_rpl();
    void test_srs_x64_tr_ti();
    void test_srs_x64_tr_index();

    void test_portio_x64_byte();
    void test_portio_x64_word();

    void test_vmx_intel_x64_vmxon_nullptr();
    void test_vmx_intel_x64_vmxon_failure();
    void test_vmx_intel_x64_vmxon_success();
    void test_vmx_intel_x64_vmxoff_failure();
    void test_vmx_intel_x64_vmxoff_success();
    void test_vmx_intel_x64_vmclear_nullptr();
    void test_vmx_intel_x64_vmclear_failure();
    void test_vmx_intel_x64_vmclear_success();
    void test_vmx_intel_x64_vmload_nullptr();
    void test_vmx_intel_x64_vmload_failure();
    void test_vmx_intel_x64_vmload_success();
    void test_vmx_intel_x64_vmreset_nullptr();
    void test_vmx_intel_x64_vmreset_failure();
    void test_vmx_intel_x64_vmreset_success();
    void test_vmx_intel_x64_vmread_failure();
    void test_vmx_intel_x64_vmwrite_failure();
    void test_vmx_intel_x64_vmread_vmwrite_succcess();
    void test_vmx_intel_x64_vmlaunch_failure();
    void test_vmx_intel_x64_vmlaunch_success();

    void test_cpuid_x64_cpuid();
    void test_cpuid_x64_cpuid_eax();
    void test_cpuid_x64_cpuid_ebx();
    void test_cpuid_x64_cpuid_ecx();
    void test_cpuid_x64_cpuid_edx();
    void test_cpuid_x64_cpuid_addr_size_phys();
    void test_cpuid_x64_cpuid_addr_size_linear();
    void test_cpuid_x64_cpuid_feature_information_ecx_sse3();
    void test_cpuid_x64_cpuid_feature_information_ecx_pclmulqdq();
    void test_cpuid_x64_cpuid_feature_information_ecx_dtes64();
    void test_cpuid_x64_cpuid_feature_information_ecx_monitor();
    void test_cpuid_x64_cpuid_feature_information_ecx_ds_cpl();
    void test_cpuid_x64_cpuid_feature_information_ecx_vmx();
    void test_cpuid_x64_cpuid_feature_information_ecx_smx();
    void test_cpuid_x64_cpuid_feature_information_ecx_eist();
    void test_cpuid_x64_cpuid_feature_information_ecx_tm2();
    void test_cpuid_x64_cpuid_feature_information_ecx_ssse3();
    void test_cpuid_x64_cpuid_feature_information_ecx_cnxt_id();
    void test_cpuid_x64_cpuid_feature_information_ecx_sdbg();
    void test_cpuid_x64_cpuid_feature_information_ecx_fma();
    void test_cpuid_x64_cpuid_feature_information_ecx_cmpxchg16b();
    void test_cpuid_x64_cpuid_feature_information_ecx_xtpr_update_control();
    void test_cpuid_x64_cpuid_feature_information_ecx_pdcm();
    void test_cpuid_x64_cpuid_feature_information_ecx_pcid();
    void test_cpuid_x64_cpuid_feature_information_ecx_dca();
    void test_cpuid_x64_cpuid_feature_information_ecx_sse41();
    void test_cpuid_x64_cpuid_feature_information_ecx_sse42();
    void test_cpuid_x64_cpuid_feature_information_ecx_x2apic();
    void test_cpuid_x64_cpuid_feature_information_ecx_movbe();
    void test_cpuid_x64_cpuid_feature_information_ecx_popcnt();
    void test_cpuid_x64_cpuid_feature_information_ecx_tsc_deadline();
    void test_cpuid_x64_cpuid_feature_information_ecx_aesni();
    void test_cpuid_x64_cpuid_feature_information_ecx_xsave();
    void test_cpuid_x64_cpuid_feature_information_ecx_osxsave();
    void test_cpuid_x64_cpuid_feature_information_ecx_avx();
    void test_cpuid_x64_cpuid_feature_information_ecx_f16c();
    void test_cpuid_x64_cpuid_feature_information_ecx_rdrand();
    void test_cpuid_x64_cpuid_feature_information_ecx_dump();
    void test_cpuid_x64_cpuid_extended_feature_flags_subleaf0_ebx_sgx();
    void test_cpuid_x64_cpuid_extended_feature_flags_subleaf0_ebx_rtm();
    void test_cpuid_x64_cpuid_extended_feature_flags_subleaf0_ebx_dump();

    void test_pm_x64_halt();
    void test_pm_x64_stop();

    void test_cache_x64_invd();
    void test_cache_x64_wbinvd();

    void test_tlb_x64_invlpg();

    void test_debug_x64_dr7();

    void test_pdpte_x64_reserved_mask();
    void test_pdpte_x64_page_directory_addr_mask();
};

#endif
