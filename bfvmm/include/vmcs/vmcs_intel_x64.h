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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <vmcs/bitmap.h>
#include <vmcs/vmcs_state_intel_x64.h>
#include <intrinsics/intrinsics_intel_x64.h>

class vmcs_intel_x64
{
public:

    /// Default Constructor
    ///
    vmcs_intel_x64(intrinsics_intel_x64 *intrinsics);

    /// Destructor
    ///
    virtual ~vmcs_intel_x64() {}

    /// Launch
    ///
    /// Launches the VMCS. Note that this will create a new guest VM when
    /// it is complete.
    ///
    /// @throws invalid_vmcs thrown if the VMCS was created without
    ///     intrinsics
    ///
    virtual void launch(const vmcs_state_intel_x64 &host_state,
                        const vmcs_state_intel_x64 &guest_state);

    /// Promote
    ///
    /// Promotes this guest to VMX root. This is used to transition out of
    /// VMX operation as the guest that this VMCS defines is likely about to
    /// disable VMX operation, and needs to be in VMX root to do so. Note
    /// that this function doesn't actually return if it is successful.
    /// Instead, the CPU resumes execution on the last instruction executed
    /// by the guest.
    ///
    /// If this function fails in the middle of it's execution, it calls
    /// abort. This is done because the process of promoting sets the CPU
    /// state, and if it dies in the middle, the CPU is left in a corrupt
    /// state.
    ///
    /// @throws invalid_vmcs thrown if the VMCS was created without
    ///     intrinsics
    ///
    virtual void promote();

protected:

    /// VM Read
    ///
    /// This is the same as intrinsics->vmread, but throws if an error
    /// occurs.
    ///
    /// @param field the vmcs field to read
    /// @return the value of the vmcs field
    ///
    /// @throws vmcs_read_failure_error thrown if the vmread fails
    ///
    virtual uint64_t vmread(uint64_t field);

    /// VM Write
    ///
    /// This is the same as intrinsics->vmwrite, but throws if an error
    /// occurs.
    ///
    /// @param field the vmcs field to read
    /// @param value the value to write to the vmcs field
    ///
    /// @throws vmcs_write_failure_error thrown if the vmwrite fails
    ///
    virtual void vmwrite(uint64_t field, uint64_t value);

private:

    void create_vmcs_region();
    void release_vmcs_region();

    void write_16bit_control_state(const vmcs_state_intel_x64 &state);
    void write_64bit_control_state(const vmcs_state_intel_x64 &state);
    void write_32bit_control_state(const vmcs_state_intel_x64 &state);
    void write_natural_control_state(const vmcs_state_intel_x64 &state);

    void write_16bit_guest_state(const vmcs_state_intel_x64 &state);
    void write_64bit_guest_state(const vmcs_state_intel_x64 &state);
    void write_32bit_guest_state(const vmcs_state_intel_x64 &state);
    void write_natural_guest_state(const vmcs_state_intel_x64 &state);

    void write_16bit_host_state(const vmcs_state_intel_x64 &state);
    void write_64bit_host_state(const vmcs_state_intel_x64 &state);
    void write_32bit_host_state(const vmcs_state_intel_x64 &state);
    void write_natural_host_state(const vmcs_state_intel_x64 &state);

    void promote_16bit_guest_state();
    void promote_64bit_guest_state();
    void promote_32bit_guest_state();
    void promote_natural_guest_state();

    void default_pin_based_vm_execution_controls();
    void default_primary_processor_based_vm_execution_controls();
    void default_secondary_processor_based_vm_execution_controls();
    void default_vm_exit_controls();
    void default_vm_entry_controls();

protected:

    virtual void dump_vmcs();

    virtual std::string check_vm_instruction_error();
    virtual bool check_is_address_canonical(uint64_t addr);
    virtual bool check_vmcs_host_state();
    virtual bool check_vmcs_guest_state();
    virtual bool check_vmcs_control_state();

    virtual bool supports_external_interrupt_exiting();
    virtual bool supports_nmi_exiting();
    virtual bool supports_virtual_nmis();
    virtual bool supports_vmx_preemption_timer();
    virtual bool supports_posted_interrupts();

    virtual bool supports_interrupt_window_exiting();
    virtual bool supports_tsc_offsetting();
    virtual bool supports_hlt_exiting();
    virtual bool supports_invlpg_exiting();
    virtual bool supports_mwait_exiting();
    virtual bool supports_rdpmc_exiting();
    virtual bool supports_rdtsc_exiting();
    virtual bool supports_cr3_load_exiting();
    virtual bool supports_cr3_store_exiting();
    virtual bool supports_cr8_load_exiting();
    virtual bool supports_cr8_store_exiting();
    virtual bool supports_tpr_shadow();
    virtual bool supports_nmi_window_exiting();
    virtual bool supports_mov_dr_exiting();
    virtual bool supports_unconditional_io_exiting();
    virtual bool supports_io_bitmaps();
    virtual bool supports_monitor_trap_flag();
    virtual bool supports_msr_bitmaps();
    virtual bool supports_monitor_exiting();
    virtual bool supports_pause_exiting();
    virtual bool supports_secondary_controls();

    virtual bool supports_virtualized_apic();
    virtual bool supports_ept();
    virtual bool supports_descriptor_table_exiting();
    virtual bool supports_rdtscp();
    virtual bool supports_x2apic_mode();
    virtual bool supports_vpid();
    virtual bool supports_wbinvd_exiting();
    virtual bool supports_unrestricted_guests();
    virtual bool supports_apic_register_virtualization();
    virtual bool supports_virtual_interrupt_delivery();
    virtual bool supports_pause_loop_exiting();
    virtual bool supports_rdrand_exiting();
    virtual bool supports_invpcid();
    virtual bool supports_vm_functions();
    virtual bool supports_vmcs_shadowing();
    virtual bool supports_rdseed_exiting();
    virtual bool supports_ept_violation_ve();
    virtual bool supports_xsave_xrestore();

    virtual bool supports_save_debug_controls_on_exit();
    virtual bool supports_host_address_space_size();
    virtual bool supports_load_ia32_perf_global_ctrl_on_exit();
    virtual bool supports_ack_interrupt_on_exit();
    virtual bool supports_save_ia32_pat_on_exit();
    virtual bool supports_load_ia32_pat_on_exit();
    virtual bool supports_save_ia32_efer_on_exit();
    virtual bool supports_load_ia32_efer_on_exit();
    virtual bool supports_save_vmx_preemption_timer_on_exit();

    virtual bool supports_load_debug_controls_on_entry();
    virtual bool supports_ia_32e_mode_guest();
    virtual bool supports_entry_to_smm();
    virtual bool supports_deactivate_dual_monitor_treatment();
    virtual bool supports_load_ia32_perf_global_ctrl_on_entry();
    virtual bool supports_load_ia32_pat_on_entry();
    virtual bool supports_load_ia32_efer_on_entry();

    virtual bool check_host_control_registers_and_msrs();
    virtual bool check_host_cr0_for_unsupported_bits();
    virtual bool check_host_cr4_for_unsupported_bits();
    virtual bool check_host_cr3_for_unsupported_bits();
    virtual bool check_host_ia32_sysenter_esp_canonical_address();
    virtual bool check_host_ia32_sysenter_eip_canonical_address();
    virtual bool check_host_ia32_perf_global_ctrl_for_reserved_bits();
    virtual bool check_host_ia32_pat_for_unsupported_bits();
    virtual bool check_host_verify_load_ia32_efer_enabled();
    virtual bool check_host_ia32_efer_for_reserved_bits();
    virtual bool check_host_ia32_efer_set();

    virtual bool check_host_segment_and_descriptor_table_registers();
    virtual bool check_host_es_selector_rpl_ti_equal_zero();
    virtual bool check_host_cs_selector_rpl_ti_equal_zero();
    virtual bool check_host_ss_selector_rpl_ti_equal_zero();
    virtual bool check_host_ds_selector_rpl_ti_equal_zero();
    virtual bool check_host_fs_selector_rpl_ti_equal_zero();
    virtual bool check_host_gs_selector_rpl_ti_equal_zero();
    virtual bool check_host_tr_selector_rpl_ti_equal_zero();
    virtual bool check_host_cs_not_equal_zero();
    virtual bool check_host_tr_not_equal_zero();
    virtual bool check_host_ss_not_equal_zero();
    virtual bool check_host_fs_canonical_base_address();
    virtual bool check_host_gs_canonical_base_address();
    virtual bool check_host_gdtr_canonical_base_address();
    virtual bool check_host_idtr_canonical_base_address();
    virtual bool check_host_tr_canonical_base_address();

    virtual bool check_host_checks_related_to_address_space_size();
    virtual bool check_host_if_outside_ia32e_mode();
    virtual bool check_host_vmcs_host_address_space_size_is_set();
    virtual bool check_host_verify_pae_is_enabled();
    virtual bool check_host_verify_rip_has_canonical_address();

    virtual bool check_guest_checks_on_guest_control_registers_debug_registers_and_msrs();
    virtual bool check_guest_cr0_for_unsupported_bits();
    virtual bool check_guest_cr0_verify_paging_enabled();
    virtual bool check_guest_cr0_verify_protected_mode_enabled();
    virtual bool check_guest_cr4_for_unsupported_bits();
    virtual bool check_guest_load_debug_controls_verify_reserved_bits_equal_zero();
    virtual bool check_guest_verify_ia_32e_mode_enabled();
    virtual bool check_guest_cr4_verify_pae_enabled();
    virtual bool check_guest_cr3_for_unsupported_bits();
    virtual bool check_guest_load_debug_controls_verify_verify_dr7();
    virtual bool check_guest_ia32_sysenter_esp_canonical_address();
    virtual bool check_guest_ia32_sysenter_eip_canonical_address();
    virtual bool check_guest_ia32_perf_global_ctrl_for_reserved_bits();
    virtual bool check_guest_ia32_pat_for_unsupported_bits();
    virtual bool check_guest_verify_load_ia32_efer_enabled();
    virtual bool check_guest_ia32_efer_for_reserved_bits();
    virtual bool check_guest_ia32_efer_set();

    virtual bool check_guest_checks_on_guest_segment_registers();
    virtual bool check_guest_v8086_mode_disabled();
    virtual bool check_guest_unrestricted_guest_disabled();
    virtual bool check_guest_tr_ti_bit_equals_0();
    virtual bool check_guest_ldtr_ti_bit_equals_0();
    virtual bool check_guest_ss_and_cs_rpl_are_the_same();
    virtual bool check_guest_tr_base_is_canonical();
    virtual bool check_guest_fs_base_is_canonical();
    virtual bool check_guest_gs_base_is_canonical();
    virtual bool check_guest_ldtr_base_is_canonical();
    virtual bool check_guest_cs_base_upper_dword_0();
    virtual bool check_guest_ss_base_upper_dword_0();
    virtual bool check_guest_ds_base_upper_dword_0();
    virtual bool check_guest_es_base_upper_dword_0();
    virtual bool check_guest_cs_access_rights_type();
    virtual bool check_guest_ss_access_rights_type();
    virtual bool check_guest_ds_access_rights_type();
    virtual bool check_guest_es_access_rights_type();
    virtual bool check_guest_fs_access_rights_type();
    virtual bool check_guest_gs_access_rights_type();
    virtual bool check_guest_cs_is_not_a_system_descriptor();
    virtual bool check_guest_ss_is_not_a_system_descriptor();
    virtual bool check_guest_ds_is_not_a_system_descriptor();
    virtual bool check_guest_es_is_not_a_system_descriptor();
    virtual bool check_guest_fs_is_not_a_system_descriptor();
    virtual bool check_guest_gs_is_not_a_system_descriptor();
    virtual bool check_guest_cs_type_not_equal_3();
    virtual bool check_guest_cs_dpl_adheres_to_ss_dpl();
    virtual bool check_guest_ss_dpl_must_equal_rpl();
    virtual bool check_guest_ss_dpl_must_equal_zero();
    virtual bool check_guest_ds_dpl();
    virtual bool check_guest_es_dpl();
    virtual bool check_guest_fs_dpl();
    virtual bool check_guest_gs_dpl();
    virtual bool check_guest_cs_must_be_present();
    virtual bool check_guest_ss_must_be_present_if_usable();
    virtual bool check_guest_ds_must_be_present_if_usable();
    virtual bool check_guest_es_must_be_present_if_usable();
    virtual bool check_guest_fs_must_be_present_if_usable();
    virtual bool check_guest_gs_must_be_present_if_usable();
    virtual bool check_guest_cs_access_rights_reserved_must_be_0();
    virtual bool check_guest_ss_access_rights_reserved_must_be_0();
    virtual bool check_guest_ds_access_rights_reserved_must_be_0();
    virtual bool check_guest_es_access_rights_reserved_must_be_0();
    virtual bool check_guest_fs_access_rights_reserved_must_be_0();
    virtual bool check_guest_gs_access_rights_reserved_must_be_0();
    virtual bool check_guest_cs_db_must_be_0_if_l_equals_1();
    virtual bool check_guest_cs_granularity();
    virtual bool check_guest_ss_granularity();
    virtual bool check_guest_ds_granularity();
    virtual bool check_guest_es_granularity();
    virtual bool check_guest_fs_granularity();
    virtual bool check_guest_gs_granularity();
    virtual bool check_guest_cs_access_rights_remaining_reserved_bit_0();
    virtual bool check_guest_ss_access_rights_remaining_reserved_bit_0();
    virtual bool check_guest_ds_access_rights_remaining_reserved_bit_0();
    virtual bool check_guest_es_access_rights_remaining_reserved_bit_0();
    virtual bool check_guest_fs_access_rights_remaining_reserved_bit_0();
    virtual bool check_guest_gs_access_rights_remaining_reserved_bit_0();
    virtual bool check_guest_tr_type_must_be_11();
    virtual bool check_guest_tr_must_be_a_system_descriptor();
    virtual bool check_guest_tr_must_be_present();
    virtual bool check_guest_tr_access_rights_reserved_must_be_0();
    virtual bool check_guest_tr_granularity();
    virtual bool check_guest_tr_must_be_usable();
    virtual bool check_guest_tr_access_rights_remaining_reserved_bit_0();
    virtual bool check_guest_ldtr_type_must_be_2();
    virtual bool check_guest_ldtr_must_be_a_system_descriptor();
    virtual bool check_guest_ldtr_must_be_present();
    virtual bool check_guest_ldtr_access_rights_reserved_must_be_0();
    virtual bool check_guest_ldtr_granularity();
    virtual bool check_guest_ldtr_access_rights_remaining_reserved_bit_0();

    virtual bool check_guest_checks_on_guest_descriptor_table_registers();
    virtual bool check_guest_gdtr_base_must_be_canonical();
    virtual bool check_guest_idtr_base_must_be_canonical();
    virtual bool check_guest_gdtr_limit_reserved_bits();
    virtual bool check_guest_idtr_limit_reserved_bits();

    virtual bool check_guest_checks_on_guest_rip_and_rflags();
    virtual bool check_guest_rflags_reserved_bits();
    virtual bool check_guest_rflag_interrupt_enable();

    virtual bool check_guest_checks_on_guest_non_register_state();
    virtual bool check_guest_valid_activity_state();
    virtual bool check_guest_activity_state_not_hlt_when_dpl_not_0();
    virtual bool check_guest_must_be_active_if_injecting_blocking_state();
    virtual bool check_guest_valid_interruptability_and_activity_state_combo();
    virtual bool check_guest_valid_activity_state_and_smm();
    virtual bool check_guest_all_interruptability_state_fields();
    virtual bool check_guest_all_vmcs_link_pointerchecks();

    virtual bool check_control_checks_on_vm_execution_control_fields();
    virtual bool check_control_pin_based_ctls_reserved_properly_set();
    virtual bool check_control_proc_based_ctls_reserved_properly_set();
    virtual bool check_control_cr3_count_less_then_4();
    virtual bool check_control_io_bitmap_address_bits();
    virtual bool check_control_msr_bitmap_address_bits();
    virtual bool check_control_tpr_shadow_and_virtual_apic();
    virtual bool check_control_nmi_exiting_and_virtual_nmi();
    virtual bool check_control_virtual_nmi_and_nmi_window();
    virtual bool check_control_virtual_apic_address_bits();
    virtual bool check_control_virtual_x2apic_and_tpr();
    virtual bool check_control_register_apic_mode_and_tpr();
    virtual bool check_control_virtual_interrupt_delivery_and_tpr();
    virtual bool check_control_x2apic_mode_and_virtual_apic_access();
    virtual bool check_control_virtual_interrupt_and_external_interrupt();
    virtual bool check_control_process_posted_interrupt_checks();
    virtual bool check_control_vpid_checks();
    virtual bool check_control_enable_ept_checks();
    virtual bool check_control_unrestricted_guests();
    virtual bool check_control_enable_vm_functions();
    virtual bool check_control_enable_vmcs_shadowing();
    virtual bool check_control_enable_ept_violation_checks();

    virtual bool check_control_checks_on_vm_exit_control_fields();
    virtual bool check_control_vm_exit_ctls_reserved_properly_set();
    virtual bool check_control_activate_and_save_premeption_timer_must_be_0();
    virtual bool check_control_exit_msr_store_address();
    virtual bool check_control_exit_msr_load_address();

    virtual bool check_control_checks_on_vm_entry_control_fields();
    virtual bool check_control_vm_entry_ctls_reserved_properly_set();
    virtual bool check_control_event_injection_checks();
    virtual bool check_control_entry_msr_load_address();

private:

    friend class vmcs_ut;

    bitmap m_msr_bitmap;
    bitmap m_io_bitmap_a;
    bitmap m_io_bitmap_b;

    uint64_t m_msr_bitmap_phys;
    uint64_t m_io_bitmap_a_phys;
    uint64_t m_io_bitmap_b_phys;

    intrinsics_intel_x64 *m_intrinsics;

    uint64_t m_vmcs_region_phys;
    std::unique_ptr<char[]> m_vmcs_region;
};

#endif
