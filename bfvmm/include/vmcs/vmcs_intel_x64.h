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

#include <intrinsics/intrinsics_intel_x64.h>
#include <memory_manager/memory_manager.h>
#include <vmcs/bitmap.h>

namespace vmcs_error
{
    enum type
    {
        success = 0,
        failure = 1,
        not_supported = 2,
        out_of_memory = 3
    };
}

class vmcs_intel_x64
{
public:

    /// Default Constructor
    ///
    vmcs_intel_x64(intrinsics_intel_x64 *intrinsics);

    /// Destructor
    ///
    virtual ~vmcs_intel_x64() {}

    /// Launch VMM
    ///
    /// Launches the VMCS. Note that this will create a new guest VM when
    /// it is complete.
    ///
    /// @return success on success, out_of_memory is the provided memory
    ///     manager is out of memory, not_supported if the current hardware
    ///     and/or software configuration is not supported, failure otherwise
    ///
    virtual vmcs_error::type launch();

    virtual vmcs_error::type unlaunch();
    virtual vmcs_error::type clear_vmcs_region();

protected:

    virtual vmcs_error::type launch_vmcs();
    virtual vmcs_error::type resume_vmcs();

    virtual vmcs_error::type save_state();

    virtual vmcs_error::type create_vmcs_region();
    virtual vmcs_error::type release_vmxon_region();


    virtual vmcs_error::type load_vmcs_region();

    virtual uint64_t vmcs_region_size();

    virtual vmcs_error::type write_16bit_control_fields();
    virtual vmcs_error::type write_16bit_guest_state_fields();
    virtual vmcs_error::type write_16bit_host_state_fields();
    virtual vmcs_error::type write_64bit_control_fields();
    virtual vmcs_error::type write_64bit_guest_state_fields();
    virtual vmcs_error::type write_64bit_host_state_fields();
    virtual vmcs_error::type write_32bit_control_fields();
    virtual vmcs_error::type write_32bit_guest_state_fields();
    virtual vmcs_error::type write_32bit_host_state_fields();
    virtual vmcs_error::type write_natural_width_control_fields();
    virtual vmcs_error::type write_natural_width_guest_state_fields();
    virtual vmcs_error::type write_natural_width_host_state_fields();

    virtual vmcs_error::type default_pin_based_vm_execution_controls();
    virtual vmcs_error::type default_primary_processor_based_vm_execution_controls();
    virtual vmcs_error::type default_secondary_processor_based_vm_execution_controls();
    virtual vmcs_error::type default_vm_exit_controls();
    virtual vmcs_error::type default_vm_entry_controls();

    virtual void vmwrite(uint64_t field, uint64_t value);
    virtual uint64_t vmread(uint64_t field);

    virtual void dump_vmcs();
    virtual void dump_state();

    virtual void print_execution_controls();
    virtual void print_pin_based_vm_execution_controls();
    virtual void print_primary_processor_based_vm_execution_controls();
    virtual void print_secondary_processor_based_vm_execution_controls();
    virtual void print_vm_exit_control_fields();
    virtual void print_vm_entry_control_fields();

    virtual void check_vm_instruction_error();
    virtual bool check_is_address_canonical(uint64_t addr);
    virtual bool check_vmcs_host_state();
    virtual bool check_vmcs_guest_state();
    virtual bool check_vmcs_control_state();

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

    bitmap *m_msr_bitmap;

    uint16_t m_es;
    uint16_t m_cs;
    uint16_t m_ss;
    uint16_t m_ds;
    uint16_t m_fs;
    uint16_t m_gs;
    uint16_t m_tr;
    uint16_t m_ldtr;

    uint64_t m_cr0;
    uint64_t m_cr3;
    uint64_t m_cr4;
    uint64_t m_dr7;
    uint64_t m_rflags;

    gdt_t m_gdt_reg;
    idt_t m_idt_reg;

    uint32_t m_es_limit;
    uint32_t m_cs_limit;
    uint32_t m_ss_limit;
    uint32_t m_ds_limit;
    uint32_t m_fs_limit;
    uint32_t m_gs_limit;
    uint32_t m_ldtr_limit;
    uint32_t m_tr_limit;

    uint32_t m_es_access;
    uint32_t m_cs_access;
    uint32_t m_ss_access;
    uint32_t m_ds_access;
    uint32_t m_fs_access;
    uint32_t m_gs_access;
    uint32_t m_ldtr_access;
    uint32_t m_tr_access;

    uint64_t m_es_base;
    uint64_t m_cs_base;
    uint64_t m_ss_base;
    uint64_t m_ds_base;
    uint64_t m_fs_base;
    uint64_t m_gs_base;
    uint64_t m_ldtr_base;
    uint64_t m_tr_base;

    bool m_valid;
    char *m_vmcs_region;

    intrinsics_intel_x64 *m_intrinsics;
};

#endif
