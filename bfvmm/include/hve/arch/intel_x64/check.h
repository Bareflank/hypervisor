//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef VMCS_INTEL_X64_CHECK_H
#define VMCS_INTEL_X64_CHECK_H

#include "check_vmcs_host_fields.h"
#include "check_vmcs_guest_fields.h"
#include "check_vmcs_control_fields.h"

/// Intel x86_64 VMCS Check
///
/// This namespace implements the checks found in sections 26.1 through
/// 26.3, Vol. 3 of the SDM.
///

// *INDENT-OFF*

namespace bfvmm
{
namespace intel_x64
{
namespace check
{

inline void
all()
{
    control_vm_exit_ctls_reserved_properly_set();
    control_activate_and_save_preemption_timer_must_be_0();
    control_exit_msr_store_address();
    control_exit_msr_load_address();
    control_vm_entry_ctls_reserved_properly_set();
    control_event_injection_type_vector_checks();
    control_event_injection_delivery_ec_checks();
    control_event_injection_reserved_bits_checks();
    control_event_injection_ec_checks();
    control_event_injection_instr_length_checks();
    control_entry_msr_load_address();
    control_pin_based_ctls_reserved_properly_set();
    control_proc_based_ctls_reserved_properly_set();
    control_proc_based_ctls2_reserved_properly_set();
    control_cr3_count_less_then_4();
    control_io_bitmap_address_bits();
    control_msr_bitmap_address_bits();
    control_tpr_shadow_and_virtual_apic();
    control_nmi_exiting_and_virtual_nmi();
    control_virtual_nmi_and_nmi_window();
    control_virtual_apic_address_bits();
    control_x2apic_mode_and_virtual_apic_access();
    control_virtual_interrupt_and_external_interrupt();
    control_process_posted_interrupt_checks();
    control_vpid_checks();
    control_enable_ept_checks();
    control_enable_pml_checks();
    control_unrestricted_guests();
    control_enable_vm_functions();
    control_enable_vmcs_shadowing();
    control_enable_ept_violation_checks();

    guest_tr_ti_bit_equals_0();
    guest_ldtr_ti_bit_equals_0();
    guest_ss_and_cs_rpl_are_the_same();
    guest_cs_base_is_shifted();
    guest_ss_base_is_shifted();
    guest_ds_base_is_shifted();
    guest_es_base_is_shifted();
    guest_fs_base_is_shifted();
    guest_gs_base_is_shifted();
    guest_tr_base_is_canonical();
    guest_fs_base_is_canonical();
    guest_gs_base_is_canonical();
    guest_ldtr_base_is_canonical();
    guest_cs_base_upper_dword_0();
    guest_ss_base_upper_dword_0();
    guest_ds_base_upper_dword_0();
    guest_es_base_upper_dword_0();
    guest_cs_limit();
    guest_ss_limit();
    guest_ds_limit();
    guest_es_limit();
    guest_gs_limit();
    guest_fs_limit();
    guest_v8086_cs_access_rights();
    guest_v8086_ss_access_rights();
    guest_v8086_ds_access_rights();
    guest_v8086_es_access_rights();
    guest_v8086_fs_access_rights();
    guest_v8086_gs_access_rights();
    guest_cs_access_rights_type();
    guest_ss_access_rights_type();
    guest_ds_access_rights_type();
    guest_es_access_rights_type();
    guest_fs_access_rights_type();
    guest_gs_access_rights_type();
    guest_cs_is_not_a_system_descriptor();
    guest_ss_is_not_a_system_descriptor();
    guest_ds_is_not_a_system_descriptor();
    guest_es_is_not_a_system_descriptor();
    guest_fs_is_not_a_system_descriptor();
    guest_gs_is_not_a_system_descriptor();
    guest_cs_type_not_equal_3();
    guest_cs_dpl_adheres_to_ss_dpl();
    guest_ss_dpl_must_equal_rpl();
    guest_ss_dpl_must_equal_zero();
    guest_ds_dpl();
    guest_es_dpl();
    guest_fs_dpl();
    guest_gs_dpl();
    guest_cs_must_be_present();
    guest_ss_must_be_present_if_usable();
    guest_ds_must_be_present_if_usable();
    guest_es_must_be_present_if_usable();
    guest_fs_must_be_present_if_usable();
    guest_gs_must_be_present_if_usable();
    guest_cs_access_rights_reserved_must_be_0();
    guest_ss_access_rights_reserved_must_be_0();
    guest_ds_access_rights_reserved_must_be_0();
    guest_es_access_rights_reserved_must_be_0();
    guest_fs_access_rights_reserved_must_be_0();
    guest_gs_access_rights_reserved_must_be_0();
    guest_cs_db_must_be_0_if_l_equals_1();
    guest_cs_granularity();
    guest_ss_granularity();
    guest_ds_granularity();
    guest_es_granularity();
    guest_fs_granularity();
    guest_gs_granularity();
    guest_cs_access_rights_remaining_reserved_bit_0();
    guest_ss_access_rights_remaining_reserved_bit_0();
    guest_ds_access_rights_remaining_reserved_bit_0();
    guest_es_access_rights_remaining_reserved_bit_0();
    guest_fs_access_rights_remaining_reserved_bit_0();
    guest_gs_access_rights_remaining_reserved_bit_0();
    guest_tr_type_must_be_11();
    guest_tr_must_be_a_system_descriptor();
    guest_tr_must_be_present();
    guest_tr_access_rights_reserved_must_be_0();
    guest_tr_granularity();
    guest_tr_must_be_usable();
    guest_tr_access_rights_remaining_reserved_bit_0();
    guest_ldtr_type_must_be_2();
    guest_ldtr_must_be_a_system_descriptor();
    guest_ldtr_must_be_present();
    guest_ldtr_access_rights_reserved_must_be_0();
    guest_ldtr_granularity();
    guest_ldtr_access_rights_remaining_reserved_bit_0();
    guest_gdtr_base_must_be_canonical();
    guest_idtr_base_must_be_canonical();
    guest_gdtr_limit_reserved_bits();
    guest_idtr_limit_reserved_bits();
    guest_rip_upper_bits();
    guest_rip_valid_addr();
    guest_rflags_reserved_bits();
    guest_rflags_vm_bit();
    guest_rflag_interrupt_enable();
    guest_valid_activity_state();
    guest_activity_state_not_hlt_when_dpl_not_0();
    guest_must_be_active_if_injecting_blocking_state();
    guest_hlt_valid_interrupts();
    guest_shutdown_valid_interrupts();
    guest_sipi_valid_interrupts();
    guest_valid_activity_state_and_smm();
    guest_interruptibility_state_reserved();
    guest_interruptibility_state_sti_mov_ss();
    guest_interruptibility_state_sti();
    guest_interruptibility_state_external_interrupt();
    guest_interruptibility_state_nmi();
    guest_interruptibility_not_in_smm();
    guest_interruptibility_entry_to_smm();
    guest_interruptibility_state_sti_and_nmi();
    guest_interruptibility_state_virtual_nmi();
    guest_interruptibility_state_enclave_interrupt();
    guest_pending_debug_exceptions_reserved();
    guest_pending_debug_exceptions_dbg_ctl();
    guest_pending_debug_exceptions_rtm();
    guest_vmcs_link_pointer_bits_11_0();
    guest_vmcs_link_pointer_valid_addr();
    guest_vmcs_link_pointer_first_word();
    guest_vmcs_link_pointer_not_in_smm();
    guest_vmcs_link_pointer_in_smm();
    guest_cr0_for_unsupported_bits();
    guest_cr0_verify_paging_enabled();
    guest_cr4_for_unsupported_bits();
    guest_load_debug_controls_verify_reserved();
    guest_verify_ia_32e_mode_enabled();
    guest_verify_ia_32e_mode_disabled();
    guest_cr3_for_unsupported_bits();
    guest_load_debug_controls_verify_dr7();
    guest_ia32_sysenter_esp_canonical_address();
    guest_ia32_sysenter_eip_canonical_address();
    guest_verify_load_ia32_perf_global_ctrl();
    guest_verify_load_ia32_pat();
    guest_verify_load_ia32_efer();
    guest_verify_load_ia32_bndcfgs();
    guest_valid_pdpte_with_ept_disabled();
    guest_valid_pdpte_with_ept_enabled();

    host_es_selector_rpl_ti_equal_zero();
    host_cs_selector_rpl_ti_equal_zero();
    host_ss_selector_rpl_ti_equal_zero();
    host_ds_selector_rpl_ti_equal_zero();
    host_fs_selector_rpl_ti_equal_zero();
    host_gs_selector_rpl_ti_equal_zero();
    host_tr_selector_rpl_ti_equal_zero();
    host_cs_not_equal_zero();
    host_tr_not_equal_zero();
    host_ss_not_equal_zero();
    host_fs_canonical_base_address();
    host_gs_canonical_base_address();
    host_gdtr_canonical_base_address();
    host_idtr_canonical_base_address();
    host_tr_canonical_base_address();
    host_if_outside_ia32e_mode();
    host_address_space_size_exit_ctl_is_set();
    host_address_space_disabled();
    host_address_space_enabled();
    host_cr0_for_unsupported_bits();
    host_cr4_for_unsupported_bits();
    host_cr3_for_unsupported_bits();
    host_ia32_sysenter_esp_canonical_address();
    host_ia32_sysenter_eip_canonical_address();
    host_verify_load_ia32_perf_global_ctrl();
    host_verify_load_ia32_pat();
    host_verify_load_ia32_efer();
}

}
}
}

// *INDENT-ON*

#endif
