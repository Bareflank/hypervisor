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

#ifndef VMCS_INTEL_X64_CHECK_H
#define VMCS_INTEL_X64_CHECK_H

#include <type_traits>
#include <intrinsics/x64.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>

/// Intel x86_64 VMCS Check
///
/// This namespace implements the checks found in sections 26.1 through
/// 26.3, Vol. 3 of the Intel manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{
namespace check
{

void all();
void control_vmx_controls_all();
void control_vm_execution_control_fields_all();
void control_pin_based_ctls_reserved_properly_set();
void control_proc_based_ctls_reserved_properly_set();
void control_proc_based_ctls2_reserved_properly_set();
void control_cr3_count_less_then_4();
void control_io_bitmap_address_bits();
void control_msr_bitmap_address_bits();
void control_tpr_shadow_and_virtual_apic();
void control_nmi_exiting_and_virtual_nmi();
void control_virtual_nmi_and_nmi_window();
void control_virtual_apic_address_bits();
void control_x2apic_mode_and_virtual_apic_access();
void control_virtual_interrupt_and_external_interrupt();
void control_process_posted_interrupt_checks();
void control_vpid_checks();
void control_enable_ept_checks();
void control_unrestricted_guests();
void control_enable_vm_functions();
void control_enable_vmcs_shadowing();
void control_enable_ept_violation_checks();
void control_enable_pml_checks();

void control_vm_exit_control_fields_all();
void control_vm_exit_ctls_reserved_properly_set();
void control_activate_and_save_preemption_timer_must_be_0();
void control_exit_msr_store_address();
void control_exit_msr_load_address();

void control_vm_entry_control_fields_all();
void control_vm_entry_ctls_reserved_properly_set();
void control_event_injection_type_vector_checks();
void control_event_injection_delivery_ec_checks();
void control_event_injection_reserved_bits_checks();
void control_event_injection_ec_checks();
void control_event_injection_instr_length_checks();
void control_entry_msr_load_address();

void host_state_all();
void host_control_registers_and_msrs_all();
void host_cr0_for_unsupported_bits();
void host_cr4_for_unsupported_bits();
void host_cr3_for_unsupported_bits();
void host_ia32_sysenter_esp_canonical_address();
void host_ia32_sysenter_eip_canonical_address();
void host_verify_load_ia32_perf_global_ctrl();
void host_verify_load_ia32_pat();
void host_verify_load_ia32_efer();

void host_segment_and_descriptor_table_registers_all();
void host_es_selector_rpl_ti_equal_zero();
void host_cs_selector_rpl_ti_equal_zero();
void host_ss_selector_rpl_ti_equal_zero();
void host_ds_selector_rpl_ti_equal_zero();
void host_fs_selector_rpl_ti_equal_zero();
void host_gs_selector_rpl_ti_equal_zero();
void host_tr_selector_rpl_ti_equal_zero();
void host_cs_not_equal_zero();
void host_tr_not_equal_zero();
void host_ss_not_equal_zero();
void host_fs_canonical_base_address();
void host_gs_canonical_base_address();
void host_gdtr_canonical_base_address();
void host_idtr_canonical_base_address();
void host_tr_canonical_base_address();

void host_address_space_size_all();
void host_if_outside_ia32e_mode();
void host_address_space_size_exit_ctl_is_set();
void host_address_space_disabled();
void host_address_space_enabled();

void guest_state_all();
void guest_control_registers_debug_registers_and_msrs_all();
void guest_cr0_for_unsupported_bits();
void guest_cr0_verify_paging_enabled();
void guest_cr4_for_unsupported_bits();
void guest_load_debug_controls_verify_reserved();
void guest_verify_ia_32e_mode_enabled();
void guest_verify_ia_32e_mode_disabled();
void guest_cr3_for_unsupported_bits();
void guest_load_debug_controls_verify_dr7();
void guest_ia32_sysenter_esp_canonical_address();
void guest_ia32_sysenter_eip_canonical_address();
void guest_verify_load_ia32_perf_global_ctrl();
void guest_verify_load_ia32_pat();
void guest_verify_load_ia32_efer();
void guest_verify_load_ia32_bndcfgs();

void guest_segment_registers_all();
void guest_tr_ti_bit_equals_0();
void guest_ldtr_ti_bit_equals_0();
void guest_ss_and_cs_rpl_are_the_same();
void guest_cs_base_is_shifted();
void guest_ss_base_is_shifted();
void guest_ds_base_is_shifted();
void guest_es_base_is_shifted();
void guest_fs_base_is_shifted();
void guest_gs_base_is_shifted();
void guest_tr_base_is_canonical();
void guest_fs_base_is_canonical();
void guest_gs_base_is_canonical();
void guest_ldtr_base_is_canonical();
void guest_cs_base_upper_dword_0();
void guest_ss_base_upper_dword_0();
void guest_ds_base_upper_dword_0();
void guest_es_base_upper_dword_0();
void guest_cs_limit();
void guest_ss_limit();
void guest_ds_limit();
void guest_es_limit();
void guest_gs_limit();
void guest_fs_limit();
void guest_v8086_cs_access_rights();
void guest_v8086_ss_access_rights();
void guest_v8086_ds_access_rights();
void guest_v8086_es_access_rights();
void guest_v8086_fs_access_rights();
void guest_v8086_gs_access_rights();
void guest_cs_access_rights_type();
void guest_ss_access_rights_type();
void guest_ds_access_rights_type();
void guest_es_access_rights_type();
void guest_fs_access_rights_type();
void guest_gs_access_rights_type();
void guest_cs_is_not_a_system_descriptor();
void guest_ss_is_not_a_system_descriptor();
void guest_ds_is_not_a_system_descriptor();
void guest_es_is_not_a_system_descriptor();
void guest_fs_is_not_a_system_descriptor();
void guest_gs_is_not_a_system_descriptor();
void guest_cs_type_not_equal_3();
void guest_cs_dpl_adheres_to_ss_dpl();
void guest_ss_dpl_must_equal_rpl();
void guest_ss_dpl_must_equal_zero();
void guest_ds_dpl();
void guest_es_dpl();
void guest_fs_dpl();
void guest_gs_dpl();
void guest_cs_must_be_present();
void guest_ss_must_be_present_if_usable();
void guest_ds_must_be_present_if_usable();
void guest_es_must_be_present_if_usable();
void guest_fs_must_be_present_if_usable();
void guest_gs_must_be_present_if_usable();
void guest_cs_access_rights_reserved_must_be_0();
void guest_ss_access_rights_reserved_must_be_0();
void guest_ds_access_rights_reserved_must_be_0();
void guest_es_access_rights_reserved_must_be_0();
void guest_fs_access_rights_reserved_must_be_0();
void guest_gs_access_rights_reserved_must_be_0();
void guest_cs_db_must_be_0_if_l_equals_1();
void guest_cs_granularity();
void guest_ss_granularity();
void guest_ds_granularity();
void guest_es_granularity();
void guest_fs_granularity();
void guest_gs_granularity();
void guest_cs_access_rights_remaining_reserved_bit_0();
void guest_ss_access_rights_remaining_reserved_bit_0();
void guest_ds_access_rights_remaining_reserved_bit_0();
void guest_es_access_rights_remaining_reserved_bit_0();
void guest_fs_access_rights_remaining_reserved_bit_0();
void guest_gs_access_rights_remaining_reserved_bit_0();
void guest_tr_type_must_be_11();
void guest_tr_must_be_a_system_descriptor();
void guest_tr_must_be_present();
void guest_tr_access_rights_reserved_must_be_0();
void guest_tr_granularity();
void guest_tr_must_be_usable();
void guest_tr_access_rights_remaining_reserved_bit_0();
void guest_ldtr_type_must_be_2();
void guest_ldtr_must_be_a_system_descriptor();
void guest_ldtr_must_be_present();
void guest_ldtr_access_rights_reserved_must_be_0();
void guest_ldtr_granularity();
void guest_ldtr_access_rights_remaining_reserved_bit_0();

void guest_descriptor_table_registers_all();
void guest_gdtr_base_must_be_canonical();
void guest_idtr_base_must_be_canonical();
void guest_gdtr_limit_reserved_bits();
void guest_idtr_limit_reserved_bits();

void guest_rip_and_rflags_all();
void guest_rip_upper_bits();
void guest_rip_valid_addr();
void guest_rflags_reserved_bits();
void guest_rflags_vm_bit();
void guest_rflag_interrupt_enable();

void guest_non_register_state_all();
void guest_valid_activity_state();
void guest_activity_state_not_hlt_when_dpl_not_0();
void guest_must_be_active_if_injecting_blocking_state();
void guest_hlt_valid_interrupts();
void guest_shutdown_valid_interrupts();
void guest_sipi_valid_interrupts();
void guest_valid_activity_state_and_smm();
void guest_interruptibility_state_reserved();
void guest_interruptibility_state_sti_mov_ss();
void guest_interruptibility_state_sti();
void guest_interruptibility_state_external_interrupt();
void guest_interruptibility_state_nmi();
void guest_interruptibility_not_in_smm();
void guest_interruptibility_entry_to_smm();
void guest_interruptibility_state_sti_and_nmi();
void guest_interruptibility_state_virtual_nmi();
void guest_interruptibility_state_enclave_interrupt();
void guest_pending_debug_exceptions_reserved();
void guest_pending_debug_exceptions_dbg_ctl();
void guest_pending_debug_exceptions_rtm();
void guest_vmcs_link_pointer_bits_11_0();
void guest_vmcs_link_pointer_valid_addr();
void guest_vmcs_link_pointer_first_word();
void guest_vmcs_link_pointer_not_in_smm();
void guest_vmcs_link_pointer_in_smm();

void guest_pdptes_all();
void guest_valid_pdpte_with_ept_disabled();
void guest_valid_pdpte_with_ept_enabled();

template<class MA, class C,
         class = typename std::enable_if<std::is_integral<MA>::value>::type,
         class = typename std::enable_if<std::is_integral<C>::value>::type>
auto control_reserved_properly_set(MA msr_addr, C ctls, const char *ctls_name)
{
    using namespace vmcs::primary_processor_based_vm_execution_controls;

    auto allowed0 = (msrs::get(msr_addr) & 0x00000000FFFFFFFFUL);
    auto allowed1 = ((msrs::get(msr_addr) >> 32) & 0x00000000FFFFFFFFUL);
    auto allowed1_failed = false;
    ctls &= 0x00000000FFFFFFFFUL;

    if ((allowed0 & ctls) != allowed0)
    {
        bferror << " failed: controls_reserved_properly_set" << '\n';
        bferror << "    - allowed0: " << view_as_pointer(allowed0) << '\n';
        bferror << "    - bad ctls: " << view_as_pointer(ctls) << '\n';

        throw std::logic_error("invalid "_s + ctls_name);
    }

    allowed1_failed = (ctls & ~allowed1) != 0UL;

    if (msrs::ia32_vmx_procbased_ctls2::addr == msr_addr)
        allowed1_failed = allowed1_failed && activate_secondary_controls::is_enabled();

    if (allowed1_failed)
    {
        bferror << " failed: check_control_ctls_reserved_properly_set" << '\n';
        bferror << "    - allowed1: " << view_as_pointer(allowed1) << '\n';
        bferror << "    - bad ctls: " << view_as_pointer(ctls) << '\n';

        throw std::logic_error("invalid "_s + ctls_name);
    }
}

template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
auto memory_type_reserved(T memory_type)
{
    switch (memory_type)
    {
        case x64::memory_type::uncacheable:
        case x64::memory_type::write_combining:
        case x64::memory_type::write_through:
        case x64::memory_type::write_protected:
        case x64::memory_type::write_back:
        case x64::memory_type::uncached:
            return false;

        default:
            return true;
    }
}

}
}
}

// *INDENT-ON*

#endif
