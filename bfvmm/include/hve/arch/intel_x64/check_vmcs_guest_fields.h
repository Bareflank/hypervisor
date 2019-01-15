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

#ifndef VMCS_INTEL_X64_CHECK_GUEST_H
#define VMCS_INTEL_X64_CHECK_GUEST_H

/// Intel x86_64 VMCS Check Guest
///
/// This namespace implements the guest checks found in
/// section 26.3, Vol. 3 of the SDM.
///

namespace bfvmm
{
namespace intel_x64
{
namespace check
{

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
void guest_gdtr_base_must_be_canonical();
void guest_idtr_base_must_be_canonical();
void guest_gdtr_limit_reserved_bits();
void guest_idtr_limit_reserved_bits();
void guest_rip_upper_bits();
void guest_rip_valid_addr();
void guest_rflags_reserved_bits();
void guest_rflags_vm_bit();
void guest_rflag_interrupt_enable();
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
void guest_valid_pdpte_with_ept_disabled();
void guest_valid_pdpte_with_ept_enabled();

}
}
}

#endif
