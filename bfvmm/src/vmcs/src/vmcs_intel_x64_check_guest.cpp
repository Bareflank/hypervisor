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

#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_exceptions.h>
#include <memory_manager/memory_manager.h>

void
vmcs_intel_x64::check_vmcs_guest_state()
{
    checks_on_guest_control_registers_debug_registers_and_msrs();
    checks_on_guest_segment_registers();
    checks_on_guest_descriptor_table_registers();
    checks_on_guest_rip_and_rflags();
    checks_on_guest_non_register_state();
}

void
vmcs_intel_x64::checks_on_guest_control_registers_debug_registers_and_msrs()
{
    check_guest_cr0_for_unsupported_bits();
    check_guest_cr0_verify_paging_enabled();
    check_guest_cr4_for_unsupported_bits();
    check_guest_load_debug_controls_verify_reserved();
    check_guest_verify_ia_32e_mode_enabled();
    check_guest_verify_ia_32e_mode_disabled();
    check_guest_cr3_for_unsupported_bits();
    check_guest_load_debug_controls_verify_dr7();
    check_guest_ia32_sysenter_esp_canonical_address();
    check_guest_ia32_sysenter_eip_canonical_address();
    check_guest_verify_load_ia32_perf_global_ctrl();
    check_guest_verify_load_ia32_pat();
    check_guest_verify_load_ia32_efer();
}

void
vmcs_intel_x64::check_guest_cr0_for_unsupported_bits()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);
    auto ia32_vmx_cr0_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED0_MSR);
    auto ia32_vmx_cr0_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED1_MSR);

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
        throw vmcs_invalid_ctrl(cr0, ia32_vmx_cr0_fixed0, ia32_vmx_cr0_fixed1);
}

void
vmcs_intel_x64::check_guest_cr0_verify_paging_enabled()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);

    if ((cr0 & CR0_PG_PAGING) == 0)
        return;

    if ((cr0 & CRO_PE_PROTECTION_ENABLE) == 0)
        throw vmcs_invalid_field("PE must be inabled in cr0 if PG is enabled",
                                 cr0);
}

void
vmcs_intel_x64::check_guest_cr4_for_unsupported_bits()
{
    auto cr4 = vmread(VMCS_GUEST_CR4);
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
        throw vmcs_invalid_ctrl(cr4, ia32_vmx_cr4_fixed0, ia32_vmx_cr4_fixed1);
}

void
vmcs_intel_x64::check_guest_load_debug_controls_verify_reserved()
{
    if (is_enabled_load_debug_controls_on_entry() == false)
        return;

    auto vmcs_ia32_debugctl =
        vmread(VMCS_GUEST_IA32_DEBUGCTL_FULL);

    if ((vmcs_ia32_debugctl & 0xFFFFFFFFFFFF003C) != 0)
        throw vmcs_invalid_field("debug ctrl msr reserved bits must be 0",
                                 vmcs_ia32_debugctl);
}

void
vmcs_intel_x64::check_guest_verify_ia_32e_mode_enabled()
{
    if (is_enabled_ia_32e_mode_guest() == false)
        return;

    auto cr0 = vmread(VMCS_GUEST_CR0);
    auto cr4 = vmread(VMCS_GUEST_CR4);

    if ((cr0 & CR0_PG_PAGING) == 0)
        throw vmcs_invalid_field("paging must be enabled if "
                                 "ia 32e guest mode is enabled", cr0);

    if ((cr4 & CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS) == 0)
        throw vmcs_invalid_field("pae must be enabled if "
                                 "ia 32e guest mode is enabled", cr4);
}

void
vmcs_intel_x64::check_guest_verify_ia_32e_mode_disabled()
{
    if (is_enabled_ia_32e_mode_guest() == true)
        return;

    auto cr4 = vmread(VMCS_GUEST_CR4);

    if ((cr4 & CR4_PCIDE_PCID_ENABLE_BIT) != 0)
        throw vmcs_invalid_field("pcide in cr4 must be disabled if "
                                 "ia 32e guest mode is disabled", cr4);
}

void
vmcs_intel_x64::check_guest_cr3_for_unsupported_bits()
{
    auto cr3 = vmread(VMCS_GUEST_CR0);

    if (is_physical_address_valid(cr3) == false)
        throw invalid_address("guest cr3 too large", cr3);
}

void
vmcs_intel_x64::check_guest_load_debug_controls_verify_dr7()
{
    if (is_enabled_load_debug_controls_on_entry() == false)
        return;

    auto dr7 = vmread(VMCS_GUEST_DR7);

    if ((dr7 & 0xFFFFFFFF00000000) != 0)
        throw vmcs_invalid_field("bits 63:32 must be 0 if "
                                 "load debug controls is 1", dr7);
}

void
vmcs_intel_x64::check_guest_ia32_sysenter_esp_canonical_address()
{
    auto esp = vmread(VMCS_GUEST_IA32_SYSENTER_ESP);

    if (is_address_canonical(esp) == false)
        throw invalid_address("guest esp must be canonical", esp);
}

void
vmcs_intel_x64::check_guest_ia32_sysenter_eip_canonical_address()
{
    auto eip = vmread(VMCS_GUEST_IA32_SYSENTER_EIP);

    if (is_address_canonical(eip) == false)
        throw invalid_address("guest eip must be canonical", eip);
}

void
vmcs_intel_x64::check_guest_verify_load_ia32_perf_global_ctrl()
{
    if (is_enabled_load_ia32_perf_global_ctrl_on_entry() == false)
        return;

    auto vmcs_ia32_perf_global_ctrl =
        vmread(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);

    if ((vmcs_ia32_perf_global_ctrl & 0xFFFFFFF8FFFFFFFC) != 0)
        throw vmcs_invalid_field("perf global ctrl msr reserved bits must be 0",
                                 vmcs_ia32_perf_global_ctrl);
}

void
vmcs_intel_x64::check_guest_verify_load_ia32_pat()
{
    if (is_enabled_load_ia32_pat_on_entry() == false)
        return;

    auto pat0 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0x00000000000000FF >> 0;
    auto pat1 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0x000000000000FF00 >> 8;
    auto pat2 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0x0000000000FF0000 >> 16;
    auto pat3 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0x00000000FF000000 >> 24;
    auto pat4 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0x000000FF00000000 >> 32;
    auto pat5 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0x0000FF0000000000 >> 40;
    auto pat6 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0x00FF000000000000 >> 48;
    auto pat7 = vmread(VMCS_GUEST_IA32_PAT_FULL) & 0xFF00000000000000 >> 56;

    if (check_pat(pat0) == false)
        throw vmcs_invalid_field("pat0 has an invalid memory type", pat0);

    if (check_pat(pat1) == false)
        throw vmcs_invalid_field("pat1 has an invalid memory type", pat1);

    if (check_pat(pat2) == false)
        throw vmcs_invalid_field("pat2 has an invalid memory type", pat2);

    if (check_pat(pat3) == false)
        throw vmcs_invalid_field("pat3 has an invalid memory type", pat3);

    if (check_pat(pat4) == false)
        throw vmcs_invalid_field("pat4 has an invalid memory type", pat4);

    if (check_pat(pat5) == false)
        throw vmcs_invalid_field("pat5 has an invalid memory type", pat5);

    if (check_pat(pat6) == false)
        throw vmcs_invalid_field("pat6 has an invalid memory type", pat6);

    if (check_pat(pat7) == false)
        throw vmcs_invalid_field("pat7 has an invalid memory type", pat7);
}

void
vmcs_intel_x64::check_guest_verify_load_ia32_efer()
{
    if (is_enabled_load_ia32_efer_on_entry() == false)
        return;

    auto efer = vmread(VMCS_GUEST_IA32_EFER_FULL);

    if ((efer & 0xFFFFFFFFFFFFF2FE) != 0)
        throw vmcs_invalid_field("ia32 efer msr reserved buts must be 0 if "
                                 "load ia32 efer entry is enabled", efer);

    auto cr0 = vmread(VMCS_GUEST_CR0);
    auto lma = (efer && IA32_EFER_LMA);
    auto lme = (efer && IA32_EFER_LME);

    if (is_enabled_ia_32e_mode_guest() == false && lma != 0)
        throw vmcs_invalid_field("ia 32e mode is 0, but efer.lma is 1. "
                                 "they must be equal", lma);

    if (is_enabled_ia_32e_mode_guest() == true && lma == 0)
        throw vmcs_invalid_field("ia 32e mode is 1, but efer.lma is 0. "
                                 "they must be equal", lma);

    if ((cr0 & CR0_PG_PAGING) == 0)
        return;

    if (lme == 0 && lma != 0)
        throw vmcs_invalid_field("efer.lme is 0, but efer.lma is 1. "
                                 "they must be equal", lma);

    if (lme != 0 && lma == 0)
        throw vmcs_invalid_field("efer.lme is 1, but efer.lma is 0. "
                                 "they must be equal", lma);
}

void
vmcs_intel_x64::checks_on_guest_segment_registers()
{
    check_guest_tr_ti_bit_equals_0();
    check_guest_ldtr_ti_bit_equals_0();
    check_guest_ss_and_cs_rpl_are_the_same();
    check_guest_cs_base_is_shifted();
    check_guest_ss_base_is_shifted();
    check_guest_ds_base_is_shifted();
    check_guest_es_base_is_shifted();
    check_guest_fs_base_is_shifted();
    check_guest_gs_base_is_shifted();
    check_guest_tr_base_is_canonical();
    check_guest_fs_base_is_canonical();
    check_guest_gs_base_is_canonical();
    check_guest_ldtr_base_is_canonical();
    check_guest_cs_base_upper_dword_0();
    check_guest_ss_base_upper_dword_0();
    check_guest_ds_base_upper_dword_0();
    check_guest_es_base_upper_dword_0();
    check_guest_cs_limit();
    check_guest_ss_limit();
    check_guest_ds_limit();
    check_guest_es_limit();
    check_guest_gs_limit();
    check_guest_fs_limit();
    check_guest_v8086_cs_access_rights();
    check_guest_v8086_ss_access_rights();
    check_guest_v8086_ds_access_rights();
    check_guest_v8086_es_access_rights();
    check_guest_v8086_fs_access_rights();
    check_guest_v8086_gs_access_rights();
    check_guest_cs_access_rights_type();
    check_guest_ss_access_rights_type();
    check_guest_ds_access_rights_type();
    check_guest_es_access_rights_type();
    check_guest_fs_access_rights_type();
    check_guest_gs_access_rights_type();
    check_guest_cs_is_not_a_system_descriptor();
    check_guest_ss_is_not_a_system_descriptor();
    check_guest_ds_is_not_a_system_descriptor();
    check_guest_es_is_not_a_system_descriptor();
    check_guest_fs_is_not_a_system_descriptor();
    check_guest_gs_is_not_a_system_descriptor();
    check_guest_cs_type_not_equal_3();
    check_guest_cs_dpl_adheres_to_ss_dpl();
    check_guest_ss_dpl_must_equal_rpl();
    check_guest_ss_dpl_must_equal_zero();
    check_guest_ds_dpl();
    check_guest_es_dpl();
    check_guest_fs_dpl();
    check_guest_gs_dpl();
    check_guest_cs_must_be_present();
    check_guest_ss_must_be_present_if_usable();
    check_guest_ds_must_be_present_if_usable();
    check_guest_es_must_be_present_if_usable();
    check_guest_fs_must_be_present_if_usable();
    check_guest_gs_must_be_present_if_usable();
    check_guest_cs_access_rights_reserved_must_be_0();
    check_guest_ss_access_rights_reserved_must_be_0();
    check_guest_ds_access_rights_reserved_must_be_0();
    check_guest_es_access_rights_reserved_must_be_0();
    check_guest_fs_access_rights_reserved_must_be_0();
    check_guest_gs_access_rights_reserved_must_be_0();
    check_guest_cs_db_must_be_0_if_l_equals_1();
    check_guest_cs_granularity();
    check_guest_ss_granularity();
    check_guest_ds_granularity();
    check_guest_es_granularity();
    check_guest_fs_granularity();
    check_guest_gs_granularity();
    check_guest_cs_access_rights_remaining_reserved_bit_0();
    check_guest_ss_access_rights_remaining_reserved_bit_0();
    check_guest_ds_access_rights_remaining_reserved_bit_0();
    check_guest_es_access_rights_remaining_reserved_bit_0();
    check_guest_fs_access_rights_remaining_reserved_bit_0();
    check_guest_gs_access_rights_remaining_reserved_bit_0();
    check_guest_tr_type_must_be_11();
    check_guest_tr_must_be_a_system_descriptor();
    check_guest_tr_must_be_present();
    check_guest_tr_access_rights_reserved_must_be_0();
    check_guest_tr_granularity();
    check_guest_tr_must_be_usable();
    check_guest_tr_access_rights_remaining_reserved_bit_0();
    check_guest_ldtr_type_must_be_2();
    check_guest_ldtr_must_be_a_system_descriptor();
    check_guest_ldtr_must_be_present();
    check_guest_ldtr_access_rights_reserved_must_be_0();
    check_guest_ldtr_granularity();
    check_guest_ldtr_access_rights_remaining_reserved_bit_0();
}

void
vmcs_intel_x64::check_guest_tr_ti_bit_equals_0()
{
    auto tr = vmread(VMCS_GUEST_TR_SELECTOR);

    if ((tr & SELECTOR_TI_FLAG) != 0)
        throw vmcs_invalid_field("guest tr's ti flag must be zero", tr);
}

void
vmcs_intel_x64::check_guest_ldtr_ti_bit_equals_0()
{
    auto ldtr = vmread(VMCS_GUEST_LDTR_SELECTOR);

    if (is_ldtr_usable() == false)
        return;

    if ((ldtr & SELECTOR_TI_FLAG) != 0)
        throw vmcs_invalid_field("guest ldtr's ti flag must be zero", ldtr);
}

void
vmcs_intel_x64::check_guest_ss_and_cs_rpl_are_the_same()
{
    if (is_enabled_v8086() == true)
        return;

    if (is_enabled_unrestricted_guests() == true)
        return;

    auto ss = vmread(VMCS_GUEST_SS_SELECTOR);
    auto cs = vmread(VMCS_GUEST_CS_SELECTOR);

    if ((ss & SELECTOR_RPL_FLAG) != (cs & SELECTOR_RPL_FLAG))
        throw vmcs_2_invalid_fields("ss and cs rpl must be the same", ss, cs);
}

void
vmcs_intel_x64::check_guest_cs_base_is_shifted()
{
    if (is_enabled_v8086() == false)
        return;

    auto cs = vmread(VMCS_GUEST_CS_SELECTOR);
    auto cs_base = vmread(VMCS_GUEST_CS_BASE);

    if ((cs << 4) != cs_base)
        throw vmcs_2_invalid_fields("if virtual 8086 mode is enabled, cs base "
                                    "must be cs shift 4 bits", cs_base, cs);
}

void
vmcs_intel_x64::check_guest_ss_base_is_shifted()
{
    if (is_enabled_v8086() == false)
        return;

    auto ss = vmread(VMCS_GUEST_SS_SELECTOR);
    auto ss_base = vmread(VMCS_GUEST_SS_BASE);

    if ((ss << 4) != ss_base)
        throw vmcs_2_invalid_fields("if virtual 8086 mode is enabled, ss base "
                                    "must be ss shift 4 bits", ss_base, ss);
}

void
vmcs_intel_x64::check_guest_ds_base_is_shifted()
{
    if (is_enabled_v8086() == false)
        return;

    auto ds = vmread(VMCS_GUEST_DS_SELECTOR);
    auto ds_base = vmread(VMCS_GUEST_DS_BASE);

    if ((ds << 4) != ds_base)
        throw vmcs_2_invalid_fields("if virtual 8086 mode is enabled, ds base "
                                    "must be ds shift 4 bits", ds_base, ds);
}

void
vmcs_intel_x64::check_guest_es_base_is_shifted()
{
    if (is_enabled_v8086() == false)
        return;

    auto es = vmread(VMCS_GUEST_ES_SELECTOR);
    auto es_base = vmread(VMCS_GUEST_ES_BASE);

    if ((es << 4) != es_base)
        throw vmcs_2_invalid_fields("if virtual 8086 mode is enabled, es base "
                                    "must be es shift 4 bits", es_base, es);
}

void
vmcs_intel_x64::check_guest_fs_base_is_shifted()
{
    if (is_enabled_v8086() == false)
        return;

    auto fs = vmread(VMCS_GUEST_FS_SELECTOR);
    auto fs_base = vmread(VMCS_GUEST_FS_BASE);

    if ((fs << 4) != fs_base)
        throw vmcs_2_invalid_fields("if virtual 8086 mode is enabled, fs base "
                                    "must be fs shift 4 bits", fs_base, fs);
}

void
vmcs_intel_x64::check_guest_gs_base_is_shifted()
{
    if (is_enabled_v8086() == false)
        return;

    auto gs = vmread(VMCS_GUEST_GS_SELECTOR);
    auto gs_base = vmread(VMCS_GUEST_GS_BASE);

    if ((gs << 4) != gs_base)
        throw vmcs_2_invalid_fields("if virtual 8086 mode is enabled, gs base "
                                    "must be gs shift 4 bits", gs_base, gs);
}

void
vmcs_intel_x64::check_guest_tr_base_is_canonical()
{
    auto tr_base = vmread(VMCS_GUEST_TR_BASE);

    if (is_address_canonical(tr_base) == false)
        throw vmcs_invalid_field("guest tr base non-canonical", tr_base);
}

void
vmcs_intel_x64::check_guest_fs_base_is_canonical()
{
    auto fs_base = vmread(VMCS_GUEST_FS_BASE);

    if (is_address_canonical(fs_base) == false)
        throw vmcs_invalid_field("guest fs base non-canonical", fs_base);
}

void
vmcs_intel_x64::check_guest_gs_base_is_canonical()
{
    auto gs_base = vmread(VMCS_GUEST_GS_BASE);

    if (is_address_canonical(gs_base) == false)
        throw vmcs_invalid_field("guest gs base non-canonical", gs_base);
}

void
vmcs_intel_x64::check_guest_ldtr_base_is_canonical()
{
    auto ldtr_base = vmread(VMCS_GUEST_LDTR_BASE);

    if (is_ldtr_usable() == false)
        return;

    if (is_address_canonical(ldtr_base) == false)
        throw vmcs_invalid_field("guest ldtr base non-canonical", ldtr_base);
}

void
vmcs_intel_x64::check_guest_cs_base_upper_dword_0()
{
    auto cs_base = vmread(VMCS_GUEST_CS_BASE);

    if ((cs_base & 0xFFFFFFFF00000000) != 0)
        throw vmcs_invalid_field("guest cs base bits 63:32 must be 0",
                                 cs_base);
}

void
vmcs_intel_x64::check_guest_ss_base_upper_dword_0()
{
    auto ss_base = vmread(VMCS_GUEST_SS_BASE);

    if (is_ds_usable() == false)
        return;

    if ((ss_base & 0xFFFFFFFF00000000) != 0)
        throw vmcs_invalid_field("guest ss base bits 63:32 must be 0",
                                 ss_base);
}

void
vmcs_intel_x64::check_guest_ds_base_upper_dword_0()
{
    auto ds_base = vmread(VMCS_GUEST_DS_BASE);

    if (is_ds_usable() == false)
        return;

    if ((ds_base & 0xFFFFFFFF00000000) != 0)
        throw vmcs_invalid_field("guest ds base bits 63:32 must be 0",
                                 ds_base);
}

void
vmcs_intel_x64::check_guest_es_base_upper_dword_0()
{
    auto es_base = vmread(VMCS_GUEST_ES_BASE);

    if (is_es_usable() == false)
        return;

    if ((es_base & 0xFFFFFFFF00000000) != 0)
        throw vmcs_invalid_field("guest es base bits 63:32 must be 0",
                                 es_base);
}

void
vmcs_intel_x64::check_guest_cs_limit()
{
    if (is_enabled_v8086() == false)
        return;

    auto cs_limit = vmread(VMCS_GUEST_CS_LIMIT);

    if (cs_limit != 0x000000000000FFFF)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "cs limit must be 0xFFFF", cs_limit);
}

void
vmcs_intel_x64::check_guest_ss_limit()
{
    if (is_enabled_v8086() == false)
        return;

    auto ss_limit = vmread(VMCS_GUEST_SS_LIMIT);

    if (ss_limit != 0x000000000000FFFF)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "ss limit must be 0xFFFF", ss_limit);
}

void
vmcs_intel_x64::check_guest_ds_limit()
{
    if (is_enabled_v8086() == false)
        return;

    auto ds_limit = vmread(VMCS_GUEST_DS_LIMIT);

    if (ds_limit != 0x000000000000FFFF)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "ds limit must be 0xFFFF", ds_limit);
}

void
vmcs_intel_x64::check_guest_es_limit()
{
    if (is_enabled_v8086() == false)
        return;

    auto es_limit = vmread(VMCS_GUEST_ES_LIMIT);

    if (es_limit != 0x000000000000FFFF)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "es limit must be 0xFFFF", es_limit);
}

void
vmcs_intel_x64::check_guest_gs_limit()
{
    if (is_enabled_v8086() == false)
        return;

    auto gs_limit = vmread(VMCS_GUEST_GS_LIMIT);

    if (gs_limit != 0x000000000000FFFF)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "gs limit must be 0xFFFF", gs_limit);
}

void
vmcs_intel_x64::check_guest_fs_limit()
{
    if (is_enabled_v8086() == false)
        return;

    auto fs_limit = vmread(VMCS_GUEST_FS_LIMIT);

    if (fs_limit != 0x000000000000FFFF)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "fs limit must be 0xFFFF", fs_limit);
}

void
vmcs_intel_x64::check_guest_v8086_cs_access_rights()
{
    if (is_enabled_v8086() == false)
        return;

    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if (cs_access != 0x00000000000000F3)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "cs access rights must be 0x00F3", cs_access);
}

void
vmcs_intel_x64::check_guest_v8086_ss_access_rights()
{
    if (is_enabled_v8086() == false)
        return;

    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if (ss_access != 0x00000000000000F3)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "ss access rights must be 0x00F3", ss_access);
}

void
vmcs_intel_x64::check_guest_v8086_ds_access_rights()
{
    if (is_enabled_v8086() == false)
        return;

    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if (ds_access != 0x00000000000000F3)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "ds access rights must be 0x00F3", ds_access);
}

void
vmcs_intel_x64::check_guest_v8086_es_access_rights()
{
    if (is_enabled_v8086() == false)
        return;

    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if (es_access != 0x00000000000000F3)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "es access rights must be 0x00F3", es_access);
}

void
vmcs_intel_x64::check_guest_v8086_fs_access_rights()
{
    if (is_enabled_v8086() == false)
        return;

    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if (fs_access != 0x00000000000000F3)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "fs access rights must be 0x00F3", fs_access);
}

void
vmcs_intel_x64::check_guest_v8086_gs_access_rights()
{
    if (is_enabled_v8086() == false)
        return;

    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if (gs_access != 0x00000000000000F3)
        throw vmcs_invalid_field("if virtual 8086 mode is enabled, "
                                 "gs access rights must be 0x00F3", gs_access);
}

void
vmcs_intel_x64::check_guest_cs_access_rights_type()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    switch (cs_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 3:
            if (is_enabled_unrestricted_guests() == false)
                break;

        case 9:
        case 11:
        case 13:
        case 15:
            return;

        default:
            break;
    }

    throw vmcs_invalid_field("guest cs type must be 9, 11, 13, 15, or "
                             "3 (if unrestricted guest support is enabled ",
                             cs_access);
}

void
vmcs_intel_x64::check_guest_ss_access_rights_type()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if (is_ss_usable() == false)
        return;

    switch (ss_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 3:
        case 7:
            return;

        default:
            break;
    }

    throw vmcs_invalid_field("guest ss type must be 3 or 7", ss_access);
}

void
vmcs_intel_x64::check_guest_ds_access_rights_type()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if (is_ds_usable() == false)
        return;

    switch (ds_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            return;

        default:
            break;
    }

    throw vmcs_invalid_field("guest ds type must be 1, 3, 5, 7, 11, or 15",
                             ds_access);
}

void
vmcs_intel_x64::check_guest_es_access_rights_type()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if (is_es_usable() == false)
        return;

    switch (es_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            return;

        default:
            break;
    }

    throw vmcs_invalid_field("guest ds type must be 1, 3, 5, 7, 11, or 15",
                             es_access);
}

void
vmcs_intel_x64::check_guest_fs_access_rights_type()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if (is_fs_usable() == false)
        return;

    switch (fs_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            return;

        default:
            break;
    }

    throw vmcs_invalid_field("guest fs type must be 1, 3, 5, 7, 11, or 15",
                             fs_access);
}

void
vmcs_intel_x64::check_guest_gs_access_rights_type()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if (is_gs_usable() == false)
        return;

    switch (gs_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            return;

        default:
            break;
    }

    throw vmcs_invalid_field("guest gs type must be 1, 3, 5, 7, 11, or 15",
                             gs_access);
}

void
vmcs_intel_x64::check_guest_cs_is_not_a_system_descriptor()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) == 0)
        throw vmcs_invalid_field("cs must be a code/data descriptor. "
                                 "S should equal 1", cs_access);
}

void
vmcs_intel_x64::check_guest_ss_is_not_a_system_descriptor()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if (is_ss_usable() == false)
        return;

    if ((ss_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) == 0)
        throw vmcs_invalid_field("ss must be a code/data descriptor. "
                                 "S should equal 1", ss_access);
}

void
vmcs_intel_x64::check_guest_ds_is_not_a_system_descriptor()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if (is_ds_usable() == false)
        return;

    if ((ds_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) == 0)
        throw vmcs_invalid_field("ds must be a code/data descriptor. "
                                 "S should equal 1", ds_access);
}

void
vmcs_intel_x64::check_guest_es_is_not_a_system_descriptor()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if (is_es_usable() == false)
        return;

    if ((es_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) == 0)
        throw vmcs_invalid_field("es must be a code/data descriptor. "
                                 "S should equal 1", es_access);
}

void
vmcs_intel_x64::check_guest_fs_is_not_a_system_descriptor()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if (is_fs_usable() == false)
        return;

    if ((fs_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) == 0)
        throw vmcs_invalid_field("fs must be a code/data descriptor. "
                                 "S should equal 1", fs_access);
}

void
vmcs_intel_x64::check_guest_gs_is_not_a_system_descriptor()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if (is_gs_usable() == false)
        return;

    if ((gs_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) == 0)
        throw vmcs_invalid_field("gs must be a code/data descriptor. "
                                 "S should equal 1", gs_access);
}

void
vmcs_intel_x64::check_guest_cs_type_not_equal_3()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & SEGMENT_ACCESS_RIGHTS_TYPE) != 3)
        return;

    if ((cs_access & SEGMENT_ACCESS_RIGHTS_DPL) != 0)
        throw vmcs_invalid_field("cs dpl must be 0 if type == 3.", cs_access);
}

void
vmcs_intel_x64::check_guest_cs_dpl_adheres_to_ss_dpl()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    switch (cs_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 9:
        case 11:
        {
            auto cs_dpl = (cs_access & SEGMENT_ACCESS_RIGHTS_DPL);
            auto ss_dpl = (ss_access & SEGMENT_ACCESS_RIGHTS_DPL);

            if (cs_dpl != ss_dpl)
                throw vmcs_2_invalid_fields("if cs access rights type is 9, 11"
                                            "cs dpl must equal ss dpl",
                                            cs_dpl, ss_dpl);
            break;
        }

        case 13:
        case 15:
        {
            auto cs_dpl = (cs_access & SEGMENT_ACCESS_RIGHTS_DPL);
            auto ss_dpl = (ss_access & SEGMENT_ACCESS_RIGHTS_DPL);

            if (cs_dpl > ss_dpl)
                throw vmcs_2_invalid_fields("if cs access rights type is 13, 15"
                                            "cs dpl must not be greater than "
                                            "ss dpl", cs_dpl, ss_dpl);
            break;
        }

        default:
            break;
    }
}

void
vmcs_intel_x64::check_guest_ss_dpl_must_equal_rpl()
{
    auto ss = vmread(VMCS_GUEST_SS_SELECTOR);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if (is_enabled_unrestricted_guests() == true)
        return;

    auto ss_dpl = (ss_access & SEGMENT_ACCESS_RIGHTS_DPL) >> 5;
    auto ss_rpl = (ss & SELECTOR_RPL_FLAG) >> 0;

    if (ss_dpl != ss_rpl)
        throw vmcs_2_invalid_fields("if unrestricted guest mode is disabled"
                                    "ss dpl must equal ss rpl",
                                    ss_dpl, ss_rpl);
}

void
vmcs_intel_x64::check_guest_ss_dpl_must_equal_zero()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    auto pe = (cr0 & CRO_PE_PROTECTION_ENABLE);
    auto cs_type = (cs_access & SEGMENT_ACCESS_RIGHTS_TYPE);

    if (cs_type != 3 && pe != 0)
        return;

    if ((ss_access & SEGMENT_ACCESS_RIGHTS_DPL) != 0)
        throw vmcs_invalid_field("if cs type is 3 or protected mode is "
                                 "disabled, DPL must be 0", ss_access);
}

void
vmcs_intel_x64::check_guest_ds_dpl()
{
    auto ds = vmread(VMCS_GUEST_DS_SELECTOR);
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if (is_enabled_unrestricted_guests() == true)
        return;

    if (is_ds_usable() == false)
        return;

    if ((ds_access & SEGMENT_ACCESS_RIGHTS_TYPE) >= 12)
        return;

    auto ds_dpl = (ds_access & SEGMENT_ACCESS_RIGHTS_DPL) >> 5;
    auto ds_rpl = (ds & SELECTOR_RPL_FLAG) >> 0;

    if (ds_dpl < ds_rpl)
        throw vmcs_2_invalid_fields("if unrestricted guest mode is disabled, "
                                    "and ds is usable, and the access rights "
                                    "type is in the range 0-11, dpl cannot be "
                                    "less than rpl", ds_dpl, ds_rpl);
}

void
vmcs_intel_x64::check_guest_es_dpl()
{
    auto es = vmread(VMCS_GUEST_ES_SELECTOR);
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if (is_enabled_unrestricted_guests() == true)
        return;

    if (is_es_usable() == false)
        return;

    if ((es_access & SEGMENT_ACCESS_RIGHTS_TYPE) >= 12)
        return;

    auto es_dpl = (es_access & SEGMENT_ACCESS_RIGHTS_DPL) >> 5;
    auto es_rpl = (es & SELECTOR_RPL_FLAG) >> 0;

    if (es_dpl < es_rpl)
        throw vmcs_2_invalid_fields("if unrestricted guest mode is disabled, "
                                    "and es is usable, and the access rights "
                                    "type is in the range 0-11, dpl cannot be "
                                    "less than rpl", es_dpl, es_rpl);
}

void
vmcs_intel_x64::check_guest_fs_dpl()
{
    auto fs = vmread(VMCS_GUEST_FS_SELECTOR);
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if (is_enabled_unrestricted_guests() == true)
        return;

    if (is_fs_usable() == false)
        return;

    if ((fs_access & SEGMENT_ACCESS_RIGHTS_TYPE) >= 12)
        return;

    auto fs_dpl = (fs_access & SEGMENT_ACCESS_RIGHTS_DPL) >> 5;
    auto fs_rpl = (fs & SELECTOR_RPL_FLAG) >> 0;

    if (fs_dpl < fs_rpl)
        throw vmcs_2_invalid_fields("if unrestricted guest mode is disabled, "
                                    "and fs is usable, and the access rights "
                                    "type is in the range 0-11, dpl cannot be "
                                    "less than rpl", fs_dpl, fs_rpl);
}

void
vmcs_intel_x64::check_guest_gs_dpl()
{
    auto gs = vmread(VMCS_GUEST_GS_SELECTOR);
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if (is_enabled_unrestricted_guests() == true)
        return;

    if (is_gs_usable() == false)
        return;

    if ((gs_access & SEGMENT_ACCESS_RIGHTS_TYPE) >= 12)
        return;

    auto gs_dpl = (gs_access & SEGMENT_ACCESS_RIGHTS_DPL) >> 5;
    auto gs_rpl = (gs & SELECTOR_RPL_FLAG) >> 0;

    if (gs_dpl < gs_rpl)
        throw vmcs_2_invalid_fields("if unrestricted guest mode is disabled, "
                                    "and gs is usable, and the access rights "
                                    "type is in the range 0-11, dpl cannot be "
                                    "less than rpl", gs_dpl, gs_rpl);
}

void
vmcs_intel_x64::check_guest_cs_must_be_present()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("cs access rights present flag must be 1 ",
                                 cs_access);
}

void
vmcs_intel_x64::check_guest_ss_must_be_present_if_usable()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if (is_ss_usable() == false)
        return;

    if ((ss_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("ss access rights present flag must be 1 "
                                 "if ss is usable", ss_access);
}

void
vmcs_intel_x64::check_guest_ds_must_be_present_if_usable()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if (is_ds_usable() == false)
        return;

    if ((ds_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("ds access rights present flag must be 1 "
                                 "if ds is usable", ds_access);
}

void
vmcs_intel_x64::check_guest_es_must_be_present_if_usable()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if (is_es_usable() == false)
        return;

    if ((es_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("es access rights present flag must be 1 "
                                 "if es is usable", es_access);
}

void
vmcs_intel_x64::check_guest_fs_must_be_present_if_usable()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if (is_fs_usable() == false)
        return;

    if ((fs_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("fs access rights present flag must be 1 "
                                 "if fs is usable", fs_access);
}

void
vmcs_intel_x64::check_guest_gs_must_be_present_if_usable()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if (is_gs_usable() == false)
        return;

    if ((gs_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("gs access rights present flag must be 1 "
                                 "if gs is usable", gs_access);
}

void
vmcs_intel_x64::check_guest_cs_access_rights_reserved_must_be_0()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & SEGMENT_ACCESS_RIGHTS_RESERVED) != 0)
        throw vmcs_invalid_field("cs access rights reserved bits must be 0 ",
                                 cs_access);
}

void
vmcs_intel_x64::check_guest_ss_access_rights_reserved_must_be_0()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if (is_ss_usable() == false)
        return;

    if ((ss_access & SEGMENT_ACCESS_RIGHTS_RESERVED) != 0)
        throw vmcs_invalid_field("ss access rights reserved bits must be 0 "
                                 "if ss is usable", ss_access);
}

void
vmcs_intel_x64::check_guest_ds_access_rights_reserved_must_be_0()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if (is_ds_usable() == false)
        return;

    if ((ds_access & SEGMENT_ACCESS_RIGHTS_RESERVED) != 0)
        throw vmcs_invalid_field("ds access rights reserved bits must be 0 "
                                 "if ds is usable", ds_access);
}

void
vmcs_intel_x64::check_guest_es_access_rights_reserved_must_be_0()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if (is_es_usable() == false)
        return;

    if ((es_access & SEGMENT_ACCESS_RIGHTS_RESERVED) != 0)
        throw vmcs_invalid_field("es access rights reserved bits must be 0 "
                                 "if es is usable", es_access);
}

void
vmcs_intel_x64::check_guest_fs_access_rights_reserved_must_be_0()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if (is_fs_usable() == false)
        return;

    if ((fs_access & SEGMENT_ACCESS_RIGHTS_RESERVED) != 0)
        throw vmcs_invalid_field("fs access rights reserved bits must be 0 "
                                 "if fs is usable", fs_access);
}

void
vmcs_intel_x64::check_guest_gs_access_rights_reserved_must_be_0()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if (is_gs_usable() == false)
        return;

    if ((gs_access & SEGMENT_ACCESS_RIGHTS_RESERVED) != 0)
        throw vmcs_invalid_field("gs access rights reserved bits must be 0 "
                                 "if gs is usable", gs_access);
}

void
vmcs_intel_x64::check_guest_cs_db_must_be_0_if_l_equals_1()
{
    if (is_enabled_ia_32e_mode_guest() == false)
        return;

    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & SEGMENT_ACCESS_RIGHTS_L) == 0)
        return;

    if ((cs_access & SEGMENT_ACCESS_RIGHTS_DB) != 0)
        throw vmcs_invalid_field("d/b for guest cs must be 0 if in ia 32e "
                                 "mode and l == 1", cs_access);
}

void
vmcs_intel_x64::check_guest_cs_granularity()
{
    auto cs_limit = vmread(VMCS_GUEST_CS_LIMIT);
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);
    auto g = (cs_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if ((cs_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest cs granularity must be 0 if any "
                                    "bit 11:0 is 0", cs_limit, cs_access);

    if ((cs_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest cs granularity must be 1 if any "
                                    "bit 31:20 is 1", cs_limit, cs_access);
}

void
vmcs_intel_x64::check_guest_ss_granularity()
{
    auto ss_limit = vmread(VMCS_GUEST_SS_LIMIT);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
    auto g = (ss_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if (is_ss_usable() == false)
        return;

    if ((ss_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest ss granularity must be 0 if any "
                                    "bit 11:0 is 0", ss_limit, ss_access);

    if ((ss_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest ss granularity must be 1 if any "
                                    "bit 31:20 is 1", ss_limit, ss_access);
}

void
vmcs_intel_x64::check_guest_ds_granularity()
{
    auto ds_limit = vmread(VMCS_GUEST_DS_LIMIT);
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);
    auto g = (ds_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if (is_ds_usable() == false)
        return;

    if ((ds_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest ds granularity must be 0 if any "
                                    "bit 11:0 is 0", ds_limit, ds_access);

    if ((ds_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest ds granularity must be 1 if any "
                                    "bit 31:20 is 1", ds_limit, ds_access);
}

void
vmcs_intel_x64::check_guest_es_granularity()
{
    auto es_limit = vmread(VMCS_GUEST_ES_LIMIT);
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);
    auto g = (es_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if (is_es_usable() == false)
        return;

    if ((es_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest es granularity must be 0 if any "
                                    "bit 11:0 is 0", es_limit, es_access);

    if ((es_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest es granularity must be 1 if any "
                                    "bit 31:20 is 1", es_limit, es_access);
}

void
vmcs_intel_x64::check_guest_fs_granularity()
{
    auto fs_limit = vmread(VMCS_GUEST_FS_LIMIT);
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);
    auto g = (fs_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if (is_fs_usable() == false)
        return;

    if ((fs_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest fs granularity must be 0 if any "
                                    "bit 11:0 is 0", fs_limit, fs_access);

    if ((fs_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest fs granularity must be 1 if any "
                                    "bit 31:20 is 1", fs_limit, fs_access);
}

void
vmcs_intel_x64::check_guest_gs_granularity()
{
    auto gs_limit = vmread(VMCS_GUEST_GS_LIMIT);
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);
    auto g = (gs_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if (is_gs_usable() == false)
        return;

    if ((gs_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest gs granularity must be 0 if any "
                                    "bit 11:0 is 0", gs_limit, gs_access);

    if ((gs_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest gs granularity must be 1 if any "
                                    "bit 31:20 is 1", gs_limit, gs_access);
}

void
vmcs_intel_x64::check_guest_cs_access_rights_remaining_reserved_bit_0()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & 0xFFFE0000) != 0)
        throw vmcs_invalid_field("guest cs access rights bits 31:17 must "
                                 "be 0 ", cs_access);
}

void
vmcs_intel_x64::check_guest_ss_access_rights_remaining_reserved_bit_0()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if (is_ss_usable() == false)
        return;

    if ((ss_access & 0xFFFE0000) != 0)
        throw vmcs_invalid_field("guest ss access rights bits 31:17 must "
                                 "be 0 ", ss_access);
}

void
vmcs_intel_x64::check_guest_ds_access_rights_remaining_reserved_bit_0()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if (is_ds_usable() == false)
        return;

    if ((ds_access & 0xFFFE0000) != 0)
        throw vmcs_invalid_field("guest ds access rights bits 31:17 must "
                                 "be 0 ", ds_access);
}

void
vmcs_intel_x64::check_guest_es_access_rights_remaining_reserved_bit_0()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if (is_es_usable() == false)
        return;

    if ((es_access & 0xFFFE0000) != 0)
        throw vmcs_invalid_field("guest es access rights bits 31:17 must "
                                 "be 0 ", es_access);
}

void
vmcs_intel_x64::check_guest_fs_access_rights_remaining_reserved_bit_0()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if (is_fs_usable() == false)
        return;

    if ((fs_access & 0xFFFE0000) != 0)
        throw vmcs_invalid_field("guest fs access rights bits 31:17 must "
                                 "be 0 ", fs_access);
}

void
vmcs_intel_x64::check_guest_gs_access_rights_remaining_reserved_bit_0()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if (is_gs_usable() == false)
        return;

    if ((gs_access & 0xFFFE0000) != 0)
        throw vmcs_invalid_field("guest gs access rights bits 31:17 must "
                                 "be 0 ", gs_access);
}

void
vmcs_intel_x64::check_guest_tr_type_must_be_11()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    switch (tr_access & SEGMENT_ACCESS_RIGHTS_TYPE)
    {
        case 3:
            if (is_enabled_ia_32e_mode_guest() == true)
                throw vmcs_invalid_field("tr type canot only be 3 if ia32e "
                                         "mode is disabled", tr_access);
        case 11:
            return;

        default:
            throw vmcs_invalid_field("tr type must be 3 or 11", tr_access);
    }
}

void
vmcs_intel_x64::check_guest_tr_must_be_a_system_descriptor()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) != 0)
        throw vmcs_invalid_field("tr must be a system descriptor. "
                                 "S should equal 0", tr_access);
}

void
vmcs_intel_x64::check_guest_tr_must_be_present()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("tr access rights present flag must be 1 ",
                                 tr_access);
}

void
vmcs_intel_x64::check_guest_tr_access_rights_reserved_must_be_0()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & 0x0F00) != 0)
        throw vmcs_invalid_field("tr access rights bits 11:8 must be 0",
                                 tr_access);
}

void
vmcs_intel_x64::check_guest_tr_granularity()
{
    auto tr_limit = vmread(VMCS_GUEST_TR_LIMIT);
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);
    auto g = (tr_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if ((tr_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest tr granularity must be 0 if any "
                                    "bit 11:0 is 0", tr_limit, tr_access);

    if ((tr_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest tr granularity must be 1 if any "
                                    "bit 31:20 is 1", tr_limit, tr_access);
}

void
vmcs_intel_x64::check_guest_tr_must_be_usable()
{
    if (is_tr_usable() == false)
        throw vmcs_invalid_field("tr must be usable", 0);
}

void
vmcs_intel_x64::check_guest_tr_access_rights_remaining_reserved_bit_0()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & 0xFFFE0000) != 0)
        throw vmcs_invalid_field("guest tr access rights bits 31:17 must "
                                 "be 0 ", tr_access);
}

void
vmcs_intel_x64::check_guest_ldtr_type_must_be_2()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if (is_ldtr_usable() == false)
        return;

    if ((ldtr_access & SEGMENT_ACCESS_RIGHTS_TYPE) != 2)
        throw vmcs_invalid_field("guest ldtr type must 2", ldtr_access);
}

void
vmcs_intel_x64::check_guest_ldtr_must_be_a_system_descriptor()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if (is_ldtr_usable() == false)
        return;

    if ((ldtr_access & SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR) != 0)
        throw vmcs_invalid_field("ldtr must be a system descriptor. "
                                 "S should equal 0", ldtr_access);
}

void
vmcs_intel_x64::check_guest_ldtr_must_be_present()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if (is_ldtr_usable() == false)
        return;

    if ((ldtr_access & SEGMENT_ACCESS_RIGHTS_PRESENT) == 0)
        throw vmcs_invalid_field("ldtr access rights present flag must be 1 "
                                 "if ldtr is usable", ldtr_access);
}

void
vmcs_intel_x64::check_guest_ldtr_access_rights_reserved_must_be_0()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if (is_ldtr_usable() == false)
        return;

    if ((ldtr_access & 0x0F00) != 0)
        throw vmcs_invalid_field("ldtr access rights bits 11:8 must be 0",
                                 ldtr_access);
}

void
vmcs_intel_x64::check_guest_ldtr_granularity()
{
    auto ldtr_limit = vmread(VMCS_GUEST_LDTR_LIMIT);
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    auto g = (ldtr_access & SEGMENT_ACCESS_RIGHTS_GRANULARITY);

    if ((ldtr_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw vmcs_2_invalid_fields("guest ldtr granularity must be 0 if any "
                                    "bit 11:0 is 0", ldtr_limit, ldtr_access);

    if ((ldtr_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw vmcs_2_invalid_fields("guest ldtr granularity must be 1 if any "
                                    "bit 31:20 is 1", ldtr_limit, ldtr_access);
}

void
vmcs_intel_x64::check_guest_ldtr_access_rights_remaining_reserved_bit_0()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if (is_ldtr_usable() == false)
        return;

    if ((ldtr_access & SEGMENT_ACCESS_RIGHTS_RESERVED) != 0)
        throw vmcs_invalid_field("ldtr access rights reserved bits must be 0 "
                                 "if ldtr is usable", ldtr_access);
}

void
vmcs_intel_x64::checks_on_guest_descriptor_table_registers()
{
    check_guest_gdtr_base_must_be_canonical();
    check_guest_idtr_base_must_be_canonical();
    check_guest_gdtr_limit_reserved_bits();
    check_guest_idtr_limit_reserved_bits();
}

void
vmcs_intel_x64::check_guest_gdtr_base_must_be_canonical()
{
    auto gdtr_base = vmread(VMCS_GUEST_GDTR_BASE);

    if (is_address_canonical(gdtr_base) == false)
        throw vmcs_invalid_field("gdtr base is non-canonical", gdtr_base);
}

void
vmcs_intel_x64::check_guest_idtr_base_must_be_canonical()
{
    auto idtr_base = vmread(VMCS_GUEST_IDTR_BASE);

    if (is_address_canonical(idtr_base) == false)
        throw vmcs_invalid_field("idtr base is non-canonical", idtr_base);
}

void
vmcs_intel_x64::check_guest_gdtr_limit_reserved_bits()
{
    auto gdtr_limit = vmread(VMCS_GUEST_GDTR_LIMIT);

    if ((gdtr_limit & 0xFFFF0000) != 0)
        throw vmcs_invalid_field("gdtr limit bits 31:16 must be 0", gdtr_limit);
}

void
vmcs_intel_x64::check_guest_idtr_limit_reserved_bits()
{
    auto idtr_limit = vmread(VMCS_GUEST_IDTR_LIMIT);

    if ((idtr_limit & 0xFFFF0000) != 0)
        throw vmcs_invalid_field("idtr limit bits 31:16 must be 0", idtr_limit);
}

void
vmcs_intel_x64::checks_on_guest_rip_and_rflags()
{
    check_guest_rip_upper_bits();
    check_guest_rip_valid_addr();
    check_guest_rflags_reserved_bits();
    check_guest_rflags_vm_bit();
    check_guest_rflag_interrupt_enable();
}

void
vmcs_intel_x64::check_guest_rip_upper_bits()
{
    auto cs_l = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS) & SEGMENT_ACCESS_RIGHTS_L;

    if (is_enabled_ia_32e_mode_guest() == true && cs_l != 0)
        return;

    auto rip = vmread(VMCS_GUEST_RIP);

    if ((rip & 0xFFFFFFFF00000000) != 0)
        throw vmcs_invalid_field("rip bits 61:32 must 0 if IA 32e mode is "
                                 "disabled or cs L is disabled", rip);
}

void
vmcs_intel_x64::check_guest_rip_valid_addr()
{
    auto cs_l = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS) & SEGMENT_ACCESS_RIGHTS_L;

    if (is_enabled_ia_32e_mode_guest() == false || cs_l == 0)
        return;

    auto rip = vmread(VMCS_GUEST_RIP);

    if (is_linear_address_valid(rip) == false)
        throw vmcs_invalid_field("rip bits must be canonical", rip);
}

void
vmcs_intel_x64::check_guest_rflags_reserved_bits()
{
    auto rflags = vmread(VMCS_GUEST_RFLAGS);

    if ((rflags & 0xFFFFFFFFFFC08028) != 0 || (rflags & 0x2) == 0)
        throw vmcs_invalid_field("reserved bits in rflags must be 0, and "
                                 "bit 1 must be 1", rflags);
}

void
vmcs_intel_x64::check_guest_rflags_vm_bit()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);
    auto rflags = vmread(VMCS_GUEST_RFLAGS);

    auto pe = cr0 & CRO_PE_PROTECTION_ENABLE;

    if (is_enabled_ia_32e_mode_guest() == false && pe == 1)
        return;

    if ((rflags & RFLAGS_VM_VIRTUAL_8086_MODE) != 0)
        throw vmcs_invalid_field("rflags VM must be 0 if ia 32e mode is 1 "
                                 "or PE is 0", rflags);
}

void
vmcs_intel_x64::check_guest_rflag_interrupt_enable()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;

    if (type != VM_INTERRUPTION_TYPE_EXTERNAL)
        return;

    auto rflags = vmread(VMCS_GUEST_RFLAGS);

    if ((rflags & RFLAGS_IF_INTERRUPT_ENABLE_FLAG) == 0)
        throw vmcs_invalid_field("rflags IF must be 1 if the valid bit is 1 "
                                 "and interrupt type is external", rflags);
}

void
vmcs_intel_x64::checks_on_guest_non_register_state()
{
    check_guest_valid_activity_state();
    check_guest_activity_state_not_hlt_when_dpl_not_0();
    check_guest_valid_activity_state();
    check_guest_activity_state_not_hlt_when_dpl_not_0();
    check_guest_must_be_active_if_injecting_blocking_state();
    check_guest_hlt_valid_interrupts();
    check_guest_shutdown_valid_interrupts();
    check_guest_sipi_valid_interrupts();
    check_guest_valid_activity_state_and_smm();
    check_guest_interruptability_state_reserved();
    check_guest_interruptability_state_sti_mov_ss();
    check_guest_interruptability_state_sti();
    check_guest_interruptability_state_external_interrupt();
    check_guest_interruptability_state_nmi();
    check_guest_interruptability_not_in_smm();
    check_guest_interruptability_entry_to_smm();
    check_guest_interruptability_state_sti_and_nmi();
    check_guest_interruptability_state_virtual_nmi();
    check_guest_pending_debug_exceptions_reserved();
    check_guest_pending_debug_exceptions_dbg_ctl();
    check_guest_vmcs_link_pointer_bits_11_0();
    check_guest_vmcs_link_pointer_valid_addr();
    check_guest_vmcs_link_pointer_first_word();
    check_guest_vmcs_link_pointer_not_in_smm();
    check_guest_vmcs_link_pointer_in_smm();
}

void
vmcs_intel_x64::check_guest_valid_activity_state()
{
    auto activity_state = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity_state > 3)
        vmcs_invalid_field("activity state must be 0 - 3", activity_state);
}

void
vmcs_intel_x64::check_guest_activity_state_not_hlt_when_dpl_not_0()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);
    auto activity_state = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity_state != VM_ACTIVITY_STATE_HLT)
        return;

    if ((ss_access & SEGMENT_ACCESS_RIGHTS_DPL) != 0)
        vmcs_invalid_field("ss.dpl must be 0 if activity state is HLT",
                           activity_state);
}

void
vmcs_intel_x64::check_guest_must_be_active_if_injecting_blocking_state()
{
    auto activity_state = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity_state == VM_ACTIVITY_STATE_ACTIVE)
        return;

    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_STI) != 0)
        throw vmcs_invalid_field("activity state must be active if "
                                 "interruptability state is sti",
                                 activity_state);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_MOV_SS) != 0)
        throw vmcs_invalid_field("activity state must be active if "
                                 "interruptability state is mov-ss",
                                 activity_state);
}

void
vmcs_intel_x64::check_guest_hlt_valid_interrupts()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto activity_state = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity_state != VM_ACTIVITY_STATE_HLT)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;
    auto vector = (interrupt_info_field & VM_INTERRUPT_INFORMATION_VECTOR) >> 0;

    switch (type)
    {
        case VM_INTERRUPTION_TYPE_EXTERNAL:
        case VM_INTERRUPTION_TYPE_NMI:
            return;

        case VM_INTERRUPTION_TYPE_HARDWARE:
            if (vector == INTERRUPT_DEBUG_EXCEPTION)
                return;

            if (vector == INTERRUPT_MACHINE_CHECK)
                return;

            break;

        case VM_INTERRUPTION_TYPE_OTHER:
            if (vector == MTF_VM_EXIT)
                return;

            break;

        default:
            break;
    }

    throw vmcs_2_invalid_fields("invalid interruption combination",
                                type, vector);
}

void
vmcs_intel_x64::check_guest_shutdown_valid_interrupts()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto activity_state = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity_state != VM_ACTIVITY_STATE_SHUTDOWN)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;
    auto vector = (interrupt_info_field & VM_INTERRUPT_INFORMATION_VECTOR) >> 0;

    switch (type)
    {
        case VM_INTERRUPTION_TYPE_NMI:
            return;

        case VM_INTERRUPTION_TYPE_HARDWARE:
            if (vector == INTERRUPT_MACHINE_CHECK)
                return;

            break;

        default:
            break;
    }

    throw vmcs_2_invalid_fields("invalid interruption combination",
                                type, vector);
}

void
vmcs_intel_x64::check_guest_sipi_valid_interrupts()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto activity_state = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity_state != VM_ACTIVITY_STATE_WAIT_FOR_SIPI)
        return;

    throw vmcs_invalid_field("invalid interruption combination",
                             activity_state);
}

void
vmcs_intel_x64::check_guest_valid_activity_state_and_smm()
{
    if (is_enabled_entry_to_smm() == false)
        return;

    auto activity_state = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity_state != VM_ACTIVITY_STATE_WAIT_FOR_SIPI)
        return;

    throw vmcs_invalid_field("activity state must not equal wait for sipi "
                             "if entry to smm is enabled",
                             activity_state);
}

void
vmcs_intel_x64::check_guest_interruptability_state_reserved()
{
    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    if ((interruptability_state & 0xFFFFFFFFFFFFFFF0) != 0)
        throw vmcs_invalid_field("interruptability state reserved bits "
                                 "31:4 must be 0", interruptability_state);
}

void
vmcs_intel_x64::check_guest_interruptability_state_sti_mov_ss()
{
    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    auto sti = interruptability_state & VM_INTERRUPTABILITY_STATE_STI;
    auto mov_ss = interruptability_state & VM_INTERRUPTABILITY_STATE_MOV_SS;

    if (sti == 1 && mov_ss == 1)
        throw vmcs_invalid_field("interruptability state sti and mov ss "
                                 "cannot both be 1", interruptability_state);

}

void
vmcs_intel_x64::check_guest_interruptability_state_sti()
{
    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    auto rflags = vmread(VMCS_GUEST_RFLAGS);

    if ((rflags & RFLAGS_IF_INTERRUPT_ENABLE_FLAG) != 0)
        return;

    auto sti = interruptability_state & VM_INTERRUPTABILITY_STATE_STI;

    if (sti != 0)
        throw vmcs_2_invalid_fields("interruptability state sti must be 0 if "
                                    "rflags interrupt enabled is 0",
                                    rflags, interruptability_state);
}

void
vmcs_intel_x64::check_guest_interruptability_state_external_interrupt()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;

    if (type != VM_INTERRUPTION_TYPE_EXTERNAL)
        return;

    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_STI) != 0)
        throw vmcs_invalid_field("interruptability state sti must be 0 if "
                                 "interrupt type is external and valid",
                                 interruptability_state);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_MOV_SS) != 0)
        throw vmcs_invalid_field("activity state must be active if "
                                 "interruptability state is mov-ss",
                                 interruptability_state);
}

void
vmcs_intel_x64::check_guest_interruptability_state_nmi()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;

    if (type != VM_INTERRUPTION_TYPE_NMI)
        return;

    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_MOV_SS) != 0)
        throw vmcs_invalid_field("activity state must be active if "
                                 "interruptability state is mov-ss",
                                 interruptability_state);
}

void
vmcs_intel_x64::check_guest_interruptability_not_in_smm()
{
}

void
vmcs_intel_x64::check_guest_interruptability_entry_to_smm()
{
    if (is_enabled_entry_to_smm() == false)
        return;

    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_SMI) == 0)
        throw vmcs_invalid_field("interruptability state smi must be enabled "
                                 "if entry to smm is enabled",
                                 interruptability_state);
}

void
vmcs_intel_x64::check_guest_interruptability_state_sti_and_nmi()
{
    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;

    if (type != VM_INTERRUPTION_TYPE_NMI)
        return;

    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_STI) != 0)
        throw vmcs_invalid_field("some processors require sti to be 0 if "
                                 "the interruption type is nmi",
                                 interruptability_state);
}

void
vmcs_intel_x64::check_guest_interruptability_state_virtual_nmi()
{
    if (is_enabled_virtual_nmis() == false)
        return;

    auto interrupt_info_field =
        vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if ((interrupt_info_field & VM_INTERRUPT_INFORMATION_VALID) == 0)
        return;

    auto type = (interrupt_info_field & VM_INTERRUPT_INFORMATION_TYPE) >> 8;

    if (type != VM_INTERRUPTION_TYPE_NMI)
        return;

    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    if ((interruptability_state & VM_INTERRUPTABILITY_STATE_NMI) != 0)
        throw vmcs_2_invalid_fields("if virtual nmi is enabled, and the "
                                    "interruption type is NMI, blocking by nmi "
                                    "must be disabled", interrupt_info_field,
                                    interruptability_state);
}

void
vmcs_intel_x64::check_guest_pending_debug_exceptions_reserved()
{
    auto pending_debug_exceptions =
        vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);

    if ((pending_debug_exceptions & 0xFFFFFFFFFFFF2FF0) != 0)
        throw vmcs_invalid_field("pending debug exception reserved bits "
                                 "must be 0", pending_debug_exceptions);
}

void
vmcs_intel_x64::check_guest_pending_debug_exceptions_dbg_ctl()
{
    auto interruptability_state =
        vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    auto activity_state =
        vmread(VMCS_GUEST_ACTIVITY_STATE);

    auto sti = interruptability_state & VM_INTERRUPTABILITY_STATE_STI;
    auto mov_ss = interruptability_state & VM_INTERRUPTABILITY_STATE_MOV_SS;
    auto hlt = activity_state & VM_ACTIVITY_STATE_HLT;

    if (sti == 0 && mov_ss == 0 && hlt == 0)
        return;

    auto pending_debug_exceptions =
        vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);

    auto bs = pending_debug_exceptions & PENDING_DEBUG_EXCEPTION_BS;

    auto rflags = vmread(VMCS_GUEST_RFLAGS);
    auto vmcs_ia32_debugctl = vmread(VMCS_GUEST_IA32_DEBUGCTL_FULL);

    auto tf = rflags & RFLAGS_TF_TRAP_FLAG;
    auto btf = vmcs_ia32_debugctl & IA32_DEBUGCTL_BTF;

    if (bs == 0 && tf != 0 && btf == 0)
        throw vmcs_invalid_field("pending debug exception bs must be 1 if "
                                 "rflags tf is 1 and debugctl btf is 0",
                                 pending_debug_exceptions);

    if (bs == 1 && tf == 0 && btf == 1)
        throw vmcs_invalid_field("pending debug exception bs must be 0 if "
                                 "rflags tf is 0 and debugctl btf is 1",
                                 pending_debug_exceptions);
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_bits_11_0()
{
    auto vmcs_link_pointer = vmread(VMCS_VMCS_LINK_POINTER_FULL);

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    if ((vmcs_link_pointer & 0x0000000000000FFF) != 0)
        throw vmcs_invalid_field("vmcs link pointer bits 11:0 must be 0",
                                 vmcs_link_pointer);
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_valid_addr()
{
    auto vmcs_link_pointer = vmread(VMCS_VMCS_LINK_POINTER_FULL);

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    if (is_physical_address_valid(vmcs_link_pointer) == false)
        throw vmcs_invalid_field("vmcs link pointer invalid physical address",
                                 vmcs_link_pointer);
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_first_word()
{
    auto vmcs_link_pointer = vmread(VMCS_VMCS_LINK_POINTER_FULL);

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    auto vmcs = g_mm->phys_to_virt((void *)vmcs_link_pointer);

    if (vmcs == 0)
        throw vmcs_invalid_field("invalid vmcs physical address",
                                 vmcs_link_pointer);

    auto basic_msr = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFFF;
    auto revision_id = (((uint32_t *)vmcs)[0]) & 0x7FFFFFFF;
    auto vmcs_shadow = (((uint32_t *)vmcs)[0]) & 0x80000000;

    if (basic_msr != revision_id)
        throw vmcs_invalid_field("shadow vmcs must contain CPU's revision id",
                                 revision_id);

    if (is_enabled_vmcs_shadowing() == false)
        return;

    if (vmcs_shadow == 0)
        throw vmcs_invalid_field("shadow vmcs bit must be enabled if vmcs "
                                 "shadowing is enabled", vmcs_shadow);

}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_not_in_smm()
{
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_in_smm()
{
}
