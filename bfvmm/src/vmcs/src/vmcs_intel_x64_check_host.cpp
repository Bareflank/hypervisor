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

void
vmcs_intel_x64::check_vmcs_host_state()
{
    check_host_control_registers_and_msrs();
    check_host_segment_and_descriptor_table_registers();
    check_host_checks_related_to_address_space_size();
}

void
vmcs_intel_x64::check_host_control_registers_and_msrs()
{
    check_host_cr0_for_unsupported_bits();
    check_host_cr4_for_unsupported_bits();
    check_host_cr3_for_unsupported_bits();
    check_host_ia32_sysenter_esp_canonical_address();
    check_host_ia32_sysenter_eip_canonical_address();
    check_host_verify_load_ia32_perf_global_ctrl();
    check_host_verify_load_ia32_pat();
    check_host_verify_load_ia32_efer();
}

void
vmcs_intel_x64::check_host_cr0_for_unsupported_bits()
{
    auto cr0 = vmread(VMCS_HOST_CR0);
    auto ia32_vmx_cr0_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED0_MSR);
    auto ia32_vmx_cr0_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED1_MSR);

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
        throw vmcs_invalid_ctrl(cr0, ia32_vmx_cr0_fixed0, ia32_vmx_cr0_fixed1);
}

void
vmcs_intel_x64::check_host_cr4_for_unsupported_bits()
{
    auto cr4 = vmread(VMCS_HOST_CR4);
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
        throw vmcs_invalid_ctrl(cr4, ia32_vmx_cr4_fixed0, ia32_vmx_cr4_fixed1);
}

void
vmcs_intel_x64::check_host_cr3_for_unsupported_bits()
{
    auto cr3 = vmread(VMCS_HOST_CR3);

    if (is_physical_address_valid(cr3) == false)
        throw invalid_address("host cr3 too large", cr3);
}

void
vmcs_intel_x64::check_host_ia32_sysenter_esp_canonical_address()
{
    auto esp = vmread(VMCS_HOST_IA32_SYSENTER_EIP);

    if (is_address_canonical(esp) == false)
        throw invalid_address("host esp must be canonical", esp);
}

void
vmcs_intel_x64::check_host_ia32_sysenter_eip_canonical_address()
{
    auto eip = vmread(VMCS_HOST_IA32_SYSENTER_EIP);

    if (is_address_canonical(eip) == false)
        throw invalid_address("host eip must be canonical", eip);
}

void
vmcs_intel_x64::check_host_verify_load_ia32_perf_global_ctrl()
{
    if (is_enabled_load_ia32_perf_global_ctrl_on_exit() == false)
        return;

    auto vmcs_ia32_perf_global_ctrl =
        vmread(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL);

    if ((vmcs_ia32_perf_global_ctrl & 0xFFFFFFF8FFFFFFFC) != 0)
        throw vmcs_invalid_field("perf global ctrl msr reserved bits must be 0",
                                 vmcs_ia32_perf_global_ctrl);
}

void
vmcs_intel_x64::check_host_verify_load_ia32_pat()
{
    if (is_enabled_load_ia32_pat_on_exit() == false)
        return;

    auto pat0 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0x00000000000000FF >> 0;
    auto pat1 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0x000000000000FF00 >> 8;
    auto pat2 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0x0000000000FF0000 >> 16;
    auto pat3 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0x00000000FF000000 >> 24;
    auto pat4 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0x000000FF00000000 >> 32;
    auto pat5 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0x0000FF0000000000 >> 40;
    auto pat6 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0x00FF000000000000 >> 48;
    auto pat7 = vmread(VMCS_HOST_IA32_PAT_FULL) & 0xFF00000000000000 >> 56;

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
vmcs_intel_x64::check_host_verify_load_ia32_efer()
{
    if (is_enabled_load_ia32_efer_on_exit() == false)
        return;

    auto efer = vmread(VMCS_HOST_IA32_EFER_FULL);

    if ((efer & 0xFFFFFFFFFFFFF2FE) != 0)
        throw vmcs_invalid_field("ia32 efer msr reserved buts must be 0 if "
                                 "load ia32 efer entry is enabled", efer);

    auto cr0 = vmread(VMCS_HOST_CR0);
    auto lma = (efer && IA32_EFER_LMA);
    auto lme = (efer && IA32_EFER_LME);

    if (is_enabled_host_address_space_size() == false && lma != 0)
        throw vmcs_invalid_field("host addr space is 0, but efer.lma is 1. "
                                 "they must be equal", lma);

    if (is_enabled_host_address_space_size() == true && lma == 0)
        throw vmcs_invalid_field("host addr space is 1, but efer.lma is 0. "
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

// -----------------------------------------------------------------------------
// Host Segment and Descriptor-Table Register Checks
// -----------------------------------------------------------------------------

void
vmcs_intel_x64::check_host_segment_and_descriptor_table_registers()
{
    check_host_es_selector_rpl_ti_equal_zero();
    check_host_cs_selector_rpl_ti_equal_zero();
    check_host_ss_selector_rpl_ti_equal_zero();
    check_host_ds_selector_rpl_ti_equal_zero();
    check_host_fs_selector_rpl_ti_equal_zero();
    check_host_gs_selector_rpl_ti_equal_zero();
    check_host_tr_selector_rpl_ti_equal_zero();
    check_host_cs_not_equal_zero();
    check_host_tr_not_equal_zero();
    check_host_ss_not_equal_zero();
    check_host_fs_canonical_base_address();
    check_host_gs_canonical_base_address();
    check_host_gdtr_canonical_base_address();
    check_host_idtr_canonical_base_address();
    check_host_tr_canonical_base_address();
}

void
vmcs_intel_x64::check_host_es_selector_rpl_ti_equal_zero()
{
    auto es = vmread(VMCS_HOST_ES_SELECTOR);

    if ((es & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw vmcs_invalid_field("host rpl / tr's es flag must be 0", es);
}

void
vmcs_intel_x64::check_host_cs_selector_rpl_ti_equal_zero()
{
    auto cs = vmread(VMCS_HOST_CS_SELECTOR);

    if ((cs & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw vmcs_invalid_field("host rpl / tr's cs flag must be 0", cs);
}

void
vmcs_intel_x64::check_host_ss_selector_rpl_ti_equal_zero()
{
    auto ss = vmread(VMCS_HOST_SS_SELECTOR);

    if ((ss & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw vmcs_invalid_field("host rpl / tr's ss flag must be 0", ss);
}

void
vmcs_intel_x64::check_host_ds_selector_rpl_ti_equal_zero()
{
    auto ds = vmread(VMCS_HOST_DS_SELECTOR);

    if ((ds & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw vmcs_invalid_field("host rpl / tr's ds flag must be 0", ds);
}

void
vmcs_intel_x64::check_host_fs_selector_rpl_ti_equal_zero()
{
    auto fs = vmread(VMCS_HOST_FS_SELECTOR);

    if ((fs & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw vmcs_invalid_field("host rpl / tr's fs flag must be 0", fs);
}

void
vmcs_intel_x64::check_host_gs_selector_rpl_ti_equal_zero()
{
    auto gs = vmread(VMCS_HOST_GS_SELECTOR);

    if ((gs & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw vmcs_invalid_field("host rpl / tr's gs flag must be 0", gs);
}

void
vmcs_intel_x64::check_host_tr_selector_rpl_ti_equal_zero()
{
    auto tr = vmread(VMCS_HOST_TR_SELECTOR);

    if ((tr & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw vmcs_invalid_field("host rpl / tr's tr flag must be 0", tr);
}

void
vmcs_intel_x64::check_host_cs_not_equal_zero()
{
    auto cs = vmread(VMCS_HOST_CS_SELECTOR);

    if (cs == 0x0000)
        throw vmcs_invalid_field("host cs cannot equal 0", cs);
}

void
vmcs_intel_x64::check_host_tr_not_equal_zero()
{
    auto tr = vmread(VMCS_HOST_TR_SELECTOR);

    if (tr == 0x0000)
        throw vmcs_invalid_field("host tr cannot equal 0", tr);
}

void
vmcs_intel_x64::check_host_ss_not_equal_zero()
{
    auto ss = vmread(VMCS_HOST_SS_SELECTOR);

    if (is_enabled_host_address_space_size() == true)
        return;

    if (ss == 0x0000)
        throw vmcs_invalid_field("host ss cannot equal 0", ss);
}

void
vmcs_intel_x64::check_host_fs_canonical_base_address()
{
    auto fs_base = vmread(VMCS_HOST_FS_BASE);

    if (is_address_canonical(fs_base) == false)
        throw invalid_address("host fs base must be canonical", fs_base);
}

void
vmcs_intel_x64::check_host_gs_canonical_base_address()
{
    auto gs_base = vmread(VMCS_HOST_GS_BASE);

    if (is_address_canonical(gs_base) == false)
        throw invalid_address("host gs base must be canonical", gs_base);
}

void
vmcs_intel_x64::check_host_gdtr_canonical_base_address()
{
    auto gdtr_base = vmread(VMCS_HOST_GDTR_BASE);

    if (is_address_canonical(gdtr_base) == false)
        throw invalid_address("host gdtr base must be canonical", gdtr_base);
}

void
vmcs_intel_x64::check_host_idtr_canonical_base_address()
{
    auto idtr_base = vmread(VMCS_HOST_IDTR_BASE);

    if (is_address_canonical(idtr_base) == false)
        throw invalid_address("host idtr base must be canonical", idtr_base);
}

void
vmcs_intel_x64::check_host_tr_canonical_base_address()
{
    auto tr_base = vmread(VMCS_HOST_FS_BASE);

    if (is_address_canonical(tr_base) == false)
        throw invalid_address("host tr base must be canonical", tr_base);
}

void
vmcs_intel_x64::check_host_checks_related_to_address_space_size()
{
    check_host_if_outside_ia32e_mode();
    check_host_vmcs_host_address_space_size_is_set();
    check_host_host_address_space_disabled();
    check_host_host_address_space_enabled();
}

void
vmcs_intel_x64::check_host_if_outside_ia32e_mode()
{
    auto ia32_efer_msr = m_intrinsics->read_msr(IA32_EFER_MSR);

    if ((ia32_efer_msr & IA32_EFER_LMA) != 0)
        return;

    if (is_enabled_ia_32e_mode_guest() == true)
        throw vmcs_invalid_field("ia 32e mode must be 0 if efer.lma == 0",
                                 ia32_efer_msr);

    if (is_enabled_host_address_space_size() == true)
        throw vmcs_invalid_field("host addr space must be 0 if efer.lma == 0",
                                 ia32_efer_msr);
}

void
vmcs_intel_x64::check_host_vmcs_host_address_space_size_is_set()
{
    auto ia32_efer_msr = m_intrinsics->read_msr(IA32_EFER_MSR);

    if ((ia32_efer_msr & IA32_EFER_LMA) == 0)
        return;

    if (is_enabled_host_address_space_size() == false)
        throw vmcs_invalid_field("host addr space must be 1 if efer.lma == 1",
                                 ia32_efer_msr);
}

void
vmcs_intel_x64::check_host_host_address_space_disabled()
{
    if (is_enabled_host_address_space_size() == true)
        return;

    if (is_enabled_ia_32e_mode_guest() == true)
        throw vmcs_invalid_field("ia 32e mode must be disabled if host addr "
                                 "space is disabled", 0);

    auto cr4 = vmread(VMCS_HOST_CR4);

    if ((cr4 & CR4_PCIDE_PCID_ENABLE_BIT) != 0)
        throw vmcs_invalid_field("cr4 pcide must be disabled if host addr "
                                 "space is disabled", 0);

    auto rip = vmread(VMCS_HOST_RIP);

    if ((rip & 0xFFFFFFFF00000000) != 0)
        throw vmcs_invalid_field("rip bits 63:32 must be 0 if host addr "
                                 "space is disabled", 0);
}

void
vmcs_intel_x64::check_host_host_address_space_enabled()
{
    if (is_enabled_host_address_space_size() == false)
        return;

    auto cr4 = vmread(VMCS_HOST_CR4);

    if ((cr4 & CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS) == 0)
        throw vmcs_invalid_field("cr4 pae must be enabled if host addr "
                                 "space is enabled", 0);

    auto rip = vmread(VMCS_HOST_RIP);

    if (is_address_canonical(rip) == false)
        throw invalid_address("host rip must be canonical", rip);
}
