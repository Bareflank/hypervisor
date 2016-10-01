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

#include <view_as_pointer.h>
#include <vmcs/vmcs_intel_x64.h>

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
    {
        bferror << " failed: check_guest_cr0_for_unsupported_bits" << bfendl;
        bferror << "    - ia32_vmx_cr0_fixed0: " << view_as_pointer(ia32_vmx_cr0_fixed0) << bfendl;
        bferror << "    - ia32_vmx_cr0_fixed1: " << view_as_pointer(ia32_vmx_cr0_fixed1) << bfendl;
        bferror << "    - cr0: " << view_as_pointer(cr0) << bfendl;

        throw std::logic_error("invalid cr0");
    }
}

void
vmcs_intel_x64::check_host_cr4_for_unsupported_bits()
{
    auto cr4 = vmread(VMCS_HOST_CR4);
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
    {
        bferror << " failed: check_guest_cr4_for_unsupported_bits" << bfendl;
        bferror << "    - ia32_vmx_cr4_fixed0: " << view_as_pointer(ia32_vmx_cr4_fixed0) << bfendl;
        bferror << "    - ia32_vmx_cr4_fixed1: " << view_as_pointer(ia32_vmx_cr4_fixed1) << bfendl;
        bferror << "    - cr4: " << view_as_pointer(cr4) << bfendl;

        throw std::logic_error("invalid cr4");
    }
}

void
vmcs_intel_x64::check_host_cr3_for_unsupported_bits()
{
    auto cr3 = vmread(VMCS_HOST_CR3);

    if (!is_physical_address_valid(cr3))
        throw std::logic_error("host cr3 too large");
}

void
vmcs_intel_x64::check_host_ia32_sysenter_esp_canonical_address()
{
    auto esp = vmread(VMCS_HOST_IA32_SYSENTER_ESP);

    if (!is_address_canonical(esp))
        throw std::logic_error("host sysenter esp must be canonical");
}

void
vmcs_intel_x64::check_host_ia32_sysenter_eip_canonical_address()
{
    auto eip = vmread(VMCS_HOST_IA32_SYSENTER_EIP);

    if (!is_address_canonical(eip))
        throw std::logic_error("host sysenter eip must be canonical");
}

void
vmcs_intel_x64::check_host_verify_load_ia32_perf_global_ctrl()
{
    if (!is_enabled_load_ia32_perf_global_ctrl_on_exit())
        return;

    auto vmcs_ia32_perf_global_ctrl =
        vmread(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL);

    if ((vmcs_ia32_perf_global_ctrl & 0xFFFFFFF8FFFFFFFC) != 0)
        throw std::logic_error("perf global ctrl msr reserved bits must be 0");
}

void
vmcs_intel_x64::check_host_verify_load_ia32_pat()
{
    if (!is_enabled_load_ia32_pat_on_exit())
        return;

    auto pat0 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0x00000000000000FF) >> 0;
    auto pat1 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0x000000000000FF00) >> 8;
    auto pat2 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0x0000000000FF0000) >> 16;
    auto pat3 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0x00000000FF000000) >> 24;
    auto pat4 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0x000000FF00000000) >> 32;
    auto pat5 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0x0000FF0000000000) >> 40;
    auto pat6 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0x00FF000000000000) >> 48;
    auto pat7 = (vmread(VMCS_HOST_IA32_PAT_FULL) & 0xFF00000000000000) >> 56;

    if (!check_pat(pat0))
        throw std::logic_error("pat0 has an invalid memory type");

    if (!check_pat(pat1))
        throw std::logic_error("pat1 has an invalid memory type");

    if (!check_pat(pat2))
        throw std::logic_error("pat2 has an invalid memory type");

    if (!check_pat(pat3))
        throw std::logic_error("pat3 has an invalid memory type");

    if (!check_pat(pat4))
        throw std::logic_error("pat4 has an invalid memory type");

    if (!check_pat(pat5))
        throw std::logic_error("pat5 has an invalid memory type");

    if (!check_pat(pat6))
        throw std::logic_error("pat6 has an invalid memory type");

    if (!check_pat(pat7))
        throw std::logic_error("pat7 has an invalid memory type");
}

void
vmcs_intel_x64::check_host_verify_load_ia32_efer()
{
    if (!is_enabled_load_ia32_efer_on_exit())
        return;

    auto efer = vmread(VMCS_HOST_IA32_EFER_FULL);

    if ((efer & 0xFFFFFFFFFFFFF2FE) != 0)
        throw std::logic_error("ia32 efer msr reserved buts must be 0 if "
                               "load ia32 efer entry is enabled");

    auto cr0 = vmread(VMCS_HOST_CR0);
    auto lma = (efer & IA32_EFER_LMA);
    auto lme = (efer & IA32_EFER_LME);

    if (!is_enabled_host_address_space_size() && lma != 0)
        throw std::logic_error("host addr space is 0, but efer.lma is 1");

    if (is_enabled_host_address_space_size() && lma == 0)
        throw std::logic_error("host addr space is 1, but efer.lma is 0");

    if ((cr0 & CR0_PG_PAGING) == 0)
        return;

    if (lme == 0 && lma != 0)
        throw std::logic_error("efer.lme is 0, but efer.lma is 1");

    if (lme != 0 && lma == 0)
        throw std::logic_error("efer.lme is 1, but efer.lma is 0");
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
        throw std::logic_error("host rpl / tr's es flag must be 0");
}

void
vmcs_intel_x64::check_host_cs_selector_rpl_ti_equal_zero()
{
    auto cs = vmread(VMCS_HOST_CS_SELECTOR);

    if ((cs & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw std::logic_error("host rpl / tr's cs flag must be 0");
}

void
vmcs_intel_x64::check_host_ss_selector_rpl_ti_equal_zero()
{
    auto ss = vmread(VMCS_HOST_SS_SELECTOR);

    if ((ss & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw std::logic_error("host rpl / tr's ss flag must be 0");
}

void
vmcs_intel_x64::check_host_ds_selector_rpl_ti_equal_zero()
{
    auto ds = vmread(VMCS_HOST_DS_SELECTOR);

    if ((ds & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw std::logic_error("host rpl / tr's ds flag must be 0");
}

void
vmcs_intel_x64::check_host_fs_selector_rpl_ti_equal_zero()
{
    auto fs = vmread(VMCS_HOST_FS_SELECTOR);

    if ((fs & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw std::logic_error("host rpl / tr's fs flag must be 0");
}

void
vmcs_intel_x64::check_host_gs_selector_rpl_ti_equal_zero()
{
    auto gs = vmread(VMCS_HOST_GS_SELECTOR);

    if ((gs & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw std::logic_error("host rpl / tr's gs flag must be 0");
}

void
vmcs_intel_x64::check_host_tr_selector_rpl_ti_equal_zero()
{
    auto tr = vmread(VMCS_HOST_TR_SELECTOR);

    if ((tr & (SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG)) != 0)
        throw std::logic_error("host rpl / tr's tr flag must be 0");
}

void
vmcs_intel_x64::check_host_cs_not_equal_zero()
{
    auto cs = vmread(VMCS_HOST_CS_SELECTOR);

    if (cs == 0x0000)
        throw std::logic_error("host cs cannot equal 0");
}

void
vmcs_intel_x64::check_host_tr_not_equal_zero()
{
    auto tr = vmread(VMCS_HOST_TR_SELECTOR);

    if (tr == 0x0000)
        throw std::logic_error("host tr cannot equal 0");
}

void
vmcs_intel_x64::check_host_ss_not_equal_zero()
{
    auto ss = vmread(VMCS_HOST_SS_SELECTOR);

    if (is_enabled_host_address_space_size())
        return;

    if (ss == 0x0000)
        throw std::logic_error("host ss cannot equal 0");
}

void
vmcs_intel_x64::check_host_fs_canonical_base_address()
{
    auto fs_base = vmread(VMCS_HOST_FS_BASE);

    if (!is_address_canonical(fs_base))
        throw std::logic_error("host fs base must be canonical");
}

void
vmcs_intel_x64::check_host_gs_canonical_base_address()
{
    auto gs_base = vmread(VMCS_HOST_GS_BASE);

    if (!is_address_canonical(gs_base))
        throw std::logic_error("host gs base must be canonical");
}

void
vmcs_intel_x64::check_host_gdtr_canonical_base_address()
{
    auto gdtr_base = vmread(VMCS_HOST_GDTR_BASE);

    if (!is_address_canonical(gdtr_base))
        throw std::logic_error("host gdtr base must be canonical");
}

void
vmcs_intel_x64::check_host_idtr_canonical_base_address()
{
    auto idtr_base = vmread(VMCS_HOST_IDTR_BASE);

    if (!is_address_canonical(idtr_base))
        throw std::logic_error("host idtr base must be canonical");
}

void
vmcs_intel_x64::check_host_tr_canonical_base_address()
{
    auto tr_base = vmread(VMCS_HOST_TR_BASE);

    if (!is_address_canonical(tr_base))
        throw std::logic_error("host tr base must be canonical");
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

    if (is_enabled_ia_32e_mode_guest())
        throw std::logic_error("ia 32e mode must be 0 if efer.lma == 0");

    if (is_enabled_host_address_space_size())
        throw std::logic_error("host addr space must be 0 if efer.lma == 0");
}

void
vmcs_intel_x64::check_host_vmcs_host_address_space_size_is_set()
{
    auto ia32_efer_msr = m_intrinsics->read_msr(IA32_EFER_MSR);

    if ((ia32_efer_msr & IA32_EFER_LMA) == 0)
        return;

    if (!is_enabled_host_address_space_size())
        throw std::logic_error("host addr space must be 1 if efer.lma == 1");
}

void
vmcs_intel_x64::check_host_host_address_space_disabled()
{
    if (is_enabled_host_address_space_size())
        return;

    if (is_enabled_ia_32e_mode_guest())
        throw std::logic_error("ia 32e mode must be disabled if host addr space is disabled");

    auto cr4 = vmread(VMCS_HOST_CR4);

    if ((cr4 & CR4_PCIDE_PCID_ENABLE_BIT) != 0)
        throw std::logic_error("cr4 pcide must be disabled if host addr space is disabled");

    auto rip = vmread(VMCS_HOST_RIP);

    if ((rip & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("rip bits 63:32 must be 0 if host addr space is disabled");
}

void
vmcs_intel_x64::check_host_host_address_space_enabled()
{
    if (!is_enabled_host_address_space_size())
        return;

    auto cr4 = vmread(VMCS_HOST_CR4);

    if ((cr4 & CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS) == 0)
        throw std::logic_error("cr4 pae must be enabled if host addr space is enabled");

    auto rip = vmread(VMCS_HOST_RIP);

    if (!is_address_canonical(rip))
        throw std::logic_error("host rip must be canonical");
}
