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
#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>

using namespace intel_x64;

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
    auto cr0 = vmcs::host_cr0::get();
    auto ia32_vmx_cr0_fixed0 = msrs::ia32_vmx_cr0_fixed0::get();
    auto ia32_vmx_cr0_fixed1 = msrs::ia32_vmx_cr0_fixed1::get();

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
    {
        bferror << " failed: check_host_cr0_for_unsupported_bits" << bfendl;
        bferror << "    - ia32_vmx_cr0_fixed0: " << view_as_pointer(ia32_vmx_cr0_fixed0) << bfendl;
        bferror << "    - ia32_vmx_cr0_fixed1: " << view_as_pointer(ia32_vmx_cr0_fixed1) << bfendl;
        bferror << "    - cr0: " << view_as_pointer(cr0) << bfendl;

        throw std::logic_error("invalid cr0");
    }
}

void
vmcs_intel_x64::check_host_cr4_for_unsupported_bits()
{
    auto cr4 = vmcs::host_cr4::get();
    auto ia32_vmx_cr4_fixed0 = msrs::ia32_vmx_cr4_fixed0::get();
    auto ia32_vmx_cr4_fixed1 = msrs::ia32_vmx_cr4_fixed1::get();

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
    {
        bferror << " failed: check_host_cr4_for_unsupported_bits" << bfendl;
        bferror << "    - ia32_vmx_cr4_fixed0: " << view_as_pointer(ia32_vmx_cr4_fixed0) << bfendl;
        bferror << "    - ia32_vmx_cr4_fixed1: " << view_as_pointer(ia32_vmx_cr4_fixed1) << bfendl;
        bferror << "    - cr4: " << view_as_pointer(cr4) << bfendl;

        throw std::logic_error("invalid cr4");
    }
}

void
vmcs_intel_x64::check_host_cr3_for_unsupported_bits()
{
    if (!is_physical_address_valid(vmcs::host_cr3::get()))
        throw std::logic_error("host cr3 too large");
}

void
vmcs_intel_x64::check_host_ia32_sysenter_esp_canonical_address()
{
    auto esp = vm::read(VMCS_HOST_IA32_SYSENTER_ESP);

    if (!is_address_canonical(esp))
        throw std::logic_error("host sysenter esp must be canonical");
}

void
vmcs_intel_x64::check_host_ia32_sysenter_eip_canonical_address()
{
    auto eip = vm::read(VMCS_HOST_IA32_SYSENTER_EIP);

    if (!is_address_canonical(eip))
        throw std::logic_error("host sysenter eip must be canonical");
}

void
vmcs_intel_x64::check_host_verify_load_ia32_perf_global_ctrl()
{
    if (vmcs::vm_exit_controls::load_ia32_perf_global_ctrl::is_disabled())
        return;

    auto vmcs_ia32_perf_global_ctrl =
        vm::read(VMCS_HOST_IA32_PERF_GLOBAL_CTRL);

    if ((vmcs_ia32_perf_global_ctrl & 0xFFFFFFF8FFFFFFFC) != 0)
        throw std::logic_error("perf global ctrl msr reserved bits must be 0");
}

void
vmcs_intel_x64::check_host_verify_load_ia32_pat()
{
    if (vmcs::vm_exit_controls::load_ia32_pat::is_disabled())
        return;

    auto pat0 = (vm::read(VMCS_HOST_IA32_PAT) & 0x00000000000000FF) >> 0;
    auto pat1 = (vm::read(VMCS_HOST_IA32_PAT) & 0x000000000000FF00) >> 8;
    auto pat2 = (vm::read(VMCS_HOST_IA32_PAT) & 0x0000000000FF0000) >> 16;
    auto pat3 = (vm::read(VMCS_HOST_IA32_PAT) & 0x00000000FF000000) >> 24;
    auto pat4 = (vm::read(VMCS_HOST_IA32_PAT) & 0x000000FF00000000) >> 32;
    auto pat5 = (vm::read(VMCS_HOST_IA32_PAT) & 0x0000FF0000000000) >> 40;
    auto pat6 = (vm::read(VMCS_HOST_IA32_PAT) & 0x00FF000000000000) >> 48;
    auto pat7 = (vm::read(VMCS_HOST_IA32_PAT) & 0xFF00000000000000) >> 56;

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
    if (vmcs::vm_exit_controls::load_ia32_efer::is_disabled())
        return;

    if (vmcs::host_ia32_efer::reserved::get() != 0)
        throw std::logic_error("ia32 efer msr reserved buts must be 0 if "
                               "load ia32 efer entry is enabled");

    auto lma = vmcs::host_ia32_efer::lma::get();
    auto lme = vmcs::host_ia32_efer::lme::get();

    if (vmcs::vm_exit_controls::host_address_space_size::is_disabled() && lma != 0)
        throw std::logic_error("host addr space is 0, but efer.lma is 1");

    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled() && lma == 0)
        throw std::logic_error("host addr space is 1, but efer.lma is 0");

    if (vmcs::host_cr0::paging::get() == 0)
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
    if (vmcs::host_es_selector::ti::get())
        throw std::logic_error("host es ti flag must be 0");

    if (vmcs::host_es_selector::rpl::get() != 0)
        throw std::logic_error("host es rpl flag must be 0");
}

void
vmcs_intel_x64::check_host_cs_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_cs_selector::ti::get())
        throw std::logic_error("host cs ti flag must be 0");

    if (vmcs::host_cs_selector::rpl::get() != 0)
        throw std::logic_error("host cs rpl flag must be 0");
}

void
vmcs_intel_x64::check_host_ss_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_ss_selector::ti::get())
        throw std::logic_error("host ss ti flag must be 0");

    if (vmcs::host_ss_selector::rpl::get() != 0)
        throw std::logic_error("host ss rpl flag must be 0");
}

void
vmcs_intel_x64::check_host_ds_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_ds_selector::ti::get())
        throw std::logic_error("host ds ti flag must be 0");

    if (vmcs::host_ds_selector::rpl::get() != 0)
        throw std::logic_error("host ds rpl flag must be 0");
}

void
vmcs_intel_x64::check_host_fs_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_fs_selector::ti::get())
        throw std::logic_error("host fs ti flag must be 0");

    if (vmcs::host_fs_selector::rpl::get() != 0)
        throw std::logic_error("host fs rpl flag must be 0");
}

void
vmcs_intel_x64::check_host_gs_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_gs_selector::ti::get())
        throw std::logic_error("host gs ti flag must be 0");

    if (vmcs::host_gs_selector::rpl::get() != 0)
        throw std::logic_error("host gs rpl flag must be 0");
}

void
vmcs_intel_x64::check_host_tr_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_tr_selector::ti::get())
        throw std::logic_error("host tr ti flag must be 0");

    if (vmcs::host_tr_selector::rpl::get() != 0)
        throw std::logic_error("host tr rpl flag must be 0");
}

void
vmcs_intel_x64::check_host_cs_not_equal_zero()
{
    if (vmcs::host_cs_selector::get() == 0)
        throw std::logic_error("host cs cannot equal 0");
}

void
vmcs_intel_x64::check_host_tr_not_equal_zero()
{
    if (vmcs::host_tr_selector::get() == 0)
        throw std::logic_error("host tr cannot equal 0");
}

void
vmcs_intel_x64::check_host_ss_not_equal_zero()
{
    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled())
        return;

    if (vmcs::host_ss_selector::get() == 0)
        throw std::logic_error("host ss cannot equal 0");
}

void
vmcs_intel_x64::check_host_fs_canonical_base_address()
{
    auto fs_base = vm::read(VMCS_HOST_FS_BASE);

    if (!is_address_canonical(fs_base))
        throw std::logic_error("host fs base must be canonical");
}

void
vmcs_intel_x64::check_host_gs_canonical_base_address()
{
    auto gs_base = vm::read(VMCS_HOST_GS_BASE);

    if (!is_address_canonical(gs_base))
        throw std::logic_error("host gs base must be canonical");
}

void
vmcs_intel_x64::check_host_gdtr_canonical_base_address()
{
    auto gdtr_base = vm::read(VMCS_HOST_GDTR_BASE);

    if (!is_address_canonical(gdtr_base))
        throw std::logic_error("host gdtr base must be canonical");
}

void
vmcs_intel_x64::check_host_idtr_canonical_base_address()
{
    auto idtr_base = vm::read(VMCS_HOST_IDTR_BASE);

    if (!is_address_canonical(idtr_base))
        throw std::logic_error("host idtr base must be canonical");
}

void
vmcs_intel_x64::check_host_tr_canonical_base_address()
{
    auto tr_base = vm::read(VMCS_HOST_TR_BASE);

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
    if (msrs::ia32_efer::lma::get())
        return;

    if (vmcs::vm_entry_controls::ia_32e_mode_guest::is_enabled())
        throw std::logic_error("ia 32e mode must be 0 if efer.lma == 0");

    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled())
        throw std::logic_error("host addr space must be 0 if efer.lma == 0");
}

void
vmcs_intel_x64::check_host_vmcs_host_address_space_size_is_set()
{
    if (!msrs::ia32_efer::lma::get())
        return;

    if (vmcs::vm_exit_controls::host_address_space_size::is_disabled())
        throw std::logic_error("host addr space must be 1 if efer.lma == 1");
}

void
vmcs_intel_x64::check_host_host_address_space_disabled()
{
    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled())
        return;

    if (vmcs::vm_entry_controls::ia_32e_mode_guest::is_enabled())
        throw std::logic_error("ia 32e mode must be disabled if host addr space is disabled");

    if (vmcs::host_cr4::pcid_enable_bit::get() != 0)
        throw std::logic_error("cr4 pcide must be disabled if host addr space is disabled");

    auto rip = vm::read(VMCS_HOST_RIP);

    if ((rip & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("rip bits 63:32 must be 0 if host addr space is disabled");
}

void
vmcs_intel_x64::check_host_host_address_space_enabled()
{
    if (vmcs::vm_exit_controls::host_address_space_size::is_disabled())
        return;

    if (vmcs::host_cr4::physical_address_extensions::get() == 0)
        throw std::logic_error("cr4 pae must be enabled if host addr space is enabled");

    auto rip = vm::read(VMCS_HOST_RIP);

    if (!is_address_canonical(rip))
        throw std::logic_error("host rip must be canonical");
}
