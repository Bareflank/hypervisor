//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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
#include <vmcs/vmcs_intel_x64_check.h>
#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_host_state_fields.h>

using namespace intel_x64;
using namespace vmcs;

void
check::host_state_all()
{
    check::host_control_registers_and_msrs_all();
    check::host_segment_and_descriptor_table_registers_all();
    check::host_address_space_size_all();
}

void
check::host_control_registers_and_msrs_all()
{
    check::host_cr0_for_unsupported_bits();
    check::host_cr4_for_unsupported_bits();
    check::host_cr3_for_unsupported_bits();
    check::host_ia32_sysenter_esp_canonical_address();
    check::host_ia32_sysenter_eip_canonical_address();
    check::host_verify_load_ia32_perf_global_ctrl();
    check::host_verify_load_ia32_pat();
    check::host_verify_load_ia32_efer();
}

void
check::host_cr0_for_unsupported_bits()
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
check::host_cr4_for_unsupported_bits()
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
check::host_cr3_for_unsupported_bits()
{
    if (!x64::is_physical_address_valid(vmcs::host_cr3::get()))
        throw std::logic_error("host cr3 too large");
}

void
check::host_ia32_sysenter_esp_canonical_address()
{
    if (!x64::is_address_canonical(vmcs::host_ia32_sysenter_esp::get()))
        throw std::logic_error("host sysenter esp must be canonical");
}

void
check::host_ia32_sysenter_eip_canonical_address()
{
    if (!x64::is_address_canonical(vmcs::host_ia32_sysenter_eip::get()))
        throw std::logic_error("host sysenter eip must be canonical");
}

void
check::host_verify_load_ia32_perf_global_ctrl()
{
    if (vmcs::vm_exit_controls::load_ia32_perf_global_ctrl::is_disabled())
        return;

    if (vmcs::host_ia32_perf_global_ctrl::reserved::get() != 0)
        throw std::logic_error("host perf global ctrl msr reserved bits must be 0");
}

void
check::host_verify_load_ia32_pat()
{
    if (vmcs::vm_exit_controls::load_ia32_pat::is_disabled())
        return;

    if (check::memory_type_reserved(host_ia32_pat::pa0::memory_type::get()))
        throw std::logic_error("pat0 has a reserved memory type");

    if (check::memory_type_reserved(host_ia32_pat::pa1::memory_type::get()))
        throw std::logic_error("pat1 has a reserved memory type");

    if (check::memory_type_reserved(host_ia32_pat::pa2::memory_type::get()))
        throw std::logic_error("pat2 has a reserved memory type");

    if (check::memory_type_reserved(host_ia32_pat::pa3::memory_type::get()))
        throw std::logic_error("pat3 has a reserved memory type");

    if (check::memory_type_reserved(host_ia32_pat::pa4::memory_type::get()))
        throw std::logic_error("pat4 has a reserved memory type");

    if (check::memory_type_reserved(host_ia32_pat::pa5::memory_type::get()))
        throw std::logic_error("pat5 has a reserved memory type");

    if (check::memory_type_reserved(host_ia32_pat::pa6::memory_type::get()))
        throw std::logic_error("pat6 has a reserved memory type");

    if (check::memory_type_reserved(host_ia32_pat::pa7::memory_type::get()))
        throw std::logic_error("pat7 has a reserved memory type");
}

void
check::host_verify_load_ia32_efer()
{
    if (vmcs::vm_exit_controls::load_ia32_efer::is_disabled())
        return;

    if (vmcs::host_ia32_efer::reserved::get() != 0)
        throw std::logic_error("host_ia32_efer reserved bits must be 0 if "
                               "load_ia32_efer exit control is enabled");

    auto lma = vmcs::host_ia32_efer::lma::is_enabled();
    auto lme = vmcs::host_ia32_efer::lme::is_enabled();

    if (vmcs::vm_exit_controls::host_address_space_size::is_disabled() && lma)
        throw std::logic_error("host addr space is 0, but efer.lma is 1");

    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled() && !lma)
        throw std::logic_error("host addr space is 1, but efer.lma is 0");

    if (vmcs::host_cr0::paging::is_disabled())
        return;

    if (!lme && lma)
        throw std::logic_error("efer.lme is 0, but efer.lma is 1");

    if (lme && !lma)
        throw std::logic_error("efer.lme is 1, but efer.lma is 0");
}

void
check::host_segment_and_descriptor_table_registers_all()
{
    check::host_es_selector_rpl_ti_equal_zero();
    check::host_cs_selector_rpl_ti_equal_zero();
    check::host_ss_selector_rpl_ti_equal_zero();
    check::host_ds_selector_rpl_ti_equal_zero();
    check::host_fs_selector_rpl_ti_equal_zero();
    check::host_gs_selector_rpl_ti_equal_zero();
    check::host_tr_selector_rpl_ti_equal_zero();
    check::host_cs_not_equal_zero();
    check::host_tr_not_equal_zero();
    check::host_ss_not_equal_zero();
    check::host_fs_canonical_base_address();
    check::host_gs_canonical_base_address();
    check::host_gdtr_canonical_base_address();
    check::host_idtr_canonical_base_address();
    check::host_tr_canonical_base_address();
}

void
check::host_es_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_es_selector::ti::get())
        throw std::logic_error("host es ti flag must be 0");

    if (vmcs::host_es_selector::rpl::get() != 0)
        throw std::logic_error("host es rpl flag must be 0");
}

void
check::host_cs_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_cs_selector::ti::get())
        throw std::logic_error("host cs ti flag must be 0");

    if (vmcs::host_cs_selector::rpl::get() != 0)
        throw std::logic_error("host cs rpl flag must be 0");
}

void
check::host_ss_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_ss_selector::ti::get())
        throw std::logic_error("host ss ti flag must be 0");

    if (vmcs::host_ss_selector::rpl::get() != 0)
        throw std::logic_error("host ss rpl flag must be 0");
}

void
check::host_ds_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_ds_selector::ti::get())
        throw std::logic_error("host ds ti flag must be 0");

    if (vmcs::host_ds_selector::rpl::get() != 0)
        throw std::logic_error("host ds rpl flag must be 0");
}

void
check::host_fs_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_fs_selector::ti::get())
        throw std::logic_error("host fs ti flag must be 0");

    if (vmcs::host_fs_selector::rpl::get() != 0)
        throw std::logic_error("host fs rpl flag must be 0");
}

void
check::host_gs_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_gs_selector::ti::get())
        throw std::logic_error("host gs ti flag must be 0");

    if (vmcs::host_gs_selector::rpl::get() != 0)
        throw std::logic_error("host gs rpl flag must be 0");
}

void
check::host_tr_selector_rpl_ti_equal_zero()
{
    if (vmcs::host_tr_selector::ti::get())
        throw std::logic_error("host tr ti flag must be 0");

    if (vmcs::host_tr_selector::rpl::get() != 0)
        throw std::logic_error("host tr rpl flag must be 0");
}

void
check::host_cs_not_equal_zero()
{
    if (vmcs::host_cs_selector::get() == 0)
        throw std::logic_error("host cs cannot equal 0");
}

void
check::host_tr_not_equal_zero()
{
    if (vmcs::host_tr_selector::get() == 0)
        throw std::logic_error("host tr cannot equal 0");
}

void
check::host_ss_not_equal_zero()
{
    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled())
        return;

    if (vmcs::host_ss_selector::get() == 0)
        throw std::logic_error("host ss cannot equal 0");
}

void
check::host_fs_canonical_base_address()
{
    if (!x64::is_address_canonical(vmcs::host_fs_base::get()))
        throw std::logic_error("host fs base must be canonical");
}

void
check::host_gs_canonical_base_address()
{
    if (!x64::is_address_canonical(vmcs::host_gs_base::get()))
        throw std::logic_error("host gs base must be canonical");
}

void
check::host_gdtr_canonical_base_address()
{
    if (!x64::is_address_canonical(vmcs::host_gdtr_base::get()))
        throw std::logic_error("host gdtr base must be canonical");
}

void
check::host_idtr_canonical_base_address()
{
    if (!x64::is_address_canonical(vmcs::host_idtr_base::get()))
        throw std::logic_error("host idtr base must be canonical");
}

void
check::host_tr_canonical_base_address()
{
    if (!x64::is_address_canonical(vmcs::host_tr_base::get()))
        throw std::logic_error("host tr base must be canonical");
}

void
check::host_address_space_size_all()
{
    check::host_if_outside_ia32e_mode();
    check::host_address_space_size_exit_ctl_is_set();
    check::host_address_space_disabled();
    check::host_address_space_enabled();
}

void
check::host_if_outside_ia32e_mode()
{
    if (msrs::ia32_efer::lma::get())
        return;

    if (vmcs::vm_entry_controls::ia_32e_mode_guest::is_enabled())
        throw std::logic_error("ia 32e mode must be 0 if efer.lma == 0");

    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled())
        throw std::logic_error("host addr space must be 0 if efer.lma == 0");
}

void
check::host_address_space_size_exit_ctl_is_set()
{
    if (!msrs::ia32_efer::lma::get())
        return;

    if (vmcs::vm_exit_controls::host_address_space_size::is_disabled())
        throw std::logic_error("host addr space must be 1 if efer.lma == 1");
}

void
check::host_address_space_disabled()
{
    if (vmcs::vm_exit_controls::host_address_space_size::is_enabled())
        return;

    if (vmcs::vm_entry_controls::ia_32e_mode_guest::is_enabled())
        throw std::logic_error("ia 32e mode must be disabled if host addr space is disabled");

    if (vmcs::host_cr4::pcid_enable_bit::is_enabled())
        throw std::logic_error("cr4 pcide must be disabled if host addr space is disabled");

    if ((vmcs::host_rip::get() & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("rip bits 63:32 must be 0 if host addr space is disabled");
}

void
check::host_address_space_enabled()
{
    if (vmcs::vm_exit_controls::host_address_space_size::is_disabled())
        return;

    if (vmcs::host_cr4::physical_address_extensions::is_disabled())
        throw std::logic_error("cr4 pae must be enabled if host addr space is enabled");

    if (!x64::is_address_canonical(vmcs::host_rip::get()))
        throw std::logic_error("host rip must be canonical");
}
