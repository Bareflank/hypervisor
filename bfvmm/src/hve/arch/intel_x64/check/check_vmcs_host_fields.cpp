//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VMCS_INTEL_X64_CHECK_HOST_H
#define VMCS_INTEL_X64_CHECK_HOST_H

#include <type_traits>

#include <intrinsics.h>
#include <memory_manager/memory_manager.h>

/// Intel x86_64 VMCS Check Host
///
/// This namespace implements the host checks found in
/// section 26.2.2, Vol. 3 of the SDM.
///

namespace bfvmm
{
namespace intel_x64
{
namespace check
{

void
host_cr0_for_unsupported_bits()
{
    auto cr0 = ::intel_x64::vmcs::host_cr0::get();
    auto ia32_vmx_cr0_fixed0 = ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get();
    auto ia32_vmx_cr0_fixed1 = ::intel_x64::msrs::ia32_vmx_cr0_fixed1::get();

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1))) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_info(0, "failed: check_host_cr0_for_unsupported_bits", msg);
            bferror_subnhex(0, "ia32_vmx_cr0_fixed0", ia32_vmx_cr0_fixed0, msg);
            bferror_subnhex(0, "ia32_vmx_cr0_fixed1", ia32_vmx_cr0_fixed1, msg);
            bferror_subnhex(0, "cr0", cr0, msg);
        });

        throw std::logic_error("invalid cr0");
    }
}

void
host_cr4_for_unsupported_bits()
{
    auto cr4 = ::intel_x64::vmcs::host_cr4::get();
    auto ia32_vmx_cr4_fixed0 = ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get();
    auto ia32_vmx_cr4_fixed1 = ::intel_x64::msrs::ia32_vmx_cr4_fixed1::get();

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1))) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_info(0, "failed: check_host_cr4_for_unsupported_bits", msg);
            bferror_subnhex(0, "ia32_vmx_cr4_fixed0", ia32_vmx_cr4_fixed0, msg);
            bferror_subnhex(0, "ia32_vmx_cr4_fixed1", ia32_vmx_cr4_fixed1, msg);
            bferror_subnhex(0, "cr4", cr4, msg);
        });

        throw std::logic_error("invalid cr4");
    }
}

void
host_cr3_for_unsupported_bits()
{
    if (!::x64::is_physical_address_valid(::intel_x64::vmcs::host_cr3::get())) {
        bfdebug_nhex(0, "host_cr3", ::intel_x64::vmcs::host_cr3::get());
        throw std::logic_error("host cr3 too large");
    }
}

void
host_ia32_sysenter_esp_canonical_address()
{
    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_ia32_sysenter_esp::get())) {
        throw std::logic_error("host sysenter esp must be canonical");
    }
}

void
host_ia32_sysenter_eip_canonical_address()
{
    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_ia32_sysenter_eip::get())) {
        throw std::logic_error("host sysenter eip must be canonical");
    }
}

void
host_verify_load_ia32_perf_global_ctrl()
{
    if (::intel_x64::vmcs::vm_exit_controls::load_ia32_perf_global_ctrl::is_disabled()) {
        return;
    }

    if (::intel_x64::vmcs::host_ia32_perf_global_ctrl::reserved::get() != 0) {
        throw std::logic_error("host perf global ctrl msr reserved bits must be 0");
    }
}

void
host_verify_load_ia32_pat()
{
    if (::intel_x64::vmcs::vm_exit_controls::load_ia32_pat::is_disabled()) {
        return;
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa0::memory_type::get())) {
        throw std::logic_error("pat0 has a reserved memory type");
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa1::memory_type::get())) {
        throw std::logic_error("pat1 has a reserved memory type");
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa2::memory_type::get())) {
        throw std::logic_error("pat2 has a reserved memory type");
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa3::memory_type::get())) {
        throw std::logic_error("pat3 has a reserved memory type");
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa4::memory_type::get())) {
        throw std::logic_error("pat4 has a reserved memory type");
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa5::memory_type::get())) {
        throw std::logic_error("pat5 has a reserved memory type");
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa6::memory_type::get())) {
        throw std::logic_error("pat6 has a reserved memory type");
    }

    if (::intel_x64::vmcs::memory_type_reserved(::intel_x64::vmcs::host_ia32_pat::pa7::memory_type::get())) {
        throw std::logic_error("pat7 has a reserved memory type");
    }
}

void
host_verify_load_ia32_efer()
{
    if (::intel_x64::vmcs::vm_exit_controls::load_ia32_efer::is_disabled()) {
        return;
    }

    if (::intel_x64::vmcs::host_ia32_efer::reserved::get() != 0) {
        throw std::logic_error("host_ia32_efer reserved bits must be 0 if "
                               "load_ia32_efer exit control is enabled");
    }

    auto lma = ::intel_x64::vmcs::host_ia32_efer::lma::is_enabled();
    auto lme = ::intel_x64::vmcs::host_ia32_efer::lme::is_enabled();

    if (::intel_x64::vmcs::vm_exit_controls::host_address_space_size::is_disabled() && lma) {
        throw std::logic_error("host addr space is 0, but efer.lma is 1");
    }

    if (::intel_x64::vmcs::vm_exit_controls::host_address_space_size::is_enabled() && !lma) {
        throw std::logic_error("host addr space is 1, but efer.lma is 0");
    }

    if (::intel_x64::vmcs::host_cr0::paging::is_disabled()) {
        return;
    }

    if (!lme && lma) {
        throw std::logic_error("efer.lme is 0, but efer.lma is 1");
    }

    if (lme && !lma) {
        throw std::logic_error("efer.lme is 1, but efer.lma is 0");
    }
}

void
host_es_selector_rpl_ti_equal_zero()
{
    if (::intel_x64::vmcs::host_es_selector::ti::is_enabled()) {
        throw std::logic_error("host es ti flag must be 0");
    }

    if (::intel_x64::vmcs::host_es_selector::rpl::get() != 0) {
        throw std::logic_error("host es rpl flag must be 0");
    }
}

void
host_cs_selector_rpl_ti_equal_zero()
{
    if (::intel_x64::vmcs::host_cs_selector::ti::is_enabled()) {
        throw std::logic_error("host cs ti flag must be 0");
    }

    if (::intel_x64::vmcs::host_cs_selector::rpl::get() != 0) {
        throw std::logic_error("host cs rpl flag must be 0");
    }
}

void
host_ss_selector_rpl_ti_equal_zero()
{
    if (::intel_x64::vmcs::host_ss_selector::ti::is_enabled()) {
        throw std::logic_error("host ss ti flag must be 0");
    }

    if (::intel_x64::vmcs::host_ss_selector::rpl::get() != 0) {
        throw std::logic_error("host ss rpl flag must be 0");
    }
}

void
host_ds_selector_rpl_ti_equal_zero()
{
    if (::intel_x64::vmcs::host_ds_selector::ti::is_enabled()) {
        throw std::logic_error("host ds ti flag must be 0");
    }

    if (::intel_x64::vmcs::host_ds_selector::rpl::get() != 0) {
        throw std::logic_error("host ds rpl flag must be 0");
    }
}

void
host_fs_selector_rpl_ti_equal_zero()
{
    if (::intel_x64::vmcs::host_fs_selector::ti::is_enabled()) {
        throw std::logic_error("host fs ti flag must be 0");
    }

    if (::intel_x64::vmcs::host_fs_selector::rpl::get() != 0) {
        throw std::logic_error("host fs rpl flag must be 0");
    }
}

void
host_gs_selector_rpl_ti_equal_zero()
{
    if (::intel_x64::vmcs::host_gs_selector::ti::is_enabled()) {
        throw std::logic_error("host gs ti flag must be 0");
    }

    if (::intel_x64::vmcs::host_gs_selector::rpl::get() != 0) {
        throw std::logic_error("host gs rpl flag must be 0");
    }
}

void
host_tr_selector_rpl_ti_equal_zero()
{
    if (::intel_x64::vmcs::host_tr_selector::ti::is_enabled()) {
        throw std::logic_error("host tr ti flag must be 0");
    }

    if (::intel_x64::vmcs::host_tr_selector::rpl::get() != 0) {
        throw std::logic_error("host tr rpl flag must be 0");
    }
}

void
host_cs_not_equal_zero()
{
    if (::intel_x64::vmcs::host_cs_selector::get() == 0) {
        throw std::logic_error("host cs cannot equal 0");
    }
}

void
host_tr_not_equal_zero()
{
    if (::intel_x64::vmcs::host_tr_selector::get() == 0) {
        throw std::logic_error("host tr cannot equal 0");
    }
}

void
host_ss_not_equal_zero()
{
    if (::intel_x64::vmcs::vm_exit_controls::host_address_space_size::is_enabled()) {
        return;
    }

    if (::intel_x64::vmcs::host_ss_selector::get() == 0) {
        throw std::logic_error("host ss cannot equal 0");
    }
}

void
host_fs_canonical_base_address()
{
    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_fs_base::get())) {
        throw std::logic_error("host fs base must be canonical");
    }
}

void
host_gs_canonical_base_address()
{
    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_gs_base::get())) {
        throw std::logic_error("host gs base must be canonical");
    }
}

void
host_gdtr_canonical_base_address()
{
    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_gdtr_base::get())) {
        throw std::logic_error("host gdtr base must be canonical");
    }
}

void
host_idtr_canonical_base_address()
{
    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_idtr_base::get())) {
        throw std::logic_error("host idtr base must be canonical");
    }
}

void
host_tr_canonical_base_address()
{
    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_tr_base::get())) {
        throw std::logic_error("host tr base must be canonical");
    }
}

void
host_if_outside_ia32e_mode()
{
    if (::intel_x64::msrs::ia32_efer::lma::is_enabled()) {
        return;
    }

    if (::intel_x64::vmcs::vm_entry_controls::ia_32e_mode_guest::is_enabled()) {
        throw std::logic_error("ia 32e mode must be 0 if efer.lma == 0");
    }

    if (::intel_x64::vmcs::vm_exit_controls::host_address_space_size::is_enabled()) {
        throw std::logic_error("host addr space must be 0 if efer.lma == 0");
    }
}

void
host_address_space_size_exit_ctl_is_set()
{
    if (!::intel_x64::msrs::ia32_efer::lma::is_enabled()) {
        return;
    }

    if (::intel_x64::vmcs::vm_exit_controls::host_address_space_size::is_disabled()) {
        throw std::logic_error("host addr space must be 1 if efer.lma == 1");
    }
}

void
host_address_space_disabled()
{
    if (::intel_x64::vmcs::vm_exit_controls::host_address_space_size::is_enabled()) {
        return;
    }

    if (::intel_x64::vmcs::vm_entry_controls::ia_32e_mode_guest::is_enabled()) {
        throw std::logic_error("ia 32e mode must be disabled if host addr space is disabled");
    }

    if (::intel_x64::vmcs::host_cr4::pcid_enable_bit::is_enabled()) {
        throw std::logic_error("cr4 pcide must be disabled if host addr space is disabled");
    }

    if ((::intel_x64::vmcs::host_rip::get() & 0xFFFFFFFF00000000) != 0) {
        throw std::logic_error("rip bits 63:32 must be 0 if host addr space is disabled");
    }
}

void
host_address_space_enabled()
{
    if (::intel_x64::vmcs::vm_exit_controls::host_address_space_size::is_disabled()) {
        return;
    }

    if (::intel_x64::vmcs::host_cr4::physical_address_extensions::is_disabled()) {
        throw std::logic_error("cr4 pae must be enabled if host addr space is enabled");
    }

    if (!::x64::is_address_canonical(::intel_x64::vmcs::host_rip::get())) {
        throw std::logic_error("host rip must be canonical");
    }
}

}
}
}

#endif
