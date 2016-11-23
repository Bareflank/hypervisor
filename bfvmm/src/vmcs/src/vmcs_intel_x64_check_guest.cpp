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
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_check.h>

#include <intrinsics/cpuid_x64.h>
#include <intrinsics/pdpte_x64.h>
#include <intrinsics/crs_intel_x64.h>

#include <memory_manager/memory_manager_x64.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;
using namespace check;

void
check::guest_state_all()
{
    check::guest_control_registers_debug_registers_and_msrs_all();
    check::guest_segment_registers_all();
    check::guest_descriptor_table_registers_all();
    check::guest_rip_and_rflags_all();
    check::guest_non_register_state_all();
    check::guest_pdptes_all();
}

void
check::guest_control_registers_debug_registers_and_msrs_all()
{
    check::guest_cr0_for_unsupported_bits();
    check::guest_cr0_verify_paging_enabled();
    check::guest_cr4_for_unsupported_bits();
    check::guest_load_debug_controls_verify_reserved();
    check::guest_verify_ia_32e_mode_enabled();
    check::guest_verify_ia_32e_mode_disabled();
    check::guest_cr3_for_unsupported_bits();
    check::guest_load_debug_controls_verify_dr7();
    check::guest_ia32_sysenter_esp_canonical_address();
    check::guest_ia32_sysenter_eip_canonical_address();
    check::guest_verify_load_ia32_perf_global_ctrl();
    check::guest_verify_load_ia32_pat();
    check::guest_verify_load_ia32_efer();
    check::guest_verify_load_ia32_bndcfgs();
}

void
check::guest_cr0_for_unsupported_bits()
{
    auto cr0 = guest_cr0::get();
    auto ia32_vmx_cr0_fixed0 = msrs::ia32_vmx_cr0_fixed0::get();
    auto ia32_vmx_cr0_fixed1 = msrs::ia32_vmx_cr0_fixed1::get();

    if (secondary_processor_based_vm_execution_controls::unrestricted_guest::is_enabled_if_exists())
        ia32_vmx_cr0_fixed0 &= ~(intel_x64::cr0::paging::mask | intel_x64::cr0::protection_enable::mask);

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
check::guest_cr0_verify_paging_enabled()
{
    if (guest_cr0::paging::is_disabled())
        return;

    if (guest_cr0::protection_enable::is_disabled())
        throw std::logic_error("PE must be enabled in cr0 if PG is enabled");
}

void
check::guest_cr4_for_unsupported_bits()
{
    auto cr4 = guest_cr4::get();
    auto ia32_vmx_cr4_fixed0 = msrs::ia32_vmx_cr4_fixed0::get();
    auto ia32_vmx_cr4_fixed1 = msrs::ia32_vmx_cr4_fixed1::get();

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
check::guest_load_debug_controls_verify_reserved()
{
    if (vm_entry_controls::load_debug_controls::is_disabled())
        return;

    if (vmcs::guest_ia32_debugctl::reserved::get() != 0)
        throw std::logic_error("debug ctrl msr reserved bits must be 0");
}

void
check::guest_verify_ia_32e_mode_enabled()
{
    if (vm_entry_controls::ia_32e_mode_guest::is_disabled())
        return;

    if (guest_cr0::paging::is_disabled())
        throw std::logic_error("paging must be enabled if ia 32e guest mode is enabled");

    if (guest_cr4::physical_address_extensions::is_disabled())
        throw std::logic_error("pae must be enabled if ia 32e guest mode is enabled");
}

void
check::guest_verify_ia_32e_mode_disabled()
{
    if (vm_entry_controls::ia_32e_mode_guest::is_enabled())
        return;

    if (guest_cr4::pcid_enable_bit::is_enabled())
        throw std::logic_error("pcide in cr4 must be disabled if ia 32e guest mode is disabled");
}

void
check::guest_cr3_for_unsupported_bits()
{
    if (!x64::is_physical_address_valid(guest_cr3::get()))
        throw std::logic_error("guest cr3 too large");
}

void
check::guest_load_debug_controls_verify_dr7()
{
    if (vm_entry_controls::load_debug_controls::is_disabled())
        return;

    auto dr7 = vmcs::guest_dr7::get();

    if ((dr7 & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("bits 63:32 of dr7 must be 0 if load debug controls is 1");
}

void
check::guest_ia32_sysenter_esp_canonical_address()
{
    if (!x64::is_address_canonical(vmcs::guest_ia32_sysenter_esp::get()))
        throw std::logic_error("guest sysenter esp must be canonical");
}

void
check::guest_ia32_sysenter_eip_canonical_address()
{
    if (!x64::is_address_canonical(vmcs::guest_ia32_sysenter_eip::get()))
        throw std::logic_error("guest sysenter eip must be canonical");
}

void
check::guest_verify_load_ia32_perf_global_ctrl()
{
    if (vm_entry_controls::load_ia32_perf_global_ctrl::is_disabled())
        return;

    if (vmcs::guest_ia32_perf_global_ctrl::reserved::get() != 0)
        throw std::logic_error("perf global ctrl msr reserved bits must be 0");
}

void
check::guest_verify_load_ia32_pat()
{
    if (vm_entry_controls::load_ia32_pat::is_disabled())
        return;

    if (check::memory_type_reserved(guest_ia32_pat::pa0::memory_type::get()))
        throw std::logic_error("pat0 has a reserved memory type");

    if (check::memory_type_reserved(guest_ia32_pat::pa1::memory_type::get()))
        throw std::logic_error("pat1 has a reserved memory type");

    if (check::memory_type_reserved(guest_ia32_pat::pa2::memory_type::get()))
        throw std::logic_error("pat2 has a reserved memory type");

    if (check::memory_type_reserved(guest_ia32_pat::pa3::memory_type::get()))
        throw std::logic_error("pat3 has a reserved memory type");

    if (check::memory_type_reserved(guest_ia32_pat::pa4::memory_type::get()))
        throw std::logic_error("pat4 has a reserved memory type");

    if (check::memory_type_reserved(guest_ia32_pat::pa5::memory_type::get()))
        throw std::logic_error("pat5 has a reserved memory type");

    if (check::memory_type_reserved(guest_ia32_pat::pa6::memory_type::get()))
        throw std::logic_error("pat6 has a reserved memory type");

    if (check::memory_type_reserved(guest_ia32_pat::pa7::memory_type::get()))
        throw std::logic_error("pat7 has a reserved memory type");
}

void
check::guest_verify_load_ia32_efer()
{
    if (vm_entry_controls::load_ia32_efer::is_disabled())
        return;

    if (guest_ia32_efer::reserved::get() != 0)
        throw std::logic_error("ia32 efer msr reserved buts must be 0 if "
                               "load ia32 efer entry is enabled");

    auto lma = guest_ia32_efer::lma::is_enabled();
    auto lme = guest_ia32_efer::lme::is_enabled();

    if (vm_entry_controls::ia_32e_mode_guest::is_disabled() && lma)
        throw std::logic_error("ia 32e mode is 0, but efer.lma is 1");

    if (vm_entry_controls::ia_32e_mode_guest::is_enabled() && !lma)
        throw std::logic_error("ia 32e mode is 1, but efer.lma is 0");

    if (guest_cr0::paging::is_disabled())
        return;

    if (!lme && lma)
        throw std::logic_error("efer.lme is 0, but efer.lma is 1");

    if (lme && !lma)
        throw std::logic_error("efer.lme is 1, but efer.lma is 0");
}

void
check::guest_verify_load_ia32_bndcfgs()
{
    if (vm_entry_controls::load_ia32_bndcfgs::is_disabled())
        return;

    auto bndcfgs = vmcs::guest_ia32_bndcfgs::get();

    if ((bndcfgs & 0x0000000000000FFC) != 0)
        throw std::logic_error("ia32 bndcfgs msr reserved bits must be 0 if "
                               "load ia32 bndcfgs entry is enabled");

    auto bound_addr = bndcfgs & 0xFFFFFFFFFFFFF000;

    if (!x64::is_address_canonical(bound_addr))
        throw std::logic_error("bound address in ia32 bndcfgs msr must be "
                               "canonical if load ia32 bndcfgs entry is enabled");
}

void
check::guest_segment_registers_all()
{
    check::guest_tr_ti_bit_equals_0();
    check::guest_ldtr_ti_bit_equals_0();
    check::guest_ss_and_cs_rpl_are_the_same();
    check::guest_cs_base_is_shifted();
    check::guest_ss_base_is_shifted();
    check::guest_ds_base_is_shifted();
    check::guest_es_base_is_shifted();
    check::guest_fs_base_is_shifted();
    check::guest_gs_base_is_shifted();
    check::guest_tr_base_is_canonical();
    check::guest_fs_base_is_canonical();
    check::guest_gs_base_is_canonical();
    check::guest_ldtr_base_is_canonical();
    check::guest_cs_base_upper_dword_0();
    check::guest_ss_base_upper_dword_0();
    check::guest_ds_base_upper_dword_0();
    check::guest_es_base_upper_dword_0();
    check::guest_cs_limit();
    check::guest_ss_limit();
    check::guest_ds_limit();
    check::guest_es_limit();
    check::guest_gs_limit();
    check::guest_fs_limit();
    check::guest_v8086_cs_access_rights();
    check::guest_v8086_ss_access_rights();
    check::guest_v8086_ds_access_rights();
    check::guest_v8086_es_access_rights();
    check::guest_v8086_fs_access_rights();
    check::guest_v8086_gs_access_rights();
    check::guest_cs_access_rights_type();
    check::guest_ss_access_rights_type();
    check::guest_ds_access_rights_type();
    check::guest_es_access_rights_type();
    check::guest_fs_access_rights_type();
    check::guest_gs_access_rights_type();
    check::guest_cs_is_not_a_system_descriptor();
    check::guest_ss_is_not_a_system_descriptor();
    check::guest_ds_is_not_a_system_descriptor();
    check::guest_es_is_not_a_system_descriptor();
    check::guest_fs_is_not_a_system_descriptor();
    check::guest_gs_is_not_a_system_descriptor();
    check::guest_cs_type_not_equal_3();
    check::guest_cs_dpl_adheres_to_ss_dpl();
    check::guest_ss_dpl_must_equal_rpl();
    check::guest_ss_dpl_must_equal_zero();
    check::guest_ds_dpl();
    check::guest_es_dpl();
    check::guest_fs_dpl();
    check::guest_gs_dpl();
    check::guest_cs_must_be_present();
    check::guest_ss_must_be_present_if_usable();
    check::guest_ds_must_be_present_if_usable();
    check::guest_es_must_be_present_if_usable();
    check::guest_fs_must_be_present_if_usable();
    check::guest_gs_must_be_present_if_usable();
    check::guest_cs_access_rights_reserved_must_be_0();
    check::guest_ss_access_rights_reserved_must_be_0();
    check::guest_ds_access_rights_reserved_must_be_0();
    check::guest_es_access_rights_reserved_must_be_0();
    check::guest_fs_access_rights_reserved_must_be_0();
    check::guest_gs_access_rights_reserved_must_be_0();
    check::guest_cs_db_must_be_0_if_l_equals_1();
    check::guest_cs_granularity();
    check::guest_ss_granularity();
    check::guest_ds_granularity();
    check::guest_es_granularity();
    check::guest_fs_granularity();
    check::guest_gs_granularity();
    check::guest_cs_access_rights_remaining_reserved_bit_0();
    check::guest_ss_access_rights_remaining_reserved_bit_0();
    check::guest_ds_access_rights_remaining_reserved_bit_0();
    check::guest_es_access_rights_remaining_reserved_bit_0();
    check::guest_fs_access_rights_remaining_reserved_bit_0();
    check::guest_gs_access_rights_remaining_reserved_bit_0();
    check::guest_tr_type_must_be_11();
    check::guest_tr_must_be_a_system_descriptor();
    check::guest_tr_must_be_present();
    check::guest_tr_access_rights_reserved_must_be_0();
    check::guest_tr_granularity();
    check::guest_tr_must_be_usable();
    check::guest_tr_access_rights_remaining_reserved_bit_0();
    check::guest_ldtr_type_must_be_2();
    check::guest_ldtr_must_be_a_system_descriptor();
    check::guest_ldtr_must_be_present();
    check::guest_ldtr_access_rights_reserved_must_be_0();
    check::guest_ldtr_granularity();
    check::guest_ldtr_access_rights_remaining_reserved_bit_0();
}

void
check::guest_tr_ti_bit_equals_0()
{
    if (guest_tr_selector::ti::get())
        throw std::logic_error("guest tr's ti flag must be zero");
}

void
check::guest_ldtr_ti_bit_equals_0()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_selector::ti::get())
        throw std::logic_error("guest ldtr's ti flag must be zero");
}

void
check::guest_ss_and_cs_rpl_are_the_same()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    if (guest_ss_selector::rpl::get() != guest_cs_selector::rpl::get())
        throw std::logic_error("ss and cs rpl must be the same");
}

void
check::guest_cs_base_is_shifted()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto cs = guest_cs_selector::get();

    if ((cs << 4) != vmcs::guest_cs_base::get())
        throw std::logic_error("if virtual 8086 mode is enabled, cs base must be cs shifted 4 bits");
}

void
check::guest_ss_base_is_shifted()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto ss = guest_ss_selector::get();

    if ((ss << 4) != vmcs::guest_ss_base::get())
        throw std::logic_error("if virtual 8086 mode is enabled, ss base must be ss shifted 4 bits");
}

void
check::guest_ds_base_is_shifted()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto ds = guest_ds_selector::get();

    if ((ds << 4) != vmcs::guest_ds_base::get())
        throw std::logic_error("if virtual 8086 mode is enabled, ds base must be ds shifted 4 bits");
}

void
check::guest_es_base_is_shifted()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto es = guest_es_selector::get();

    if ((es << 4) != vmcs::guest_es_base::get())
        throw std::logic_error("if virtual 8086 mode is enabled, es base must be es shifted 4 bits");
}

void
check::guest_fs_base_is_shifted()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto fs = guest_fs_selector::get();

    if ((fs << 4) != vmcs::guest_fs_base::get())
        throw std::logic_error("if virtual 8086 mode is enabled, fs base must be fs shifted 4 bits");
}

void
check::guest_gs_base_is_shifted()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto gs = guest_gs_selector::get();

    if ((gs << 4) != vmcs::guest_gs_base::get())
        throw std::logic_error("if virtual 8086 mode is enabled, gs base must be gs shift 4 bits");
}

void
check::guest_tr_base_is_canonical()
{
    if (!x64::is_address_canonical(vmcs::guest_tr_base::get()))
        throw std::logic_error("guest tr base non-canonical");
}

void
check::guest_fs_base_is_canonical()
{
    if (!x64::is_address_canonical(vmcs::guest_fs_base::get()))
        throw std::logic_error("guest fs base non-canonical");
}

void
check::guest_gs_base_is_canonical()
{
    if (!x64::is_address_canonical(vmcs::guest_gs_base::get()))
        throw std::logic_error("guest gs base non-canonical");
}

void
check::guest_ldtr_base_is_canonical()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (!x64::is_address_canonical(vmcs::guest_ldtr_base::get()))
        throw std::logic_error("guest ldtr base non-canonical");
}

void
check::guest_cs_base_upper_dword_0()
{
    if ((vmcs::guest_cs_base::get() & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest cs base bits 63:32 must be 0");
}

void
check::guest_ss_base_upper_dword_0()
{
    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if ((vmcs::guest_ss_base::get() & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest ss base bits 63:32 must be 0");
}

void
check::guest_ds_base_upper_dword_0()
{
    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if ((vmcs::guest_ds_base::get() & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest ds base bits 63:32 must be 0");
}

void
check::guest_es_base_upper_dword_0()
{
    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if ((vmcs::guest_es_base::get() & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest es base bits 63:32 must be 0");
}

void
check::guest_cs_limit()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto cs_limit = vmcs::guest_cs_limit::get();

    if (cs_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, cs limit must be 0xFFFF");
}

void
check::guest_ss_limit()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto ss_limit = vmcs::guest_ss_limit::get();

    if (ss_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, ss limit must be 0xFFFF");
}

void
check::guest_ds_limit()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto ds_limit = vmcs::guest_ds_limit::get();

    if (ds_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, ds limit must be 0xFFFF");
}

void
check::guest_es_limit()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto es_limit = vmcs::guest_es_limit::get();

    if (es_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, es limit must be 0xFFFF");
}

void
check::guest_gs_limit()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto gs_limit = vmcs::guest_gs_limit::get();

    if (gs_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, gs limit must be 0xFFFF");
}

void
check::guest_fs_limit()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    auto fs_limit = vmcs::guest_fs_limit::get();

    if (fs_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, fs limit must be 0xFFFF");
}

void
check::guest_v8086_cs_access_rights()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    if (guest_cs_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, cs access rights must be 0x00F3");
}

void
check::guest_v8086_ss_access_rights()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    if (guest_ss_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, ss access rights must be 0x00F3");
}

void
check::guest_v8086_ds_access_rights()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    if (guest_ds_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, ds access rights must be 0x00F3");
}

void
check::guest_v8086_es_access_rights()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    if (guest_es_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, es access rights must be 0x00F3");
}

void
check::guest_v8086_fs_access_rights()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    if (guest_fs_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, fs access rights must be 0x00F3");
}

void
check::guest_v8086_gs_access_rights()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_disabled())
        return;

    if (guest_gs_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, gs access rights must be 0x00F3");
}

void
check::guest_cs_access_rights_type()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    switch (guest_cs_access_rights::type::get())
    {
        case access_rights::type::read_write_accessed:
            if (activate_secondary_controls::is_disabled())
                break;

            if (unrestricted_guest::is_disabled_if_exists())
                break;

        case access_rights::type::execute_only_accessed:
        case access_rights::type::read_execute_accessed:
        case access_rights::type::execute_only_conforming_accessed:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    throw std::logic_error("guest cs type must be 9, 11, 13, 15, or "
                           "3 (if unrestricted guest support is enabled");
}

void
check::guest_ss_access_rights_type()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    switch (guest_ss_access_rights::type::get())
    {
        case access_rights::type::read_write_accessed:
        case access_rights::type::read_write_expand_down_accessed:
            return;

        default:
            break;
    }

    throw std::logic_error("guest ss type must be 3 or 7");
}

void
check::guest_ds_access_rights_type()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    switch (guest_ds_access_rights::type::get())
    {
        case access_rights::type::read_only_accessed:
        case access_rights::type::read_write_accessed:
        case access_rights::type::read_only_expand_down_accessed:
        case access_rights::type::read_write_expand_down_accessed:
        case access_rights::type::read_execute_accessed:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    throw std::logic_error("guest ds type must be 1, 3, 5, 7, 11, or 15");
}

void
check::guest_es_access_rights_type()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    switch (guest_es_access_rights::type::get())
    {
        case access_rights::type::read_only_accessed:
        case access_rights::type::read_write_accessed:
        case access_rights::type::read_only_expand_down_accessed:
        case access_rights::type::read_write_expand_down_accessed:
        case access_rights::type::read_execute_accessed:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    throw std::logic_error("guest ds type must be 1, 3, 5, 7, 11, or 15");
}

void
check::guest_fs_access_rights_type()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    switch (guest_fs_access_rights::type::get())
    {
        case access_rights::type::read_only_accessed:
        case access_rights::type::read_write_accessed:
        case access_rights::type::read_only_expand_down_accessed:
        case access_rights::type::read_write_expand_down_accessed:
        case access_rights::type::read_execute_accessed:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    throw std::logic_error("guest fs type must be 1, 3, 5, 7, 11, or 15");
}

void
check::guest_gs_access_rights_type()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    switch (guest_gs_access_rights::type::get())
    {
        case access_rights::type::read_only_accessed:
        case access_rights::type::read_write_accessed:
        case access_rights::type::read_only_expand_down_accessed:
        case access_rights::type::read_write_expand_down_accessed:
        case access_rights::type::read_execute_accessed:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    throw std::logic_error("guest gs type must be 1, 3, 5, 7, 11, or 15");
}

void
check::guest_cs_is_not_a_system_descriptor()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_cs_access_rights::s::get() == 0)
        throw std::logic_error("cs must be a code/data descriptor. S should equal 1");
}

void
check::guest_ss_is_not_a_system_descriptor()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if (guest_ss_access_rights::s::get() == 0)
        throw std::logic_error("ss must be a code/data descriptor. S should equal 1");
}

void
check::guest_ds_is_not_a_system_descriptor()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if (guest_ds_access_rights::s::get() == 0)
        throw std::logic_error("ds must be a code/data descriptor. S should equal 1");
}

void
check::guest_es_is_not_a_system_descriptor()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if (guest_es_access_rights::s::get() == 0)
        throw std::logic_error("es must be a code/data descriptor. S should equal 1");
}

void
check::guest_fs_is_not_a_system_descriptor()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_fs_access_rights::s::get() == 0)
        throw std::logic_error("fs must be a code/data descriptor. S should equal 1");
}

void
check::guest_gs_is_not_a_system_descriptor()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_gs_access_rights::unusable::get() != 0)
        return;

    if (guest_gs_access_rights::s::get() == 0)
        throw std::logic_error("gs must be a code/data descriptor. S should equal 1");
}

void
check::guest_cs_type_not_equal_3()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    switch (guest_cs_access_rights::type::get())
    {
        case access_rights::type::read_write_accessed:
            break;

        default:
            return;
    }

    if (guest_cs_access_rights::dpl::get() != 0)
        throw std::logic_error("cs dpl must be 0 if type == 3");
}

void
check::guest_cs_dpl_adheres_to_ss_dpl()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    switch (guest_cs_access_rights::type::get())
    {
        case access_rights::type::execute_only_accessed:
        case access_rights::type::read_execute_accessed:
        {
            auto cs_dpl = guest_cs_access_rights::dpl::get();
            auto ss_dpl = guest_ss_access_rights::dpl::get();

            if (cs_dpl != ss_dpl)
                throw std::logic_error("if cs access rights type is 9, 11 cs dpl must equal ss dpl");

            break;
        }

        case access_rights::type::execute_only_conforming_accessed:
        case access_rights::type::read_execute_conforming_accessed:
        {
            auto cs_dpl = guest_cs_access_rights::dpl::get();
            auto ss_dpl = guest_ss_access_rights::dpl::get();

            if (cs_dpl > ss_dpl)
                throw std::logic_error("if cs access rights type is 13, 15 cs dpl must not be greater than ss dpl");

            break;
        }

        default:
            break;
    }
}

void
check::guest_ss_dpl_must_equal_rpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    auto ss_rpl = guest_ss_selector::rpl::get();
    auto ss_dpl = guest_ss_access_rights::dpl::get();

    if (ss_dpl != ss_rpl)
        throw std::logic_error("if unrestricted guest mode is disabled ss dpl must equal ss rpl");
}

void
check::guest_ss_dpl_must_equal_zero()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    switch (guest_cs_access_rights::type::get())
    {
        case access_rights::type::read_write_accessed:
            break;

        default:
            if (guest_cr0::protection_enable::is_enabled())
                return;
    }

    if (guest_ss_access_rights::dpl::get() != 0)
        throw std::logic_error("if cs type is 3 or protected mode is disabled, ss DPL must be 0");
}

void
check::guest_ds_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    switch (guest_ds_access_rights::type::get())
    {
        case access_rights::type::execute_only_conforming:
        case access_rights::type::execute_only_conforming_accessed:
        case access_rights::type::read_execute_conforming:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    auto ds_rpl = guest_ds_selector::rpl::get();
    auto ds_dpl = guest_ds_access_rights::dpl::get();

    if (ds_dpl < ds_rpl)
        throw std::logic_error("if unrestricted guest mode is disabled, "
                               "and ds is usable, and the access rights "
                               "type is in the range 0-11, dpl cannot be "
                               "less than rpl");
}

void
check::guest_es_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    switch (guest_es_access_rights::type::get())
    {
        case access_rights::type::execute_only_conforming:
        case access_rights::type::execute_only_conforming_accessed:
        case access_rights::type::read_execute_conforming:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    auto es_rpl = guest_es_selector::rpl::get();
    auto es_dpl = guest_es_access_rights::dpl::get();

    if (es_dpl < es_rpl)
        throw std::logic_error("if unrestricted guest mode is disabled, "
                               "and es is usable, and the access rights "
                               "type is in the range 0-11, dpl cannot be "
                               "less than rpl");
}

void
check::guest_fs_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    switch (guest_fs_access_rights::type::get())
    {
        case access_rights::type::execute_only_conforming:
        case access_rights::type::execute_only_conforming_accessed:
        case access_rights::type::read_execute_conforming:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    auto fs_rpl = guest_fs_selector::rpl::get();
    auto fs_dpl = guest_fs_access_rights::dpl::get();

    if (fs_dpl < fs_rpl)
        throw std::logic_error("if unrestricted guest mode is disabled, "
                               "and fs is usable, and the access rights "
                               "type is in the range 0-11, dpl cannot be "
                               "less than rpl");
}

void
check::guest_gs_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    if (guest_gs_access_rights::unusable::get() != 0)
        return;

    switch (guest_gs_access_rights::type::get())
    {
        case access_rights::type::execute_only_conforming:
        case access_rights::type::execute_only_conforming_accessed:
        case access_rights::type::read_execute_conforming:
        case access_rights::type::read_execute_conforming_accessed:
            return;

        default:
            break;
    }

    auto gs_rpl = guest_gs_selector::rpl::get();
    auto gs_dpl = guest_gs_access_rights::dpl::get();

    if (gs_dpl < gs_rpl)
        throw std::logic_error("if unrestricted guest mode is disabled, "
                               "and gs is usable, and the access rights "
                               "type is in the range 0-11, dpl cannot be "
                               "less than rpl");
}

void
check::guest_cs_must_be_present()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_cs_access_rights::present::get() == 0)
        throw std::logic_error("cs access rights present flag must be 1 ");
}

void
check::guest_ss_must_be_present_if_usable()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if (guest_ss_access_rights::present::get() == 0)
        throw std::logic_error("ss access rights present flag must be 1 if ss is usable");
}

void
check::guest_ds_must_be_present_if_usable()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if (guest_ds_access_rights::present::get() == 0)
        throw std::logic_error("ds access rights present flag must be 1 if ds is usable");
}

void
check::guest_es_must_be_present_if_usable()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if (guest_es_access_rights::present::get() == 0)
        throw std::logic_error("es access rights present flag must be 1 if es is usable");
}

void
check::guest_fs_must_be_present_if_usable()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_fs_access_rights::present::get() == 0)
        throw std::logic_error("fs access rights present flag must be 1 if fs is usable");
}

void
check::guest_gs_must_be_present_if_usable()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_gs_access_rights::unusable::get() != 0)
        return;

    if (guest_gs_access_rights::present::get() == 0)
        throw std::logic_error("gs access rights present flag must be 1 if gs is usable");
}

void
check::guest_cs_access_rights_reserved_must_be_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_cs_access_rights::reserved::get() != 0)
        throw std::logic_error("cs access rights reserved bits must be 0 ");
}

void
check::guest_ss_access_rights_reserved_must_be_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if (guest_ss_access_rights::reserved::get() != 0)
        throw std::logic_error("ss access rights reserved bits must be 0 if ss is usable");
}

void
check::guest_ds_access_rights_reserved_must_be_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if (guest_ds_access_rights::reserved::get() != 0)
        throw std::logic_error("ds access rights reserved bits must be 0 if ds is usable");
}

void
check::guest_es_access_rights_reserved_must_be_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if (guest_es_access_rights::reserved::get() != 0)
        throw std::logic_error("es access rights reserved bits must be 0 if es is usable");
}

void
check::guest_fs_access_rights_reserved_must_be_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_fs_access_rights::reserved::get() != 0)
        throw std::logic_error("fs access rights reserved bits must be 0 if fs is usable");
}

void
check::guest_gs_access_rights_reserved_must_be_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_gs_access_rights::unusable::get() != 0)
        return;

    if (guest_gs_access_rights::reserved::get() != 0)
        throw std::logic_error("gs access rights reserved bits must be 0 if gs is usable");
}

void
check::guest_cs_db_must_be_0_if_l_equals_1()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (vm_entry_controls::ia_32e_mode_guest::is_disabled())
        return;

    if (guest_cs_access_rights::l::get() == 0)
        return;

    if (guest_cs_access_rights::db::get() != 0)
        throw std::logic_error("d/b for guest cs must be 0 if in ia 32e mode and l == 1");
}

void
check::guest_cs_granularity()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    auto cs_limit = vmcs::guest_cs_limit::get();
    auto g = guest_cs_access_rights::granularity::get();

    if ((cs_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest cs granularity must be 0 if any bit 11:0 is 0");

    if ((cs_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest cs granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_ss_granularity()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    auto ss_limit = vmcs::guest_ss_limit::get();
    auto g = guest_ss_access_rights::granularity::get();

    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if ((ss_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest ss granularity must be 0 if any bit 11:0 is 0");

    if ((ss_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest ss granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_ds_granularity()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    auto ds_limit = vmcs::guest_ds_limit::get();
    auto g = guest_ds_access_rights::granularity::get();

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if ((ds_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest ds granularity must be 0 if any bit 11:0 is 0");

    if ((ds_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest ds granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_es_granularity()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    auto es_limit = vmcs::guest_es_limit::get();
    auto g = guest_es_access_rights::granularity::get();

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if ((es_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest es granularity must be 0 if any bit 11:0 is 0");

    if ((es_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest es granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_fs_granularity()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    auto fs_limit = vmcs::guest_fs_limit::get();
    auto g = guest_fs_access_rights::granularity::get();

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if ((fs_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest fs granularity must be 0 if any bit 11:0 is 0");

    if ((fs_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest fs granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_gs_granularity()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    auto gs_limit = vmcs::guest_gs_limit::get();
    auto g = guest_gs_access_rights::granularity::get();

    if (guest_gs_access_rights::unusable::get() != 0)
        return;

    if ((gs_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest gs granularity must be 0 if any bit 11:0 is 0");

    if ((gs_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest gs granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_cs_access_rights_remaining_reserved_bit_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if ((guest_cs_access_rights::get() & 0xFFFE0000UL) != 0UL)
        throw std::logic_error("guest cs access rights bits 31:17 must be 0");
}

void
check::guest_ss_access_rights_remaining_reserved_bit_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if ((guest_ss_access_rights::get() & 0xFFFE0000UL) != 0UL)
        throw std::logic_error("guest ss access rights bits 31:17 must be 0");
}

void
check::guest_ds_access_rights_remaining_reserved_bit_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if ((guest_ds_access_rights::get() & 0xFFFE0000UL) != 0UL)
        throw std::logic_error("guest ds access rights bits 31:17 must be 0");
}

void
check::guest_es_access_rights_remaining_reserved_bit_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if ((guest_es_access_rights::get() & 0xFFFE0000UL) != 0UL)
        throw std::logic_error("guest es access rights bits 31:17 must be 0");
}

void
check::guest_fs_access_rights_remaining_reserved_bit_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if ((guest_fs_access_rights::get() & 0xFFFE0000UL) != 0UL)
        throw std::logic_error("guest fs access rights bits 31:17 must be 0");
}

void
check::guest_gs_access_rights_remaining_reserved_bit_0()
{
    if (vmcs::guest_rflags::virtual_8086_mode::is_enabled())
        return;

    if (guest_gs_access_rights::unusable::get() != 0)
        return;

    if ((guest_gs_access_rights::get() & 0xFFFE0000UL) != 0UL)
        throw std::logic_error("guest gs access rights bits 31:17 must be 0");
}

void
check::guest_tr_type_must_be_11()
{
    switch (guest_tr_access_rights::type::get())
    {
        case access_rights::type::read_write_accessed:
            if (vm_entry_controls::ia_32e_mode_guest::is_enabled())
                throw std::logic_error("tr type cannot be 3 if ia_32e_mode_guest is enabled");

            return;

        case access_rights::type::read_execute_accessed:
            return;

        default:
            throw std::logic_error("tr type must be 3 or 11");
    }
}

void
check::guest_tr_must_be_a_system_descriptor()
{
    if (guest_tr_access_rights::s::get() != 0)
        throw std::logic_error("tr must be a system descriptor. S should equal 0");
}

void
check::guest_tr_must_be_present()
{
    if (guest_tr_access_rights::present::get() == 0)
        throw std::logic_error("tr access rights present flag must be 1 ");
}

void
check::guest_tr_access_rights_reserved_must_be_0()
{
    if (guest_tr_access_rights::reserved::get() != 0)
        throw std::logic_error("tr access rights bits 11:8 must be 0");
}

void
check::guest_tr_granularity()
{
    auto tr_limit = vmcs::guest_tr_limit::get();
    auto g = guest_tr_access_rights::granularity::get();

    if ((tr_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest tr granularity must be 0 if any bit 11:0 is 0");

    if ((tr_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest tr granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_tr_must_be_usable()
{
    if (guest_tr_access_rights::unusable::get() != 0)
        throw std::logic_error("tr must be usable");
}

void
check::guest_tr_access_rights_remaining_reserved_bit_0()
{
    auto tr_access = vmcs::guest_tr_access_rights::get();

    if ((tr_access & 0xFFFE0000) != 0)
        throw std::logic_error("guest tr access rights bits 31:17 must be 0");
}

void
check::guest_ldtr_type_must_be_2()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    switch (guest_ldtr_access_rights::type::get())
    {
        case access_rights::type::read_write:
            break;

        default:
            throw std::logic_error("guest ldtr type must 2");
    }
}

void
check::guest_ldtr_must_be_a_system_descriptor()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_access_rights::s::get() != 0)
        throw std::logic_error("ldtr must be a system descriptor. S should equal 0");
}

void
check::guest_ldtr_must_be_present()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_access_rights::present::get() == 0)
        throw std::logic_error("ldtr access rights present flag must be 1 if ldtr is usable");
}

void
check::guest_ldtr_access_rights_reserved_must_be_0()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_access_rights::reserved::get() != 0)
        throw std::logic_error("ldtr access rights bits 11:8 must be 0");
}

void
check::guest_ldtr_granularity()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    auto ldtr_limit = vmcs::guest_ldtr_limit::get();
    auto g = guest_ldtr_access_rights::granularity::get();

    if ((ldtr_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest ldtr granularity must be 0 if any bit 11:0 is 0");

    if ((ldtr_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest ldtr granularity must be 1 if any bit 31:20 is 1");
}

void
check::guest_ldtr_access_rights_remaining_reserved_bit_0()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    auto ldtr_access = vmcs::guest_ldtr_access_rights::get();

    if ((ldtr_access & 0xFFFE0000) != 0)
        throw std::logic_error("guest ldtr access rights bits 31:17 must be 0 if ldtr is usable");
}

void
check::guest_descriptor_table_registers_all()
{
    check::guest_gdtr_base_must_be_canonical();
    check::guest_idtr_base_must_be_canonical();
    check::guest_gdtr_limit_reserved_bits();
    check::guest_idtr_limit_reserved_bits();
}

void
check::guest_gdtr_base_must_be_canonical()
{
    if (!x64::is_address_canonical(vmcs::guest_gdtr_base::get()))
        throw std::logic_error("gdtr base is non-canonical");
}

void
check::guest_idtr_base_must_be_canonical()
{
    if (!x64::is_address_canonical(vmcs::guest_idtr_base::get()))
        throw std::logic_error("idtr base is non-canonical");
}

void
check::guest_gdtr_limit_reserved_bits()
{
    auto gdtr_limit = vmcs::guest_gdtr_limit::get();

    if ((gdtr_limit & 0xFFFF0000) != 0)
        throw std::logic_error("gdtr limit bits 31:16 must be 0");
}

void
check::guest_idtr_limit_reserved_bits()
{
    auto idtr_limit = vmcs::guest_idtr_limit::get();

    if ((idtr_limit & 0xFFFF0000) != 0)
        throw std::logic_error("idtr limit bits 31:16 must be 0");
}

void
check::guest_rip_and_rflags_all()
{
    check::guest_rip_upper_bits();
    check::guest_rip_valid_addr();
    check::guest_rflags_reserved_bits();
    check::guest_rflags_vm_bit();
    check::guest_rflag_interrupt_enable();
}

void
check::guest_rip_upper_bits()
{
    auto cs_l = guest_cs_access_rights::l::get();

    if (vm_entry_controls::ia_32e_mode_guest::is_enabled() && cs_l != 0)
        return;

    if ((vmcs::guest_rip::get() & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("rip bits 61:32 must 0 if IA 32e mode is disabled or cs L is disabled");
}

void
check::guest_rip_valid_addr()
{
    auto cs_l = guest_cs_access_rights::l::get();

    if (vm_entry_controls::ia_32e_mode_guest::is_disabled())
        return;

    if (cs_l == 0)
        return;

    if (!is_linear_address_valid(vmcs::guest_rip::get()))
        throw std::logic_error("rip bits must be canonical");
}

void
check::guest_rflags_reserved_bits()
{
    if (guest_rflags::reserved::get() != 0)
        throw std::logic_error("reserved bits in rflags must be 0");

    if (guest_rflags::always_enabled::get() == 0)
        throw std::logic_error("always enabled bits in rflags must be 1");
}

void
check::guest_rflags_vm_bit()
{
    if (vm_entry_controls::ia_32e_mode_guest::is_disabled() && guest_cr0::protection_enable::is_enabled())
        return;

    if (guest_rflags::virtual_8086_mode::is_enabled())
        throw std::logic_error("rflags VM must be 0 if ia 32e mode is 1 or PE is 0");
}

void
check::guest_rflag_interrupt_enable()
{
    using namespace vm_entry_interruption_information_field;

    if (valid_bit::is_disabled())
        return;

    if (interruption_type::get() != interruption_type::external_interrupt)
        return;

    if (guest_rflags::interrupt_enable_flag::is_disabled())
        throw std::logic_error("rflags IF must be 1 if the valid bit is 1 and interrupt type is external");
}

void
check::guest_non_register_state_all()
{
    check::guest_valid_activity_state();
    check::guest_activity_state_not_hlt_when_dpl_not_0();
    check::guest_must_be_active_if_injecting_blocking_state();
    check::guest_hlt_valid_interrupts();
    check::guest_shutdown_valid_interrupts();
    check::guest_sipi_valid_interrupts();
    check::guest_valid_activity_state_and_smm();
    check::guest_interruptibility_state_reserved();
    check::guest_interruptibility_state_sti_mov_ss();
    check::guest_interruptibility_state_sti();
    check::guest_interruptibility_state_external_interrupt();
    check::guest_interruptibility_state_nmi();
    check::guest_interruptibility_not_in_smm();
    check::guest_interruptibility_entry_to_smm();
    check::guest_interruptibility_state_sti_and_nmi();
    check::guest_interruptibility_state_virtual_nmi();
    check::guest_interruptibility_state_enclave_interrupt();
    check::guest_pending_debug_exceptions_reserved();
    check::guest_pending_debug_exceptions_dbg_ctl();
    check::guest_pending_debug_exceptions_rtm();
    check::guest_vmcs_link_pointer_bits_11_0();
    check::guest_vmcs_link_pointer_valid_addr();
    check::guest_vmcs_link_pointer_first_word();
    check::guest_vmcs_link_pointer_not_in_smm();
    check::guest_vmcs_link_pointer_in_smm();
}

void
check::guest_valid_activity_state()
{
    if (vmcs::guest_activity_state::get() > 3)
        throw std::logic_error("activity state must be 0 - 3");
}

void
check::guest_activity_state_not_hlt_when_dpl_not_0()
{
    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::hlt)
        return;

    if (guest_ss_access_rights::dpl::get() != 0)
        throw std::logic_error("ss.dpl must be 0 if activity state is HLT");
}

void
check::guest_must_be_active_if_injecting_blocking_state()
{
    if (vmcs::guest_activity_state::get() == vmcs::guest_activity_state::active)
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_sti::get() != 0U)
        throw std::logic_error("activity state must be active if "
                               "interruptibility state is sti");

    if (vmcs::guest_interruptibility_state::blocking_by_mov_ss::get() != 0U)
        throw std::logic_error("activity state must be active if "
                               "interruptibility state is mov-ss");
}

void
check::guest_hlt_valid_interrupts()
{
    using namespace vm_entry_interruption_information_field;

    if (valid_bit::is_disabled())
        return;

    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::hlt)
        return;

    auto type = interruption_type::get();
    auto vector = vector::get();

    switch (type)
    {
        case interruption_type::external_interrupt:
        case interruption_type::non_maskable_interrupt:
            return;

        case interruption_type::hardware_exception:
            if (vector == interrupt::debug_exception)
                return;

            if (vector == interrupt::machine_check)
                return;

            break;

        case interruption_type::other_event:
            if (vector == interrupt::divide_error)
                return;

            break;

        default:
            break;
    }

    throw std::logic_error("invalid interruption combination for guest hlt");
}

void
check::guest_shutdown_valid_interrupts()
{
    using namespace vm_entry_interruption_information_field;

    if (valid_bit::is_disabled())
        return;

    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::shutdown)
        return;

    auto type = interruption_type::get();
    auto vector = vector::get();

    switch (type)
    {
        case interruption_type::non_maskable_interrupt:
            return;

        case interruption_type::hardware_exception:
            if (vector == interrupt::machine_check)
                return;

            break;

        default:
            break;
    }

    throw std::logic_error("invalid interruption combination for guest shutdown");
}

void
check::guest_sipi_valid_interrupts()
{
    if (vm_entry_interruption_information_field::valid_bit::is_disabled())
        return;

    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::wait_for_sipi)
        return;

    throw std::logic_error("invalid interruption combination");
}

void
check::guest_valid_activity_state_and_smm()
{
    if (vm_entry_controls::entry_to_smm::is_disabled())
        return;

    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::wait_for_sipi)
        return;

    throw std::logic_error("activity state must not equal wait for sipi if entry to smm is enabled");
}

void
check::guest_interruptibility_state_reserved()
{
    if (vmcs::guest_interruptibility_state::reserved::get() != 0)
        throw std::logic_error("interruptibility state reserved bits 31:5 must be 0");
}

void
check::guest_interruptibility_state_sti_mov_ss()
{
    auto sti = vmcs::guest_interruptibility_state::blocking_by_sti::get();
    auto mov_ss = vmcs::guest_interruptibility_state::blocking_by_mov_ss::get();

    if (sti != 0U && mov_ss != 0U)
        throw std::logic_error("interruptibility state sti and mov ss cannot both be 1");

}

void
check::guest_interruptibility_state_sti()
{
    if (guest_rflags::interrupt_enable_flag::is_enabled())
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_sti::get() != 0U)
        throw std::logic_error("interruptibility state sti must be 0 if rflags interrupt enabled is 0");
}

void
check::guest_interruptibility_state_external_interrupt()
{
    using namespace vm_entry_interruption_information_field;

    if (valid_bit::is_disabled())
        return;

    if (interruption_type::get() != interruption_type::external_interrupt)
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_sti::get() != 0U)
        throw std::logic_error("interruptibility state sti must be 0 if "
                               "interrupt type is external and valid");

    if (vmcs::guest_interruptibility_state::blocking_by_mov_ss::get() != 0U)
        throw std::logic_error("activity state must be active if "
                               "interruptibility state is mov-ss");
}

void
check::guest_interruptibility_state_nmi()
{
    using namespace vm_entry_interruption_information_field;

    if (valid_bit::is_disabled())
        return;

    if (interruption_type::get() != interruption_type::non_maskable_interrupt)
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_mov_ss::get() != 0U)
        throw std::logic_error("vali interrupt type must not be nmi if "
                               "interruptibility state is mov-ss");
}

void
check::guest_interruptibility_not_in_smm()
{
}

void
check::guest_interruptibility_entry_to_smm()
{
    if (vm_entry_controls::entry_to_smm::is_disabled())
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_smi::get() == 0U)
        throw std::logic_error("interruptibility state smi must be enabled "
                               "if entry to smm is enabled");
}

void
check::guest_interruptibility_state_sti_and_nmi()
{
    using namespace vm_entry_interruption_information_field;

    if (valid_bit::is_disabled())
        return;

    if (interruption_type::get() != interruption_type::non_maskable_interrupt)
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_sti::get() != 0U)
        throw std::logic_error("some processors require sti to be 0 if "
                               "the interruption type is nmi");
}

void
check::guest_interruptibility_state_virtual_nmi()
{
    using namespace vm_entry_interruption_information_field;

    if (pin_based_vm_execution_controls::virtual_nmis::is_disabled())
        return;

    if (valid_bit::is_disabled())
        return;

    if (interruption_type::get() != interruption_type::non_maskable_interrupt)
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_nmi::get() != 0)
        throw std::logic_error("if virtual nmi is enabled, and the interruption "
                               "type is NMI, blocking by nmi must be disabled");
}

void
check::guest_interruptibility_state_enclave_interrupt()
{
    if (guest_interruptibility_state::enclave_interruption::get() == 0)
        return;

    if (guest_interruptibility_state::blocking_by_mov_ss::get() != 0)
        throw std::logic_error("blocking by mov ss is enabled but enclave interrupt is "
                               "also enabled in interruptibility state");

    if (!x64::cpuid::extended_feature_flags::subleaf0::ebx::sgx::get())
        throw std::logic_error("enclave interrupt is 1 in interruptibility state "
                               "but the processor does not support sgx");
}

void
check::guest_pending_debug_exceptions_reserved()
{
    if (vmcs::guest_pending_debug_exceptions::reserved::get() != 0)
        throw std::logic_error("pending debug exception reserved bits must be 0");
}

void
check::guest_pending_debug_exceptions_dbg_ctl()
{
    auto sti = vmcs::guest_interruptibility_state::blocking_by_sti::get();
    auto mov_ss = vmcs::guest_interruptibility_state::blocking_by_mov_ss::get();
    auto activity_state = vmcs::guest_activity_state::get();

    if (sti == 0 && mov_ss == 0 && activity_state != vmcs::guest_activity_state::hlt)
        return;

    auto bs = vmcs::guest_pending_debug_exceptions::bs::is_enabled();
    auto tf = vmcs::guest_rflags::trap_flag::is_enabled();
    auto btf = vmcs::guest_ia32_debugctl::btf::is_enabled();

    if (!bs && tf && !btf)
        throw std::logic_error("pending debug exception bs must be 1 if "
                               "rflags tf is 1 and debugctl btf is 0");

    if (bs && !tf && btf)
        throw std::logic_error("pending debug exception bs must be 0 if "
                               "rflags tf is 0 and debugctl btf is 1");
}

void
check::guest_pending_debug_exceptions_rtm()
{
    if (guest_pending_debug_exceptions::rtm::is_disabled())
        return;

    if ((guest_pending_debug_exceptions::get() & 0xFFFFFFFFFFFEAFFF) != 0)
        throw std::logic_error("pending debug exception reserved bits and bits 3:0 "
                               "must be 0 if rtm is 1");

    if (guest_pending_debug_exceptions::enabled_breakpoint::is_disabled())
        throw std::logic_error("pending debug exception bit 12 must be 1 if rtm is 1");

    if (!x64::cpuid::extended_feature_flags::subleaf0::ebx::rtm::get())
        throw std::logic_error("rtm is set in pending debug exception but "
                               "rtm is unsupported by the processor");

    if (guest_interruptibility_state::blocking_by_mov_ss::get() == 1)
        throw std::logic_error("interruptibility-state field indicates blocking by mov ss"
                               " but rtm is set in pending debug exceptions field");
}

void
check::guest_vmcs_link_pointer_bits_11_0()
{
    auto vmcs_link_pointer = vmcs::vmcs_link_pointer::get();

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    if ((vmcs_link_pointer & 0x0000000000000FFF) != 0)
        throw std::logic_error("vmcs link pointer bits 11:0 must be 0");
}

void
check::guest_vmcs_link_pointer_valid_addr()
{
    auto vmcs_link_pointer = vmcs::vmcs_link_pointer::get();

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    if (!x64::is_physical_address_valid(vmcs_link_pointer))
        throw std::logic_error("vmcs link pointer invalid physical address");
}

void
check::guest_vmcs_link_pointer_first_word()
{
    auto vmcs_link_pointer = vmcs::vmcs_link_pointer::get();

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    auto vmcs = g_mm->physint_to_virtptr(vmcs_link_pointer);

    if (vmcs == nullptr)
        throw std::logic_error("invalid vmcs physical address");

    auto revision_id = *static_cast<uint32_t *>(vmcs) & 0x7FFFFFFF;
    auto vmcs_shadow = *static_cast<uint32_t *>(vmcs) & 0x80000000;

    if (revision_id != msrs::ia32_vmx_basic::revision_id::get())
        throw std::logic_error("shadow vmcs must contain CPU's revision id");

    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::vmcs_shadowing::is_disabled_if_exists())
        return;

    if (vmcs_shadow == 0)
        throw std::logic_error("shadow vmcs bit must be enabled if vmcs shadowing is enabled");
}

void
check::guest_vmcs_link_pointer_not_in_smm()
{
}

void
check::guest_vmcs_link_pointer_in_smm()
{
}

void
check::guest_pdptes_all()
{
    check::guest_valid_pdpte_with_ept_disabled();
    check::guest_valid_pdpte_with_ept_enabled();
}

void
check::guest_valid_pdpte_with_ept_disabled()
{
    if (guest_cr0::paging::is_disabled())
        return;

    if (guest_cr4::physical_address_extensions::is_disabled())
        return;

    if (vm_entry_controls::ia_32e_mode_guest::is_enabled())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_ept::is_enabled_if_exists())
        return;

    auto cr3 = vmcs::guest_cr3::get();
    auto virt_pdpt = static_cast<uint64_t *>(g_mm->physint_to_virtptr(cr3 & 0xFFFFFFE0UL));

    if (virt_pdpt == nullptr)
        throw std::logic_error("pdpt address is null");

    if ((virt_pdpt[0] & x64::pdpte::reserved::mask()) != 0U)
        throw std::logic_error("pdpte0 reserved bits set with ept disabled and pae paging enabled");

    if ((virt_pdpt[1] & x64::pdpte::reserved::mask()) != 0U)
        throw std::logic_error("pdpte1 reserved bits set with ept disabled and pae paging enabled");

    if ((virt_pdpt[2] & x64::pdpte::reserved::mask()) != 0U)
        throw std::logic_error("pdpte2 reserved bits set with ept disabled and pae paging enabled");

    if ((virt_pdpt[3] & x64::pdpte::reserved::mask()) != 0U)
        throw std::logic_error("pdpte3 reserved bits set with ept disabled and pae paging enabled");
}

void
check::guest_valid_pdpte_with_ept_enabled()
{
    if (guest_cr0::paging::is_disabled())
        return;

    if (guest_cr4::physical_address_extensions::is_disabled())
        return;

    if (vm_entry_controls::ia_32e_mode_guest::is_enabled())
        return;

    if (primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled())
        return;

    if (secondary_processor_based_vm_execution_controls::enable_ept::is_disabled_if_exists())
        return;

    if (vmcs::guest_pdpte0::reserved::get() != 0U)
        throw std::logic_error("pdpte0 reserved bits set with ept and pae paging enabled");

    if (vmcs::guest_pdpte1::reserved::get() != 0U)
        throw std::logic_error("pdpte1 reserved bits set with ept and pae paging enabled");

    if (vmcs::guest_pdpte2::reserved::get() != 0U)
        throw std::logic_error("pdpte2 reserved bits set with ept and pae paging enabled");

    if (vmcs::guest_pdpte3::reserved::get() != 0U)
        throw std::logic_error("ppdpte3 reserved bits set with ept and pae paging enabled");
}
