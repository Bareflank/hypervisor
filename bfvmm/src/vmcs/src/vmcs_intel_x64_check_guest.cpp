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
#include <vmcs/vmcs_intel_x64_16bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <memory_manager/memory_manager_x64.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

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
    auto cr0 = guest_cr0::get();
    auto ia32_vmx_cr0_fixed0 = msrs::ia32_vmx_cr0_fixed0::get();
    auto ia32_vmx_cr0_fixed1 = msrs::ia32_vmx_cr0_fixed1::get();

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
vmcs_intel_x64::check_guest_cr0_verify_paging_enabled()
{
    if (guest_cr0::paging::get() == 0)
        return;

    if (guest_cr0::protection_enable::get() == 0)
        throw std::logic_error("PE must be enabled in cr0 if PG is enabled");
}

void
vmcs_intel_x64::check_guest_cr4_for_unsupported_bits()
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
vmcs_intel_x64::check_guest_load_debug_controls_verify_reserved()
{
    if (vm_entry_controls::load_debug_controls::is_disabled())
        return;

    if (guest_ia32_debugctl::reserved::get() != 0)
        throw std::logic_error("debug ctrl msr reserved bits must be 0");
}

void
vmcs_intel_x64::check_guest_verify_ia_32e_mode_enabled()
{
    if (vm_entry_controls::ia_32e_mode_guest::is_disabled())
        return;

    if (guest_cr0::paging::get() == 0)
        throw std::logic_error("paging must be enabled if ia 32e guest mode is enabled");

    if (guest_cr4::physical_address_extensions::get() == 0)
        throw std::logic_error("pae must be enabled if ia 32e guest mode is enabled");
}

void
vmcs_intel_x64::check_guest_verify_ia_32e_mode_disabled()
{
    if (vm_entry_controls::ia_32e_mode_guest::is_enabled())
        return;

    if (guest_cr4::pcid_enable_bit::get() != 0)
        throw std::logic_error("pcide in cr4 must be disabled if ia 32e guest mode is disabled");
}

void
vmcs_intel_x64::check_guest_cr3_for_unsupported_bits()
{
    if (!is_physical_address_valid(guest_cr3::get()))
        throw std::logic_error("guest cr3 too large");
}

void
vmcs_intel_x64::check_guest_load_debug_controls_verify_dr7()
{
    if (vm_entry_controls::load_debug_controls::is_disabled())
        return;

    auto dr7 = vm::read(VMCS_GUEST_DR7);

    if ((dr7 & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("bits 63:32 of dr7 must be 0 if load debug controls is 1");
}

void
vmcs_intel_x64::check_guest_ia32_sysenter_esp_canonical_address()
{
    auto esp = vm::read(VMCS_GUEST_IA32_SYSENTER_ESP);

    if (!is_address_canonical(esp))
        throw std::logic_error("guest sysenter esp must be canonical");
}

void
vmcs_intel_x64::check_guest_ia32_sysenter_eip_canonical_address()
{
    auto eip = vm::read(VMCS_GUEST_IA32_SYSENTER_EIP);

    if (!is_address_canonical(eip))
        throw std::logic_error("guest sysenter eip must be canonical");
}

void
vmcs_intel_x64::check_guest_verify_load_ia32_perf_global_ctrl()
{
    if (vm_entry_controls::load_ia32_perf_global_ctrl::is_disabled())
        return;

    auto vmcs_ia32_perf_global_ctrl =
        vm::read(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL);

    if ((vmcs_ia32_perf_global_ctrl & 0xFFFFFFF8FFFFFFFC) != 0)
        throw std::logic_error("perf global ctrl msr reserved bits must be 0");
}

void
vmcs_intel_x64::check_guest_verify_load_ia32_pat()
{
    if (vm_entry_controls::load_ia32_pat::is_disabled())
        return;

    auto pat0 = vm::read(VMCS_GUEST_IA32_PAT) & 0x00000000000000FF >> 0;
    auto pat1 = vm::read(VMCS_GUEST_IA32_PAT) & 0x000000000000FF00 >> 8;
    auto pat2 = vm::read(VMCS_GUEST_IA32_PAT) & 0x0000000000FF0000 >> 16;
    auto pat3 = vm::read(VMCS_GUEST_IA32_PAT) & 0x00000000FF000000 >> 24;
    auto pat4 = vm::read(VMCS_GUEST_IA32_PAT) & 0x000000FF00000000 >> 32;
    auto pat5 = vm::read(VMCS_GUEST_IA32_PAT) & 0x0000FF0000000000 >> 40;
    auto pat6 = vm::read(VMCS_GUEST_IA32_PAT) & 0x00FF000000000000 >> 48;
    auto pat7 = vm::read(VMCS_GUEST_IA32_PAT) & 0xFF00000000000000 >> 56;

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
vmcs_intel_x64::check_guest_verify_load_ia32_efer()
{
    if (vm_entry_controls::load_ia32_efer::is_disabled())
        return;

    if (guest_ia32_efer::reserved::get() != 0)
        throw std::logic_error("ia32 efer msr reserved buts must be 0 if "
                               "load ia32 efer entry is enabled");

    auto lma = guest_ia32_efer::lma::get();
    auto lme = guest_ia32_efer::lme::get();

    if (vm_entry_controls::ia_32e_mode_guest::is_disabled() && lma != 0)
        throw std::logic_error("ia 32e mode is 0, but efer.lma is 1");

    if (vm_entry_controls::ia_32e_mode_guest::is_enabled() && lma == 0)
        throw std::logic_error("ia 32e mode is 1, but efer.lma is 0");

    if (guest_cr0::paging::get() == 0)
        return;

    if (lme == 0 && lma != 0)
        throw std::logic_error("efer.lme is 0, but efer.lma is 1");

    if (lme != 0 && lma == 0)
        throw std::logic_error("efer.lme is 1, but efer.lma is 0");
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
    check_guest_tr_type_must_be_11();
    check_guest_tr_must_be_a_system_descriptor();
    check_guest_tr_must_be_present();
    check_guest_tr_access_rights_reserved_must_be_0();
    check_guest_tr_granularity();
    check_guest_tr_must_be_usable();
    check_guest_ldtr_type_must_be_2();
    check_guest_ldtr_must_be_a_system_descriptor();
    check_guest_ldtr_must_be_present();
    check_guest_ldtr_access_rights_reserved_must_be_0();
    check_guest_ldtr_granularity();
}

void
vmcs_intel_x64::check_guest_tr_ti_bit_equals_0()
{
    if (guest_tr_selector::ti::get())
        throw std::logic_error("guest tr's ti flag must be zero");
}

void
vmcs_intel_x64::check_guest_ldtr_ti_bit_equals_0()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_selector::ti::get())
        throw std::logic_error("guest ldtr's ti flag must be zero");
}

void
vmcs_intel_x64::check_guest_ss_and_cs_rpl_are_the_same()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (is_enabled_v8086())
        return;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    if (guest_ss_selector::rpl::get() != guest_cs_selector::rpl::get())
        throw std::logic_error("ss and cs rpl must be the same");
}

void
vmcs_intel_x64::check_guest_cs_base_is_shifted()
{
    if (!is_enabled_v8086())
        return;

    auto cs = guest_cs_selector::get();
    auto cs_base = vm::read(VMCS_GUEST_CS_BASE);

    if ((cs << 4) != cs_base)
        throw std::logic_error("if virtual 8086 mode is enabled, cs base must be cs shifted 4 bits");
}

void
vmcs_intel_x64::check_guest_ss_base_is_shifted()
{
    if (!is_enabled_v8086())
        return;

    auto ss = guest_ss_selector::get();
    auto ss_base = vm::read(VMCS_GUEST_SS_BASE);

    if ((ss << 4) != ss_base)
        throw std::logic_error("if virtual 8086 mode is enabled, ss base must be ss shifted 4 bits");
}

void
vmcs_intel_x64::check_guest_ds_base_is_shifted()
{
    if (!is_enabled_v8086())
        return;

    auto ds = guest_ds_selector::get();
    auto ds_base = vm::read(VMCS_GUEST_DS_BASE);

    if ((ds << 4) != ds_base)
        throw std::logic_error("if virtual 8086 mode is enabled, ds base must be ds shifted 4 bits");
}

void
vmcs_intel_x64::check_guest_es_base_is_shifted()
{
    if (!is_enabled_v8086())
        return;

    auto es = guest_es_selector::get();
    auto es_base = vm::read(VMCS_GUEST_ES_BASE);

    if ((es << 4) != es_base)
        throw std::logic_error("if virtual 8086 mode is enabled, es base must be es shifted 4 bits");
}

void
vmcs_intel_x64::check_guest_fs_base_is_shifted()
{
    if (!is_enabled_v8086())
        return;

    auto fs = guest_fs_selector::get();
    auto fs_base = vm::read(VMCS_GUEST_FS_BASE);

    if ((fs << 4) != fs_base)
        throw std::logic_error("if virtual 8086 mode is enabled, fs base must be fs shifted 4 bits");
}

void
vmcs_intel_x64::check_guest_gs_base_is_shifted()
{
    if (!is_enabled_v8086())
        return;

    auto gs = guest_gs_selector::get();
    auto gs_base = vm::read(VMCS_GUEST_GS_BASE);

    if ((gs << 4) != gs_base)
        throw std::logic_error("if virtual 8086 mode is enabled, gs base must be gs shift 4 bits");
}

void
vmcs_intel_x64::check_guest_tr_base_is_canonical()
{
    auto tr_base = vm::read(VMCS_GUEST_TR_BASE);

    if (!is_address_canonical(tr_base))
        throw std::logic_error("guest tr base non-canonical");
}

void
vmcs_intel_x64::check_guest_fs_base_is_canonical()
{
    auto fs_base = vm::read(VMCS_GUEST_FS_BASE);

    if (!is_address_canonical(fs_base))
        throw std::logic_error("guest fs base non-canonical");
}

void
vmcs_intel_x64::check_guest_gs_base_is_canonical()
{
    auto gs_base = vm::read(VMCS_GUEST_GS_BASE);

    if (!is_address_canonical(gs_base))
        throw std::logic_error("guest gs base non-canonical");
}

void
vmcs_intel_x64::check_guest_ldtr_base_is_canonical()
{
    auto ldtr_base = vm::read(VMCS_GUEST_LDTR_BASE);

    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (!is_address_canonical(ldtr_base))
        throw std::logic_error("guest ldtr base non-canonical");
}

void
vmcs_intel_x64::check_guest_cs_base_upper_dword_0()
{
    auto cs_base = vm::read(VMCS_GUEST_CS_BASE);

    if ((cs_base & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest cs base bits 63:32 must be 0");
}

void
vmcs_intel_x64::check_guest_ss_base_upper_dword_0()
{
    auto ss_base = vm::read(VMCS_GUEST_SS_BASE);

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if ((ss_base & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest ss base bits 63:32 must be 0");
}

void
vmcs_intel_x64::check_guest_ds_base_upper_dword_0()
{
    auto ds_base = vm::read(VMCS_GUEST_DS_BASE);

    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if ((ds_base & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest ds base bits 63:32 must be 0");
}

void
vmcs_intel_x64::check_guest_es_base_upper_dword_0()
{
    auto es_base = vm::read(VMCS_GUEST_ES_BASE);

    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if ((es_base & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("guest es base bits 63:32 must be 0");
}

void
vmcs_intel_x64::check_guest_cs_limit()
{
    if (!is_enabled_v8086())
        return;

    auto cs_limit = vmcs::guest_cs_limit::get();

    if (cs_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, cs limit must be 0xFFFF");
}

void
vmcs_intel_x64::check_guest_ss_limit()
{
    if (!is_enabled_v8086())
        return;

    auto ss_limit = vmcs::guest_ss_limit::get();

    if (ss_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, ss limit must be 0xFFFF");
}

void
vmcs_intel_x64::check_guest_ds_limit()
{
    if (!is_enabled_v8086())
        return;

    auto ds_limit = vmcs::guest_ds_limit::get();

    if (ds_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, ds limit must be 0xFFFF");
}

void
vmcs_intel_x64::check_guest_es_limit()
{
    if (!is_enabled_v8086())
        return;

    auto es_limit = vmcs::guest_es_limit::get();

    if (es_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, es limit must be 0xFFFF");
}

void
vmcs_intel_x64::check_guest_gs_limit()
{
    if (!is_enabled_v8086())
        return;

    auto gs_limit = vmcs::guest_gs_limit::get();

    if (gs_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, gs limit must be 0xFFFF");
}

void
vmcs_intel_x64::check_guest_fs_limit()
{
    if (!is_enabled_v8086())
        return;

    auto fs_limit = vmcs::guest_fs_limit::get();

    if (fs_limit != 0x000000000000FFFF)
        throw std::logic_error("if virtual 8086 mode is enabled, fs limit must be 0xFFFF");
}

void
vmcs_intel_x64::check_guest_v8086_cs_access_rights()
{
    if (!is_enabled_v8086())
        return;

    if (guest_cs_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, cs access rights must be 0x00F3");
}

void
vmcs_intel_x64::check_guest_v8086_ss_access_rights()
{
    if (!is_enabled_v8086())
        return;

    if (guest_ss_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, ss access rights must be 0x00F3");
}

void
vmcs_intel_x64::check_guest_v8086_ds_access_rights()
{
    if (!is_enabled_v8086())
        return;

    if (guest_ds_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, ds access rights must be 0x00F3");
}

void
vmcs_intel_x64::check_guest_v8086_es_access_rights()
{
    if (!is_enabled_v8086())
        return;

    if (guest_es_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, es access rights must be 0x00F3");
}

void
vmcs_intel_x64::check_guest_v8086_fs_access_rights()
{
    if (!is_enabled_v8086())
        return;

    if (guest_fs_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, fs access rights must be 0x00F3");
}

void
vmcs_intel_x64::check_guest_v8086_gs_access_rights()
{
    if (!is_enabled_v8086())
        return;

    if (guest_gs_access_rights::get() != 0x00000000000000F3)
        throw std::logic_error("if virtual 8086 mode is enabled, gs access rights must be 0x00F3");
}

void
vmcs_intel_x64::check_guest_cs_access_rights_type()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    switch (guest_cs_access_rights::type::get())
    {
        case access_rights::type::read_write_accessed:
            if (unrestricted_guest::is_disabled_if_exists())
                break;

            if (activate_secondary_controls::is_disabled())
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
vmcs_intel_x64::check_guest_ss_access_rights_type()
{
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
vmcs_intel_x64::check_guest_ds_access_rights_type()
{
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
vmcs_intel_x64::check_guest_es_access_rights_type()
{
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
vmcs_intel_x64::check_guest_fs_access_rights_type()
{
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
vmcs_intel_x64::check_guest_gs_access_rights_type()
{
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
vmcs_intel_x64::check_guest_cs_is_not_a_system_descriptor()
{
    if (guest_cs_access_rights::s::get() == 0)
        throw std::logic_error("cs must be a code/data descriptor. S should equal 1");
}

void
vmcs_intel_x64::check_guest_ss_is_not_a_system_descriptor()
{
    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if (guest_ss_access_rights::s::get() == 0)
        throw std::logic_error("ss must be a code/data descriptor. S should equal 1");
}

void
vmcs_intel_x64::check_guest_ds_is_not_a_system_descriptor()
{
    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if (guest_ds_access_rights::s::get() == 0)
        throw std::logic_error("ds must be a code/data descriptor. S should equal 1");
}

void
vmcs_intel_x64::check_guest_es_is_not_a_system_descriptor()
{
    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if (guest_es_access_rights::s::get() == 0)
        throw std::logic_error("es must be a code/data descriptor. S should equal 1");
}

void
vmcs_intel_x64::check_guest_fs_is_not_a_system_descriptor()
{
    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_fs_access_rights::s::get() == 0)
        throw std::logic_error("fs must be a code/data descriptor. S should equal 1");
}

void
vmcs_intel_x64::check_guest_gs_is_not_a_system_descriptor()
{
    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_gs_access_rights::s::get() == 0)
        throw std::logic_error("gs must be a code/data descriptor. S should equal 1");
}

void
vmcs_intel_x64::check_guest_cs_type_not_equal_3()
{
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
vmcs_intel_x64::check_guest_cs_dpl_adheres_to_ss_dpl()
{
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
vmcs_intel_x64::check_guest_ss_dpl_must_equal_rpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    auto ss_rpl = guest_ss_selector::rpl::get();
    auto ss_dpl = guest_ss_access_rights::dpl::get();

    if (ss_dpl != ss_rpl)
        throw std::logic_error("if unrestricted guest mode is disabled ss dpl must equal ss rpl");
}

void
vmcs_intel_x64::check_guest_ss_dpl_must_equal_zero()
{
    switch (guest_cs_access_rights::type::get())
    {
        case access_rights::type::read_write_accessed:
            break;

        default:
            if (guest_cr0::protection_enable::get() != 0)
                return;
    }

    if (guest_ss_access_rights::dpl::get() != 0)
        throw std::logic_error("if cs type is 3 or protected mode is disabled, ss DPL must be 0");
}

void
vmcs_intel_x64::check_guest_ds_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

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
vmcs_intel_x64::check_guest_es_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

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
vmcs_intel_x64::check_guest_fs_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

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
vmcs_intel_x64::check_guest_gs_dpl()
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    if (unrestricted_guest::is_enabled_if_exists() && activate_secondary_controls::is_enabled())
        return;

    if (guest_fs_access_rights::unusable::get() != 0)
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
vmcs_intel_x64::check_guest_cs_must_be_present()
{
    if (guest_cs_access_rights::present::get() == 0)
        throw std::logic_error("cs access rights present flag must be 1 ");
}

void
vmcs_intel_x64::check_guest_ss_must_be_present_if_usable()
{
    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if (guest_ss_access_rights::present::get() == 0)
        throw std::logic_error("ss access rights present flag must be 1 if ss is usable");
}

void
vmcs_intel_x64::check_guest_ds_must_be_present_if_usable()
{
    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if (guest_ds_access_rights::present::get() == 0)
        throw std::logic_error("ds access rights present flag must be 1 if ds is usable");
}

void
vmcs_intel_x64::check_guest_es_must_be_present_if_usable()
{
    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if (guest_es_access_rights::present::get() == 0)
        throw std::logic_error("es access rights present flag must be 1 if es is usable");
}

void
vmcs_intel_x64::check_guest_fs_must_be_present_if_usable()
{
    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_fs_access_rights::present::get() == 0)
        throw std::logic_error("fs access rights present flag must be 1 if fs is usable");
}

void
vmcs_intel_x64::check_guest_gs_must_be_present_if_usable()
{
    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_gs_access_rights::present::get() == 0)
        throw std::logic_error("gs access rights present flag must be 1 if gs is usable");
}

void
vmcs_intel_x64::check_guest_cs_access_rights_reserved_must_be_0()
{
    if (guest_cs_access_rights::reserved::get() != 0)
        throw std::logic_error("cs access rights reserved bits must be 0 ");
}

void
vmcs_intel_x64::check_guest_ss_access_rights_reserved_must_be_0()
{
    if (guest_ss_access_rights::unusable::get() != 0)
        return;

    if (guest_ss_access_rights::reserved::get() != 0)
        throw std::logic_error("ss access rights reserved bits must be 0 if ss is usable");
}

void
vmcs_intel_x64::check_guest_ds_access_rights_reserved_must_be_0()
{
    if (guest_ds_access_rights::unusable::get() != 0)
        return;

    if (guest_ds_access_rights::reserved::get() != 0)
        throw std::logic_error("ds access rights reserved bits must be 0 if ds is usable");
}

void
vmcs_intel_x64::check_guest_es_access_rights_reserved_must_be_0()
{
    if (guest_es_access_rights::unusable::get() != 0)
        return;

    if (guest_es_access_rights::reserved::get() != 0)
        throw std::logic_error("es access rights reserved bits must be 0 if es is usable");
}

void
vmcs_intel_x64::check_guest_fs_access_rights_reserved_must_be_0()
{
    if (guest_fs_access_rights::unusable::get() != 0)
        return;

    if (guest_fs_access_rights::reserved::get() != 0)
        throw std::logic_error("fs access rights reserved bits must be 0 if fs is usable");
}

void
vmcs_intel_x64::check_guest_gs_access_rights_reserved_must_be_0()
{
    if (guest_gs_access_rights::unusable::get() != 0)
        return;

    if (guest_gs_access_rights::reserved::get() != 0)
        throw std::logic_error("gs access rights reserved bits must be 0 if gs is usable");
}

void
vmcs_intel_x64::check_guest_cs_db_must_be_0_if_l_equals_1()
{
    if (vm_entry_controls::ia_32e_mode_guest::is_disabled())
        return;

    if (guest_cs_access_rights::l::get() == 0)
        return;

    if (guest_cs_access_rights::db::get() != 0)
        throw std::logic_error("d/b for guest cs must be 0 if in ia 32e mode and l == 1");
}

void
vmcs_intel_x64::check_guest_cs_granularity()
{
    auto cs_limit = vmcs::guest_cs_limit::get();
    auto g = guest_cs_access_rights::granularity::get();

    if ((cs_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest cs granularity must be 0 if any bit 11:0 is 0");

    if ((cs_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest cs granularity must be 1 if any bit 31:20 is 1");
}

void
vmcs_intel_x64::check_guest_ss_granularity()
{
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
vmcs_intel_x64::check_guest_ds_granularity()
{
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
vmcs_intel_x64::check_guest_es_granularity()
{
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
vmcs_intel_x64::check_guest_fs_granularity()
{
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
vmcs_intel_x64::check_guest_gs_granularity()
{
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
vmcs_intel_x64::check_guest_tr_type_must_be_11()
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
vmcs_intel_x64::check_guest_tr_must_be_a_system_descriptor()
{
    if (guest_tr_access_rights::s::get() != 0)
        throw std::logic_error("tr must be a system descriptor. S should equal 0");
}

void
vmcs_intel_x64::check_guest_tr_must_be_present()
{
    if (guest_tr_access_rights::present::get() == 0)
        throw std::logic_error("tr access rights present flag must be 1 ");
}

void
vmcs_intel_x64::check_guest_tr_access_rights_reserved_must_be_0()
{
    if (guest_tr_access_rights::reserved::get() != 0)
        throw std::logic_error("tr access rights bits 11:8 must be 0");
}

void
vmcs_intel_x64::check_guest_tr_granularity()
{
    auto tr_limit = vmcs::guest_tr_limit::get();
    auto g = guest_tr_access_rights::granularity::get();

    if ((tr_limit & 0x00000FFF) != 0x00000FFF && g != 0)
        throw std::logic_error("guest tr granularity must be 0 if any bit 11:0 is 0");

    if ((tr_limit & 0xFFF00000) != 0x00000000 && g == 0)
        throw std::logic_error("guest tr granularity must be 1 if any bit 31:20 is 1");
}

void
vmcs_intel_x64::check_guest_tr_must_be_usable()
{
    if (guest_tr_access_rights::unusable::get() != 0)
        throw std::logic_error("tr must be usable");
}

void
vmcs_intel_x64::check_guest_ldtr_type_must_be_2()
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
vmcs_intel_x64::check_guest_ldtr_must_be_a_system_descriptor()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_access_rights::s::get() != 0)
        throw std::logic_error("ldtr must be a system descriptor. S should equal 0");
}

void
vmcs_intel_x64::check_guest_ldtr_must_be_present()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_access_rights::present::get() == 0)
        throw std::logic_error("ldtr access rights present flag must be 1 if ldtr is usable");
}

void
vmcs_intel_x64::check_guest_ldtr_access_rights_reserved_must_be_0()
{
    if (guest_ldtr_access_rights::unusable::get() != 0)
        return;

    if (guest_ldtr_access_rights::reserved::get() != 0)
        throw std::logic_error("ldtr access rights bits 11:8 must be 0");
}

void
vmcs_intel_x64::check_guest_ldtr_granularity()
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
    auto gdtr_base = vm::read(VMCS_GUEST_GDTR_BASE);

    if (!is_address_canonical(gdtr_base))
        throw std::logic_error("gdtr base is non-canonical");
}

void
vmcs_intel_x64::check_guest_idtr_base_must_be_canonical()
{
    auto idtr_base = vm::read(VMCS_GUEST_IDTR_BASE);

    if (!is_address_canonical(idtr_base))
        throw std::logic_error("idtr base is non-canonical");
}

void
vmcs_intel_x64::check_guest_gdtr_limit_reserved_bits()
{
    auto gdtr_limit = vmcs::guest_gdtr_limit::get();

    if ((gdtr_limit & 0xFFFF0000) != 0)
        throw std::logic_error("gdtr limit bits 31:16 must be 0");
}

void
vmcs_intel_x64::check_guest_idtr_limit_reserved_bits()
{
    auto idtr_limit = vmcs::guest_idtr_limit::get();

    if ((idtr_limit & 0xFFFF0000) != 0)
        throw std::logic_error("idtr limit bits 31:16 must be 0");
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
    auto cs_l = guest_cs_access_rights::l::get();

    if (vm_entry_controls::ia_32e_mode_guest::is_enabled() && cs_l != 0)
        return;

    auto rip = vm::read(VMCS_GUEST_RIP);

    if ((rip & 0xFFFFFFFF00000000) != 0)
        throw std::logic_error("rip bits 61:32 must 0 if IA 32e mode is disabled or cs L is disabled");
}

void
vmcs_intel_x64::check_guest_rip_valid_addr()
{
    auto cs_l = guest_cs_access_rights::l::get();

    if (vm_entry_controls::ia_32e_mode_guest::is_disabled())
        return;

    if (cs_l == 0)
        return;

    auto rip = vm::read(VMCS_GUEST_RIP);

    if (!is_linear_address_valid(rip))
        throw std::logic_error("rip bits must be canonical");
}

void
vmcs_intel_x64::check_guest_rflags_reserved_bits()
{
    if (guest_rflags::reserved::get() != 0)
        throw std::logic_error("reserved bits in rflags must be 0");

    if (guest_rflags::always_enabled::get() == 0)
        throw std::logic_error("always enabled bits in rflags must be 1");
}

void
vmcs_intel_x64::check_guest_rflags_vm_bit()
{
    if (vm_entry_controls::ia_32e_mode_guest::is_disabled() && guest_cr0::protection_enable::get() == 1)
        return;

    if (guest_rflags::virtual_8086_mode::get() != 0)
        throw std::logic_error("rflags VM must be 0 if ia 32e mode is 1 or PE is 0");
}

void
vmcs_intel_x64::check_guest_rflag_interrupt_enable()
{
    using namespace vm_entry_interruption_information_field;

    if (valid_bit::is_disabled())
        return;

    if (interruption_type::get() != interruption_type::external_interrupt)
        return;

    if (guest_rflags::interrupt_enable_flag::get() == 0)
        throw std::logic_error("rflags IF must be 1 if the valid bit is 1 and interrupt type is external");
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
    check_guest_interruptibility_state_reserved();
    check_guest_interruptibility_state_sti_mov_ss();
    check_guest_interruptibility_state_sti();
    check_guest_interruptibility_state_external_interrupt();
    check_guest_interruptibility_state_nmi();
    check_guest_interruptibility_not_in_smm();
    check_guest_interruptibility_entry_to_smm();
    check_guest_interruptibility_state_sti_and_nmi();
    check_guest_interruptibility_state_virtual_nmi();
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
    if (vmcs::guest_activity_state::get() > 3)
        throw std::logic_error("activity state must be 0 - 3");
}

void
vmcs_intel_x64::check_guest_activity_state_not_hlt_when_dpl_not_0()
{
    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::hlt)
        return;

    if (guest_ss_access_rights::dpl::get() != 0)
        throw std::logic_error("ss.dpl must be 0 if activity state is HLT");
}

void
vmcs_intel_x64::check_guest_must_be_active_if_injecting_blocking_state()
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
vmcs_intel_x64::check_guest_hlt_valid_interrupts()
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
            if (vector == MTF_VM_EXIT)
                return;

            break;

        default:
            break;
    }

    throw std::logic_error("invalid interruption combination for guest hlt");
}

void
vmcs_intel_x64::check_guest_shutdown_valid_interrupts()
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
vmcs_intel_x64::check_guest_sipi_valid_interrupts()
{
    if (vm_entry_interruption_information_field::valid_bit::is_disabled())
        return;

    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::wait_for_sipi)
        return;

    throw std::logic_error("invalid interruption combination");
}

void
vmcs_intel_x64::check_guest_valid_activity_state_and_smm()
{
    if (vm_entry_controls::entry_to_smm::is_disabled())
        return;

    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::wait_for_sipi)
        return;

    throw std::logic_error("activity state must not equal wait for sipi if entry to smm is enabled");
}

void
vmcs_intel_x64::check_guest_interruptibility_state_reserved()
{
    if (vmcs::guest_interruptibility_state::reserved::get() != 0)
        throw std::logic_error("interruptibility state reserved bits 31:5 must be 0");
}

void
vmcs_intel_x64::check_guest_interruptibility_state_sti_mov_ss()
{
    auto sti = vmcs::guest_interruptibility_state::blocking_by_sti::get();
    auto mov_ss = vmcs::guest_interruptibility_state::blocking_by_mov_ss::get();

    if (sti != 0U && mov_ss != 0U)
        throw std::logic_error("interruptibility state sti and mov ss cannot both be 1");

}

void
vmcs_intel_x64::check_guest_interruptibility_state_sti()
{
    if (guest_rflags::interrupt_enable_flag::get() != 0U)
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_sti::get() != 0U)
        throw std::logic_error("interruptibility state sti must be 0 if rflags interrupt enabled is 0");
}

void
vmcs_intel_x64::check_guest_interruptibility_state_external_interrupt()
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
vmcs_intel_x64::check_guest_interruptibility_state_nmi()
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
vmcs_intel_x64::check_guest_interruptibility_not_in_smm()
{
}

void
vmcs_intel_x64::check_guest_interruptibility_entry_to_smm()
{
    if (vm_entry_controls::entry_to_smm::is_disabled())
        return;

    if (vmcs::guest_interruptibility_state::blocking_by_smi::get() == 0U)
        throw std::logic_error("interruptibility state smi must be enabled "
                               "if entry to smm is enabled");
}

void
vmcs_intel_x64::check_guest_interruptibility_state_sti_and_nmi()
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
vmcs_intel_x64::check_guest_interruptibility_state_virtual_nmi()
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
vmcs_intel_x64::check_guest_pending_debug_exceptions_reserved()
{
    auto pending_debug_exceptions =
        vm::read(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);

    if ((pending_debug_exceptions & 0xFFFFFFFFFFFF2FF0) != 0)
        throw std::logic_error("pending debug exception reserved bits must be 0");
}

void
vmcs_intel_x64::check_guest_pending_debug_exceptions_dbg_ctl()
{
    auto sti = vmcs::guest_interruptibility_state::blocking_by_sti::get();
    auto mov_ss = vmcs::guest_interruptibility_state::blocking_by_mov_ss::get();
    auto activity_state = vmcs::guest_activity_state::get();

    if (sti == 0 && mov_ss == 0 && activity_state != vmcs::guest_activity_state::hlt)
        return;

    auto pending_debug_exceptions =
        vm::read(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);

    auto bs = pending_debug_exceptions & PENDING_DEBUG_EXCEPTION_BS;

    auto tf = guest_rflags::trap_flag::get();
    auto btf = guest_ia32_debugctl::btf::get();

    if (bs == 0 && tf != 0 && btf == 0)
        throw std::logic_error("pending debug exception bs must be 1 if "
                               "rflags tf is 1 and debugctl btf is 0");

    if (bs == 1 && tf == 0 && btf == 1)
        throw std::logic_error("pending debug exception bs must be 0 if "
                               "rflags tf is 0 and debugctl btf is 1");
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_bits_11_0()
{
    auto vmcs_link_pointer = vm::read(VMCS_VMCS_LINK_POINTER);

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    if ((vmcs_link_pointer & 0x0000000000000FFF) != 0)
        throw std::logic_error("vmcs link pointer bits 11:0 must be 0");
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_valid_addr()
{
    auto vmcs_link_pointer = vm::read(VMCS_VMCS_LINK_POINTER);

    if (vmcs_link_pointer == 0xFFFFFFFFFFFFFFFF)
        return;

    if (!is_physical_address_valid(vmcs_link_pointer))
        throw std::logic_error("vmcs link pointer invalid physical address");
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_first_word()
{
    auto vmcs_link_pointer = vm::read(VMCS_VMCS_LINK_POINTER);

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
vmcs_intel_x64::check_guest_vmcs_link_pointer_not_in_smm()
{
}

void
vmcs_intel_x64::check_guest_vmcs_link_pointer_in_smm()
{
}
