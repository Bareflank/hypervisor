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

#include <test.h>
#include <vmcs/vmcs_intel_x64_check.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>

#include <intrinsics/x64.h>
#include <intrinsics/pdpte_x64.h>
#include <intrinsics/crs_intel_x64.h>

using namespace intel_x64;
using namespace msrs;
using namespace vmcs;

static struct control_flow_path path;

static void
make_usable(uint32_t access_rights)
{ g_vmcs_fields[access_rights] &= ~x64::access_rights::unusable; }

static void
make_unusable(uint32_t access_rights)
{ g_vmcs_fields[access_rights] |= x64::access_rights::unusable; }

static void
enable_v8086()
{ guest_rflags::virtual_8086_mode::enable(); }

static void
disable_v8086()
{ guest_rflags::virtual_8086_mode::disable(); }

static void
setup_check_guest_control_registers_debug_registers_and_msrs_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
        g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0ULL;
        g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
        guest_cr0::paging::disable();
        g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0ULL;
        g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
        vm_entry_controls::load_debug_controls::disable();
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_cr4::pcid_enable_bit::disable();
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        guest_cr3::set(0x1000UL);
        guest_ia32_sysenter_esp::set(0x1000UL);
        guest_ia32_sysenter_eip::set(0x1000UL);
        vm_entry_controls::load_ia32_perf_global_ctrl::disable();
        vm_entry_controls::load_ia32_pat::disable();
        vm_entry_controls::load_ia32_efer::disable();
        vm_entry_controls::load_ia32_bndcfgs::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_segment_registers_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        guest_tr_selector::ti::set(false);
        guest_ldtr_access_rights::unusable::set(1U);
        guest_rflags::virtual_8086_mode::enable();
        guest_cs_selector::set(0x1U);
        guest_cs_base::set(0x10U);
        guest_ss_selector::set(0x1U);
        guest_ss_base::set(0x10U);
        guest_ds_selector::set(0x1U);
        guest_ds_base::set(0x10U);
        guest_es_selector::set(0x1U);
        guest_es_base::set(0x10U);
        guest_fs_selector::set(0x1U);
        guest_fs_base::set(0x10U);
        guest_gs_selector::set(0x1U);
        guest_gs_base::set(0x10U);
        guest_tr_base::set(0x10U);
        guest_cs_limit::set(0xFFFFUL);
        guest_ss_limit::set(0xFFFFUL);
        guest_ds_limit::set(0xFFFFUL);
        guest_es_limit::set(0xFFFFUL);
        guest_gs_limit::set(0xFFFFUL);
        guest_fs_limit::set(0xFFFFUL);
        guest_cs_access_rights::set(0xF3UL);
        guest_ss_access_rights::set(0xF3UL);
        guest_ds_access_rights::set(0xF3UL);
        guest_es_access_rights::set(0xF3UL);
        guest_fs_access_rights::set(0xF3UL);
        guest_gs_access_rights::set(0xF3UL);
        guest_tr_access_rights::type::set(x64::access_rights::type::read_execute_accessed);
        guest_tr_access_rights::s::set(0U);
        guest_tr_access_rights::present::set(1U);
        guest_tr_access_rights::reserved::set(0U);
        guest_tr_limit::set(0x1UL);
        guest_tr_access_rights::granularity::set(0U);
        guest_tr_access_rights::unusable::set(0U);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_descriptor_table_registers_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        guest_gdtr_base::set(0x1000UL);
        guest_idtr_base::set(0x1000UL);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_rip_and_rflags_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_rip::set(0x1000U);
        guest_rflags::reserved::set(0U);
        guest_rflags::always_enabled::set(0x2U);
        guest_cr0::protection_enable::enable();
        vm_entry_interruption_information_field::valid_bit::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_non_register_state_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
        guest_activity_state::set(guest_activity_state::active);
        guest_interruptibility_state::blocking_by_sti::set(0U);
        guest_interruptibility_state::blocking_by_mov_ss::set(0U);
        vm_entry_interruption_information_field::valid_bit::disable();
        vm_entry_controls::entry_to_smm::disable();
        guest_interruptibility_state::reserved::set(0U);
        guest_interruptibility_state::enclave_interruption::set(0U);
        guest_pending_debug_exceptions::reserved::set(0U);
        guest_pending_debug_exceptions::rtm::disable();
        vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFFUL);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_pdptes_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_cr0::paging::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
setup_check_guest_state_all_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;

    setup_check_guest_control_registers_debug_registers_and_msrs_all_paths(sub_cfg);
    setup_check_guest_segment_registers_all_paths(sub_cfg);
    setup_check_guest_descriptor_table_registers_all_paths(sub_cfg);
    setup_check_guest_rip_and_rflags_all_paths(sub_cfg);
    setup_check_guest_non_register_state_all_paths(sub_cfg);
    setup_check_guest_pdptes_all_paths(sub_cfg);

    path.setup = [sub_cfg]
    {
        for (const auto &sub_path : sub_cfg)
            sub_path.setup();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cr0_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        guest_cr0::set(0UL);
        g_msrs[ia32_vmx_cr0_fixed0::addr] = 0U;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
        g_msrs[ia32_vmx_cr0_fixed0::addr] = intel_x64::cr0::paging::mask | intel_x64::cr0::protection_enable::mask;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_cr0_verify_paging_enabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_cr0::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cr0::paging::enable(); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cr0::protection_enable::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cr4_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        guest_cr4::set(0U);
        g_msrs[ia32_vmx_cr4_fixed0::addr] = 0;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_cr4_fixed0::addr] = 1; };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_load_debug_controls_verify_reserved_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::load_debug_controls::mask);
        vm_entry_controls::load_debug_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::load_debug_controls::mask);
        vm_entry_controls::load_debug_controls::enable();
        guest_ia32_debugctl::reserved::set(0xCU);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_debugctl::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_verify_ia_32e_mode_enabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
        guest_cr0::set(0UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cr0::paging::enable();
        guest_cr4::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cr4::physical_address_extensions::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_verify_ia_32e_mode_disabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_cr4::pcid_enable_bit::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cr4::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cr3_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_cr3::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cr3::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_load_debug_controls_verify_dr7_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::load_debug_controls::mask);
        vm_entry_controls::load_debug_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::load_debug_controls::mask);
        vm_entry_controls::load_debug_controls::enable();
        guest_dr7::set(0x100000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_dr7::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ia32_sysenter_esp_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_ia32_sysenter_esp::set(0x800000000000UL); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_sysenter_esp::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ia32_sysenter_eip_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_ia32_sysenter_eip::set(0x800000000000UL); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_sysenter_eip::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_verify_load_ia32_perf_global_ctrl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask);
        vm_entry_controls::load_ia32_perf_global_ctrl::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask);
        vm_entry_controls::load_ia32_perf_global_ctrl::enable();
        guest_ia32_perf_global_ctrl::reserved::set(0xCU);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_perf_global_ctrl::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_verify_load_ia32_pat_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::load_ia32_pat::mask);
        vm_entry_controls::load_ia32_pat::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::load_ia32_pat::mask);
        vm_entry_controls::load_ia32_pat::enable();
        guest_ia32_pat::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(2ULL << 8); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(2ULL << 16); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(2ULL << 24); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(2ULL << 32); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(2ULL << 40); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(2ULL << 48); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(2ULL << 56); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_pat::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_verify_load_ia32_efer_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::load_ia32_efer::mask);
        vm_entry_controls::load_ia32_efer::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::load_ia32_efer::mask);
        vm_entry_controls::load_ia32_efer::enable();
        guest_ia32_efer::reserved::set(0xEUL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_ia32_efer::reserved::set(0x0UL);
        guest_ia32_efer::lma::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
        guest_ia32_efer::lma::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_ia32_efer::lma::enable();
        guest_cr0::paging::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cr0::paging::enable(); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_ia32_efer::lma::disable();
        guest_ia32_efer::lme::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_efer::lme::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_verify_load_ia32_bndcfgs_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask);
        vm_entry_controls::load_ia32_bndcfgs::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask);
        vm_entry_controls::load_ia32_bndcfgs::enable();
        guest_ia32_bndcfgs::reserved::set(0xCUL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_bndcfgs::set(0x800000000000UL); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ia32_bndcfgs::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_ti_bit_equals_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_tr_selector::ti::set(false); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_ti_bit_equals_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ldtr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_selector::ti::set(true);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_and_cs_rpl_are_the_same_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        guest_ss_selector::set(0U);
        guest_cs_selector::rpl::set(3U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_selector::rpl::set(3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_base_is_shifted_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_cs_selector::set(0U);
        guest_cs_base::set(0x10U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_selector::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_base_is_shifted_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_ss_selector::set(0U);
        guest_ss_base::set(0x10U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_selector::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_base_is_shifted_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_ds_selector::set(0U);
        guest_ds_base::set(0x10U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_selector::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_es_base_is_shifted_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_es_selector::set(0U);
        guest_es_base::set(0x10U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_selector::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_base_is_shifted_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_fs_selector::set(0U);
        guest_fs_base::set(0x10U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_selector::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_base_is_shifted_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_gs_selector::set(0U);
        guest_gs_base::set(0x10U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_selector::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_base_is_canonical_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_tr_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_base::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_base_is_canonical_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_fs_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_base::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_base_is_canonical_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_gs_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_base::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_base_is_canonical_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ldtr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_base::set(0x800000000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_base::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_base_upper_dword_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_cs_base::set(0xf00000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_base::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_base_upper_dword_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ss_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ss_access_rights::addr);
        vmcs::guest_ss_base::set(0xf00000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_base::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_base_upper_dword_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ds_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ds_access_rights::addr);
        vmcs::guest_ds_base::set(0xf00000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_base::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_es_base_upper_dword_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_es_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_es_access_rights::addr);
        vmcs::guest_es_base::set(0xf00000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_base::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_limit_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_cs_limit::set(0x10000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_limit::set(0xffffU); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_limit_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_ss_limit::set(0x10000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_limit::set(0xffffU); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_limit_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_ds_limit::set(0x10000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_limit::set(0xffffU); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_es_limit_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_es_limit::set(0x10000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_limit::set(0xffffU); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_limit_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_gs_limit::set(0x10000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_limit::set(0xffffU); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_limit_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_fs_limit::set(0x10000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_limit::set(0xffffU); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_v8086_cs_access_rights_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_cs_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(0xf3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_v8086_ss_access_rights_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_ss_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0xf3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_v8086_ds_access_rights_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_ds_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::set(0xf3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_v8086_es_access_rights_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_es_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::set(0xf3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_v8086_fs_access_rights_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_fs_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::set(0xf3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_v8086_gs_access_rights_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_v8086();
        guest_gs_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::set(0xf3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_access_rights_type_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
        guest_cs_access_rights::set(3U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(7U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_access_rights_type_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ss_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ss_access_rights::addr);
        vmcs::guest_ss_access_rights::set(3U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_access_rights_type_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ds_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ds_access_rights::addr);
        vmcs::guest_ds_access_rights::set(15U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_es_access_rights_type_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_es_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_es_access_rights::addr);
        vmcs::guest_es_access_rights::set(15U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_access_rights_type_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_fs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_fs_access_rights::addr);
        vmcs::guest_fs_access_rights::set(15U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_access_rights_type_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_gs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_gs_access_rights::addr);
        vmcs::guest_gs_access_rights::set(15U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_is_not_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::s::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_is_not_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ss_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ss_access_rights::addr);
        guest_ss_access_rights::s::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::s::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_is_not_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ds_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ds_access_rights::addr);
        guest_ds_access_rights::s::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::s::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_es_is_not_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_es_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_es_access_rights::addr);
        guest_es_access_rights::s::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::s::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_is_not_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_fs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_fs_access_rights::addr);
        guest_fs_access_rights::s::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::s::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_is_not_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_gs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_gs_access_rights::addr);
        guest_gs_access_rights::s::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::s::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_type_not_equal_3_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_access_rights::set(1U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(0x63U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(0x03U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_dpl_adheres_to_ss_dpl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_access_rights::set(0x3bU);
        guest_ss_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0x30U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(0x6dU); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0x60U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(2U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_dpl_must_equal_rpl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        guest_ss_selector::set(0U);
        guest_ss_access_rights::set(0x60U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_dpl_must_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_access_rights::set(0U);
        vmcs::guest_cr0::protection_enable::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cs_access_rights::set(3U);
        guest_ss_access_rights::dpl::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_dpl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        make_unusable(guest_ds_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ds_access_rights::addr);
        vmcs::guest_ds_access_rights::type::set(x64::access_rights::type::read_execute_conforming);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::guest_ds_access_rights::type::set(x64::access_rights::type::tss_busy);
        guest_ds_access_rights::dpl::set(0x0U);
        guest_ds_selector::rpl::set(0x1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_selector::rpl::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_es_dpl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        make_unusable(guest_es_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_es_access_rights::addr);
        vmcs::guest_es_access_rights::type::set(x64::access_rights::type::read_execute_conforming);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::guest_es_access_rights::type::set(x64::access_rights::type::tss_busy);
        guest_es_access_rights::dpl::set(0x0U);
        guest_es_selector::rpl::set(0x1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_selector::rpl::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_dpl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        make_unusable(guest_fs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_fs_access_rights::addr);
        vmcs::guest_fs_access_rights::type::set(x64::access_rights::type::read_execute_conforming);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::guest_fs_access_rights::type::set(x64::access_rights::type::tss_busy);
        guest_fs_access_rights::dpl::set(0x0U);
        guest_fs_selector::rpl::set(0x1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_selector::rpl::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_dpl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        make_unusable(guest_gs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_gs_access_rights::addr);
        vmcs::guest_gs_access_rights::type::set(x64::access_rights::type::read_execute_conforming);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::guest_gs_access_rights::type::set(x64::access_rights::type::tss_busy);
        guest_gs_access_rights::dpl::set(0x0U);
        guest_gs_selector::rpl::set(0x1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_selector::rpl::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_must_be_present_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_access_rights::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_must_be_present_if_usable_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ss_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_must_be_present_if_usable_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ds_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}
static void
setup_check_guest_es_must_be_present_if_usable_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_es_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_must_be_present_if_usable_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_fs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}
static void
setup_check_guest_gs_must_be_present_if_usable_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_gs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_access_rights::reserved::set(0xffffffffffU);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ss_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ss_access_rights::addr);
        guest_ss_access_rights::reserved::set(0x1FFFFUL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ds_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ds_access_rights::addr);
        guest_ds_access_rights::reserved::set(0xfffffffUL);;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_es_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_es_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_es_access_rights::addr);
        guest_es_access_rights::reserved::set(0xfffffffUL);;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_fs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_fs_access_rights::addr);
        guest_fs_access_rights::reserved::set(0xfffffffUL);;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_gs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_gs_access_rights::addr);
        guest_gs_access_rights::reserved::set(0xfffffffUL);;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_db_must_be_0_if_l_equals_1_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
        guest_cs_access_rights::l::set(0U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::l::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::db::set(1U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_limit::set(0U);
        guest_cs_access_rights::granularity::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ss_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ss_access_rights::addr);
        guest_ss_limit::set(0U);
        guest_ss_access_rights::granularity::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ds_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ds_access_rights::addr);
        guest_ds_limit::set(0U);
        guest_ds_access_rights::granularity::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_es_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_es_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_es_access_rights::addr);
        guest_es_limit::set(0U);
        guest_es_access_rights::granularity::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_es_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_fs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_fs_access_rights::addr);
        guest_fs_limit::set(0U);
        guest_fs_access_rights::granularity::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_gs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_gs_access_rights::addr);
        guest_gs_limit::set(0U);
        guest_gs_access_rights::granularity::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_cs_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        guest_cs_access_rights::set(0xE0000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_cs_access_rights::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ss_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ss_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ss_access_rights::addr);
        guest_ss_access_rights::set(0xe0000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0x0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ds_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ds_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ds_access_rights::addr);
        guest_ds_access_rights::set(0xe0000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ds_access_rights::set(0x0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_es_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_es_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_es_access_rights::addr);
        guest_es_access_rights::set(0xe0000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_es_access_rights::set(0x0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_fs_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_fs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_fs_access_rights::addr);
        guest_fs_access_rights::set(0xe0000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_fs_access_rights::set(0x0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gs_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_gs_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_gs_access_rights::addr);
        guest_gs_access_rights::set(0xe0000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gs_access_rights::set(0x0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_type_must_be_11_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        guest_tr_access_rights::set(3U);
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_access_rights::set(11U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_must_be_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_tr_access_rights::s::set(1U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_access_rights::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_must_be_present_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_tr_access_rights::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_tr_access_rights::set(0xf00U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_access_rights::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_tr_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_tr_access_rights::addr);
        guest_tr_limit::set(0U);
        guest_tr_access_rights::granularity::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_must_be_usable_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_tr_access_rights::addr); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { make_usable(guest_tr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_tr_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_tr_access_rights::set(0xe0000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_tr_access_rights::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_type_must_be_2_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ldtr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_access_rights::type::set(3U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_access_rights::type::set(2U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_must_be_a_system_descriptor_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ldtr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_access_rights::s::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_access_rights::s::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_must_be_present_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ldtr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_access_rights::present::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_access_rights::present::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_access_rights_reserved_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ldtr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_access_rights::reserved::set(0x100U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_access_rights::reserved::set(0x0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_granularity_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_v8086(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_v8086();
        make_unusable(guest_ldtr_access_rights::addr);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_limit::set(0U);
        guest_ldtr_access_rights::granularity::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_access_rights::granularity::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_limit::set(0xf000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_ldtr_access_rights_remaining_reserved_bit_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { make_unusable(guest_ldtr_access_rights::addr); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        make_usable(guest_ldtr_access_rights::addr);
        guest_ldtr_access_rights::reserved::set(0xE0000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ldtr_access_rights::reserved::set(0x0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gdtr_base_must_be_canonical_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_gdtr_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gdtr_base::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_idtr_base_must_be_canonical_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_idtr_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_idtr_base::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_gdtr_limit_reserved_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_gdtr_limit::set(0xf0000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_gdtr_limit::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_idtr_limit_reserved_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_idtr_limit::set(0xf0000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_idtr_limit::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_rip_upper_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
        guest_cs_access_rights::l::set(1U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_rip::set(0xf00000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_rip::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_rip_valid_addr_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
        guest_cs_access_rights::l::set(0U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cs_access_rights::l::set(1U);
        guest_rip::set(0x800000000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_rip::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_rflags_reserved_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_rflags::reserved::set(0xffffffffU); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_rflags::set(0x0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_rflags::set(2U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_rflags_vm_bit_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_cr0::protection_enable::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cr0::protection_enable::disable();
        guest_rflags::virtual_8086_mode::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_rflags::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_rflag_interrupt_enable_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        interruption_type::set(interruption_type::non_maskable_interrupt);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::external_interrupt);
        guest_rflags::interrupt_enable_flag::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_rflags::interrupt_enable_flag::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_valid_activity_state_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_activity_state::set(4U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_activity_state::set(3U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_activity_state_not_hlt_when_dpl_not_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_activity_state::set(vmcs::guest_activity_state::shutdown); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_activity_state::set(vmcs::guest_activity_state::hlt);
        guest_ss_access_rights::dpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_ss_access_rights::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_must_be_active_if_injecting_blocking_state_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_activity_state::set(vmcs::guest_activity_state::active); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_activity_state::set(vmcs::guest_activity_state::hlt);
        guest_interruptibility_state::blocking_by_sti::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_interruptibility_state::blocking_by_sti::set(0U);
        guest_interruptibility_state::blocking_by_mov_ss::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_hlt_valid_interrupts_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        guest_activity_state::set(vmcs::guest_activity_state::active);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_activity_state::set(vmcs::guest_activity_state::hlt);
        interruption_type::set(interruption_type::external_interrupt);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::hardware_exception);
        vector::set(x64::interrupt::debug_exception);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vector::set(x64::interrupt::machine_check); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vector::set(x64::interrupt::double_fault); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::other_event);
        vector::set(x64::interrupt::divide_error);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vector::set(x64::interrupt::double_fault); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { interruption_type::set(interruption_type::software_exception); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_shutdown_valid_interrupts_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        guest_activity_state::set(vmcs::guest_activity_state::hlt);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_activity_state::set(vmcs::guest_activity_state::shutdown);
        interruption_type::set(interruption_type::non_maskable_interrupt);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::hardware_exception);
        vector::set(x64::interrupt::machine_check);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vector::set(x64::interrupt::double_fault); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { interruption_type::set(interruption_type::software_exception); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_sipi_valid_interrupts_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        guest_activity_state::set(vmcs::guest_activity_state::shutdown);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_activity_state::set(vmcs::guest_activity_state::wait_for_sipi); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_valid_activity_state_and_smm_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::entry_to_smm::mask);
        vm_entry_controls::entry_to_smm::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::entry_to_smm::mask);
        vm_entry_controls::entry_to_smm::enable();
        guest_activity_state::set(vmcs::guest_activity_state::shutdown);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { guest_activity_state::set(vmcs::guest_activity_state::wait_for_sipi); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_reserved_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_interruptibility_state::reserved::set(0xe0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_sti_mov_ss_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_interruptibility_state::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_interruptibility_state::blocking_by_sti::set(1U);
        guest_interruptibility_state::blocking_by_mov_ss::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_sti_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_rflags::interrupt_enable_flag::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_rflags::interrupt_enable_flag::disable();
        guest_interruptibility_state::blocking_by_sti::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::blocking_by_sti::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_external_interrupt_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        interruption_type::set(interruption_type::non_maskable_interrupt);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::external_interrupt);
        guest_interruptibility_state::blocking_by_sti::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_interruptibility_state::blocking_by_sti::set(0U);
        guest_interruptibility_state::blocking_by_mov_ss::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::blocking_by_mov_ss::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_nmi_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        interruption_type::set(interruption_type::hardware_exception);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::non_maskable_interrupt);
        guest_interruptibility_state::blocking_by_mov_ss::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::blocking_by_mov_ss::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_not_in_smm_paths(std::vector<struct control_flow_path> &cfg)
{
    (void) cfg;
}

static void
setup_check_guest_interruptibility_entry_to_smm_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::entry_to_smm::mask);
        vm_entry_controls::entry_to_smm::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::entry_to_smm::mask);
        vm_entry_controls::entry_to_smm::enable();
        guest_interruptibility_state::blocking_by_smi::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::blocking_by_smi::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_sti_and_nmi_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        interruption_type::set(interruption_type::hardware_exception);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::non_maskable_interrupt);
        guest_interruptibility_state::blocking_by_sti::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::blocking_by_sti::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_virtual_nmi_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information_field;

    path.setup = [&]
    {
        pin_ctl_allow0(ia32_vmx_true_pinbased_ctls::virtual_nmis::mask);
        pin_based_vm_execution_controls::virtual_nmis::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::virtual_nmis::mask);
        pin_based_vm_execution_controls::virtual_nmis::enable();
        valid_bit::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        interruption_type::set(interruption_type::hardware_exception);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::non_maskable_interrupt);
        guest_interruptibility_state::blocking_by_nmi::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::blocking_by_nmi::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_interruptibility_state_enclave_interrupt_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_interruptibility_state::enclave_interruption::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_interruptibility_state::enclave_interruption::set(1U);
        guest_interruptibility_state::blocking_by_mov_ss::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_interruptibility_state::blocking_by_mov_ss::set(0U);
        g_cpuid_regs.ebx = 0U;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { g_cpuid_regs.ebx = x64::cpuid::extended_feature_flags::subleaf0::ebx::sgx::mask; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_pending_debug_exceptions_reserved_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_pending_debug_exceptions::set(0xf0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_pending_debug_exceptions::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_pending_debug_exceptions_dbg_ctl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        guest_interruptibility_state::set(0U);
        guest_activity_state::set(0U);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_interruptibility_state::blocking_by_sti::set(1U);
        guest_pending_debug_exceptions::bs::disable();
        guest_rflags::trap_flag::enable();
        guest_ia32_debugctl::btf::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_pending_debug_exceptions::bs::enable();
        guest_rflags::trap_flag::disable();
        guest_ia32_debugctl::btf::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_pending_debug_exceptions::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_pending_debug_exceptions_rtm_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_pending_debug_exceptions::rtm::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_pending_debug_exceptions::rtm::enable();
        guest_pending_debug_exceptions::reserved::set(0xF0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_pending_debug_exceptions::reserved::set(0x00U);
        guest_pending_debug_exceptions::b0::disable();
        guest_pending_debug_exceptions::b1::disable();
        guest_pending_debug_exceptions::b2::disable();
        guest_pending_debug_exceptions::b3::disable();
        guest_pending_debug_exceptions::enabled_breakpoint::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_pending_debug_exceptions::enabled_breakpoint::enable();
        g_cpuid_regs.ebx = 0U;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_cpuid_regs.ebx = x64::cpuid::extended_feature_flags::subleaf0::ebx::rtm::mask;
        guest_interruptibility_state::blocking_by_mov_ss::set(1U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_interruptibility_state::blocking_by_mov_ss::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_vmcs_link_pointer_bits_11_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vmcs_link_pointer::set(0xffffffffffffffffU); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs_link_pointer::set(0xfU); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { vmcs_link_pointer::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_vmcs_link_pointer_valid_addr_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vmcs_link_pointer::set(0xffffffffffffffffU); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs_link_pointer::set(0xf000000000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { vmcs_link_pointer::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_vmcs_link_pointer_first_word_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vmcs_link_pointer::set(0xffffffffffffffffU); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs_link_pointer::set(0x10U);
        g_phys_to_virt_return_nullptr = true;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_phys_to_virt_return_nullptr = false;
        g_test_addr = g_vmcs_link_addr;
        g_msrs[ia32_vmx_basic::addr] = 1U;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[ia32_vmx_basic::addr] = 0U;
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::vmcs_shadowing::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
        secondary_processor_based_vm_execution_controls::vmcs_shadowing::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_link_mem[0] = 0x80000000U; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_valid_pdpte_with_ept_disabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_cr0::paging::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cr0::paging::enable();
        guest_cr4::physical_address_extensions::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cr4::physical_address_extensions::enable();
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::enable_ept::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::enable_ept::disable();
        g_phys_to_virt_return_nullptr = true;
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_phys_to_virt_return_nullptr = false;
        g_test_addr = g_pdpt_addr;
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        g_pdpt_mem[0] = x64::pdpte::reserved::mask();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_pdpt_mem[0] = 0x0U;
        g_pdpt_mem[1] = x64::pdpte::reserved::mask();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_pdpt_mem[1] = 0x0U;
        g_pdpt_mem[2] = x64::pdpte::reserved::mask();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_pdpt_mem[2] = 0x0U;
        g_pdpt_mem[3] = x64::pdpte::reserved::mask();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { g_pdpt_mem[3] = 0x0U; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_guest_valid_pdpte_with_ept_enabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { guest_cr0::paging::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cr0::paging::enable();
        guest_cr4::physical_address_extensions::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_cr4::physical_address_extensions::enable();
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_ept::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::enable_ept::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::enable_ept::enable();
        guest_pdpte0::set(x64::pdpte::reserved::mask());
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_pdpte0::reserved::set(0U);
        guest_pdpte1::set(x64::pdpte::reserved::mask());
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_pdpte1::reserved::set(0U);
        guest_pdpte2::reserved::set(x64::pdpte::reserved::mask());
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        guest_pdpte2::reserved::set(0U);
        guest_pdpte3::reserved::set(x64::pdpte::reserved::mask());
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { guest_pdpte3::reserved::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
vmcs_ut::test_check_guest_state_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_state_all_paths(cfg);

    test_vmcs_check(cfg, check::guest_state_all);
}

void
vmcs_ut::test_check_guest_control_registers_debug_registers_and_msrs_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_control_registers_debug_registers_and_msrs_all_paths(cfg);

    test_vmcs_check(cfg, check::guest_control_registers_debug_registers_and_msrs_all);
}

void
vmcs_ut::test_check_guest_segment_registers_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_segment_registers_all_paths(cfg);

    test_vmcs_check(cfg, check::guest_segment_registers_all);
}

void
vmcs_ut::test_check_guest_descriptor_table_registers_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_descriptor_table_registers_all_paths(cfg);

    test_vmcs_check(cfg, check::guest_descriptor_table_registers_all);
}

void
vmcs_ut::test_check_guest_rip_and_rflags_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_rip_and_rflags_all_paths(cfg);

    test_vmcs_check(cfg, check::guest_rip_and_rflags_all);
}

void
vmcs_ut::test_check_guest_non_register_state_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_non_register_state_all_paths(cfg);

    test_vmcs_check(cfg, check::guest_non_register_state_all);
}

void
vmcs_ut::test_check_guest_pdptes_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_pdptes_all_paths(cfg);

    test_vmcs_check(cfg, check::guest_pdptes_all);
}

void
vmcs_ut::test_check_guest_cr0_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cr0_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, check::guest_cr0_for_unsupported_bits);
}

void
vmcs_ut::test_check_guest_cr0_verify_paging_enabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cr0_verify_paging_enabled_paths(cfg);

    test_vmcs_check(cfg, check::guest_cr0_verify_paging_enabled);
}

void
vmcs_ut::test_check_guest_cr4_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cr4_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, check::guest_cr4_for_unsupported_bits);
}

void
vmcs_ut::test_check_guest_load_debug_controls_verify_reserved()
{

    std::vector<struct control_flow_path> cfg;
    setup_check_guest_load_debug_controls_verify_reserved_paths(cfg);

    test_vmcs_check(cfg, check::guest_load_debug_controls_verify_reserved);
}

void
vmcs_ut::test_check_guest_verify_ia_32e_mode_enabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_verify_ia_32e_mode_enabled_paths(cfg);

    test_vmcs_check(cfg, check::guest_verify_ia_32e_mode_enabled);
}

void
vmcs_ut::test_check_guest_verify_ia_32e_mode_disabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_verify_ia_32e_mode_disabled_paths(cfg);

    test_vmcs_check(cfg, check::guest_verify_ia_32e_mode_disabled);
}

void
vmcs_ut::test_check_guest_cr3_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cr3_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, check::guest_cr3_for_unsupported_bits);
}

void
vmcs_ut::test_check_guest_load_debug_controls_verify_dr7()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_load_debug_controls_verify_dr7_paths(cfg);

    test_vmcs_check(cfg, check::guest_load_debug_controls_verify_dr7);
}

void
vmcs_ut::test_check_guest_ia32_sysenter_esp_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ia32_sysenter_esp_canonical_address_paths(cfg);

    test_vmcs_check(cfg, check::guest_ia32_sysenter_esp_canonical_address);
}

void
vmcs_ut::test_check_guest_ia32_sysenter_eip_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ia32_sysenter_eip_canonical_address_paths(cfg);

    test_vmcs_check(cfg, check::guest_ia32_sysenter_eip_canonical_address);
}

void
vmcs_ut::test_check_guest_verify_load_ia32_perf_global_ctrl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_verify_load_ia32_perf_global_ctrl_paths(cfg);

    test_vmcs_check(cfg, check::guest_verify_load_ia32_perf_global_ctrl);
}

void
vmcs_ut::test_check_guest_verify_load_ia32_pat()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_verify_load_ia32_pat_paths(cfg);

    test_vmcs_check(cfg, check::guest_verify_load_ia32_pat);
}

void
vmcs_ut::test_check_guest_verify_load_ia32_efer()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_verify_load_ia32_efer_paths(cfg);

    test_vmcs_check(cfg, check::guest_verify_load_ia32_efer);
}

void
vmcs_ut::test_check_guest_verify_load_ia32_bndcfgs()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_verify_load_ia32_bndcfgs_paths(cfg);

    test_vmcs_check(cfg, check::guest_verify_load_ia32_bndcfgs);
}

void
vmcs_ut::test_check_guest_tr_ti_bit_equals_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_ti_bit_equals_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_ti_bit_equals_0);
}

void
vmcs_ut::test_check_guest_ldtr_ti_bit_equals_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_ti_bit_equals_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_ti_bit_equals_0);
}

void
vmcs_ut::test_check_guest_ss_and_cs_rpl_are_the_same()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_and_cs_rpl_are_the_same_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_and_cs_rpl_are_the_same);
}

void
vmcs_ut::test_check_guest_cs_base_is_shifted()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_base_is_shifted_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_base_is_shifted);
}

void
vmcs_ut::test_check_guest_ss_base_is_shifted()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_base_is_shifted_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_base_is_shifted);
}

void
vmcs_ut::test_check_guest_ds_base_is_shifted()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_base_is_shifted_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_base_is_shifted);
}

void
vmcs_ut::test_check_guest_es_base_is_shifted()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_base_is_shifted_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_base_is_shifted);
}

void
vmcs_ut::test_check_guest_fs_base_is_shifted()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_base_is_shifted_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_base_is_shifted);
}

void
vmcs_ut::test_check_guest_gs_base_is_shifted()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_base_is_shifted_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_base_is_shifted);
}

void
vmcs_ut::test_check_guest_tr_base_is_canonical()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_base_is_canonical_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_base_is_canonical);
}

void
vmcs_ut::test_check_guest_fs_base_is_canonical()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_base_is_canonical_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_base_is_canonical);
}

void
vmcs_ut::test_check_guest_gs_base_is_canonical()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_base_is_canonical_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_base_is_canonical);
}

void
vmcs_ut::test_check_guest_ldtr_base_is_canonical()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_base_is_canonical_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_base_is_canonical);
}

void
vmcs_ut::test_check_guest_cs_base_upper_dword_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_base_upper_dword_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_base_upper_dword_0);
}

void
vmcs_ut::test_check_guest_ss_base_upper_dword_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_base_upper_dword_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_base_upper_dword_0);
}

void
vmcs_ut::test_check_guest_ds_base_upper_dword_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_base_upper_dword_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_base_upper_dword_0);
}

void
vmcs_ut::test_check_guest_es_base_upper_dword_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_base_upper_dword_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_base_upper_dword_0);
}

void
vmcs_ut::test_check_guest_cs_limit()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_limit_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_limit);
}

void
vmcs_ut::test_check_guest_ss_limit()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_limit_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_limit);
}

void
vmcs_ut::test_check_guest_ds_limit()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_limit_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_limit);
}

void
vmcs_ut::test_check_guest_es_limit()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_limit_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_limit);
}

void
vmcs_ut::test_check_guest_gs_limit()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_limit_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_limit);
}

void
vmcs_ut::test_check_guest_fs_limit()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_limit_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_limit);
}

void
vmcs_ut::test_check_guest_v8086_cs_access_rights()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_v8086_cs_access_rights_paths(cfg);

    test_vmcs_check(cfg, check::guest_v8086_cs_access_rights);
}

void
vmcs_ut::test_check_guest_v8086_ss_access_rights()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_v8086_ss_access_rights_paths(cfg);

    test_vmcs_check(cfg, check::guest_v8086_ss_access_rights);
}

void
vmcs_ut::test_check_guest_v8086_ds_access_rights()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_v8086_ds_access_rights_paths(cfg);

    test_vmcs_check(cfg, check::guest_v8086_ds_access_rights);
}

void
vmcs_ut::test_check_guest_v8086_es_access_rights()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_v8086_es_access_rights_paths(cfg);

    test_vmcs_check(cfg, check::guest_v8086_es_access_rights);
}

void
vmcs_ut::test_check_guest_v8086_fs_access_rights()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_v8086_fs_access_rights_paths(cfg);

    test_vmcs_check(cfg, check::guest_v8086_fs_access_rights);
}

void
vmcs_ut::test_check_guest_v8086_gs_access_rights()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_v8086_gs_access_rights_paths(cfg);

    test_vmcs_check(cfg, check::guest_v8086_gs_access_rights);
}


void
vmcs_ut::test_check_guest_cs_access_rights_type()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_access_rights_type_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_access_rights_type);
}

void
vmcs_ut::test_check_guest_ss_access_rights_type()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_access_rights_type_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_access_rights_type);
}

void
vmcs_ut::test_check_guest_ds_access_rights_type()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_access_rights_type_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_access_rights_type);
}

void
vmcs_ut::test_check_guest_es_access_rights_type()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_access_rights_type_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_access_rights_type);
}

void
vmcs_ut::test_check_guest_fs_access_rights_type()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_access_rights_type_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_access_rights_type);
}

void
vmcs_ut::test_check_guest_gs_access_rights_type()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_access_rights_type_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_access_rights_type);
}

void
vmcs_ut::test_check_guest_cs_is_not_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_is_not_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_is_not_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_ss_is_not_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_is_not_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_is_not_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_ds_is_not_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_is_not_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_is_not_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_es_is_not_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_is_not_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_is_not_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_fs_is_not_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_is_not_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_is_not_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_gs_is_not_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_is_not_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_is_not_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_cs_type_not_equal_3()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_type_not_equal_3_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_type_not_equal_3);
}

void
vmcs_ut::test_check_guest_cs_dpl_adheres_to_ss_dpl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_dpl_adheres_to_ss_dpl_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_dpl_adheres_to_ss_dpl);
}

void
vmcs_ut::test_check_guest_ss_dpl_must_equal_rpl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_dpl_must_equal_rpl_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_dpl_must_equal_rpl);
}

void
vmcs_ut::test_check_guest_ss_dpl_must_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_dpl_must_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_dpl_must_equal_zero);
}

void
vmcs_ut::test_check_guest_ds_dpl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_dpl_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_dpl);
}

void
vmcs_ut::test_check_guest_es_dpl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_dpl_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_dpl);
}

void
vmcs_ut::test_check_guest_fs_dpl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_dpl_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_dpl);
}

void
vmcs_ut::test_check_guest_gs_dpl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_dpl_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_dpl);
}

void
vmcs_ut::test_check_guest_cs_must_be_present()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_must_be_present_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_must_be_present);
}

void
vmcs_ut::test_check_guest_ss_must_be_present_if_usable()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_must_be_present_if_usable_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_must_be_present_if_usable);
}

void
vmcs_ut::test_check_guest_ds_must_be_present_if_usable()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_must_be_present_if_usable_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_must_be_present_if_usable);
}

void
vmcs_ut::test_check_guest_es_must_be_present_if_usable()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_must_be_present_if_usable_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_must_be_present_if_usable);
}

void
vmcs_ut::test_check_guest_fs_must_be_present_if_usable()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_must_be_present_if_usable_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_must_be_present_if_usable);
}

void
vmcs_ut::test_check_guest_gs_must_be_present_if_usable()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_must_be_present_if_usable_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_must_be_present_if_usable);
}

void
vmcs_ut::test_check_guest_cs_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_ss_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_ds_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_es_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_fs_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_gs_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_cs_db_must_be_0_if_l_equals_1()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_db_must_be_0_if_l_equals_1_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_db_must_be_0_if_l_equals_1);
}

void
vmcs_ut::test_check_guest_cs_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_granularity);
}

void
vmcs_ut::test_check_guest_ss_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_granularity);
}

void
vmcs_ut::test_check_guest_ds_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_granularity);
}

void
vmcs_ut::test_check_guest_es_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_granularity);
}

void
vmcs_ut::test_check_guest_fs_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_granularity);
}

void
vmcs_ut::test_check_guest_gs_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_granularity);
}

void
vmcs_ut::test_check_guest_cs_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_cs_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_cs_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_ss_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ss_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ss_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_ds_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ds_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ds_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_es_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_es_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_es_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_fs_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_fs_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_fs_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_gs_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gs_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_gs_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_tr_type_must_be_11()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_type_must_be_11_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_type_must_be_11);
}

void
vmcs_ut::test_check_guest_tr_must_be_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_must_be_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_must_be_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_tr_must_be_present()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_must_be_present_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_must_be_present);
}

void
vmcs_ut::test_check_guest_tr_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_tr_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_granularity);
}

void
vmcs_ut::test_check_guest_tr_must_be_usable()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_must_be_usable_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_must_be_usable);
}

void
vmcs_ut::test_check_guest_tr_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_tr_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_tr_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_ldtr_type_must_be_2()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_type_must_be_2_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_type_must_be_2);
}

void
vmcs_ut::test_check_guest_ldtr_must_be_a_system_descriptor()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_must_be_a_system_descriptor_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_must_be_a_system_descriptor);
}

void
vmcs_ut::test_check_guest_ldtr_must_be_present()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_must_be_present_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_must_be_present);
}

void
vmcs_ut::test_check_guest_ldtr_access_rights_reserved_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_access_rights_reserved_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_access_rights_reserved_must_be_0);
}

void
vmcs_ut::test_check_guest_ldtr_granularity()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_granularity_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_granularity);
}

void
vmcs_ut::test_check_guest_ldtr_access_rights_remaining_reserved_bit_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_ldtr_access_rights_remaining_reserved_bit_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_ldtr_access_rights_remaining_reserved_bit_0);
}

void
vmcs_ut::test_check_guest_gdtr_base_must_be_canonical()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gdtr_base_must_be_canonical_paths(cfg);

    test_vmcs_check(cfg, check::guest_gdtr_base_must_be_canonical);
}

void
vmcs_ut::test_check_guest_idtr_base_must_be_canonical()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_idtr_base_must_be_canonical_paths(cfg);

    test_vmcs_check(cfg, check::guest_idtr_base_must_be_canonical);
}

void
vmcs_ut::test_check_guest_gdtr_limit_reserved_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_gdtr_limit_reserved_bits_paths(cfg);

    test_vmcs_check(cfg, check::guest_gdtr_limit_reserved_bits);
}

void
vmcs_ut::test_check_guest_idtr_limit_reserved_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_idtr_limit_reserved_bits_paths(cfg);

    test_vmcs_check(cfg, check::guest_idtr_limit_reserved_bits);
}

void
vmcs_ut::test_check_guest_rip_upper_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_rip_upper_bits_paths(cfg);

    test_vmcs_check(cfg, check::guest_rip_upper_bits);
}

void
vmcs_ut::test_check_guest_rip_valid_addr()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_rip_valid_addr_paths(cfg);

    test_vmcs_check(cfg, check::guest_rip_valid_addr);
}

void
vmcs_ut::test_check_guest_rflags_reserved_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_rflags_reserved_bits_paths(cfg);

    test_vmcs_check(cfg, check::guest_rflags_reserved_bits);
}

void
vmcs_ut::test_check_guest_rflags_vm_bit()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_rflags_vm_bit_paths(cfg);

    test_vmcs_check(cfg, check::guest_rflags_vm_bit);
}

void
vmcs_ut::test_check_guest_rflag_interrupt_enable()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_rflag_interrupt_enable_paths(cfg);

    test_vmcs_check(cfg, check::guest_rflag_interrupt_enable);
}

void
vmcs_ut::test_check_guest_valid_activity_state()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_valid_activity_state_paths(cfg);

    test_vmcs_check(cfg, check::guest_valid_activity_state);
}

void
vmcs_ut::test_check_guest_activity_state_not_hlt_when_dpl_not_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_activity_state_not_hlt_when_dpl_not_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_activity_state_not_hlt_when_dpl_not_0);
}

void
vmcs_ut::test_check_guest_must_be_active_if_injecting_blocking_state()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_must_be_active_if_injecting_blocking_state_paths(cfg);

    test_vmcs_check(cfg, check::guest_must_be_active_if_injecting_blocking_state);
}

void
vmcs_ut::test_check_guest_hlt_valid_interrupts()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_hlt_valid_interrupts_paths(cfg);

    test_vmcs_check(cfg, check::guest_hlt_valid_interrupts);
}

void
vmcs_ut::test_check_guest_shutdown_valid_interrupts()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_shutdown_valid_interrupts_paths(cfg);

    test_vmcs_check(cfg, check::guest_shutdown_valid_interrupts);
}

void
vmcs_ut::test_check_guest_sipi_valid_interrupts()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_sipi_valid_interrupts_paths(cfg);

    test_vmcs_check(cfg, check::guest_sipi_valid_interrupts);
}

void
vmcs_ut::test_check_guest_valid_activity_state_and_smm()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_valid_activity_state_and_smm_paths(cfg);

    test_vmcs_check(cfg, check::guest_valid_activity_state_and_smm);
}

void
vmcs_ut::test_check_guest_interruptibility_state_reserved()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_reserved_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_reserved);
}

void
vmcs_ut::test_check_guest_interruptibility_state_sti_mov_ss()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_sti_mov_ss_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_sti_mov_ss);
}

void
vmcs_ut::test_check_guest_interruptibility_state_sti()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_sti_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_sti);
}

void
vmcs_ut::test_check_guest_interruptibility_state_external_interrupt()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_external_interrupt_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_external_interrupt);
}

void
vmcs_ut::test_check_guest_interruptibility_state_nmi()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_nmi_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_nmi);
}

void
vmcs_ut::test_check_guest_interruptibility_not_in_smm()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_not_in_smm_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_not_in_smm);
}

void
vmcs_ut::test_check_guest_interruptibility_entry_to_smm()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_entry_to_smm_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_entry_to_smm);
}

void
vmcs_ut::test_check_guest_interruptibility_state_sti_and_nmi()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_sti_and_nmi_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_sti_and_nmi);
}

void
vmcs_ut::test_check_guest_interruptibility_state_virtual_nmi()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_virtual_nmi_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_virtual_nmi);
}

void
vmcs_ut::test_check_guest_interruptibility_state_enclave_interrupt()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_interruptibility_state_enclave_interrupt_paths(cfg);

    test_vmcs_check(cfg, check::guest_interruptibility_state_enclave_interrupt);
}

void
vmcs_ut::test_check_guest_pending_debug_exceptions_reserved()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_pending_debug_exceptions_reserved_paths(cfg);

    test_vmcs_check(cfg, check::guest_pending_debug_exceptions_reserved);
}

void
vmcs_ut::test_check_guest_pending_debug_exceptions_dbg_ctl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_pending_debug_exceptions_dbg_ctl_paths(cfg);

    test_vmcs_check(cfg, check::guest_pending_debug_exceptions_dbg_ctl);
}

void
vmcs_ut::test_check_guest_pending_debug_exceptions_rtm()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_pending_debug_exceptions_rtm_paths(cfg);

    test_vmcs_check(cfg, check::guest_pending_debug_exceptions_rtm);
}

void
vmcs_ut::test_check_guest_vmcs_link_pointer_bits_11_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_vmcs_link_pointer_bits_11_0_paths(cfg);

    test_vmcs_check(cfg, check::guest_vmcs_link_pointer_bits_11_0);
}

void
vmcs_ut::test_check_guest_vmcs_link_pointer_valid_addr()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_vmcs_link_pointer_valid_addr_paths(cfg);

    test_vmcs_check(cfg, check::guest_vmcs_link_pointer_valid_addr);
}

void
vmcs_ut::test_check_guest_vmcs_link_pointer_first_word()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_vmcs_link_pointer_first_word_paths(cfg);

    test_vmcs_check(cfg, check::guest_vmcs_link_pointer_first_word);
}

void
vmcs_ut::test_check_guest_valid_pdpte_with_ept_disabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_valid_pdpte_with_ept_disabled_paths(cfg);

    test_vmcs_check(cfg, check::guest_valid_pdpte_with_ept_disabled);
}

void
vmcs_ut::test_check_guest_valid_pdpte_with_ept_enabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_guest_valid_pdpte_with_ept_enabled_paths(cfg);

    test_vmcs_check(cfg, check::guest_valid_pdpte_with_ept_enabled);
}
