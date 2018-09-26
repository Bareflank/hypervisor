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

#include "test_support.h"

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

static void
setup_check_host_cr0_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        host_cr0::set(0U);
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0;
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0;
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_cr0::set(0xFFFFFFFFFFFFFFFFULL);
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0x00000000FFFFFFFFULL;
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFF00000000ULL;
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_cr4_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        host_cr4::set(0U);
        g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0;
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 1; };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_cr3_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        host_cr3::set(0xff00000000000000UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        host_cr3::set(0x1000UL);
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void
setup_check_host_ia32_sysenter_esp_canonical_address_paths(std::vector<struct control_flow_path>
        &cfg)
{
    g_path.setup = [&] { host_ia32_sysenter_esp::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ia32_sysenter_esp::set(0x800000000000U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_ia32_sysenter_eip_canonical_address_paths(std::vector<struct control_flow_path>
        &cfg)
{
    g_path.setup = [&] { host_ia32_sysenter_eip::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ia32_sysenter_eip::set(0x800000000000U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_verify_load_ia32_perf_global_ctrl_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask);
        vm_exit_controls::load_ia32_perf_global_ctrl::disable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask);
        vm_exit_controls::load_ia32_perf_global_ctrl::enable();
        host_ia32_perf_global_ctrl::set(0xcU);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ia32_perf_global_ctrl::set(0x0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void
setup_check_host_verify_load_ia32_pat_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask);
        vm_exit_controls::load_ia32_pat::disable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask);
        vm_exit_controls::load_ia32_pat::enable();
        host_ia32_pat::pa0::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_pat::pa0::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa1::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_pat::pa1::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa2::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_pat::pa2::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa3::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_pat::pa3::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa4::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_pat::pa4::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa5::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_pat::pa5::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa6::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_pat::pa6::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa7::memory_type::set(2ULL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ia32_pat::pa7::set(x64::memory_type::uncacheable); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void
setup_check_host_verify_load_ia32_efer_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask);
        vm_exit_controls::load_ia32_efer::disable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask);
        vm_exit_controls::load_ia32_efer::enable();
        host_ia32_efer::reserved::set(0xEUL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
        host_ia32_efer::reserved::set(0x0UL);
        host_ia32_efer::lma::enable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
        host_ia32_efer::lma::disable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ia32_efer::lma::enable();
        host_cr0::paging::disable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_cr0::paging::enable();
        host_ia32_efer::lma::enable();
        host_ia32_efer::lme::disable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
        host_ia32_efer::lme::enable();
        host_ia32_efer::lma::disable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ia32_efer::lme::disable(); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void setup_check_host_es_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_es_selector::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_es_selector::ti::set(true); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_es_selector::ti::set(false);
        host_es_selector::rpl::set(1UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_cs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_cs_selector::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_cs_selector::ti::set(true); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_cs_selector::ti::set(false);
        host_cs_selector::rpl::set(1UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_ss_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_ss_selector::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ss_selector::ti::set(true); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ss_selector::ti::set(false);
        host_ss_selector::rpl::set(1UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_ds_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_ds_selector::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ds_selector::ti::set(true); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_ds_selector::ti::set(false);
        host_ds_selector::rpl::set(1UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_fs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_fs_selector::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_fs_selector::ti::set(true); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_fs_selector::ti::set(false);
        host_fs_selector::rpl::set(1UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_gs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_gs_selector::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_gs_selector::ti::set(true); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_gs_selector::ti::set(false);
        host_gs_selector::rpl::set(1UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_tr_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_tr_selector::set(0U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_tr_selector::ti::set(true); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_tr_selector::ti::set(false);
        host_tr_selector::rpl::set(1UL);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_cs_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_cs_selector::set(1UL); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_cs_selector::set(0U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_tr_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_tr_selector::set(1UL); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_tr_selector::set(0U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_ss_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
        host_ss_selector::set(0U);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_ss_selector::set(1U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void
setup_check_host_fs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_fs_base::set(1U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_fs_base::set(0x800000000000U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_gs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_gs_base::set(1U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_gs_base::set(0x800000000000U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_gdtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_gdtr_base::set(1U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_gdtr_base::set(0x800000000000U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_idtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_idtr_base::set(1U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_idtr_base::set(0x800000000000U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_tr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { host_tr_base::set(1U); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_tr_base::set(0x800000000000U); };
    g_path.throws_exception = true;
    cfg.push_back(g_path);
}

static void
setup_check_host_if_outside_ia32e_mode_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] { g_msrs[intel_x64::msrs::ia32_efer::addr] = intel_x64::msrs::ia32_efer::lma::mask; };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_efer::addr] = 0;
        entry_ctl_allow1(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        vm_entry_controls::ia_32e_mode_guest::disable();
        vm_exit_controls::host_address_space_size::enable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void
setup_check_host_address_space_size_exit_ctl_is_set_paths(std::vector<struct control_flow_path>
        &cfg)
{
    g_path.setup = [&] { g_msrs[intel_x64::msrs::ia32_efer::addr] = 0; };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_efer::addr] = intel_x64::msrs::ia32_efer::lma::mask;
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void
setup_check_host_address_space_disabled_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        entry_ctl_allow1(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_exit_controls::host_address_space_size::disable();
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        entry_ctl_allow0(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        host_cr4::pcid_enable_bit::enable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_cr4::set(0U);
        host_rip::set(0xf000000000U);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_rip::set(static_cast<uint64_t>(0)); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

static void
setup_check_host_address_space_enabled_paths(std::vector<struct control_flow_path> &cfg)
{
    g_path.setup = [&] {
        exit_ctl_allow0(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
    };
    g_path.throws_exception = false;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
        host_cr4::physical_address_extensions::disable();
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] {
        host_cr4::physical_address_extensions::enable();
        host_rip::set(0x800000000000U);
    };
    g_path.throws_exception = true;
    cfg.push_back(g_path);

    g_path.setup = [&] { host_rip::set(static_cast<uint64_t>(0)); };
    g_path.throws_exception = false;
    cfg.push_back(g_path);
}

TEST_CASE("check_host_cr0_for_unsupported_bits")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr0_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_cr0_for_unsupported_bits);
}

TEST_CASE("check_host_cr4_for_unsupported_bits")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr4_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_cr4_for_unsupported_bits);
}

TEST_CASE("check_host_cr3_for_unsupported_bits")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr3_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_cr3_for_unsupported_bits);
}

TEST_CASE("check_host_ia32_sysenter_esp_canonical_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_esp_canonical_address_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_ia32_sysenter_esp_canonical_address);
}

TEST_CASE("check_host_ia32_sysenter_eip_canonical_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_eip_canonical_address_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_ia32_sysenter_eip_canonical_address);
}

TEST_CASE("check_host_verify_load_ia32_perf_global_ctrl")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_perf_global_ctrl_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_verify_load_ia32_perf_global_ctrl);
}

TEST_CASE("check_host_verify_load_ia32_pat")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_pat_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_verify_load_ia32_pat);
}

TEST_CASE("check_host_verify_load_ia32_efer")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_efer_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_verify_load_ia32_efer);
}

TEST_CASE("check_host_es_selector_rpl_ti_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_es_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_es_selector_rpl_ti_equal_zero);
}

TEST_CASE("check_host_cs_selector_rpl_ti_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_cs_selector_rpl_ti_equal_zero);
}

TEST_CASE("check_host_ss_selector_rpl_ti_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_ss_selector_rpl_ti_equal_zero);
}

TEST_CASE("check_host_ds_selector_rpl_ti_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ds_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_ds_selector_rpl_ti_equal_zero);
}

TEST_CASE("check_host_fs_selector_rpl_ti_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_fs_selector_rpl_ti_equal_zero);
}

TEST_CASE("check_host_gs_selector_rpl_ti_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_gs_selector_rpl_ti_equal_zero);
}

TEST_CASE("check_host_tr_selector_rpl_ti_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_tr_selector_rpl_ti_equal_zero);
}

TEST_CASE("check_host_cs_not_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_not_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_cs_not_equal_zero);
}

TEST_CASE("check_host_tr_not_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_not_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_tr_not_equal_zero);
}

TEST_CASE("check_host_ss_not_equal_zero")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_not_equal_zero_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_ss_not_equal_zero);
}

TEST_CASE("check_host_fs_canonical_base_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_fs_canonical_base_address);
}

TEST_CASE("check_host_gs_canonical_base_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_gs_canonical_base_address);
}

TEST_CASE("check_host_gdtr_canonical_base_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gdtr_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_gdtr_canonical_base_address);
}

TEST_CASE("check_host_idtr_canonical_base_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_idtr_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_idtr_canonical_base_address);
}

TEST_CASE("check_host_tr_canonical_base_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_tr_canonical_base_address);
}

TEST_CASE("check_host_if_outside_ia32e_mode")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_if_outside_ia32e_mode_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_if_outside_ia32e_mode);
}

TEST_CASE("check_host_address_space_size_exit_ctl_is_set")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_address_space_size_exit_ctl_is_set_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_address_space_size_exit_ctl_is_set);
}

TEST_CASE("check_host_address_space_disabled")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_address_space_disabled_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_address_space_disabled);
}

TEST_CASE("check_host_address_space_enabled")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_address_space_enabled_paths(cfg);

    test_vmcs_check(cfg, bfvmm::intel_x64::check::host_address_space_enabled);
}

#endif
