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
#include <string>

#include <vmcs/vmcs_intel_x64_check.h>
#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_host_state_fields.h>

#include <intrinsics/srs_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

using namespace x64;
using namespace intel_x64;
using namespace msrs;
using namespace vmcs;

static struct control_flow_path path;

static void
setup_check_host_control_registers_and_msrs_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[ia32_vmx_cr0_fixed0::addr] = 0ULL;                  // allow cr0 and
        g_msrs[ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; // cr4 bits to be
        g_msrs[ia32_vmx_cr4_fixed0::addr] = 0ULL;                  // either 0 or 1
        g_msrs[ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; //
        host_cr3::set(0x1000ULL); // host_cr3 is valid physical address
        host_ia32_sysenter_esp::set(0x1000UL); // esp is canonical address
        host_ia32_sysenter_eip::set(0x1000UL); // eip is canonical address
        vm_exit_controls::load_ia32_perf_global_ctrl::disable();
        vm_exit_controls::load_ia32_pat::disable();
        vm_exit_controls::load_ia32_efer::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_segment_and_descriptor_table_registers_all_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vmcs;
    using namespace segment_register;

    path.setup = [&]
    {
        host_es_selector::ti::set(false); host_es_selector::rpl::set(0U); // es.ti == 0 && es.rpl == 0
        host_cs_selector::ti::set(false); host_cs_selector::rpl::set(0U); // cs.ti == 0 && cs.rpl == 0
        host_ss_selector::ti::set(false); host_ss_selector::rpl::set(0U); // ss.ti == 0 && ss.rpl == 0
        host_ds_selector::ti::set(false); host_ds_selector::rpl::set(0U); // ds.ti == 0 && ds.rpl == 0
        host_fs_selector::ti::set(false); host_fs_selector::rpl::set(0U); // fs.ti == 0 && fs.rpl == 0
        host_gs_selector::ti::set(false); host_gs_selector::rpl::set(0U); // gs.ti == 0 && gs.rpl == 0
        host_tr_selector::ti::set(false); host_tr_selector::rpl::set(0U); // tr.ti == 0 && tr.rpl == 0

        host_cs_selector::set(~(cs::ti::mask | cs::rpl::mask)); // cs != 0
        host_tr_selector::set(~(tr::ti::mask | tr::rpl::mask)); // tr != 0

        vm_exit_controls::host_address_space_size::enable(); // VM-exit ctrl host_address_space_size is 1
        host_fs_base::set(0x1000UL); // fs base is canonical address
        host_gs_base::set(0x1000UL); // gs base is canonical address
        host_gdtr_base::set(0x1000UL); // gdtr base is canonical address
        host_idtr_base::set(0x1000UL); // idtr base is canonical address
        host_tr_base::set(0x1000UL); // tr base is canonical address
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_address_space_size_all_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[ia32_efer::addr] |= msrs::ia32_efer::lma::mask; // efer.lma == 1
        vm_exit_controls::host_address_space_size::enable(); // VM-exit ctrl host_address_space_size is 1
        host_cr4::physical_address_extensions::enable(); // host_cr4::physical_address_extensions == 1
        host_rip::set(0x1000UL); // rip is canonical address
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
setup_check_host_state_all_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;

    setup_check_host_control_registers_and_msrs_all_paths(sub_cfg);
    setup_check_host_segment_and_descriptor_table_registers_all_paths(sub_cfg);
    setup_check_host_address_space_size_all_paths(sub_cfg);

    path.setup = [sub_cfg]
    {
        for (const auto &sub_path : sub_cfg)
            sub_path.setup();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_cr0_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        host_cr0::set(0U);
        g_msrs[ia32_vmx_cr0_fixed0::addr] = 0;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_cr0_fixed0::addr] = 1; };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_cr4_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        host_cr4::set(0U);
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
setup_check_host_cr3_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_cr3::set(0xff00000000000000UL); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { host_cr3::set(0x1000UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_ia32_sysenter_esp_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_ia32_sysenter_esp::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_ia32_sysenter_esp::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_ia32_sysenter_eip_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_ia32_sysenter_eip::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_ia32_sysenter_eip::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_perf_global_ctrl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask);
        vm_exit_controls::load_ia32_perf_global_ctrl::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask);
        vm_exit_controls::load_ia32_perf_global_ctrl::enable();
        host_ia32_perf_global_ctrl::set(0xcU);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { host_ia32_perf_global_ctrl::set(0x0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_pat_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::load_ia32_pat::mask);
        vm_exit_controls::load_ia32_pat::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::load_ia32_pat::mask);
        vm_exit_controls::load_ia32_pat::enable();
        host_ia32_pat::pa0::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_pat::pa0::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa1::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_pat::pa1::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa2::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_pat::pa2::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa3::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_pat::pa3::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa4::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_pat::pa4::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa5::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_pat::pa5::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa6::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_pat::pa6::memory_type::set(x64::memory_type::uncacheable);
        host_ia32_pat::pa7::memory_type::set(2ULL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { host_ia32_pat::pa7::set(x64::memory_type::uncacheable); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_efer_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::load_ia32_efer::mask);
        vm_exit_controls::load_ia32_efer::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::load_ia32_efer::mask);
        vm_exit_controls::load_ia32_efer::enable();
        host_ia32_efer::reserved::set(0xEUL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
        host_ia32_efer::reserved::set(0x0UL);
        host_ia32_efer::lma::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
        host_ia32_efer::lma::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ia32_efer::lma::enable();
        host_cr0::paging::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_cr0::paging::enable();
        host_ia32_efer::lma::enable();
        host_ia32_efer::lme::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
        host_ia32_efer::lme::enable();
        host_ia32_efer::lma::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { host_ia32_efer::lme::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}


static void
setup_check_host_es_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_es_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_es_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_es_selector::ti::set(false);
        host_es_selector::rpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_cs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_cs_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_cs_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_cs_selector::ti::set(false);
        host_cs_selector::rpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_ss_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_ss_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_ss_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ss_selector::ti::set(false);
        host_ss_selector::rpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_ds_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_ds_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_ds_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_ds_selector::ti::set(false);
        host_ds_selector::rpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_fs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_fs_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_fs_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_fs_selector::ti::set(false);
        host_fs_selector::rpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_gs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_gs_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_gs_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_gs_selector::ti::set(false);
        host_gs_selector::rpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_tr_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_tr_selector::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_tr_selector::ti::set(true); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_tr_selector::ti::set(false);
        host_tr_selector::rpl::set(1UL);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_cs_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_cs_selector::set(1UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_cs_selector::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_tr_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_tr_selector::set(1UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_tr_selector::set(0U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_ss_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
        host_ss_selector::set(0U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { host_ss_selector::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_fs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_fs_base::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_fs_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_gs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_gs_base::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_gs_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_gdtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_gdtr_base::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_gdtr_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_idtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_idtr_base::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_idtr_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_tr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { host_tr_base::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { host_tr_base::set(0x800000000000U); };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);
}

static void
setup_check_host_if_outside_ia32e_mode_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[ia32_efer::addr] = msrs::ia32_efer::lma::mask; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[ia32_efer::addr] = 0;
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        vm_entry_controls::ia_32e_mode_guest::disable();
        vm_exit_controls::host_address_space_size::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_address_space_size_exit_ctl_is_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[ia32_efer::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[ia32_efer::addr] = msrs::ia32_efer::lma::mask;
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_address_space_disabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        entry_ctl_allow1(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_exit_controls::host_address_space_size::disable();
        vm_entry_controls::ia_32e_mode_guest::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        entry_ctl_allow0(ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask);
        vm_entry_controls::ia_32e_mode_guest::disable();
        host_cr4::pcid_enable_bit::enable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_cr4::set(0U);
        host_rip::set(0xf000000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { host_rip::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_address_space_enabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable();
        host_cr4::physical_address_extensions::disable();
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&]
    {
        host_cr4::physical_address_extensions::enable();
        host_rip::set(0x800000000000U);
    };
    path.throws_exception = true;
    path.exception = ""_ut_lee;
    cfg.push_back(path);

    path.setup = [&] { host_rip::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
vmcs_ut::test_check_host_state_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_state_all_paths(cfg);

    test_vmcs_check(cfg, check::host_state_all);
}

void
vmcs_ut::test_check_host_control_registers_and_msrs_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_control_registers_and_msrs_all_paths(cfg);

    test_vmcs_check(cfg, check::host_control_registers_and_msrs_all);
}

void
vmcs_ut::test_check_host_segment_and_descriptor_table_registers_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_segment_and_descriptor_table_registers_all_paths(cfg);

    test_vmcs_check(cfg, check::host_segment_and_descriptor_table_registers_all);
}

void
vmcs_ut::test_check_host_address_space_size_all()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_address_space_size_all_paths(cfg);

    test_vmcs_check(cfg, check::host_address_space_size_all);
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr0_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, check::host_cr0_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_cr4_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr4_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, check::host_cr4_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_cr3_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr3_for_unsupported_bits_paths(cfg);

    test_vmcs_check(cfg, check::host_cr3_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_ia32_sysenter_esp_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_esp_canonical_address_paths(cfg);

    test_vmcs_check(cfg, check::host_ia32_sysenter_esp_canonical_address);
}

void
vmcs_ut::test_check_host_ia32_sysenter_eip_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_eip_canonical_address_paths(cfg);

    test_vmcs_check(cfg, check::host_ia32_sysenter_eip_canonical_address);
}

void
vmcs_ut::test_check_host_verify_load_ia32_perf_global_ctrl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_perf_global_ctrl_paths(cfg);

    test_vmcs_check(cfg, check::host_verify_load_ia32_perf_global_ctrl);
}

void
vmcs_ut::test_check_host_verify_load_ia32_pat()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_pat_paths(cfg);

    test_vmcs_check(cfg, check::host_verify_load_ia32_pat);
}

void
vmcs_ut::test_check_host_verify_load_ia32_efer()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_efer_paths(cfg);

    test_vmcs_check(cfg, check::host_verify_load_ia32_efer);
}

void
vmcs_ut::test_check_host_es_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_es_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_es_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_cs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_cs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_ss_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_ss_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_ds_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ds_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_ds_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_fs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_fs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_gs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_gs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_tr_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_selector_rpl_ti_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_tr_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_cs_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_not_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_cs_not_equal_zero);
}

void
vmcs_ut::test_check_host_tr_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_not_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_tr_not_equal_zero);
}

void
vmcs_ut::test_check_host_ss_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_not_equal_zero_paths(cfg);

    test_vmcs_check(cfg, check::host_ss_not_equal_zero);
}

void
vmcs_ut::test_check_host_fs_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, check::host_fs_canonical_base_address);
}

void
vmcs_ut::test_check_host_gs_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, check::host_gs_canonical_base_address);
}

void
vmcs_ut::test_check_host_gdtr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gdtr_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, check::host_gdtr_canonical_base_address);
}

void
vmcs_ut::test_check_host_idtr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_idtr_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, check::host_idtr_canonical_base_address);
}

void
vmcs_ut::test_check_host_tr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_canonical_base_address_paths(cfg);

    test_vmcs_check(cfg, check::host_tr_canonical_base_address);
}

void
vmcs_ut::test_check_host_if_outside_ia32e_mode()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_if_outside_ia32e_mode_paths(cfg);

    test_vmcs_check(cfg, check::host_if_outside_ia32e_mode);
}

void
vmcs_ut::test_check_host_address_space_size_exit_ctl_is_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_address_space_size_exit_ctl_is_set_paths(cfg);

    test_vmcs_check(cfg, check::host_address_space_size_exit_ctl_is_set);
}

void
vmcs_ut::test_check_host_address_space_disabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_address_space_disabled_paths(cfg);

    test_vmcs_check(cfg, check::host_address_space_disabled);
}

void
vmcs_ut::test_check_host_address_space_enabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_address_space_enabled_paths(cfg);

    test_vmcs_check(cfg, check::host_address_space_enabled);
}
