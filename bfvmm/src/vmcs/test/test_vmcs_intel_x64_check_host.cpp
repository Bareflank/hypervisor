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

#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>

#include <intrinsics/srs_x64.h>
#include <intrinsics/crs_intel_x64.h>

using namespace x64;
using namespace intel_x64;

static struct control_flow_path path;

static void
setup_check_host_control_registers_and_msrs_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0ULL;                  // allow cr0 and
        g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; // cr4 bits to be
        g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0ULL;                  // either 0 or 1
        g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; //
        vmcs::host_cr3::set(0x1000ULL); // host_cr3 is valid physical address
        g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_ESP] = 0x1000UL; // esp is canonical address
        g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_EIP] = 0x1000UL; // eip is canonical address
        disable_exit_ctl(vmcs::vm_exit_controls::load_ia32_perf_global_ctrl::mask);
        disable_exit_ctl(vmcs::vm_exit_controls::load_ia32_pat::mask);
        disable_exit_ctl(vmcs::vm_exit_controls::load_ia32_efer::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_segment_and_descriptor_table_registers_paths(std::vector<struct control_flow_path> &cfg)
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

        enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); // VM-exit ctrl host_address_space_size is 1
        g_vmcs_fields[VMCS_HOST_FS_BASE] = 0x1000UL; // fs base is canonical address
        g_vmcs_fields[VMCS_HOST_GS_BASE] = 0x1000UL; // gs base is canonical address
        g_vmcs_fields[VMCS_HOST_GDTR_BASE] = 0x1000UL; // gdtr base is canonical address
        g_vmcs_fields[VMCS_HOST_IDTR_BASE] = 0x1000UL; // idtr base is canonical address
        g_vmcs_fields[VMCS_HOST_TR_BASE] = 0x1000UL; // tr base is canonical address
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_checks_related_to_address_space_size_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_efer::addr] |= msrs::ia32_efer::lma::mask; // efer.lma == 1
        enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); // VM-exit ctrl host_address_space_size is 1
        vmcs::host_cr4::physical_address_extensions::set(1U); // host_cr4::physical_address_extensions == 1
        g_vmcs_fields[VMCS_HOST_RIP] = 0x1000UL; // rip is canonical address
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
setup_check_vmcs_host_state_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;

    setup_check_host_control_registers_and_msrs_paths(sub_cfg);
    setup_check_host_segment_and_descriptor_table_registers_paths(sub_cfg);
    setup_check_host_checks_related_to_address_space_size_paths(sub_cfg);

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
    path.setup = [&] { g_vmcs_fields[vmcs::host_cr0::addr] = 0; g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid cr0"));
    cfg.push_back(path);
}

static void
setup_check_host_cr4_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_cr4::addr] = 0; g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid cr4"));
    cfg.push_back(path);
}

static void
setup_check_host_cr3_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_cr3::addr] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host cr3 too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_cr3::addr] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_ia32_sysenter_esp_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_ESP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_ESP] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host sysenter esp must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_ia32_sysenter_eip_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_EIP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_EIP] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host sysenter eip must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_perf_global_ctrl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::load_ia32_perf_global_ctrl::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::load_ia32_perf_global_ctrl::mask); g_vmcs_fields[VMCS_HOST_IA32_PERF_GLOBAL_CTRL] = 0xc; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("perf global ctrl msr reserved bits must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PERF_GLOBAL_CTRL] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_pat_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::load_ia32_pat::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::load_ia32_pat::mask); g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat0 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL << 8; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat1 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL << 16; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat2 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL << 24; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat3 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL << 32; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat4 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL << 40; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat5 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL << 48; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat6 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 2ULL << 56; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat7 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_efer_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::load_ia32_efer::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::load_ia32_efer::mask); g_vmcs_fields[vmcs::host_ia32_efer::addr] = 0xe; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ia32 efer msr reserved buts must be 0 if load ia32 efer entry is enabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); g_vmcs_fields[vmcs::host_ia32_efer::addr] = msrs::ia32_efer::lma::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space is 0, but efer.lma is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); g_vmcs_fields[vmcs::host_ia32_efer::addr] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space is 1, but efer.lma is 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_ia32_efer::addr] = msrs::ia32_efer::lma::mask; g_vmcs_fields[vmcs::host_cr0::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_cr0::addr] = cr0::paging::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("efer.lme is 0, but efer.lma is 1"));
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); g_vmcs_fields[vmcs::host_ia32_efer::addr] = msrs::ia32_efer::lme::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("efer.lme is 1, but efer.lma is 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_ia32_efer::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}


static void
setup_check_host_es_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_es_selector::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_es_selector::addr] = segment_register::es::ti::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host es ti flag must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_es_selector::addr] = segment_register::es::rpl::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host es rpl flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_cs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_cs_selector::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_cs_selector::addr] = segment_register::cs::ti::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host cs ti flag must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_cs_selector::addr] = segment_register::cs::rpl::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host cs rpl flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_ss_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_ss_selector::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_ss_selector::addr] = segment_register::ss::ti::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host ss ti flag must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_ss_selector::addr] = segment_register::ss::rpl::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host ss rpl flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_ds_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_ds_selector::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_ds_selector::addr] = segment_register::ds::ti::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host ds ti flag must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_ds_selector::addr] = segment_register::ds::rpl::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host ds rpl flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_fs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_fs_selector::addr] = 0;};
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_fs_selector::addr] = segment_register::fs::ti::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host fs ti flag must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_fs_selector::addr] = segment_register::fs::rpl::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host fs rpl flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_gs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_gs_selector::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_gs_selector::addr] = segment_register::gs::ti::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host gs ti flag must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_gs_selector::addr] = segment_register::gs::rpl::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host gs rpl flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_tr_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_tr_selector::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_tr_selector::addr] = segment_register::tr::ti::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host tr ti flag must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_tr_selector::addr] = segment_register::tr::rpl::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host tr rpl flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_cs_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_cs_selector::addr] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_cs_selector::addr] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host cs cannot equal 0"));
    cfg.push_back(path);
}

static void
setup_check_host_tr_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[vmcs::host_tr_selector::addr] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_tr_selector::addr] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host tr cannot equal 0"));
    cfg.push_back(path);
}

static void
setup_check_host_ss_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); g_vmcs_fields[vmcs::host_ss_selector::addr] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host ss cannot equal 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_ss_selector::addr] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_fs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_FS_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_FS_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host fs base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_gs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GS_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GS_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host gs base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_gdtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GDTR_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GDTR_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host gdtr base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_idtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IDTR_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IDTR_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host idtr base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_tr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host tr base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_if_outside_ia32e_mode_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[msrs::ia32_efer::addr] = msrs::ia32_efer::lma::mask; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_efer::addr] = 0; enable_entry_ctl(vmcs::vm_entry_controls::ia_32e_mode_guest::mask); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ia 32e mode must be 0 if efer.lma == 0"));
    cfg.push_back(path);

    path.setup = [&] { disable_entry_ctl(vmcs::vm_entry_controls::ia_32e_mode_guest::mask); enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space must be 0 if efer.lma == 0"));
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_vmcs_host_address_space_size_is_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[msrs::ia32_efer::addr] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_efer::addr] = msrs::ia32_efer::lma::mask; disable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space must be 1 if efer.lma == 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_host_address_space_disabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); enable_entry_ctl(vmcs::vm_entry_controls::ia_32e_mode_guest::mask); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ia 32e mode must be disabled if host addr space is disabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_entry_ctl(vmcs::vm_entry_controls::ia_32e_mode_guest::mask); g_vmcs_fields[vmcs::host_cr4::addr] = cr4::pcid_enable_bit::mask; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("cr4 pcide must be disabled if host addr space is disabled"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_cr4::addr] = 0; g_vmcs_fields[VMCS_HOST_RIP] = 0xf000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("rip bits 63:32 must be 0 if host addr space is disabled"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_RIP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_host_address_space_enabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(vmcs::vm_exit_controls::host_address_space_size::mask); g_vmcs_fields[vmcs::host_cr4::addr] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("cr4 pae must be enabled if host addr space is enabled"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::host_cr4::addr] = cr4::physical_address_extensions::mask; g_vmcs_fields[VMCS_HOST_RIP] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rip must be canonical"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_RIP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
vmcs_ut::test_check_vmcs_host_state()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_vmcs_host_state_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_vmcs_host_state);
}

void
vmcs_ut::test_check_host_control_registers_and_msrs()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_control_registers_and_msrs_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_control_registers_and_msrs);
}

void
vmcs_ut::test_check_host_segment_and_descriptor_table_registers()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_segment_and_descriptor_table_registers_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_segment_and_descriptor_table_registers);
}

void
vmcs_ut::test_check_host_checks_related_to_address_space_size()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_checks_related_to_address_space_size_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_checks_related_to_address_space_size);
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr0_for_unsupported_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cr0_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_cr4_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr4_for_unsupported_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cr4_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_cr3_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr3_for_unsupported_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cr3_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_ia32_sysenter_esp_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_esp_canonical_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ia32_sysenter_esp_canonical_address);
}

void
vmcs_ut::test_check_host_ia32_sysenter_eip_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_eip_canonical_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ia32_sysenter_eip_canonical_address);
}

void
vmcs_ut::test_check_host_verify_load_ia32_perf_global_ctrl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_perf_global_ctrl_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_verify_load_ia32_perf_global_ctrl);
}

void
vmcs_ut::test_check_host_verify_load_ia32_pat()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_pat_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_verify_load_ia32_pat);
}

void
vmcs_ut::test_check_host_verify_load_ia32_efer()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_efer_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_verify_load_ia32_efer);
}

void
vmcs_ut::test_check_host_es_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_es_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_es_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_cs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_ss_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ss_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_ds_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ds_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ds_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_fs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_fs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_gs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_gs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_tr_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_tr_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_cs_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_not_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cs_not_equal_zero);
}

void
vmcs_ut::test_check_host_tr_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_not_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_tr_not_equal_zero);
}

void
vmcs_ut::test_check_host_ss_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_not_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ss_not_equal_zero);
}

void
vmcs_ut::test_check_host_fs_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_fs_canonical_base_address);
}

void
vmcs_ut::test_check_host_gs_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_gs_canonical_base_address);
}

void
vmcs_ut::test_check_host_gdtr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gdtr_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_gdtr_canonical_base_address);
}

void
vmcs_ut::test_check_host_idtr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_idtr_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_idtr_canonical_base_address);
}

void
vmcs_ut::test_check_host_tr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_tr_canonical_base_address);
}

void
vmcs_ut::test_check_host_if_outside_ia32e_mode()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_if_outside_ia32e_mode_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_if_outside_ia32e_mode);
}

void
vmcs_ut::test_check_host_vmcs_host_address_space_size_is_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_vmcs_host_address_space_size_is_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_vmcs_host_address_space_size_is_set);
}

void
vmcs_ut::test_check_host_host_address_space_disabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_host_address_space_disabled_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_host_address_space_disabled);
}

void
vmcs_ut::test_check_host_host_address_space_enabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_host_address_space_enabled_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_host_address_space_enabled);
}
