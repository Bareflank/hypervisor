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
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>

using namespace intel_x64;

static struct control_flow_path path;

static void
setup_checks_on_guest_control_registers_debug_registers_and_msrs_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0ULL;
        g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
        g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0ULL;
        g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
        disable_entry_ctl(vmcs::vm_entry_controls::load_debug_controls::mask);
        disable_entry_ctl(vmcs::vm_entry_controls::ia_32e_mode_guest::mask);
        vmcs::guest_cr4::pcid_enable_bit::disable();
        vmcs::guest_ia32_sysenter_esp::set(0x1000UL);
        vmcs::guest_ia32_sysenter_eip::set(0x1000UL);
        disable_entry_ctl(vmcs::vm_entry_controls::load_ia32_perf_global_ctrl::mask);
        disable_entry_ctl(vmcs::vm_entry_controls::load_ia32_pat::mask);
        disable_entry_ctl(vmcs::vm_entry_controls::load_ia32_efer::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
setup_check_vmcs_guest_state_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;

    setup_checks_on_guest_control_registers_debug_registers_and_msrs_paths(sub_cfg);
    // setup_checks_on_guest_segment_registers_paths(cfg);
    // setup_checks_on_guest_descriptor_table_registers_paths(cfg);
    // setup_checks_on_guest_rip_and_rflags_paths(cfg);
    // setup_checks_on_guest_non_register_state_paths(cfg);

    path.setup = [sub_cfg]
    {
        for (const auto &sub_path : sub_cfg)
            sub_path.setup();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}
