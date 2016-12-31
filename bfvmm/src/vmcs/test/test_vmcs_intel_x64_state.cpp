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

#include <test.h>
#include <vmcs/vmcs_intel_x64_state.h>
#include <intrinsics/x64.h>

using namespace x64;

void
vmcs_ut::test_state()
{
    this->expect_no_exception([&] { vmcs_intel_x64_state state{}; });
}

void
vmcs_ut::test_state_segment_registers()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.es() == 0U);
        this->expect_true(state.cs() == 0U);
        this->expect_true(state.ss() == 0U);
        this->expect_true(state.ds() == 0U);
        this->expect_true(state.fs() == 0U);
        this->expect_true(state.gs() == 0U);
        this->expect_true(state.tr() == 0U);
        this->expect_true(state.ldtr() == 0U);
        this->expect_no_exception([&]{ state.set_es(42U); });
        this->expect_no_exception([&]{ state.set_cs(42U); });
        this->expect_no_exception([&]{ state.set_ss(42U); });
        this->expect_no_exception([&]{ state.set_ds(42U); });
        this->expect_no_exception([&]{ state.set_fs(42U); });
        this->expect_no_exception([&]{ state.set_gs(42U); });
        this->expect_no_exception([&]{ state.set_tr(42U); });
        this->expect_no_exception([&]{ state.set_ldtr(42U); });
    });
}

void
vmcs_ut::test_state_control_registers()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.cr0() == 0U);
        this->expect_true(state.cr3() == 0U);
        this->expect_true(state.cr4() == 0U);
        this->expect_no_exception([&]{ state.set_cr0(42U); });
        this->expect_no_exception([&]{ state.set_cr3(42U); });
        this->expect_no_exception([&]{ state.set_cr4(42U); });
    });
}

void
vmcs_ut::test_state_debug_registers()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.dr7() == 0U);
        this->expect_no_exception([&]{ state.set_dr7(42U); });
    });
}

void
vmcs_ut::test_state_rflags()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.rflags() == 0U);
        this->expect_no_exception([&]{ state.set_rflags(42U); });
    });
}

void
vmcs_ut::test_state_gdt_base()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.gdt_base() == 0U);
        this->expect_no_exception([&]{ state.set_gdt_base(42U); });
    });
}

void
vmcs_ut::test_state_idt_base()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.idt_base() == 0U);
        this->expect_no_exception([&]{ state.set_idt_base(42U); });
    });
}

void
vmcs_ut::test_state_gdt_limit()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.gdt_limit() == 0U);
        this->expect_no_exception([&]{ state.set_gdt_limit(42U); });
    });
}

void
vmcs_ut::test_state_idt_limit()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.idt_limit() == 0U);
        this->expect_no_exception([&]{ state.set_idt_limit(42U); });
    });
}

void
vmcs_ut::test_state_segment_registers_limit()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.es_limit() == 0U);
        this->expect_true(state.cs_limit() == 0U);
        this->expect_true(state.ss_limit() == 0U);
        this->expect_true(state.ds_limit() == 0U);
        this->expect_true(state.fs_limit() == 0U);
        this->expect_true(state.gs_limit() == 0U);
        this->expect_true(state.tr_limit() == 0U);
        this->expect_true(state.ldtr_limit() == 0U);
        this->expect_no_exception([&]{ state.set_es_limit(42U); });
        this->expect_no_exception([&]{ state.set_cs_limit(42U); });
        this->expect_no_exception([&]{ state.set_ss_limit(42U); });
        this->expect_no_exception([&]{ state.set_ds_limit(42U); });
        this->expect_no_exception([&]{ state.set_fs_limit(42U); });
        this->expect_no_exception([&]{ state.set_gs_limit(42U); });
        this->expect_no_exception([&]{ state.set_tr_limit(42U); });
        this->expect_no_exception([&]{ state.set_ldtr_limit(42U); });
    });

}

void
vmcs_ut::test_state_segment_registers_access_rights()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.es_access_rights() == access_rights::unusable);
        this->expect_true(state.cs_access_rights() == access_rights::unusable);
        this->expect_true(state.ss_access_rights() == access_rights::unusable);
        this->expect_true(state.ds_access_rights() == access_rights::unusable);
        this->expect_true(state.fs_access_rights() == access_rights::unusable);
        this->expect_true(state.gs_access_rights() == access_rights::unusable);
        this->expect_true(state.tr_access_rights() == access_rights::unusable);
        this->expect_true(state.ldtr_access_rights() == access_rights::unusable);
        this->expect_no_exception([&]{ state.set_es_access_rights(42U); });
        this->expect_no_exception([&]{ state.set_cs_access_rights(42U); });
        this->expect_no_exception([&]{ state.set_ss_access_rights(42U); });
        this->expect_no_exception([&]{ state.set_ds_access_rights(42U); });
        this->expect_no_exception([&]{ state.set_fs_access_rights(42U); });
        this->expect_no_exception([&]{ state.set_gs_access_rights(42U); });
        this->expect_no_exception([&]{ state.set_tr_access_rights(42U); });
        this->expect_no_exception([&]{ state.set_ldtr_access_rights(42U); });
    });
}

void
vmcs_ut::test_state_segment_register_base()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.es_base() == 0U);
        this->expect_true(state.cs_base() == 0U);
        this->expect_true(state.ss_base() == 0U);
        this->expect_true(state.ds_base() == 0U);
        this->expect_true(state.fs_base() == 0U);
        this->expect_true(state.gs_base() == 0U);
        this->expect_true(state.tr_base() == 0U);
        this->expect_true(state.ldtr_base() == 0U);
        this->expect_no_exception([&]{ state.set_es_base(42U); });
        this->expect_no_exception([&]{ state.set_cs_base(42U); });
        this->expect_no_exception([&]{ state.set_ss_base(42U); });
        this->expect_no_exception([&]{ state.set_ds_base(42U); });
        this->expect_no_exception([&]{ state.set_fs_base(42U); });
        this->expect_no_exception([&]{ state.set_gs_base(42U); });
        this->expect_no_exception([&]{ state.set_tr_base(42U); });
        this->expect_no_exception([&]{ state.set_ldtr_base(42U); });
    });
}

void
vmcs_ut::test_state_msrs()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};

        this->expect_true(state.ia32_debugctl_msr() == 0U);
        this->expect_true(state.ia32_pat_msr() == 0U);
        this->expect_true(state.ia32_efer_msr() == 0U);
        this->expect_true(state.ia32_perf_global_ctrl_msr() == 0U);
        this->expect_true(state.ia32_sysenter_cs_msr() == 0U);
        this->expect_true(state.ia32_sysenter_esp_msr() == 0U);
        this->expect_true(state.ia32_sysenter_eip_msr() == 0U);
        this->expect_true(state.ia32_fs_base_msr() == 0U);
        this->expect_true(state.ia32_gs_base_msr() == 0U);
        this->expect_no_exception([&]{ state.set_ia32_debugctl_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_pat_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_efer_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_perf_global_ctrl_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_sysenter_cs_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_sysenter_esp_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_sysenter_eip_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_fs_base_msr(42U); });
        this->expect_no_exception([&]{ state.set_ia32_gs_base_msr(42U); });
    });
}

void
vmcs_ut::test_state_is_guest()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};
        this->expect_false(state.is_guest());
    });
}

void
vmcs_ut::test_state_dump()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_state state{};
        this->expect_no_exception([&] { state.dump(); });
    });
}
