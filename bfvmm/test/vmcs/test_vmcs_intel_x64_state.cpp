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

#include <catch/catch.hpp>

#include <vmcs/vmcs_intel_x64_state.h>
#include <intrinsics/x86/common_x64.h>

using namespace x64;

TEST_CASE("vmcs: state")
{
    CHECK_NOTHROW(vmcs_intel_x64_state{});
}

TEST_CASE("vmcs: state_segment_registers")
{
    vmcs_intel_x64_state state{};

    CHECK(state.es() == 0U);
    CHECK(state.cs() == 0U);
    CHECK(state.ss() == 0U);
    CHECK(state.ds() == 0U);
    CHECK(state.fs() == 0U);
    CHECK(state.gs() == 0U);
    CHECK(state.tr() == 0U);
    CHECK(state.ldtr() == 0U);
    CHECK_NOTHROW(state.set_es(42U));
    CHECK_NOTHROW(state.set_cs(42U));
    CHECK_NOTHROW(state.set_ss(42U));
    CHECK_NOTHROW(state.set_ds(42U));
    CHECK_NOTHROW(state.set_fs(42U));
    CHECK_NOTHROW(state.set_gs(42U));
    CHECK_NOTHROW(state.set_tr(42U));
    CHECK_NOTHROW(state.set_ldtr(42U));
}

TEST_CASE("vmcs: state_control_registers")
{
    vmcs_intel_x64_state state{};

    CHECK(state.cr0() == 0U);
    CHECK(state.cr3() == 0U);
    CHECK(state.cr4() == 0U);
    CHECK_NOTHROW(state.set_cr0(42U));
    CHECK_NOTHROW(state.set_cr3(42U));
    CHECK_NOTHROW(state.set_cr4(42U));
}

TEST_CASE("vmcs: state_debug_registers")
{
    vmcs_intel_x64_state state{};

    CHECK(state.dr7() == 0U);
    CHECK_NOTHROW(state.set_dr7(42U));
}

TEST_CASE("vmcs: state_rflags")
{
    vmcs_intel_x64_state state{};

    CHECK(state.rflags() == 0U);
    CHECK_NOTHROW(state.set_rflags(42U));
}

TEST_CASE("vmcs: state_gdt_base")
{
    vmcs_intel_x64_state state{};

    CHECK(state.gdt_base() == 0U);
    CHECK_NOTHROW(state.set_gdt_base(42U));
}

TEST_CASE("vmcs: state_idt_base")
{
    vmcs_intel_x64_state state{};

    CHECK(state.idt_base() == 0U);
    CHECK_NOTHROW(state.set_idt_base(42U));
}

TEST_CASE("vmcs: state_gdt_limit")
{
    vmcs_intel_x64_state state{};

    CHECK(state.gdt_limit() == 0U);
    CHECK_NOTHROW(state.set_gdt_limit(42U));
}

TEST_CASE("vmcs: state_idt_limit")
{
    vmcs_intel_x64_state state{};

    CHECK(state.idt_limit() == 0U);
    CHECK_NOTHROW(state.set_idt_limit(42U));
}

TEST_CASE("vmcs: state_segment_registers_limit")
{
    vmcs_intel_x64_state state{};

    CHECK(state.es_limit() == 0U);
    CHECK(state.cs_limit() == 0U);
    CHECK(state.ss_limit() == 0U);
    CHECK(state.ds_limit() == 0U);
    CHECK(state.fs_limit() == 0U);
    CHECK(state.gs_limit() == 0U);
    CHECK(state.tr_limit() == 0U);
    CHECK(state.ldtr_limit() == 0U);
    CHECK_NOTHROW(state.set_es_limit(42U));
    CHECK_NOTHROW(state.set_cs_limit(42U));
    CHECK_NOTHROW(state.set_ss_limit(42U));
    CHECK_NOTHROW(state.set_ds_limit(42U));
    CHECK_NOTHROW(state.set_fs_limit(42U));
    CHECK_NOTHROW(state.set_gs_limit(42U));
    CHECK_NOTHROW(state.set_tr_limit(42U));
    CHECK_NOTHROW(state.set_ldtr_limit(42U));

}

TEST_CASE("vmcs: state_segment_registers_access_rights")
{
    vmcs_intel_x64_state state{};

    CHECK(state.es_access_rights() == access_rights::unusable);
    CHECK(state.cs_access_rights() == access_rights::unusable);
    CHECK(state.ss_access_rights() == access_rights::unusable);
    CHECK(state.ds_access_rights() == access_rights::unusable);
    CHECK(state.fs_access_rights() == access_rights::unusable);
    CHECK(state.gs_access_rights() == access_rights::unusable);
    CHECK(state.tr_access_rights() == access_rights::unusable);
    CHECK(state.ldtr_access_rights() == access_rights::unusable);
    CHECK_NOTHROW(state.set_es_access_rights(42U));
    CHECK_NOTHROW(state.set_cs_access_rights(42U));
    CHECK_NOTHROW(state.set_ss_access_rights(42U));
    CHECK_NOTHROW(state.set_ds_access_rights(42U));
    CHECK_NOTHROW(state.set_fs_access_rights(42U));
    CHECK_NOTHROW(state.set_gs_access_rights(42U));
    CHECK_NOTHROW(state.set_tr_access_rights(42U));
    CHECK_NOTHROW(state.set_ldtr_access_rights(42U));
}

TEST_CASE("vmcs: state_segment_register_base")
{
    vmcs_intel_x64_state state{};

    CHECK(state.es_base() == 0U);
    CHECK(state.cs_base() == 0U);
    CHECK(state.ss_base() == 0U);
    CHECK(state.ds_base() == 0U);
    CHECK(state.fs_base() == 0U);
    CHECK(state.gs_base() == 0U);
    CHECK(state.tr_base() == 0U);
    CHECK(state.ldtr_base() == 0U);
    CHECK_NOTHROW(state.set_es_base(42U));
    CHECK_NOTHROW(state.set_cs_base(42U));
    CHECK_NOTHROW(state.set_ss_base(42U));
    CHECK_NOTHROW(state.set_ds_base(42U));
    CHECK_NOTHROW(state.set_fs_base(42U));
    CHECK_NOTHROW(state.set_gs_base(42U));
    CHECK_NOTHROW(state.set_tr_base(42U));
    CHECK_NOTHROW(state.set_ldtr_base(42U));
}

TEST_CASE("vmcs: state_msrs")
{
    vmcs_intel_x64_state state{};

    CHECK(state.ia32_debugctl_msr() == 0U);
    CHECK(state.ia32_pat_msr() == 0U);
    CHECK(state.ia32_efer_msr() == 0U);
    CHECK(state.ia32_perf_global_ctrl_msr() == 0U);
    CHECK(state.ia32_sysenter_cs_msr() == 0U);
    CHECK(state.ia32_sysenter_esp_msr() == 0U);
    CHECK(state.ia32_sysenter_eip_msr() == 0U);
    CHECK(state.ia32_fs_base_msr() == 0U);
    CHECK(state.ia32_gs_base_msr() == 0U);
    CHECK_NOTHROW(state.set_ia32_debugctl_msr(42U));
    CHECK_NOTHROW(state.set_ia32_pat_msr(42U));
    CHECK_NOTHROW(state.set_ia32_efer_msr(42U));
    CHECK_NOTHROW(state.set_ia32_perf_global_ctrl_msr(42U));
    CHECK_NOTHROW(state.set_ia32_sysenter_cs_msr(42U));
    CHECK_NOTHROW(state.set_ia32_sysenter_esp_msr(42U));
    CHECK_NOTHROW(state.set_ia32_sysenter_eip_msr(42U));
    CHECK_NOTHROW(state.set_ia32_fs_base_msr(42U));
    CHECK_NOTHROW(state.set_ia32_gs_base_msr(42U));
}

TEST_CASE("vmcs: state_is_guest")
{
    vmcs_intel_x64_state state{};
    CHECK_FALSE(state.is_guest());
}

TEST_CASE("vmcs: state_dump")
{
    vmcs_intel_x64_state state{};
    CHECK_NOTHROW(state.dump());
}
