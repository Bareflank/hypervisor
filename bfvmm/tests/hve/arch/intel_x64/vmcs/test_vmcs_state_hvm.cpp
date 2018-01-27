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

#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("vmcs: host_vm_state")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    CHECK_NOTHROW(vmcs_intel_x64_host_vm_state{});
}

TEST_CASE("vmcs: host_vm_state_segment_registers")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    segment_register::es::set(1U);
    segment_register::cs::set(1U);
    segment_register::ss::set(1U);
    segment_register::ds::set(1U);
    segment_register::fs::set(1U);
    segment_register::gs::set(1U);
    segment_register::tr::set(1U);
    segment_register::ldtr::set(1U);

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.es() == 1U);
    CHECK(state.cs() == 1U);
    CHECK(state.ss() == 1U);
    CHECK(state.ds() == 1U);
    CHECK(state.fs() == 1U);
    CHECK(state.gs() == 1U);
    CHECK(state.tr() == 1U);
    CHECK(state.ldtr() == 1U);
}

TEST_CASE("vmcs: host_vm_state_control_registers")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    intel_x64::cr0::set(1U);
    intel_x64::cr3::set(2U);
    intel_x64::cr4::set(3U);

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.cr0() == 1U);
    CHECK(state.cr3() == 2U);
    CHECK(state.cr4() == (3U | intel_x64::cr4::vmx_enable_bit::mask));
}

TEST_CASE("vmcs: host_vm_state_debug_registers")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    dr7::set(42U);
    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.dr7() == 42U);
}

TEST_CASE("vmcs: host_vm_state_rflags")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    rflags::set(42U);
    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.rflags() == 42U);
}

TEST_CASE("vmcs: host_vm_state_gdt_base")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.gdt_base() == bfscast(gdt_x64::integer_pointer, g_gdtr.base));
}

TEST_CASE("vmcs: host_vm_state_idt_base")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.idt_base() == bfscast(gdt_x64::integer_pointer, g_idtr.base));
}

TEST_CASE("vmcs: host_vm_state_gdt_limit")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.gdt_limit() == g_gdtr.limit);
}

TEST_CASE("vmcs: host_vm_state_idt_limit")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.idt_limit() == g_idtr.limit);
}

TEST_CASE("vmcs: host_vm_state_es_limit")
{
    SECTION("es_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_limit() == 0U);
    }

    SECTION("es_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::es::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_cs_limit")
{
    SECTION("cs_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_limit() == 0U);
    }

    SECTION("cs_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::cs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ss_limit")
{
    SECTION("ss_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_limit() == 0U);
    }

    SECTION("ss_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ss::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ds_limit")
{
    SECTION("ds_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_limit() == 0U);
    }

    SECTION("ds_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ds::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_fs_limit")
{
    SECTION("fs_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_limit() == 0U);
    }

    SECTION("fs_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::fs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_gs_limit")
{
    SECTION("gs_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_limit() == 0U);
    }

    SECTION("gs_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::gs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_tr_limit")
{
    SECTION("tr_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_limit() == 0U);
    }

    SECTION("tr_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::tr::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ldtr_limit")
{
    SECTION("ldtr_limit == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_limit() == 0U);
    }

    SECTION("ldtr_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ldtr::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_es_access_rights")
{
    SECTION("es_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_access_rights() == x64::access_rights::unusable);
    }

    SECTION("es_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::es::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_cs_access_rights")
{
    SECTION("cs_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_access_rights() == x64::access_rights::unusable);
    }

    SECTION("cs_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::cs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_ss_access_rights")
{
    SECTION("ss_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_access_rights() == x64::access_rights::unusable);
    }

    SECTION("ss_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ss::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_ds_access_rights")
{
    SECTION("ds_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_access_rights() == x64::access_rights::unusable);
    }

    SECTION("ds_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ds::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_fs_access_rights")
{
    SECTION("fs_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_access_rights() == x64::access_rights::unusable);
    }

    SECTION("fs_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::fs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_gs_access_rights")
{
    SECTION("gs_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_access_rights() == x64::access_rights::unusable);
    }

    SECTION("gs_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::gs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_tr_access_rights")
{
    SECTION("tr_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_access_rights() == x64::access_rights::unusable);
    }

    SECTION("tr_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::tr::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_ldtr_access_rights")
{
    SECTION("ldtr_access_rights unusable") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_access_rights() == x64::access_rights::unusable);
    }

    SECTION("ldtr_access_rights == 0x70") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ldtr::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_es_base")
{
    SECTION("es_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_base() == 0U);
    }

    SECTION("es_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::es::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_cs_base")
{
    SECTION("cs_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_base() == 0U);
    }

    SECTION("cs_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::cs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ss_base")
{
    SECTION("ss_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_base() == 0U);
    }

    SECTION("ss_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ss::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ds_base")
{
    SECTION("ds_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_base() == 0U);
    }

    SECTION("ds_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ds::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_fs_base")
{
    SECTION("fs_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_base() == 0U);
    }

    SECTION("fs_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::fs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_gs_base")
{
    SECTION("gs_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_base() == 0U);
    }

    SECTION("gs_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::gs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_tr_base")
{
    SECTION("tr_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_base() == 0U);
    }

    SECTION("tr_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::tr::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ldtr_base")
{
    SECTION("ldtr_base == 0") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_base() == 0U);
    }

    SECTION("ldtr_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_gdt();
    setup_idt();

        segment_register::ldtr::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ia32_msrs_no_perf")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    intel_x64::msrs::ia32_debugctl::set(42U);
    x64::msrs::ia32_pat::set(42U);
    intel_x64::msrs::ia32_efer::set(42U);
    intel_x64::msrs::ia32_perf_global_ctrl::set(42U);
    intel_x64::msrs::ia32_sysenter_cs::set(42U);
    intel_x64::msrs::ia32_sysenter_esp::set(42U);
    intel_x64::msrs::ia32_sysenter_eip::set(42U);
    intel_x64::msrs::ia32_fs_base::set(42U);
    intel_x64::msrs::ia32_gs_base::set(42U);

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.ia32_debugctl_msr() == 42U);
    CHECK(state.ia32_pat_msr() == 42U);
    CHECK(state.ia32_efer_msr() == 42U);
    CHECK(state.ia32_perf_global_ctrl_msr() != 42U);
    CHECK(state.ia32_sysenter_cs_msr() == 42U);
    CHECK(state.ia32_sysenter_esp_msr() == 42U);
    CHECK(state.ia32_sysenter_eip_msr() == 42U);
    CHECK(state.ia32_fs_base_msr() == 42U);
    CHECK(state.ia32_gs_base_msr() == 42U);
}

TEST_CASE("vmcs: host_vm_state_ia32_msrs_perf")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    intel_x64::msrs::ia32_debugctl::set(42U);
    x64::msrs::ia32_pat::set(42U);
    intel_x64::msrs::ia32_efer::set(42U);
    intel_x64::msrs::ia32_perf_global_ctrl::set(42U);
    intel_x64::msrs::ia32_sysenter_cs::set(42U);
    intel_x64::msrs::ia32_sysenter_esp::set(42U);
    intel_x64::msrs::ia32_sysenter_eip::set(42U);
    intel_x64::msrs::ia32_fs_base::set(42U);
    intel_x64::msrs::ia32_gs_base::set(42U);
    g_eax_cpuid[intel_x64::cpuid::arch_perf_monitoring::addr] = 2;

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.ia32_debugctl_msr() == 42U);
    CHECK(state.ia32_pat_msr() == 42U);
    CHECK(state.ia32_efer_msr() == 42U);
    CHECK(state.ia32_perf_global_ctrl_msr() == 42U);
    CHECK(state.ia32_sysenter_cs_msr() == 42U);
    CHECK(state.ia32_sysenter_esp_msr() == 42U);
    CHECK(state.ia32_sysenter_eip_msr() == 42U);
    CHECK(state.ia32_fs_base_msr() == 42U);
    CHECK(state.ia32_gs_base_msr() == 42U);
}

TEST_CASE("vmcs: host_vm_state_dump")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    vmcs_intel_x64_host_vm_state state{};
    CHECK_NOTHROW(state.dump());
}

#endif
