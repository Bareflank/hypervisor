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
#include <hippomocks.h>

#include <intrinsics/x86/intel_x64.h>
#include <vmcs/vmcs_intel_x64_vmm_state.h>

#include <memory_manager/pat_x64.h>
#include <memory_manager/root_page_table_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

static uint32_t
test_cpuid_ecx(uint32_t addr) noexcept
{
    bfignored(addr);
    return 0xFFFFFFFFU;
}

static uint32_t
test_cpuid_subebx(uint32_t addr, uint32_t leaf)
{
    bfignored(addr);
    bfignored(leaf);
    return 0xFFFFFFFFU;
}

static void
setup_mm(MockRepository &mocks)
{
    auto pt = mocks.Mock<root_page_table_x64>();

    mocks.OnCallFunc(root_pt).Return(pt);
    mocks.OnCall(pt, root_page_table_x64::cr3).Return(42U);
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_cpuid_ecx).Do(test_cpuid_ecx);
    mocks.OnCallFunc(_cpuid_subebx).Do(test_cpuid_subebx);
}

TEST_CASE("vmcs: vmm_state")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};
}

TEST_CASE("vmcs: state_segment_registers")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs() == 1U << 3);
    CHECK(state.ss() == 2U << 3);
    CHECK(state.fs() == 3U << 3);
    CHECK(state.gs() == 4U << 3);
    CHECK(state.tr() == 5U << 3);
}

TEST_CASE("vmcs: state_control_registers")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cr0() != 0U);
    CHECK(state.cr3() != 0U);
    CHECK(state.cr4() != 0U);
}

TEST_CASE("vmcs: state_debug_registers")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.dr7() == 0U);
}

TEST_CASE("vmcs: state_rflags")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.rflags() == 0U);
}

TEST_CASE("vmcs: state_gdt_base")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.gdt_base() != 0U);
}

TEST_CASE("vmcs: state_idt_base")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.idt_base() != 0U);
}

TEST_CASE("vmcs: state_gdt_limit")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.gdt_limit() == 4095U);
}

TEST_CASE("vmcs: state_idt_limit")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.idt_limit() == 2047U);
}

TEST_CASE("vmcs: state_segment_registers_limit")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs_limit() == 0xFFFFFFFF);
    CHECK(state.ss_limit() == 0xFFFFFFFF);
    CHECK(state.fs_limit() == 0xFFFFFFFF);
    CHECK(state.gs_limit() == 0xFFFFFFFF);
    CHECK(state.tr_limit() != 0U);
}

TEST_CASE("vmcs: state_segment_registers_access_rights")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs_access_rights() == access_rights::ring0_cs_descriptor);
    CHECK(state.ss_access_rights() == access_rights::ring0_ss_descriptor);
    CHECK(state.fs_access_rights() == access_rights::ring0_fs_descriptor);
    CHECK(state.gs_access_rights() == access_rights::ring0_gs_descriptor);
    CHECK(state.tr_access_rights() == access_rights::ring0_tr_descriptor);
}

TEST_CASE("vmcs: state_segment_register_base")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs_base() == 0U);
    CHECK(state.ss_base() == 0U);
    CHECK(state.fs_base() == 0U);
    CHECK(state.gs_base() == 0U);
    CHECK(state.tr_base() != 0U);
}

TEST_CASE("vmcs: state_msrs")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.ia32_pat_msr() != 0U);
    CHECK(state.ia32_efer_msr() != 0U);
}

TEST_CASE("vmcs: state_dump")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_intrinsics(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK_NOTHROW(state.dump());
}

#endif
