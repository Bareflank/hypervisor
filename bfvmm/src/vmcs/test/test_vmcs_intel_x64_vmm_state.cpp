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
#include <vmcs/vmcs_intel_x64_vmm_state.h>

#include <intrinsics/srs_x64.h>
#include <intrinsics/gdt_x64.h>
#include <intrinsics/idt_x64.h>
#include <intrinsics/debug_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>
#include <memory_manager/root_page_table_x64.h>

using namespace x64;

extern uint64_t test_cr0;
extern uint64_t test_cr3;
extern uint64_t test_cr4;

extern void setup_gdt();
extern void setup_idt();

static uint64_t test_ia32_efer_msr;

static void
setup_vmm_state(MockRepository &mocks)
{
    auto pt = mocks.Mock<root_page_table_x64>();
    mocks.OnCallFunc(root_page_table_x64::instance).Return(pt);
    mocks.OnCall(pt, root_page_table_x64::phys_addr).Return(test_cr3);


    test_cr0 = cr0::protection_enable::mask;
    test_cr0 |= cr0::monitor_coprocessor::mask;
    test_cr0 |= cr0::extension_type::mask;
    test_cr0 |= cr0::numeric_error::mask;
    test_cr0 |= cr0::write_protect::mask;
    test_cr0 |= cr0::paging::mask;

    test_cr3 = 0x000000ABCDEF0000;

    test_cr4 = cr4::physical_address_extensions::mask;
    test_cr4 |= cr4::page_global_enable::mask;
    test_cr4 |= cr4::vmx_enable_bit::mask;
    test_cr4 |= cr4::osfxsr::mask;
    test_cr4 |= cr4::osxsave::mask;
}

void
vmcs_ut::test_vmm_state_gdt_not_setup()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    auto cs_access_rights = (access_rights::ring0_cs_descriptor & 0xF0FFULL);
    auto ss_access_rights = (access_rights::ring0_ss_descriptor & 0xF0FFULL);
    auto fs_access_rights = (access_rights::ring0_fs_descriptor & 0xF0FFULL);
    auto gs_access_rights = (access_rights::ring0_gs_descriptor & 0xF0FFULL);
    auto tr_access_rights = (access_rights::ring0_tr_descriptor & 0xF0FFULL);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};

            this->expect_true(g_gdt.access_rights(1) == cs_access_rights);
            this->expect_true(g_gdt.access_rights(2) == ss_access_rights);
            this->expect_true(g_gdt.access_rights(3) == fs_access_rights);
            this->expect_true(g_gdt.access_rights(4) == gs_access_rights);
            this->expect_true(g_gdt.access_rights(5) == tr_access_rights);

            this->expect_true(g_gdt.base(1) == 0);
            this->expect_true(g_gdt.base(2) == 0);
            this->expect_true(g_gdt.base(3) == 0);
            this->expect_true(g_gdt.base(4) == 0);
            this->expect_true(g_gdt.base(5) == reinterpret_cast<gdt_x64::integer_pointer>(&g_tss));

            this->expect_true(g_gdt.limit(1) == 0xFFFFFFFF);
            this->expect_true(g_gdt.limit(2) == 0xFFFFFFFF);
            this->expect_true(g_gdt.limit(3) == 0xFFFFFFFF);
            this->expect_true(g_gdt.limit(4) == 0xFFFFFFFF);
            this->expect_true(g_gdt.limit(5) == sizeof(g_tss));
        });
    });
}

void
vmcs_ut::test_vmm_state_segment_registers()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};

            this->expect_true(state.cs() == 1U << 3);
            this->expect_true(state.ss() == 2U << 3);
            this->expect_true(state.fs() == 3U << 3);
            this->expect_true(state.gs() == 4U << 3);
            this->expect_true(state.tr() == 5U << 3);
        });
    });
}

void
vmcs_ut::test_vmm_state_control_registers()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};

            this->expect_true(state.cr0() == test_cr0);
            this->expect_true(state.cr3() == test_cr3);
            this->expect_true(state.cr4() == test_cr4);
        });
    });
}

void
vmcs_ut::test_vmm_state_rflags()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};
            this->expect_true(state.rflags() == 0U);
        });
    });
}

void
vmcs_ut::test_vmm_state_gdt_base()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};
            this->expect_true(state.gdt_base() == g_gdt.base());
        });
    });
}

void
vmcs_ut::test_vmm_state_idt_base()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};
            this->expect_true(state.idt_base() == g_idt.base());
        });
    });
}

void
vmcs_ut::test_vmm_state_gdt_limit()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};
            this->expect_true(state.gdt_limit() == g_gdt.limit());
        });
    });
}

void
vmcs_ut::test_vmm_state_idt_limit()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};
            this->expect_true(state.idt_limit() == g_idt.limit());
        });
    });
}

void
vmcs_ut::test_vmm_state_segment_registers_limit()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};

            this->expect_true(state.cs_limit() == g_gdt.limit(1U));
            this->expect_true(state.ss_limit() == g_gdt.limit(2U));
            this->expect_true(state.fs_limit() == g_gdt.limit(3U));
            this->expect_true(state.gs_limit() == g_gdt.limit(4U));
            this->expect_true(state.tr_limit() == g_gdt.limit(5U));
        });
    });
}

void
vmcs_ut::test_vmm_state_segment_registers_access_rights()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};

            this->expect_true(state.cs_access_rights() == g_gdt.access_rights(1U));
            this->expect_true(state.ss_access_rights() == g_gdt.access_rights(2U));
            this->expect_true(state.fs_access_rights() == g_gdt.access_rights(3U));
            this->expect_true(state.gs_access_rights() == g_gdt.access_rights(4U));
            this->expect_true(state.tr_access_rights() == g_gdt.access_rights(5U));
        });
    });
}

void
vmcs_ut::test_vmm_state_segment_registers_base()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};

            this->expect_true(state.cs_base() == g_gdt.base(1U));
            this->expect_true(state.ss_base() == g_gdt.base(2U));
            this->expect_true(state.fs_base() == g_gdt.base(3U));
            this->expect_true(state.gs_base() == g_gdt.base(4U));
            this->expect_true(state.tr_base() == g_gdt.base(5U));
        });
    });
}

void
vmcs_ut::test_vmm_state_ia32_efer_msr()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    test_ia32_efer_msr = 0;
    test_ia32_efer_msr |= msrs::ia32_efer::lme::mask;
    test_ia32_efer_msr |= msrs::ia32_efer::lma::mask;
    test_ia32_efer_msr |= msrs::ia32_efer::nxe::mask;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};
            this->expect_true(state.ia32_efer_msr() == test_ia32_efer_msr);
        });
    });
}

void
vmcs_ut::test_vmm_state_dump()
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]
        {
            vmcs_intel_x64_vmm_state state{};
            this->expect_no_exception([&] { state.dump(); });
        });
    });
}
