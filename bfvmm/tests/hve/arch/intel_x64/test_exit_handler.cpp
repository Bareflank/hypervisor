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

#include <test/support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

static bool
handle_test(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{ bfignored(vmcs); return true; }

auto
setup_vmcs(MockRepository &mocks, ::intel_x64::vmcs::value_type reason)
{
    setup_test_support();

    auto vmcs = mocks.Mock<bfvmm::intel_x64::vmcs>();

    mocks.OnCall(vmcs, bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(vmcs, bfvmm::intel_x64::vmcs::resume);
    mocks.OnCall(vmcs, bfvmm::intel_x64::vmcs::promote);
    mocks.OnCall(vmcs, bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(vmcs, bfvmm::intel_x64::vmcs::save_state).Return(&g_save_state);

    g_vmcs_fields[::intel_x64::vmcs::exit_reason::addr] = reason;
    g_vmcs_fields[::intel_x64::vmcs::vm_exit_instruction_length::addr] = 42;

    g_eax_cpuid[intel_x64::cpuid::arch_perf_monitoring::addr] = 0xFFFFFFFF;
    g_ecx_cpuid[intel_x64::cpuid::feature_information::addr] = 0xFFFFFFFF;
    g_ebx_cpuid[intel_x64::cpuid::extended_feature_flags::addr] = 0xFFFFFFFF;

    return vmcs;
}

TEST_CASE("quiet")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);

    handle_test(vmcs);
}

TEST_CASE("exit_handler: halt")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);

    CHECK_NOTHROW(halt(vmcs));
}

TEST_CASE("exit_handler: advance")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);

    CHECK_NOTHROW(advance(vmcs));
}

TEST_CASE("exit_handler: construct / destruct")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);

    g_mm->add_md(0x1000, 0x1000, MEMORY_TYPE_R | MEMORY_TYPE_E);
    g_mm->add_md(0x2000, 0x2000, MEMORY_TYPE_R | MEMORY_TYPE_W);

    CHECK_NOTHROW(bfvmm::intel_x64::exit_handler{vmcs});
}

TEST_CASE("exit_handler: add_handler")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    CHECK_NOTHROW(
        ehlr.add_handler(0, handler_delegate_t::create<handle_test>())
    );
}

TEST_CASE("exit_handler: add_handler invalid reason")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    CHECK_THROWS(
        ehlr.add_handler(1000, handler_delegate_t::create<handle_test>())
    );
}

TEST_CASE("exit_handler: unhandled exit reason")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: unhandled exit reason, invalid guest state")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::vm_entry_failure::mask);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: unhandled exit reason, invalid reason")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0000BEEF);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: handle_nmi")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rip = 0;
    g_vmcs_fields[::intel_x64::vmcs::vm_exit_interruption_information::addr]
        = ::intel_x64::vmcs::vm_exit_interruption_information::interruption_type::non_maskable_interrupt
          << ::intel_x64::vmcs::vm_exit_interruption_information::interruption_type::from;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip == 0);
    CHECK(::intel_x64::vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting::is_enabled());
}

TEST_CASE("exit_handler: handle_nmi_window")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::nmi_window);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rip = 0;
    ::intel_x64::vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting::enable();
    ::intel_x64::vmcs::vm_entry_interruption_information::set(0);

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip == 0);
    CHECK(::intel_x64::vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting::is_disabled());
    CHECK(::intel_x64::vmcs::vm_entry_interruption_information::vector::get() == 2);
    CHECK(::intel_x64::vmcs::vm_entry_interruption_information::valid_bit::is_enabled());
    CHECK(::intel_x64::vmcs::vm_entry_interruption_information::interruption_type::get()
          == ::intel_x64::vmcs::vm_entry_interruption_information::interruption_type::non_maskable_interrupt);
}

TEST_CASE("exit_handler: handle_cpuid")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

bool
test_handler(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    bfignored(vmcs);
    return true;
}

TEST_CASE("exit_handler: handle_cpuid init")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    ehlr.add_init_handler(
        ::handler_delegate_t::create<test_handler>()
    );

    g_save_state.rax = 0xBF10;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_cpuid start")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rax = 0xBF11;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_cpuid fini")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    ehlr.add_fini_handler(
        ::handler_delegate_t::create<test_handler>()
    );

    g_save_state.rax = 0xBF20;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_cpuid stop")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rax = 0xBF21;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_invd")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::invd);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_vmxoff")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::vmxoff);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_debug_ctl")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_debugctl::addr] = 0x0000000200000001;
    g_save_state.rcx = intel_x64::msrs::ia32_debugctl::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x1);
    CHECK(g_save_state.rdx == 0x2);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_pat")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_pat::addr] = 0x0000000300000002;
    g_save_state.rcx = x64::msrs::ia32_pat::addr;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x2);
    CHECK(g_save_state.rdx == 0x3);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_efer")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_efer::addr] = 0x0000000400000003;
    g_save_state.rcx = intel_x64::msrs::ia32_efer::addr;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x3);
    CHECK(g_save_state.rdx == 0x4);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_perf")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_perf_global_ctrl::addr] = 0x0000000400000003;
    g_save_state.rcx = intel_x64::msrs::ia32_perf_global_ctrl::addr;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x3);
    CHECK(g_save_state.rdx == 0x4);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_cs")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_cs::addr] = 0x0000000500000004;
    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_cs::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x4);
    CHECK(g_save_state.rdx == 0x5);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_esp")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_esp::addr] = 0x0000000600000005;
    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_esp::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x5);
    CHECK(g_save_state.rdx == 0x6);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_eip")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_eip::addr] = 0x0000000700000006;
    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_eip::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x6);
    CHECK(g_save_state.rdx == 0x7);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_fs_base")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_fs_base::addr] = 0x0000000800000007;
    g_save_state.rcx = intel_x64::msrs::ia32_fs_base::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x7);
    CHECK(g_save_state.rdx == 0x8);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_gs_base")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::guest_gs_base::addr] = 0x0000000900000008;
    g_save_state.rcx = intel_x64::msrs::ia32_gs_base::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x8);
    CHECK(g_save_state.rdx == 0x9);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_default")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_msrs[0x10] = 0x0000000A00000009;
    g_save_state.rcx = 0x10;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x9);
    CHECK(g_save_state.rdx == 0xA);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_ignore")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_msrs[0x31] = 0x0;
    g_save_state.rcx = 0x31;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0);
    CHECK(g_save_state.rdx == 0);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_debug_ctrl")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_debugctl::addr;
    g_save_state.rax = 0x1;
    g_save_state.rdx = 0x2;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_debugctl::addr] == 0x0000000200000001);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_pat")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = x64::msrs::ia32_pat::addr;
    g_save_state.rax = 0x2;
    g_save_state.rdx = 0x3;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_pat::addr] == 0x0000000300000002);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_efer")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_efer::addr;
    g_save_state.rax = 0x3;
    g_save_state.rdx = 0x4;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_efer::addr] == 0x0000000400000003);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_perf")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_perf_global_ctrl::addr;
    g_save_state.rax = 0x3;
    g_save_state.rdx = 0x4;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_perf_global_ctrl::addr] == 0x0000000400000003);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_cs")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_cs::addr;
    g_save_state.rax = 0x4;
    g_save_state.rdx = 0x5;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_cs::addr] == 0x0000000500000004);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_esp")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_esp::addr;
    g_save_state.rax = 0x5;
    g_save_state.rdx = 0x6;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_esp::addr] == 0x0000000600000005);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_eip")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_eip::addr;
    g_save_state.rax = 0x6;
    g_save_state.rdx = 0x7;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_eip::addr] == 0x0000000700000006);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_fs_base")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_fs_base::addr;
    g_save_state.rax = 0x7;
    g_save_state.rdx = 0x8;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_fs_base::addr] == 0x0000000800000007);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_gs_base")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = intel_x64::msrs::ia32_gs_base::addr;
    g_save_state.rax = 0x8;
    g_save_state.rdx = 0x9;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_gs_base::addr] == 0x0000000900000008);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_default")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_save_state.rcx = 0x10;
    g_save_state.rax = 0x9;
    g_save_state.rdx = 0xA;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_msrs[0x10] == 0x0000000A00000009);
}

TEST_CASE("exit_handler: vm_exit_reason_wrcr4")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::control_register_accesses);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 4;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(::intel_x64::vmcs::guest_cr4::vmx_enable_bit::is_enabled());
}

TEST_CASE("exit_handler: vm_exit_reason_wrcr4 invalid")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::control_register_accesses);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vmcs};

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 42;
    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: emulate_rdgpr rax")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000000ULL;
    vmcs->save_state()->rax = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rcx")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000100ULL;
    vmcs->save_state()->rcx = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rdx")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000200ULL;
    vmcs->save_state()->rdx = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rbx")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000300ULL;
    vmcs->save_state()->rbx = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rsp")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000400ULL;
    vmcs->save_state()->rsp = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rbp")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000500ULL;
    vmcs->save_state()->rbp = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rsi")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000600ULL;
    vmcs->save_state()->rsi = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rdi")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000700ULL;
    vmcs->save_state()->rdi = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r8")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000800ULL;
    vmcs->save_state()->r08 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r9")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000900ULL;
    vmcs->save_state()->r09 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r10")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000A00ULL;
    vmcs->save_state()->r10 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r11")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000B00ULL;
    vmcs->save_state()->r11 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r12")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000C00ULL;
    vmcs->save_state()->r12 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r13")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000D00ULL;
    vmcs->save_state()->r13 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r14")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000E00ULL;
    vmcs->save_state()->r14 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r15")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000F00ULL;
    vmcs->save_state()->r15 = 42;

    CHECK(emulate_rdgpr(vmcs) == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rax")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000000ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rax == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rcx")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000100ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rcx == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rdx")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000200ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rdx == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rbx")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000300ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rbx == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rsp")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000400ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rsp == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rbp")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000500ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rbp == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rsi")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000600ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rsi == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rdi")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000700ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->rdi == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r8")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000800ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r08 == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r9")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000900ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r09 == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r10")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000A00ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r10 == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r11")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000B00ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r11 == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r12")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000C00ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r12 == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r13")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000D00ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r13 == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r14")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000E00ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r14 == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r15")
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000F00ULL;
    emulate_wrgpr(vmcs, 42);

    CHECK(vmcs->save_state()->r15 == 42);
}

#endif
