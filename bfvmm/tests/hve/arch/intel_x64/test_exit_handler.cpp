//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

static bool
test_handler(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{ bfignored(vcpu); return true; }

TEST_CASE("quiet")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);

    test_handler(vcpu);
}

TEST_CASE("exit_handler: construct / destruct")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);

    g_mm->add_md(0x1000, 0x1000, MEMORY_TYPE_R | MEMORY_TYPE_E);
    g_mm->add_md(0x2000, 0x2000, MEMORY_TYPE_R | MEMORY_TYPE_W);

    CHECK_NOTHROW(bfvmm::intel_x64::exit_handler{vcpu});
}

TEST_CASE("exit_handler: add_handler")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(
        ehlr.add_handler(0, handler_delegate_t::create<test_handler>())
    );
}

TEST_CASE("exit_handler: add_handler invalid reason")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_THROWS(
        ehlr.add_handler(1000, handler_delegate_t::create<test_handler>())
    );
}

TEST_CASE("exit_handler: unhandled exit reason")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: unhandled exit reason, invalid guest state")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::vm_entry_failure::mask);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: unhandled exit reason, invalid reason")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0000BEEF);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: add_exit_handler")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(
        ehlr.add_exit_handler(handler_delegate_t::create<test_handler>())
    );

    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: handle_nmi")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::nmi_window);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_cpuid ack")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    ehlr.add_init_handler(
        ::handler_delegate_t::create<test_handler>()
    );

    g_save_state.rax = 0x4BF00000;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
    CHECK(g_save_state.rax == 0x4BF00001);
}

TEST_CASE("exit_handler: handle_cpuid init")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    ehlr.add_init_handler(
        ::handler_delegate_t::create<test_handler>()
    );

    g_save_state.rax = 0x4BF00010;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_cpuid start")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rax = 0x4BF00011;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_cpuid fini")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    ehlr.add_fini_handler(
        ::handler_delegate_t::create<test_handler>()
    );

    g_save_state.rax = 0x4BF00020;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_cpuid stop")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rax = 0x4BF00021;
    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_invd")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::invd);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip != 0);
}

TEST_CASE("exit_handler: handle_vmxoff")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::vmxoff);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rip = 0;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_debug_ctl")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_debugctl::addr] = 0x0000000200000001;
    g_save_state.rcx = intel_x64::msrs::ia32_debugctl::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x1);
    CHECK(g_save_state.rdx == 0x2);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_pat")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_cs::addr] = 0x0000000500000004;
    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_cs::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x4);
    CHECK(g_save_state.rdx == 0x5);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_esp")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_esp::addr] = 0x0000000600000005;
    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_esp::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x5);
    CHECK(g_save_state.rdx == 0x6);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_eip")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_eip::addr] = 0x0000000700000006;
    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_eip::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x6);
    CHECK(g_save_state.rdx == 0x7);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_fs_base")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::guest_fs_base::addr] = 0x0000000800000007;
    g_save_state.rcx = intel_x64::msrs::ia32_fs_base::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x7);
    CHECK(g_save_state.rdx == 0x8);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_gs_base")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::guest_gs_base::addr] = 0x0000000900000008;
    g_save_state.rcx = intel_x64::msrs::ia32_gs_base::addr;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x8);
    CHECK(g_save_state.rdx == 0x9);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_default")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_msrs[0x10] = 0x0000000A00000009;
    g_save_state.rcx = 0x10;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0x9);
    CHECK(g_save_state.rdx == 0xA);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_ignore")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_msrs[0x31] = 0x0;
    g_save_state.rcx = 0x31;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_save_state.rax == 0);
    CHECK(g_save_state.rdx == 0);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_debug_ctrl")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rcx = intel_x64::msrs::ia32_debugctl::addr;
    g_save_state.rax = 0x1;
    g_save_state.rdx = 0x2;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_debugctl::addr] == 0x0000000200000001);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_pat")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

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
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_cs::addr;
    g_save_state.rax = 0x4;
    g_save_state.rdx = 0x5;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_cs::addr] == 0x0000000500000004);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_esp")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_esp::addr;
    g_save_state.rax = 0x5;
    g_save_state.rdx = 0x6;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_esp::addr] == 0x0000000600000005);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_eip")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rcx = intel_x64::msrs::ia32_sysenter_eip::addr;
    g_save_state.rax = 0x6;
    g_save_state.rdx = 0x7;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_ia32_sysenter_eip::addr] == 0x0000000700000006);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_fs_base")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rcx = intel_x64::msrs::ia32_fs_base::addr;
    g_save_state.rax = 0x7;
    g_save_state.rdx = 0x8;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_fs_base::addr] == 0x0000000800000007);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_gs_base")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rcx = intel_x64::msrs::ia32_gs_base::addr;
    g_save_state.rax = 0x8;
    g_save_state.rdx = 0x9;

    CHECK_NOTHROW(ehlr.handle(&ehlr));

    CHECK(g_vmcs_fields[::intel_x64::vmcs::guest_gs_base::addr] == 0x0000000900000008);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_default")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_save_state.rcx = 0x10;
    g_save_state.rax = 0x9;
    g_save_state.rdx = 0xA;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(g_msrs[0x10] == 0x0000000A00000009);
}

TEST_CASE("exit_handler: vm_exit_reason_wrcr4")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::control_register_accesses);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 4;

    CHECK_NOTHROW(ehlr.handle(&ehlr));
    CHECK(::intel_x64::vmcs::guest_cr4::vmx_enable_bit::is_enabled());
}

TEST_CASE("exit_handler: vm_exit_reason_wrcr4 invalid")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::basic_exit_reason::control_register_accesses);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 42;
    CHECK_NOTHROW(ehlr.handle(&ehlr));
}

TEST_CASE("exit_handler: emulate_rdgpr rax")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000000ULL;
    vcpu->set_rax(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rcx")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000100ULL;
    vcpu->set_rcx(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rdx")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000200ULL;
    vcpu->set_rdx(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rbx")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000300ULL;
    vcpu->set_rbx(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rsp")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000400ULL;
    vcpu->set_rsp(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rbp")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000500ULL;
    vcpu->set_rbp(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rsi")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000600ULL;
    vcpu->set_rsi(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr rdi")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000700ULL;
    vcpu->set_rdi(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r8")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000800ULL;
    vcpu->set_r08(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r9")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000900ULL;
    vcpu->set_r09(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r10")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000A00ULL;
    vcpu->set_r10(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r11")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000B00ULL;
    vcpu->set_r11(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r12")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000C00ULL;
    vcpu->set_r12(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r13")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000D00ULL;
    vcpu->set_r13(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r14")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000E00ULL;
    vcpu->set_r14(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_rdgpr r15")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000F00ULL;
    vcpu->set_r15(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rax")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000000ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rax() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rcx")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000100ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rcx() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rdx")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000200ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rdx() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rbx")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000300ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rbx() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rsp")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000400ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rsp() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rbp")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000500ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rbp() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rsi")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000600ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rsi() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr rdi")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000700ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rdi() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r8")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000800ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r08() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r9")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000900ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r09() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r10")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000A00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r10() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r11")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000B00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r11() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r12")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000C00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r12() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r13")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000D00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r13() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r14")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000E00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r14() == 42);
}

TEST_CASE("exit_handler: emulate_wrgpr r15")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[::intel_x64::vmcs::exit_qualification::addr] = 0x0000000000000F00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r15() == 42);
}

#endif
