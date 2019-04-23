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
#include <hve/arch/intel_x64/vmexit/control_register.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

void emulate_rdgpr(bfvmm::intel_x64::vcpu *vcpu);
void emulate_wrgpr(bfvmm::intel_x64::vcpu *vcpu);

TEST_CASE("emulate_rdgpr rax")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000000ULL;
    vcpu->set_rax(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr rcx")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000100ULL;
    vcpu->set_rcx(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr rdx")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000200ULL;
    vcpu->set_rdx(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr rbx")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000300ULL;
    vcpu->set_rbx(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr rsp")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000400ULL;
    vcpu->set_rsp(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr rbp")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000500ULL;
    vcpu->set_rbp(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr rsi")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000600ULL;
    vcpu->set_rsi(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr rdi")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000700ULL;
    vcpu->set_rdi(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r8")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000800ULL;
    vcpu->set_r08(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r9")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000900ULL;
    vcpu->set_r09(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r10")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000A00ULL;
    vcpu->set_r10(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r11")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000B00ULL;
    vcpu->set_r11(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r12")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000C00ULL;
    vcpu->set_r12(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r13")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000D00ULL;
    vcpu->set_r13(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r14")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000E00ULL;
    vcpu->set_r14(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_rdgpr r15")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000F00ULL;
    vcpu->set_r15(42);

    CHECK(emulate_rdgpr(vcpu) == 42);
}

TEST_CASE("emulate_wrgpr rax")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000000ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rax() == 42);
}

TEST_CASE("emulate_wrgpr rcx")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000100ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rcx() == 42);
}

TEST_CASE("emulate_wrgpr rdx")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000200ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rdx() == 42);
}

TEST_CASE("emulate_wrgpr rbx")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000300ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rbx() == 42);
}

TEST_CASE("emulate_wrgpr rsp")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000400ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rsp() == 42);
}

TEST_CASE("emulate_wrgpr rbp")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000500ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rbp() == 42);
}

TEST_CASE("emulate_wrgpr rsi")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000600ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rsi() == 42);
}

TEST_CASE("emulate_wrgpr rdi")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000700ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->rdi() == 42);
}

TEST_CASE("emulate_wrgpr r8")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000800ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r08() == 42);
}

TEST_CASE("emulate_wrgpr r9")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000900ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r09() == 42);
}

TEST_CASE("emulate_wrgpr r10")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000A00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r10() == 42);
}

TEST_CASE("emulate_wrgpr r11")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000B00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r11() == 42);
}

TEST_CASE("emulate_wrgpr r12")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000C00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r12() == 42);
}

TEST_CASE("emulate_wrgpr r13")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000D00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r13() == 42);
}

TEST_CASE("emulate_wrgpr r14")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000E00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r14() == 42);
}

TEST_CASE("emulate_wrgpr r15")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    g_vmcs_fields[vmcs_n::exit_qualification::addr] = 0x0000000000000F00ULL;
    emulate_wrgpr(vcpu, 42);

    CHECK(vcpu->r15() == 42);
}

bool
test_handler(
    vcpu_t *vcpu, bfvmm::intel_x64::control_register_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return false;
}

bool
test_handler_ignore_write(
    vcpu_t *vcpu, bfvmm::intel_x64::control_register_handler::info_t &info)
{
    bfignored(vcpu);

    info.ignore_write = true;
    return false;
}

bool
test_handler_ignore_advance(
    vcpu_t *vcpu, bfvmm::intel_x64::control_register_handler::info_t &info)
{
    bfignored(vcpu);

    info.ignore_advance = true;
    return false;
}

TEST_CASE("constructor/destruction")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    CHECK_NOTHROW(bfvmm::intel_x64::control_register_handler(vcpu));
}

TEST_CASE("add handlers")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    CHECK_NOTHROW(handler.add_wrcr0_handler(test_handler));
    CHECK_NOTHROW(handler.add_rdcr3_handler(test_handler));
    CHECK_NOTHROW(handler.add_wrcr3_handler(test_handler));
    CHECK_NOTHROW(handler.add_wrcr4_handler(test_handler));
}

TEST_CASE("enable exiting")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    CHECK_NOTHROW(
        handler.enable_wrcr0_exiting(0xFFFFFFFFFFFFFFFF)
    );

    CHECK_NOTHROW(
        handler.enable_wrcr4_exiting(0xFFFFFFFFFFFFFFFF)
    );

    CHECK_NOTHROW(handler.enable_rdcr3_exiting());
    CHECK_NOTHROW(handler.enable_wrcr3_exiting());
}

TEST_CASE("wrcr0 exit")
{
    setup_test_support();

    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 42;
    vmcs_n::guest_cr0::set(0);
    vmcs_n::cr0_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(test_handler);

    CHECK(handler.handle(vcpu) == true);
    CHECK(vmcs_n::guest_cr0::get() == 42);
    CHECK(vmcs_n::cr0_read_shadow::get() == 42);
}

TEST_CASE("wrcr0 exit, ignore write")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 42;
    vmcs_n::guest_cr0::set(0);
    vmcs_n::cr0_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(test_handler_ignore_write);

    CHECK(handler.handle(vcpu) == true);
    CHECK(vmcs_n::guest_cr0::get() == 0);
    CHECK(vmcs_n::cr0_read_shadow::get() == 0);
}

TEST_CASE("wrcr0 exit, ignore advance")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_wrcr0_handler(test_handler_ignore_advance);

    CHECK(handler.handle(vcpu) == true);
    CHECK(g_state.rip == 0);
}

TEST_CASE("cr0 mov_from_cr not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000010ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("cr0 clts not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000020ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("cr0 lmsw not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000030ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("wrcr3 exit")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 42;
    vmcs_n::guest_cr3::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(test_handler);

    CHECK(handler.handle(vcpu) == true);
    CHECK(vmcs_n::guest_cr3::get() == 42);
}

TEST_CASE("wrcr3 exit, ignore write")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 42;
    vmcs_n::guest_cr3::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(test_handler_ignore_write);

    CHECK(handler.handle(vcpu) == true);
    CHECK(vmcs_n::guest_cr3::get() == 0);
}

TEST_CASE("wrcr3 exit, ignore advance")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_wrcr3_handler(test_handler_ignore_advance);

    CHECK(handler.handle(vcpu) == true);
    CHECK(g_state.rip == 0);
}

TEST_CASE("rdcr3 exit")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 0;
    vmcs_n::guest_cr3::set(42);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(test_handler);

    CHECK(handler.handle(vcpu) == true);
    CHECK(g_state.rax == 42);
}

TEST_CASE("rdcr3 exit, ignore write")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 0;
    vmcs_n::guest_cr3::set(42);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(test_handler_ignore_write);

    CHECK(handler.handle(vcpu) == true);
    CHECK(g_state.rax == 0);
}

TEST_CASE("rdcr3 exit, ignore advance")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_rdcr3_handler(test_handler_ignore_advance);

    CHECK(handler.handle(vcpu) == true);
    CHECK(g_state.rip == 0);
}

TEST_CASE("cr3 clts not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000023ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("cr3 lmsw not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000033ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("wrcr4 exit")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 42;
    vmcs_n::guest_cr4::set(0);
    vmcs_n::cr4_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(test_handler);

    CHECK(handler.handle(vcpu) == true);
    CHECK(vmcs_n::guest_cr4::get() == 0x202a);
    CHECK(vmcs_n::cr4_read_shadow::get() == 42);
}

TEST_CASE("wrcr4 exit, ignore write")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rax = 42;
    vmcs_n::guest_cr4::set(0);
    vmcs_n::cr4_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(test_handler_ignore_write);

    CHECK(handler.handle(vcpu) == true);
    CHECK(vmcs_n::guest_cr4::get() == 0);
    CHECK(vmcs_n::cr4_read_shadow::get() == 0);
}

TEST_CASE("wrcr4 exit, ignore advance")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    g_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_wrcr4_handler(test_handler_ignore_advance);

    CHECK(handler.handle(vcpu) == true);
    CHECK(g_state.rip == 0);
}

TEST_CASE("cr4 mov_from_cr not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000014ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("cr4 clts not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000024ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("cr4 lmsw not supported")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000034ULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

TEST_CASE("invalid cr")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = bfvmm::intel_x64::control_register_handler(vcpu);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x000000000000000AULL
    );

    CHECK_THROWS(handler.handle(vcpu));
}

#endif
